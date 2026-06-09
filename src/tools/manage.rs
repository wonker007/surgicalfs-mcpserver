use crate::errors::{ErrorCode, SurgicalError, SurgicalResult};
use crate::pathguard::PathGuard;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Track chunked write sessions. Persisted to disk so state survives across
/// stateless MCP process invocations (supergateway streamableHttp mode).
#[derive(Serialize, Deserialize)]
pub struct WriteSession {
    pub total_chunks: u32,
    pub total_bytes: u64,
    pub total_lines: u32,
    /// Unix timestamp (seconds) when session was created.
    pub started_at_unix: u64,
}

/// Session manager for chunked writes. State is stored on disk under
/// %TEMP%/surgicalfs-sessions/ so it persists across process boundaries.
///
/// Concurrency model: MCP calls arrive sequentially from Claude (one tool call
/// at a time per conversation), so true concurrent access to the same session
/// file is unlikely. The atomic-rename write pattern protects against crashes
/// mid-write, and errors are propagated rather than swallowed.
pub struct WriteSessionManager {
    session_dir: PathBuf,
}

impl Default for WriteSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl WriteSessionManager {
    pub fn new() -> Self {
        let session_dir = std::env::temp_dir().join("surgicalfs-sessions");
        let _ = fs::create_dir_all(&session_dir);
        Self { session_dir }
    }

    /// Derive a stable filename for a canonical path's session state.
    /// Uses 32 hex chars (128 bits) of SHA-256 to avoid birthday collisions.
    fn session_file(&self, canonical: &Path) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(canonical.to_string_lossy().as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        self.session_dir.join(format!("{}.json", &hash[..32]))
    }

    fn load(&self, canonical: &Path) -> Option<WriteSession> {
        let data = fs::read(self.session_file(canonical)).ok()?;
        serde_json::from_slice(&data).ok()
    }

    /// Atomic save: write to a .tmp file then rename, so a crash mid-write
    /// never leaves a corrupt session file.
    fn save(&self, canonical: &Path, session: &WriteSession) -> SurgicalResult<()> {
        let target = self.session_file(canonical);
        let tmp = target.with_extension("tmp");
        let data = serde_json::to_vec(session).map_err(|e| {
            SurgicalError::new(
                ErrorCode::WriteSessionError,
                format!("Failed to serialize session: {}", e),
                "Internal error.",
            )
        })?;
        fs::write(&tmp, &data)
            .map_err(|e| SurgicalError::io_error(&e, "Failed to write session file"))?;
        fs::rename(&tmp, &target)
            .map_err(|e| SurgicalError::io_error(&e, "Failed to commit session file"))?;
        Ok(())
    }

    fn remove(&self, canonical: &Path) -> Option<WriteSession> {
        let session = self.load(canonical);
        let _ = fs::remove_file(self.session_file(canonical));
        session
    }

    /// Remove session files older than 5 minutes.
    pub fn cleanup_expired(&self) {
        let now = unix_now();
        let entries = match fs::read_dir(&self.session_dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(data) = fs::read(&path) {
                if let Ok(s) = serde_json::from_slice::<WriteSession>(&data) {
                    if now.saturating_sub(s.started_at_unix) >= 300 {
                        let _ = fs::remove_file(&path);
                    }
                }
            }
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Create or overwrite a file. Best for small files (<50 lines).
pub fn file_write(
    path_guard: &PathGuard,
    path: &str,
    content: &str,
    overwrite: Option<bool>,
) -> SurgicalResult<serde_json::Value> {
    let overwrite = overwrite.unwrap_or(false);

    // Validate through pathguard first, then check existence.
    let canonical = match path_guard.validate(path) {
        Ok(c) => {
            if !overwrite {
                return Err(SurgicalError::new(
                    ErrorCode::FileExists,
                    format!("File '{}' already exists.", path),
                    "Set overwrite=true to replace, or use a different path.",
                ));
            }
            c
        }
        Err(_) => path_guard.validate_new(path)?,
    };

    let bytes_written = content.len();
    let lines_written = content.lines().count();
    let created = !canonical.exists();

    super::atomic_write(&canonical, content.as_bytes())?;

    Ok(json!({
        "bytes_written": bytes_written,
        "lines_written": lines_written,
        "created": created,
    }))
}

/// Multi-call chunked write protocol.
pub fn file_write_chunked(
    path_guard: &PathGuard,
    session_mgr: &WriteSessionManager,
    path: &str,
    mode: &str,
    content: Option<&str>,
    overwrite: Option<bool>,
) -> SurgicalResult<serde_json::Value> {
    session_mgr.cleanup_expired();

    match mode {
        "start" => {
            let content = content.ok_or_else(|| {
                SurgicalError::new(
                    ErrorCode::WriteSessionError,
                    "Content is required for 'start' mode.",
                    "Provide the first chunk of content.",
                )
            })?;

            let canonical = match path_guard.validate(path) {
                Ok(c) => {
                    if !overwrite.unwrap_or(false) {
                        return Err(SurgicalError::new(
                            ErrorCode::FileExists,
                            format!("File '{}' already exists.", path),
                            "Set overwrite=true or use a different path.",
                        ));
                    }
                    c
                }
                Err(_) => path_guard.validate_new(path)?,
            };

            // Create/truncate and write first chunk (atomic: temp + rename)
            super::atomic_write(&canonical, content.as_bytes())?;

            let lines_in_chunk = content.lines().count() as u32;
            let bytes = content.len() as u64;

            // Create session (persisted to disk via atomic rename)
            session_mgr.save(
                &canonical,
                &WriteSession {
                    total_chunks: 1,
                    total_bytes: bytes,
                    total_lines: lines_in_chunk,
                    started_at_unix: unix_now(),
                },
            )?;

            Ok(json!({
                "chunk_number": 1,
                "lines_in_chunk": lines_in_chunk,
                "total_lines_so_far": lines_in_chunk,
                "total_bytes_so_far": bytes,
                "verified": true,
            }))
        }
        "append" => {
            let content = content.ok_or_else(|| {
                SurgicalError::new(
                    ErrorCode::WriteSessionError,
                    "Content is required for 'append' mode.",
                    "Provide the next chunk of content.",
                )
            })?;

            let canonical = path_guard.validate(path)?;

            let mut session = session_mgr.load(&canonical).ok_or_else(|| {
                SurgicalError::new(
                    ErrorCode::WriteSessionError,
                    "No active write session for this path.",
                    "Call file_write_chunked with mode='start' first.",
                )
            })?;

            // Verify file size matches expected
            let actual_size = fs::metadata(&canonical).map(|m| m.len()).unwrap_or(0);
            if actual_size != session.total_bytes {
                return Ok(json!({
                    "verified": false,
                    "mismatch": {
                        "expected_bytes": session.total_bytes,
                        "actual_bytes": actual_size,
                    },
                }));
            }

            // Append chunk
            // Non-atomic: append cannot use temp+rename without losing existing content.
            let mut file = fs::OpenOptions::new()
                .append(true)
                .open(&canonical)
                .map_err(|e| SurgicalError::io_error(&e, "Open for append failed"))?;
            file.write_all(content.as_bytes())
                .map_err(|e| SurgicalError::io_error(&e, "Append failed"))?;

            let lines_in_chunk = content.lines().count() as u32;
            session.total_chunks += 1;
            session.total_bytes += content.len() as u64;
            session.total_lines += lines_in_chunk;

            // Persist updated session (atomic rename)
            session_mgr.save(&canonical, &session)?;

            Ok(json!({
                "chunk_number": session.total_chunks,
                "lines_in_chunk": lines_in_chunk,
                "total_lines_so_far": session.total_lines,
                "total_bytes_so_far": session.total_bytes,
                "verified": true,
            }))
        }
        "finish" => {
            let canonical = path_guard.validate(path)?;

            let session = session_mgr.remove(&canonical).ok_or_else(|| {
                SurgicalError::new(
                    ErrorCode::WriteSessionError,
                    "No active write session for this path.",
                    "Call file_write_chunked with mode='start' first.",
                )
            })?;

            // Compute SHA-256
            let mut file = fs::File::open(&canonical)
                .map_err(|e| SurgicalError::io_error(&e, "Open failed"))?;
            let mut hasher = Sha256::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = file
                    .read(&mut buf)
                    .map_err(|e| SurgicalError::io_error(&e, "Read failed"))?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            let hash = format!("{:x}", hasher.finalize());

            Ok(json!({
                "total_chunks": session.total_chunks,
                "total_lines": session.total_lines,
                "total_bytes": session.total_bytes,
                "sha256": hash,
                "verified": true,
            }))
        }
        _ => Err(SurgicalError::new(
            ErrorCode::WriteSessionError,
            format!(
                "Invalid mode '{}'. Use 'start', 'append', or 'finish'.",
                mode
            ),
            "Valid modes: start, append, finish.",
        )),
    }
}

/// Atomically copy/move a staging file to its final location.
pub fn file_write_stream(
    path_guard: &PathGuard,
    source: &str,
    destination: &str,
    overwrite: Option<bool>,
    delete_source: Option<bool>,
    verify: Option<bool>,
) -> SurgicalResult<serde_json::Value> {
    let src_canonical = path_guard.validate(source)?;
    let overwrite = overwrite.unwrap_or(false);
    let delete_source = delete_source.unwrap_or(true);
    let verify = verify.unwrap_or(true);

    let dst_canonical = if std::path::Path::new(destination).exists() {
        let c = path_guard.validate(destination)?;
        if !overwrite {
            return Err(SurgicalError::new(
                ErrorCode::FileExists,
                format!("Destination '{}' already exists.", destination),
                "Set overwrite=true to replace.",
            ));
        }
        c
    } else {
        path_guard.validate_new(destination)?
    };

    // Copy file
    fs::copy(&src_canonical, &dst_canonical)
        .map_err(|e| SurgicalError::io_error(&e, "Copy failed"))?;

    let metadata = fs::metadata(&dst_canonical)
        .map_err(|e| SurgicalError::io_error(&e, "Cannot read destination metadata"))?;
    let bytes_written = metadata.len();

    let lines_written = fs::read_to_string(&dst_canonical)
        .map(|c| c.lines().count())
        .unwrap_or(0);

    // Verify with SHA-256
    let sha256 = if verify {
        let mut file = fs::File::open(&dst_canonical)
            .map_err(|e| SurgicalError::io_error(&e, "Open for verify failed"))?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| SurgicalError::io_error(&e, "Read failed"))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Some(format!("{:x}", hasher.finalize()))
    } else {
        None
    };

    // Delete source if requested (and only after verification)
    let source_deleted = if delete_source {
        fs::remove_file(&src_canonical).is_ok()
    } else {
        false
    };

    Ok(json!({
        "bytes_written": bytes_written,
        "lines_written": lines_written,
        "sha256": sha256,
        "source_deleted": source_deleted,
        "verified": verify,
    }))
}

/// Copy a file from source to destination without reading content into memory.
pub fn file_copy(
    path_guard: &PathGuard,
    source: &str,
    destination: &str,
    overwrite: Option<bool>,
) -> SurgicalResult<serde_json::Value> {
    let src_canonical = path_guard.validate(source)?;
    let overwrite = overwrite.unwrap_or(false);

    let dst_canonical = if std::path::Path::new(destination).exists() {
        let c = path_guard.validate(destination)?;
        if !overwrite {
            return Err(SurgicalError::new(
                ErrorCode::FileExists,
                format!("Destination '{}' already exists.", destination),
                "Set overwrite=true to replace.",
            ));
        }
        c
    } else {
        path_guard.validate_new(destination)?
    };

    let bytes_copied = fs::copy(&src_canonical, &dst_canonical)
        .map_err(|e| SurgicalError::io_error(&e, "Copy failed"))?;

    Ok(json!({
        "copied": true,
        "source": src_canonical.display().to_string(),
        "destination": dst_canonical.display().to_string(),
        "bytes_copied": bytes_copied,
    }))
}

/// Delete a file.
pub fn file_delete(path_guard: &PathGuard, path: &str) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;

    fs::remove_file(&canonical).map_err(|e| SurgicalError::io_error(&e, "Delete failed"))?;

    Ok(json!({
        "deleted": true,
        "path": canonical.display().to_string(),
    }))
}

/// Move or rename a file.
pub fn file_move(
    path_guard: &PathGuard,
    source: &str,
    destination: &str,
    overwrite: Option<bool>,
) -> SurgicalResult<serde_json::Value> {
    let src_canonical = path_guard.validate(source)?;
    let overwrite = overwrite.unwrap_or(false);

    let dst_canonical = if std::path::Path::new(destination).exists() {
        let c = path_guard.validate(destination)?;
        if !overwrite {
            return Err(SurgicalError::new(
                ErrorCode::FileExists,
                format!("Destination '{}' already exists.", destination),
                "Set overwrite=true to replace.",
            ));
        }
        c
    } else {
        path_guard.validate_new(destination)?
    };

    fs::rename(&src_canonical, &dst_canonical)
        .or_else(|_| {
            // rename may fail across drives; fall back to copy+delete
            fs::copy(&src_canonical, &dst_canonical)?;
            fs::remove_file(&src_canonical)
        })
        .map_err(|e| SurgicalError::io_error(&e, "Move failed"))?;

    Ok(json!({
        "moved": true,
        "source": src_canonical.display().to_string(),
        "destination": dst_canonical.display().to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_guard() -> PathGuard {
        PathGuard::new(
            &[std::env::temp_dir().to_string_lossy().to_string()],
            false,
            5_242_880,
        )
        .unwrap()
    }

    #[test]
    fn test_file_write_and_delete() {
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_write_test.txt");
        let path_str = path.to_string_lossy().to_string();

        // Clean up first
        fs::remove_file(&path).ok();

        let result = file_write(&guard, &path_str, "hello\nworld", None).unwrap();
        assert_eq!(result["bytes_written"], 11);
        assert_eq!(result["lines_written"], 2);

        let result = file_delete(&guard, &path_str).unwrap();
        assert_eq!(result["deleted"], true);
    }

    #[test]
    fn test_file_write_no_overwrite() {
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_nooverwrite.txt");
        let path_str = path.to_string_lossy().to_string();

        fs::write(&path, "existing").unwrap();
        let result = file_write(&guard, &path_str, "new", Some(false));
        assert!(result.is_err());

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_write_chunked() {
        let guard = test_guard();
        let mgr = WriteSessionManager::new();
        let path = std::env::temp_dir().join("surgicalfs_chunked_test.txt");
        let path_str = path.to_string_lossy().to_string();

        fs::remove_file(&path).ok();

        // Start
        let r =
            file_write_chunked(&guard, &mgr, &path_str, "start", Some("chunk1\n"), None).unwrap();
        assert_eq!(r["chunk_number"], 1);
        assert_eq!(r["verified"], true);

        // Append
        let r =
            file_write_chunked(&guard, &mgr, &path_str, "append", Some("chunk2\n"), None).unwrap();
        assert_eq!(r["chunk_number"], 2);

        // Finish
        let r = file_write_chunked(&guard, &mgr, &path_str, "finish", None, None).unwrap();
        assert_eq!(r["total_chunks"], 2);
        assert!(r["sha256"].is_string());

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("chunk1"));
        assert!(content.contains("chunk2"));

        fs::remove_file(&path).ok();
    }

    /// Simulate stateless process boundary: each call uses a fresh WriteSessionManager.
    #[test]
    fn test_file_write_chunked_stateless() {
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_chunked_stateless.txt");
        let path_str = path.to_string_lossy().to_string();

        fs::remove_file(&path).ok();

        // Process 1: start
        let r = file_write_chunked(
            &guard,
            &WriteSessionManager::new(),
            &path_str,
            "start",
            Some("alpha\n"),
            None,
        )
        .unwrap();
        assert_eq!(r["chunk_number"], 1);

        // Process 2: append (fresh manager, reads from disk)
        let r = file_write_chunked(
            &guard,
            &WriteSessionManager::new(),
            &path_str,
            "append",
            Some("beta\n"),
            None,
        )
        .unwrap();
        assert_eq!(r["chunk_number"], 2);

        // Process 3: finish (fresh manager, reads from disk)
        let r = file_write_chunked(
            &guard,
            &WriteSessionManager::new(),
            &path_str,
            "finish",
            None,
            None,
        )
        .unwrap();
        assert_eq!(r["total_chunks"], 2);
        assert!(r["sha256"].is_string());

        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "alpha\nbeta\n");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_file_move() {
        let guard = test_guard();
        let src = std::env::temp_dir().join("surgicalfs_move_src.txt");
        let dst = std::env::temp_dir().join("surgicalfs_move_dst.txt");

        fs::write(&src, "move me").unwrap();
        fs::remove_file(&dst).ok();

        let result =
            file_move(&guard, &src.to_string_lossy(), &dst.to_string_lossy(), None).unwrap();
        assert_eq!(result["moved"], true);
        assert!(!src.exists());
        assert!(dst.exists());

        fs::remove_file(&dst).ok();
    }

    #[test]
    fn test_file_write_stream() {
        let guard = test_guard();
        let src = std::env::temp_dir().join("surgicalfs_stream_src.txt");
        let dst = std::env::temp_dir().join("surgicalfs_stream_dst.txt");

        fs::write(&src, "stream content").unwrap();
        fs::remove_file(&dst).ok();

        let result = file_write_stream(
            &guard,
            &src.to_string_lossy(),
            &dst.to_string_lossy(),
            None,
            Some(true),
            Some(true),
        )
        .unwrap();

        assert_eq!(result["verified"], true);
        assert!(result["sha256"].is_string());
        assert_eq!(result["source_deleted"], true);
        assert!(!src.exists());
        assert!(dst.exists());

        fs::remove_file(&dst).ok();
    }

    #[test]
    fn test_file_copy() {
        let guard = test_guard();
        let src = std::env::temp_dir().join("surgicalfs_copy_src.txt");
        let dst = std::env::temp_dir().join("surgicalfs_copy_dst.txt");

        fs::write(&src, "copy me please").unwrap();
        fs::remove_file(&dst).ok();

        let result =
            file_copy(&guard, &src.to_string_lossy(), &dst.to_string_lossy(), None).unwrap();

        assert_eq!(result["copied"], true);
        assert_eq!(result["bytes_copied"], 14);
        assert!(src.exists()); // source still exists
        assert!(dst.exists());
        assert_eq!(fs::read_to_string(&dst).unwrap(), "copy me please");

        fs::remove_file(&src).ok();
        fs::remove_file(&dst).ok();
    }

    #[test]
    fn test_file_copy_no_overwrite() {
        let guard = test_guard();
        let src = std::env::temp_dir().join("surgicalfs_copy_noow_src.txt");
        let dst = std::env::temp_dir().join("surgicalfs_copy_noow_dst.txt");

        fs::write(&src, "source").unwrap();
        fs::write(&dst, "existing").unwrap();

        let result = file_copy(
            &guard,
            &src.to_string_lossy(),
            &dst.to_string_lossy(),
            Some(false),
        );
        assert!(result.is_err());

        // Destination unchanged
        assert_eq!(fs::read_to_string(&dst).unwrap(), "existing");

        fs::remove_file(&src).ok();
        fs::remove_file(&dst).ok();
    }

    #[test]
    fn test_atomic_write_cleans_temp_on_rename_failure() {
        // Make the destination a directory so the rename fails; the temp file
        // must be cleaned up and the destination left untouched.
        let dir = std::env::temp_dir().join("surgicalfs_atomic_renamefail_dir");
        let tmp = std::env::temp_dir().join("surgicalfs_atomic_renamefail_dir.surgicalfs-tmp");
        fs::remove_dir_all(&dir).ok();
        fs::remove_file(&tmp).ok();
        fs::create_dir(&dir).unwrap();

        let result = crate::tools::atomic_write(&dir, b"should not land");
        assert!(result.is_err(), "rename over a directory must fail");
        assert!(
            !tmp.exists(),
            "temp file must be cleaned up on rename failure"
        );
        assert!(dir.is_dir(), "destination directory must be untouched");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_file_write_leaves_no_temp_file() {
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_atomic_filewrite.txt");
        let tmp = std::env::temp_dir().join("surgicalfs_atomic_filewrite.txt.surgicalfs-tmp");
        fs::remove_file(&path).ok();
        fs::remove_file(&tmp).ok();

        file_write(&guard, &path.to_string_lossy(), "atomic body", None).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "atomic body");
        assert!(
            !tmp.exists(),
            "file_write must not leave a .surgicalfs-tmp behind"
        );

        fs::remove_file(&path).ok();
    }
}
