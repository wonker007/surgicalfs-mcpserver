//! Per-boot control-plane authentication token (DEC-DRAFT-M).
//!
//! A fresh token is minted at every HTTP-mode startup and written next to the
//! config file (or the temp dir). The running server holds it in memory and
//! injects it into `/dashboard`; the control routes validate it. It is never
//! logged (DOC-003 §"What NOT to do") and never committed.
//!
//! The token is URL-safe, unpadded base64 (alphabet `A–Z a–z 0–9 - _`) so it can
//! ride the `/events?token=` query string (the EventSource auth fallback,
//! DEC-DRAFT-H / prompt §9.4 Option A) without percent-encoding ambiguity, while
//! still serving as the `Authorization: Bearer` value on the other routes.

use std::path::{Path, PathBuf};

/// Generate a 32-byte CSPRNG token, URL-safe base64 (43 chars, no padding).
///
/// Uses `rand::rng()` (a ChaCha-based CSPRNG seeded from the OS), not
/// `OsRng::random()` — in rand 0.9 `OsRng` implements only `TryRngCore`, so
/// `Rng::random()` is not available on it.
pub fn generate_ctl_token() -> String {
    use base64::Engine as _;
    use rand::Rng as _;
    let bytes: [u8; 32] = rand::rng().random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Write the token to `path`, creating parent dirs if needed.
/// On Windows, restrict the ACL to owner + SYSTEM (best-effort).
pub fn write_ctl_token(path: &Path, token: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, token)?;

    // Best-effort ACL restriction on Windows. If icacls fails (or the username
    // can't be resolved), the token file still exists with default permissions —
    // log a warning, don't abort. We never lock out the owner: if we can't name
    // the owner we skip the restriction entirely rather than grant SYSTEM-only.
    //
    // The owner is granted MODIFY (`(M)`), not read-only: a per-boot token is
    // rewritten on every HTTP start, and `std::fs::write` truncates the existing
    // file. With only `(R)` the owner lacks FILE_WRITE_DATA (ownership confers
    // WRITE_DAC/READ_CONTROL, not write-data), so the SECOND boot's rewrite would
    // fail with Access Denied and abort startup. `(M)` keeps the file owner-only
    // (other users still get nothing once inheritance is stripped) while allowing
    // the owner to rewrite it next boot.
    #[cfg(windows)]
    {
        let username = std::env::var("USERNAME").unwrap_or_default();
        if username.is_empty() {
            tracing::warn!(
                "Could not resolve USERNAME; leaving default ACL on control token: {}",
                path.display()
            );
            return Ok(());
        }
        let path_str = path.to_string_lossy();
        let result = std::process::Command::new("icacls")
            .args([
                &*path_str,
                "/inheritance:r",
                "/grant:r",
                &format!("{username}:(M)"),
                "/grant:r",
                "SYSTEM:(R)",
            ])
            .output();
        match result {
            Ok(o) if o.status.success() => {
                tracing::info!("Control token ACL restricted: {}", path.display());
            }
            Ok(o) => {
                tracing::warn!(
                    "icacls failed (token file has default ACL): {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                );
            }
            Err(e) => {
                tracing::warn!("Could not run icacls (token file has default ACL): {e}");
            }
        }
    }
    Ok(())
}

/// Determine the token file path: next to the config file if provided,
/// otherwise in the system temp dir.
pub fn ctl_token_path(config_path: Option<&Path>) -> PathBuf {
    if let Some(cfg) = config_path {
        if let Some(parent) = cfg.parent() {
            return parent.join("surgicalfs-ctl.token");
        }
    }
    std::env::temp_dir().join("surgicalfs-ctl.token")
}

// ─── Sidecar tool-state persistence (Stage 4, DEC-DRAFT-C) ─────────────────────
//
// The TOML `[tools] enable` is the BOOT DEFAULT; this sidecar is the RUNTIME
// overlay, rewritten on every tool toggle and loaded over the TOML defaults at
// startup. Holds no secrets (only tool names) and lives next to the config (or in
// the temp dir). A deliberate reset is "delete the sidecar".

/// On-disk runtime tool state. `version` lets the schema evolve; `updated_at` is
/// an ISO-8601 timestamp for operator diffing.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SidecarState {
    pub version: u32,
    pub enabled_tools: Vec<String>,
    pub updated_at: String,
}

/// Derive the sidecar path: next to the config file, or in the temp dir.
pub fn sidecar_path(config_path: Option<&Path>) -> PathBuf {
    if let Some(cfg) = config_path {
        if let Some(parent) = cfg.parent() {
            return parent.join("surgicalfs-state.json");
        }
    }
    std::env::temp_dir().join("surgicalfs-state.json")
}

/// Write the sidecar atomically: write to a sibling `.tmp`, then rename over the
/// target. The rename is atomic on a single volume, so a hard kill mid-write
/// never leaves a torn file in place (DEC-DRAFT-C).
pub fn write_sidecar(
    path: &Path,
    enabled_tools: &std::collections::HashSet<String>,
) -> std::io::Result<()> {
    let state = SidecarState {
        version: 1,
        enabled_tools: {
            let mut v: Vec<String> = enabled_tools.iter().cloned().collect();
            v.sort(); // deterministic on disk for diffing
            v
        },
        updated_at: chrono::Utc::now().to_rfc3339(),
    };
    let json = serde_json::to_string_pretty(&state).map_err(std::io::Error::other)?;

    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Read the sidecar. `Ok(None)` if the file is absent (use TOML defaults);
/// `Err` only on a parse failure (corrupt file), so the caller can log-and-skip
/// rather than abort startup.
pub fn read_sidecar(path: &Path) -> Result<Option<std::collections::HashSet<String>>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read sidecar {}: {e}", path.display()))?;
    let state: SidecarState = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse sidecar {}: {e}", path.display()))?;
    Ok(Some(state.enabled_tools.into_iter().collect()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_43_chars_url_safe_base64() {
        let t = generate_ctl_token();
        // 32 bytes → ceil(32 * 8 / 6) = 43 base64 chars, no padding.
        assert_eq!(t.len(), 43, "token was {:?}", t);
        assert!(
            t.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "token has non-URL-safe chars: {t}"
        );
    }

    #[test]
    fn tokens_are_unique_per_call() {
        let a = generate_ctl_token();
        let b = generate_ctl_token();
        assert_ne!(a, b, "CSPRNG produced identical tokens");
    }

    #[test]
    fn write_then_read_round_trips() {
        // Unique dir per test run to avoid cross-test races.
        let dir = std::env::temp_dir().join(format!(
            "sfs-ctl-state-test-{}-{}",
            std::process::id(),
            generate_ctl_token().get(..8).unwrap_or("x")
        ));
        let path = dir.join("surgicalfs-ctl.token");
        let token = generate_ctl_token();
        write_ctl_token(&path, &token).expect("write should succeed");
        let read_back = std::fs::read_to_string(&path).expect("read should succeed");
        assert_eq!(read_back, token);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression: the token is rewritten on every HTTP boot, so a second
    /// `write_ctl_token` to the same path MUST succeed. With a read-only owner ACL
    /// it would fail with Access Denied on Windows (the owner couldn't truncate);
    /// the owner is granted MODIFY so the rewrite works. On non-Windows this just
    /// confirms the overwrite path.
    #[test]
    fn write_twice_to_same_path_succeeds() {
        let dir = std::env::temp_dir().join(format!(
            "sfs-ctl-rewrite-test-{}-{}",
            std::process::id(),
            generate_ctl_token().get(..8).unwrap_or("x")
        ));
        let path = dir.join("surgicalfs-ctl.token");
        let first = generate_ctl_token();
        write_ctl_token(&path, &first).expect("first write should succeed");
        let second = generate_ctl_token();
        write_ctl_token(&path, &second).expect("second write (rewrite) must succeed");
        let read_back = std::fs::read_to_string(&path).expect("read should succeed");
        assert_eq!(read_back, second, "rewrite should replace the old token");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_next_to_config_when_provided() {
        let cfg = Path::new("C:\\some\\dir\\surgicalfs.toml");
        let p = ctl_token_path(Some(cfg));
        assert!(p.ends_with("surgicalfs-ctl.token"));
        assert_eq!(p.parent().unwrap(), Path::new("C:\\some\\dir"));
    }

    #[test]
    fn path_falls_back_to_temp_when_no_config() {
        let p = ctl_token_path(None);
        assert!(p.ends_with("surgicalfs-ctl.token"));
        assert_eq!(p.parent().unwrap(), std::env::temp_dir());
    }

    // ── Sidecar persistence ──

    /// Unique sidecar dir per test to avoid cross-test races.
    fn unique_sidecar_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sfs-sidecar-{tag}-{}-{}",
            std::process::id(),
            generate_ctl_token().get(..8).unwrap_or("x")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn set_of(names: &[&str]) -> std::collections::HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn sidecar_write_read_round_trip() {
        let dir = unique_sidecar_dir("rt");
        let path = dir.join("surgicalfs-state.json");
        let tools = set_of(&["file_info", "file_head", "json_query"]);
        write_sidecar(&path, &tools).expect("write should succeed");
        let read = read_sidecar(&path).expect("read should succeed");
        assert_eq!(read, Some(tools));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sidecar_write_is_sorted_on_disk() {
        let dir = unique_sidecar_dir("sort");
        let path = dir.join("surgicalfs-state.json");
        write_sidecar(&path, &set_of(&["zzz", "aaa", "mmm"])).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        let parsed: SidecarState = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.enabled_tools, vec!["aaa", "mmm", "zzz"]);
        assert_eq!(parsed.version, 1);
        assert!(!parsed.updated_at.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sidecar_atomic_tmp_is_cleaned_up() {
        let dir = unique_sidecar_dir("tmp");
        let path = dir.join("surgicalfs-state.json");
        write_sidecar(&path, &set_of(&["file_info"])).unwrap();
        // The rename consumes the `.tmp`; only the final file should remain.
        assert!(path.exists());
        assert!(!path.with_extension("json.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sidecar_overwrites_existing() {
        let dir = unique_sidecar_dir("ow");
        let path = dir.join("surgicalfs-state.json");
        write_sidecar(&path, &set_of(&["file_info"])).unwrap();
        write_sidecar(&path, &set_of(&["json_query", "csv_read"])).unwrap();
        let read = read_sidecar(&path).unwrap();
        assert_eq!(read, Some(set_of(&["json_query", "csv_read"])));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sidecar_missing_returns_none() {
        let dir = unique_sidecar_dir("missing");
        let path = dir.join("surgicalfs-state.json");
        assert_eq!(read_sidecar(&path).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sidecar_corrupt_returns_err() {
        let dir = unique_sidecar_dir("corrupt");
        let path = dir.join("surgicalfs-state.json");
        std::fs::write(&path, "{ not valid json ]").unwrap();
        assert!(read_sidecar(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sidecar_path_next_to_config() {
        let cfg = Path::new("C:\\some\\dir\\surgicalfs.toml");
        let p = sidecar_path(Some(cfg));
        assert!(p.ends_with("surgicalfs-state.json"));
        assert_eq!(p.parent().unwrap(), Path::new("C:\\some\\dir"));
    }

    #[test]
    fn sidecar_path_temp_fallback() {
        let p = sidecar_path(None);
        assert!(p.ends_with("surgicalfs-state.json"));
        assert_eq!(p.parent().unwrap(), std::env::temp_dir());
    }
}
