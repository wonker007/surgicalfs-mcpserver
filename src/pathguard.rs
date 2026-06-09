use crate::errors::{ErrorCode, SurgicalError, SurgicalResult};
use std::path::{Path, PathBuf};

/// Security guard that validates all file paths against an allowlist.
#[derive(Debug, Clone)]
pub struct PathGuard {
    allowed_dirs: Vec<PathBuf>,
    follow_symlinks: bool,
    max_file_size: u64,
}

impl PathGuard {
    pub fn new(
        allowed_directories: &[String],
        follow_symlinks: bool,
        max_file_size: u64,
    ) -> SurgicalResult<Self> {
        let mut allowed_dirs = Vec::new();
        for dir in allowed_directories {
            let canonical = dunce::canonicalize(dir).map_err(|e| {
                SurgicalError::new(
                    ErrorCode::PathDenied,
                    format!("Cannot canonicalize allowed directory '{}': {}", dir, e),
                    "Ensure the directory exists and is accessible.",
                )
            })?;
            allowed_dirs.push(canonical);
        }
        Ok(Self {
            allowed_dirs,
            follow_symlinks,
            max_file_size,
        })
    }

    /// Validate a path against the allowlist. Returns the canonicalized path.
    pub fn validate(&self, path: &str) -> SurgicalResult<PathBuf> {
        // Reject null bytes
        if path.contains('\0') {
            return Err(SurgicalError::new(
                ErrorCode::PathDenied,
                "Path contains null bytes.",
                "Remove null bytes from the path.",
            ));
        }

        let input_path = Path::new(path);

        // Canonicalize the path
        let canonical =
            dunce::canonicalize(input_path).map_err(|_| SurgicalError::file_not_found(path))?;

        // Check symlinks if not allowed
        if !self.follow_symlinks {
            self.check_symlinks(input_path, &canonical)?;
        }

        // Check against allowlist using proper path component comparison
        let allowed = self
            .allowed_dirs
            .iter()
            .any(|allowed_dir| path_starts_with_ci(&canonical, allowed_dir));

        if !allowed {
            return Err(SurgicalError::path_denied(path));
        }

        Ok(canonical)
    }

    /// Validate a path that may not exist yet (for write operations).
    /// Validates the parent directory instead.
    pub fn validate_new(&self, path: &str) -> SurgicalResult<PathBuf> {
        if path.contains('\0') {
            return Err(SurgicalError::new(
                ErrorCode::PathDenied,
                "Path contains null bytes.",
                "Remove null bytes from the path.",
            ));
        }

        let input_path = Path::new(path);

        // For new files, validate the parent directory
        let parent = input_path.parent().ok_or_else(|| {
            SurgicalError::new(
                ErrorCode::PathDenied,
                format!("Cannot determine parent directory of '{}'", path),
                "Provide a full file path.",
            )
        })?;

        let canonical_parent = dunce::canonicalize(parent).map_err(|_| {
            SurgicalError::new(
                ErrorCode::FileNotFound,
                format!("Parent directory does not exist: '{}'", parent.display()),
                "Create the parent directory first.",
            )
        })?;

        if !self.follow_symlinks {
            self.check_symlinks(parent, &canonical_parent)?;
        }

        let allowed = self
            .allowed_dirs
            .iter()
            .any(|allowed_dir| path_starts_with_ci(&canonical_parent, allowed_dir));

        if !allowed {
            return Err(SurgicalError::path_denied(path));
        }

        // Build the full canonical path for the new file
        let file_name = input_path.file_name().ok_or_else(|| {
            SurgicalError::new(
                ErrorCode::PathDenied,
                "Path has no file name component.",
                "Provide a valid file path.",
            )
        })?;

        Ok(canonical_parent.join(file_name))
    }

    /// Check file size against the configured maximum.
    pub fn check_size(&self, path: &Path) -> SurgicalResult<u64> {
        let metadata = std::fs::metadata(path).map_err(|e| {
            SurgicalError::io_error(
                &e,
                &format!("Cannot read metadata for '{}'", path.display()),
            )
        })?;
        let size = metadata.len();
        if size > self.max_file_size {
            return Err(SurgicalError::file_too_large(
                &path.display().to_string(),
                size,
                self.max_file_size,
            ));
        }
        Ok(size)
    }

    /// Check that no path component is a symlink.
    fn check_symlinks(&self, original: &Path, _canonical: &Path) -> SurgicalResult<()> {
        let mut current = PathBuf::new();
        for component in original.components() {
            current.push(component);
            if current.exists() {
                let meta = std::fs::symlink_metadata(&current).map_err(|e| {
                    SurgicalError::io_error(
                        &e,
                        &format!("Cannot read metadata for '{}'", current.display()),
                    )
                })?;
                if meta.is_symlink() {
                    return Err(SurgicalError::new(
                        ErrorCode::PathDenied,
                        format!(
                            "Path component '{}' is a symbolic link. Symlinks are disabled.",
                            current.display()
                        ),
                        "Set follow_symlinks=true in config, or use the real path.",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn max_file_size(&self) -> u64 {
        self.max_file_size
    }
}

/// Case-insensitive path prefix check on Windows, case-sensitive elsewhere.
fn path_starts_with_ci(path: &Path, prefix: &Path) -> bool {
    if cfg!(windows) {
        // On Windows, do case-insensitive component comparison
        let path_str = path.to_string_lossy().to_lowercase();
        let prefix_str = prefix.to_string_lossy().to_lowercase();
        // Use path component comparison, not string prefix
        let path_norm = Path::new(&path_str);
        let prefix_norm = Path::new(&prefix_str);
        path_norm.starts_with(prefix_norm)
    } else {
        path.starts_with(prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_null_bytes_rejected() {
        let guard = PathGuard::new(&["C:\\".into()], false, 5_000_000).unwrap();
        assert!(guard.validate("C:\\test\0file.txt").is_err());
    }

    #[test]
    fn test_valid_path() {
        let temp = std::env::temp_dir();
        let temp_str = temp.to_string_lossy().to_string();
        let guard = PathGuard::new(std::slice::from_ref(&temp_str), false, 5_000_000).unwrap();

        // Create a temp file
        let test_file = temp.join("surgicalfs_test_pathguard.txt");
        fs::write(&test_file, "test").unwrap();

        let result = guard.validate(&test_file.to_string_lossy());
        assert!(result.is_ok());

        fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_path_outside_allowlist() {
        let temp = std::env::temp_dir();
        let sub = temp.join("surgicalfs_allowed");
        fs::create_dir_all(&sub).ok();

        let guard = PathGuard::new(&[sub.to_string_lossy().to_string()], false, 5_000_000).unwrap();

        // Create file outside allowed dir
        let outside = temp.join("surgicalfs_outside.txt");
        fs::write(&outside, "test").unwrap();

        let result = guard.validate(&outside.to_string_lossy());
        assert!(result.is_err());

        fs::remove_file(&outside).ok();
        fs::remove_dir(&sub).ok();
    }

    #[test]
    fn test_size_check() {
        let temp = std::env::temp_dir();
        let temp_str = temp.to_string_lossy().to_string();
        let guard = PathGuard::new(&[temp_str], false, 10).unwrap(); // 10 byte limit

        let test_file = temp.join("surgicalfs_test_size.txt");
        fs::write(&test_file, "this is more than 10 bytes of content").unwrap();

        let result = guard.check_size(&test_file);
        assert!(result.is_err());

        fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_traversal_basic() {
        // Create a temp subdirectory and allow only that
        let temp = std::env::temp_dir();
        let allowed = temp.join("surgicalfs_traversal_test");
        fs::create_dir_all(&allowed).ok();

        let guard =
            PathGuard::new(&[allowed.to_string_lossy().to_string()], false, 5_000_000).unwrap();

        // Attempt to escape via .. traversal (e.g. C:\Users\<user>\AppData\Local\Temp\surgicalfs_traversal_test\..\..\..\..\Windows\System32)
        let traversal_path = allowed
            .join("..")
            .join("..")
            .join("..")
            .join("..")
            .join("Windows")
            .join("System32");
        let result = guard.validate(&traversal_path.to_string_lossy());
        assert!(result.is_err(), "Traversal via .. should be denied");

        fs::remove_dir(&allowed).ok();
    }

    #[test]
    fn test_sibling_directory_bypass() {
        // If allowed is "surgicalfs_allowed", then "surgicalfs_allowed_extra" must be DENIED
        // This ensures path component comparison, not string prefix matching.
        let temp = std::env::temp_dir();
        let allowed = temp.join("surgicalfs_allowed");
        let sibling = temp.join("surgicalfs_allowed_extra");
        fs::create_dir_all(&allowed).ok();
        fs::create_dir_all(&sibling).ok();

        let guard =
            PathGuard::new(&[allowed.to_string_lossy().to_string()], false, 5_000_000).unwrap();

        // Create a file inside the sibling directory
        let sibling_file = sibling.join("sneaky.txt");
        fs::write(&sibling_file, "should not be accessible").unwrap();

        let result = guard.validate(&sibling_file.to_string_lossy());
        assert!(
            result.is_err(),
            "Sibling directory with similar prefix should be denied"
        );

        fs::remove_file(&sibling_file).ok();
        fs::remove_dir(&sibling).ok();
        fs::remove_dir(&allowed).ok();
    }

    #[test]
    fn test_null_byte_in_path() {
        let temp = std::env::temp_dir();
        let guard =
            PathGuard::new(&[temp.to_string_lossy().to_string()], false, 5_000_000).unwrap();

        let path_with_null = format!("{}\\foo\0bar.txt", temp.display());
        let result = guard.validate(&path_with_null);
        assert!(result.is_err(), "Path with null byte should be denied");

        // Also check validate_new
        let result_new = guard.validate_new(&path_with_null);
        assert!(
            result_new.is_err(),
            "validate_new with null byte should be denied"
        );
    }

    #[test]
    fn test_empty_path() {
        let temp = std::env::temp_dir();
        let guard =
            PathGuard::new(&[temp.to_string_lossy().to_string()], false, 5_000_000).unwrap();

        let result = guard.validate("");
        assert!(result.is_err(), "Empty path should fail validation");
    }

    #[test]
    fn test_dot_dot_path() {
        let temp = std::env::temp_dir();
        let guard =
            PathGuard::new(&[temp.to_string_lossy().to_string()], false, 5_000_000).unwrap();

        let result = guard.validate("..");
        // ".." resolves to the parent of CWD which is very likely not in the allowlist,
        // or if it somehow is, the test still verifies validate doesn't panic.
        // For most environments, this should be denied.
        assert!(
            result.is_err(),
            "Bare '..' path should be denied (resolves outside allowlist)"
        );
    }

    #[cfg(windows)]
    #[test]
    fn test_case_insensitive_windows() {
        let temp = std::env::temp_dir();
        let allowed = temp.join("SurgicalFS_CaseTest");
        fs::create_dir_all(&allowed).ok();

        let guard =
            PathGuard::new(&[allowed.to_string_lossy().to_string()], false, 5_000_000).unwrap();

        // Create a file
        let test_file = allowed.join("TestFile.txt");
        fs::write(&test_file, "case test").unwrap();

        // Access with different casing: lowercase the entire path
        let lower_path = allowed.to_string_lossy().to_lowercase() + "\\testfile.txt";
        let result = guard.validate(&lower_path);
        assert!(
            result.is_ok(),
            "Case-insensitive access should succeed on Windows: {:?}",
            result.err()
        );

        // Access with uppercase
        let upper_path = allowed.to_string_lossy().to_uppercase() + "\\TESTFILE.TXT";
        let result_upper = guard.validate(&upper_path);
        assert!(
            result_upper.is_ok(),
            "Uppercase path should succeed on Windows: {:?}",
            result_upper.err()
        );

        fs::remove_file(&test_file).ok();
        fs::remove_dir(&allowed).ok();
    }

    #[test]
    fn test_validate_new_outside_allowlist() {
        let temp = std::env::temp_dir();
        let allowed = temp.join("surgicalfs_new_allowed");
        let outside = temp.join("surgicalfs_new_outside");
        fs::create_dir_all(&allowed).ok();
        fs::create_dir_all(&outside).ok();

        let guard =
            PathGuard::new(&[allowed.to_string_lossy().to_string()], false, 5_000_000).unwrap();

        // Try to create a new file in the outside directory
        let new_file = outside.join("new_file.txt");
        let result = guard.validate_new(&new_file.to_string_lossy());
        assert!(
            result.is_err(),
            "validate_new for path outside allowlist should fail"
        );

        fs::remove_dir(&outside).ok();
        fs::remove_dir(&allowed).ok();
    }

    #[test]
    fn test_validate_new_valid() {
        let temp = std::env::temp_dir();
        let allowed = temp.join("surgicalfs_new_valid");
        fs::create_dir_all(&allowed).ok();

        let guard =
            PathGuard::new(&[allowed.to_string_lossy().to_string()], false, 5_000_000).unwrap();

        // validate_new for a file that doesn't exist yet, inside the allowed directory
        let new_file = allowed.join("brand_new_file.txt");
        // Make sure it doesn't exist
        fs::remove_file(&new_file).ok();

        let result = guard.validate_new(&new_file.to_string_lossy());
        assert!(
            result.is_ok(),
            "validate_new for valid new file path should succeed: {:?}",
            result.err()
        );

        // The returned path should end with the file name
        let validated = result.unwrap();
        assert_eq!(
            validated.file_name().unwrap().to_string_lossy(),
            "brand_new_file.txt"
        );

        fs::remove_dir(&allowed).ok();
    }
}
