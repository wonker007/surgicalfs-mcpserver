use crate::errors::{ErrorCode, SurgicalError, SurgicalResult};
use crate::pathguard::PathGuard;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;

/// Compute a checksum of a file using streaming hash.
pub fn file_checksum(
    path_guard: &PathGuard,
    path: &str,
    algorithm: Option<String>,
) -> SurgicalResult<serde_json::Value> {
    let canonical = path_guard.validate(path)?;
    let algorithm = algorithm.unwrap_or_else(|| "sha256".to_string());

    let metadata = fs::metadata(&canonical)
        .map_err(|e| SurgicalError::io_error(&e, "Cannot read metadata"))?;
    let size = metadata.len();

    let mut file =
        fs::File::open(&canonical).map_err(|e| SurgicalError::io_error(&e, "Open failed"))?;

    let checksum = match algorithm.as_str() {
        "sha256" => {
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
            format!("{:x}", hasher.finalize())
        }
        "md5" => {
            use md5::Digest as Md5Digest;
            let mut hasher = md5::Md5::new();
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
            format!("{:x}", hasher.finalize())
        }
        "blake3" => {
            let mut hasher = blake3::Hasher::new();
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
            hasher.finalize().to_hex().to_string()
        }
        _ => {
            return Err(SurgicalError::new(
                ErrorCode::InternalError,
                format!(
                    "Unsupported algorithm '{}'. Use sha256, md5, or blake3.",
                    algorithm
                ),
                "Valid algorithms: sha256, md5, blake3.",
            ));
        }
    };

    Ok(json!({
        "checksum": checksum,
        "algorithm": algorithm,
        "size_bytes": size,
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
    fn test_sha256_checksum() {
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_checksum.txt");
        fs::write(&path, "hello").unwrap();

        let result = file_checksum(&guard, &path.to_string_lossy(), Some("sha256".into())).unwrap();
        assert_eq!(result["algorithm"], "sha256");
        assert!(result["checksum"].as_str().unwrap().len() == 64);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_md5_checksum() {
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_checksum_md5.txt");
        fs::write(&path, "hello").unwrap();

        let result = file_checksum(&guard, &path.to_string_lossy(), Some("md5".into())).unwrap();
        assert_eq!(result["algorithm"], "md5");
        assert!(result["checksum"].as_str().unwrap().len() == 32);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_blake3_checksum() {
        let guard = test_guard();
        let path = std::env::temp_dir().join("surgicalfs_checksum_blake3.txt");
        fs::write(&path, "hello").unwrap();

        let result = file_checksum(&guard, &path.to_string_lossy(), Some("blake3".into())).unwrap();
        assert_eq!(result["algorithm"], "blake3");

        fs::remove_file(&path).ok();
    }
}
