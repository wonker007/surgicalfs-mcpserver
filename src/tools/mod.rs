//! Tool implementations, plus shared helpers used across tool modules.

use std::fs;
use std::path::Path;

use crate::errors::SurgicalError;

pub mod compat;
pub mod csv_ops;
pub mod directory;
pub mod document;
pub mod inspect;
pub mod json_ops;
pub mod manage;
pub mod mutate;
pub mod search;
pub mod spreadsheet;
pub mod utility;

/// Atomically write `content` to `path` via temp-file + rename.
///
/// Writes to a sibling temp file in the same directory, then `fs::rename`s it
/// over the destination. `fs::rename` is atomic on the same volume (the temp
/// file is in the same directory, so same-volume is guaranteed), so a hard
/// kill, power loss, or service stop can never leave the destination torn or
/// half-written: it is either the old content or the complete new content. If
/// the write fails the original is untouched; if the rename fails the temp file
/// is cleaned up.
pub fn atomic_write(path: &Path, content: &[u8]) -> Result<(), SurgicalError> {
    let tmp_path = {
        let mut t = path.as_os_str().to_owned();
        t.push(".surgicalfs-tmp");
        std::path::PathBuf::from(t)
    };
    fs::write(&tmp_path, content)
        .map_err(|e| SurgicalError::io_error(&e, "Write to temp file failed"))?;
    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        SurgicalError::io_error(&e, "Atomic rename failed")
    })
}
