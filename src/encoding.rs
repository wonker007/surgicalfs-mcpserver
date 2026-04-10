use crate::errors::{ErrorCode, SurgicalError};

/// Detect encoding, strip BOM, and decode bytes to a String.
/// When `encoding_hint` is "auto", tries UTF-8 first then falls back to Windows-1252.
pub fn decode_bytes(
    bytes: &[u8],
    encoding_hint: &str,
) -> Result<(String, &'static str), SurgicalError> {
    match encoding_hint {
        "utf-8" => decode_utf8(bytes),
        "utf-8-bom" => decode_utf8_bom(bytes),
        "latin-1" | "windows-1252" => decode_windows1252(bytes),
        _ => decode_auto(bytes),
    }
}

fn decode_utf8(bytes: &[u8]) -> Result<(String, &'static str), SurgicalError> {
    let text = strip_utf8_bom(bytes);
    std::str::from_utf8(text)
        .map(|s| (s.to_string(), "utf-8"))
        .map_err(|e| {
            SurgicalError::new(
                ErrorCode::EncodingError,
                format!("UTF-8 decode failed: {}", e),
                "Try encoding='auto' or encoding='windows-1252'.",
            )
        })
}

fn decode_utf8_bom(bytes: &[u8]) -> Result<(String, &'static str), SurgicalError> {
    let text = strip_utf8_bom(bytes);
    std::str::from_utf8(text)
        .map(|s| (s.to_string(), "utf-8-bom"))
        .map_err(|e| {
            SurgicalError::new(
                ErrorCode::EncodingError,
                format!("UTF-8 BOM decode failed: {}", e),
                "File has BOM but is not valid UTF-8.",
            )
        })
}

fn decode_windows1252(bytes: &[u8]) -> Result<(String, &'static str), SurgicalError> {
    let (decoded, _, _) = encoding_rs::WINDOWS_1252.decode(bytes);
    Ok((decoded.into_owned(), "windows-1252"))
}

fn decode_auto(bytes: &[u8]) -> Result<(String, &'static str), SurgicalError> {
    // Check for UTF-8 BOM
    let stripped = strip_utf8_bom(bytes);
    let had_bom = stripped.len() != bytes.len();

    // Try UTF-8 first
    match std::str::from_utf8(stripped) {
        Ok(s) => {
            let enc = if had_bom { "utf-8-bom" } else { "utf-8" };
            Ok((s.to_string(), enc))
        }
        Err(_) => {
            // Fallback to Windows-1252
            let (decoded, _, _) = encoding_rs::WINDOWS_1252.decode(bytes);
            Ok((decoded.into_owned(), "windows-1252"))
        }
    }
}

fn strip_utf8_bom(bytes: &[u8]) -> &[u8] {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &bytes[3..]
    } else {
        bytes
    }
}

/// Check if bytes appear to be a binary file by looking for null bytes in the first 8KB.
pub fn is_binary(bytes: &[u8]) -> bool {
    let check_len = bytes.len().min(8192);
    bytes[..check_len].contains(&0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utf8_decode() {
        let (text, enc) = decode_bytes(b"hello world", "auto").unwrap();
        assert_eq!(text, "hello world");
        assert_eq!(enc, "utf-8");
    }

    #[test]
    fn test_utf8_bom_strip() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"hello");
        let (text, enc) = decode_bytes(&bytes, "auto").unwrap();
        assert_eq!(text, "hello");
        assert_eq!(enc, "utf-8-bom");
    }

    #[test]
    fn test_windows1252_fallback() {
        // 0x80 is not valid UTF-8 but is valid Windows-1252 (€)
        let bytes = &[0x80, 0x41, 0x42];
        let (text, enc) = decode_bytes(bytes, "auto").unwrap();
        assert_eq!(enc, "windows-1252");
        assert!(text.contains('A'));
    }

    #[test]
    fn test_binary_detection() {
        assert!(is_binary(&[0x00, 0x01, 0x02]));
        assert!(!is_binary(b"hello world"));
    }
}
