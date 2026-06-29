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
    restrict_owner_acl(path);
    Ok(())
}

/// Best-effort owner-only ACL restriction on Windows for a secret-bearing file
/// (the control token and the MCP auth sidecar). If icacls fails (or the username
/// can't be resolved), the file still exists with default permissions — log a
/// warning, don't abort. We never lock out the owner: if we can't name the owner
/// we skip the restriction entirely rather than grant SYSTEM-only.
///
/// The owner is granted MODIFY (`(M)`), not read-only: these files are rewritten
/// (the ctl token every boot; the auth sidecar on every change), and `std::fs::write`
/// truncates. With only `(R)` the owner lacks FILE_WRITE_DATA (ownership confers
/// WRITE_DAC/READ_CONTROL, not write-data), so a later rewrite would fail with
/// Access Denied. `(M)` keeps the file owner-only (others get nothing once
/// inheritance is stripped) while allowing the owner to rewrite it.
#[cfg(windows)]
fn restrict_owner_acl(path: &Path) {
    let username = std::env::var("USERNAME").unwrap_or_default();
    if username.is_empty() {
        tracing::warn!(
            "Could not resolve USERNAME; leaving default ACL on {}",
            path.display()
        );
        return;
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
            tracing::info!("ACL restricted: {}", path.display());
        }
        Ok(o) => {
            tracing::warn!(
                "icacls failed (file has default ACL): {}",
                String::from_utf8_lossy(&o.stderr).trim()
            );
        }
        Err(e) => {
            tracing::warn!("Could not run icacls (file has default ACL): {e}");
        }
    }
}

#[cfg(not(windows))]
fn restrict_owner_acl(_path: &Path) {}

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

// ─── MCP auth-token sidecar (Phase 3) ──────────────────────────────────────────
//
// The `[server] auth_token` TOML value is the BOOT DEFAULT; this sidecar is a
// persistent OVERRIDE (unlike the per-boot ctl token, it is NOT regenerated each
// boot). It is a plain-text file holding just the bearer value (no JSON, no
// newline) so the operator can copy it verbatim. Present + non-empty → that token;
// present + empty → auth disabled; absent → fall back to the TOML default. A
// deliberate reset is "delete the sidecar". Rationale mirrors DEC-DRAFT-C: never
// rewrite the TOML (it would destroy comments/formatting).

/// Derive the auth sidecar path: next to the config file, or in the temp dir.
pub fn auth_sidecar_path(config_path: Option<&Path>) -> PathBuf {
    if let Some(cfg) = config_path {
        if let Some(parent) = cfg.parent() {
            return parent.join("surgicalfs-auth.token");
        }
    }
    std::env::temp_dir().join("surgicalfs-auth.token")
}

/// Write the bearer token to the auth sidecar (owner-only ACL on Windows — it
/// holds a secret). The value is written verbatim, no trailing newline.
///
/// Atomic (`.tmp` → rename) like the other sidecars: a hard kill mid-write must
/// never leave an empty/torn file, because an empty auth sidecar reads as "auth
/// disabled" (`read_auth_sidecar` → `Some("")`), which would fail the boot OPEN
/// (`/mcp` unauthenticated). The all-or-nothing rename makes that impossible.
pub fn write_auth_sidecar(path: &Path, token: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("token.tmp");
    std::fs::write(&tmp, token)?;
    std::fs::rename(&tmp, path)?;
    restrict_owner_acl(path);
    Ok(())
}

/// Read the auth sidecar. `None` if the file is absent (use the TOML default);
/// `Some(token)` otherwise — where an empty string means "auth disabled". A
/// trailing newline (if an operator added one by hand) is trimmed.
pub fn read_auth_sidecar(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim_end_matches(['\r', '\n']).to_string())
}

/// Delete the auth sidecar (reset to the TOML default on next boot). Succeeds if
/// the file is already absent.
pub fn clear_auth_sidecar(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

// ─── Logging sidecar (Phase 4) ─────────────────────────────────────────────────
//
// `surgicalfs-logging.json` next to the config overrides `[logging] log_dir` and
// `retention_days` at boot — so the dashboard can enable/disable file logging
// without rewriting the TOML (same rationale as the auth sidecar / DEC-DRAFT-C).
// Holds no secrets (just a directory path + retention). Read BEFORE `setup_logging`
// because tracing-appender needs the final `log_dir`.

/// On-disk logging override: tracing-log dir + retention, AND (Phase 4.5) the
/// analytics JSONL dir + retention so the dashboard's single "Enable Logging"
/// toggle turns on BOTH subsystems. The analytics fields are `#[serde(default)]`,
/// so pre-4.5 sidecars (without them) still parse — backward compatible.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct LoggingSidecar {
    pub log_dir: String,
    #[serde(default)]
    pub retention_days: u32,
    /// Analytics JSONL log directory. When non-empty, overrides `[analytics] log_dir`.
    #[serde(default)]
    pub analytics_log_dir: String,
    /// Analytics retention days. Overrides `[analytics] retention_days` when the
    /// sidecar is present.
    #[serde(default = "default_analytics_retention")]
    pub analytics_retention_days: u32,
}

fn default_analytics_retention() -> u32 {
    90
}

impl LoggingSidecar {
    /// Phase 4.6: when file logging is enabled (`log_dir` non-empty) but the
    /// sidecar omits an analytics dir — e.g. a pre-4.5 sidecar, where
    /// `analytics_log_dir` deserializes to "" — default analytics to the same
    /// directory so a single "Enable Logging" toggle drives BOTH subsystems.
    /// Analytics is NEVER force-enabled when file logging itself is off (empty
    /// `log_dir`). A non-empty analytics dir with zero retention is clamped to
    /// the default so it does not prune immediately.
    pub fn apply_analytics_fallback(&mut self) {
        if !self.log_dir.is_empty() && self.analytics_log_dir.is_empty() {
            self.analytics_log_dir = self.log_dir.clone();
        }
        if !self.analytics_log_dir.is_empty() && self.analytics_retention_days == 0 {
            self.analytics_retention_days = default_analytics_retention();
        }
    }
}

/// Derive the logging sidecar path: next to the config file, or in the temp dir.
pub fn logging_sidecar_path(config_path: Option<&Path>) -> PathBuf {
    if let Some(cfg) = config_path {
        if let Some(parent) = cfg.parent() {
            return parent.join("surgicalfs-logging.json");
        }
    }
    std::env::temp_dir().join("surgicalfs-logging.json")
}

/// Write the logging sidecar atomically (`.tmp` → rename).
pub fn write_logging_sidecar(
    path: &Path,
    log_dir: &str,
    retention_days: u32,
    analytics_log_dir: &str,
    analytics_retention_days: u32,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let state = LoggingSidecar {
        log_dir: log_dir.to_string(),
        retention_days,
        analytics_log_dir: analytics_log_dir.to_string(),
        analytics_retention_days,
    };
    let json = serde_json::to_string_pretty(&state).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Read the logging sidecar. `None` if absent or unparseable (fall back to TOML).
pub fn read_logging_sidecar(path: &Path) -> Option<LoggingSidecar> {
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Delete the logging sidecar (reset to the TOML default on next boot). Succeeds
/// if the file is already absent. Retained utility (mirrors `clear_auth_sidecar`):
/// since Phase 4.6 the `disable` action WRITES an empty sidecar instead of
/// deleting, so this has no non-test caller — kept for a future "reset to TOML
/// default" and exercised by the round-trip test.
#[allow(dead_code)]
pub fn clear_logging_sidecar(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
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

    // ── Auth-token sidecar (Phase 3) ──

    #[test]
    fn auth_sidecar_read_write_roundtrip() {
        let dir = unique_sidecar_dir("auth-rt");
        let path = dir.join("surgicalfs-auth.token");
        write_auth_sidecar(&path, "s3cret-bearer-AZ09").unwrap();
        assert_eq!(
            read_auth_sidecar(&path).as_deref(),
            Some("s3cret-bearer-AZ09")
        );
        // Empty sidecar = "auth disabled" (Some(""), not None).
        write_auth_sidecar(&path, "").unwrap();
        assert_eq!(read_auth_sidecar(&path).as_deref(), Some(""));
        // Clear removes it → back to None (TOML default).
        clear_auth_sidecar(&path).unwrap();
        assert_eq!(read_auth_sidecar(&path), None);
        // Clearing an already-absent file is not an error.
        clear_auth_sidecar(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auth_sidecar_missing_returns_none() {
        let dir = unique_sidecar_dir("auth-missing");
        let path = dir.join("surgicalfs-auth.token");
        assert_eq!(read_auth_sidecar(&path), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auth_sidecar_path_next_to_config_and_temp_fallback() {
        let cfg = Path::new("C:\\some\\dir\\surgicalfs.toml");
        let p = auth_sidecar_path(Some(cfg));
        assert!(p.ends_with("surgicalfs-auth.token"));
        assert_eq!(p.parent().unwrap(), Path::new("C:\\some\\dir"));
        let t = auth_sidecar_path(None);
        assert_eq!(t.parent().unwrap(), std::env::temp_dir());
    }

    // ── Logging sidecar (Phase 4) ──

    #[test]
    fn logging_sidecar_read_write_roundtrip() {
        let dir = unique_sidecar_dir("logging");
        let path = dir.join("surgicalfs-logging.json");
        write_logging_sidecar(&path, "C:\\logs\\sfs", 45, "", 90).unwrap();
        let s = read_logging_sidecar(&path).expect("sidecar should read back");
        assert_eq!(s.log_dir, "C:\\logs\\sfs");
        assert_eq!(s.retention_days, 45);
        // Clear removes it → None (TOML default).
        clear_logging_sidecar(&path).unwrap();
        assert!(read_logging_sidecar(&path).is_none());
        // Clearing an already-absent file is not an error.
        clear_logging_sidecar(&path).unwrap();
        // Path derivation.
        let cfg = Path::new("C:\\d\\surgicalfs.toml");
        assert!(logging_sidecar_path(Some(cfg)).ends_with("surgicalfs-logging.json"));
        assert_eq!(
            logging_sidecar_path(None).parent().unwrap(),
            std::env::temp_dir()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Logging sidecar analytics fields (Phase 4.5) ──

    #[test]
    fn logging_sidecar_includes_analytics_fields() {
        let dir = unique_sidecar_dir("logging-an");
        let path = dir.join("surgicalfs-logging.json");
        write_logging_sidecar(&path, "C:\\logs", 30, "C:\\logs\\an", 60).unwrap();
        let s = read_logging_sidecar(&path).expect("sidecar should read back");
        assert_eq!(s.log_dir, "C:\\logs");
        assert_eq!(s.retention_days, 30);
        assert_eq!(s.analytics_log_dir, "C:\\logs\\an");
        assert_eq!(s.analytics_retention_days, 60);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn logging_sidecar_backward_compat() {
        // A pre-4.5 sidecar (no analytics fields) must still parse, with defaults
        // applied (analytics_log_dir = "", analytics_retention_days = 90).
        let dir = unique_sidecar_dir("logging-bc");
        let path = dir.join("surgicalfs-logging.json");
        std::fs::write(&path, r#"{"log_dir":"C:\\old","retention_days":15}"#).unwrap();
        let s = read_logging_sidecar(&path).expect("old sidecar should still parse");
        assert_eq!(s.log_dir, "C:\\old");
        assert_eq!(s.retention_days, 15);
        assert_eq!(s.analytics_log_dir, "");
        assert_eq!(s.analytics_retention_days, 90);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn analytics_defaults_to_log_dir_when_empty() {
        // Phase 4.6: a pre-4.5 sidecar (log_dir set, analytics_log_dir empty)
        // gets analytics defaulted to the same dir + default retention, so one
        // "Enable Logging" toggle drives BOTH subsystems.
        let mut sc = LoggingSidecar {
            log_dir: "C:\\logs".to_string(),
            retention_days: 15,
            analytics_log_dir: String::new(),
            analytics_retention_days: 0,
        };
        sc.apply_analytics_fallback();
        assert_eq!(sc.analytics_log_dir, "C:\\logs");
        assert_eq!(sc.analytics_retention_days, 90);

        // A disabled sidecar (empty log_dir) must NOT force analytics on.
        let mut off = LoggingSidecar {
            log_dir: String::new(),
            retention_days: 0,
            analytics_log_dir: String::new(),
            analytics_retention_days: 0,
        };
        off.apply_analytics_fallback();
        assert!(off.analytics_log_dir.is_empty());

        // An explicit analytics dir is preserved (not clobbered).
        let mut keep = LoggingSidecar {
            log_dir: "C:\\logs".to_string(),
            retention_days: 30,
            analytics_log_dir: "C:\\other".to_string(),
            analytics_retention_days: 45,
        };
        keep.apply_analytics_fallback();
        assert_eq!(keep.analytics_log_dir, "C:\\other");
        assert_eq!(keep.analytics_retention_days, 45);
    }
}
