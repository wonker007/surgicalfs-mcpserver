//! Analytics subsystem (Phase 2): per-tool / per-repo response-byte accounting,
//! a presentation-vs-content split, an append-only daily JSONL audit log, and
//! on-demand time-bucketed rollups for the control plane's `/analytics` endpoint.
//!
//! Security boundary (distinct from the `/events` redaction): the JSONL log and
//! `/analytics` contain FULL file paths (for repo aggregation). That is acceptable
//! because both are operator-only — the JSONL file is a local artifact (same model
//! as the tracing logs) and `/analytics` is on the localhost-only, ctl-token-authed
//! control plane. The redacted `/events` pipeline (DEC-DRAFT-N) is unchanged and
//! independent.
//!
//! Recording is HTTP-only: `handler.rs` measures the serialized response bytes and
//! calls into here. The stdio path never touches it. The JSONL append is invoked
//! by the caller inside `block_in_place` so it never blocks an async worker.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

use crate::config::AnalyticsConfig;

/// Sentinel repo bucket for tool calls without a path argument
/// (e.g. `list_allowed_directories`).
const NO_REPO: &str = "(no repo / system)";

/// Cap lines aggregated per JSONL file so a runaway log can't blow up memory or
/// latency on the `/analytics` rollup (prompt §6.3).
const MAX_LINES_PER_FILE: usize = 50_000;

// ─── In-memory per-tool / per-repo counters ───────────────────────────────────

/// Per-tool session metrics. Updated on every recorded tool call.
#[derive(Default, Clone)]
pub struct ToolAnalytics {
    pub calls: u64,
    pub errors: u64,
    pub total_bytes: u64,
    pub total_duration_us: u64,
    pub last_called: Option<chrono::DateTime<chrono::Utc>>,
}

/// Per-repo session metrics. `tools_used` counts distinct tool names.
#[derive(Default)]
struct RepoAnalytics {
    calls: u64,
    total_bytes: u64,
    tools_used: HashSet<String>,
}

// ─── JSONL entry ───────────────────────────────────────────────────────────────

/// One line in the daily JSONL analytics file. `Deserialize` is needed for the
/// rollup reads (`/analytics` parses prior days' files back into this shape).
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ToolCallEntry {
    pub timestamp: String, // ISO 8601 (RFC 3339)
    pub tool: String,
    pub duration_ms: u64,
    pub response_bytes: usize,
    pub status: String, // "ok" or "error"
    pub path: Option<String>,
    pub repo: Option<String>,
}

impl ToolCallEntry {
    /// Build an entry stamped with the current UTC time. `repo` is precomputed by
    /// the caller (it needs the analytics store's allowed dirs — see `repo_for`).
    pub fn new(
        tool: &str,
        duration_ms: u64,
        response_bytes: usize,
        status: &str,
        path: Option<String>,
        repo: Option<String>,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            tool: tool.to_string(),
            duration_ms,
            response_bytes,
            status: status.to_string(),
            path,
            repo,
        }
    }
}

// ─── JSONL writer ──────────────────────────────────────────────────────────────

/// Append-only daily JSONL writer. Rotates by the date embedded in each entry's
/// `timestamp` (first 10 chars, `YYYY-MM-DD`) so rotation is deterministic and
/// unit-testable without faking the wall clock.
pub struct JsonlWriter {
    dir: PathBuf,
    current_date: String,
    file: Option<std::fs::File>,
}

impl JsonlWriter {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            current_date: String::new(),
            file: None,
        }
    }

    /// Append one entry, rotating to a new daily file when the entry's date
    /// differs from the currently-open file's date.
    pub fn write(&mut self, entry: &ToolCallEntry) -> std::io::Result<()> {
        let date = entry.timestamp.get(..10).unwrap_or("unknown").to_string();
        if self.file.is_none() || self.current_date != date {
            std::fs::create_dir_all(&self.dir)?;
            let path = self.dir.join(format!("surgicalfs-analytics-{date}.jsonl"));
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            self.file = Some(f);
            self.current_date = date;
        }
        let line = serde_json::to_string(entry).map_err(std::io::Error::other)?;
        use std::io::Write as _;
        writeln!(self.file.as_mut().unwrap(), "{line}")?;
        Ok(())
    }
}

// ─── Analytics store ───────────────────────────────────────────────────────────

pub struct AnalyticsStore {
    /// Per-tool metrics. Key = tool name.
    pub per_tool: RwLock<HashMap<String, ToolAnalytics>>,
    /// Per-repo metrics. Key = repo name (or the NO_REPO sentinel).
    per_repo: RwLock<HashMap<String, RepoAnalytics>>,

    /// Presentation (tools/list schema payload) byte total this session.
    pub presentation_bytes_session: AtomicU64,
    /// Number of tools/list calls served (a proxy for "sessions").
    pub presentation_calls: AtomicU64,
    /// Content (tools/call output) byte total this session.
    pub content_bytes_session: AtomicU64,

    /// Chars-per-token estimate from config (for the token display).
    pub chars_per_token: f64,

    /// JSONL writer (None when analytics logging is disabled).
    pub writer: Option<Mutex<JsonlWriter>>,

    /// Allowed directories (canonicalized once) for repo extraction.
    allowed_directories: Vec<PathBuf>,
    /// Log directory (Some only when logging is enabled) — used by the rollup
    /// reads and reported in the `/analytics` status.
    log_dir: Option<PathBuf>,
}

impl AnalyticsStore {
    pub fn new(cfg: &AnalyticsConfig, allowed_directories: &[String]) -> Self {
        // Canonicalize the allowed dirs once (project convention: dunce, never
        // std::fs::canonicalize). Fall back to the raw path if a dir can't be
        // canonicalized — repo naming should never fail startup.
        let allowed: Vec<PathBuf> = allowed_directories
            .iter()
            .map(|d| dunce::canonicalize(d).unwrap_or_else(|_| PathBuf::from(d)))
            .collect();

        let (writer, log_dir) = if cfg.log_dir.is_empty() {
            (None, None)
        } else {
            let dir = PathBuf::from(&cfg.log_dir);
            (Some(Mutex::new(JsonlWriter::new(dir.clone()))), Some(dir))
        };

        Self {
            per_tool: RwLock::new(HashMap::new()),
            per_repo: RwLock::new(HashMap::new()),
            presentation_bytes_session: AtomicU64::new(0),
            presentation_calls: AtomicU64::new(0),
            content_bytes_session: AtomicU64::new(0),
            chars_per_token: cfg.chars_per_token,
            writer,
            allowed_directories: allowed,
            log_dir,
        }
    }

    /// `bytes / chars_per_token`, guarded against a non-positive ratio.
    fn est_tokens(&self, bytes: u64) -> u64 {
        if self.chars_per_token <= 0.0 {
            return 0;
        }
        (bytes as f64 / self.chars_per_token) as u64
    }

    /// Extract the repo name for a path using the store's allowed dirs.
    pub fn repo_for(&self, path: &str) -> Option<String> {
        repo_from_path(path, &self.allowed_directories)
    }

    /// Record a tools/list response (presentation bytes). Pure atomics — safe to
    /// call directly from the async handler (no I/O).
    pub fn record_presentation(&self, response_bytes: usize) {
        self.presentation_bytes_session
            .fetch_add(response_bytes as u64, Ordering::Relaxed);
        self.presentation_calls.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a tools/call response: update per-tool + per-repo counters and append
    /// to the JSONL log (if enabled). The JSONL append is blocking I/O, so the
    /// caller MUST invoke this inside `block_in_place` (it is, in handler.rs).
    pub fn record_tool_call(&self, entry: ToolCallEntry) {
        self.content_bytes_session
            .fetch_add(entry.response_bytes as u64, Ordering::Relaxed);

        {
            let mut pt = self.per_tool.write().unwrap();
            let a = pt.entry(entry.tool.clone()).or_default();
            a.calls += 1;
            if entry.status == "error" {
                a.errors += 1;
            }
            a.total_bytes += entry.response_bytes as u64;
            a.total_duration_us += entry.duration_ms.saturating_mul(1000);
            a.last_called = chrono::DateTime::parse_from_rfc3339(&entry.timestamp)
                .ok()
                .map(|t| t.with_timezone(&chrono::Utc))
                .or_else(|| Some(chrono::Utc::now()));
        }

        {
            let repo_key = entry.repo.clone().unwrap_or_else(|| NO_REPO.to_string());
            let mut pr = self.per_repo.write().unwrap();
            let r = pr.entry(repo_key).or_default();
            r.calls += 1;
            r.total_bytes += entry.response_bytes as u64;
            r.tools_used.insert(entry.tool.clone());
        }

        if let Some(w) = &self.writer {
            if let Err(e) = w.lock().unwrap().write(&entry) {
                tracing::warn!("analytics JSONL write failed: {e}");
            }
        }
    }

    /// Current-session totals (since boot), used by tests and the session card.
    pub fn session_totals(&self) -> SessionTotals {
        let pt = self.per_tool.read().unwrap();
        let mut t = SessionTotals::default();
        for a in pt.values() {
            t.content_calls += a.calls;
            t.content_errors += a.errors;
            t.total_duration_us += a.total_duration_us;
        }
        // Content bytes come from the O(1) session atomic (the single source of
        // truth; it equals the sum of per_tool.total_bytes by construction).
        t.content_bytes = self.content_bytes_session.load(Ordering::Relaxed);
        t.presentation_calls = self.presentation_calls.load(Ordering::Relaxed);
        t.presentation_bytes = self.presentation_bytes_session.load(Ordering::Relaxed);
        t
    }

    fn session_period(&self) -> PeriodSummary {
        let t = self.session_totals();
        PeriodSummary {
            total_calls: t.content_calls,
            total_bytes: t.content_bytes,
            estimated_tokens: self.est_tokens(t.content_bytes),
            total_errors: t.content_errors,
            avg_duration_ms: if t.content_calls > 0 {
                (t.total_duration_us as f64 / t.content_calls as f64) / 1000.0
            } else {
                0.0
            },
            // The session period leaves latency_buckets zero — the dashboard's
            // Session window reads the cumulative /metrics histogram instead.
            latency_buckets: [0; 8],
        }
    }

    /// Per-tool summary (session), tools with calls > 0, sorted by calls desc.
    pub fn per_tool_summary(&self) -> Vec<ToolSummary> {
        let pt = self.per_tool.read().unwrap();
        let mut v: Vec<ToolSummary> = pt
            .iter()
            .filter(|(_, a)| a.calls > 0)
            .map(|(name, a)| ToolSummary {
                tool: name.clone(),
                calls: a.calls,
                total_bytes: a.total_bytes,
                estimated_tokens: self.est_tokens(a.total_bytes),
                errors: a.errors,
                avg_duration_ms: (a.total_duration_us as f64 / a.calls as f64) / 1000.0,
                last_called: a.last_called.map(|t| t.to_rfc3339()),
            })
            .collect();
        v.sort_by(|a, b| b.calls.cmp(&a.calls));
        v
    }

    /// Per-repo summary (session), sorted by calls desc.
    pub fn per_repo_summary(&self) -> Vec<RepoSummary> {
        let pr = self.per_repo.read().unwrap();
        let mut v: Vec<RepoSummary> = pr
            .iter()
            .map(|(repo, a)| RepoSummary {
                repo: repo.clone(),
                calls: a.calls,
                total_bytes: a.total_bytes,
                estimated_tokens: self.est_tokens(a.total_bytes),
                tools_used: a.tools_used.len(),
            })
            .collect();
        v.sort_by(|a, b| b.calls.cmp(&a.calls));
        v
    }

    fn presentation_summary(&self) -> PresentationSummary {
        let calls = self.presentation_calls.load(Ordering::Relaxed);
        let bytes = self.presentation_bytes_session.load(Ordering::Relaxed);
        PresentationSummary {
            calls,
            total_bytes: bytes,
            estimated_tokens: self.est_tokens(bytes),
            bytes_per_call: if calls > 0 { bytes / calls } else { 0 },
        }
    }

    /// Aggregate the full `/analytics` response. Reads JSONL files for today / last
    /// 7 / last 30 days when logging is enabled (None otherwise). Performs blocking
    /// file reads, so the caller wraps it in `spawn_blocking` (control.rs).
    pub fn aggregate(&self) -> AnalyticsResponse {
        // `today` is read from today's JSONL file ONLY (not JSONL + in-memory
        // session): every recorded call already appends to today's file, so adding
        // the session counters would double-count. Day/week/month are intentionally
        // `None` when logging is disabled (dashboard shows "N/A — enable log_dir",
        // prompt §8.3) — this resolves the §6.1/§8.3 wording tension in favor of the
        // dashboard contract and the no-double-count invariant.
        let (today, last_7, last_30) = if self.log_dir.is_some() {
            (
                Some(self.aggregate_dates(&last_n_dates(1))),
                Some(self.aggregate_dates(&last_n_dates(7))),
                Some(self.aggregate_dates(&last_n_dates(30))),
            )
        } else {
            (None, None, None)
        };
        AnalyticsResponse {
            session: self.session_period(),
            today,
            last_7_days: last_7,
            last_30_days: last_30,
            per_tool: self.per_tool_summary(),
            per_repo: self.per_repo_summary(),
            presentation: self.presentation_summary(),
            chars_per_token: self.chars_per_token,
            logging_enabled: self.log_dir.is_some(),
            log_dir: self.log_dir.as_ref().map(|p| p.display().to_string()),
        }
    }

    /// Sum the JSONL files for the given dates into one `PeriodSummary`.
    fn aggregate_dates(&self, dates: &[String]) -> PeriodSummary {
        let mut s = PeriodSummary::default();
        let dir = match &self.log_dir {
            Some(d) => d,
            None => return s,
        };
        let mut total_dur_ms: u64 = 0;
        for date in dates {
            let path = dir.join(format!("surgicalfs-analytics-{date}.jsonl"));
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            // Count every non-empty PHYSICAL line toward the cap (not just the
            // ones that parse) so a log padded with malformed lines can't make the
            // loop scan far past the limit.
            let mut scanned = 0usize;
            for line in content.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                scanned += 1;
                if scanned > MAX_LINES_PER_FILE {
                    tracing::warn!(
                        "analytics file {} exceeds {} lines; aggregation truncated",
                        path.display(),
                        MAX_LINES_PER_FILE
                    );
                    break;
                }
                if let Ok(e) = serde_json::from_str::<ToolCallEntry>(line) {
                    s.total_calls += 1;
                    s.total_bytes += e.response_bytes as u64;
                    if e.status == "error" {
                        s.total_errors += 1;
                    }
                    total_dur_ms += e.duration_ms;
                    s.latency_buckets[latency_bucket(e.duration_ms)] += 1;
                }
            }
        }
        s.estimated_tokens = self.est_tokens(s.total_bytes);
        s.avg_duration_ms = if s.total_calls > 0 {
            total_dur_ms as f64 / s.total_calls as f64
        } else {
            0.0
        };
        s
    }

    /// Raw JSONL export for `/analytics/export?range=...`. Returns the concatenated
    /// file contents for the range (empty when logging is disabled). Blocking I/O —
    /// caller wraps in `spawn_blocking`.
    pub fn export_range(&self, range: &str) -> String {
        let dir = match &self.log_dir {
            Some(d) => d.clone(),
            None => return String::new(),
        };
        if range == "all" {
            return export_all(&dir);
        }
        let dates = match range {
            "week" => last_n_dates(7),
            "month" => last_n_dates(30),
            _ => last_n_dates(1), // "today" / default
        };
        let mut out = String::new();
        for date in dates {
            let path = dir.join(format!("surgicalfs-analytics-{date}.jsonl"));
            if let Ok(c) = std::fs::read_to_string(&path) {
                out.push_str(&c);
                if !c.is_empty() && !c.ends_with('\n') {
                    out.push('\n');
                }
            }
        }
        out
    }
}

/// Concatenate every `surgicalfs-analytics-*.jsonl` file in `dir` (sorted by name
/// = chronological).
fn export_all(dir: &Path) -> String {
    let mut out = String::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        let mut files: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("surgicalfs-analytics-") && n.ends_with(".jsonl"))
                    .unwrap_or(false)
            })
            .collect();
        files.sort();
        for p in files {
            if let Ok(c) = std::fs::read_to_string(&p) {
                out.push_str(&c);
                if !c.is_empty() && !c.ends_with('\n') {
                    out.push('\n');
                }
            }
        }
    }
    out
}

/// The last `n` calendar dates (UTC), most recent first, as `YYYY-MM-DD`.
fn last_n_dates(n: i64) -> Vec<String> {
    let today = chrono::Utc::now().date_naive();
    (0..n)
        .map(|i| {
            (today - chrono::Duration::days(i))
                .format("%Y-%m-%d")
                .to_string()
        })
        .collect()
}

/// Delete analytics files older than `retention_days` (0 = unlimited). Uses the
/// date embedded in the filename — no `stat`. Best-effort; errors are ignored.
pub fn cleanup_old_analytics_files(dir: &Path, retention_days: u32) {
    if retention_days == 0 {
        return;
    }
    let cutoff = chrono::Utc::now().date_naive() - chrono::Duration::days(retention_days as i64);
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(date_str) = name
            .strip_prefix("surgicalfs-analytics-")
            .and_then(|s| s.strip_suffix(".jsonl"))
        {
            if let Ok(date) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
                if date < cutoff {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }
}

/// Extract the repo name from a full file path: find which allowed-directory
/// prefix matches (case-insensitively on Windows, by path component), then take
/// the first component after the prefix. Purely lexical — no filesystem access —
/// so it works on not-yet-existing/synthetic paths and adds no hot-path I/O.
/// Handles both `\` and `/` separators. Returns None if no allowed dir is a
/// proper prefix (or the path IS the allowed dir, with no component after).
pub fn repo_from_path(path: &str, allowed_dirs: &[PathBuf]) -> Option<String> {
    let path_comps = split_components(path);
    for dir in allowed_dirs {
        let dir_str = dir.to_string_lossy();
        let dir_comps = split_components(&dir_str);
        if dir_comps.is_empty() || path_comps.len() <= dir_comps.len() {
            continue;
        }
        let matches = dir_comps.iter().zip(path_comps.iter()).all(|(d, p)| {
            if cfg!(windows) {
                d.eq_ignore_ascii_case(p)
            } else {
                d == p
            }
        });
        if matches {
            return Some(path_comps[dir_comps.len()].to_string());
        }
    }
    None
}

/// Split a path into non-empty components on either separator.
fn split_components(p: &str) -> Vec<&str> {
    p.split(['\\', '/']).filter(|s| !s.is_empty()).collect()
}

/// Bucket a duration (ms) into the 8 latency ranges. Kept BYTE-FOR-BYTE in sync
/// with `metrics::MetricsRegistry::record_call` (which buckets the live histogram);
/// metrics.rs is out of scope for this change, so the match is duplicated here by
/// design (Phase 3.5 §1.2). The boundary test pins the equivalence.
fn latency_bucket(ms: u64) -> usize {
    match ms {
        0 => 0,
        1..=9 => 1,
        10..=49 => 2,
        50..=99 => 3,
        100..=499 => 4,
        500..=999 => 5,
        1000..=4999 => 6,
        _ => 7,
    }
}

// ─── Output shapes (serialized by /analytics) ─────────────────────────────────

#[derive(Default)]
pub struct SessionTotals {
    pub content_calls: u64,
    pub content_bytes: u64,
    pub content_errors: u64,
    pub total_duration_us: u64,
    pub presentation_calls: u64,
    pub presentation_bytes: u64,
}

/// Serialize the 8-element latency histogram as a NAMED object matching the
/// `/metrics` key names, so the dashboard can use one set of constants for both
/// `/metrics` and `/analytics` (Phase 3.5).
fn serialize_latency_buckets<S>(buckets: &[u64; 8], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeMap;
    const KEYS: [&str; 8] = [
        "lt_1ms", "lt_10ms", "lt_50ms", "lt_100ms", "lt_500ms", "lt_1s", "lt_5s", "gte_5s",
    ];
    let mut m = s.serialize_map(Some(8))?;
    for (k, v) in KEYS.iter().zip(buckets.iter()) {
        m.serialize_entry(k, v)?;
    }
    m.end()
}

#[derive(Default, serde::Serialize)]
pub struct PeriodSummary {
    pub total_calls: u64,
    pub total_bytes: u64,
    pub estimated_tokens: u64,
    pub total_errors: u64,
    pub avg_duration_ms: f64,
    /// Per-range call counts (Phase 3.5), same 8 ranges as `MetricsRegistry`.
    /// Populated for the JSONL-derived periods (today/7d/30d); the in-memory
    /// session period leaves it zero (the dashboard's Session window reads the
    /// cumulative `/metrics` histogram instead).
    #[serde(serialize_with = "serialize_latency_buckets")]
    pub latency_buckets: [u64; 8],
}

#[derive(serde::Serialize)]
pub struct ToolSummary {
    pub tool: String,
    pub calls: u64,
    pub total_bytes: u64,
    pub estimated_tokens: u64,
    pub errors: u64,
    pub avg_duration_ms: f64,
    pub last_called: Option<String>,
}

#[derive(serde::Serialize)]
pub struct RepoSummary {
    pub repo: String,
    pub calls: u64,
    pub total_bytes: u64,
    pub estimated_tokens: u64,
    pub tools_used: usize,
}

#[derive(serde::Serialize)]
pub struct PresentationSummary {
    pub calls: u64,
    pub total_bytes: u64,
    pub estimated_tokens: u64,
    pub bytes_per_call: u64,
}

#[derive(serde::Serialize)]
pub struct AnalyticsResponse {
    pub session: PeriodSummary,
    pub today: Option<PeriodSummary>,
    pub last_7_days: Option<PeriodSummary>,
    pub last_30_days: Option<PeriodSummary>,
    pub per_tool: Vec<ToolSummary>,
    pub per_repo: Vec<RepoSummary>,
    pub presentation: PresentationSummary,
    pub chars_per_token: f64,
    pub logging_enabled: bool,
    pub log_dir: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_no_log() -> AnalyticsStore {
        AnalyticsStore::new(&AnalyticsConfig::default(), &[])
    }

    fn entry(tool: &str, bytes: usize, status: &str, repo: Option<&str>) -> ToolCallEntry {
        ToolCallEntry::new(tool, 5, bytes, status, None, repo.map(|s| s.to_string()))
    }

    // ── repo_from_path ──

    #[test]
    fn repo_from_path_extracts_first_component() {
        let dirs = vec![PathBuf::from("C:\\Users\\example\\projects")];
        let repo = repo_from_path(
            "C:\\Users\\example\\projects\\surgicalfs-mcp\\src\\server.rs",
            &dirs,
        );
        assert_eq!(repo.as_deref(), Some("surgicalfs-mcp"));
        // Forward slashes and case differences also resolve (Windows).
        if cfg!(windows) {
            let repo2 = repo_from_path("c:/users/example/projects/other-repo/x.txt", &dirs);
            assert_eq!(repo2.as_deref(), Some("other-repo"));
        }
    }

    #[test]
    fn repo_from_path_returns_none_for_unmatched() {
        let dirs = vec![PathBuf::from("C:\\Users\\example\\projects")];
        assert_eq!(repo_from_path("D:\\other\\file.txt", &dirs), None);
    }

    #[test]
    fn repo_from_path_returns_none_for_root() {
        let dirs = vec![PathBuf::from("C:\\Users\\example\\projects")];
        // The path IS the allowed dir — no component after the prefix.
        assert_eq!(repo_from_path("C:\\Users\\example\\projects", &dirs), None);
        // Trailing separator must not change that.
        assert_eq!(repo_from_path("C:\\Users\\example\\projects\\", &dirs), None);
    }

    // ── counters ──

    #[test]
    fn record_tool_call_increments_counters() {
        let s = store_no_log();
        for _ in 0..3 {
            s.record_tool_call(entry("file_info", 100, "ok", None));
        }
        let pt = s.per_tool.read().unwrap();
        let a = pt.get("file_info").unwrap();
        assert_eq!(a.calls, 3);
        assert_eq!(a.total_bytes, 300);
        assert_eq!(a.errors, 0);
        assert!(a.last_called.is_some());
    }

    #[test]
    fn record_presentation_accumulates_bytes() {
        let s = store_no_log();
        s.record_presentation(1000);
        s.record_presentation(500);
        assert_eq!(s.presentation_bytes_session.load(Ordering::Relaxed), 1500);
        assert_eq!(s.presentation_calls.load(Ordering::Relaxed), 2);
        let p = s.presentation_summary();
        assert_eq!(p.calls, 2);
        assert_eq!(p.total_bytes, 1500);
        assert_eq!(p.bytes_per_call, 750);
    }

    #[test]
    fn session_totals_reflect_all_recordings() {
        let s = store_no_log();
        s.record_presentation(2000);
        s.record_tool_call(entry("file_info", 100, "ok", Some("repoA")));
        s.record_tool_call(entry("file_search", 250, "error", Some("repoA")));
        let t = s.session_totals();
        assert_eq!(t.content_calls, 2);
        assert_eq!(t.content_bytes, 350);
        assert_eq!(t.content_errors, 1);
        assert_eq!(t.presentation_calls, 1);
        assert_eq!(t.presentation_bytes, 2000);
        // Per-repo aggregation: one repo, two distinct tools.
        let repos = s.per_repo_summary();
        assert_eq!(repos.len(), 1);
        assert_eq!(repos[0].repo, "repoA");
        assert_eq!(repos[0].calls, 2);
        assert_eq!(repos[0].tools_used, 2);
        // Per-tool summary lists both, sorted by calls (tie → either order).
        assert_eq!(s.per_tool_summary().len(), 2);
    }

    // ── JSONL writer ──

    fn unique_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sfs-analytics-{tag}-{}-{}",
            std::process::id(),
            crate::state::generate_ctl_token().get(..8).unwrap_or("x")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn jsonl_writer_creates_daily_file() {
        let dir = unique_dir("create");
        let mut w = JsonlWriter::new(dir.clone());
        let mut e = entry("file_info", 42, "ok", None);
        e.timestamp = "2026-06-14T10:00:00Z".to_string();
        w.write(&e).unwrap();
        let path = dir.join("surgicalfs-analytics-2026-06-14.jsonl");
        assert!(path.exists(), "daily file not created");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"tool\":\"file_info\""), "got: {content}");
        assert!(content.ends_with('\n'));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn jsonl_writer_rotates_on_date_change() {
        let dir = unique_dir("rotate");
        let mut w = JsonlWriter::new(dir.clone());
        let mut e1 = entry("file_info", 1, "ok", None);
        e1.timestamp = "2026-06-14T23:59:00Z".to_string();
        w.write(&e1).unwrap();
        let mut e2 = entry("file_head", 1, "ok", None);
        e2.timestamp = "2026-06-15T00:01:00Z".to_string();
        w.write(&e2).unwrap();
        assert!(dir.join("surgicalfs-analytics-2026-06-14.jsonl").exists());
        assert!(dir.join("surgicalfs-analytics-2026-06-15.jsonl").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn aggregate_reads_jsonl_when_enabled() {
        let dir = unique_dir("agg");
        let cfg = AnalyticsConfig {
            log_dir: dir.to_string_lossy().to_string(),
            ..AnalyticsConfig::default()
        };
        let s = AnalyticsStore::new(&cfg, &[]);
        // Two recordings today → written to today's file.
        s.record_tool_call(entry("file_info", 100, "ok", None));
        s.record_tool_call(entry("file_info", 100, "error", None));
        let resp = s.aggregate();
        assert!(resp.logging_enabled);
        let today = resp
            .today
            .expect("today should be Some when logging enabled");
        assert_eq!(today.total_calls, 2);
        assert_eq!(today.total_bytes, 200);
        assert_eq!(today.total_errors, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Latency histogram (Phase 3.5) ──

    #[test]
    fn latency_bucket_boundaries_match_metrics() {
        // Exactly mirrors MetricsRegistry::record_call's bucketing.
        assert_eq!(latency_bucket(0), 0);
        assert_eq!(latency_bucket(1), 1);
        assert_eq!(latency_bucket(9), 1);
        assert_eq!(latency_bucket(10), 2);
        assert_eq!(latency_bucket(49), 2);
        assert_eq!(latency_bucket(50), 3);
        assert_eq!(latency_bucket(99), 3);
        assert_eq!(latency_bucket(100), 4);
        assert_eq!(latency_bucket(499), 4);
        assert_eq!(latency_bucket(500), 5);
        assert_eq!(latency_bucket(999), 5);
        assert_eq!(latency_bucket(1000), 6);
        assert_eq!(latency_bucket(4999), 6);
        assert_eq!(latency_bucket(5000), 7);
    }

    #[test]
    fn aggregate_includes_latency_buckets() {
        let dir = unique_dir("latbuckets");
        let cfg = AnalyticsConfig {
            log_dir: dir.to_string_lossy().to_string(),
            ..AnalyticsConfig::default()
        };
        let s = AnalyticsStore::new(&cfg, &[]);
        // Three calls landing in buckets 0 (0ms), 2 (25ms), 7 (7000ms).
        s.record_tool_call(ToolCallEntry::new("file_info", 0, 10, "ok", None, None));
        s.record_tool_call(ToolCallEntry::new("file_info", 25, 10, "ok", None, None));
        s.record_tool_call(ToolCallEntry::new("file_info", 7000, 10, "ok", None, None));
        let today = s.aggregate().today.expect("today present when enabled");
        assert_eq!(today.total_calls, 3);
        assert_eq!(today.latency_buckets[0], 1);
        assert_eq!(today.latency_buckets[2], 1);
        assert_eq!(today.latency_buckets[7], 1);
        // The untouched buckets stay zero.
        assert_eq!(today.latency_buckets[1], 0);
        assert_eq!(today.latency_buckets.iter().sum::<u64>(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
