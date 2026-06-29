//! Process lifecycle: how and when this stdio server decides to shut down.
//!
//! A stdio MCP server is normally reaped by its client closing stdin (EOF),
//! which makes [`rmcp`]'s transport finish and `service.waiting()` return. That
//! is the deterministic, preferred shutdown path and it works for well-behaved
//! supervisors (Claude Desktop, IDEs, the MCP Inspector).
//!
//! The remote deployment is different. There, the server runs behind
//! `supergateway` in stateless `streamableHttp` mode, which spawns a *fresh*
//! child per HTTP request via `spawn(cmd, { shell: true })` and then fails to
//! reap it on Windows for two independent reasons:
//!
//!   1. The gateway's only teardown hook is `transport.onclose -> child.kill()`,
//!      but in stateless mode the MCP SDK's response path closes the HTTP stream
//!      without ever invoking `onclose`, so `child.kill()` is never called.
//!   2. `shell: true` interposes a `cmd.exe` wrapper, so even when a kill *does*
//!      fire it terminates the wrapper, not this `.exe` grandchild.
//!
//! Crucially, the gateway also never closes the child's stdin, and the
//! long-lived Node parent keeps the write-end of that pipe open for the child's
//! entire life — so **stdin EOF never arrives while the parent is alive.** The
//! children pile up until Node exhausts its own handle table and the endpoint
//! goes dark. (Killing `cmd.exe` would not deliver EOF either: the *parent*, not
//! `cmd.exe`, owns the write-end.)
//!
//! Because no deterministic abandonment signal exists under that supervisor,
//! the server must own its own lifecycle. This module centralizes every way the
//! process can decide to exit, so the policy lives in one documented place
//! rather than as scattered ad-hoc checks.
//!
//! ## Exit triggers (see `tokio::select!` in `main`)
//!
//! | Trigger                | Source                          | When it fires |
//! |------------------------|---------------------------------|---------------|
//! | MCP session ended      | `service.waiting()`             | client closed the protocol / stdin EOF |
//! | Ctrl+C                 | `tokio::signal::ctrl_c`         | interactive interrupt |
//! | stdin pipe broken      | [`stdin_pipe_broken`]           | the *parent* process (e.g. Node) exited |
//! | idle self-reap         | [`idle_watchdog`]               | no tool activity for `idle_timeout_secs` (orphan reaper; off by default) |
//!
//! The idle self-reap is the only one that fires while an *alive-but-negligent*
//! supervisor holds the stdin pipe open. It is opt-in (`idle_timeout_secs > 0`)
//! so that local stdio clients — where an idle pause is normal and stdin EOF is
//! the real shutdown signal — are never killed mid-session. See the `[runtime]`
//! config section and `--idle-timeout-secs`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How often the idle watchdog re-checks activity. The effective idle timeout
/// therefore has up to this much extra latency, which is fine for orphan reaping.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Shared record of "is this server doing anything, and when did it last?".
///
/// One instance is held by the server (which stamps it on every request) and
/// cloned to the idle watchdog (which reads it). It tracks both the last
/// activity time *and* the number of in-flight requests, so the watchdog never
/// reaps a process that is mid-response under concurrent load.
#[derive(Debug)]
pub struct ActivityTracker {
    last_activity: Mutex<Instant>,
    in_flight: AtomicUsize,
}

impl ActivityTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            last_activity: Mutex::new(Instant::now()),
            in_flight: AtomicUsize::new(0),
        })
    }

    /// Record that something just happened (request arrived or completed).
    pub fn touch(&self) {
        if let Ok(mut t) = self.last_activity.lock() {
            *t = Instant::now();
        }
    }

    /// How long since the last recorded activity.
    pub fn idle_for(&self) -> Duration {
        self.last_activity
            .lock()
            .map(|t| t.elapsed())
            .unwrap_or_default()
    }

    /// Whether any request is currently being handled.
    pub fn is_busy(&self) -> bool {
        self.in_flight.load(Ordering::SeqCst) > 0
    }

    /// Mark a request as in-flight for the lifetime of the returned guard.
    /// Stamps activity on both entry and exit (drop), so the idle clock is
    /// measured from when the response finished, not when the request arrived.
    pub fn in_flight_guard(self: &Arc<Self>) -> InFlightGuard {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        self.touch();
        InFlightGuard(self.clone())
    }
}

/// RAII guard that keeps a request counted as in-flight until dropped, then
/// stamps activity. Using a guard (rather than manual enter/leave) keeps the
/// count correct across early returns, `?`, and panics in the handler.
#[derive(Debug)]
pub struct InFlightGuard(Arc<ActivityTracker>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
        self.0.touch();
    }
}

/// Pure decision function: should the process self-exit right now?
///
/// Exits only when the server is idle (no in-flight requests) *and* the idle
/// duration has reached the timeout. Factored out so the policy is unit-tested
/// without spawning real timers or processes.
pub fn should_self_exit(idle_for: Duration, busy: bool, timeout: Duration) -> bool {
    !busy && idle_for >= timeout
}

/// Resolve once the server has been idle (no activity, no in-flight requests)
/// for `timeout_secs`. The caller wires this into `select!` so its completion
/// triggers a clean shutdown. Only meaningful when `timeout_secs > 0`.
pub async fn idle_watchdog(activity: Arc<ActivityTracker>, timeout_secs: u64) {
    let timeout = Duration::from_secs(timeout_secs);
    let poll = POLL_INTERVAL.min(timeout);
    loop {
        tokio::time::sleep(poll).await;
        if should_self_exit(activity.idle_for(), activity.is_busy(), timeout) {
            return;
        }
    }
}

/// Resolve when the stdin pipe's writer (the parent process) has gone away.
///
/// On Windows this uses `PeekNamedPipe` with a zero-byte buffer to check the
/// pipe handle's health *without* reading, so it never competes with rmcp's
/// stdin reader. It returns once the pipe is broken — i.e. when the parent that
/// owns the write-end (e.g. the Node `supergateway` process) exits. Note this
/// does **not** fire while that parent stays alive (it holds the write-end
/// open), which is exactly why [`idle_watchdog`] is needed for orphan reaping.
///
/// On Unix this is a no-op: rmcp's stdio transport detects EOF via poll/epoll,
/// so `service.waiting()` already returns on parent exit.
pub async fn stdin_pipe_broken() {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        tokio::task::spawn_blocking(|| {
            let stdin = std::io::stdin();
            let handle = stdin.as_raw_handle();
            loop {
                // Zero-byte PeekNamedPipe: checks pipe state without consuming.
                // Returns FALSE (0) when the pipe is broken (ERROR_BROKEN_PIPE).
                let ok = unsafe {
                    PeekNamedPipe(
                        handle,
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                };
                if ok == 0 {
                    break;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
        })
        .await
        .ok();
    }

    #[cfg(not(windows))]
    {
        std::future::pending::<()>().await;
    }
}

// ─── Self-maintenance: orphaned temp-file sweep (Stage 5, DOC-002 §7.4) ────────

/// Minimum age before an orphaned temp file is reaped. `atomic_write`
/// (`tools::atomic_write`) writes then renames within milliseconds, so anything
/// older than this is a genuine orphan from a hard kill — never an in-flight
/// write. This is what keeps the sweep from racing an active tool call
/// (STOP §9.3) even in the brief unlocked window between write-close and rename.
const TMP_SWEEP_MIN_AGE: Duration = Duration::from_secs(60);

/// Sweep orphaned `.surgicalfs-tmp` files from the allowed directories. These are
/// left behind only when the process is hard-killed between `atomic_write`'s
/// write and rename. Best-effort: missing/inaccessible dirs and locked files are
/// logged and skipped, never fatal. Spawned on a timer from `run_http()`.
pub fn sweep_tmp_files(allowed_dirs: &[String]) {
    for dir in allowed_dirs {
        let dir_path = std::path::Path::new(dir);
        if !dir_path.exists() {
            continue;
        }
        match sweep_dir(dir_path, TMP_SWEEP_MIN_AGE) {
            Ok(count) if count > 0 => {
                tracing::info!("Swept {count} orphaned .surgicalfs-tmp file(s) from {dir}");
            }
            Ok(_) => {} // nothing to sweep
            Err(e) => {
                tracing::warn!("Failed to sweep {dir}: {e}");
            }
        }
    }
}

/// Remove `.surgicalfs-tmp` files under `dir` older than `min_age`. Returns the
/// count removed. `min_age` is a parameter (not the const) so tests can sweep
/// freshly-created files with `Duration::ZERO`.
fn sweep_dir(dir: &std::path::Path, min_age: Duration) -> std::io::Result<usize> {
    let mut count = 0;
    for entry in walkdir::WalkDir::new(dir)
        .max_depth(10)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("surgicalfs-tmp") {
            continue;
        }
        // Skip anything younger than `min_age` (an in-flight atomic write) and
        // anything we cannot stat — better to leave a file than reap an active one.
        let too_recent = match path.metadata().and_then(|m| m.modified()) {
            Ok(mtime) => mtime.elapsed().map(|age| age < min_age).unwrap_or(true),
            Err(_) => true,
        };
        if too_recent {
            continue;
        }
        match std::fs::remove_file(path) {
            Ok(()) => count += 1,
            // A locked file (active write on Windows) or a permission error is
            // skipped, not fatal — it will be swept on a later pass.
            Err(e) => tracing::warn!("Could not remove {}: {e}", path.display()),
        }
    }
    Ok(count)
}

/// Delete rolling tracing-log files (`surgicalfs.log.YYYY-MM-DD`) older than
/// `retention_days` (Phase 3). 0 = unlimited (skip). Uses the date embedded in the
/// filename — no `stat`. Best-effort; errors are ignored. Mirrors
/// `analytics::cleanup_old_analytics_files`. Called on startup and from the
/// 5-minute maintenance timer in `run_http`.
pub fn cleanup_old_log_files(log_dir: &str, retention_days: u32) {
    if log_dir.is_empty() || retention_days == 0 {
        return;
    }
    let cutoff = chrono::Utc::now().date_naive() - chrono::Duration::days(retention_days as i64);
    let rd = match std::fs::read_dir(std::path::Path::new(log_dir)) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(date_str) = name.strip_prefix("surgicalfs.log.") {
            if let Ok(date) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
                if date < cutoff {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }
}

#[cfg(windows)]
extern "system" {
    /// Win32 `PeekNamedPipe` — checks pipe state without consuming data.
    /// <https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-peeknamedpipe>
    fn PeekNamedPipe(
        h_named_pipe: *mut std::ffi::c_void,
        lp_buffer: *mut std::ffi::c_void,
        n_buffer_size: u32,
        lp_bytes_read: *mut u32,
        lp_total_bytes_avail: *mut u32,
        lp_bytes_left_this_message: *mut u32,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exits_after_idle_past_timeout() {
        assert!(should_self_exit(
            Duration::from_secs(31),
            false,
            Duration::from_secs(30)
        ));
    }

    #[test]
    fn boundary_is_inclusive() {
        assert!(should_self_exit(
            Duration::from_secs(30),
            false,
            Duration::from_secs(30)
        ));
    }

    #[test]
    fn stays_while_fresh() {
        assert!(!should_self_exit(
            Duration::from_secs(5),
            false,
            Duration::from_secs(30)
        ));
    }

    #[test]
    fn never_exits_while_busy() {
        // Even long past the timeout, an in-flight request blocks self-exit.
        assert!(!should_self_exit(
            Duration::from_secs(3600),
            true,
            Duration::from_secs(30)
        ));
    }

    #[test]
    fn tracker_reports_busy_only_during_guard() {
        let t = ActivityTracker::new();
        assert!(!t.is_busy());
        {
            let _g = t.in_flight_guard();
            assert!(t.is_busy());
            // A nested request (concurrent call) keeps it busy until both finish.
            let _g2 = t.in_flight_guard();
            assert!(t.is_busy());
        }
        assert!(!t.is_busy());
    }

    #[test]
    fn guard_stamps_activity_on_drop() {
        let t = ActivityTracker::new();
        std::thread::sleep(Duration::from_millis(20));
        // Idle has accumulated since construction...
        assert!(t.idle_for() >= Duration::from_millis(20));
        {
            let _g = t.in_flight_guard(); // stamps on enter
        } // stamps on drop
          // ...and is reset to ~0 right after the guard drops.
        assert!(t.idle_for() < Duration::from_millis(20));
    }

    // ── Orphaned temp-file sweep (Stage 5) ──

    fn unique_sweep_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sfs-sweep-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn sweep_removes_old_tmp_files() {
        let dir = unique_sweep_dir("old");
        let tmp = dir.join("report.md.surgicalfs-tmp");
        std::fs::write(&tmp, b"orphan").unwrap();
        // min_age 0 → treat as old, so the freshly-created file is reaped.
        let removed = sweep_dir(&dir, Duration::ZERO).unwrap();
        assert_eq!(removed, 1);
        assert!(!tmp.exists(), "orphaned temp file should be removed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_skips_recent_tmp_files() {
        let dir = unique_sweep_dir("recent");
        let tmp = dir.join("inflight.txt.surgicalfs-tmp");
        std::fs::write(&tmp, b"in-flight").unwrap();
        // A large min_age means a just-created file is "too recent" → preserved,
        // so the sweep can never race an active atomic write.
        let removed = sweep_dir(&dir, Duration::from_secs(3600)).unwrap();
        assert_eq!(removed, 0);
        assert!(tmp.exists(), "an in-flight temp file must be preserved");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_ignores_non_tmp_files() {
        let dir = unique_sweep_dir("real");
        let real = dir.join("keep.txt");
        std::fs::write(&real, b"real content").unwrap();
        let removed = sweep_dir(&dir, Duration::ZERO).unwrap();
        assert_eq!(removed, 0);
        assert!(real.exists(), "non-temp files must never be touched");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_tmp_files_tolerates_missing_dir() {
        // A non-existent allowed dir must not panic or error.
        let missing = std::env::temp_dir().join("sfs-sweep-does-not-exist-xyz");
        let _ = std::fs::remove_dir_all(&missing);
        sweep_tmp_files(&[missing.to_string_lossy().to_string()]);
    }
}
