//! Process- and request-level metrics for the HTTP control plane (DOC-002 §6.1).
//!
//! `MetricsRegistry` holds lock-free atomic counters plus a latency histogram,
//! updated on every `call_tool` (see `server::SurgicalFsServer::call_tool`).
//! `ProcessSnapshot` is refreshed every 10s by [`process_metrics_sampler`] in
//! HTTP mode. The counters are *written* in Stage 2; the Stage 3 control plane
//! (`/metrics`, `/health`) reads them — hence the `allow(dead_code)` on the
//! fields that have no reader yet.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Lock-free request counters + a fixed-bucket latency histogram (DOC-002 §6.1).
pub struct MetricsRegistry {
    pub requests_total: AtomicU64,
    pub requests_errors: AtomicU64,
    pub latency_sum_us: AtomicU64,
    pub latency_buckets: [AtomicU64; 8],
    /// Session count — incremented by the Stage 4 session registry.
    /// `allow(dead_code)`: declared now so the registry shape is stable.
    #[allow(dead_code)]
    pub sessions_total: AtomicU64,
    pub process_snapshot: RwLock<ProcessSnapshot>,
}

/// Latest sampled process metrics. Written by [`process_metrics_sampler`]; read
/// by the control plane (`/health`, `/metrics`) and bridged onto the SSE bus as
/// an `ActivityEvent::Health`.
pub struct ProcessSnapshot {
    pub rss_bytes: u64,
    pub handle_count: u32,
    pub sampled_at: Instant,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            requests_errors: AtomicU64::new(0),
            latency_sum_us: AtomicU64::new(0),
            latency_buckets: Default::default(),
            sessions_total: AtomicU64::new(0),
            process_snapshot: RwLock::new(ProcessSnapshot {
                rss_bytes: 0,
                handle_count: 0,
                sampled_at: Instant::now(),
            }),
        }
    }

    /// Record one completed tool call: bump totals, the error counter (on
    /// failure), the latency sum, and the matching latency bucket. Every update
    /// is `Relaxed` — these are independent counters with no inter-counter
    /// ordering requirement.
    pub fn record_call(&self, duration: Duration, success: bool) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.requests_errors.fetch_add(1, Ordering::Relaxed);
        }
        let us = duration.as_micros() as u64;
        self.latency_sum_us.fetch_add(us, Ordering::Relaxed);
        let bucket = match duration.as_millis() {
            0 => 0,           // <1ms
            1..=9 => 1,       // <10ms
            10..=49 => 2,     // <50ms
            50..=99 => 3,     // <100ms
            100..=499 => 4,   // <500ms
            500..=999 => 5,   // <1s
            1000..=4999 => 6, // <5s
            _ => 7,           // >=5s
        };
        self.latency_buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Periodically refresh [`ProcessSnapshot`] (RSS + OS handle count). HTTP mode
/// only — spawned from `run_http`. Samples every 10s; the first sample lands
/// ~10s after startup.
pub async fn process_metrics_sampler(shared: std::sync::Arc<crate::shared::SharedState>) {
    use sysinfo::{Pid, ProcessesToUpdate, System};
    let mut sys = System::new();
    let pid = Pid::from(std::process::id() as usize);
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        // Refresh only this process; do not prune dead processes from the map.
        sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), false);
        let rss = sys.process(pid).map(|p| p.memory()).unwrap_or(0);
        let handles = get_handle_count();
        *shared.metrics.process_snapshot.write().unwrap() = ProcessSnapshot {
            rss_bytes: rss,
            handle_count: handles,
            sampled_at: Instant::now(),
        };

        // Bridge each sample onto the SSE event bus when the dashboard is
        // watching (the "sampler→bus bridge", DEC-DRAFT-H). Skipped with no
        // subscriber so we don't push events nobody reads. `in_flight` is the
        // configured concurrency ceiling minus the permits still available.
        if shared.event_bus.receiver_count() > 0 {
            let max = shared.config_snapshot.max_concurrent_requests;
            let in_flight = max.saturating_sub(shared.concurrency.available_permits()) as u32;
            let _ = shared.event_bus.send(crate::shared::ActivityEvent::Health {
                rss_bytes: rss,
                handle_count: handles,
                in_flight,
            });
        }
    }
}

/// Current process's open-handle count via Win32 `GetProcessHandleCount`.
/// Mirrors the FFI style in `crate::lifecycle` (`PeekNamedPipe`). Uses the
/// `GetCurrentProcess` pseudo-handle, which must NOT be closed (no leak).
#[cfg(windows)]
fn get_handle_count() -> u32 {
    extern "system" {
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
        fn GetProcessHandleCount(
            h_process: *mut std::ffi::c_void,
            lpdw_handle_count: *mut u32,
        ) -> i32;
    }
    let mut count: u32 = 0;
    unsafe {
        let handle = GetCurrentProcess();
        if GetProcessHandleCount(handle, &mut count) != 0 {
            count
        } else {
            0
        }
    }
}

#[cfg(not(windows))]
fn get_handle_count() -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_initializes_counters_to_zero() {
        let m = MetricsRegistry::new();
        assert_eq!(m.requests_total.load(Ordering::Relaxed), 0);
        assert_eq!(m.requests_errors.load(Ordering::Relaxed), 0);
        assert_eq!(m.latency_sum_us.load(Ordering::Relaxed), 0);
        assert_eq!(m.sessions_total.load(Ordering::Relaxed), 0);
        for b in &m.latency_buckets {
            assert_eq!(b.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn record_call_increments_totals_and_bucket() {
        let m = MetricsRegistry::new();
        m.record_call(Duration::from_millis(0), true); // bucket 0
        m.record_call(Duration::from_millis(25), true); // bucket 2
        m.record_call(Duration::from_secs(7), true); // bucket 7
        assert_eq!(m.requests_total.load(Ordering::Relaxed), 3);
        assert_eq!(m.requests_errors.load(Ordering::Relaxed), 0);
        assert_eq!(m.latency_buckets[0].load(Ordering::Relaxed), 1);
        assert_eq!(m.latency_buckets[2].load(Ordering::Relaxed), 1);
        assert_eq!(m.latency_buckets[7].load(Ordering::Relaxed), 1);
    }

    #[test]
    fn record_call_error_increments_error_counter() {
        let m = MetricsRegistry::new();
        m.record_call(Duration::from_millis(5), false);
        assert_eq!(m.requests_total.load(Ordering::Relaxed), 1);
        assert_eq!(m.requests_errors.load(Ordering::Relaxed), 1);
        assert_eq!(m.latency_buckets[1].load(Ordering::Relaxed), 1);
    }

    #[test]
    fn process_snapshot_write_read_round_trip() {
        let m = MetricsRegistry::new();
        {
            let mut snap = m.process_snapshot.write().unwrap();
            snap.rss_bytes = 12_345;
            snap.handle_count = 42;
        }
        let snap = m.process_snapshot.read().unwrap();
        assert_eq!(snap.rss_bytes, 12_345);
        assert_eq!(snap.handle_count, 42);
    }
}
