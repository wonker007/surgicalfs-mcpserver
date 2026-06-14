//! Shared, process-wide server state (DEC-DRAFT-L). One `Arc<SharedState>` is
//! built at startup and held by the server — and, in HTTP mode, by the metrics
//! sampler. It centralizes the live tool set, the activity tracker, metrics, the
//! concurrency limiter, the event bus, and a frozen config snapshot, so the data
//! plane (`call_tool`) and the Stage 3 control plane read a single source.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::sync::{broadcast, Mutex, Semaphore};

use crate::config::Config;
use crate::lifecycle::ActivityTracker;
use crate::metrics::MetricsRegistry;
use crate::search_backend::SearchBackend;

pub struct SharedState {
    /// Mutable tool set — `RwLock` for live toggling (Stage 4). The read lock is
    /// held only briefly in `list_tools`/`call_tool` (`HashSet::contains` is O(1)).
    pub enabled_tools: RwLock<HashSet<String>>,

    /// Immutable after startup. Read-only always wins over toggles: write tools
    /// are stripped at construction AND re-stripped by the Stage 4 toggle API
    /// (`POST /admin/tools`), which reads this flag to stay authoritative.
    pub read_only: bool,

    /// Shared activity tracker — `call_tool`'s in-flight guard and `list_tools`'s
    /// touch, plus the idle watchdog in stdio mode.
    pub activity: Arc<ActivityTracker>,

    /// Lock-free counters and latency histogram.
    pub metrics: MetricsRegistry,

    /// SSE event source. Subscribers are added in Stage 3; until then `send`
    /// returns `Err(NoSubscribers)` and the event is dropped (intended).
    pub event_bus: broadcast::Sender<ActivityEvent>,

    /// Concurrency limiter. `try_acquire` in `call_tool` rejects at capacity.
    pub concurrency: Semaphore,

    /// Frozen config subset for the control plane (`/health`, `/ready`,
    /// `/metrics`). Read by `control.rs`.
    pub config_snapshot: ConfigSnapshot,

    /// Search backend — detected once at startup, shared by every server clone.
    pub search_backend: Arc<SearchBackend>,

    /// Sidecar state-file path for tool-toggle persistence (Stage 4, DEC-DRAFT-C).
    /// Derived from the config source path; `None` when that is unknown (stdio /
    /// directory-argument mode), in which case toggles are ephemeral.
    pub state_file_path: Option<PathBuf>,

    /// Serializes `POST /admin/tools` (Stage 4 review fix): held across the
    /// in-memory commit AND the sidecar file write so two concurrent toggles can't
    /// collide on the temp file or invert the persisted-vs-live order.
    pub sidecar_lock: Mutex<()>,
}

impl SharedState {
    /// Build the shared state. `source_path` is the filesystem path the config was
    /// loaded from (for the control plane's `/ready` `config_source`); `None` in
    /// stdio/legacy/directory-argument paths where it is unknown or irrelevant.
    pub fn new(config: &Config, source_path: Option<PathBuf>) -> Self {
        // Tool-set construction (incl. read-only stripping) lives here so the
        // server's `new()`/`new_with_shared()` stay thin and both transports
        // build the same set.
        let mut enabled_tools = crate::config::enabled_tool_names(&config.tools);

        // Sidecar path derived from the config source path (Stage 4).
        let state_file_path = source_path
            .as_ref()
            .map(|p| crate::state::sidecar_path(Some(p.as_path())));

        // Overlay the sidecar (runtime state) over the TOML defaults if present
        // (DEC-DRAFT-C: TOML = boot default, sidecar = runtime overlay). A corrupt
        // sidecar is logged and ignored — never abort startup. Deliberate reset is
        // "delete the sidecar".
        if let Some(ref sfp) = state_file_path {
            match crate::state::read_sidecar(sfp) {
                Ok(Some(sidecar_tools)) => {
                    if sidecar_tools.is_empty() {
                        tracing::warn!(
                            "Sidecar at {} enables ZERO tools — the server will expose none. \
                             Delete it to reset to the config defaults.",
                            sfp.display()
                        );
                    }
                    tracing::info!(
                        "Loaded sidecar tool state from {} ({} tools)",
                        sfp.display(),
                        sidecar_tools.len()
                    );
                    enabled_tools = sidecar_tools;
                }
                Ok(None) => {
                    tracing::debug!("No sidecar tool state at {}", sfp.display());
                }
                Err(e) => {
                    tracing::warn!("Ignoring corrupt sidecar: {e}");
                }
            }
        }

        let read_only = config.security.read_only;

        // Read-only is applied AFTER the sidecar overlay — read-only always wins.
        if read_only {
            for name in crate::config::WRITE_TOOL_NAMES {
                enabled_tools.remove(*name);
            }
            tracing::info!("Read-only mode: write tools disabled");
        }

        tracing::info!(
            "Enabled tools: {} of {} total",
            enabled_tools.len(),
            crate::config::ALL_TOOL_CATEGORIES
                .iter()
                .flat_map(|c| crate::config::tools_in_category(c))
                .count()
        );

        // 256 buffered events; with no subscribers, sends are dropped (intended).
        let (event_tx, _) = broadcast::channel(256);

        Self {
            enabled_tools: RwLock::new(enabled_tools),
            read_only,
            activity: ActivityTracker::new(),
            metrics: MetricsRegistry::new(),
            event_bus: event_tx,
            concurrency: Semaphore::new(config.server.max_concurrent_requests),
            config_snapshot: ConfigSnapshot::from_config(config, source_path),
            search_backend: Arc::new(SearchBackend::detect(&config.search.ripgrep_path)),
            state_file_path,
            sidecar_lock: Mutex::new(()),
        }
    }
}

/// Frozen config subset for the control plane (Stage 3). Populated at startup;
/// every field is read by `control.rs` (`/health`, `/ready`, `/metrics`).
pub struct ConfigSnapshot {
    pub config_source: Option<PathBuf>,
    pub allowed_directories: Vec<String>,
    pub read_only: bool,
    pub mcp_bind: String,
    pub control_bind: String,
    pub auth_enabled: bool,
    pub version: &'static str,
    /// Configured concurrency ceiling (the `concurrency` Semaphore's initial
    /// permits). Used by `/metrics` to report `in_flight` = max − available.
    pub max_concurrent_requests: usize,
    /// Process start instant — set when `SharedState` is built. `/health` reports
    /// `uptime_secs` as its elapsed time.
    pub start_time: Instant,
}

impl ConfigSnapshot {
    pub fn from_config(config: &Config, source_path: Option<PathBuf>) -> Self {
        Self {
            config_source: source_path,
            allowed_directories: config.security.allowed_directories.clone(),
            read_only: config.security.read_only,
            mcp_bind: config.server.bind.clone(),
            control_bind: config.server.control_bind.clone(),
            auth_enabled: !config.server.auth_token.is_empty(),
            version: env!("CARGO_PKG_VERSION"),
            max_concurrent_requests: config.server.max_concurrent_requests,
            start_time: Instant::now(),
        }
    }
}

/// Events emitted by the server for the `/events` SSE stream (Stage 3).
///
/// Serialized to JSON for the SSE `data:` payload. Internally tagged with `kind`
/// (`"tool_call"` / `"health"`) so the dashboard can read fields directly without
/// unwrapping a variant name; the SSE `event:` type mirrors that tag. `ToolCall`
/// is emitted by `call_tool`; `Health` by the process-metrics sampler — both
/// only when a subscriber is attached.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActivityEvent {
    ToolCall {
        tool: String,
        /// Redacted, allowlisted arg summary (DEC-DRAFT-N) — never raw content.
        args_summary: String,
        duration_ms: u64,
        result_size: usize,
        status: String,
    },
    /// Periodic health snapshot — emitted by the process-metrics sampler.
    Health {
        rss_bytes: u64,
        handle_count: u32,
        in_flight: u32,
    },
    /// A control-plane tool toggle (Stage 4) — fanned out so the dashboard can
    /// refresh its tool panel live instead of polling. Serializes with
    /// `kind: "tool_toggle"`.
    ToolToggle {
        action: String,
        targets: Vec<String>,
        enabled_count: usize,
        total_count: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_call_serializes_with_kind_tag() {
        let ev = ActivityEvent::ToolCall {
            tool: "file_read_lines".into(),
            args_summary: "path:main.rs, start_line:1".into(),
            duration_ms: 7,
            result_size: 1234,
            status: "ok".into(),
        };
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["kind"], "tool_call");
        assert_eq!(v["tool"], "file_read_lines");
        assert_eq!(v["args_summary"], "path:main.rs, start_line:1");
        assert_eq!(v["duration_ms"], 7);
        assert_eq!(v["result_size"], 1234);
        assert_eq!(v["status"], "ok");
    }

    #[test]
    fn health_serializes_with_kind_tag() {
        let ev = ActivityEvent::Health {
            rss_bytes: 42_000,
            handle_count: 321,
            in_flight: 2,
        };
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["kind"], "health");
        assert_eq!(v["rss_bytes"], 42_000);
        assert_eq!(v["handle_count"], 321);
        assert_eq!(v["in_flight"], 2);
    }

    /// End-to-end of the `/events` security contract: the redacted summary that
    /// `call_tool` builds, pushed through the broadcast bus and serialized exactly
    /// as the SSE handler does, must show the path basename and a byte count — and
    /// must NEVER carry the raw content or the directory portion of the path.
    #[tokio::test(flavor = "multi_thread")]
    async fn tool_call_event_through_bus_leaks_no_content() {
        let tmp = std::env::temp_dir().to_string_lossy().to_string();
        let cfg = Config::from_directories(vec![tmp]).unwrap();
        let shared = SharedState::new(&cfg, None);
        let mut rx = shared.event_bus.subscribe();

        // Mirror call_tool's emission path with a content-bearing write.
        let args = serde_json::json!({
            "path": "C:\\Users\\victim\\secret\\creds.txt",
            "content": "SUPER SECRET VALUE"
        });
        let summary = crate::redact::summarize_args("file_write", args.as_object());
        shared
            .event_bus
            .send(ActivityEvent::ToolCall {
                tool: "file_write".into(),
                args_summary: summary,
                duration_ms: 3,
                result_size: 40,
                status: "ok".into(),
            })
            .expect("send should succeed with a live subscriber");

        let ev = rx.recv().await.expect("event should arrive");
        let json = serde_json::to_string(&ev).unwrap();

        assert!(json.contains("\"kind\":\"tool_call\""), "json: {json}");
        assert!(json.contains("path:creds.txt"), "basename missing: {json}");
        assert!(
            json.contains("content:<18 bytes>"),
            "content size missing: {json}"
        );
        // The two things that must never leak onto the wire:
        assert!(
            !json.contains("SUPER SECRET VALUE"),
            "raw content leaked: {json}"
        );
        assert!(!json.contains("victim"), "path dir leaked: {json}");
    }

    #[test]
    fn tool_toggle_serializes_with_kind_tag() {
        let ev = ActivityEvent::ToolToggle {
            action: "disable".into(),
            targets: vec!["compat".into()],
            enabled_count: 33,
            total_count: 47,
        };
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["kind"], "tool_toggle");
        assert_eq!(v["action"], "disable");
        assert_eq!(v["targets"][0], "compat");
        assert_eq!(v["enabled_count"], 33);
        assert_eq!(v["total_count"], 47);
    }

    /// Build a config whose source path is `dir/surgicalfs.toml` (so the sidecar
    /// resolves to `dir/surgicalfs-state.json`), allowing one allowed directory.
    fn cfg_with_source(dir: &std::path::Path) -> (Config, PathBuf) {
        let cfg = Config::from_directories(vec![dir.to_string_lossy().to_string()]).unwrap();
        (cfg, dir.join("surgicalfs.toml"))
    }

    #[test]
    fn sidecar_overlay_replaces_toml_defaults() {
        let dir = std::env::temp_dir().join(format!(
            "sfs-overlay-test-{}-{}",
            std::process::id(),
            crate::state::generate_ctl_token().get(..8).unwrap_or("x")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // Sidecar enables only two tools — a strict subset of the TOML default (all).
        let sidecar = dir.join("surgicalfs-state.json");
        let want: HashSet<String> = ["file_info", "json_query"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        crate::state::write_sidecar(&sidecar, &want).unwrap();

        let (cfg, source) = cfg_with_source(&dir);
        let shared = SharedState::new(&cfg, Some(source));
        let enabled = shared.enabled_tools.read().unwrap().clone();
        assert_eq!(enabled, want, "sidecar should override the TOML defaults");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sidecar_overlay_then_readonly_strips_write_tools() {
        let dir = std::env::temp_dir().join(format!(
            "sfs-overlay-ro-test-{}-{}",
            std::process::id(),
            crate::state::generate_ctl_token().get(..8).unwrap_or("x")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let sidecar = dir.join("surgicalfs-state.json");
        // Sidecar contains a write tool AND a read tool.
        let stored: HashSet<String> = ["file_write", "file_info"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        crate::state::write_sidecar(&sidecar, &stored).unwrap();

        let (mut cfg, source) = cfg_with_source(&dir);
        cfg.security.read_only = true; // read-only must win over the sidecar
        let shared = SharedState::new(&cfg, Some(source));
        let enabled = shared.enabled_tools.read().unwrap().clone();
        assert!(
            !enabled.contains("file_write"),
            "read-only must strip write tools"
        );
        assert!(enabled.contains("file_info"), "read tool should survive");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
