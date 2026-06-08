//! Binary-level regression tests for the idle self-reap watchdog.
//!
//! These spawn the real `surgicalfs-mcp` binary (not the library) because the
//! bug they guard against was in `main()`'s wiring, not the pure logic: the
//! watchdog used to sit in the post-`serve()` select, and `serve()` does not
//! return until the MCP initialize handshake completes — so a child stuck
//! before/during init (the orphan case under supergateway) never reached it.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A child that connects but never initializes must still be reaped by the idle
/// watchdog. serve() blocks awaiting init, so only the independent watchdog task
/// can end the process. (Regression: previously it never exited.)
#[test]
fn idle_watchdog_reaps_child_stuck_before_init() {
    let tmp = std::env::temp_dir();
    let mut child = Command::new(env!("CARGO_BIN_EXE_surgicalfs-mcp"))
        .arg("--idle-timeout-secs")
        .arg("2")
        .arg(tmp.to_string_lossy().to_string()) // positional allowed dir; no config file needed
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn surgicalfs-mcp binary");

    // Hold stdin open and send NOTHING — the "connected but never initialized"
    // orphan. The pipe stays healthy (no EOF), so only the idle watchdog can win.
    let stdin = child.stdin.take().expect("child stdin");

    let start = Instant::now();
    let deadline = Duration::from_secs(8); // idle timeout is 2s; generous margin for CI
    loop {
        match child.try_wait().expect("try_wait failed") {
            Some(_status) => {
                drop(stdin);
                return; // self-reaped — correct
            }
            None => {
                if start.elapsed() > deadline {
                    let _ = child.kill();
                    drop(stdin);
                    panic!(
                        "idle watchdog did not reap a pre-init child within {deadline:?} (idle timeout was 2s)"
                    );
                }
                std::thread::sleep(Duration::from_millis(150));
            }
        }
    }
}

/// With idle-exit disabled (the default, 0), an idle process must NOT self-exit
/// — otherwise local stdio clients (Claude Desktop, IDEs) would be killed during
/// a normal think-time pause.
#[test]
fn no_idle_exit_when_disabled() {
    let tmp = std::env::temp_dir();
    let mut child = Command::new(env!("CARGO_BIN_EXE_surgicalfs-mcp"))
        .arg(tmp.to_string_lossy().to_string()) // no --idle-timeout-secs => default 0 (off)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn surgicalfs-mcp binary");

    let stdin = child.stdin.take().expect("child stdin");
    std::thread::sleep(Duration::from_secs(3));
    let still_alive = child.try_wait().expect("try_wait failed").is_none();
    let _ = child.kill();
    drop(stdin);
    assert!(
        still_alive,
        "process self-exited with idle-exit disabled (timeout=0) — would kill local clients"
    );
}
