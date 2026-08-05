//! Reach the FOREIGN gating logic behind the rebuild site's ENOENT
//! classification.
//!
//! `RealEnv::run_rebuild` maps a `BoundedRun::run` error through `exec_err`, so
//! an absent rebuild tool becomes `EnvError::ToolMissing` (structural, no retry
//! can clear it) instead of `EnvError::BuildFailed` (transient, retried on the
//! cooldown cadence forever). That mapping is only correct if tsunagu actually
//! surfaces a failed spawn as `std::io::ErrorKind::NotFound` rather than
//! wrapping it — it ends in `cmd.spawn()?` (`tsunagu-0.1.4/src/exec.rs:178`),
//! so today it does. That is a fact about someone else's crate, and a version
//! bump could change it in silence. This is the tripwire.
//!
//! ── ★ WHY THIS IS AN INTEGRATION BINARY AND NOT A UNIT TEST ──────────────
//! It has to attempt a real spawn, and a `fork` anywhere in the unit-test
//! binary transiently leaks the `flock` that `acquire_switch_lock`'s tests
//! hold: the child inherits the open file description, so the lock outlives
//! the guard's `Drop` until the child execs or exits. Measured on cid
//! 2026-08-05 — putting this test in `real_env.rs` took
//! `an_uncontended_lock_is_acquired_and_released_on_drop` from 0 failures in
//! 25 runs to **19 in 25**. Cargo runs test binaries serially, so its own
//! binary is genuine isolation rather than a suppressed symptom.

use std::process::Command;
use std::time::Duration;
use tsunagu::exec::BoundedRun;

#[test]
fn a_failed_spawn_surfaces_as_enoent_through_bounded_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cmd = Command::new(dir.path().join("no-such-rebuild-tool"));
    let err = BoundedRun::new(&dir.path().join("capture.out"))
        .timeout(Duration::from_secs(5))
        .run(cmd)
        .expect_err("spawning a binary that does not exist must fail");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "if tsunagu stops surfacing ENOENT, the rebuild site silently reverts \
         to reporting a broken installation as a build failure — retried on \
         the cooldown cadence forever while the loop reads healthy"
    );
}
