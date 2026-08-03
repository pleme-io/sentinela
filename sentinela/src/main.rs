//! sentinela — the pure-Rust Darwin GitOps node-sync daemon (the Mac peer
//! of NixOS `comin`). Keeps this Mac's darwin system equal to one repo's
//! branch HEAD: probe (git protocol) → build rev-pinned → re-check
//! freshness → switch → attest. See the workspace `README.md` and
//! `docs/gitops-v2-daemon.md` in the nix repo.
//!
//! The daemon is ONE long-running process with one loop, so single-flight
//! is structural (no lock) — the failure mode the v1.5 launchd
//! `StartInterval` loop needed a lock to avoid is gone.

#![forbid(unsafe_code)]

mod real_env;

use clap::{Parser, Subcommand};
use real_env::RealEnv;
use sentinela_config::SentinelaConfig;
use sentinela_core::{GitopsEnv, Sentinela, State, TickOutcome};
use std::path::PathBuf;
use std::time::Duration;

/// sentinela — Darwin GitOps node-sync daemon.
#[derive(Parser)]
#[command(name = "sentinela", version, about)]
struct Cli {
    /// Path to the rendered config yaml (the nix module writes this).
    #[arg(
        long,
        env = "SENTINELA_CONFIG",
        default_value = "/etc/pleme-gitops/config.yaml"
    )]
    config: PathBuf,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon loop (the launchd entry point).
    Run,
    /// Print the current deploy state (chain head + verification) as JSON.
    Status {
        /// Exit non-zero unless the node is POSITIVELY converged: a fresh
        /// heartbeat, a verified chain, no failure streak. Absent evidence
        /// exits non-zero too — "cannot tell" is not "fine".
        #[arg(long)]
        gate: bool,
    },
    /// Verify the receipt chain; exit non-zero if broken.
    Verify,
    /// Resolve the configured branch HEAD (git ls-remote) and print it —
    /// no build, no switch. A safe dry-run of the probe half.
    Probe,
    /// Run exactly one cycle and print the typed outcome, then exit.
    TickOnce,
}

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let cfg = match load_config(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, path = %cli.config.display(), "sentinela: config load failed");
            return std::process::ExitCode::FAILURE;
        }
    };

    match cli.command {
        Cmd::Run => run(cfg),
        Cmd::Status { gate } => status(&cfg, gate),
        Cmd::Verify => verify(&cfg),
        Cmd::Probe => probe(&cfg),
        Cmd::TickOnce => tick_once(&cfg),
    }
}

/// Resolve + print the branch HEAD (no build/switch) — a safe dry-run.
fn probe(cfg: &SentinelaConfig) -> std::process::ExitCode {
    let env = RealEnv::new(cfg.clone());
    match env.probe_head() {
        Ok(Some(rev)) => {
            println!("{rev}");
            std::process::ExitCode::SUCCESS
        }
        Ok(None) => {
            tracing::warn!(branch = %cfg.rev_probe.branch, "HEAD unresolvable (empty ls-remote)");
            std::process::ExitCode::FAILURE
        }
        Err(e) => {
            tracing::error!(error = %e, "probe failed");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Load + parse the config yaml.
fn load_config(path: &PathBuf) -> Result<SentinelaConfig, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_yaml::from_str(&raw).map_err(|e| e.to_string())
}

/// The daemon loop: one cycle, then sleep `poll_seconds`, forever.
fn run(cfg: SentinelaConfig) -> std::process::ExitCode {
    let poll = Duration::from_secs(cfg.poll_seconds.max(1));
    let loop_cfg = cfg.loop_config();
    let env = RealEnv::new(cfg);
    let mut sentinela = Sentinela::new(loop_cfg);
    tracing::info!(poll_seconds = poll.as_secs(), "sentinela: daemon started");

    // ── ★ ANNOUNCE THE STREAK AT STARTUP ──────────────────────────────────
    // A restart is the one moment we are guaranteed to write to the log, so
    // it is the moment to say whether this loop has been WORKING. Without
    // this the only startup evidence is "daemon started", which reads
    // identically whether the last tick activated cleanly or the last four
    // thousand failed. MEASURED on ryn 2026-08-02: 4136 consecutive
    // failures across 27.9 days, and 15 `daemon started` lines in that same
    // log — every restart had the number available and printed none of it.
    match env.load_chain() {
        Ok(chain) => {
            let streak = chain.consecutive_failures();
            let last_ok = chain
                .last_activated_rev()
                .map_or_else(|| "never".to_owned(), |r| r.short().to_owned());
            // An empty chain has a zero streak, so a naive `streak == 0`
            // reports a loop that has NEVER deployed as converged. Absence
            // of failure is not evidence of convergence; only an activation
            // is. Seen for real on cid 2026-08-02, freshly migrated onto
            // this engine: receipts=0, streak=0, last_activated=never.
            if chain.is_empty() {
                tracing::warn!(
                    "gitops: no deploy recorded yet — expected on a freshly-enrolled node"
                );
            } else if streak == 0 {
                tracing::info!(last_activated = %last_ok, "gitops: converged");
            } else {
                tracing::error!(
                    consecutive_failures = streak,
                    last_activated = %last_ok,
                    "gitops: DEGRADED — this node is not tracking the branch"
                );
            }
        }
        // Unreadable chain is itself worth saying out loud: it means the
        // audit trail — the only durable record of whether we converge —
        // cannot be consulted.
        Err(e) => tracing::error!(error = %e, "gitops: receipt chain unreadable"),
    }
    loop {
        let outcome = sentinela.tick(&env);
        log_outcome(&outcome);
        std::thread::sleep(poll);
    }
}

/// Emit one tick's outcome as a typed structured log line.
fn log_outcome(outcome: &TickOutcome) {
    match outcome {
        TickOutcome::Deployed { rev, generation } => {
            tracing::info!(rev = rev.short(), generation = %generation, "deployed");
        }
        TickOutcome::Unchanged { rev } => tracing::debug!(rev = rev.short(), "unchanged"),
        TickOutcome::Deferred { built, newer } => {
            tracing::info!(
                built = built.short(),
                newer = newer.short(),
                "deferred (HEAD moved mid-build)"
            );
        }
        TickOutcome::ReprobeInconclusive { built } => {
            tracing::warn!(
                built = built.short(),
                "post-build re-probe empty — not activated (fail-closed)"
            );
        }
        TickOutcome::Unresolvable => tracing::warn!("HEAD unresolvable (fail-closed)"),
        TickOutcome::ProbeError { error } => tracing::warn!(%error, "probe error (fail-closed)"),
        TickOutcome::BuildFailed { rev, error } => {
            tracing::error!(rev = rev.short(), %error, "build failed");
        }
        TickOutcome::SwitchFailed { rev, error } => {
            tracing::error!(rev = rev.short(), %error, "switch failed");
        }
        TickOutcome::CoolingDown { remaining_ms } => {
            tracing::debug!(remaining_ms, "cooling down");
        }
    }
}

/// Print the current state as JSON (for the observability surface).
fn status(cfg: &SentinelaConfig, gate: bool) -> std::process::ExitCode {
    let env = RealEnv::new(cfg.clone());
    let chain = match env.load_chain() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "status: could not load chain");
            return std::process::ExitCode::FAILURE;
        }
    };
    let verified = chain.verify().is_ok();
    // ── ★ THE THREE FIELDS THAT MAKE THIS DOCUMENT DECIDABLE ─────────────
    // Without these a reader can only see what the daemon DID, never
    // whether it is still doing it, so a dead loop and a converged one
    // print the same thing. `fleet rebuild`'s verdict now requires them
    // and reports `unknown` when they are absent — see pleme-io/fleet
    // 6f0c8b2.
    //
    //   last_tick_at_unix_ms — liveness. An ACTIVATION time cannot serve:
    //                          a converged loop activates nothing for weeks.
    //   head_rev             — where the branch actually points, as seen by
    //                          the last tick. Already probed every cycle and
    //                          previously discarded; this surfaces a value we
    //                          were computing, not a new network call.
    //   poll_seconds         — the interval, without which "silent for 60177s"
    //                          cannot be judged stale.
    let beat = env.load_heartbeat();
    let status = serde_json::json!({
        "hostname": cfg.hostname,
        "flake_url": cfg.flake_url,
        "branch": cfg.rev_probe.branch,
        "receipts": chain.len(),
        "consecutive_failures": chain.consecutive_failures(),
        "chain_verified": verified,
        "last_activated_rev": chain.last_activated_rev().map(sentinela_core::Rev::as_str),
        "head": chain.head(),
        "poll_seconds": cfg.poll_seconds,
        "last_tick_at_unix_ms": beat.as_ref().map(|b| b.at_unix_ms),
        "last_tick_outcome": beat.as_ref().map(|b| b.outcome.clone()),
        "head_rev": beat
            .as_ref()
            .and_then(|b| b.head_rev.as_ref())
            .map(|r| r.as_str().to_owned()),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&status).unwrap_or_default()
    );

    if !gate {
        return std::process::ExitCode::SUCCESS;
    }
    // `--gate`: an exit code a launchd/systemd/cron monitor can act on.
    // Absent evidence is NOT success — the whole lesson of this incident is
    // that "I cannot tell" must not be spelled the same way as "fine".
    let now_ms = env.now_unix_ms();
    match convergence_gate(
        &beat,
        now_ms,
        cfg.poll_seconds,
        chain.consecutive_failures(),
        verified,
    ) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(why) => {
            tracing::error!(reason = %why, "gitops: NOT CONVERGED");
            std::process::ExitCode::FAILURE
        }
    }
}

/// The pure gate behind `status --gate`, split from IO so each refusal is
/// testable without a daemon, a clock, or a filesystem.
///
/// Returns `Err(reason)` for anything that is not positively converged —
/// including the "no evidence" case, which the pre-2026-08-03 surface
/// reported as success.
fn convergence_gate(
    beat: &Option<sentinela_core::Heartbeat>,
    now_unix_ms: u64,
    poll_seconds: u64,
    consecutive_failures: usize,
    chain_verified: bool,
) -> Result<(), String> {
    /// Same tolerance the fleet verdict uses: one slow build plus one
    /// missed cycle before a loop is presumed stopped.
    const STALE_AFTER_POLLS: u64 = 3;

    if !chain_verified {
        return Err("receipt chain failed verification".to_owned());
    }
    let Some(beat) = beat else {
        return Err("no heartbeat has ever been published — liveness unknown".to_owned());
    };
    let silent_ms = now_unix_ms.saturating_sub(beat.at_unix_ms);
    let budget_ms = STALE_AFTER_POLLS * poll_seconds.max(1) * 1000;
    if silent_ms > budget_ms {
        return Err(format!(
            "no tick for {}s (budget {}s) — the loop is stopped, not idle",
            silent_ms / 1000,
            budget_ms / 1000
        ));
    }
    if consecutive_failures > 0 {
        return Err(format!("{consecutive_failures} consecutive failed ticks"));
    }
    Ok(())
}

/// Verify the chain; non-zero exit on a broken chain.
fn verify(cfg: &SentinelaConfig) -> std::process::ExitCode {
    let env = RealEnv::new(cfg.clone());
    match env.load_chain().map(|c| c.verify()) {
        Ok(Ok(())) => {
            println!("ok: receipt chain verified");
            std::process::ExitCode::SUCCESS
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "chain verification FAILED");
            std::process::ExitCode::FAILURE
        }
        Err(e) => {
            tracing::error!(error = %e, "could not load chain");
            std::process::ExitCode::FAILURE
        }
    }
}

/// One cycle, print the outcome, exit 0 (the tick itself is fail-closed).
fn tick_once(cfg: &SentinelaConfig) -> std::process::ExitCode {
    let env = RealEnv::new(cfg.clone());
    let mut sentinela = Sentinela::new(cfg.loop_config());
    let outcome = sentinela.tick(&env);
    log_outcome(&outcome);
    if matches!(sentinela.state(), State::CoolingDown { .. }) {
        tracing::info!("entered cooldown after a failure");
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
mod gate_tests {
    use super::convergence_gate;
    use sentinela_core::Heartbeat;

    const POLL: u64 = 60;
    /// Wall clock used by every case; the numbers below are offsets from it.
    const NOW_MS: u64 = 1_785_724_816_000;

    fn beat_at(ms: u64) -> Option<Heartbeat> {
        Some(Heartbeat {
            at_unix_ms: ms,
            outcome: "unchanged".to_owned(),
            head_rev: None,
            poll_seconds: POLL,
        })
    }

    /// ── ★ THE CASE THE OLD SURFACE GOT WRONG ─────────────────────────────
    /// `sentinela status` exited 0 unconditionally, so every monitor that
    /// could have been built on it would have read a dead daemon as fine.
    /// No evidence must be a refusal, not a pass.
    #[test]
    fn no_heartbeat_is_a_refusal_not_a_pass() {
        let err = convergence_gate(&None, NOW_MS, POLL, 0, true)
            .expect_err("absent liveness evidence must never gate green");
        assert!(err.contains("no heartbeat"), "{err}");
    }

    /// cid's real numbers: last tick 1785664639s, judged at 1785724816s.
    #[test]
    fn cids_16_hour_silence_fails_the_gate() {
        let err = convergence_gate(&beat_at(1_785_664_639_000), NOW_MS, POLL, 0, true)
            .expect_err("a loop silent for 16.7h against a 60s poll is stopped");
        assert!(err.contains("60177s"), "{err}");
        assert!(err.contains("stopped, not idle"), "{err}");
    }

    #[test]
    fn a_fresh_tick_on_a_verified_chain_passes() {
        convergence_gate(&beat_at(NOW_MS - 30_000), NOW_MS, POLL, 0, true)
            .expect("a loop that ticked 30s ago on a 60s poll is alive");
    }

    /// Exactly at the 3-interval budget is still alive; one ms past is not.
    /// Pinned because an off-by-one here either cries wolf every few
    /// minutes or never fires at all.
    #[test]
    fn the_staleness_boundary_is_three_poll_intervals() {
        let budget_ms = 3 * POLL * 1000;
        convergence_gate(&beat_at(NOW_MS - budget_ms), NOW_MS, POLL, 0, true)
            .expect("exactly at the budget is not yet stale");
        convergence_gate(&beat_at(NOW_MS - budget_ms - 1), NOW_MS, POLL, 0, true)
            .expect_err("one millisecond past the budget is stale");
    }

    #[test]
    fn a_failure_streak_fails_even_with_a_fresh_pulse() {
        let err = convergence_gate(&beat_at(NOW_MS - 1000), NOW_MS, POLL, 4136, true)
            .expect_err("the ryn outage shape must not gate green");
        assert!(err.contains("4136"), "{err}");
    }

    #[test]
    fn an_unverifiable_chain_fails_before_anything_else_is_considered() {
        let err = convergence_gate(&beat_at(NOW_MS - 1000), NOW_MS, POLL, 0, false)
            .expect_err("tamper-evidence outranks liveness");
        assert!(err.contains("verification"), "{err}");
    }
}
