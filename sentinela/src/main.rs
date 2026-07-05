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
    #[arg(long, env = "SENTINELA_CONFIG", default_value = "/etc/pleme-gitops/config.yaml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon loop (the launchd entry point).
    Run,
    /// Print the current deploy state (chain head + verification) as JSON.
    Status,
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
        Cmd::Status => status(&cfg),
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
            tracing::info!(built = built.short(), newer = newer.short(), "deferred (HEAD moved mid-build)");
        }
        TickOutcome::ReprobeInconclusive { built } => {
            tracing::warn!(built = built.short(), "post-build re-probe empty — not activated (fail-closed)");
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
fn status(cfg: &SentinelaConfig) -> std::process::ExitCode {
    let env = RealEnv::new(cfg.clone());
    let chain = match env.load_chain() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "status: could not load chain");
            return std::process::ExitCode::FAILURE;
        }
    };
    let verified = chain.verify().is_ok();
    // Typed status object rendered to JSON via serde (a typed emission
    // surface, not string composition).
    let status = serde_json::json!({
        "hostname": cfg.hostname,
        "flake_url": cfg.flake_url,
        "branch": cfg.rev_probe.branch,
        "receipts": chain.len(),
        "chain_verified": verified,
        "last_activated_rev": chain.last_activated_rev().map(sentinela_core::Rev::as_str),
        "head": chain.head(),
    });
    println!("{}", serde_json::to_string_pretty(&status).unwrap_or_default());
    std::process::ExitCode::SUCCESS
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
