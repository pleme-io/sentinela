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

mod introspect;
mod real_env;

use clap::{Parser, Subcommand};
use real_env::RealEnv;
use sentinela_config::SentinelaConfig;
use sentinela_core::{GitopsEnv, Sentinela, State, TickOutcome};
use std::path::PathBuf;

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
    /// Print the current deploy state — verdict first, then the evidence.
    Status {
        /// Exit non-zero unless the node is POSITIVELY converged: a fresh
        /// heartbeat, a verified chain, no failure streak. Absent evidence
        /// exits non-zero too — "cannot tell" is not "fine".
        #[arg(long)]
        gate: bool,
        /// Emit the machine surface (the same JSON document this command
        /// printed unconditionally before 0.1.18) instead of the operator
        /// view. Every field is unchanged, so a consumer adds one flag.
        #[arg(long)]
        json: bool,
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
        Cmd::Status { gate, json } => status(&cfg, gate, json),
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

/// One reason this daemon must not start.
///
/// A typed sum rather than a `Vec<String>` of prose: the two refusals have
/// genuinely different fixes — one is "install/expose a binary", the other is
/// "this pair of config fields cannot work together" — and an operator reading
/// a log at 3am should not have to infer which from the wording.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PreflightFailure {
    /// A binary the daemon invokes is absent. Mirrors
    /// [`sentinela_core::EnvError::ToolMissing`], which is the same condition
    /// discovered at tick time instead of at startup.
    ToolMissing { tool: String },
    /// The selected rebuild tool structurally cannot resolve the configured
    /// `flake_url`. See `sentinela_config::FlakeRefSyntax`.
    FlakeRefUnsupported {
        tool: &'static str,
        flake_url: String,
    },
}

impl std::fmt::Display for PreflightFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToolMissing { tool } => write!(f, "required tool not found: {tool}"),
            Self::FlakeRefUnsupported { tool, flake_url } => write!(
                f,
                "{tool} cannot resolve the flake ref `{flake_url}` — it accepts \
                 an absolute filesystem path only, and this daemon builds a \
                 rev-pinned ref off `flake_url`. Every tick would fail closed \
                 while the loop reported healthy."
            ),
        }
    }
}

/// Every precondition this daemon cannot do its job without, checked before
/// the loop starts. Returns the failures, in the order they would bite.
///
/// ── ★ REFUSE TO START, DO NOT DISCOVER IT ONCE A MINUTE FOREVER ────────
/// A reconciler whose preconditions are structurally unsatisfiable must not
/// present as healthy. Without this the daemon starts, ticks, fails closed
/// on every tick, rewrites a fresh heartbeat each time, and reports
/// `active (running)` with `NRestarts=0` — so `systemctl status`,
/// `systemctl --failed` and the fleet MCP's heartbeat reader all show a
/// working loop while `head_rev` is `null` forever.
///
/// MEASURED on rio 2026-08-05: exactly that, for over an hour, because the
/// systemd unit shipped no `path` and a NixOS unit inherits systemd's
/// default PATH (coreutils, findutils, gnugrep, gnused, systemd — no
/// `git`). The Nix-side fix landed in `nix@36c1e3de`, but a fix in one
/// module protects one module: this protects every consumer, on both
/// platforms, including a hand-run `sentinela run`.
///
/// `git` is probed by EXECUTING it rather than by scanning `$PATH`, because
/// the failure being modelled is `Command::output()` returning ENOENT — the
/// only faithful test is the same syscall, which also catches a present but
/// non-executable file. The rebuild tool is an absolute path
/// (`/run/current-system/sw/bin/…`), so for it existence is the question.
///
/// ── ★ A PRESENT BINARY IS NOT A USABLE ONE ─────────────────────────────
/// The flake-ref check is the same failure SHAPE with a different cause: the
/// tool is installed and runs, and still cannot do the job, because the ref
/// this daemon constructs is not one it can parse. Adding
/// `RebuildTool::Sui` made that reachable by configuration for the first
/// time, so the refusal lands here rather than in a comment.
fn preflight(cfg: &SentinelaConfig) -> Vec<PreflightFailure> {
    let mut failures = Vec::new();

    match std::process::Command::new("git").arg("--version").output() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            failures.push(PreflightFailure::ToolMissing {
                tool: "git".to_owned(),
            });
        }
        // Any other error (a git that exists but errors) is NOT a missing
        // tool — fail-closed at tick time carries those, with context.
        Err(_) | Ok(_) => {}
    }

    let rebuild = cfg.rebuild_tool.binary();
    if !std::path::Path::new(rebuild).exists() {
        failures.push(PreflightFailure::ToolMissing {
            tool: rebuild.to_owned(),
        });
    }

    failures.extend(flake_ref_failure(cfg));

    failures
}

/// The tool-vs-flake-ref half of [`preflight`], split out as a PURE function.
///
/// ── ★ SPLIT SO ITS TESTS DO NOT FORK ────────────────────────────────────
/// Not cosmetic. [`preflight`] runs `git --version`, and a forked child
/// inherits the parent's open descriptors — including the `flock`ed
/// `/tmp/fleet-rebuild.lock` held by `real_env::acquire_switch_lock`. Calling
/// `preflight` from three tests turned `an_uncontended_lock_is_acquired_and_released_on_drop`
/// from green into **19 failures in 25 runs** (measured on cid 2026-08-05;
/// `HEAD` was 0/25, single-threaded is 0/25), because the lock outlives the
/// guard's `Drop` for as long as any forked child still references the
/// description. The pure half is where the new behaviour lives, so it is the
/// half that gets the tests.
///
/// The daemon has the same property deliberately and documents it as an honest
/// residual (`real_env::GitopsEnv::switch`); this is the test-side consequence
/// of it, recorded rather than papered over.
fn flake_ref_failure(cfg: &SentinelaConfig) -> Option<PreflightFailure> {
    if cfg.flake_ref_is_resolvable() {
        return None;
    }
    Some(PreflightFailure::FlakeRefUnsupported {
        tool: cfg.rebuild_tool.binary(),
        flake_url: cfg.flake_url.clone(),
    })
}

/// The daemon loop: one cycle, then sleep `poll_seconds`, forever.
fn run(cfg: SentinelaConfig) -> std::process::ExitCode {
    // ── ★ PREFLIGHT BEFORE THE LOOP, AND EXIT IF IT FAILS ────────────────
    // See `missing_tools`. Exiting non-zero is what makes the fault reach an
    // operator: the unit lands in `activating (auto-restart)` and then, once
    // the start limit trips, `failed` — where `systemctl --failed` finally
    // shows it. That start limit is NOT optional and NOT systemd's default:
    // with `RestartSec=30` the default 5-starts-per-10s can never be
    // reached, so an un-tuned unit restarts forever and stays invisible.
    // The nix module pairs this with an explicit
    // StartLimitIntervalSec/StartLimitBurst for exactly that reason.
    let failures = preflight(&cfg);
    if !failures.is_empty() {
        let reasons = failures
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        tracing::error!(
            reasons = %reasons,
            rebuild_tool = cfg.rebuild_tool.binary(),
            "sentinela: PREFLIGHT FAILED — refusing to start. \
             A daemon that cannot probe or rebuild must not report itself healthy; \
             every tick would fail closed while every liveness surface read green. \
             On NixOS add missing tools to the unit's `path` (systemd does not \
             inherit a login PATH)."
        );
        return std::process::ExitCode::FAILURE;
    }

    // ── ★ NO `poll` LOCAL ON PURPOSE ─────────────────────────────────────
    // There used to be a `Duration` here and `sleep(poll)` below, which
    // overruled the FSM's per-outcome cadence on every tick. Deleting it is
    // the enforcement: the only `Duration` reachable at the sleep is the one
    // the outcome produces, so "sleep the wrong interval" has no expression
    // rather than being a rule someone has to remember.
    let loop_cfg = cfg.loop_config();
    let env = std::sync::Arc::new(RealEnv::new(cfg));

    // ── ★ THE RECONCILER BECOMES ASKABLE ───────────────────────────────
    // Bound before the loop so a node is answerable from its first tick.
    // `spawn_sidecar` returns `Some(path)` only when the socket is actually
    // BOUND, not merely when a thread started, so announcing it here is not a
    // lie. A `None` is logged and the loop continues: introspection is how you
    // ask what converged, never a precondition for converging.
    match kanshou::Server::spawn_sidecar(
        "sentinela",
        introspect::SentinelaIntrospect::new(std::sync::Arc::clone(&env)),
    ) {
        Some(sock) => tracing::info!(socket = %sock.display(), "introspection live"),
        None => tracing::warn!("introspection unavailable — the loop still converges"),
    }
    let mut sentinela = Sentinela::new(loop_cfg);
    tracing::info!(
        poll_seconds = loop_cfg.poll_seconds,
        "sentinela: daemon started"
    );

    // ── ★ ANNOUNCE THE STREAK AT STARTUP ──────────────────────────────────
    // A restart is the one moment we are guaranteed to write to the log, so
    // it is the moment to say whether this loop has been WORKING. Without
    // this the only startup evidence is "daemon started", which reads
    // identically whether the last tick activated cleanly or the last four
    // thousand failed. MEASURED on ryn 2026-08-02: 4136 consecutive
    // failures across 27.9 days, and 15 `daemon started` lines in that same
    // log — every restart had the number available and printed none of it.
    let mut prev = health(&env);
    log_health(&prev);

    // ── ★ AND RE-ASK IT EVERY TICK ────────────────────────────────────────
    // The announcement above answers "is this loop working?" exactly once,
    // at startup, because it sits before `loop`. That was the whole defect
    // in the next outage: MEASURED on ryn 2026-08-06, the daemon started at
    // 00:28, printed DEGRADED once at 07:28, and then said nothing for the
    // 19.5 hours it spent failing, deferring and standing aside on an
    // operator-held machine lock. It was alive the entire time, so KeepAlive
    // was satisfied; it was ticking, so nothing looked hung; and the one
    // surface that knew the number had already spoken and would not speak
    // again for the life of the process.
    //
    // A startup-only verdict answers the question at the one moment it is
    // least likely to be interesting — a fresh process has nothing to report
    // yet. Re-ask it after every tick.
    //
    // Quiet while converged, loud otherwise. Emitting unconditionally would
    // print an info line every poll interval on a healthy node, which is the
    // fastest way to train an operator to filter the word out — the exact
    // failure the DEGRADED/STARVED split above exists to avoid. So a healthy
    // loop stays silent after its startup line, a broken one says so on
    // every tick, and the transition back to healthy is announced once.
    loop {
        let outcome = sentinela.tick(&*env);
        log_outcome(&outcome);

        let now = health(&env);
        if should_report(&prev, &now) {
            log_health(&now);
        }
        prev = now;

        std::thread::sleep(outcome.next_delay(&loop_cfg));
    }
}

/// Emit one tick's outcome as a typed structured log line.
// ── ★ `Health` + its derivation MOVED to `introspect` (2026-08-28) ─────
// They used to live here, private to the binary, which is exactly why the
// loop could not be ASKED what it was doing -- the verdict existed as a value
// and had no surface but a log line. A monitor built on that log text read a
// DEGRADED emitted twenty minutes before the build it was watching.
//
// Moved rather than copied: the logger below and the kanshou socket are now
// two renderings of ONE derivation. Deriving them separately would let the
// log say DEGRADED while the socket said converged, with no way to tell which
// was lying -- the precise class this crate exists to close.
use introspect::Health;

/// The loop's health. A thin alias over the one derivation, kept so every
/// call site and test here reads unchanged.
fn health(env: &RealEnv) -> Health {
    introspect::health_of(env)
}

/// Say something whenever anything is wrong, and once more on the transition
/// back to healthy. Stay silent while converged.
///
/// The silence is deliberate and is the only judgement call here. Emitting
/// unconditionally would print an info line every poll interval on a healthy
/// node — which is the fastest way to train an operator to filter the word
/// out, and filtering is exactly the failure the DEGRADED/STARVED split
/// exists to prevent. A broken loop therefore says so on EVERY tick, and
/// recovery is announced once so the log shows when it stopped.
fn should_report(prev: &Health, now: &Health) -> bool {
    !matches!(now, Health::Converged { .. }) || !matches!(prev, Health::Converged { .. })
}

fn log_health(h: &Health) {
    match h {
        Health::NeverDeployed => {
            tracing::warn!("gitops: no deploy recorded yet — expected on a freshly-enrolled node")
        }
        Health::Degraded { streak, last_ok } => tracing::error!(
            consecutive_failures = streak,
            last_activated = %last_ok,
            "gitops: DEGRADED — this node is not tracking the branch"
        ),
        Health::Starved { deferrals, last_ok } => tracing::warn!(
            consecutive_deferrals = deferrals,
            last_activated = %last_ok,
            "gitops: STARVED — each build finishes against a moved HEAD; \
             nothing is broken, the branch is moving faster than one build"
        ),
        Health::Converged { last_ok } => {
            tracing::info!(last_activated = %last_ok, "gitops: converged")
        }
        Health::Unreadable { error } => {
            tracing::error!(error = %error, "gitops: receipt chain unreadable")
        }
    }
}

fn log_outcome(outcome: &TickOutcome) {
    match outcome {
        TickOutcome::Deployed { rev, generation } => {
            tracing::info!(rev = rev.short(), generation = %generation, "deployed");
        }
        TickOutcome::DeployedBehind {
            rev,
            generation,
            newer,
        } => {
            // Deliberately its own line, not folded into "deployed": the node
            // is now running a rev we already know is superseded, and an
            // operator reading the log must be able to see that this was the
            // starvation escape rather than a normal convergence.
            tracing::info!(
                rev = rev.short(),
                generation = %generation,
                newer = newer.short(),
                "deployed an ancestor of HEAD to escape starvation; converging next tick"
            );
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
        TickOutcome::SwitchDeferred { rev, holder } => {
            tracing::info!(
                rev = rev.short(),
                holder = %holder,
                "switch deferred — another rebuild holds the machine lock; standing aside"
            );
        }
        TickOutcome::CoolingDown { remaining_ms } => {
            tracing::debug!(remaining_ms, "cooling down");
        }
    }
}

/// Print the current state as JSON (for the observability surface).
fn status(cfg: &SentinelaConfig, gate: bool, json: bool) -> std::process::ExitCode {
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
        // Deferrals are NOT failures (see ReceiptChain::consecutive_failures),
        // so the streak alone can no longer answer "is it converging?". This
        // is the other half: 0/0 is healthy, n/0 is broken, 0/n is starved.
        "consecutive_deferrals": chain.consecutive_deferrals(),
        "chain_verified": verified,
        "last_activated_rev": chain.last_activated_rev().map(sentinela_core::Rev::as_str),
        "head": chain.head(),
        "poll_seconds": cfg.poll_seconds,
        "last_tick_at_unix_ms": beat.as_ref().map(|b| b.at_unix_ms),
        "last_tick_outcome": beat.as_ref().map(|b| b.outcome.clone()),
        // ── ★ PHASE + VERDICT CROSS THE WIRE, NOT JUST THE TYPE ──────────
        // `Phase` was added 2026-08-02 after a healthy 12m02s build reported
        // "the loop is stopped" against a 180s budget. `convergence_gate`
        // below was taught to match on it and has been right ever since.
        //
        // This document was NOT, and that is how the same false alarm
        // recurred on cid 2026-08-03: `fleet rebuild` re-derives the verdict
        // from `last_tick_at_unix_ms` + `poll_seconds`, and `phase` was
        // absent here — so the field that makes the question decidable never
        // crossed the process boundary. A 29-minute darwin build published
        // `last_tick_outcome: "building"` and was reported STOPPED.
        //
        // Publishing `phase` alone would let a consumer get it right. That is
        // not enough: it also lets the next consumer get it WRONG, in a new
        // way, and the whole point is that this verdict is decided ONCE. So
        // `converged` is the SAME `convergence_gate` the `--gate` exit code
        // uses — one function, one answer, every reader.
        "phase": beat.as_ref().map(|b| b.phase),
        // The DISTILLED cause of the most recent failure. See
        // `distill_failure` — the raw receipt is mostly cascade.
        "last_failure": last_failure_lines(&chain),
        "converged": convergence_gate(
            &beat,
            env.now_unix_ms(),
            cfg.poll_seconds,
            cfg.build_timeout_seconds,
            chain.consecutive_failures(),
            verified,
        )
        .map_or_else(|why| serde_json::json!({"ok": false, "why": why}),
                     |()| serde_json::json!({"ok": true, "why": null})),
        "head_rev": beat
            .as_ref()
            .and_then(|b| b.head_rev.as_ref())
            .map(|r| r.as_str().to_owned()),
    });
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&status).unwrap_or_default()
        );
    } else {
        print!("{}", StatusView(&status));
    }

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
        cfg.build_timeout_seconds,
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
    build_timeout_seconds: u64,
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
    // The operator's own configured ceiling on a build, not a second opinion
    // invented here — `build_timeout_seconds` is what the loop already agreed
    // a build may take, so a tick past it has outlived its own contract.
    let build_budget_ms = build_timeout_seconds.max(1) * 1000;
    // ── ★ A BUILD IS NOT SILENCE ─────────────────────────────────────────
    // The poll budget answers "should another tick have happened by now?",
    // which is only a question about a loop BETWEEN ticks. A tick that is
    // still running has not missed anything — it is doing the work. Judging
    // an in-flight pulse against the poll budget is what made a healthy
    // 12m02s build report "the loop is stopped" against a 180s budget on ryn
    // 2026-08-02, and any build longer than two polls was un-gateable.
    //
    // Matched with NO wildcard arm: a future phase must be classified here
    // rather than silently inheriting the stopped-loop verdict.
    match beat.phase {
        // ── ★ AND A HANG IS NOT A BUILD ──────────────────────────────────
        // Exempting an in-flight tick from the POLL budget is right — it has
        // not missed a cycle, it is doing the work. Exempting it from every
        // bound is not: this arm was empty, so a tick that entered `building`
        // and never came back stayed "converging" forever.
        //
        // Measured on cid 2026-08-12: a tick sat `building` for 4h39m — the
        // daemon had in fact been dead since it wrote that phase — and
        // `status` printed `● CONVERGED` the whole time, beside its own
        // `← BEHIND` and `4h40m ago · building`. Three surfaces, one state,
        // and the green one is the one an operator reads. The MCP verdict
        // applied a build budget and said `stopped` correctly, which is what
        // makes this a bug in the gate rather than a disagreement.
        //
        // So a build gets its own, much larger budget, and past it says the
        // thing that is actually true: a build this long is a hang.
        sentinela_core::Phase::InFlight => {
            if silent_ms > build_budget_ms {
                return Err(format!(
                    "tick has been building for {}s, past the {}s build budget \
                     — a build this long is a hang, not progress",
                    silent_ms / 1000,
                    build_budget_ms / 1000
                ));
            }
        }
        sentinela_core::Phase::Resolved => {
            if silent_ms > budget_ms {
                return Err(format!(
                    "no tick for {}s (budget {}s) — the loop is stopped, not idle",
                    silent_ms / 1000,
                    budget_ms / 1000
                ));
            }
        }
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
mod preflight_tests {
    use super::{PreflightFailure, flake_ref_failure};
    use sentinela_config::{RebuildTool, SentinelaConfig};

    fn cfg_with(tool: RebuildTool, flake_url: &str) -> SentinelaConfig {
        SentinelaConfig {
            flake_url: flake_url.to_owned(),
            hostname: "rio".to_owned(),
            rebuild_tool: tool,
            ..SentinelaConfig::default()
        }
    }

    /// ── ★ THE REFUSAL THAT MAKES `RebuildTool::Sui` SAFE TO SHIP ─────────
    /// sui cannot parse a `github:` flake ref (`sui-compat/src/flake_ref.rs`
    /// treats the left half of `<ref>#<attr>` as a filesystem path; measured
    /// live on cid 2026-08-05 against sui 0.1.154). Without this refusal, a
    /// node that selected sui would start, tick, fail closed on every build
    /// with `getFlake: … No such file or directory`, and report `active
    /// (running)` with a fresh heartbeat forever — the exact rio 2026-08-05
    /// shape, reintroduced by a config knob.
    #[test]
    fn sui_against_a_remote_flake_url_is_refused_before_the_loop_starts() {
        assert_eq!(
            flake_ref_failure(&cfg_with(RebuildTool::Sui, "github:pleme-io/nix")),
            Some(PreflightFailure::FlakeRefUnsupported {
                tool: RebuildTool::Sui.binary(),
                flake_url: "github:pleme-io/nix".to_owned(),
            }),
            "selecting sui against a remote repo must refuse at startup"
        );
    }

    /// The refusal must be SCOPED to the tool that cannot do it — otherwise
    /// it would ground the two tools that run the fleet today.
    #[test]
    fn the_nix_tools_are_never_refused_for_a_remote_flake_url() {
        for tool in [RebuildTool::DarwinRebuild, RebuildTool::NixosRebuild] {
            assert_eq!(
                flake_ref_failure(&cfg_with(tool, "github:pleme-io/nix")),
                None,
                "{tool:?} resolves remote refs natively"
            );
        }
    }

    /// And sui IS reachable — the variant is gated, not dead. An absolute
    /// path is the one shape it can resolve, so that pairing passes the
    /// flake-ref check (the binary may still be absent on a given host, which
    /// is a separate, correctly-typed failure).
    #[test]
    fn sui_against_an_absolute_path_passes_the_flake_ref_check() {
        assert_eq!(
            flake_ref_failure(&cfg_with(RebuildTool::Sui, "/srv/nix-checkouts")),
            None,
            "an absolute path is exactly what sui's parser accepts"
        );
    }

    /// The message has to name both halves — a refusal an operator cannot act
    /// on reproduces the opacity this whole vocabulary exists to remove.
    #[test]
    fn the_refusal_names_the_tool_and_the_url() {
        let msg = PreflightFailure::FlakeRefUnsupported {
            tool: "/run/current-system/sw/bin/sui",
            flake_url: "github:pleme-io/nix".to_owned(),
        }
        .to_string();
        assert!(msg.contains("sui"), "{msg}");
        assert!(msg.contains("github:pleme-io/nix"), "{msg}");
    }
}

#[cfg(test)]
mod health_report_tests {
    use super::{should_report, Health};

    fn converged() -> Health {
        Health::Converged {
            last_ok: "28638ed".to_owned(),
        }
    }

    /// The ryn 2026-08-06 outage, pinned at the level it actually broke.
    ///
    /// The daemon printed DEGRADED once at 07:28 and then said nothing for
    /// the 19.5 hours it spent failing. It was alive, so KeepAlive was
    /// satisfied; it was ticking, so nothing looked hung. A degraded loop
    /// must speak on every tick, not once per process.
    #[test]
    fn degraded_reports_on_every_tick() {
        let d = Health::Degraded {
            streak: 9,
            last_ok: "28638ed".to_owned(),
        };
        assert!(should_report(&d, &d), "a persistently degraded loop stays loud");
    }

    /// Starved is not broken, but it is still not converged — it means the
    /// branch is outrunning the builder, which an operator may want to know.
    #[test]
    fn starved_reports_on_every_tick() {
        let s = Health::Starved {
            deferrals: 2,
            last_ok: "28638ed".to_owned(),
        };
        assert!(should_report(&s, &s));
    }

    /// The silence that makes the noise credible. Without it a healthy node
    /// prints an info line every poll interval, and an operator learns to
    /// filter the word — which is the failure the DEGRADED/STARVED split
    /// exists to prevent.
    #[test]
    fn converged_stays_quiet() {
        assert!(!should_report(&converged(), &converged()));
    }

    /// Recovery is announced once, so the log shows when it stopped.
    #[test]
    fn recovery_is_announced_once() {
        let broken = Health::Degraded {
            streak: 9,
            last_ok: "28638ed".to_owned(),
        };
        assert!(should_report(&broken, &converged()), "the recovery tick speaks");
        assert!(
            !should_report(&converged(), &converged()),
            "the tick after recovery is silent again"
        );
    }

    /// An empty chain has a zero failure streak, so a naive `streak == 0`
    /// would call a loop that has NEVER deployed converged. Absence of
    /// failure is not evidence of convergence.
    #[test]
    fn never_deployed_is_not_converged() {
        assert!(should_report(&Health::NeverDeployed, &Health::NeverDeployed));
    }

    /// If the chain cannot be read, the one durable record of whether we
    /// converge is unavailable — that is a finding, not a quiet state.
    #[test]
    fn unreadable_chain_reports() {
        let u = Health::Unreadable {
            error: "permission denied".to_owned(),
        };
        assert!(should_report(&u, &u));
    }
}

#[cfg(test)]
mod gate_tests {
    use super::convergence_gate;
    use sentinela_core::Heartbeat;

    const POLL: u64 = 60;
    /// Wall clock used by every case; the numbers below are offsets from it.
    const NOW_MS: u64 = 1_785_724_816_000;

    /// The cid 2026-08-03 recurrence, pinned at the level it actually broke.
    ///
    /// `Phase` was added 2026-08-02 and `convergence_gate` has matched on it
    /// correctly ever since — the tests below already prove that. What was
    /// NOT proven is that the verdict SURVIVES THE WIRE: `status` published
    /// neither `phase` nor a verdict, so `fleet rebuild` re-derived one from
    /// `last_tick_at_unix_ms` + `poll_seconds` and reproduced the exact bug
    /// that had just been fixed one layer down. A 29-minute darwin build
    /// reported STOPPED while it was converging normally.
    ///
    /// So this asserts the two verdicts AGREE on the case that separates
    /// them. If `status` ever stops carrying the phase-aware answer, the
    /// in-flight arm here goes red — which is the only thing that would have
    /// caught the recurrence.
    #[test]
    fn a_build_longer_than_the_stale_budget_is_never_reported_stopped() {
        let budget_ms = 3 * POLL * 1000;
        // Well past the budget — 29 minutes, the measured cid case.
        let ancient = NOW_MS - (29 * 60 * 1000);
        assert!(
            ancient < NOW_MS - budget_ms,
            "the fixture must exceed the budget"
        );

        assert!(
            convergence_gate(&in_flight_beat_at(ancient), NOW_MS, POLL, BUILD_BUDGET, 0, true).is_ok(),
            "a tick still inside its build has not missed a cycle — it is doing the work"
        );

        // The same timestamp with a RESOLVED phase IS stopped. Without this
        // half the test would pass on a gate that ignored staleness entirely.
        let err = convergence_gate(&beat_at(ancient), NOW_MS, POLL, BUILD_BUDGET, 0, true)
            .expect_err("a finished tick that old means the loop stopped");
        assert!(err.contains("stopped"), "got: {err}");
    }

    /// The build ceiling the gate is handed. Comfortably larger than every
    /// legitimate-build fixture below (12m, 29m), so those keep meaning
    /// exactly what they meant — and small enough that the hang fixture is
    /// unambiguously past it.
    const BUILD_BUDGET: u64 = 2700;

    fn beat_at(ms: u64) -> Option<Heartbeat> {
        Some(Heartbeat {
            at_unix_ms: ms,
            outcome: "unchanged".to_owned(),
            phase: sentinela_core::Phase::Resolved,
            head_rev: None,
            poll_seconds: POLL,
            in_flight: None,
        })
    }

    /// A pulse from a tick that is still inside its build.
    fn in_flight_beat_at(ms: u64) -> Option<Heartbeat> {
        Some(Heartbeat {
            at_unix_ms: ms,
            outcome: "building".to_owned(),
            phase: sentinela_core::Phase::InFlight,
            head_rev: None,
            poll_seconds: POLL,
            // These fixtures predate per-drv progress and stay that way on
            // purpose: the gate's staleness verdict must not depend on a
            // driver being able to report steps.
            in_flight: None,
        })
    }

    #[test]
    fn a_long_build_is_not_a_stopped_loop() {
        // THE REGRESSION TEST FOR THE FALSE VERDICT. Measured on ryn
        // 2026-08-02: a 12m02s build produced 722s of silence against a 180s
        // budget (STALE_AFTER_POLLS 3 × poll 60), and the gate reported "the
        // loop is stopped, not idle" while the loop was converging normally.
        // 722s is far past the budget on purpose — the point is that the
        // phase, not the elapsed time, decides.
        let silent_ms = 722_000;
        assert!(
            silent_ms > 3 * POLL * 1000,
            "the scenario must exceed the budget, or this proves nothing"
        );
        assert_eq!(
            convergence_gate(&in_flight_beat_at(NOW_MS - silent_ms), NOW_MS, POLL, BUILD_BUDGET, 0, true),
            Ok(()),
            "a build in flight is work, not silence"
        );
        // And the same silence from a RESOLVED tick is still a stopped loop —
        // otherwise the fix would have deleted the check rather than scoped it.
        assert!(
            convergence_gate(&beat_at(NOW_MS - silent_ms), NOW_MS, POLL, BUILD_BUDGET, 0, true).is_err(),
            "a resolved tick that old IS a stopped loop"
        );
    }

    #[test]
    fn an_in_flight_pulse_does_not_mask_a_real_failure_streak() {
        // The phase exempts a build from the STALENESS check only. A loop
        // that is building while its last ticks failed is still degraded.
        assert!(
            convergence_gate(&in_flight_beat_at(NOW_MS - 722_000), NOW_MS, POLL, BUILD_BUDGET, 3, true).is_err(),
            "in-flight must not suppress the failure-streak verdict"
        );
    }

    /// ── ★ THE CASE THE OLD SURFACE GOT WRONG ─────────────────────────────
    /// `sentinela status` exited 0 unconditionally, so every monitor that
    /// could have been built on it would have read a dead daemon as fine.
    /// No evidence must be a refusal, not a pass.
    #[test]
    fn no_heartbeat_is_a_refusal_not_a_pass() {
        let err = convergence_gate(&None, NOW_MS, POLL, BUILD_BUDGET, 0, true)
            .expect_err("absent liveness evidence must never gate green");
        assert!(err.contains("no heartbeat"), "{err}");
    }

    /// cid's real numbers: last tick 1785664639s, judged at 1785724816s.
    #[test]
    fn cids_16_hour_silence_fails_the_gate() {
        let err = convergence_gate(&beat_at(1_785_664_639_000), NOW_MS, POLL, BUILD_BUDGET, 0, true)
            .expect_err("a loop silent for 16.7h against a 60s poll is stopped");
        assert!(err.contains("60177s"), "{err}");
        assert!(err.contains("stopped, not idle"), "{err}");
    }

    #[test]
    fn a_fresh_tick_on_a_verified_chain_passes() {
        convergence_gate(&beat_at(NOW_MS - 30_000), NOW_MS, POLL, BUILD_BUDGET, 0, true)
            .expect("a loop that ticked 30s ago on a 60s poll is alive");
    }

    /// Exactly at the 3-interval budget is still alive; one ms past is not.
    /// Pinned because an off-by-one here either cries wolf every few
    /// minutes or never fires at all.
    #[test]
    fn the_staleness_boundary_is_three_poll_intervals() {
        let budget_ms = 3 * POLL * 1000;
        convergence_gate(&beat_at(NOW_MS - budget_ms), NOW_MS, POLL, BUILD_BUDGET, 0, true)
            .expect("exactly at the budget is not yet stale");
        convergence_gate(&beat_at(NOW_MS - budget_ms - 1), NOW_MS, POLL, BUILD_BUDGET, 0, true)
            .expect_err("one millisecond past the budget is stale");
    }

    #[test]
    fn a_failure_streak_fails_even_with_a_fresh_pulse() {
        let err = convergence_gate(&beat_at(NOW_MS - 1000), NOW_MS, POLL, BUILD_BUDGET, 4136, true)
            .expect_err("the ryn outage shape must not gate green");
        assert!(err.contains("4136"), "{err}");
    }

    #[test]
    fn an_unverifiable_chain_fails_before_anything_else_is_considered() {
        let err = convergence_gate(&beat_at(NOW_MS - 1000), NOW_MS, POLL, BUILD_BUDGET, 0, false)
            .expect_err("tamper-evidence outranks liveness");
        assert!(err.contains("verification"), "{err}");
    }
}

// ── The operator-facing face of `status` ────────────────────────────────
//
// ── ★ WHY THIS EXISTS: A DOCUMENT IS NOT A VERDICT ──────────────────────
// `status` printed one pretty-printed JSON object and nothing else. Every
// field it needed was in there and it was still not *readable*: the answer
// ("is this node converging?") sat in a nested `converged.ok` two thirds of
// the way down, next to an epoch-milliseconds timestamp and two 40-char
// hex revs that the reader has to compare character by character.
//
// Measured cost, 2026-08-07: over one session an operator-agent piped this
// command through a hand-written Python parser THREE separate times purely
// to answer "is it healthy and how old is the last tick" — converting
// `last_tick_at_unix_ms` by hand each time. A surface that every reader
// rewrites a parser for is not a surface, it is a data dump.
//
// So the view answers, in order of how urgently a human needs it:
//   1. the VERDICT, first line, one word, coloured, with a glyph — legible
//      before the eye reaches the second line;
//   2. WHY, immediately under it, only when the answer is not "fine";
//   3. deployed and head ADJACENT, with an explicit marker when they
//      differ, so "behind" is seen rather than computed;
//   4. durations in human units — `42s`, `36m`, `2h03m` — never epochs;
//   5. what to run next, when there is a next thing to run.
//
// The JSON is not gone and not reshaped: `--json` prints the identical
// document. A machine consumer adds one flag; a human stops needing one.
//
// TYPED EMISSION: this is a `Display` impl driven by `write!`, which is the
// sanctioned emission surface — not `format!` of a rendered blob.
//
// TIER: only-mitigated. Nothing stops a future field from being added to
// the JSON and never surfacing here; the two are hand-kept in step.
// DESTINATION: `kazari` (飾り), the fleet's typed line-output primitive, so
// the block is DERIVED from the typed status rather than written twice.
// Not adopted here because it is a new dependency, and this crate's
// `Cargo.lock` is mid-`gen`-regeneration for the tsunagu bump.
// `pending-despacho: status-view-through-kazari`
struct StatusView<'a>(&'a serde_json::Value);

/// ANSI, applied only when the stream is a terminal and `NO_COLOR` is unset.
fn paint(s: &str, code: &str) -> String {
    use std::io::IsTerminal as _;
    if std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal() {
        ["\x1b[", code, "m", s, "\x1b[0m"].concat()
    } else {
        s.to_owned()
    }
}

/// Epoch-milliseconds → the age a human reads at a glance.
///
/// The whole point of the view: `1786134280041` tells a reader nothing
/// without arithmetic, and the arithmetic is where the mistakes live —
/// this session mis-read one such number as a ratio against the poll
/// interval and published a false claim off it.
fn human_age(then_ms: u64, now_ms: u64) -> String {
    let secs = now_ms.saturating_sub(then_ms) / 1000;
    match secs {
        0..=59 => [&secs.to_string(), "s"].concat(),
        60..=3599 => [&(secs / 60).to_string(), "m", &(secs % 60).to_string(), "s"].concat(),
        3600..=86399 => [&(secs / 3600).to_string(), "h", &((secs % 3600) / 60).to_string(), "m"].concat(),
        _ => [&(secs / 86400).to_string(), "d", &((secs % 86400) / 3600).to_string(), "h"].concat(),
    }
}

/// First 8 chars of a rev — enough to compare two by eye, which is the job.
fn short(rev: &str) -> &str {
    rev.get(..8).unwrap_or(rev)
}

/// The command that actually helps, given the numbers.
///
/// Pure so the three branches are testable; a hint buried in a `Display` impl
/// is a hint nobody checks.
///
/// Classified from NUMERIC fields, never by matching the prose in `why`: a
/// human-readable sentence is not a stable key, and a hint keyed on one
/// silently stops matching the moment the wording moves.
fn next_step(
    last_tick_at_unix_ms: Option<u64>,
    now_ms: u64,
    poll_seconds: u64,
    consecutive_failures: u64,
) -> &'static str {
    let stopped = match last_tick_at_unix_ms {
        // Never ticked: it has not started, which is the stopped case.
        None => true,
        Some(t) => now_ms.saturating_sub(t) > poll_seconds.max(1) * 3 * 1000,
    };
    if stopped {
        // The loop is not running. Restarting it is the fix, and NOTHING else
        // helps until it is — reading logs of a dead process is a detour.
        "sudo launchctl kickstart -k system/org.nixos.pleme-gitops"
    } else if consecutive_failures > 0 {
        // Running and failing: the build output is the evidence.
        "log show --predicate 'process == \"sentinela\"' --last 30m"
    } else {
        // Running, not failing, still behind — the probe half decides what to
        // build, so that is the half to interrogate.
        "sentinela probe"
    }
}

impl std::fmt::Display for StatusView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v = self.0;
        let s = |k: &str| v.get(k).and_then(serde_json::Value::as_str).unwrap_or("—").to_owned();
        let n = |k: &str| v.get(k).and_then(serde_json::Value::as_u64);

        let ok = v.pointer("/converged/ok").and_then(serde_json::Value::as_bool).unwrap_or(false);
        let why = v.pointer("/converged/why").and_then(serde_json::Value::as_str);

        let (glyph, word, colour) = if ok {
            ("●", "CONVERGED", "32;1")
        } else {
            ("✗", "NOT CONVERGED", "31;1")
        };
        writeln!(f)?;
        writeln!(f, "  {} {:<44}{}", paint(glyph, colour), paint(word, colour), paint(&s("hostname"), "1"))?;
        if let Some(w) = why {
            writeln!(f, "    {:<11} {}", "why", paint(w, "31"))?;
        }
        writeln!(f)?;

        writeln!(f, "    {:<11} {} · {}", "tracking", s("flake_url"), s("branch"))?;

        // Deployed and head ADJACENT — the comparison is the diagnosis.
        let deployed = v.get("last_activated_rev").and_then(serde_json::Value::as_str);
        let head = v.get("head_rev").and_then(serde_json::Value::as_str);
        writeln!(f, "    {:<11} {}", "deployed", deployed.map_or("— never activated".to_owned(), |r| short(r).to_owned()))?;
        match (deployed, head) {
            (Some(d), Some(h)) if d == h => writeln!(f, "    {:<11} {}  {}", "head", short(h), paint("(in sync)", "32"))?,
            (_, Some(h)) => writeln!(f, "    {:<11} {}  {}", "head", short(h), paint("← BEHIND", "33;1"))?,
            (_, None) => writeln!(f, "    {:<11} {}", "head", paint("— the last tick resolved no branch head", "33"))?,
        }

        // Liveness, in units a human owns.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let tick = match n("last_tick_at_unix_ms") {
            Some(t) => [
                &human_age(t, now_ms), " ago · ", &s("last_tick_outcome"), " · ", &s("phase"),
            ].concat(),
            None => paint("no heartbeat has ever been published", "31").to_string(),
        };
        writeln!(f, "    {:<11} {}   {}", "last tick", tick,
                 paint(&["(poll ", &n("poll_seconds").unwrap_or(0).to_string(), "s)"].concat(), "2"))?;

        // ── WHY IT FAILED, on the panel, not in a 38 MB log ──────────────
        //
        // Printed directly under the liveness line because that is where the
        // eye already is once `last tick` says `buildFailed`, and the very
        // next question is always "failed at what". Everything here was
        // already on disk; the only thing missing was showing it.
        if let Some(lines) = v.get("last_failure").and_then(serde_json::Value::as_array) {
            if !lines.is_empty() {
                writeln!(f)?;
                writeln!(f, "    {:<11} {}", "failure", paint("the last tick failed at", "31;1"))?;
                for l in lines {
                    if let Some(t) = l.as_str() {
                        writeln!(f, "      {}", paint(t, "31"))?;
                    }
                }
            }
        }

        let verified = v.get("chain_verified").and_then(serde_json::Value::as_bool).unwrap_or(false);
        writeln!(f, "    {:<11} {} · chain {}", "receipts", n("receipts").unwrap_or(0),
                 if verified { paint("verified", "32") } else { paint("UNVERIFIED", "31;1") })?;

        let fails = n("consecutive_failures").unwrap_or(0);
        let defers = n("consecutive_deferrals").unwrap_or(0);
        // 0/0 healthy · n/0 broken · 0/n starved — the doc's own reading.
        let streaks = [
            &if fails == 0 { paint("0 failures", "32") } else { paint(&[&fails.to_string(), " failures"].concat(), "31;1") },
            " · ",
            &if defers == 0 { paint("0 deferrals", "32") } else { paint(&[&defers.to_string(), " deferrals"].concat(), "33;1") },
        ].concat();
        writeln!(f, "    {:<11} {}", "streaks", streaks)?;

        if !ok {
            // The next step must match WHY it is not converged, and must exist
            // on the platform. This used to print `journalctl -u pleme-gitops`
            // unconditionally — a Linux command, from a daemon whose own
            // --help calls itself "Darwin GitOps node-sync daemon", offered
            // identically for three failure modes that need three different
            // actions. It sent the reader to a command that does not exist.
            //
            // Classified from the NUMERIC fields, never by matching the prose
            // in `why`: a human-readable sentence is not a stable key, and a
            // hint keyed on one silently stops matching when the wording moves.
            let next = next_step(
                n("last_tick_at_unix_ms"),
                now_ms,
                n("poll_seconds").unwrap_or(60),
                fails,
            );
            writeln!(f)?;
            writeln!(f, "    {:<11} {}", "next", paint(next, "36"))?;
        }
        writeln!(f)
    }
}

#[cfg(test)]
mod next_step_tests {
    use super::next_step;

    const NOW: u64 = 1_000_000_000;
    const FRESH: u64 = NOW - 10 * 1000;
    const STALE: u64 = NOW - 12 * 3600 * 1000;

    /// A dead loop must be told to RESTART. This is the case that cost 12
    /// hours: sentinela was stopped, and `status` said
    /// `journalctl -u pleme-gitops` — a Linux command, from a daemon whose own
    /// --help calls itself "Darwin GitOps node-sync daemon". Reading the logs
    /// of a dead process is a detour; restarting it is the fix.
    #[test]
    fn a_stopped_loop_is_told_to_restart() {
        assert!(next_step(Some(STALE), NOW, 60, 0).starts_with("sudo launchctl kickstart"));
        // Never ticked at all is the same case, not a special one.
        assert!(next_step(None, NOW, 60, 0).starts_with("sudo launchctl kickstart"));
    }

    /// A LIVE loop that is failing needs the build output, not a restart —
    /// restarting a working loop only loses its place.
    #[test]
    fn a_live_failing_loop_is_pointed_at_the_logs() {
        assert!(next_step(Some(FRESH), NOW, 60, 3).contains("log show"));
    }

    /// Live, not failing, still behind: the probe half decides what to build.
    #[test]
    fn a_live_healthy_but_behind_loop_is_pointed_at_the_probe() {
        assert_eq!(next_step(Some(FRESH), NOW, 60, 0), "sentinela probe");
    }

    /// No hint may name a Linux-only tool. This binary is Darwin-only, and a
    /// Linux command is exactly what the single hardcoded hint used to be.
    #[test]
    fn no_hint_is_a_linux_only_command() {
        let all = [
            next_step(Some(STALE), NOW, 60, 0),
            next_step(None, NOW, 60, 0),
            next_step(Some(FRESH), NOW, 60, 3),
            next_step(Some(FRESH), NOW, 60, 0),
        ];
        // The denominator: every branch must be represented, or this passes
        // while checking a subset of them.
        assert_eq!(all.len(), 4, "all four branches must be exercised");
        for h in all {
            assert!(!h.contains("journalctl"), "Linux-only hint on a Darwin daemon: {h}");
            assert!(!h.contains("systemctl"), "Linux-only hint on a Darwin daemon: {h}");
            assert!(!h.is_empty(), "an empty hint is worse than none");
        }
    }

    /// The stopped threshold tracks the CONFIGURED poll rather than a
    /// hardcoded number — a slow-polling node must not be called stopped for
    /// ticking exactly on schedule.
    #[test]
    fn the_stopped_threshold_scales_with_the_poll_interval() {
        let age_10min = NOW - 600 * 1000;
        assert!(next_step(Some(age_10min), NOW, 60, 0).starts_with("sudo launchctl"));
        assert_eq!(next_step(Some(age_10min), NOW, 600, 0), "sentinela probe");
    }
}

/// The distilled cause of the most recent failed receipt, newest first.
///
/// `None` when the chain's latest failure is older than its latest success —
/// a fixed problem must stop being reported, or the panel becomes a place
/// operators learn to ignore.
fn last_failure_lines(chain: &sentinela_core::ReceiptChain) -> Option<Vec<String>> {
    let mut seen_success = false;
    for r in chain.entries().iter().rev() {
        match &r.outcome {
            sentinela_core::Outcome::Activated { .. } => seen_success = true,
            sentinela_core::Outcome::Failed { error } if !seen_success => {
                return Some(distill_failure(error));
            }
            _ => {}
        }
    }
    None
}

/// Reduce a nix build failure to the lines that name the CAUSE.
///
/// # Why this exists
///
/// A failed darwin build writes hundreds of lines of which almost all are
/// cascade: every derivation downstream of the one that actually broke
/// reports `Cannot build …` / `Reason: 1 dependency failed` / `Output paths`.
/// Diagnosing cid on 2026-08-12 meant grepping a 38 MB log, then a receipts
/// file, then filtering four kinds of cascade noise, to arrive at ONE line:
///
/// ```text
/// build failed: …-rust_serde_derive_internals-0.29.1.drv
/// ```
///
/// Everything needed to print that was already on disk. The operator should
/// never have to do that walk, so `status` does it.
///
/// The rule is subtractive on purpose — drop the shapes that are known to be
/// consequence, keep the rest — because an allowlist of "real" errors would
/// silently swallow a failure mode nobody had seen yet. Keeping too much is a
/// worse panel; keeping too little is a lie.
fn distill_failure(raw: &str) -> Vec<String> {
    /// A line that is downstream noise rather than a cause.
    fn is_cascade(l: &str) -> bool {
        let t = l.trim();
        t.is_empty()
            || t.starts_with("Reason:")
            || t.starts_with("Output paths:")
            || t.starts_with("/nix/store/")
            || t.contains("Build failed due to failed dependency")
            || t.contains("Cannot build '")
            || t.starts_with("building '")
            || t.starts_with("unpacking ")
            || t.starts_with("these ")
            || t.starts_with("copying ")
            || t.starts_with("warning:")
    }

    let mut out: Vec<String> = Vec::new();
    for line in raw.lines() {
        if is_cascade(line) {
            continue;
        }
        let t = line.trim().to_owned();
        // Collapse the exact repeats a cascade produces — the same
        // `build failed: X` is emitted once per dependent.
        if out.last().map(String::as_str) == Some(t.as_str()) {
            continue;
        }
        out.push(t);
    }
    out.dedup();

    // Bound it. A panel is a summary; the receipt keeps the whole text.
    const MAX_LINES: usize = 6;
    if out.len() > MAX_LINES {
        let dropped = out.len() - MAX_LINES;
        out.truncate(MAX_LINES);
        let mut note = String::from("… ");
        note.push_str(&dropped.to_string());
        note.push_str(" more line(s) in the receipt");
        out.push(note);
    }
    out
}

#[cfg(test)]
mod distill_tests {
    use super::distill_failure;

    /// **THE MEASURED CASE.** The real cid failure: one causal line buried in
    /// cascade. If this ever stops surfacing `serde_derive_internals`, the
    /// panel has gone back to being a wall of consequence.
    #[test]
    fn the_root_cause_survives_the_cascade() {
        let raw = "\
building '/nix/store/aaa-rust_thing.drv'...
      build failed: bylq-rust_serde_derive_internals-0.29.1.drv
        /nix/store/412niara-rust_async-trait-0.1.89.drv
      error: Cannot build '/nix/store/397p-home-manager-generation.drv'.
             Reason: 1 dependency failed.
             Output paths:
               /nix/store/9m25-home-manager-generation
      error: Build failed due to failed dependency
";
        let out = distill_failure(raw);
        assert!(
            out.iter().any(|l| l.contains("serde_derive_internals")),
            "the cause must survive: {out:?}",
        );
        assert!(
            !out.iter().any(|l| l.contains("Cannot build")),
            "the cascade must not: {out:?}",
        );
        assert!(
            !out.iter().any(|l| l.contains("home-manager-generation")),
            "nor its output paths: {out:?}",
        );
    }

    /// Repeats collapse — a cascade emits the same causal line once per
    /// dependent, and six copies of one line is not six facts.
    #[test]
    fn repeated_causes_collapse_to_one() {
        let raw = "      build failed: X.drv\n      build failed: X.drv\n      build failed: X.drv\n";
        assert_eq!(distill_failure(raw), vec!["build failed: X.drv".to_owned()]);
    }

    /// An unrecognised failure shape is KEPT. The filter is subtractive so a
    /// mode nobody has seen yet still reaches the operator.
    #[test]
    fn an_unknown_error_shape_is_kept_rather_than_swallowed() {
        let raw = "error: attribute 'darwinConfigurations.cid' missing\n";
        let out = distill_failure(raw);
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("attribute"), "{out:?}");
    }

    /// Bounded, and it says so — a truncation that looks like the whole story
    /// is how a panel starts lying.
    #[test]
    fn a_long_failure_is_bounded_and_says_it_was() {
        let raw: String = (0..40)
            .map(|i| {
                let mut l = String::from("error: distinct problem ");
                l.push_str(&i.to_string());
                l.push('\n');
                l
            })
            .collect();
        let out = distill_failure(&raw);
        assert_eq!(out.len(), 7, "6 lines + the elision note: {out:?}");
        assert!(out.last().expect("note").contains("more line(s)"), "{out:?}");
    }
}

#[cfg(test)]
mod hang_gate_tests {
    use super::convergence_gate;
    use sentinela_core::Heartbeat;

    const NOW_MS: u64 = 1_785_724_816_000;
    const POLL: u64 = 60;
    const BUILD_BUDGET: u64 = 2700;

    fn in_flight_at(ms: u64) -> Option<Heartbeat> {
        Some(Heartbeat {
            at_unix_ms: ms,
            outcome: "building".to_owned(),
            phase: sentinela_core::Phase::InFlight,
            head_rev: None,
            poll_seconds: POLL,
            in_flight: None,
        })
    }

    /// **THE MEASURED BUG.** cid, 2026-08-12: a tick sat `building` for
    /// 4h39m — the daemon had in fact been dead since it wrote that phase —
    /// and `status` printed `● CONVERGED` the whole time, beside its own
    /// `← BEHIND` and `4h40m ago · building`. The in-flight arm exempted a
    /// build from the poll budget, correctly, and from every other bound too.
    #[test]
    fn a_build_past_its_own_budget_is_a_hang_not_progress() {
        let stuck = NOW_MS - (4 * 3600 + 39 * 60) * 1000;
        let err = convergence_gate(&in_flight_at(stuck), NOW_MS, POLL, BUILD_BUDGET, 0, true)
            .expect_err("a 4h39m build is a hang, and must not gate green");
        assert!(err.contains("hang"), "the reason must say so: {err}");
        assert!(err.contains("2700"), "and name the budget: {err}");
    }

    /// And the fix must not undo what it scoped: a build INSIDE its budget is
    /// still work, not silence, however far past the poll budget it is.
    #[test]
    fn a_build_inside_its_budget_is_still_work() {
        let running = NOW_MS - 29 * 60 * 1000; // the measured 29-minute case
        assert!(
            29 * 60 > 3 * POLL,
            "the fixture must exceed the POLL budget or it proves nothing",
        );
        assert_eq!(
            convergence_gate(&in_flight_at(running), NOW_MS, POLL, BUILD_BUDGET, 0, true),
            Ok(()),
            "29m < 45m budget — converging normally",
        );
    }

    /// The boundary is the configured ceiling, not a constant invented here:
    /// a smaller configured budget makes the same build a hang.
    #[test]
    fn the_budget_is_the_operators_not_a_hardcoded_one() {
        let running = NOW_MS - 29 * 60 * 1000;
        assert!(
            convergence_gate(&in_flight_at(running), NOW_MS, POLL, 600, 0, true).is_err(),
            "29m against a 10m ceiling is past it",
        );
    }
}
