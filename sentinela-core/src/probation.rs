//! Health-gated rollback — the typed vocabulary for "an activation is not
//! finished until the machine proves it survived it".
//!
//! ── ★ THE GAP THIS CLOSES ───────────────────────────────────────────────
//! Every guard the loop had before this module is about WHICH rev to
//! activate: fail-closed, skip-if-unchanged, no-downgrade, the two
//! starvation escapes. None of them says anything about what happens AFTER
//! a switch returns `Ok`. A generation that builds and activates cleanly can
//! still drop the network, kill `tailscaled`, or wedge the daemon that would
//! have to notice — and the loop, having attested `Activated`, would sit on
//! that generation until a human arrived. For a node run as an unattended
//! server (cid) that human is the whole problem.
//!
//! So an activation now optionally enters PROBATION: the loop runs the
//! operator's probes until they pass a required number of consecutive times,
//! or the window closes on a failing round, in which case the PREVIOUS system
//! generation is re-activated and the rev is quarantined.
//!
//! ── ★ A ROLLBACK IS NOT THE NO-DOWNGRADE RULE ───────────────────────────
//! No-downgrade refuses to activate a rev the BRANCH moved away from; it is a
//! statement about git history. A rollback reverts the SYSTEM PROFILE to the
//! generation that was running before this switch; it is a statement about
//! the machine. The branch is untouched — HEAD is still the bad rev — which
//! is exactly why the rev must then be quarantined: otherwise the very next
//! tick would see "HEAD != last activated" and re-deploy it.
//!
//! Everything here is pure data. The side effects (running a probe, reading
//! the profile generation, re-activating one) are [`crate::GitopsEnv`]
//! methods, so every path is provable against the mock.

use crate::receipt::Generation;
use crate::rev::Rev;
use serde::{Deserialize, Serialize};

/// One health probe, already validated by the config layer.
///
/// Constructed only from a config entry that parsed and passed validation —
/// see `sentinela_config::RollbackConfig::plan` — so the FSM never meets an
/// empty argv or an unbounded timeout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthProbe {
    /// The operator's name for it. Names are unique within a policy, so the
    /// name alone identifies which check failed in a receipt.
    pub name: String,
    /// What the probe does.
    pub check: ProbeCheck,
}

/// The closed set of things a probe can check.
///
/// Closed on purpose: each kind needs its own runner in the real env, and a
/// kind the binary cannot run must be refused at config load (by name, with
/// its siblings still loading) rather than accepted and then failing every
/// round — which would roll back every deploy forever.
///
/// There is no `http` kind: no HTTP client exists in this workspace's default
/// build (the ones in `Cargo.lock` arrive only with the optional `sui-driver`
/// feature), and adding one for a probe would be a large dependency for a
/// check `command` already expresses with an absolute `curl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ProbeCheck {
    /// Run `argv` directly — never through a shell — and require
    /// `expect_exit`, within `timeout_seconds`.
    Command {
        /// The program and its arguments. `argv[0]` is an absolute path: a
        /// daemon started by launchd/systemd has no useful `$PATH`.
        argv: Vec<String>,
        /// The exit status that means healthy.
        expect_exit: i32,
        /// How long one run may take before it counts as a failure. Always
        /// positive — an unbounded probe could wedge the tick it runs in.
        timeout_seconds: u64,
    },
}

/// The effective rollback policy — present only when rollback is enabled AND
/// at least one probe survived validation.
///
/// ── ★ ZERO PROBES IS NOT A PASSING POLICY ──────────────────────────────
/// A policy with no probes would "verify" every activation vacuously, which
/// reads in the chain as a proof of health that nobody took. The config layer
/// therefore yields no policy at all in that case, and says so, rather than a
/// policy whose every round trivially passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackPolicy {
    /// How long after the switch a failing round may still recover before the
    /// loop rolls back, in milliseconds.
    pub window_ms: u64,
    /// Seconds between probe rounds while in probation.
    pub interval_seconds: u64,
    /// Consecutive passing rounds required to call the activation verified.
    /// Always at least 1.
    pub required_consecutive_passes: u32,
    /// The probes, run in order each round; the first failure ends the round.
    pub probes: Vec<HealthProbe>,
}

/// Which probe failed, and what it said.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeFailure {
    /// The failing probe's configured name.
    pub probe: String,
    /// Exit status and the tail of its output, bounded to
    /// [`crate::receipt::MAX_ERROR_BYTES`] — this lands in the append-only
    /// chain on a rollback, and a failing probe must not write its own weight
    /// to disk any more than a failing build may.
    pub evidence: String,
}

/// An activation under probation — the between-tick state, and what the
/// heartbeat publishes while it lasts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Probation {
    /// The rev that was activated.
    pub rev: Rev,
    /// The generation that activation produced — the one being judged.
    pub generation: Generation,
    /// The generation running before the switch, read BEFORE it — the
    /// rollback target.
    pub previous_generation: Generation,
    /// When a failing round stops being allowed to recover, unix-ms.
    pub deadline_unix_ms: u64,
    /// The current consecutive-pass streak.
    pub passes: u32,
    /// The streak that verifies the activation.
    pub required_passes: u32,
    /// The most recent round's failure, if the most recent round failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure: Option<ProbeFailure>,
}
