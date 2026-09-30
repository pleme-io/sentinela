//! sentinela-config — the shikumi-typed config surface for the Darwin
//! GitOps daemon. It mirrors, field-for-field, the `pleme.gitops` nix
//! option surface (`modules/pleme/darwin/gitops.nix`): the nix module
//! renders this struct to a yaml file the daemon loads. Two tiers per the
//! shikumi discipline — [`bare`](shikumi::TieredConfig::bare) is the
//! zero-opinion floor, [`prescribed_default`](shikumi::TieredConfig::prescribed_default)
//! is the shipped posture (60s poll, 5-minute failure cooldown, `main`).
//!
//! Node-specific coordinates (`flake_url` / `hostname` / probe
//! `git_url`) have no universal default — the nix module fills them from
//! the node's identity; both tiers leave them empty so a mis-render is a
//! visible empty string, never a wrong silent default.

use serde::{Deserialize, Serialize};

/// The freshness-guard probe (git-protocol HEAD resolution). Always
/// present in v2 (the v1.5 `revProbe = null` bare path is retired — the
/// daemon is always guarded).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RevProbeConfig {
    /// HTTPS git URL to `ls-remote` (e.g. `https://github.com/pleme-io/nix`).
    pub git_url: String,
    /// Branch whose HEAD is tracked.
    pub branch: String,
    /// Optional file holding a token; when set, injected as
    /// `x-access-token` into the https URL for private-repo probes.
    pub token_file: Option<String>,
}

impl Default for RevProbeConfig {
    fn default() -> Self {
        Self::prescribed()
    }
}

impl RevProbeConfig {
    /// Zero-opinion floor.
    #[must_use]
    pub fn bare() -> Self {
        Self {
            git_url: String::new(),
            branch: String::new(),
            token_file: None,
        }
    }

    /// Shipped: `main`, no token (public-repo default; the module sets a
    /// token_file for private repos).
    #[must_use]
    pub fn prescribed() -> Self {
        Self {
            git_url: String::new(),
            branch: "main".to_owned(),
            token_file: None,
        }
    }
}

/// WHICH FORM of flake reference a rebuild tool can resolve.
///
/// ── ★ NOT A STYLE DIFFERENCE — THE ONE THING BLOCKING P5 ────────────────
/// sentinela's entire safety model is a **rev-pinned remote** flake ref: it
/// resolves branch HEAD over the git protocol and then builds
/// `<flake_url>/<rev>#<hostname>` (`sentinela::real_env::RealEnv::flake_ref`).
/// `darwin-rebuild`/`nixos-rebuild` hand that string to nix, which fetches the
/// rev. sui **cannot**: `sui_compat::flake_ref::FlakeRef::parse`
/// (`sui/sui-compat/src/flake_ref.rs:37-58`) splits on `#` and treats the left
/// half as a *filesystem path* — there is no fetcher on that path at all — and
/// `sui_eval::builtins::evaluate_flake`
/// (`sui/sui-eval/src/builtins/flake_eval.rs:43`) takes a `&Path`.
///
/// MEASURED, cid 2026-08-05, sui 0.1.154:
/// ```text
/// $ sui system rebuild dry-activate \
///     --flake 'github:pleme-io/nix/0123…4567#ryn'
/// Error: rebuild failed: eval: I/O error: getFlake:
///   github:pleme-io/nix/0123…4567/flake.nix: No such file or directory
/// ```
///
/// So this is a TYPED PROPERTY OF THE TOOL, checked before the loop starts.
/// Without it, selecting sui would produce a daemon that fails every tick
/// forever while every liveness surface reads green — the exact class
/// [`crate::RebuildTool`]'s sibling [`sentinela_core::EnvError::ToolMissing`]
/// was introduced to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlakeRefSyntax {
    /// Anything nix itself accepts, including `github:owner/repo/<rev>` — the
    /// rev-pinned remote form this daemon is built around.
    Remote,
    /// A filesystem path only. No fetcher: the ref's left half is opened as a
    /// directory and `flake.nix` read out of it.
    LocalPathOnly,
}

impl FlakeRefSyntax {
    /// Can a tool with this syntax resolve `flake_url` at all?
    ///
    /// Deliberately strict for [`Self::LocalPathOnly`]: only an absolute path
    /// (bare or `path:`-prefixed, both of which sui's parser accepts —
    /// `flake_ref.rs:48`). A relative path would resolve against the daemon's
    /// cwd, which is the state dir, which is not a checkout — a config that
    /// *looks* plausible and cannot work.
    #[must_use]
    pub fn accepts(self, flake_url: &str) -> bool {
        match self {
            Self::Remote => true,
            Self::LocalPathOnly => {
                let bare = flake_url.strip_prefix("path:").unwrap_or(flake_url);
                bare.starts_with('/')
            }
        }
    }
}

/// WHICH rebuild tool the daemon drives — a closed sum, not a path.
///
/// sentinela was Darwin-only until 2026-08-05, and the binary was a `const`
/// in `real_env.rs`. That const is why the fleet's ONLY reconciler carrying
/// the dual starvation escape could not run on a NixOS node: rio ran upstream
/// `comin` instead, which has neither escape, and on 2026-08-04 it discarded
/// 13 generations in 6 hours without landing one.
///
/// A closed sum rather than a configurable path: a free-form path would let a
/// config name a binary that cannot take these arguments — an unrepresentable
/// state made representable for no gain. Each variant therefore carries its
/// own [`argv_prefix`](Self::argv_prefix) and its own
/// [`flake_ref_syntax`](Self::flake_ref_syntax) rather than the sum assuming
/// one shape for all of them, which is what it used to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum RebuildTool {
    /// nix-darwin. The historical behaviour, so it stays the default: an
    /// existing Mac config that never mentions `rebuild_tool` keeps working
    /// byte-for-byte.
    #[default]
    DarwinRebuild,
    /// NixOS.
    NixosRebuild,
    /// sui — the fleet's own pure-Rust nix. **The P5 destination, and NOT
    /// USABLE BY THIS DAEMON YET.**
    ///
    /// ── ★ WHY IT IS HERE ANYWAY (MODULARIZE, DON'T DELETE) ───────────────
    /// `sui-orchestrate` states its own purpose as *"Replaces darwin-rebuild,
    /// nixos-rebuild, deploy-rs, and colmena"*
    /// (`sui/sui-orchestrate/src/lib.rs:3`), so the subprocess this daemon
    /// spawns is a reimplementation boundary against a primitive the fleet
    /// already owns — doctrine P5 / `theory/RECONCILER-LIVENESS.md` §IV.3.
    /// The pipeline behind `sui system rebuild` is real and wired: 10 of 11
    /// surfaces on the marquee path are REAL
    /// (`sui/docs/SUI-SUPREMACY-ROADMAP.md:105-121`), M2.6 closed
    /// (`sui/docs/SUI-EQUIVALENCE.md:110`).
    ///
    /// ── ★ WHY IT CANNOT BE SELECTED TODAY ────────────────────────────────
    /// Its [`flake_ref_syntax`](Self::flake_ref_syntax) is
    /// [`FlakeRefSyntax::LocalPathOnly`], and every real sentinela config
    /// names a remote repo — so `sentinela::preflight` REFUSES the pairing and
    /// the daemon exits rather than failing every tick forever. See
    /// [`FlakeRefSyntax`] for the measured evidence.
    ///
    /// Two things must land before this variant is reachable, and neither is
    /// in this repo:
    /// 1. sui gains a fetcher for `github:owner/repo/<rev>` in `FlakeRef` —
    ///    then this becomes [`FlakeRefSyntax::Remote`] and nothing else moves;
    ///    **or** sentinela materializes each rev into `<flake_url>/<rev>/` and
    ///    the config names an absolute path, which needs a materializer this
    ///    daemon does not have.
    /// 2. sui's byte-identical toplevel is proven, not just built — the loop
    ///    inherits that gate (`sui/docs/CONVERGENCE.md` R5). A node reconciler
    ///    that activates a *different* system than `nix run .#rebuild` is
    ///    worse than one that shells out.
    Sui,
}

impl RebuildTool {
    /// Absolute path, taken from the running system rather than `$PATH` — a
    /// daemon started by launchd/systemd has no useful `$PATH`, and running
    /// as root means no sudo is needed either way.
    #[must_use]
    pub fn binary(self) -> &'static str {
        match self {
            Self::DarwinRebuild => "/run/current-system/sw/bin/darwin-rebuild",
            Self::NixosRebuild => "/run/current-system/sw/bin/nixos-rebuild",
            Self::Sui => "/run/current-system/sw/bin/sui",
        }
    }

    /// Argv words that precede the verb.
    ///
    /// `darwin-rebuild`/`nixos-rebuild` ARE the rebuild command, so the verb
    /// is argv[1]. sui is a multi-command CLI where the same verb lives at
    /// `sui system rebuild <verb>`. This used to be an assumption baked into
    /// `run_rebuild` (`cmd.arg(verb)` first, unconditionally) and stated in
    /// this sum's own doc comment as *"their argv shape is identical"* — true
    /// of two tools, false of the family, and the thing that made a third
    /// tool inexpressible rather than merely unimplemented.
    #[must_use]
    pub fn argv_prefix(self) -> &'static [&'static str] {
        match self {
            Self::DarwinRebuild | Self::NixosRebuild => &[],
            Self::Sui => &["system", "rebuild"],
        }
    }

    /// Which flake-ref forms this tool can resolve. See [`FlakeRefSyntax`].
    #[must_use]
    pub fn flake_ref_syntax(self) -> FlakeRefSyntax {
        match self {
            Self::DarwinRebuild | Self::NixosRebuild => FlakeRefSyntax::Remote,
            Self::Sui => FlakeRefSyntax::LocalPathOnly,
        }
    }
}

/// The full daemon config surface (mirrors `pleme.gitops`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SentinelaConfig {
    /// `github:owner/repo` flake ref the node's darwin system is built
    /// from. The daemon builds `<flake_url>/<rev>#<hostname>`.
    pub flake_url: String,
    /// `darwinConfigurations.<hostname>` attribute to switch to.
    pub hostname: String,
    /// Seconds between cycles (the daemon's internal sleep — NOT a
    /// launchd `StartInterval`; single-flight is structural).
    pub poll_seconds: u64,
    /// Directory for the receipt chain + logs.
    pub state_dir: String,
    /// Extra args passed through to `darwin-rebuild`.
    pub extra_rebuild_args: Vec<String>,
    /// The freshness-guard probe.
    pub rev_probe: RevProbeConfig,
    /// Milliseconds to cool down after a failed build/switch/probe.
    pub cooldown_after_failure_ms: u64,
    /// Consecutive deferrals before the loop will land a rev that is an
    /// ANCESTOR of HEAD rather than HEAD itself — the escape from
    /// starvation when a build outlasts the interval between pushes. `0`
    /// keeps the strict "must still be HEAD" rule forever, and with it the
    /// possibility of never converging on a busy branch.
    pub land_ancestor_after_deferrals: usize,
    /// Consecutive BUILD FAILURES before the loop will fall back to the
    /// newest rev it already proved buildable, instead of retrying a HEAD
    /// that does not build. `0` keeps retrying the broken head forever —
    /// which is what this daemon did before 0.1.9, and how a node can hold a
    /// verified rev unactivated for as long as main stays red. See
    /// `sentinela_core::LoopConfig::land_last_good_after_failures`.
    pub land_last_good_after_failures: usize,
    /// Seconds a `darwin-rebuild build` may run before the daemon gives up
    /// and KILLS its process group. A build has mutated nothing, so killing
    /// is free.
    ///
    /// This bounds the TICK, which nothing else does. The file-capture fix in
    /// 0.1.9 removed the one hang we had diagnosed; it did not stop a
    /// different one (a stalled fetch, a wedged nix daemon) from producing
    /// the same permanent wedge. Past this deadline a hang becomes an
    /// ordinary failure and feeds the cooldown + `land_last_good_after_failures`
    /// machinery, so the node keeps converging instead of stopping forever.
    ///
    /// Generous on purpose: a cold darwin rebuild measured 7-23 minutes on
    /// cid, and a deadline that kills a legitimate build would trade a rare
    /// hang for a routine regression. `0` disables the bound entirely and
    /// restores the pre-0.1.10 "wait forever" behaviour.
    pub build_timeout_seconds: u64,
    /// Seconds a rebuild may produce **no output at all** before the daemon
    /// treats it as wedged, independent of `build_timeout_seconds`.
    ///
    /// ── ★ A DEADLINE ALONE CANNOT TELL SLOW FROM STUCK ──
    /// `build_timeout_seconds` is generous because a legitimate cold rebuild
    /// is slow, and that generosity is exactly what a wedge exploits: it
    /// costs the FULL bound to notice, every tick, forever. Measured on cid
    /// 2026-08-11 — four consecutive ticks each burned the whole 5400s while
    /// the tree was provably doing nothing: zero `/nix/store` writes, no
    /// `nix` process alive, and a `jq` sitting 89 minutes waiting for an EOF
    /// that nothing would ever send. Six hours of wall clock to learn a fact
    /// that was true after the first minute.
    ///
    /// The wedge was inside `darwin-rebuild`'s own
    /// `nix build --json … | jq -r` command substitution — one level below
    /// anything sentinela hands to `BoundedRun`, so it cannot be prevented
    /// here, only *detected*. Silence is the signal that separates it from
    /// slow work, and `BoundedRun` already reports it distinctly ("no
    /// output; a wedge, not slow work") rather than as a plain timeout.
    ///
    /// Generous for the same reason the deadline is: a single long crate
    /// compile inside `nix build` legitimately emits nothing for many
    /// minutes, so this must sit well above the quietest honest stretch or
    /// it trades a rare hang for a routine false kill — the precise error
    /// `build_timeout_seconds`' own doc warns about. 1800s is ~3x the
    /// longest silent stretch observed and still cuts a wedged tick to a
    /// third of its cost. `0` disables the check.
    pub build_silence_seconds: u64,
    /// Seconds of quiet AFTER the rebuild has printed `error:` before the
    /// daemon calls it wedged. Short on purpose, and safe to be short:
    /// unlike [`Self::build_silence_seconds`] this needs the failure to
    /// already be reported, so it is not competing with honest slow work —
    /// a build that prints an error and keeps going resets the window and is
    /// never killed. `0` disables the check.
    ///
    /// This is the guard that would have ended the 2026-08-11 incident in
    /// about a minute instead of 5400s per tick: nix had errored and exited
    /// while a downstream `jq` held the tree open, so the reason was on disk
    /// almost immediately and nothing was ever going to read it.
    pub build_error_quiet_seconds: u64,
    /// Seconds a `darwin-rebuild switch` may run before the daemon stops
    /// waiting. The child is deliberately NOT killed — it may be
    /// mid-activation, and killing it there is how a machine ends up half
    /// switched. The activation finishes detached and the next tick
    /// reconciles against whatever actually landed. `0` disables the bound.
    pub switch_timeout_seconds: u64,
    /// Seconds a single **git** invocation may run before the daemon stops
    /// waiting — `ls-remote` when probing the branch head, and the `fetch`
    /// + ancestry pair.
    ///
    /// ── ★ THESE ARE NETWORK CALLS INSIDE AN OTHERWISE-BOUNDED TICK ──
    /// `build_timeout_seconds` and `switch_timeout_seconds` bound the
    /// rebuild and nothing else, so before this field existed a `git
    /// ls-remote` against a stalled TLS connection blocked the tick
    /// FOREVER — no receipt, no cooldown, no retry, and a heartbeat frozen
    /// mid-tick. That is the exact wedge P1 exists to forbid, arriving by
    /// the one path in the tick that had no deadline.
    ///
    /// Not hypothetical: on rio 2026-08-07 a nix build sat at zero CPU
    /// holding two `CLOSE-WAIT` HTTPS sockets with unread bytes. A git
    /// transfer can reach the same state, and git's own
    /// `http.lowSpeedLimit` is unset by default.
    ///
    /// Short on purpose, unlike the rebuild bounds: `ls-remote` against a
    /// healthy remote is sub-second, so 120s is ~100x headroom and still
    /// two polls. `0` disables the bound.
    pub git_timeout_seconds: u64,
    /// Which rebuild tool to drive. Defaults to `darwin-rebuild` so every
    /// existing config is unchanged; a NixOS node sets `nixos-rebuild`.
    pub rebuild_tool: RebuildTool,
    /// Health-gated rollback after each activation. OFF in both tiers, so an
    /// existing config that never mentions it behaves exactly as before.
    pub rollback: RollbackConfig,
    /// Which revision may be deployed: `head` (both tiers; today's
    /// behaviour) or `{green: {required: [...]}}`.
    pub revision_policy: RevisionPolicyConfig,
}

/// The `revision_policy:` section. See [`sentinela_core::RevisionPolicy`].
///
/// ```yaml
/// revision_policy: { kind: head }          # the default; same as omitting it
/// revision_policy:
///   kind: green
///   required: [promotion-gate]   # check-run names / status contexts
///   recheck_seconds: 300         # pending/blind answers are re-asked after this
///   max_candidates: 50           # how far back from HEAD to look
/// ```
///
/// Internally tagged (`kind:`) because the document is also rendered as JSON
/// by the nix module, and serde_yaml reads an externally tagged enum only
/// from a YAML `!tag`, which JSON cannot carry.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RevisionPolicyConfig {
    /// Branch HEAD.
    #[default]
    Head,
    /// The newest revision whose required checks all passed.
    Green {
        /// The check-run names / status contexts that must all conclude success.
        required: Vec<String>,
        /// Seconds a pending or blind answer stands before it is asked again.
        #[serde(default = "default_green_recheck_seconds")]
        recheck_seconds: u64,
        /// How far back from HEAD to look for a green revision.
        #[serde(default = "default_green_max_candidates")]
        max_candidates: usize,
    },
}

fn default_green_recheck_seconds() -> u64 {
    300
}

fn default_green_max_candidates() -> usize {
    50
}

/// Default probation window, seconds.
pub const DEFAULT_ROLLBACK_WINDOW_SECONDS: u64 = 300;
/// Default seconds between probe rounds.
pub const DEFAULT_ROLLBACK_INTERVAL_SECONDS: u64 = 15;
/// Default consecutive passing rounds that verify an activation.
pub const DEFAULT_ROLLBACK_REQUIRED_PASSES: u32 = 2;
/// Default per-probe timeout, seconds, when an entry does not state one.
pub const DEFAULT_PROBE_TIMEOUT_SECONDS: u64 = 10;

/// The `rollback:` section — health-gated rollback after each activation.
///
/// ```yaml
/// rollback:
///   enabled: true
///   window_seconds: 300
///   interval_seconds: 15
///   required_consecutive_passes: 2
///   probes:
///     - name: tailscale
///       kind: command
///       argv: ["/run/current-system/sw/bin/tailscale", "status"]
///       expect_exit: 0      # default 0
///       timeout_seconds: 10 # default 10
/// ```
///
/// ── ★ THE SECTION IS STRICT, THE PROBE LIST IS OPEN ───────────────────
/// The section's own keys carry `deny_unknown_fields` like every other part
/// of this surface: a typo'd `windw_seconds` is one field of one struct, and
/// silently ignoring it would run the wrong window. The probe LIST is
/// different — its entries are independent, and a closed-enum `Vec` would let
/// one malformed entry refuse the whole config, which stops the daemon and
/// takes every valid sibling (and every deploy) down with it. So entries are
/// held open ([`ProbeEntry`]) and parsed one at a time by [`Self::plan`]:
/// a bad entry is refused BY NAME, and its siblings load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RollbackConfig {
    /// Master switch. `false` is today's behaviour exactly.
    pub enabled: bool,
    /// How long after a switch a failing round may still recover, seconds.
    pub window_seconds: u64,
    /// Seconds between probe rounds during probation.
    pub interval_seconds: u64,
    /// Consecutive passing rounds that verify an activation.
    pub required_consecutive_passes: u32,
    /// The probes, as written. See [`ProbeEntry`].
    pub probes: Vec<ProbeEntry>,
}

impl Default for RollbackConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window_seconds: DEFAULT_ROLLBACK_WINDOW_SECONDS,
            interval_seconds: DEFAULT_ROLLBACK_INTERVAL_SECONDS,
            required_consecutive_passes: DEFAULT_ROLLBACK_REQUIRED_PASSES,
            probes: Vec::new(),
        }
    }
}

/// One probe entry exactly as written — an open value, so that it cannot
/// fail the document it sits in. Its typed view is produced by
/// [`RollbackConfig::plan`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProbeEntry(pub serde_json::Value);

/// The closed kind enum an entry must parse into (minus its `name`).
///
/// `deny_unknown_fields`: inside ONE entry a typo'd key (`expect_exti`) is
/// refused with that entry, rather than silently defaulting the exit code.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ProbeSpec {
    Command {
        argv: Vec<String>,
        #[serde(default)]
        expect_exit: i32,
        #[serde(default = "default_probe_timeout")]
        timeout_seconds: u64,
    },
}

fn default_probe_timeout() -> u64 {
    DEFAULT_PROBE_TIMEOUT_SECONDS
}

/// A probe entry that was refused, named so an operator can find it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeRefusal {
    /// The entry's `name`, or `#<index>` when it has no usable name.
    pub name: String,
    /// Why it was refused.
    pub reason: String,
}

impl std::fmt::Display for ProbeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "probe `{}` refused: {}", self.name, self.reason)
    }
}

/// What the `rollback:` section resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackPlan {
    /// The effective policy — `None` when disabled, or when enabled with no
    /// probe surviving validation (see [`sentinela_core::RollbackPolicy`] on
    /// why zero probes is not a passing policy).
    pub policy: Option<sentinela_core::RollbackPolicy>,
    /// Every entry that was refused, by name.
    pub refused: Vec<ProbeRefusal>,
    /// `true` when rollback was enabled but no probe survived — the case an
    /// operator must hear about, because they asked for protection and are
    /// not getting it.
    pub enabled_without_probes: bool,
}

impl RollbackConfig {
    /// Resolve the section into an effective policy plus the refused entries.
    ///
    /// `exists` answers whether a probe's `argv[0]` is present — injected so
    /// this stays pure and testable; the daemon passes a filesystem check. A
    /// probe whose binary is absent at startup would fail every round and roll
    /// back every deploy forever, so it is refused here, by name, instead.
    ///
    /// Refused entries are reported even when rollback is disabled: a config
    /// error is worth seeing before the day somebody turns it on.
    #[must_use]
    pub fn plan(&self, exists: &dyn Fn(&str) -> bool) -> RollbackPlan {
        let mut probes: Vec<sentinela_core::HealthProbe> = Vec::new();
        let mut refused = Vec::new();
        for (index, entry) in self.probes.iter().enumerate() {
            match parse_probe(index, &entry.0, exists) {
                Ok(p) if probes.iter().any(|q| q.name == p.name) => refused.push(ProbeRefusal {
                    name: p.name,
                    reason: "duplicate name — names identify the failing probe in a receipt"
                        .to_owned(),
                }),
                Ok(p) => probes.push(p),
                Err(r) => refused.push(r),
            }
        }
        let enabled_without_probes = self.enabled && probes.is_empty();
        let policy = (self.enabled && !probes.is_empty()).then(|| sentinela_core::RollbackPolicy {
            window_ms: self.window_seconds.saturating_mul(1000),
            interval_seconds: self.interval_seconds.max(1),
            required_consecutive_passes: self.required_consecutive_passes.max(1),
            probes,
        });
        RollbackPlan {
            policy,
            refused,
            enabled_without_probes,
        }
    }
}

/// Parse and validate one entry. Every refusal carries the entry's name.
fn parse_probe(
    index: usize,
    raw: &serde_json::Value,
    exists: &dyn Fn(&str) -> bool,
) -> Result<sentinela_core::HealthProbe, ProbeRefusal> {
    let by_index = || ["#", &index.to_string()].concat();
    let Some(obj) = raw.as_object() else {
        return Err(ProbeRefusal {
            name: by_index(),
            reason: "not a mapping".to_owned(),
        });
    };
    let name = match obj.get("name").and_then(serde_json::Value::as_str) {
        Some(n) if !n.trim().is_empty() => n.to_owned(),
        _ => {
            return Err(ProbeRefusal {
                name: by_index(),
                reason: "missing or empty `name`".to_owned(),
            });
        }
    };
    let refuse = |reason: String| ProbeRefusal {
        name: name.clone(),
        reason,
    };
    let mut rest = obj.clone();
    rest.remove("name");
    let spec: ProbeSpec =
        serde_json::from_value(serde_json::Value::Object(rest)).map_err(|e| refuse(e.to_string()))?;
    match spec {
        ProbeSpec::Command {
            argv,
            expect_exit,
            timeout_seconds,
        } => {
            let Some(program) = argv.first() else {
                return Err(refuse("`argv` is empty".to_owned()));
            };
            // Absolute, never a `$PATH` lookup: a launchd/systemd daemon has
            // no useful PATH (the rio 2026-08-05 lesson). A bare `curl` would
            // fail every round and roll back every deploy.
            if !program.starts_with('/') {
                return Err(refuse(
                    ["`argv[0]` must be an absolute path, got `", program, "`"].concat(),
                ));
            }
            if !exists(program) {
                return Err(refuse(["`", program, "` does not exist"].concat()));
            }
            if timeout_seconds == 0 {
                return Err(refuse(
                    "`timeout_seconds` must be positive — an unbounded probe can wedge the tick"
                        .to_owned(),
                ));
            }
            Ok(sentinela_core::HealthProbe {
                name,
                check: sentinela_core::ProbeCheck::Command {
                    argv,
                    expect_exit,
                    timeout_seconds,
                },
            })
        }
    }
}

/// Default poll cadence, seconds.
pub const DEFAULT_POLL_SECONDS: u64 = 60;
/// Default failure cooldown, milliseconds (5 minutes).
pub const DEFAULT_COOLDOWN_MS: u64 = 5 * 60 * 1000;
/// Default deferral streak before landing an ancestor of HEAD.
pub const DEFAULT_LAND_ANCESTOR_AFTER_DEFERRALS: usize = 2;
/// Default build-failure streak before falling back to the last rev that
/// built. Higher than the deferral threshold on purpose — a failure may be
/// transient where a deferral is not.
pub const DEFAULT_LAND_LAST_GOOD_AFTER_FAILURES: usize = 3;
/// Default build deadline, seconds (90 min). Well above the 7-23 min a cold
/// cid rebuild measured, because killing a real build is a regression while
/// the bound only has to catch a hang.
pub const DEFAULT_BUILD_TIMEOUT_SECONDS: u64 = 90 * 60;
/// Default git deadline, seconds (2 min). A healthy `ls-remote` is
/// sub-second; this is ~100x headroom and still only two polls, because a
/// hung network read has nothing in common with a long build.
pub const DEFAULT_GIT_TIMEOUT_SECONDS: u64 = 120;
/// Default switch deadline, seconds (30 min). Activation is minutes, not
/// tens of minutes, so this can be tighter than the build bound.
pub const DEFAULT_SWITCH_TIMEOUT_SECONDS: u64 = 30 * 60;

/// Default for [`SentinelaConfig::build_silence_seconds`] — 30 minutes with
/// no output at all. Sits well above the longest honest silent stretch (a
/// single long crate compile) and a third of the 90-minute deadline, so a
/// wedge costs one third as much to detect as it did on 2026-08-11.
pub const DEFAULT_BUILD_SILENCE_SECONDS: u64 = 30 * 60;

/// Default for [`SentinelaConfig::build_error_quiet_seconds`] — 60s of quiet
/// after a reported error. Two orders of magnitude below the deadline, and
/// specific enough to afford it.
pub const DEFAULT_BUILD_ERROR_QUIET_SECONDS: u64 = 60;

impl Default for SentinelaConfig {
    fn default() -> Self {
        <Self as shikumi::TieredConfig>::prescribed_default()
    }
}

impl SentinelaConfig {
    /// The rollback plan, checking probe binaries against the filesystem.
    #[must_use]
    pub fn rollback_plan(&self) -> RollbackPlan {
        self.rollback
            .plan(&|p: &str| std::path::Path::new(p).exists())
    }

    /// The revision policy, or why it is refused. A `green` policy that
    /// requires nothing would call every commit green, so it is refused
    /// (the daemon then refuses to start) rather than run vacuously.
    ///
    /// # Errors
    /// A message naming the refusal.
    pub fn revision_policy(&self) -> Result<sentinela_core::RevisionPolicy, String> {
        match &self.revision_policy {
            RevisionPolicyConfig::Head => Ok(sentinela_core::RevisionPolicy::Head),
            RevisionPolicyConfig::Green { required, .. }
                if required.iter().all(|r| r.trim().is_empty()) =>
            {
                Err("revision_policy (green): `required` is empty, so every commit would read as green".to_owned())
            }
            RevisionPolicyConfig::Green {
                required,
                recheck_seconds,
                max_candidates,
            } => Ok(sentinela_core::RevisionPolicy::Green(
                sentinela_core::GreenPolicy {
                    required: required.clone(),
                    recheck_ms: recheck_seconds.max(&1).saturating_mul(1000),
                    max_candidates: *max_candidates.max(&1),
                },
            )),
        }
    }

    /// The [`sentinela_core::LoopConfig`] derived from this surface.
    #[must_use]
    pub fn loop_config(&self) -> sentinela_core::LoopConfig {
        sentinela_core::LoopConfig {
            cooldown_after_failure_ms: self.cooldown_after_failure_ms,
            // The cadence travels WITH the pulse: a reader judging
            // staleness from a timestamp alone cannot tell an hourly loop
            // from a 60s one, and 400s of silence means opposite things
            // under each.
            poll_seconds: self.poll_seconds,
            land_ancestor_after_deferrals: self.land_ancestor_after_deferrals,
            land_last_good_after_failures: self.land_last_good_after_failures,
        }
    }

    /// `false` when the selected tool structurally cannot resolve the
    /// configured `flake_url` — a config that would fail-closed on every tick
    /// forever while presenting as a healthy loop.
    ///
    /// Pure, so the refusal is provable without a daemon, a binary, or a
    /// network; `sentinela::preflight` is the one caller and turns a `false`
    /// here into a refusal to start.
    ///
    /// An EMPTY `flake_url` is deliberately NOT judged here: both config tiers
    /// ship it empty on purpose (the nix module fills it), so judging it would
    /// make `prescribed_default()` itself unusable. A mis-rendered empty url
    /// is already a visible failure at probe time.
    #[must_use]
    pub fn flake_ref_is_resolvable(&self) -> bool {
        self.flake_url.is_empty()
            || self
                .rebuild_tool
                .flake_ref_syntax()
                .accepts(&self.flake_url)
    }
}

impl shikumi::TieredConfig for SentinelaConfig {
    fn bare() -> Self {
        Self {
            flake_url: String::new(),
            hostname: String::new(),
            poll_seconds: 0,
            state_dir: String::new(),
            extra_rebuild_args: Vec::new(),
            rev_probe: RevProbeConfig::bare(),
            cooldown_after_failure_ms: 0,
            land_ancestor_after_deferrals: 0,
            land_last_good_after_failures: 0,
            build_timeout_seconds: 0,
            build_silence_seconds: 0,
            build_error_quiet_seconds: 0,
            switch_timeout_seconds: 0,
            git_timeout_seconds: 0,
            rebuild_tool: RebuildTool::DarwinRebuild,
            rollback: RollbackConfig {
                enabled: false,
                window_seconds: 0,
                interval_seconds: 0,
                required_consecutive_passes: 0,
                probes: Vec::new(),
            },
            revision_policy: RevisionPolicyConfig::Head,
        }
    }

    fn prescribed_default() -> Self {
        Self {
            flake_url: String::new(),
            hostname: String::new(),
            poll_seconds: DEFAULT_POLL_SECONDS,
            state_dir: "/var/log/pleme-gitops".to_owned(),
            extra_rebuild_args: Vec::new(),
            rev_probe: RevProbeConfig::prescribed(),
            cooldown_after_failure_ms: DEFAULT_COOLDOWN_MS,
            land_ancestor_after_deferrals: DEFAULT_LAND_ANCESTOR_AFTER_DEFERRALS,
            land_last_good_after_failures: DEFAULT_LAND_LAST_GOOD_AFTER_FAILURES,
            build_timeout_seconds: DEFAULT_BUILD_TIMEOUT_SECONDS,
            build_silence_seconds: DEFAULT_BUILD_SILENCE_SECONDS,
            build_error_quiet_seconds: DEFAULT_BUILD_ERROR_QUIET_SECONDS,
            switch_timeout_seconds: DEFAULT_SWITCH_TIMEOUT_SECONDS,
            git_timeout_seconds: DEFAULT_GIT_TIMEOUT_SECONDS,
            rebuild_tool: RebuildTool::DarwinRebuild,
            // Off. Shipping it on would change what every node does on its
            // next deploy; a node opts in.
            rollback: RollbackConfig::default(),
            // HEAD: today's behaviour. A node opts into `green`.
            revision_policy: RevisionPolicyConfig::Head,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shikumi::TieredConfig;

    #[test]
    fn bare_is_zero_opinion() {
        let b = SentinelaConfig::bare();
        assert_eq!(b.poll_seconds, 0);
        assert_eq!(b.cooldown_after_failure_ms, 0);
        assert!(b.rev_probe.branch.is_empty());
    }

    #[test]
    fn prescribed_has_shipped_defaults() {
        let p = SentinelaConfig::prescribed_default();
        assert_eq!(p.poll_seconds, DEFAULT_POLL_SECONDS);
        assert_eq!(p.cooldown_after_failure_ms, DEFAULT_COOLDOWN_MS);
        assert_eq!(p.rev_probe.branch, "main");
        // Node-specific coordinates are intentionally empty (module fills).
        assert!(p.flake_url.is_empty());
        assert!(p.hostname.is_empty());
    }

    #[test]
    fn revision_policy_defaults_to_head_and_reads_green() {
        let head: SentinelaConfig = serde_yaml::from_str("hostname: plo").unwrap();
        assert_eq!(head.revision_policy(), Ok(sentinela_core::RevisionPolicy::Head));
        let green: SentinelaConfig =
            serde_yaml::from_str("revision_policy:\n  kind: green\n  required: [promotion-gate]\n").unwrap();
        match green.revision_policy() {
            Ok(sentinela_core::RevisionPolicy::Green(g)) => {
                assert_eq!(g.required, vec!["promotion-gate".to_owned()]);
                assert_eq!(g.recheck_ms, 300_000);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_green_policy_requiring_nothing_is_refused() {
        let c: SentinelaConfig =
            serde_yaml::from_str("revision_policy:\n  kind: green\n  required: []\n").unwrap();
        assert!(c.revision_policy().is_err());
        // And as the nix module renders it: JSON.
        let c: SentinelaConfig = serde_yaml::from_str(
            r#"{"revision_policy":{"kind":"green","required":["promotion-gate"]}}"#,
        )
        .unwrap();
        assert!(matches!(c.revision_policy(), Ok(sentinela_core::RevisionPolicy::Green(_))));
        let c: SentinelaConfig = serde_yaml::from_str("revision_policy:\n  kind: green\n  required: []\n").unwrap();
        assert!(c.revision_policy().is_err());
    }

    #[test]
    fn loop_config_carries_cooldown() {
        let p = SentinelaConfig::prescribed_default();
        assert_eq!(
            p.loop_config().cooldown_after_failure_ms,
            DEFAULT_COOLDOWN_MS
        );
        // The starvation escape must reach the FSM, or the knob is decorative.
        assert_eq!(
            p.loop_config().land_ancestor_after_deferrals,
            DEFAULT_LAND_ANCESTOR_AFTER_DEFERRALS
        );
        // `bare()` is zero-opinion: the relaxation is OFF unless something
        // states it, so an un-prescribed config keeps the strict rule.
        assert_eq!(
            SentinelaConfig::bare()
                .loop_config()
                .land_ancestor_after_deferrals,
            0
        );
    }

    #[test]
    fn yaml_roundtrips_and_rejects_unknown_fields() {
        let cfg = SentinelaConfig {
            flake_url: "github:pleme-io/nix".to_owned(),
            hostname: "ryn".to_owned(),
            poll_seconds: 60,
            state_dir: "/var/log/pleme-gitops".to_owned(),
            extra_rebuild_args: vec!["--option".to_owned(), "foo".to_owned()],
            rev_probe: RevProbeConfig {
                git_url: "https://github.com/pleme-io/nix".to_owned(),
                branch: "main".to_owned(),
                token_file: Some("/run/tok".to_owned()),
            },
            cooldown_after_failure_ms: 300_000,
            land_ancestor_after_deferrals: 2,
            land_last_good_after_failures: 3,
            build_timeout_seconds: 5400,
            build_silence_seconds: 1800,
            build_error_quiet_seconds: 60,
            switch_timeout_seconds: 1800,
            git_timeout_seconds: 120,
            rebuild_tool: RebuildTool::NixosRebuild,
            rollback: RollbackConfig::default(),
            revision_policy: RevisionPolicyConfig::Head,
        };
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        let back: SentinelaConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(cfg, back);
        // deny_unknown_fields guards against a stale/typo'd render.
        assert!(serde_yaml::from_str::<SentinelaConfig>("bogus_key: 1").is_err());
    }
}

#[cfg(test)]
mod rollback_tests {
    use super::*;

    const ALL_EXIST: &dyn Fn(&str) -> bool = &|_| true;

    fn from_yaml(y: &str) -> SentinelaConfig {
        serde_yaml::from_str(y).expect("the document must load")
    }

    /// Off in both tiers, and absent from an existing config: nothing changes
    /// for a node that never mentions it.
    #[test]
    fn rollback_is_off_unless_a_node_opts_in() {
        use shikumi::TieredConfig as _;
        assert!(!SentinelaConfig::prescribed_default().rollback.enabled);
        assert!(!SentinelaConfig::bare().rollback.enabled);
        let cfg = from_yaml("flake_url: github:pleme-io/nix\nhostname: cid\n");
        assert!(cfg.rollback_plan().policy.is_none());
    }

    /// THE SCOPED REFUSAL. One document, four entries: one good, three bad in
    /// three different ways. The document loads, the good sibling is in the
    /// policy, and each bad one is refused BY NAME with its own reason — never
    /// a whole-config failure that stops the daemon.
    #[test]
    fn a_malformed_probe_is_refused_by_name_and_its_siblings_load() {
        let cfg = from_yaml(
            r#"
flake_url: github:pleme-io/nix
hostname: cid
rollback:
  enabled: true
  probes:
    - name: tailscale
      kind: command
      argv: ["/run/current-system/sw/bin/tailscale", "status"]
    - name: typo
      kind: command
      argv: ["/usr/bin/true"]
      expect_exti: 0
    - name: web
      kind: http
      url: http://localhost:8123
    - name: bare-path
      kind: command
      argv: ["curl", "-fsS", "http://localhost"]
    - argv: ["/usr/bin/true"]
"#,
        );
        let plan = cfg.rollback.plan(ALL_EXIST);
        let policy = plan.policy.expect("a valid sibling keeps the policy alive");
        assert_eq!(
            policy.probes.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["tailscale"]
        );
        assert_eq!(
            policy.probes[0].check,
            sentinela_core::ProbeCheck::Command {
                argv: vec!["/run/current-system/sw/bin/tailscale".into(), "status".into()],
                expect_exit: 0,
                timeout_seconds: DEFAULT_PROBE_TIMEOUT_SECONDS,
            },
            "defaults fill what the entry did not state"
        );
        let refused: Vec<(&str, &str)> = plan
            .refused
            .iter()
            .map(|r| (r.name.as_str(), r.reason.as_str()))
            .collect();
        assert_eq!(refused.len(), 4, "{refused:?}");
        assert_eq!(refused[0].0, "typo");
        assert!(refused[0].1.contains("expect_exti"), "{}", refused[0].1);
        assert_eq!(refused[1].0, "web");
        assert!(refused[1].1.contains("http"), "{}", refused[1].1);
        assert_eq!(refused[2].0, "bare-path");
        assert!(refused[2].1.contains("absolute"), "{}", refused[2].1);
        assert_eq!(refused[3].0, "#4", "no name: identified by position");
        assert!(plan.refused[0].to_string().contains("probe `typo` refused"));
    }

    /// Rollback asked for, nothing to judge with: no policy, and the plan
    /// says so — a vacuous verification would attest health nobody measured.
    #[test]
    fn enabled_with_no_valid_probe_is_no_policy_and_says_so() {
        let cfg = from_yaml(
            "rollback:\n  enabled: true\n  probes:\n    - name: x\n      kind: command\n      argv: []\n",
        );
        let plan = cfg.rollback.plan(ALL_EXIST);
        assert!(plan.policy.is_none());
        assert!(plan.enabled_without_probes);
        assert_eq!(plan.refused[0].name, "x");
    }

    /// Absent binaries, zero timeouts and duplicate names are entry-level
    /// refusals too.
    #[test]
    fn missing_binaries_zero_timeouts_and_duplicates_are_refused_per_entry() {
        let cfg = from_yaml(
            r#"
rollback:
  enabled: true
  window_seconds: 120
  interval_seconds: 5
  required_consecutive_passes: 3
  probes:
    - {name: a, kind: command, argv: ["/present"], expect_exit: 3, timeout_seconds: 4}
    - {name: b, kind: command, argv: ["/absent"]}
    - {name: c, kind: command, argv: ["/present"], timeout_seconds: 0}
    - {name: a, kind: command, argv: ["/present"]}
"#,
        );
        let plan = cfg.rollback.plan(&|p: &str| p == "/present");
        let policy = plan.policy.unwrap();
        assert_eq!(policy.window_ms, 120_000);
        assert_eq!(policy.interval_seconds, 5);
        assert_eq!(policy.required_consecutive_passes, 3);
        assert_eq!(policy.probes.len(), 1);
        let names: Vec<&str> = plan.refused.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["b", "c", "a"]);
    }

    /// The section's OWN keys stay strict: that is one struct, not a list of
    /// independent entries, and a silently ignored typo would run the wrong
    /// window.
    #[test]
    fn a_typo_in_the_section_itself_is_still_refused() {
        assert!(serde_yaml::from_str::<SentinelaConfig>("rollback:\n  windw_seconds: 5\n").is_err());
    }

    #[test]
    fn the_section_round_trips() {
        let cfg = from_yaml(
            "rollback:\n  enabled: true\n  probes:\n    - {name: a, kind: command, argv: [\"/x\"]}\n",
        );
        let back: SentinelaConfig = serde_yaml::from_str(&serde_yaml::to_string(&cfg).unwrap()).unwrap();
        assert_eq!(cfg, back);
    }
}

#[cfg(test)]
mod rebuild_tool_tests {
    use super::*;

    /// The whole point of the sum: each variant maps to the tool that can
    /// actually build that platform's system closure.
    #[test]
    fn each_variant_names_its_tool() {
        assert_eq!(
            RebuildTool::DarwinRebuild.binary(),
            "/run/current-system/sw/bin/darwin-rebuild"
        );
        assert_eq!(
            RebuildTool::NixosRebuild.binary(),
            "/run/current-system/sw/bin/nixos-rebuild"
        );
        assert_eq!(RebuildTool::Sui.binary(), "/run/current-system/sw/bin/sui");
    }

    /// The verb is NOT always argv[1]. `sui` is a multi-command CLI and the
    /// rebuild verb lives at `sui system rebuild <verb>`; the two nix-* tools
    /// ARE the rebuild command and take the verb directly.
    #[test]
    fn each_variant_carries_its_own_argv_prefix() {
        assert_eq!(RebuildTool::DarwinRebuild.argv_prefix(), &[] as &[&str]);
        assert_eq!(RebuildTool::NixosRebuild.argv_prefix(), &[] as &[&str]);
        assert_eq!(RebuildTool::Sui.argv_prefix(), &["system", "rebuild"]);
    }

    /// ── ★ THE MEASURED BLOCKER, AS A TEST ────────────────────────────────
    /// sui parses the left half of `<ref>#<attr>` as a filesystem path
    /// (`sui/sui-compat/src/flake_ref.rs:37-58`), so a `github:` ref becomes a
    /// directory that does not exist. Proven live on cid 2026-08-05 against
    /// sui 0.1.154:
    ///   `getFlake: github:pleme-io/nix/<rev>/flake.nix: No such file or directory`
    #[test]
    fn sui_cannot_resolve_a_remote_flake_ref_and_the_nix_tools_can() {
        assert_eq!(
            RebuildTool::Sui.flake_ref_syntax(),
            FlakeRefSyntax::LocalPathOnly
        );
        assert_eq!(
            RebuildTool::DarwinRebuild.flake_ref_syntax(),
            FlakeRefSyntax::Remote
        );
        assert_eq!(
            RebuildTool::NixosRebuild.flake_ref_syntax(),
            FlakeRefSyntax::Remote
        );

        let remote = "github:pleme-io/nix";
        assert!(FlakeRefSyntax::Remote.accepts(remote));
        assert!(
            !FlakeRefSyntax::LocalPathOnly.accepts(remote),
            "a github: ref has no fetcher on sui's path — it is opened as a directory"
        );
    }

    /// The accepted local forms are exactly the two sui's parser handles
    /// (`flake_ref.rs:48` strips `path:`), and a RELATIVE path is refused on
    /// purpose: it would resolve against the daemon's cwd, which is the state
    /// dir, not a checkout.
    #[test]
    fn local_path_only_accepts_absolute_paths_bare_or_path_prefixed() {
        assert!(FlakeRefSyntax::LocalPathOnly.accepts("/var/lib/sentinela/checkout"));
        assert!(FlakeRefSyntax::LocalPathOnly.accepts("path:/var/lib/sentinela/checkout"));
        assert!(!FlakeRefSyntax::LocalPathOnly.accepts("relative/checkout"));
        assert!(!FlakeRefSyntax::LocalPathOnly.accepts("."));
        assert!(!FlakeRefSyntax::LocalPathOnly.accepts("git+https://example.invalid/r"));
    }

    /// The pairing check the preflight refuses on. A remote-capable tool never
    /// trips it; sui trips it for every realistic sentinela config.
    #[test]
    fn a_remote_flake_url_is_unresolvable_under_sui_and_fine_under_the_nix_tools() {
        let with = |tool| SentinelaConfig {
            flake_url: "github:pleme-io/nix".to_owned(),
            hostname: "rio".to_owned(),
            rebuild_tool: tool,
            ..SentinelaConfig::default()
        };
        assert!(with(RebuildTool::DarwinRebuild).flake_ref_is_resolvable());
        assert!(with(RebuildTool::NixosRebuild).flake_ref_is_resolvable());
        assert!(
            !with(RebuildTool::Sui).flake_ref_is_resolvable(),
            "selecting sui against a remote repo must be refused BEFORE the loop \
             starts — otherwise every tick fails closed forever while the unit \
             reads active(running) and the heartbeat stays fresh"
        );
    }

    /// The empty url both tiers ship must not be judged, or `bare()` and
    /// `prescribed_default()` would be self-refusing configs.
    #[test]
    fn an_empty_flake_url_is_not_judged_by_the_pairing_check() {
        use shikumi::TieredConfig as _;
        assert!(SentinelaConfig::bare().flake_ref_is_resolvable());
        assert!(SentinelaConfig::prescribed_default().flake_ref_is_resolvable());
        let mut cfg = SentinelaConfig::prescribed_default();
        cfg.rebuild_tool = RebuildTool::Sui;
        assert!(cfg.flake_ref_is_resolvable());
    }

    /// A node selects sui by config, same as every other tool — the variant is
    /// retired-by-configuration, not absent (★★ MODULARIZE, DON'T DELETE).
    #[test]
    fn sui_has_a_wire_spelling() {
        let yaml = "flake_url: /srv/nix\nhostname: h\nrebuild_tool: sui\n";
        let cfg: SentinelaConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.rebuild_tool, RebuildTool::Sui);
        assert!(serde_yaml::to_string(&cfg).unwrap().contains("sui"));
    }

    /// BACKWARD COMPATIBILITY, asserted rather than assumed. `SentinelaConfig`
    /// carries `deny_unknown_fields`, so binary and config cross a generation
    /// boundary together — a config rendered by an older module must still
    /// parse, and must still mean darwin-rebuild.
    #[test]
    fn absent_field_defaults_to_darwin() {
        let yaml = "flake_url: github:pleme-io/nix\nhostname: ryn\n";
        let cfg: SentinelaConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.rebuild_tool, RebuildTool::DarwinRebuild);
    }

    /// The wire spelling is kebab-case, matching every other field's rendering
    /// from the Nix side.
    #[test]
    fn wire_spelling_is_kebab_case() {
        let yaml = "flake_url: f\nhostname: h\nrebuild_tool: nixos-rebuild\n";
        let cfg: SentinelaConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.rebuild_tool, RebuildTool::NixosRebuild);
        assert!(
            serde_yaml::to_string(&cfg)
                .unwrap()
                .contains("nixos-rebuild")
        );
    }

    /// An unspelled tool has no representation — the reason this is a sum and
    /// not a path.
    #[test]
    fn unknown_tool_is_rejected() {
        let yaml = "flake_url: f\nhostname: h\nrebuild_tool: home-manager\n";
        assert!(serde_yaml::from_str::<SentinelaConfig>(yaml).is_err());
    }
}
