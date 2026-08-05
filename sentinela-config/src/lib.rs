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
    /// Seconds a `darwin-rebuild switch` may run before the daemon stops
    /// waiting. The child is deliberately NOT killed — it may be
    /// mid-activation, and killing it there is how a machine ends up half
    /// switched. The activation finishes detached and the next tick
    /// reconciles against whatever actually landed. `0` disables the bound.
    pub switch_timeout_seconds: u64,
    /// Which rebuild tool to drive. Defaults to `darwin-rebuild` so every
    /// existing config is unchanged; a NixOS node sets `nixos-rebuild`.
    pub rebuild_tool: RebuildTool,
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
/// Default switch deadline, seconds (30 min). Activation is minutes, not
/// tens of minutes, so this can be tighter than the build bound.
pub const DEFAULT_SWITCH_TIMEOUT_SECONDS: u64 = 30 * 60;

impl Default for SentinelaConfig {
    fn default() -> Self {
        <Self as shikumi::TieredConfig>::prescribed_default()
    }
}

impl SentinelaConfig {
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
            switch_timeout_seconds: 0,
            rebuild_tool: RebuildTool::DarwinRebuild,
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
            switch_timeout_seconds: DEFAULT_SWITCH_TIMEOUT_SECONDS,
            rebuild_tool: RebuildTool::DarwinRebuild,
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
            switch_timeout_seconds: 1800,
            rebuild_tool: RebuildTool::NixosRebuild,
        };
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        let back: SentinelaConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(cfg, back);
        // deny_unknown_fields guards against a stale/typo'd render.
        assert!(serde_yaml::from_str::<SentinelaConfig>("bogus_key: 1").is_err());
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
