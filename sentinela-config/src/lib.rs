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

/// WHICH rebuild tool the daemon drives — a closed sum, not a path.
///
/// sentinela was Darwin-only until 2026-08-05, and the binary was a `const`
/// in `real_env.rs`. That const is why the fleet's ONLY reconciler carrying
/// the dual starvation escape could not run on a NixOS node: rio ran upstream
/// `comin` instead, which has neither escape, and on 2026-08-04 it discarded
/// 13 generations in 6 hours without landing one.
///
/// A closed sum rather than a configurable path: the two tools are the only
/// two that exist, their argv shape is identical (`<verb> --flake <ref>`), and
/// a free-form path would let a config name a binary that cannot take those
/// arguments — an unrepresentable state made representable for no gain.
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
        assert!(serde_yaml::to_string(&cfg).unwrap().contains("nixos-rebuild"));
    }

    /// An unspelled tool has no representation — the reason this is a sum and
    /// not a path.
    #[test]
    fn unknown_tool_is_rejected() {
        let yaml = "flake_url: f\nhostname: h\nrebuild_tool: home-manager\n";
        assert!(serde_yaml::from_str::<SentinelaConfig>(yaml).is_err());
    }
}
