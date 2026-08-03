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
}

/// Default poll cadence, seconds.
pub const DEFAULT_POLL_SECONDS: u64 = 60;
/// Default failure cooldown, milliseconds (5 minutes).
pub const DEFAULT_COOLDOWN_MS: u64 = 5 * 60 * 1000;

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
        };
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        let back: SentinelaConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(cfg, back);
        // deny_unknown_fields guards against a stale/typo'd render.
        assert!(serde_yaml::from_str::<SentinelaConfig>("bogus_key: 1").is_err());
    }
}
