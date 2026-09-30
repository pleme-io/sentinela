//! Which revision a node deploys — branch HEAD, or the newest one whose
//! required checks all passed.
//!
//! ── ★ WHY A POLICY AND NOT A FLAG ──────────────────────────────────────
//! Measured 2026-09-29/30 on plo: automatic lock bumps reached the node as
//! branch HEAD before anything had checked them, and twice in one day a broken
//! input landed on the house. `Head` is today's behaviour, and stays the
//! default so no node changes by upgrading. `Green` deploys only a revision
//! whose required checks concluded success on that exact commit. A sum, so a
//! future policy (a promoted-closure record, say) is a new variant that every
//! `match` must place.
//!
//! Pure data and one pure decision ([`verdict`]); reading check results is a
//! [`crate::GitopsEnv`] method.

use crate::rev::Rev;

/// Which revision the loop is allowed to deploy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RevisionPolicy {
    /// Branch HEAD, as it always was.
    #[default]
    Head,
    /// The newest revision on the branch whose required checks all passed.
    Green(GreenPolicy),
}

/// The `Green` policy's parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GreenPolicy {
    /// The check-run names / status contexts that must all conclude success.
    /// Never empty: a policy requiring nothing would call every commit green.
    pub required: Vec<String>,
    /// How long a PENDING or BLIND answer stands before the loop asks again.
    /// A green or red answer is final for its revision and never re-asked.
    pub recheck_ms: u64,
    /// How far back from HEAD the loop looks for a green revision.
    pub max_candidates: usize,
}

/// One check's state on one commit, as the forge reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    /// Concluded success.
    Success,
    /// Queued, in progress, or a status still `pending`.
    Pending,
    /// Concluded anything else (failure, cancelled, timed out, error, …).
    Failed,
}

/// A named check result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    /// The check-run name or status context.
    pub name: String,
    /// Its state.
    pub state: CheckState,
}

/// What the required checks say about one revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChecksVerdict {
    /// Every required check concluded success.
    Green,
    /// None failed, but these have not concluded (or not appeared) yet.
    Pending {
        /// The required checks still outstanding.
        waiting: Vec<String>,
    },
    /// These required checks concluded without success.
    Red {
        /// The failed required checks.
        failed: Vec<String>,
    },
    /// The checks could not be read (unreachable forge, rejected token).
    Blind {
        /// Why.
        reason: String,
    },
}

impl ChecksVerdict {
    /// Whether this answer is final for its revision (never re-asked).
    #[must_use]
    pub fn is_final(&self) -> bool {
        matches!(self, Self::Green | Self::Red { .. })
    }
}

/// Judge one revision's results against the required set.
///
/// A failed required check makes the revision red even while others are
/// pending: it will not become green. A required check that has not appeared
/// is pending, never absent-means-fine.
#[must_use]
pub fn verdict(required: &[String], results: &[CheckResult]) -> ChecksVerdict {
    let mut failed = Vec::new();
    let mut waiting = Vec::new();
    for name in required {
        match results.iter().find(|r| &r.name == name).map(|r| r.state) {
            Some(CheckState::Success) => {}
            Some(CheckState::Failed) => failed.push(name.clone()),
            Some(CheckState::Pending) | None => waiting.push(name.clone()),
        }
    }
    if !failed.is_empty() {
        ChecksVerdict::Red { failed }
    } else if !waiting.is_empty() {
        ChecksVerdict::Pending { waiting }
    } else {
        ChecksVerdict::Green
    }
}

/// A cached answer and when it was obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cached {
    pub(crate) verdict: ChecksVerdict,
    pub(crate) at_ms: u64,
}

/// Whether a cached answer can stand at `now_ms`.
pub(crate) fn still_valid(c: &Cached, now_ms: u64, recheck_ms: u64) -> bool {
    c.verdict.is_final() || now_ms.saturating_sub(c.at_ms) < recheck_ms
}

/// The loop's per-revision cache, keyed by revision.
pub(crate) type Cache = std::collections::HashMap<Rev, Cached>;

#[cfg(test)]
mod tests {
    use super::*;

    fn r(name: &str, state: CheckState) -> CheckResult {
        CheckResult {
            name: name.to_owned(),
            state,
        }
    }

    fn req() -> Vec<String> {
        vec!["promotion-gate".to_owned(), "blue-check".to_owned()]
    }

    #[test]
    fn all_required_success_is_green_and_extra_checks_do_not_matter() {
        let results = [
            r("promotion-gate", CheckState::Success),
            r("blue-check", CheckState::Success),
            r("unrelated", CheckState::Failed),
        ];
        assert_eq!(verdict(&req(), &results), ChecksVerdict::Green);
    }

    #[test]
    fn a_missing_required_check_is_pending_not_green() {
        let results = [r("promotion-gate", CheckState::Success)];
        assert_eq!(
            verdict(&req(), &results),
            ChecksVerdict::Pending {
                waiting: vec!["blue-check".to_owned()]
            }
        );
    }

    #[test]
    fn a_failure_is_red_even_while_another_is_pending() {
        let results = [
            r("promotion-gate", CheckState::Pending),
            r("blue-check", CheckState::Failed),
        ];
        assert_eq!(
            verdict(&req(), &results),
            ChecksVerdict::Red {
                failed: vec!["blue-check".to_owned()]
            }
        );
    }

    #[test]
    fn only_final_answers_are_cached_forever() {
        let c = |v| Cached { verdict: v, at_ms: 0 };
        assert!(still_valid(&c(ChecksVerdict::Green), 1_000_000, 10));
        assert!(still_valid(&c(ChecksVerdict::Red { failed: vec![] }), 1_000_000, 10));
        let pending = c(ChecksVerdict::Pending { waiting: vec![] });
        assert!(still_valid(&pending, 9, 10));
        assert!(!still_valid(&pending, 10, 10), "a pending answer is re-asked after recheck");
        let blind = c(ChecksVerdict::Blind { reason: String::new() });
        assert!(!still_valid(&blind, 10, 10), "so is a blind one");
    }
}
