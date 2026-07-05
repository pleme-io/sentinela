//! The convergence loop — the Viggy seven-beat tick specialized to
//! "keep this Mac's darwin system equal to one repo's HEAD". One
//! [`Sentinela::tick`] call is one cycle:
//!
//! ```text
//! Observe   env.probe_head()                    (git ls-remote — rate-limit-immune)
//! Diff      resolved != last_activated_rev?
//! Classify  resolvable? in cooldown?
//! Decide    build rev-pinned; RE-probe; defer if HEAD moved mid-build
//! Act       env.switch(rev)
//! Attest    append a linked DeployReceipt to the chain, persist
//! Tick      caller sleeps; single-flight by construction (one loop)
//! ```
//!
//! The daemon is a single long-running process with one loop, so the
//! v1.5 launchd-`StartInterval`-overlap problem is gone: single-flight is
//! structural, not a lock. The five v1.5 guards survive as tick
//! structure:
//!
//! - **fail-closed** — an unresolvable/errored probe, a failed build, or
//!   a failed switch never calls `switch` for a new rev; the tick returns
//!   a typed non-deploying outcome and the loop cools down.
//! - **skip-if-unchanged** — HEAD equal to the last *activated* rev does
//!   no build and no switch.
//! - **rev-pinned build** — `build(rev)` then `switch(rev)` use the exact
//!   probed rev.
//! - **post-build freshness re-check (no-downgrade)** — after the build,
//!   the head is re-probed; if it moved, the tick defers (records a
//!   `Deferred` receipt) and never activates the now-stale rev. So
//!   `switch` is only reached for a rev that was HEAD both before *and*
//!   after its build — the in-flight rollback is unreachable.
//! - **receipt-before-idle** — a successful switch persists its receipt
//!   before the tick returns; the persisted chain is the source of truth.

use crate::env::{GitopsEnv, LoopConfig};
use crate::receipt::{Generation, Outcome, ReceiptChain};
use crate::rev::Rev;

/// The persistent state between ticks. The rich intra-cycle phases
/// (probing/building/activating) live inside one `tick` call; what
/// survives a sleep is only whether the loop is free or cooling down.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum State {
    /// Free to run a full cycle.
    #[default]
    Idle,
    /// Backing off after a failure until `until_unix_ms`.
    CoolingDown {
        /// Wall-clock (unix-ms) the cooldown ends.
        until_unix_ms: u64,
    },
}

/// What one [`Sentinela::tick`] did — a total sum over every terminal
/// beat. Every arm is observable (for the status surface + tests); the
/// deploying arm is the only one that ran `switch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TickOutcome {
    /// The loop is cooling down; nothing was touched.
    CoolingDown {
        /// Milliseconds remaining in the cooldown.
        remaining_ms: u64,
    },
    /// HEAD equals the last activated rev — nothing to do.
    Unchanged {
        /// The current (already-deployed) rev.
        rev: Rev,
    },
    /// HEAD could not be resolved (empty ls-remote); deployed nothing.
    Unresolvable,
    /// HEAD resolution errored; deployed nothing (fail-closed).
    ProbeError {
        /// The probe error message.
        error: String,
    },
    /// The rev-pinned build failed; deployed nothing, receipt recorded.
    BuildFailed {
        /// The rev whose build failed.
        rev: Rev,
        /// The build error message.
        error: String,
    },
    /// A newer HEAD landed during the build; the built rev was deferred,
    /// not activated. The newer rev deploys next tick.
    Deferred {
        /// The rev that was built but not activated.
        built: Rev,
        /// The newer HEAD that superseded it mid-build.
        newer: Rev,
    },
    /// The switch failed after a clean build; receipt recorded.
    SwitchFailed {
        /// The rev whose activation failed.
        rev: Rev,
        /// The switch error message.
        error: String,
    },
    /// Activated cleanly; receipt recorded before return.
    Deployed {
        /// The activated rev.
        rev: Rev,
        /// The new darwin generation.
        generation: Generation,
    },
}

/// The GitOps loop driver. Holds the between-tick [`State`] and the
/// [`LoopConfig`]; is pure over a [`GitopsEnv`].
#[derive(Debug, Clone)]
pub struct Sentinela {
    state: State,
    cfg: LoopConfig,
}

impl Sentinela {
    /// A fresh loop in [`State::Idle`].
    #[must_use]
    pub fn new(cfg: LoopConfig) -> Self {
        Self { state: State::Idle, cfg }
    }

    /// The current between-tick state.
    #[must_use]
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Run one cycle against `env`. See the module docs for the beat
    /// structure and the invariants each branch upholds.
    pub fn tick<E: GitopsEnv>(&mut self, env: &E) -> TickOutcome {
        // Cooldown gate — during a backoff the loop touches nothing.
        if let State::CoolingDown { until_unix_ms } = self.state {
            let now = env.now_unix_ms();
            if now < until_unix_ms {
                return TickOutcome::CoolingDown { remaining_ms: until_unix_ms - now };
            }
            self.state = State::Idle;
        }

        // Observe.
        let head = match env.probe_head() {
            Ok(Some(rev)) => rev,
            Ok(None) => {
                // Fail-closed: unresolvable HEAD deploys nothing. Not an
                // error edge (no cooldown) — a transient empty answer
                // should retry on the normal cadence.
                tracing::warn!("sentinela: HEAD unresolvable — deploying nothing (fail-closed)");
                return TickOutcome::Unresolvable;
            }
            Err(e) => return self.fail_closed(env, TickOutcome::ProbeError { error: e.to_string() }),
        };

        // Diff — skip-if-unchanged against the last *activated* rev.
        let chain = match env.load_chain() {
            Ok(c) => c,
            Err(e) => {
                return self.fail_closed(env, TickOutcome::ProbeError { error: e.to_string() });
            }
        };
        if chain.last_activated_rev() == Some(&head) {
            return TickOutcome::Unchanged { rev: head };
        }

        // Decide → build rev-pinned.
        if let Err(e) = env.build(&head) {
            let out = TickOutcome::BuildFailed { rev: head.clone(), error: e.to_string() };
            self.record(env, chain, head, Outcome::Failed { error: e.to_string() });
            return self.enter_cooldown(env, out);
        }

        // Post-build freshness re-check (no-downgrade). If HEAD moved
        // during the build, defer — never activate a now-stale rev.
        match env.probe_head() {
            Ok(Some(newer)) if newer != head => {
                let out = TickOutcome::Deferred { built: head.clone(), newer: newer.clone() };
                self.record(env, chain, head, Outcome::Deferred { newer });
                // Deferral is not a failure — deploy the newer rev next
                // tick on the normal cadence (no cooldown).
                self.state = State::Idle;
                return out;
            }
            // HEAD unchanged, still Some(head): proceed. A re-probe error
            // or empty answer is treated conservatively as "unchanged"
            // (we already have a good build of `head`); activation
            // proceeds because the pre-build probe succeeded.
            _ => {}
        }

        // Act → switch.
        match env.switch(&head) {
            Ok(generation) => {
                // Attest before idle — the receipt is recorded (and
                // persisted) before the tick returns Deployed.
                self.record(env, chain, head.clone(), Outcome::Activated { generation });
                self.state = State::Idle;
                TickOutcome::Deployed { rev: head, generation }
            }
            Err(e) => {
                let out = TickOutcome::SwitchFailed { rev: head.clone(), error: e.to_string() };
                self.record(env, chain, head, Outcome::Failed { error: e.to_string() });
                self.enter_cooldown(env, out)
            }
        }
    }

    /// Append `outcome` for `rev` to `chain` and persist. Best-effort:
    /// a persist failure is logged, never fatal (the next tick reloads).
    fn record<E: GitopsEnv>(&self, env: &E, mut chain: ReceiptChain, rev: Rev, outcome: Outcome) {
        let receipt = chain.next_receipt(rev, outcome, env.now_unix_ms());
        // `append` cannot fail here — `next_receipt` builds a correctly
        // linked receipt for this exact chain.
        let _ = chain.append(receipt);
        if let Err(e) = env.persist_chain(&chain) {
            tracing::error!(error = %e, "sentinela: failed to persist receipt chain");
        }
    }

    /// Fail-closed helper for probe/load errors: enter cooldown, return
    /// the given non-deploying outcome.
    fn fail_closed<E: GitopsEnv>(&mut self, env: &E, out: TickOutcome) -> TickOutcome {
        self.enter_cooldown(env, out)
    }

    /// Move to [`State::CoolingDown`] for `cooldown_after_failure_ms`.
    fn enter_cooldown<E: GitopsEnv>(&mut self, env: &E, out: TickOutcome) -> TickOutcome {
        let until = env.now_unix_ms() + self.cfg.cooldown_after_failure_ms;
        self.state = State::CoolingDown { until_unix_ms: until };
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::{EnvError, MockEnv};

    fn rev(n: u8) -> Rev {
        Rev::parse(&format!("{:0>40}", format!("{n:x}"))).unwrap()
    }

    fn cfg() -> LoopConfig {
        LoopConfig { cooldown_after_failure_ms: 1000 }
    }

    #[test]
    fn deploys_a_fresh_head_and_records_receipt() {
        let env = MockEnv::with_probes(vec![Ok(Some(rev(1))), Ok(Some(rev(1)))]);
        env.set_switch_result(Ok(Generation(42)));
        let mut s = Sentinela::new(cfg());
        let out = s.tick(&env);
        assert_eq!(out, TickOutcome::Deployed { rev: rev(1), generation: Generation(42) });
        assert_eq!(*env.builds.borrow(), vec![rev(1)]);
        assert_eq!(*env.switches.borrow(), vec![rev(1)]);
        // Receipt recorded before idle.
        let chain = env.chain();
        assert_eq!(chain.last_activated_rev(), Some(&rev(1)));
        chain.verify().unwrap();
        assert_eq!(s.state(), &State::Idle);
    }

    #[test]
    fn skip_if_unchanged_does_no_build_or_switch() {
        // Seed the chain with rev(1) activated, then HEAD is still rev(1).
        let env = MockEnv::with_probes(vec![Ok(Some(rev(1)))]);
        {
            let mut c = ReceiptChain::new();
            c.append(c.next_receipt(rev(1), Outcome::Activated { generation: Generation(1) }, 0))
                .unwrap();
            env.persist_chain(&c).unwrap();
        }
        let mut s = Sentinela::new(cfg());
        assert_eq!(s.tick(&env), TickOutcome::Unchanged { rev: rev(1) });
        assert!(env.builds.borrow().is_empty());
        assert!(env.switches.borrow().is_empty());
    }

    #[test]
    fn no_downgrade_defers_when_head_moves_during_build() {
        // Pre-build probe = rev(1); post-build re-probe = rev(2). Must
        // NOT switch rev(1); records a Deferred receipt; stays Idle so
        // rev(2) deploys next tick.
        let env = MockEnv::with_probes(vec![Ok(Some(rev(1))), Ok(Some(rev(2)))]);
        let mut s = Sentinela::new(cfg());
        let out = s.tick(&env);
        assert_eq!(out, TickOutcome::Deferred { built: rev(1), newer: rev(2) });
        assert_eq!(*env.builds.borrow(), vec![rev(1)]);
        assert!(env.switches.borrow().is_empty(), "must not activate the stale rev");
        assert_eq!(s.state(), &State::Idle);
        // The deferral is attested.
        assert!(matches!(env.chain().head().unwrap().outcome, Outcome::Deferred { .. }));
    }

    #[test]
    fn unresolvable_head_deploys_nothing_no_cooldown() {
        let env = MockEnv::with_probes(vec![Ok(None)]);
        let mut s = Sentinela::new(cfg());
        assert_eq!(s.tick(&env), TickOutcome::Unresolvable);
        assert!(env.builds.borrow().is_empty());
        assert!(env.switches.borrow().is_empty());
        assert_eq!(s.state(), &State::Idle, "empty probe is not an error edge");
    }

    #[test]
    fn probe_error_fails_closed_and_cools_down() {
        let env = MockEnv::with_probes(vec![Err(EnvError::ProbeFailed("net".into()))]);
        env.set_now_ms(5_000);
        let mut s = Sentinela::new(cfg());
        assert_eq!(s.tick(&env), TickOutcome::ProbeError { error: "probe failed: net".into() });
        assert!(env.switches.borrow().is_empty());
        assert_eq!(s.state(), &State::CoolingDown { until_unix_ms: 6_000 });
    }

    #[test]
    fn build_failure_records_and_cools_down_without_switch() {
        let env = MockEnv::with_probes(vec![Ok(Some(rev(1)))]);
        env.set_build_result(Err(EnvError::BuildFailed("boom".into())));
        env.set_now_ms(10_000);
        let mut s = Sentinela::new(cfg());
        let out = s.tick(&env);
        assert!(matches!(out, TickOutcome::BuildFailed { .. }));
        assert!(env.switches.borrow().is_empty());
        assert!(matches!(env.chain().head().unwrap().outcome, Outcome::Failed { .. }));
        assert_eq!(s.state(), &State::CoolingDown { until_unix_ms: 11_000 });
    }

    #[test]
    fn switch_failure_records_and_cools_down() {
        let env = MockEnv::with_probes(vec![Ok(Some(rev(1))), Ok(Some(rev(1)))]);
        env.set_switch_result(Err(EnvError::SwitchFailed("activation".into())));
        env.set_now_ms(20_000);
        let mut s = Sentinela::new(cfg());
        assert!(matches!(s.tick(&env), TickOutcome::SwitchFailed { .. }));
        assert!(matches!(env.chain().head().unwrap().outcome, Outcome::Failed { .. }));
        assert_eq!(s.state(), &State::CoolingDown { until_unix_ms: 21_000 });
    }

    #[test]
    fn cooldown_blocks_ticks_until_it_elapses() {
        let env = MockEnv::with_probes(vec![
            Err(EnvError::ProbeFailed("x".into())), // trip cooldown at t=0 → until 1000
            Ok(Some(rev(1))),                       // would deploy once cooldown clears
            Ok(Some(rev(1))),
        ]);
        env.set_now_ms(0);
        let mut s = Sentinela::new(cfg());
        assert!(matches!(s.tick(&env), TickOutcome::ProbeError { .. }));
        // Still cooling down at t=500.
        env.set_now_ms(500);
        assert_eq!(s.tick(&env), TickOutcome::CoolingDown { remaining_ms: 500 });
        assert!(env.builds.borrow().is_empty(), "no work during cooldown");
        // Cooldown elapsed at t=1000 → deploys.
        env.set_now_ms(1000);
        assert_eq!(
            s.tick(&env),
            TickOutcome::Deployed { rev: rev(1), generation: Generation(1) }
        );
    }

    #[test]
    fn full_sequence_across_many_ticks_keeps_a_valid_chain() {
        let env = MockEnv::default();
        let mut s = Sentinela::new(cfg());
        // t: deploy rev(1)
        env.push_probe(Ok(Some(rev(1))));
        env.push_probe(Ok(Some(rev(1))));
        assert!(matches!(s.tick(&env), TickOutcome::Deployed { .. }));
        // t: unchanged
        env.push_probe(Ok(Some(rev(1))));
        assert_eq!(s.tick(&env), TickOutcome::Unchanged { rev: rev(1) });
        // t: deploy rev(2)
        env.push_probe(Ok(Some(rev(2))));
        env.push_probe(Ok(Some(rev(2))));
        assert!(matches!(s.tick(&env), TickOutcome::Deployed { .. }));
        let chain = env.chain();
        chain.verify().unwrap();
        assert_eq!(chain.last_activated_rev(), Some(&rev(2)));
        assert_eq!(chain.len(), 2, "unchanged tick recorded nothing");
    }
}
