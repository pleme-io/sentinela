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

use crate::env::{EnvError, GitopsEnv, Heartbeat, LoopConfig};
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
    /// The post-build re-probe could not re-confirm HEAD (empty answer —
    /// e.g. the branch was deleted/reset mid-build). Fail-closed: the
    /// built rev was NOT activated; retry next cadence.
    ReprobeInconclusive {
        /// The rev that was built but not activated.
        built: Rev,
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

impl TickOutcome {
    /// The variant name, for the heartbeat and for logs. Exhaustive by
    /// construction: a new variant is a compile error here, so it cannot
    /// be published as an unnamed pulse.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::CoolingDown { .. } => "coolingDown",
            Self::Unchanged { .. } => "unchanged",
            Self::Unresolvable => "unresolvable",
            Self::ProbeError { .. } => "probeError",
            Self::BuildFailed { .. } => "buildFailed",
            Self::Deferred { .. } => "deferred",
            Self::ReprobeInconclusive { .. } => "reprobeInconclusive",
            Self::SwitchFailed { .. } => "switchFailed",
            Self::Deployed { .. } => "deployed",
        }
    }

    /// Branch HEAD as this tick observed it, when it got far enough to
    /// observe one.
    ///
    /// `None` for the three outcomes that never obtained a HEAD
    /// (`CoolingDown`, `Unresolvable`, `ProbeError`) — reporting a
    /// remembered rev there would be exactly the fabricate-an-unmeasured-
    /// value mistake this whole change exists to remove. For `Deferred`
    /// the answer is `newer`, not `built`: `newer` is what the re-probe
    /// actually saw.
    #[must_use]
    pub fn observed_head(&self) -> Option<&Rev> {
        match self {
            Self::CoolingDown { .. } | Self::Unresolvable | Self::ProbeError { .. } => None,
            Self::Unchanged { rev }
            | Self::BuildFailed { rev, .. }
            | Self::SwitchFailed { rev, .. }
            | Self::Deployed { rev, .. } => Some(rev),
            Self::Deferred { newer, .. } => Some(newer),
            Self::ReprobeInconclusive { built } => Some(built),
        }
    }
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
        let outcome = self.tick_inner(env);
        // ── ★ THE PULSE IS WRITTEN HERE, NOT INSIDE `tick_inner` ──────────
        // `tick_inner` has nine return points and every one of them is a
        // real outcome the operator needs counted as "the loop was alive".
        // A `write_heartbeat` call at the end of the body would be skipped
        // by all eight early returns, and — worse — the tenth return point
        // someone adds later would skip it silently. A wrapper cannot be
        // bypassed by adding a `return` to the body, so liveness reporting
        // is structural rather than a rule contributors must remember.
        //
        // Best-effort by design: a loop that did its work but could not
        // record its pulse has still done its work. The failure is logged,
        // never propagated — a read-only state dir must not stop deploys.
        let beat = Heartbeat {
            at_unix_ms: env.now_unix_ms(),
            outcome: outcome.kind().to_owned(),
            head_rev: outcome.observed_head().cloned(),
        };
        if let Err(e) = env.write_heartbeat(&beat) {
            tracing::warn!(error = %e, "sentinela: could not write heartbeat (loop is fine)");
        }
        outcome
    }

    /// The cycle proper. Every `return` here is a completed tick; the
    /// heartbeat is applied by [`Sentinela::tick`], which wraps this.
    fn tick_inner<E: GitopsEnv>(&mut self, env: &E) -> TickOutcome {
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
        let mut chain = match env.load_chain() {
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
            // Best-effort attest (the system is unchanged, so a persist
            // failure here corrupts nothing).
            let _ = self.record(&mut chain, env, head, Outcome::failed(e.to_string()));
            return self.enter_cooldown(env, out);
        }

        // Post-build freshness re-check (no-downgrade + fail-closed). We
        // activate ONLY when the re-probe re-confirms HEAD == the rev we
        // just built. A moved HEAD, a vanished branch, or a probe error
        // must NOT activate a rev we can no longer confirm is HEAD.
        match env.probe_head() {
            // Re-confirmed still HEAD → fall through to activation.
            Ok(Some(confirmed)) if confirmed == head => {}
            // HEAD moved during the build → defer; the newer rev deploys
            // next tick (no cooldown — deferral is not a failure).
            Ok(Some(newer)) => {
                let out = TickOutcome::Deferred { built: head.clone(), newer: newer.clone() };
                let _ = self.record(&mut chain, env, head, Outcome::Deferred { newer });
                self.state = State::Idle;
                return out;
            }
            // Empty re-probe (branch deleted/reset mid-build). Fail-closed:
            // cannot confirm HEAD → do not activate. Retry next cadence
            // (transient branch state, no cooldown).
            Ok(None) => {
                tracing::warn!(
                    rev = head.short(),
                    "post-build re-probe empty — not activating (fail-closed)"
                );
                self.state = State::Idle;
                return TickOutcome::ReprobeInconclusive { built: head };
            }
            // Re-probe errored → cannot confirm freshness. Fail-closed +
            // cooldown (a health problem that must back off, symmetric with
            // build/switch failures).
            Err(e) => {
                return self.enter_cooldown(env, TickOutcome::ProbeError { error: e.to_string() });
            }
        }

        // Act → switch (re-check confirmed head is still HEAD).
        match env.switch(&head) {
            Ok(generation) => {
                // Attest before idle. A persist failure would leave the
                // on-disk chain behind the real system → a re-deploy loop
                // on the next skip-if-unchanged check; treat it as a
                // (cooling-down) failure, never a silent Deployed.
                match self.record(&mut chain, env, head.clone(), Outcome::Activated { generation }) {
                    Ok(()) => {
                        self.state = State::Idle;
                        TickOutcome::Deployed { rev: head, generation }
                    }
                    Err(e) => {
                        let out = TickOutcome::SwitchFailed {
                            rev: head.clone(),
                            error: ["activated, but receipt persist failed: ", &e.to_string()]
                                .concat(),
                        };
                        self.enter_cooldown(env, out)
                    }
                }
            }
            Err(e) => {
                let out = TickOutcome::SwitchFailed { rev: head.clone(), error: e.to_string() };
                let _ = self.record(&mut chain, env, head, Outcome::failed(e.to_string()));
                self.enter_cooldown(env, out)
            }
        }
    }

    /// Append `outcome` for `rev` to `chain` and persist. Returns the
    /// persist result so the caller can distinguish a durable receipt
    /// (safe to report Deployed + idle) from a persist failure (the chain
    /// would fall behind the real system → must cool down, never loop).
    ///
    /// # Errors
    /// The [`EnvError`] from `persist_chain`.
    fn record<E: GitopsEnv>(
        &self,
        chain: &mut ReceiptChain,
        env: &E,
        rev: Rev,
        outcome: Outcome,
    ) -> Result<(), EnvError> {
        let receipt = chain.next_receipt(rev, outcome, env.now_unix_ms());
        // `append` cannot fail — `next_receipt` builds a correctly linked
        // receipt for this exact chain.
        let _ = chain.append(receipt);
        env.persist_chain(chain)
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

    /// ── ★ LIVENESS IS ONLY REAL IF EVERY PATH REPORTS IT ─────────────────
    /// Drives one tick into each terminal outcome and asserts a pulse was
    /// published for it. The failure this closes is not hypothetical: cid's
    /// daemon died and `status` kept reporting `consecutive_failures: 0,
    /// chain_verified: true` from its last good receipt, because a stopped
    /// loop writes nothing and a chain cannot record a tick that never ran.
    ///
    /// The valuable arms are the FAIL-CLOSED ones. A heartbeat that only
    /// appears on success would leave a permanently-failing loop looking
    /// dead and a dead loop looking failing — the two states we most need
    /// to tell apart.
    ///
    /// Red run: move the `write_heartbeat` call from `tick` into the end of
    /// `tick_inner`'s body and every early-returning arm here goes red
    /// (7 of 9), which is exactly why it is a wrapper.
    #[test]
    fn every_tick_outcome_publishes_exactly_one_heartbeat() {
        // (env-builder, expected outcome kind, expected observed head)
        let cases: Vec<(Box<dyn Fn() -> MockEnv>, &str, Option<Rev>)> = vec![
            (
                Box::new(|| {
                    let e = MockEnv::with_probes(vec![Ok(Some(rev(1))), Ok(Some(rev(1)))]);
                    e.set_switch_result(Ok(Generation(7)));
                    e
                }),
                "deployed",
                Some(rev(1)),
            ),
            (
                Box::new(|| MockEnv::with_probes(vec![Ok(None)])),
                "unresolvable",
                None,
            ),
            (
                Box::new(|| {
                    MockEnv::with_probes(vec![Err(EnvError::ProbeFailed("boom".into()))])
                }),
                "probeError",
                None,
            ),
            (
                Box::new(|| {
                    let e = MockEnv::with_probes(vec![Ok(Some(rev(2)))]);
                    e.set_build_result(Err(EnvError::BuildFailed("nope".into())));
                    e
                }),
                "buildFailed",
                Some(rev(2)),
            ),
            (
                Box::new(|| MockEnv::with_probes(vec![Ok(Some(rev(3))), Ok(Some(rev(4)))])),
                "deferred",
                Some(rev(4)),
            ),
            (
                Box::new(|| MockEnv::with_probes(vec![Ok(Some(rev(5))), Ok(None)])),
                "reprobeInconclusive",
                Some(rev(5)),
            ),
            (
                Box::new(|| {
                    let e = MockEnv::with_probes(vec![Ok(Some(rev(6))), Ok(Some(rev(6)))]);
                    e.set_switch_result(Err(EnvError::SwitchFailed("denied".into())));
                    e
                }),
                "switchFailed",
                Some(rev(6)),
            ),
        ];

        for (build_env, expected_kind, expected_head) in cases {
            let env = build_env();
            let mut s = Sentinela::new(cfg());
            let out = s.tick(&env);
            assert_eq!(out.kind(), expected_kind, "wrong outcome for this case");

            let beats = env.heartbeats.borrow();
            assert_eq!(
                beats.len(),
                1,
                "outcome `{expected_kind}` published {} heartbeats, expected exactly 1",
                beats.len()
            );
            assert_eq!(beats[0].outcome, expected_kind);
            assert_eq!(
                beats[0].head_rev, expected_head,
                "outcome `{expected_kind}` reported the wrong observed head"
            );
        }
    }

    /// `Unchanged` and `CoolingDown` need a prior tick to reach, so they
    /// get their own case — with the SECOND tick's pulse checked.
    #[test]
    fn the_quiet_outcomes_publish_a_pulse_too() {
        // Unchanged: deploy, then probe the same rev again.
        let env = MockEnv::with_probes(vec![Ok(Some(rev(1))), Ok(Some(rev(1))), Ok(Some(rev(1)))]);
        env.set_switch_result(Ok(Generation(1)));
        let mut s = Sentinela::new(cfg());
        s.tick(&env);
        let out = s.tick(&env);
        assert_eq!(out.kind(), "unchanged");
        let beats = env.heartbeats.borrow();
        assert_eq!(beats.len(), 2, "an idle loop must still prove it is alive");
        assert_eq!(beats[1].outcome, "unchanged");
        assert_eq!(beats[1].head_rev, Some(rev(1)));
        drop(beats);

        // CoolingDown: fail, then tick again inside the cooldown window.
        let env2 = MockEnv::with_probes(vec![Err(EnvError::ProbeFailed("x".into()))]);
        let mut s2 = Sentinela::new(cfg());
        s2.tick(&env2);
        let out2 = s2.tick(&env2);
        assert_eq!(out2.kind(), "coolingDown");
        let beats2 = env2.heartbeats.borrow();
        assert_eq!(beats2.len(), 2, "a cooling loop is alive and must say so");
        assert_eq!(beats2[1].outcome, "coolingDown");
        assert_eq!(
            beats2[1].head_rev, None,
            "a cooling tick observed no HEAD and must not report one"
        );
    }

    /// A loop that cannot record its pulse has still done its work. The
    /// heartbeat is diagnostics, never a precondition for converging.
    #[test]
    fn a_heartbeat_write_failure_does_not_change_the_outcome() {
        let env = MockEnv::with_probes(vec![Ok(Some(rev(1))), Ok(Some(rev(1)))]);
        env.set_switch_result(Ok(Generation(9)));
        env.set_heartbeat_result(Err(EnvError::HeartbeatIo("read-only fs".into())));
        let mut s = Sentinela::new(cfg());
        let out = s.tick(&env);
        assert_eq!(
            out,
            TickOutcome::Deployed {
                rev: rev(1),
                generation: Generation(9)
            }
        );
        assert!(
            env.heartbeats.borrow().is_empty(),
            "the write failed, so nothing was stored"
        );
        assert_eq!(
            env.chain().last_activated_rev(),
            Some(&rev(1)),
            "but the deploy still happened"
        );
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
    fn persist_failure_after_switch_cools_down_and_does_not_loop() {
        // The critical hole the happy-path tests missed: a switch succeeds
        // but the receipt cannot be persisted. Must NOT return Deployed
        // (which would let skip-if-unchanged re-deploy forever); must cool
        // down and surface the failure.
        let env = MockEnv::with_probes(vec![Ok(Some(rev(1))), Ok(Some(rev(1)))]);
        env.set_persist_result(Err(EnvError::ReceiptIo("disk full".into())));
        env.set_now_ms(1_000);
        let mut s = Sentinela::new(cfg());
        let out = s.tick(&env);
        // Switch ran, but the outcome is a cooling-down failure, not Deployed.
        assert_eq!(*env.switches.borrow(), vec![rev(1)]);
        assert!(matches!(out, TickOutcome::SwitchFailed { .. }), "got {out:?}");
        assert_eq!(s.state(), &State::CoolingDown { until_unix_ms: 2_000 });
        // The chain was NOT advanced (persist failed) — so no false
        // "already deployed" claim next tick.
        assert!(env.chain().last_activated_rev().is_none());
    }

    #[test]
    fn reprobe_error_after_build_fails_closed_and_cools_down() {
        // Pre-build probe ok (rev 1); post-build re-probe errors. Must NOT
        // switch (can't confirm freshness) and must cool down.
        let env = MockEnv::with_probes(vec![
            Ok(Some(rev(1))),
            Err(EnvError::ProbeFailed("timeout".into())),
        ]);
        env.set_now_ms(3_000);
        let mut s = Sentinela::new(cfg());
        let out = s.tick(&env);
        assert_eq!(*env.builds.borrow(), vec![rev(1)]);
        assert!(env.switches.borrow().is_empty(), "must not activate when re-probe is uncertain");
        assert!(matches!(out, TickOutcome::ProbeError { .. }));
        assert_eq!(s.state(), &State::CoolingDown { until_unix_ms: 4_000 });
    }

    #[test]
    fn reprobe_empty_after_build_is_inconclusive_no_switch() {
        // Post-build re-probe returns None (branch vanished/reset). Must
        // NOT activate; retry next cadence (no cooldown).
        let env = MockEnv::with_probes(vec![Ok(Some(rev(1))), Ok(None)]);
        let mut s = Sentinela::new(cfg());
        let out = s.tick(&env);
        assert_eq!(*env.builds.borrow(), vec![rev(1)]);
        assert!(env.switches.borrow().is_empty(), "must not activate an unconfirmable rev");
        assert_eq!(out, TickOutcome::ReprobeInconclusive { built: rev(1) });
        assert_eq!(s.state(), &State::Idle);
    }

    #[test]
    fn chain_load_error_fails_closed_and_cools_down() {
        let env = MockEnv::with_probes(vec![Ok(Some(rev(1)))]);
        env.set_load_result(Some(Err(EnvError::ReceiptIo("corrupt".into()))));
        env.set_now_ms(500);
        let mut s = Sentinela::new(cfg());
        let out = s.tick(&env);
        assert!(env.builds.borrow().is_empty(), "a chain-load error deploys nothing");
        assert!(env.switches.borrow().is_empty());
        assert!(matches!(out, TickOutcome::ProbeError { .. }));
        assert_eq!(s.state(), &State::CoolingDown { until_unix_ms: 1_500 });
    }

    #[test]
    fn failed_rev_retries_the_same_rev_after_cooldown() {
        // A build failure records a Failed receipt + cools down; once the
        // cooldown elapses the SAME rev is retried (skip-if-unchanged does
        // not fire, because the last *activated* rev is still None).
        let env = MockEnv::default();
        env.push_probe(Ok(Some(rev(1)))); // tick 1: build fails
        env.set_build_result(Err(EnvError::BuildFailed("transient".into())));
        env.set_now_ms(0);
        let mut s = Sentinela::new(cfg());
        assert!(matches!(s.tick(&env), TickOutcome::BuildFailed { .. }));
        assert_eq!(s.state(), &State::CoolingDown { until_unix_ms: 1_000 });
        // Cooldown elapses; build now succeeds → same rev deploys.
        env.set_build_result(Ok(()));
        env.set_now_ms(1_000);
        env.push_probe(Ok(Some(rev(1)))); // pre-build
        env.push_probe(Ok(Some(rev(1)))); // re-probe
        assert!(matches!(s.tick(&env), TickOutcome::Deployed { rev: r, .. } if r == rev(1)));
        assert_eq!(env.chain().last_activated_rev(), Some(&rev(1)));
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
