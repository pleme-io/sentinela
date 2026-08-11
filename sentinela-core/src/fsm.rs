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
    /// The switch was NOT attempted: an operator `fleet rebuild` holds the
    /// machine-wide rebuild lock, so this tick stood aside. Not a failure —
    /// no receipt, no cooldown — just a courtesy deferral that converges
    /// the moment the operator finishes. The built rev stays pending.
    SwitchDeferred {
        /// The rev that was built and is awaiting its switch.
        rev: Rev,
        /// Who holds the machine lock (`pid N · user` from the lock file).
        holder: String,
    },
    /// Activated a rev that is a verified ANCESTOR of the current HEAD —
    /// the starvation escape. Forward progress, deliberately not the newest
    /// rev; the next tick converges toward `newer`.
    DeployedBehind {
        /// The activated rev (an ancestor of `newer`).
        rev: Rev,
        /// The new darwin generation.
        generation: Generation,
        /// The HEAD this activation is behind.
        newer: Rev,
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
            Self::SwitchDeferred { .. } => "switchDeferred",
            Self::DeployedBehind { .. } => "deployedBehind",
            Self::Deployed { .. } => "deployed",
        }
    }

    /// How long the caller should sleep before the next tick.
    ///
    /// ── ★ THE CADENCE DECISION LIVES WITH THE OUTCOME ────────────────────
    /// The FSM decides not to cool down after a deferral — `tick_inner`'s
    /// deferral arm returns to `Idle` with the comment "deferral is not a
    /// failure" — and then the caller slept a full `poll_seconds` anyway,
    /// because `run()` had one `Duration` in scope and matched on nothing.
    /// The FSM's decision had no way to reach the thing that controls
    /// cadence, so it was silently overruled on every tick.
    ///
    /// Exhaustive with NO wildcard arm, exactly like [`Self::kind`]: a new
    /// outcome must state its own cadence, and cannot inherit a default that
    /// happens to be wrong for it.
    ///
    /// **Deliberately not a config knob.** These are bounds, not preferences
    /// — no value here changes what the loop DOES, only how soon it looks
    /// again — and a knob would freeze this shape as a public interface
    /// before it has earned one.
    #[must_use]
    pub fn next_delay(&self, cfg: &LoopConfig) -> std::time::Duration {
        /// After a deferral we ALREADY know a newer rev exists, so a full
        /// poll is pure added latency on a loop that is losing a race. Not
        /// zero, though: a cache-hit build can return in seconds, and a
        /// zero-delay retry would then be an unbounded `ls-remote`+build
        /// churn loop. One second keeps the fast path fast and still bounds
        /// the worst case to something a human can see in the log.
        const DEFERRED_RETRY_SECS: u64 = 1;
        /// A lock-held deferral retries slower than a branch deferral. The
        /// two share the "converge soon" shape, but a `Deferred` waits on a
        /// NEWER rev (each retry builds fresh work) while a
        /// `SwitchDeferred` waits on the OPERATOR's lock — the rev is
        /// unchanged, so a 1s retry would re-run the same cache-hit build
        /// dozens of times a minute for the whole operator hold. An operator
        /// rebuild owns the machine for minutes; 30s bounds that churn to a
        /// couple of builds a minute and still converges within half a
        /// minute of them finishing. A bound, not a preference — see the
        /// `next_delay` doc.
        const SWITCH_DEFERRED_RETRY_SECS: u64 = 30;

        let poll = std::time::Duration::from_secs(cfg.poll_seconds.max(1));
        match self {
            // Same reasoning as a deferral: a newer rev is already known,
            // so converge toward it now rather than after a full poll.
            Self::Deferred { .. } | Self::DeployedBehind { .. } => {
                std::time::Duration::from_secs(DEFERRED_RETRY_SECS)
            }
            Self::SwitchDeferred { .. } => {
                std::time::Duration::from_secs(SWITCH_DEFERRED_RETRY_SECS)
            }
            // Everything else waits a normal cycle. Note `CoolingDown` is
            // deliberately NOT lengthened here: the cooldown is a gate inside
            // `tick_inner`, not a longer sleep, so the loop must keep ticking
            // (and keep publishing a pulse) while it backs off. Sleeping the
            // cooldown here instead would starve liveness reporting.
            Self::CoolingDown { .. }
            | Self::Unchanged { .. }
            | Self::Unresolvable
            | Self::ProbeError { .. }
            | Self::BuildFailed { .. }
            | Self::ReprobeInconclusive { .. }
            | Self::SwitchFailed { .. }
            | Self::Deployed { .. } => poll,
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
            | Self::SwitchDeferred { rev, .. }
            | Self::Deployed { rev, .. } => Some(rev),
            Self::Deferred { newer, .. } | Self::DeployedBehind { newer, .. } => Some(newer),
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
        Self {
            state: State::Idle,
            cfg,
        }
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
            phase: crate::env::Phase::Resolved,
            head_rev: outcome.observed_head().cloned(),
            poll_seconds: self.cfg.poll_seconds,
            // A resolved tick has nothing in flight by definition. Clearing
            // it rather than carrying the last step forward: a stale drv
            // beside a finished outcome reads as a build still running.
            in_flight: None,
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
                return TickOutcome::CoolingDown {
                    remaining_ms: until_unix_ms - now,
                };
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
            Err(e) => {
                return self.fail_closed(
                    env,
                    TickOutcome::ProbeError {
                        error: e.to_string(),
                    },
                );
            }
        };

        // Diff — skip-if-unchanged against the last *activated* rev.
        let mut chain = match env.load_chain() {
            Ok(c) => c,
            Err(e) => {
                return self.fail_closed(
                    env,
                    TickOutcome::ProbeError {
                        error: e.to_string(),
                    },
                );
            }
        };
        if chain.last_activated_rev() == Some(&head) {
            return TickOutcome::Unchanged { rev: head };
        }

        // ── ★ PULSE BEFORE THE BUILD, NOT ONLY AFTER IT ──────────────────
        // `env.build` is the long pole — measured at 12m02s on ryn — and the
        // wrapper's pulse lands only once it RETURNS. That left the whole
        // build window with no pulse and no log line, so an observer could
        // not tell a healthy long build from a hung process, and
        // `convergence_gate` actively reported "the loop is stopped" against
        // its 180s budget. Publishing here makes the in-flight tick a thing
        // that EXISTS in the record rather than an absence to be interpreted.
        //
        // Best-effort and deliberately not propagated, exactly like the
        // wrapper's: a loop that cannot write its pulse has still done its
        // work, and a read-only state dir must never stop a deploy.
        //
        // Placement is inside the body, so unlike the wrapper this IS
        // bypassable by a future early return added above it. That is the
        // honest tier — only-mitigated, not structural — and it is why the
        // gate treats a MISSING in-flight pulse as "judge by the poll
        // budget" rather than trusting this to always be here.
        let in_flight = Heartbeat {
            at_unix_ms: env.now_unix_ms(),
            outcome: "building".to_owned(),
            phase: crate::env::Phase::InFlight,
            head_rev: Some(head.clone()),
            poll_seconds: self.cfg.poll_seconds,
            // Published BEFORE the build starts, so there is no step to
            // report yet. A driver that streams progress overwrites this
            // pulse as it goes; one that cannot leaves it None, which reads
            // as "not measured" rather than "not moving".
            in_flight: None,
        };
        if let Err(e) = env.write_heartbeat(&in_flight) {
            tracing::warn!(error = %e, "sentinela: could not write in-flight heartbeat (build proceeds)");
        }
        tracing::info!(rev = head.short(), "build started");

        // Decide → build rev-pinned.
        if let Err(e) = env.build(&head) {
            let out = TickOutcome::BuildFailed {
                rev: head.clone(),
                error: e.to_string(),
            };
            // Best-effort attest (the system is unchanged, so a persist
            // failure here corrupts nothing).
            let _ = self.record(
                &mut chain,
                env,
                head.clone(),
                Outcome::failed(e.to_string()),
            );

            // ── ★ THE SECOND ESCAPE: A RED HEAD MUST NOT STARVE THE NODE ──
            // Retrying is the right first answer — most build failures are
            // transient. It is the wrong LAST answer: a rev that fails to
            // build does not repair itself, so past some streak every further
            // tick is a full build spent to re-learn the same fact while a rev
            // we ALREADY BUILT sits unactivated. See
            // `land_last_good_after_failures` for the 2026-08-04 measurement
            // that motivated this.
            //
            // The record above is written FIRST, deliberately: the streak this
            // reads must include the failure we just had, so the threshold
            // counts attempts rather than attempts-minus-one.
            //
            // Both ancestry proofs are the deferral escape's, unchanged and
            // fail-closed. Nothing here weakens the strict path — a healthy
            // loop never reaches this branch at all.
            if let Some(out) = self.try_land_last_good(&mut chain, env, &head) {
                return out;
            }
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
                // ── ★ THE ESCAPE FROM STARVATION ─────────────────────────
                // "Still HEAD" is strictly stronger than "safe to activate".
                // When a build outlasts the interval between pushes, that
                // stronger condition is PERMANENTLY unsatisfiable and the
                // node starves — every build thrown away, forever. Measured
                // on ryn 2026-08-02: a 12m02s build against a sub-7m median
                // inter-commit gap.
                //
                // Two facts make landing `head` a FORWARD step rather than
                // the rollback the no-downgrade rule refuses:
                //   1. head is an ancestor of `newer` — the branch still
                //      contains it, so this is a step along the same
                //      history, merely not the newest one. A force-push,
                //      reset or revert fails this, which is exactly the
                //      2026-07-02 rollback the guard was written for.
                //   2. head is a descendant of what this node last
                //      activated — forward FOR THIS NODE, never backward.
                //
                // Both are required, both fail closed, and the whole path is
                // gated on an actual deferral streak so normal operation
                // keeps the strict rule. The post-build re-probe above is
                // untouched: this does not weaken the guard, it adds a
                // second, narrower door that only opens on the failure state
                // the guard would otherwise trap us in.
                let streak = chain.consecutive_deferrals();
                let threshold = self.cfg.land_ancestor_after_deferrals;
                if threshold > 0 && streak + 1 >= threshold {
                    let forward_on_branch = env.is_ancestor(&head, &newer);
                    let forward_for_node = match chain.last_activated_rev() {
                        // Nothing activated yet: any rev on the branch is
                        // forward for this node.
                        None => Ok(true),
                        Some(last) => env.is_ancestor(last, &head),
                    };
                    match (forward_on_branch, forward_for_node) {
                        (Ok(true), Ok(true)) => {
                            tracing::info!(
                                rev = head.short(),
                                newer = newer.short(),
                                deferrals = streak,
                                "starved: landing an ancestor of HEAD to make progress"
                            );
                            return self.activate(chain, env, head, Some(newer));
                        }
                        // Anything else — not an ancestor, a rollback, or an
                        // unanswerable question — defers exactly as before.
                        (a, b) => {
                            if let Some(e) = a.as_ref().err().or_else(|| b.as_ref().err()) {
                                tracing::warn!(
                                    error = %e,
                                    "ancestry unanswerable — deferring (fail-closed)"
                                );
                            }
                        }
                    }
                }
                let out = TickOutcome::Deferred {
                    built: head.clone(),
                    newer: newer.clone(),
                };
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
                return self.enter_cooldown(
                    env,
                    TickOutcome::ProbeError {
                        error: e.to_string(),
                    },
                );
            }
        }

        // Act → switch (re-check confirmed head is still HEAD).
        self.activate(chain, env, head, None)
    }

    /// After a failed build against `head`, decide whether to fall back to
    /// the newest rev this node already proved buildable.
    ///
    /// `Some(outcome)` means the fallback fired and `outcome` is the tick's
    /// result; `None` means it did not, and the caller proceeds to its normal
    /// cooldown. Returning the caller's outcome rather than a bool keeps the
    /// "which activation happened" decision in ONE place — the fallback shares
    /// [`Self::activate`], so it reports [`TickOutcome::DeployedBehind`] with
    /// the same meaning the deferral escape gives it: a verified ancestor of
    /// HEAD, landed knowingly.
    ///
    /// Every gate below fails closed — a missing candidate, an ancestry
    /// question the network cannot answer, or a threshold not yet reached all
    /// take the caller's cooldown path unchanged.
    fn try_land_last_good<E: GitopsEnv>(
        &mut self,
        chain: &mut ReceiptChain,
        env: &E,
        head: &Rev,
    ) -> Option<TickOutcome> {
        let threshold = self.cfg.land_last_good_after_failures;
        if threshold == 0 {
            return None;
        }
        let streak = chain.consecutive_failures();
        if streak < threshold {
            return None;
        }
        // The candidate is never speculative: `last_built_unactivated_rev`
        // only returns a rev carrying a receipt that this node built it, and
        // only searches back to the last activation, so it is newer than what
        // we run.
        let candidate = chain.last_built_unactivated_rev()?.clone();
        // Guard the degenerate case explicitly rather than relying on the
        // ancestry calls: a rev is its own ancestor under `merge-base
        // --is-ancestor`, so a candidate that IS head would otherwise pass
        // both checks and re-attempt the switch of a rev we just failed to
        // build. Cannot happen today (a failed build records `Failed`, never
        // `Deferred`), which is exactly why it deserves a guard rather than a
        // comment — the invariant lives in another function.
        if candidate == *head {
            return None;
        }
        // Forward along the same history: the branch must still contain the
        // candidate. A force-push, reset or revert fails this — the rollback
        // case the no-downgrade rule exists to refuse.
        let forward_on_branch = env.is_ancestor(&candidate, head);
        // Forward for THIS node: never activate something behind what we run.
        let forward_for_node = match chain.last_activated_rev() {
            None => Ok(true),
            Some(last) => env.is_ancestor(last, &candidate),
        };
        match (forward_on_branch, forward_for_node) {
            (Ok(true), Ok(true)) => {
                tracing::info!(
                    rev = candidate.short(),
                    head = head.short(),
                    failures = streak,
                    "head will not build: landing the newest rev that did"
                );
                // `activate` consumes the chain (it appends + persists), and
                // we hold it by reference. Taking it is sound precisely
                // because this arm RETURNS the tick: the caller's `chain` is
                // never read again on this path.
                Some(self.activate(std::mem::take(chain), env, candidate, Some(head.clone())))
            }
            (a, b) => {
                if let Some(e) = a.as_ref().err().or_else(|| b.as_ref().err()) {
                    tracing::warn!(
                        error = %e,
                        "ancestry unanswerable — not landing last-good (fail-closed)"
                    );
                }
                None
            }
        }
    }

    /// Switch to `rev` and attest, shared by the two paths that reach an
    /// activation: the strict one (the re-probe re-confirmed `rev` is HEAD)
    /// and the starvation escape (`rev` is a verified ancestor of HEAD).
    ///
    /// `behind` carries the newer HEAD when this is the escape path, so the
    /// outcome can say so rather than presenting a knowingly-superseded rev
    /// as a plain deploy.
    fn activate<E: GitopsEnv>(
        &mut self,
        mut chain: ReceiptChain,
        env: &E,
        rev: Rev,
        behind: Option<Rev>,
    ) -> TickOutcome {
        match env.switch(&rev) {
            Ok(generation) => {
                // Attest before idle. A persist failure would leave the
                // on-disk chain behind the real system → a re-deploy loop
                // on the next skip-if-unchanged check; treat it as a
                // (cooling-down) failure, never a silent Deployed.
                match self.record(
                    &mut chain,
                    env,
                    rev.clone(),
                    Outcome::Activated { generation },
                ) {
                    Ok(()) => {
                        self.state = State::Idle;
                        match behind {
                            None => TickOutcome::Deployed { rev, generation },
                            Some(newer) => TickOutcome::DeployedBehind {
                                rev,
                                generation,
                                newer,
                            },
                        }
                    }
                    Err(e) => {
                        let out = TickOutcome::SwitchFailed {
                            rev: rev.clone(),
                            error: ["activated, but receipt persist failed: ", &e.to_string()]
                                .concat(),
                        };
                        self.enter_cooldown(env, out)
                    }
                }
            }
            Err(EnvError::SwitchBusy(holder)) => {
                // NOT a failure: an operator `fleet rebuild` owns the
                // machine-wide rebuild lock right now. Stand aside — no
                // receipt (nothing changed), no cooldown (nothing broke) —
                // and retry on the bounded deferral cadence so the rev
                // converges the moment the operator finishes.
                tracing::info!(
                    rev = rev.short(),
                    holder = %holder,
                    "switch deferred: another rebuild holds the machine lock"
                );
                self.state = State::Idle;
                TickOutcome::SwitchDeferred { rev, holder }
            }
            Err(e) => {
                let out = TickOutcome::SwitchFailed {
                    rev: rev.clone(),
                    error: e.to_string(),
                };
                let _ = self.record(&mut chain, env, rev, Outcome::failed(e.to_string()));
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
        self.state = State::CoolingDown {
            until_unix_ms: until,
        };
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
        LoopConfig {
            cooldown_after_failure_ms: 1000,
            poll_seconds: 60,
            // OFF for the general cases, so the existing suite keeps proving
            // the STRICT semantics. The starvation escape is exercised only
            // by the tests that opt into it — a relaxation that silently
            // applied everywhere would make every other assertion weaker
            // without anyone noticing.
            land_ancestor_after_deferrals: 0,
            // OFF for the same reason, and it matters MORE here: this escape
            // fires from the build-failure path, which the general suite
            // exercises constantly. Left on, a "build failed → cooldown" case
            // could silently become "build failed → landed something else"
            // and still pass a weaker assertion.
            land_last_good_after_failures: 0,
        }
    }

    /// The same config with the starvation escape armed at `n` deferrals.
    fn cfg_landing_after(n: usize) -> LoopConfig {
        LoopConfig {
            land_ancestor_after_deferrals: n,
            ..cfg()
        }
    }

    fn cfg_last_good_after(n: usize) -> LoopConfig {
        LoopConfig {
            land_last_good_after_failures: n,
            ..cfg()
        }
    }

    /// Drive the cid scenario up to (but not through) the threshold tick:
    /// rev(1) builds and defers, then rev(2) becomes HEAD and never builds.
    /// Returns the loop with `fails` failures already recorded against rev(2).
    ///
    /// The clock is advanced past each cooldown, because the point under test
    /// is the FAILURE STREAK — a tick that returns `coolingDown` never reaches
    /// the escape and would silently make the streak assertions vacuous.
    fn starve_on_a_red_head(env: &MockEnv, threshold: usize, fails: u32) -> Sentinela {
        env.set_ancestry_result(Ok(true));
        let mut s = Sentinela::new(cfg_last_good_after(threshold));
        assert_eq!(
            s.tick(env).kind(),
            "deferred",
            "setup: rev(1) must build and defer, so a known-good exists"
        );
        env.set_build_result(Err(EnvError::BuildFailed(
            "flake.lock: [json.exception.parse_error.101] parse error".to_owned(),
        )));
        for n in 1..=fails {
            env.set_now_ms(u64::from(n) * 10_000);
            let out = s.tick(env);
            assert_eq!(
                out.kind(),
                "buildFailed",
                "failure {n} is below the threshold and must simply retry"
            );
            assert!(
                env.switches.borrow().is_empty(),
                "nothing may be activated before the threshold is reached"
            );
        }
        s
    }

    #[test]
    fn a_head_that_will_not_build_falls_back_to_the_newest_rev_that_did() {
        // THE 2026-08-04 CID SCENARIO, as a test. rev(1) built clean and
        // deferred; rev(2) then landed an unresolved git merge in flake.lock
        // and could never build. The old code's answer was
        // `cooldown → retry rev(2)` forever — a node holding a rev it had
        // already built and verified, never activating it, for as long as
        // main stayed red. The rev it was holding carried a kubeconfig token
        // the fleet needed.
        let env = MockEnv::with_probes(vec![
            Ok(Some(rev(1))),
            Ok(Some(rev(2))), // tick 1: built 1, HEAD moved to 2 → defer
            Ok(Some(rev(2))), // tick 2: 2 fails to build (streak 1)
            Ok(Some(rev(2))), // tick 3: fails again    (streak 2)
            Ok(Some(rev(2))), // tick 4: fails again    (streak 3) → escape
        ]);
        let mut s = starve_on_a_red_head(&env, 3, 2);

        env.set_now_ms(30_000);
        let out = s.tick(&env);
        assert_eq!(
            out.kind(),
            "deployedBehind",
            "a HEAD that cannot build must not starve the node forever"
        );
        assert_eq!(
            *env.switches.borrow(),
            vec![rev(1)],
            "it must land the rev it BUILT — never the red HEAD it never built"
        );
        // It reports being behind rather than presenting this as a plain
        // deploy: the operator must still see that HEAD is red.
        match out {
            TickOutcome::DeployedBehind { rev: r, newer, .. } => {
                assert_eq!(r, rev(1));
                assert_eq!(newer, rev(2), "the red HEAD must be named in the outcome");
            }
            other => panic!("expected DeployedBehind, got {other:?}"),
        }
    }

    #[test]
    fn a_force_push_is_refused_even_while_a_red_head_starves_us() {
        // Same starvation, but the known-good rev is NOT contained in HEAD —
        // a force-push, reset or revert. Landing it would be the downgrade
        // the no-downgrade rule exists to refuse, so continuing to fail is
        // the CORRECT answer. This is the gate proving it still blocks: the
        // only difference from the passing test is the ancestry answer.
        let env = MockEnv::with_probes(vec![
            Ok(Some(rev(1))),
            Ok(Some(rev(2))),
            Ok(Some(rev(2))),
            Ok(Some(rev(2))),
            Ok(Some(rev(2))),
        ]);
        let mut s = starve_on_a_red_head(&env, 3, 2);

        env.set_ancestry_result(Ok(false)); // HEAD no longer contains rev(1)
        env.set_now_ms(30_000);
        let out = s.tick(&env);
        assert_eq!(
            out.kind(),
            "buildFailed",
            "a non-ancestor must never land, even to escape starvation"
        );
        assert!(
            env.switches.borrow().is_empty(),
            "no activation may happen when ancestry says no"
        );
    }

    #[test]
    fn an_unanswerable_ancestry_question_refuses_the_fallback() {
        // Fail-closed, symmetric with the deferral escape: "I could not
        // check" must read as "do not", never "probably".
        let env = MockEnv::with_probes(vec![
            Ok(Some(rev(1))),
            Ok(Some(rev(2))),
            Ok(Some(rev(2))),
            Ok(Some(rev(2))),
            Ok(Some(rev(2))),
        ]);
        let mut s = starve_on_a_red_head(&env, 3, 2);

        env.set_ancestry_result(Err(EnvError::ProbeFailed("network down".to_owned())));
        env.set_now_ms(30_000);
        assert_eq!(s.tick(&env).kind(), "buildFailed");
        assert!(env.switches.borrow().is_empty(), "must not guess");
    }

    #[test]
    fn a_red_head_with_nothing_ever_built_just_keeps_failing() {
        // No deferral ever happened, so there is no proven-good rev to fall
        // back TO. The escape must find no candidate and change nothing —
        // the fallback may never invent a rev it has not built.
        let env = MockEnv::with_probes(vec![
            Ok(Some(rev(2))),
            Ok(Some(rev(2))),
            Ok(Some(rev(2))),
            Ok(Some(rev(2))),
        ]);
        env.set_ancestry_result(Ok(true));
        env.set_build_result(Err(EnvError::BuildFailed(
            "broken from the start".to_owned(),
        )));
        let mut s = Sentinela::new(cfg_last_good_after(3));
        for n in 1u32..=4 {
            env.set_now_ms(u64::from(n) * 10_000);
            assert_eq!(s.tick(&env).kind(), "buildFailed");
        }
        assert!(
            env.switches.borrow().is_empty(),
            "with nothing proven-good, there is nothing to land"
        );
    }

    #[test]
    fn the_fallback_is_off_when_its_threshold_is_zero() {
        // `0` must keep the pre-0.1.9 behaviour exactly — retry the red head
        // forever — so the relaxation is opt-out, not silently mandatory.
        let env = MockEnv::with_probes(vec![
            Ok(Some(rev(1))),
            Ok(Some(rev(2))),
            Ok(Some(rev(2))),
            Ok(Some(rev(2))),
            Ok(Some(rev(2))),
            Ok(Some(rev(2))),
        ]);
        env.set_ancestry_result(Ok(true));
        let mut s = Sentinela::new(cfg_last_good_after(0));
        assert_eq!(s.tick(&env).kind(), "deferred");
        env.set_build_result(Err(EnvError::BuildFailed("red".to_owned())));
        for n in 1u32..=4 {
            env.set_now_ms(u64::from(n) * 10_000);
            assert_eq!(s.tick(&env).kind(), "buildFailed");
        }
        assert!(
            env.switches.borrow().is_empty(),
            "threshold 0 must never take the escape"
        );
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
    fn the_final_pulse_of_every_tick_is_its_resolved_outcome() {
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
                Box::new(|| MockEnv::with_probes(vec![Err(EnvError::ProbeFailed("boom".into()))])),
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
            (
                Box::new(|| {
                    let e = MockEnv::with_probes(vec![Ok(Some(rev(7))), Ok(Some(rev(7)))]);
                    e.set_switch_result(Err(EnvError::SwitchBusy("pid 42 · drzzln".into())));
                    e
                }),
                "switchDeferred",
                Some(rev(7)),
            ),
        ];

        for (build_env, expected_kind, expected_head) in cases {
            let env = build_env();
            let mut s = Sentinela::new(cfg());
            let out = s.tick(&env);
            assert_eq!(out.kind(), expected_kind, "wrong outcome for this case");

            let beats = env.heartbeats.borrow();
            // ── ★ RESTATED 2026-08-02: the FINAL pulse is the resolved one ──
            // This asserted `beats.len() == 1`. A tick that builds now
            // publishes an in-flight pulse first, so the count is 1 or 2 —
            // but the invariant the wrapper actually guarantees is unchanged
            // and is the one worth pinning: whatever else a tick emits, the
            // LAST thing it says is its resolved outcome. Loosening this to
            // `last()` keeps the wrapper-cannot-be-bypassed property; asserting
            // a count would have pinned an implementation detail instead.
            let last = beats.last().expect("every tick must publish a pulse");
            assert_eq!(
                last.phase,
                crate::env::Phase::Resolved,
                "outcome `{expected_kind}` left an in-flight pulse as its last word"
            );
            assert_eq!(last.outcome, expected_kind);
            // Any earlier pulse in the same tick must be in-flight — a second
            // RESOLVED pulse would mean the tick reported twice.
            for b in &beats[..beats.len() - 1] {
                assert_eq!(
                    b.phase,
                    crate::env::Phase::InFlight,
                    "a non-final pulse must be in-flight, got `{}`",
                    b.outcome
                );
            }
            // The cadence travels with the pulse. Without it a reader holds
            // a perfectly good heartbeat and still cannot judge staleness,
            // which is what `fleet convergence` hit on its first run against
            // a live node: it printed the tick's age and "no poll interval"
            // in the same document.
            assert_eq!(
                last.poll_seconds, 60,
                "every heartbeat must carry the interval it is judged against"
            );
            assert_eq!(
                last.head_rev, expected_head,
                "outcome `{expected_kind}` reported the wrong observed head"
            );
        }
    }

    #[test]
    fn a_starved_loop_lands_an_ancestor_and_makes_progress() {
        // THE STARVATION SCENARIO. Every build finishes against a moved
        // HEAD, so under the strict rule the node NEVER activates anything.
        // Two probes per tick: pre-build and post-build.
        let env = MockEnv::with_probes(vec![
            Ok(Some(rev(1))),
            Ok(Some(rev(2))), // tick 1: built 1, HEAD moved to 2 → defer
            Ok(Some(rev(2))),
            Ok(Some(rev(3))), // tick 2: built 2, HEAD moved to 3 → armed
        ]);
        env.set_ancestry_result(Ok(true));
        let mut s = Sentinela::new(cfg_landing_after(2));

        let first = s.tick(&env);
        assert_eq!(first.kind(), "deferred", "the first overlap still defers");
        assert!(
            env.switches.borrow().is_empty(),
            "nothing may activate on the first deferral"
        );

        let second = s.tick(&env);
        assert_eq!(
            second.kind(),
            "deployedBehind",
            "a second consecutive deferral must escape, not starve"
        );
        assert_eq!(
            *env.switches.borrow(),
            vec![rev(2)],
            "it must land the rev it BUILT, never the newer one it never built"
        );
        // And it asked the right questions, in the right direction.
        let q = env.ancestry_queries.borrow();
        assert!(
            q.contains(&(rev(2), rev(3))),
            "must ask: is the built rev an ancestor of HEAD? got {q:?}"
        );
    }

    #[test]
    fn a_force_push_is_refused_even_while_starving() {
        // The 2026-07-02 rollback: HEAD moved to a rev that does NOT contain
        // what we built. Landing it would be the downgrade the no-downgrade
        // rule exists to refuse — starving is the correct answer here.
        let env = MockEnv::with_probes(vec![
            Ok(Some(rev(1))),
            Ok(Some(rev(2))),
            Ok(Some(rev(2))),
            Ok(Some(rev(3))),
        ]);
        env.set_ancestry_result(Ok(false)); // not an ancestor
        let mut s = Sentinela::new(cfg_landing_after(2));
        s.tick(&env);
        let out = s.tick(&env);
        assert_eq!(out.kind(), "deferred", "a non-ancestor must never land");
        assert!(
            env.switches.borrow().is_empty(),
            "no activation may happen when ancestry says no"
        );
    }

    #[test]
    fn an_unanswerable_ancestry_question_defers_rather_than_guessing() {
        // Fail-closed. The escape relaxes the strictest rule the loop has,
        // so "I could not check" must read as "do not", never "probably".
        let env = MockEnv::with_probes(vec![
            Ok(Some(rev(1))),
            Ok(Some(rev(2))),
            Ok(Some(rev(2))),
            Ok(Some(rev(3))),
        ]);
        env.set_ancestry_result(Err(EnvError::AncestryFailed("no network".into())));
        let mut s = Sentinela::new(cfg_landing_after(2));
        s.tick(&env);
        let out = s.tick(&env);
        assert_eq!(out.kind(), "deferred");
        assert!(env.switches.borrow().is_empty());
    }

    #[test]
    fn the_escape_is_off_unless_armed_and_never_fires_early() {
        // Threshold 0 disables it entirely: the strict rule forever, which
        // is what every other test in this file relies on.
        let env = MockEnv::with_probes(vec![
            Ok(Some(rev(1))),
            Ok(Some(rev(2))),
            Ok(Some(rev(2))),
            Ok(Some(rev(3))),
            Ok(Some(rev(3))),
            Ok(Some(rev(4))),
        ]);
        env.set_ancestry_result(Ok(true));
        let mut s = Sentinela::new(cfg()); // land_ancestor_after_deferrals: 0
        for _ in 0..3 {
            assert_eq!(s.tick(&env).kind(), "deferred");
        }
        assert!(
            env.switches.borrow().is_empty(),
            "disabled means disabled, however long the streak"
        );
        assert!(
            env.ancestry_queries.borrow().is_empty(),
            "a disabled escape must not even ASK — no network cost when off"
        );
    }

    #[test]
    fn a_deferral_retries_fast_and_everything_else_waits_a_poll() {
        // The FSM already decided a deferral is not a failure and returns to
        // Idle without cooling down — then the caller slept a full poll
        // anyway, because `run()` had one Duration in scope and matched on
        // nothing. This pins that the decision now travels with the outcome.
        let c = cfg();
        let poll = std::time::Duration::from_secs(c.poll_seconds);

        let deferred = TickOutcome::Deferred {
            built: rev(1),
            newer: rev(2),
        };
        assert!(
            deferred.next_delay(&c) < poll,
            "a deferral already knows a newer rev exists — waiting a full poll is pure latency"
        );
        assert!(
            !deferred.next_delay(&c).is_zero(),
            "but not zero: a cache-hit build would make a zero-delay retry an unbounded churn loop"
        );

        // CoolingDown must still tick at the normal cadence. The cooldown is
        // a gate INSIDE tick_inner, not a longer sleep — lengthening it here
        // would starve the liveness pulse the gate reads.
        assert_eq!(
            TickOutcome::CoolingDown { remaining_ms: 1000 }.next_delay(&c),
            poll,
            "cooling down must keep ticking, or liveness reporting starves"
        );
        for o in [
            TickOutcome::Unchanged { rev: rev(1) },
            TickOutcome::Unresolvable,
            TickOutcome::Deployed {
                rev: rev(1),
                generation: Generation(1),
            },
        ] {
            assert_eq!(o.next_delay(&c), poll, "`{}` must wait a poll", o.kind());
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
        // The first tick BUILDS (in-flight + resolved), the second is idle
        // (resolved only) — so the count is 3, not 2. What matters is that an
        // idle tick still proves it is alive, which the last pulse carries.
        assert!(
            beats.len() >= 2,
            "an idle loop must still prove it is alive"
        );
        let last = beats.last().expect("pulse");
        assert_eq!(last.outcome, "unchanged");
        assert_eq!(last.phase, crate::env::Phase::Resolved);
        assert_eq!(last.head_rev, Some(rev(1)));
        // The deploying tick announced itself before its build.
        assert!(
            beats
                .iter()
                .any(|b| b.phase == crate::env::Phase::InFlight && b.outcome == "building"),
            "a tick that builds must publish an in-flight pulse first"
        );
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
        assert_eq!(
            out,
            TickOutcome::Deployed {
                rev: rev(1),
                generation: Generation(42)
            }
        );
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
            c.append(c.next_receipt(
                rev(1),
                Outcome::Activated {
                    generation: Generation(1),
                },
                0,
            ))
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
        assert_eq!(
            out,
            TickOutcome::Deferred {
                built: rev(1),
                newer: rev(2)
            }
        );
        assert_eq!(*env.builds.borrow(), vec![rev(1)]);
        assert!(
            env.switches.borrow().is_empty(),
            "must not activate the stale rev"
        );
        assert_eq!(s.state(), &State::Idle);
        // The deferral is attested.
        assert!(matches!(
            env.chain().head().unwrap().outcome,
            Outcome::Deferred { .. }
        ));
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
        assert_eq!(
            s.tick(&env),
            TickOutcome::ProbeError {
                error: "probe failed: net".into()
            }
        );
        assert!(env.switches.borrow().is_empty());
        assert_eq!(
            s.state(),
            &State::CoolingDown {
                until_unix_ms: 6_000
            }
        );
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
        assert!(matches!(
            env.chain().head().unwrap().outcome,
            Outcome::Failed { .. }
        ));
        assert_eq!(
            s.state(),
            &State::CoolingDown {
                until_unix_ms: 11_000
            }
        );
    }

    #[test]
    fn switch_failure_records_and_cools_down() {
        let env = MockEnv::with_probes(vec![Ok(Some(rev(1))), Ok(Some(rev(1)))]);
        env.set_switch_result(Err(EnvError::SwitchFailed("activation".into())));
        env.set_now_ms(20_000);
        let mut s = Sentinela::new(cfg());
        assert!(matches!(s.tick(&env), TickOutcome::SwitchFailed { .. }));
        assert!(matches!(
            env.chain().head().unwrap().outcome,
            Outcome::Failed { .. }
        ));
        assert_eq!(
            s.state(),
            &State::CoolingDown {
                until_unix_ms: 21_000
            }
        );
    }

    #[test]
    fn a_lock_contended_switch_defers_instead_of_failing() {
        // The operator owns the machine-wide rebuild lock. The daemon must
        // stand aside — a deferral, not a failure: no receipt (nothing was
        // attempted), no cooldown (nothing broke), state stays Idle so the
        // next tick converges the moment the operator finishes.
        let env = MockEnv::with_probes(vec![Ok(Some(rev(1))), Ok(Some(rev(1)))]);
        env.set_switch_result(Err(EnvError::SwitchBusy("pid 42 · drzzln".into())));
        env.set_now_ms(30_000);
        let mut s = Sentinela::new(cfg());
        let out = s.tick(&env);
        assert_eq!(
            out,
            TickOutcome::SwitchDeferred {
                rev: rev(1),
                holder: "pid 42 · drzzln".into()
            }
        );
        // The built rev WAS built (that is how we reached the switch).
        assert_eq!(*env.builds.borrow(), vec![rev(1)]);
        // The switch was ATTEMPTED (that is how the lock was found busy) —
        // but no activation happened (the outcome is a deferral, never
        // Deployed/DeployedBehind) and nothing was recorded.
        assert_eq!(
            *env.switches.borrow(),
            vec![rev(1)],
            "switch attempted once"
        );
        assert!(env.chain().head().is_none(), "no receipt for a non-switch");
        assert_eq!(
            s.state(),
            &State::Idle,
            "lock contention is not a failure — no cooldown"
        );
        // The cadence is a bounded deferral, not the failure cooldown: a
        // lock-held switch must retry well before a full poll, but not
        // hammer the same cache-hit build at the 1s branch-race rate.
        let c = cfg();
        let delay = out.next_delay(&c);
        assert!(
            delay < std::time::Duration::from_secs(c.poll_seconds),
            "a contended switch must retry soon, not wait a full poll"
        );
        assert!(
            delay >= std::time::Duration::from_secs(1),
            "a contended switch must not spin at the branch-race rate"
        );
    }

    #[test]
    fn a_lock_contended_switch_does_not_count_as_a_failure() {
        // Two consecutive operator-holds must not trip the failure gate: the
        // chain (the source of the `consecutive_failures` verdict) carries
        // no Failed receipt for either, so the node is still "not broken,
        // just standing aside".
        let env = MockEnv::with_probes(vec![
            Ok(Some(rev(1))),
            Ok(Some(rev(1))),
            Ok(Some(rev(1))),
            Ok(Some(rev(1))),
        ]);
        env.set_switch_result(Err(EnvError::SwitchBusy("pid 42 · drzzln".into())));
        let mut s = Sentinela::new(cfg());
        assert_eq!(s.tick(&env).kind(), "switchDeferred");
        assert_eq!(s.tick(&env).kind(), "switchDeferred");
        assert_eq!(
            env.chain().consecutive_failures(),
            0,
            "a held lock is not a failure"
        );
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
            TickOutcome::Deployed {
                rev: rev(1),
                generation: Generation(1)
            }
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
        assert!(
            matches!(out, TickOutcome::SwitchFailed { .. }),
            "got {out:?}"
        );
        assert_eq!(
            s.state(),
            &State::CoolingDown {
                until_unix_ms: 2_000
            }
        );
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
        assert!(
            env.switches.borrow().is_empty(),
            "must not activate when re-probe is uncertain"
        );
        assert!(matches!(out, TickOutcome::ProbeError { .. }));
        assert_eq!(
            s.state(),
            &State::CoolingDown {
                until_unix_ms: 4_000
            }
        );
    }

    #[test]
    fn reprobe_empty_after_build_is_inconclusive_no_switch() {
        // Post-build re-probe returns None (branch vanished/reset). Must
        // NOT activate; retry next cadence (no cooldown).
        let env = MockEnv::with_probes(vec![Ok(Some(rev(1))), Ok(None)]);
        let mut s = Sentinela::new(cfg());
        let out = s.tick(&env);
        assert_eq!(*env.builds.borrow(), vec![rev(1)]);
        assert!(
            env.switches.borrow().is_empty(),
            "must not activate an unconfirmable rev"
        );
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
        assert!(
            env.builds.borrow().is_empty(),
            "a chain-load error deploys nothing"
        );
        assert!(env.switches.borrow().is_empty());
        assert!(matches!(out, TickOutcome::ProbeError { .. }));
        assert_eq!(
            s.state(),
            &State::CoolingDown {
                until_unix_ms: 1_500
            }
        );
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
        assert_eq!(
            s.state(),
            &State::CoolingDown {
                until_unix_ms: 1_000
            }
        );
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
