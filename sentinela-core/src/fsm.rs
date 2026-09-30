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
//!
//! And one guard that looks AFTER the switch rather than before it, off
//! unless a [`RollbackPolicy`] is attached ([`Sentinela::with_rollback`]):
//!
//! - **health-gated rollback** — an activation enters
//!   [`State::Verifying`]; each tick runs one probe round until the required
//!   consecutive passes land (`Verified`) or the window closes on a failing
//!   round, which re-activates the PREVIOUS system generation, attests
//!   `RolledBack` with the failing probe's evidence, and quarantines the rev
//!   until HEAD moves. See [`crate::probation`] for why this is not the
//!   no-downgrade rule.

use crate::env::{EnvError, GitopsEnv, Heartbeat, LoopConfig, Phase};
use crate::probation::{ProbeFailure, Probation, RollbackPolicy};
use crate::receipt::{Generation, Outcome, ReceiptChain, bound_text};
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
        /// The rev whose failure caused this backoff.
        ///
        /// A cooldown exists to stop hammering an input that just failed. It
        /// is NOT a reason to ignore a DIFFERENT input: when HEAD moves, the
        /// thing that failed is no longer the thing on offer, and the new rev
        /// may well be the fix. Carrying the rev is what lets the gate ask
        /// "same input?" instead of only "has the clock run out?".
        ///
        /// `None` for a failure with no resolved rev (a probe error), where
        /// there is nothing to compare against and the clock is all there is.
        failed_rev: Option<Rev>,
    },
    /// An activation is on health probation. While here the loop runs one
    /// probe round per tick and does NOT probe HEAD or deploy: stacking a new
    /// activation on an unverified one would make the unverified one the
    /// rollback target. The window bounds how long that can last.
    Verifying(Probation),
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
    /// One probe round ran; the probation is still open. Carries the
    /// probation as it stands, including the failing probe when the round
    /// failed inside the window.
    Verifying(Probation),
    /// The probation passed its required consecutive rounds.
    Verified {
        /// The rev whose activation is now verified.
        rev: Rev,
        /// Its generation.
        generation: Generation,
    },
    /// The window closed on a failing round and the previous generation was
    /// re-activated. `rev` is quarantined until HEAD moves.
    RolledBack {
        /// The rev whose activation was undone.
        rev: Rev,
        /// The generation that failed its probation.
        from: Generation,
        /// The generation now active.
        to: Generation,
        /// Which probe failed, and what it said.
        failure: ProbeFailure,
    },
    /// A rollback was due, but an operator rebuild holds the machine lock.
    /// Stays in probation and retries on the probe interval — racing the
    /// operator's activation is worse than a few seconds' delay.
    RollbackDeferred {
        /// The rev awaiting its rollback.
        rev: Rev,
        /// Who holds the machine lock.
        holder: String,
    },
    /// A rollback was attempted and did not complete. The machine may still
    /// be on the bad generation, so the loop stays in probation and tries
    /// again; nothing is attested until a rollback actually lands.
    RollbackFailed {
        /// The rev awaiting its rollback.
        rev: Rev,
        /// Why the rollback failed.
        error: String,
    },
    /// The system profile is no longer on the generation under probation —
    /// somebody else (an operator rebuild) activated something. Judging it
    /// further would mean rolling back THEIR switch, so probation ends.
    ProbationAbandoned {
        /// The rev whose probation ended.
        rev: Rev,
        /// The generation that was on trial.
        expected: Generation,
        /// What the profile points at now, when readable.
        found: Option<Generation>,
    },
    /// HEAD is a rev a health-gated rollback quarantined. Nothing built,
    /// nothing switched, nothing recorded; lifts when HEAD moves.
    Quarantined {
        /// The quarantined rev (HEAD).
        rev: Rev,
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
            Self::Verifying(_) => "verifying",
            Self::Verified { .. } => "verified",
            Self::RolledBack { .. } => "rolledBack",
            Self::RollbackDeferred { .. } => "rollbackDeferred",
            Self::RollbackFailed { .. } => "rollbackFailed",
            Self::ProbationAbandoned { .. } => "probationAbandoned",
            Self::Quarantined { .. } => "quarantined",
        }
    }

    /// Whether the pulse for this outcome reports a finished convergence or
    /// one still in flight.
    ///
    /// ── ★ A PROBATION IS CONVERGENCE STILL IN FLIGHT ──────────────────────
    /// A verifying tick observes no HEAD (it does not probe the branch), so
    /// published as `Resolved` it would read to the fleet reader exactly like
    /// a loop that is alive and doing nothing — its `ineffective` verdict.
    /// It is not that: the activation it is judging has not resolved yet,
    /// which is what `InFlight` means. `outcome` then names the pending
    /// action (`verifying`), the documented widening that field already has.
    ///
    /// `RollbackFailed` is deliberately `Resolved`: it is a finished attempt
    /// that failed, and must not hide inside an in-progress verdict.
    /// Exhaustive, no `_` arm, like [`Self::kind`].
    #[must_use]
    pub fn phase(&self) -> Phase {
        match self {
            Self::Verifying(_) | Self::RollbackDeferred { .. } => Phase::InFlight,
            Self::CoolingDown { .. }
            | Self::Unchanged { .. }
            | Self::Unresolvable
            | Self::ProbeError { .. }
            | Self::BuildFailed { .. }
            | Self::Deferred { .. }
            | Self::ReprobeInconclusive { .. }
            | Self::SwitchFailed { .. }
            | Self::SwitchDeferred { .. }
            | Self::DeployedBehind { .. }
            | Self::Deployed { .. }
            | Self::Verified { .. }
            | Self::RolledBack { .. }
            | Self::RollbackFailed { .. }
            | Self::ProbationAbandoned { .. }
            | Self::Quarantined { .. } => Phase::Resolved,
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
            //
            // And a probation just ended (verified / rolled back /
            // abandoned): the loop has not looked at HEAD since the switch,
            // so look now rather than a poll from now — a verified node
            // should reach `unchanged` promptly, and a rolled-back one
            // should publish that HEAD is quarantined.
            Self::Deferred { .. }
            | Self::DeployedBehind { .. }
            | Self::Verified { .. }
            | Self::RolledBack { .. }
            | Self::ProbationAbandoned { .. } => {
                std::time::Duration::from_secs(DEFERRED_RETRY_SECS)
            }
            // A due rollback waiting on the operator's lock waits like a
            // switch does.
            Self::SwitchDeferred { .. } | Self::RollbackDeferred { .. } => {
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
            | Self::Deployed { .. }
            // The probation cadence is the POLICY's interval, which this
            // outcome cannot see — `Sentinela::next_delay` applies it while
            // the loop is verifying. A poll is the fallback, and it is also
            // right for a failed rollback: each retry is a whole activation
            // attempt and should not run at the probe rate.
            | Self::Verifying(_)
            | Self::RollbackFailed { .. }
            | Self::Quarantined { .. } => poll,
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
            // Probation ticks never probe the branch either. The rev under
            // trial is REMEMBERED from the deploy tick, not observed, so it
            // is not reported as HEAD.
            Self::CoolingDown { .. }
            | Self::Unresolvable
            | Self::ProbeError { .. }
            | Self::Verifying(_)
            | Self::Verified { .. }
            | Self::RolledBack { .. }
            | Self::RollbackDeferred { .. }
            | Self::RollbackFailed { .. }
            | Self::ProbationAbandoned { .. } => None,
            Self::Unchanged { rev }
            | Self::Quarantined { rev }
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
    /// `None` = health-gated rollback OFF, which is the default and is
    /// today's behaviour exactly: no generation reads, no probes, no
    /// probation receipts, no quarantine.
    rollback: Option<RollbackPolicy>,
    /// Whether this process has looked for a probation left open by a
    /// previous one. Checked once: after that, the in-memory state is the
    /// authority.
    resume_checked: bool,
}

impl Sentinela {
    /// A fresh loop in [`State::Idle`].
    #[must_use]
    pub fn new(cfg: LoopConfig) -> Self {
        Self {
            state: State::Idle,
            cfg,
            rollback: None,
            resume_checked: false,
        }
    }

    /// Attach (or, with `None`, keep off) health-gated rollback.
    ///
    /// A separate step rather than a [`LoopConfig`] field: `LoopConfig` is
    /// `Copy` plain bounds, and a probe list is neither — and keeping it out
    /// means every existing construction of the loop is unchanged.
    #[must_use]
    pub fn with_rollback(mut self, policy: Option<RollbackPolicy>) -> Self {
        self.rollback = policy;
        self
    }

    /// How long the caller should sleep before the next tick.
    ///
    /// The outcome's own [`TickOutcome::next_delay`], except while an
    /// activation is on probation, where the policy's probe interval rules —
    /// a 60s poll against a 300s window would give the probes five chances,
    /// and the interval is what the operator configured instead. A failed
    /// rollback keeps its outcome's (slower) cadence: each retry is a whole
    /// activation attempt.
    #[must_use]
    pub fn next_delay(&self, outcome: &TickOutcome) -> std::time::Duration {
        if let (State::Verifying(_), Some(policy)) = (&self.state, &self.rollback)
            && !matches!(outcome, TickOutcome::RollbackFailed { .. })
        {
            return std::time::Duration::from_secs(policy.interval_seconds.max(1));
        }
        outcome.next_delay(&self.cfg)
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
            // `Resolved` for every outcome that existed before probation;
            // see `TickOutcome::phase` for the two that are not.
            phase: outcome.phase(),
            head_rev: outcome.observed_head().cloned(),
            poll_seconds: self.cfg.poll_seconds,
            // A resolved tick has nothing in flight by definition. Clearing
            // it rather than carrying the last step forward: a stale drv
            // beside a finished outcome reads as a build still running.
            in_flight: None,
            // The probation as it stands AFTER this tick — including on the
            // deploy tick that opened it — so the pulse says what the loop
            // is waiting on and which probe failed last.
            verification: match &self.state {
                State::Verifying(p) => Some(p.clone()),
                State::Idle | State::CoolingDown { .. } => None,
            },
        };
        if let Err(e) = env.write_heartbeat(&beat) {
            tracing::warn!(error = %e, "sentinela: could not write heartbeat (loop is fine)");
        }
        outcome
    }

    /// The cycle proper. Every `return` here is a completed tick; the
    /// heartbeat is applied by [`Sentinela::tick`], which wraps this.
    fn tick_inner<E: GitopsEnv>(&mut self, env: &E) -> TickOutcome {
        // ── Probation first, and BEFORE any network call ─────────────────
        // A generation that broke the network also breaks `probe_head`; if
        // probation waited behind the head probe, the fail-closed probe
        // error would enter a cooldown and the bad generation would never be
        // judged. Both calls are no-ops unless rollback is enabled.
        self.resume_probation(env);
        if matches!(self.state, State::Verifying(_))
            && let Some(out) = self.verify_tick(env)
        {
            return out;
        }

        // ── Cooldown gate — a backoff from an INPUT, not from the clock ──
        //
        // The cooldown stops the loop hammering a rev that just failed. It
        // must not also stop it noticing that somebody pushed a fix: a new
        // HEAD is a different input, and the whole reason a human reacts to a
        // red build by committing is that they expect the next build to be
        // attempted. Waiting out five minutes of backoff against a rev nobody
        // is proposing any more is dead time in exactly the moment an
        // operator is watching.
        //
        // So the gate probes HEAD first and releases early when it moved.
        // Same rev ⇒ the clock still rules, which is the case the cooldown
        // was built for.
        if let State::CoolingDown {
            until_unix_ms,
            ref failed_rev,
        } = self.state
        {
            let now = env.now_unix_ms();
            if now < until_unix_ms {
                // A cheap `git ls-remote`, the same call the observe step
                // makes a line later — no build, no switch.
                // SHORT-CIRCUIT on purpose: `match (failed_rev, env.probe_head())`
                // evaluates both elements before matching, so it probes even
                // when there is no rev to compare against — spending a
                // `git ls-remote` to reach a `_ => false` arm. Caught by
                // `cooldown_blocks_ticks_until_it_elapses`, where the wasted
                // probe consumed the answer the later freshness re-check
                // needed and turned a Deployed into a ReprobeInconclusive.
                let moved = match failed_rev {
                    Some(failed) => {
                        matches!(env.probe_head(), Ok(Some(head)) if &head != failed)
                    }
                    // Nothing to compare — the clock is all there is.
                    None => false,
                };
                if !moved {
                    return TickOutcome::CoolingDown {
                        remaining_ms: until_unix_ms - now,
                    };
                }
                tracing::info!(
                    "sentinela: HEAD moved during cooldown — releasing early to try the new rev"
                );
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
        // ── Quarantine — a rev this machine already rolled back ──────────
        // After a rollback the node runs the previous rev, so HEAD (still the
        // bad rev) differs from `last_activated_rev` and would be rebuilt and
        // re-activated every tick — a rollback loop. Refused until HEAD moves.
        // Only while rollback is on: configured off means off, and a node
        // that turned it off wants to converge.
        if self.rollback.is_some() && chain.quarantined_rev() == Some(&head) {
            tracing::warn!(
                rev = head.short(),
                "HEAD is a rev this node rolled back — not re-attempting until HEAD moves"
            );
            return TickOutcome::Quarantined { rev: head };
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
            // A tick reaching a build is by construction not on probation.
            verification: None,
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
        // Read BEFORE the switch: afterwards the profile points at the new
        // generation and "the one before" is no longer a fact we observed.
        // Only when rollback is on — off means no new env calls at all.
        let previous = self
            .rollback
            .as_ref()
            .and_then(|_| env.current_generation());
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
                        self.begin_probation(&mut chain, env, &rev, generation, previous);
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
                let _ = self.record(&mut chain, env, rev.clone(), Outcome::failed(e.to_string()));
                // ── ★ A FAILED SWITCH MAY HAVE MOVED THE MACHINE ─────────────
                // `switch-to-configuration` exits non-zero when a unit fails to
                // start, AFTER the new generation is active. Then "failed" means
                // the machine runs the broken generation, and a cooldown only
                // retries the same rev on it. With rollback on, judge what is
                // running exactly as after a clean switch: a probation from the
                // generation read before the switch.
                if let (Some(prev), Some(now)) = (
                    previous,
                    self.rollback.as_ref().and_then(|_| env.current_generation()),
                ) && now != prev
                {
                    tracing::warn!(
                        rev = rev.short(),
                        generation = %now,
                        "switch failed, but the machine moved to a new generation — judging it"
                    );
                    self.begin_probation(&mut chain, env, &rev, now, Some(prev));
                    if matches!(self.state, State::Verifying(_)) {
                        return out;
                    }
                }
                self.enter_cooldown(env, out)
            }
        }
    }

    /// Open a probation for the activation just attested, when rollback is on
    /// and a rollback is actually possible.
    ///
    /// Declines — logging why, never failing the deploy — when the previous
    /// generation could not be read (nothing to return to), when the switch
    /// produced no readable generation (the superseded check could never
    /// pass), or when the generation did not change (the same system cannot
    /// have been broken by this switch, and "rolling back" to it is a no-op).
    fn begin_probation<E: GitopsEnv>(
        &mut self,
        chain: &mut ReceiptChain,
        env: &E,
        rev: &Rev,
        generation: Generation,
        previous: Option<Generation>,
    ) {
        let Some(policy) = &self.rollback else {
            return;
        };
        let previous_generation = match previous {
            Some(p) if p != generation && generation.0 != 0 => p,
            other => {
                tracing::warn!(
                    rev = rev.short(),
                    generation = %generation,
                    previous = ?other,
                    "rollback enabled, but this activation has no distinct readable \
                     previous generation — NOT on probation"
                );
                return;
            }
        };
        let deadline_unix_ms = env.now_unix_ms().saturating_add(policy.window_ms);
        let probation = Probation {
            rev: rev.clone(),
            generation,
            previous_generation,
            deadline_unix_ms,
            passes: 0,
            required_passes: policy.required_consecutive_passes.max(1),
            last_failure: None,
        };
        // Durable, so a restart or reboot resumes the trial. A persist
        // failure still leaves the in-memory probation guarding this process
        // — losing the receipt must not also lose the rollback.
        if let Err(e) = self.record(
            chain,
            env,
            rev.clone(),
            Outcome::Probation {
                generation,
                previous_generation,
                deadline_unix_ms,
            },
        ) {
            tracing::warn!(error = %e, "probation receipt not persisted — probation holds for this process only");
        }
        tracing::info!(
            rev = rev.short(),
            generation = %generation,
            previous = %previous_generation,
            "activation on health probation"
        );
        self.state = State::Verifying(probation);
    }

    /// Resume a probation a previous process left open — once per process,
    /// and only with rollback on.
    ///
    /// The chain's newest receipt being [`Outcome::Probation`] means the
    /// trial never concluded: the daemon restarted (its own plist changed,
    /// it crashed, the machine rebooted — the reboot being exactly when a bad
    /// generation tends to show). The streak restarts at zero; the deadline
    /// is the original one.
    fn resume_probation<E: GitopsEnv>(&mut self, env: &E) {
        if self.resume_checked {
            return;
        }
        self.resume_checked = true;
        let Some(policy) = &self.rollback else {
            return;
        };
        if !matches!(self.state, State::Idle) {
            return;
        }
        let Ok(mut chain) = env.load_chain() else {
            // The normal path loads it again and fails closed with a reason.
            return;
        };
        let Some(head) = chain.head() else {
            return;
        };
        let Outcome::Probation {
            generation,
            previous_generation,
            deadline_unix_ms,
        } = head.outcome
        else {
            return;
        };
        let rev = head.rev.clone();
        match env.current_generation() {
            Some(g) if g == generation => {
                tracing::info!(rev = rev.short(), generation = %generation, "resuming an open probation");
                self.state = State::Verifying(Probation {
                    rev,
                    generation,
                    previous_generation,
                    deadline_unix_ms,
                    passes: 0,
                    required_passes: policy.required_consecutive_passes.max(1),
                    last_failure: None,
                });
            }
            // The rollback itself landed after the process that started it
            // died — an activation that changes this daemon's own unit kills
            // it mid-activation, and the detached child finishes. Attest it
            // now, or the chain would claim the rev is still running.
            Some(g) if g == previous_generation => {
                let _ = self.record(
                    &mut chain,
                    env,
                    rev.clone(),
                    Outcome::RolledBack {
                        from: generation,
                        to: g,
                        probe: "(unknown)".to_owned(),
                        evidence: "the rollback completed across a daemon restart; the failing \
                                   probe's evidence did not survive it"
                            .to_owned(),
                    },
                );
                tracing::warn!(rev = rev.short(), "a rollback landed across a restart — recorded");
            }
            found => {
                tracing::warn!(
                    rev = rev.short(),
                    expected = %generation,
                    found = ?found,
                    "open probation found, but the system moved — not resuming"
                );
            }
        }
    }

    /// One probation tick: one probe round, then verified, still open, or
    /// rolled back. `None` means the loop was not actually able to verify
    /// (no policy) and the caller runs a normal cycle.
    fn verify_tick<E: GitopsEnv>(&mut self, env: &E) -> Option<TickOutcome> {
        let (State::Verifying(p), Some(policy)) = (&self.state, &self.rollback) else {
            self.state = State::Idle;
            return None;
        };
        let mut p = p.clone();
        let round = policy.probes.iter().try_for_each(|probe| {
            env.run_health_probe(probe).map_err(|evidence| ProbeFailure {
                probe: probe.name.clone(),
                evidence: bound_text(evidence),
            })
        });
        match round {
            Ok(()) => {
                p.passes = p.passes.saturating_add(1);
                p.last_failure = None;
                if p.passes < p.required_passes {
                    self.state = State::Verifying(p.clone());
                    return Some(TickOutcome::Verifying(p));
                }
                // Best-effort attest: a lost `Verified` receipt leaves the
                // `Probation` at the head, and the next process re-verifies a
                // healthy generation — harmless.
                if let Ok(mut chain) = env.load_chain() {
                    let _ = self.record(
                        &mut chain,
                        env,
                        p.rev.clone(),
                        Outcome::Verified {
                            generation: p.generation,
                            passes: p.passes,
                        },
                    );
                }
                tracing::info!(rev = p.rev.short(), generation = %p.generation, "activation verified");
                self.state = State::Idle;
                Some(TickOutcome::Verified {
                    rev: p.rev,
                    generation: p.generation,
                })
            }
            Err(failure) => {
                p.passes = 0;
                p.last_failure = Some(failure.clone());
                tracing::warn!(
                    rev = p.rev.short(),
                    probe = %failure.probe,
                    evidence = %failure.evidence,
                    "health probe failed"
                );
                // ── ★ ONLY A FAILING ROUND PAST THE DEADLINE ROLLS BACK ────
                // A passing round at the deadline earns the next round rather
                // than a rollback: never revert a machine whose most recent
                // evidence is healthy. Still bounded — the next failing round
                // rolls back at once, and `required_passes` passing rounds
                // verify, so the trial ends within that many more rounds.
                if env.now_unix_ms() < p.deadline_unix_ms {
                    self.state = State::Verifying(p.clone());
                    return Some(TickOutcome::Verifying(p));
                }
                Some(self.roll_back(env, p, failure))
            }
        }
    }

    /// The window closed on a failing round: re-activate the previous
    /// generation, attest, quarantine.
    fn roll_back<E: GitopsEnv>(
        &mut self,
        env: &E,
        p: Probation,
        failure: ProbeFailure,
    ) -> TickOutcome {
        // Never revert a generation that is not the one on trial.
        match env.current_generation() {
            Some(g) if g == p.generation => {}
            // A previous attempt's detached activation already landed.
            Some(g) if g == p.previous_generation => {
                return self.attest_rollback(env, p, g, failure);
            }
            found => {
                tracing::warn!(
                    rev = p.rev.short(),
                    expected = %p.generation,
                    found = ?found,
                    "the system moved during probation — not rolling back someone else's switch"
                );
                self.state = State::Idle;
                return TickOutcome::ProbationAbandoned {
                    rev: p.rev,
                    expected: p.generation,
                    found,
                };
            }
        }
        tracing::error!(
            rev = p.rev.short(),
            from = %p.generation,
            to = %p.previous_generation,
            probe = %failure.probe,
            "probation failed — rolling back to the previous generation"
        );
        match env.rollback_to(p.previous_generation) {
            Ok(restored) => self.attest_rollback(env, p, restored, failure),
            Err(EnvError::SwitchBusy(holder)) => {
                let rev = p.rev.clone();
                self.state = State::Verifying(p);
                TickOutcome::RollbackDeferred { rev, holder }
            }
            Err(e) => {
                let rev = p.rev.clone();
                self.state = State::Verifying(p);
                TickOutcome::RollbackFailed {
                    rev,
                    error: e.to_string(),
                }
            }
        }
    }

    /// Record the rollback (which quarantines the rev) and return to idle.
    fn attest_rollback<E: GitopsEnv>(
        &mut self,
        env: &E,
        p: Probation,
        to: Generation,
        failure: ProbeFailure,
    ) -> TickOutcome {
        // Honest residual: if this persist fails, the chain still says the
        // rev is activated, so the next tick reads HEAD as `Unchanged` — the
        // node sits on the restored generation rather than re-deploying the
        // bad one. Safe direction, wrong record; logged loudly.
        let persisted = env.load_chain().and_then(|mut chain| {
            self.record(
                &mut chain,
                env,
                p.rev.clone(),
                Outcome::RolledBack {
                    from: p.generation,
                    to,
                    probe: failure.probe.clone(),
                    evidence: failure.evidence.clone(),
                },
            )
        });
        if let Err(e) = persisted {
            tracing::error!(error = %e, "rolled back, but the rollback receipt was not persisted");
        }
        self.state = State::Idle;
        TickOutcome::RolledBack {
            rev: p.rev,
            from: p.generation,
            to,
            failure,
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
        // Remember WHICH input failed, so the gate can release early when a
        // different one shows up. Read off the outcome rather than threaded
        // through every call site: the outcome already names the rev, and a
        // second parameter would be one more thing to get wrong at each of
        // the failure edges.
        let failed_rev = out.observed_head().cloned();
        self.state = State::CoolingDown {
            until_unix_ms: until,
            failed_rev,
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
            until_unix_ms: 6_000,
            // No HEAD was ever observed, so there is nothing to
                // compare a later probe against — the clock is all there is.
                failed_rev: None
            }
        );
    }

    /// **A COOLDOWN BACKS OFF FROM AN INPUT, NOT FROM THE CLOCK.**
    ///
    /// The scenario is the one that motivated it: a build fails, a human sees
    /// the red, pushes a fix — and the loop is still sitting in a five-minute
    /// backoff against a rev nobody is proposing any more. The new HEAD is a
    /// different input and may well be the fix, so the gate releases early.
    #[test]
    fn a_new_head_during_cooldown_releases_it_early() {
        // Probe 1 fails the build at rev 1; probes 2+ answer rev 2 — the fix.
        let env = MockEnv::with_probes(vec![
            Ok(Some(rev(1))),
            Ok(Some(rev(2))),
            Ok(Some(rev(2))),
            Ok(Some(rev(2))),
        ]);
        env.set_build_result(Err(EnvError::BuildFailed("boom".into())));
        env.set_now_ms(0);
        let mut s = Sentinela::new(cfg());
        assert!(matches!(s.tick(&env), TickOutcome::BuildFailed { .. }));
        let State::CoolingDown { until_unix_ms, .. } = *s.state() else {
            panic!("a failed build must cool down, got {:?}", s.state());
        };

        // WELL INSIDE the cooldown — the clock alone would refuse.
        env.set_now_ms(until_unix_ms - 1);
        env.set_build_result(Ok(()));
        let out = s.tick(&env);
        assert!(
            !matches!(out, TickOutcome::CoolingDown { .. }),
            "a moved HEAD must release the cooldown early, got {out:?}",
        );
        assert!(
            env.builds.borrow().iter().any(|r| r == &rev(2)),
            "and the NEW rev is what gets built: {:?}",
            env.builds.borrow(),
        );
    }

    /// The other half, and the one that keeps the cooldown meaning anything:
    /// the SAME rev still waits out the clock. Without this the change would
    /// have deleted the backoff rather than scoped it, and a rev that fails
    /// deterministically would be rebuilt every single tick.
    #[test]
    fn the_same_head_during_cooldown_still_waits() {
        let env = MockEnv::with_probes(vec![
            Ok(Some(rev(1))),
            Ok(Some(rev(1))),
            Ok(Some(rev(1))),
        ]);
        env.set_build_result(Err(EnvError::BuildFailed("boom".into())));
        env.set_now_ms(0);
        let mut s = Sentinela::new(cfg());
        assert!(matches!(s.tick(&env), TickOutcome::BuildFailed { .. }));
        let State::CoolingDown { until_unix_ms, .. } = *s.state() else {
            panic!("a failed build must cool down");
        };
        let builds_before = env.builds.borrow().len();

        env.set_now_ms(until_unix_ms - 1);
        assert!(
            matches!(s.tick(&env), TickOutcome::CoolingDown { .. }),
            "an unchanged HEAD must keep waiting",
        );
        assert_eq!(
            env.builds.borrow().len(),
            builds_before,
            "and must not rebuild the rev that just failed",
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
            until_unix_ms: 11_000,
            failed_rev: Some(rev(1))
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
            until_unix_ms: 21_000,
            failed_rev: Some(rev(1))
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
            until_unix_ms: 2_000,
            failed_rev: Some(rev(1))
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
            until_unix_ms: 4_000,
            // No HEAD was ever observed, so there is nothing to
                // compare a later probe against — the clock is all there is.
                failed_rev: None
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
            until_unix_ms: 1_500,
            // No HEAD was ever observed, so there is nothing to
                // compare a later probe against — the clock is all there is.
                failed_rev: None
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
            until_unix_ms: 1_000,
            failed_rev: Some(rev(1))
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

    // ── Health-gated rollback ──────────────────────────────────────────

    use crate::probation::{HealthProbe, ProbeCheck};

    /// A 300s window probed every 15s, verified by 2 consecutive passes —
    /// the shipped defaults — over two probes, so a test can see a round
    /// stop at its FIRST failure.
    fn policy() -> RollbackPolicy {
        let probe = |name: &str| HealthProbe {
            name: name.to_owned(),
            check: ProbeCheck::Command {
                argv: vec!["/usr/bin/true".to_owned()],
                expect_exit: 0,
                timeout_seconds: 10,
            },
        };
        RollbackPolicy {
            window_ms: 300_000,
            interval_seconds: 15,
            required_consecutive_passes: 2,
            probes: vec![probe("network"), probe("tailscale")],
        }
    }

    fn guarded() -> Sentinela {
        Sentinela::new(cfg()).with_rollback(Some(policy()))
    }

    /// A node running rev(1) at generation 41, about to be offered rev(2).
    fn node_on_rev1() -> MockEnv {
        let env = MockEnv::default();
        let mut c = ReceiptChain::new();
        c.append(c.next_receipt(
            rev(1),
            Outcome::Activated {
                generation: Generation(41),
            },
            0,
        ))
        .unwrap();
        env.persist_chain(&c).unwrap();
        env.set_generation(Some(Generation(41)));
        env.set_switch_result(Ok(Generation(42)));
        env
    }

    /// Deploy rev(2) under a guarded loop; returns the loop in probation.
    fn deploy_rev2_on_probation(env: &MockEnv) -> Sentinela {
        env.push_probe(Ok(Some(rev(2))));
        env.push_probe(Ok(Some(rev(2))));
        let mut s = guarded();
        assert_eq!(
            s.tick(env),
            TickOutcome::Deployed {
                rev: rev(2),
                generation: Generation(42)
            }
        );
        let State::Verifying(p) = s.state().clone() else {
            panic!("an activation under a rollback policy must enter probation, got {:?}", s.state());
        };
        assert_eq!(p.previous_generation, Generation(41), "read BEFORE the switch");
        assert_eq!(p.generation, Generation(42));
        s
    }

    fn outcomes(env: &MockEnv) -> Vec<&'static str> {
        env.chain()
            .entries()
            .iter()
            .map(|r| match r.outcome {
                Outcome::Activated { .. } => "activated",
                Outcome::Failed { .. } => "failed",
                Outcome::Deferred { .. } => "deferred",
                Outcome::Probation { .. } => "probation",
                Outcome::Verified { .. } => "verified",
                Outcome::RolledBack { .. } => "rolledBack",
            })
            .collect()
    }

    /// A switch that FAILED after the machine moved to the new generation is
    /// judged like a clean one. `switch-to-configuration` exits non-zero when
    /// a unit fails to start, AFTER the new generation is active, so "switch
    /// failed" can mean "the machine now runs the broken generation" — the
    /// case a rollback exists for, and the one a cooldown-and-retry never
    /// leaves.
    #[test]
    fn a_failed_switch_that_moved_the_machine_is_judged_and_rolled_back() {
        let env = node_on_rev1();
        env.set_switch_result(Err(EnvError::SwitchFailed(
            "engenho-daemon.service failed to start".to_owned(),
        )));
        env.set_switch_moves_on_error(Some(Generation(42)));
        env.push_probe(Ok(Some(rev(2))));
        env.push_probe(Ok(Some(rev(2))));
        let mut s = guarded();
        assert!(matches!(s.tick(&env), TickOutcome::SwitchFailed { .. }));
        let State::Verifying(p) = s.state().clone() else {
            panic!("a failed switch that moved the machine must enter probation, got {:?}", s.state());
        };
        assert_eq!((p.generation, p.previous_generation), (Generation(42), Generation(41)));

        env.push_probe_result(Err("http home-assistant: no answer".to_owned()));
        env.set_now_ms(p.deadline_unix_ms + 1);
        assert!(matches!(
            s.tick(&env),
            TickOutcome::RolledBack { to: Generation(41), .. }
        ));
        assert_eq!(env.rollbacks.borrow().as_slice(), &[Generation(41)]);
        assert_eq!(env.chain().quarantined_rev(), Some(&rev(2)));
        assert_eq!(env.chain().last_activated_rev(), Some(&rev(1)));
    }

    /// A failed switch that left the machine where it was opens nothing: the
    /// previous generation still runs, and there is nothing to roll back.
    #[test]
    fn a_failed_switch_that_left_the_machine_alone_cools_down_as_before() {
        let env = node_on_rev1();
        env.set_switch_result(Err(EnvError::SwitchFailed("eval error".to_owned())));
        env.push_probe(Ok(Some(rev(2))));
        env.push_probe(Ok(Some(rev(2))));
        let mut s = guarded();
        assert!(matches!(s.tick(&env), TickOutcome::SwitchFailed { .. }));
        assert!(matches!(s.state(), State::CoolingDown { .. }), "{:?}", s.state());
        assert!(env.probe_runs.borrow().is_empty());
    }

    /// PATH 1 — probes pass, so the activation converges. Two consecutive
    /// passing rounds verify it; nothing is rolled back; the next tick is the
    /// ordinary `unchanged`.
    #[test]
    fn passing_probes_verify_the_activation_and_the_loop_converges() {
        let env = node_on_rev1();
        let mut s = deploy_rev2_on_probation(&env);

        // The deploy tick's pulse already says what the loop waits on.
        let deploy_beat = env.heartbeats.borrow().last().cloned().unwrap();
        assert!(deploy_beat.verification.is_some(), "the probation is visible from its first tick");

        env.set_now_ms(15_000);
        let first = s.tick(&env);
        assert!(
            matches!(&first, TickOutcome::Verifying(p) if p.passes == 1),
            "one pass is not two: {first:?}"
        );
        assert_eq!(s.next_delay(&first), std::time::Duration::from_secs(15), "the probe interval rules");
        let beat = env.heartbeats.borrow().last().cloned().unwrap();
        assert_eq!(beat.outcome, "verifying");
        assert_eq!(beat.phase, Phase::InFlight, "probation is convergence in flight, not an idle loop");

        env.set_now_ms(30_000);
        assert_eq!(
            s.tick(&env),
            TickOutcome::Verified {
                rev: rev(2),
                generation: Generation(42)
            }
        );
        assert_eq!(s.state(), &State::Idle);
        assert!(env.rollbacks.borrow().is_empty());
        assert_eq!(outcomes(&env), ["activated", "activated", "probation", "verified"]);
        assert_eq!(
            *env.probe_runs.borrow(),
            ["network", "tailscale", "network", "tailscale"],
            "every probe, every round"
        );

        env.push_probe(Ok(Some(rev(2))));
        assert_eq!(s.tick(&env), TickOutcome::Unchanged { rev: rev(2) });
        env.chain().verify().unwrap();
    }

    /// PATH 2 — the window expires on a failing round: the PREVIOUS
    /// generation is re-activated, and the rev is marked bad in the chain
    /// with the failing probe's name and evidence.
    #[test]
    fn a_failing_probe_past_the_window_rolls_back_and_marks_the_rev_bad() {
        let env = node_on_rev1();
        let mut s = deploy_rev2_on_probation(&env);

        // Inside the window a failure only resets the streak.
        env.push_probe_result(Err("exit 1: tailscaled not running".to_owned()));
        env.set_now_ms(15_000);
        let out = s.tick(&env);
        match &out {
            TickOutcome::Verifying(p) => {
                assert_eq!(p.passes, 0);
                let f = p.last_failure.as_ref().expect("the failure is carried");
                assert_eq!(f.probe, "network", "the round stops at its first failure");
            }
            other => panic!("inside the window a failure must not roll back: {other:?}"),
        }
        assert!(env.rollbacks.borrow().is_empty());
        let beat = env.heartbeats.borrow().last().cloned().unwrap();
        assert_eq!(
            beat.verification.and_then(|p| p.last_failure).map(|f| f.evidence),
            Some("exit 1: tailscaled not running".to_owned()),
            "the pulse names the failing probe's output"
        );

        // Past the deadline, a failing round rolls back.
        env.push_probe_result(Ok(()));
        env.push_probe_result(Err("exit 2: no route to host".to_owned()));
        env.set_now_ms(300_000);
        let out = s.tick(&env);
        assert_eq!(
            out,
            TickOutcome::RolledBack {
                rev: rev(2),
                from: Generation(42),
                to: Generation(41),
                failure: ProbeFailure {
                    probe: "tailscale".to_owned(),
                    evidence: "exit 2: no route to host".to_owned(),
                },
            }
        );
        assert_eq!(*env.rollbacks.borrow(), vec![Generation(41)], "back to the generation read before the switch");
        assert_eq!(env.current_generation(), Some(Generation(41)));
        assert_eq!(s.state(), &State::Idle);

        let chain = env.chain();
        match &chain.head().unwrap().outcome {
            Outcome::RolledBack { from, to, probe, evidence } => {
                assert_eq!((*from, *to), (Generation(42), Generation(41)));
                assert_eq!(probe, "tailscale");
                assert_eq!(evidence, "exit 2: no route to host");
            }
            other => panic!("the rev must be marked bad in the chain, got {other:?}"),
        }
        assert_eq!(chain.quarantined_rev(), Some(&rev(2)));
        assert_eq!(chain.last_activated_rev(), Some(&rev(1)), "the node runs rev(1) again");
        assert!(chain.consecutive_failures() > 0, "and it is not converged");
        chain.verify().unwrap();
        // A rollback is NOT the no-downgrade rule: the branch is untouched.
        assert_eq!(*env.switches.borrow(), vec![rev(2)], "no git-level rollback happened");
    }

    /// PATH 3 — the bad rev is not retried while it is HEAD, and is tried
    /// again (with a fresh build) only once HEAD moves.
    #[test]
    fn a_rolled_back_rev_is_not_retried_until_head_moves() {
        let env = node_on_rev1();
        let mut s = deploy_rev2_on_probation(&env);
        env.push_probe_result(Err("dead".to_owned()));
        env.set_now_ms(300_000);
        assert_eq!(s.tick(&env).kind(), "rolledBack");
        let builds = env.builds.borrow().len();

        for n in 1..=3u64 {
            env.set_now_ms(300_000 + n * 60_000);
            env.push_probe(Ok(Some(rev(2))));
            assert_eq!(
                s.tick(&env),
                TickOutcome::Quarantined { rev: rev(2) },
                "HEAD is still the rolled-back rev"
            );
        }
        assert_eq!(env.builds.borrow().len(), builds, "never rebuilt");
        assert_eq!(env.switches.borrow().len(), 1, "never re-activated");
        assert_eq!(env.chain().len(), 4, "and the refusal writes nothing to the chain");
        let beat = env.heartbeats.borrow().last().cloned().unwrap();
        assert_eq!(beat.head_rev, Some(rev(2)), "a quarantined tick did observe HEAD");

        // HEAD moves: the new rev deploys (and goes on probation itself).
        env.set_switch_result(Ok(Generation(43)));
        env.push_probe(Ok(Some(rev(3))));
        env.push_probe(Ok(Some(rev(3))));
        assert!(matches!(s.tick(&env), TickOutcome::Deployed { rev: r, .. } if r == rev(3)));
        assert!(matches!(s.state(), State::Verifying(p) if p.previous_generation == Generation(41)));
    }

    /// PATH 4 — disabled means today's behaviour exactly. No policy: no
    /// probation, no probes, no rollbacks, no probation receipt, a resolved
    /// pulse with no verification field — and no quarantine, even over a
    /// chain that carries a rollback from when it was on. (The existing
    /// suite is the rest of the proof: every test above this section runs
    /// `Sentinela::new(cfg())` with no policy and is unchanged.)
    #[test]
    fn rollback_off_is_todays_behaviour_exactly() {
        let env = node_on_rev1();
        let mut c = env.chain();
        c.append(c.next_receipt(rev(2), Outcome::Activated { generation: Generation(42) }, 1))
            .unwrap();
        c.append(c.next_receipt(
            rev(2),
            Outcome::RolledBack {
                from: Generation(42),
                to: Generation(41),
                probe: "network".into(),
                evidence: "x".into(),
            },
            2,
        ))
        .unwrap();
        env.persist_chain(&c).unwrap();
        for _ in 0..4 {
            env.push_probe_result(Err("would fail".to_owned()));
        }
        env.push_probe(Ok(Some(rev(2))));
        env.push_probe(Ok(Some(rev(2))));

        let mut s = Sentinela::new(cfg()).with_rollback(None);
        assert_eq!(
            s.tick(&env),
            TickOutcome::Deployed {
                rev: rev(2),
                generation: Generation(42)
            },
            "off means the loop converges on HEAD as it always has"
        );
        assert_eq!(s.state(), &State::Idle, "no probation");
        assert!(env.probe_runs.borrow().is_empty(), "no probes run");
        assert!(env.rollbacks.borrow().is_empty());
        assert_eq!(
            outcomes(&env),
            ["activated", "activated", "rolledBack", "activated"],
            "one Activated receipt, exactly as before — no probation receipt"
        );
        let beat = env.heartbeats.borrow().last().cloned().unwrap();
        assert_eq!(beat.phase, Phase::Resolved);
        assert_eq!(beat.verification, None);
        assert!(
            !serde_json::to_string(&beat).unwrap().contains("verification"),
            "the pulse is byte-shaped as before"
        );
        assert_eq!(
            s.next_delay(&TickOutcome::Deployed { rev: rev(2), generation: Generation(42) }),
            std::time::Duration::from_secs(60)
        );
    }

    /// The reboot case. The daemon dies mid-probation (its own unit
    /// changed, a crash, a reboot) and the new process must resume the
    /// trial from the chain — and do it WITHOUT the network, because a
    /// generation that broke the network breaks `probe_head` too.
    #[test]
    fn an_open_probation_survives_a_restart_and_rolls_back_without_the_network() {
        let env = node_on_rev1();
        let dead = deploy_rev2_on_probation(&env);
        drop(dead); // the process that opened the probation is gone

        // Every head probe now fails: the bad generation took the network.
        for _ in 0..4 {
            env.push_probe(Err(EnvError::ProbeFailed("network unreachable".into())));
        }
        env.push_probe_result(Err("exit 1".to_owned()));
        env.set_now_ms(400_000);
        let mut fresh = guarded();
        assert_eq!(
            fresh.tick(&env).kind(),
            "rolledBack",
            "a restarted loop must finish the trial, not forget it"
        );
        assert_eq!(*env.rollbacks.borrow(), vec![Generation(41)]);
    }

    /// Never revert a generation that is not the one on trial: an operator
    /// switched during the window, so the rollback would undo THEIR work.
    #[test]
    fn a_system_that_moved_during_probation_is_not_rolled_back() {
        let env = node_on_rev1();
        let mut s = deploy_rev2_on_probation(&env);
        env.set_generation(Some(Generation(50))); // someone else's switch
        env.push_probe_result(Err("dead".to_owned()));
        env.set_now_ms(300_000);
        assert_eq!(
            s.tick(&env),
            TickOutcome::ProbationAbandoned {
                rev: rev(2),
                expected: Generation(42),
                found: Some(Generation(50)),
            }
        );
        assert!(env.rollbacks.borrow().is_empty());
        assert_eq!(s.state(), &State::Idle);
    }

    /// A due rollback stands aside for an operator's lock and a failed one
    /// retries — neither is attested as a rollback, and both stay on trial.
    #[test]
    fn a_blocked_or_failed_rollback_stays_on_probation() {
        let env = node_on_rev1();
        let mut s = deploy_rev2_on_probation(&env);
        env.set_now_ms(300_000);

        env.set_rollback_result(Err(EnvError::SwitchBusy("pid 7 · drzzln".into())));
        env.push_probe_result(Err("dead".to_owned()));
        assert_eq!(s.tick(&env).kind(), "rollbackDeferred");
        assert!(matches!(s.state(), State::Verifying(_)));

        env.set_rollback_result(Err(EnvError::RollbackFailed("activate: exit 1".into())));
        env.push_probe_result(Err("dead".to_owned()));
        let out = s.tick(&env);
        assert_eq!(out.kind(), "rollbackFailed");
        assert_eq!(out.phase(), Phase::Resolved, "a failed rollback is loud, never in-progress");
        assert!(matches!(s.state(), State::Verifying(_)));
        assert!(env.chain().quarantined_rev().is_none(), "nothing attested until a rollback lands");

        env.set_rollback_result(Ok(()));
        env.push_probe_result(Err("dead".to_owned()));
        assert_eq!(s.tick(&env).kind(), "rolledBack");
        assert_eq!(env.rollbacks.borrow().len(), 3);
    }

    /// A passing round at the deadline earns another round: never revert a
    /// machine whose latest evidence is healthy.
    #[test]
    fn a_passing_round_past_the_deadline_is_not_rolled_back() {
        let env = node_on_rev1();
        let mut s = deploy_rev2_on_probation(&env);
        env.set_now_ms(999_000);
        assert!(matches!(s.tick(&env), TickOutcome::Verifying(p) if p.passes == 1));
        assert_eq!(s.tick(&env).kind(), "verified");
        assert!(env.rollbacks.borrow().is_empty());
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
