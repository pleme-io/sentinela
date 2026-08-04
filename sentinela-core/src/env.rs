//! The injectable side-effect boundary. Every impure action the daemon
//! takes — resolving HEAD, building, switching, reading/writing the
//! receipt chain, reading the clock — is a method on [`GitopsEnv`]. The
//! FSM ([`crate::Sentinela`]) is pure over this trait: it decides *what*
//! to do; the env *does* it. Production ships one real impl (git
//! ls-remote + darwin-rebuild + a file-backed chain); tests drive the
//! FSM against [`MockEnv`], so every transition + invariant is provable
//! with no network, no build, no clock. This is the TYPED-SPEC
//! Environment-trait discipline.

use crate::receipt::{Generation, ReceiptChain};
use crate::rev::Rev;

/// A hard failure from an env operation. Every variant is fail-closed at
/// the FSM layer — a build/switch/probe error never advances the system.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvError {
    /// `git ls-remote` failed (network, auth, bad url).
    #[error("probe failed: {0}")]
    ProbeFailed(String),
    /// `darwin-rebuild build` failed for the rev.
    #[error("build failed: {0}")]
    BuildFailed(String),
    /// `darwin-rebuild switch` failed for the rev.
    #[error("switch failed: {0}")]
    SwitchFailed(String),
    /// The machine-wide rebuild lock (`/tmp/fleet-rebuild.lock`, shared with
    /// `fleet rebuild`) is held by another process — an operator rebuild is
    /// in progress. The payload names the holder. NOT a failure: the FSM
    /// defers the switch (no receipt, no cooldown) and retries on a bounded
    /// cadence, so the daemon stands aside while the operator owns the
    /// machine instead of racing their activation state.
    #[error("switch deferred: another rebuild holds the machine lock ({0})")]
    SwitchBusy(String),
    /// Reading or writing the receipt chain failed.
    #[error("receipt store io: {0}")]
    ReceiptIo(String),
    /// Writing the liveness heartbeat failed. Never fatal to a cycle — a
    /// loop that cannot record its pulse must still do its job — but it is
    /// reported so the silence has a cause.
    #[error("heartbeat io: {0}")]
    HeartbeatIo(String),
    /// An ancestry question could not be answered. ALWAYS fail-closed: an
    /// unanswerable "is this a forward move?" must read as *no*, never as
    /// *probably*.
    #[error("ancestry check failed: {0}")]
    AncestryFailed(String),
}

/// One tick's pulse: proof the loop was ALIVE at a moment, independent of
/// whether it had anything to do.
///
/// ── ★ WHY A RECEIPT CANNOT SERVE AS A HEARTBEAT ─────────────────────────
/// The receipt chain records *activations*. A healthy loop with nothing to
/// do activates nothing for weeks, so its newest receipt is indefinitely
/// old — meaning "last receipt was 27 days ago" is equally consistent with
/// a perfectly converged node and a process that died 27 days ago.
///
/// That ambiguity is not theoretical. On 2026-08-02 cid's `status` printed
/// `consecutive_failures: 0, chain_verified: true` from a chain whose head
/// was a clean activation, while the LaunchDaemon had been dead since boot
/// (exit 78 EX_CONFIG) and the node sat 14 commits behind origin/main.
/// Every stored fact was true and the node was not reconciling.
///
/// So liveness gets its own record, written on EVERY tick including every
/// fail-closed path. A reader compares `at_unix_ms` against the poll
/// interval: silence beyond a few intervals is a STOPPED loop, which is a
/// failure, not an absence of news.
/// Whether a pulse reports a tick that FINISHED or one still running.
///
/// ── ★ WHY A LONG BUILD MUST NOT LOOK LIKE A DEAD LOOP ────────────────────
/// A pulse used to be written only after the tick resolved, so the whole
/// build was silent. MEASURED on ryn 2026-08-02: a 12m02s darwin build
/// produced 722s of silence against a 180s staleness budget
/// (`STALE_AFTER_POLLS = 3` × `poll_seconds` 60), so `status --gate` reported
/// *"the loop is stopped, not idle"* while the loop was converging normally.
/// Any build longer than two poll intervals was structurally un-gateable, and
/// the wrong verdict was produced by the tool rather than by the reader — it
/// took a human down the wrong diagnosis for an hour.
///
/// So the phase is a TYPE, not a sentinel value in `outcome`: consumers
/// `match` on it, and a new phase is a compile error at every reader rather
/// than an unrecognised string that silently takes the wrong branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// The tick finished; `outcome` names what it did.
    ///
    /// The default on purpose: a heartbeat written before this field existed
    /// deserializes as a completed tick, which is what it was.
    #[default]
    Resolved,
    /// The tick is inside a build that had not returned when this was
    /// written. `outcome` names the PENDING action, not a completed one.
    InFlight,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Heartbeat {
    /// When this tick completed, unix-millis from the env's clock.
    pub at_unix_ms: u64,
    /// The [`crate::TickOutcome`] variant name — what the loop did.
    ///
    /// When [`Self::phase`] is [`Phase::InFlight`] this is the pending
    /// action (`"building"`) rather than a resolved variant. That is a
    /// deliberate, documented widening of this field's namespace: the
    /// alternative — leaving the previous tick's resolved outcome in place
    /// while a build runs — publishes a value that is simply false for the
    /// current tick, and the external `fleet` consumer would read it as
    /// current. A reader that must distinguish the two cases matches
    /// [`Self::phase`]; a reader that only wants "what is it doing" gets a
    /// true answer either way.
    pub outcome: String,
    /// Whether this pulse reports a finished tick or one still in flight.
    ///
    /// `#[serde(default)]` is load-bearing, not tidiness: `load_heartbeat`
    /// swallows a parse error into `None`, and the gate reports `None` as
    /// *"no heartbeat has ever been published"*. Without the default, the
    /// first run after an upgrade would read every pre-existing heartbeat as
    /// corrupt and report a live loop as never-having-run.
    #[serde(default)]
    pub phase: Phase,
    /// Branch HEAD as observed by THIS tick, when the tick got far enough
    /// to observe one. `None` on a probe error or an unresolvable HEAD:
    /// we did not measure it, so we do not report one.
    pub head_rev: Option<Rev>,
    /// The loop's poll interval, in seconds.
    ///
    /// Published WITH the pulse because a reader cannot judge staleness
    /// from a timestamp alone — "last tick 400s ago" is healthy at an
    /// hourly cadence and dead at a 60s one. Without it every consumer
    /// either guesses (manufacturing a verdict from a number nobody wrote)
    /// or reports `unknown` while holding a perfectly good heartbeat.
    /// Measured on the first consumer, which did exactly the latter.
    pub poll_seconds: u64,
}

/// FSM tunables (mirrors the operator-facing `pleme.gitops` surface that
/// matters to the loop's decisions; wiring/paths live in the real env).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopConfig {
    /// How long to cool down after a failure before the next probe, in
    /// milliseconds. During cooldown the loop touches nothing.
    pub cooldown_after_failure_ms: u64,
    /// Seconds between cycles. The FSM does not sleep — the caller does —
    /// but it stamps every heartbeat with this so a reader never has to
    /// guess the cadence it is judging staleness against.
    pub poll_seconds: u64,
    /// How many consecutive deferrals before the loop will accept landing a
    /// rev that is an ANCESTOR of HEAD rather than HEAD itself.
    ///
    /// ── ★ WHY A THRESHOLD AND NOT ALWAYS ─────────────────────────────────
    /// Landing an ancestor is always *safe* (it is on the branch, and it is
    /// forward for this node), but during normal operation it is not
    /// *desirable*: it means deliberately activating a rev we already know
    /// has been superseded, when simply deferring one tick would have landed
    /// the newest. The strict rule is right when the loop is keeping up.
    ///
    /// It is only wrong when the loop CANNOT keep up — and a deferral streak
    /// is exactly the measurement of that. So the strict semantics stay the
    /// default and this relaxation is reachable only from the failure state
    /// it exists to escape, which bounds its blast radius to the case where
    /// today's alternative is starving forever.
    ///
    /// A BOUND, not a preference: it changes no program's meaning, only how
    /// long the loop insists on the strictest form of progress before
    /// accepting a weaker one. `0` disables the relaxation entirely.
    pub land_ancestor_after_deferrals: usize,
    /// How many consecutive BUILD FAILURES before the loop will fall back to
    /// the newest rev it already proved buildable — the second starvation
    /// escape. `0` disables it.
    ///
    /// ── ★ THE HOLE THIS CLOSES: A BROKEN HEAD STARVES THE NODE FOREVER ───
    /// `land_ancestor_after_deferrals` escapes the case where the loop cannot
    /// keep up. It does NOT escape the case where HEAD simply does not build:
    /// that path is `record → cooldown → retry the same broken rev`, which
    /// makes no progress no matter how many times it runs, because the rev is
    /// not going to start building on its own. A node can hold a rev it
    /// already built and verified while HEAD stays red indefinitely.
    ///
    /// MEASURED on cid 2026-08-04. `8b7af29` built clean and deferred; two
    /// commits then landed an unresolved git merge in `flake.lock` (16
    /// conflict markers — JSON, so it fails at the parser), and every
    /// subsequent tick failed in ~1–8s against that head. The node held
    /// `8b7af29`, which BUILT, and would never have activated it — and that
    /// rev carried a kubeconfig token re-seed the whole fleet was waiting on.
    /// The break was upstream and human; the starvation was ours.
    ///
    /// Safety is IDENTICAL to the deferral escape and reuses its two proofs:
    /// the candidate must be an ancestor of HEAD (forward along the same
    /// history — a force-push or revert fails this) and a descendant of what
    /// this node last activated (forward for this node). Both fail closed.
    /// The candidate itself is never speculative: it is only ever a rev with
    /// a receipt saying this node built it.
    ///
    /// Deliberately a SEPARATE knob from the deferral threshold: they escape
    /// different traps and want different numbers. A deferral means the loop
    /// is healthy but slow, so 2 is patient. A failure streak means HEAD is
    /// red, where each extra attempt costs a full build and buys nothing.
    pub land_last_good_after_failures: usize,
}

impl Default for LoopConfig {
    fn default() -> Self {
        // A failed activation is usually a transient build/network fault;
        // back off five minutes before retrying so a broken HEAD does not
        // hammer the builder.
        Self {
            cooldown_after_failure_ms: 5 * 60 * 1000,
            poll_seconds: 60,
            // Two deferrals in a row is already ~25 minutes of building with
            // nothing landed — long enough to be a pattern rather than one
            // unlucky overlap, short enough that a node does not sit stale
            // for an hour proving what it already knows.
            land_ancestor_after_deferrals: 2,
            // Three failures against the same head, at a 5-minute cooldown,
            // is ~15 minutes of a red HEAD. Higher than the deferral
            // threshold on purpose: a deferral is one healthy tick losing a
            // race, while a failure may genuinely be transient (a flaky
            // fetch, a substituter blip), and falling back on the FIRST one
            // would trade a self-healing retry for a knowingly-stale deploy.
            // Three is past where "transient" is a credible reading.
            land_last_good_after_failures: 3,
        }
    }
}

/// The injectable side-effect boundary — see the module docs.
pub trait GitopsEnv {
    /// Resolve the configured branch HEAD via the **git protocol**
    /// (`git ls-remote`), never the GitHub API — so a rate limit can
    /// never substitute a stale cached tree.
    ///
    /// - `Ok(Some(rev))` — resolved HEAD.
    /// - `Ok(None)` — could not resolve (empty output); fail-closed:
    ///   deploy nothing this cycle.
    /// - `Err` — a hard probe error; also fail-closed.
    ///
    /// # Errors
    /// [`EnvError::ProbeFailed`] on a hard failure.
    fn probe_head(&self) -> Result<Option<Rev>, EnvError>;

    /// Build `rev` (rev-pinned), without activating it.
    ///
    /// # Errors
    /// [`EnvError::BuildFailed`].
    fn build(&self, rev: &Rev) -> Result<(), EnvError>;

    /// Is `ancestor` reachable from `descendant` — i.e. does the branch's
    /// history at `descendant` CONTAIN `ancestor`?
    ///
    /// ── ★ THE FACT THE LOOP WAS MISSING ──────────────────────────────────
    /// `probe_head` returns a bare rev, so the loop could only ever ask "is
    /// the rev I built still HEAD?" — a strict equality against a moving
    /// target. When a build takes longer than the interval between pushes
    /// that question is PERMANENTLY unsatisfiable, and the node starves
    /// while every build is thrown away. MEASURED on ryn 2026-08-02: a
    /// 12m02s build against a branch whose median inter-commit gap was under
    /// 7 minutes.
    ///
    /// "Still HEAD" is strictly stronger than "safe to activate". A rev that
    /// is an ANCESTOR of the new HEAD is still on the branch — activating it
    /// is a forward step, just not the newest one — whereas a rev the branch
    /// moved *away* from (force-push, reset, revert) is the rollback the
    /// no-downgrade rule exists to refuse. Only ancestry separates those two
    /// cases, and `git ls-remote` structurally cannot answer it.
    ///
    /// Implementations MUST fail closed: any doubt is `Ok(false)` or an
    /// [`EnvError::AncestryFailed`], never an optimistic `true`.
    ///
    /// # Errors
    /// [`EnvError::AncestryFailed`] when the question could not be answered.
    fn is_ancestor(&self, ancestor: &Rev, descendant: &Rev) -> Result<bool, EnvError>;

    /// Activate (`switch`) `rev`, returning the new generation.
    ///
    /// # Errors
    /// [`EnvError::SwitchFailed`].
    fn switch(&self, rev: &Rev) -> Result<Generation, EnvError>;

    /// Load the persisted receipt chain (an empty chain if none exists).
    ///
    /// # Errors
    /// [`EnvError::ReceiptIo`].
    fn load_chain(&self) -> Result<ReceiptChain, EnvError>;

    /// Persist the chain (atomically — a crash never leaves a half-written
    /// chain).
    ///
    /// # Errors
    /// [`EnvError::ReceiptIo`].
    fn persist_chain(&self, chain: &ReceiptChain) -> Result<(), EnvError>;

    /// Current time as unix-millis — the only clock the core observes.
    fn now_unix_ms(&self) -> u64;

    /// Record this tick's [`Heartbeat`], overwriting the previous one.
    ///
    /// Deliberately a REQUIRED method with no default. A defaulted no-op
    /// would let a real env silently never publish a pulse, which is the
    /// precise shape of the bug this exists to close — the reader would
    /// see no heartbeat and could not distinguish "not implemented" from
    /// "stopped".
    ///
    /// # Errors
    /// [`EnvError::HeartbeatIo`]. Callers treat this as non-fatal: a tick
    /// that did its work but could not write its pulse still succeeded.
    fn write_heartbeat(&self, beat: &Heartbeat) -> Result<(), EnvError>;
}

#[cfg(any(test, feature = "mock"))]
pub use mock::MockEnv;

#[cfg(any(test, feature = "mock"))]
mod mock {
    use super::{EnvError, GitopsEnv};
    use crate::receipt::{Generation, ReceiptChain};
    use crate::rev::Rev;
    use std::cell::RefCell;

    /// One programmed probe result.
    type ProbeResult = Result<Option<Rev>, EnvError>;

    /// A fully programmable [`GitopsEnv`] for driving the FSM in tests.
    /// Probe results are a queue (so a mid-build re-probe can differ from
    /// the initial probe); build/switch outcomes are programmable and
    /// recorded; the clock is settable; the chain is in-memory.
    pub struct MockEnv {
        probes: RefCell<std::collections::VecDeque<ProbeResult>>,
        build_result: RefCell<Result<(), EnvError>>,
        switch_result: RefCell<Result<Generation, EnvError>>,
        persist_result: RefCell<Result<(), EnvError>>,
        load_result: RefCell<Option<Result<ReceiptChain, EnvError>>>,
        chain: RefCell<ReceiptChain>,
        clock_ms: RefCell<u64>,
        pub builds: RefCell<Vec<Rev>>,
        pub switches: RefCell<Vec<Rev>>,
        pub persists: RefCell<u32>,
        /// Every heartbeat written, in order — so a test can prove that
        /// EVERY tick path published a pulse, not just the happy one.
        pub heartbeats: RefCell<Vec<super::Heartbeat>>,
        heartbeat_result: RefCell<Result<(), EnvError>>,
        /// Every `(ancestor, descendant)` pair the FSM asked about, in
        /// order — so a test can prove the loop asked the RIGHT question,
        /// not merely that it got the answer it wanted.
        pub ancestry_queries: RefCell<Vec<(Rev, Rev)>>,
        ancestry_result: RefCell<Result<bool, EnvError>>,
    }

    impl Default for MockEnv {
        fn default() -> Self {
            Self {
                probes: RefCell::new(std::collections::VecDeque::new()),
                build_result: RefCell::new(Ok(())),
                switch_result: RefCell::new(Ok(Generation(1))),
                persist_result: RefCell::new(Ok(())),
                load_result: RefCell::new(None),
                chain: RefCell::new(ReceiptChain::new()),
                clock_ms: RefCell::new(0),
                builds: RefCell::new(Vec::new()),
                switches: RefCell::new(Vec::new()),
                persists: RefCell::new(0),
                heartbeats: RefCell::new(Vec::new()),
                heartbeat_result: RefCell::new(Ok(())),
                ancestry_queries: RefCell::new(Vec::new()),
                // Fail-closed by default: a test that does not program an
                // answer must NOT accidentally exercise the relaxed path.
                ancestry_result: RefCell::new(Ok(false)),
            }
        }
    }

    impl MockEnv {
        /// A mock whose probe queue yields these results in order.
        #[must_use]
        pub fn with_probes(probes: Vec<ProbeResult>) -> Self {
            let m = Self::default();
            *m.probes.borrow_mut() = probes.into();
            m
        }

        /// Queue one more probe result.
        pub fn push_probe(&self, r: ProbeResult) {
            self.probes.borrow_mut().push_back(r);
        }

        /// Program the build outcome for subsequent `build` calls.
        pub fn set_build_result(&self, r: Result<(), EnvError>) {
            *self.build_result.borrow_mut() = r;
        }

        /// Program the switch outcome for subsequent `switch` calls.
        pub fn set_switch_result(&self, r: Result<Generation, EnvError>) {
            *self.switch_result.borrow_mut() = r;
        }

        /// Program the outcome of subsequent `persist_chain` calls (to
        /// exercise the receipt-IO failure path — the persist-after-switch
        /// hole the happy-path tests missed).
        pub fn set_persist_result(&self, r: Result<(), EnvError>) {
            *self.persist_result.borrow_mut() = r;
        }

        /// Force `load_chain` to return this exact result (to exercise a
        /// chain-load error). When `None` (default), `load_chain` returns
        /// the in-memory chain.
        pub fn set_load_result(&self, r: Option<Result<ReceiptChain, EnvError>>) {
            *self.load_result.borrow_mut() = r;
        }

        /// Set the clock.
        pub fn set_now_ms(&self, ms: u64) {
            *self.clock_ms.borrow_mut() = ms;
        }

        /// Snapshot the current chain.
        #[must_use]
        pub fn chain(&self) -> ReceiptChain {
            self.chain.borrow().clone()
        }

        /// Program the heartbeat-write outcome — to prove a tick still
        /// succeeds when its pulse cannot be recorded.
        /// Program the answer to every ancestry question.
        pub fn set_ancestry_result(&self, r: Result<bool, EnvError>) {
            *self.ancestry_result.borrow_mut() = r;
        }

        pub fn set_heartbeat_result(&self, r: Result<(), EnvError>) {
            *self.heartbeat_result.borrow_mut() = r;
        }
    }

    impl GitopsEnv for MockEnv {
        fn probe_head(&self) -> Result<Option<Rev>, EnvError> {
            self.probes.borrow_mut().pop_front().unwrap_or(Ok(None))
        }

        fn build(&self, rev: &Rev) -> Result<(), EnvError> {
            self.builds.borrow_mut().push(rev.clone());
            self.build_result.borrow().clone()
        }

        fn is_ancestor(&self, ancestor: &Rev, descendant: &Rev) -> Result<bool, EnvError> {
            self.ancestry_queries
                .borrow_mut()
                .push((ancestor.clone(), descendant.clone()));
            self.ancestry_result.borrow().clone()
        }

        fn switch(&self, rev: &Rev) -> Result<Generation, EnvError> {
            self.switches.borrow_mut().push(rev.clone());
            self.switch_result.borrow().clone()
        }

        fn load_chain(&self) -> Result<ReceiptChain, EnvError> {
            if let Some(forced) = self.load_result.borrow().as_ref() {
                return forced.clone();
            }
            Ok(self.chain.borrow().clone())
        }

        fn persist_chain(&self, chain: &ReceiptChain) -> Result<(), EnvError> {
            self.persist_result.borrow().clone()?;
            *self.persists.borrow_mut() += 1;
            *self.chain.borrow_mut() = chain.clone();
            Ok(())
        }

        fn now_unix_ms(&self) -> u64 {
            *self.clock_ms.borrow()
        }

        fn write_heartbeat(&self, beat: &super::Heartbeat) -> Result<(), EnvError> {
            self.heartbeat_result.borrow().clone()?;
            self.heartbeats.borrow_mut().push(beat.clone());
            Ok(())
        }
    }
}
