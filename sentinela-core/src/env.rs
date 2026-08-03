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
    /// Reading or writing the receipt chain failed.
    #[error("receipt store io: {0}")]
    ReceiptIo(String),
    /// Writing the liveness heartbeat failed. Never fatal to a cycle — a
    /// loop that cannot record its pulse must still do its job — but it is
    /// reported so the silence has a cause.
    #[error("heartbeat io: {0}")]
    HeartbeatIo(String),
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Heartbeat {
    /// When this tick completed, unix-millis from the env's clock.
    pub at_unix_ms: u64,
    /// The [`crate::TickOutcome`] variant name — what the loop did.
    pub outcome: String,
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
}

impl Default for LoopConfig {
    fn default() -> Self {
        // A failed activation is usually a transient build/network fault;
        // back off five minutes before retrying so a broken HEAD does not
        // hammer the builder.
        Self {
            cooldown_after_failure_ms: 5 * 60 * 1000,
            poll_seconds: 60,
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
