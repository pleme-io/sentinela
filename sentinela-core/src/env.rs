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
}

/// FSM tunables (mirrors the operator-facing `pleme.gitops` surface that
/// matters to the loop's decisions; wiring/paths live in the real env).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopConfig {
    /// How long to cool down after a failure before the next probe, in
    /// milliseconds. During cooldown the loop touches nothing.
    pub cooldown_after_failure_ms: u64,
}

impl Default for LoopConfig {
    fn default() -> Self {
        // A failed activation is usually a transient build/network fault;
        // back off five minutes before retrying so a broken HEAD does not
        // hammer the builder.
        Self { cooldown_after_failure_ms: 5 * 60 * 1000 }
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
    }

    impl GitopsEnv for MockEnv {
        fn probe_head(&self) -> Result<Option<Rev>, EnvError> {
            self.probes
                .borrow_mut()
                .pop_front()
                .unwrap_or(Ok(None))
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
    }
}
