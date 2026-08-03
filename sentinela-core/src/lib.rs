//! sentinela-core — the injectable, testable algebra of `sentinela`, the
//! Darwin GitOps node-sync daemon (the Mac peer of NixOS `comin`).
//!
//! A single long-running daemon keeps this Mac's darwin system equal to
//! one repo's branch HEAD: it probes HEAD over the git protocol
//! (rate-limit-immune), builds it rev-pinned, re-checks freshness, and
//! activates — attesting each deploy to an append-only BLAKE3 chain.
//!
//! This crate is **pure over a [`GitopsEnv`]**: it decides *what* to do;
//! the env *does* it (ls-remote / build / switch / clock / receipt-store).
//! Every transition and invariant is provable against [`MockEnv`] — no
//! network, no build, no clock. The real env (git + darwin-rebuild + a
//! file-backed chain) lives in the `sentinela` binary.
//!
//! The five guards that made the v1.5 shell loop rollback-proof survive
//! as *structure* here (see [`fsm`]): fail-closed, skip-if-unchanged,
//! rev-pinned build, post-build no-downgrade re-check, receipt-before-idle
//! — plus single-flight, which is now structural (one daemon, one loop).

#![forbid(unsafe_code)]

mod env;
mod fsm;
mod receipt;
mod rev;

pub use env::{EnvError, GitopsEnv, Heartbeat, LoopConfig};
pub use fsm::{Sentinela, State, TickOutcome};
pub use receipt::{ChainError, DeployReceipt, Generation, Outcome, ReceiptChain, GENESIS_HASH};
pub use rev::{Rev, RevError};

#[cfg(any(test, feature = "mock"))]
pub use env::MockEnv;
