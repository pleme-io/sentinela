//! Defer an activation while the machine is busy.

use crate::probation::HealthProbe;
use crate::rev::Rev;
use serde::{Deserialize, Serialize};

/// The effective busy gate: present only when at least one probe survived
/// validation. A probe says busy when its exit status equals `expect_exit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusyGate {
    /// Run in order before each activation.
    pub probes: Vec<HealthProbe>,
    /// Past this wait, the activation proceeds over a busy probe.
    pub max_wait_ms: u64,
    /// Seconds between checks while deferred. Always at least 1.
    pub recheck_seconds: u64,
}

/// What one run of a probe observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ProbeReading {
    /// The exit status equalled `expect_exit`.
    Matched,
    /// The probe ran and exited with another status.
    Unmatched {
        /// Exit status and output tail.
        evidence: String,
    },
    /// The probe timed out, was killed, or could not start.
    Unreadable {
        /// Why it could not be read.
        reason: String,
    },    TimedOut {
        reason: String,
    },
}

/// Why a probe holds the activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum BusyReading {
    /// The probe matched: the machine is busy.
    Busy,
    /// The probe could not be read, so idle was not proven.
    Unknown {
        /// Why it could not be read.
        reason: String,
    },
}

/// An activation held back by a busy probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BusyDeferral {
    /// The built rev waiting to be activated.
    pub rev: Rev,
    /// The probe that holds it.
    pub probe: String,
    /// What that probe said.
    pub reading: BusyReading,
    /// When the wait began, unix-ms.
    pub since_unix_ms: u64,
    /// How long the activation has waited so far.
    pub waited_ms: u64,
    /// The bound past which it activates anyway.
    pub max_wait_ms: u64,
}

/// An activation that proceeded over a busy probe at the bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BusyOverride {
    /// The probe that still held it.
    pub probe: String,
    /// What that probe said.
    pub reading: BusyReading,
    /// How long the activation waited.
    pub waited_ms: u64,
}

/// One round of the gate: the first probe that matched, else the first that
/// could not be read, else idle.
pub(crate) fn first_busy(
    probes: &[HealthProbe],
    read: impl Fn(&HealthProbe) -> ProbeReading,
) -> Option<(String, BusyReading)> {
    let mut unknown = None;
    for probe in probes {
        match read(probe) {
            ProbeReading::Matched => return Some((probe.name.clone(), BusyReading::Busy)),
            ProbeReading::Unreadable { reason } | ProbeReading::TimedOut { reason } => {
                if unknown.is_none() {
                    unknown = Some((probe.name.clone(), BusyReading::Unknown { reason }));
                }
            }
            ProbeReading::Unmatched { .. } => {}
        }
    }
    unknown
}
