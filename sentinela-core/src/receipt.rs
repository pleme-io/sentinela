//! The attested deploy history — an append-only BLAKE3-chained log of
//! [`DeployReceipt`]s. This is the v1.5 one-line `deployed-rev` state
//! file grown into a tamper-evident chain: each receipt commits to the
//! previous receipt's hash, so a truncation or reorder is detectable
//! (`ReceiptChain::verify`). The chain is the source of truth for
//! `skip-if-unchanged` (the head receipt's rev) and the audit trail.

use crate::rev::Rev;
use serde::{Deserialize, Serialize};

/// A darwin-rebuild generation number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Generation(pub u64);

impl std::fmt::Display for Generation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The result of a deploy attempt, as recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Outcome {
    /// Activated cleanly to this generation.
    Activated { generation: Generation },
    /// The build or activation failed (message retained).
    Failed { error: String },
    /// A newer HEAD landed mid-build; this rev was deferred, not activated.
    Deferred { newer: Rev },
}

/// One entry in the deploy chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployReceipt {
    /// Monotonic sequence number (0-based; each receipt is `prev + 1`).
    pub seq: u64,
    /// The revision this receipt is about.
    pub rev: Rev,
    /// What happened.
    pub outcome: Outcome,
    /// Unix-millis timestamp (injected by the env's clock; the core never
    /// reads a wall clock itself).
    pub at_unix_ms: u64,
    /// BLAKE3 hex of the previous receipt's [`content_hash`](Self::content_hash),
    /// or the 64-zero genesis for `seq == 0`.
    pub prev_hash: String,
}

/// The genesis previous-hash for the first receipt.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

impl DeployReceipt {
    /// Content hash over the load-bearing fields (excludes `prev_hash`,
    /// which links receipts; the link is verified separately). Two
    /// receipts with identical content but different chains still each
    /// commit to their own predecessor via `prev_hash`.
    #[must_use]
    pub fn content_hash(&self) -> String {
        let mut h = blake3::Hasher::new();
        h.update(&self.seq.to_le_bytes());
        h.update(self.rev.as_str().as_bytes());
        h.update(&self.at_unix_ms.to_le_bytes());
        // The outcome is hashed by its canonical JSON so a variant change
        // is covered without hand-listing every field.
        let outcome_json = serde_json::to_vec(&self.outcome).unwrap_or_default();
        h.update(&outcome_json);
        h.update(self.prev_hash.as_bytes());
        h.finalize().to_hex().to_string()
    }

    /// Whether this receipt represents a clean activation.
    #[must_use]
    pub fn is_activated(&self) -> bool {
        matches!(self.outcome, Outcome::Activated { .. })
    }
}

/// An append-only, verifiable chain of deploy receipts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReceiptChain {
    entries: Vec<DeployReceipt>,
}

/// Why a chain is invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// `seq` is not the contiguous `prev + 1`.
    #[error("receipt {index}: seq {got} is not the expected {want}")]
    SeqGap { index: usize, got: u64, want: u64 },
    /// `prev_hash` does not match the actual previous receipt's content hash.
    #[error("receipt {index}: prev_hash does not match the previous receipt")]
    BrokenLink { index: usize },
}

impl ReceiptChain {
    /// An empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The most recent receipt, if any.
    #[must_use]
    pub fn head(&self) -> Option<&DeployReceipt> {
        self.entries.last()
    }

    /// The most recent *cleanly-activated* rev — the one to compare HEAD
    /// against for `skip-if-unchanged`. A failed/deferred receipt does
    /// not count as deployed.
    #[must_use]
    pub fn last_activated_rev(&self) -> Option<&Rev> {
        self.entries
            .iter()
            .rev()
            .find(|r| r.is_activated())
            .map(|r| &r.rev)
    }

    /// Number of receipts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the chain is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All receipts, oldest first.
    #[must_use]
    pub fn entries(&self) -> &[DeployReceipt] {
        &self.entries
    }

    /// Build the next receipt for `rev`/`outcome`/`at_unix_ms`, correctly
    /// linked to the current head — the ONLY sanctioned way to extend the
    /// chain, so a caller cannot mislink `seq`/`prev_hash` by hand.
    #[must_use]
    pub fn next_receipt(&self, rev: Rev, outcome: Outcome, at_unix_ms: u64) -> DeployReceipt {
        let (seq, prev_hash) = match self.head() {
            Some(h) => (h.seq + 1, h.content_hash()),
            None => (0, GENESIS_HASH.to_owned()),
        };
        DeployReceipt { seq, rev, outcome, at_unix_ms, prev_hash }
    }

    /// Append a receipt that was built via [`next_receipt`](Self::next_receipt).
    /// Rejects a receipt that does not correctly extend the chain, so the
    /// in-memory chain can never hold a broken link.
    ///
    /// # Errors
    /// [`ChainError`] if `seq` or `prev_hash` do not follow the head.
    pub fn append(&mut self, receipt: DeployReceipt) -> Result<(), ChainError> {
        let index = self.entries.len();
        let (want_seq, want_prev) = match self.head() {
            Some(h) => (h.seq + 1, h.content_hash()),
            None => (0, GENESIS_HASH.to_owned()),
        };
        if receipt.seq != want_seq {
            return Err(ChainError::SeqGap { index, got: receipt.seq, want: want_seq });
        }
        if receipt.prev_hash != want_prev {
            return Err(ChainError::BrokenLink { index });
        }
        self.entries.push(receipt);
        Ok(())
    }

    /// Verify the whole chain: contiguous `seq` and every `prev_hash`
    /// matching the real previous content hash.
    ///
    /// # Errors
    /// The first [`ChainError`] encountered.
    pub fn verify(&self) -> Result<(), ChainError> {
        let mut prev: Option<&DeployReceipt> = None;
        for (index, r) in self.entries.iter().enumerate() {
            let (want_seq, want_prev) = match prev {
                Some(p) => (p.seq + 1, p.content_hash()),
                None => (0, GENESIS_HASH.to_owned()),
            };
            if r.seq != want_seq {
                return Err(ChainError::SeqGap { index, got: r.seq, want: want_seq });
            }
            if r.prev_hash != want_prev {
                return Err(ChainError::BrokenLink { index });
            }
            prev = Some(r);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rev(n: u8) -> Rev {
        Rev::parse(&format!("{:0>40}", format!("{n:x}"))).unwrap()
    }

    #[test]
    fn empty_chain_has_no_head_or_activated_rev() {
        let c = ReceiptChain::new();
        assert!(c.is_empty());
        assert!(c.head().is_none());
        assert!(c.last_activated_rev().is_none());
    }

    #[test]
    fn append_links_and_increments_seq() {
        let mut c = ReceiptChain::new();
        let r0 = c.next_receipt(rev(1), Outcome::Activated { generation: Generation(10) }, 1000);
        assert_eq!(r0.seq, 0);
        assert_eq!(r0.prev_hash, GENESIS_HASH);
        c.append(r0).unwrap();

        let r1 = c.next_receipt(rev(2), Outcome::Activated { generation: Generation(11) }, 2000);
        assert_eq!(r1.seq, 1);
        assert_ne!(r1.prev_hash, GENESIS_HASH);
        c.append(r1).unwrap();

        assert_eq!(c.len(), 2);
        assert_eq!(c.last_activated_rev().unwrap(), &rev(2));
        c.verify().unwrap();
    }

    #[test]
    fn last_activated_skips_failed_and_deferred() {
        let mut c = ReceiptChain::new();
        c.append(c.next_receipt(rev(1), Outcome::Activated { generation: Generation(1) }, 1)).unwrap();
        c.append(c.next_receipt(rev(2), Outcome::Failed { error: "boom".into() }, 2)).unwrap();
        c.append(c.next_receipt(rev(3), Outcome::Deferred { newer: rev(4) }, 3)).unwrap();
        // The last *activated* rev is still rev(1), not the failed/deferred later ones.
        assert_eq!(c.last_activated_rev().unwrap(), &rev(1));
    }

    #[test]
    fn append_rejects_seq_gap() {
        let mut c = ReceiptChain::new();
        let mut bad = c.next_receipt(rev(1), Outcome::Activated { generation: Generation(1) }, 1);
        bad.seq = 5;
        assert!(matches!(c.append(bad).unwrap_err(), ChainError::SeqGap { got: 5, want: 0, .. }));
    }

    #[test]
    fn append_rejects_broken_link() {
        let mut c = ReceiptChain::new();
        c.append(c.next_receipt(rev(1), Outcome::Activated { generation: Generation(1) }, 1)).unwrap();
        let mut bad = c.next_receipt(rev(2), Outcome::Activated { generation: Generation(2) }, 2);
        bad.prev_hash = GENESIS_HASH.to_owned();
        assert!(matches!(c.append(bad).unwrap_err(), ChainError::BrokenLink { index: 1 }));
    }

    #[test]
    fn verify_catches_tampered_middle_receipt() {
        let mut c = ReceiptChain::new();
        c.append(c.next_receipt(rev(1), Outcome::Activated { generation: Generation(1) }, 1)).unwrap();
        c.append(c.next_receipt(rev(2), Outcome::Activated { generation: Generation(2) }, 2)).unwrap();
        c.append(c.next_receipt(rev(3), Outcome::Activated { generation: Generation(3) }, 3)).unwrap();
        c.verify().unwrap();
        // Tamper with the middle receipt's rev — the following receipt's
        // prev_hash no longer matches → BrokenLink.
        let mut tampered = c.clone();
        tampered.entries[1].rev = rev(99);
        assert!(matches!(tampered.verify().unwrap_err(), ChainError::BrokenLink { index: 2 }));
    }

    #[test]
    fn chain_serde_roundtrips_and_reverifies() {
        let mut c = ReceiptChain::new();
        c.append(c.next_receipt(rev(1), Outcome::Activated { generation: Generation(7) }, 111)).unwrap();
        c.append(c.next_receipt(rev(2), Outcome::Deferred { newer: rev(3) }, 222)).unwrap();
        let json = serde_json::to_string(&c).unwrap();
        let back: ReceiptChain = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
        back.verify().unwrap();
    }
}
