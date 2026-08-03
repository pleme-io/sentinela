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

/// Ceiling on the error text one failed receipt retains.
///
/// ── ★ WHY A FAILING LOOP MUST NOT WRITE ITS OWN WEIGHT TO DISK ──────────
/// The chain is append-only and never pruned — pruning the front would
/// break the BLAKE3 links that make it tamper-evident, which is the whole
/// point of it. So every byte written is permanent, and an unbounded error
/// string means a *failing* loop grows the chain fastest.
///
/// MEASURED on ryn 2026-08-02: 4136 consecutive failures, each embedding a
/// full multi-line nix error, produced a **31 MB** receipts.json (~7.5 KB
/// per receipt). `sentinela status` parses all of it on every call, and
/// that call is now on the `fleet rebuild` path — so the outage was also
/// quietly taxing every rebuild.
///
/// A nix failure puts its signal in the first lines; the tail is store
/// paths and dependency chatter already reproducible from the rev. 2 KiB
/// keeps the diagnosis and drops the bulk.
pub const MAX_ERROR_BYTES: usize = 2048;

/// The result of a deploy attempt, as recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Outcome {
    /// Activated cleanly to this generation.
    Activated { generation: Generation },
    /// The build or activation failed (message retained, bounded — build
    /// via [`Outcome::failed`] rather than constructing this directly).
    Failed { error: String },
    /// A newer HEAD landed mid-build; this rev was deferred, not activated.
    Deferred { newer: Rev },
}

impl Outcome {
    /// A `Failed` outcome whose retained text is bounded to
    /// [`MAX_ERROR_BYTES`], truncated on a char boundary with an explicit
    /// marker so a reader knows the text was cut rather than that the build
    /// stopped talking.
    ///
    /// TIER: only-mitigated, not unrepresentable — `Failed { error }` stays
    /// publicly constructible (tests build it directly), so this bounds the
    /// production path rather than making an oversized receipt impossible.
    #[must_use]
    pub fn failed(error: impl Into<String>) -> Self {
        let mut e: String = error.into();
        if e.len() > MAX_ERROR_BYTES {
            // Walk back to a char boundary; `floor_char_boundary` is still
            // unstable, so do it by hand rather than risk a panic on a
            // multi-byte split.
            let mut cut = MAX_ERROR_BYTES;
            while cut > 0 && !e.is_char_boundary(cut) {
                cut -= 1;
            }
            e.truncate(cut);
            e.push_str("\n… [truncated]");
        }
        Self::Failed { error: e }
    }
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

    /// How many receipts at the tail of the chain are *not* activations —
    /// the current unbroken failure streak. `0` when the head activated
    /// cleanly (or the chain is empty).
    ///
    /// This is the number that makes a silent reconciler loud. A daemon
    /// failing every tick looks exactly like a quiet healthy one from the
    /// outside: same empty terminal, same absent alert. MEASURED on ryn
    /// 2026-08-02, this chain read 4136 failed / 1 activated across 27.9
    /// days — every tick since seq 0 had failed and nothing said so.
    /// Report it wherever an operator already looks.
    #[must_use]
    pub fn consecutive_failures(&self) -> usize {
        self.entries
            .iter()
            .rev()
            .take_while(|r| !r.is_activated())
            .count()
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
        DeployReceipt {
            seq,
            rev,
            outcome,
            at_unix_ms,
            prev_hash,
        }
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
            return Err(ChainError::SeqGap {
                index,
                got: receipt.seq,
                want: want_seq,
            });
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
                return Err(ChainError::SeqGap {
                    index,
                    got: r.seq,
                    want: want_seq,
                });
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
        let r0 = c.next_receipt(
            rev(1),
            Outcome::Activated {
                generation: Generation(10),
            },
            1000,
        );
        assert_eq!(r0.seq, 0);
        assert_eq!(r0.prev_hash, GENESIS_HASH);
        c.append(r0).unwrap();

        let r1 = c.next_receipt(
            rev(2),
            Outcome::Activated {
                generation: Generation(11),
            },
            2000,
        );
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
        c.append(c.next_receipt(
            rev(1),
            Outcome::Activated {
                generation: Generation(1),
            },
            1,
        ))
        .unwrap();
        c.append(c.next_receipt(
            rev(2),
            Outcome::Failed {
                error: "boom".into(),
            },
            2,
        ))
        .unwrap();
        c.append(c.next_receipt(rev(3), Outcome::Deferred { newer: rev(4) }, 3))
            .unwrap();
        // The last *activated* rev is still rev(1), not the failed/deferred later ones.
        assert_eq!(c.last_activated_rev().unwrap(), &rev(1));
    }

    #[test]
    fn failed_bounds_the_retained_error_text() {
        // The real shape: 4136 of these, each holding a full nix error,
        // made a 31 MB append-only chain that can never be pruned.
        let huge = "error: builder failed\n".repeat(5000);
        assert!(huge.len() > MAX_ERROR_BYTES * 10);
        let Outcome::Failed { error } = Outcome::failed(huge) else {
            panic!("must stay a Failed outcome");
        };
        assert!(
            error.len() <= MAX_ERROR_BYTES + 32,
            "got {} bytes",
            error.len()
        );
        // The diagnosis survives; only the bulk is dropped.
        assert!(error.starts_with("error: builder failed"));
        assert!(error.ends_with("… [truncated]"), "cut must be explicit");
    }

    #[test]
    fn failed_leaves_short_errors_untouched_and_never_splits_a_char() {
        let short = Outcome::failed("boom");
        assert_eq!(
            short,
            Outcome::Failed {
                error: "boom".to_owned()
            }
        );

        // A multi-byte char straddling the cut must not panic or produce
        // invalid UTF-8 — the reason the boundary walk is hand-rolled.
        let multi = "é".repeat(MAX_ERROR_BYTES);
        let Outcome::Failed { error } = Outcome::failed(multi) else {
            panic!("must stay a Failed outcome");
        };
        assert!(error.len() <= MAX_ERROR_BYTES + 32);
        assert!(std::str::from_utf8(error.as_bytes()).is_ok());
    }

    #[test]
    fn consecutive_failures_counts_the_tail_streak_only() {
        let mut c = ReceiptChain::new();
        assert_eq!(c.consecutive_failures(), 0, "empty chain has no streak");

        c.append(c.next_receipt(rev(1), Outcome::Failed { error: "a".into() }, 1))
            .unwrap();
        c.append(c.next_receipt(rev(2), Outcome::Failed { error: "b".into() }, 2))
            .unwrap();
        assert_eq!(c.consecutive_failures(), 2);

        // An activation resets the streak — this is the whole point: the
        // number must fall to 0 the moment the loop recovers, or a stale
        // alarm trains the operator to ignore it.
        c.append(c.next_receipt(
            rev(3),
            Outcome::Activated {
                generation: Generation(3),
            },
            3,
        ))
        .unwrap();
        assert_eq!(c.consecutive_failures(), 0);

        // Only the TAIL streak counts, not the two failures before rev(3).
        c.append(c.next_receipt(rev(4), Outcome::Failed { error: "c".into() }, 4))
            .unwrap();
        assert_eq!(c.consecutive_failures(), 1);

        // Deferred is not an activation, so it extends the streak rather
        // than clearing it — a deferral means nothing was deployed.
        c.append(c.next_receipt(rev(5), Outcome::Deferred { newer: rev(6) }, 5))
            .unwrap();
        assert_eq!(c.consecutive_failures(), 2);
    }

    #[test]
    fn append_rejects_seq_gap() {
        let mut c = ReceiptChain::new();
        let mut bad = c.next_receipt(
            rev(1),
            Outcome::Activated {
                generation: Generation(1),
            },
            1,
        );
        bad.seq = 5;
        assert!(matches!(
            c.append(bad).unwrap_err(),
            ChainError::SeqGap {
                got: 5,
                want: 0,
                ..
            }
        ));
    }

    #[test]
    fn append_rejects_broken_link() {
        let mut c = ReceiptChain::new();
        c.append(c.next_receipt(
            rev(1),
            Outcome::Activated {
                generation: Generation(1),
            },
            1,
        ))
        .unwrap();
        let mut bad = c.next_receipt(
            rev(2),
            Outcome::Activated {
                generation: Generation(2),
            },
            2,
        );
        bad.prev_hash = GENESIS_HASH.to_owned();
        assert!(matches!(
            c.append(bad).unwrap_err(),
            ChainError::BrokenLink { index: 1 }
        ));
    }

    #[test]
    fn verify_catches_tampered_middle_receipt() {
        let mut c = ReceiptChain::new();
        c.append(c.next_receipt(
            rev(1),
            Outcome::Activated {
                generation: Generation(1),
            },
            1,
        ))
        .unwrap();
        c.append(c.next_receipt(
            rev(2),
            Outcome::Activated {
                generation: Generation(2),
            },
            2,
        ))
        .unwrap();
        c.append(c.next_receipt(
            rev(3),
            Outcome::Activated {
                generation: Generation(3),
            },
            3,
        ))
        .unwrap();
        c.verify().unwrap();
        // Tamper with the middle receipt's rev — the following receipt's
        // prev_hash no longer matches → BrokenLink.
        let mut tampered = c.clone();
        tampered.entries[1].rev = rev(99);
        assert!(matches!(
            tampered.verify().unwrap_err(),
            ChainError::BrokenLink { index: 2 }
        ));
    }

    #[test]
    fn chain_serde_roundtrips_and_reverifies() {
        let mut c = ReceiptChain::new();
        c.append(c.next_receipt(
            rev(1),
            Outcome::Activated {
                generation: Generation(7),
            },
            111,
        ))
        .unwrap();
        c.append(c.next_receipt(rev(2), Outcome::Deferred { newer: rev(3) }, 222))
            .unwrap();
        let json = serde_json::to_string(&c).unwrap();
        let back: ReceiptChain = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
        back.verify().unwrap();
    }
}
