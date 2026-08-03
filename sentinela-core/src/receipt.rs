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
    /// What this outcome says about the loop's health — see [`Health`].
    ///
    /// **Deliberately exhaustive: do not add a `_` arm.** The absent wildcard
    /// is the enforcement — a new variant becomes a compile error here until
    /// somebody classifies it, which is what keeps every consumer of
    /// "is this a failure?" in agreement.
    #[must_use]
    pub fn health(&self) -> Health {
        match self {
            Self::Activated { .. } => Health::Converged,
            Self::Deferred { .. } => Health::Benign,
            Self::Failed { .. } => Health::Broken,
        }
    }

    /// A `Failed` outcome whose retained text is bounded to
    /// [`MAX_ERROR_BYTES`], cut on char boundaries with an explicit marker so
    /// a reader knows the text was elided rather than that the build stopped
    /// talking.
    ///
    /// Keeps BOTH ENDS. A build log carries its context at the head (what was
    /// being built) and its diagnosis at the tail (why it stopped) — a
    /// head-only cut therefore discards the only part anyone reads. Measured
    /// on ryn 2026-08-03: a real receipt retained 2048 bytes of
    /// `unpacking … into the Git cache` and ended at `err… [truncated]`,
    /// leaving the failure undiagnosable from its own record.
    ///
    /// TIER: only-mitigated, not unrepresentable — `Failed { error }` stays
    /// publicly constructible (tests build it directly), so this bounds the
    /// production path rather than making an oversized receipt impossible.
    #[must_use]
    pub fn failed(error: impl Into<String>) -> Self {
        let e: String = error.into();
        if e.len() <= MAX_ERROR_BYTES {
            return Self::Failed { error: e };
        }

        // A quarter for context, the rest for the diagnosis. The tail gets the
        // larger share deliberately: the head is usually preamble.
        let head_budget = MAX_ERROR_BYTES / 4;
        let tail_budget = MAX_ERROR_BYTES - head_budget;

        // `floor_char_boundary` / `ceil_char_boundary` are still unstable, so
        // walk to a boundary by hand rather than risk a panic on a multi-byte
        // split.
        let mut head_end = head_budget;
        while head_end > 0 && !e.is_char_boundary(head_end) {
            head_end -= 1;
        }
        let mut tail_start = e.len() - tail_budget;
        while tail_start < e.len() && !e.is_char_boundary(tail_start) {
            tail_start += 1;
        }

        let elided = tail_start.saturating_sub(head_end);
        let mut out = String::with_capacity(MAX_ERROR_BYTES + 48);
        out.push_str(&e[..head_end]);
        out.push_str(&format!("\n… [{elided} bytes elided] …\n"));
        out.push_str(&e[tail_start..]);
        Self::Failed { error: out }
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

    /// What this receipt says about the loop's health.
    #[must_use]
    pub fn health(&self) -> Health {
        self.outcome.health()
    }
}

/// What one receipt says about the loop's health.
///
/// ── ★ THE ONE CLASSIFICATION, EXHAUSTIVE BY CONSTRUCTION ─────────────────
/// [`Outcome::health`] matches every variant with **no wildcard arm**, so a
/// new `Outcome` cannot be added without deciding what it means for health —
/// the compiler refuses. That is the invariant: "is this a failure?" has
/// exactly one answer, in one place, and it cannot drift.
///
/// It exists because it *did* drift. `fsm.rs` defers with the comment
/// "no cooldown — deferral is not a failure", while `consecutive_failures`
/// counted anything that was not an activation — so a deferral was
/// simultaneously not-a-failure (FSM) and a failure (chain). MEASURED on ryn
/// 2026-08-02: a healthy deferral moved the streak 4 → 5 and the startup
/// banner declared DEGRADED while the loop was converging normally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    /// The node moved to this rev. The loop did its job.
    Converged,
    /// Nothing broke and nothing deployed — the loop declined on purpose.
    Benign,
    /// The loop tried to converge and could not.
    Broken,
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

    /// How many [`Health::Broken`] receipts sit at the tail since the last
    /// activation — the current unbroken *failure* streak. `0` when the head
    /// activated cleanly (or the chain is empty).
    ///
    /// This is the number that makes a silent reconciler loud. A daemon
    /// failing every tick looks exactly like a quiet healthy one from the
    /// outside: same empty terminal, same absent alert. MEASURED on ryn
    /// 2026-08-02, this chain read 4136 failed / 1 activated across the
    /// preceding 27.9 days — every tick since seq 0 had failed and nothing
    /// said so. (That streak is a *dated measurement*, not current state; it
    /// was the read-only `./result` symlink bug, fixed by anchoring the
    /// rebuild cwd.) Report it wherever an operator already looks.
    ///
    /// ── ★ A DEFERRAL IS TRANSPARENT, NOT A FAILURE ───────────────────────
    /// [`Health::Benign`] receipts are skipped: they neither extend the
    /// streak nor clear it. Counting them inflated the number on exactly the
    /// repos where it matters most — a busy branch defers often and healthily
    /// — and an alarm that fires while the loop is fine trains the operator
    /// to ignore it, which is the failure this function exists to prevent.
    /// Nor may a deferral *reset* the streak: nothing was fixed, so a real
    /// failure underneath must stay visible. Use [`Self::consecutive_deferrals`]
    /// for the distinct "building slower than the push cadence" condition.
    #[must_use]
    pub fn consecutive_failures(&self) -> usize {
        let mut broken = 0;
        for r in self.entries.iter().rev() {
            match r.health() {
                Health::Converged => break,
                Health::Broken => broken += 1,
                Health::Benign => {}
            }
        }
        broken
    }

    /// How many [`Health::Benign`] receipts sit at the very tail — the
    /// current unbroken *deferral* streak, ended by any activation or
    /// failure. `0` unless the head is a deferral.
    ///
    /// This names a condition that previously had no name and masqueraded as
    /// failure: the build takes longer than the interval between pushes, so
    /// every build finishes against a HEAD that has already moved and defers
    /// forever. Nothing is broken — the loop converges the moment the branch
    /// goes quiet — but it is not converging *now*, and that is worth saying
    /// out loud in different words than "DEGRADED". MEASURED on ryn
    /// 2026-08-02: a 12m02s darwin build against a branch whose median
    /// inter-commit gap that evening was under 7 minutes.
    /// ── ★ EXHAUSTIVE `match`, NOT `==` ───────────────────────────────────
    /// This read `r.health() == Health::Benign`. An equality test is a hole in
    /// the very invariant [`Outcome::health`] exists to hold: adding a
    /// `Health` variant compile-errors at `health()` and at
    /// [`Self::consecutive_failures`] (both wildcard-free `match`es) but
    /// **silently compiles here**, defaulting the new variant to "not a
    /// deferral" with nobody asked. Caught 2026-08-02, in code landed hours
    /// earlier — the exhaustive matches elsewhere made it *look* sealed.
    /// Every consumer of the classification must be a `match` with no `_` arm,
    /// or the seal is only as strong as its weakest reader.
    #[must_use]
    pub fn consecutive_deferrals(&self) -> usize {
        let mut benign = 0;
        for r in self.entries.iter().rev() {
            match r.health() {
                Health::Benign => benign += 1,
                Health::Converged | Health::Broken => break,
            }
        }
        benign
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
        // The fixture must have a DISTINCT head and tail. The previous one
        // was a single line repeated, so head and tail were identical and the
        // test passed under a head-only cut that discarded every real
        // diagnosis — it asserted "the diagnosis survives" while being
        // structurally unable to detect its loss.
        let huge = format!(
            "CONTEXT-HEAD building the system configuration\n{}error: THE-ACTUAL-DIAGNOSIS attribute 'foo' missing\n",
            "unpacking 'github:pleme-io/x' into the Git cache...\n".repeat(5000),
        );
        assert!(huge.len() > MAX_ERROR_BYTES * 10);
        let Outcome::Failed { error } = Outcome::failed(huge) else {
            panic!("must stay a Failed outcome");
        };
        assert!(
            error.len() <= MAX_ERROR_BYTES + 48,
            "got {} bytes",
            error.len()
        );
        // Both ends survive: the head says what was being built...
        assert!(
            error.starts_with("CONTEXT-HEAD"),
            "context was dropped: {}",
            &error[..error.len().min(80)]
        );
        // ...and the tail — the only part anyone actually reads — says why.
        assert!(
            error.contains("THE-ACTUAL-DIAGNOSIS"),
            "the diagnosis was discarded, which is the whole defect this guards"
        );
        assert!(error.contains("bytes elided"), "the cut must be explicit");
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

        // ── ★ CHANGED 2026-08-02: a deferral is TRANSPARENT ──────────────
        // This previously asserted 2 — a deferral extended the streak. That
        // contradicted `fsm.rs`, which defers with "no cooldown — deferral is
        // not a failure", and it made the DEGRADED banner fire on healthy
        // convergence (measured on ryn: streak 4 → 5 across a clean
        // deferral). A deferral neither extends nor clears: the real failure
        // at rev(4) must stay visible underneath it.
        c.append(c.next_receipt(rev(5), Outcome::Deferred { newer: rev(6) }, 5))
            .unwrap();
        assert_eq!(
            c.consecutive_failures(),
            1,
            "a deferral must not extend the failure streak"
        );
        assert_eq!(
            c.consecutive_deferrals(),
            1,
            "but it is a deferral streak of 1"
        );

        // Still transparent when stacked, and still not masking rev(4).
        c.append(c.next_receipt(rev(6), Outcome::Deferred { newer: rev(7) }, 6))
            .unwrap();
        assert_eq!(
            c.consecutive_failures(),
            1,
            "deferrals never accumulate as failures"
        );
        assert_eq!(c.consecutive_deferrals(), 2);

        // A real failure on top still counts, through the deferrals.
        c.append(c.next_receipt(rev(7), Outcome::Failed { error: "d".into() }, 7))
            .unwrap();
        assert_eq!(
            c.consecutive_failures(),
            2,
            "rev(4) and rev(7); rev(5)/rev(6) skipped"
        );
        assert_eq!(
            c.consecutive_deferrals(),
            0,
            "a failure ends the deferral streak"
        );
    }

    #[test]
    fn health_classifies_every_outcome_variant() {
        // `Outcome::health` has NO wildcard arm, so a new variant is a
        // compile error until classified. This pins the three current
        // answers so a silent reclassification is caught too.
        assert_eq!(
            Outcome::Activated {
                generation: Generation(1)
            }
            .health(),
            Health::Converged
        );
        assert_eq!(Outcome::Deferred { newer: rev(2) }.health(), Health::Benign);
        assert_eq!(Outcome::failed("boom").health(), Health::Broken);
    }

    #[test]
    fn a_healthy_deferring_loop_is_never_reported_as_degraded() {
        // The regression this change exists to prevent: a busy branch where
        // every build finishes against a moved HEAD. Nothing is broken, so
        // `consecutive_failures` — the number the DEGRADED banner reads —
        // must stay 0 however long the deferral run gets.
        let mut c = ReceiptChain::new();
        c.append(c.next_receipt(
            rev(1),
            Outcome::Activated {
                generation: Generation(1),
            },
            1,
        ))
        .unwrap();
        for i in 2..12u8 {
            c.append(c.next_receipt(
                rev(i),
                Outcome::Deferred { newer: rev(i + 1) },
                u64::from(i),
            ))
            .unwrap();
        }
        assert_eq!(c.consecutive_failures(), 0, "deferring is not degraded");
        assert_eq!(
            c.consecutive_deferrals(),
            10,
            "but it IS a 10-deep deferral streak"
        );
    }

    #[test]
    fn deferrals_before_any_activation_are_still_not_failures() {
        // A freshly-enrolled node that defers on its first ticks has never
        // deployed, but nothing has broken either — the never-deployed case
        // is carried by `is_empty` / `last_activated_rev`, not by the streak.
        let mut c = ReceiptChain::new();
        c.append(c.next_receipt(rev(1), Outcome::Deferred { newer: rev(2) }, 1))
            .unwrap();
        assert_eq!(c.consecutive_failures(), 0);
        assert_eq!(c.consecutive_deferrals(), 1);
        assert_eq!(c.last_activated_rev(), None);
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
