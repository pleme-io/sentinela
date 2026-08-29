//! sentinela's kanshou surface — the reconciler, made askable.
//!
//! ── ★ WHY THE RECONCILER WAS THE WORST DAEMON TO LEAVE UNASKABLE ───────
//!
//! Measured across the five pleme-io daemons 2026-08-28, `sentinela` was the
//! only one with no `kanshou` dependency. Of all of them it is the one whose
//! entire job is **converging state you cannot see** — so the only way to ask
//! "is this node actually deploying?" was to read `journalctl` and interpret
//! prose.
//!
//! That is not hypothetical. A monitor built on this loop's log text read a
//! `DEGRADED` line emitted **twenty minutes before** the build it was
//! watching, and reported a verdict it had never observed. The log was
//! correct; the reader had no way to know how old it was, because a log line
//! carries its timestamp beside the text rather than inside the answer.
//!
//! ── ★ THEREFORE: EVERY ANSWER CARRIES ITS OWN AGE ──────────────────────
//!
//! `chain.head` reports `age_ms` alongside the receipt, and every response
//! carries `answered_at_unix_ms`. A caller cannot accidentally treat a stale
//! fact as current, because the staleness is *in the value* rather than
//! inferable from where it was found. This is [`SHATEI`] applied to time: the
//! fact "this verdict is from 20 minutes ago" must hold at every site that
//! reads the verdict, so it travels with it.
//!
//! ── ★ ONE DERIVATION, TWO CONSUMERS ────────────────────────────────────
//!
//! [`Health`] and [`health_of`] moved here from `main.rs` rather than being
//! copied. The logger and the query surface are now two renderings of ONE
//! verdict — if they were derived separately, the log could say `DEGRADED`
//! while the socket said `converged`, and the operator would have no way to
//! tell which was lying. That is precisely the class this whole crate exists
//! to close, so reproducing it inside the fix would be absurd.
//!
//! ── ★ QUERIES READ THE PERSISTED CHAIN, NOT AN IN-MEMORY COPY ──────────
//!
//! Every query calls [`ChainView::load_chain`] fresh. Holding a cached chain
//! would create a second source of truth that drifts from the file the next
//! tick appends to — and "the daemon says X, the receipt file says Y" is the
//! failure mode of every status surface that caches.
//!
//! [`SHATEI`]: https://github.com/pleme-io/theory/blob/main/SHATEI.md

use std::sync::Arc;

use kanshou::{Introspect, Query, QueryError, QueryResult};
use sentinela_core::{EnvError, GitopsEnv, ReceiptChain};

/// The slice of the environment introspection actually needs.
///
/// ★ TWO METHODS, NOT NINETEEN. `GitopsEnv` carries the whole reconciler
/// surface — ls-remote, build, switch, persist, heartbeat. Introspection reads
/// the chain and the clock, and narrowing to that is what makes this testable:
/// `MockEnv` is built on `RefCell` and is therefore not `Send + Sync`, which
/// kanshou requires, so a full-surface fake could not be used here even if
/// writing one were pleasant.
pub trait ChainView: Send + Sync {
    /// Load the persisted receipt chain.
    ///
    /// # Errors
    /// Propagates whatever the underlying store reports.
    fn load_chain(&self) -> Result<ReceiptChain, EnvError>;

    /// The current wall clock in unix millis.
    fn now_unix_ms(&self) -> u64;
}

impl<E: GitopsEnv + Send + Sync> ChainView for E {
    fn load_chain(&self) -> Result<ReceiptChain, EnvError> {
        GitopsEnv::load_chain(self)
    }
    fn now_unix_ms(&self) -> u64 {
        GitopsEnv::now_unix_ms(self)
    }
}

/// What the receipt chain says about this loop, as a VALUE.
///
/// ★ NOT `sentinela_core::Health`, which grades a SINGLE receipt
/// (Converged/Benign/Broken). This grades the LOOP across the whole chain,
/// where "three failures in a row" and "starved by a fast-moving branch" are
/// different conditions that one receipt cannot express. Deliberately not
/// merged: they answer different questions at different scopes.
///
/// ── ★ THREE STATES OF "NOT CONVERGED", NOT ONE ──
/// A loop whose builds FAIL needs a human; a loop that keeps DEFERRING
/// because the branch moves faster than it can build needs nothing — it
/// converges the moment pushing stops. Reporting both as DEGRADED is what
/// trains an operator to ignore the word. Broken outranks starved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    /// Chain readable, nothing deployed yet.
    ///
    /// ★ An empty chain has a ZERO failure streak, so a naive `streak == 0`
    /// reports a loop that has NEVER deployed as converged. Absence of
    /// failure is not evidence of convergence; only an activation is. Seen
    /// for real on cid 2026-08-02, freshly migrated onto this engine.
    NeverDeployed,
    Degraded { streak: usize, last_ok: String },
    Starved { deferrals: usize, last_ok: String },
    Converged { last_ok: String },
    /// An unreadable chain is worth saying out loud: the audit trail — the
    /// only durable record of whether we converge — cannot be consulted.
    Unreadable { error: String },
}

impl Health {
    /// The stable machine-facing tag. Kept separate from the log prose so a
    /// reworded log line cannot silently change a consumer's parse.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::NeverDeployed => "never-deployed",
            Self::Degraded { .. } => "degraded",
            Self::Starved { .. } => "starved",
            Self::Converged { .. } => "converged",
            Self::Unreadable { .. } => "unreadable",
        }
    }
}

/// Derive the loop's health from the persisted chain. The ONE derivation.
pub fn health_of(env: &dyn ChainView) -> Health {
    let chain = match env.load_chain() {
        Ok(c) => c,
        Err(e) => {
            return Health::Unreadable {
                error: e.to_string(),
            };
        }
    };
    if chain.is_empty() {
        return Health::NeverDeployed;
    }
    let last_ok = chain
        .last_activated_rev()
        .map_or_else(|| "never".to_owned(), |r| r.short().to_owned());
    let streak = chain.consecutive_failures();
    if streak > 0 {
        return Health::Degraded { streak, last_ok };
    }
    let deferrals = chain.consecutive_deferrals();
    if deferrals > 0 {
        return Health::Starved { deferrals, last_ok };
    }
    Health::Converged { last_ok }
}

/// The kanshou consumer.
pub struct SentinelaIntrospect<E: ChainView> {
    env: Arc<E>,
}

impl<E: ChainView> SentinelaIntrospect<E> {
    #[must_use]
    pub fn new(env: Arc<E>) -> Arc<Self> {
        Arc::new(Self { env })
    }

    fn health_json(&self) -> serde_json::Value {
        let h = health_of(&*self.env);
        let mut v = serde_json::json!({ "state": h.tag() });
        let obj = v.as_object_mut().expect("json object");
        match &h {
            Health::Degraded { streak, last_ok } => {
                obj.insert("consecutive_failures".into(), (*streak).into());
                obj.insert("last_activated".into(), last_ok.clone().into());
            }
            Health::Starved { deferrals, last_ok } => {
                obj.insert("consecutive_deferrals".into(), (*deferrals).into());
                obj.insert("last_activated".into(), last_ok.clone().into());
            }
            Health::Converged { last_ok } => {
                obj.insert("last_activated".into(), last_ok.clone().into());
            }
            Health::Unreadable { error } => {
                obj.insert("error".into(), error.clone().into());
            }
            Health::NeverDeployed => {}
        }
        obj.insert(
            "answered_at_unix_ms".into(),
            self.env.now_unix_ms().into(),
        );
        v
    }

    /// The head receipt, WITH ITS AGE. The leaf this whole module exists for.
    fn head_json(&self) -> serde_json::Value {
        let now = self.env.now_unix_ms();
        let chain = match self.env.load_chain() {
            Ok(c) => c,
            Err(e) => {
                return serde_json::json!({
                    "status": "unreadable",
                    "error": e.to_string(),
                    "answered_at_unix_ms": now,
                });
            }
        };
        match chain.head() {
            // ★ An empty chain is a FINDING, not an error (kotae: `empty` and
            // `refused` must not render as the same bytes). A node that has
            // never deployed is a real, reportable state — answering with a
            // QueryError would make it indistinguishable from asking for a
            // leaf that does not exist.
            None => serde_json::json!({
                "status": "empty",
                "answered_at_unix_ms": now,
            }),
            Some(r) => serde_json::json!({
                "status": "found",
                "seq": r.seq,
                "rev": r.rev.short(),
                "outcome": r.outcome,
                "activated": r.is_activated(),
                "at_unix_ms": r.at_unix_ms,
                // ★ THE ANTI-STALE FIELD. saturating_sub because a receipt
                // written by a node whose clock later stepped backwards must
                // report age 0, not a wrapped u64 that reads as 500 million
                // years and would look like corruption rather than skew.
                "age_ms": now.saturating_sub(r.at_unix_ms),
                "answered_at_unix_ms": now,
            }),
        }
    }
}

impl<E: ChainView + 'static> Introspect for SentinelaIntrospect<E> {
    fn query(&self, q: &Query) -> QueryResult {
        let path: Vec<&str> = q.path.iter().map(String::as_str).collect();
        let now = self.env.now_unix_ms();
        match path.as_slice() {
            ["health"] => Ok(self.health_json()),
            ["chain", "head"] => Ok(self.head_json()),
            ["chain", "len"] => Ok(serde_json::json!({
                "len": self.env.load_chain().map(|c| c.len()).unwrap_or(0),
                "readable": self.env.load_chain().is_ok(),
                "answered_at_unix_ms": now,
            })),
            ["chain", "verify"] => Ok(match self.env.load_chain() {
                Ok(c) => match c.verify() {
                    Ok(()) => serde_json::json!({
                        "ok": true, "answered_at_unix_ms": now }),
                    Err(e) => serde_json::json!({
                        "ok": false, "error": e.to_string(), "answered_at_unix_ms": now }),
                },
                Err(e) => serde_json::json!({
                    "ok": false, "error": e.to_string(), "answered_at_unix_ms": now }),
            }),
            _ => Err(QueryError::UnknownField {
                field: q.path.join("."),
            }),
        }
    }

    fn schema(&self) -> &'static [&'static str] {
        &["health", "chain.head", "chain.len", "chain.verify"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinela_core::{Generation, Outcome, Rev};
    use std::sync::Mutex;

    /// A Send+Sync fake — see [`ChainView`] for why `MockEnv` cannot be used.
    struct Fake {
        chain: Mutex<Result<ReceiptChain, String>>,
        now: Mutex<u64>,
    }
    impl Fake {
        fn with(chain: ReceiptChain, now: u64) -> Arc<Self> {
            Arc::new(Self {
                chain: Mutex::new(Ok(chain)),
                now: Mutex::new(now),
            })
        }
        fn unreadable() -> Arc<Self> {
            Arc::new(Self {
                chain: Mutex::new(Err("permission denied".into())),
                now: Mutex::new(1_000),
            })
        }
    }
    impl ChainView for Fake {
        fn load_chain(&self) -> Result<ReceiptChain, EnvError> {
            self.chain
                .lock()
                .expect("lock")
                .clone()
                .map_err(EnvError::ReceiptIo)
        }
        fn now_unix_ms(&self) -> u64 {
            *self.now.lock().expect("lock")
        }
    }

    fn rev(s: &str) -> Rev {
        Rev::parse(s).expect("rev")
    }
    const R1: &str = "1111111111111111111111111111111111111111";

    fn activated_chain(at: u64) -> ReceiptChain {
        let mut c = ReceiptChain::new();
        let r = c.next_receipt(
            rev(R1),
            Outcome::Activated {
                generation: Generation(7),
            },
            at,
        );
        c.append(r).expect("append");
        c
    }

    #[test]
    fn the_head_answer_carries_its_own_age() {
        // THE point of the module. A caller must not be able to treat a
        // twenty-minute-old verdict as current, which is the failure that
        // motivated it.
        let env = Fake::with(activated_chain(1_000), 1_000 + 20 * 60 * 1_000);
        let i = SentinelaIntrospect::new(env);
        let v = i.query(&Query::field(["chain", "head"])).expect("ok");
        assert_eq!(v["age_ms"], 20 * 60 * 1_000);
        assert_eq!(v["status"], "found");
    }

    #[test]
    fn a_backwards_clock_reports_zero_age_not_a_wrapped_u64() {
        // A wrapped subtraction reads as ~584 million years and looks like
        // corruption rather than clock skew.
        let env = Fake::with(activated_chain(9_000), 1_000);
        let i = SentinelaIntrospect::new(env);
        let v = i.query(&Query::field(["chain", "head"])).expect("ok");
        assert_eq!(v["age_ms"], 0);
    }

    #[test]
    fn an_empty_chain_is_a_finding_not_an_error() {
        // kotae: `empty` and `refused` must not render as the same bytes.
        let env = Fake::with(ReceiptChain::new(), 5_000);
        let i = SentinelaIntrospect::new(env);
        let v = i.query(&Query::field(["chain", "head"])).expect("not an Err");
        assert_eq!(v["status"], "empty");
    }

    #[test]
    fn a_never_deployed_loop_is_not_reported_as_converged() {
        // An empty chain has a zero failure streak; `streak == 0` alone would
        // call a node that never deployed healthy. Seen on cid 2026-08-02.
        let env = Fake::with(ReceiptChain::new(), 5_000);
        let i = SentinelaIntrospect::new(env);
        let v = i.query(&Query::field(["health"])).expect("ok");
        assert_eq!(v["state"], "never-deployed");
    }

    #[test]
    fn an_unreadable_chain_says_so_rather_than_reporting_health() {
        let i = SentinelaIntrospect::new(Fake::unreadable());
        let v = i.query(&Query::field(["health"])).expect("ok");
        assert_eq!(v["state"], "unreadable");
    }

    #[test]
    fn a_converged_loop_reports_its_last_activation() {
        let env = Fake::with(activated_chain(1_000), 2_000);
        let i = SentinelaIntrospect::new(env);
        let v = i.query(&Query::field(["health"])).expect("ok");
        assert_eq!(v["state"], "converged");
        // `Rev::short()` is 7 chars, git's abbreviation length -- measured,
        // not assumed: this assertion said 12 and the test caught it.
        assert_eq!(v["last_activated"], &R1[..7]);
    }

    #[test]
    fn every_answer_carries_when_it_was_answered() {
        let env = Fake::with(activated_chain(1_000), 4_242);
        let i = SentinelaIntrospect::new(env);
        for leaf in [
            vec!["health"],
            vec!["chain", "head"],
            vec!["chain", "len"],
            vec!["chain", "verify"],
        ] {
            let v = i.query(&Query::field(leaf.clone())).expect("ok");
            assert_eq!(v["answered_at_unix_ms"], 4_242, "leaf {leaf:?}");
        }
    }

    #[test]
    fn every_advertised_leaf_answers() {
        // A schema entry nothing answers is a lie to an operator enumerating
        // the surface.
        let env = Fake::with(activated_chain(1_000), 2_000);
        let i = SentinelaIntrospect::new(env);
        for leaf in i.schema() {
            let path: Vec<&str> = leaf.split('.').collect();
            assert!(
                i.query(&Query::field(path)).is_ok(),
                "advertised leaf `{leaf}` does not answer"
            );
        }
    }

    #[test]
    fn an_unknown_leaf_is_refused_by_name() {
        let env = Fake::with(activated_chain(1_000), 2_000);
        let i = SentinelaIntrospect::new(env);
        let e = i
            .query(&Query::field(["chain", "nope"]))
            .expect_err("must refuse");
        assert_eq!(
            e,
            QueryError::UnknownField {
                field: "chain.nope".into()
            }
        );
    }

    #[test]
    fn the_chain_verifies() {
        let env = Fake::with(activated_chain(1_000), 2_000);
        let i = SentinelaIntrospect::new(env);
        let v = i.query(&Query::field(["chain", "verify"])).expect("ok");
        assert_eq!(v["ok"], true);
    }
}
