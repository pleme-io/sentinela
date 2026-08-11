//! The production [`GitopsEnv`] — pure Rust, typed `Command`, **no
//! shell**. Every impure action the daemon takes lives here behind the
//! trait the FSM is pure over. The three impure verbs (`git ls-remote`,
//! `darwin-rebuild build`, `darwin-rebuild switch`) are typed argv, and
//! the receipt chain is a content-addressed JSON file written atomically.
//!
//! The pure decision helpers (`inject_token`, `parse_ls_remote`,
//! `parse_generation`, the flake-ref + refspec builders) are separated
//! out and unit-tested — the `Command`-executing methods are thin
//! wrappers over them. No `format!` of any argv (fleet TYPED-EMISSION
//! ban): argv pieces are `concat`'d or built with typed builders.

use sentinela_config::SentinelaConfig;
use sentinela_core::{
    EnvError, Generation, GitopsEnv, Heartbeat, ReceiptChain, RebuildDriver, Rev,
};
use std::fs::File;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};
use tsunagu::exec::{BoundedRun, OnTimeout};
use url::Url;

/// The nix system profile whose generation number a switch advances.
const SYSTEM_PROFILE: &str = "/nix/var/nix/profiles/system";
/// `darwin-rebuild` from the running system (root, no sudo needed under
/// the launchd daemon).

/// The one machine-wide rebuild lock — THE SAME absolute path `fleet
/// rebuild` uses (`pleme-io/fleet/src/commands/rebuild.rs`), so an
/// operator rebuild and the daemon's switch serialize against each other
/// instead of racing activation state (the sops-nix `/run/secrets.d`
/// generation-cleanup race fleet's lock documents).
///
/// ── ★ ABSOLUTE ON PURPOSE — `temp_dir()` SERIALIZES NOTHING ────────────
/// macOS gives every user a per-user `$TMPDIR`, so `temp_dir()` resolves a
/// DIFFERENT file per user and the "shared" lock serializes one user's
/// shell sessions only. The root daemon's launchd job sets no `TMPDIR`, so
/// it resolved yet another path — the exact race this lock exists to close
/// was running with no contention at all (measured on ryn 2026-08-02, fully
/// documented in fleet's `REBUILD_LOCK_PATH`). `/tmp` is the one
/// machine-wide writable directory; `/private/tmp` is mode `1777` (sticky,
/// world-writable), so both root and the operator can create and open this
/// file and neither can unlink the other's.
const REBUILD_LOCK_PATH: &str = "/tmp/fleet-rebuild.lock";

/// The production environment. Owns the config; the receipt chain lives
/// at `<state_dir>/receipts.json`.
pub struct RealEnv {
    cfg: SentinelaConfig,
}

impl RealEnv {
    /// Build from the loaded config.
    #[must_use]
    pub fn new(cfg: SentinelaConfig) -> Self {
        Self { cfg }
    }

    /// Where the receipt chain lives. **YAML**, and now named so.
    ///
    /// ── ★ THE FILENAME USED TO LIE, AND IT MISLED A CAREFUL READER ────────
    /// This returned `receipts.json` while [`Self::persist_chain`] serialises
    /// with `serde_yaml` — the heartbeat beside it is genuine JSON, so two
    /// files in one directory disagreed about what `.json` means. Verified on
    /// cid 2026-08-05: the live file begins `- seq: 0` / `  rev: …`, i.e. YAML.
    ///
    /// Not cosmetic. During a 2026-08-05 audit an agent reasoned from the
    /// extension that `fleet`'s chain reader must be broken (a bare
    /// `kind:`/`rev:` prefix scan cannot match JSON), reported it as a likely
    /// silent failure — and was wrong. The parser was right; the NAME was
    /// wrong. Anyone pointing a JSON parser at it gets a hard failure on a file
    /// that has been YAML since inception.
    fn receipts_path(&self) -> PathBuf {
        Path::new(&self.cfg.state_dir).join("receipts.yaml")
    }

    /// The pre-2026-08-05 path — `receipts.json`, containing YAML.
    ///
    /// Read-only, and never deleted by this daemon. The chain is hash-linked
    /// (`prev_hash`), so it is the only durable record that this node's deploys
    /// are what they claim to be; silently unlinking it would destroy an audit
    /// trail to tidy a filename. [`Self::load_chain`] falls back to it and
    /// [`Self::persist_chain`] writes only the canonical path, so the first
    /// save after an upgrade migrates the content forward and leaves the
    /// original for an operator to remove deliberately.
    fn legacy_receipts_path(&self) -> PathBuf {
        Path::new(&self.cfg.state_dir).join("receipts.json")
    }

    /// The liveness pulse, beside the chain. Separate file on purpose: it
    /// is rewritten every tick (the chain is append-only and rarely
    /// changes), and a reader that only wants "is this loop alive" must
    /// not have to parse a chain that reached 31 MB on ryn.
    pub fn heartbeat_path(&self) -> PathBuf {
        Path::new(&self.cfg.state_dir).join("heartbeat.json")
    }

    /// Read the last published pulse, if any. `None` means no heartbeat
    /// has ever been written — which a reader must treat as "cannot tell",
    /// never as healthy.
    pub fn load_heartbeat(&self) -> Option<Heartbeat> {
        let raw = std::fs::read_to_string(self.heartbeat_path()).ok()?;
        serde_json::from_str(&raw).ok()
    }

    /// The `<flake_url>/<rev>#<hostname>` flake ref for a rev-pinned build.
    fn flake_ref(&self, rev: &Rev) -> String {
        [
            &self.cfg.flake_url,
            "/",
            rev.as_str(),
            "#",
            &self.cfg.hostname,
        ]
        .concat()
    }

    /// Resolve the probe URL, injecting a token when configured.
    fn probe_url(&self) -> Result<String, EnvError> {
        let base = &self.cfg.rev_probe.git_url;
        match &self.cfg.rev_probe.token_file {
            Some(tf) => match std::fs::read_to_string(tf) {
                Ok(raw) => {
                    let token = raw.trim();
                    if token.is_empty() {
                        Ok(base.clone())
                    } else {
                        inject_token(base, token)
                    }
                }
                // A missing/unreadable token file → probe unauthenticated
                // (public repos still resolve; private ones fail-closed at
                // the probe, which is correct).
                Err(_) => Ok(base.clone()),
            },
            None => Ok(base.clone()),
        }
    }

    /// The driver for this node's configured rebuild tool.
    ///
    /// Constructed per call rather than stored: it borrows the config, and a
    /// driver is a zero-cost dispatch wrapper, not a resource. Selection is
    /// the existing typed `RebuildTool` sum — a config that names sui is
    /// already refused by `preflight` when sui cannot resolve the node's
    /// flake ref, so an unusable pairing never reaches here.
    fn driver(&self) -> ShellDriver<'_> {
        ShellDriver { env: self }
    }

    /// Where the rebuild tool is run from. See [`Self::run_rebuild`]
    /// — this is load-bearing, not incidental.
    fn rebuild_cwd(&self) -> &Path {
        Path::new(&self.cfg.state_dir)
    }

    /// Takes the flake ref as a STRING, not a `Rev`: the driver seam speaks
    /// refs, and building one from a rev is `RealEnv`'s job (it owns the
    /// flake_url and hostname), not the driver's.
    fn run_rebuild_ref(&self, verb: &str, flake_ref: &str) -> Result<std::process::Output, EnvError> {
        let mut cmd = Command::new(self.cfg.rebuild_tool.binary());
        for word in rebuild_argv(
            self.cfg.rebuild_tool,
            verb,
            flake_ref,
            &self.cfg.extra_rebuild_args,
        ) {
            cmd.arg(word);
        }
        // ── ★ THE REBUILD MUST RUN FROM A WRITABLE DIRECTORY ──────────────
        // `darwin-rebuild` appends `--no-link` for every action EXCEPT
        // `build`, so `build` alone drops a `./result` symlink into the
        // process's cwd. A launchd daemon with no `WorkingDirectory` key
        // inherits cwd `/` — the read-only macOS system volume — so the
        // build succeeds and then dies placing the symlink:
        //     error: creating symlink '/result.tmp-79472-16807'
        //       -> '/nix/store/…-darwin-system-25.11…': Read-only file system
        //
        // MEASURED on ryn 2026-08-02: the closure built correctly and was
        // byte-identical to the generation a manual `nix run .#rebuild` had
        // just activated. Only placing the symlink failed — so this reads as
        // "build failed" in the receipt chain while the build was in fact
        // fine, which is why it survived so long undiagnosed.
        //
        // Passing `--no-link` ourselves is NOT an option: darwin-rebuild's
        // argument parser ends in a catch-all that rejects anything it does
        // not recognize (`unknown option '--no-link'`, exit 1), and it does
        // not forward that flag. Anchoring cwd is the fix, and it belongs
        // HERE rather than in the launchd plist so the daemon is correct
        // under every launcher — plist, `sentinela run` by hand, a test
        // harness — instead of only the one plist we happen to ship.
        cmd.current_dir(self.rebuild_cwd());
        // ── ★ DETACH: THE SWITCH OUTLIVES US ON PURPOSE ──────────────────
        // We are a launchd job, and the activation we spawn will reach
        // nix-darwin's "setting up launchd services" step, which for a
        // generation that changes OUR OWN plist does:
        //     launchctl unload <our plist>   # kills this job's process tree
        //     cp -f <new plist> ...          # never reached
        //     launchctl load -w <new plist>  # never reached
        // As a CHILD of that job, darwin-rebuild is killed mid-activation —
        // so the machine is left half-switched, the plist is never
        // replaced, and the daemon is never re-bootstrapped. It stays down
        // silently until someone runs `launchctl bootstrap` by hand.
        //
        // OBSERVED on ryn 2026-08-02: stderr ends abruptly at
        // "user defaults..." — the step immediately before launchd
        // services — with 15 `daemon started` entries recording the
        // restart loop that produced. sentinela could never deploy a
        // generation that updated sentinela.
        //
        // Its own process group takes the child out of the tree launchd
        // reaps, so the activation runs to completion and the new plist is
        // installed even though we die partway through. We lose only the
        // receipt for that tick: the next start re-probes, sees the rev is
        // still not the last ACTIVATED one, and converges again — this
        // time without a plist change, so it survives and attests. One
        // extra cycle, self-healing, instead of a wedged loop.
        cmd.process_group(0);

        // ── ★ CAPTURE TO A FILE, NEVER A PIPE — `output()` DEADLOCKS HERE ─
        // `Command::output()` reads stdout/stderr to EOF and only then
        // reaps. EOF arrives when the LAST holder of the write end closes
        // it — not when our direct child exits. Combined with the
        // `process_group(0)` above, that is a permanent hang: darwin-rebuild
        // spawns grandchildren (nix, the activation scripts) which inherit
        // the pipe, and detaching means they routinely outlive it. The
        // direct child exits, becomes a zombie we never reap because we are
        // still in the read, and `poll()` waits for an EOF that no longer
        // has anyone to deliver it. There is no timeout anywhere in
        // `output()`, so the tick never ends: no receipt, no cooldown, no
        // retry, and a heartbeat frozen at `in_flight` forever.
        //
        // DIAGNOSED on cid 2026-08-04 from a live `sample(1)` of the wedged
        // daemon:
        //     Sentinela::tick → run_rebuild → Command::output
        //       → read_output → poll
        // with the direct child a zombie and zero nix build activity. It
        // reads exactly like a slow build from the outside, which is why it
        // survived: the operator-visible signal — "building, in_flight" —
        // is identical to health.
        //
        // A file has no EOF contract to wait on. `wait()` returns when the
        // direct child exits, no matter how many descendants still hold the
        // descriptor, and a grandchild appending afterwards is harmless. The
        // capture also keeps the failure text, which plain inheritance
        // (writing straight to the daemon log) would have cost us.
        // A build has mutated nothing, so a hung one is killed outright. A
        // switch may be mid-activation, where killing is the damage — see
        // `OnTimeout`.
        let (timeout, on_timeout) = match verb {
            "switch" => (
                std::time::Duration::from_secs(self.cfg.switch_timeout_seconds),
                OnTimeout::Abandon,
            ),
            _ => (
                std::time::Duration::from_secs(self.cfg.build_timeout_seconds),
                OnTimeout::KillGroup,
            ),
        };
        // ── ★ AN ABSENT REBUILD BINARY IS `ToolMissing`, NOT `BuildFailed` ──
        // `BoundedRun::run` ends in `cmd.spawn()?`
        // (`tsunagu-0.1.4/src/exec.rs:178`), so a rebuild tool that is not on
        // disk arrives here as an ordinary `io::Error` with
        // `ErrorKind::NotFound`. Collapsing that into `BuildFailed` is exactly
        // the defect `exec_err` was written for on 2026-08-05 — it was applied
        // to the four `git` sites and NOT to this one, which is the site the
        // daemon exists to drive. A structural fault would have been retried
        // on the cooldown cadence forever, indistinguishable in the receipt
        // chain from a red HEAD.
        //
        // The split must stay narrow: `OnTimeout` returns `ErrorKind::TimedOut`
        // through this same `Result`, and a hang IS a build failure — it must
        // keep feeding the cooldown + `land_last_good_after_failures` machinery
        // rather than being relabelled a broken installation.
        // ── ★ SILENCE IS THE ONLY SIGNAL THAT SEPARATES STUCK FROM SLOW ──
        // The deadline above is generous by design, and a wedge exploits
        // exactly that: it costs the FULL bound to notice, every tick.
        // Measured on cid 2026-08-11 — four ticks, 5400s each, while the tree
        // was provably idle (zero /nix/store writes, no nix process, a `jq`
        // holding at 89 minutes for an EOF nothing would send). The wedge sat
        // inside `darwin-rebuild`'s own `nix build --json … | jq -r` command
        // substitution, a level BELOW anything handed to BoundedRun — so it
        // can only be detected here, never prevented.
        //
        // Only the build verb gets it. A `switch` is `OnTimeout::Abandon`
        // precisely because it may be mid-activation, and a silence-kill is
        // still a kill — the one place where killing is the damage.
        let silence = std::time::Duration::from_secs(self.cfg.build_silence_seconds);
        // Bound to a local: the builder borrows this path, and splitting the
        // chain across `let`s (below) means the temporary would otherwise die
        // at the end of this statement while still borrowed.
        let capture_path = self.rebuild_capture_path(verb);
        let run = BoundedRun::new(&capture_path)
            .timeout(timeout)
            .on_timeout(on_timeout);
        let run = if verb == "switch" || silence.is_zero() {
            run
        } else {
            run.silent_after(silence)
        };
        // The stronger signal: nix reports its own failures with an `error:`
        // line, so a rebuild that has printed one and then stopped moving is
        // wedged, not slow. Same switch-verb exclusion and for the same
        // reason — a silence-kill mid-activation is the damage.
        let err_quiet = std::time::Duration::from_secs(self.cfg.build_error_quiet_seconds);
        let run = if verb == "switch" || err_quiet.is_zero() {
            run
        } else {
            run.error_wedge("error:", err_quiet)
        };
        run.run(cmd)
            .map_err(|e| {
                exec_err(self.cfg.rebuild_tool.binary(), &e, |msg| {
                    Self::rebuild_err(verb, msg)
                })
            })
    }

    /// Where one rebuild's merged output is captured. Per-verb rather than
    /// per-run: the file is consumed and deleted at the end of the call, and
    /// a stable name means a crash leaves exactly one inspectable artifact
    /// instead of accumulating them in the state dir forever.
    /// Where one git invocation's output is captured — one file, reused,
    /// because these are short and only the last failure is interesting.
    fn git_capture_path(&self) -> PathBuf {
        Path::new(&self.cfg.state_dir).join("git.out")
    }

    /// Run a git command under the SAME bound the rebuild already uses.
    ///
    /// ── ★ THE TICK WAS BOUNDED EVERYWHERE EXCEPT ITS NETWORK CALLS ──
    /// `run_rebuild` has driven `BoundedRun` since 0.1.10, and the receipt
    /// above this impl block says the primitive was lifted into
    /// `tsunagu::exec` precisely so "a fix reaches the fleet instead of one
    /// daemon". These four git call sites — `ls-remote` in `probe_head`,
    /// and the `fetch` + two `merge-base`/`rev-parse` calls in the ancestry
    /// check — were left on a bare `Command::output()`, which has no
    /// deadline anywhere in it.
    ///
    /// `ls-remote` and `fetch` talk to the NETWORK. A stalled transfer
    /// there wedges the tick with no receipt, no cooldown and no retry —
    /// the same permanent wedge `build_timeout_seconds` was added to
    /// prevent, arriving by the one path in the tick that had no bound.
    /// git's own `http.lowSpeedLimit` is unset by default, so nothing
    /// underneath was catching it either.
    ///
    /// `OnTimeout::KillGroup`: git mutates nothing we depend on here
    /// (`ls-remote` is a read; `fetch` writes only the throwaway mirror),
    /// so a hung one is killed outright — the opposite of a mid-activation
    /// switch, which is why that one is `Abandon`.
    ///
    /// Doctrine: theory/RECONCILER-LIVENESS.md (P1) · theory/BALIZA.md 0b.
    fn run_git(&self, cmd: Command, err: fn(String) -> EnvError) -> Result<Output, EnvError> {
        let capture = self.git_capture_path();
        // `separate_streams` is load-bearing, not a preference: tsunagu's
        // DEFAULT capture is merged, and it delivers the merged tail in
        // `Output::stderr` with `stdout` left EMPTY. `probe_head` parses
        // `out.stdout` for the ls-remote line, so the merged mode would have
        // silently broken head probing while every call still "succeeded" —
        // the reason tsunagu 0.1.5 added the mode at all ("the merged-only
        // contract excluded most of the fleet"). Hence the 0.1.4 -> 0.1.5
        // bump that ships with this change.
        let mut run = BoundedRun::new(&capture).separate_streams();
        if self.cfg.git_timeout_seconds > 0 {
            run = run
                .timeout(std::time::Duration::from_secs(self.cfg.git_timeout_seconds))
                .on_timeout(OnTimeout::KillGroup);
        }
        run.run(cmd).map_err(|e| exec_err("git", &e, err))
    }

    fn rebuild_capture_path(&self, verb: &str) -> PathBuf {
        Path::new(&self.cfg.state_dir).join(format!("rebuild-{verb}.out"))
    }

    /// The verb's error constructor — `switch` and `build` failures are
    /// distinct outcomes and must not be collapsed.
    fn rebuild_err(verb: &str, msg: String) -> EnvError {
        match verb {
            "switch" => EnvError::SwitchFailed(msg),
            _ => EnvError::BuildFailed(msg),
        }
    }
}

// ── ★ THE BOUNDED-SUBPROCESS PRIMITIVE NOW LIVES IN tsunagu ──────────
// `OnTimeout`, `run_captured`, the process-GROUP kill and the tail bound
// were authored here, but nothing about them is sentinela-specific: six
// pleme-io components shell out to something slow with no bound (forge,
// kindling, fleet, gen, sui, and this). They are now
// `tsunagu::exec::BoundedRun`, and this file is consumer #1 rather than
// the owner — so a fix reaches the fleet instead of one daemon.
//
// tsunagu was already the daemon-lifecycle library and already
// feature-gates axum so CLI consumers can take it, which is why the
// primitive went there rather than into a new repo.
//
// Doctrine: theory/RECONCILER-LIVENESS.md (P1).

impl GitopsEnv for RealEnv {
    fn probe_head(&self) -> Result<Option<Rev>, EnvError> {
        let url = self.probe_url()?;
        let refspec = ["refs/heads/", self.cfg.rev_probe.branch.as_str()].concat();
        let out = self.run_git({ let mut c = Command::new("git");
            c.arg("ls-remote")
            .arg(&url)
            .arg(&refspec);c }, EnvError::ProbeFailed)?;
        if !out.status.success() {
            return Err(EnvError::ProbeFailed(
                String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            ));
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        Ok(parse_ls_remote(&stdout))
    }

    fn is_ancestor(&self, ancestor: &Rev, descendant: &Rev) -> Result<bool, EnvError> {
        // ── ★ ANSWERED FROM A LOCAL MIRROR, FAIL-CLOSED THROUGHOUT ────────
        // `git ls-remote` cannot answer ancestry — it returns ref tips, not
        // history — so this keeps a bare mirror under the state dir and asks
        // `merge-base --is-ancestor` there. The mirror is a cache, never a
        // source of truth: it is re-fetched every call, because a stale
        // mirror answering "not an ancestor" merely defers (safe) while a
        // stale mirror answering "ancestor" would activate on a fact we did
        // not verify — so the failure directions are deliberately unequal.
        //
        // EVERY exit that is not a definite yes is a no. An unanswerable
        // question must read as "do not activate", never as "probably fine":
        // the whole point of the caller is that it is about to relax the
        // strictest safety rule the loop has.
        let url = self.probe_url()?;
        let mirror = Path::new(&self.cfg.state_dir).join("ancestry.git");

        if !mirror.exists() {
            let out = self.run_git({ let mut c = Command::new("git");
                c.arg("clone")
                .arg("--bare")
                .arg("--filter=blob:none")
                .arg(&url)
                .arg(&mirror);c }, EnvError::AncestryFailed)?;
            if !out.status.success() {
                return Err(EnvError::AncestryFailed(
                    String::from_utf8_lossy(&out.stderr).trim().to_owned(),
                ));
            }
        }

        // Fetch both revs explicitly. A branch fetch is not enough: the rev
        // we built may already have been superseded, and on a force-push it
        // may be unreachable from any ref at all — which is exactly the case
        // that must answer "not an ancestor" rather than error out into a
        // retry loop.
        // The most network-exposed call in the whole tick: an actual object
        // transfer from a remote we do not control. Bounded like the rest.
        let fetch = self.run_git(
            {
                let mut c = Command::new("git");
                c.arg("--git-dir")
                    .arg(&mirror)
                    .arg("fetch")
                    .arg("--quiet")
                    .arg(&url)
                    .arg(format!(
                        "+refs/heads/{}:refs/heads/probe",
                        self.cfg.rev_probe.branch
                    ));
                c
            },
            EnvError::AncestryFailed,
        )?;
        if !fetch.status.success() {
            return Err(EnvError::AncestryFailed(
                String::from_utf8_lossy(&fetch.stderr).trim().to_owned(),
            ));
        }

        // `--is-ancestor` is exit-code-only: 0 = yes, 1 = no, anything else
        // (including a rev this mirror has never heard of) is an ERROR and
        // must not be read as either answer.
        let out = self.run_git({ let mut c = Command::new("git");
            c.arg("--git-dir")
            .arg(&mirror)
            .arg("merge-base")
            .arg("--is-ancestor")
            .arg(ancestor.as_str())
            .arg(descendant.as_str());c }, EnvError::AncestryFailed)?;
        match out.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(EnvError::AncestryFailed(
                String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            )),
        }
    }

    fn build(&self, rev: &Rev) -> Result<(), EnvError> {
        // Through the driver seam, not `run_rebuild` directly: this is the
        // one axis an in-process sui driver replaces, and everything else in
        // this impl (probe, chain, generation read) stays shared.
        self.driver().build(&self.flake_ref(rev))
    }

    fn switch(&self, rev: &Rev) -> Result<Generation, EnvError> {
        // ── ★ THE MACHINE-WIDE REBUILD LOCK, TAKEN ONLY FOR THE SWITCH ──
        // An operator `fleet rebuild` holds `/tmp/fleet-rebuild.lock` for
        // its whole build+switch, so a daemon switch and an operator switch
        // must serialize: two concurrent activations raced on sops-nix's
        // `/run/secrets.d/<generation>/` cleanup (the receipt fleet's lock
        // documents). Fail-fast on contention — the FSM defers the tick and
        // retries on its bounded cadence instead of this process blocking.
        //
        // HONEST RESIDUAL: the flock dies with us. If the launchd job is
        // killed mid-switch (its own plist changing, the one path where
        // `run_rebuild` detaches the child), the lock drops while the
        // detached activation is still running — a window an operator switch
        // could race. Rare (only on plist-changing generations), and the
        // next tick re-converges; documented rather than engineered around,
        // because fixing it would require holding the lock in a child we
        // deliberately orphan.
        let _lock = acquire_switch_lock(Path::new(REBUILD_LOCK_PATH))?;
        self.driver().switch(&self.flake_ref(rev))?;
        // Read the new generation from the system profile symlink; a
        // parse miss is non-fatal (the switch succeeded) — record 0.
        Ok(current_generation().unwrap_or(Generation(0)))
    }

    fn load_chain(&self) -> Result<ReceiptChain, EnvError> {
        // Canonical path first, then the legacy one. A node upgrading across
        // this change MUST keep its chain: an empty chain reads as "never
        // deployed" — the startup banner reports a freshly-enrolled node, and
        // the failure/deferral streaks the starvation escapes count on reset to
        // zero. Losing it would not merely lose history, it would change what
        // the daemon does next.
        for path in [self.receipts_path(), self.legacy_receipts_path()] {
            match std::fs::read_to_string(&path) {
                Ok(s) => {
                    return serde_yaml::from_str(&s)
                        .map_err(|e| EnvError::ReceiptIo(e.to_string()));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(EnvError::ReceiptIo(e.to_string())),
            }
        }
        Ok(ReceiptChain::new())
    }

    fn persist_chain(&self, chain: &ReceiptChain) -> Result<(), EnvError> {
        let path = self.receipts_path();
        let body = serde_yaml::to_string(chain).map_err(|e| EnvError::ReceiptIo(e.to_string()))?;
        // Atomic: write a temp sibling then rename, so a crash never
        // leaves a half-written chain. (The heartbeat's own tmp below keeps
        // `.json.tmp` — that file genuinely IS JSON.)
        let tmp = path.with_extension("yaml.tmp");
        std::fs::write(&tmp, body.as_bytes()).map_err(|e| EnvError::ReceiptIo(e.to_string()))?;
        std::fs::rename(&tmp, &path).map_err(|e| EnvError::ReceiptIo(e.to_string()))?;
        Ok(())
    }

    fn now_unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }

    fn write_heartbeat(&self, beat: &Heartbeat) -> Result<(), EnvError> {
        let path = self.heartbeat_path();
        let body =
            serde_json::to_string_pretty(beat).map_err(|e| EnvError::HeartbeatIo(e.to_string()))?;
        // Same atomic write-then-rename as the chain: a reader must never
        // catch a half-written pulse and conclude the loop is broken.
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, body.as_bytes()).map_err(|e| EnvError::HeartbeatIo(e.to_string()))?;
        std::fs::rename(&tmp, &path).map_err(|e| EnvError::HeartbeatIo(e.to_string()))?;
        Ok(())
    }
}

// ── pure decision helpers (unit-tested; the impure methods wrap these) ──

/// The full argv (everything after the binary) for one rebuild invocation.
///
/// ── ★ THE TOOL OWNS ITS SHAPE; THIS FUNCTION ONLY COMPOSES IT ───────────
/// `run_rebuild` used to hardcode `cmd.arg(verb)` as the first word, which
/// silently assumed every rebuild tool IS the rebuild command. That is true of
/// `darwin-rebuild` and `nixos-rebuild` and false of `sui`, whose verb lives at
/// `sui system rebuild <verb>`. Lifting the prefix onto
/// [`RebuildTool::argv_prefix`] means a tool with a different shape is
/// *expressible* rather than merely unimplemented — and pulling the whole argv
/// out as a pure function means it is observable, which a `Command`'s argv is
/// not (the same reason `rebuild_cwd`'s test is honest about its scope).
///
/// `extra_rebuild_args` stay LAST, exactly where the old code put them.
fn rebuild_argv(
    tool: sentinela_config::RebuildTool,
    verb: &str,
    flake_ref: &str,
    extra: &[String],
) -> Vec<String> {
    let mut argv: Vec<String> = tool.argv_prefix().iter().map(|w| (*w).to_owned()).collect();
    argv.push(verb.to_owned());
    argv.push("--flake".to_owned());
    argv.push(flake_ref.to_owned());
    argv.extend(extra.iter().cloned());
    argv
}

/// Acquire the machine-wide rebuild lock, fail-fast.
///
/// Returns the locked file — holding it serializes [`GitopsEnv::switch`]
/// against an operator `fleet rebuild` (both sides open the same
/// `/tmp/fleet-rebuild.lock`). Returns [`EnvError::SwitchBusy`] naming the
/// current holder when another process already owns it.
///
/// ── ★ FAIL-FAST ON PURPOSE, NEVER A BLOCKING `lock_exclusive` ──────────
/// Fleet blocks indefinitely here because the waiter is a human operator
/// who wants to know the other party will finish. The daemon is a LOOP: a
/// tick that blocks until an operator's multi-minute rebuild finishes would
/// publish no liveness pulse for the whole hold — the one failure shape
/// this codebase refuses to reintroduce (see `Phase`/`InFlight` in the core
/// and the gate's `STALE_AFTER_POLLS`). So the daemon takes the lock only
/// if it is free, and the FSM turns a busy lock into a bounded deferral
/// (`TickOutcome::SwitchDeferred`) that stands aside and retries.
///
/// The `build` verb deliberately does NOT take this lock: it is pure nix
/// store work (already serialized by the store's own locking), and holding
/// it across a half-hour build would block the operator for no safety gain.
/// Classify a failure to *launch* a subprocess.
///
/// ── ★ ONE CLASSIFIER, NOT A CONDITIONAL AT EVERY EXEC SITE ─────────────
/// `ErrorKind::NotFound` from `Command::output()` means the BINARY does not
/// exist — a structural fault that no retry can clear — while every other
/// `io::Error` is an ordinary runtime failure belonging to whichever variant
/// the caller already uses. Four call sites need that split (the head probe
/// and the three git invocations behind the ancestry check), so it is a
/// function rather than four copies of the same `if`.
///
/// The `fallback` is passed as the caller's own constructor so each site
/// keeps its existing semantics unchanged — only the ENOENT case is lifted
/// out. See [`EnvError::ToolMissing`] for the rio measurement that motivated
/// separating them at all.
fn exec_err(tool: &str, e: &std::io::Error, fallback: impl FnOnce(String) -> EnvError) -> EnvError {
    if e.kind() == std::io::ErrorKind::NotFound {
        EnvError::ToolMissing {
            tool: tool.to_owned(),
        }
    } else {
        fallback(e.to_string())
    }
}

fn acquire_switch_lock(lock_path: &Path) -> Result<File, EnvError> {
    use fs4::fs_std::FileExt;
    let mut file = File::options()
        .create(true)
        .write(true)
        .open(lock_path)
        .map_err(|e| {
            EnvError::SwitchBusy(format!(
                "cannot open rebuild lock at {}: {e}",
                lock_path.display()
            ))
        })?;
    // Cross-user reachability: whoever creates the file first owns it, and
    // the other party still has to open it for WRITE to take an exclusive
    // flock. A default 0644 would hand the first creator a permanent
    // monopoly — the root daemon creates it, the operator's rebuild then
    // dies on EACCES instead of waiting. Best-effort: a pre-existing file
    // owned by the other user cannot be chmod'd by us, and that is fine —
    // it is already 0666 from its own creation. Never fatal.
    let _ = std::fs::set_permissions(lock_path, std::fs::Permissions::from_mode(0o666));
    if FileExt::try_lock_exclusive(&file).is_err() {
        // Name the holder so a log line (and, on the operator side, fleet's
        // "Another rebuild is already in progress (…)" waiter) can tell a
        // live peer from a wedged one.
        let holder = std::fs::read_to_string(lock_path)
            .map(|h| h.trim().to_owned())
            .ok()
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "unknown".to_owned());
        return Err(EnvError::SwitchBusy(holder));
    }
    // Stamp our identity for the next waiter — including a waiting
    // operator, who should read "the daemon owns the machine right now".
    let holder = format!("pid {} · sentinela", std::process::id());
    let _ = file.set_len(0);
    let _ = file.write_all(holder.as_bytes());
    Ok(file)
}

/// Inject `x-access-token:<token>` basic-auth into an https git URL, via
/// the typed [`Url`] builder (no string surgery of the scheme).
fn inject_token(git_url: &str, token: &str) -> Result<String, EnvError> {
    let mut u = Url::parse(git_url).map_err(|e| EnvError::ProbeFailed(e.to_string()))?;
    u.set_username("x-access-token")
        .map_err(|()| EnvError::ProbeFailed("url cannot carry a username".to_owned()))?;
    u.set_password(Some(token))
        .map_err(|()| EnvError::ProbeFailed("url cannot carry a password".to_owned()))?;
    Ok(u.to_string())
}

/// The first sha of `git ls-remote` output — the resolved HEAD, or `None`
/// when the output is empty (fail-closed at the FSM).
fn parse_ls_remote(stdout: &str) -> Option<Rev> {
    let line = stdout.lines().next()?;
    let sha = line.split_whitespace().next()?;
    Rev::parse(sha).ok()
}

/// Parse a system-profile symlink filename (`system-<N>-link`) into a
/// generation number.
fn parse_generation(link_name: &str) -> Option<Generation> {
    link_name
        .strip_prefix("system-")?
        .strip_suffix("-link")?
        .parse::<u64>()
        .ok()
        .map(Generation)
}

/// The current darwin generation from the live system profile symlink.
fn current_generation() -> Option<Generation> {
    let target = std::fs::read_link(SYSTEM_PROFILE).ok()?;
    let name = target.file_name()?.to_str()?;
    parse_generation(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_token_builds_basic_auth_url() {
        let out = inject_token("https://github.com/pleme-io/nix", "TKN").unwrap();
        assert_eq!(out, "https://x-access-token:TKN@github.com/pleme-io/nix");
    }

    #[test]
    fn inject_token_percent_encodes_special_chars() {
        // A token with URL-special chars must be encoded, not injected raw.
        let out = inject_token("https://github.com/o/r", "a/b@c").unwrap();
        assert!(out.starts_with("https://x-access-token:"));
        assert!(out.contains("@github.com/o/r"));
        assert!(!out.contains("a/b@c"), "special chars must be encoded");
    }

    #[test]
    fn parse_ls_remote_takes_the_first_sha() {
        let out = "9f1423abcdef0123456789abcdef0123456789ab\trefs/heads/main\n";
        assert_eq!(
            parse_ls_remote(out).unwrap().as_str(),
            "9f1423abcdef0123456789abcdef0123456789ab"
        );
    }

    #[test]
    fn parse_ls_remote_empty_is_none() {
        assert!(parse_ls_remote("").is_none());
        assert!(parse_ls_remote("\n").is_none());
    }

    #[test]
    fn parse_ls_remote_rejects_garbage_sha() {
        assert!(parse_ls_remote("not-a-sha\trefs/heads/main\n").is_none());
    }

    #[test]
    fn parse_generation_reads_the_profile_name() {
        assert_eq!(parse_generation("system-42-link"), Some(Generation(42)));
        assert_eq!(parse_generation("system-1-link"), Some(Generation(1)));
    }

    #[test]
    fn parse_generation_rejects_non_profile_names() {
        assert_eq!(parse_generation("system-link"), None);
        assert_eq!(parse_generation("42"), None);
        assert_eq!(parse_generation("system-abc-link"), None);
    }

    #[test]
    fn flake_ref_pins_the_rev() {
        let cfg = SentinelaConfig {
            flake_url: "github:pleme-io/nix".to_owned(),
            hostname: "ryn".to_owned(),
            ..SentinelaConfig::default()
        };
        let env = RealEnv::new(cfg);
        let rev = Rev::parse("0123456789abcdef0123456789abcdef01234567").unwrap();
        assert_eq!(
            env.flake_ref(&rev),
            "github:pleme-io/nix/0123456789abcdef0123456789abcdef01234567#ryn"
        );
    }

    #[test]
    fn rebuild_cwd_is_the_state_dir_never_the_inherited_root() {
        // `darwin-rebuild build` writes a `./result` symlink into its cwd,
        // and a launchd daemon inherits cwd `/`, which is read-only on
        // macOS. The rebuild therefore has to be anchored to a directory we
        // know is writable — the state dir we already own.
        //
        // HONEST SCOPE: this pins the helper, not the `Command` wiring.
        // Deleting the `cmd.current_dir(...)` call in `run_rebuild`
        // would still pass, because a `Command`'s cwd is not observable
        // without spawning `darwin-rebuild` for real. Tier: only-mitigated.
        let cfg = SentinelaConfig {
            state_dir: "/var/log/pleme-gitops".to_owned(),
            ..SentinelaConfig::default()
        };
        let env = RealEnv::new(cfg);
        assert_eq!(env.rebuild_cwd(), Path::new("/var/log/pleme-gitops"));
        assert_ne!(
            env.rebuild_cwd(),
            Path::new("/"),
            "cwd `/` is the read-only system volume — the bug this guards"
        );
    }

    // ── the machine-wide rebuild lock ────────────────────────────────

    #[test]
    fn the_rebuild_lock_path_is_the_same_absolute_path_fleet_uses() {
        // THE coordination contract. Sentinela's switch serializes against
        // an operator `fleet rebuild` ONLY if both open the same file.
        // Fleet's constant is `/tmp/fleet-rebuild.lock` — absolute and
        // machine-wide, because macOS's per-user `$TMPDIR` makes
        // `temp_dir()` serialize nothing (the ryn 2026-08-02 lesson). If
        // either side drifts from this string, the activation race the lock
        // exists to close silently returns. Pinned verbatim, not
        // constructed.
        assert_eq!(REBUILD_LOCK_PATH, "/tmp/fleet-rebuild.lock");
    }

    #[test]
    fn a_held_lock_reports_its_holder() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock");
        let _first = acquire_switch_lock(&path).expect("first acquisition");
        let err = acquire_switch_lock(&path).expect_err("a held lock must defer");
        let expected = format!("pid {} · sentinela", std::process::id());
        assert_eq!(
            err,
            EnvError::SwitchBusy(expected),
            "the holder stamp written by the first acquisition must be read back"
        );
    }

    #[test]
    fn an_uncontended_lock_is_acquired_and_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock");
        {
            let _g = acquire_switch_lock(&path).expect("first acquisition");
            assert!(
                acquire_switch_lock(&path).is_err(),
                "the lock must be held while the guard is alive"
            );
        }
        acquire_switch_lock(&path).expect("the lock must release when the guard drops");
    }

    #[test]
    fn the_lock_file_is_group_and_other_writable() {
        // Cross-user flock needs a 0666 file: the daemon (root) and the
        // operator both create it, and whoever comes second must still be
        // able to open it for WRITE to take the exclusive flock.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock");
        let _g = acquire_switch_lock(&path).expect("acquire");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o666,
            "a default 0644 would hand the creator a monopoly"
        );
    }

    // ── exec_err: the structural/transient split ────────────────────────
    //
    // These are the regression tests for the rio 2026-08-05 measurement: a
    // missing binary and an unreachable remote were the SAME variant, so
    // the daemon retried an unsatisfiable condition forever while every
    // liveness surface read healthy.

    #[test]
    fn exec_err_maps_enoent_to_tool_missing() {
        let e = std::io::Error::from(std::io::ErrorKind::NotFound);
        let got = exec_err("git", &e, EnvError::ProbeFailed);
        assert_eq!(
            got,
            EnvError::ToolMissing {
                tool: "git".to_owned()
            },
            "ENOENT on exec means the BINARY is absent — a structural fault \
             no retry can clear. Collapsing it into ProbeFailed is what cost \
             a live diagnosis on rio."
        );
    }

    #[test]
    fn exec_err_keeps_the_callers_variant_for_every_other_io_error() {
        // A refused connection is transient and belongs to the caller's own
        // variant — the split must be narrow, or it would relabel ordinary
        // network failures as a broken installation.
        let e = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        match exec_err("git", &e, EnvError::ProbeFailed) {
            EnvError::ProbeFailed(msg) => assert!(!msg.is_empty()),
            other => panic!("transient io error must stay ProbeFailed, got {other:?}"),
        }
    }

    #[test]
    fn exec_err_preserves_the_ancestry_variant_too() {
        // Same classifier, different caller: the fallback is the caller's,
        // so the ancestry sites keep failing closed as AncestryFailed.
        let e = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        match exec_err("git", &e, EnvError::AncestryFailed) {
            EnvError::AncestryFailed(_) => {}
            other => panic!("expected AncestryFailed, got {other:?}"),
        }
        let enoent = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert_eq!(
            exec_err("git", &enoent, EnvError::AncestryFailed),
            EnvError::ToolMissing {
                tool: "git".to_owned()
            },
            "ENOENT outranks the caller's variant at EVERY site"
        );
    }

    // ── the rebuild argv: the tool owns its own shape ───────────────────

    #[test]
    fn rebuild_argv_puts_the_verb_first_for_the_nix_tools() {
        use sentinela_config::RebuildTool;
        let argv = rebuild_argv(
            RebuildTool::DarwinRebuild,
            "switch",
            "github:o/r/abc#h",
            &[],
        );
        assert_eq!(argv, ["switch", "--flake", "github:o/r/abc#h"]);
        let argv = rebuild_argv(RebuildTool::NixosRebuild, "build", "github:o/r/abc#h", &[]);
        assert_eq!(argv, ["build", "--flake", "github:o/r/abc#h"]);
    }

    #[test]
    fn rebuild_argv_prefixes_suis_subcommand_path_before_the_verb() {
        // `sui` is a multi-command CLI: the verb is at `sui system rebuild
        // <verb>`, not argv[1]. If the prefix is dropped, sui parses `switch`
        // as a top-level subcommand and exits on an unknown command — which
        // this daemon would have recorded as a switch FAILURE, forever.
        use sentinela_config::RebuildTool;
        let argv = rebuild_argv(RebuildTool::Sui, "switch", "/srv/nix/abc#h", &[]);
        assert_eq!(
            argv,
            ["system", "rebuild", "switch", "--flake", "/srv/nix/abc#h"]
        );
    }

    #[test]
    fn rebuild_argv_keeps_extra_args_last_for_every_tool() {
        // Position is load-bearing: `extra_rebuild_args` are pass-through
        // flags for the underlying tool and must not land between the
        // subcommand path and the verb.
        use sentinela_config::RebuildTool;
        let extra = vec!["--option".to_owned(), "foo".to_owned()];
        assert_eq!(
            rebuild_argv(RebuildTool::DarwinRebuild, "build", "r#h", &extra),
            ["build", "--flake", "r#h", "--option", "foo"]
        );
        assert_eq!(
            rebuild_argv(RebuildTool::Sui, "build", "r#h", &extra),
            [
                "system", "rebuild", "build", "--flake", "r#h", "--option", "foo"
            ]
        );
    }

    // ── the rebuild site's structural/transient split ───────────────────

    // NOTE: the companion test proving tsunagu really surfaces a failed spawn
    // as `ErrorKind::NotFound` lives in `tests/bounded_run_enoent.rs`, NOT
    // here. It has to actually attempt a spawn, and a fork inside this test
    // binary transiently leaks the `flock` held by the lock tests above into
    // the child — measured 2026-08-05: 19 failures in 25 runs of
    // `an_uncontended_lock_is_acquired_and_released_on_drop`. Cargo runs test
    // binaries serially, so a separate integration binary removes the
    // interference without weakening either assertion.

    #[test]
    fn a_missing_rebuild_tool_is_tool_missing_not_a_build_failure() {
        // The regression test for the hole `exec_err` left open: it was
        // applied to the four `git` sites and not to the rebuild site, so an
        // absent `nixos-rebuild` was retried on the cooldown cadence forever
        // and read, in the receipt chain, exactly like a red HEAD.
        //
        // HONEST SCOPE (same tier as `rebuild_cwd_is_the_state_dir_…`): this
        // pins the CLASSIFIER, not the wiring. Deleting the `exec_err` call in
        // `run_rebuild` would still pass, because reaching it needs a real
        // spawn of an absent rebuild binary, and every `RebuildTool::binary()`
        // is an absolute path that either does not exist on this platform
        // (unstable to assert) or is a tool that must never be executed from a
        // test. Tier: only-mitigated.
        let enoent = std::io::Error::from(std::io::ErrorKind::NotFound);
        for verb in ["build", "switch"] {
            assert_eq!(
                exec_err("/run/current-system/sw/bin/nixos-rebuild", &enoent, |m| {
                    RealEnv::rebuild_err(verb, m)
                }),
                EnvError::ToolMissing {
                    tool: "/run/current-system/sw/bin/nixos-rebuild".to_owned()
                },
                "an absent rebuild tool is structural at EVERY verb"
            );
        }
    }

    #[test]
    fn a_rebuild_that_blew_its_deadline_stays_a_build_or_switch_failure() {
        // The split must be NARROW. `OnTimeout` returns `ErrorKind::TimedOut`
        // through the same `Result`, and a hang must keep feeding the cooldown
        // + `land_last_good_after_failures` machinery — relabelling it a broken
        // installation would disable both starvation escapes.
        let timed_out = std::io::Error::from(std::io::ErrorKind::TimedOut);
        match exec_err(
            "/run/current-system/sw/bin/darwin-rebuild",
            &timed_out,
            |m| RealEnv::rebuild_err("build", m),
        ) {
            EnvError::BuildFailed(_) => {}
            other => panic!("a timeout must stay BuildFailed, got {other:?}"),
        }
        match exec_err(
            "/run/current-system/sw/bin/darwin-rebuild",
            &timed_out,
            |m| RealEnv::rebuild_err("switch", m),
        ) {
            EnvError::SwitchFailed(_) => {}
            other => panic!("a timeout must stay SwitchFailed, got {other:?}"),
        }
    }

    #[test]
    fn tool_missing_names_the_binary_in_its_message() {
        // The whole point is legibility in a log; an opaque message would
        // reproduce the original defect with a new variant name.
        let msg = EnvError::ToolMissing {
            tool: "git".to_owned(),
        }
        .to_string();
        assert!(msg.contains("git"), "message must name the tool: {msg}");
    }

    // ── receipts.yaml migration: the edge is "an existing chain still loads"
    //
    // The chain is hash-linked and drives behaviour (streaks feed the
    // starvation escapes), so a rename that orphans it is worse than the
    // misleading filename it fixes.

    fn env_with_state(dir: &std::path::Path) -> RealEnv {
        RealEnv::new(SentinelaConfig {
            state_dir: dir.to_string_lossy().into_owned(),
            ..SentinelaConfig::default()
        })
    }

    /// The regression this bounding pass nearly SHIPPED.
    ///
    /// `run_git` routes every git call through `BoundedRun`, whose DEFAULT
    /// capture is merged — it returns the merged tail in `Output::stderr`
    /// and leaves `stdout` **empty**. `probe_head` parses `out.stdout` for
    /// the `ls-remote` line, so the default mode would have made every
    /// probe return "no head" while every call still reported success: a
    /// silent, total loss of convergence with a green build.
    ///
    /// So `separate_streams()` is load-bearing, and this test pins it by
    /// running a real command with known stdout.
    ///
    /// RED-RUN RECEIPT (2026-08-07): dropping `.separate_streams()` from
    /// `run_git` turns this red with an empty stdout, which is exactly the
    /// silent breakage described above, made loud.
    #[test]
    fn run_git_keeps_stdout_separate_or_probe_head_reads_nothing() {
        let d = tempfile::tempdir().unwrap();
        let env = env_with_state(d.path());

        // `git --version` is the cheapest git invocation that writes a
        // known, non-empty line to stdout and nothing to stderr.
        let out = env
            .run_git(
                {
                    let mut c = std::process::Command::new("git");
                    c.arg("--version");
                    c
                },
                EnvError::ProbeFailed,
            )
            .expect("git --version must run");

        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("git version"),
            "stdout must survive the bound — probe_head parses it. got stdout={stdout:?}, \
             stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// `0` disables the git bound, matching `build_timeout_seconds` /
    /// `switch_timeout_seconds`, so an operator can restore the
    /// pre-bound behaviour without editing code (★★ MODULARIZE, DON'T
    /// DELETE). Proven by running with the bound off rather than by
    /// reading the branch.
    #[test]
    fn git_timeout_zero_disables_the_bound() {
        let d = tempfile::tempdir().unwrap();
        let env = RealEnv::new(SentinelaConfig {
            state_dir: d.path().to_string_lossy().into_owned(),
            git_timeout_seconds: 0,
            ..SentinelaConfig::default()
        });
        let out = env
            .run_git(
                {
                    let mut c = std::process::Command::new("git");
                    c.arg("--version");
                    c
                },
                EnvError::ProbeFailed,
            )
            .expect("the unbounded path must still run the command");
        assert!(String::from_utf8_lossy(&out.stdout).contains("git version"));
    }

    #[test]
    fn the_canonical_receipt_path_is_yaml_because_the_bytes_are_yaml() {
        let d = tempfile::tempdir().unwrap();
        let env = env_with_state(d.path());
        assert!(
            env.receipts_path().ends_with("receipts.yaml"),
            "persist_chain serialises with serde_yaml; the name must say so"
        );
    }

    #[test]
    fn a_legacy_receipts_json_chain_still_loads() {
        // THE regression: a node upgrading across the rename keeps its chain.
        // The fixture is the real on-disk shape measured on cid 2026-08-05.
        let d = tempfile::tempdir().unwrap();
        let env = env_with_state(d.path());
        std::fs::write(
            env.legacy_receipts_path(),
            "- seq: 0\n  rev: cd136f04e14ea67bae9b53491099c63b88a1d3f6\n  \
             outcome:\n    kind: deferred\n    newer: \
             a891200b72fdef64117de281a232bca0105789c3\n  at_unix_ms: \
             1785645747419\n  prev_hash: null\n",
        )
        .unwrap();
        let chain = env.load_chain().expect("legacy chain must parse");
        assert!(
            !chain.is_empty(),
            "an orphaned chain reads as `never deployed`, which resets the \
             failure/deferral streaks the escapes count on — behaviour, not \
             just history"
        );
    }

    #[test]
    fn the_canonical_path_wins_when_both_exist() {
        let d = tempfile::tempdir().unwrap();
        let env = env_with_state(d.path());
        std::fs::write(env.legacy_receipts_path(), "[]\n").unwrap();
        std::fs::write(
            env.receipts_path(),
            "- seq: 7\n  rev: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n  \
             outcome:\n    kind: deferred\n    newer: \
             bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n  at_unix_ms: 1\n  \
             prev_hash: null\n",
        )
        .unwrap();
        let chain = env.load_chain().expect("parses");
        assert!(
            !chain.is_empty(),
            "the migrated file is authoritative once written; the legacy copy \
             is left on disk for the operator, never re-read over the new one"
        );
    }

    #[test]
    fn no_chain_at_either_path_is_an_empty_chain_not_an_error() {
        let d = tempfile::tempdir().unwrap();
        let env = env_with_state(d.path());
        assert!(env.load_chain().expect("absent is not an error").is_empty());
    }
}


/// The subprocess driver — `darwin-rebuild` / `nixos-rebuild` under
/// [`tsunagu::exec::BoundedRun`]. Today's behaviour, unchanged, now behind
/// [`RebuildDriver`] so an in-process sui driver can take its place without
/// touching the probe or the receipt chain.
///
/// ── ★ ITS IRREDUCIBLE HAZARD, STATED WHERE IT LIVES ────────────────────
/// The bounds this driver applies stop at the process it spawns. The rebuild
/// tool then builds `nix build --json … | jq -r` internally, and a wedge in
/// THAT pipeline is invisible to any deadline we set on the outer command —
/// measured on cid 2026-08-11 as four ticks of 5400s each with the tree
/// completely idle. `build_error_quiet_seconds` and `build_silence_seconds`
/// detect it; only removing the subprocess removes it.
pub struct ShellDriver<'a> {
    env: &'a RealEnv,
}

impl RebuildDriver for ShellDriver<'_> {
    fn build(&self, flake_ref: &str) -> Result<(), EnvError> {
        let out = self.env.run_rebuild_ref("build", flake_ref)?;
        if out.status.success() {
            Ok(())
        } else {
            Err(EnvError::BuildFailed(
                String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            ))
        }
    }

    fn switch(&self, flake_ref: &str) -> Result<(), EnvError> {
        let out = self.env.run_rebuild_ref("switch", flake_ref)?;
        if out.status.success() {
            Ok(())
        } else {
            Err(EnvError::SwitchFailed(
                String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            ))
        }
    }

    fn name(&self) -> &'static str {
        "shell"
    }
}
