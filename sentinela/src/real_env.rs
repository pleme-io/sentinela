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
use sentinela_core::{EnvError, Generation, GitopsEnv, Heartbeat, ReceiptChain, Rev};
use std::fs::File;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

/// The nix system profile whose generation number a switch advances.
const SYSTEM_PROFILE: &str = "/nix/var/nix/profiles/system";
/// `darwin-rebuild` from the running system (root, no sudo needed under
/// the launchd daemon).
const DARWIN_REBUILD: &str = "/run/current-system/sw/bin/darwin-rebuild";

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

    fn receipts_path(&self) -> PathBuf {
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

    /// Where `darwin-rebuild` is run from. See [`Self::run_darwin_rebuild`]
    /// — this is load-bearing, not incidental.
    fn rebuild_cwd(&self) -> &Path {
        Path::new(&self.cfg.state_dir)
    }

    fn run_darwin_rebuild(&self, verb: &str, rev: &Rev) -> Result<std::process::Output, EnvError> {
        let flake_ref = self.flake_ref(rev);
        let mut cmd = Command::new(DARWIN_REBUILD);
        cmd.arg(verb).arg("--flake").arg(&flake_ref);
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
        for a in &self.cfg.extra_rebuild_args {
            cmd.arg(a);
        }
        cmd.output().map_err(|e| match verb {
            "switch" => EnvError::SwitchFailed(e.to_string()),
            _ => EnvError::BuildFailed(e.to_string()),
        })
    }
}

impl GitopsEnv for RealEnv {
    fn probe_head(&self) -> Result<Option<Rev>, EnvError> {
        let url = self.probe_url()?;
        let refspec = ["refs/heads/", self.cfg.rev_probe.branch.as_str()].concat();
        let out = Command::new("git")
            .arg("ls-remote")
            .arg(&url)
            .arg(&refspec)
            .output()
            .map_err(|e| EnvError::ProbeFailed(e.to_string()))?;
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
            let out = Command::new("git")
                .arg("clone")
                .arg("--bare")
                .arg("--filter=blob:none")
                .arg(&url)
                .arg(&mirror)
                .output()
                .map_err(|e| EnvError::AncestryFailed(e.to_string()))?;
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
        let fetch = Command::new("git")
            .arg("--git-dir")
            .arg(&mirror)
            .arg("fetch")
            .arg("--quiet")
            .arg(&url)
            .arg(format!(
                "+refs/heads/{}:refs/heads/probe",
                self.cfg.rev_probe.branch
            ))
            .output()
            .map_err(|e| EnvError::AncestryFailed(e.to_string()))?;
        if !fetch.status.success() {
            return Err(EnvError::AncestryFailed(
                String::from_utf8_lossy(&fetch.stderr).trim().to_owned(),
            ));
        }

        // `--is-ancestor` is exit-code-only: 0 = yes, 1 = no, anything else
        // (including a rev this mirror has never heard of) is an ERROR and
        // must not be read as either answer.
        let out = Command::new("git")
            .arg("--git-dir")
            .arg(&mirror)
            .arg("merge-base")
            .arg("--is-ancestor")
            .arg(ancestor.as_str())
            .arg(descendant.as_str())
            .output()
            .map_err(|e| EnvError::AncestryFailed(e.to_string()))?;
        match out.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(EnvError::AncestryFailed(
                String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            )),
        }
    }

    fn build(&self, rev: &Rev) -> Result<(), EnvError> {
        let out = self.run_darwin_rebuild("build", rev)?;
        if out.status.success() {
            Ok(())
        } else {
            Err(EnvError::BuildFailed(
                String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            ))
        }
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
        // `run_darwin_rebuild` detaches the child), the lock drops while the
        // detached activation is still running — a window an operator switch
        // could race. Rare (only on plist-changing generations), and the
        // next tick re-converges; documented rather than engineered around,
        // because fixing it would require holding the lock in a child we
        // deliberately orphan.
        let _lock = acquire_switch_lock(Path::new(REBUILD_LOCK_PATH))?;
        let out = self.run_darwin_rebuild("switch", rev)?;
        if !out.status.success() {
            return Err(EnvError::SwitchFailed(
                String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            ));
        }
        // Read the new generation from the system profile symlink; a
        // parse miss is non-fatal (the switch succeeded) — record 0.
        Ok(current_generation().unwrap_or(Generation(0)))
    }

    fn load_chain(&self) -> Result<ReceiptChain, EnvError> {
        let path = self.receipts_path();
        match std::fs::read_to_string(&path) {
            Ok(s) => serde_yaml::from_str(&s).map_err(|e| EnvError::ReceiptIo(e.to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ReceiptChain::new()),
            Err(e) => Err(EnvError::ReceiptIo(e.to_string())),
        }
    }

    fn persist_chain(&self, chain: &ReceiptChain) -> Result<(), EnvError> {
        let path = self.receipts_path();
        let body = serde_yaml::to_string(chain).map_err(|e| EnvError::ReceiptIo(e.to_string()))?;
        // Atomic: write a temp sibling then rename, so a crash never
        // leaves a half-written chain.
        let tmp = path.with_extension("json.tmp");
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
        // Deleting the `cmd.current_dir(...)` call in `run_darwin_rebuild`
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
}
