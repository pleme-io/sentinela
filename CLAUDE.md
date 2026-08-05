# sentinela — repo guide

The Darwin GitOps node-sync daemon (Mac peer of NixOS comin). Keeps a
Mac's nix-darwin system equal to one repo's branch HEAD. Replaces the
interim guarded-shell `pleme.gitops` v1.5 loop with a pure-Rust daemon
behind the same nix option surface (`engine = "daemon"`). Full design +
phases: `nix/docs/gitops-v2-daemon.md`.

## Layout

| Crate | Role |
|---|---|
| `sentinela-core` | the injectable, testable algebra — typed FSM (`Sentinela::tick`) pure over the `GitopsEnv` trait; `Rev` (parse-don't-validate), `ReceiptChain` (BLAKE3 chain), `MockEnv` |
| `sentinela-config` | shikumi-typed config surface mirroring `pleme.gitops` |
| `sentinela` | the bin — real `GitopsEnv` (typed `Command`, no shell), daemon loop, CLI |

## Conventions

- **NO shell.** The three impure verbs (`git ls-remote`,
  `<rebuild-tool> build/switch`) are typed `std::process::Command` argv;
  the launchd unit runs the `sentinela` binary directly. The rebuild argv is
  composed by the pure `real_env::rebuild_argv` from the tool's own
  `RebuildTool::argv_prefix()` — never assumed to start with the verb.
- **A structural fault is never a transient one.** An absent binary is
  `EnvError::ToolMissing` at every exec site (`exec_err`), and `preflight`
  refuses to start rather than letting the loop rediscover it once a minute
  forever while every liveness surface reads green.
- **No `format!()` in production paths** — argv pieces are `concat`'d;
  URLs go through `url::Url`; output is `write!`/`tracing`/`serde`/
  `println!` of `Display` values. Fixtures in `#[cfg(test)]` may use
  `format!`.
- **The core is pure over `GitopsEnv`.** New behavior is a new FSM branch
  proven against `MockEnv` first, then wired into the real env. Do not
  add side effects to `sentinela-core`.
- **Every invariant is a test.** no-downgrade, fail-closed,
  skip-if-unchanged, receipt-before-idle, chain-verify — see
  `sentinela-core/src/fsm.rs` + `receipt.rs`.

## ★ P5 — why the rebuild is still a subprocess (measured 2026-08-05)

Doctrine P5 (`theory/RECONCILER-LIVENESS.md` §IV.3) wants this daemon off
`darwin-rebuild`/`nixos-rebuild` and onto **sui**, the fleet's own pure-Rust
nix — `sui-orchestrate/src/lib.rs:3` states its purpose as *"Replaces
darwin-rebuild, nixos-rebuild, deploy-rs, and colmena"*. Graded honestly:

| Question | Answer |
|---|---|
| Is `sui-orchestrate` a consumable **library**? | **Yes.** Published (`0.1.154`, 14 versions), and a bare consumer `cargo check`s clean on aarch64-darwin. |
| Does the **closure** suit a node daemon? | **Poorly.** 196 → **627** packages, dragging in sea-orm + sqlx + gix + rustls + two `reqwest` majors. Needs a `kstring ≤ 2.0.2` pin at rustc 1.91.1. No dependency cycle. musl/x86_64-linux is UNVERIFIED — do not claim it. |
| Does `sui system rebuild` work **end-to-end**? | Real and wired — 10/11 marquee surfaces REAL (`sui/docs/SUI-SUPREMACY-ROADMAP.md:105-121`), M2.6 closed — but the *byte-identical* toplevel is still gated (`sui/docs/CONVERGENCE.md` R5). |

**THE BLOCKER, and it is neither packaging nor async:** sui resolves
**local filesystem paths only**. `sui_compat::flake_ref::FlakeRef::parse`
(`sui/sui-compat/src/flake_ref.rs:37-58`) splits on `#` and treats the left
half as a directory; `sui_eval::builtins::evaluate_flake`
(`sui/sui-eval/src/builtins/flake_eval.rs:43`) takes a `&Path`. This daemon
exists to build a **rev-pinned remote** ref. Measured on cid against sui
0.1.154:

```
$ sui system rebuild dry-activate --flake 'github:pleme-io/nix/0123…4567#ryn'
Error: rebuild failed: eval: I/O error: getFlake:
  github:pleme-io/nix/0123…4567/flake.nix: No such file or directory
```

So the swap is blocked at sui's API. What landed instead is the typed shape
the swap needs: `RebuildTool::Sui` exists and is config-selectable, each
variant owns its `argv_prefix()` (`sui system rebuild <verb>` is not
`<verb>`) and its `flake_ref_syntax()`, and `sentinela::preflight` REFUSES
the sui + remote-url pairing at startup — so the variant cannot ship the
rio-2026-08-05 shape (a loop that fails every tick while reading healthy).
**Two things unblock it, neither in this repo:** a `github:` fetcher in
sui's `FlakeRef` (then `flake_ref_syntax()` becomes `Remote` and nothing
else moves), or a rev materializer here plus sui's byte-identity proof.

## Build / test

```
cargo test            # 100 tests, 0 warnings
gen build .           # regenerate Cargo.build-spec.json + Cargo.gen.lock
                      # (required after any dep change — the nix build's
                      #  D2 freshness tie fails on a stale gen lock)
nix build             # the flake-built binary (substrate.rust.tool)
```

Consumed by the nix repo as the `sentinela` flake input; the darwin
`pleme.gitops` module (`modules/pleme/darwin/gitops.nix`) renders the
launchd unit that runs `sentinela run` when `engine = "daemon"`.
