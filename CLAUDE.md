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
  `darwin-rebuild build/switch`) are typed `std::process::Command` argv;
  the launchd unit runs the `sentinela` binary directly.
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

## Build / test

```
cargo test            # 36 tests, 0 warnings
gen build .           # regenerate Cargo.build-spec.json + Cargo.gen.lock
                      # (required after any dep change — the nix build's
                      #  D2 freshness tie fails on a stale gen lock)
nix build             # the flake-built binary (substrate.rust.tool)
```

Consumed by the nix repo as the `sentinela` flake input; the darwin
`pleme.gitops` module (`modules/pleme/darwin/gitops.nix`) renders the
launchd unit that runs `sentinela run` when `engine = "daemon"`.
