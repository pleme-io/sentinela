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

## Health-gated rollback (off by default)

`rollback:` in the config (`sentinela-config::RollbackConfig`) attaches a
`RollbackPolicy` via `Sentinela::with_rollback`. With it, every activation
enters `State::Verifying` (a `Probation` receipt makes it survive restarts and
reboots); each tick runs one probe round WITHOUT probing HEAD, until
`required_consecutive_passes` land (`Verified`) or a round fails past the
window, which re-activates the previous generation using that generation's own
tools (`real_env::rollback_argv`), attests `RolledBack`, and quarantines the rev
until HEAD moves (`ReceiptChain::quarantined_rev`). Probe entries are an open
list parsed one at a time: a malformed entry is refused by name and its
siblings load. Kinds: `command` only (no HTTP client in the default build).
Not the no-downgrade rule: that is about git history, this about the system
profile. Code: `sentinela-core/src/probation.rs` + the probation methods in
`fsm.rs`.

On NixOS the rollback's `switch-to-configuration` runs with `NIXOS_NO_CHECK=1`
(a pre-switch gate that holds forward moves, like plo's engenho restart gate,
must not hold the switch that undoes one), and "which generation" means the one
whose closure RUNS (`/run/current-system`), not the one the profile names: a
rollback flips the profile before it activates, so a failed activation must not
read as rolled back. `rollback_to` returns Ok only once the restored generation
is running (`real_env::rollback_steps`, `real_env::running_generation`).

## Revision policy: `head` (default) or `green`

`revision_policy:` (`sentinela-config::RevisionPolicyConfig`, internally tagged
`kind:` so the JSON the nix module renders parses) chooses what is deployed.
`head` is branch HEAD, unchanged: no history walk, no check reads. `green`
walks HEAD's first-parent history back to the active revision
(`--ancestry-path`, so nothing older than what runs is offered) and deploys
the newest revision whose `required` check-runs / status contexts all
concluded success (`sentinela-core/src/checks.rs`). No green revision means no
build and no receipt: `waitingForGreen` (quiet), `checksRed <rev>` or
`checksBlind <reason>` (said once per revision / reason). A 401 / 403 is
`checksBlind`, never green. Caching and transport:
[docs/revision-policy-checks.md](docs/revision-policy-checks.md).

## Quiet window: a build starts only on a HEAD that stopped moving

A new HEAD waits in `settling` for `head_quiet_seconds` (default 600, `0` =
off); a newer HEAD restarts the wait. `head_quiet_max_seconds` (default 3600)
bounds it, so a busy branch still builds. A deferral releases the window once,
so the newer HEAD builds next tick (`build_newer_after_deferral`); STARVED
needs `starved_after_deferrals` (default 2) deferrals. [Detail](docs/quiet-window.md).

## A new config is loaded by exiting between ticks

The service manager never restarts this daemon on activation (it performs the
activation), so `run` compares its config path's resolved target after every
tick and exits 0 when it moved; systemd `Restart=always` / launchd `KeepAlive`
start the new generation's daemon, and an open probation resumes from its
receipt. On nix-managed nodes the resolved target is a store path, so a nix
renderer that wants a BINARY bump to restart the daemon too makes the config
file's store path depend on the package (`main::config_moved`).

## Rebuild engine: nix or sui, sui as a subprocess or embedded (2026-10-08)

`rebuild_tool` picks the engine: `darwin-rebuild` (default), `nixos-rebuild`,
or `sui` (doctrine P5, `theory/RECONCILER-LIVENESS.md` §IV.3). For sui,
`sui.mode` picks how it runs:

| `sui.mode` | Driver | Needs |
|---|---|---|
| `subprocess` (default) | `ShellDriver` runs `<sui.binary> system rebuild <verb> --flake <ref>` | the sui CLI (`sui.binary`, default `/run/current-system/sw/bin/sui`) |
| `embedded` | `SuiDriver` calls sui-orchestrate in-process (`build_toplevel`, `rebuild_native`): no subprocess, no pipe, no `jq` wedge | a binary built with the `sui-driver` feature (`packages.sentinela-sui-driver`); `preflight` refuses to start otherwise |

sui resolves the rev-pinned `github:owner/repo/<rev>` ref since 0.1.176 (sui
b53648b); the pin is sui-orchestrate 0.1.219. The nix side is
`pleme.gitops.rebuildEngine` + `pleme.gitops.sui.{mode,package}` in the nix
repo (`modules/pleme/shared/gitops.nix`); on NixOS sui needs
`nixosBackend = "sentinela"`.

Open, tier-honest:
- **The `sui-driver` variant spec goes stale on every release.** The flake
  builds it from `Cargo.sui-driver.build-spec.json`
  (`gen build . --features sui-driver --out …`, substrate `variants`), whose
  freshness tie is Cargo.lock's hash. Every auto-release bumps the workspace
  version in Cargo.lock and regenerates only the canonical spec, so the
  embedded package fails eval with "variant spec is STALE" at any released
  HEAD. Fix belongs in gen (declared variants regenerated by `gen build .`)
  and the release workflow's regenerable paths.
- **The embedded driver is compile-checked against 0.1.219, not run.** Its
  musl build (plo's target) is unverified.
- sui's whole-system byte-identity gate is still open
  (`sui/docs/SILENT-DIVERGENCE-HUNT.md`), which is why nothing selects sui by
  default.

## Build / test

```
cargo test            # 208 tests (2026-10-08)
gen build .           # regenerate Cargo.build-spec.json + Cargo.gen.lock
                      # (required after any dep change — the nix build's
                      #  D2 freshness tie fails on a stale gen lock)
nix build             # the flake-built binary (substrate.rust.tool)
```

Consumed by the nix repo as the `sentinela` flake input; the darwin
`pleme.gitops` module (`modules/pleme/darwin/gitops.nix`) renders the
launchd unit that runs `sentinela run` when `engine = "daemon"`.
