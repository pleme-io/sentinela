# sentinela

**The Darwin GitOps node-sync daemon — the Mac peer of NixOS [comin](https://github.com/nlewo/comin).**

A single long-running Rust daemon keeps a Mac's nix-darwin system equal to
one repo's branch HEAD: it probes HEAD over the **git protocol**
(`git ls-remote` — rate-limit-immune, unlike the GitHub API), builds it
rev-pinned, re-checks freshness, and activates — attesting every deploy to
an append-only BLAKE3-chained receipt log.

It replaces the interim guarded-shell loop (`pleme.gitops` v1.5) with a
pure-Rust, typed, testable daemon (NO shell), behind the same
`pleme.gitops` nix option surface (`engine = "daemon"`).

## Why a daemon (what the bare `darwin-rebuild switch` loop got wrong)

A naïve 60-second `darwin-rebuild switch --flake github:…#host` loop is a
**rollback machine**: a GitHub API rate limit makes the `github:` fetcher
deploy a *stale cached* tree; an in-flight run finishing after a newer push
re-registers the older system; overlapping multi-minute builds contend.
`sentinela` closes all three by construction:

| Guard | How |
|---|---|
| **rate-limit immunity** | resolve HEAD via `git ls-remote` (git protocol), never the GitHub API |
| **skip-if-unchanged** | HEAD == last *activated* rev → no build, no switch |
| **rev-pinned build** | build+switch the exact probed rev |
| **no-downgrade** | re-probe after the build; if HEAD moved, *defer* — never activate a stale rev |
| **receipt-before-idle** | a switch persists its attested receipt before the cycle ends |
| **single-flight** | structural — one daemon, one loop (no lock needed) |
| **fail-closed** | any probe/build/switch error deploys nothing and cools down |

## Architecture

- **`sentinela-core`** — the injectable, testable algebra. A typed FSM
  (`Sentinela::tick`) pure over the **`GitopsEnv`** trait (ls-remote /
  build / switch / clock / receipt-store). Every transition and invariant
  is proven against `MockEnv` — no network, no build, no clock.
  `Rev` is parse-don't-validate (40-hex); `ReceiptChain` is a verifiable
  BLAKE3 chain.
- **`sentinela-config`** — the shikumi-typed config surface mirroring the
  `pleme.gitops` nix options.
- **`sentinela`** — the binary: the real `GitopsEnv` (typed `Command`, no
  shell), the daemon loop, and the CLI.

## CLI

```
sentinela run          # the daemon loop (launchd entry point)
sentinela status       # current deploy state + chain verification (JSON)
sentinela verify       # verify the receipt chain; non-zero on a break
sentinela tick-once    # run one cycle, print the outcome, exit
```

Config path: `--config` / `$SENTINELA_CONFIG` (default
`/etc/pleme-gitops/config.yaml`, rendered by the nix module).

## Status

M0+M1 shipped: typed core (36 tests), real env, CLI, launchd wiring behind
`pleme.gitops.engine = "daemon"`. Design + phases:
`nix/docs/gitops-v2-daemon.md`.
