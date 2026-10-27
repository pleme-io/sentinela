# Quiet window: a build starts only on a HEAD that stopped moving

`head_quiet_seconds` (default 600, `0` = build every new HEAD at once, the
pre-0.1.31 behaviour) holds a new HEAD in `settling` until it has been
unchanged that long. A newer HEAD restarts the window, so the latest rev wins.

`head_quiet_max_seconds` (default 3600, raised to the window when below it)
bounds the wait from the first unbuilt HEAD. A branch that never goes quiet
still builds. The deferral escape (`land_ancestor_after_deferrals`) still
lands an ancestor.

A deferral releases the window once: the HEAD that superseded the build is
built on the next tick (`build_newer_after_deferral`, default on, `false` =
every HEAD waits). Measured on rio 2026-10-27: without it, `6134909` restarted
the 600s window after `7a2434c` deferred, and further pushes kept it settling
toward the ceiling. Health reads `deferring` below `starved_after_deferrals`
(default 2, the deferral escape's streak; `0` or `1` = every deferral is
STARVED) and STARVED at it.

The gate is `sentinela-core/src/quiet.rs`. `tick_inner` moves the probed HEAD
through `Quiet::admit` before anything can build it.

The window lives in memory. A daemon restart starts it again.
