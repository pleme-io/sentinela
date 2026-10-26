# Quiet window: a build starts only on a HEAD that stopped moving

`head_quiet_seconds` (default 600, `0` = build every new HEAD at once, the
pre-0.1.31 behaviour) holds a new HEAD in `settling` until it has been
unchanged that long. A newer HEAD restarts the window, so the latest rev wins.

`head_quiet_max_seconds` (default 3600, raised to the window when below it)
bounds the wait from the first unbuilt HEAD. A branch that never goes quiet
still builds. The deferral escape (`land_ancestor_after_deferrals`) still
lands an ancestor.

The gate is `sentinela-core/src/quiet.rs`. `tick_inner` moves the probed HEAD
through `Quiet::admit` before anything can build it.

The window lives in memory. A daemon restart starts it again.
