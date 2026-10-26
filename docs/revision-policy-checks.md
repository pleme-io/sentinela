# Revision policy `green`: check reads

Answers are cached per revision: green and red forever, pending and blind for
`recheck_seconds`.

Checks are read over GitHub's REST API with curl, the token on stdin. A 401 /
403 is `checksBlind` naming the missing permission (Checks: read, Commit
statuses: read).
