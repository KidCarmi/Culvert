# Disclosure — earlier producer run reported in PR #1528 comment 6304155625

File: `d75afe85-producer-run.retained.txt` — the only retained record of that run, published byte-for-byte as it exists now.

What it is and is not:

- **Not raw test output.** The command was run without `-v`, so `go test` printed one `ok` line per package. No per-test lines and **no shuffle seeds** were recorded (`-shuffle=on` chose seeds that were not printed). The seeds cannot be recovered.
- **Line 3 was edited by the producer after the run.** As written at run time it read:
  `source-sha: b0eb0e12d4a596b24c43506ef055ae054d690481   (branch content == review/1528-fdisk-splash-fix tip after this commit)`
  It was rewritten to name `d75afe85`. Reason: the run started at committed HEAD `b0eb0e12` with `internal/feedsync/heldwriter_recovery_test.go` present but uncommitted (dirty tree); that file was committed unchanged as `d75afe85` after the run. No `git status` was captured at run time, so the dirty-tree state is the producer's account, not recorded evidence.
- Header time `2026-10-20T23:26:13Z`; the file was last modified at 23:30Z (the line-3 edit).

Treat this run as **unverified and superseded**. The authoritative evidence is the seed-recorded verbose run at `c278a2ee` in this directory, captured from a clean tree.
