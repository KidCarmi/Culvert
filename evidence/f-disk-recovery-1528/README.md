# F-DISK recovery — Linux test evidence (PR #1528)

Evidence only. Nothing in this directory is product source, and no OVA, lab
workflow or CI job produced it. Published on its own branch so the audited
source branch (`review/1528-fdisk-splash-fix`) keeps its tip at the exact SHA
the log names.

| File | What it is |
|---|---|
| `c278a2ee-race-run.log` | Raw `go test -v` output, clean tree, source `c278a2ee`. Header records SHA, dirty-tree status (empty = clean), Go version, kernel, GOOS/GOARCH/CGO_ENABLED/GOFLAGS, exact command; footer records exit status and finish time. One `-test.shuffle <seed>` line per package. |
| `d75afe85-producer-run.retained.txt` | The earlier, weaker run reported in comment 6304155625 — published as retained. |
| `d75afe85-producer-run.DISCLOSURE.md` | What that earlier file is and is not (no seeds, SHA line edited after the run). Superseded. |
| `SHA256SUMS` | SHA-256 of both logs (`sha256sum -c SHA256SUMS`). |

Reproduce: `git checkout c278a2ee && go test -race -count=2 -shuffle=<seed> -v ./internal/<pkg>/`
using the per-package seed from the log.

Scope: unit/package-level tests on a Linux container (producer-run, not an
independent execution). Not a booted appliance, service-manager restart,
physical ENOSPC, mmap/SIGBUS, power loss or ESXi result.

## f9db48fd — item 4 (cancellation and bounded shutdown)

`f9db48fd-item4-race-run.log`: `go test -race -count=2 -shuffle=on -v` over
internal/feedsync, internal/catdb, internal/storeguard, plus the root
category-feed row/metrics tests. Shuffle seeds and the two SIGTERM→exit
measurements are in the log. Under `-race` the ~1 s exit is dominated by the
race runtime's default 1 s exit sleep (`atexit_sleep_ms`); the store close was
22–26 ms, and 61 ms SIGTERM→exit was measured without `-race`. Source-level
Linux evidence only. Not covered: service-manager stop, physical ENOSPC, a
booted appliance.

## cfae7d67: ASTRA 6359611097 #5/#6 source fixes, with a self-generated receipt

`cfae7d67-race-run.log` was written by the run itself and not edited afterwards.
It records the full head SHA, the tree id, `git status --porcelain` before and
after (both empty), go version, uname, goenv, both exact commands, the
`-test.shuffle` seeds and each command's exit status (0 and 0).

## Lab run 39916602574 (ba1eda2a harness, superseded by 7854ed76)

`lab-run-39916602574-midimport-kill-evidence.zip` is the run's artifact as
downloaded (GitHub digest
sha256:20a38ece3d03129a29576f162600c1b09a17e2f466cab0d1ac1471e323d96e55). The
harness it ran had the P1 defects ASTRA found in 6359611097, so the run is
**non-qualifying** and is retained as a record only. It finished on its own
before the owner-requested cancel reached it (the cancel returned 409). Recorded
outcome: 25 PASS / 2 FAIL. Convergence was proven: sync complete, 2,601,320
domains. Both failures were the guessed adult-domain probe, and the lab
mirror's feed carries no adult list. The large quarantine files were deleted
under the pre-fix hash-only custody. Only their manifest, inventory and files
under 1 MiB were retained, and that is not complete custody.
