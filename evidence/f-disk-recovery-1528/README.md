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
