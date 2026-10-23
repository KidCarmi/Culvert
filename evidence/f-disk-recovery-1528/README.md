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

## 90c5fc65: harness fixes for ASTRA 6360307931, with a self-generated local-proof receipt

`90c5fc65-harness-proof.log` was written by the run itself on Linux. It records
head, tree, clean porcelain before and after, the exact commands and their exit
statuses. It covers convergence-oracle_test.sh (23 assertions),
recovery-custody_test.sh run with REQUIRE_PROCESS_PROOF=1 (64 assertions, 0
unsupported) and shellcheck. It is source-level local proof; it is not a lab
run.

Correction to the earlier summary of lab run 39916602574: its checks.jsonl
totals **39 PASS / 2 FAIL** (12 E0 + 27 K PASS, 2 K FAIL), not 25 / 2. The
earlier figure counted only the K rows visible in the report tail.

## 880ae60b: evidence-protection lifecycle (ASTRA 6360721903), with a self-generated receipt

`880ae60b-harness-proof.log` was written by the run itself on Linux. It
records head, tree, clean porcelain before and after, the exact commands and
exit 0 for each: convergence-oracle 23/23, recovery-custody 74/74 with
REQUIRE_PROCESS_PROOF=1 (0 unsupported), and shellcheck clean. It is
source-level local proof, not a lab run.

## 67694982: archive reuse/deletion requires recoverable bytes (ASTRA 6361214485)

`67694982-harness-proof.log` was self-generated on Linux: head, tree, clean porcelain before and after, exact commands and their exits. It covers convergence-oracle 23/23, recovery-custody 81/81 with REQUIRE_PROCESS_PROOF=1, and shellcheck. Source-level local proof, not a lab run.

## Lab run 39943952965 (67694982 harness, `[midimport-kill]`): 44 PASS / 0 FAIL

- **Artifact.** `lab-run-39943952965-midimport-kill-evidence.zip` is the evidence artifact as downloaded (id 12498020087, GitHub digest sha256:155dbc23500ba6fcfca187c4e51951250edb064a8b32b13443e07012f2b9151b; recomputed digest identical).
- **Totals.** Its checks.jsonl totals 12 E0, 31 K and 1 mandatory convergence verdict, all PASS. There was one attempt, and only this job ran; the OVA build was skipped.
- **Quarantine archive.** The archive is the separate artifact 12496688726 (sha256:63f17a9fb632ee12b1f8f4c27798d6e9412b702bf9d0b4f8d98d3461ce759c82). It is retained by GitHub until 2026-11-22 and is not committed here because of its size; its digests are recorded instead.
- **Independent verification.** `lab-run-39943952965-verify.log` records it:
  - `quarantine.tar.gz` sha256 1d6740c8…cb8ee4 matches its sidecar;
  - the archive extracts to exactly 6 files and 403,701,806 bytes;
  - `sha256sum -c` against `manifest.sha256` (sha256 3e23a814…b33d0) passes for all 6;
  - the final evidence state is `clear:post-restart`.
- **Scope.**
  - This proves the harness, at 67694982, running against the frozen application image from 4524311b. It does not validate the later recovery source fixes, which are absent from the frozen 4524311b/27006cf4.
  - Convergence follows the harness's verified preservation and deletion of the quarantined partial, then freeing space and a restart. It is not automatic pressure pruning.
  - It does not prove stalled-Flush completion, power loss, systemd/whole-appliance cancellation, general ENOSPC, or ESXi reproduction.
  - Run 39916602574 remains non-qualifying.

## R1/R5 integration tree and test map (ASTRA 6364575740, OPUS item a)

`r1-r5-integration-map.md` proposes `cfae7d67` as the integration tree: a linear descendant of frozen `4524311b` that carries the reviewed R1 ownership and R5 console fixes. It maps changed and unchanged bytes to tests.

`integ-receipt-cfae7d67+main.log` is self-generated. It is a merge of current main `2892dbf6` with `--no-commit`. It asserts that the tested closure is byte-identical to merge-tree `1b44dd34`, and that none of the 5 pre-existing conflicts are inside that closure. On go1.26.10, feedsync/catdb/storeguard `-race -count=2 -shuffle=on` gave 290 PASS / 0 FAIL / 2 helper SKIP, and boot-splash_test.sh passed. This is source-level producer execution, not a lab run.
