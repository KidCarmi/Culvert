# R1/R5 integration tree and test map (ASTRA 6364575740, OPUS handoff item a)

Prepared 2026-10-23. Preparation only: no build, lab run, VM change, push to the PR head, merge or release.

## Proposed integration tree

**`cfae7d67d96522b5bd5d751a8dcca74458bae75f`** (tree `c2ff3f853cf61804e381ac4b6d33907231741441`), branch `review/1528-fdisk-splash-fix`.

- It is a strict linear descendant of frozen head `4524311b`: 12 commits and 13 files, with no rebase and no merge commit.
- It carries the accepted R1 ownership fix (`4f95a315` and follow-ons) and the accepted R5 console fixes (`14e714c6`, `89e8fbd4`).
- Both fixes are already reviewed: R1 in E3, ASTRA 6360307931; R5 in E2, ASTRA 6304005247.
- Nothing new is introduced. This document only maps what is already there.

### Commits 4524311b..cfae7d67

| Commit | Row | Kind | Files |
|---|---|---|---|
| 0322df62 | R5 | test | appliance/build/boot-splash_test.sh |
| 14e714c6 | R5 | fix | culvert-splash-status, boot-splash_test.sh |
| 89e8fbd4 | R5 | fix | culvert-splash-status, boot-splash_test.sh (80-column budget) |
| 4f95a315 | R1 | fix | internal/feedsync/feedsync.go (quiesce after an abandoned BulkWrite), design doc |
| b0eb0e12 | R1 | fix/test | stale comment, Linux-only skip |
| d75afe85 | R1 | test | Linux held-writer late return and quarantine on reopen |
| c278a2ee | R1 | test | join the actual writer return; reopen and reimport chain |
| f9db48fd | R1 | feat | abandoned-import latch surfaced on Health, the operator row and the gauge (restart required); subprocess bounded-exit tests |
| cfae7d67 | R1 | test/docs | absolute deadlines and bounded joins; narrowed claims in the operator doc |
| d103d8a1, d3a08297, 1cd0c7d4 | R6 | docs only | docs/appliance/docker-cve-upgrade-proposal.md (no code) |

The truthful restart-required behaviour R1 asks for is the latched surface added by f9db48fd:
- `Health.WriteAbandoned` with its cause and timestamp;
- the `category_feed_db` row, which says "restart required" and never claims earlier data serves;
- `culvert_category_feed_write_abandoned`;
- docs/operator/category-store-recovery.md.

## Changed versus unchanged bytes (4524311b → cfae7d67)

| Path | State | Covered by |
|---|---|---|
| internal/feedsync/feedsync.go | **changed** (R1 production) | all feedsync tests below |
| catfeeddb_health.go, urlcat_metrics.go | **changed** (R1 operator surface) | catfeeddb_writeabandoned_test.go |
| appliance/boot-splash/culvert-splash-status | **changed** (R5 production) | boot-splash_test.sh |
| internal/feedsync/heldwriter_recovery_test.go | new | TestHeldWriter_LateReturnDoesNotCertifyAndKeepsMarker, TestHeldWriter_RecoveryPersistsAcrossReopens |
| internal/feedsync/parkedwriter_test.go | new (helpers only) | used by the held-writer tests |
| internal/feedsync/bulkwrite_watchdog_test.go | changed | TestSyncRound_QuiescesAfterAbandonedWrite, TestWriteBulkWatched_* |
| internal/feedsync/shutdown_subprocess_test.go | new | TestShutdown_SIGTERMExitsBoundedWithAbandonedWriter, TestShutdown_SIGKILLWithAbandonedWriterRecoversOnReopen, TestShutdown_DeadlineIsNotRenewedByOutput |
| catfeeddb_writeabandoned_test.go | new | TestCategoryFeedRow_WriteAbandoned* (3), TestCategoryFeedMetrics_WriteAbandonedGauge |
| appliance/build/boot-splash_test.sh | changed | failed-unit display and the nine width cases (E2) |
| internal/catdb, internal/storeguard, third_party/badger, third_party/ristretto, go.mod, go.sum | **unchanged** | regression-run in both receipts |

### ASTRA's invariant chain mapped to tests

| Step | Test |
|---|---|
| hold, then timeout | TestWriteBulkWatched_StallSurfaced |
| retry refused (quiesce; no overlapping writer) | TestSyncRound_QuiescesAfterAbandonedWrite |
| actual late return does not certify, and the marker is kept | TestHeldWriter_LateReturnDoesNotCertifyAndKeepsMarker |
| marker, then reopen, then quarantine, then reimport across reopens | TestHeldWriter_RecoveryPersistsAcrossReopens |
| bounded process exit; SIGKILL recovers on reopen | TestShutdown_* (real subprocess) |

## Merge with current main (2892dbf6, 133 commits since 4524311b)

- **Conflicts are pre-existing and are not caused by R1/R5.** `git merge-tree` conflicts on 5 identical paths for `4524311b`+main and for `cfae7d67`+main: `.github/workflows/_build-image.yml`, `d0_helpers_test.go`, `docs/api/API-INVENTORY.md`, `frontend/src/api/types.gen.ts` and `ui_routes_meta_test.go`. The fixes add none. Syncing with main is a separate step, and the owner decides when; resolving it now would go stale as main moves.
- **No intervening ownership change.** Main's 133 commits touch none of: internal/feedsync, catdb, storeguard, shutdown, feedsched, hostutil, obs, third_party, the splash script or its test, or the R1 root files. Main's only dependency change is `toolchain go1.26.9 → go1.26.10` (GO-2026-6809, crypto/x509). go.sum is unchanged.
- **What is byte-identical, stated precisely** (corrected after ASTRA 6365334113):
  - **cfae7d67 vs the merged tree:** the package sources (`go list -deps -test` module closure of feedsync, catdb and storeguard), third_party/badger, third_party/ristretto, go.sum and the splash files are byte-identical. **go.mod is not**: it differs by the toolchain line (`go1.26.9` → `go1.26.10`).
  - **The receipt's working tree vs merge-tree `1b44dd34e139560fef69e269ec6dfa247ef899f5`:** the whole tested closure, go.mod included, is identical. The receipt asserts this in-script.
  - The go1.26.10 run is the evidence for the toolchain change; it is not covered by the cfae7d67 receipt.

## Receipts

| Receipt | Tree | Toolchain | Result |
|---|---|---|---|
| `cfae7d67-race-run.log` (existing, E3) | cfae7d67 | go1.26.9 | feedsync, catdb and storeguard `-race -count=2 -shuffle=on`, plus the root R1 subset: PASS |
| `integ-receipt-cfae7d67+main.log` (new) | cfae7d67 with origin/main 2892dbf6 merged `--no-commit`; closure identical to merge-tree 1b44dd34 | **go1.26.10** | feedsync, catdb and storeguard `-race -count=2 -shuffle=on`: **290 PASS / 0 FAIL / 2 SKIP**; boot-splash_test.sh: PASS (exit 0) |

- The 2 SKIPs are `TestShutdownHelperProcess`, the child-process entry point, which skips when it is not launched as a child (once per count). Every R1 chain test above passed in both counts.
- **Not re-run on the merged tree:** the root-package R1 subset (`TestCategoryFeed*`, `TestMetrics_CatFeedDB*`). The root package cannot compile until the two conflicted root test files (`d0_helpers_test.go`, `ui_routes_meta_test.go`) are resolved in the main sync. Its own files are byte-identical, but 74 other root files differ because of main. That re-run belongs to the main-sync step, and its CI (Fast PR Gate `-race`) covers it.

## What this does not establish

- No application bytes have been shipped. Frozen `4524311b` / OVA `27006cf4` and lab run E5 (39943952965) do not contain feedsync.go from cfae7d67. Shipping these fixes requires a new candidate identity and R4 delta qualification.
- These are source-level receipts produced by OPUS (this is producer execution). They are not an independent Linux execution and not a lab run.
- R5 live VGA proof is still NOT RUN; it belongs to the R4 replacement boot visit.
