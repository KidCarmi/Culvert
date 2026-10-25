# F-DISK-RECOVERY-1 — mid-write ENOSPC must not leave the Layer-2 cache permanently degraded

_Recovery design for ASTRA independent review (PR #1528). P1 appliance-reliability
blocker, owner decision OPTION A (fix; risk acceptance rejected). This document is
the recovery design; the implementation lands in `internal/storeguard`,
`internal/catdb` and `internal/feedsync` with deterministic fault-injection tests._

## 1. The failure (preserved evidence)

Lab `appliance-lab` run **39314161458 attempt-1** (candidate `8d3ca1c7`), F-DISK-1
`midwrite` scenario, verbatim:

```
19:51:21 pass [W] filled-during-write: FeedSync: parsed 2581437 domain entries, writing to BadgerDB; write still in flight; filled to 6120KiB free
19:51:52 FAIL [W] degraded-state-truthful: last_sync=0 sync_failures_total=0 catfeeddb_available=0 quarantined_copies=0 ; write error: no bulk-write-failed/refused line
19:51:53 FAIL [W] category-store-opens: culvert_catfeeddb_available 0 quarantined_copies 0
20:22:00 FAIL [W] category-import-converges: no import retry finished within 1800s of recovery
```

The FAVOURABLE landing (run 39306980073, attempt-2 of 39314161458) returns a clean
`bulk write failed … fallocate 00002.mem: no space`, keeps `available=1`,
`sync_failures=1`, and converges 11 s after recovery. The gap is intermittent
(~1-in-3), timing-dependent on where the mid-write fill lands relative to badger's
write phases.

## 2. Root cause (two coupled sub-gaps, both rooted in CHAOS-74 containing a FULL-DISK fault)

1. **Not surfaced.** On the unfavourable landing the badger mmap write faults on the
   full disk. CHAOS-74 (`internal/catdb` `contain`/`latchFault`) contains the fault
   on a badger-internal goroutine and latches `RuntimeDegraded` (`available=0`), but
   the outer `BulkWrite` call does not *return* (badger blocks >31 s on the full
   disk). `feedsync.syncRound`'s `noteFailure(failWrite)` is only reached on
   `BulkWrite` returning, so `sync_failures_total` stays 0 — the incomplete import is
   not truthfully surfaced.

2. **No recovery.** The quarantine-on-next-boot machinery already exists
   (`storeguard.RecordFault` → `storeguard.Open` `TriggerRuntimeFault`), but
   `recordFault` writes its marker into the store's PARENT directory, on the SAME
   full filesystem, AT fault time, so it fails with ENOSPC (`catdb.go:271` comments
   this exact outcome). No marker ⇒ the torn store re-opens on restart and the boot
   `RunNow: !ImportComplete()` re-import re-faults and re-latches; the proxy never
   crashes (fault is contained), so nothing restarts it. The damaged Layer-2 store
   stays degraded across every restart until an operator deletes `/data/catfeeddb`.

Scope: Layer-2 community CACHE only (no authoritative state). Layer-1 admin
categories, default-deny enforcement, proxy traffic, admin login, CA identity,
request-history and config state are unaffected and all PASSED in the failing run.
Pre-existing in main's CHAOS-74 path (present on the prior qualified candidate too);
surfaced by the F-FEED-1 hardened oracle (`f7ae4d49`).

## 3. Fix — write the intent BEFORE the risky write; never depend on a post-failure write to a full disk

### C1. Durable import-pending intent before BulkWrite (owner req 1, 3)

`internal/storeguard` gains an opt-in *import-pending* marker, mirroring the
fault-marker durability discipline (temp file → write → `fsync` → atomic rename →
`fsync(parent dir)`):

- `MarkImportPending(dir) error` — sibling `<base>.importing` in the parent dir.
- `ClearImportPending(dir) error` — removes it, `fsync(parent)`.
- `importPending(dir) bool` — regular-file check (a directory never counts).

`internal/catdb`:

- `BeginImport` writes the marker FIRST (via `storeguard.MarkImportPending`), fsyncs
  it, and only then deletes the badger completion record. **If the marker write
  fails, `BeginImport` returns the error and touches no badger state — the import
  does not start** (fail-closed: we never begin a risky write we could not record an
  intent for). `feedsync` counts this as a sync failure and backs off.
- `CompleteImport` clears the marker AFTER the badger completion record is set and
  fsynced. A clear failure is returned (fsync'd clear), so `feedsync` retries; a
  stale marker on a genuinely complete store would only cost an unnecessary
  quarantine+re-sync on the next boot, never data loss.

**Why this satisfies req 3:** `BeginImport` runs BEFORE `BulkWrite`, and the disk
fills DURING `BulkWrite`, so the marker is written while space still exists. The fix
never writes a recovery marker to an already-full filesystem after a failure.

### C2. Startup detection + quarantine/rebuild (owner req 2, 5)

`storeguard.recoverBeforeOpen` gains a THIRD signal after poison and fault, a new
`TriggerInterruptedImport`:

- If `importPending(dir)` is true AND the store dir exists → `ApplyQuarantine`
  (move aside to `.corrupt.<unixnano>`, pruned to one copy, store-lock-gated — never
  a delete), then clear the marker. badger then creates a fresh empty store and
  `feedsync` re-imports cleanly (a clean store cannot carry the mid-write damage).
- Ordering: `poison > fault > interrupted-import`. An interrupted import with no
  poison/fault signal still quarantines: a partial Layer-2 cache is throwaway, and
  rebuilding guarantees the re-import is against an undamaged store on EITHER landing.

**Bounded + idempotent (req 5), and the key anti-loop property:** the marker is
written only when an import actually BEGINS, i.e. past `feedsync.spaceRefusal`
(free-space floor). So on a persistently full disk: boot → quarantine the torn store
→ rebuild empty → clear marker → `feedsync` refuses the import (disk full, no
`BeginImport`, no new marker). Next boot: no marker ⇒ NO quarantine; the empty store
is stable. **Exactly one quarantine on a full disk, then stable — no rebuild loop.**
When space is freed, the import runs: `BeginImport` writes the marker, `BulkWrite`
succeeds, `CompleteImport` clears it. Quarantine prunes to one copy so repeated
restarts cannot grow the volume. A store that COMPLETED its last import and shut down
cleanly carries no marker (CompleteImport cleared it) ⇒ never a false quarantine.

### C3. Surface a contained fault / stalled BulkWrite truthfully (owner req 4)

`feedsync.syncRound` runs `BulkWrite` in a goroutine and watches three conditions:

- `BulkWrite` returns → normal path (its error, or `CompleteImport` on success).
- The store latches degraded (`fs.storeDegraded()` poll, ~500 ms) → record
  `noteFailure(failWrite)` and return false IMMEDIATELY, **even though `BulkWrite`
  has not returned**. This is the bad-landing path: the contained mmap fault latches
  within ~1 s, so `sync_failures_total` becomes ≥1 well inside the oracle window.
- A stall deadline (`bulkWriteStallTimeout`, backstop for a non-faulting stall on a
  full disk) → same truthful failure.

The abandoned `BulkWrite` goroutine is bounded by process lifetime; the store is
already degraded (no further writes), and it is quarantined+rebuilt on the next boot,
so its mid-write state is thrown away. **This is the one genuine architectural
trade-off (see §6) — surfacing a write that never returns REQUIRES not waiting for
it, and badger's `WriteBatch.Flush` takes no context, so the goroutine is abandoned
rather than cancelled.**

### C4. Shared-engine safety + regression coverage (owner req 6)

The import-pending marker is OPT-IN: only `internal/catdb` writes it. `internal/logstore`
(request-history) and any other `storeguard` user never writes it, so
`storeguard.Open` finds no marker for them and their behaviour is byte-identical.
Explicit regression tests: (a) a store with no import-pending marker is never
quarantined by the new path; (b) `logstore.OpenResilientTTL` is unaffected; (c) the
existing CHAOS-50/74 poison/fault/corruption recovery tests stay green; (d) the
`internal/catdb` guard-wall (`TestCommunityDB_EveryBadgerAccessIsGuarded`) stays
green — the marker calls are `storeguard` (filesystem), not badger, like the existing
`recordFault`.

### C5. Deterministic fault-injection tests (owner req 7, 8)

All via injected clock / filesystem / opener and the existing `writeFault`
(`SetBulkWriteFaultForTest`) seam — no reliance on an intermittently-green lab run:

| Fault mode | Test |
|---|---|
| mid-write ENOSPC | `writeFault` faults at write N; store latches degraded; `syncRound` surfaces `sync_failures≥1` within the poll window even though `BulkWrite` is abandoned |
| process kill mid-import | marker present + partial store (no CompleteImport) ⇒ `OpenResilient` quarantines + rebuilds empty |
| power loss | marker written+fsync'd survives; an unsynced marker may be lost ⇒ the import simply re-runs (idempotent) |
| restart, disk STILL full | quarantine once; `spaceRefusal` refuses the import; no new marker; next boot does NOT re-quarantine |
| repeated restart | quarantine prunes to one copy; volume does not grow; store stays empty+stable |
| free-space recovery | `BeginImport`→`BulkWrite`→`CompleteImport` converges; marker cleared |
| intent-write failure | injected marker-write ENOSPC ⇒ `BeginImport` returns error, touches no badger, import refused |
| ACTUAL failure mode (req 8) | a test reproducing the midwrite→contained-fault→no-marker→stuck sequence that FAILS against the pre-fix tree and CONVERGES against the fix |

## 4. Mapping to owner requirements

1. durable intent before risky writes + fail-closed on intent-write failure → **C1**
2. startup detect + quarantine/rebuild → **C2**
3. no post-failure marker write to a full FS → **C1** (intent written before the fill)
4. surface contained faults + stalled BulkWrite even when it never returns → **C3**
5. bounded + idempotent, no loop, no false quarantine, no healthy-state destruction → **C2**
6. Layer-1/admin/identity/CA/policy/request-history intact; storeguard/logstore regression → **C4**
7. deterministic fault-injection tests → **C5**
8. preserve evidence + test the actual failure mode → **§1 + C5 last row**

## 5. What is deliberately NOT changed

- The FAVOURABLE landing path is unchanged (clean `bulk write failed` → in-place
  re-sync); the watchdog only fires on a stall/degrade.
- CHAOS-50's "leave the disk alone while it is full" rule is unchanged — the
  interrupted-import quarantine happens at BOOT, when the disk has recovered, and only
  moves aside (never deletes).
- `OnInspectError` fail-open, Layer-1 priority, and the policy decision on an
  uncategorised host are unchanged.

## 6. Open architectural trade-off for ASTRA

**C3 abandons a blocked `BulkWrite` goroutine** to surface a write that never returns.
The alternatives are worse: waiting for it defeats req 4 (the whole point is it does
not return within the window), and badger's `WriteBatch.Flush` accepts no context, so
there is no clean cancellation. A stalled import holding a goroutine + a badger write
transaction indefinitely is itself a resource the appliance should not carry, so the
decision is to abandon.

**CORRECTION — the held-writer overwrite (ASTRA-confirmed; `review/1528-fdisk-splash-fix`).**
The first design claimed the abandoned goroutine "touches only a store that has already
latched degraded and will be quarantined+rebuilt on the next boot, so its state is
discarded." That is true for the **degrade** path (`storeDegraded()` latches, so the
next `syncRound` skips) but FALSE for the **stall** path: a non-faulting stall on a full
disk does NOT degrade the store, so `storeDegraded()` stays false and the scheduler's
next round would start a SECOND `BulkWrite` while the held writer is still blocked. If
that second writer then reaches `CompleteImport`, the held writer can later flush stale
data over the now-CERTIFIED store — which the import-pending marker would NOT quarantine
(the marker was cleared by the second writer's `CompleteImport`). That is a silent,
restart-surviving data-integrity hazard, not a discarded store.

**Ownership/quiescence correction (shipped on the review branch):** `writeBulkWatched`
abandoning a write (stall OR contained fault) now latches an in-memory `writeAbandoned`
flag, and `syncRound` refuses any further import while it is set — so the held writer is
the SOLE writer, no second writer can certify the store, and the marker `BeginImport`
already wrote makes the next boot quarantine+rebuild and discard the abandoned data. The
latch is in-memory by design: the hazard is intra-process, a restart is the recovery,
and the durable marker carries the interrupted-import state across it. Proven by
`TestSyncRound_QuiescesAfterAbandonedWrite` (feedsync), which FAILS against the pre-fix
tree (`faultCalls 1 -> 2`, a second BulkWrite starts, racing the held writer) and passes
under `-race` with the latch. This narrows the trade-off: abandoning the goroutine is
acceptable because the store it may still touch can never be certified in this process.

## 7. Acceptance

- Deterministic unit/integration tests (§C5) green under `-race -count=2 -shuffle=on`.
- Fast + Deep PR gates green on the new head.
- Lab F-DISK-1 `midwrite` GREEN across **repeated** runs (determinism, not one green
  attempt) — this is the end-to-end proof against the actual failure mode.
- New hash-verified candidate OVA; ASTRA independent ESXi requalification.
- No merge/pilot/release without final acceptance and explicit owner approval.
