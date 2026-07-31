# Culvert Chaos Engineering Review — 2026-07-31

> **Owner:** Chaos Engineering routine · **Status:** Point-in-time review (repeatable)
> **Method:** Targeted-fix pass against the open-findings register as left by the
> 2026-07-26B run (`CHAOS-ENGINEERING-REVIEW-2026-07-26B.md`), which closed
> CHAOS-11 down to a posture-config remainder and promoted **CHAOS-27 / F-12**
> to the top open item. The finding was re-verified live at HEAD (`6810fce`)
> before any code was written, and the verification found the defect to be
> **substantially larger than the register recorded**.
> **Companion change:** the fix ships with this review (see "Fixed in this change").

---

## Executive Summary

The register's top open item was narrow: *"config rollback swallows `Save()`
errors → 200 on a partial-durability apply."* Re-verification at HEAD confirmed
it — and then showed the rollback handler was only the **symptom of a
persistence layer that cannot report failure at all**.

1. **`fileutil.AtomicWrite` is the durable-write chokepoint for the whole
   product** — 50 call sites across 35 files — and **12 of those call sites
   discard its error outright** (`_ = fileutil.AtomicWrite(...)`), because the
   surrounding `Save()` returns nothing: `internal/blocklist` (×4),
   `internal/catgroup`, `internal/urlcat`, `internal/fileblock`,
   `internal/decryptprofile`, `internal/scanner`, `internal/sslbypass`,
   `internal/alerts`. `policy.go`'s `PolicyStore.Save` checks the error only to
   skip its sidecar, then returns void. Nothing above them ever learns.

2. **The only storage health signal was a one-shot boot probe.**
   `probeStorageWritability` (`diagnostics.go`) runs ONCE at startup, caches its
   verdict for the life of the process, and is explicitly contracted never to
   re-run. So the entire class of *after-boot* storage failures — the volume
   remounting read-only, the filesystem or inode table filling, a quota
   engaging, the mount going away — was **structurally unobservable**:

   > Every admin-API config change answered **200**, rendered from memory, was
   > never written to disk, and evaporated on the next restart — while
   > `/api/diagnostics` kept reporting *"data directory writable (verified once
   > at startup)"* and `/metrics` carried no persistence-health series at all.

   For a security appliance this is worse than a crash. A crash is loud. This
   silently converts a policy tightening into a change that survives exactly
   until the next restart, and the operator's evidence — the green dashboard and
   the 200 — actively argues that it landed.

3. **Config rollback was the worst instance of it, because rollback is what an
   operator reaches for when things are already going wrong.** A rollback during
   a disk incident applied in memory, reported `200 rolled_back`, and came back
   after restart as a *mixture* of the old and new configs — matching neither
   the snapshot nor the pre-rollback state, with nothing in the audit trail
   saying so.

**Fixed in this change (CHAOS-45 + CHAOS-27/F-12):** the failure is reported
from the chokepoint itself. `fileutil` gained a write-failure observer seam;
package main counts every failure, names the file, degrades the operator
contract, exports Prometheus series, and fires a rate-limited
`storage_write_failed` alert. Config rollback consumes a scoped view of the
same signal and now answers `500 rolled_back_not_durable` — with `applied:true`
so the caller knows the running config *did* change and retrying is not the fix.

**Posture unchanged, deliberately.** Writes are not made to fail-closed and the
process does not exit. A gateway that stops forwarding traffic because its
config directory filled up would convert a storage fault into a network outage.
What this change removes is the *silence*.

---

## Fixed in this change

### F1 — Durable-write failures are observable (CHAOS-45) · HIGH (visibility)

- **Was (re-verified at HEAD):** `grep -rn "_ = fileutil.AtomicWrite"` → 12
  production call sites across 8 packages, every one of them dropping the error
  on the floor. No counter, no log line, no alert, no metric anywhere in the
  product for a failed durable write.
- **Fix (`internal/fileutil/fileutil.go`):** `SetWriteFailureObserver(fn)` — an
  `atomic.Pointer` seam that every failure branch of `AtomicWrite` notifies via
  `noteWriteFailure(path, err)`, which returns the error unchanged. Callers that
  *do* check the error are unaffected: the observer is notified **in addition
  to**, never instead of, the returned error. The success path performs no
  atomic load, so healthy writes are byte-identical.
- **Fix (`storage_health.go`, new):** package main publishes the observer at
  `init` (so coverage starts before the first store loads) and records:
  a monotonic failure count, the failing file's base name, the error text, and
  the timestamp — all memory-only, on the failing goroutine, because that
  goroutine may hold a store lock.
- **Surfaces:**
  - `checkStorage()` (`diagnostics.go`) now reports observed runtime failures
    **ahead of** the cached boot probe: `fail` while a failure sits inside
    `storageDegradedWindow` (15m), `warn` afterwards (a healed incident still
    means edits made during the window never reached disk), otherwise the
    existing probe verdict. This closes the "one-shot probe caches forever" gap
    without making the handler do disk I/O — the contract that check has always
    kept.
  - `/metrics`: `culvert_storage_write_failures_total` (counter),
    `culvert_storage_write_degraded` (gauge), and
    `culvert_storage_write_last_failure_age_seconds` — the age gauge is **omitted
    entirely** when nothing has failed, because a `0` there would read as "a
    write just failed" on every healthy node in the fleet.
  - `storage_write_failed` webhook alert (added to the alerts supported-event
    contract and the admin UI event picker).
- **Two hazards designed around, both pinned by tests:**
  - **Alert-path recursion/deadlock.** `alerts.Dispatch` → `enqueueRetry` takes
    the retry mutex and can synchronously `AtomicWrite` the retry queue. Firing
    an alert from the observer inline would re-enter that mutex on the *same*
    goroutine — a hard deadlock. Two guards: the alert goes out through a
    `go`-spawning seam (never inline), and a failure whose target is
    `alert_retry_queue.json` is counted and logged but **never alerted** — the
    channel that is itself broken must not be used to report its own breakage.
  - **Alert flood.** A failing disk fails *every* write. Un-gated, this producer
    would saturate the bounded webhook queue and evict every other alert — the
    storage fault would take the alerting channel down with it. The log line and
    the alert are rate-gated to one per `storageWriteAlertInterval` (5m) under
    the same lock that increments the counter; the **counter itself is never
    gated**, so magnitude is preserved. The gate re-arms, so a disk that stays
    broken keeps paging rather than going quiet after one message.

### F2 — Config rollback reports partial durability (CHAOS-27 / F-12) · MED-HIGH

- **Was (re-verified at HEAD):** `applyConfigBackup(b *configBackup)` — no
  return value, seven error-mute `Save()` calls; `rollbackConfigVersion` wrote
  `{"status":"rolled_back"}` with 200 unconditionally.
- **Fix (`configversion.go`):** `applyConfigBackup` returns an `error`.
  Because the stores cannot report, the failures are collected from the F1
  observer through a **scoped collector** (`beginStorageWriteScope`), opened for
  the duration of the apply under the existing `configRollbackMu`.
- **The in-memory apply stays unconditional.** A persistence failure does not
  abort the remaining steps: a *half-applied running config* would be strictly
  worse than a fully-applied one that is not yet durable. What the error carries
  is the fact the caller previously had no way to learn.
- **Handler contract:** `500` + `status:"rolled_back_not_durable"`,
  `applied:true`, `durable:false`, `persist_errors` naming the files. `applied`
  is load-bearing — it tells the operator the running config **has already
  changed**, so the recovery is *fix the disk and re-save*, not *retry the
  rollback*. The healthy path additionally reports `durable:true`. The audit
  entry is appended with `— NOT DURABLE: …`: "who rolled back to what" is an
  incomplete compliance record without "and it did not persist".
- **The CP→DP snapshot is still published** on the failure path: the fleet must
  converge on what this node is actually *enforcing*, and the DP snapshot is a
  separate durability path from the local store files.
- **Scope semantics (recorded):** membership is by TIME, not by goroutine — Go
  has no goroutine-local storage and the fileutil seam is process-wide, so a
  concurrent unrelated write that fails inside the window is attributed to the
  scope. That over-reporting is deliberate and safe in the only direction that
  matters: the scope answers *"is what I just applied durable?"*, and on a
  filesystem failing other writes at that instant the honest answer is no.
  Under-reporting would be the dangerous direction.

### Tests

- `internal/fileutil/writefail_test.go` — observer fires on failure carrying the
  **target** path (not the temp name) and the same error `AtomicWrite` returns;
  **never** fires on success and does not alter the written bytes; nil observer
  is safe; a replaced observer does not double-fire.
- `storage_health_test.go` —
  `TestStorageWriteFailure_CountedAlertedAndSurfaced`;
  `TestCheckStorage_RuntimeFailureOutranksBootProbe` (the core regression: boot
  probe says writable, a live write fails, the contract must flip to `fail` and
  name the file — and must not re-probe);
  `TestCheckStorage_HealedFailureDegradesToWarn`;
  `TestStorageWriteAlert_RateGated` (25 failures → 25 counted, 1 alert; re-arms
  after the interval);
  `TestStorageWriteAlert_RetryQueueNeverAlerts` (recursion guard: counted and
  degrading, never alerted);
  `TestStorageWriteScope_CollectsFailuresWhileOpen` (window boundaries,
  per-file dedup, once-guarded `finish`);
  `TestMetrics_StorageWriteSeries` (including the absent-not-zero age gauge).
- `configversion_rollback_durability_test.go` — plan item **T4**:
  `TestApplyConfigBackup_ReportsPersistenceFailure` (returns a non-nil error
  naming the file **and** still applies the snapshot in memory),
  `TestRollbackConfigVersion_PartialDurabilityIsNot200` (500 +
  `rolled_back_not_durable` + `applied:true` + degraded storage health; the
  pre-fix behaviour was a flat 200),
  `TestRollbackConfigVersion_HealthyPathUnchanged`.
- Test failures are injected via a **missing parent directory**, not a
  `chmod 0500` one: root bypasses mode bits and CI containers run as root, so
  the missing-directory ENOENT is the only uid-independent injection.
- `diagnostics_test.go`'s `withCachedStorageState` helper now also clears the
  process-global failure record on both edges — otherwise any earlier test in
  the package that provoked a real write failure would leak into the
  storage-state assertions (the `-count=2 -shuffle=on` determinism class).

---

## Failure Scenarios examined (this run)

| Scenario | Behavior before | Behavior after |
|---|---|---|
| Data volume remounts read-only after boot | Every save fails silently; API 200s; diagnostics still "writable (verified once at startup)" | Counted, logged, alerted, `storage_path` = **fail** naming the file, `culvert_storage_write_degraded 1` |
| Filesystem / inode table fills up | Same silence; config changes evaporate on restart | Same signals; magnitude visible via the un-gated counter |
| Disk full during a config rollback | `200 rolled_back`; restart comes up on a MIXED config; audit says the rollback succeeded | `500 rolled_back_not_durable` + `applied:true` + `persist_errors`; audit records "NOT DURABLE" |
| Transient failure that then heals | Invisible in both directions | `fail` → `warn` after the window, still naming the incident (edits during it did not land) |
| Disk fails while the alert retry queue is being persisted | n/a (nothing observed) | Counted + degrades health; **never** alerted — no re-entry into the retry mutex, no recursion |
| Sustained failure, thousands of writes | n/a | 1 alert per 5 min (queue protected), every failure counted, gate re-arms so it keeps paging |
| Healthy node | n/a | Byte-identical write path (no atomic load on success); age gauge absent, not zero |
| Rollback with a healthy disk | `200 rolled_back` | `200 rolled_back` + explicit `durable:true` |

## Risk Matrix / Recovery Assessment (updates only)

| Scenario | Before | After |
|---|---|---|
| Post-boot storage failure (CHAOS-45) | ❌ structurally invisible on every surface; changes silently lost at restart | ⚠️ bounded by alarm (webhook), measured (counter + gauge), visible (operator contract names the file). Recovery stays **manual and explicit** — fix the mount/space, re-apply changes made during the window |
| Rollback under partial disk failure (CHAOS-27/F-12) | ❌ 200 over a mixed-state apply; audit trail claims success | ✅ 500 + machine-readable non-durable status + failing files named + audit records it |

**Automatic recovery: deliberately none.** Writes are not retried and the
process does not exit. A durable-write failure means the operator's *intent*
was not recorded, and a retry loop against a full disk is an infinite retry —
which the implementation rules forbid. The recovery path is explicit: the
contract row tells the operator exactly what to check and that changes made
during the window must be re-applied.

## Operational / Security Impact

- **Operational:** zero new configuration. Operators get a Prometheus counter +
  gauge, a `fail`/`warn` row on `/api/diagnostics` that names the file, and a
  webhook event, for a failure class that previously had **no signal at all**.
  The standing register's headline theme — *silent degradation of a control the
  operator cannot see fail* — applied to persistence itself.
- **Security:** the practical exposure is a **policy tightening that silently
  does not survive a restart**. An admin blocks a category, revokes an exempt
  CIDR, or rolls back a bad change during an incident; the API confirms it; the
  node restarts hours later on the pre-change config with nobody aware. That
  window is now alarmed and, for rollback specifically, refused a success code.

## Verification notes (re-checked at HEAD before acting)

- The 12 error-discarding `AtomicWrite` call sites enumerated by grep and each
  read in context to confirm the enclosing `Save()` returns void.
- `probeStorageWritability` read end-to-end; its one-shot/cached contract is
  stated in its own doc comment and pinned by
  `TestApiDiagnostics_NoIOOnRepeatedCalls` — which is why the fix adds a
  *second, independent* signal instead of making the check re-probe.
- The alerts deadlock path traced concretely: `Dispatch` → `enqueueRetry` →
  `retryMu.Lock()` → `saveRetryQueueLocked()` → `AtomicWrite(retryFile)`. This
  is the same hazard `internal/upstream`'s `fireFallbackAlert` documents, and
  the same mitigation shape is used.
- `applyConfigBackup`'s single production caller confirmed
  (`configversion.go:224`); the existing test call sites ignore the new return
  value, which is legal Go and leaves them unchanged.
- `go build ./...`, `go vet ./...`, `gofmt -l` clean; full `go test ./...`
  green; `make api-verify` green after documenting the new 500 in the OpenAPI
  spec and regenerating the bundle.

## Open-findings register — status after this run

Statuses relative to the 2026-07-26B table. Findings not listed are unchanged;
the 2026-07-05 review remains the authority for detailed write-ups.

| ID | Sev | Title | Status |
|---|---|---|---|
| CHAOS-45 | HIGH (vis.) | Durable-write failures are silent; storage health is a one-shot boot probe | **FIXED** (this change) — observer seam + counter/gauge/alert/contract row |
| CHAOS-27 (F-12) | LOW-MED | Config rollback swallows `Save()` errors → 200 on a partial-durability apply | **FIXED** (this change) — T4 is now GREEN |
| CHAOS-27 (relay) | LOW-MED | Double write-block escapes the idle reaper (ID collision — the 07-10 finding) | OPEN — unrelated to the config finding that shares this ID; **the collision should be resolved by renumbering** |
| CHAOS-11 | MED | Upstream-pool all-down fails open to direct | MITIGATED (07-26B) — remainder: `upstream.fail_mode` posture config |
| CHAOS-10 | MED | ClamAV error mid-request fails open silently | MITIGATED (07-26) — remainder: `scan.on_error` posture config |
| CHAOS-15/16 | MED | HMAC rotation no grace window; auth negative caching | OPEN — **now the top open item** |
| CHAOS-18 | MED | DP snapshot applied before local store inits | OPEN |
| CHAOS-08 | MED | No semantic floor on snapshots | OPEN (policy decision required) |
| CHAOS-28 | LOW-MED | Failed rotation-triggered renewal not retried until the 30-day window | OPEN |
| CHAOS-13/14 | MED-LOW | No jitter on legacy feed tickers; no gRPC keepalives on CP/DP channel | OPEN |
| CHAOS-19/20/21 | LOW-MED | Audit-write counter; feed staleness metrics; CA-rotation window race | OPEN — **CHAOS-19 is now cheap**: the audit writer is an append path, but the same observer pattern applies |
| CHAOS-24/25/26 | LOW | Release-platform delta lows | OPEN |

### Suggested next runs

1. **CHAOS-16 / F-11** — stop caching LDAP/OIDC *error-path* negatives, so an
   IdP outage cannot pin a user out past the outage.
2. **CHAOS-19** — the audit writer drops on I/O failure with no counter
   (`internal/audit`); it does not go through `AtomicWrite`, so it needs its own
   counter wired to the same `/healthz` + contract surface this run established.
3. **CHAOS-13/14** — jitter the legacy feed tickers; gRPC keepalives on the
   CP/DP channel.
4. **CHAOS-27 ID collision** — renumber the surviving relay finding (double
   write-block escapes the idle reaper) so the register stops carrying one ID
   for two unrelated defects.

## Residual Risk

- **Detection, not prevention.** A write that fails is still a write that did
  not happen. This change guarantees the operator *learns*; it does not make the
  data land. Deliberate — see the recovery note above.
- **Non-`AtomicWrite` writers stay dark.** The audit JSONL appender
  (`internal/audit`), the request-log rotating writer, and the Badger stores do
  not route through this chokepoint. `internal/reqlog` already counts its own
  drops; audit does not (CHAOS-19).
- **Scope attribution is by time window**, so a rollback can be reported
  non-durable because a *different* store failed concurrently. Safe direction,
  documented at the type.
- **The alert rate gate is a constant** (5m), not operator-tunable — consistent
  with the other chaos-hardening thresholds in the codebase (recorded
  deferral, same class as the release-catalog thresholds).
- **`/healthz` and `/readyz` are untouched.** Whether a storage-degraded node
  should fail readiness is CHAOS-09 / F-08's open policy decision, not this
  run's to make — flipping readiness would restart containers under a disk
  incident, which is exactly the self-inflicted outage this change avoids.
