# Culvert Chaos Engineering Review — 2026-07-31

> **Owner:** Chaos Engineering routine · **Status:** Point-in-time review (repeatable)
> **Method:** Targeted-fix pass against the open-findings register as left by the
> 2026-07-26B run, which closed CHAOS-11 and named **CHAOS-27 / F-12
> (config-rollback swallows Save errors)** as the top open item and the run's
> first suggested next target. The finding was re-verified live at HEAD
> (`addfbd7`) before any code was written — and re-verification found the defect
> is **materially larger than the register recorded**. **Companion change:** one
> fix ships with this review (see "Fixed in this change").

---

## Executive Summary

The register described CHAOS-27 as a rollback-path defect: `applyConfigBackup`
discards every store's `Save()` error and returns nothing, so a rollback onto a
failing disk answers `200 {"status":"rolled_back"}` having persisted none of it.

That is true, but it is a **symptom**. Re-verification at HEAD found the root
cause one layer down and much wider:

> **Nine of the ten config stores that hold enforcement state discard their
> durable-write error entirely.** The idiom is literally
> `_ = fileutil.AtomicWrite(s.path, data, 0o600)` — the store's `Save()` returns
> `void`, so no caller anywhere in the codebase *can* know the write failed.

On a full, read-only, or permission-broken data directory this produces the
worst failure class an in-line appliance can have — a **completely silent** one:

| Surface | Behaviour before this change |
|---|---|
| API | `200 OK` |
| UI | success toast, new value rendered |
| Runtime | change applied and enforced (in memory) |
| Disk | unchanged — still the OLD value |
| Logs | nothing |
| Metrics | nothing |
| Alerts | nothing |
| `/readyz` | `ready` |
| **Next restart** | **the change silently disappears** |

The stores affected are exactly the ones whose silent revert changes
*enforcement*: `policy_rules` (+ `.meta`), `blocklist`, `blocklist_mode` (the
allow/block flip — a default-deny ⇄ default-allow inversion), the blocklist
`.sources`/`.exceptions`/`.manual` sidecars, `category_groups`,
`url_categories`, `decryption_profiles` (including the `OnInspectError`
fail-open/fail-closed posture), `ssl_bypass`, `content_scan`, and `file_block`.

`PolicyStore.Save` is the sharpest example: it already *checked* the error
(deliberately, so the `.meta` sidecar cannot record a newer version than the
rules on disk) — and then `return`ed without a log line. The most
security-critical store in the product had the failure in hand and dropped it.

This is the standing register's headline theme ("silent fail-open degradation")
applied to durability rather than to a security control: an operator cannot act
on a failure they cannot see, and here they could not see it on *any* surface.

**Fixed in this change.** The write sites now go through a tracked durable-write
primitive; failures are counted per store, logged, alerted on the transition
edge, surfaced as a report-only `/readyz` row and as Prometheus series — and the
rollback API stops reporting an unqualified success it cannot substantiate.

---

## Fixed in this change

### F1 — Durable-write failures are recorded and reported (CHAOS-27 root cause) · HIGH (visibility)

- **Was (re-verified at HEAD):** `grep -rn "_ = fileutil.AtomicWrite"` →
  12 production sites across 8 internal packages; `policy.go:422` checked the
  error and discarded it; `policy.go:385` used the `_ =` form. No store's
  `Save()` returns an error, so the information does not exist above the write.
- **Fix (`internal/fileutil/persist.go`, new):** `AtomicWriteTracked(store,
  path, data, perm) error` — `AtomicWrite` plus accounting. It records
  per-store failure state (consecutive count, monotonic total, last error, a
  global failure sequence) and calls a reporter hook. The package contract stays
  stdlib-only (ADR-0003): the hook is how package main attaches logging and
  alerting without `fileutil` importing anything.
- **Edge-triggered by design.** A store that fails and then succeeds emits a
  recovery event and drops out of the failing set, so the derived signals
  (`/readyz` rows, the Prometheus gauge) describe the CURRENT state of the disk
  rather than accumulating scar tissue. The per-store totals stay monotonic so
  `rate()` still works.
- **Wired at every enforcement-state write site:** `internal/blocklist` (×5),
  `internal/urlcat`, `internal/catgroup`, `internal/decryptprofile`,
  `internal/sslbypass`, `internal/scanner`, `internal/fileblock`, and
  `PolicyStore.Save`/`saveMetaSnapshot` via a new `atomicWriteFileTracked`
  wrapper next to the existing `atomicWriteFile` seam.
- **Deliberately NOT converted:** `internal/alerts`' own retry-queue write. The
  reporter fires alerts, and routing the alert engine's persistence through the
  reporter would be re-entrant. Recorded, not overlooked.

### F2 — Operator-visible on four surfaces (`config_persist.go`, new) · HIGH (visibility)

Mirrors the CHAOS-05/07 state-corruption model in `state_corruption.go`:

1. **Log** — a `WARN` line on every failure naming the store, the path, the
   error, and the consequence ("the running config is NOT on disk and will be
   lost on restart"), plus a line on recovery. User-controlled text is
   `sanitizeLog`-wrapped and `%q`-formatted (CWE-117).
2. **Alert** — `config_persist_failed` on the TRANSITION into failing (not per
   save: a permanently broken disk would otherwise emit one webhook per dedup
   window forever) and `config_persist_recovered` on the way back. Fired through
   `deferStartupAlert`, so a failure during an early startup slice is not
   swallowed by an empty webhook list — the CHAOS-06 lesson. Both events are in
   the alerts supported-event contract and the webhook event picker in the SPA.
3. **`/readyz`** — one report-only `config_persist_<store>` fail row per failing
   store. Report-only matches the CHAOS-06 posture (a durability fault must not
   eject a node whose in-memory config is correct), and the detail is FIXED and
   path-free because `/readyz` is served unauthenticated on the proxy port —
   same disclosure posture as `appendStateFileChecks`. The row KEY names the
   store, so the operator signal survives.
4. **`/metrics`** — `culvert_config_persist_failing_stores` (gauge, emitted
   even when healthy so an alerting rule never depends on a series that only
   appears once things are broken), plus
   `culvert_config_persist_failures_total{store}` (counter) and
   `culvert_config_persist_failing{store}` (gauge) once a store has failed.

### F3 — Config rollback stops reporting an unqualified success (CHAOS-27 headline) · MED-HIGH

- **Was:** `applyConfigBackup(&target)` → `200 {"status":"rolled_back"}`,
  unconditionally, whatever happened on disk.
- **Fix (`configversion.go`):** `applyConfigBackup` now returns the config
  stores whose durable write failed while the snapshot was being applied. It
  gets them from the `fileutil` registry — the global failure sequence is
  sampled either side of the apply (inside `configRollbackMu`, via a deferred
  read ordered before the unlock) and any store failing inside that window is
  named. This avoids changing `Save()`'s signature across ~60 call sites, which
  would silently convert every existing call into an `errcheck` violation that
  the diff-scoped PR lint would not catch.
- **Attribution is conservative by construction** and that is the correct bias:
  a concurrent unrelated save that fails inside the window is also named. The
  fact being reported — "a durable write failed while this operation ran, treat
  the result as not durable" — is true either way, and an under-report puts us
  back in the silent regime. Recorded in the code.
- **Response:** `500` with `{"status":"rolled_back_not_durable", "applied":
  true, "persist_durable": false, "persist_errors":[...]}`. The `500` is
  deliberate — the operator MUST treat the rollback as incomplete — and
  `applied:true` is equally deliberate, because the running config *did* change.
  The audit entry is amended in the same way (`— NOT DURABLE: N config store(s)
  failed to persist (...)`): the compliance record must not read as a clean
  rollback.
- **SPA:** the Rollback button now reads the body on a non-2xx (`apiFetch`, not
  `api`) and distinguishes "rollback failed" from "rollback applied but NOT
  saved to disk — it will be lost on restart", naming the failing stores. The
  OpenAPI contract documents the new 500 (bundle regenerated; `make api-verify`
  green).

### Posture decision (recorded)

**Report, do not refuse.** A failed config write means the RUNNING enforcement
is correct and strictly *newer* than disk. Refusing to serve, or refusing the
API write, converts a durability problem into an availability outage on an
in-line appliance — the wrong trade for a fault the operator can fix while
traffic keeps flowing. What must not happen, and no longer does, is the operator
not knowing. (This is the same reasoning as the CHAOS-06 report-only readiness
rows, and the opposite of the fail-closed posture chosen where a *security*
control degrades.)

### Tests

- `internal/fileutil/persist_test.go` — registry semantics: failure recorded
  with consecutive/total/error; transition-edge accounting; recovery clears the
  failing set while totals stay monotonic; a second healthy write does not
  re-report; `PersistFailuresSince` window attribution (pre-window failures
  excluded, in-window sorted+deduplicated, recovered stores dropped); healthy
  writes byte-identical to `AtomicWrite` and silent; nil-reporter safety; the
  returned error is the real `AtomicWrite` error.
- `config_persist_test.go` — alert fires exactly once per transition and
  re-arms after recovery; healthy writes emit nothing on any surface; the
  `/readyz` row is present, `fail`, path-free, and provably report-only (the
  default verdict is unchanged with and without the failure); the metrics
  exposition emits the zero gauge when healthy and the labelled series when not,
  with the counter monotonic across recovery; **`TestRollback_PartialDurability
  IsReported`** is the named regression for the original defect (500 +
  `rolled_back_not_durable` + `persist_errors:["policy_rules"]`, where before
  the fix the same request produced `200 {"status":"rolled_back"}`);
  `TestRollback_DurableRollbackStillReportsSuccess` pins that the new verdict
  does not turn every rollback into a 500;
  `TestApplyConfigBackup_ReportsFailingStores` exercises the attribution
  primitive directly.

**Fault-injection note.** Every test forces a REAL `AtomicWrite` failure by
writing under a directory that does not exist (`ENOENT` from `os.CreateTemp`),
never a stub. That choice is deliberate: the obvious alternative — `chmod 0500`
on the parent directory — does **not** fail for a root test runner, and CI
containers routinely run as root. A permission-based test here would pass
locally, pass in CI, and prove nothing.

---

## Failure Scenarios examined (this run)

| Scenario | Behaviour after this change |
|---|---|
| Data dir full (`ENOSPC`) during a policy-rule edit | Write fails → WARN log naming store+consequence, `config_persist_failed` alert, `/readyz` row, gauge+counter. Rule stays enforced in memory; operator learns immediately instead of at the next restart |
| Data dir mounted read-only (`EROFS`) | Identical, for whichever store is next written; each store reports independently under its own label |
| Permission-broken data dir (`EACCES`) | Identical |
| Disk recovers (space freed / remount rw) | First successful write per store emits `config_persist_recovered`, clears the `/readyz` row and the gauge; the counter stays monotonic |
| Disk permanently broken, admin keeps editing | Exactly ONE alert per store per failing episode (transition edge). The ongoing state lives on the gauge and the readiness row, so a broken disk cannot become a webhook flood |
| Config rollback with one store failing | `500 rolled_back_not_durable` + `persist_errors`, audit entry marked NOT DURABLE, SPA toast says applied-but-not-saved and names the stores |
| Config rollback, healthy disk | `200 rolled_back`, `persist_durable:true`, `persist_errors:[]` — unchanged behaviour |
| Blocklist mode flip (`allow` ⇄ `block`) not persisted | Now surfaced under `blocklist_mode`. This was the highest-consequence silent revert in the set: it inverts the list's default posture on restart |
| Healthy appliance (the overwhelmingly common case) | Byte-identical write path; one extra map lookup + atomic add per save; no alerts, no readiness rows, `culvert_config_persist_failing_stores 0` |
| Failure during an early startup slice (before webhooks load) | Alert queued by `deferStartupAlert` and delivered at `flushStartupAlerts` — not swallowed (CHAOS-06 contract) |
| Reporter invoked while a store lock is held (`saveExceptions`/`saveManual` hold `b.mu.RLock` across the write) | Reporter only logs and enqueues; it never re-enters a store. Documented at both call sites and in the hook's contract |

## Risk Matrix / Recovery Assessment (updates only)

| Scenario | Before | After |
|---|---|---|
| Config change not durable (CHAOS-27 root cause) | ❌ silent on every surface; discovered at the next restart as an unexplained config regression | ✅ logged + alerted (transition edge) + counted + probe-visible + graphable; recovery is auto-detected and reported |
| Rollback onto a failing disk (CHAOS-27 headline) | ❌ `200 {"status":"rolled_back"}`; audit records a clean rollback that never reached disk | ✅ `500 rolled_back_not_durable` + failing store names in body, audit, and UI toast |
| Recovery path | ❌ none (nothing knew a failure had happened) | ✅ automatic: the next successful write per store clears the state and reports recovery. Manual step is the operator's — fix the filesystem, then re-apply or re-roll-back to force a rewrite |

## Operational / Security Impact

- **Operational:** zero new configuration. Operators gain a Prometheus gauge to
  alert on (`culvert_config_persist_failing_stores > 0`), a per-store counter, a
  `/readyz` row for probes, two webhook events, and log lines that name the
  store and the consequence rather than nothing at all. The recommended alert is
  on the gauge, not the counter — the gauge answers "is my running config
  currently un-persisted?", which is the question that matters at 03:00.
- **Security:** several of these stores ARE the security posture —
  `blocklist_mode` (default-deny ⇄ default-allow), `decryption_profiles`
  (including the autoexclude fail-open opt-in), `ssl_bypass` (what gets
  inspected), `policy_rules`, `file_block`. Before this change, a hardening
  change made on a degraded appliance could be silently un-made by the next
  restart, with the admin UI, API, and audit trail all recording that it had
  been applied. That is a control-integrity gap, not just a durability one.
- **Data integrity:** unchanged on the happy path — this adds accounting around
  `AtomicWrite`, not a new write path. The atomicity/fsync guarantees are
  exactly as before.

## Verification notes (re-checked at HEAD before acting)

- The 12 `_ = fileutil.AtomicWrite` production sites and the two silent
  `atomicWriteFile` sites in `policy.go` were each read individually; the two
  `enrollment.go` `os.WriteFile` backup sites are cert-rotation backups on a
  path that already propagates and were left alone.
- Every store's `Save()` signature confirmed `void` — the errors are not
  discarded by the *callers*, they are destroyed inside the store, which is why
  no caller-side fix was possible without the registry.
- `applyConfigBackup`'s deferred registry read is registered AFTER
  `defer configRollbackMu.Unlock()`, so LIFO ordering runs the sample while the
  rollback mutex is still held. Verified by reading, then by the passing
  attribution test.
- `go build ./...`, `go vet ./...`, `make api-verify`, and the full
  `go test ./...` suite are green; the new tests additionally pass under
  `-race -count=2 -shuffle=on` (the determinism gate that caught the alert-
  goroutine flakes in the CHAOS-10 and CHAOS-11 runs — avoided here by swapping
  the `configPersistAlert` seam for a synchronous local recorder instead of
  listening on the process-global alerts sink).

## Open-findings register — status after this run

Statuses relative to the 2026-07-26B table. Findings not listed are unchanged.

| ID | Sev | Title | Status |
|---|---|---|---|
| CHAOS-27 | MED→HIGH | Config-store durable-write failures are silent; rollback reports success after a partial-durability apply | **MITIGATED** (this change) — all enforcement-state writes tracked; logged/alerted/counted/probe-visible; rollback reports partial durability. Remainder: the residual non-atomic/untracked writers (`cdrpolicy.go`, `internal/scanexcl`, `update_cluster.go` — register ST-10) and `admin_settings.json`/`ui_users.json`, which have their own quarantine story but not yet write-failure tracking |
| CHAOS-27 (tunnel) | LOW-MED | Double write-block escapes the idle reaper | OPEN — unrelated finding sharing the ID (see the ID-collision note in `PRODUCTION-FAILURE-MODE-AUDIT.md`); untouched by this run |
| CHAOS-15/16 | MED | HMAC rotation no grace window; auth negative caching | OPEN — **now the top open item** |
| CHAOS-11 | MED | Upstream-pool fail-open posture config (`upstream.fail_mode`) | OPEN (remainder only) |
| CHAOS-10 | MED | ClamAV error posture config (`scan.on_error`) | OPEN (remainder only) |
| CHAOS-18 | MED | DP snapshot applied before local store inits | OPEN |
| CHAOS-08 | MED | No semantic floor on snapshots | OPEN (policy decision required) |
| CHAOS-28 | LOW-MED | Failed rotation-triggered renewal not retried until the 30-day window | OPEN |
| CHAOS-13/14 | MED-LOW | No jitter on legacy feed tickers; no gRPC keepalives on CP/DP channel | OPEN |
| CHAOS-19/20/21 | LOW-MED | Audit-write counter; feed staleness metrics; CA-rotation window race | OPEN — **CHAOS-19 is now anomalous**: the audit writer is the last high-value state writer still dropping I/O failures with no counter, and the pattern to fix it now exists |
| CHAOS-24/25/26 | LOW | Release-platform delta lows | OPEN |

## Suggested next-run targets (priority order)

1. **CHAOS-16 / F-11** — stop caching LDAP/OIDC *error-path* negatives (denies
   valid credentials for minutes past IdP recovery); bound post-dial LDAP ops.
2. **CHAOS-19** — apply this run's pattern to the audit writer
   (`internal/audit`): a dropped audit write is a compliance failure and is
   still silent. Small diff now that `AtomicWriteTracked` and the reporter exist.
3. **ST-10 residuals** — route `cdrpolicy.go`, `internal/scanexcl`, and
   `update_cluster.go` onto the tracked primitive; extend tracking to
   `admin_settings.json` / `ui_users.json` write failures (their *corruption*
   story is done, their *write-failure* story is not).
4. **CHAOS-11 / CHAOS-10 remainders** — the `upstream.fail_mode` and
   `scan.on_error` posture configs, now that both observability substrates exist.
5. **CHAOS-13/14** — jitter the legacy feed tickers; gRPC keepalives on the
   CP/DP channel (half-open-TCP class).
6. Deep-dive passes never yet done: maintenance-agent host-ops surface (F-05
   persisted op journal), `update_cluster.go` failure paths (RISK-011), SAML
   metadata refresh.

## Residual risk

- **Tracking is process-local and volatile.** A node that fails a write and is
  then restarted loses the failing set (the file on disk is simply stale, with
  no marker). The `/readyz` row and gauge therefore describe *this* process's
  observations. Mitigation is the alert, which is delivered when the failure
  happens; a durable "this store is known-stale" marker would itself need a
  successful write, which is exactly what is unavailable. Accepted, and the same
  class as the existing `direct_fallback` counter's volatility.
- **A store that is never written again stays silently stale.** Tracking is
  triggered by writes; if the disk breaks and nothing calls that store's
  `Save()` again, only the original alert reports it. The readiness row persists
  for the life of the process, which covers the realistic case.
- **Window attribution is conservative** (see F3): a rollback can be reported as
  non-durable because an unrelated concurrent save failed. Over-reporting a real
  disk fault is the intended bias.
- **Report-not-refuse posture** means an appliance can keep serving indefinitely
  with a running config that disk does not have. That is the deliberate trade —
  the alternative converts a fixable durability fault into an outage — and it is
  now fully observable rather than silent.
- **Not every writer is covered yet.** `admin_settings.json`, `ui_users.json`,
  the audit log, the session revocation list, and the ST-10 residual writers are
  outside this change; each is listed above as a follow-up target with the
  pattern now available to apply.
