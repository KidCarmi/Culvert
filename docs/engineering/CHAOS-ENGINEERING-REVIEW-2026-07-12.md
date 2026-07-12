# Culvert Chaos Engineering Review — 2026-07-12

> **Owner:** Chaos Engineering routine · **Status:** Point-in-time review (repeatable)
> **Method:** Targeted-fix pass against the open-findings register from the 2026-07-11
> review (`CHAOS-ENGINEERING-REVIEW-2026-07-11.md`), acting on its #1 ranked next-run
> target. The finding was re-verified live at HEAD (`b0dd056`) before any code was
> written. **Companion change:** one fix ships with this review (see "Fixed in this
> change").

---

## Executive Summary

This run closed **CHAOS-05/07 — the top open finding after the 07-11 run**: a
present-but-corrupt `ui_users.json` (admin roster + TOTP enrollments) or
`cluster.json` (enrolled-node roster + **revoked-cert list**) was logged, skipped,
and then **overwritten by the next save** — the only copy of the data destroyed with
one startup log line as the only trace. The two halves differ in blast radius:

1. **CHAOS-05 (availability/lockout).** Corrupt roster → empty in-memory roster →
   legacy/env fallback credentials silently become live. The next admin mutation —
   or the `--reset-password` one-shot, whose stated purpose is *recovery* and which
   ignores the load error (`main.go:394`) — atomically overwrites the corrupt file.
   Every admin account and TOTP enrollment is gone permanently.
2. **CHAOS-07 (security regression).** Corrupt cluster DB → "starting fresh" →
   empty `Revoked` list → `IsRevoked` **revalidates revoked DP certificates**. A
   deprovisioned (possibly compromised) node can rejoin the cluster, and the next
   save destroys the only record that its cert was ever revoked.

Both now **quarantine instead of losing the evidence**: on a parse failure the
loader renames the corrupt file to `<path>.corrupt.<unixnano>` *before* returning
(same-directory rename — atomic, never a copy), fires a `state_file_corrupt` alert
through the deferred-startup-alert queue, and records the failure for `/readyz` as a
report-only fail row. The F4 fix (2026-07-05, fsynced atomic writes) removed the
main *cause* of torn files; this run fixes the *response* to one.

Boot still proceeds with an empty store (survivable: env fallback creds /
re-enrollment), so the revoked-cert amnesia window persists **until the operator
restores the quarantined file** — but it is now alerted, visible on `/readyz`, and
recoverable. The full fail-closed posture (refuse to boot on corrupt `cluster.json`)
is a product decision recorded as the remainder.

---

## Fixed in this change

### F1 — Corrupt state files silently reset then overwritten (CHAOS-05/07) · MED-HIGH

- **Was (re-verified at HEAD before writing code):**
  - `LoadUIUsersFile` (`store.go`) returned the raw parse error; `loadAuth`
    (`auth_startup.go:39-43`) logged one line and continued with an empty roster;
    `SaveUIUsersFile` later overwrote the file in place. The `--reset-password`
    one-shot (`main.go:389-404`) was a second, *guaranteed* destruction path:
    `_ = cfg.LoadUIUsersFile()` → `SaveUIUsersFile()` — found this run while
    enumerating callers.
  - `ClusterStore.Load` (`enrollment.go`) returned `parse cluster state: …`;
    `loadCluster` (`cluster_startup.go:32-33`) logged "starting fresh"; any later
    `Save()` (heartbeats save periodically) overwrote the roster + revocations.
- **Fix (`state_corruption.go`, hooks in both loaders):**
  `quarantineCorruptStateFile(kind, path, parseErr)` — called from the parse-failure
  branch of `LoadUIUsersFile` and `ClusterStore.Load`, so **every** caller (startup
  loaders, the reset one-shot, any future caller) is covered at the engine layer:
  1. **Quarantine** — `os.Rename` to `<path>.corrupt.<unixnano>` in the same
     directory (same filesystem ⇒ atomic). If the rename itself fails, the detail
     says so explicitly ("the next save WILL OVERWRITE it; copy it elsewhere now")
     and the alert/record still fire.
  2. **Alert** — `state_file_corrupt` (Source `"storage"`) via `deferStartupAlert`:
     both loads run before `loadPersistentAdminState` populates the webhook store
     (the CHAOS-06 lesson), so a direct `fireAlert` would fan out to an empty list
     and vanish.
  3. **Probe visibility** — recorded in `stateCorruptionByKind`; `handleReady`
     surfaces `state_file_ui_users` / `state_file_cluster` as **report-only** fail
     rows (the CHAOS-06 `ca`-row posture: visible to probes, never flaps the LB —
     the node genuinely still serves).
  - Read errors (EACCES/EIO) deliberately do **not** quarantine: content may be
    intact, and `os.Rename` needs only directory permissions, so quarantining could
    move a healthy file aside on a transient permission problem. Only a file that
    was **read and failed to parse** is treated as corrupt. Missing files keep the
    silent first-run path byte-identical.
- **Tests:** `state_corruption_test.go` —
  `TestLoadUIUsersFile_CorruptRosterQuarantinedNotOverwritten` (the exact pre-fix
  destruction scenario: corrupt load → quarantine → `SetUIUser`+`SaveUIUsersFile` →
  evidence byte-identical; alert queued until flush);
  `TestClusterStoreLoad_CorruptDBQuarantined_RevocationEvidencePreserved` (torn
  write through the revoked-cert list; "starting fresh" save cannot destroy the
  revoked serial);
  `TestLoadUIUsersFile_MissingFile_NoQuarantineNoAlert` (first-run path unchanged);
  `TestQuarantineCorruptStateFile_RenameFailureStillAlertsAndRecords` (fallback
  branch);
  `TestHandleReady_SurfacesStateFileCorruption` (row present + fail + quarantine
  path in detail; readiness verdict provably unchanged — report-only).
- **Accepted residuals:**
  (a) **Boot proceeds with an empty store.** Refuse-to-boot (or boot-to-locked-admin)
  on corrupt `cluster.json` is the fail-closed endgame; it can take a fleet down on
  a single bad sector, so it needs an owner decision — registered as the
  **CHAOS-05/07 remainder** (mirrors the P0-3 remainder in
  `PRODUCTION-FAILURE-MODE-AUDIT.md`).
  (b) **Revoked-cert amnesia persists until restore.** The window is now alerted and
  bounded by operator response time instead of permanent and silent.
  (c) **Lower-severity stores still silent-reset** (`internal/nodegroup`,
  `admin_settings.json`, blocklist `.sources`, alert retry queue, hit counters —
  `metrics.go:129`). Same pattern, much smaller blast radius; extending the helper
  to them is mechanical now that it exists — registered as the CHAOS-05 tail.
  (d) Quarantine files accumulate if corruption repeats (one per boot). Not bounded;
  a repeating corruption implies failing storage, where more evidence is the right
  bias.

---

## Verification notes (re-checked at HEAD before acting)

- Caller enumeration for `LoadUIUsersFile`: `loadAuth` (boot), `--reset-password`
  one-shot (`main.go:394` — ignores the error and saves), tests. For
  `ClusterStore.Load`: `loadCluster` only. Hooking the engines rather than the
  loaders covers all of them and any future caller.
- `ClusterStore.Load` assigns `cs.path` *before* reading, so the post-quarantine
  `Save()` (the "starting fresh" persistence) targets the original path — the
  quarantined sibling is out of its line of fire. Verified by test.
- `Load` holds `cs.mu` across the quarantine call; the helper touches only its own
  mutex + `os.Rename` + the alert queue — no lock-order interaction.
- `/readyz` assertions elsewhere in the suite are substring-based (checked
  `misc_test.go`, `rootca_failure_visibility_test.go`, D0) — additive report-only
  rows cannot break them; the corruption record has a test-isolation reset
  (`resetStateCorruption`) mirroring the PR3d fence-pollution lesson.
- `{}`-shaped roster files (valid JSON, not a valid roster) already returned an
  error (`coldstart_uiusers_test.go` pins it); they now quarantine too — correct,
  since a roster that parses to nothing is indistinguishable from corruption at
  this layer.

## Recovery assessment (updates only)

| Scenario | Before this change | After |
|---|---|---|
| Corrupt `ui_users.json`, admin then edits any user | ❌ roster permanently destroyed, silent | ✅ evidence quarantined; alert + `/readyz` row; restore = move file back + restart |
| Corrupt `ui_users.json`, operator runs `--reset-password` (the documented recovery move) | ❌ roster permanently destroyed by the recovery itself | ✅ quarantine happens inside the loader — reset writes a fresh file, evidence intact |
| Corrupt `cluster.json` on CP boot | ❌ revoked DP certs validate again; next heartbeat save destroys the record | ⚠️ amnesia until restore (alerted, visible), evidence preserved — fail-closed refusal is the recorded remainder |
| Corrupt file + quarantine rename also fails (read-only dir) | ❌ n/a (no quarantine existed) | ✅ alert + row still fire, detail says the evidence is still exposed |
| Missing state file (first run) | ✅ silent bootstrap | ✅ unchanged (pinned) |

## Open-findings register — status after this run

Statuses relative to the 2026-07-11 table. Findings not listed are unchanged; the
2026-07-05 review remains the authority for their detailed write-ups.

| ID | Sev | Title | Status |
|---|---|---|---|
| CHAOS-05/07 | MED-HIGH | Corrupt `ui_users.json` / `cluster.json` silently reset then overwritten | **FIXED** (this change) — remainder: refuse-to-boot posture decision; lesser stores still silent-reset |
| CHAOS-12 | MED-HIGH | DP cert renewal inert until restart | FIXED (07-11) — remainder: CP-side re-enrollment for expired-but-registered nodes (now the top open item) |
| CHAOS-23 | MED | Freshness watchdog inert for disabled-fetch/permissive deployments | OPEN |
| CHAOS-06 | HIGH | Root-CA load failure → silent fail-open | MITIGATED (07-09); `inspection.required` fail-closed mode still open |
| CHAOS-09 | MED | Readiness blind to CP-poll failure / cert expiry | OPEN |
| CHAOS-10/17 | MED | Scan-error posture inconsistent (fail-open holes) | OPEN |
| CHAOS-11 | MED | Upstream-pool all-down fails open to direct | OPEN (posture decision required) |
| CHAOS-15/16 | MED | HMAC rotation no grace window; auth negative caching | OPEN |
| CHAOS-18 | MED | DP snapshot applied before local store inits | OPEN |
| CHAOS-08 | MED | No semantic floor on snapshots | OPEN (policy decision required) |
| CHAOS-28 | LOW-MED | Failed rotation-triggered renewal not retried until the 30-day window | OPEN |
| CHAOS-13/14 | MED-LOW | No jitter on legacy feed tickers; no gRPC keepalives on CP/DP channel | OPEN |
| CHAOS-24/25/26 | LOW | Release-platform delta lows | OPEN |
| CHAOS-27 | LOW-MED | Double write-block escapes the idle reaper | OPEN |
| CHAOS-19/20/21 | LOW-MED | Audit-write counter; feed staleness metrics; CA-rotation window race | OPEN |

## Suggested next-run targets (priority order)

1. **CHAOS-12 remainder** — CP-side recovery path for an expired-but-registered
   node (expiry-bounded re-enrollment or admin-approved rejoin): the last
   silent-brick scenario in the cluster domain.
2. **CHAOS-09** — readiness degrades on sustained CP-poll failure + imminent cert
   expiry (the 07-11 alert latch is the natural signal source).
3. **CHAOS-23** — decouple `evaluateCatalogFreshness()` from the fetch loop.
4. **CHAOS-05/07 remainder** — take the refuse-to-boot posture decision to the
   owner (fleet-down risk vs. revoked-cert amnesia window); extend
   `quarantineCorruptStateFile` to the lesser stores (mechanical now).
5. **CHAOS-10/17** — `scan.on_error` posture config + `culvert_scan_errors_total`.
6. Deep-dive passes never yet done: maintenance-agent host-ops surface,
   `update_cluster.go` failure paths (RISK-011), SAML metadata refresh.

## Residual risk

- The new code runs only on the parse-failure branch of two loaders — success and
  missing-file paths are byte-identical to before (pinned by the existing
  `coldstart_uiusers_test.go`, which passes unmodified).
- The quarantine rename is the only new filesystem side effect; it targets the same
  directory the loader just read from, and its own failure degrades to
  log+alert+record (tested).
- `state_file_corrupt` reuses the deferred-startup-alert queue (CHAOS-06 machinery,
  already regression-tested) rather than new delivery plumbing.
- `/readyz` rows are report-only by construction — the readiness verdict is computed
  from `allOK`, which the new loop never touches (pinned by
  `TestHandleReady_SurfacesStateFileCorruption`).
