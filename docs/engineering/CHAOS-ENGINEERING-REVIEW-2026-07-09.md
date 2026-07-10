# Culvert Chaos Engineering Review — 2026-07-09

> **Owner:** Chaos Engineering routine · **Status:** Point-in-time review (repeatable)
> **Method:** Delta pass over the tree at `328c883` against the open-findings register from
> the 2026-07-05 review (`CHAOS-ENGINEERING-REVIEW-2026-07-05.md`). Each finding acted on
> this run was independently re-verified against HEAD before any code was written.
> **Companion change:** four fixes ship with this review (see "Fixed in this change").

---

## Executive Summary

This run closed the **top-priority open finding from the last review** — the CP
config-version reset that silently poisoned DP config sync — plus three more from the
top-six list. All four were re-verified live at HEAD before fixing; none had been fixed
incidentally by the ~30 commits merged since 07-05 (that window was dominated by the
`internal/secret` KEK-containment migration, maintenance-agent socket persistence, and
policy-priority TOCTOU fixes — none of which touch these paths).

**Fixed in this change (with regression tests):**

1. **CHAOS-01 (HIGH)** — CP restart reset the in-memory config-version counter; every
   long-running DP then silently ignored **all** post-restart config changes (new blocks
   included) until the counter caught back up. The counter now persists a durable floor
   and reseeds from `max(floor, wall clock)`.
2. **CHAOS-02 (HIGH)** — SOCKS5 sessions bypassed the per-IP connection limiter entirely;
   one IP could open unbounded concurrent tunnels under a limit the HTTP path enforced.
3. **CHAOS-04 (MED-HIGH)** — a transient OCSP responder outage was cached as REVOKED for
   the full 1h TTL, hard-failing all TLS to the affected upstream for an hour after a
   seconds-long blip. Indeterminate verdicts stay fail-closed but now expire in 2 minutes.
4. **CHAOS-06 (HIGH, partial)** — a configured-but-failed Root-CA load (silent fail-open
   on the primary inspection control) is now visible: `/healthz` gains an
   `ssl_inspection` field, `/readyz` shows a failing (non-gating) `ca` check, and a new
   `ca_load_failed` webhook alert fires — via a deferred-startup-alert queue, because the
   Root-CA slice runs before the webhook store loads. The optional
   `inspection.required` fail-closed mode remains future work.

**Top remaining risks (unchanged posture, re-ranked):** CHAOS-03 (no idle deadline on any
raw relay — now the sole remaining leg of the resource-exhaustion pair), CHAOS-12 (DP cert
renewal inert until restart; expiry during CP outage bricks the node), CHAOS-05/07
(corrupt `ui_users.json` / `cluster.json` silently reset to empty, including the
revoked-cert list).

---

## Fixed in this change

### F1 — CP restart poisons DP config sync (CHAOS-01) · HIGH
- **Was:** `ConfigStore.version` lived only in memory (`controlplane_snapshot.go`),
  incremented from 0 each process start. The DP applies a snapshot only when
  `snap.Version > c.lastVersion` (`controlplane_client.go`). CP at v500 restarts → counter
  restarts at 0 → every running DP holds `lastVersion=500` and hits the "nothing changed"
  short-circuit for all subsequent config — no log line, no metric, `/readyz` green.
  Asymmetric: a DP restart self-healed; a CP restart poisoned every running DP. Recovery
  was manual (restart every DP). The same staleness applied across HA failover: a promoted
  standby published from its own independent (lower) counter.
- **Fix:** `armVersionPersistence` (called at CP activation in `enableControlPlane`,
  which is also the HA-promotion path) seeds the counter with
  **max(persisted floor, wall clock)** and every `Update` persists the floor via
  `atomicWriteFile` (`<dataDir>/cp_config_version.json`), written under the store lock so
  floors land in version order. The two seeds are complementary fail-safes: the floor
  file survives clock rollback (VM snapshot restore, NTP step-back); the clock seed
  survives a deleted/corrupt floor file **and** makes a promoted standby publish above
  anything the old leader ever issued. A corrupt floor is recoverable, never fatal.
- **Tests:** `controlplane_version_persist_test.go` — restart publishes strictly above
  pre-restart versions; persisted floor beats a rolled-back clock; missing floor seeds
  from clock and rewrites a valid floor; corrupt floor falls back to clock and is
  replaced; bare (unarmed) stores keep the old behavior byte-for-byte.
- **Accepted residuals:** (a) simultaneous floor-file loss AND clock rollback below the
  last published version can still re-issue seen versions — documented, requires two
  independent failures; (b) the DP gate is still a bare counter, not a content hash: an
  equal-version different-content snapshot would not apply (pre-existing, unchanged);
  (c) floor persist failure (disk full) is logged, not alerted — the clock seed recovers
  monotonicity at the next restart.

### F2 — SOCKS5 uncovered by the connection limiter (CHAOS-02) · HIGH
- **Was:** `handleSOCKS5` checked the IP filter and rate limiter but never
  `connLimiter.Acquire/Release`; the HTTP/CONNECT path does. One client IP could hold
  thousands of concurrent SOCKS5 tunnels (2 goroutines + 2 FDs each, indefinitely — no
  idle deadline, CHAOS-03) under the rate-limit burst budget.
- **Fix:** `connLimiter.Acquire(clientIP)` at SOCKS5 accept (before the IP-filter check,
  mirroring `handleRequest`), released when the handler unwinds. Over-limit sessions are
  closed pre-negotiation and logged/recorded as `CONN_LIMITED`. Default posture unchanged
  (limiter ships disabled; `Acquire` is a no-op then).
- **Tests:** `socks5_connlimit_test.go` — with max=1: first session negotiates, second
  concurrent session from the same IP is refused, slot releases (no leak) after the first
  closes; disabled limiter admits concurrent sessions unchanged.
- **Accepted residuals:** established tunnels still pin their slot until a peer closes
  (CHAOS-03 idle deadline still open); no global (cross-IP) connection ceiling.
- Also fixed the stale `socks5Server` comment that claimed in-flight tunnels keep
  "per-conn 30s deadlines" — the deadline is cleared before the relay starts (the
  CHAOS-03 note said fix code or comment together; the comment now tells the truth).

### F3 — OCSP outage cached as revocation (CHAOS-04) · MED-HIGH
- **Was:** all-responders-unreachable returned "revoked" (fail-closed — correct posture)
  and then cached that verdict for the full 1h TTL, indistinguishable from a genuine
  revocation. A seconds-long responder blip hard-failed all TLS to the affected
  upstream(s) for an hour after recovery (outage amplification).
- **Fix:** `checkResponders` now distinguishes *confirmed* verdicts from the
  *indeterminate* fail-closed outcome; indeterminate verdicts are cached for
  `indeterminateTTL` (2 min) instead of 1h. Still fail-closed while cached; recovery now
  tracks the dependency, not the cache. The rejection error names the actual condition
  ("revocation status unavailable — failing closed") instead of claiming revocation.
- **Tests:** `internal/ocsp/ocsp_test.go` — unreachable responder fails closed, is cached
  ≤ 2 min (not 1h), still rejects from cache within the window, and is re-queried after
  expiry.
- **Accepted residuals:** during an ongoing responder outage connections to affected
  upstreams still fail (intended fail-closed posture); up to 2 minutes of rejection tail
  after responder recovery.

### F4 — Root-CA load failure invisible (CHAOS-06, visibility half) · HIGH
- **Was:** `rootca_startup.go` logged one warning and continued with SSL inspection
  disabled — for a Zero-Trust SWG, fail-open on the primary control (no MITM scanning,
  DLP, YARA, CDR on TLS traffic), indefinitely, invisible to `/healthz`, `/readyz`,
  alerts, and dashboards. `/readyz` *omitted* the `ca` row entirely in this state.
- **Fix:** the failure is recorded (`sslInspectionLoadError`); `/healthz` gains
  `ssl_inspection: ready|unavailable|load_failed`; `/readyz` shows
  `ca: fail` with the load error as a **report-only** check (readiness verdict
  deliberately unchanged — the proxy still serves as a plain forward proxy; posture
  mirrors `policy_loaded`); a new `ca_load_failed` alert event fires. Because the Root-CA
  slice runs before the webhook store loads (`loadPersistentAdminState` is the last
  slice), a small **deferred-startup-alert queue** (`deferStartupAlert` /
  `flushStartupAlerts`, flushed as step 7 of `loadPersistentAdminState`) carries the
  alert until delivery is possible — reusable by any future early-init producer. The
  event is in the webhook UI's event list and the `internal/alerts` catalog (GUI parity).
- **Tests:** `rootca_failure_visibility_test.go` — alert queued (not lost) until flush,
  then delivered with event/source intact, passthrough after flush; `/readyz` shows the
  fail row with detail and provably does not change the readiness verdict; `/healthz`
  distinguishes `load_failed` from `unavailable`.
- **Accepted residuals:** (a) no `inspection.required` fail-closed mode yet (refuse
  TLS-bypass service when a CA was configured but failed) — that is a config surface with
  GUI-parity obligations, deliberately not rushed into this change; (b) the alert covers
  the *startup* load path; runtime rotation-persist failures (CA-2/CA-13 from the
  2026-07-04 review) remain open and silent.

---

## Open-findings register — status after this run

Statuses relative to the 2026-07-05 matrix. Findings not listed are unchanged (open).

| ID | Sev | Title | Status |
|---|---|---|---|
| CHAOS-01 | HIGH | CP restart resets config version; DPs silently ignore post-restart config | **FIXED** (this change) |
| CHAOS-02 | HIGH | SOCKS5 has no per-IP connection limit | **FIXED** (this change) |
| CHAOS-04 | MED-HIGH | OCSP outage cached as REVOKED for 1h | **FIXED** (this change) |
| CHAOS-06 | HIGH | Root-CA load failure silently disables SSL inspection | **MITIGATED** — alert + `/healthz` + `/readyz` visibility shipped; `inspection.required` fail-closed mode still open |
| CHAOS-03 | HIGH | No idle/half-open deadline on any raw relay | OPEN — now the top open finding; M-sized, touches all four relay paths |
| CHAOS-12 | MED-HIGH | DP cert renewal inert until restart; expiry brick | OPEN |
| CHAOS-05/07 | MED-HIGH | Corrupt `ui_users.json` / `cluster.json` silently reset (revoked certs revalidate) | OPEN |
| CHAOS-09 | MED | Readiness blind to CP-poll failure / cert expiry | OPEN (CHAOS-06 fix added the CA row; CP-poll + cert-expiry gates still missing) |
| CHAOS-10/17 | MED | Scan-error posture inconsistent (fail-open holes) | OPEN |
| CHAOS-11 | MED | Upstream-pool all-down fails open to direct | OPEN (documented posture decision required) |
| CHAOS-15/16 | MED | HMAC rotation no grace window; auth negative-caching of outages | OPEN |
| CHAOS-18 | MED | DP snapshot applied before local store inits | OPEN |
| CHAOS-08 | MED | No semantic floor on snapshots | OPEN (policy decision required) |
| CHAOS-13/14 | MED-LOW | No jitter; no gRPC keepalives on CP/DP channel | OPEN |
| CHAOS-19/20/21 | LOW-MED | Audit-write counter; feed staleness metrics; CA-rotation window race | OPEN |

### Delta scan of code merged since 2026-07-05

Commit-level review (not a full re-audit): the window was dominated by (a) the
`internal/secret` KEK-containment migration — refactor of already-fail-closed key-at-rest
paths, migration claims byte-equivalent behavior and ships its own executable proofs
(`test: pin the review claims with executable proofs`); (b) maintenance-agent socket
persistence + installer TOML robustness — host-ops surface, outside the proxy data path;
(c) policy-priority TOCTOU fixes (`PolicyStore.Add`) — closes a concurrency defect,
consistent with this review's goals; (d) an appliance-install→catalog-update E2E. No new
long-lived goroutines, no new fail-open branches, and no new unfsynced persistence paths
were introduced in the window as far as commit-level inspection shows. The
maintenance-agent surface remains un-deep-dived by any chaos pass (carried forward).

---

## Recovery assessment (updates only)

| Scenario | Before this change | After |
|---|---|---|
| CP restart with running DPs | ❌ silent config staleness on all DPs, manual DP restarts | ✅ automatic — version floor + clock seed; DPs keep applying |
| HA standby promotion | ❌ same staleness if standby's counter was behind | ✅ automatic — promotion path reseeds above old leader's counter |
| SOCKS5 tunnel flood from one IP | ❌ unbounded (limiter bypassed) | ✅ bounded when limiter enabled (still off by default; CHAOS-03 idle reaping open) |
| OCSP responder blip | ❌ 1h of hard-fail after recovery | ✅ ≤2 min tail, still fail-closed during the outage |
| Root CA unloadable | ❌ inspection off until fixed, zero signals | ⚠️ still off (fail-open) but alerted + visible on /healthz + /readyz; fail-closed mode pending |

---

## Required tests (shipped with this change)

- `controlplane_version_persist_test.go` — 5 tests (restart survival, clock-rollback
  floor, missing/corrupt floor reseed, unarmed-store no-op).
- `socks5_connlimit_test.go` — 2 tests (enforcement + release, disabled no-op).
- `internal/ocsp/ocsp_test.go` — indeterminate short-TTL regression (+ signature update
  of two existing cache tests).
- `rootca_failure_visibility_test.go` — 3 tests (deferred alert queue/flush/passthrough,
  `/readyz` report-only fail row, `/healthz` state field).

## Suggested next-run targets (priority order)

1. **CHAOS-03** — idle deadline (re-armed on activity) across the four raw-relay paths;
   the `stallDetectReadCloser` pattern is already in-tree. Now the highest-value open item.
2. **CHAOS-12** — reconnect/hot-swap TLS after DP cert renewal; expiry-approaching alert
   while CP unreachable.
3. **CHAOS-05/07** — quarantine-don't-overwrite (`.corrupt.<ts>`) + alert on corrupt
   `ui_users.json` / `cluster.json`.
4. **CHAOS-06 (remainder)** — `inspection.required` fail-closed mode (config + API + UI
   panel per GUI-parity).
5. **CHAOS-09** — readiness gates for sustained CP-poll failure + imminent node-cert expiry.
6. Deep-dive passes never yet done: maintenance-agent host-ops surface,
   `update_cluster.go` failure paths (RISK-011), SAML metadata refresh.

## Residual risk

- The four fixes alter failure-path behavior only; happy paths are unchanged (the
  CHAOS-01 fix changes published version *numbers* — they are larger (epoch-seconds
  scale) but the contract everywhere is strictly-greater comparison, verified against the
  DP gate, the last-good persist path, and `/api/cluster` reporting).
- CHAOS-06 remains fail-open by design until `inspection.required` ships; the mitigation
  is detection latency (alert + probes), not elimination.
- Everything in the open-findings table above is still open; the 2026-07-05 review's
  detailed write-ups remain the authority for those.
