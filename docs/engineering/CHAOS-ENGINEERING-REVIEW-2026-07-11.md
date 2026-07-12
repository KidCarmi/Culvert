# Culvert Chaos Engineering Review — 2026-07-11

> **Owner:** Chaos Engineering routine · **Status:** Point-in-time review (repeatable)
> **Method:** Targeted-fix pass against the open-findings register from the 2026-07-10
> review (`CHAOS-ENGINEERING-REVIEW-2026-07-10.md`), acting on its #1 ranked next-run
> target. The finding was re-verified live at HEAD (`7c64699`) before any code was
> written. **Companion change:** one fix (three coordinated behaviors) ships with this
> review (see "Fixed in this change").

---

## Executive Summary

This run closed **CHAOS-12 — the top open finding of the last two reviews**: DP node
certificate renewal was **inert until process restart**. `renewDPCert` persisted the
renewed cert/key/CA to disk, but the gRPC channel to the Control Plane only reads TLS
material inside `connect()` — at client construction and failover. The live connection
kept presenting the **old** certificate indefinitely. Consequences, in escalating order:

1. **CA rotation half-broken (zero-touch rotation wasn't).** The rotation-triggered
   renewal "succeeded", but the connection kept the old cert AND the old `RootCAs`
   pool. After the CP's dual-CA cleanup dropped the old CA, the next reconnect
   (network blip, CP restart, failover) failed mTLS in **both directions** — old cert
   no longer accepted by the CP, new CP cert no longer trusted by the stale pool —
   despite fully valid renewed material sitting on disk. Manual restart required;
   the failure surfaces hours or days after the rotation that caused it.
2. **Expiry brick with no warning.** A CP outage spanning the 30-day renewal window
   bricked the DP at cert expiry: the mTLS handshake fails, and a still-registered
   node cannot re-enroll (`controlplane_server.go` rejects re-enrollment of
   registered nodes). Renewal failures were a `logger.Printf` only — no alert, no
   escalation — so operators learned about the brick when the node went dark.
3. **6-hour blind spot at boot.** The renewal loop's first check was one full ticker
   period (6h) after start, so a node powered off past its renewal window idled on a
   nearly-expired cert for another 6 hours before even attempting renewal.

All three are fixed this run, with regression tests. The renewal path now: reconnects
the active CP channel after every successful renewal (re-reading cert/key/CA from
disk — this also completes the zero-touch CA-rotation story), checks immediately at
loop start, and fires a **latched, escalating** `cert_expiry` alert when renewal fails
while the expiry clock is running.

---

## Fixed in this change

### F1 — DP cert renewal inert until restart; expiry brick unwarned (CHAOS-12) · MED-HIGH

- **Was:** `renewDPCert` (`dp_enrollment.go`) wrote the renewed cert/key/CA and
  returned; nothing consulted the new material until the next `connect()` —
  construction or failover only. `dpCertRenewalLoop` waited a full 6h tick before its
  first check, and renewal failures logged one line with no alert regardless of how
  close the cert was to expiry. Hand-verified at HEAD before writing code: the only
  TLS load point is `buildClientTLS` called from `connect()`
  (`controlplane_client.go`), and neither renewal path touches the connection.
- **Fix (three coordinated behaviors):**
  1. **Post-renewal reconnect** — new `DataPlaneClient.reconnectActive()`
     (`controlplane_client.go`) redials the currently-active CP address under the
     client mutex; `connect()` re-reads cert/key/CA from disk, so the renewed
     identity is presented on the wire immediately. Fail-safe by construction:
     `connect()` swaps the connection only after a successful build, so a failed
     redial (e.g. torn files) keeps the existing connection — the reconnect can only
     improve on the pre-renewal state, never drop the CP link. In-flight RPCs on the
     swapped-out connection are safe (gRPC lazy `Close()` — same contract the
     failover path already relies on, documented at `call()`).
  2. **Immediate first check** — `dpCertRenewalLoop` runs `tryRenewDPCert` once at
     start, then every 6h. A node booting inside its renewal window acts at once.
  3. **Latched escalating expiry alert** — `alertDPCertRenewalFailure` fires a
     `cert_expiry` alert (Source `"cluster"`, Host = node ID) when a renewal attempt
     fails with the cert inside the renewal window, latched once per escalation
     level (≤30d → ≤7d → expired; RT-H2 latch precedent) so the 6h ticker cannot
     fire four identical alerts a day. The latch resets on successful renewal; a
     restart re-fires once at the current level (documented, same posture as the
     release-catalog latches). Delivery goes through `deferStartupAlert` because the
     loop's immediate first check can run before `loadPersistentAdminState` populates
     the webhook store (the CHAOS-06 lesson). Rotation-triggered renewal failures on
     a still-fresh cert stay log-only — no expiry clock is running against them.
- **Tests:** `dp_cert_renewal_test.go` —
  `TestReconnectActive_RereadsTLSAndKeepsConnOnFailure` (success swaps the conn from
  current disk material; garbage on disk keeps the old conn — the fail-safe half);
  `TestReconnectActive_NoopOnStubClient`;
  `TestRenewDPCert_PersistsAndReconnects` (end-to-end with a fake CP signing the real
  CSR: renewed cert/CA persisted, connection swapped — pre-fix this assertion fails —
  and alert latch cleared); `TestAlertDPCertRenewalFailure_LatchesPerEscalation`
  (one alert per escalation, fresh certs never alert, reset re-arms);
  `TestDPCertRenewalLoop_ChecksImmediatelyAtStart` (renewal RPC observed at loop
  start, not 6h in — pre-fix this blocks; the failed check on a 5-day cert also
  fires the alert).
- **Accepted residuals:**
  (a) **Offline grace is unchanged** — a CP outage spanning the whole window still
  bricks the node at `NotAfter`; the fix makes the slide visible (escalating alerts
  from day 30, day 7, and at expiry) instead of silent, but the CP-side re-enrollment
  refusal for registered nodes (the recovery path) is a Control-Plane design change,
  registered as the CHAOS-12 remainder.
  (b) A **failed rotation-triggered renewal is not retried until the 30-day window**:
  `caRotationNotify` fires once per fingerprint *change* (`lastSeenCAFingerprint`
  updates immediately, `applySnapshotClusterRuntime`), so if the immediate renewal
  RPC fails, nothing re-triggers it while the cert stays fresh — the node coasts on
  the dual-CA overlap. Newly registered as **CHAOS-28**.
  (c) The alert threshold constants (30d/7d) mirror `certNeedsRenewal`'s existing
  window; making them configurable carries the GUI-parity obligation — recorded
  deferral, mirroring the M1-3 threshold-constants precedent.

---

## Verification notes (re-checked at HEAD before acting)

- `connect()` is the sole TLS load point: `buildClientTLS` → `loadDPNodeKeyPair` +
  `loadCertPool`, called from `NewDataPlaneClient` and `failover()` only.
- `renewDPCert` epoch-fences the response (`dpObserveEpoch`, ADR-0005 S3) **before**
  persisting — the reconnect added this run happens strictly after the fence, so a
  fenced-out zombie CP still cannot cause a reconnect onto its chain.
- The renewal loop is started only from `startDataPlane` (one goroutine per process);
  the new latch state is still mutex-guarded for test/race hygiene.
- `reconnectActive` holds `c.mu` across the redial — the same locking discipline as
  `failover()`; `call()` snapshots the conn pointer under the same mutex (CL-11).

## Recovery assessment (updates only)

| Scenario | Before this change | After |
|---|---|---|
| DP cert renewed while CP reachable | ✅ disk updated, ❌ old cert presented until restart | ✅ renewed cert live within one redial (no restart) |
| CA rotation → renewal → CP dual-CA cleanup → any reconnect | ❌ mTLS fails both directions; manual restart, delayed hours/days from cause | ✅ new cert + new RootCAs live immediately after renewal |
| Node boots inside renewal window (was powered off) | ❌ idles 6h before first check | ✅ renewal attempted at startup |
| CP unreachable across renewal window | ❌ silent slide to expiry brick | ⚠️ still bricks at expiry (CP-side re-enroll refusal — open remainder), but escalating alerts at ≤30d / ≤7d / expired |
| Renewal RPC fails transiently | ✅ retried every 6h | ✅ unchanged, plus latched alert once the expiry clock is running |

## Open-findings register — status after this run

Statuses relative to the 2026-07-10 table. Findings not listed are unchanged (open);
the 2026-07-05 review remains the authority for their detailed write-ups.

| ID | Sev | Title | Status |
|---|---|---|---|
| CHAOS-12 | MED-HIGH | DP cert renewal inert until restart; expiry brick | **FIXED** (this change) — remainder: CP-side re-enrollment path for expired-but-registered nodes |
| CHAOS-28 | LOW-MED | Failed rotation-triggered renewal not retried until the 30-day window (single-shot `caRotationNotify`) | OPEN (new — registered this run) |
| CHAOS-05/07 | MED-HIGH | Corrupt `ui_users.json` / `cluster.json` silently reset (revoked certs revalidate) | OPEN — now the top open finding |
| CHAOS-23 | MED | Freshness watchdog inert for disabled-fetch/permissive deployments | OPEN |
| CHAOS-06 | HIGH | Root-CA load failure → silent fail-open | MITIGATED (07-09); `inspection.required` fail-closed mode still open |
| CHAOS-09 | MED | Readiness blind to CP-poll failure / cert expiry | OPEN |
| CHAOS-10/17 | MED | Scan-error posture inconsistent (fail-open holes) | OPEN |
| CHAOS-11 | MED | Upstream-pool all-down fails open to direct | OPEN (posture decision required) |
| CHAOS-15/16 | MED | HMAC rotation no grace window; auth negative caching | OPEN |
| CHAOS-18 | MED | DP snapshot applied before local store inits | OPEN |
| CHAOS-08 | MED | No semantic floor on snapshots | OPEN (policy decision required) |
| CHAOS-13/14 | MED-LOW | No jitter on legacy feed tickers; no gRPC keepalives on CP/DP channel | OPEN |
| CHAOS-24/25/26 | LOW | Release-platform delta lows | OPEN |
| CHAOS-27 | LOW-MED | Double write-block escapes the idle reaper | OPEN |
| CHAOS-19/20/21 | LOW-MED | Audit-write counter; feed staleness metrics; CA-rotation window race | OPEN |

## Suggested next-run targets (priority order)

1. **CHAOS-05/07** — quarantine-don't-overwrite (`.corrupt.<ts>`) + alert on corrupt
   `ui_users.json` / `cluster.json`; the revoked-cert-amnesia half is security-relevant.
2. **CHAOS-12 remainder** — CP-side recovery path for an expired-but-registered node
   (expiry-bounded re-enrollment or admin-approved rejoin), closing the brick for real.
3. **CHAOS-23** — decouple `evaluateCatalogFreshness()` from the fetch loop.
4. **CHAOS-09** — readiness degrades on sustained CP-poll failure + imminent cert
   expiry (the new alert latch is the natural signal source to surface there).
5. **CHAOS-28** — re-arm rotation-triggered renewal on failure (retry with backoff or
   re-signal while `lastSeenCAFingerprint` ≠ presented-cert issuer).
6. Deep-dive passes never yet done: maintenance-agent host-ops surface,
   `update_cluster.go` failure paths (RISK-011), SAML metadata refresh.

## Residual risk

- The reconnect fires only on the success path of `renewDPCert`, after the epoch
  fence and all three writes — failure paths are byte-identical to before. The only
  new behavior on a live connection is one redial per successful renewal (≈1 per
  cert lifetime, plus one per CA rotation); in-flight RPCs ride the documented gRPC
  lazy-close contract already exercised by failover.
- The alert path reuses the existing `cert_expiry` event type (consumers/webhooks
  already subscribe to it for the inspection CA) rather than minting a new event —
  payload `Source: "cluster"` distinguishes DP-node-cert alerts for filtering.
- Everything else in the open table is unchanged; the 2026-07-05 and 2026-07-10
  registers remain the authority for detailed write-ups.
