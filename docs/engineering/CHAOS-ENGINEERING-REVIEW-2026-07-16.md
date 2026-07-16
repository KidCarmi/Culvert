# Culvert Chaos Engineering Review — 2026-07-16

> **Owner:** Chaos Engineering routine · **Status:** Point-in-time review (repeatable)
> **Method:** Targeted-fix pass against the open-findings register from the 2026-07-12
> review (`CHAOS-ENGINEERING-REVIEW-2026-07-12.md`), acting on its #1 ranked next-run
> target. The finding was re-verified live at HEAD (`dbd448b`) before any code was
> written. **Companion change:** one fix ships with this review (see "Fixed in this
> change").

---

## Executive Summary

This run closed **the CHAOS-12 remainder — the #1 ranked open item for the last two
runs**: an enrolled DP node whose certificate had already **expired** was permanently
bricked with no recovery path. The 07-11 run fixed renewal (hot reload, immediate
first check, escalating alerts), but a CP outage spanning the whole 30-day renewal
window still slid the node to `NotAfter`, and from there every door was locked:

1. **mTLS is dead** — the CP's TLS handshake rejects the expired client cert, so the
   node cannot reach any RPC.
2. **Renewal is dead** — `RenewCert` requires that same handshake (`verifyNode` cert
   pinning), so the renewal path is unreachable by construction.
3. **Re-enrollment was denied** — `admitEnrollment` blanket-denied any registered,
   non-revoked node ID (`controlplane_server.go`), so even an operator standing at
   the console with a fresh enrollment token got `enrollment denied`. The only
   recovery was the undocumented revoke-then-re-enroll dance — and nothing told the
   operator that; the DP just logged connection failures forever.

The fix is **expiry-bounded re-enrollment**: the duplicate-node gate now admits a
registered node exactly when its certificate is expired per the CP clock — the same
clock the CP's own TLS handshake uses to reject that cert — so at no moment can both
a live cert and an enrollment token claim the same node ID. Everything else about
enrollment is unchanged: a fresh **admin-issued token** is still mandatory (recovery
stays operator-gated), the per-IP rate limit still applies, the CSR CommonName gate
still binds the cert to the claimed identity, and the denial for live-cert nodes is
byte-identical (token deliberately NOT consumed on that path). The swap is never
invisible: the superseded serial is added to the CRL, and the event is logged,
audited (`cluster.node.reenroll-expired`), and alerted (`cluster_node_reenrolled`,
GUI-subscribable).

---

## Fixed in this change

### F1 — Expired-but-registered DP node permanently bricked (CHAOS-12 remainder) · MED-HIGH

- **Was (re-verified at HEAD before writing code):**
  - `admitEnrollment` (`controlplane_server.go`): `GetNode(req.NodeID)` + `Status !=
    "revoked"` ⇒ unconditional `PermissionDenied` — expiry never consulted.
  - `RenewCert` requires `verifyNode` (mTLS cert pinning) — unreachable with an
    expired cert; `connect()`/`buildClientTLS` on the DP side present the expired
    cert and the handshake fails both ways.
  - Recovery required knowing to `RevokeNode` first (revoked nodes may re-enroll) —
    an undocumented two-step that also poisons the node's status history.
- **Fix (`controlplane_server.go`, `enrollment.go`):**
  1. **Expiry gate** — `nodeCertExpired(n)`: non-zero `CertExpiry` strictly in the
     past per the CP clock. Zero `CertExpiry` (unknown/legacy registration) is
     treated as *not* expired — **fail closed on missing data**, pinned by the
     pre-existing `TestEnroll_NodeExistenceLeak` (registers a zero-expiry node and
     expects denial), which passes unmodified.
  2. **Same admission terms as everyone else** — the expired-node path continues
     into `ValidateAndConsumeToken` (admin-issued, single-use, prefix/CIDR/TTL
     enforced, atomic consumption) and `validateEnrollCSR` (CN = node ID). The
     denial for live-cert nodes happens **before** token consumption, exactly as
     before — a probe against a live node cannot burn a token.
  3. **Label continuity** — admin-assigned `Labels` carry forward to the new
     registration: they are config (node-group membership → bandwidth/QoS
     policies), and dropping them would silently detach the node from its groups —
     an operational surprise in its own right.
  4. **Evidence trail** (`recordExpiredNodeReenrollment`) — superseded serial
     appended to the CRL via the new `ClusterStore.RevokeSerial` (status untouched;
     `RevokeNode` remains the operator path that retires a node), plus logger line,
     audit entry `cluster.node.reenroll-expired` (actor = source IP), and a
     `cluster_node_reenrolled` alert through the new `enrollAlertFire` seam
     (mirrors `releaseAlertFire`). The alert event is subscribable from the GUI
     webhook modal (exact-name filter class), and `state_file_corrupt` — fired
     since 07-12 but missing from the modal — was added alongside it (parity gap
     from the previous run).
- **Why the gate cannot widen the attack surface:** the CRL/pinning story is
  unchanged — `verifyNodeCert` pins the *registered* serial, so the superseded cert
  is excluded everywhere the moment the new one registers (the CRL entry is
  defense-in-depth and the durable record). A token holder could already enroll
  arbitrary **new** nodes into the cluster and re-enroll **revoked** node IDs; the
  only new capability is claiming an ID whose cert is provably unusable — the same
  outcome the revoke-dance already permitted, minus the operator friction, plus an
  audit/alert trail the dance never had.
- **Tests:** `enroll_expired_reenroll_test.go` —
  `TestEnroll_ExpiredNodeReenrollsWithToken` (full RPC path: new serial, connected,
  labels preserved, old serial CRL'd, new serial not, audit content-asserted, one
  alert); `TestEnroll_ValidCertNodeStillDenied_TokenUnconsumed` (denial
  byte-identical, no leak, no revocation, no alert, and the token still enrolls a
  fresh node afterwards — consumption-ordering pinned);
  `TestEnroll_ZeroExpiryNodeStillDenied` (fail-closed on unknown expiry);
  `TestEnroll_ExpiredNodeBadTokenDenied_RegistrationUntouched` (a bad token cannot
  touch the registration, the CRL, or the alert stream).
- **Accepted residuals:**
  (a) **Recovery is deliberately manual.** The node cannot self-heal — someone must
  mint a token (admin API/UI) and run `-enroll` on the node. Automatic rejoin
  without a fresh secret would convert the expiry gate into an authentication
  bypass; the alert chain from the 07-11 fix (≤30d / ≤7d / expired) exists precisely
  to page the operator before and at the brick.
  (b) **Denial-shape observation.** An unauthenticated prober could already
  distinguish "registered, non-revoked" (bare `enrollment denied`) from "unknown
  node" (`enrollment denied: <token error>`); the boundary now places expired nodes
  in the second class. No node **names** leak (pinned by the existing leak test);
  accepted as an information-shape delta of the recovery feature.
  (c) **`EnrolledAt`/`EnrolledBy` reset** to the new enrollment — it *is* a new
  identity issuance; the audit entry preserves the historical linkage.
  (d) **HA/clock caveat:** the gate runs on the acting CP's clock — the same clock
  that terminates its TLS. Issuance is lease-fenced (ADR-0005), so a zombie leader
  with a skewed clock cannot sign at all; a *legitimately elected* leader with a
  wildly wrong clock mis-times both TLS and this gate identically (no new
  inconsistency introduced).

---

## Failure Scenarios examined (this run)

| Scenario | Behavior after this change |
|---|---|
| CP unreachable across entire 30-day renewal window; DP cert expires | Escalating alerts (07-11) → operator mints token → node re-enrolls, labels intact; superseded serial CRL'd; audit + alert on the swap |
| Attacker with stolen *valid* token targets a live node's ID | Denied before token consumption — byte-identical to pre-fix; token not burned |
| Attacker with stolen token targets an expired node's ID | Succeeds — identical in power to enrolling a new node (already possible with a token) or the revoke-dance; now audited + alerted, superseded serial CRL'd |
| Attacker without a valid token targets an expired node | Denied at token validation; per-IP rate limit applies; registration/CRL untouched |
| Legacy registration with zero `CertExpiry` | Still denied (fail closed on unknown) |
| CP clock rollback after a re-enrollment | Old cert would pass raw TLS again, but `verifyNodeCert` pins the NEW serial and the CRL carries the old one — both gates hold |

## Risk Matrix / Recovery Assessment (updates only)

| Scenario | Before | After |
|---|---|---|
| Expired-but-registered DP node | ❌ permanent brick; recovery = undocumented revoke+re-enroll dance, silent | ✅ token-gated re-enrollment; audited, alerted, CRL evidence; labels survive |
| Node-existence leak via enrollment errors | bare vs detailed denial distinguishes registered/unknown | unchanged shape; expired nodes reclassified to the recoverable side (residual b) |
| Superseded-cert lifetime | n/a (no supersede path) | pinned out by serial + CRL'd at swap time |

## Operational / Security Impact

- **Operational:** the last silent-brick in the cluster domain now has a
  self-service-shaped (but operator-gated) recovery: mint token → `-enroll`. The
  runbook step "revoke the node first" is obsolete; node-group membership and
  bandwidth policies survive the recovery (label carry-forward).
- **Security:** no new trust path — the enrollment token remains the sole authority,
  and the gate opens only when the cert-based path is provably dead on the same
  clock. Monitoring gains a dedicated, GUI-subscribable alert for every identity
  swap; the audit ring gains `cluster.node.reenroll-expired` with the source IP as
  actor.

## Verification notes (re-checked at HEAD before acting)

- Caller enumeration: `admitEnrollment` is called only from `Enroll`;
  `ha_fencing_test.go` reaches `Enroll` with `{}` but is fenced before admission.
- Zero-expiry fail-closed is pinned by the *existing* `TestEnroll_NodeExistenceLeak`
  (its fixture node has no `CertExpiry`) — it passes unmodified, proving the denial
  path is byte-compatible.
- `RegisterNode` overwrites the map entry wholesale — label carry-forward has to be
  explicit (done in `Enroll`), and `autoGeoLabel` re-derives geo labels on the same
  map, matching heartbeat behavior.
- `RevokeSerial` takes `cs.mu` only around the append and persists via the same
  fsynced `Save()` path as `RevokeNode` (F4 atomic-write fix applies).
- Suite: full `go test ./...` green (52 packages); `-race -count=2 -shuffle=on` on
  the enrollment/cluster tests green; `golangci-lint --new-from-rev=origin/main`
  clean.

## Open-findings register — status after this run

Statuses relative to the 2026-07-12 table. Findings not listed are unchanged; the
2026-07-05 review remains the authority for their detailed write-ups.

| ID | Sev | Title | Status |
|---|---|---|---|
| CHAOS-12 | MED-HIGH | DP cert renewal inert until restart; expiry brick | **FULLY CLOSED** — renewal fixed 07-11; expired-node recovery path shipped this run |
| CHAOS-09 | MED | Readiness blind to CP-poll failure / cert expiry | OPEN — **now the top open item** |
| CHAOS-23 | MED | Freshness watchdog inert for disabled-fetch/permissive deployments | OPEN |
| CHAOS-05/07 | MED-HIGH | Corrupt state files | FIXED (07-12) — remainder: refuse-to-boot posture decision; lesser stores still silent-reset |
| CHAOS-06 | HIGH | Root-CA load failure → silent fail-open | MITIGATED (07-09); `inspection.required` fail-closed mode still open |
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

1. **CHAOS-09** — readiness degrades on sustained CP-poll failure + imminent cert
   expiry (`dpControlPlanePollFailing` + the 07-11 alert latch are the signal
   sources; `FAILURE-INJECTION-TEST-PLAN.md` already specs the test). Decide
   report-only rows vs. an opt-in `/readyz?strict=1` — gating the default verdict
   on CP-poll failure would let a CP outage eject the entire DP fleet from the LB.
2. **CHAOS-23** — decouple `evaluateCatalogFreshness()` from the fetch loop.
3. **CHAOS-05/07 remainder** — refuse-to-boot posture decision (owner);
   extend `quarantineCorruptStateFile` to the lesser stores (mechanical).
4. **CHAOS-10/17** — `scan.on_error` posture config + `culvert_scan_errors_total`.
5. **CHAOS-28** — retry the rotation-triggered renewal before the 30-day window.
6. Deep-dive passes never yet done: maintenance-agent host-ops surface,
   `update_cluster.go` failure paths (RISK-011), SAML metadata refresh.

## Residual risk

- The new code runs only inside the previously-denying branch of `admitEnrollment`
  and after a successful re-registration in `Enroll`; every other enrollment path is
  byte-identical (denial ordering, token consumption, rate limiting, CSR checks —
  all pinned by existing tests that pass unmodified).
- `RevokeSerial` failure (e.g. read-only disk) degrades to a logged error — the
  re-enrollment still completes (availability over evidence in that corner; serial
  pinning still excludes the old cert), and the CHAOS-05/07 storage machinery is the
  systemic answer to failing persistence.
- The alert rides the existing webhook engine (dedup, retry, SSRF-guarded delivery)
  — no new delivery plumbing.
