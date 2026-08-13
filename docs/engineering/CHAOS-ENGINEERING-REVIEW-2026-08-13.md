# Chaos Engineering Review — 2026-08-13

**Domain:** the **cluster CA** across its lifecycle — the certificate authority that
signs the node certificates carrying CP↔DP mTLS. Distinct from the inspection CA
(`internal/ca`) that CHAOS-28 hardened on 2026-08-09; this is the *other* CA, with a
different lifecycle, a different consumer, and a different blast radius.
**Register items:** **CA-13** (recorded 2026-08-09, marked "next sweep") · adds and closes
three previously unrecorded defects, one of which is a recovery failure that cannot be
repaired in-band.
**Verdict:** six confirmed defects, all fixed. Three were reproduced empirically against
`main` before the fix was written; the other three are wiring and state-integrity faults
established by reading the call graph and pinned by tests that fail on the pre-fix code.

---

## Executive Summary

CHAOS-28 gave the inspection CA a three-part contract: `Usable()` is distinct from
`Ready()`, the sign path fails **closed** when the CA is outside its own validity window,
and a leaf's validity is **clamped to its issuer's** at both ends. It closed by naming the
surviving half of the problem — the cluster CA has none of it — and recorded it as CA-13.

This sweep confirms CA-13 is live on `main` and found that the domain is worse than
recorded in three ways. The most serious is not the missing guard that CA-13 describes.
It is that the missing **clamp** silently defeats the one recovery mechanism the cluster
CA has, turning a scheduled, zero-touch CA rotation into a fleet-wide manual
re-enrollment for any node that happens to be offline during the overlap window.

| # | Failure mode | Class | Why the existing design did not cover it |
|---|---|---|---|
| 1 | An **expired cluster CA keeps signing node certificates**; `Enroll`/`RenewCert` report success | Silent failure → cluster-wide enrollment outage | `SignCSR` checked `cert == nil` only; `x509.CreateCertificate` does not check the parent's validity |
| 2 | Node certs are **not clamped to the issuer**, so a leaf outlives the CA by up to a year | **Recovery failure** — defeats the DP renewal loop | the leaf lifetime was a fixed `now+365d`, independent of the issuer |
| 3 | Cluster-CA auto-rotation is **gated on the *inspection* CA being ready** | Hidden SPOF / cross-subsystem coupling | one `if certMgr.Ready()` guarded a loop that drives **both** CAs |
| 4 | A failing auto-rotation has **no counter, no alert, no health signal** | Silent failure | `Info()` only — an admin-API field nobody reads on a healthy day |
| 5 | A failed `ImportCA` leaves a **phantom dual-CA overlap** in memory | State corruption | the secondary was swapped *before* persistence, and the error path did not unwind it |
| 6 | First `ImportCA` onto a node with no cluster CA **nil-derefs** | Crash (admin plane) | `sha256.Sum256(ca.secondaryCert.Raw)` unguarded; the POST path has no `Ready()` precondition |

### Why defect 2 is the headline

Defect 1 is the CA-1 defect class transplanted, and it is bad in the ordinary way: an
operator watches an enrollment "succeed" and the node never connects, with nothing in any
log, metric or probe explaining why. That is a diagnosis problem, and the fix is a guard.

Defect 2 is a **recovery** problem, and the appliance already contains the machinery that
was supposed to prevent it. The design intent is sound and complete:

- `RotateIfNeeded` rotates the cluster CA 30 days before expiry, keeping the old CA as a
  **secondary** so certificates signed by it stay acceptable during the overlap.
- The DP renewal loop (`dpCertRenewalLoop`, CHAOS-12) renews a node certificate 30 days
  before *it* expires, and additionally renews **immediately** on a CA-rotation
  notification — the zero-touch path.

The two thresholds were supposed to coincide. They do not, because the DP loop reads the
**leaf's** `NotAfter` (`certNeedsRenewal`) and the leaf was minted at a flat `now + 365d`
regardless of how much life its issuer had left. A node enrolled eleven months before the
CA's expiry carries a certificate claiming 365 days of validity while its issuer has 20
days to live. Measured against `main`:

```
PROOF 2 CONFIRMED: CA expires 2026-09-02 but the node cert claims 2027-08-13
                   — 345 days past its own issuer
PROOF 2: certNeedsRenewal threshold is 30d; the leaf reports 364 days left
         => renewal NOT triggered, while the issuer dies in 19 days
```

A node that is online during the overlap window is saved by the rotation *notification*,
not by its own expiry logic. A node that is **powered off, partitioned, or in a
maintenance window** for those 30 days misses the notification, comes back with a
certificate that looks perfectly healthy to every check it runs, and discovers the problem
only when the CP rejects its client certificate — at which point it has no authenticated
transport left to call `RenewCert` on. **Manual re-enrollment is the only way back, and
nothing warned anybody.** `checkDPCertExpiry` reports the node as healthy throughout,
because the leaf it is reading really does say 300 days.

Clamping the leaf to its issuer makes the two thresholds the same instant by construction:
a certificate that dies with its CA crosses the 30-day renewal line at the same moment the
CA crosses its 30-day rotation line. The node renews *inside* the overlap window using its
own logic, without depending on having been awake for a notification. **The fix is three
lines; what it buys is that the existing recovery path actually reaches the nodes it was
written for.**

### Why defect 3 is the one that would have surprised us

`StartCAAutoRotation` drives **both** CAs — the comment in `ca.go` says so explicitly
("The loop lives here, not in the package, because it spans both CAs"). It was started
from exactly one place:

```go
if certMgr.Ready() {          // ← the inspection CA
    StartCAAutoRotation(ctx, cfg.Path, cfg.Passphrase)
}
```

A corrupt CA bundle, a wrong `CULVERT_CA_PASSPHRASE`, or an unwritable CA directory leaves
`certMgr` not-ready. That is *already* a known, accepted, documented degradation for
inspection — register row CA-3, fail-open to tunnel-only. What nobody recorded is that the
same condition silently switches off **cluster-CA auto-rotation** on a control plane. Two
subsystems that share nothing but a ticker, coupled by one guard, with the consequence
deferred by years and surfacing as a fleet-wide mTLS outage in which no rotation was ever
attempted. The two failures are also causally linked in the field: an operator who moves
or re-permissions the data directory breaks both at once.

Running the loop unconditionally costs one zero-expiry comparison per 24 hours
(`RotateIfNeeded` returns immediately when `CAExpiry()` is zero), and each CA is already
guarded separately inside the round by CHAOS-24's `runGuarded`.

---

## Measured, against `main`

A temporary proof harness (`TestProof_*`, removed before commit) was run against the
unmodified engine. Defects 1, 2 and 5 reproduced on the first attempt:

```
PROOF 1 CONFIRMED: expired CA (NotAfter=2026-08-12T22:35:15Z) signed a node cert
                   serial=412e68593be4cd7134b944e3672dee7 expiry=2027-08-13T22:35:15Z
PROOF 1: the issued cert fails validation: x509: certificate has expired or is not yet
         valid: current time 2026-08-13T22:35:15Z is after 2026-08-12T22:35:15Z

PROOF 2 CONFIRMED: (above)

PROOF 3 CONFIRMED: import FAILED but SecondaryActive()==true — Info() now reports
                   dualCAActive for an overlap that never happened
```

Defect 1's second line is the whole point: the appliance produced, recorded on the node
roster, and returned over the wire a certificate that it could itself immediately prove
was invalid.

---

## Failure Scenarios

### FS-1 — Cluster CA expires (or the clock rolls forward past its `NotAfter`)

| | |
|---|---|
| **Current behavior (pre-fix)** | `SignCSR` signs. `Enroll` returns a certificate + CA bundle and registers the node. `RenewCert` returns a fresh certificate that the DP **persists over its still-valid one**. `Ready()` stays true, `/healthz` says nothing, `/readyz` has no row, `/metrics` moves no series. |
| **Expected behavior** | Refuse to issue, name the condition at the RPC boundary, and make it visible on every operator surface. |
| **Failure mode** | Silent fail-*forward*: the control plane hands out credentials it can prove are dead. |
| **Recovery path** | Import or rotate a cluster CA. Auto-rotation would have prevented it 30 days earlier — **if** it was running (see FS-3). |
| **Customer impact** | No new nodes can join; every existing node is ejected at its own certificate's next handshake. CP↔DP config sync stops fleet-wide; DPs serve last-good config indefinitely (register row HA-1). |
| **Security impact** | Policy, blocklist and threat-feed updates stop propagating. Nodes enforce an increasingly stale allowlist and a stale revocation view. Revoking a node's certificate no longer reaches the fleet. |
| **Monitoring visibility (pre-fix)** | **None.** |
| **Post-fix** | `codes.FailedPrecondition` naming the window · `culvert_cluster_ca_usable 0` · `culvert_cluster_ca_sign_refused_total` · `/healthz cluster_ca: expired` · `/readyz cluster_ca` (report-only) · `/api/diagnostics cluster_ca: fail` · `cert_expiry` alert · red banner on the cluster CA panel. |

### FS-2 — Node offline through the dual-CA overlap window

| | |
|---|---|
| **Current behavior (pre-fix)** | The node's leaf claims up to a year of validity, so its own renewal check stays quiet. It misses the rotation notification. On return, its client certificate chains to a CA the CP has already cleaned up, mTLS fails, and `RenewCert` is unreachable because `RenewCert` itself requires mTLS. |
| **Expected behavior** | The node's own expiry logic should fire inside the overlap window, without depending on having been awake for a push. |
| **Failure mode** | **Recovery failure.** The self-heal path exists and is unreachable. |
| **Recovery path (pre-fix)** | Manual re-enrollment with a fresh token, per node, on the node. |
| **Recovery path (post-fix)** | Automatic: the clamped leaf crosses the 30-day renewal threshold at the same moment the CA crosses its rotation threshold, so the node renews on its own cadence inside the window. |
| **Monitoring visibility (pre-fix)** | Worse than none — `checkDPCertExpiry` actively reported the node as healthy. |
| **Post-fix** | `culvert_cluster_ca_cert_clamped_total` moves as soon as the CA is within one node-cert lifetime of expiry — an early warning that arrives ~11 months before the cliff. |

### FS-3 — Inspection CA fails to load on a control plane

| | |
|---|---|
| **Current behavior (pre-fix)** | Inspection degrades to tunnel-only (accepted, CA-3) **and** cluster-CA auto-rotation never starts. |
| **Expected behavior** | The two CAs are independent; a fault in one must not disarm the other's lifecycle. |
| **Failure mode** | Hidden SPOF; latent, surfacing years later as FS-1 with no rotation ever attempted. |
| **Post-fix** | The loop starts unconditionally; each CA is guarded separately inside the round. |

### FS-4 — Auto-rotation fails repeatedly (read-only volume, disk full, no entropy)

| | |
|---|---|
| **Current behavior (pre-fix)** | One log line per attempt, plus `lastRotationError` on `GET /api/cluster/ca`. No counter, no alert, no health signal. |
| **Expected behavior** | The 30-day window before expiry is the last chance to fix this; it must page. |
| **Failure mode** | Silent failure with a hard deadline. |
| **Post-fix** | `culvert_cluster_ca_rotation_failures_total` · `cert_expiry` alert naming the failing stage (bounded by construction at one per 24h, so it needs no rate gate) · `/api/diagnostics cluster_ca: warn` while the CA is still valid — the window in which acting is cheap · the existing panel warning, now backed by a count. |

### FS-5 — `ImportCA` persist failure

| | |
|---|---|
| **Current behavior (pre-fix)** | Returns an error **after** publishing the secondary. `Info()` reports `dualCAActive` with the old CA as both primary and secondary; the panel shows a rotation in flight that never started; `CleanupSecondary` later logs the end of an overlap that was never entered. |
| **Expected behavior** | A failed import leaves in-memory state byte-identical to what it found. |
| **Post-fix** | Every mutation moved onto the success path, after both writes. |

### FS-6 — First `ImportCA` on a node with no cluster CA

| | |
|---|---|
| **Current behavior (pre-fix)** | `sha256.Sum256(ca.secondaryCert.Raw)` nil-derefs. `POST /api/cluster/ca` has no `Ready()` precondition; the panic is contained by `net/http`'s per-connection recover, so the blast radius is a dropped admin connection rather than the process — but the import's post-steps (rotation tracking, config-version bump) never run. |
| **Post-fix** | Guarded — a first import has no predecessor, so there is no rotation to track. |

---

## Risk Matrix

| ID | Failure | Likelihood | Impact | Pre-fix severity | Post-fix |
|---|---|---|---|---|---|
| FS-1 | Expired cluster CA still issues | Low (10y cert) but **certain** at end of life | Fleet-wide CP↔DP outage, silent | **H** | Fail-closed + fully observable |
| FS-2 | Offline node misses the overlap | **Medium** (any maintenance window ≥30d) | Per-node brick, manual recovery | **H** | Self-heals |
| FS-3 | Rotation disarmed by inspection-CA fault | Low–Medium | Turns FS-1 from preventable into inevitable | **M/H** | Decoupled |
| FS-4 | Rotation failing silently | Medium | Removes the only automatic recovery | **M** | Counted + alerted |
| FS-5 | Phantom dual-CA overlap | Low | Operator misdiagnosis during an incident | **L/M** | State integrity restored |
| FS-6 | Nil-deref on first import | Low | Admin-plane crash, partial import | **L/M** | Guarded |

---

## Recovery Assessment

| Scenario | Automatic recovery | Manual recovery | Post-fix |
|---|---|---|---|
| Cluster CA nearing expiry | Auto-rotation at T−30d | Import CA via admin UI | Unchanged, but now *reliably running* (FS-3) and *visible when failing* (FS-4) |
| Node online during overlap | Rotation notification → immediate renewal | — | Unchanged |
| Node offline during overlap | **None (pre-fix)** | Re-enroll per node | **Automatic** — clamped leaf triggers the node's own renewal |
| Cluster CA already expired | None — and the fleet has no authenticated transport left | Import a CA on the CP; nodes re-enroll | Unchanged; the fix is prevention + visibility, and the refusal now names the remedy |

**What is deliberately NOT recoverable in-band.** Once the cluster CA has expired, every
DP has lost the mTLS channel it would use to fetch a replacement. That is inherent to
mutual TLS bootstrapped from a single root, exactly as client-side trust redistribution is
inherent to the inspection CA (CHAOS-28 §16.5). This is why the investment here is in
making the condition visible *long* before the cliff —
`culvert_cluster_ca_expires_in_seconds` and `culvert_cluster_ca_cert_clamped_total` both
move roughly a year out — rather than only at it.

---

## Security Impact

Fail-closed here is a **strict security improvement in both directions**, which is not
always true of fail-closed changes and is worth stating precisely.

Refusing to issue costs no availability relative to the pre-fix state: a certificate
chained to an expired issuer already fails path validation in every mainstream TLS
implementation, so the enrollment was dead on arrival either way. What changed is that the
appliance now knows, says so, and names the remediation.

On the renewal path it is a genuine availability **gain**: pre-fix, `RenewCert` handed a
node a dead certificate which the node then **persisted over its still-valid one**,
converting a CP-side fault into a permanent node-side one. Post-fix the node keeps its
working certificate and retries on its cadence, so the fleet self-heals the moment an
operator rotates.

The refusal deliberately does **not** honour any fail-open posture. There is no equivalent
of the decryption profile's `OnInspectError=fail-open` on this path, and there must not
be: issuing an unusable credential is not a degraded service, it is a wrong answer.

Two disclosure rules are preserved. `/readyz` is unauthenticated on the proxy port, so the
`cluster_ca` row carries a **fixed** detail with no expiry date, path or fingerprint — the
live cause lives on the role-gated `/api/cluster/ca`. All new metrics are **label-free**
per the CA-2 contract: no node ID, subject, serial, fingerprint or key material, only
counts and one time delta.

---

## Operational Impact

- **No new configuration.** No flag, no env var, no YAML key. Nothing to tune, nothing to
  get wrong, no GUI-parity debt incurred.
- **Existing alert event reused.** The `cert_expiry` event already carries the inspection
  CA and DP node certs (CHAOS-12). A cluster-CA-specific event name would need a new
  subscription in every existing deployment to be seen at all; `Source: "cluster-ca"`
  carries the distinction instead.
- **Behaviour on a healthy appliance is unchanged.** The clamp is a no-op while the CA
  outlives its leaves (pinned by
  `TestClusterCA_UnclampedLeafIsLeftAloneWhenIssuerOutlivesIt`), the usability check is
  two time comparisons on a path that runs once per enrollment, and the rotation loop's
  extra work when no inspection CA is present is one zero-expiry comparison per day.
- **Clock skew.** A 5-minute tolerance mirrors `caClockSkewTolerance`, so an NTP step or a
  restored VM snapshot cannot brick the cluster PKI over a few minutes of drift.

---

## Suggested Improvements (not taken in this PR)

- **CA-4's retry half, for the cluster CA too.** A rotation that fails waits a full 24h
  before retrying. With the alert now firing, an operator is at least told; a backoff-free
  retry on failure would still be better. Same deferral as the inspection CA.
- **A max-staleness ceiling for DP config (HA-1).** FS-1's blast radius is amplified by
  DPs serving last-good config indefinitely. Out of scope here; recorded and unchanged.
- **Two-file commit for the CA cert+key pair.** The existing comment documents the
  crash-between-writes window as detected-on-next-startup and out of scope; this review
  did not revisit that judgement.

---

## Required Tests (all shipped)

`cluster_ca_validity_test.go`:

| Assertion | Test |
|---|---|
| Expired CA refuses to sign; refusal counted; degraded | `TestClusterCA_ExpiredCARefusesToSign` |
| Not-yet-valid CA refuses to sign | `TestClusterCA_NotYetValidRefusesToSign` |
| ±5 min skew stays usable (both ends) | `TestClusterCA_ClockSkewToleranceKeepsMarginalCAUsable` |
| `Usable()` is distinct from `Ready()` | `TestClusterCA_UsableIsDistinctFromReady` |
| Leaf clamped to issuer at both ends; counted; returned expiry agrees with the cert | `TestClusterCA_NodeCertClampedToIssuer` |
| Clamp is a no-op on a healthy CA | `TestClusterCA_UnclampedLeafIsLeftAloneWhenIssuerOutlivesIt` |
| **Clamp makes DP renewal fire inside the overlap window** | `TestClusterCA_ClampMakesRenewalFireInsideTheOverlapWindow` |
| Failed import leaves no phantom overlap, CA untouched | `TestClusterCA_ImportFailureLeavesNoPhantomOverlap` |
| First import with no predecessor does not panic | `TestClusterCA_FirstImportWithNoPriorCADoesNotPanic` |
| Rotation failure counted + surfaced on the admin API | `TestClusterCA_RotationFailureIsCountedAndSurfaced` |
| Recovery requires observed evidence, never elapsed time | `TestClusterCA_RecoveryRequiresObservedEvidence` |
| Alert rate-limited, counter is not | `TestClusterCA_UnusableAlertIsRateLimitedButTheCounterIsNot` |
| Alert carries no key material | `TestClusterCA_AlertCarriesNoKeyMaterial` |
| Metrics expose the usability series | `TestClusterCA_MetricsExposeUsabilitySeries` |
| Expiry series omitted when no CA (0 ≠ "expires now") | `TestClusterCA_ExpirySeriesOmittedWhenNoCA` |
| `/healthz` reports expired / ready / not_configured | `TestClusterCA_HealthzReportsExpiredNotReady` |
| `/readyz` row is report-only and date-free | `TestClusterCA_ReadyzRowIsReportOnly` |
| `Info()` surfaces usability for the GUI banner | `TestClusterCA_InfoSurfacesUsability` |
| `/api/diagnostics` row: fail / warn-on-failing-rotation / ok-when-standalone, no window leak | `TestClusterCA_DiagnosticsRowReportsTheOutage` |
| Rotation loop is not re-gated on the inspection CA | `TestClusterCA_RotationLoopNotGatedOnInspectionCA` |

---

## Residual Risk

1. **An already-expired cluster CA still requires manual recovery**, and always will —
   mTLS bootstrapped from one root has no in-band path back. Mitigated by moving the
   warning ~1 year earlier.
2. **A node offline longer than its full certificate lifetime** (now ≤ the CA's remaining
   life) still needs re-enrollment. Clamping shrinks the window in which that can happen;
   it cannot eliminate it.
3. **Rotation still has no backoff** — a persistent fault burns one attempt per 24h. Now
   alerted rather than silent.
4. **The 5-minute skew tolerance is a fixed constant**, not operator-tunable. Consistent
   with `caClockSkewTolerance`; a deliberate no-new-knobs decision.
5. **`RenewCert`'s roster write remains best-effort** (`saveLocked` failure is logged, not
   returned). Unchanged by this review; the certificate itself is correct, only the CP's
   record of its serial may lag.
