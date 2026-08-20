# Chaos Engineering Review — 2026-08-20

**Domain:** the **cluster CA** across its lifecycle — the trust root for CP↔DP mTLS, node
enrollment, and node-certificate renewal (`enrollment.go`, `controlplane_server.go`,
`ui_cluster.go`).
**Register items:** **CA-13** (open since 2026-08-09, handed off by CHAOS-28 as "suggested
as the next sweep") · adds and closes three previously unrecorded defects, one of which is a
reachable process-level panic on the documented recovery path.
**Verdict:** four confirmed defects, all fixed. All four were reproduced empirically against
unmodified `main` before any fix was written, and every regression gate in this change was
re-verified to FAIL against the pre-fix engine. Two further defects (FS-5, FS-6) were found by
review *of the fix* and are recorded below — one of them, the spent enrollment token, was
already live on `main` through the pre-existing `Ready()` precondition.

---

## Executive Summary

CHAOS-28 (2026-08-09) established a contract for a CA that has aged out: `Ready()` ("is a CA
installed") is not `Usable()` ("can it issue something a relying party will accept"), the sign
path fails **closed** on an unusable issuer rather than emitting artifacts that cannot work,
leaves are clamped so they can never outlive their issuer, and the whole condition is visible
on a metric, a health probe, and an alert. It shipped that for the **inspection** CA
(`internal/ca`) and explicitly handed off the identical hole in the **cluster** CA as CA-13,
on the grounds that the lifecycle and blast radius were different enough to deserve their own
sweep.

They are different, and the cluster-CA version is quieter. The inspection CA's failure at
least surfaces as a browser warning on every inspected site. The cluster CA's failure surfaces
as nothing at all on the appliance and as an opaque mTLS error on N separate data-plane
machines — and it is **latent**: the appliance keeps reporting `enrollEnabled: true`, keeps
accepting enrollment tokens, and keeps handing back certificates. They just never work.

| # | Failure mode | Class | Why the existing design did not cover it |
|---|---|---|---|
| 1 | An **expired cluster CA keeps signing** node certs; enrollment reports success | Silent failure → fleet-wide enrollment/renewal outage | `x509.CreateCertificate` never checks the parent's validity window, and `Ready()` (the enrollment gate) only asks whether a CA is loaded |
| 2 | Node certs carried a **fixed 1-year lifetime** regardless of issuer life left | Recovery failure (self-defeating) | the DP renewal loop triggers off the NODE cert's expiry, so an issuer-outliving cert keeps the node quiet through exactly the window in which it needed to renew |
| 3 | **`ImportCA` panics** when no CA is currently installed | Crash on the recovery path + state split | the dual-CA overlap block dereferenced `ca.secondaryCert` unconditionally; it is nil on a first import — which is precisely what an operator does after `InitOrLoad` fails |
| 4 | A **failed persist still mutated** the in-memory overlap state | State corruption | the secondary was recorded before the writes, so a read-only volume left the live CA installed as its own secondary until a restart |

Defects 3 and 4 were not in the register. Defect 3 is the most acute: it is a nil-pointer
dereference on the one path an operator takes to recover from a cluster CA that failed to load.

### Measured, against `main`

A temporary proof harness (`TestProof_*`, removed before commit) was run against the unmodified
engine. All four reproduced on the first attempt:

```
REPRODUCED: expired cluster CA signed a node cert (serial=3ae4a2ac… expiry=2027-08-20T22:16:20Z,
            603 bytes) and Ready()=true so enrollment reports success
REPRODUCED: node cert NotAfter=2027-08-20T22:16:20Z outlives issuer NotAfter=2026-08-30T22:16:20Z
            by 8520h0m0s (returned expiry=2027-08-20T22:16:20Z)
REPRODUCED: ImportCA panicked on first import: runtime error: invalid memory address or nil
            pointer dereference
  ... and the CA WAS applied in memory before the panic (silent split)
REPRODUCED: failed import left a phantom secondary CA (SecondaryActive=true, same-as-primary=true)
```

---

## Failure Scenarios

### FS-1 — The cluster CA expires and enrollment silently stops working

**Simulated:** certificate expired · clock rollback · NTP failure.

**Current behavior (pre-fix).** `clusterCA.Ready()` is `cert != nil && key != nil`. It is the
gate `Enroll` uses (`controlplane_server.go:404`) and the value `/api/cluster` publishes as
`enrollEnabled`. An expired cluster CA satisfies all of it. So:

1. The admin panel shows a green **Active** cluster CA and offers the enroll-token button.
2. A new data-plane node presents a token and a CSR. `SignCSR` mints a certificate — Go's
   `x509.CreateCertificate` does not check the parent's `NotBefore`/`NotAfter`, so the
   signature is well-formed and the operation returns success.
3. The CP registers an `EnrolledNode` record and logs `node "dp-7" enrolled`.
4. The DP writes the cert to disk, believes it is enrolled, and attempts its first mTLS
   connection — which fails path validation in Go's own TLS stack, forever.

The terminal state is a Control Plane that reports a healthy CA and a growing roster of
registered nodes that will never connect, with no log line, no metric, and no health-probe row
moving anywhere on the appliance. The same path governs **renewal** (`controlplane_server.go:608`),
so the existing fleet cannot renew either — they simply expire, one at a time, over the
following year.

**Expected behavior.** The same as CHAOS-28 decided for the inspection CA: refuse. Refusing
costs no availability that signing would have preserved — the chain was already dead — and it
converts N indistinguishable per-node TLS errors into one countable, alertable event on the
machine that can actually fix it.

**Fix.** `SignCSR` now calls `clusterCAUsable(ca.cert, time.Now())` and fails closed with a
sentinel (`errClusterCAUnusable`), recording a refusal. `Ready()` is deliberately left alone:
folding validity into it would silently change what every existing caller means.

The clock-skew half matters here more than it does for the inspection CA, because a Control
Plane that boots with a bad RTC or takes an NTP step backwards would otherwise refuse to enroll
the entire fleet. `clusterCAClockSkewTolerance` (5 min) matches the backdating `SignCSR`
already applies to the certs it issues, so both ends of the same window use one tolerance.

### FS-2 — Node certificates outlive their issuer, defeating their own renewal

**Simulated:** certificate expired · unexpected startup order · broken retries.

**Current behavior (pre-fix).** `SignCSR` used a fixed `notAfter := time.Now().Add(365*24*time.Hour)`.
Any cluster CA with under a year of life left therefore issued node certs that outlive it. That
is not a corner case:

- Every CA inside its own 30-day auto-rotation window.
- Every custom CA an operator imports with a shorter life — `parseAndValidateCACert` accepts
  anything not already expired, so a 90-day intermediate is a legal import.
- Every CA on a node that was powered off through its rotation window.

The damage is not merely cosmetic, and this is the part worth dwelling on: **it disables the
recovery machinery.** The DP renewal loop triggers off `certNeedsRenewal`, which reads the
**node's own** certificate and renews 30 days before *it* expires. A node holding a cert that
claims a year of life while its issuer has ten days left is, by that measure, perfectly healthy.
It stays quiet through the entire window in which it needed to renew, and then the whole fleet
drops off mTLS together at the instant the CA expires.

There is a rotation-notification path (`dpCertRenewalLoop` watches for a CA fingerprint change
and force-renews), and it is real resilience — but it only fires when rotation *succeeds*. It
does nothing for a CA whose rotation is failing (read-only CA directory, ENOSPC), which is
exactly the case where the fleet needed the node-cert clock to be honest.

**Fix.** `clampNodeCertValidity` narrows both bounds to the issuer's window, mirroring
`internal/ca`'s `clampLeafValidity`. The window becomes self-correcting: inside the CA's own
rotation window, issued node certs are short, so the DP renewal loop keeps checking back at its
6h cadence and picks up the rotated CA as soon as it lands. The **returned** expiry is the
clamped value, so `EnrolledNode.CertExpiry` — the field every operator view and the heartbeat
monitor read — stops lying.

A clamped issuance is counted (`culvert_cluster_ca_node_cert_clamped_total`) because it is the
leading indicator that the CA is inside its rotation window, and because it explains an
otherwise surprising uptick in renewal traffic.

### FS-3 — `ImportCA` panics on the documented recovery path

**Simulated:** permission denied · configuration corruption · disk read-only · power loss
(partial pair on disk).

**Current behavior (pre-fix).** `initClusterCA` (`main.go:1150`) logs and continues on error:

```go
if err := globalClusterCA.InitOrLoad(caDir); err != nil {
    logger.Printf("ClusterCA: init error: %v — enrollment disabled", err)
}
```

So `cert == nil` is a fully reachable steady state, reached by a partial cert/key pair on disk
(a power loss between the two writes — the code documents this and fails closed by design), a
permission error, a corrupt PEM, or a wrong CA-3 KEK. The process runs; enrollment is off.

The operator then does the documented thing: **Cluster → CA → Import Custom Cluster CA**. That
reaches `ImportCA`, which ends with:

```go
oldFP := sha256.Sum256(ca.secondaryCert.Raw)   // ← nil on a first import
```

The secondary is only ever assigned when `ca.cert != nil`, so on a first import this is a
nil-pointer dereference. `net/http` recovers it per-connection, so the process survives — but
the failure lands in the worst possible place. By the time it panics, lines above have already
written both files, swapped the new CA into memory, and called `onRotate()` to rebuild the TLS
pool. What did **not** run: `StartCARotation`, the `globalConfigStore.Update` that tells DP
nodes the fingerprint changed, the rotation metric, and — because it sits in the caller — the
`auditEvent`. The operator sees a failed request against a CA that is, in fact, live and
unaudited.

**And then they retry**, because the request failed. On the retry `ca.cert` is no longer nil,
so the old code installed the just-imported CA as its **own secondary** and called
`StartCARotation(fp, fp, …)` — opening a phantom dual-CA overlap in which every enrolled node
is marked pending renewal. A fleet-wide renewal storm, for a rotation that never happened,
triggered by an operator recovering from an unrelated fault.

**Fix.** Three layers:

- `ImportCA` captures the outgoing CA explicitly (`prev`) and treats `prev == nil` as *not a
  rotation* — no overlap, no tracking, no panic.
- A re-import of the **identical** certificate (`prev.Equal(cert)`) is likewise not a rotation,
  which closes the retry path directly.
- `StartCARotation` rejects `newFP == oldFP` (and an empty `newFP`) as defense in depth, because
  the cost of getting this wrong is paid by the entire fleet and the cost of the check is one
  string comparison.

### FS-4 — A failed persist corrupts the dual-CA overlap state

**Simulated:** disk full · disk read-only · permission denied.

**Current behavior (pre-fix).** `ImportCA` recorded the dual-CA overlap **before** writing:

```go
ca.secondaryCert = ca.cert            // ← mutated first
...
if err := atomicWriteFile(certFile, certPEM, 0o600); err != nil {
    return fmt.Errorf("write cluster CA cert: %w", err)   // ← returns with state already changed
}
```

So an import onto a read-only volume returned an error having installed the **currently live**
CA as its own secondary. `AllCACertsPEM()` then emitted the same certificate twice into the
client cert pool, `SecondaryActive()` returned true, and `Info()` reported `dualCAActive` — the
admin panel showing a rotation in progress that had not happened and could not complete. Only a
process restart cleared it.

**Fix.** Persist-before-swap: both writes happen first and **nothing** in memory is mutated
until they land. This is the same rule `persistReplicatedKey` (ha.go) already documents for the
HA standby path — "a decrypt, validation, or persist failure leaves `globalClusterCA` unchanged"
— now applied to the import path it was missing from. A failed persist leaves the running CA
byte-identical to what it was.

The two-file write is still **not** a true atomic commit; a crash between the cert and key
writes can leave a mismatched pair on disk. That is unchanged, deliberately: it is detected on
the next startup by `loadFromPEM`'s cross-validation and fails closed (D1.1f).

### FS-5 — The fail-closed gate spent the caller's one-time enrollment token

**Found in review of the fix, not of `main`** — recorded here because it is the same class this
sweep exists to catch: a guard that is correct in isolation and creates a new operational
failure at its seam.

`Enroll` calls `admitEnrollment` first, and the last thing `admitEnrollment` does is
`ValidateAndConsumeToken` — which marks the single-use enrollment token consumed **and persists
that**. The CA gate ran afterwards. So a node that attempted enrollment while the CA was expired
(or the CP's clock was behind) lost a valid token and got no certificate; once the fault was
repaired its retry was denied, and an admin had to mint and distribute a replacement token. The
refusal was correct; the cost landed on the wrong party.

The pre-existing `if !globalClusterCA.Ready()` check in `Enroll` had the **identical** shape, so
this was live on `main` before this change — the new gate merely widened it from "CA never
loaded" (rare on a running CP) to "CA expired or clock behind" (a long-lived state).

`admitEnrollment` already states the invariant for its other deny path — *"the denial stays
byte-identical and the token stays unconsumed on the deny path"* — so the fix is to honour the
rule the file already keeps: `clusterCAIssuancePrecondition()` now runs **after** the per-IP rate
limiter (so an unauthenticated flood cannot drive the refusal counter or the alert gate) and
**before** the token is spent. `SignCSR` keeps its own guard as the authoritative backstop —
`RenewCert` reaches it too, and no caller can bypass it — and because the precondition returns
first, a refusal is still counted exactly once.

### FS-6 — A clock fault was reported as an expiry, pointing at the wrong remediation

Also found in review of the fix. `Usable()` fails for two reasons with **opposite** remediations:
an expired CA needs a rotation or an import; a not-yet-valid one means this Control Plane's clock
is behind and the trust root is fine. Reporting both as `expired` — which `/healthz` did, and
which the GUI rendered as **"EXPIRED - Enrollment Down"** with an instruction to import a
replacement — steers the operator into an unnecessary fleet-wide trust-root rotation that does
not fix the actual fault, while the real cause (NTP) goes untouched.

`clusterCAUsable` now wraps a second sentinel alongside the umbrella one (Go multi-`%w`), so
`errClusterCAExpired` and `errClusterCANotYetValid` are distinguishable by `errors.Is`.
`clusterCAUnusableKind` classifies; `clusterCAUnusableRemediation` is kept next to it so the two
cannot drift. `/healthz` gains a distinct `not_yet_valid` state, `/api/cluster/ca` carries
`unusableKind` + `unusableRemediation`, `/api/cluster` carries `caUnusableKind`, and the panel
renders **"CLOCK FAULT - Enrollment Down"** with the clock remediation. The log line and the
alert detail are reason-specific for the same reason.

---

## Risk Matrix

| # | Likelihood | Impact | Pre-fix detectability | Residual |
|---|---|---|---|---|
| FS-1 expired CA signs | Low (10y CA) but **certain** if auto-rotation is broken, and immediate for a short imported CA | **Critical** — fleet-wide enrollment + renewal outage | **None** | Low — refused, counted, alerted, on `/healthz` |
| FS-2 unclamped node certs | **High** — every issuance inside the rotation window, every short imported CA | High — mass simultaneous mTLS loss; defeats the renewal trigger | None | Low — clamped; see residual on renewal cadence |
| FS-3 ImportCA panic | Medium — needs a prior CA load failure, then the documented recovery | High — 500 + unaudited live CA; retry ⇒ fleet renewal storm | Panic in the HTTP log only | None |
| FS-4 failed persist | Medium — read-only/full volume | Medium — phantom overlap until restart | `dualCAActive` reported the *wrong* thing | None |
| FS-5 token spent on refusal | Medium — any refusal, and live on `main` via the `Ready()` check | Medium — a valid token is destroyed; enrollment blocked past the repair until an admin re-issues | None | None — refused before the token is spent |
| FS-6 clock fault reported as expiry | Low/Medium — NTP step or bad RTC | Medium — operator performs an unnecessary fleet-wide CA rotation and does not fix the clock | Misleading, not absent | None |

---

## Recovery Assessment

**Automatic.** `RotateIfNeeded` fires once the CA is within 30 days of expiry — including when
it is already past it (`daysLeft` goes negative and stays ≤ 30) — generates a fresh 10-year CA,
opens a genuine dual-CA overlap, and bumps the config version so every DP force-renews. That
loop already runs one round **immediately at boot** before its 24h ticker: the cluster CA shares
`StartCAAutoRotation` with the inspection CA, so it inherited CHAOS-28's CA-4 fix for free — the
restart an operator performs to recover is no longer followed by a 24-hour blind spot.

**Manual.** Import a replacement CA (Cluster → CA), which now works on a first import instead of
panicking. Already-connected nodes keep working until their own certificates expire, so the
manual path is not a hard cutover.

**What is still manual and cannot be otherwise.** A node that was offline through the entire
dual-CA overlap window comes back holding a certificate signed by a CA that is now both expired
and removed from the pool. It must re-enroll with a fresh token. Nothing in-band can fix that,
which is the same shape as CHAOS-28's "client trust redistribution stays manual" — and the same
reason this change invests most heavily in making the condition visible *before* the cliff
(`culvert_cluster_ca_expires_in_seconds`) rather than only at it.

---

## Operational / Security / Data-Integrity Impact

**Operational.** Before: an expiring cluster CA moved nothing an operator could scrape.
`culvert_cluster_ca_rotations_total` counts only successes, and there was no expiry series at
all. After: `culvert_cluster_ca_expires_in_seconds` is the series to alert on well before the
cliff; `culvert_cluster_ca_usable`, `_sign_refused_total` and `_node_cert_clamped_total` confirm
the cliff was hit and how hard. `/healthz` gains a `cluster_ca` row (`ready` / `expired` /
`absent`) — `absent` is the normal state on a data-plane node and never fails the probe. The
Cluster CA panel renders a red banner naming the fault and the remediation instead of a green
"Active".

**Security.** This is an availability failure, not a bypass — and the fix is careful to keep it
that way. Refusing to sign is the *conservative* direction: nothing is trusted that was not
trusted before, no validation is relaxed, and there is no fail-open counterpart anywhere in this
change. Clamping strictly narrows certificate lifetimes. One genuine security improvement falls
out of FS-3: a first import no longer completes without its `auditEvent`, so an imported cluster
CA can no longer become live with no audit record.

**Data integrity.** FS-4 was the only integrity defect and it was in-memory only — the on-disk
pair was never corrupted by it (the writes had failed). Persist-before-swap removes the
divergence entirely.

**Alert quality.** The unusable-CA producer is rate-limited to one signal per 5 minutes on an
independent gate from the log line, and `HasSubscriber`-gated per the per-request
alert-producer contract in CLAUDE.md — a reconnect storm drives every node at the enrollment RPC
at once, and one webhook per node per attempt would overflow the queue with the very alerts the
operator needs. The counters carry the magnitude; one signal per interval carries the page.
Recovery is reported on **observed evidence** (an issuance that actually succeeded), never on
elapsed time, matching the `storage_health.go` contract: a still-expired CA looks exactly like a
healthy one if nothing happens to need a certificate.

---

## Required Tests

All in `cluster_ca_validity_test.go`, all verified to **FAIL** against the pre-fix engine:

| Gate | Proves |
|---|---|
| `TestClusterCAUsable_Windows` | the predicate — nil, inside, past `NotAfter`, before `NotBefore`, and **within** skew tolerance (a slow RTC must not take enrollment down) |
| `TestClusterCA_ExpiredIssuerRefusesToSign` | fail-closed, `Ready()` deliberately still true, counter moves, exactly one alert, degraded flag set |
| `TestClusterCA_NotYetValidIssuerRefusesToSign` | clock rollback fails closed and the error names the clock |
| `TestClusterCA_UnusableAlertIsRateLimited` | 25 refusals ⇒ 1 alert, 25 on the counter |
| `TestClusterCA_RecoveryReportedOnEvidenceOnly` | the degraded flag clears on a successful issuance, not on elapsed time |
| `TestClusterCA_NodeCertNeverOutlivesIssuer` | clamped on both bounds across three issuer lifetimes; the **returned** expiry matches the actual cert |
| `TestClusterCA_ClampedNodeCertStillChains` | the clamped cert actually verifies — the artifact has to work, not just be short |
| `TestClusterCA_FirstImportDoesNotPanicOrOpenRotation` | no panic, no overlap, no rotation tracking |
| `TestClusterCA_ReimportOfSameCAIsNotARotation` | the operator-retry path opens no phantom overlap |
| `TestClusterCA_RealRotationStillOpensOverlap` | the negative assertions did not disable the real thing — overlap opens, fingerprints differ, both CAs are offered to the TLS layer |
| `TestClusterCA_FailedPersistLeavesRunningCAUnchanged` | the live CA, the overlap, rotation tracking and `Info()` are all untouched by a failed write |
| `TestStartCARotation_RejectsSelfRotation` | self-rotation and empty-fingerprint rejected; a genuine rotation still recorded |
| `TestClusterCA_InfoSurfacesUsability` | `usable` / `unusableReason` / `expiresInDays` on the admin API |
| `TestClusterCA_MetricsSurfaceUsabilityAndExpiry` | the expiry series is **omitted** with no CA (0 would read as "expires now" and page every DP node) |
| `TestClusterCA_HealthzRowTracksUsability` | `ready` / `expired` / `absent` |
| `TestClusterCA_UnusableKindsAreDistinct` | expiry vs clock fault classified distinctly on `/healthz`, `Info()`, and the remediation text |
| `TestEnroll_UnusableCADoesNotConsumeToken` | the token survives a refusal, the node is not registered, the refusal is counted **once**, and the preserved token enrolls once the CA is repaired |
| `TestEnroll_UninitializedCADoesNotConsumeToken` | same rule for the pre-existing "not initialized" precondition |

Verified under `-race -count=2 -shuffle=on`. The alert seam
(`fireClusterCAUnusableAlert`) is a package-level variable so tests observe transitions
synchronously rather than racing the process-global sink — the determinism class the CI gate
catches.

---

## Residual Risk

- **Clamping raises renewal traffic while the CA is inside its rotation window.** A node holding
  a 10-day clamped cert renews on every 6h check until the rotated CA lands (normally within
  24h, because the rotation loop runs daily and immediately at boot). If rotation is *persistently*
  failing — a read-only CA directory — that becomes a standing 4-renewals-per-node-per-day
  background cost. It is bounded, cheap (one CSR signature), and strictly preferable to the
  pre-fix alternative of silence followed by a simultaneous fleet-wide expiry. The underlying
  rotation failure is already surfaced via `lastRotationError` on the CA panel.
- **The two-file CA write is still not atomic.** Unchanged and deliberate: a crash between the
  cert and key writes is detected on the next startup by `loadFromPEM` cross-validation and fails
  closed. Auto-repair remains out of scope.
- **`ImportCASilent` (ha.go) does not clear a stale secondary.** An HA standby that replicates a
  new CA pair from the leader keeps whatever secondary it already had until `CleanupSecondary`
  expires it. Bounded by the old CA's own `NotAfter` and no worse than before this change, but it
  is a divergence between the two import paths. Recorded as **CA-17**.
- **A single overlap slot.** Two rotations inside one overlap window drop the first secondary
  immediately, ejecting nodes that had renewed against it. `RotateIfNeeded` cannot produce this
  (it only fires inside 30 days of expiry), but two rapid manual imports can. Recorded as **CA-18**.
- **Only the enrollment plane's CA is covered here.** The per-node client certificates themselves
  have no equivalent usability gate on the *presenting* side beyond `checkDPCertExpiry`'s warning;
  the DP's own expiry brick is covered separately by CHAOS-12.
