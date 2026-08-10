# Chaos Engineering Review — 2026-08-10

**Domain:** the **cluster CA** across its full lifecycle — expiry, clock rollback, import
validation, auto-rotation, and the node-certificate renewal clock that hangs off it.
**Register items:** CHAOS-29 (new) · closes standing row **CA-13**; adds and closes four
previously unrecorded defects (**CA-17**, **CA-18**, **CA-19**, **CA-20**).
**Verdict:** six confirmed defects, all fixed, every regression gate proven to fail against
the pre-fix code. (**CA-20** was surfaced in review of PR #1110 — see FS-6.)

---

## Executive Summary

The register named this sweep in advance. CHAOS-28 closed the inspection CA's lifecycle and
left row **CA-13** open with an explicit note: *"the same defect class in the OTHER CA, with a
different lifecycle and blast radius."* That framing turned out to be right about the class
and to understate the blast radius.

The inspection CA fails toward **inspected HTTPS is down**. The cluster CA fails toward **the
fleet cannot talk to its Control Plane** — every DP↔CP mTLS handshake fails path validation
at the dead root, so config sync, heartbeat, and centralised audit all stop at once. But the
property that makes it materially worse is not the size of the outage. It is that the
cluster CA's failure is **self-sustaining through its own recovery path**:

> A Data Plane node whose certificate stopped working re-enrolls. The Control Plane signs a
> fresh certificate with the same expired CA. The new certificate fails exactly as the old
> one did. The node retries. Forever.

Enrollment is the documented recovery for a broken node certificate, and against an expired
CA it ran to completion, reported success, issued a valid-looking certificate, and changed
nothing. The register calls that shape **fake recovery**, and it is the reason the guard
this sweep adds belongs on the *signing path* rather than on a health probe — a probe tells
an operator who is already looking, while the sign gate stops the appliance from
manufacturing certificates it knows cannot work.

| # | Failure mode | Class | Why the existing design did not cover it |
|---|---|---|---|
| 1 | Expired / not-yet-valid cluster CA **keeps signing node certs** | Silent fail-broken → fleet-wide mTLS outage, unrecoverable by re-enrollment | `x509.CreateCertificate` never checks the parent's validity, and nothing else did either |
| 2 | Node cert **not clamped** to the issuer — and it is the DP's renewal clock | Silent fail-broken → renewal never fires before the cliff | node lifetime was a flat `now+365d`, independent of the CA |
| 3 | `ImportCA` **nil-dereferences** when no CA was previously loaded | Panic + persisted/announced state divergence | the secondary is set only in the `cert != nil` branch; the fingerprint read was unconditional |
| 4 | Auto-rotation failure was **log-only + a pull-only API field** | Silent failure → discovered at expiry | no counter, no alert, nothing an alerting rule could evaluate |

\#1 and \#2 are the outage — and they compose: \#2 guarantees the fleet is holding
long-lived node certs that hide \#1 until the CA is already dead. \#3 is what happens to the
operator who tries to recover. \#4 is why nobody was told the clock was running. FS-5 and FS-6
below carry two more: a not-yet-valid CA accepted at import, and — the one review surfaced —
a refused enrollment that **spent the node's one-use token**, so the fix for the outage
consumed the credential needed to apply it.

Everything here is now fail-closed, counted, alerted, and visible on `/metrics`,
`/api/diagnostics`, `/api/cluster/ca` and the Cluster CA panel.

---

## Failure Scenarios

### FS-1 — The expired cluster CA that never stopped signing (CA-13)

**Current behavior (pre-fix).** `SignCSR` (enrollment.go) checked only that a CA was loaded:

```go
if ca.cert == nil || ca.key == nil {
    return nil, "", time.Time{}, fmt.Errorf("cluster CA not initialized")
}
...
certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.key)
```

No validity check on `ca.cert`, at any layer — and, exactly as in CHAOS-28, **the standard
library does not supply one**. This is not an inference. `TestClusterCA_ExpiredCARefusesToSign`
was run against the pre-fix engine and the sign *succeeded*, returning a well-formed one-year
node certificate from a CA that had expired an hour earlier:

```
--- FAIL: TestClusterCA_ExpiredCARefusesToSign
    expired cluster CA signed a node certificate — every mTLS peer would reject it
```

Both call sites in `controlplane_server.go` (`Enroll` at :407 and `RenewCert` at :608) propagate
whatever `SignCSR` returns, so both handed out unusable credentials with a success status.

**Expected behavior.** A trust anchor that cannot perform its function refuses, loudly, in one
place — rather than emitting output that cannot work, N times, silently.

**Failure mode.** Fleet-wide loss of CP↔DP mTLS. Go's own TLS stack is on both ends of this
connection, and it fails the chain at the expired root: `x509: certificate has expired or is
not yet valid`. Config sync stops, heartbeats stop, centralised audit aggregation stops. Data
Plane nodes keep proxying traffic on their last-good config — which is the correct degradation
and the reason this is not instantly customer-visible, and therefore the reason it can run for
a long time undiscovered.

**Blast radius, precisely.** *Simultaneous and fleet-wide.* Every node in a cluster trusts one
cluster CA with one `NotAfter`. There is no canary, no partial degradation, no staggering. And
because the CA is a 10-year certificate, the population most exposed is the one that has been
running longest and is furthest from anyone's attention.

**The recovery trap.** This is the part with no analogue in CHAOS-28. The documented fix for a
node that lost trust is re-enrollment, and re-enrollment *ran fine*: the token validated, the
CSR was accepted, a certificate came back, and the node stored it and reconnected — into the
same failure. An operator can execute the correct runbook, observe every step succeed, and
make no progress. The only signal distinguishing "re-enrollment fixed it" from "re-enrollment
is a treadmill" was the DP-side TLS error, several layers away from where the operator was
working.

**Fix.** `Usable()` (cluster_ca_validity.go) is deliberately **distinct** from `Ready()`, on the
same reasoning CHAOS-28 recorded: `Ready()` answers *is a CA installed*, and callers use it to
decide whether enrollment is offered at all. Folding validity into it would report an expired
CA as "enrollment not configured" — a misleading answer that sends the operator to look at the
wrong subsystem. `SignCSR` now gates on `Usable()` and returns `ErrClusterCAUnusable`, which
both RPC handlers already propagate.

The gate is evaluated **before** taking `ca.mu`, so the observer runs with the lock released —
matching the engine-observer convention `internal/ca` established.

**Why refusing costs nothing.** A node certificate chained to an expired issuer fails
verification in every mainstream stack, including the one at both ends of this specific
connection. The traffic was already dead. What changes is that the appliance now knows, says
so once, and stops manufacturing credentials that cannot work.

---

### FS-2 — The node certificate that outlived its issuer, and hid the cliff (CA-18)

**Current behavior (pre-fix).** `SignCSR` minted an unconditional one-year node cert:

```go
notAfter := time.Now().Add(365 * 24 * time.Hour) // 1 year
```

independent of how much life the *issuer* had. Proven:

```
--- FAIL: TestClusterCA_NodeCertClampedToIssuer
    returned expiry 2027-08-10 outlives the issuer 2026-09-24 by 320 days
```

**Why this is worse here than in CHAOS-28.** The inspection CA's equivalent (CA-1b) was a
diagnosability defect: the leaf looked valid, the chain did not, and incidents moved around as
clients revalidated. The cluster CA's version is a **control-loop** defect, because the node
certificate is not merely a credential — it is the clock the renewal loop runs on:

```go
// dp_enrollment.go
func certNeedsRenewal(certFile string) (int, bool) {
    days := int(time.Until(cert.NotAfter).Hours() / 24)   // ← the NODE cert
```

`dpCertRenewalLoop` renews inside a 30-day window measured against the node certificate.
So a DP that enrolled against a CA with 45 days left received a certificate that looked healthy
for a **year**, and its renewal loop stayed correctly, confidently quiet for 335 days while the
trust anchor underneath it died. The node had a valid certificate and no trust, and nothing on
the node was watching the thing that actually broke.

The CHAOS-12 hardening of that loop — immediate check at boot, latched escalation alerts,
panic containment — is all sound, and all of it was reading the wrong clock.

**Fix.** `clampNodeCertValidity` narrows the node cert to the issuer's window on both ends.
That is not just hygiene: it pulls the DP's existing 30-day renewal window *in front of* the
CA's expiry, so renewal fires while the CA is still alive and dual-CA overlap has something to
hand it. The two mechanisms were designed to work together and were not connected.

`TestClusterCA_HealthyCAStillIssuesFullYear` guards the other direction — a normal 10-year CA
must keep issuing the full one-year cert, so the clamp only ever fires when it is load-bearing.

---

### FS-3 — The import that panicked *after* installing the CA (CA-17)

**Current behavior (pre-fix).** `ImportCA` assigns a secondary only when a CA is already
loaded, then read the secondary unconditionally ~50 lines later:

```go
if ca.cert != nil {
    ca.secondaryCert = ca.cert          // ← only here
    ...
}
...
oldFP := sha256.Sum256(ca.secondaryCert.Raw)   // ← unconditional
```

**Reachability.** `initClusterCA` (main.go:1149) **logs and continues** on failure:

```go
if err := globalClusterCA.InitOrLoad(caDir); err != nil {
    logger.Printf("ClusterCA: init error: %v — enrollment disabled", err)
}
```

A read-only CA directory, a permission-denied volume, a full disk, or a corrupt PEM therefore
leaves a **running** node with `cert == nil`. That is precisely the state in which an admin
reaches for the Cluster CA import — the fix for exactly this situation — and the fix panicked.

**What makes it more than a crash.** The panic lands *after* the new CA is written to disk and
published in memory, and *before* `globalConfigStore.Update(...)`. The pre-fix run shows the
ordering directly — the success log line precedes the segfault:

```
[test] ClusterCA: imported custom CA (expires 2036-08-07, fingerprint db7774d9...)
--- FAIL: TestClusterCA_ImportWithNoPriorCADoesNotPanic
panic: runtime error: invalid memory address or nil pointer dereference
    .../enrollment.go:1237 ImportCA
```

`net/http` recovers per-connection, so the process survives and the admin sees a failed request
— against a CA that **was in fact installed**, persisted, and never announced to any DP node.
The operator's next move is to retry or to escalate, both starting from a false picture of
what the appliance is holding. Failure reported, change applied, fleet not told: three states
that should never disagree.

**Fix.** Guard the tracking block. A first install has no predecessor and therefore no overlap
to track — the correct behaviour is to skip rotation tracking, not to invent it. The tail of
`ImportCA` (config-store bump, rotation counter, recovery observer) now always runs.

---

### FS-4 — The rotation that stopped, quietly (CA-13, observability half)

**Current behavior (pre-fix).** All five failure branches in `RotateIfNeeded` funnel through
`recordRotationFailure`, which stored the message for `Info()`. That is a real improvement over
nothing, and the Cluster CA panel already rendered it. But it is a **pull** surface: it informs
an operator who is already looking at that panel. There was no counter, no alert, and nothing
an alerting rule could evaluate.

`culvert_cluster_ca_rotations_total` counts only *successes*, so a CA that stopped rotating
produced a **flat counter** — indistinguishable from a healthy CA nowhere near its window. The
one metric covering this subsystem was structurally incapable of showing the failure.

**Failure mode.** A cluster CA inside its 30-day window that cannot persist a replacement (the
same read-only-volume class as CA-2) retries every 24h, fails every 24h, and says so only in a
log line and a panel nobody has open. Thirty days later the fleet loses mTLS trust — and, per
FS-1, cannot re-enroll out of it.

**Fix.** `recordRotationFailure` is the chokepoint every branch already used, so the health
plane is pushed from there — a future branch cannot forget it. It now increments
`culvert_cluster_ca_rotation_failures_total`, logs with impact stated, and fires a `cert_expiry`
alert. Bounded by construction (at most one per 24h check), so it needs no rate gate, matching
`ca_health.go`'s treatment of the persist-failure path.

---

### FS-5 — The not-yet-valid CA accepted at the boundary (CA-19)

`parseAndValidateCACert` rejected an already-expired CA but never checked `NotBefore`:

```
--- FAIL: TestParseAndValidateCACert_RejectsNotYetValid
    accepted a cluster CA whose NotBefore is 72h in the future
```

A future-dated CA signs certificates that fail path validation exactly like an expired one,
with the extra confusion that every status surface reports it healthy and "expiring in ten
years". Reached by a CA issued from an offline PKI with a forward-dated window, or by importing
on a node whose clock has rolled back. Now rejected at the boundary — with the same ±5 min skew
tolerance the sign gate uses, so a CA minted moments ago on a slightly fast peer still imports
(`TestParseAndValidateCACert_AcceptsWithinSkew`).

---

### FS-6 — The refused enrollment that spent the node's token (CA-20)

Raised in review of PR #1110, and a genuine extension of FS-1's theme one layer up.

`Enroll` (controlplane_server.go) calls `admitEnrollment` first, which validates and
**consumes** the one-use enrollment token. Every CA check — the pre-existing `Ready()` one and
the new usability gate — sat *after* it. So a node enrolling against a CA that cannot issue
spent its credential, received nothing, and **could not retry once an operator replaced the
CA**: it needed a freshly minted token, which it has no authenticated channel to request.

This is FS-1's failure shape reflected into the credential layer. FS-1 is "the recovery action
runs and changes nothing"; FS-6 is "the recovery action consumes the thing you needed to
recover." An enrollment outage that also destroys the credential needed to recover from it is
strictly worse than the outage.

**Fix.** `clusterCAIssuanceRefusal` runs as a precondition beside the existing HA fencing check
— already the "fail before consuming anything" position in that function — and ahead of
`admitEnrollment`. Restoring the token atomically was considered and rejected: un-consuming a
one-use token is a replay-adjacent operation, and not spending it is simpler than giving it
back correctly. The sign-path gate stays as the backstop that cannot be bypassed; the
precondition governs *when* we fail, not whether. Both paths share one helper so failing
earlier costs no observability.

**Honest scoping.** This predates the CHAOS-29 gate — the old `Ready()` check had the same
placement, so an uninitialised CA burned tokens before this sweep. The usability gate widened
the window materially (an unusable CA is far longer-lived than an uninitialised one), which is
what makes it this sweep's to fix. `RenewCert` needs no equivalent: it consumes no token,
authenticating via the node's existing certificate.

Pinned by `TestEnroll_UnusableCADoesNotConsumeToken`, verified to fail with the precondition
removed.

---

## Risk Matrix

| ID | Failure mode | Likelihood | Impact | Detect (pre) | Detect (post) | Residual |
|----|--------------|-----------|--------|--------------|---------------|----------|
| CA-13a | Expired/not-yet-valid cluster CA signs unusable node certs | Low-Med (10y cert; reached via clock skew, restored backup, imported near-expiry CA, or a long-lived deployment) | **Critical** — fleet-wide CP↔DP outage, unrecoverable by re-enrollment | None | Sign refusal + counter + alert + `usable` gauge + diagnostics row | Low |
| CA-18 | Node cert outlives issuer; DP renewal clock reads the wrong certificate | **High** — fires on every enrollment inside the CA's final year | High — renewal never triggers before the cliff | None | Clamped at signing; DP window now precedes CA expiry | Low |
| CA-17 | `ImportCA` panics with no prior CA; state divergence | Med — reached by the exact recovery action for a failed `InitOrLoad` | High — operator misled during an incident | Panic in logs only | Guarded; import completes and announces | Low |
| CA-13b | Auto-rotation stops silently | Med | High — becomes CA-13a in ≤30 days | Log line + panel field | Counter + alert + degraded status row | Low |
| CA-19 | Not-yet-valid CA imported | Low | High | None | Rejected at import | Low |
| CA-20 | A refused enrollment **consumes the one-use token**, so the node cannot retry after the CA is fixed | Med (fires on every refused enrollment) | High — the recovery action destroys the credential needed to apply it | None | Refused as a precondition, before anything is consumed | Low |

---

## Recovery Assessment

| Scenario | Automatic | Manual | Notes |
|---|---|---|---|
| Cluster CA expired | ✗ (by design) | Import a replacement, then re-enroll every DP | Rotation is the only automatic path and it must run *before* expiry — which is what FS-4's alerting now protects |
| Rotation failing on a read-only volume | ✗ | Restore write access; next check rotates, or import manually | Degraded row clears on **observed** success, never on elapsed time |
| Node cert nearing expiry | ✓ | — | CHAOS-12 loop, now reading a clock clamped to the issuer |
| `InitOrLoad` failed at boot | ✗ | Import via `/api/cluster/ca` | This is the path FS-3 unblocked |
| Clock rolled back | ✓ within ±5 min | Fix NTP | Outside tolerance, fails closed rather than signing |

**The one recovery this sweep deliberately does not automate:** an expired cluster CA requires
re-enrolling the fleet. That is inherent — a new trust anchor means new credentials for every
node — and inventing an automatic path would mean accepting an unauthenticated re-enrollment,
which trades an availability incident for a security one. The design choice is to make the
condition impossible to miss *before* it arrives, not to soften it afterward.

---

## Operational Impact

**Before:** an expired cluster CA moved nothing an operator could scrape. `/api/cluster/ca`
reported `initialized: true`, the rotations counter sat flat, no expiry series existed, and no
diagnostics row covered it. The first symptom was DP nodes going stale — several layers from
the cause.

**After:**

| Surface | Signal |
|---|---|
| `/metrics` | `culvert_cluster_ca_usable`, `culvert_cluster_ca_expires_in_seconds`, `culvert_cluster_ca_sign_refused_total`, `culvert_cluster_ca_rotation_failures_total` |
| `/api/diagnostics` | `cluster_ca` operator-contract row (fail / warn / ok + operator action) |
| `/api/cluster/ca` | `usable`, `unusableReason`, `expiresInDays` |
| Alerts | `cert_expiry` from `culvert-cluster-ca` — usability (5-min gated) and rotation failure (bounded by cadence) |
| GUI | Cluster CA panel: `UNUSABLE` status, red banner with the operator action, day countdown that turns red inside 30 days |

`culvert_cluster_ca_expires_in_seconds` is the one to alert on well before the cliff; the rest
confirm the cliff was hit.

**Both gauges are omitted entirely when no cluster CA is loaded.** Most Culvert deployments are
standalone proxies with no cluster CA at all, and `culvert_cluster_ca_usable 0` on every one of
them would read as a fleet-wide outage. An absent series is honest; a `0` is not — and the
alerting rule an operator writes has to be safe to deploy without first enumerating which nodes
are Control Planes. Pinned by `TestClusterCA_MetricsOmittedWithoutCA`.

---

## Security Impact

**Net positive, with one honest trade recorded.**

- **Fail-closed, not fail-open.** The refusal denies enrollment; it never admits a node on a
  weaker path. There is no branch here that downgrades to "trust it anyway" — deliberately, and
  by contrast with the decryption-profile `fail-open` posture, whose confirm-count contract is
  scoped to per-origin incompatibility and would be meaningless against an appliance-wide fault.
- **No new material exposure.** All new surfaces are counts and one time delta, label-free per
  the CA-2 metrics contract — no node ID, subject, serial, fingerprint, or key material.
- **Viewer-role guardrail respected.** The `cluster_ca` diagnostics row carries impact and a
  count, never the raw cause, which names the appliance's exact certificate state. Full detail
  stays in the logs, the alert, and the admin-role API. Pinned by
  `TestClusterCA_DiagnosticsRowFailsClosed`.
- **The trade:** refusing to sign converts a silent trust failure into an explicit enrollment
  outage. Enrollment was already broken in every way that mattered — the certificates issued
  could not authenticate — so this surrenders no availability that existed. It does mean a
  cluster whose CA expires now fails *visibly* rather than *slowly*. That is the intended
  direction.

---

## Suggested Improvements (deferred, recorded)

1. **Rotation retry/backoff.** A failed cluster-CA rotation waits a full 24h, exactly the CA-4
   residual CHAOS-28 left open for the inspection CA. Both CAs share `StartCAAutoRotation`, so
   one bounded-retry change covers both — worth doing as a single scoped change rather than
   twice.
2. **`ImportCA` two-file commit.** The existing comment is candid that a crash between the cert
   and key writes leaves a mismatch, detected at next startup by cross-validation and failing
   closed. Fail-closed is correct; the window remains.
3. **Cluster CA on `/healthz`.** `ssl_inspection` has an expiry-aware state; the cluster CA is
   surfaced on diagnostics and metrics but not on the health probe. Deferred as a probe-schema
   change, not a defect.
4. **Fleet-wide expiry aggregation.** Each CP reports its own CA. A cluster whose CP nodes
   somehow diverge would need cross-node comparison to notice — out of scope here.

---

## Required Tests — all present, all proven to fail pre-fix

`cluster_ca_validity_test.go`:

| Test | Pins |
|---|---|
| `TestClusterCA_ExpiredCARefusesToSign` | FS-1 — refusal, sentinel, counter, health record |
| `TestClusterCA_ClockRollbackRefusesToSign` | FS-1 far end |
| `TestClusterCA_SkewToleranceDoesNotBreakFreshCA` | the guard is not too tight |
| `TestClusterCA_NodeCertClampedToIssuer` | FS-2 — both the returned expiry and the certificate |
| `TestClusterCA_HealthyCAStillIssuesFullYear` | no over-clamping |
| `TestClusterCA_ImportWithNoPriorCADoesNotPanic` | FS-3 — and that the tail of `ImportCA` ran |
| `TestParseAndValidateCACert_RejectsNotYetValid` / `_AcceptsWithinSkew` | FS-5, both directions |
| `TestClusterCA_RotationFailureIsCountedAndDegraded` | FS-4 |
| `TestClusterCA_RotationRecoveryOnEvidence` | recovery on evidence; counter never goes backwards |
| `TestClusterCA_MetricsOmittedWithoutCA` / `_MetricsReportUnusable` | standalone-node posture |
| `TestClusterCA_DiagnosticsRowFailsClosed` / `_SilentOnStandalone` | operator contract + viewer guardrail |
| `TestClusterCA_InfoSurfacesUsability` | admin API |
| `TestEnroll_UnusableCADoesNotConsumeToken` | FS-6 — the token survives a refused enrollment, and failing early still counts |

**Evidence of gate strength.** Each defect gate was executed against a copy of the tree with
*only the four fixes* reverted (observability scaffolding retained, so the failures isolate the
behaviour and not a compile error). All five defect gates failed; the observability gates
passed, as they should. That separation is what makes the suite a regression wall rather than a
snapshot of current behaviour.

---

## Residual Risk

**Low, with three named residuals.**

- **Rotation retry cadence (shared with CA-4).** A transient failure costs 24h. Bounded and
  alerted, no longer silent — but still slow.
- **Import atomicity.** The cert/key write pair is not a true two-file commit; a crash between
  them fails closed at next startup with no auto-repair, by existing design.
- **Recovery remains manual by design.** An expired cluster CA requires an import plus fleet
  re-enrollment. Automating it would require accepting unauthenticated re-enrollment. The
  mitigation is detection far enough ahead — which is what this sweep delivers.

**What is now structurally impossible:** the cluster CA cannot silently issue credentials that
cannot authenticate; a node certificate cannot outlive the CA that signed it; the import path
cannot panic partway through and leave disk, memory, and the fleet disagreeing; and rotation
cannot stop without a counter, an alert, and a status row saying so.
