# Chaos Engineering Review — 2026-08-18

**Domain:** the **cluster CA** across its lifecycle — the Certificate Authority that signs
Data-Plane node certificates, and therefore owns the credential for every CP↔DP mTLS
channel in the fleet.
**Register items:** **CA-13**, open since 2026-08-09 and named as the next sweep by both
of the last two reviews ("the CHAOS-28 defect class in the *other* CA"). This sweep
confirms CA-13 and finds the domain is worse than recorded in four further ways, none of
which are about rotation reporting at all.
**Verdict:** **seven** confirmed defects, all fixed. Five were reproduced empirically against
unmodified `main` before any fix was written; FS-6 was found while restructuring the code the
fifth lives in; **FS-7 — a self-deadlock that wedges the entire enrollment plane on every real
Control Plane — was found by the tests written for this change, and is the most severe finding
in the sweep.**

---

## Executive Summary

CHAOS-28 (2026-08-09) hardened the **inspection CA** against its own expiry. The finding
that drove it was that `x509.CreateCertificate` does not check the parent's validity
window, so an expired Root CA kept minting well-formed leaves that every client rejected —
a fleet-wide inspected-HTTPS outage with `/healthz` reporting `ssl_inspection: ready`
throughout. The fix separated `Usable()` from `Ready()`, failed the sign path closed,
clamped leaves to their issuer, and built a health plane around all of it.

That review closed by naming what it had not touched: **the cluster CA has none of it.**
This sweep confirms that, and the domain turns out to hold five more defects beyond the
one recorded.

The blast radius is worse than the inspection CA's, and in a way that is easy to
understate. A DP node certificate is the credential for the mTLS channel that carries
every `ConfigSnapshot`. When it stops validating, the Data Plane does not fail, alarm, or
stop: it **keeps serving traffic under whatever policy it last received, indefinitely**,
while the Control Plane believes it is publishing. A policy change an operator makes to
stop an active incident silently never arrives. An inspection-CA expiry is a loud outage;
a cluster-CA expiry is a silent, fleet-wide **configuration freeze**.

| # | Failure mode | Class | Why the existing design did not cover it |
|---|---|---|---|
| 1 | An **expired cluster CA still signs** node certificates; enrollment reports success | Silent fail-open → cluster-wide enrollment outage | `Ready()` (= a CA is loaded) was the only gate; nothing asked whether the CA could still *issue* |
| 2 | Cluster-CA auto-rotation is **gated on the inspection CA loading** | SPOF / hidden coupling | one loop drives two unrelated CAs, and the startup call sat behind `if certMgr.Ready()` |
| 3 | Node certificates are **not clamped to their issuer** | Broken recovery — the node's own renewal trigger is fed a false deadline | leaf `NotAfter` was unconditionally `now + 1 year` |
| 4 | An **expired CA on disk loads silently** at boot | Silent failure | `loadFromPEM` has no validity check, and its success log reads like success |
| 5 | A **failed rotation** is recorded only in an admin-API JSON field | Silent failure | `recordRotationFailure` fed `Info()` and nothing else — no counter, no alert, no probe |
| 6 | A **failed `ImportCA` mutates live dual-CA state**, and importing into an uninitialised CA **panics** | State corruption + crash on the recovery path | in-memory swap ran before persistence; rotation tracking dereferenced a secondary that need not exist |
| **7** | **`ImportCA`/`CleanupSecondary` self-deadlock on the process-global CA**, permanently wedging the CA write lock | **Deadlock → total enrollment-plane hang** | re-entrant callbacks (`onRotate`, `CurrentConfigSnapshot`) were invoked while `ca.mu.Lock()` was held; every existing test uses a LOCAL `&clusterCA{}`, where the re-entrant read lands on a different mutex |

Defects 1 and 2 are the serious pair, and they compound. Defect 2 means the appliance can
silently stop rotating the cluster CA; defect 1 means that when the CA then expires,
nothing refuses, nothing counts, and nothing alerts — the Control Plane hands every node a
certificate that cannot work and reports that enrollment succeeded.

Defect 2 deserves emphasis because the coupling is invisible from either side. The
auto-rotation loop drives **two CAs with nothing in common**, and it was started only when
the *inspection* CA had loaded:

```go
if certMgr.Ready() {
    StartCAAutoRotation(ctx, cfg.Path, cfg.Passphrase)
}
```

`certMgr.Ready()` is false in exactly the situation register row **CA-3** already
describes — a corrupt bundle, a wrong `CULVERT_CA_PASSPHRASE`, an unreadable bundle path.
That is not exotic; it is the ordinary consequence of restoring a backup with the wrong
passphrase. And it is specifically the *existing-bundle* path that leaves `Ready()` false,
because `LoadOrInitCA` routes an existing file straight to `LoadCA` without ever calling
`InitCA`:

```go
func (cm *Manager) LoadOrInitCA(path, passphrase string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		... InitCA() ... SaveCA() ...
	}
	return cm.LoadCA(path, passphrase)   // ← failure here leaves Ready() false
}
```

So one operator mistake produced two failures on wildly different fuses: SSL inspection
goes down **today**, loudly, with a `ca_load_failed` alert — and the ability to enroll or
renew any node in the fleet goes down **in ten years**, silently, with nothing connecting
the two events. By the time the second fires, the first is long forgotten.

Defect 3 is the one that makes the resulting incident hardest to diagnose. The DP's own
renewal trigger reads its certificate's `NotAfter`:

```go
// dp_enrollment.go — certNeedsRenewal checks if a PEM cert file expires within 30 days
```

Unclamped, a node enrolled shortly before the cluster CA expires is handed a **full-year**
certificate. Its renewal logic therefore reports a year of runway and does nothing —
through the entire window in which it had to renew — while every handshake it makes has
been failing since the day its issuer expired. The node's view of its own health and the
truth are exactly inverted, which is the same shape CHAOS-28 recorded as CA-1b for the
inspection CA.

### Measured, against `main`

A temporary proof harness (`TestProof_*`, removed before commit) was run against the
unmodified engine. Every defect reproduced on the first attempt:

```
PROOF 1: InitOrLoad accepted an EXPIRED cluster CA; Ready()=true
PROOF 2: expired CA signed node cert serial=f92072ec… expiry=2027-08-18T22:15:29Z
PROOF 2: chain verification of that cert: x509: certificate has expired or is not yet
         valid: current time 2026-08-18T22:15:29Z is after 2026-08-17T22:15:29Z
PROOF 3: CA NotAfter=2026-09-07  leaf NotAfter=2027-08-18  (leaf outlives issuer by 345 days)
PROOF 3: DP certNeedsRenewal() would report needsRenewal=false (~365 days left) while
         every handshake fails from day 20
PROOF 4: ImportCA failed as expected: write cluster CA cert: … rename: file exists
PROOF 4: after the FAILED import — SecondaryActive()=true
PROOF 4: AllCACertsPEM() now emits 1254 bytes (primary duplicated as secondary: true)
PROOF 5 CONFIRMED: ImportCA panicked with no prior CA:
         runtime error: invalid memory address or nil pointer dereference
```

Post-fix, the same harness fails at every assertion — signing is refused with
`cluster CA unusable: expired at …`, the leaf clamps exactly to the issuer
(`leaf outlives issuer by -0 days`), the failed import leaves `SecondaryActive()=false`,
and the first install does not panic.

---

## Failure Scenarios

### FS-1 — An expired cluster CA issues node certificates that cannot work

**Current behavior (pre-fix).** `SignCSR` checked `ca.cert == nil || ca.key == nil` and
nothing else. `x509.CreateCertificate` does not validate the parent's window, so an expired
cluster CA produced a syntactically perfect node certificate. The gRPC `Enroll` handler
returned it with `codes.OK`; the CP registered the node as `connected`; the admin UI
reported `enrollEnabled: true`.

**Expected behavior.** Refuse, loudly and countably.

**Why refusing costs nothing.** A leaf chained to an expired issuer fails path validation
in every TLS stack, so the enrollment was already dead. Refusing does not remove
availability that signing preserved. What changes is that the appliance now *knows*: one
counted, named, alerted event on the node that can fix it, instead of N indistinguishable
handshake failures on N nodes that cannot.

**Fix.** `clusterCAUsable(cert, now)` — a pure predicate with a 5-minute clock-skew
tolerance matching the inspection CA's — consulted at the top of `SignCSR`, returning an
error wrapping `ErrClusterCAUnusable` and recording the refusal.

`Usable()` is deliberately **distinct from `Ready()`**, for a different reason than in
CHAOS-28. There, folding validity into `Ready()` would have routed the fault into the
bypass branch and silently disabled every inspection control. Here the hazard is
diagnostic: `Ready()` is what the enrollment surfaces use to decide whether to *offer*
enrollment, and its failure message is "cluster CA not initialized". Reporting that for a
CA which is very much initialized — just expired — sends the operator to the wrong runbook
at the worst moment.

### FS-2 — Cluster-CA rotation is silently disabled by an unrelated subsystem

**Current behavior (pre-fix).** As described in the summary: `StartCAAutoRotation` — the
only driver of `globalClusterCA.RotateIfNeeded()` anywhere in the process — was started
only `if certMgr.Ready()`.

A second reachability path made it worse. `enableControlPlane` is callable from the admin
API, so a node can *become* a Control Plane at runtime and acquire a cluster CA long after
the startup decision was made. Nothing started the loop for it.

**Fix.** The gate is removed and the call made unconditional; `StartCAAutoRotation` is now
idempotent (a `CompareAndSwap` on `caAutoRotationStarted`), and `enableControlPlane` claims
it too. The gate bought nothing to begin with: `RotateIfNeeded` returns immediately when
its CA has no expiry, and `CleanupSecondaryCA` is nil-safe, so on a node with no inspection
CA the loop costs one zero-check per 24-hour tick.

Making the call idempotent rather than adding a second, cluster-CA-only loop is the
load-bearing choice. A second loop would have to be started from every present and future
promotion path, and forgetting one reproduces exactly this defect in a new place.

### FS-3 — Node certificates outlive their issuer

**Current behavior (pre-fix).** `notAfter := time.Now().Add(365 * 24 * time.Hour)`,
unconditionally.

**Fix.** `clampNodeCertValidity` narrows the window to the issuer's on both ends. The
returned `expiry` — which the CP stores as `EnrolledNode.CertExpiry` and the DP writes to
disk — is the clamped value, so all three views of the node's lifetime agree.

**Deliberate consequence.** As a cluster CA approaches expiry, node certificates get
correspondingly short, and DPs begin renewing every 6-hour tick until the CA rotates. That
is not churn to be suppressed; it is the system reacting correctly to a deadline it
previously could not see, and it is the pressure that gets every node onto the new CA once
rotation happens. Pre-fix the nodes sat still and then broke.

### FS-4 — An expired CA loads silently at boot

**Current behavior (pre-fix).** `loadFromPEM` parses, cross-validates cert against key, and
logs `ClusterCA: loaded existing cluster CA (expires 2019-04-02)` — a line that reads like
success and is the entire signal.

There was an asymmetry here too: `ImportCA` has always *refused* an expired CA
(`parseAndValidateCACert`), so an operator could not install one deliberately while the
loader accepted one silently on every boot.

**Fix.** Still loads — refusing would brick the one node that can repair the situation, and
rotation is the recovery path (`RotateIfNeeded` treats a negative remaining lifetime as
due, and since CHAOS-28 the loop runs a round immediately at startup rather than at +24h).
But the fault is now recorded, so the counter, the alert, and every status surface are
armed from the first second of uptime instead of from the first node that fails to enroll.

### FS-5 — A failed rotation is invisible (CA-13 as recorded)

**Current behavior (pre-fix).** `recordRotationFailure` wrote `lastRotationErr` +
`lastRotationErrAt` for `Info()` to surface on `/api/cluster/ca`. Nothing counted it,
nothing alerted, no probe moved. `culvert_cluster_ca_rotations_total` counts only
*successes*, so a CA whose rotation had failed every day for a month is indistinguishable
on that series from one that simply is not due yet — flat in both cases.

**Fix.** The health plane in `cluster_ca_validity.go`, mirroring `ca_health.go` and
`storage_health.go`: count every event, rate-limit the log and the alert on independent
gates, never spawn a delivery goroutine when nothing subscribes, and report recovery on
**evidence** — an observed successful rotation — never on elapsed time.

Two rules carried over deliberately. The cumulative counter is never decremented (it feeds
a Prometheus counter, which must not go backwards), and the *status* row is keyed on
`clusterCARotationDegraded()` rather than on that counter — a counter-keyed warning would
latch until process restart and keep contradicting an operator who had already fixed the
volume and rotated.

The alert reuses the existing `cert_expiry` event name rather than introducing a new one.
An operator who already subscribed a webhook to certificate-lifecycle events must not have
to discover and add a second name to keep hearing about the CA whose expiry takes the whole
cluster down. `Host` (`culvert-cluster-ca` vs `culvert-ca`) distinguishes them.

### FS-6 — `ImportCA` corrupts live state on failure, and panics on the recovery path

Two defects in one function, both on paths an operator reaches while *repairing* a cluster
CA.

**State corruption.** The dual-CA overlap assignment ran **before** the persistence writes.
A write failure — full or read-only volume, a path occupied by something that is not a
regular file — returned an error having already installed the current CA as its own
secondary. `SecondaryActive()` flipped true, `AllCACertsPEM()` emitted the same certificate
twice into the CP's client CA pool, and the next `CleanupSecondary` fired `onRotate` and
called `globalClusterStore.ClearCARotation()` for a rotation that never happened.

**Crash.** Rotation tracking dereferenced `ca.secondaryCert` unconditionally:

```go
oldFP := sha256.Sum256(ca.secondaryCert.Raw)
```

A first install has no secondary. That state is not hypothetical — it is precisely the
state a Control Plane is in when `initClusterCA` failed at boot ("ClusterCA: init error …
— enrollment disabled"), which is exactly when an operator opens the Cluster CA panel and
imports a good pair to recover. The import panicked half-way through, after the files had
been written and after `onRotate` had already fired.

**Fix.** Persist-before-swap: the writes happen first, and no in-memory state is touched
until both succeed, so a failed import is a true no-op on live state. Rotation tracking is
guarded on a `hadPrior` flag — a first install is not a rotation, there is no old
fingerprint for nodes to migrate off, and there is nothing to track.

The pre-existing two-file non-atomicity is unchanged and still documented in place: a crash
*between* the cert and key writes can leave a mismatched pair on disk, which the next
startup detects via `loadFromPEM` cross-validation and fails closed on.

### FS-7 — `ImportCA` and `CleanupSecondary` self-deadlock the cluster CA

**The most severe finding in this sweep, and the one nothing was looking for.** It was found
by the tests written for FS-1..FS-6, not by review.

**Current behavior (pre-fix).** `ImportCA` holds `ca.mu.Lock()` for its whole body, and from
inside that critical section calls out to two things that read the CA again:

```go
ca.mu.Lock()
defer ca.mu.Unlock()
...
ca.onRotate()                                   // → rebuildCPCertPool
                                                //   → globalClusterCA.AllCACertsPEM() → ca.mu.RLock()
...
_ = globalConfigStore.Update(CurrentConfigSnapshot())
                                                // → globalClusterCA.CACertFingerprint() → ca.mu.RLock()
```

`sync.RWMutex` is not reentrant. Taking `RLock` while the same goroutine holds `Lock` blocks
forever. `CleanupSecondary` has the identical shape.

**Why it fires only in production.** The re-entrant calls do not go through the receiver —
they go through the package-level `globalClusterCA`. On any *other* instance those resolve
to a different mutex and are completely harmless. Every test in this repository constructs a
local `&clusterCA{}`, and `buildServerTLS` — which installs the `onRotate` callback — never
runs in them. So the deadlock requires exactly the production configuration:
`globalClusterCA` as the receiver, with mTLS wired. That is why a suite of 1300+ tests,
including ones specifically covering cluster-CA rotation and import, never saw it.

**Impact.** On a Control Plane, the first cluster-CA rotation or manual import hangs
forever **while holding the CA write lock**. `SignCSR` takes `RLock`, so from that instant
every node enrollment and every certificate renewal blocks permanently. The admin API
request that triggered a manual import never returns. Nothing recovers without a restart —
and a restart re-enters the same path if the CA is still inside its rotation window.

It fires precisely when the CA is being replaced. The recovery path for cluster-CA expiry
deadlocks the very subsystem it exists to recover.

**Interaction with FS-2 — why this had to ship in the same change.** FS-2's fix makes
rotation *actually run* on nodes where it previously never did (an inspection-CA fault no
longer disables it, and a runtime promotion now schedules it). Shipping FS-2 without FS-7
would have converted a silent failure-to-rotate into a hard hang, on more nodes than before.
The two are one change.

**Fix.** Both methods are split: a locked core that persists and swaps in-memory state and
performs **no** call that can re-enter the receiver, and an epilogue that runs after the
lock is released and owns every outward-facing side effect (`onRotate`,
`StartCARotation`, the config-snapshot republish, the metric). The `onRotate` function
pointer is captured under the lock and invoked outside it.

Keeping the epilogue outside the lock is a **correctness requirement, not a style
preference**, and is commented as such at both sites — the failure mode is a silent hang,
and the next person to "tidy up" by folding a call back inside would reintroduce it with no
test failure to warn them, unless they hit the new global-instance tests below.

**How the tests differ from every other test in the file.** The three FS-7 tests operate on
the **global** instance with `onRotate` wired, because that is the only configuration that
reproduces it. Each runs its subject on a goroutine under an explicit timeout, because a
regression here manifests as a hang rather than a failed assertion — without the watchdog
the whole package would simply time out with no indication of the cause. Each also asserts
that `onRotate` actually fired, so the test cannot pass vacuously by never taking the
re-entrant path at all.

---

## Risk Matrix

| ID | Failure mode | Likelihood | Impact | Pre-fix detection | Status |
|---|---|---|---|---|---|
| FS-1 | Expired cluster CA issues unusable node certs | Low (10y fuse) | **Critical** — no node can enroll or renew; fleet-wide config freeze | **None** | CLOSED |
| FS-2 | Rotation silently disabled by inspection-CA fault | **Medium** — a wrong passphrase is an ordinary ops event | **Critical** (as FS-1, with certainty added) | **None** | CLOSED |
| FS-3 | Node cert outlives issuer | **High** — every enrollment in the CA's final year | High — nodes never renew; the incident is maximally hard to diagnose | **None** | CLOSED |
| FS-4 | Expired CA loads silently at boot | Low | Medium — removes the last chance to notice before impact | Log line reading as success | CLOSED |
| FS-5 | Failed rotation invisible | Medium | High — removes the only recovery path, silently | `/api/cluster/ca` JSON field | CLOSED |
| FS-6 | Failed import corrupts state / first install panics | Medium — both are repair-path operations | High — corrupts the CP client CA pool; crashes the recovery | **None** | CLOSED |
| **FS-7** | **Self-deadlock on rotation/import** | **Certain** on any CP that rotates or imports | **Critical** — CA write lock held forever; all enrollment and renewal hang; no self-recovery | **None** (a hang, not an error) | CLOSED |

---

## Recovery Assessment

**Automatic.** Rotation is the recovery for an expired or near-expired cluster CA, and it
is now reliably driven: the loop starts unconditionally, runs a round immediately at
startup, and treats a negative remaining lifetime as due. A Control Plane that boots with
an expired cluster CA rotates within seconds of startup rather than never.

**Manual.** Where automatic rotation cannot run — no write access to the CA directory, a
CA the operator wants to replace with their own PKI — `POST /api/cluster/ca` import is the
path, and FS-6 makes it work from the two states an operator actually reaches it from.

**Residual manual step.** Rotating a cluster CA that has *already* expired means every
existing node certificate was signed by a CA that is gone: dual-CA overlap retains the old
CA only until its own `NotAfter`, which is in the past. Those nodes must re-enroll. This is
unchanged by this work and is inherent — the credentials were already invalid. What changes
is that the situation is now detected months earlier, via
`culvert_cluster_ca_expires_in_seconds`, while ordinary rotation still fixes it without
touching a single node.

---

## Operational Impact

New surfaces, all label-free per the CA-2 metrics contract (no node ID, subject, serial,
fingerprint, or key material):

| Surface | Signal |
|---|---|
| `/metrics` | `culvert_cluster_ca_usable` (gauge) |
| `/metrics` | `culvert_cluster_ca_expires_in_seconds` (gauge; **omitted** when no cluster CA is loaded, so it never pages on a Data Plane) |
| `/metrics` | `culvert_cluster_ca_sign_refused_total` (counter) |
| `/metrics` | `culvert_cluster_ca_rotation_failures_total` (counter) |
| `/readyz` | `cluster_ca` row — report-only; absent on nodes with no cluster CA |
| `/api/cluster/ca` | `usable`, `usableError`, `signRefusals`, `rotationFailures`, `rotationDegraded` |
| Alerts | `cert_expiry` from `culvert-cluster-ca` — on refused issuance (rate-limited) and on failed rotation |

`culvert_cluster_ca_expires_in_seconds` is the one to alert on, months ahead of the cliff.
The rest confirm the cliff was hit.

The `cluster_ca` readiness row is **report-only** and never gates the default verdict, for
the same reason the `ca` row does not: an expired cluster CA does not stop this node serving
proxy traffic, and gating readiness on it would pull a healthy gateway out of a
load-balancer rotation over a control-plane fault. A failing *rotation* does not even set
the row to `fail` — it rides an `ok` row's detail, so the endpoint's `ok`/`fail` vocabulary
stays exactly what every existing consumer handles.

---

## Security Impact

**Net positive, with one honest trade.**

FS-1's fix converts a fail-open into a fail-closed. Pre-fix, an expired cluster CA produced
certificates that no peer would accept — which is fail-closed *by accident*, via the peer's
validation, not by the appliance's decision. The distinction matters: the appliance's own
records said the node was enrolled and connected, so its notion of cluster membership
diverged from reality with no signal. Making the refusal explicit means the CP's records
and the fleet's actual trust state agree.

FS-3's clamp removes a class of certificate that should never have been issued: a
credential asserting validity beyond its issuer's. Nothing accepted those in practice, but
issuing them at all is a PKI hygiene failure and it is what fed the DP a false deadline.

The `usableError` string on `/api/cluster/ca` names the violated bound and a timestamp. It
carries no key material and no path, and the endpoint is role-gated. The unauthenticated
`/readyz` row deliberately carries a fixed detail with no cause — and unlike the `ca` row,
naming the posture here is safe, because this failure fails *closed*: it tells an observer
that issuance is refused, not that traffic is flowing uninspected.

---

## Data-Integrity Impact

FS-6's persist-before-swap removes a state-corruption path in the CP's TLS client CA pool.
The pre-existing two-file write non-atomicity is unchanged and remains detected-and-fail-closed
at next startup.

No persisted format changed. No config surface changed — the health record is process-local
and volatile by construction, so it is off export/import, off rollback, and off CP→DP sync,
and `config_surfaces_test.go` is unaffected.

---

## Required Tests

All in `cluster_ca_validity_test.go`. Every one of them failed on the commit before this work.

| Test | Pins |
|---|---|
| `TestClusterCA_ExpiredCARefusesToSignNodeCert` | FS-1 — refusal wraps `ErrClusterCAUnusable`, is counted, and alerts once |
| `TestClusterCA_NotYetValidCAIsRefusedButSmallSkewIsTolerated` | FS-1 — clock rollback fails closed; skew inside tolerance does not |
| `TestClusterCA_UsableCAStillSignsNormally` | the healthy path is untouched, and the issued cert really chains to its issuer |
| `TestClusterCA_NodeCertIsClampedToIssuerWindow` | FS-3 — both ends clamped; returned expiry agrees with the certificate |
| `TestClusterCA_ClampDoesNotShortenCertsUnderALongLivedCA` | FS-3 — the clamp is a ceiling, not a new policy |
| `TestClampNodeCertValidity_NilIssuerIsIdentity` | FS-3 — degenerate input |
| `TestClusterCA_ExpiredCAAtBootIsLoadedButRecorded` | FS-4 — loads (recovery stays possible) but is counted and alerted |
| `TestClusterCA_ReadyAndUsableAreDistinct` | FS-1 — the two predicates must not be merged |
| `TestClusterCA_FailedImportDoesNotMutateLiveState` | FS-6 — persist-before-swap |
| `TestClusterCA_ImportIntoUninitialisedCASucceeds` | FS-6 — the recovery path no longer panics |
| `TestClusterCA_SuccessfulImportStillEstablishesOverlap` | FS-6 — the reordering did not cost dual-CA overlap |
| `TestClusterCA_RotationFailureIsCountedAndAlerted` | FS-5 — counter + alert + `Info()` agreement |
| `TestClusterCA_RotationDegradedClearsOnObservedSuccess` | FS-5 — evidence-driven recovery; counter never decrements |
| `TestClusterCA_RefusalAlertIsRateLimitedButCountsAreNot` | FS-5 — a 25-attempt storm ⇒ 25 counted, 1 alert |
| `TestClusterCA_UsabilityRecoveryRequiresObservedEvidence` | FS-5 — silence is not recovery |
| `TestClusterCA_RotationLoopIsNotGatedOnTheInspectionCA` | FS-2 — the anti-regression wall on the coupling |
| `TestClusterCA_AutoRotationStartIsIdempotent` | FS-2 — repeat claims start at most one ticker |
| `TestClusterCA_RepeatStartStillRunsARotationCheck` | FS-2 — a repeat call still runs a round, so a runtime promotion's newly-loaded CA is not left unrotated for up to 24h |
| `TestClusterCA_RotationRoundRotatesNearExpiryCA` | FS-2 — the round itself rotates a CA inside its window |
| `TestClusterCA_ImportRejectsNotYetValidCA` | admission and use share one predicate, so an import cannot succeed and immediately disable issuance |
| `TestClusterCA_ManualImportClearsRotationDegraded` | the documented manual recovery clears the degraded state |
| `TestClusterCA_FailedImportDoesNotClearRotationDegraded` | …but only a PERSISTED import is evidence |
| `TestClusterCA_StateGaugesOmittedOnNodesWithoutAClusterCA` | the gauges are absent on non-issuers, so a `== 0` alert cannot fire fleet-wide |
| `TestClusterCA_ImportOnGlobalInstanceDoesNotSelfDeadlock` | **FS-7** — the production configuration, bounded by a watchdog |
| `TestClusterCA_CleanupSecondaryOnGlobalInstanceDoesNotSelfDeadlock` | **FS-7** — the same shape on the tick path |
| `TestClusterCA_AutoRotationOnGlobalInstanceDoesNotSelfDeadlock` | **FS-7** — the full production rotation round |

The health record is reset per test via `resetClusterCAHealthForTest`, and alerts are
observed through the `fireClusterCAAlert` seam rather than the process-global alert store,
so nothing here depends on webhook wiring or survives into another test under
`-count=2 -shuffle=on`.

---

## Residual Risk

- **Renewal churn near CA expiry (new, accepted).** With FS-3's clamp, node certificates
  issued while the cluster CA is inside its final 30 days are short, so DPs renew on every
  6-hour tick until the CA rotates. Renewals are cheap and the window is short (rotation
  triggers at 30 days out and force-renews every connected node), and the alternative is
  the pre-fix behaviour where nodes sat still and then broke. Worth revisiting only if an
  estate reports load.

- **`ImportCASilent` is unguarded.** The HA replication path (`ha.go`) installs the
  leader's CA without a validity check. Left as-is deliberately: the leader is the
  authority, and a standby that refused the leader's CA would diverge from the cluster
  rather than converge with it. `loadFromPEM` still records the fault, so a replicated
  expired CA is visible on the standby.

- **Nodes offline through the rotation window still need re-enrollment.** Dual-CA overlap
  ends at the *old* CA's `NotAfter`. A node powered off across that boundary comes back
  with a certificate signed by a CA no longer in the pool. Unchanged by this work; the
  earlier detection FS-5 provides is what gives an operator time to notice.

- **The two-file CA write is still not atomic.** A crash between the cert and key writes
  leaves a mismatched pair, detected and failed closed at next startup. Auto-repair remains
  out of scope, as recorded in the original code.

- **The lock split is enforced by comment and test, not by the type system.** Nothing
  prevents a future change from moving a call back inside `importLocked`. The three
  global-instance tests are the wall; the comments at both sites say explicitly that the
  epilogue's position is a correctness requirement. A stronger guarantee would need the
  callback plumbing restructured so re-entry is impossible by construction, which is a
  larger refactor than this fix should carry.

- **Other callers of `globalClusterCA` under a held lock were not audited exhaustively.**
  This change fixed the two that the tests reached. A systematic sweep for "package-global
  read reached from inside that same object's critical section" is the natural follow-up,
  and is recorded as the suggested next run.

- **`clusterCAClockSkewTolerance` is a constant.** Five minutes, matching the inspection
  CA. An estate with worse clock discipline than that has larger problems, but this is a
  one-constant change if needed.

---

## Deliberately Left Open

- **CA-4's retry half** — a rotation that fails still waits a full 24 h before retrying.
  Now that failures are counted and alerted, the operator learns immediately; a backoff
  retry is a separate change and applies to both CAs.
- **CA-3** — inspection-CA load failure is still fail-open for the inspection control
  itself. This sweep removed its *collateral* effect on the cluster CA; the primary
  behaviour is unchanged and remains recorded.
- **CHAOS-46**, **CHAOS-43** — unchanged from the previous review.

---

## A note on how these findings were found

The 2026-08-03 review recorded a reusable lens: *for every cache and memoisation, does the
stored value distinguish "the dependency said no" from "the dependency did not answer?"*

This sweep used a second one, and it is worth recording because it is equally cheap:
**for every predicate that gates a security or availability decision, does it answer the
question the caller is actually asking?**

`Ready()` answers "is a CA loaded". Four call sites used it to decide "can I issue a
certificate" — a strictly stronger question. Every one of the FS-1 findings is that gap.
The same question applied to the *scheduling* of work rather than to a predicate produced
FS-2: `if certMgr.Ready()` was answering "is the inspection CA loaded" for a loop whose job
was "keep two unrelated CAs alive". The mismatch is invisible when reading either side
alone and obvious the moment the question is stated out loud.

Applied to this codebase the lens has an obvious next target, recorded above: every other
caller of a `Ready()`-shaped predicate in the enrollment and HA paths.

FS-7 came from somewhere else entirely, and the lesson is worth recording separately because
it is about method rather than about code. It was not found by reading — it was found because
a test exercised the **production configuration** (the process-global singleton, with its
callback wired) instead of the convenient one (a fresh local instance). Every existing test
of this subsystem used a local `&clusterCA{}`, which is faster, isolated, and correct-looking,
and which silently made the bug unreachable: the re-entrant read landed on a different mutex.

The generalisable question is therefore: *for every singleton with registered callbacks, does
any test exercise it as the singleton, with the callbacks installed?* Where the answer is no,
a whole class of re-entrancy and initialisation-order faults is structurally invisible to the
suite no matter how thorough it looks. That question is worth asking of `certMgr`, the alert
store, and the config store next.
