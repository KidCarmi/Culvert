# Chaos Engineering Review — 2026-08-15

**Domain:** the **cluster CA** (`enrollment.go`) — the trust root that signs every Data Plane's
client certificate for the mTLS control channel — across its lifecycle: rotation, import,
expiry, dual-CA overlap, and persistence failure.
**Register items:** **CA-13** (recorded 2026-07-04, marked "**next sweep**" by CHAOS-28 on
2026-08-09) · adds and closes four previously unrecorded defects, one of which is a permanent
process-wide deadlock on the production path.
**Verdict:** six confirmed defects, all fixed, all reproduced empirically against `main` before
a line of the fix was written.

---

## Executive Summary

CHAOS-28 (2026-08-09) hardened the **inspection** Root CA and closed by naming the other one:

> **CA-13** — cluster-CA rotation still logs-and-returns on every failure branch. Same defect
> class as CA-2, in the OTHER CA, with a different lifecycle and blast radius.

That is what this sweep set out to confirm. It is true, and it is the *least* serious thing in
the domain. The cluster CA turned out to carry a defect one class worse than a silent failure:
**every cluster-CA rotation permanently deadlocked the process**, while holding the write lock
that node enrollment, DP config sync, and the admin API all need to read.

| # | Failure mode | Class | Why the existing design did not cover it |
|---|---|---|---|
| FS-1 | `ImportCA` **self-deadlocks** and hangs holding the write lock | Deadlock → CP-wide freeze | the post-install side effects re-enter the same `RWMutex` for reading; `sync.RWMutex` is not reentrant |
| FS-2 | `CleanupSecondary` self-deadlocks the same way, 30 days later | Deadlock (delayed twin) | same callback, different caller |
| FS-3 | An **expired** cluster CA keeps signing node certificates | Silent failure → fleet-wide enrollment break | `x509.CreateCertificate` does not check the parent's validity window; `Ready()` only asks "is a CA loaded" |
| FS-4 | Node certs are **not clamped** to the issuer's window | Silent failure (delayed) | a 1-year node cert from a CA with 10 days left; the DP renewal trigger keyed on the *node* cert |
| FS-5 | `ImportCA` **panics** on a first install | Crash | rotation tracking dereferenced a secondary that only exists on a *re*-install |
| FS-6 | A failed rotation is invisible on `/metrics` and fires no alert; a failed persist leaves a **phantom secondary** | Silent failure + state corruption | CA-13 as recorded, plus in-memory state moved *before* the durable write |

### FS-1 is the finding

`ImportCA` is the single chokepoint through which the cluster CA is replaced — auto-rotation and
the admin "Import Custom Cluster CA" button both land there. It held `ca.mu` for writing across
its side effects, and two of those side effects come straight back for a read lock:

```
ImportCA  ── ca.mu.Lock() ──┐
                            ├─ onRotate() → rebuildCPCertPool → AllCACertsPEM      → ca.mu.RLock()  ✗
                            └─ CurrentConfigSnapshot()        → CACertFingerprint  → ca.mu.RLock()  ✗
```

Go's `sync.RWMutex` is not reentrant: an `RLock` behind the same goroutine's own `Lock` blocks
forever. So the rotation goroutine parks permanently — and because it parks *holding the writer*,
every reader of the cluster CA parks behind it:

| Reader | What stops |
|---|---|
| `SignCSR` | node enrollment and every DP certificate renewal |
| `CACertFingerprint` (via `CurrentConfigSnapshot`) | **every DP config poll** — fleet-wide policy distribution |
| `Info` | `GET /api/cluster/ca`, the admin panel |
| `AllCACertsPEM` | the CP TLS client-CA pool rebuild |
| `CAKeyPEM` | HA state replication to the standby |

Two triggers reach it, and neither is exotic:

1. **Auto-rotation**, fired by `StartCAAutoRotation` when the CA is within 30 days of expiry —
   unattended, on a schedule the operator did not choose.
2. **An operator importing a cluster CA** through the admin API — the documented remediation for
   half the failure modes in this domain, which means the recovery action was itself the trigger.

There is a third consequence that is easy to miss. `StartCAAutoRotation` (`ca.go:80-85`) drives
*both* CAs from one goroutine:

```go
certMgr.RotateIfNeeded(caPath, passphrase)   // Root CA
certMgr.CleanupSecondaryCA()
globalClusterCA.RotateIfNeeded()             // ← deadlocks here
globalClusterCA.CleanupSecondary()
```

so a cluster-CA rotation deadlock also kills **Root CA auto-rotation** for the life of the
process. The inspection CA then rides to its own expiry unrotated and lands in the CHAOS-28
fail-closed state. One deadlock, two CAs, both eventually expired.

**Why the test suite never saw it.** Six existing tests call `ImportCA` — and every one of them
calls it on a *locally constructed* `&clusterCA{}`. The re-entrant reads go through
`globalClusterCA`, a **different mutex**. The production singleton path had no test at all, so a
guaranteed, unconditional, permanent deadlock sat on `main` behind a green suite. The new gates
in `cluster_ca_chaos_test.go` drive `globalClusterCA` deliberately, and that is the durable
lesson from this sweep: *a test that exercises an instance the production path never uses is
not a test of the production path.*

### Measured, against `main`

A temporary proof harness (`TestProof_*`, removed before commit) ran against the unmodified
engine. Every defect reproduced on the first attempt:

```
--- FAIL: TestProof_GlobalClusterCAImportSelfDeadlocks (5.23s)
    DEADLOCK CONFIRMED: globalClusterCA.ImportCA did not return within 5s
--- FAIL: TestProof_DeadlockBlocksEnrollment (5.74s)
    ENROLLMENT FROZEN: SignCSR blocked >5s behind the deadlocked ImportCA
--- FAIL: TestProof_ExpiredClusterCAStillSignsNodeCerts (0.00s)
    DEFECT: expired CA (NotAfter=2026-08-15T21:15:14Z) signed a node cert valid until
    2027-08-15T22:15:14Z — every mTLS peer will reject it
      and it does not verify: x509: certificate has expired or is not yet valid
--- FAIL: TestProof_NodeCertOutlivesTheCA (0.00s)
    DEFECT: node cert NotAfter=2027-08-15 outlives CA NotAfter=2026-08-25 by 355 days —
    the node believes it has 365 days of validity left
--- FAIL: TestProof_ImportCAOnUninitializedPanics (0.00s)
    DEFECT: ImportCA panicked on an uninitialized cluster CA:
    runtime error: invalid memory address or nil pointer dereference
```

---

## Failure Scenarios

### FS-1 / FS-2 — the deadlock pair

**Current behavior (pre-fix).** `ImportCA` takes `ca.mu.Lock()` with a deferred unlock, then
calls `ca.onRotate()` (wired to `rebuildCPCertPool` whenever the CP runs with a `-cluster-ca`
file) and `CurrentConfigSnapshot()`. Both re-enter `ca.mu.RLock()`. The goroutine never returns.
`CleanupSecondary` has the identical shape, reached ~30 days after a rotation when the overlap
window ends.

**Expected behavior.** A rotation completes, the TLS pool is rebuilt, DP nodes learn the new
fingerprint on their next poll.

**Failure mode.** Permanent deadlock holding a writer lock. Note the ordering detail that
decides the recovery path: the deadlock happens *after* both files are written and the in-memory
swap is done, so the CA itself is durably installed. It is the process that is stuck, not the
state.

**Recovery path.** Manual, and only by process restart. Nothing in the appliance detects it: the
deadlocked goroutine is not a panic, `runGuarded` does not cover it, `/healthz` has no cluster-CA
liveness row, and the DP nodes see the CP as *up* — the gRPC listener still accepts, the RPCs
just never return.

**Customer impact.** No new node can enroll; no existing node can renew its certificate; no DP
receives a config update. Existing tunnels keep flowing (the data path does not touch the cluster
CA), so this is a **control-plane** outage that looks healthy from the proxy's own metrics — the
worst kind to page on.

**Fix.** `ImportCA` is split: `installLocked` does the durable write and the in-memory swap under
`ca.mu` and touches nothing else; the callback, rotation tracking, and snapshot republish run
after the lock is released. Serialization of concurrent imports is preserved by a separate
`importMu`, which **no reader ever takes** — so serializing imports can never again block
enrollment. `CleanupSecondary` gets the same treatment.

### FS-3 — an expired cluster CA keeps issuing certificates

**Current behavior (pre-fix).** `SignCSR` checked `ca.cert == nil`. Nothing checked whether the
CA was inside its own validity window, and neither `x509.CreateCertificate` nor the ECDSA
primitive checks the parent's `NotBefore`/`NotAfter`. An expired cluster CA therefore returned a
perfectly well-formed node certificate, and the CP recorded a successful enrollment.

**Expected behavior.** Refuse, loudly, and say why.

**Failure mode.** Silent failure of exactly the shape the register's §1 theme names: the control
did not degrade, it produced output that cannot work. The node persists its new certificate,
restarts into DP mode, and fails every mTLS handshake with `x509: certificate has expired or is
not yet valid` — a message about the *CA*, surfacing on the *node*, while the CP that issued it
reports nothing.

**Fix.** `Usable()` is introduced as deliberately distinct from `Ready()` — the same split
CHAOS-28 made for the Root CA — with the same 5-minute clock-skew tolerance so a CP with a fast
RTC does not refuse enrollment against its own freshly generated CA. `SignCSR` refuses with
`errClusterCAUnusable`, counts the refusal, and drives the alert. Refusing costs no availability
that signing would have preserved: the certificate was already worthless.

### FS-4 — node certificates outlive their issuer

**Current behavior (pre-fix).** `SignCSR` always issued `time.Now() + 365d`, regardless of how
much life the CA had left. A CA with 10 days remaining issued node certs valid for a year.

**Failure mode.** The DP renewal loop (`certNeedsRenewal`, 30 days) keys on the **node** cert's
expiry, so a node holding a year-long cert stays quiet — through the CA's expiry, through the end
of the dual-CA overlap, and out the other side, where its certificate is still "valid" by its own
dates and chains to a CA that no longer exists in any peer's pool. The node has no local signal
that anything is wrong until the handshake fails.

It also broke the dual-CA overlap's core assumption. The secondary is retained until the old CA's
`NotAfter`, which is only a sufficient overlap if no cert outlives the CA that signed it.

**Fix.** Clamp `NotAfter` to the issuer's `NotAfter` and floor `NotBefore` at the issuer's
`NotBefore`. The overlap window is now a true superset of every certificate the old CA issued.

### FS-5 — `ImportCA` panics on a first install

**Current behavior (pre-fix).** Rotation tracking read `sha256.Sum256(ca.secondaryCert.Raw)`
unconditionally, but the secondary is only assigned when a *previous* CA existed. On a first
install `secondaryCert` is nil → nil-pointer dereference.

**Reachability.** `InitOrLoad` bootstraps a CA on a clean data directory, so the common path is
safe. It is reachable exactly where it hurts: `InitOrLoad` **fails closed** when one of the two
CA files is missing or unreadable (a half-restored backup, a truncated volume), leaving no CA
loaded — and the documented recovery is for the operator to import one through the admin API,
which panics the handler goroutine.

**Fix.** Rotation tracking is skipped when there was no previous CA; a first install is not a
rotation and should not be reported as one.

### FS-6 — CA-13 as recorded, plus a phantom secondary

**Current behavior (pre-fix).** Each of `RotateIfNeeded`'s five failure branches logs and
returns. `recordRotationFailure` puts the text on `Info()`. `culvert_cluster_ca_rotations_total`
counts only **successes**, which is the wrong shape for the question an operator has: *is this
appliance still able to renew its own trust root?* No metric moved, no alert fired, and the next
attempt is 24 hours later — so a rotation that starts failing at the 30-day mark can burn all 30
days in silence and then expire into FS-3.

Separately, `ImportCA` promoted the current CA to secondary **before** the durable writes. A
failed write returned early, leaving a live CA listed as its own secondary: `SecondaryActive()`
true, `AllCACertsPEM` emitting the same PEM twice, `Info()` reporting `dualCAActive` with
identical fingerprints on both halves — a dual-CA state that never existed.

**Fix.** A health plane modeled on `ca_health.go` / `storage_health.go`: counters for rotation
failures and sign refusals, independent 5-minute rate gates for the log and the alert, a
`HasSubscriber`-gated `cluster_ca_degraded` alert, and recovery reported on **evidence** (a
rotation that actually installed a CA) rather than elapsed time. `installLocked` now writes
durably first and mutates in-memory state only after the write succeeds, so a failed persist
leaves the CA exactly as it was.

---

## Risk Matrix

| ID | Likelihood (pre-fix) | Blast radius | Detectability (pre-fix) | Severity | Status |
|---|---|---|---|---|---|
| FS-1 | **Certain** — every rotation, every import | Whole control plane: enrollment, config sync, admin API, HA replication, *and* Root CA rotation | **None** — no panic, no metric, no health row; the CP still accepts connections | **Critical** | Fixed |
| FS-2 | Certain, ~30 days after any rotation | Same | None | High | Fixed |
| FS-3 | Certain once the CA expires (which FS-1/FS-6 make likely) | Fleet-wide: no enrollment, no renewal | None at the CP; N opaque TLS errors at N data planes | High | Fixed |
| FS-4 | Certain for any cert issued in the CA's last year | Per-node, delayed; defeats the renewal trigger and the overlap window | None | Medium/High | Fixed |
| FS-5 | Low — needs a failed `InitOrLoad` first | The admin handler goroutine (recovered by the HTTP server, but the import does not happen) | Panic in the log | Medium | Fixed |
| FS-6 | Whenever the CA volume is read-only/full | The rotation, silently | `Info()` only — nothing polls it | Medium | Fixed |

---

## Recovery Assessment

| Scenario | Pre-fix | Post-fix |
|---|---|---|
| Cluster CA rotates (auto or manual) | **None automatic.** Permanent deadlock; only a process restart clears it, and the CA *was* installed, so the restart recovers cleanly — if anyone works out that a restart is what is needed | Automatic: the rotation completes and the fleet converges on the next DP poll |
| Dual-CA overlap ends | None automatic (FS-2) | Automatic |
| Cluster CA expires | None automatic — the CA keeps issuing unusable certs indefinitely | Fail closed and self-announcing: enrollment is refused with an operator-actionable error, `culvert_cluster_ca_usable 0`, an alert, and a banner. Recovery is a CA import, which now works |
| Rotation fails on a read-only volume | Retried silently every 24 h until expiry | Retried on the same 24 h cadence, but counted, alerted, and surfaced on the admin panel from the first failure |
| Failed persist mid-import | Left a phantom dual-CA state | The CA is unchanged; the error propagates to the API caller |

**Manual recovery remains required in one place, unchanged:** a cluster CA that has already
expired must be replaced by an operator (import, or delete both files and re-bootstrap), and
every DP must re-enroll. That is inherent — a trust root cannot renew itself with authority it no
longer has. The change is that this state is now announced 30 days early instead of discovered by
the fleet.

---

## Operational Impact

Everything new rides existing surfaces; no new CLI flag, YAML key, or config option is
introduced, so **GUI parity is satisfied by construction**:

| Surface | Signal |
|---|---|
| `/metrics` | `culvert_cluster_ca_rotation_failures_total`, `culvert_cluster_ca_sign_refused_total`, `culvert_cluster_ca_usable`, `culvert_cluster_ca_expires_in_seconds` |
| `GET /api/cluster/ca` | `usable`, `usableError`, `daysRemaining`, `rotationFailures`, `signRefusals` (alongside the existing `lastRotationError`) |
| Alerts | `cluster_ca_degraded` — new event, `HasSubscriber`-gated, 5-minute rate limit, selectable in the webhook panel |
| Cluster CA panel | an "unusable" banner that outranks the rotation-failure banner, naming the bound that was violated and the refusal count |
| Logs | `ClusterCA: DEGRADED — …` (rate-limited), `ClusterCA: recovered — …` |

`culvert_cluster_ca_expires_in_seconds` is the series to alert on, well before the cliff:
auto-rotation triggers at 30 days, so this dropping below ~30 days *and staying there* means
rotation is not working, whatever the reason. Both gauges are omitted entirely on a node with no
cluster CA, so a DP-only node never emits `usable 0` for a CA it is not supposed to have.

The event name is deliberately **not** `cert_expiry`: that one belongs to the MITM inspection
Root CA, a different CA with a different lifecycle and a different blast radius. Overloading it
would make the two indistinguishable in a webhook consumer — the same reasoning that produced
`identity_backend_unreachable` in CHAOS-47.

---

## Security Impact

- **Availability of an authentication control.** The mTLS client certificate *is* how a Data
  Plane authenticates to the Control Plane. FS-3 silently issued credentials that cannot
  authenticate; FS-1 froze the ability to issue any at all. Both are now fail-closed and
  observable.
- **No weakening anywhere.** Every change either refuses something that used to be permitted
  (FS-3), narrows a certificate's validity (FS-4), or moves a side effect out of a lock (FS-1).
  Nothing widens trust, and the dual-CA overlap — the mechanism that keeps already-enrolled nodes
  working across a rotation — is preserved exactly, and is now provably a superset of the certs
  it must cover.
- **No new credential exposure.** The health plane records error text only; it never touches key
  material, and the metrics remain label-free per the CA-2 contract (no fingerprints, serials,
  subjects, SANs, or node IDs).
- **A denial-of-service is removed, not added.** Pre-fix, one admin import — an *authenticated
  admin* action, but still — permanently froze the control plane. That is a self-inflicted DoS
  reachable from the documented recovery procedure.

## Data Integrity Impact

FS-6's phantom secondary was the only state-corruption finding, and it was in-memory only: no
on-disk artifact was affected, and a restart re-derived correct state from the files. The
write-then-swap ordering now makes the in-memory state a strict function of what actually reached
the disk. The two-file commit remains non-atomic (a crash between the cert and key writes is
still detected at startup by `loadFromPEM` cross-validation and fails closed) — unchanged, and
still out of scope.

---

## What already worked, and why

Credit where the design was already right, since the fix depends on all of it:

- **The DP side of this story is in good shape.** `dpCertRenewalLoop` (`dp_enrollment.go`) checks
  once immediately at boot (CHAOS-12: a node powered off past its renewal window must not wait
  for the first tick), renews on a 6 h cadence, reacts to a CA-rotation signal with an *immediate*
  forced renewal, wraps each round in `runGuarded`, and alerts on failure via
  `alertDPCertRenewalFailure`. The CP-side gap this review closes is what that machinery was
  renewing *against*.
- **Fail-closed `InitOrLoad`.** A cert present with the key missing refuses to regenerate over
  the survivor, rather than silently minting a new CA and orphaning the fleet.
- **`loadFromPEM` cross-validation** catches a cert/key mismatch from a torn two-file write.
- **The dual-CA overlap itself** is the right design: existing nodes keep authenticating against
  the old CA while new enrollments get the new one. It needed FS-4's clamp to be sound, not
  replacing.
- **`atomicWriteFile`** routes cluster-CA persistence through the CHAOS-45 durable-write
  chokepoint, so a failed write already reached the storage-health plane
  (`storage_write_failed`). That is why FS-6 is scoped to *rotation* visibility rather than
  write visibility.
- **CA-7's `getCPTLSConfigForClient`** already fixed the handshake-vs-rebuild race on the CP TLS
  config; this review did not need to touch it.

---

## Required Tests

All in `cluster_ca_chaos_test.go`; each corresponds to a proof that reproduced against `main`.

| Test | Pins |
|---|---|
| `TestChaos50_ImportCADoesNotDeadlock` | FS-1 — the production singleton path returns |
| `TestChaos50_ImportCADoesNotFreezeReaders` | FS-1 blast radius — `SignCSR`, `CACertFingerprint`, `Info` stay live during an import |
| `TestChaos50_CleanupSecondaryDoesNotDeadlock` | FS-2 — with an `onRotate` that re-enters `AllCACertsPEM`, exactly as `rebuildCPCertPool` does |
| `TestChaos50_ExpiredClusterCARefusesToSign` | FS-3 — refusal, `errClusterCAUnusable`, counter, degraded state, one alert |
| `TestChaos50_NotYetValidCAToleratesClockSkew` | FS-3's other end — 2 min future tolerated, 1 h refused |
| `TestChaos50_NodeCertClampedToCAWindow` | FS-4 — clamped both ends, returned expiry agrees, cert still verifies |
| `TestChaos50_HealthyCAStillIssuesFullYear` | FS-4's converse — the clamp must not shorten certs on a healthy cluster |
| `TestChaos50_ImportCAOnUninitializedDoesNotPanic` | FS-5 — first install works and reports no overlap |
| `TestChaos50_FailedPersistLeavesCAUnchanged` | FS-6 — no phantom secondary, CA untouched |
| `TestChaos50_RotationFailureIsCountedAlertedAndRecovers` | FS-6 — counted, alerted, degraded; clears on evidence |
| `TestChaos50_MetricsExposeClusterCAHealth` | the scrapeable surface, incl. gauge omission with no CA |
| `TestChaos50_ConcurrentImportsAreSerialized` | `importMu` still orders imports while readers run unblocked (race-clean) |

Verification run: `go build ./...`, `go vet ./...`, `gofmt -l .` clean; `go test ./...` green
(all packages); `go test -race -count=1 -run 'TestChaos50_|TestClusterCA|TestCA7_|TestCARotation|TestEnroll'`
clean; `make api-bundle-check` reports artifacts up to date.

---

## Residual Risk

- **The 24 h retry cadence is unchanged.** A failed rotation still waits a full day before the
  next attempt — the same open item as **CA-4's retry half** for the Root CA. With the alert now
  firing on the first failure, the operator learns within minutes instead of at expiry, so the
  cadence is a latency problem rather than a visibility one. Left open deliberately, as one fix
  for both CAs.
- **No `/healthz` row for the cluster CA.** Usability is on `/metrics` and `/api/cluster/ca` but
  not in the health probe. `/healthz` is consumed by orchestrators as a restart signal, and a CP
  whose cluster CA expired should *not* be restarted — restarting does not renew it and would drop
  the config-sync channel for the whole fleet. Metrics and the alert are the right shape here;
  adding a report-only row is a reasonable follow-up if operators ask.
- **Renewal churn near CA expiry (accepted, bounded).** With FS-4's clamp, a CA inside its final
  30 days issues node certs shorter than the DP's 30-day renewal trigger, so each DP re-renews
  once per 6 h tick until the CA rotates. Bounded by the tick and by the fleet size, confined to a
  window in which auto-rotation should already have replaced the CA, and self-clearing the moment
  it does (the rotation signal triggers one immediate renewal, and certs go back to a full year).
  It is also a *signal*: renewal churn now correlates with a CA that is not rotating.
- **Deadlock detection generally.** This review fixed two instances; nothing structurally
  prevents a third. The repository has no lock-ordering discipline or `go vet` equivalent for
  re-entrant `RWMutex` use, and the Go race detector does not find self-deadlocks. The mitigation
  shipped here is convention plus tests: the doc comment on `installLocked` states the rule
  ("nothing that can call back into a `clusterCA` method may be invoked from here"), and the gates
  drive the real singleton. A static check for callbacks invoked under a held lock would be a
  genuine improvement and is out of scope for a chaos fix.
- **Tests must drive production singletons.** FS-1 survived a green suite because six tests
  exercised a look-alike instance. This class is not confined to the cluster CA; a sweep for other
  globals whose tests only touch local instances is a worthwhile follow-up.
- **Clock rollback beyond tolerance still refuses enrollment.** A CP whose clock jumps backwards
  more than 5 minutes will treat its own CA as not-yet-valid and refuse to sign. That is the
  intended fail-closed posture (the certs it would issue would be rejected by peers with correct
  clocks), and it matches the Root CA's tolerance, but it makes NTP a hard dependency for
  enrollment — consistent with register row CA-10/AU-9.

---

## Deliberately Left Open

- **CHAOS-46** — config rollback vs. admin-settings durability (owner decision).
- **CHAOS-43** — OCSP fail-open when the issuer cert cannot be resolved from the chain.
- **CA-4's retry half** — a failed rotation still waits 24 h before retrying, in both CAs.
- **CA-11** — no single-flight on the leaf cache (re-scoped down by CHAOS-28).
- **CA-14** — session-revocation persistence still uses `os.WriteFile`+rename with no fsync.
