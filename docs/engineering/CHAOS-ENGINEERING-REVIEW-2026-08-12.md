# Chaos-Engineering Review — CHAOS-29: the Cluster CA across its lifecycle

**Date:** 2026-08-12
**Scope:** The cluster CA (`enrollment.go`) — bootstrap, load, sign, rotate, overlap,
cleanup, import — and the observability plane around it.
**Closes:** register row **CA-13**.
**Opens and closes:** **CA-17** (re-entrant-callback deadlock), **CA-18** (bootstrap-import
panic), **CA-19** (node cert outlives its issuer).
**Method:** Evidence-first source review. Every finding below was reproduced as a failing
test against unmodified `main` before any fix was written; the observed pre-fix output is
quoted with each finding.

---

## Executive Summary

CHAOS-28 hardened the **inspection** CA and handed off row CA-13 — "cluster CA rotation
mirrors CA-2: every failure branch logs-and-returns with no alert or metric" — as the same
defect class in the **other** CA. That is what this sweep set out to close.

CA-13 was real and is closed. But it was the smallest of the four defects found, and it was
not the most serious. Sweeping the cluster CA's full lifecycle rather than only its rotation
failure branches turned up a **Critical, currently-live self-deadlock** on the appliance's
single most privileged mutex, reachable from two ordinary operator actions.

The four findings, in severity order:

| # | Finding | Severity | Trigger |
|---|---|---|---|
| **FS-1** | `ImportCA` and `CleanupSecondary` invoke re-entrant callbacks while holding the cluster CA **write** lock. `sync.RWMutex` is not reentrant ⇒ permanent deadlock, holding the write lock. | **Critical** | Every manual CA import; every auto-rotation; every dual-CA overlap close |
| **FS-2** | `SignCSR` signs with a cluster CA that is outside its **own** validity window, and reports success. | **High** | Cluster CA reaches `NotAfter` |
| **FS-3** | Node certificates are issued for a fixed 365 days with no clamp to the issuer, so every cert signed in a CA's final month outlives its issuer — by up to eleven. | **Medium** | Any enrollment inside the 30-day rotation window |
| **FS-4** | Auto-rotation failure reaches a log line and a pull-only admin field. No counter, no alert, no probe. *(the recorded CA-13)* | **Medium** | Read-only CA directory, full volume, bad KEK |

Plus one latent panic found on the way: `ImportCA` nil-dereferenced the absent secondary CA
on a **bootstrap** import (**CA-18**), panicking *after* the new CA had already been written
to disk and installed in memory.

The cross-cutting theme is the register's own §1 theme, in its second form. §1 is about a
security control that **degrades silently**. FS-2 and FS-3 are exactly that. FS-1 is its
mirror: a failure so total that it produces **no** signal — not a wrong answer, not a
degraded one, but no answer at all, forever, from a goroutine that does not panic, does not
exit, and does not time out. The existing `runGuarded` containment around the rotation tick
does not help, because a deadlock is not a panic.

---

## Failure Scenarios

### FS-1 — Re-entrant callback under the write lock ⇒ permanent deadlock **[Critical]**

**Current behaviour (pre-fix).** `ImportCA` took `ca.mu.Lock()` with `defer ca.mu.Unlock()`
and then, still holding it, ran the publication steps:

```go
ca.mu.Lock()
defer ca.mu.Unlock()
...
if ca.onRotate != nil { ca.onRotate() }              // → rebuildCPCertPool
...
_ = globalConfigStore.Update(CurrentConfigSnapshot()) // → CACertFingerprint
```

Both re-enter the same mutex:

```
onRotate    → rebuildCPCertPool     → globalClusterCA.AllCACertsPEM()      → ca.mu.RLock
Update(...) → CurrentConfigSnapshot → globalClusterCA.CACertFingerprint()  → ca.mu.RLock
```

`sync.RWMutex` is not reentrant. An `RLock` taken by the goroutine that already holds the
write lock blocks forever, and Go's runtime deadlock detector never fires because other
goroutines remain runnable.

`CleanupSecondary` has the same shape: write lock held across `ca.onRotate()`.

**Reproduced against unmodified `main`** with the production shape (`ImportCA` invoked on
`globalClusterCA`, which is how both callers reach it):

```
--- FAIL: TestMainDeadlockRepro (20.02s)
    DEADLOCK: ImportCA never returned (holds ca.mu write lock;
    CurrentConfigSnapshot re-enters via CACertFingerprint RLock)
```

with the goroutine dump naming the exact re-entry:

```
goroutine 54 [sync.RWMutex.RLock, 10 minutes]:
  (*clusterCA).CACertFingerprint  enrollment.go:1058
  CurrentConfigSnapshot           controlplane_snapshot.go:1258
  (*clusterCA).ImportCA           enrollment.go:1242
```

**Why the existing test suite missed it.** The identity `ca == globalClusterCA` *is* the bug.
Every existing cluster-CA test constructs a local `&clusterCA{}` and calls `ImportCA` on it
while `globalClusterCA` stays a different object, so the re-entry lands on a different mutex
and returns cleanly. The deadlock only appears when the CA being imported into is the global
one — which is the only way production ever calls it.

**On a real Control Plane it is worse than the reproduction.** `onRotate` is nil in unit
tests (it is wired in `buildServerTLS`, `controlplane_tls.go:104`). On a CP with mTLS
configured the callback is live, so the deadlock happens *earlier*, at the pool rebuild,
before the config-snapshot path is even reached.

**Failure mode.** Deadlock with the **write** lock held. Every reader then queues behind it
forever:

| Blocked | Consequence |
|---|---|
| `SignCSR` | Node enrollment and cert renewal hang (not fail — hang) |
| `AllCACertsPEM` | CP TLS client pool can never be rebuilt |
| `CACertPEM` / `CACertFingerprint` | `CurrentConfigSnapshot` hangs ⇒ **all** CP→DP config sync stops |
| `Ready()` / `Info()` | `/api/cluster/ca`, `/api/cluster/status`, `/healthz` hang |

The `CurrentConfigSnapshot` entry is the widest: it is on the CP→DP config-distribution path,
so a hung cluster-CA lock stops policy, blocklist and threat-feed propagation to the entire
fleet, not just certificate operations.

**Trigger frequency.** Three ordinary paths, none of them exotic:

1. `POST /api/cluster/ca` — an admin importing a corporate CA. Every time.
2. `RotateIfNeeded` → `ImportCA` — auto-rotation, 30 days before CA expiry.
3. `CleanupSecondary` — when a dual-CA overlap window closes.

(3) is the most dangerous. It runs on the shared `StartCAAutoRotation` tick
(`ca.go:85`) inside `runGuarded("cluster_ca_rotation", …)`. `runGuarded` recovers **panics**;
a deadlock is not a panic. So the rotation goroutine is simply lost — and it is the *same*
goroutine that drives inspection-CA rotation (`ca.go:80`), so a cluster-CA overlap close
silently kills **inspection**-CA auto-rotation too. That is a cross-CA blast radius nobody
would predict from either file alone: the CHAOS-28 recovery path is disabled by a fault in an
unrelated CA.

**Recovery path.** Process restart, and only that. No timeout, no backoff, no retry, no
supervisor — Go offers no way to break a held mutex.

**Monitoring visibility (pre-fix).** Essentially nil, and actively misleading. The admin API
request hangs rather than erroring, so the operator sees a browser spinner. `/healthz` hangs
on the same lock. Metrics do not move — `culvert_cluster_ca_rotations_total` counts successes
and the rotation never completed. The one honest signal is a rising goroutine count.

**Fix.** Mutate under the lock; capture what the publication needs; release; publish.
`installCA` is the locked half and returns a `caPublication`; `ImportCA` runs `onRotate`,
`StartCARotation` and `Update(CurrentConfigSnapshot())` with `ca.mu` released.
`CleanupSecondary` gets the same treatment. A new `publishMu` serialises whole
install→publish sequences against each other, so two concurrent rotations cannot interleave
between the unlock and the publish and leave the TLS pool rebuilt from the older of the two.
Lock ordering is `publishMu → mu`, never the reverse.

---

### FS-2 — `SignCSR` signs with an expired cluster CA and reports success **[High]**

**Current behaviour (pre-fix).** `SignCSR` checked only that a CA was *loaded*
(`ca.cert == nil || ca.key == nil`). Neither `x509.CreateCertificate` nor the ECDSA primitive
checks the **issuer's** `NotBefore`/`NotAfter`, so an expired cluster CA signed normally.

Observed against unmodified `main`:

```
err=<nil> serial=a53e759c8e3d0ee5117afc36e1a4c6b5 len=607
EVIDENCE: expired cluster CA SIGNED a node cert;
  issuer NotAfter=2026-08-11  leaf NotAfter=2027-08-12  (leaf OUTLIVES issuer by 8784h)
```

**Failure mode — the silent kind.** RFC 5280 path validation evaluates the whole chain at
time of use, so the certificate is dead on arrival. But nothing in the issuing path says so:

- `SignCSR` returns `nil` error;
- the Enroll RPC returns success and the node persists the cert;
- `Ready()` stays `true`;
- no counter moves, because nothing rotated and nothing failed.

The node then fails its next mTLS handshake with `x509: certificate has expired or is not yet
valid` — an error that points at the **node's** certificate, which was issued minutes ago and
is perfectly valid on its own terms. The appliance reported a successful enrollment and
handed back material guaranteed not to work, and the diagnostic points away from the cause.

**Expected behaviour.** Refuse, once, loudly, naming the violated bound.

**Why refusing is not an availability regression.** The certificate was already unusable.
Refusing costs nothing that signing would have preserved; it converts N nodes independently
discovering an opaque handshake error into one countable, alertable event on the CP.

**Why this is fail-closed, and safely so.** A refused signing is a node that does not join
the cluster. There is no branch that admits an unauthenticated peer, downgrades mTLS or
widens trust. Compare the inspection CA, where the equivalent "just let it through" fix would
have silently disabled decryption fleet-wide (CHAOS-28 FS-1) — the cluster CA has no such
inversion available, which is why the gate here is simpler than that one.

**Recovery is deliberately not gated by the guard.** `RotateIfNeeded` → `ImportCA` does not
route through `SignCSR`, so the refusal cannot block the rotation that fixes it. Verified by
`TestClusterCARotationDegraded_ClearsOnEvidence`, which recovers a degraded CA by import
while the sign gate is armed.

**Clock-skew handling.** `clusterCAClockSkewTolerance` (5 min) matches
`caClockSkewTolerance` so both CAs use one tolerance. It matters more here than for the
inspection CA: the cluster CA is replicated to HA peers (`ha.go` `ImportCASilent`), and a peer
whose clock runs slightly ahead can hand over a CA that is, by the receiver's clock, not yet
valid. Refusing enrollment for five minutes because two machines disagree about the second
would be self-inflicted.

---

### FS-3 — Node certificates outlive their issuer **[Medium]**

**Current behaviour (pre-fix).** `NotAfter` was an unconditional `time.Now().Add(365 days)`.

This is not a corner case. Node certs are issued for a fixed year; the CA auto-rotates when
it has **30 days** left. So *every* certificate signed in a CA's final month outlived its
issuer, by up to eleven months.

**Failure mode.** The hardest incident shape to read: the node certificate inspects as valid,
the chain does not validate, and the failure appears to move around as different peers
revalidate at different moments.

It also breaks the renewal loop's arithmetic. `certNeedsRenewal` (`dp_enrollment.go:382`)
keys on the **certificate's own** `NotAfter`. An unclamped cert says it has eleven months
left when its chain dies in thirty days, so the DP's renewal window opens *after* the cliff it
was supposed to prevent. Clamping pulls renewal forward to before the CA's expiry, which is
where it belongs.

**Fix.** `clampNodeCertValidity` narrows both ends to the issuer's window. Verified to be a
no-op in the normal case (a fresh 10-year CA) so no fleet-wide shortening is introduced.

---

### FS-4 — Auto-rotation failure is not alerted or metered *(the recorded CA-13)* **[Medium]**

**Current behaviour (pre-fix).** Every failure branch in `RotateIfNeeded` (keygen, serial,
create-cert, marshal, import) called `logger.Printf` plus `recordRotationFailure`, which set
`lastRotationErr` for `Info()` to surface. No counter, no alert, no probe row.

**Why that is not enough.** Auto-rotation is the cluster CA's **only** automatic recovery. It
gets one attempt per 24h tick inside a 30-day window. A persistent cause — read-only CA
directory, full volume, a KEK that no longer decrypts — therefore had thirty chances to fail
silently before the CA expired and took the whole cluster's mTLS trust with it. The one
signal was a log line among the day's other log lines, plus a field on an admin page nobody
opens while the cluster looks healthy — which is precisely the month in which this has to be
caught.

**Fix.** `recordRotationFailure` now also reaches the health plane: a cumulative counter, a
log line, and a `cert_expiry` alert on `culvert-cluster-ca` (distinct from the inspection
CA's `culvert-ca` — different blast radius, different runbook, and an operator paged at 3am
must know which CA died without opening the appliance). The alert is unconditional rather
than rate-gated: `RotateIfNeeded` fires at most once per 24h tick, so it is bounded by
construction — the case the per-request alert-producer contract explicitly exempts. The
`HasSubscriber` gate is still honoured so every producer in the codebase reads the same way.

Both cluster-CA producers deliver through one seam (`fireClusterCAAlert`), which keeps the
host/source/event triple in a single place and gives tests a synchronous observation point.
That second property is load-bearing rather than cosmetic: the first version of the
rotation-failure test swapped `globalAlertStore` and restored it in `t.Cleanup`, which races
the in-flight delivery goroutine — caught by the race detector, and exactly the
`-count`/`-shuffle` determinism class the CI gate exists for.

---

### CA-18 — Bootstrap import nil-dereference **[Medium, latent]**

`ImportCA` dereferenced `ca.secondaryCert.Raw` unconditionally, but the secondary is only set
when a previous CA exists. On a node with **no** cluster CA — every standalone and every Data
Plane node — `POST /api/cluster/ca` panicked.

Observed against unmodified `main`:

```
[test] ClusterCA: imported custom CA (expires 2026-08-13, fingerprint 77327ccb…)
EVIDENCE: ImportCA on an uninitialised cluster CA PANICKED:
  runtime error: invalid memory address or nil pointer dereference
```

Note the ordering in that output: the success log line comes **first**. The panic is late —
after the new CA has been written to disk, installed in memory and pushed to the TLS pool. So
the operator sees the admin request fail (`net/http` recovers the panic per-connection) while
the import has in fact happened, and the config-version bump that tells DP nodes about it
never runs. A confusing half-committed state produced by a request that reported failure.

Fixed by guarding on the secondary existing — which is also the semantically correct
condition, since rotation tracking exists to describe an overlap between an old CA and a new
one, and a bootstrap import has no old one.

---

## Risk Matrix

| ID | Finding | Sev | Likelihood | Detectability (pre-fix) | Status |
|---|---|---|---|---|---|
| CA-17 | Re-entrant callback deadlock under the write lock | **Critical** | Certain (3 ordinary paths) | Very low — hangs, no error/panic/metric | **CLOSED** |
| CA-1c | `SignCSR` signs with an out-of-window CA | High | Certain at CA expiry | None — reports success | **CLOSED** |
| CA-19 | Node cert outlives issuer (no clamp) | Medium | Certain in the rotation window | Low — looks valid on inspection | **CLOSED** |
| CA-13 | Rotation failure not alerted or metered | Medium | Moderate (disk/perm faults) | Low — log line + pull-only field | **CLOSED** |
| CA-18 | Bootstrap-import nil deref | Medium | Low (needs a non-CP import) | Medium — 500, but state half-committed | **CLOSED** |

---

## Recovery Assessment

| Scenario | Automatic recovery | Manual recovery | Now observable via |
|---|---|---|---|
| Cluster CA expired | None — rotation must run | Import a replacement CA, then **re-enroll every DP node** | `culvert_cluster_ca_usable` · `/healthz cluster_ca` · `cluster_ca` contract row · panel banner |
| Auto-rotation failing | Retries each 24h tick | Restore write access to the CA directory, or import manually | `culvert_cluster_ca_rotation_failures_total` · `cert_expiry` alert · `cluster_ca` warn row |
| Deadlock (pre-fix) | **None** | Process restart | *(was)* rising goroutine count only |
| Bootstrap import on a fresh node | n/a | n/a — now simply succeeds | — |

**The residual manual step is deliberate and unavoidable.** Rotating the cluster CA restores
*signing*; it cannot restore *trust*. Certificates issued under the old CA no longer chain,
so every enrolled node must re-enroll. The zero-touch path
(`dpCertRenewalLoop`'s CA-rotation notification, `dp_enrollment.go:359`) works only while the
old CA is still valid — i.e. only for a rotation done **before** expiry. This is exactly why
`culvert_cluster_ca_expires_in_seconds` is the series to alert on, well before the cliff, and
why it did not exist until now.

---

## Operational Impact

- **On a healthy node: none measurable.** One `time.Time` comparison per CSR signing —
  against a path that already does a P-256 signature. No new goroutine, no allocation, no
  lock added to any hot path. `publishMu` is taken only by import/cleanup, which run at most
  once per 24h tick plus admin actions.
- **The proxy data path is untouched.** Nothing in this change is reachable from
  `handleRequest`, `handleTunnel` or the SOCKS5 path.
- **Log volume is bounded.** An unusable cluster CA fails every enrollment and every renewal,
  and a fleet that has lost mTLS trust retries from every node at once. Both the log line and
  the alert sit behind independent 5-minute gates; the counters carry the magnitude that rate
  limiting drops.
- **Alert volume is bounded twice.** Both producers are `HasSubscriber`-gated, so the default
  posture (no webhooks configured) never spawns a delivery goroutine.
- **Metrics gauges are omitted, not zeroed, on nodes with no cluster CA.** Publishing
  `culvert_cluster_ca_usable 0` on every standalone and Data Plane node would page the
  majority of a fleet for a CA they are not supposed to have. The counters are always
  published so `rate()` works from boot.

---

## Security Impact

- **No new bypass, and none was available.** Every fix here fails closed toward "this node
  does not join the cluster". There is no branch that admits an unauthenticated peer,
  downgrades mTLS or widens the trust pool. The dual-CA overlap — the one place trust *is*
  deliberately widened — is untouched, and its negative control
  (`TestImportCA_RotationStillTracksOverlap`) asserts a real rotation still preserves the
  secondary and the trust pool.
- **The deadlock fix narrows a denial-of-service surface.** Pre-fix, an authenticated admin
  action (`POST /api/cluster/ca`) permanently disabled cluster-CA operations *and* CP→DP
  config distribution *and* inspection-CA auto-rotation, recoverable only by restart. It
  required admin credentials, so it is not an unauthenticated DoS, but "one admin click
  bricks the Control Plane until restart" is a availability defect worth naming as such.
- **Metrics stay label-free**, per the CA-2 contract: no node ID, serial, fingerprint,
  subject or key material — counts and one time delta. Asserted by
  `TestClusterCAMetrics_AreLabelFree`.
- **The viewer-role contract row carries impact and counts, never the cause.** `cluster_ca`
  states that enrollment is blocked and how many signings were refused; the exact `NotAfter`
  stays in the logs, the alert and the admin-role CA API. Asserted, not assumed.
- **`/api/cluster/ca`'s new `unusableReason` discloses nothing new.** The same viewer-role
  payload already returns `expires` and `fingerprint`; the reason restates the former.

---

## Suggested Improvements (shipped in this PR)

| Change | File |
|---|---|
| `installCA` / `caPublication` split — publication runs with `ca.mu` RELEASED | `enrollment.go` |
| `CleanupSecondary` releases the lock before `onRotate` | `enrollment.go` |
| `publishMu` serialises whole install→publish sequences | `enrollment.go` |
| `Usable()` / `clusterCAUsable` validity predicate + `ErrClusterCAUnusable` + skew tolerance | `cluster_ca_validity.go` |
| `SignCSR` refuses an out-of-window CA; node cert clamped to the issuer | `enrollment.go`, `cluster_ca_validity.go` |
| Bootstrap-import nil-deref guard | `enrollment.go` |
| Rotation failure counted, logged and alerted; recovery on observed evidence | `cluster_ca_health.go`, `enrollment.go` |
| `culvert_cluster_ca_usable` · `_expires_in_seconds` · `_sign_refused_total` · `_rotation_failures_total` | `ca_metrics.go` |
| `/healthz` `cluster_ca` posture row | `healthcheck.go` |
| `cluster_ca` operator-contract row (emitted only on nodes that hold a cluster CA) | `diagnostics.go` |
| `GET /api/cluster/ca` `usable` / `unusableReason`; Cluster CA panel banner | `enrollment.go`, `static/index.html` |

---

## Required Tests (shipped)

All in `cluster_ca_expiry_failclosed_test.go`. The four **defect** gates were executed against
unmodified `main` and observed to fail — the deadlock (quoted above with its goroutine dump),
the expired-CA signing, the issuer-outliving node cert, and the bootstrap panic. The
remaining tests are negative controls, surface assertions and contract pins written
alongside the fix; they are not claimed as pre-fix reproductions.

**The deadlock (FS-1)** — `withDeadlineGuard` is the harness: a deadlock cannot be caught any
other way, since the goroutine does not panic, error or exit. On timeout the test dumps all
goroutine stacks, so a regression names its own re-entry path.
- `TestImportCA_DoesNotDeadlockOnPublication` — the config-snapshot re-entry, in the
  production shape (`ImportCA` on `globalClusterCA`), plus a post-import read probe that
  would catch a lock leaked on the success path.
- `TestImportCA_DoesNotDeadlockWithRotationCallbackWired` — the `onRotate` re-entry that a
  unit test without a Control Plane never wires, and that deadlocks *earlier* on a real CP.
- `TestCleanupSecondary_DoesNotDeadlock` — the rotation-tick path, plus the no-op case
  (nothing expired ⇒ callback must not fire).
- `TestClusterCA_ConcurrentImportsAndReadsStayLive` — imports, cleanups, `Info`, `Usable`,
  `AllCACertsPEM` and `SignCSR` racing under one deadline.

**The sign gate (FS-2)**
- `TestClusterCAUsable_ValidityWindow` — 7 cases: inside, either side of expiry, long
  expired, no CA, clock rollback within/past tolerance.
- `TestSignCSR_RefusesExpiredClusterCA` — **the gate**: refusal, `ErrClusterCAUnusable`, no
  material returned, both counters moved.
- `TestSignCSR_RefusesNotYetValidClusterCA` — the other bound.
- `TestSignCSR_HealthyClusterCAIsUnaffected` — negative control, including that the issued
  cert still verifies against its own CA.

**The clamp (FS-3)**
- `TestSignCSR_ClampsNodeCertValidityToIssuer` — leaf `NotAfter` ≤ issuer's, `NotBefore` ≥
  issuer's, and the **returned** expiry matches the certificate (the cluster store and the DP
  renewal loop must not disagree about when a node dies).
- `TestClampNodeCertValidity_LeavesRoomyIssuerAlone` — no-op on a fresh 10-year CA, and nil
  issuer passes through rather than zeroing the window.

**Rotation observability (FS-4)**
- `TestRecordRotationFailure_IsCountedAndAlerted` — counter, degraded state, cause preserved,
  and the pre-existing `Info()` field still populated.
- `TestClusterCARotationDegraded_ClearsOnEvidence` — clears on an observed successful import,
  re-arms on a later failure, cumulative counter never decreases.
- `TestClusterCAAlert_IsRateLimitedButFullyCounted` — 500 refusals ⇒ 1 alert, count still 500.
- `TestClusterCAAlert_NoSubscriberSpawnsNoGoroutine` — the default-posture contract.

**The bootstrap panic (CA-18)**
- `TestImportCA_BootstrapWithNoExistingCA` — succeeds, installs, invents no secondary.
- `TestImportCA_RotationStillTracksOverlap` — negative control: a real rotation still records
  the overlap and keeps the trust pool populated.

**Surfaces**
- `TestClusterCAMetrics_SurfaceUsabilityAndOmitWhenAbsent` — gauges omitted with no CA,
  present and correct when expired and when healthy; counters always present.
- `TestClusterCAMetrics_AreLabelFree` — the CA-2 contract.
- `TestHealthz_ClusterCAPosture` — `not_initialized` / `ready` / `expired`.
- `TestOperatorContract_ClusterCARow` — absent on a node with no cluster CA; `fail` with
  impact + operator action when expired; no raw cause leaked to a viewer; `ok` when healthy.
- `TestClusterCAInfo_ReportsUsability` — `usable` false but `initialized` still true; the two
  are different questions.

---

## Residual Risk

1. **Re-entrancy is prevented here by review, not by construction.** The fix removes the two
   known re-entrant calls; nothing stops a third from being added. The general guard would be
   a lock-order/re-entrancy linter or restructuring `clusterCA` so publication is
   architecturally outside the lock (e.g. a publish queue). Not attempted here — the same
   pattern (`Lock()` + `defer Unlock()` + a callback) exists elsewhere in the codebase and
   deserves its own sweep. **Suggested next.**
2. **`ImportCASilent` (the HA replication path) does not validate the incoming CA's window.**
   It calls `loadFromPEM` directly, which cross-validates cert↔key but does not check
   expiry. A leader replicating an expired CA installs it on the standby. The new `SignCSR`
   gate catches the consequence, so this is a diagnosis-quality gap rather than a new hole —
   but the standby should refuse the handover, not discover it at first signature.
3. **The two-file CA write is still not atomic** (pre-existing, documented in place). A crash
   between the cert and key writes leaves a mismatched pair, detected at next startup by
   `loadFromPEM` cross-validation and failed closed. Auto-repair remains out of scope.
4. **`clusterCAUsable` reads wall-clock `time.Now()`**, so a clock stepped *forward* past the
   CA's `NotAfter` produces a false refusal until the clock is corrected. This is the correct
   direction to fail — a peer with the same wrong clock would reject the chain anyway — but
   NTP misconfiguration can present as a cluster-CA incident. The refusal text names the
   violated bound and the timestamp, which is what disambiguates it. Same posture as
   CHAOS-28's residual #4.
5. **Re-enrollment after a post-expiry rotation is fully manual** (see Recovery Assessment).
   The mitigation is early warning on `culvert_cluster_ca_expires_in_seconds`, which now
   exists; operators should alert on it at 60+ days, not 30.
6. **`InitOrLoad` accepts an expired cluster CA at startup and reports `Ready()`.** This is
   deliberate: refusing to load would remove the only object rotation can replace, and
   `StartCAAutoRotation` now runs a rotation round immediately at boot (CHAOS-28 / CA-4), so
   the recovery is already wired. The condition is visible on `/healthz`, `/metrics` and the
   contract row from the first scrape.
