# Chaos Engineering Review — 2026-08-19

**Sweep:** CHAOS-50 — the **cluster (enrollment) CA** across its lifecycle
**Register rows:** closes **CA-13**, and opens+closes **CA-17 (new, Critical)**, **CA-18**, **CA-19**,
**CA-20**; extends the CHAOS-28 contract to the second trust root
**Scope:** `enrollment.go` (`clusterCA`), `ca.go` (the shared rotation loop), `rootca_startup.go`,
and the observability surfaces (`/metrics`, `/healthz`, `/readyz`, `/api/diagnostics`,
`GET /api/cluster/ca`, the Cluster CA admin panel)
**Method:** every defect below was reproduced against `main` before any fix was written — D0 with a
goroutine stack trace, D1/D2/D6 by running the inverted assertion against the pre-fix engine, D5 by
reverting only `rootca_startup.go` and watching the gate fail. The observability gates
(metrics/`/healthz`/`/readyz`/diagnostics/admin API) assert surfaces that did not exist at all before
this change, so "fails pre-fix" is trivially true for them and was not separately staged.

---

## 1. Executive Summary

CHAOS-28 hardened the **inspection** CA and closed by naming the **cluster** CA as the same defect
class in the other trust root, "with a different lifecycle and blast radius." That handoff was
right about the class and understated the blast radius.

Culvert has two independent trust roots. The inspection CA authenticates the gateway *to clients*;
the cluster CA authenticates *every node to the control plane*. When the inspection CA fails, one
security control degrades and clients see certificate warnings. When the cluster CA fails, the
**control plane itself stops** — config sync, policy distribution, enrollment, and cert renewal all
run over mTLS anchored in that root.

Seven defects, all confirmed on `main`. The first was not on the register at all, is the most
severe thing found in any sweep to date, and was **already known to the codebase** — worked around
in the test suite rather than recorded:

| # | Defect | Severity |
|---|--------|----------|
| **D0** | **`clusterCA.ImportCA` and `CleanupSecondary` self-deadlock**, holding the cluster CA's write lock forever. Fires on `POST /api/cluster/ca` (the documented enterprise custom-CA import) and, unattended, on auto-rotation and on dual-CA overlap cleanup. Wedges enrollment, cert renewal, config publication and TLS-pool rebuild until restart — and hangs the shared rotation loop, so the **inspection** CA stops rotating too. | **Critical** |
| **D1** | An **expired cluster CA kept signing node certificates.** `x509.CreateCertificate` does not check the parent's validity window and nothing else did either. | **High** |
| **D2** | Node certificate `NotAfter` was **not clamped to the issuer's** — an unconditional `now+365d`. In ordinary operation a node enrolled anywhere in the CA's final year held a cert claiming *months* of validity past its own root. | **High** |
| **D3** | An auto-rotation failure reached **`Info()` and nothing else** — no metric, no alert, no probe row, no diagnostics row. Rotation is the CA's *only* recovery, so its failure was the single most important fact about the subsystem and it was invisible to monitoring. | **High** |
| **D4** | **No usability or expiry observability at all.** `culvert_cluster_ca_rotations_total` counts *successes*, so a CP that had failed to rotate every day for a month read identically to one that had never needed to. Both `0`. | **High** |
| **D5** | **The cluster CA's only rotation driver was gated on the *inspection* CA being ready.** A corrupt bundle or a wrong `CULVERT_CA_PASSPHRASE` silently disabled cluster-CA rotation *and* secondary-CA cleanup on a node whose cluster CA was perfectly healthy. | **Medium/High** |
| **D6** | **Nil dereference on the first `ImportCA`** on a node that never ran `InitOrLoad` — and it fired *after* the new CA was swapped in, leaving the trust change partially applied (TLS pool never rebuilt, no rotation tracking). | **Medium** |

The theme is the register's own worst one, in a new place: **the appliance produced output that
could not work, and reported success.** D0 adds a second theme the register has not had to name
before: **a defect the test suite works around is a defect the register never hears about.**

---

## 2. D0 — the self-deadlock (Critical)

### 2.1 The mechanism

`clusterCA.ImportCA` took `ca.mu.Lock()` with a deferred unlock and then, still holding it, ran its
post-commit side effects. Two of those read the cluster CA back:

- `ca.onRotate()` → `rebuildCPCertPool` → `globalClusterCA.AllCACertsPEM()` → `ca.mu.RLock()`
- `globalConfigStore.Update(CurrentConfigSnapshot())` → `globalClusterCA.CACertFingerprint()` → `ca.mu.RLock()`

`sync.RWMutex` is not reentrant, and **the receiver is the package global in production** — every
caller is `globalClusterCA.ImportCA(...)`. So the goroutine blocks on itself. Proven against `main`:

```
panic: test timed out after 25s
goroutine 21 [sync.RWMutex.RLock]:
sync.(*RWMutex).RLock(...)
github.com/KidCarmi/Culvert.(*clusterCA).CACertFingerprint(0x69d1b99a480)
github.com/KidCarmi/Culvert.(*clusterCA).ImportCA(0x69d1b99a480, …)
```

Same pointer, holding `Lock`, taking `RLock`. `CleanupSecondary` had the identical shape with
`onRotate` under `ca.mu.Lock()`.

### 2.2 Blast radius

The goroutine does not merely hang — it hangs **while holding the write lock**, so every reader
queues behind it permanently:

| Blocked call | Consequence |
|---|---|
| `SignCSR` | Enrollment **and** unattended cert renewal stop, fleet-wide |
| `CACertFingerprint` | `CurrentConfigSnapshot()` blocks → **all config publication** stops |
| `AllCACertsPEM` | `rebuildCPCertPool` blocks → TLS pool can never be rebuilt |
| `Ready()`, `Info()` | `/api/cluster/*`, the bootstrap page, and the admin panel hang |

Three trigger paths, two of them unattended:

1. **`POST /api/cluster/ca`** — the documented enterprise "import your own cluster CA" flow. The
   admin's request never returns; the connection and goroutine leak.
2. **`RotateIfNeeded` → `ImportCA`** — automatic, 30 days before the CA expires. This one also hangs
   the goroutine started by `StartCAAutoRotation`, which drives **both** trust roots — so the
   inspection CA silently stops rotating as well, and `CleanupSecondaryCA` stops running.
3. **`CleanupSecondary`** — automatic, ~30 days after any rotation, when the dual-CA overlap closes.

Recovery is a process restart, and it does work: `commitImport`'s durable writes complete *before*
the deadlock point, so the new CA is on disk and reloads. The cost is the outage window, plus the
fact that nothing anywhere says what happened — a hang produces no panic, so even `runGuarded` (the
CHAOS-24 containment) cannot see it.

### 2.3 Why it survived, which is the part worth recording

The codebase already knew. `cluster_ca_keyatrest_test.go` sets the global to a *different* empty CA
before every import test, and says why:

> *"Pointing the global at a separate empty CA (cert==nil → fingerprint returns fast) keeps the
> snapshot read off the receiver's held write lock. (A pre-existing self-deadlock exists if
> globalClusterCA IS the receiver being imported — out of scope for this key-encryption PR…)"*

Every test that reaches `ImportCA` follows that pattern. The suite is green, the workaround is
honestly documented at the call site — and the defect appears in **no** register, risk row, or ADR.
A known defect parked in a test comment is invisible to everything that reads the register, which is
how a Critical control-plane deadlock stayed live through fourteen chaos sweeps.

`TestChaos50_ImportCADoesNotDeadlock` and `TestChaos50_CleanupSecondaryDoesNotDeadlock` are written
to use the production aliasing *on purpose*, and to assert the side effects actually ran rather than
having been skipped to dodge the lock.

### 2.4 The fix

Commit under the lock, notify with it released. `commitImport` does the backup, dual-CA demotion,
durable write and in-memory swap, and returns the inputs the side effects need; `ImportCA` then runs
`onRotate`, rotation tracking and snapshot publication with `ca.mu` free. `CleanupSecondary` gets the
same split. Concurrent operations are serialised by a **separate** `importMu`, so two admins racing
cannot interleave side effects while readers stay unblocked.

The struct comment now states the invariant directly: `mu` is never held across a call that reads the
cluster CA back.

---

## 3. D1/D2 — the failure scenario, end to end

This is the sequence that made D1 more than a hygiene defect. It was reproduced in pieces; the
chain is what turns them into an incident.

1. The cluster CA reaches `NotAfter`. Rotation was failing (read-only volume — D3, invisible), or
   never ran at all (D5, also invisible).
2. Every enrolled DP's client certificate now chains to an expired root. `buildServerTLS` puts the
   cluster CA in the `ClientCAs` pool, and Go's path validation checks the validity window of
   **every** certificate in the chain, roots included. So every mTLS handshake fails with
   `x509: certificate has expired`. **Config sync stops fleet-wide.** Nothing in the fleet is
   exempt — they were all issued from the same root at the same time.
3. The operator does the obvious thing: re-enroll the node. And it *works* — `Enroll` uses
   `tls.VerifyClientCertIfGiven`, so an unenrolled caller needs no client cert. `SignCSR` signed a
   fresh node certificate with the dead CA. The RPC returned `200`. The node persisted the cert,
   logged a successful enrollment, reconnected — and failed the handshake again, with the same
   opaque error.
4. The operator can loop there indefinitely. Every surface reports success. `/healthz` said
   `status: ok` and carried no cluster-CA field at all. `/readyz` had no row. `/api/diagnostics`
   had no row. `/metrics` moved no counter. `GET /api/cluster/ca` reported
   `initialized: true` and a green *"Active"* in the admin panel.

That is the part worth naming precisely: **the recovery path did not merely fail, it manufactured
evidence that it had worked.** A failure that produces no signal is bad; a failure that produces a
*success* signal actively spends the operator's time.

Reproduction (verified against `main`, both now inverted as gates):

```
--- FAIL: TestRepro_ExpiredClusterCASignsAnyway
    DEFECT D1: expired cluster CA signed a node cert (607 bytes, expiry 2027-08-19…)
--- FAIL: TestRepro_NodeCertOutlivesIssuer
    DEFECT D2: node cert NotAfter 2027-08-19T22:16:49Z outlives issuer 2026-08-29T22:16:49Z by 8520h
```

`TestChaos50_…` also confirms the intermediate claim directly: a cert signed by an expired CA fails
`x509.Verify` against its own issuer. It was unusable from birth.

---

## 4. The decisions that mattered

### 4.1 Fail closed at the signer, not at the RPC gate

The guard lives inside `SignCSR`, not only at `Enroll`'s precondition check. Two call sites reach
the signer — `Enroll` and `RenewCert` — and **renewal is the one that runs unattended on every node
in the fleet**, every 6 hours, forever. A gate on the enrollment RPC alone would have left the
high-volume path unguarded and the low-volume path protected, which is exactly backwards.

Refusing costs no availability that signing would have preserved: the certificate could never
validate. What changes is that an unbounded loop of opaque client-side TLS errors becomes one
countable, named, actionable event **on the node that can actually fix it**.

### 4.2 `Usable()` stays separate from `Ready()` — again, and for a different reason

CHAOS-28 kept `ca.Manager.Usable()` distinct from `Ready()` because folding validity into `Ready()`
would route an expired inspection CA into the **bypass** branch and silently turn off DLP/AV/CDR
fleet-wide. There is no bypass branch here, so the temptation is different — and so is the cost.

`clusterCA.Ready()` is what the enrollment gates, the bootstrap page, and the UI use to decide
whether the *feature exists*. Folding validity in would make an expired CA read as
**"enrollment not configured"** — hiding a live trust outage behind a setup message, on the surface
an operator reaches for first. `Ready()` therefore still answers "is a CA installed"; `Usable()`
answers "can it issue an identity peers will accept"; and `Info()` reports both, separately.

### 4.3 The clamp makes the certificate state honest, and the churn is the point

Unclamped, this was materially worse than the leaf case CHAOS-28 fixed. A forged inspection leaf
overclaimed by up to 24 hours. A node certificate overclaims by up to **a year** — so
`GET /api/cluster/nodes` reported months of validity, the node's own `checkDPCertExpiry` agreed, and
every handshake failed anyway. *Nothing in the fleet was looking at the only date that mattered.*

Clamping does not shorten any window that would otherwise have worked. Its downstream effect is
deliberate: a clamped cert inside the DP's 30-day renewal window puts that node into renewal, so a
silent cliff becomes visible pressure — repeated renewals, a rising
`culvert_cluster_ca_node_certs_clamped_total`, and a warning row.

The renewal churn is bounded and cheap (one CSR per node per 6h), and it is reachable **only on a
fleet whose CA is inside its final 30 days and has not rotated** — i.e. only when something is
already wrong. On a healthy fleet the clamp is inert, because `clusterCARenewalWindow` deliberately
equals the CA's own rotation window: a working CP replaces the CA before any clamp is reachable.
One constant, three consumers, so the three windows cannot drift apart.

### 4.4 Recovery is reported on evidence, never on elapsed time

Both degraded states follow the `storage_health.go` contract:

- `clusterCAUsabilityDegraded()` clears only on an **observed** usable verification.
- `clusterCARotationDegraded()` clears only on a **landed** rotation (both file writes returned).

Elapsed time is not evidence, and here the reason is unusually sharp: **on a settled fleet, nothing
needs a certificate for weeks.** A still-expired CA is indistinguishable from a healthy one if
nothing asks it to sign. A time-based heuristic would report the control plane recovered almost
immediately, and would be wrong every time.

The same split as CHAOS-28 applies to the counters: `rotationFailures` is cumulative (the right
shape for a Prometheus counter, the wrong shape for a status row), so the *current* state is keyed
on `lastRotationFail` vs `lastRotationOK`. A row keyed on the counter would keep contradicting an
operator who had already fixed the volume and imported a replacement.

### 4.5 One loop driving two trust roots must not depend on either (D5)

`StartCAAutoRotation` drives both CAs. Its caller started it only `if certMgr.Ready()`, which reads
as a harmless optimisation — why run a rotation loop for a CA that failed to load? — but the loop is
**the cluster CA's only driver**, so the optimisation silently took down the lifecycle manager of an
unrelated, healthy trust root, along with secondary-CA overlap cleanup.

What makes this the nastiest of the six is the **time constant**: a cluster CA is a 10-year
certificate. The consequence surfaces years after the inspection-CA fault that caused it, with
nothing left to connect them. No log line, at any point, mentions the coupling.

Both halves are individually no-ops when their CA is absent (`RotateIfNeeded` returns immediately on
a zero expiry), so the loop is now started unconditionally and costs one comparison per day on a
node with no inspection CA. The gate is pinned by
`TestChaos50_ClusterRotationSurvivesInspectionCALoadFailure`, which drives the real startup loader
with a corrupt bundle and asserts the cluster CA still rotates.

### 4.6 Reusing `cert_expiry` rather than minting an event name

A new alert event would be **silently unsubscribed on every already-configured webhook**
(`HasSubscriber` compares names exactly — the trap `normalizeEventNames` exists to paper over). An
operator who is paged for Root-CA expiry today plainly wants to be paged for cluster-CA expiry too.
`Host` (`culvert-cluster-ca` vs `culvert-ca`) distinguishes them. No new config, no new operator
vocabulary, no migration.

---

## 5. Risk Matrix

| Defect | Likelihood | Impact | Priority | Now |
|---|---|---|---|---|
| **D0 self-deadlock** | **High** — two of the three triggers are unattended and reached on an ordinary schedule (−30d rotation, +30d overlap cleanup); the third is a documented admin action | Control plane wedged until restart: no enrollment, no renewal, no config publication, no TLS-pool rebuild; the inspection CA stops rotating too. No panic, so nothing observes it | **P0** | Commit-then-notify + `importMu`; two gates using production aliasing |
| D1 expired CA signs | Low (10y cert) but **certain at end of life**, and reachable much earlier via D3/D5 | Fleet-wide control-plane outage with a recovery path that reports false success | **P1** | Fail closed + counted + alerted |
| D2 unclamped node cert | **Certain** — every issuance in the CA's final year | Every expiry surface in the fleet reports validity that does not exist | **P1** | Clamped both ends; gate proves chain validity |
| D3 silent rotation failure | Medium (read-only volume, perms, disk full) | Removes the only recovery path, invisibly, for up to 10 years | **P1** | Counter + alert + `fail` rows |
| D4 no observability | Certain (absence) | The cliff and the slide toward it are both unmonitorable | **P1** | 5 series + 2 probe rows + contract row |
| D5 cross-CA coupling | Low–Medium (needs an inspection-CA fault) | Silently disables an unrelated trust root's lifecycle for years | **P2** | Decoupled + gated |
| D6 first-import nil deref | Low (needs an admin POST on a CA-less node) | 500 + partially applied trust change | **P3** | Guarded |

---

## 6. Recovery Assessment

| | Before | After |
|---|---|---|
| **Detect** | Nothing. Every surface green. | `culvert_cluster_ca_expires_in_seconds` (alert *before* the cliff), `culvert_cluster_ca_rotation_failures_total` (the automatic remedy is not working), `/healthz cluster_ca`, `/readyz cluster_ca`, `/api/diagnostics cluster_ca`, admin banner |
| **Diagnose** | Opaque `x509: certificate has expired` on N nodes; no CP-side signal | One log line and one alert naming the bound violated, on the CP that can fix it; `unusableReason` on the admin API |
| **Automatic recovery** | Auto-rotation at 30 days — **if** the loop was started (D5) and **if** it succeeded (D3, unreported) | Same, and both preconditions are now observable |
| **Manual recovery** | `POST /api/cluster/ca` (import) — unchanged, and never blocked by the new gate | Same, plus the failing surfaces name it as the action |
| **False-success removal** | Re-enrollment returned a dead certificate with a success response | Refused, with an error that says why |
| **Availability of the recovery path itself (D0)** | Importing a replacement CA — the one manual remedy — **wedged the control plane** rather than fixing it | The import completes; a restart is no longer part of the procedure |

The gate deliberately does **not** stand in front of recovery: `ImportCA` and `RotateIfNeeded` do
not go through `SignCSR`, so an unusable CA can always be replaced.

---

## 7. Security Impact

- **Fail-closed is the correct posture here and costs nothing.** The refused certificate could not
  have authenticated anything.
- **No new secret exposure.** Every added surface is counts, booleans, and one time delta.
  `unusableReason` (the only free text) is admin/viewer-role and contains no key material.
- **The unauthenticated surface stays fixed-string.** `/readyz` is served on the proxy port, so the
  `cluster_ca` row carries no dates, paths, or counts — a pinned assertion, because the specific
  cause is a precise fingerprint of a control-plane-degraded node. The gate asserts the detail
  contains no digits at all.
- **Naming the posture is safe in this direction only.** CHAOS-28 established that
  `/readyz` must not publish a *fail-open* posture (it hands an observer the exfiltration window).
  This row fails **closed**, so saying issuance is refused discloses no such window.
- **`Ready()` semantics unchanged**, so no gate anywhere widened.

## 8. Operational Impact

- Healthy fleets are unaffected: `TestChaos50_HealthyCAIssuesUnchangedOneYearCert` pins the
  unchanged 365-day issuance with no counter movement.
- Nodes signed by a CA in its final 30 days now renew repeatedly instead of holding a
  false-validity cert. Bounded (one CSR per node per 6h) and reachable only when something is
  already wrong.
- One new `/readyz` row and one new `/healthz` field, both **absent/`disabled`** when no cluster CA
  exists — a single-node appliance sees no change.
- Alerting rules keyed on `cert_expiry` now also receive cluster-CA events (distinguished by
  `Host`). This is intended; no existing rule needs editing.

## 9. Data-Integrity Impact

D0 left the *process* in a partially-applied state rather than the *files*: `commitImport`'s durable
writes complete before the deadlock point, so the on-disk pair is always consistent and reloads
correctly — which is why a restart recovers. What was inconsistent was live state: a new CA active in
memory whose TLS pool had never been rebuilt and whose rotation tracking never started, frozen there.

D6 was the other integrity defect, with the same shape and a different cause: the first-import panic fired *after* `ca.cert`/`ca.key` were
swapped, so the process ran with a new CA whose TLS pool had never been rebuilt and whose rotation
tracking never started. Now guarded — a first import is a bootstrap, not a rotation, and there is no
prior CA to track. `TestChaos50_FirstImportDoesNotPanic` asserts the import completes, the CA is
usable, and `onRotate` actually ran.

---

## 10. What shipped

| Area | Change |
|---|---|
| `enrollment.go` — **D0** | `ImportCA` split into `commitImport` (locked) + side effects (unlocked); `CleanupSecondary` likewise; new `importMu` serialises operations; struct comment states the never-hold-across-a-callback invariant |
| `cluster_ca_validity.go` (new) | `clusterCAUsable` predicate, `Usable()`, `Expiry()`, `clampNodeCertValidity`, `errClusterCAUnusable`, the shared `clusterCARenewalWindow` |
| `cluster_ca_health.go` (new) | Health record + observers, mirroring `ca_health.go`: count everything, independent log/alert gates, `HasSubscriber`-gated producer, recovery on evidence |
| `enrollment.go` | `SignCSR` fails closed + clamps; `recordRotationFailure` reaches monitoring; `ImportCA` records landed rotations and no longer nil-derefs on a first import; `Info()` reports usability |
| `ca.go`, `rootca_startup.go` | Rotation loop decoupled from inspection-CA readiness |
| `ca_metrics.go` | `culvert_cluster_ca_{usable,expires_in_seconds,sign_refused_total,node_certs_clamped_total,rotation_failures_total}` |
| `healthcheck.go` | `/healthz cluster_ca`, report-only `/readyz cluster_ca` (fixed detail, strict-mode aware) |
| `diagnostics.go` | `cluster_ca` operator-contract row (fail / fail / warn / ok), absent without a cluster CA |
| `static/index.html` | Outage banner, clamp-shoulder banner, and an honest status (`EXPIRED (enrollment blocked)` instead of green *Active*) |

## 11. Required Tests

`cluster_ca_chaos_test.go` (18 gates): **no self-deadlock in `ImportCA` or `CleanupSecondary` under the
production aliasing, with the side effects asserted to have actually run**; fail-closed on expiry; clock-rollback refused *and* skew tolerance held;
clamp correctness plus chain-verifiability of the clamped cert; unchanged healthy issuance;
rotation-failure counted and alerted; both degraded states clearing on evidence only and not on
time; cumulative counters never decreasing; alert gated and rate-limited while every refusal is
counted; `/healthz` + `/readyz` (fail, report-only, strict-aware, no-digit detail); `disabled`/absent
without a cluster CA; diagnostics fail + warn rows with actions and no viewer-visible cause; metrics
present, label-free, expiry gauge omitted when absent; admin API separating `usable` from
`initialized`; first-import no-panic; and the cross-CA coupling gate driving the real startup loader.

---

## 12. Residual Risk

- **Client-side trust cannot be repaired in band.** Rotation restores the CP's ability to *issue*;
  a DP whose cert already expired must re-enroll. That is why this change invests most in making the
  slide visible (`culvert_cluster_ca_expires_in_seconds`, the clamp counter) rather than only the
  cliff.
- **`RotateIfNeeded` still waits a full 24h after a failed attempt** — the cluster-CA twin of CA-4's
  open retry/backoff half. Bounded by a 30-day window, so ~30 attempts before expiry.
- **`ImportCA` is still not a two-file commit.** A crash between the cert and key writes leaves a
  mismatched pair, detected and failed closed at next startup by `loadFromPEM`. Pre-existing,
  documented at the call site, out of scope here.
- **No early-warning alert purely on days-remaining.** Rotation is automatic at 30 days, so the
  actionable signal is "rotation is failing", which now alerts. Operators wanting a days-based page
  have the gauge. A threshold alert would be a reasonable follow-up.
- **Secondary-CA overlap cleanup shares the same 24h loop** and is therefore subject to the same
  single-driver structure — now decoupled from the inspection CA, but still one loop.
- **The workaround comment in `cluster_ca_keyatrest_test.go` has been rewritten** to record the
  history rather than the excuse, so the pattern is not restored as if still load-bearing. There is
  no automated wall against the general class — a test that dodges a known defect instead of
  registering it. A lint/review convention ("a documented pre-existing defect needs a register row")
  would be the systemic fix and is out of scope here.
- **HA replication path (`ImportCASilent`) does not record a rotation observation.** By design: a
  standby replicating leader state has not rotated anything. A standby promoted mid-outage inherits
  the leader's CA and, with it, the leader's usability state — which the new surfaces will report
  correctly on the promoted node.


---

## 13. Review follow-up — two defects in the fix itself

Both were found by automated review of the first cut and both were real. They belong in the record
because they are the *same* mistake the sweep is about, made while fixing it.

### 13.1 `culvert_cluster_ca_usable 0` on every node without a cluster CA

`Usable()` returns "no cluster CA loaded" when there is no CA, so an unconditional gauge rendered
`culvert_cluster_ca_usable 0` on every standalone appliance and every data-plane node —
indistinguishable from an expired CA on a real control plane. §12's own recommended paging rule is
literally `culvert_cluster_ca_usable == 0`, so the shipped runbook would have paged for the entire
estate while promising, two paragraphs later, that these rules "do not fire outside a cluster."

What makes it worth recording is that the neighbouring series got this exactly right:
`culvert_cluster_ca_expires_in_seconds` was already omitted when no CA exists, with a comment
explaining that `0` would read as "expires now." The reasoning was applied to one gauge and not to
the one beside it. Both gauges are now omitted; the counters stay present at `0`, which is their
normal non-alerting state and keeps `rate()`/`increase()` working from the first scrape.

### 13.2 The `NotBefore` skew tolerance issued certificates this node's own verifier rejects

The first cut mirrored the inspection CA's `caClockSkewTolerance`, allowing a `NotBefore` up to five
minutes in the future. Inside that window `Usable()` said yes, `SignCSR` succeeded, and
`clampNodeCertValidity` pinned the leaf's `NotBefore` to the CA's — so the CP issued a certificate
that its **own** x509 verifier rejects, because the CP checks DP client certs against that same CA
using that same clock.

That is the failure mode this entire change exists to remove, reintroduced in miniature: a
successful-looking enrollment producing a certificate that cannot authenticate. Milder than the
expired case — bounded by the skew and self-clearing, and the DP's reconnect backoff covers it —
which is why it is P2 rather than P1, but the shape is identical.

The tolerance was copied without re-deriving its justification. On the inspection CA it absorbs
disagreement between *two machines*: a CA generated seconds ago on a faster peer must not take the
gateway down. Here the rejecting verifier is **co-located with the signer**, so the tolerance does
not reconcile two clocks — it makes one node contradict itself. `NotBefore` is now strict, and clock
rollback lands in the same branch with the same verdict, which is correct for it too: if this node
believes the current time precedes the CA's start, its verifier will reject everything the CA signs.

> **The generalisable rule:** a tolerance is only sound where the two parties it reconciles are
> genuinely distinct. Copying one across a boundary where the verifier is the signer converts
> "absorb disagreement" into "disagree with yourself."
