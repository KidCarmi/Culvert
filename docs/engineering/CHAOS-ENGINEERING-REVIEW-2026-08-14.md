# Chaos Engineering Review — 2026-08-14

**Domain:** the **CA plane's recovery paths** — what the appliance does *after* a
certificate authority fails. Two CAs are in scope because they share one
goroutine and one failure philosophy: the **inspection CA** (`internal/ca`,
MITM/SSL-inspect) and the **cluster CA** (`enrollment.go`, node enrollment and
CP↔DP mTLS).
**Register items:** **CA-3** (open since 2026-07-04, severity H) and **CA-13**
(named by CHAOS-28 as "next sweep") · opens **CHAOS-50** and **CHAOS-51**.
**Verdict:** eight confirmed defects, all fixed. One of them — CHAOS-51 — is a
**hard, unrecoverable Control-Plane deadlock** that was not in the register, was
not suspected, and was found by accident: it fired inside the *control* arm of
the harness written to reproduce something else.

---

## Executive Summary

The register's two prior CA sweeps each closed one question and left the next one
unasked. CHAOS-06 made a Root-CA load failure **visible** (`sslInspectionLoadError`
→ `/healthz`, `/readyz`, a `ca_load_failed` alert). CHAOS-28 made an **expired**
CA **fail closed** rather than sign leaves no client would accept. Neither asked
what happens *next* — and the answer, uniformly, was **nothing**. The bundle was
read exactly once, at startup. The recorded failure was never cleared by anything.
The one background loop that could have healed either CA was skipped whenever the
inspection CA was the thing that failed.

Then the cluster CA turned out not to have a recovery problem at all. It has a
liveness problem: **its install path self-deadlocks**, permanently, and takes the
whole Control Plane with it.

| # | Failure mode | Class | Sev |
|---|---|---|---|
| FS-1 | `ImportCA` holds `ca.mu` across `onRotate` → `rebuildCPCertPool` → `AllCACertsPEM` → `ca.mu.RLock` | **Deadlock** (self, on a non-reentrant RWMutex) | **Critical** |
| FS-2 | `ImportCA` holds `ca.mu` across `CurrentConfigSnapshot` → `CACertFingerprint` → `ca.mu.RLock` | **Deadlock** | **Critical** |
| FS-3 | `CleanupSecondary` holds `ca.mu` across `onRotate` (same chain as FS-1), driven by the unattended 24 h loop | **Deadlock** | **Critical** |
| FS-4 | `ImportCA` dereferences `ca.secondaryCert` unconditionally; a first import has no secondary | Nil-panic | H |
| FS-5 | The auto-rotation loop is gated on `certMgr.Ready()`, but it drives the **cluster** CA too | Cross-subsystem SPOF / silent failure | H |
| FS-6 | A failed CA load is never retried — a transient volume/permission fault disables inspection until restart | Recovery failure | H |
| FS-7 | `sslInspectionLoadError` is write-only — health, readiness and support telemetry stay red after a real recovery | Silent failure (inverted) | M/H |
| FS-8 | An admin-uploaded MITM CA was never persisted, and the inspect-matched fail-open bypass had no counter | Silent failure ×2 | M |

### How CHAOS-51 was found

The harness for this sweep was written to prove FS-5: *"a corrupt inspection-CA
bundle stops the cluster CA from rotating."* It had a control arm — same setup,
**healthy** inspection CA — whose only job was to show the cluster CA *does*
rotate when the loop runs.

The control arm hung. `go test` killed the package at its 300 s timeout and
printed the reason:

```
goroutine 20 [sync.RWMutex.RLock, 5 minutes]:
  Culvert.(*clusterCA).CACertFingerprint(...)      enrollment.go:1030
  Culvert.CurrentConfigSnapshot()                  controlplane_snapshot.go:1258
  Culvert.(*clusterCA).ImportCA(...)               enrollment.go:1201
  Culvert.(*clusterCA).RotateIfNeeded(...)         enrollment.go:1312
  Culvert.StartCAAutoRotation.func1()              ca.go:84
```

`ImportCA` takes `ca.mu.Lock()` at the top with a deferred unlock and, 70 lines
later, calls `CurrentConfigSnapshot()`, which reads `globalClusterCA.CACertFingerprint()`,
which takes `ca.mu.RLock()`. Go's `sync.RWMutex` is not reentrant: an `RLock` on
a mutex the calling goroutine already holds for writing blocks forever. Reading
outwards from there found the same shape twice more — `onRotate` (which is wired
to `rebuildCPCertPool`, which calls `AllCACertsPEM`, which `RLock`s) in both
`ImportCA` and `CleanupSecondary`.

**The blast radius is not the caller.** The write lock is held forever, so every
reader of the cluster CA blocks forever too: `CACertFingerprint` — and therefore
**every CP→DP `ConfigSnapshot`** — plus `Ready`, `Info`, `SecondaryActive`, and
`AllCACertsPEM`, i.e. every TLS client-CA pool rebuild. Node enrollment stops,
config distribution stops, the cluster admin API hangs, and the goroutine holding
the lock cannot be interrupted. Only a process restart clears it, and for the
auto-rotation trigger the restart does not help: the expiry condition that armed
`RotateIfNeeded` survives the restart, so the node deadlocks again on the next
round. That is a **self-reproducing, non-recoverable outage**.

**And it is worse than one mutex.** `rebuildCPCertPool` takes `cpTLSConfig.mu`
*first* and only then blocks on `ca.mu.RLock`, so on the FS-1 path the CP TLS
config mutex is stranded too — and that is the mutex
`getCPTLSConfigForClient` takes on **every ClientHello**. So the CP's gRPC
listener stops completing handshakes at all: a DP that reconnects after the
deadlock cannot even reach the RPC that would have returned stale config. This
was not deduced from the source; it was observed. The pre-fix proof run wedged in
the *test cleanup*, which restores `cpTLSConfig.cfg` and therefore takes the same
stranded mutex. (The gate's helper now uses `TryLock` there, so a future
regression reports a failure instead of hanging CI behind it.)

**Reachable two ways, one of them unattended:**

1. `POST /api/cluster/ca` — the admin "import custom cluster CA" button. Fires
   **immediately and deterministically** on any Control Plane whose gRPC server is
   up, because that is exactly what wires `onRotate` (`controlplane_tls.go:107`).
2. `clusterCA.RotateIfNeeded` — auto-rotation, when the cluster CA enters its last
   30 days. No operator involved.
3. `CleanupSecondary` — when a dual-CA overlap window ends. Also unattended, also
   from the 24 h loop.

### Why the existing tests never saw it

Every existing `ImportCA` test calls the method on a **local** `clusterCA` value:

```go
cca := &clusterCA{}                  // cert_rotation_metrics_test.go:99
_ = cca.InitOrLoad(t.TempDir())
_ = cca.ImportCA(newCertPEM, newKeyPEM)   // passes, always
```

The re-entrant reads go through the `globalClusterCA` **package variable** — a
different object, a different mutex. The tests exercised the method; production
exercises the wiring. Nothing in the suite ever made the object under test *be*
the global, and `rebuildCPCertPool` additionally returns early when
`cpTLSConfig.cfg == nil`, which it always is in a unit test, so even a test that
did use the global would have missed FS-1 unless it also stood up the CP TLS
config. The new gates (`chaos51_clusterca_deadlock_test.go`) do both, deliberately.

This is the generalisable lesson of the sweep, and it is worth more than the fix:
**a test that constructs its own instance of a singleton cannot observe a
re-entrancy defect in that singleton.** Deadlocks of this class live in the gap
between "the method works" and "the method works where it is actually called."

### Measured, against `main`

| Observation | Result on unmodified `main` |
|---|---|
| Cluster-CA auto-rotation with the real global (the harness *control* arm) | **Hung.** Package killed at the 300 s timeout; dump shows `ImportCA` → `CurrentConfigSnapshot` → `CACertFingerprint` blocked in `RLock` for 5 minutes |
| The CHAOS-51 gates run against an unmodified `enrollment.go` (fix reverted, everything else in place) | **Hung**, on the FS-1 site this time — see the stack below. It also hung *harder* than expected: the wedge propagated into the test **cleanup**, which restores `cpTLSConfig.cfg` and so takes the mutex `rebuildCPCertPool` stranded on its way into the deadlock |
| The same gates against the fixed `enrollment.go` | Pass; imports, rotation, cleanup and every reader complete in ~10 ms |
| First `ImportCA` with no prior CA (`ca.secondaryCert == nil`) | Nil dereference — but only when `onRotate` is unwired (no CP TLS server); with a CP up, the FS-1 deadlock at the preceding line wins the race, which is why the panic had never been seen |

The second row's stack, from the 10-minute dump — the FS-1 site, with the exact
wiring a running Control Plane has:

```
goroutine 24 [sync.RWMutex.RLock, 10 minutes]:
  Culvert.(*clusterCA).AllCACertsPEM(...)   enrollment.go:1234
  Culvert.rebuildCPCertPool()               controlplane_tls.go:43
  Culvert.(*clusterCA).ImportCA(...)        enrollment.go:1186
```

So both re-entrant sites are confirmed by observation, not by inference: FS-2
from the first run, FS-1 from the second. That second row is also where the
`cpTLSConfig.mu` half of the blast radius came from — the proof harness
demonstrated it by deadlocking in a place that had no business deadlocking.

---

## Failure Scenarios

### FS-1 / FS-2 / FS-3 — the cluster CA install path deadlocks

**Current behavior (pre-fix).** `ImportCA` (`enrollment.go:1118`) takes
`ca.mu.Lock()` at line 1128 with `defer ca.mu.Unlock()`, then at lines 1185 and
1201 calls out of the object twice:

```go
ca.mu.Lock()
defer ca.mu.Unlock()
...
if ca.onRotate != nil { ca.onRotate() }              // → AllCACertsPEM → RLock
...
_ = globalConfigStore.Update(CurrentConfigSnapshot()) // → CACertFingerprint → RLock
```

`CleanupSecondary` (line 1215) repeats the first one.

**Expected behavior.** A mutation completes and releases its lock; notification
and publication happen outside it. Nothing called under `ca.mu` may reach
`globalClusterCA`, `CurrentConfigSnapshot`, or the CP TLS pool.

**Failure mode.** Permanent self-deadlock, write lock held for the life of the
process, all readers blocked.

**Recovery path.** None automatic. Restart clears the lock but not the trigger for
the auto-rotation and cleanup variants.

**Customer impact.** Total Control-Plane stall on a multi-node deployment: no new
node can enroll, no DP receives config, the cluster admin surface hangs.

**Security impact.** DP nodes keep enforcing their last-good config, so this is an
availability and staleness failure, not an open door — but it freezes policy
distribution indefinitely, which means a *policy tightening* (a new block rule, a
revoked node) silently never reaches the fleet. HA-1's "no max-staleness ceiling"
becomes unbounded in practice.

**Fix.** `ImportCA` is split: `installLocked` does validation, backup, overlap
bookkeeping, persistence and the state swap under the lock and returns a
`clusterCAImportEffects` value; `ImportCA` then runs `onRotate`,
`StartCARotation`, the config publish and the counter with the lock released.
`CleanupSecondary` captures `onRotate` under the lock and calls it after
unlocking. The invariant is stated as a comment on `ImportCA` so the next edit
does not re-introduce it.

### FS-4 — first cluster-CA import nil-panics

`ImportCA` computed the rotation-tracking window from `ca.secondaryCert.Raw`
unconditionally, but the secondary is only set when a previous CA existed
(`if ca.cert != nil` at line 1150). A first import on a node whose cluster CA was
never initialised therefore dereferenced nil.

It is ordered *between* the two deadlocks — after the `onRotate` call (FS-1),
before the config publish (FS-2) — so which failure a node gets depends on
whether its CP TLS server is up: with `onRotate` wired it deadlocks first and the
panic is unreachable; without it (a node that is not serving the CP), the panic
fires. Either way the import does not complete.

**Fix.** `StartCARotation` is called only when there was a previous CA to overlap
with. Pinned by `TestChaos51_FirstImportWithNoPriorCADoesNotPanic`.

### FS-5 — an inspection-CA failure silently stops cluster-CA rotation

**Current behavior (pre-fix).** `rootca_startup.go`:

```go
if certMgr.Ready() {
    StartCAAutoRotation(ctx, cfg.Path, cfg.Passphrase)
}
```

`StartCAAutoRotation` (`ca.go:63`) drives **four** things per round:
`certMgr.RotateIfNeeded`, `certMgr.CleanupSecondaryCA`,
`globalClusterCA.RotateIfNeeded`, `globalClusterCA.CleanupSecondary`. The gate
asks about one of them.

So a wrong `CULVERT_CA_PASSPHRASE`, a corrupt `ca.bundle`, or a data volume that
attached after the container started — all of them inspection-CA faults — left
the **cluster** CA with no auto-rotation and no overlap cleanup for the life of
the process. Two CAs with different lifecycles, different blast radii and no
functional relationship, coupled by a single `if`.

The gate also bought nothing: both `RotateIfNeeded` implementations already return
immediately when their own CA is absent (`CAExpiry().IsZero()`;
`ca.cert == nil`), so on a CA-less node the round is two nil checks a day.

**The compounding case.** It also made every *runtime* recovery permanent-but-
useless. An operator who fixes inspection with the admin force-rotate gets a
working CA that will **never auto-rotate**, because the loop that would have
rotated it was skipped at boot and nothing else starts it.

**Fix.** `StartCAAutoRotation` is called unconditionally.

### FS-6 — a failed CA load is never retried

**Current behavior (pre-fix).** `initInspectionCA` reads the bundle once. On
failure it logs, records, alerts — and stops. There is no retry anywhere in the
process.

The faults that actually happen in production are transient: a data volume that
attaches after the container starts, an NFS/EBS hiccup, a parent directory whose
ownership is corrected a minute later, a disk that was full when the first bundle
was written. In every one of them the appliance stayed with SSL inspection
disabled long after the underlying fault had cleared, until a human noticed and
restarted it.

**Fix.** A bounded retry campaign (`rootca_recovery.go`): 10 attempts on a 5 s →
5 min exponential backoff (≈25 min of coverage), then a terminal log line naming
the manual recovery. Bounded and logged, per the project's "avoid infinite
retries / avoid hidden retries" rules. No goroutine is spawned on a healthy boot.

**The load-bearing decision here is what a retry is allowed to do.**
`LoadOrInitCA` *generates and persists a brand-new root* when the bundle path does
not exist. That is correct on first boot and catastrophic on a retry: if the fault
is an unmounted volume then the path **is** absent, so a minting retry would
silently replace the fleet's trust anchor with one no client has been told to
trust, and write it to the container's ephemeral layer — reproducing the CA-1
symptom (every client rejects every leaf) from a completely different cause, with
the appliance reporting itself healthy throughout. The retry therefore re-reads
the *configured* bundle (`LoadCA`) and never mints. Minting a root is a trust
decision; it belongs to an operator pressing a button, not to a timer. Pinned by
`TestChaos50_RecoveryNeverMintsANewRoot`.

The attempt is also matched to the fault: no path configured ⇒ re-`InitCA`
(the failure was entropy, nothing is persisted); a CA already loaded ⇒ re-`SaveCA`
(the failure was the durability half — `LoadOrInitCA` runs `InitCA` before
`SaveCA`, so a save failure leaves a recorded failure with `Ready()` true);
otherwise ⇒ re-`LoadCA`.

### FS-7 — the health signal outlives the fault it describes

**Current behavior (pre-fix).** `sslInspectionLoadError` had exactly one writer
and no clearer in the entire non-test tree. An operator who recovered inspection
at runtime — force-rotate, or a custom CA upload — kept:

- `/healthz` → `ssl_inspection: load_failed`
- `/readyz` → `ca: fail`
- `/readyz?strict=1` → **503 `not_ready`**, forever
- `support_health_ssl_inspection` → not ready

…until the process restarted. On a `?strict=1` readiness probe that is an
orchestrator that will never return the node to service after the operator has
already fixed it.

This inverts the rule the rest of this plane is built on. `ca_health.go` and
`storage_health.go` both insist that degraded state clears **on observed evidence,
never on elapsed time** — and they are right, but the corollary is that it must
actually clear *when the evidence arrives*.

**Fix.** `noteSSLInspectionRecovered` clears the latch, and is called only where
the evidence covers the fault: from the recovery loop on a successful re-read, and
from `apiCARotate` **after** the persist check (a rotation that did not reach disk
resolves the load half and not the durability half, so the failure must stay
recorded).

### FS-8 — two silent halves

**(a) An uploaded MITM CA was never persisted.** `apiCertsUpload(target=mitm)`
called `LoadCustomCA` and returned 200. Nothing wrote the bundle, so the admin's
enterprise CA silently vanished on the next restart — the same swallowed-durability
shape CHAOS-28 fixed for rotation, on the other CA-install path. It now persists,
reports `persisted:false` with a warning when the write fails, and clears the load
latch only when the bundle actually landed.

**(b) The fail-open bypass had no counter.** When policy selects inspection and no
CA is loaded, `handleTunnel` falls through to `handleTunnelBypass` — DLP, AV, YARA,
CDR and DPI all off for that session. An *expired* CA moves
`culvert_ca_inspect_blocked_total`; a CA that never loaded moved **nothing**. An
operator could not answer "how much traffic left this gateway uninspected during
the incident" from any surface in the appliance. It is now counted
(`culvert_ca_inspect_bypassed_total`), rate-limited-logged, and surfaced on
`/api/ca/status` and the CA panel.

---

## Risk Matrix

| # | Likelihood | Impact | Detectability (pre-fix) | Residual |
|---|---|---|---|---|
| FS-1/2 | **Certain** on any custom cluster-CA import; certain at cluster-CA expiry−30d | Total CP stall, non-recoverable | Zero — no log, no metric, no probe; the process stays "up" | Closed |
| FS-3 | Certain when an overlap window ends | Same | Zero | Closed |
| FS-4 | First import on an un-initialised cluster CA | Panic (contained on the loop path by `runGuarded`, uncontained on the API path) | Crash record | Closed |
| FS-5 | Any inspection-CA load failure | Cluster CA never rotates; overlap never cleaned | Zero — the CA panel shows the *inspection* CA | Closed |
| FS-6 | Common (container volume race) | Inspection disabled until restart | Startup log + alert only | Bounded retry; permanent faults still need a human |
| FS-7 | Every runtime recovery | Strict readiness never returns | Actively misleading | Closed |
| FS-8a | Every custom MITM CA upload | CA lost on restart | Zero | Closed |
| FS-8b | Whole duration of any load failure | Uninspected egress, unmeasured | Zero | Counted; **posture unchanged — see Residual Risk** |

---

## Recovery Assessment

| Scenario | Before | After |
|---|---|---|
| Cluster CA imported / rotated | **Deadlock; no recovery, and restart re-triggers it** | Completes; readers unblocked |
| CA bundle unreadable at boot, fault clears | Restart only | Automatic within ~25 min, bounded |
| CA bundle unreadable at boot, fault permanent | Restart only | Same — but now with a terminal log line that says so |
| Bundle path's volume disappears | (n/a — nothing retried) | Retries fail and give up; **never mints a replacement root** |
| Operator force-rotates to recover | CA works, health stays red forever, rotation loop still dead | Health clears, rotation loop already running |
| Operator uploads a custom MITM CA | Works until restart, then silently gone | Persisted, or explicitly reported as not persisted |

---

## Operational Impact

New signals, all on surfaces that already exist:

| Surface | Signal |
|---|---|
| `/metrics` | `culvert_ca_load_failed` (gauge), `culvert_ca_load_recovery_attempts_total`, `culvert_ca_inspect_bypassed_total` |
| `/api/ca/status` | `loadFailed`, `loadFailureReason`, `inspectBypassed`, `loadRecoveryAttempts`, `loadRecoveryGaveUp`, `loadRecoveryError` |
| CA panel | a red fail-**open** banner stating that traffic is leaving uninspected, the count, and whether recovery is still retrying or has given up |
| `POST /api/certs/upload` (mitm) | `persisted` + a warning when the bundle write fails |
| Logs | `SSLCA: Root CA recovery attempt N/M failed …`, `SSLCA: Root CA recovered …`, `SSLCA: Root CA recovery gave up …`, `SSLCA: no Root CA loaded — N inspect-matched CONNECT(s) have been forwarded UNINSPECTED …` |

**GUI parity:** no new CLI flag, YAML key or config option is introduced — the
retry schedule is a code constant, deliberately (see Residual Risk). The new
*status* is surfaced on the admin API and the CA panel.

`culvert_ca_load_failed` is the one to alert on: it is the only series that
distinguishes "this node was never configured to inspect" from "this node's
configured CA failed and its traffic is leaving uninspected". `culvert_ca_usable`
reports 0 for both.

---

## Security Impact

- **CHAOS-51 freezes policy distribution.** DP nodes keep their last-good config,
  so nothing opens — but a tightening (new block rule, revoked node, updated
  threat feed) silently never lands. An availability failure that presents as a
  security-currency failure.
- **The minting guard is the security-critical part of CHAOS-50.** A retry that
  could mint would let an unmounted volume rotate the fleet's trust anchor with no
  human decision and no audit event.
- **Uninspected egress is now measurable.** FS-8b does not change what happens; it
  makes the window observable while it is open, which is the precondition for the
  posture decision below.
- **No new credential exposure.** `loadFailureReason` carries the bundle path and
  goes only to the role-gated admin API — the unauthenticated `/readyz` row keeps
  its fixed, posture-free detail (the CHAOS-28 reasoning about fingerprinting a
  security-degraded node is unchanged).

## Data Integrity Impact

FS-8a is the only data-integrity finding: an admin-uploaded cluster-trust artefact
was accepted and not persisted. The CHAOS-51 deadlock occurs *after* both cluster
CA files are atomically written, so no on-disk state is corrupted by it — the
process wedges with correct bytes on disk, which is why a restart recovers the
lock (and why the trigger surviving the restart is the real problem).

---

## Suggested Improvements (beyond this PR)

1. **Take the CA-3b posture decision.** The data to take it on now exists
   (`culvert_ca_inspect_bypassed_total`). If the answer is fail-closed, the
   natural shape is to reuse `failClosedUnusableCA` for the `!Ready()` branch —
   a three-line change — plus a documented break-glass for estates that
   deliberately run without a CA.
2. **A lock-discipline check for `clusterCA`.** CHAOS-51 is a shape, not a typo:
   "a method holds its own mutex and calls a package-level function that reads the
   same singleton". A small vet-style test that walks the AST of `enrollment.go`
   for calls to `globalClusterCA.*`, `CurrentConfigSnapshot` or `rebuildCPCertPool`
   inside a `ca.mu.Lock()` region would make the invariant executable rather than
   a comment. Worth doing if a second instance of this shape ever appears.
3. **Audit the other singletons for the same shape.** `clusterCA` is not special;
   any `mu.Lock()`-holding method that calls out to package-level code which reads
   the same global has this defect latent. `certMgr`, `globalClusterStore` and
   `policyStore` are the obvious candidates for the next sweep.
4. **CA-13** — give the cluster CA's rotation failures the alert + metric the
   inspection CA got in CHAOS-28.

## Shipped in this PR

| Change | File |
|---|---|
| `ImportCA` split into `installLocked` + post-lock effects; nil-secondary guard | `enrollment.go` |
| `CleanupSecondary` calls `onRotate` unlocked | `enrollment.go` |
| Auto-rotation loop started unconditionally | `rootca_startup.go` |
| Bounded, never-minting CA load recovery + evidence-based latch clearing + fail-open counter | `rootca_recovery.go` (new) |
| Fail-open bypass counted at the dispatch decision | `proxy_tunnel.go` |
| `culvert_ca_{load_failed,load_recovery_attempts_total,inspect_bypassed_total}` | `ca_metrics.go` |
| `/api/ca/status` load posture; force-rotate and MITM-upload clear the latch; MITM upload now persists | `ui_security.go` |
| CA-panel fail-open banner | `static/index.html` |
| Gates | `chaos51_clusterca_deadlock_test.go`, `rootca_recovery_test.go` (new) |
| Runbook §6 | `docs/operator/root-ca-expiry.md` |

## Required Tests

`chaos51_clusterca_deadlock_test.go` — all drive the call on a child goroutine and
fail on a 20 s timeout, so a regression reports instead of wedging CI:

| Test | Pins |
|---|---|
| `TestChaos51_ImportCAOnGlobalDoesNotDeadlock` | FS-1 + FS-2, with the object under test installed **as `globalClusterCA`** and `cpTLSConfig.cfg` non-nil — the only configuration in which the defect exists |
| `TestChaos51_FirstImportWithNoPriorCADoesNotPanic` | FS-4 |
| `TestChaos51_CleanupSecondaryDoesNotDeadlock` | FS-3 |
| `TestChaos51_CleanupSecondaryNoOpWhenOverlapLive` | the restructure kept the guard — a live overlap is untouched |
| `TestChaos51_ConcurrentReadersProgressDuringImport` | the blast radius: readers must progress after an import |

`rootca_recovery_test.go`:

| Test | Pins |
|---|---|
| `TestChaos50_RotationLoopStartsDespiteInspectionCAFailure` | FS-5 — the cluster CA rotates even though the inspection bundle is corrupt |
| `TestChaos50_TransientLoadFailureSelfHeals` | FS-6 — a fixed bundle is re-read without a restart |
| `TestChaos50_RecoveryNeverMintsANewRoot` | FS-6's security half — a missing bundle must never produce a new root |
| `TestChaos50_RecoveryIsBounded` | exactly `caLoadRetryBudget` attempts, and it stays stopped |
| `TestChaos50_HealthClearsOnRecoveryEvidence` | FS-7 — `/healthz` and `/readyz?strict=1` recover |
| `TestChaos50_RecoveryClearsOnlyOnRealEvidence` | the converse — nothing fabricates a recovery |
| `TestChaos50_InspectMatchedBypassIsCounted` | FS-8b — and that it is **not** counted as a fail-closed block |
| `TestChaos50_MetricsExposeLoadPosture` / `TestChaos50_CAStatusSurfacesLoadPosture` | the operator surfaces |

---

## Residual Risk

- **The fail-open posture is unchanged, and is the main open item.** An inspect-
  matched CONNECT with no CA loaded still proceeds as an unscanned tunnel, while
  the same appliance-wide fault discovered at *expiry* is refused with a 502.
  Same fault class, opposite posture, decided by whether `caCert != nil`.
  CHAOS-28's own comment argues the bypass branch is the wrong destination for an
  appliance-wide CA fault — but its supporting reasoning ("refusing does not cost
  availability that signing would have preserved") does **not** carry over: an
  expired CA's traffic was already dead, whereas this traffic works fine as a
  tunnel. Flipping it converts a silent degradation into a visible outage for
  every estate currently running with a broken CA path. That is a customer-visible
  availability decision and it belongs to the owner, not to a chaos fix. This
  review's contribution is to make the window short (FS-6) and measurable (FS-8b)
  so the decision can be taken on data. **Recorded as CA-3b.**
- **The retry schedule is not configurable.** 5 s → 5 min, 10 attempts, in code.
  An estate whose volume attaches later than ~25 min after boot still needs a
  restart. Deliberate: a new tunable would need a flag, YAML key, admin endpoint
  and panel under the GUI-parity rule, for a value nobody has yet asked to change.
- **A permanent fault still needs a human.** Wrong passphrase and corrupt bundle
  are not self-healing, by construction. The change is that the appliance now says
  so explicitly instead of going quiet.
- **`caRuntime` remains unsynchronised.** `loadRootCA` writes `caRuntime.path` /
  `.passphrase` without a lock, and the recovery goroutine reads its own resolved
  copy (`cfg`), not `caRuntime` — so this change adds no new race. The pre-existing
  one flagged by `ARCH_DISCOVERY` is untouched and still open.
- **`CleanupSecondary` publishes no ConfigSnapshot.** The restructure preserved
  existing behaviour exactly; whether the end of an overlap window should bump the
  config version is a separate question and is left as it was.

---

## Deliberately Left Open

- **CA-13** — the cluster CA's rotation *failure* branches still log-and-return
  with no alert or metric (they do record `lastRotationErr` for `Info()`, which is
  more than the register credits). Named again for the next sweep; this sweep
  found something worse on the same path and spent its budget there.
- **CA-4's retry half** — a rotation that fails still waits a full 24 h.
- **CHAOS-46**, **CHAOS-43**, **CA-8**, **CA-10**, **CA-12**, **CA-14**, **CA-15** —
  unchanged.
