# Chaos engineering review — 2026-11-25

Reviewer: Culvert Chaos Engineer (automated round). Base revision `f4f9379`
(`origin/main`), clean worktree at branch point.
[CHAOS-ENGINEERING-REVIEW.md](../../roadmap/CHAOS-ENGINEERING-REVIEW.md) stays
the index; this is the dated record for the round it registers.

Id claimed: **CHAOS-128**, in a committed placeholder row as commit one
(`5f65312`), before any code, and checked against `origin/main` rather than the
working tree per the register's 2026-09-25 amendment. `CHAOS-126` was the
highest id anywhere on `origin/main` at `f4f9379`; open PR #2075
(`feat(geoip): export the country database's freshness, and gate the class`)
holds `CHAOS-127`, so this round took 128. Of the other 29 open PRs none is a
chaos sweep and none claims a chaos id.

Scope: **the commit order of the support-evidence upload drain** — what happens
to a bundle an operator consented to send when the durable write that records
its outcome fails. Three failure domains were swept in parallel (plugin/MCP
execution, support-bundle/diagnostics export, cluster convergence); all three
returned a finding. One was fixed, two are recorded in §8 with evidence for a
later round, because each belongs to a different owner and a single PR that
touched all three would be three reviews pretending to be one.

---

## 1. Executive summary

**CHAOS-128 (MED for integrity, MED for availability) — the drain performed two
irreversible side effects on the strength of a durable write that had just
failed, and the comment beside them named the artifact that did not survive.**

`finishUploadDrain` persisted the post-attempt queue entry, treated a persist
error as **log-only**, did **not** return, and then unconditionally ran the two
side effects that are valid only if that write landed
(`support_upload_worker.go:81-100` at base):

1. `removeSealedUpload(updated.BundleID)` → `os.Remove` of the sealed blob
   (`support_upload_wire.go:241`) — the only copy of the bytes
   `BundleSHA256` was computed over; and
2. `auditSystem("support.bundle.upload", …, "receipt "+sig)`, whose own comment
   asserted *"the receipt lives on the persisted queue entry"*
   (`support_upload_worker.go:93-95` at base) — precisely the artifact that had
   just failed to persist.

On an ENOSPC/EROFS/EIO volume the durable entry therefore still read
`queued, attempts=0, next_retry_at=0`, with no `UploadID` and no `Receipt`,
while the bytes were gone and the compliance record already said the evidence
had been delivered. Three consequences compound:

1. **The gateway's signed receipt — the node's only proof of delivery — is lost
   for good.** It existed only on the entry that did not persist.
2. **The next attempt is sent at a file that no longer exists.** `os.Open` of
   the deleted blob returns a plain error, not a `GatewayError`
   (`support_upload_wire.go:305-307`), so `drainUploadEntry` classifies it
   **transient** (`support_upload_queue.go:290-320`), burns the 6-attempt
   budget, and lands `deferred` with
   `last_error="open sealed bundle: no such file or directory"`. The operator
   surface and `support.bundle.upload_deferred` then say the upload **failed**
   while `support.bundle.upload` says it **succeeded** — two durable records of
   the same bundle asserting opposite outcomes.
3. **The same lost write unbounds the retry ladder.** A *transient* failure's
   entire bookkeeping is `Attempts++` and a backoff `NextRetryAt`. If that write
   is lost, the disk keeps `attempts=0, next_retry_at=0`, the entry is
   immediately due again, and the bounded 6-attempt ladder becomes a re-send
   every `supportUploadTick` (30 s) that **can never reach `deferred`** — the
   "broken backoff / infinite retries" class, caused by a disk fault rather than
   by the network.

**The repair is a hold, not an early return, and that distinction is the round's
real content.** Returning before the side effects fixes integrity and
introduces an availability defect in its place: the retained entry is
immediately due on every tick, so the worker would re-upload the **whole
bundle** to the vendor every 30 s for as long as the volume stayed unwritable —
a local disk fault amplified into unbounded egress of operator evidence. So the
outcome is **held in RAM until its write lands**, whatever its state. Holding
does both jobs at once: the receipt is not thrown away, and the bundle is not
re-sent.

Measured on this tree through the production drain (gates in §7):

| probe | before | after |
|---|---|---|
| successful transfer, writer returns ENOSPC | sealed blob **deleted**, `support.bundle.upload` **recorded**, receipt **lost** | blob **retained**, no delivery audited, receipt held + logged |
| 5 worker ticks against an unwritable volume | **5** full bundle transfers | **1** |
| volume recovers after a held success | — (nothing left to commit) | entry lands `uploaded` with its receipt, blob released, delivery audited **once**, 0 held |
| 8 ticks, transient upload error, unwritable volume | **8** transfers, cap (6) never trips | **1** transfer, `attempts=1` and the backoff deadline preserved in the hold |

**Deliberately refused, with reasons in the file comments and §6:** no new
operator setting (the posture is not a choice — an unrecorded outcome must never
authorize a delete), no durable journal for the held outcome (it would need the
same volume that is refusing writes), no alert of its own (`storage_write_failed`
already fires from the `fileutil.AtomicWrite` observer on every failing path,
and a second alert for the same root cause is noise), and no attempt to make the
restart case lossless (see §9 — it is not a gap, it is the only honest
recovery).

---

## 2. Failure scenarios

### 2.1 The one that was open (CHAOS-128)

**Simulated:** disk full / disk read-only / permission denied / slow failing
filesystem on `<dataDir>/support`, while a consented bundle is in the queue.
Injected at the domain's own seam, `supportDurableWriter`
(`support_durable_write.go:24`), which is `fileutil.AtomicWrite` in production.
The fault is injected **after** the enqueue and seal, so the queue entry and the
blob are genuinely on disk — the fault is the drain's write alone, which is the
realistic shape (the bundle store ceiling is 2 GiB and the sealed blob roughly
doubles a bundle's footprint, so the volume can cross full *between* the seal
and the drain).

| | |
|---|---|
| **Current behaviour (base)** | persist error logged; blob deleted; `support.bundle.upload` written; receipt lost; next attempt ENOENT → transient → budget burned → `deferred` |
| **Expected behaviour** | an outcome that is not durable authorizes nothing: keep the bytes, record no delivery, do not re-send, make the condition visible |
| **Failure mode** | silent data destruction plus audit-trail divergence; secondarily, an unbounded retry ladder |
| **Recovery path** | **automatic** once the volume accepts writes: the held outcome is persisted and committed on the next tick, no operator action and no re-consent |
| **Manual recovery** | only if the process restarts while an outcome is held — the bundle is re-sent and a fresh receipt obtained; still no operator action |
| **Customer impact** | an evidence upload the operator believes failed has actually been delivered (or vice versa); re-consent/re-seal work that was not needed |
| **Security impact** | the audit trail asserts a delivery the node cannot substantiate — see §5 |
| **Data-integrity impact** | the sealed ciphertext is destroyed while still owed to the gateway; `BundleSHA256` can no longer be re-derived from anything on the appliance |
| **Monitoring visibility (base)** | `storage_write_failed` fires (the `AtomicWrite` observer), but nothing links it to the lost receipt or the stranded bundle |
| **Monitoring visibility (now)** | `culvert_support_upload_commit_held` (gauge) and `culvert_support_upload_commit_held_total` (counter), plus two log lines — one naming the hold, one carrying the unpersisted receipt signature |
| **Logging quality (now)** | the receipt is logged at the moment it could not be persisted, because a log line is the only form in which it survives the failure (the same reasoning CHAOS-126 applied to `FlushFinal`'s count) |
| **Alert quality** | unchanged by design: `storage_write_failed` is the right alert and already fires; the new series answer "what did that cost me?", which is a dashboard question, not a page |
| **Residual risk** | §9 |

### 2.2 Scenarios checked and found already resilient

These were simulated or traced in the same sweep and are **not** defects. Each
names the code path that provides the resilience, per the round's charter.

- **Durable write that succeeded but could not be fsynced.** Reported as
  `fileutil.ErrReplacedNotSynced` and treated as **committed** by
  `durableSupportWrite` (`support_durable_write.go:51-57`). This is the
  *opposite* case to CHAOS-128 and the distinction is load-bearing: the bytes
  are visible to every reader, so restoring prior state would make memory
  contradict the file. The new hold does not disturb it — the sentinel never
  reaches `finishUploadDrain` as an error. Pinned by
  `support_replaced_notsynced_test.go`.
- **Transient network failure, dropped connection, restart mid-transfer.**
  Bounded exponential backoff with an attempt cap
  (`maxUploadAttempts`/`uploadRetryBase`/`uploadRetryCap`,
  `support_upload_queue.go:46-48`), and `UploadID` is captured on **every** path
  including a transient failure so a resume point survives
  (`support_upload_queue.go:303-307`). The transfer does not restart from zero.
- **Unreachable cloud / vendor gateway down indefinitely.** The appliance
  degrades to "queued + offline export available", never a stall
  (`support_upload_queue.go:26-32`); `uploadEnabled()` is consulted each tick so
  disabling upload pauses egress immediately
  (`support_upload_worker.go:19-21`).
- **Panic inside the drain round.** Contained per round under
  `runGuarded(crashComponentSupportUpload, …)`
  (`support_upload_worker.go:55`), so a fault in one entry costs one tick rather
  than the gateway — the CHAOS-105 contract, which this worker is registered
  under (`chaos105_worker_guard_test.go`).
- **Queue growth without limit.** Both the non-terminal and terminal
  populations are capped (`maxUploadQueue`/`maxUploadTerminal`,
  `support_upload_queue.go:52-60`). The new hold inherits that bound: a key is
  only ever a `BundleID` that `dueUploadEntries` returned, and bundle ids are
  Culvert-generated, not caller-chosen (`supportBundleIDRe`,
  `ui_support.go:392`).
- **Unrecovered panic in a detached goroutine (the whole class).** An AST sweep
  of all 112 `go` statements in package main found the periodic rounds covered
  by one of the two guard primitives — `runGuarded` in main, `obs.SafeCall` in
  internal owners (e.g. `upstream.RunHealthCheckLoop`,
  `internal/upstream/upstream.go:1009-1026`) — or trivially bounded. `fireAlert`
  is itself guarded (`alerts.go:61-64`), which covers its ~25 detached call
  sites at once. **One observation worth a later round, not a defect today:**
  `chaos105Workers` (`chaos105_worker_guard_test.go:133`) asserts that every
  *registered* worker is guarded but nothing asserts the *inventory is
  complete*, and two genuinely-guarded workers added since are already absent
  from it (`dpCertRenewalLoop`, guarded under CHAOS-24,
  `dp_enrollment.go:353-366`; `retryCPAddrPublish`, guarded under CHAOS-119,
  `cp_addr_publish.go:586-596`). The contract holds; the gate that protects it
  does not yet enumerate.
- **Clock skew / rollback on the upload backoff.** Covered exhaustively by
  CHAOS-84, which enumerated the whole int64-stamp interval class
  (`chaos84_clock_rollback_test.go`).
- **Shutdown while an outcome is in flight.** The worker is parented to the app
  lifecycle context and exits cleanly with no dedicated hook
  (`support_upload_worker.go:40-44`). The hold is RAM-only and dies with the
  process — intentionally; see §9.

---

## 3. Risk matrix

| Id | Finding | Likelihood | Impact | Status | Severity |
|---|---|---|---|---|---|
| CHAOS-128a | An unrecorded outcome deletes the sealed blob and audits a delivery it cannot prove | Medium (any ENOSPC/EROFS/EIO on the support volume during a consented upload) | High per bundle (evidence bytes + proof of delivery destroyed; contradictory audit records) | **CLOSED** | **MED** |
| CHAOS-128b | A lost transient-attempt write unbounds the 6-attempt ladder into a 30 s re-send | Medium (same trigger) | Medium (repeated full-bundle egress to the vendor; `deferred` unreachable) | **CLOSED** | **MED** |
| CHAOS-128c | The naive repair (early return, no hold) trades 128a for unbounded egress | — | Medium | **PREVENTED** (gate `HeldOutcomeIsNotResentWhileTheVolumeIsUnwritable`) | — |
| CL-1 (§8.1) | `nodeMetrics` has no deleter: a decommissioned node is a permanent straggler and the audit-completeness total counts the dead | High (any decommission or autoscaled enroll/revoke churn) | Medium (a fleet-convergence alert that cannot be cleared without restarting the CP masks a real lagging DP) | **OPEN — recorded, not fixed** | MED |
| MCP-1 (§8.2) | `internal/mcp/approval`'s `byID` map is append-only; `List` is unordered and truncates at 200 with no signal | Medium | Medium (a live four-eyes request can fall outside the queue page; unbounded RSS) | **OPEN — recorded, not fixed** | MED |

---

## 4. Recovery assessment

**Automatic.** The volume recovering is the whole recovery. `drainDueUploads`
calls `retryHeldUploadCommits()` first on every tick; a landed write immediately
commits the outcome it authorizes — entry persisted, blob released, delivery
audited exactly once. No operator action, no re-consent, no re-transfer.

**Ordering decision, and why it is above the gate.** `retryHeldUploadCommits()`
runs **before** the `uploadEnabled()` check. Committing a held outcome is a local
write plus an audit record for a transfer that already happened; it dials
nothing. Disabling upload must pause **egress**, not strand the record of a
delivery the node already made. The gate
`HeldOutcomeCommitsEvenWhileUploadIsDisabled` pins that ordering, and the
mutation that moves the call below the gate fails exactly that gate and nothing
else.

**Manual.** None required in any scenario. If the process restarts while an
outcome is held, the bundle is re-sent on the next tick and a fresh receipt
recorded — automatic, just not free (see §9).

**Determinism.** Nothing that was ever durable is lost, and nothing is deleted
on the strength of a write that failed. The hold covers **every** state, not
only terminal ones, so the attempt counter and backoff deadline of a transient
failure survive as well — which is what keeps the ladder bounded. The mutation
that narrows the hold to terminal states fails `LostAttemptBookkeeping…` alone.

---

## 5. Security impact

The defect was not a confidentiality failure — the blob is sealed to the TAC
recipient's public key throughout, and nothing the fix adds crosses a trust
boundary. It was an **audit-integrity** failure, in the direction that matters:
`support.bundle.upload` is the durable record of an *egress of operator
evidence*, and the base behaviour wrote it on a path where the receipt proving
that egress did not exist. A compliance reader could not distinguish a delivery
from a destroyed one, and the same bundle could carry both a
`support.bundle.upload` and a `support.bundle.upload_deferred` record. After the
fix no delivery is audited unless its receipt is on disk, and the one case where
a receipt exists without a durable home is logged explicitly rather than
silently converted into an unprovable audit line.

Secondarily, 128b was a self-amplifying egress path: a local disk fault caused
repeated full-bundle transfers to an external vendor endpoint, with the attempt
cap that exists to bound exactly that unable to trip. Bounding it is a reduction
in uncommanded outbound volume.

No security posture, persistence format, wire format or RBAC surface changed.
`go run ./cmd/contractcheck impact -base origin/main` reports **no contract code
paths touched**.

---

## 6. Suggested improvements — and what was refused

**Shipped.** The persist is authoritative; the outcome is held in RAM until it
lands; the hold suppresses re-sends for that bundle; held outcomes commit before
the egress gate; two scrapeable series and two log lines (one of which carries
the otherwise-unrecoverable receipt signature); the operator guide documents the
state and the remedy (`docs/operator/secure-upload.md` §4, §8).

**Refused, deliberately:**

- **A durable journal for the held outcome.** It would need a write to the
  volume that is refusing writes. Holding in RAM is not a weaker version of
  journalling; it is the only option that does not depend on the failed
  resource.
- **A dedicated alert.** `fileutil.AtomicWrite` notifies the write-failure
  observer on every failing path, so `storage_write_failed` /
  `storageDegraded()` already fire on the root cause
  (`support_durable_write.go:44-50`). A second alert for the same cause competes
  with real threat alerts in the bounded retry queue — the WK-12/RS-5 lesson.
  The new series are the dashboard answer to "what did it cost", which is not a
  page.
- **An operator setting.** There is no defensible configuration in which an
  unrecorded outcome should authorize deleting the evidence.
- **Reclassifying the ENOENT on a missing sealed blob as terminal.** Tempting —
  it would stop the budget burn in scenario 2 — but it treats a symptom, and a
  genuinely transient open error (EINTR, a transiently unavailable mount) would
  then become terminal. With the blob no longer deleted, the ENOENT does not
  arise from this path at all.
- **CAS on the queue write-back.** The drain's write-back is last-writer-wins
  (`support_upload_queue.go:298-304`, `support_upload_worker.go:82`). Real, and
  already written up as **L4** in
  `docs/security-reviews/2026-07-24-secure-upload-delta-sync-openapi-window.md:376-412`
  with its recommended fix and required test. Out of scope here: it is a
  concurrency contract change to the same function, and folding it in would make
  one PR two.

---

## 7. Required tests (shipped)

`support_upload_commit_order_chaos128_test.go`, six gates plus a control:

| gate | pins |
|---|---|
| `FailedPersistKeepsTheBytesAndRecordsNoDelivery` | the integrity half: blob retained byte-for-byte, no `support.bundle.upload`, the condition visible |
| `HeldOutcomeIsNotResentWhileTheVolumeIsUnwritable` | the availability half: 5 ticks → **1** transfer |
| `HeldOutcomeCommitsWhenTheWriteLands` | recovery: entry + receipt land, blob released, delivery audited once, nothing held, **no second transfer** |
| `HeldOutcomeCommitsEvenWhileUploadIsDisabled` | the gate ordering, and that no dial happens while disabled |
| `LostAttemptBookkeepingDoesNotUnboundTheRetryLadder` | 8 ticks → **1** transfer; `Attempts` and the backoff deadline preserved in the hold |
| `HeldOutcomesAreScrapeable` | both series' names and types |
| `ControlHealthyDrainStillReleasesTheBytesAndAudits` (**CONTROL**) | the cheapest way to pass every gate above is to stop deleting blobs and stop auditing deliveries entirely; this fails against that, and against a hold that forgets to release |

**Mutation testing.** Five mutations, all caught, each by the gate that owns it:

| mutation | result |
|---|---|
| M1 — restore the pre-fix log-only persist | all six gates RED; control green |
| M2 — the naive repair (early return, no hold) | all six gates RED |
| M3 — hold but never release after a successful retry | `HeldOutcomeCommitsWhenTheWriteLands` RED (alone) |
| M5 — move the commit retry below the `uploadEnabled()` gate | `HeldOutcomeCommitsEvenWhileUploadIsDisabled` RED (alone) |
| M6 — hold only terminal states | `LostAttemptBookkeepingDoesNotUnboundTheRetryLadder` RED (alone) |

That M3, M5 and M6 each fail exactly one gate is the point: the three decisions
in the fix that are not forced by the headline defect — release on commit,
commit above the egress gate, hold every state — each have their own gate, and
none of them is carried by another.

Shared-global hygiene: `uploadCommitHeld` is a package global, and a leaked hold
would silently suppress another test's drain, so `resetUploadCommitHoldForTest`
clears it at test **start** and again on cleanup (the `setupProxyTest` lesson in
[conventions](../agent-context/conventions.md)). Audit assertions key on the
bundle id, not on ring length.

---

## 8. Recorded, not fixed — two findings for a later round

Both were verified first-hand at `f4f9379`, both have zero prior coverage
anywhere in `roadmap/` or `docs/`, and both belong to owners this PR does not
touch. They are written down here so they are not lost.

### 8.1 CL-1 — the control plane's per-node metrics map has no deleter

`nodeMetrics` (`controlplane.go:163-166`) has exactly **one writer**
(`controlplane_server.go:348`) and **no `delete` anywhere in the tree,
tests included**. A node that is revoked or never returns leaves its last
`MetricsReport` in the map for the whole CP process lifetime, because
`verifyNode` refuses a revoked node's `PushMetrics` with `PermissionDenied`
(`controlplane_server.go:50-53`) — so the entry freezes rather than ageing out,
and `RevokeNode` never touches it (`enrollment.go:609-635`).

What makes this a defect rather than a shrug is that the file disagrees with
itself. Two numbers are printed side by side to answer *"is our centralized
audit trail complete?"*: `auditClusterPushUnreportingNodes`
(`controlplane.go:217-233`) iterates the **enrolled roster**
(`globalClusterStore.ListNodes()`) and consults the map only as a lookup, so a
removed node correctly leaves it — while `auditClusterPushDropsTotal`
(`controlplane.go:184-199`) iterates **the map**, so it sums a decommissioned
node's last drop count forever. Two siblings in the same file do sweep
(`rateLimitAggregator.generation`'s `rlNodeStaleAfter` cutoff,
`controlplane.go:319-332`; `enrollRateLimit.attempts`,
`controlplane.go:855-864`). `computeFleetConvergence`
(`cluster_convergence.go:60-87`) also iterates the map, so `NodeCount` and
`Stragglers` include the corpse and its `VersionsBehind` grows with every
publish — and those feed `culvert_cluster_config_straggler_nodes`
(`cluster_metrics.go:167-170`). Net effect: after a decommission the one
fleet-convergence alert an operator has fires permanently, clearable only by
restarting the control plane, which makes a *real* lagging DP indistinguishable
from a retired node's remains. Secondary axis: enroll/revoke churn
(autoscaled DPs with per-instance ids) grows the map for the process lifetime.

**Suggested fix, with the hazard named.** Reconcile the map against the enrolled
roster — drop entries whose node is absent or `revoked` — mirroring the
rate-limit aggregator's prune. Two constraints a fix must respect: (a)
`checkHeartbeats` holds `cs.mu` for its whole body (`enrollment.go:793-814`), so
the sweep must take the roster via `ListNodes()` and release before touching
`nodeMetricsMu`, never nest the two (the CHAOS-118 lock-pairing lesson); and (b)
an **empty** roster must sweep nothing — an empty read is indistinguishable from
a cluster store that failed to load, which is exactly CHAOS-117's shape, and
blanking every node's metrics during an incident is worse than one stale row.
`disconnected`/`draining` entries must be kept: those are legitimate stragglers
an operator needs to see.

### 8.2 MCP-1 — the MCP approval store's request index is append-only

`internal/mcp/approval.Store` is documented as *"a bounded, in-memory …
projection"* (`internal/mcp/approval/store.go:75-78`), but its `byID` map
(`store.go:82`) has no `delete` in the package. The caps count **pending**
requests only (`store.go:126-132`, `301-309`), so a request that reaches a
terminal state — or lapses at its TTL — frees capacity while the `*Request` is
retained for the process lifetime; `perTenant` likewise never drops a zero key,
and `tenant` is a free-form string taken from the request body
(`ui_mcp.go:602`). With shipped defaults (`MaxPendingApprovals: 8192`,
`ApprovalTTL: 24h`, `internal/mcp/adminapi/limits.go:228-230`) a `RoleOperator`
can add 8192 permanent entries per day, and every `Create` then runs
`sweepLocked` plus `pendingCountLocked` — two full O(n) scans under `s.mu`,
which `List` also holds while walking the whole map.

The sharper half is not memory. `List` walks a Go map in **randomized order**
and truncates at `MaxPageSize` (200) with no ordering, cursor or truncation
signal (`store.go:160-178`; callers hardcode the limit at `ui_mcp.go:573, 698`),
so once a few hundred decided/expired requests accumulate, a **live pending
four-eyes request can simply fall outside the page an approver is looking at** —
a control failing quietly rather than loudly. The sibling decision surface got
both a scan bound and cursor pagination
(`internal/mcp/adminapi/decisions.go:271, 323`); approvals got neither.
`PublicationService.sweepPending` (`publication.go:152-171`) states this exact
threat model — *"so an operator cannot grow memory unbounded by letting request
TTLs elapse"* — and fixes it one layer up only.

Mitigating, and the reason it is not urgent: `appCommit` is always
`mcpDisabledCommitter` in this build (`ui_mcp.go:51-57, 104`), so no decision
can commit today. **Suggested fix:** evict decided/expired requests under a
counted retention bound, keep a pending index so `Create` stops full-scanning,
and make `List` deterministic (newest-first) with a cursor and an explicit
truncation signal.

---

## 9. Residual risk

- **A restart while an outcome is held re-sends that bundle.** This is the one
  loss the fix does not eliminate, and it is deliberate rather than a gap: the
  in-RAM receipt is genuinely gone, the durable entry still reads `queued` and
  the sealed blob is still on disk, so re-sending is the only way to end up
  holding proof of delivery again. The alternative — committing the delete and
  the audit from a record that did not survive — is the defect this round
  closed. Cost: one duplicate delivery of a bundle the operator had already
  consented to send, for the same case. Documented in
  `docs/operator/secure-upload.md` §4.
- **The hold is bounded by the queue, not by an independent cap.** Keys come
  only from `dueUploadEntries`, whose population is bounded by `maxUploadQueue`,
  and bundle ids are Culvert-generated (`supportBundleIDRe`). A future caller
  that fed `finishUploadDrain` entries from somewhere else would need to
  re-establish that argument; the comment at the declaration says so.
- **`culvert_support_upload_commit_held_total` counts attempts, not bundles.**
  One bundle held across many ticks increments it once per failed retry. That is
  the number an operator wants ("is the volume still refusing?"), but it is not
  a bundle count; the gauge is.
- **Last-writer-wins on the queue write-back is unchanged** (L4, §6). The hold
  does not widen it: a held entry is skipped by the drain, so the held outcome
  and a concurrent attempt for the same bundle cannot both be in flight from
  this path.
- **CL-1 and MCP-1 remain open** (§8), with evidence and a suggested fix each.
- **A passing local suite is not a passing merge gate.** Commands and results
  are in §10.

---

## 10. Verification

Run at the fix revision on this branch, with the compiler from `go.mod`
`toolchain` (`go1.27.4`) — not overridden, and no gate weakened:

| check | result |
|---|---|
| `go build ./...` | clean |
| `go vet .` | clean |
| `go test -run TestCHAOS128 -count=1 .` | ok (7 gates) |
| `go test -run 'Upload\|Support\|CHAOS128\|Durable\|Storage' -count=1 .` | ok |
| `go test -count=1 .` (full package main, 546 s) | **ok** |
| `golangci-lint run --timeout=10m --new-from-rev origin/main` (v2.15.0, the version pr-fast-gate installs, built with the `go.mod` toolchain) | **0 issues** |
| `golangci-lint run` (full tree) | 174 pre-existing issues across the module, **none in any file this change touches** — see the note below |
| `python3 docs/agent-context/check.py` | exit 0 |
| `go run ./cmd/contractcheck impact -base origin/main` | no contract code paths touched |

On the full-tree pass: the repository's baseline is not zero (174 issues:
`gocritic` 40, `cyclop` 25, `gocognit` 24, `noctx` 17, `gosec` 15, `staticcheck`
14, `errcheck` 8, `nestif` 8, `funlen` 7, `unparam` 7, `dupl` 4, `bodyclose` 3,
`unconvert` 2), so a bare exit code says nothing. The comparison that matters is
that **no issue is reported in `support_upload_worker.go`, `ui_support.go` or
`support_upload_commit_order_chaos128_test.go`** — which settles the axis
`--new-from-rev` is blind to, since `cyclop`, `funlen` and `gocognit` attribute
to a function's DECLARATION line and would therefore surface on the modified
functions rather than on the changed lines. (Test files are linted: the
`--new-from-rev` pass flagged two `gocritic` issues on this round's own files,
`stringXbytes` in the gate and `rangeValCopy` in `retryHeldUploadCommits`, and
both were fixed — the second by keying the range instead of copying the entry,
per [conventions](../agent-context/conventions.md).)

**Not run, and why:** the hosted Fast PR Gate, CodeQL and the aggregate CI
matrix run on the pushed SHA and are not reproducible here; the Docker and
real-Docker qualification jobs are unrelated to this change (no image,
packaging or maintenance path touched). An independent review of the fix has
**not** happened yet — and CHAOS-126's own record is the argument for insisting
on one: that round's fix shipped a privacy defect in the very property it
introduced, with a green module suite and two clean lint passes behind it.
