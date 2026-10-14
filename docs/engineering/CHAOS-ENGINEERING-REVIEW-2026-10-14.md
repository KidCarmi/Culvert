# Chaos Engineering Review — 2026-10-14

## CHAOS-71 — The Data Plane's control-plane sync plane had no panic containment
## CHAOS-72 — A Data Plane boot silently drops two CP-authoritative config slices

**Scope.** `controlplane_client.go` (`DataPlaneClient.Run` and the five workers it
launches), `controlplane_snapshot.go` (`applySnapshotExtendedState`), and the
startup ordering in `main.go` / `cluster_startup.go` / `dp_enrollment.go` that
decides when those workers first run.

**Origin.** Not a register row. The CHAOS-62 review closed with a process
lesson — *"a rule adopted in one place is a checklist item for every other place
that does the same thing, and nothing in the tree was checking"* — so this sweep
took the repository's own most load-bearing worker rule (CHAOS-24: every
long-lived background worker runs its round under `runGuarded`) and audited it
for sites the original sweep never enumerated. The DP control-plane sync plane
is one. Reading its startup path for a second time produced CHAOS-72.

---

## 1. Executive Summary

**Five long-lived workers inside the proxy's own process ran unguarded rounds
over payloads the node does not author.** `DataPlaneClient.Run`
(`controlplane_client.go:209`) launches the config poll, the heartbeat, the
rate-limit gossip, the revocation sync and the audit push. Go terminates the
process on an unrecovered panic in **any** goroutine, so a fault in any one of
those rounds was a **total gateway outage** — every in-flight tunnel dropped —
and a deterministic fault was an unattended crash loop under the shipped
`docker-compose.yml`'s `restart: unless-stopped`, because the node replays the
same last-known-good snapshot on every boot.

**This was an omission, not a reasoned exception.** CHAOS-24 enumerated fifteen
workers and guarded them per round; §12.6 recorded three deliberate deferrals
(the HA sync loops, the MCP runtime listener, `internal/yara`'s match goroutine),
each closed or tracked since. The DP sync plane appears in neither list. The
clearest evidence that it was simply out of scope: `startDataPlane`
(`dp_enrollment.go:306-307`) calls `dpClient.Run` and, on the **very next line**,
starts `dpCertRenewalLoop` — which *is* guarded, with a CHAOS-24 citation in its
own comment. The five loops next to it were the odd ones out, in the same shape
as the one relay goroutine CHAOS-57 found still unguarded.

**The exposure is not theoretical, and it is not a clean fail-closed.** Every
round here parses and then **applies** CP-supplied state. `fetchAndApply` drives
a snapshot that can reach ~60 MiB into the blocklist, IP filter, rate limiter,
policy/SSL-bypass/rewrite compilers, URL categories, the IdP registry and a
signed MCP envelope; the gossip round merges a remote-count broadcast; the
revocation round merges a revocation set; the heartbeat parses a reply. CP/DP
version skew during a rolling upgrade reaches all of it, and so does a
fenced-out zombie leader — the actor the epoch ratchet exists precisely to
distrust. Nor is process death the safe outcome an appliance wants here: the
crash loop takes down the **admin UI and the health endpoint** alongside the
proxy, so the operator loses the surface they would use to diagnose it.

**Two of the five rounds could not simply be wrapped, and that is the finding
inside the finding.** Naive containment makes them *worse* than the crash:

- **The audit round would destroy evidence on a schedule.** `audit.Drain()`
  *removes* the batch from the pending queue, so between the drain and a
  successful push the only copy is a local slice. A panic used to lose that
  batch once, loudly, with the process gone. Contained and ignored, it loses a
  batch **every ten seconds, forever**, with the process alive and every
  dashboard green — silent, recurring destruction of the audit trail the
  appliance exists to produce. The fix returns the batch on the panic path, so a
  panicked push is treated exactly as a failed push.
- **The config round would report a half-applied snapshot as healthy.**
  `configsnapshot_apply_health.go` documents an outcome model —
  received → parsed → validated → fenced → synchronized → applied — and marks
  the apply rejected at every payload-content failure point in it. A panic is
  the one way the *applied* step can fail without reaching any of them: the
  round dies before `markConfigSnapshotApplyOK`, leaving the surface reporting
  the **previous** success while the node enforces a partially applied snapshot
  (blocklist and IP filter swapped, policy rules or URL categories not). That
  state was unreachable before this change because the process died, so
  containment *creates* it; the surface therefore had to learn about it in the
  same commit.

**CHAOS-72, found while reading the same startup path: a Data Plane boot
silently discards two CP-authoritative config slices, and records the apply as a
complete success.** `applySnapshotExtendedState` guards the bandwidth and
node-group applies on a non-nil field **and** a non-nil store. The two guards
answer different questions. A nil *field* is the presence contract (an older or
rolled-back CP omitting a slice must not clear local state). A nil *store* is a
startup-**order** fact:

| Step | Site | What it does |
|---|---|---|
| `main.go:228` | `initCluster(s)` | → `startDataPlane` → `applyDPLastGoodConfigSnapshot()` replays the last-known-good snapshot **synchronously** |
| `main.go:255` | `initPersistentAdminState(s)` | → constructs `globalNodeGroups` and `globalBandwidth` |

So on **every** DP boot the replay reaches the apply with both stores still
`nil`, drops both slices, and the surrounding apply then persists last-good,
advances `lastVersion` and marks the apply OK. The version ratchet
(`snap.Version <= c.lastVersion.Load()`) suppresses the next poll, so nothing
re-applies them until the CP increments the config version. The ordering
comment in `persistent_admin_state_startup.go` states the contract this
violates: *"node-group + bandwidth stores — constructed before anything can
consume them."*

Enforcement usually still converges, because both stores reload the same content
from their own node-local JSON moments later (`ReplaceAll` persists on every
apply). That convergence is a property of the local files, not of the apply — a
restored, re-imaged or partially-populated volume breaks it, and the node then
enforces stale or absent bandwidth/QoS and node-group state with every surface
reporting a current config.

---

## 2. Failure Scenarios

| # | Injected condition | Pre-change behavior | Post-change behavior |
|---|---|---|---|
| 1 | Fault in a config-snapshot apply (CP/DP skew, a compiler fault under the ~60 MiB fan-out) | **Process death.** Proxy, admin UI and health endpoint gone. `restart: unless-stopped` + last-good replay ⇒ crash loop | Round contained, counted as `dp_config_poll`, apply-health **failed closed**; next poll re-fetches the same version (lastVersion never advanced) |
| 2 | Fault in a heartbeat reply parse / epoch ratchet | Process death | Round contained as `dp_metrics_push`; a missing heartbeat is already loud via the CP's own timeout path |
| 3 | Fault merging a rate-limit broadcast | Process death | Round contained as `dp_ratelimit_gossip`; the per-tick CHAOS-61 freshness evaluation stays armed, so cluster limiting degrades to local and *says so* |
| 4 | Fault merging a revocation set | Process death | Round contained as `dp_revocation_sync`; the next tick re-sends the full local set (`ExportRevocations` is a full export, not a delta) |
| 5 | Fault pushing an audit batch | Process death, batch lost once | Round contained as `dp_audit_push`, **batch returned to the queue** and retried next tick |
| 6 | DP restart with a last-known-good snapshot carrying bandwidth policies / node groups (CHAOS-72) | Both slices silently dropped; apply recorded as complete; version ratchet suppresses re-apply | Drop is **reported** with the slice and config version; enforcement unchanged pending the ordering fix |

**Why "guard the round, never the goroutine" is unchanged here.** A `recover` at
the top of any of these five goroutines would convert a loud crash into a
**silent permanent stall** with the process up: config never syncs again,
revocations never propagate (a security fail-**open** — a logout on one node
would stop invalidating sessions fleet-wide), and the gossip goroutine would
leave the limiter cluster-enabled with nothing ever refreshing the broadcast,
which is exactly the frozen-broadcast blackhole CHAOS-61 closed — manufactured
by the recovery instead of by an outage. That is the §12.2 objection applying
unchanged, and it is why the gossip gate asserts the loop still disarms cluster
limiting on cancellation *after* contained panics.

---

## 3. Risk Matrix

| ID | Finding | Severity | Reachable in the stock container? | State |
|---|---|---|---|---|
| CHAOS-71 | Five DP↔CP sync workers run unguarded rounds; a panic in any kills the gateway | **High** | Yes — any node run with `-dp-addr` / an enrollment config | **Fixed** here |
| CHAOS-71a | Contained audit round would destroy a drained batch per interval | **High** (data integrity) | Yes, once containment exists | **Fixed** in the same commit |
| CHAOS-71b | Contained config round would report a half-applied snapshot as healthy | **Medium** | Yes, once containment exists | **Fixed** in the same commit |
| CHAOS-72 | DP boot drops CP-authoritative bandwidth + node-group slices and records a complete apply | **Low** | Yes, every DP boot; impact masked by node-local persistence | **Reported**, not repaired — see §7 |

Severity for CHAOS-71 is availability-led: a single auxiliary worker could take
the whole in-line gateway down, which is the blast-radius property the CHAOS-24
sweep rated Critical for the fifteen workers it did cover.

---

## 4. Recovery Assessment

- **Automatic, and deterministic.** A contained config round costs one poll
  interval (30 s). `lastVersion` advances only after a *complete* apply, so the
  next poll re-fetches and re-applies the same version rather than
  short-circuiting on it — the recovery path is the one the code already had for
  a rejected snapshot, not a new one.
- **Containment is still not repair** (the CHAOS-24 §12.6 residual risk,
  unchanged). A round that panics on every tick makes no progress: config goes
  stale, revocations stop propagating. The signal is
  `culvert_crash_records_total{component}` being non-zero — 0 in a healthy
  process — now with five distinct component labels so an operator can tell
  *which* worker is faulting. A config fault additionally fails the apply-health
  surface closed, which `/api/diagnostics` (`diagnostics.go:282`) and the
  support telemetry registry already read.
- **Manual recovery** is unchanged and still available: restart the node, or fix
  the CP-side payload. What changed is that the operator now has a running
  appliance and a working admin UI from which to do it.
- **No new persistence, wire or schema surface.** No config, API or GUI change,
  so no GUI-parity obligation is created.

---

## 5. Operational / Security / Data-integrity Impact

- **Operational.** A fault in an auxiliary sync worker no longer takes the proxy,
  admin UI and health endpoint with it. The five crash components make the
  faulting worker nameable in metrics and in the SIEM crash record.
- **Security.** The revocation round's containment keeps cluster-wide session
  invalidation propagating; the gossip round's containment keeps the CHAOS-61
  freshness surface armed so cluster rate limiting degrades to local
  *observably* rather than silently freezing. Neither fix widens any trust
  boundary: the epoch fence, the per-slice caps and the IdP compile-before-swap
  all run exactly where they did.
- **Data integrity.** The audit requeue is the material change: a panicked push
  no longer consumes the drained batch. `audit.Requeue` is bounded
  (`trimPendingLocked`), so a persistent fault degrades to the queue's existing
  newest-kept drop policy and its `PendingDrops` counter rather than to
  unbounded growth.
- **Monitoring / logging / alerting.** Reuses the existing crash plane
  (`recordCrash` → bounded, redacted record + unthrottled counter) and the
  existing apply-health surface. No new alert rule ships here; an alert on
  `culvert_crash_records_total` remains the operator-facing follow-up CHAOS-24
  recorded.

---

## 6. Suggested PR

Branch `claude/serene-cerf-4brbca`, three files:

- `controlplane_client.go` — five round bodies extracted to named methods
  (`metricsRound`, `rateLimitGossipRound`, `revocationSyncRound`,
  `auditPushRound`) and run under `runGuarded` with one component constant each;
  `guardedConfigRound` additionally marks the apply rejected on a panicked
  round; `auditPushRound` returns its drained batch via a deferred requeue that
  also subsumes the pre-existing error-path requeue.
- `controlplane_snapshot.go` — `reportDroppedStartupOrderSlices`, called at the
  end of `applySnapshotExtendedState`, reports a CP-authoritative slice dropped
  because its store does not exist yet.
- `chaos71_dp_sync_worker_panic_test.go` — 13 gates (§8).

No behavior changes on any healthy path: a clean round is byte-identical to
before, and the `continue`→`return` rewrites inside the extracted rounds
preserve each loop's existing skip semantics.

---

## 7. Residual Risk / deliberately left

- **CHAOS-72 is reported, not repaired.** The real fix is to construct the
  node-group and bandwidth stores before `initCluster` can replay a snapshot
  into them — a startup-**ordering** change, which this repository treats as a
  contract needing its own analysis (`loadPersistentAdminState` documents
  "ORDER IS THE CONTRACT" verbatim) and which reaches across an init slice
  boundary. Bundling it behind a panic-containment diff is precisely the
  hiding-a-change-in-a-large-diff mistake CHAOS-24 §12.6 avoided. Tracked as the
  next sweep's first candidate; the exposure meanwhile is masked by the two
  stores' node-local persistence and is now logged when it happens.
- **Thirteen other unguarded ticker loops remain** in package main
  (`controlplane_client.go` was the densest cluster, but `decryption_trend.go`,
  `events.go`, `mcp_telemetry.go`, `support_debug_level.go`,
  `support_upload_worker.go`, `ui_support.go`, `release_dispatch_exec.go` and
  `enrollment.go`'s heartbeat-timeout loop all run bare rounds). None of them
  applies CP-supplied state, so none carries this finding's trigger surface, but
  each is the same process-death shape and each needs its own fail-closed
  reading — `enrollment.go`'s loop in particular, since it runs on the **control
  plane** and a panic there stops every DP in the fleet from syncing. Recorded
  as the CHAOS-73 candidate rather than swept blind here.
- **`crashThrottleEvery` (1 s per component)** still means a tight panic loop
  reports a fraction of its rounds to the SIEM; the unthrottled counter remains
  the lossless signal (M1 anti-forensics-DoS trade-off, inherited unchanged).
- **A panicked config round can leave partially applied state.** Containment
  does not roll back the slices that applied before the fault. This is now
  *converging* (the next poll re-applies the same version), but it is not
  atomic, and making the snapshot apply transactional is a far larger change
  than this sweep.

  **It is also less visible than "apply-health closed" implies, and that
  correction is owed here.** The CodeRabbit architecture review of this change
  made the sharper observation: the apply-health bit has exactly two consumers,
  `/api/diagnostics` (`diagnostics.go:282`) and the support telemetry registry
  (`support_telemetry_registry.go:161`) — and **no `readyz*.go` file reads it**.
  So the state this sweep newly makes reachable reports **ready** to a load
  balancer and keeps taking traffic, where before the process died and the node
  left the pool. The failure is visible on a role-gated surface, not on the one
  that governs traffic.

  The obvious repair is wrong twice over. `readyz_dp_health.go` already records
  why its `cp_poll` and `node_cert` rows are report-only: *"gating the default
  verdict on CP-poll failure would let a CP outage eject the entire DP fleet
  from the load balancer at once"* — and a bad CP snapshot is fleet-wide by
  construction. Worse, the bit is latched by every PRE-mutation rejection
  (malformed JSON, over-cap, IdP sync), where the node serves its
  last-known-good config perfectly coherently; gating on it as it stands would
  eject healthy nodes. The in-pattern fix needs (1) a signal distinct from those
  pre-mutation rejections, raised only when a round died AFTER live mutation
  began, (2) a report-only `/ready` row on it gating under `?strict=1`, (3) a
  fixed operator-directed detail string honouring that file's disclosure
  contract (`/ready` is unauthenticated on the proxy port, so a row may name a
  degraded subsystem but never the enforcement consequence), and (4) a fault
  injected AFTER a live mutation — a fair criticism of the gates here, which
  inject at `callForTest`, i.e. pre-mutation. That is a new unauthenticated
  operator contract changing when a node leaves the load-balancer pool, so it
  belongs in its own change with its own fail-closed analysis, not bundled into
  a containment diff. Tracked alongside the CHAOS-72 ordering fix.

---

## 8. Required Tests

**Every defect gate was verified FAILING against the reintroduced pre-fix
shape**, not merely written after the fix. The loop gates fail by *killing the
test binary*, which is the defect itself:

| Gate | Pre-fix result |
|---|---|
| `TestChaos71_ConfigRoundPanicIsContainedAndMarksApplyRejected` | FAIL — binary died inside `fetchAndApply` |
| `TestChaos71_PollLoopSurvivesEveryPanickingRound` | FAIL — binary died on round 1 |
| `TestChaos71_MetricsLoopSurvivesEveryPanickingRound` | FAIL — binary died on round 1 |
| `TestChaos71_RevocationLoopSurvivesEveryPanickingRound` | FAIL — binary died on round 1 |
| `TestChaos71_AuditPushLoopSurvivesEveryPanickingRound` | FAIL — binary died on round 1 |
| `TestChaos71_GossipLoopSurvivesPanicsAndStillDisarmsOnCancel` | FAIL — binary died on round 1 |
| `TestChaos71_AuditRoundPanicReturnsTheDrainedBatchToTheQueue` | FAIL — `pending audit events after a panicking push = 0, want 3` (mutated by removing only the deferred requeue, with the loop guards intact) |
| `TestChaos72_DroppedBandwidthSliceIsReported` | FAIL — `a dropped bandwidth slice must be reported, got:` then nothing (empty capture) |

**CONTROLS** — a passing gate must not be able to mean the mechanism simply
stopped firing, or that it fires unconditionally:

- `TestChaos71_CleanConfigRoundRecordsNothingAndLeavesApplyHealthOK` — a clean
  round records no crash and leaves apply-health healthy, so the fail-closed
  marking is caused by the panic and not by the guard existing.
- `TestChaos71_DeliveredAuditBatchIsNotRequeued` — a delivered batch stays
  delivered; without this, the requeue gate would pass against a round that
  never clears the queue and duplicates every event forever.
- `TestChaos71_FailedAuditPushStillRequeues` — pins the pre-existing error-path
  retry that the deferred requeue replaced.
- `TestChaos72_OmittedSlicesAreNotReportedAsDropped` — an omitted slice is the
  presence contract, so it must stay quiet; otherwise the report would fire on
  every poll from a CP that ships neither slice.
- `TestChaos71_SyncPlaneComponentsAreDistinct` — five distinct non-empty crash
  components, so a config fault can never be mistaken for an audit fault in
  `culvert_crash_records_total{component}`.

**Counts.** 13 new gates (11 CHAOS-71, 2 CHAOS-72) in one new root file.

**Commands and results** (Go 1.26.9 from `go.mod`'s `toolchain`):

| Check | Result |
|---|---|
| `go build ./...` | pass |
| `go vet .` | pass |
| `gofmt -l` on the three changed files | clean |
| `go test -run 'TestChaos71\|TestChaos72' -count=1 .` | pass (13/13) |
| `go test -run 'TestChaos71\|TestChaos72\|Chaos24' -count=1 -race .` | pass, race-clean |
| `go test -run 'Chaos24\|FetchAndApply\|Revocation\|Gossip\|RateLimit\|AuditPush\|Admission\|DeltaApply\|LastGood\|Heartbeat\|Epoch' -count=1 .` | pass |
| `go test -count=1 .` (full root package, 410 s) | **9 pre-existing failures, no new ones** |

**Not run, and why.** `golangci-lint` could not execute in this environment: the
installed binary is built with Go 1.25 and panics with *"package requires newer
Go version go1.26"* on this module. The changed functions were kept inside the
configured budgets by hand instead — longest new function 35 lines against
`funlen: 80`, and the CHAOS-72 reporting was extracted to its own helper
specifically so `applySnapshotExtendedState` stays at 47 lines rather than
crossing 80. The hosted Fast PR Gate remains the authority.

**The 9 pre-existing failures are environmental, not a regression.** All are IdP
tests (`TestIdPRegistry_UpsertPersistsAtomically` and siblings) failing with
*"URL must be https:// and must not point to a private address"* — this
sandbox's DNS resolves the tests' IdP hostnames to a private address, so the
`isPrivateHost` SSRF guard correctly refuses them. Verified identical on a
clean `git stash` of this branch, i.e. present on `main` in this environment.

---

## 9. The process lesson

**The CHAOS-62 lesson held on its first application, and the sweep it produced
was found by reading a list rather than by reasoning about a subsystem.** The
previous review closed with *"a rule adopted in one place is a checklist item
for every other place that does the same thing, and nothing in the tree was
checking."* Mechanically checking that one rule — count `runGuarded` call sites
(18), count long-lived ticker loops (37) — located CHAOS-71 in minutes, without
any hypothesis about what the DP sync plane does.

The second half is sharper, and it is the half a mechanical sweep would have got
wrong. **Two of the five rounds would have been made worse by the obvious fix**,
and in both cases the evidence was in the code's own comments rather than in the
panic. `audit.Drain` says it *removes* the batch; `configsnapshot_apply_health.go`
enumerates every failure point in its outcome model, and a panic is not among
them. Wrapping all five in `runGuarded` and stopping would have passed every
containment test, shipped a gateway that destroys an audit batch every ten
seconds, and reported a half-applied config as healthy. §12.2 said this once
about the fencing lease; it is a property of containment, not of that lease.

CHAOS-72 arrived the same way. **Reading the startup path to answer "when does
this worker first run?" is a different question from "what does this worker
do?", and it is the one that finds ordering bugs.** The `globalBandwidth != nil`
guard looks like defensive hygiene and reads like the presence contract beside
it. It is neither: it is a load-bearing guard against a store that provably does
not exist yet, 27 lines of `main()` away — and the init slice whose order it
violates documents that order as its contract, in capital letters.
