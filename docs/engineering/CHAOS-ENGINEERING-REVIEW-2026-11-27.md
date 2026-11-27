# Chaos engineering review — 2026-11-27

Reviewer: Culvert Chaos Engineer (automated round). Base revision `2fad1fb`
(`origin/main`), clean worktree at branch point.
[CHAOS-ENGINEERING-REVIEW.md](../../roadmap/CHAOS-ENGINEERING-REVIEW.md) stays
the index; this is the dated record for the round it registers.

Id claimed: **CHAOS-130**, in a committed placeholder row as commit one
(`928b047`), before any production code, and checked against `origin/main`
rather than the working tree per the register's 2026-09-25 amendment.
`CHAOS-126` was the highest id anywhere on `origin/main` at `2fad1fb`;
`CHAOS-127`, `CHAOS-128` and `CHAOS-129` are held by open PRs #2075, #2119 and
#2125 — exactly the case the amendment exists for — so this round did NOT take
the next id after main's highest. Of the other 58 open PRs none is a chaos
sweep. Recent rounds do not claim a `§` section number (`CHAOS-123` through
`CHAOS-126` all omit it); this one follows them.

Scope: **the OTLP export plane's LIFECYCLE OWNERSHIP.** `CHAOS-126` settled
what the exporters do with a batch. This round asks the question one level up —
*who owns the push loop* — and takes its entry point from two residual risks
that round recorded as pre-existing and unchanged: `R9` (`Configure`'s
two-phase locking) and `R7` (the CP snapshot deciding for both exporters from
the metrics exporter's state).

---

## 1. Executive summary

Both residual risks are real, both reproduce, and they are the same defect seen
from two distances: **a lifecycle transition that is not atomic with the state
it publishes.** Inside an exporter that costs an unreclaimable goroutine.
Across the pair it costs a telemetry plane that is permanently half on — and in
one direction it fails OPEN.

**CHAOS-130a (MED) — `Configure` publishes the endpoint and the loop's
`cancel` under two separate holds of the mutex, so a concurrent caller
overwrites the only handle to a running push loop.**

```go
e.mu.Lock()
if e.cancel != nil { e.cancel() }
e.endpoint = endpoint
e.mu.Unlock()                                   // ← the window
if endpoint == "" { return }
ctx, cancel := context.WithCancel(context.Background())
e.mu.Lock()
e.cancel = cancel                               // ← overwrites a live loop's handle
e.mu.Unlock()
go e.pushLoop(ctx)
```

Identical in both exporters (`internal/otlp/spans.go:174-205`,
`internal/otlp/otlp.go:110-127` at base). Two callers interleave, each stores
its own `cancel`, and the loser's loop is left with **no handle at all**:
`Stop()` cancels what `e.cancel` holds, and that is not it. The loop is
unreachable for the rest of the process's life.

Measured on this tree, through the production constructors (probes in §9):

| probe | observed |
|---|---|
| 8 concurrent `Configure` (spans) | **3** live `pushLoop` goroutines, want 1 |
| …then `Stop()` — the operator's disable | **2** still running |
| 8 concurrent `Configure` (metrics) | **2** live, want 1; **10** POSTs over 5 intervals against the 5 configured |
| 40 raced saves at the production 15 s cadence | **9** live loops; **8** survive `Stop()` |
| 40 raced saves, then a clean disable **and** re-enable | **19** and **50** POSTs over 10 intervals against the 10 configured |
| `Configure("")` | returns with an already-cancelled `cancel` still stored |

Three things follow, in rising order of how much they cost:

1. **The leak is permanent and it grows with operator activity.** Nothing
   reclaims it — not `Stop()`, not a reconfigure, not a disable. Only the
   process exit.
2. **It bills the collector.** `MetricsExporter.push` always POSTs a full
   cumulative snapshot, so every stranded loop adds a whole push cadence:
   measured at **1.9× and 5×** the configured request rate, *after* a clean
   disable and re-enable. An operator who sees duplicate data points and
   doubled ingest has no control that fixes it and no counter that names it.
3. **It reintroduces a defect the previous round's reviewer removed by
   design.** The span exporter's own `pushSlot` comment records that two
   concurrent pushers inverted the ring and made overflow evict the *newest*
   spans. The leak manufactures exactly that second pusher.

**CHAOS-130b (MED) — the pair is never applied atomically, so the export plane
settles half on, and the control plane then cements it.** All four callers
configure or stop metrics and traces in sequence —
`observability_startup.go:64`, `admin_settings.go:545`, `ui_config.go:2690`,
`controlplane_snapshot.go:1845` — and nothing serialises the pair. Two
concurrent admin saves, or a save racing a CP snapshot apply, leave one half
running. That alone would be transient. It is not, because the CP snapshot
apply decided **both** halves from the **metrics** exporter's state:

```go
if snap.OTLPEndpoint != "" {
    if !globalOTLP.Enabled() || globalOTLP.Endpoint() != snap.OTLPEndpoint {
        globalOTLP.Configure(snap.OTLPEndpoint, nil)
        globalOTLPTraces.Configure(snap.OTLPEndpoint, nil)
    }
} else if globalOTLP.Enabled() {
    globalOTLP.Stop()
    globalOTLPTraces.Stop()
}
```

Measured: metrics at the right endpoint with traces stopped survives **five
consecutive applies carrying that endpoint** — the guard matches on metrics and
skips both. Spans are not exported again until an operator happens to save a
*different* endpoint.

**CHAOS-130c (MED→HIGH for posture, MED for likelihood) — the same guard fails
OPEN in the other direction.** With metrics already off and traces running, a
snapshot that **disables** export reaches `else if globalOTLP.Enabled()`, finds
false, and stops **neither**. Measured: traces still exporting after the
disabling apply. A fleet-wide instruction to stop shipping telemetry left the
gateway shipping `SpanRecord`s — **client IP, target host, policy rule and
enforcement decision, per request** — to the collector, and the control plane
had no way to know it had not been obeyed. For a secure web gateway the
difference between "we stopped exporting" and "we believe we stopped
exporting" is the whole value of the control.

**CHAOS-130d (MED) — and none of it was visible.** `checkOTLPExport`
(`diagnostics_otlp_export.go:29-34` at base) reports an export that is
**failing**; it has nothing to say about one that is **off**. Measured: a plane
with traces dark produced **zero** diagnostic rows. `GET /api/otlp` reports a
single `enabled` read from the metrics exporter, and the legacy panel renders
that flag as *"✓ Exporting metrics + traces to …"* (`static/index.html:11536`).
Every surface an operator has agreed that everything was fine.

**CHAOS-130e (LOW, found while rewriting the reconcile) — the reconcile
compared two different alphabets.** `Configure` normalises its argument
(`TrimSpace` then strip trailing `/`), so `Endpoint()` returns the *normalised*
value — and the apply compared it against the **raw** `snap.OTLPEndpoint`. A
control plane whose stored endpoint carries a trailing slash or stray
whitespace therefore compared unequal on **every** apply. `CHAOS-126` flagged
exactly this class in `MetricsExporter.Configure`'s own comment and fixed the
normalisation; the comparison was left reading the un-normalised side.
Measured on the pre-fix tree: five consecutive snapshots that change nothing
produced **10 reconfigure log lines** — both push loops cancelled and
restarted, and the cancelled loop's bounded final flush run, on each apply.
Rated LOW because today's snapshot producers emit an already-normalised value
(`snap.OTLPEndpoint = globalOTLP.Endpoint()`, `controlplane_snapshot.go:2209`,
and `AdminSettings.OTLPEndpoint` likewise), so it is latent rather than live —
but it is latent only by the grace of a producer, which is not a guarantee.

**The asymmetry the design missed**, in one sentence: `Stop()` sets
`cancel = nil` because it knows a disabled exporter owns no loop, and
`Configure` published the endpoint before the `cancel` — so the one function
that creates ownership was the one that briefly had none.

---

## 2. Failure scenarios

| # | Scenario | Before | After |
|---|---|---|---|
| F1 | Two admin saves of the OTLP endpoint land together | a push loop is stranded; `Stop()` can never reclaim it | one transition wins; exactly one loop |
| F2 | An admin save races a CP snapshot apply | as F1, on every data-plane node that polls | serialised; one loop |
| F3 | 40 raced saves over a node's life | 9 live loops, 8 surviving a disable | 1 |
| F4 | Operator disables OTLP after a raced save | loop survives; re-enabling gives 1.9–5× the collector load | disable reclaims everything |
| F5 | A disable interleaves a configure | `Enabled()` false with a live loop behind it | the two reports always agree |
| F6 | `Configure("")` | stale already-cancelled handle retained | no handle; a disabled exporter owns nothing |
| F7 | Traces stopped alone, CP endpoint unchanged | **dark forever**, silent | restored on the next apply |
| F8 | Metrics stopped alone, CP endpoint unchanged | metrics dark forever, silent | restored on the next apply |
| F9 | CP disables export, metrics already off | **traces keep exporting request spans** | both stopped |
| F10 | CP disables export, traces already off | metrics stopped (correct) | unchanged |
| F11 | CP repoints the collector | both moved (correct) | unchanged |
| F12 | Five applies carrying the endpoint already in use | no-op (correct) | unchanged — buffered spans are not discarded by a reconcile that changes nothing |
| F13 | A plane half enabled for any reason | no row, no counter, no log line | `otlp_export_partial` WARN naming the dark half |
| F14 | Reconfigure storm while recording and pushing | — | no leak, export continues (race detector clean) |
| F15 | Snapshot endpoint differing only by a trailing slash or whitespace | both push loops restarted on **every** apply | a no-op |

---

## 3. Risk matrix

| Id | Finding | Sev | Likelihood | Blast radius | Detectability (before) |
|---|---|---|---|---|---|
| 130a | Unreclaimable push loop on a raced `Configure` | **MED** | MED — two saves, or a save racing a snapshot poll | per node: a goroutine, a ticker and a full extra push cadence, permanently | **none** — no counter, no log, no gauge |
| 130b | Traces (or metrics) dark forever after a half transition | **MED** | LOW–MED — needs 130a's window or any sequence interruption | all trace data for that node | **none** |
| 130c | CP disable leaves the other half exporting | **MED→HIGH** posture | LOW — needs metrics already off | per-request client IP, host, rule and decision keep leaving the appliance | **none**; CP believes it complied |
| 130d | A half-enabled plane is unreportable | **MED** | certain, given 130b/c | the operator's whole picture | n/a — this *is* the detectability finding |
| 130e | Reconcile compares a raw endpoint against a normalised one | **LOW** | latent — needs a producer that does not normalise | both push loops restarted per apply, per node | a repeating log line nobody reads |

Severity is capped at MED for 130a/b because the data at risk is telemetry, not
traffic: proxy enforcement, policy and the audit trail are untouched on every
path here. 130c is rated higher on posture alone — it is an export-suppression
control that did not suppress.

---

## 4. Recovery assessment

| | Before | After |
|---|---|---|
| **Automatic** | none for 130a (only process exit); none for 130b/c — the CP guard was the thing that prevented recovery | 130b/c self-heal on the next snapshot apply, per exporter |
| **Manual** | restart the node for 130a; for 130b, save a *different* endpoint, because saving the same one is a no-op | re-saving the endpoint now fixes any divergence, and so does the next apply |
| **Detection** | impossible from any surface | `otlp_export_partial` on the diagnostics report |

The reconcile is deliberately *reconciliation, not reapplication*: an exporter
already at the snapshot's endpoint is left alone. Reconfiguring unconditionally
would cancel a healthy loop every apply and, for traces, discard the buffered
spans each time — trading this round's silent loss for a metronomic one. F12 is
that gate.

---

## 5. Operational impact

- **Collector load.** Measured 1.9× and 5× the configured push rate after
  raced saves, unaffected by disabling and re-enabling. On a fleet this is
  multiplied by node count and is indistinguishable, at the collector, from a
  capacity problem.
- **Duplicate data points.** Two loops posting the same cumulative snapshot at
  slightly different instants is not harmless for a counter: rate windows see
  two samples per interval with inconsistent timestamps.
- **Goroutines and tickers.** Small per leak, bounded only by how often an
  operator saves. Visible in a goroutine dump, nowhere else.
- **The missing dashboard.** 130b's real cost is an operator who built alerting
  on this node's traces and gets silence that looks like calm. Dashboards going
  flat is the *only* symptom, and it is indistinguishable from "no traffic".

## 6. Security impact

One finding, and it is 130c. `SpanRecord` carries `ClientIP`, `Host`, `Rule`,
`Status` and `SSLAction` for every proxied request — the shape of the record the
previous round refused to deliver to a collector it was not collected for. A
control-plane instruction to stop exporting is the operator's lever for exactly
that data, and with metrics already off the lever moved nothing. The gateway
kept shipping, and the CP's own view said export was off.

Nothing here touches enforcement. There is no path by which a mis-owned
exporter allows a request, changes a policy verdict, or alters the audit trail;
`RecordSpan` is called after the decision and reads nothing back. Fail-open in
the *proxy* sense is not implicated. The `isPrivateHost`/`validEndpoint` SSRF
barriers on the endpoint are unchanged and still inline at the call sites.

---

## 7. Shipped

**Ownership is atomic (`internal/otlp/spans.go`, `internal/otlp/otlp.go`).**
The loop's context is built *before* the lock, and cancelling the old loop,
publishing the endpoint and publishing the new `cancel` happen under **one**
hold of the mutex. Two orderings remain and both are coherent: the configure
wins and a loop runs, or the stop wins and none does. `cancel` is stored as
`nil` on the disable path, so a disabled exporter holds no handle to anything.

**`SpanExporter.Endpoint()`** — the reader the span exporter lacked, which is
*why* the CP apply was reading the metrics exporter's endpoint for both.

**The pair moves as one decision (`otlp.go`).** `otlpPairMu` serialises the
transition; `configureOTLPPair`, `stopOTLPPair` and
`reconcileOTLPPairToEndpoint` are the only ways the pair is touched, and all
four callers go through them.

**The CP apply reconciles each exporter from its own state**
(`controlplane_snapshot.go`), which closes F7, F8 and F9 together: the
`else if globalOTLP.Enabled()` arm that failed open is gone, replaced by a
per-exporter stop.

**One definition of the stored endpoint form (`otlp.NormalizeEndpoint`).**
Exported from the engine and used by both `Configure`s and by the reconcile, so
a caller comparing a configured endpoint against `Endpoint()` cannot drift from
the normalisation `Configure` applies (130e).

**A half-enabled plane is reportable (`diagnostics_otlp_export.go`).** A new
`otlp_export_partial` WARN row names the dark half and says it will not recover
on its own. It reads both halves under `otlpPairMu`, so a transition caught in
progress is never reported as a divergence. The row exists even though the
transitions are now atomic, because "unreachable" is a claim about the callers
that exist today and the failure mode it guards is silence.

---

## 8. Required tests — shipped

`internal/otlp/lifecycle_ownership_chaos130_test.go` (8 gates):

- `ConcurrentConfigureLeavesOneSpanPushLoop` / `…MetricsPushLoop` — 60 rounds
  of 8 concurrent `Configure` on a fresh exporter; exactly one loop, and zero
  after `Stop()`.
- `RacedSavesDoNotAccumulateLoops` — 40 raced saves at the production cadence.
- `RacedSavesDoNotAmplifyCollectorLoad` — the collector's POST count after a
  raced save plus a clean disable/re-enable.
- `StopAndConfigureAreExclusive` — 600 races; `Enabled()` and the stored handle
  must agree.
- `DisableLeavesNoLoopAndNoStaleCancel`, `SpanExporterReportsItsEndpoint`,
  `ConfigureUnderConcurrentLoadStillDelivers` (recording + pushing +
  reconfiguring at once, must still deliver).
- `NormalizeEndpointIsTheStoredForm` — the exported rule over ten endpoint
  shapes, plus the invariant that binds it to `Configure`: for every shape,
  what `Configure` stores is what `NormalizeEndpoint` returns.

`otlp_pair_lifecycle_chaos130_test.go` (7 gates): the snapshot restoring a
traces exporter stopped alone; the disabling snapshot stopping traces with
metrics already off (F9); a coherent plane left alone with no span discarded
(F12); a repoint moving both halves; 200 concurrent pair transitions never
settling half on; the `otlp_export_partial` row present for each direction
and absent for both-on and both-off; and five snapshots differing from the
stored endpoint only by normalisation emitting **zero** reconfigure log lines
(the oracle is the exporters' own "exporting … to" line, which is what an
operator would see repeating on a node that is changing nothing).

**Differential oracle.** Each gate was run against the pre-fix shape, with the
fix reverted in place and the rest of the tree held constant:

| gate | pre-fix |
|---|---|
| `ConcurrentConfigureLeavesOneSpanPushLoop` | FAIL at round 9 — 2 live loops |
| `ConcurrentConfigureLeavesOneMetricsPushLoop` | FAIL at round 5 — 2 live loops |
| `RacedSavesDoNotAccumulateLoops` | FAIL — 2 live, 1 surviving `Stop()` |
| `RacedSavesDoNotAmplifyCollectorLoad` | FAIL — 19 and 50 POSTs where 10 is correct |
| `DisableLeavesNoLoopAndNoStaleCancel` | FAIL — stale handle retained |
| `SnapshotRestoresATracesExporterStoppedAlone` | FAIL |
| `SnapshotDisableStopsTracesEvenWhenMetricsIsAlreadyOff` | FAIL |
| `HalfEnabledExportIsReported` (both directions) | FAIL — the state was silent |
| `SnapshotEndpointNormalisationIsANoOp` | FAIL — 10 reconfigure lines across 5 no-op snapshots |
| `StopAndConfigureAreExclusive` | **PASS** — see §9 |

---

## 9. Verification

Go 1.27.4 (`go.mod` `toolchain`), `GOTOOLCHAIN` not overridden.

- `go build ./...` — clean.
- `go vet .` and `go vet ./internal/otlp/` — clean.
- `go test ./internal/otlp/ -race -count=1` — **ok** (whole package, not just
  the new gates).
- `go test . -run 'TestChaos130' -race -count=1` — **ok**.
- `go test . -run 'OTLP|Observability|Chaos126|Snapshot|Diagnostic' -count=1` —
  **ok**.
- `go run ./cmd/contractcheck impact -base origin/main` lists **CLU-002**,
  **CLU-003** and **POL-900**, all because they name `controlplane_snapshot.go`
  or `admin_settings.go` as code paths; none concerns OTLP. Their named tests
  were run and pass (`TestConfigStoreVersion_SurvivesRestart`, the seven
  `TestPolicyEditsPublish_*`; POL-900 is `open` with no tests). No contract
  statement changes, so no `amended`/`retired` record is due.
- `go test ./internal/contracts/ -count=1` — **ok** (registry soundness).
- `python3 docs/agent-context/check.py` — passes.

**An honest correction to this round's own measurements.** An early probe
reported *"5 of 200 `Stop()`/`Configure()` races ended with `Enabled()` false
and a live push loop"*. That probe counted goroutines after a 1 ms sleep
without waiting for the previous attempt's cancelled loop to unwind, so it was
partly measuring its own residue. Under a settled count the figure did not
reproduce in 600 attempts, and **that number is withdrawn.** The inversion is
still reachable by construction — pre-fix, a `Stop()` completing between
`Configure`'s two phases leaves a stored `cancel` and a running loop for an
endpoint that was just cleared — and `StopAndConfigureAreExclusive` states the
invariant. It is recorded here as an **invariant gate, not a reproduction**:
unlike the other eight it does not fail on the pre-fix tree, and it is kept
because the property is the right one, not because it caught anything.

---

## 10. Residual risk

- **R1 — the leak was only ever observable in a goroutine dump.** There is
  still no gauge of live push loops, and no counter that would have moved. The
  gates are now the detection; a running appliance has none. Exporting
  something like `culvert_otlp_push_loops` is the natural companion and belongs
  with `OBS-2`'s scrape work rather than here.
- **R2 — `GET /api/otlp` still reports one `enabled`, read from the metrics
  exporter**, and the legacy panel still renders *"✓ Exporting metrics +
  traces"* from it (`static/index.html:11536`). Accurate whenever the plane is
  coherent, which it now always is from the four known callers — but the
  *stated* fix for the silence is the diagnostics row, deliberately, because
  adding `metricsEnabled`/`tracesEnabled` to the response pulls in
  `api/openapi/openapi.yaml` and the generated TypeScript client with it. Not
  done here; recorded as the next increment, and the reason is scope, not
  disagreement.
- **R3 — `otlpPairMu` is a main-package convention, not a type.** Nothing
  prevents a future caller from reaching `globalOTLP.Configure` directly and
  reopening 130b. A linter rule or a wrapper type that makes the globals
  unreachable except through the three helpers would; neither exists.
- **R4 — the reconcile compares endpoints, not headers.** A CP snapshot
  carries no auth header (`Configure(snap.OTLPEndpoint, nil)` on both paths,
  unchanged by this round), so a node whose header was set locally keeps it as
  long as the endpoint matches and loses it on a repoint. That is the
  pre-existing behaviour and arguably correct — credentials for collector A are
  not credentials for collector B — but it is a decision nothing states.
- **R5 — `droppedSpans` is still monotonic with no recency**, and still not
  scrapeable. `CHAOS-126`'s R4/R5 stand untouched.
- **R6 — the half-enabled row is report-only.** It tells an operator what to
  do; it does not reconcile. On a CP-managed node the next apply fixes it; on a
  standalone node it waits for a human. Self-healing a standalone node would
  mean a background reconciler owning a settings surface, which is a larger
  ownership decision than this round should make.
- **R7 — nothing here addresses `CHAOS-126`'s R1.** A RAM buffer is still a RAM
  buffer: SIGKILL, OOM or a power loss lose what is held.
