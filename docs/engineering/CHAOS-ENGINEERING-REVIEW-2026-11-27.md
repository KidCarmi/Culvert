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
wins and a loop runs, or the stop wins and the exporter ends disabled holding
no handle. (Precisely — see §11 F1 — when the stop wins, Configure still starts
a goroutine, because `go pushLoop(ctx)` is necessarily outside the lock; it
takes its `ctx.Done()` arm immediately and exits, with nothing to flush. The
exporter *converges* on "no loop" rather than holding that property at an
instant.) `cancel` is stored as
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

`internal/otlp/lifecycle_ownership_chaos130_test.go` (8 gates; the counts and
the shape of two of them changed under the independent review — see §11):

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

`otlp_pair_lifecycle_chaos130_test.go` (9 gates): the snapshot restoring a
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
- `go test . -count=1` (the whole root package) — **ok**.
- `go test . -run 'TestChaos130|OTLP|Observability|Chaos126' -count=2 -shuffle=on`
  and `go test ./internal/otlp/ -count=2 -shuffle=on -race` — **ok**, for the
  shared-global hygiene the conventions require of a test that touches
  `globalOTLP`/`globalOTLPTraces`.
- **golangci-lint v2.15.0**, the version
  [pr-fast-gate.yml](../../.github/workflows/pr-fast-gate.yml) installs, built
  with the `go.mod` toolchain (`GOTOOLCHAIN=go1.27.4 go install
  …/golangci-lint@v2.15.0`) rather than the container's older binary:
  - the gate's own command, `run --new-from-rev origin/main` — **0 issues**.
  - a **full-tree** pass as well, because `cyclop`, `funlen` and `gocognit`
    attribute to a function's DECLARATION line and a diff-scoped run cannot see
    a function made more complex in place. The full tree reports 174
    pre-existing issues; **none is in any file this change touches**, and none
    names any function it changed or added. Checked explicitly: the complexity
    findings in `controlplane_snapshot.go`, `admin_settings.go` and
    `ui_config.go` are `validateConfigSnapshot`, `applySnapshotClusterRuntime`,
    `CurrentConfigSnapshot`, `apiConfigExport`, `buildImportSettingsPreview`,
    `saveAdminSettingsWithOverrides`, `buildLogFilterPredicate`,
    `apiConfigImport` and a PAC `nestif` — not `applySnapshotExtendedState`,
    `applyAdminServices` or `apiOTLPConfig`. That is a stronger result than a
    count comparison against the base: no function in a touched file is over
    any threshold at HEAD, so there is no regression for the base measurement
    to reveal.

Lengths of the two functions this round rewrote, against the configured bars
(`funlen` 80 lines / 50 statements, `cyclop` 15, `gocognit` 30):
`SpanExporter.Configure` 67 lines, `MetricsExporter.Configure` 46,
`checkOTLPExport` 24. All under, and the linter confirms it.

**Not run here**, and named rather than implied: the hosted Fast and Deep
gates, CodeQL, the API-governance gate (no route, OpenAPI or
`uiRoutes` change in this round — the new diagnostics row is a free-form `Code`
string in an existing list, not an endpoint), and the race-sharded QA gate.
A passing local check is not a passing merge gate.

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

---

## 11. Independent review of the fix, and what it found

The round's fix was reviewed independently before the PR was finished, with the
reviewer given the code and a bounded question set and explicitly told not to
read this document or the register entry. **It found one defect that would have
broken CI on every unrelated PR, one real regression introduced by the fix, one
vacuous gate, and one overstatement in this round's own prose.** All four were
reproduced by the lead before being changed, and each now has its reproduction
as a gate.

### F1 (HIGH) — the round shipped a flaky gate, and CI runs exactly the command that trips it

`TestChaos130_StopAndConfigureAreExclusive` asserted the invariant on a
**process-wide differential goroutine count**. That cannot express it, because
`go pushLoop(ctx)` is necessarily outside the critical section: when `Stop()`
wins the race, `Configure` still starts a goroutine, which takes its
`ctx.Done()` arm and exits at once. The exporter therefore **converges** on "no
loop" instead of holding that property at an instant, and a neighbouring
attempt's straggler shifts the per-attempt baseline by ±1.

Reproduced by the lead on a loaded machine — the shape of a CI shard:

| command | result |
|---|---|
| `go test -race -run TestChaos130 -count=3 ./internal/otlp/`, machine idle | 0/6 fail |
| the same, with four CPU hogs running | **3 of 3 runs FAIL** |

with readings including the impossible:

```
attempt 503: Enabled() = false with -1 live push loop(s); want 0
attempt 553: Enabled() = true  with  0 live push loop(s); want 1
```

`-1` is the proof: the baseline, not the product, was wrong. And the Fast Gate
and the QA gate both run `go test -race -count=1 -timeout=10m -v ./...`
(`pr-fast-gate.yml:494`, `qa-gate.yml:553`), so this would have reddened **any**
PR that happened to land on the shard carrying this package, roughly one run in
six, with a message pointing at the product code rather than at the harness.
The worst kind of gate: one that cries wolf about someone else's change.

**Fixed** by stating the invariant where it is instantaneous — `e.cancel` under
`e.mu`, plus the endpoint settling with the active flag — and keeping the
goroutine count only as a single **aggregate** assertion after all 600 races,
where "every loop has unwound" is a property the implementation really does
hold. A `quiesceLoops` helper now samples any baseline only once the count has
stopped moving, which removes the same latent contamination from the three
other gates that use a differential count. Re-measured under the identical
load: **0 of 5 runs fail** at `-race -count=3`, and **0 of 3** for the whole
package at `-race -count=1`. The differential oracle survived the rewrite —
four gates still fail on the two-phase tree, one of them now reporting **72
POSTs over 10 intervals** where 10 is correct.

### F2 (MED) — the per-exporter reconcile could leave the two halves holding different credentials

This one the fix introduced. Deciding each half independently is what closes
130b and 130c — but it also means only the *wrong* half gets reconfigured, and
the snapshot's inputs then reach only that half. From metrics off and traces at
`E` with a locally configured auth header, a snapshot carrying `E` configured
metrics with the snapshot's `nil` headers and **skipped traces**, so metrics
would 401 against an authenticating collector forever while traces kept
working. The old coupled guard never produced that state, because it always
configured both.

**Fixed** by separating the *decision* from the *action*: each half is still
examined on its own, so a half that is dark or misdirected is still detected —
but when **either** is wrong, **both** are reconfigured from the one set of
inputs. The steady-state no-op is untouched (F12 still holds: both already at
the endpoint ⇒ return, nothing cancelled, nothing discarded). The cost is
restarting one healthy loop in an already-anomalous state, which no
steady-state apply reaches, and it is the reading that matches this round's own
thesis: the pair is one decision.

### F3 (MED, caught as a vacuous gate) — the first credential gate asserted nothing

The gate written for F2 passed against the broken code. `SpanExporter` had no
`Headers()` reader, so the test could only check the metrics half — the half
that was already correct. **This is the same shape as 130b's root cause**: the
property could not be stated because the accessor did not exist, which is
exactly why the CP apply had been reading the metrics exporter for both halves.
`SpanExporter.Headers()` was added, mirroring its twin, and the gate now fails
on the per-half reconcile with the right message.

### F4 (LOW) — "the stop wins and nothing does" was not true

This round's own comment and commit message said that under one critical
section either the configure wins and a loop runs, or the stop wins and
**nothing** does. A goroutine does start in the second case; it just exits
immediately. The claim is corrected in `spans.go` and in §7 above, and the
distinction is not cosmetic — it is precisely what made F1's assertion
unsound.

### Also closed while the findings were being fixed

- **A split export plane is now reported.** The reviewer noted that
  `otlp_export_partial` keys on `Enabled()` alone, so **both** halves running
  against **different** collectors stayed as silent as the half-enabled case
  used to be. A second row, `otlp_export_split`, names it — without naming
  either endpoint, since one may embed a token.

### Review findings recorded and NOT fixed here

- **(LOW, pre-existing) `adminSettingsSave` can pair a new endpoint with the
  old collector's token.** `admin_settings.go:843-846` writes
  `s.OTLPEndpoint = globalOTLP.Endpoint()` unconditionally but
  `s.OTLPHeaders` only when non-empty. A CP repoint to collector B passes `nil`
  headers; the next unrelated admin save persists **endpoint B with the
  retained header for collector A**, and the next restart sends A's bearer
  token to B. Pre-existing on both the old and new CP paths, and a credential
  hygiene question about `AdminSettings` persistence rather than about exporter
  ownership — but it is the sharpest of the carried items and should be the
  next one taken.
- **(LOW, pre-existing) the shutdown flush is not under the pair mutex.**
  `flushOTLPExporters` (`main_shutdown.go:428-437`) calls `FlushFinal`/`Flush`
  directly. `FlushFinal` sets `finalized = true`; a `Configure` landing after
  it resets `finalized = false`, re-arming `requeue` into a ring that dies with
  the process — the silent loss `CHAOS-126` removed, in the last second of the
  process's life. Narrow (it needs an admin save or a CP apply inside the flush
  reserve, with the admin listener still up) and pre-existing, but noted
  because this round's thesis is that this pair is one decision.

### What the review confirmed sound

No deadlock and no lock inversion: `otlpPairMu → exporter.mu` is the only order
in the tree, and the inverse is *unconstructible* because `internal/otlp`
cannot reference a `package main` symbol (ADR-0003). The only outward call from
inside `Configure`/`Stop` is `obs.Printf` into an async `internal/logsink`
writer, so no network write happens under the pair mutex. `checkOTLPExport` has
one caller (`diagnostics.go:314`), not under the lock, and releases before
`Health()`. No helper re-enters another. `grep` for
`globalOTLP*.Configure|Stop` outside tests returns only the three helpers in
`otlp.go` — all four lifecycle callers really do go through them. `go vet`'s
`lostcancel` is clean and no path creates a cancel that is never stored, so the
goroutine leak is genuinely closed. The new row has no reachable false
positive, and the existing `otlp_export` failure row is behaviourally
unchanged. Conventions check out: the inline `url.Parse` → scheme → 
`isPrivateHost` SSRF guard is intact and still before the dial, handler-level
`requireRole` is on both arms, the audit-then-save ordering is unchanged, and
every function the change touched or added is inside the complexity gates.
