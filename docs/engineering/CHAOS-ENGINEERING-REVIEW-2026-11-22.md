# Chaos engineering review — 2026-11-22

Reviewer: Culvert Chaos Engineer (automated round). Base revision `ef94311`
(`origin/main`), clean worktree at branch point.
[CHAOS-ENGINEERING-REVIEW.md](../../roadmap/CHAOS-ENGINEERING-REVIEW.md) stays
the index; this is the dated record for the round it registers. The round was
CLAIMED and investigated on 2026-11-21 — the same day
[the CHAOS-125 record](CHAOS-ENGINEERING-REVIEW-2026-11-21.md) was committed,
a few hours earlier — and recorded the following day, which is the date this
file carries, matching the convention the CHAOS-125 round used for the same
split.

Id claimed: **CHAOS-126**, in a committed placeholder row as commit one
(`32e1142`), before any code, and checked against `origin/main` rather than the
working tree per the register's 2026-09-25 amendment. `CHAOS-125` was the
highest id anywhere on `origin/main` at `ef94311`, and no open PR held a chaos
id (#1994, #1993, #1992, #1705, #1549, #1548, #1536, #1528, #1526).

Scope: **the observability plane's own loss accounting** — what happens to a
request span between `RecordSpan` (`proxy.go:1233`) and an OTLP collector,
when the collector is unavailable and when the process restarts. This round
**narrows `OBS-2`**, which swept this same domain and recorded the export
engines as *"sound: bounded queues with counted non-blocking drops … 5 s write
deadlines, drain-before-post so no mutex is held across `client.Do`"*.

---

## 1. Executive summary

`OBS-2` was right that nothing holds a mutex across `client.Do`. It credited
the statement that achieves that — `drain()` before the POST — without
noticing that for the SPAN exporter, drain-before-post means
**drain-and-destroy-on-failure**.

**CHAOS-126a (MED→HIGH for the counter, MED for the loss) — the batch is
dequeued before anyone knows whether the collector will take it, and the
counter that exists to report the loss cannot see it.**
`SpanExporter.push` opened with `spans := e.drain()`
(`internal/otlp/spans.go:199` at base), and every failure arm below it simply
returned the error. The spans were already out of the ring; nothing held a
reference to them; they were gone. Three consequences compound:

1. A collector that is down, slow or 5xx-ing destroys **100%** of the spans it
   is handed, once per push interval, for as long as the outage lasts.
2. Because the ring is emptied on every tick **whatever the outcome**, it can
   never FILL. `droppedSpans` counted ring overwrites only — and its own
   comment named the state it could not reach: *"ring-buffer overwrites
   (collector unreachable + buffer full)"* (`spans.go:70` at base).
3. The cap's documented purpose — *"The buffer cap (spanBufferCap) prevents OOM
   when the collector is down"* (`spans.go:9` at base) — was therefore vacuous.
   Peak occupancy during an outage was not 4096 spans; it was one interval's
   arrivals, and the reason was data destruction, not a bound.

Measured on this tree, before the fix, through the production push loop
(control probes recorded in §9):

| probe | observed |
|---|---|
| 7 spans, collector returns 503 | push error reported; **buffer 0**, `droppedSpans` **0**; on recovery the exporter POSTs **nothing** — there is nothing left |
| 2000 spans recorded over 6 intervals against a 502 collector | **0 delivered, 0 buffered, `droppedSpans` 0, `failureCount` 6** |
| 5 spans buffered, then `Stop()` | collector received **0 requests**; buffer **0**; `droppedSpans` **0** |
| 1 span recorded, process exits mid-interval | **0 delivered**, 1 still in RAM |

**CHAOS-126b (MED) — "Final flush on shutdown" has never run on a shutdown.**
`pushLoop`'s `ctx.Done()` arm is commented exactly that (`spans.go:187` at
base). Nothing in the shutdown sequence cancels that loop:
`registerLateShutdownHooks` flushes the cluster store, syslog, the community
DB, the log store, the request log and the audit FD
(`main_shutdown.go`, orders 55–140) and has **no OTLP hook at all**. The loop's
context comes from `context.Background()` in `Configure`, so it is not even
tied to `appLifecycleCancel`. The only two callers that DO cancel it are:

- `Stop()`, which clears the endpoint **first** — so the cancelled loop's
  flush drained the ring and returned at `endpoint == ""`, having posted
  nothing (row three above); and
- `Configure(new)`, whose flush re-reads the endpoint and posts the **old**
  collector's spans to the **new** one.

Neither is a shutdown. So the sink whose entire state is a RAM ring buffer was
the one sink with no flush hook, and up to a full push interval of request
spans was lost at every graceful restart, uncounted and unlogged.

**The asymmetry the design missed** is one sentence long: the metrics exporter
beside this one pushes a **cumulative snapshot**, so a failed push costs
resolution and the next tick re-derives everything. **Nothing re-derives a
span.** The two exporters were written to the same shape, and only one of them
could afford it.

---

## 2. Failure scenarios

Each row is the scenario, the behaviour before this round, and the behaviour
after. "Counted" means `droppedSpans` moves; "silent" means no counter, no log
line, no metric.

| # | Scenario | Before | After |
|---|---|---|---|
| F1 | Collector down for one interval | every buffered span destroyed, **silent** | batch retained, delivered on the next successful tick |
| F2 | Collector down for longer than the cap | all spans destroyed each tick, `droppedSpans` 0 | 4096 most recent spans retained; each eviction **counted**; one POST per interval |
| F3 | Collector returns 500/502/503/504 | destroyed, silent | retained (`retryableCollectorStatus`, `spans.go:314`) |
| F4 | Collector returns 429/408 (overloaded) | destroyed, silent | retained — the condition can change on its own |
| F5 | Collector returns 400/413 (payload rejected) | destroyed, silent | dropped and **counted**, with a log line naming the status; retaining bytes the collector will never accept would starve spans that could still go |
| F6 | Collector returns 401/403 (bad credentials) | destroyed, silent | dropped and **counted**; the operator's own gap is better reported than hidden behind a buffer quietly evicting live traffic |
| F7 | Collector accepts TCP, never responds | destroyed after the client's 10 s timeout, silent | retained; `Flush` additionally honours the caller's deadline |
| F8 | Process receives SIGTERM | up to one interval of spans lost, **silent**; the "final flush" branch unreachable | `otlp-flush` hook (`main_shutdown.go:545`) makes one bounded attempt |
| F9 | Admin disables OTLP export | buffer drained and destroyed by the cancelled loop's flush, silent | buffer ended at `Stop()`, **counted**, with a log line |
| F10 | Admin repoints at a different collector | collector A's spans POSTed to collector B | buffer ended, **counted**, logged; B receives only what was recorded for it |
| F11 | Admin changes only the auth header | (as F10, same endpoint ⇒ delivered) | buffer kept and delivered — nothing is at risk |
| F12 | `Configure("/")` or a whitespace-only endpoint | `Enabled()` reported **true**; a loop ran that could never post | normalised first; `Enabled()` false, no loop |
| F13 | >273 req/s with a healthy collector | oldest evicted, counted (correct before and after) | unchanged |
| F14 | Endpoint fails the `validEndpoint` barrier | batch drained then destroyed, failure counted | batch **not** drained; failure still counted, so the operator keeps the signal |

---

## 3. Risk matrix

| Id | Finding | Sev | Likelihood | Blast radius | Detectability (before) |
|---|---|---|---|---|---|
| 126a-1 | Undelivered batch destroyed on every push failure | **MED** | HIGH — any collector restart, rollout or 5xx | all trace data, per node | `failureCount` moved; **data loss itself invisible** |
| 126a-2 | `droppedSpans` structurally unable to observe the scenario it documents | **HIGH** (as a reporting defect) | CERTAIN | the operator's only loss surface, plus the GUI row built on it | **none** — it reads 0 |
| 126a-3 | `spanBufferCap`'s "prevents OOM when the collector is down" unreachable | LOW (benign direction) | CERTAIN | memory claim only | none |
| 126b-1 | No shutdown flush hook for a RAM-only sink | **MED** | CERTAIN — every restart | ≤ one interval of spans per restart | **none** |
| 126b-2 | `Stop()` ordering makes the loop's own flush a buffer shredder | MED | every disable | buffered spans | none |
| 126b-3 | `Configure(new)` flush delivers collector A's spans to collector B | LOW-MED (privacy) | every repoint | one window of client IPs + hosts | none |
| 126c | `Enabled()` derived from the un-normalised argument | LOW | configuration-dependent | a lying status surface | none |

Severity reasoning, stated rather than asserted: the spans are **not** the
authoritative record. The audit log (`internal/audit`), the request log
(`internal/reqlog`) and the log store are separate, durable and already
flushed at shutdown, so losing traces does not lose the compliance evidence.
That caps 126a-1/126b-1 at MED. What earns HIGH is 126a-2: a counter whose
documented meaning is the exact scenario it cannot observe is worse than no
counter, because an operator asking "did we lose telemetry?" gets a confident
**no**.

---

## 4. Recovery assessment

| Scenario | Automatic recovery (before) | Automatic recovery (after) | Manual recovery |
|---|---|---|---|
| Collector outage shorter than the cap | **none** — data destroyed | **full** — every span delivered on recovery | n/a |
| Collector outage longer than the cap | none | partial by construction: the 4096 most recent spans survive, older ones counted as lost | raise the collector before the cap fills; the counter now says what was missed |
| Permanent rejection (400/413) | none | none, by design — counted and logged so the cause is actionable | fix the collector's limits/version; the log line names the status |
| Graceful restart | none | one bounded attempt at the end of the sequence | n/a |
| SIGKILL / OOM / kernel panic | none | **none** — RAM is RAM | none. Stated as residual risk R1 rather than engineered around |

Retention is deliberately **not** a retry ladder, because the register's own
rules are "avoid hidden retries" and "avoid infinite retries": there is no
attempt counter, no backoff schedule and no amplification. One POST per
interval happens either way; the only change is whether the batch handed to it
is the data that failed last time or a fresh slice of a ring that threw it
away. Memory is bounded by the same `spanBufferCap` as before, and the
worst-case request size is unchanged (one full ring, ≈2 MB).

---

## 5. Operational impact

- **New, honest signal.** `droppedSpans` now means *never delivered* and is
  reachable: overflow during an outage longer than the cap, a rejected batch,
  or a disable/repoint that ends buffered spans. Each of the latter two also
  emits a log line naming the cause (`spans.go:286`).
- **Corrected GUI claim.** `static/index.html` said *"trace span(s) dropped
  (buffer full - collector unreachable)"*. After this round an outage alone
  loses nothing until the cap, so the row no longer attributes the count to
  one; it names the three things that can actually end a span.
- **Shutdown cost.** One extra hook at the very end of the flush phase,
  bounded to `otlpShutdownFlushBudget` = 2 s (`main_shutdown.go:296`) against
  a 10 s flush reserve, and a no-op when export is disabled (the shipped
  default), so the common path adds nothing measurable.
- **What an operator must now re-read.** A non-zero `droppedSpans` no longer
  implies "the collector is unreachable". An operator who had learned to read
  it that way will read it wrongly until they see the new text; that is the
  cost of correcting a surface, and it is why the GUI string changed in the
  same commit as the semantics.

## 6. Security impact

- **Forensic completeness, improved.** A span carries `Status` (`OK`,
  `BLOCKED`, `FILE_BLOCKED`, …), the matched `Rule`, the `ClientIP`, the
  target `Host` and the `SSLAction` (`spans.go:51-62`). That is a record of
  what the gateway DECIDED. It was being destroyed, in bulk, exactly when the
  observability backend was unhealthy — which is also when an incident is most
  likely to be under way. It is now retained across a bounded outage and
  flushed at a graceful restart.
- **Destination discipline, new.** Repointing at a different collector no
  longer ships the previous window's client IPs and hostnames to a destination
  the operator did not choose for them (F10). A headers-only reconfigure keeps
  the buffer, because nothing is at risk (F11).
- **No new outbound surface.** The SSRF posture is untouched: the same
  `ssrf.SafeDialContext` transport, the same `validEndpoint` regexp barrier
  CodeQL recognises, in the same position relative to the POST. The barrier
  moved one statement earlier (ahead of the drain) and still gates every
  request.
- **No fail-open introduced.** Nothing about this exporter gates traffic;
  retention cannot block, delay or alter a proxied request. `RecordSpan` is
  one mutex-guarded struct copy and is unchanged.

---

## 7. Shipped

`internal/otlp/spans.go`, `internal/otlp/otlp.go`, `main_shutdown.go`,
`static/index.html`.

1. **`push` reads the endpoint before the drain** (`spans.go:347`). This is the
   whole of 126b-2: a disabled exporter can no longer shred its buffer on the
   way to discovering it had nowhere to post it.
2. **`requeue`** (`spans.go:256`) returns an undelivered batch to the FRONT of
   the ring, ahead of spans recorded while the push was in flight, preserving
   oldest-first order, and counts whatever no longer fits. A batch whose
   exporter was stopped or repointed mid-push is counted and let go — there is
   nothing left to retain it for.
3. **`deliver`** (`spans.go:397`) owns the retain-vs-discard decision, split
   out of `push` so the policy is one readable function and so `push` did not
   grow past the repository's complexity thresholds.
4. **`retryableCollectorStatus`** (`spans.go:314`) — transport error, 408, 429
   and any 5xx retain; every other 4xx is discarded and counted. The set is
   pinned by a gate so neither direction can drift silently.
5. **`discard` / `discardBufferedLocked`** (`spans.go:286`, `:296`) — the two
   counted exits. Every span that leaves this exporter without reaching a
   collector passes through one of them or through `requeue`'s overflow arm,
   which is what lets `droppedSpans` be read as total undelivered.
6. **`Flush(ctx)`** on both exporters (`spans.go:200`, `otlp.go`) and the
   **`otlp-flush` shutdown hook** at order 138 (`main_shutdown.go:545`,
   `flushOTLPExporters` at `:402`) — after every durable closer, before the log
   closer, bounded to 2 s.
7. **The loop's `ctx.Done()` flush is bounded** (`spanFinalFlushTimeout` = 5 s,
   `spans.go:44`) and its comment now says what it is: a reconfigure/disable
   flush, not a shutdown one.
8. **`Configure` normalises first** (`spans.go:138`), so `Enabled()` and the
   decision to start a loop both come from the value that will actually be
   posted to.
9. **Honest documentation** on `droppedSpans`, `PushHealth.DroppedSpans`,
   `spanBufferCap` and the package header, plus the corrected GUI row.

### Refused, with reasons

- **No alert.** A collector restart is routine; a threshold on its normal
  background rate is noise. The existing `failureCount` + `lastErrorAt` pair
  already gives recency, which is what the register's own OBS findings ask for.
- **No scrape metric.** `culvert_otlp_*` still does not exist, and that is
  `OBS-2`'s open ask, not this round's. Deliberately left to it: exporting
  `droppedSpans` **before** this round would have published a counter that
  reads 0 through a total outage. Fixing the meaning is the prerequisite, and
  OBS-2's row is now narrowed to "wire the counter", not "wire this counter".
- **No operator setting** for the buffer cap, the budget or the retain/discard
  split. Three thresholds nobody asked for, in a plane that gates nothing.
- **No `description` added to `droppedSpans` in `api/openapi/openapi.yaml`.**
  The spec carries no semantic claim to correct (the field is bare
  `{type: integer}`), and touching it drags the generated-client and
  committed-dist drift gates into a round whose API shape is unchanged. The
  claim that was wrong lived in the GUI string, and that is what changed.
- **No flush on `Stop()`.** `Stop()` is reached from an admin API handler; a
  synchronous POST to a possibly-dead collector inside a request handler buys
  an operator a hung disable. The buffer is counted and released instead.
- **No change to the 15 s interval and no jitter.** `WK-13`/`R-5` already owns
  OTLP's missing jitter; adding it here would take an open row's scope without
  its analysis.

---

## 8. Required tests — shipped

`internal/otlp/span_loss_accounting_chaos126_test.go` (15 gates) and
`otlp_shutdown_flush_chaos126_test.go` (4 gates), plus the canonical late-hook
fixture in `runtime_shutdown_wiring_test.go`.

Engine gates: outage retains and then delivers on recovery (the headline, with
the batch counted at the collector, not merely "a request happened"); a
**healthy** push still clears the buffer (the negative control that a
"retain everything" regression would otherwise pass); permanent rejection
dropped and counted across five 4xx codes; the retryable set pinned in both
directions; retention bounded at the cap with eviction counted; **requeue's own
overflow** counted, using a collector that records spans into the exporter
while it is deciding, so the "spans arrived during the in-flight push" path is
real rather than simulated; oldest-first order preserved across a requeue;
`Stop()` counts the buffer it ends and the cancelled loop's flush neither
double-counts it nor POSTs after a disable; a disabled push leaves the buffer
untouched; an unpostable endpoint retains and still reports; an endpoint change
does not ship the old window to the new collector while a headers-only change
keeps it; `Enabled()` tracks the normalised endpoint; `Flush` delivers; `Flush`
honours the caller's deadline against a blackholed collector **and** keeps the
batch.

Main-side gates: the `otlp-flush` hook exists, sits in the flush partition,
runs after **every** durable closer and before the log closer; the hook reaches
the production singletons (driven through an endpoint the `validEndpoint`
barrier rejects, so the gate needs no network and cannot be satisfied by a hook
that quietly does nothing); it is a no-op when export is disabled; and the
budget fits inside the flush reserve with room for the closers sharing it.

Delivery is **not** gated from package main on purpose: the shipped transport
dials through `ssrf.SafeDialContext`, which correctly refuses the loopback
address an `httptest` collector listens on. A main-side test that posted to one
would be evidence the SSRF guard had been weakened.

---

## 9. Verification

**Control probes (pre-fix, deleted before the fix landed).** Four probes
through the real `push`/`pushLoop`/`Stop` path produced the measurements in §1.
The sharpest is probe D: a running loop, interval 20 ms, collector returning
502, 2000 spans recorded — `recorded=2000 pushAttempts=6 stillBuffered=0
droppedSpans=0 failures=6 lost=2000`.

**Mutation testing — 8 mutations, each applied to the fixed tree and reverted.**

| # | Mutation | Caught by |
|---|---|---|
| M1 | drop instead of retain on a retryable failure | 5 gates (outage+recovery, bounded retention, order, reconfigure, loop end-to-end) |
| M2 | restore the original drain-before-endpoint-check ordering | 4 gates |
| M3 | treat every status as retryable | permanent-rejection gate, all five codes |
| M4 | retain without counting `requeue`'s overflow | **nothing, on the first pass** |
| M5 | `Stop()` leaves the buffer uncounted (the pre-fix shape) | Stop gate |
| M6 | derive `Enabled()`/start from the un-normalised argument | normalisation gate |
| M7 | remove the `otlp-flush` hook registration | 3 gates incl. the canonical fixture |
| M8 | register the hook below the flush boundary | position gate, naming all five closers it would jump |

**M4 is the one worth recording.** The eviction gate asserts
`droppedSpans == extra` after recording past a full ring — but those evictions
happen in `RecordSpan`, not in `requeue`. The requeue overflow arm (batch +
in-flight arrivals > cap) had **no** gate, which is precisely the arm where
silent loss would reappear. A dedicated gate was added for it — a collector
that records 50 spans into the exporter while serving the failing request —
and M4 is now caught naming the count. Found by mutation, not by review.

A second harness bug was fixed the same way: the endpoint-change gate first
asserted buffer OCCUPANCY after a headers-only reconfigure, which races the
cancelled loop's legitimate flush to the same endpoint. Re-aimed at the
property that actually matters and does not race — the spans recorded FOR that
endpoint are delivered to it, and nothing extra is counted as dropped.
Confirmed stable over `-count=5`.

**Checks run** (toolchain `go1.27.4` from `go.mod`'s `toolchain` line,
`GOTOOLCHAIN=auto`, `go env GOVERSION` = `go1.27.4`):

| Check | Result |
|---|---|
| `go vet ./...` | clean |
| `go mod tidy -diff` | clean |
| `gofmt -l` (Go tree) | clean |
| `go build ./...`, `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build` | pass |
| `go test -race -shuffle=on -count=2 ./internal/otlp ./internal/shutdown` | pass |
| `go test -race -count=1` root, CHAOS-126 + shutdown-wiring + observability + audit-close selection | pass |
| `TEST_SEED=20260421 go test -count=2 -shuffle=on ./...` (Deep determinism command) | **pass — 130 packages, exit 0**, root package 1115 s |
| `golangci-lint v2.15.0` (the version Fast installs), `run --new-from-rev origin/main` | **0 issues** |
| `golangci-lint v2.15.0` full-tree on the changed packages, compared against the SAME measurement on the base | see below |
| Each commit builds and tests independently | pass |

The full-tree comparison is the check `--new-from-rev` cannot do, and it
earned its keep. `registerLateShutdownHooks` already carries a pre-existing
`gocognit` finding: **37** on the base, over the threshold of 30. Registering
the new hook as an inline closure took it to **41** — invisible to the
diff-scoped run, because `gocognit` attributes to the declaration line.
Extracting the body into `flushOTLPExporters`, for the reason
`drainActiveTunnels` is extracted, returned it to **37**: no regression, and
the pre-existing finding is left where it was rather than "fixed" inside an
unrelated round. The only other finding on a changed file
(`spans_test.go:246` `whyNoLint`) measures identically on the base and is not
this round's.

Not run, and why: `make api-verify` and the OpenAPI breaking/client gates (no
schema change — see §7's refusal), the frontend `npm run verify` tree (the
React bundle does not render this field; only `types.gen.ts` mentions it, and
it is unchanged), the `benchgate` lane (no wall-clock gate added or touched;
`internal/otlp` owns no `benchgate` file), and the privileged/sharded CI
evidence a local run cannot reproduce. A passing local selection is not
aggregate CI approval.

---

## 10. Residual risk

- **R1 — a RAM buffer is still a RAM buffer.** SIGKILL, OOM, a kernel panic or
  a power loss lose whatever is held. Spilling spans to disk would make the
  trace plane a persistence owner with its own corruption, quota and
  redaction contracts, for data whose authoritative counterpart (audit,
  request log) is already durable. Explicitly not engineered around.
- **R2 — the shutdown flush is one bounded attempt.** A collector that is down
  at the moment of a restart still costs that window. The alternative is
  spending more of a reserve the durable closers share, which is the trade the
  reserve exists to prevent.
- **R3 — an outage longer than the cap still loses the oldest spans.** Now
  counted, and the cap is now a real bound rather than a decorative one, but
  4096 spans is ≈15 s of traffic at 273 req/s and minutes at low volume: the
  cap is a chosen number, not a budget derived from a memory limit.
- **R4 — `droppedSpans` is monotonic.** It carries no recency of its own, so
  twenty losses three days ago and twenty in the last minute read identically.
  `failureCount` has `lastErrorAt`/`lastSuccessAt` beside it; the drop counter
  does not. The same shape the register has flagged repeatedly (WK-5,
  CHAOS-59, CHAOS-123, CHAOS-124) — recorded here, not fixed here.
- **R5 — still not scrapeable.** `OBS-2` remains open and is now narrowed:
  the counter it wants exported finally measures something.
- **R6 — no gauge of buffer occupancy.** An operator cannot see "the ring is
  73% full and rising" before the first eviction; they see failures, then
  drops. A gauge is the natural companion and belongs with R5's scrape work.
- **R7 — the CP snapshot's OTLP apply still decides for both exporters from
  the METRICS exporter's state** (`controlplane_snapshot.go:1808-1818`:
  `globalOTLP.Enabled()` gates the `Stop()` of both). Pre-existing, out of
  this round's scope, and harmless today because the two are always configured
  together — but it is a divergence waiting for the first caller that
  configures them separately.
- **R8 — `MaxIdleConnsPerHost: 2` with no `MaxConnsPerHost`** on the span
  client, and the response body is closed without being drained, so a 4xx/5xx
  body prevents connection reuse. Costs a connection per failed interval
  against a failing collector; noted, not changed, because it is a transport
  tuning question and not a loss-accounting one.
