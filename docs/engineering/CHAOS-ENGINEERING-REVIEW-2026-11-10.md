# Chaos Engineering Review — 2026-11-10

## CHAOS-116 — The unauthenticated liveness probe dials the AV daemon, and enough probes make the daemon stop answering real scans

**Scope.** The SIMULATE list's *ClamAV unavailable*, *API overload*, *thousands
of simultaneous connections*, *half-open TCP*, *network latency* and *slow
filesystem* rows, aimed at the **status/liveness plane** rather than at the scan
path. CHAOS-115 bounded what the scan sidecar will BUFFER; this round asks what
an unauthenticated client can make a node DIAL.

**Status.** One defect found, reproduced on this tree before any fix, fixed. A
second defect — a 30 s startup stall holding the scanner's write lock — was
found while reading the first one's call site and is fixed in the same round,
because it is the same inline ping and the same fix removes both. Four further
findings were verified against the source and are **not** fixed here; they are
recorded in §8 with file/line evidence and a verification status for each,
because three of them are a different plane and the fourth is a different class.

**Closes.** Nothing carried forward. CHAOS-115's residual-risk items 1-6 are
untouched by this round and remain open as written.

---

## 1. Executive summary

`Scanner.ClamAVStatus` served a cache miss by dialing the ClamAV daemon INLINE,
on whatever goroutine asked:

```go
// internal/secscan/secscan.go, pre-fix
ss.mu.RUnlock()
var val string
if err := clam.Ping(); err != nil {        // 30 s dial + 30 s read, context.Background()
    val = fmt.Sprintf("unreachable: %v", err)
} else {
    val = "connected"
}
```

Three facts turn that from a slow endpoint into a fleet-wide fail-open.

**It is on the unauthenticated surface.** `/health` and `/ready` are dispatched
by `routeProxyListenerBuiltin` ([pac.go:141-157](../../pac.go)) on the **proxy**
listener, and `buildAndStartProxyServer` calls it BEFORE `handleRequest`
([main.go:1185-1189](../../main.go)) — therefore before the IP filter, the rate
limiter and `connLimiter.Acquire`, all of which live inside `handleRequest`.
`handleHealth`'s own doc comment states it: *"there is no proxy authentication,
no admin session, and no IP guard in front of it. Every client that can use the
gateway can read whatever is written here."* So an unauthenticated client chose
how often that ping happened.

**It was unbounded and uncancellable.** `clamav.Client.timeout` is 30 s, sized
for a scan, and `Ping` applied it to the dial and then again to the read
deadline — up to ~60 s per probe. It dialed with `context.Background()`, so
neither a caller's deadline nor a client's disconnect could end it.

**It bypassed the semaphore that exists for exactly this.** `clamav.clamSem`
([clamav.go:47-49](../../internal/clamav/clamav.go)) bounds concurrent scans
"to prevent overwhelming the daemon"; `Ping` takes no slot (`clamSem` appears
only in the scan path). The probe path was therefore the one way to open
unbounded connections to the daemon that semaphore protects. A daemon whose
connection queue is full fails real scans, and `internal/secscan` classifies a
failed scan as an engine fault and **forwards the content UNSCANNED** —
`statClamScanError`, logged as *"forwarding UNSCANNED (fail-open)"*
([secscan.go:1322](../../internal/secscan/secscan.go)).

**Measured on the pre-fix tree**, with `internal/secscan/secscan.go` and
`metrics.go` restored from `origin/main` and this round's gate run against them:
48 unauthenticated `/health` requests against a daemon that accepts and does not
answer — **not one of the 48 completed** inside the gate's 10 s bound. The dial
COUNT cannot be read from that run (the gate fails on the wait before it reaches
the dial assertion), so it was measured separately, by removing single-flight
from the fixed tree while keeping the caller bound: **48 requests, 48 dials**,
and at the scanner level **64 concurrent readers, 64 dials** (§9, mutations 1-2;
the pre-fix code contained both defects at once).

And the window was not rare. `Init` deliberately clears the status cache so the
next read re-pings, which means every boot and every reconfigure reopened it —
and `Init`'s own ping held the scanner's **write lock** across that dial:
**measured 30.03 s of startup delay** against a silent daemon, before the proxy
listener came up at all.

The fix: one probe goroutine at a time, under its own 5 s budget, on its own
context, panic-guarded; callers wait at most 750 ms and are then answered from
the previous observation, or — only before any observation exists — with a value
that reads as unreachable on every surface that consumes it.

---

## 2. Failure scenarios

| # | Scenario | Pre-fix behaviour | Post-fix behaviour |
|---|---|---|---|
| 1 | Daemon blackholed (packets dropped, or accepts and never answers); unauthenticated `GET /health` at rate R | R x ~60 s concurrent dials + goroutines + sockets; the probe cannot be cancelled by the client going away | One dial per `clamStatusTTL`; every request answered within 750 ms |
| 2 | Same, with the daemon merely SATURATED (clamd at `MaxThreads`) | Ping flood fills the daemon's connection queue → real scans fail → content forwarded **UNSCANNED** | The probe cannot be the thing that saturates the daemon: one connection, 5 s, independent of request rate |
| 3 | Orchestrator liveness probe (1 s timeout) during a daemon outage | `/health` answers in up to ~60 s → a **healthy** gateway is restarted | `/health` answers from memory; the AV outage shows as `clamav: unreachable`, which is what the probe is for |
| 4 | Boot (or reconfigure) with a silent daemon | `Init` holds the scanner's write lock for up to 30 s before the proxy listener starts — measured 30.03 s | `Init` returns immediately; the observation lands asynchronously |
| 5 | Daemon dies at RUNTIME | Failing `/ready` row with **no log line anywhere** (the gap `healthcheck.go`'s own comment records) | The probe logs the transition, naming the fail-open consequence |
| 6 | TTL expiry on a healthy-but-slow daemon | n/a (every caller dialed) | Previous observation served, counted in `..._stale_total`; the row does not flap |
| 7 | Client disconnects mid-probe | Probe runs to its ~60 s budget regardless | Probe is not on the caller's context: it completes and stores its observation (a caller must not be able to keep the status unobserved by disconnecting) |
| 8 | Probe panics | Detached-goroutine panic ⇒ **process death** (an in-line security gateway) | `obs.SafeCall` contains and reports it; the flight is released so the next read can probe |

---

## 3. Risk matrix

| Risk | Likelihood (pre-fix) | Impact | Detectability (pre-fix) | Post-fix |
|---|---|---|---|---|
| AV scanning suppressed fleet-wide by unauthenticated traffic | Medium — needs a sick daemon plus traffic; both are ordinary | **Critical** — malware forwarded, fail-open, per node | Poor: `culvert_clam_scan_errors_total` rises, attributing it to the daemon, never to the probe path | Removed: dial rate is decoupled from request rate |
| Healthy gateway restarted by its own liveness probe | High whenever the daemon is sick | High — every in-flight tunnel dropped | Poor: looks like a gateway fault | Removed: `/health` is a memory read |
| Goroutine/FD exhaustion from parked probes | Medium | High | Partial (`culvert_goroutines`) | Bounded at one probe |
| Startup stalled up to 30 s with the scanner's write lock held | High on a sick daemon | Medium — delayed protection, and per `Init`'s own comment a future runtime caller would freeze all scanning | None | Removed |
| Status silently stale forever | n/a | Medium | None | Counted (`..._stale_total`) and logged on transition |

---

## 4. Recovery assessment

- **Automatic.** A probe that fails stores `unreachable: <cause>`, which fails
  the `/ready` row and feeds the existing operator path. The next read after the
  TTL probes again, so recovery is observed within one TTL of the daemon coming
  back, with a transition log line both ways. No operator action is needed for
  the status plane itself.
- **Manual.** Fixing the daemon. Unchanged, and the runbook is unchanged.
- **Deterministic?** Yes, and that is the change. Pre-fix, the number of dials
  and the time to answer were both functions of the arriving request rate.
  Post-fix both are functions of constants: at most one dial per
  `clamStatusTTL`, at most `clamStatusWait` per caller.
- **Ordering invariant.** `clamStatusWait` (750 ms) must stay below
  `clamStatusProbeBudget` (5 s), or a caller's bound becomes the probe's bound
  and the dial rate follows the request rate again.
  `TestChaos116_ProbeCarriesItsOwnBudgetNotTheScanTimeout` asserts the ordering
  directly, so a later edit to either constant fails a gate rather than quietly
  restoring the defect. (This is the shape CHAOS-115 §10.5 recorded as missing
  for its own pair of constants.)

---

## 5. Operational impact

- `/health` and `/ready` latency stops depending on the AV daemon. Monitoring
  predicates are unchanged: `coarseClamAVStatus` still publishes only
  `disabled` / `connected` / `unreachable`, pinned by the existing disclosure
  tests and by a new gate of this round.
- Three new series. `culvert_clamav_status_probes_total` is the dial rate (one
  per TTL on a healthy node); `culvert_clamav_status_probe_coalesced_total` is
  the amplification that no longer reaches the daemon — its ratio to probes IS
  the storm; `culvert_clamav_status_stale_total` rising means the daemon answers
  slower than 750 ms.
- One new log line, on transition only: an AV daemon that dies at runtime now
  says so in the log, naming the fail-open consequence. The producer's rate is
  the TTL, and only changes are logged, so a steady state is silent.
- **Behaviour change to note in an upgrade:** for the first few milliseconds
  after a cold `Init`, before the first observation lands, the `/ready` `clamav`
  row reports `fail`. That is readiness doing its job — the node has not yet
  reached a security control — and `Init`'s warm-up probe starts before the
  listeners do. An orchestrator that gates traffic on `/ready` will see one
  extra not-ready sample at boot on a slow daemon.

---

## 6. Security impact

The pre-fix path let an **unauthenticated** client degrade a security control on
every node it could reach, with no credential, no policy bypass and no exploit —
only requests to the documented liveness endpoint. The fail-open is not an
inference: `internal/secscan` logs it (*"forwarding UNSCANNED (fail-open)"*) and
counts it (`statClamScanError`), and `clamav.clamSem`'s own comment names
protecting the daemon as the reason that limit exists — which the probe path
bypassed.

The fix keeps every posture decision already recorded and adds none:

- **Fail closed on the unknown.** `clamStatusUnknown` is reachable only before
  any observation exists, and it reads as a failure everywhere:
  `coarseClamAVStatus` collapses anything that is not `disabled`/`connected` to
  `unreachable`, and `computeReadiness`'s switch takes its failing default
  branch. Gated from both ends.
- **No new disclosure.** The new status string never reaches the unauthenticated
  surface verbatim; the `/ready` detail stays the fixed operator sentence.
  `TestChaos116_UnauthenticatedHealthKeepsTheCoarseEnum` and the leak sweep in
  `TestChaos116_ReadinessFailsClosedWhileTheDaemonIsUnobserved` hold it, beside
  the existing `readyz_detail_disclosure_test.go` suite.
- **A caller cannot suppress the probe.** The probe is deliberately NOT on a
  caller's context. If it were, an unauthenticated client could keep the status
  permanently unobserved by disconnecting mid-probe — the fail-open state this
  fix closes, re-entered through the cancellation path.

---

## 7. What was fixed

1. **`internal/clamav`: `PingContext(ctx)`.** The bounded ping, reusing the scan
   path's own reviewed `effectiveDeadline` and `watchCancel` helpers rather than
   duplicating them: the deadline applied is the earlier of the caller's and
   `now+timeout`, so a context can only ever TIGHTEN the existing bound, and a
   cancelled context closes the socket because a blocking `Read` cannot be
   interrupted any other way. `Ping()` delegates with `context.Background()` and
   is behaviourally unchanged for every existing caller.
2. **`internal/secscan`: a single-flight probe.** `startClamStatusProbe` returns
   the in-flight handle and starts a probe only if none is running;
   `runClamStatusProbe` dials under `clamStatusProbeBudget` on
   `context.Background()`, stores the observation, and logs transitions.
   `ClamAVStatus` waits `clamStatusWait`, then falls back to the previous
   observation (counted) or `clamStatusUnknown`.
3. **`internal/secscan`: `Init` no longer pings inline** under the write lock. It
   starts the same probe, which both removes the startup stall and warms the
   cache before the listeners come up.
4. **`metrics.go`: three series** for the probe plane.

Deliberately NOT done: a background refresher. It would need its own lifecycle
and its own CHAOS-105 guard registration, and it would change the documented
"re-pings on cache miss" contract that `healthcheck.go`'s readiness comment
points operators at. Single-flight plus a caller bound achieves the same dial
rate with no new worker.

---

## 8. Also verified this round, NOT fixed

Each item below was reached by this round's discovery sweep and then checked
against the source. The verification column is exact, because the difference
matters: *reproduced* means a failing reproduction was run on this tree,
*source-verified* means every link in the chain was read at this revision, and
*reported* means it came from a parallel investigation and is recorded for the
next round without independent confirmation.

**8.1 `cluster.json` with a `null` map VALUE is process-fatal, and it persists
— so it is a crash loop.** *(reproduced)* `ClusterStore.Load` normalises nil
MAPS ([enrollment.go:150-165](../../enrollment.go)) but not nil VALUES inside
them, and `{"nodes":{"dp-1":null}}` is valid JSON, so CHAOS-07's quarantine —
which fires on a PARSE failure — does not. `checkNodeLiveness` then dereferences
`node.Status` ([enrollment.go:674-678](../../enrollment.go)) and `tokenExpired`
dereferences `tok.Used` ([enrollment.go:704-709](../../enrollment.go)).
Reproduced directly: `Load` accepts the document and `checkHeartbeats` panics
with a nil pointer dereference, for a null node and for a null token. The
consumer is `StartHeartbeatMonitor`'s detached, **unguarded** 30 s ticker loop
([enrollment.go:639-650](../../enrollment.go)), started on control-plane
activation ([cp_grpc_activation.go:168](../../cp_grpc_activation.go)), so the
panic terminates the process — and the poison is on disk, so it recurs 30 s
after every restart. `ImportFullState` has the same one-level-too-shallow
defence ([enrollment.go:744-758](../../enrollment.go)) and persists what it
imports, so an HA leader can propagate it. This is the THIRD instance of a class
the repository already tracks twice: the top-level nil maps in `Load`, and
`CARotation.RenewedNodes`, whose own regression test
([qa_gate_test.go:329](../../qa_gate_test.go)) calls it "a second nil-map class
defect".

**8.2 Six detached ticker loops are outside the panic-containment framework, and
the registry that was supposed to assure coverage cannot discover them.**
*(source-verified)* `chaos105Workers`
([chaos105_worker_guard_test.go:137-141](../../chaos105_worker_guard_test.go))
is a hand-written five-entry list; it proves those five are guarded and says
nothing about any other worker. An AST sweep of every `go` statement in package
main finds **32 ticker-loop goroutine sites**, of which these six have no guard
on their round:

| Loop | Started at | Round |
|---|---|---|
| `startSyslogHealthWatchdog` | `background_services_startup.go:38` | `evaluateSyslogDegradation()` |
| `ClusterStore.StartHeartbeatMonitor`'s literal | `enrollment.go:640` | `cs.checkHeartbeats()` — see 8.1 |
| `telemetryRuntime.flushLoop` | `mcp_telemetry.go:301` | `t.mgr.FlushDenials(...)` |
| `telemetryRuntime.exportLoop` | `mcp_telemetry.go:305` | `t.exportStep(ctx, part)` |
| `runInspectionCARecoveryLoop` | `rootca_recovery.go:337` | `tryInspectionCARecovery(...)` |
| `runIdPMetadataDegradationWatchdog` | `ui_access_policy_startup.go:116` | the sweep + ceiling enforcement inline |

Three of the six are the exact inversion CHAOS-105's own header names — a
non-essential observability loop able to kill the data plane it reports on — and
the IdP one is not observability at all: it ENFORCES the metadata staleness
ceiling. The replacement for a list is a discovery gate: enumerate the
ticker-loop goroutines mechanically and require each to reach a guard or carry an
explicit, reasoned exemption.

**8.2a The obvious fix for two of them is worse than the bug.** *(source-verified)*
`checkHeartbeats` takes `cs.mu` and releases it with a plain
`cs.mu.Unlock()` at the end, not a `defer`
([enrollment.go:654-670](../../enrollment.go)); `syslogFeedState` and
`commitSyslogDegradation` have the same shape. Today a panic there kills the
process, so the lock does not matter. Add a round guard WITHOUT converting those
releases to `defer` and the panic is contained into a permanently held
`ClusterStore` lock: every enrollment, heartbeat and admin read blocks forever —
no crash, no restart, no alert, which is precisely the silent-stall outcome
`internal/obs/guard.go`'s header warns about. Any round that takes 8.2 must pair
each guard with deferred release and pin it with a post-panic usability test.

**8.3 A state file that is PRESENT but unreadable is treated as a file that is
ABSENT.** *(source-verified for the roster chain; the overwrite and
row-precedence legs are reported)* `loadUIUsersFile` returns a bare error on any
non-`ENOENT` read error ([store.go:1772-1779](../../store.go)), `loadAuth` only
logs it ([auth_startup.go:48-50](../../auth_startup.go)), so `cfg.uiUsers` stays
empty and `IsConfigured()` is false on an appliance whose admins were created
through the GUI ([store.go:1295-1300](../../store.go)). `durableSetupComplete`
then treats every read error as "not complete"
([setup_bootstrap_window.go:79-85](../../setup_bootstrap_window.go)), so
`bootstrapWindowOpen()` is true and the first-run window — an unauthenticated
`RoleAdmin` grant — is open on a node whose roster file is intact but, say,
owned by the wrong uid after a volume re-attach. Note that the same file
deliberately leaves the window open for a CORRUPT roster, and says so; the
distinction this finding rests on is that corrupt is *provably* not a usable
roster and is quarantined (so the accounts survive), while unreadable means
*unknown* — the roster may be full of admins — and nothing is set aside. The
reported legs still to confirm: that `readRosterDurabilityFacts`' early return
on `!IsConfigured()` ([diagnostics.go:1329-1331](../../diagnostics.go)) makes
the row read `ok / setup incomplete` instead of the "configured but unusable
roster" state that exists for this, and that completing the wizard can rename a
new roster over the unreadable one (a rename needs only directory permission —
the property `state_corruption.go:32` already notes). The same
unreadable-is-absent shape appears in `ClusterStore.Load`, which adopts
`cs.path` at [enrollment.go:128](../../enrollment.go) BEFORE the read and leaves
the state empty on a read error, where `PolicyStore.Load`'s recorded posture is
that the old path and rules stand untouched.

**8.4 Reported, not verified here.** `swapCatalogDir` moves the live catalog to
`.bak` before installing the staged one and nothing ever reads that name again,
while the next seed's first statement is `os.RemoveAll(bak)`
([release_autoseed.go:110-132](../../release_autoseed.go)) — so a kill inside
the swap window leaves the only copy at `.bak`, and the next boot deletes it.
`catgroup.Store.Load` treats every read error as first-run
([internal/catgroup/catgroup.go:433-436](../../internal/catgroup/catgroup.go)),
emptying the store with no log line, which makes an enabled category-group DENY
rule stop denying. Crash-orphaned staging directories have no reaper
(`saas_feed_genstore.go:360`, `release_catalog_http.go:197`). An unsynchronised
`uiCustomTLSCorrupt` global is written from an admin handler and read by two
viewer-gated handlers (`ui_tls_custom.go:66`, `ui_security.go:405`,
`diagnostics_ui_tls_cert.go:47`). `buildOperatorContract`'s "never opens files"
contract is contradicted by its own body and by the new UI-TLS row
([diagnostics.go:160-167](../../diagnostics.go)).

---

## 9. Verification

Tested revision: this branch at the commit that adds the fix, base
`origin/main` `ac4e223`. `go env GOVERSION` = `go1.27.3`, matching `go.mod`'s
`toolchain`; `GOTOOLCHAIN=auto`.

**Mutation sweep.** Each mutation was applied to the fixed tree, the gates run,
and the tree restored. Every one is caught, and three reproduce the pre-fix
measurement exactly.

| # | Mutation | Caught by | What it reported |
|---|---|---|---|
| 1 | Remove single-flight (dial per caller) | `OneDialServesEveryConcurrentStatusReader` + the main-package flood gate | `dials = 64, want 1` / `ClamAV dials = 48 for 48 unauthenticated /health requests` — the pre-fix dial counts |
| 2 | Remove the caller's bounded wait | `NoCallerWaitsOnTheDaemonsNetworkPath` | `panic: test timed out after 40s` — the caller blocks indefinitely, which IS the pre-fix behaviour |
| 3 | Drop the stale fallback | `StaleObservationIsServedWhileRevalidating` (+1) | `status = "unknown: ..." while revalidating, want the previous "connected"` |
| 4 | Make the unknown value read as `connected` | `NoCallerWaitsOnTheDaemonsNetworkPath` + `NothingClaimsHealthBeforeTheFirstObservation` | `status = "connected" while the daemon has never answered` |
| 5 | Remove `obs.SafeCall` | `PanickingProbeIsContainedAndTheFlightIsReleased` | `panic: status probe exploded` — the **test binary died**, which is what would happen to the gateway |
| 6 | Restore `Init`'s inline ping | `InitDoesNotBlockOnABlackholedDaemon` | `Init took 30.029434007s against a silent daemon` — the measured pre-fix stall |
| 7 | Probe with no budget | `ProbeCarriesItsOwnBudgetNotTheScanTimeout` | `the probe passed no deadline: an unbounded status dial is the defect` |

Mutation 5 is the one worth reading twice: the guard's absence is not reported
as a failing assertion but as the death of the process running the assertions.

**The whole pre-fix tree was also measured directly**, not only through
mutations: with `internal/secscan/secscan.go` and `metrics.go` restored from
`origin/main` (both, because `metrics.go` now reads the new counters and the
package would not otherwise build), the main-package flood gate fails with *"48 unauthenticated /health requests did not
complete while ClamAV was silent"* after 10 s. That is the defect as shipped:
the two mutations above separate its two causes, and this run shows them
together.

**Commands and results.**

- `go vet ./...` — clean. `go mod tidy -diff` — clean.
- `CGO_ENABLED=0 go build -ldflags="-s -w" -o culvert .` — ok;
  `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o /dev/null .` — ok.
- `TEST_SEED=20260421 go test ./... -count=1 -timeout=30m` — **117 packages ok,
  0 failures**, root package ok in 522.6 s.
- `go test -race -shuffle=on -count=2 -timeout=20m ./internal/secscan ./internal/clamav`
  — ok (91.6 s / 22.8 s).
- `go test -tags benchgate -run 'TestBenchGate_' -count=1 -p 1 -timeout=10m`
  over all eight benchgate-owning packages — ok. `internal/secscan`'s three
  gates were confirmed to actually RUN (`-v`), not filtered out.
- `python3 docs/agent-context/check.py` — passes (no guidance path changed; run
  as a control).

**Lint, measured in both directions** — the repository's own rule, because
`cyclop`, `funlen` and `gocognit` attribute to a function's DECLARATION line, so
`--new-from-rev` cannot see a function made more complex. golangci-lint
`v2.15.0`, the version `pr-fast-gate.yml` installs, built with the `go.mod`
toolchain. (The container's `golangci-lint` on `PATH` is `v2.5.0` and PANICS on
this module — the exact failure `conventions.md` records as having been
repeatedly mistaken for "local lint is unavailable". The pinned binary was
invoked by absolute path.)

- The gate's own command, `run --timeout=10m --new-from-rev origin/main`:
  **0 issues**. Seven were found on the first pass — all in the new test files —
  and all seven were FIXED rather than suppressed: named results on three fake
  `Scan` methods, `httptest.NewRequestWithContext` for three handler calls, and
  `(&net.ListenConfig{}).Listen` for the blackhole listener.
- Full tree on this branch: **174 issues**, all pre-existing, which is the same
  total CHAOS-115 recorded. Two land in a file this change touches, and neither
  names anything it adds: `metrics.go:823` errcheck (inside the pre-existing
  `Fprintf`, 88 lines above the edit) and `handleMetrics` gocognit 51.
- The declaration-attributed check, measured directly rather than argued:
  `--default=none --enable=gocognit,cyclop,funlen .` in a clean worktree of
  `origin/main` and on this branch — **162 issues on both**, and
  `handleMetrics` cognitive complexity **51 on both**. The change adds three
  `# HELP`/`# TYPE`/series lines inside an existing raw string literal and three
  arguments to the same call, so it adds no control flow; the measurement
  confirms it.

**Gates added (13).**

`internal/secscan/clam_status_probe_chaos116_test.go` (9):
`OneDialServesEveryConcurrentStatusReader` (the reproduction, plus the coalesced
accounting), `NoCallerWaitsOnTheDaemonsNetworkPath`,
`StaleObservationIsServedWhileRevalidating`,
`AFreshObservationReplacesTheStaleOne`,
`NothingClaimsHealthBeforeTheFirstObservation`,
`TheProbeOutlivesTheCallerThatStartedIt`,
`ProbeCarriesItsOwnBudgetNotTheScanTimeout` (including the two constant
orderings, so a later edit cannot quietly restore the defect),
`OrdinaryDaemonIsUnaffected` (negative control: one dial per TTL, zero stale
reads, and a genuinely-down daemon still reports its cause) and
`PanickingProbeIsContainedAndTheFlightIsReleased`, plus
`InitDoesNotBlockOnABlackholedDaemon` driven through a real loopback listener
that accepts and never answers.

Package `main`, `clam_status_probe_chaos116_test.go` (4):
`UnauthenticatedHealthFloodDialsTheDaemonOnce` (48 concurrent requests through
the REAL handler — the gate that would have caught the defect),
`UnauthenticatedHealthKeepsTheCoarseEnum` (disclosure control),
`ReadinessFailsClosedWhileTheDaemonIsUnobserved` (the posture decision, plus a
leak sweep on the detail) and `ProbeAccountingReachesMetrics`.

**Not run.** The Deep determinism lane
(`go test -count=2 -shuffle=on -timeout=20m ./...`) and the sharded race/coverage
lanes were not run locally: the single-count full module run and a race+shuffle
double run of the two changed packages were run instead. The frontend tree, the
`cmd/culvert-maint` module and the API-contract lanes were not run — no file in
either tree or in `api/` changed. A local pass is not aggregate CI approval; the
hosted gates decide.

---

## 10. Residual risk

1. **A `ClamScanner` that does not implement `PingContext` keeps the unbounded
   ping.** The shipped `*clamav.Client` implements it and the fallback exists
   only for injected fakes — but it is a fallback, and it is the shape
   `clamVersioner` already established, so a future collaborator could be
   written without it and silently lose the budget. The type assertion is in one
   place and the probe is still single-flighted, so the exposure is one
   unbounded goroutine rather than one per request.
2. **`clamStatusWait` is a chosen number.** 750 ms is below a typical
   orchestrator probe timeout and far above a healthy ping, but it is not
   derived from anything. A deployment whose daemon genuinely answers in ~1 s
   (a loaded remote clamd over a congested link) will see every TTL expiry
   served from the previous observation and `..._stale_total` climbing, which is
   honest but will read as a problem.
3. **A cold `/ready` can report `clamav: fail` for a few milliseconds after
   `Init`.** The warm-up probe starts before the listeners, so traffic normally
   arrives after the first observation; a daemon slower than the gap between
   `Init` and the first probe will produce one not-ready sample. This is
   deliberate (an unobserved security control must not read as ready) and is
   gated, but it is a behaviour change at boot.
4. **The status plane is observable; the probe plane's SATURATION is not
   alerted.** No alert fires on `..._stale_total` leaving zero or on the
   transition line. The existing `/ready` row and the AV alerts carry the
   outage itself, which is the operator-actionable fact; a rule on the new
   series is suggested rather than shipped, for the reason CHAOS-115 §8.7 gave
   about instantaneous versus cumulative inputs.
5. **Every other unauthenticated builtin route still does per-request work.**
   This round bounded the ClamAV dial because it reaches a security control and
   a remote daemon. `/metrics` on the same unauthenticated dispatcher still
   performs an `os.Stat` per scrape and takes all 64 `connlimit` shard locks via
   `ActiveIPs()`; on a wedged mount an uncancellable `Stat` parks the handler
   goroutine, which `WriteTimeout` does not reclaim. The per-scrape stat itself
   is a recorded, closed decision (register row AU-39); the residual is the
   uncancellable wait on a sick volume, and it is unaddressed.
6. **§8.1 and §8.2 are open, and §8.1 is a persistent crash loop of the control
   plane.** It was reproduced, not fixed, because it is a different plane from
   this round's and because §8.2a shows its fix has a trap in it: the guard must
   land together with deferred lock release, or a process crash becomes a
   permanent `ClusterStore` deadlock. It is the sharpest open item in this
   document and should be the next round's.
