# Chaos Engineering Review — 2026-11-07

## CHAOS-113 — The scan sidecar listener: the one socket nobody watched is the socket that decides whether a fleet scans

**Scope.** The SIMULATE list's *SIGTERM*, *unexpected restart*, *unexpected
startup order* and *ClamAV unavailable* rows, aimed at `-scan-svc-listen` — the
last listener in the tree with no supervision of any kind.

**Status.** Three defects found, all reproduced on this tree before any fix, all
fixed. The fail-open posture at the far end is unchanged and remains the
recorded owner decision (WK-2b); what changed is that the condition which
triggers it is now observable and self-healing.

**Closes.** The scan-sidecar half of the 2026-10-13 backlog's `L-5` — the half
that row recorded as `delegated` while its Control-Plane-gRPC half was closed by
CHAOS-71.

---

## 1. Executive summary

Culvert has four listeners. Three of them have a rebind ladder, an `up` gauge,
bind/accept counters, an operator-contract row and an alert, each added by its
own round for the same reason: a listener that dies silently is a node that
reports healthy while a service is gone.

- the admin UI listener — CHAOS-57 (`admin_ui_health.go`)
- the SOCKS5 listener — CHAOS-66 / CHAOS-102 (`socks5_health.go`)
- the Control-Plane gRPC listener — CHAOS-71 (`cp_grpc_bind.go`, `cp_grpc_health.go`)

The fourth is the scan sidecar. Before this round it had **one `logger.Printf`
and a goroutine that returned**:

```go
svc := NewScanService(listenAddr)
if err := svc.Listen(); err != nil {
        logger.Printf("ScanSvc: listen error: %v", err)
        return svc                       // never serves again. Ever.
}
go func() {
        if err := svc.Start(); err != nil {
                logger.Printf("ScanSvc: error: %v", err)   // and the goroutine exits
        }
}()
```

**Why this is the sharp instance of the class rather than the leftover one.**
For the other three, a dead listener costs the availability of that surface.
For this one it costs a **security control on every other node in the
deployment**. A sidecar that is not listening is precisely the condition under
which `internal/secscan`'s `remoteScanFail` takes its fail-**OPEN** branch
(WK-2b, `internal/secscan/remote.go:148`) and the fleet forwards response
bodies **UNSCANNED**. The socket nobody watched is the socket that decides
whether a fleet scans at all — and the deployment this affects is the one the
CHAOS-52 runbook *recommends* as the remedy for a slow in-process scanner.

Three defects, in increasing order of how well they hide:

**Defect 1 — a `Shutdown` that reports success and does nothing, plus a real
data race.** `ScanService.server` was written by the goroutine running `Start()`
and read by the shutdown hook (`main_shutdown.go:392`), unsynchronised.
`Shutdown`'s `if ss.server == nil { return nil }` returned **success** when it
landed in the window before that write, having closed nothing — and the
registry discards the error anyway (`_ = s.scanSvc.Shutdown(ctx)`), so nothing
would have said otherwise. `Start()` then built its own server and served.
Measured: `/health` answered **200 after a `Shutdown` that returned `nil`**,
with the listening socket still held. Under `-race`, 50 iterations produced
**3 DATA RACE reports** (write `scan_svc.go:92` vs. reads `scan_svc.go:108`
and `:111`). This is the orchestrator-cancel-during-startup case of the
2026-10-13 backlog's `L-3`, on the one component whose "I stopped" was a lie
rather than a missed flush.

**Defect 2 — a serve loop that dies with no recovery and no trace.** Measured:
closing the listener under the serve loop returned
`accept tcp 127.0.0.1:38541: use of closed network connection`, the goroutine
was gone, **the process was alive**, and **the sidecar's own address was
free** — nothing rebound it, and no counter, gauge, health row or alert existed
anywhere in the tree to say so. A bind failure at boot was worse: one log line
and then a process that would serve nothing for its entire life, with no retry
*ever*. One further observation from the same reproduction: a caller holding a
warm keep-alive connection kept being served after the serve loop died, so the
first client to notice is whichever one next opens a connection.

**Defect 3 — the one alert that would have told anyone could not be subscribed
to.** `remoteScanFail` gates on `alerts.HasSubscriber("scan_svc_down")` before
it does any work. That gate is correct and deliberate. Its consequence is that
an event with no way to subscribe is an event that **never fires**. Measured by
differential over the tree at claim time: **13 production alert events were
fired with no checkbox in the Alerts panel**, and the scanning plane had
**one of four** subscribable (`scan_clam_error`). `scan_svc_down`,
`scan_timeout` and `scan_skipped` were all absent — and `scan_svc_down` was
absent from `internal/alerts/store.go`'s event registry too, so the string was
not discoverable from any surface the product exposes. The admin API does not
validate event names, so an operator who already knew the string could POST it
by hand; nothing told them it existed.

End to end, before this round: a scan sidecar could fail to bind at boot, or
lose its socket at hour nine, and every node pointed at it would forward
unscanned traffic indefinitely, with the sidecar's process reporting healthy, no
gauge at zero, no row failing, and the alert built for exactly this condition
structurally unable to fire.

---

## 2. Failure scenarios

### 2.1 `Unexpected startup order` / `SIGTERM` — the shutdown that was a no-op

| | |
|---|---|
| **Current behavior (pre-fix)** | `Shutdown` returns `nil` without closing anything; `Start()` then serves. Socket stays held. Plus a data race on `ss.server`. |
| **Expected** | `Shutdown` is terminal whenever it is called, and the socket is released. |
| **Failure mode** | Silent failure — the shutdown registry records a clean stop that did not happen. |
| **Recovery** | None needed on the serving side; the process is exiting. The *replacement* cannot bind the held port. |
| **Customer impact** | A rolling restart can leave the successor unable to bind, which is Defect 2's boot case. |
| **Security impact** | The 30 s drain budget is spent on nothing, so in-flight `/scan` requests are cut at process exit rather than drained. Each cut scan is a transport error at the caller, which classifies as a FAULT and therefore forwards the body unscanned (fail-open). |
| **Monitoring** | None. The registry discards the error. |

### 2.2 `Unexpected restart` / lost socket — the serve loop that dies

| | |
|---|---|
| **Current behavior (pre-fix)** | `Start()` returns, the goroutine exits, the process lives on, the address is free, nothing rebinds. |
| **Expected** | Rebind with bounded backoff; report the gap while it lasts. |
| **Failure mode** | Silent, permanent loss of the scanning plane on a live process. |
| **Recovery** | Manual only, and only once someone notices — a full process restart. |
| **Customer impact** | None visible. Traffic keeps flowing, which is the problem. |
| **Security impact** | **HIGH.** Every caller fails open (WK-2b) and forwards bodies unscanned for the whole window. |
| **Monitoring** | Nothing: no counter, no gauge, no row, no alert. One log line at the moment of death. |

### 2.3 `Permission denied` / port held — the bind that never retried

Identical to 2.2 except that `EverBound` is false, so there is not even a
"this used to work" signal in the process log's history. A port held by a
draining predecessor — the exact trigger CHAOS-66 fixed for SOCKS5 — produced a
sidecar that served nothing for the life of the process.

### 2.4 `Silent failures` — the alert that could not be subscribed to

| | |
|---|---|
| **Current behavior (pre-fix)** | `HasSubscriber("scan_svc_down")` is always false, because no UI surface offers the event. The producer returns before building a payload. |
| **Expected** | Every event the code fires is subscribable from the panel that lists events. |
| **Failure mode** | A dead alert path that looks implemented in source review. |
| **Security impact** | The fail-open scanning fault had counters and a rate-limited log, and no page. |

### 2.5 Already-correct behavior, and why

Worth stating, because most of this plane is right and the round should not be
read as finding it broken:

- **The client's posture classification is correct and hard-won.**
  `internal/secscan/remote.go`'s three-way `verdict / budget-or-capacity /
  fault` split is the CHAOS-52/53 fix: a scan that is merely *slow* fails
  **closed** against the process's own budget, and only an actual fault fails
  open. A sidecar that is *down* is a fault, so fail-open is the posture by
  design, not by accident.
- **The client's observability is thorough.** `culvert_remote_scan_fail_total`,
  `culvert_remote_scan_saturated_total` and `culvert_remote_scan_inflight` all
  exist; the log line is rate-limited by the same `degradedLogAllowed` CAS the
  engine uses; the alert detail is a bounded class precisely *because* a
  transport error embeds the ephemeral local port and could not dedup.
- **A verdict must be affirmative.** `if !sr.Clean { … remoteFaultNoVerdict }`
  closes the silent-admission case where any JSON-parsing 200 was read as clean.
- **The reply is bounded** (`maxRemoteScanResponse`, `maxRemoteStatusResponse`),
  and the hash is computed from the bytes actually scanned, never taken from
  the reply — so a compromised sidecar cannot name objects in the operator's UI.

None of that helps when the socket is gone, which is what this round is about.

---

## 3. Risk matrix

| # | Scenario | Likelihood | Impact | Pre-fix severity | Post-fix |
|---|---|---|---|---|---|
| 1 | Sidecar never binds at boot (port held by a draining predecessor) | **High** — the ordinary redeploy | Fleet-wide fail-open scanning, indefinitely | **HIGH** | Rebinds; `warn` inside the 30 s threshold, then `up 0`, FAIL row and alert |
| 2 | Serve loop dies at runtime (lost socket, fd exhaustion, interface teardown) | Medium | Fleet-wide fail-open scanning, indefinitely | **HIGH** | Rebinds; counted and surfaced |
| 3 | SIGTERM during sidecar startup | Medium — every orchestrated restart | Held port → scenario 1 for the successor; severed in-flight scans | **MED** | `Shutdown` is terminal; socket released |
| 4 | Data race on `ss.server` | Low (observable), always present (latent) | Undefined behavior on the shutdown path | **MED** | Removed; gated under `-race` |
| 5 | `scan_svc_down` unsubscribable | **Certain** | The scanning plane's fail-open fault cannot page | **MED-HIGH** | Subscribable; registry documented |
| 6 | Ten other events unsubscribable | **Certain** | Per-plane; owner decision each | **MED** | **Recorded, not fixed** — pinned by a gate |

---

## 4. Recovery assessment

| | Pre-fix | Post-fix |
|---|---|---|
| **Automatic recovery** | None, in either direction. A bind failure was permanent; a serve death was permanent. | Bind → serve → rebind, 1 s doubling to a 30 s ceiling, ±25% jitter, ladder reset after a 60 s stable serve. |
| **Manual recovery** | Full process restart, once someone noticed by other means. | Still available; rarely needed. |
| **Determinism** | n/a | The ladder is pure (`nextScanSvcBindBackoff`, `scanSvcBackoffAfterServe`) and pinned without a clock. |
| **Stop ownership** | Ambiguous — `Shutdown` could run before the thing it shuts down existed. | Explicit: `Shutdown` is terminal, `Listen` refuses afterwards, and the supervisor observes both `ctx` and `stoppedByShutdown()`. |
| **Fail-closed where recovery is impossible** | n/a | Deliberately **not** applied here. Supervision is recovery; the far end's refusal posture is WK-2b's owner decision and is unchanged. |

The jitter is not decoration. A fleet restarted together would otherwise retry
in phase against whatever is holding the port — the property
`internal/feedsched` exists to hold for feed loops, applied to this listener for
the same reason.

---

## 5. Operational impact

**New surfaces, all gated on the sidecar being configured** — a node that never
ran a sidecar exports nothing, for the reason the `socks5_listener` and
`cluster_ca` gauges document: `up 0` on a node with no sidecar is
indistinguishable from a dead one.

- `culvert_scan_svc_listener_up` — paging rule `== 0`. **This is the one gauge
  in `metrics.go` whose zero means a security control is off rather than a
  surface being unavailable.**
- `culvert_scan_svc_listener_down` — 1 past the 30 s unavailability threshold.
- `culvert_scan_svc_bind_failures_total`, `culvert_scan_svc_serve_exits_total`
- `culvert_scan_svc_bind_backoff_seconds`
- Operator-contract row `scan_svc_listener`, beside its three siblings in
  `diagnostics.go`. Its message states what a down sidecar **costs** —
  "every caller pointed here is forwarding bodies UNSCANNED (fail-open)" —
  because an operator must not have to know the far end's posture to understand
  that scanning is off.
- `/healthz` field `scan_svc` (fixed enum
  `disabled`/`stopped`/`down`/`degraded`/`ready`), beside the `socks5`,
  `admin_ui` and `cp_grpc` fields its three siblings already publish there.
  Omitted entirely on a node that never asked for a sidecar — the `cp_grpc`
  field's rule, not socks5's always-present one, because an always-present value
  would make every ordinary proxy look like a sidecar host whose listener is
  down. Posture only: the attempt count, the bind reason class and the remedy
  stay on the role-gated `/api/diagnostics` row, because `handleHealth` serves
  this UNAUTHENTICATED on the proxy port.
- `/ready` row `scan_svc`, **report-only**, absent on a node that never asked
  for a sidecar and absent after a graceful stop. Report-only for the cp_grpc
  row's reason: a node whose sidecar cannot bind is proxying its OWN traffic
  perfectly, so gating the default verdict would eject a healthy gateway from
  rotation because the plane that scans for OTHER nodes is down — converting a
  scanning outage into a traffic outage. **Report-only is a judgement about
  this node's rotation, not about whether unscanned traffic is acceptable**;
  that consequence is carried by the role-gated contract row, the alert and the
  gauge, which is where a security decision belongs rather than in a
  load-balancer probe. Strict callers opt in via `?strict=1`.
- Alert `scan_svc_listener_down`, once per episode, detail = bounded bind class.
- Four new Alerts-panel checkboxes: `scan_svc_listener_down`, `scan_svc_down`,
  `scan_timeout`, `scan_skipped`.

**Threshold choice, and the bug this round shipped in its first form.** 30 s
before the row fails and the alert fires, matching the Control-Plane listener's,
for the same reason: shorter, and an ordinary restart of a colocated
predecessor holding the port would page someone. A sidecar that is merely
rebinding inside the threshold stays `up 1` with a `warn` row — the same
asymmetry `culvert_socks5_listener_up` carries.

**`EverBound` chooses WHICH fail row and remedy, never WHETHER there is one.**
The first form of this change had `!EverBound && BindFailures > 0` as its own
fail arm, in both the contract row and the gauge — so a sidecar whose port was
briefly held at boot failed its row and exported `up 0` on its FIRST failed
bind, i.e. paged on every ordinary redeploy. That is precisely the condition
CHAOS-66 added the threshold for on SOCKS5, whose never-bound branch is likewise
gated on `BindUnavailable` rather than on the first attempt. It passed every
other gate, because the only rebinding control covered the `EverBound` path —
`TestChaos113_ControlRebindingSidecarDoesNotPage` drove a sidecar that HAD
served. Found by re-reading this round's own gate, not by a gate.
`TestChaos113_ControlNeverBoundInsideThresholdDoesNotPage` is the missing
direction, and M15/M16 in §9.6 are the two mutations that reintroduce it.

---

## 6. Security impact

The chain this round breaks, stated once and plainly:

1. A sidecar listener dies or never binds.
2. Nothing in the sidecar's process rebinds it, counts it, gauges it, fails a
   row for it or alerts on it.
3. Every node pointed at that address classifies the resulting transport error
   as a **fault**, not a budget overrun — correctly, per CHAOS-53.
4. A fault is fail-**OPEN** (WK-2b): the response body is forwarded
   **UNSCANNED**.
5. The caller counts it and writes a rate-limited log line, and fires the one
   alert built for this condition — except that `HasSubscriber("scan_svc_down")`
   is false on every deployment, because the panel that lists subscribable
   events does not list it.

Steps 2 and 5 are now closed. Step 4 is deliberately unchanged: converting a
sidecar fault to a refusal is a posture change for every large download on
every node, and it belongs to the owner, not to the round that made the
condition visible. It is recorded in §8.2.

Nothing in this round weakens a control. The sidecar's `/health` and `/status`
remain unauthenticated, which is the documented, opt-in trust model of
`-scan-svc-listen` (and which the 2026-11-05 regression review had just
re-stated); adding a role check there would change a deliberate deployment
contract and is out of scope.

---

## 7. Data-integrity impact

None. This round adds no persistence, changes no wire format and touches no
stored state. The sidecar holds no durable state: its verdict cache is the
caller's (`internal/hashcache`), and the hash is recomputed by the caller from
the bytes it actually scanned.

One durability-adjacent improvement falls out of Defect 1's fix: a `Shutdown`
that now actually closes the listener releases the port for the successor,
which is what a rolling restart depends on.

---

## 8. Suggested improvements (left open, attributed rather than fixed)

### 8.1 The ten other GUI-unsubscribable alert events (MED) — the highest-value remainder

`admin_ui_unavailable`, `cdr_unavailable`, `disk_critical`, `dns_failure`,
`ha_lease_reacquired`, `ha_manual_failover_required`, `ha_resume_unfenced`,
`ha_self_fenced`, `pac_profile_degraded`, `yara_degraded`.

Each belongs to a plane this round does not own, and each needs an owner
decision about wording and severity in the panel — a checkbox is an
operator-facing contract, not a string. They are recorded in **executable**
form, in `scanAlertGUIKnownGaps`, with two gates:
`TestChaos113_EveryFiredAlertIsSubscribableInTheGUI` stops a *new* event from
joining the list by accident, and `TestChaos113_KnownAlertGUIGapsAreStillGaps`
fails if an entry has since been fixed or is no longer fired, so the list can
only get shorter and cannot rot into a list of things that are fine.

Note the asymmetry that makes this worth a sweep of its own: the drift is
**one-way**. Every event the panel offers *is* fired by production code; it is
only the reverse direction that leaks. That is the signature of events being
added to code without the panel, which is a process gap, not ten independent
mistakes.

### 8.2 The fail-open posture itself (WK-2b) — owner decision, unchanged

A sidecar fault forwards the body unscanned. With supervision and an alert in
place, the argument for a *refusal tier* (fail closed once the sidecar has been
unavailable for longer than some operator-set window) is stronger than it was,
because an operator would now see it coming. It is still a posture change for
large downloads that no operator asked for. Recorded, not taken.

### 8.3 A caller-side `remote_scan` operator-contract row (MED)

This round gave the sidecar's own process a health row. The **caller** — the
proxy that is actually failing open — still has none: it has three metrics and
a rate-limited log, and now a subscribable alert, but no row in the
operator-contract report. A node delegating scanning to an unreachable sidecar
reports a clean diagnostics report. Narrower than it sounds (the counters
exist; the row is a presentation of them) and deliberately left to the plane's
owner.

### 8.4 Converge the three bind-error classifiers (LOW)

`classifySOCKS5BindError`, `classifyAdminUIListenError` and this round's
`classifyScanSvcBindError` are the same errno switch three times, including the
same narrowed `net.Error`-must-be-a-timeout branch that each had to learn
separately. A chaos round should not refactor two other listeners' hardened
classifiers to add a third; the extraction is a clean follow-up with three
existing test suites to hold it.

### 8.5 Make the sidecar's rebind ceiling an operator setting (LOW)

`scanSvcBindBackoffMax` (30 s) and `scanSvcUnavailableAfter` (30 s) are
constants, matching the Control-Plane listener's. Neither is operator-settable
there either, so this is a consistency item rather than a gap.

### 8.6 The sidecar has no `up`-equivalent on its own `/health` (LOW)

`/health` answers 200 whenever it answers at all, which is tautological for
liveness and is fine. The listener state is now on `/metrics` and the contract
row; teaching `/health` to report the supervisor's view would help a probe that
only has `/health`. Minor.

### 8.7 Close the unavailability episode on a STABLE SERVE, not on a bind (MED)

The flapping-sidecar gap in §10.4. `noteScanSvcBound` clears `firstFailure` and
the `alerted` latch when the bind succeeds, so a socket that binds and dies
immediately resets the episode every cycle and never crosses the 30 s
threshold. Moving that reset to the post-serve path, gated on
`scanSvcServeStableAfter`, is the correct shape and is a small change — but it
is a state-machine change to a surface this round just added, it needs a flap
gate plus a control proving an ordinary redeploy still does not page, and it is
exactly the kind of same-round follow-on that produces an alert that is wrong in
the other direction. Until then, alert on
`increase(culvert_scan_svc_serve_exits_total[15m]) > 3`, which is monotonic
through a flap.

---

## 9. Measurements and commands

All reproductions were run on this tree, at the pre-fix shape, before any fix
was written.

### 9.1 RED — the shutdown that reported success (baseline)

```
--- FAIL: TestRedA_ShutdownBeforeServeIsASilentNoop
    Shutdown returned nil (success) with server==nil
    RED: sidecar answered /health with 200 AFTER a successful Shutdown
```

### 9.2 RED — the serve loop that died unsupervised (baseline)

```
--- FAIL: TestRedB_ServeDeathIsUnsupervised
    RED: Start() returned accept tcp 127.0.0.1:38541: use of closed network
         connection — goroutine gone, process alive
    unexpected: something is still serving 127.0.0.1:38541      <- a warm keep-alive
    RED: the sidecar's own address is FREE — no rebind was attempted
```

The middle line is itself a finding: a caller with a pooled idle connection
kept being served after the serve loop died, so the first client to notice is
whichever one next opens a connection. The post-fix gates therefore probe with
`DisableKeepAlives` transports — without that, a dead sidecar "answers".

### 9.3 RED — the data race (baseline, `-race`, 50 iterations)

```
WARNING: DATA RACE   (x3)
  write  /home/user/Culvert/scan_svc.go:92     (ss.server = &http.Server{...})
  read   /home/user/Culvert/scan_svc.go:108    (Shutdown: if ss.server == nil)
  read   /home/user/Culvert/scan_svc.go:111    (Shutdown: ss.server.Shutdown)
```

Reachable from production at `main_shutdown.go:392`.

### 9.4 RED — the alert differential (baseline, source scan)

13 production alert events fired with no Alerts-panel checkbox. Scanning plane:
1 of 4 subscribable. `scan_svc_down` additionally absent from
`internal/alerts/store.go`'s event registry.

```
admin_ui_unavailable  cdr_unavailable  disk_critical  dns_failure
ha_lease_reacquired   ha_manual_failover_required     ha_resume_unfenced
ha_self_fenced        pac_profile_degraded            scan_skipped
scan_svc_down         scan_timeout                    yara_degraded
```

Drift in the other direction: **zero**. Every event the panel offers is fired.

### 9.5 GREEN — the same conditions under the fix

```
=== RUN   TestChaos113_ServeDeathRebinds                      PASS (1.19s)
=== RUN   TestChaos113_NeverBoundIsVisibleAndAlerts           PASS (0.93s)
=== RUN   TestChaos113_DownAlertFiresOncePerEpisode           PASS
=== RUN   TestChaos113_ControlRebindingSidecarDoesNotPage     PASS
=== RUN   TestChaos113_ControlHealthySidecarIsSilent          PASS
=== RUN   TestChaos113_GracefulStopIsNotAnOutage              PASS
=== RUN   TestChaos113_ControlNeverBoundInsideThresholdDoesNotPage PASS
=== RUN   TestChaos113_HealthzFieldOmittedUnlessConfigured    PASS
=== RUN   TestChaos113_ReadinessRowIsReportOnlyAndAbsentWhenUnconfigured PASS
=== RUN   TestChaos113_BackoffLadderIsBoundedAndResets        PASS
=== RUN   TestChaos113_BindErrorClassesAreBounded             PASS
=== RUN   TestChaos113_ShutdownBeforeServeIsHonoured          PASS
=== RUN   TestChaos113_ShutdownRacesTheServeGoroutine         PASS
=== RUN   TestChaos113_ListenAfterShutdownRefuses             PASS
=== RUN   TestChaos113_ShutdownConcurrentWithListenLeaksNoSocket PASS
=== RUN   TestChaos113_ControlShutdownAfterServeStillDrains   PASS
=== RUN   TestChaos113_EveryFiredAlertIsSubscribableInTheGUI  PASS
=== RUN   TestChaos113_KnownAlertGUIGapsAreStillGaps          PASS
```

`TestChaos113_ShutdownRacesTheServeGoroutine` is only meaningful under `-race`;
the suite is run both ways.

### 9.6 Mutation tests — the gates have teeth

Every gate was run against a mutation of the thing it claims to pin. A gate
that stays green under its own mutation is not a gate. Twenty-six mutations were
run; the twenty-three below are red, and the three that came back green are the most
useful thing in this section — see the note under the table.

| # | Mutation | Gate | Result |
|---|---|---|---|
| M1' | `srv.Shutdown(ctx)` is never called | `ControlShutdownAfterServeStillDrains` | **RED** |
| M2 | `Shutdown` stops closing the listener | `ShutdownBeforeServeIsHonoured` | **RED** |
| M3-pair | BOTH `stopped` checks removed from `Listen` | `ListenAfterShutdownRefuses` | **RED** |
| M3'' | only the POST-BIND `stopped` check removed | `ShutdownConcurrentWithListenLeaksNoSocket` | **RED** (gate added in response — see below) |
| M4 | supervisor becomes single-shot (the pre-fix shape) | `ServeDeathRebinds` | **RED** |
| M5 | the unavailability threshold is dropped | `ControlRebindingSidecarDoesNotPage` | **RED** |
| M6 | the down alert stops latching per episode | `DownAlertFiresOncePerEpisode` | **RED** |
| M7 | the backoff ladder loses its ceiling | `BackoffLadderIsBoundedAndResets` | **RED** |
| M8 | jitter degrades to a constant (fleet stays in phase) | `BackoffLadderIsBoundedAndResets` | **RED** |
| M9 | a stable serve no longer resets the ladder | `BackoffLadderIsBoundedAndResets` | **RED** |
| M10 | the bind classifier takes the unqualified `net.Error` branch | `BindErrorClassesAreBounded` | **RED** |
| M11 | a graceful stop is no longer recorded as graceful | `GracefulStopIsNotAnOutage` | **RED** |
| M12 | the gauge is exported on a node with no sidecar | `ControlHealthySidecarIsSilent` | **RED** |
| M13 | the scanning-plane checkboxes are removed | `EveryFiredAlertIsSubscribableInTheGUI` | **RED** |
| M14 | a recorded gap is quietly fixed but left in the list | `KnownAlertGUIGapsAreStillGaps` | **RED** |
| M15 | never-bound fails its row on the FIRST bind (the bug this round shipped first) | `ControlNeverBoundInsideThresholdDoesNotPage` | **RED** |
| M16 | the gauge drops on the FIRST failed bind of a never-bound sidecar | `ControlNeverBoundInsideThresholdDoesNotPage` | **RED** |
| M17 | never-bound and lost-socket share one message, losing the bind remedy | `NeverBoundIsVisibleAndAlerts` | **RED** |
| M18 | the `/healthz` field is always present (every proxy looks like a sidecar host) | `HealthzFieldOmittedUnlessConfigured` | **RED** |
| M19 | the `/healthz` field reports a first-retry sidecar as `down` | `HealthzFieldOmittedUnlessConfigured` | **RED** |
| M20 | the `/ready` row is published on a node with no sidecar | `ReadinessRowIsReportOnlyAndAbsentWhenUnconfigured` | **RED** |
| M21 | the `/ready` detail leaks the bind reason class and address | `ReadinessRowIsReportOnlyAndAbsentWhenUnconfigured` | **RED** |
| M22 | a not-serving sidecar reports `/ready` ok | `ReadinessRowIsReportOnlyAndAbsentWhenUnconfigured` | **RED** |

**Three mutations came back GREEN. One was correct, one was mis-aimed, and one
was a real gap in this round's own gates.**

The CORRECT green is M3' — removing only the PRE-bind `stopped` check. The
post-bind check is a genuine second barrier that still holds the guarantee, so
the single-check mutant is equivalent and there is nothing for a gate to catch.
Recorded rather than "fixed", because adding an assertion that fails on an
equivalent mutant would be pinning the implementation rather than the contract.

The MIS-AIMED green is recorded so the next reader does not re-run it:
reverting `Shutdown` to its `if srv == nil { return nil }` shape changes nothing *after this fix*, because `srv` is never nil — the server is
built in `NewScanService`. Re-aimed at the thing that IS load-bearing on that
path (`srv.Shutdown` itself, M1'), it is red.

The REAL gap was the post-bind check. `Listen` checks `stopped` twice, before
and after `net.Listen`, and removing either alone left every gate green — which
is correct for the first (above) and was not for the second: the window it
guards (a `Shutdown` that reads `ss.listener` as nil, then a `Listen` that
publishes a socket onto an already-stopped service, leaving a bound listener
nothing will ever close or accept on) needs CONCURRENCY to reach, and no gate
drove `Listen` and `Shutdown` concurrently.
`TestChaos113_ShutdownConcurrentWithListenLeaksNoSocket` was written in
response — and the FIRST version of it was still green, which is the part worth
recording: a 200-iteration opportunistic `Listen`-vs-`Shutdown` race never
reaches the window, because the pre-bind check wins it almost every time. The
gate only has teeth with a seam (`scanSvcListenHook`, fired between the two
checks — the same role `internal/fileutil`'s `openParentDir`/`syncDir` play for
its own white-box tests), which holds `Listen` past the first check so the
second one is the only thing between a completed `Shutdown` and a published
socket. With the seam it is **RED** against M3''. Its discriminator is that a
bound-but-unserved socket still completes a TCP handshake from the kernel
backlog while a closed one refuses, so "the dial was refused" is an assertion a
leaked socket cannot pass.


### 9.7 Checks run

```
go build ./...                                            OK
go vet ./...                                              OK
go test -run 'TestChaos113_' -count=1 .                   OK   18 gates, 3.841s
go test -race -run 'TestChaos113_' -count=1 .             OK   32.037s
go test -run 'TestScanSvc|TestChaos101|TestChaos53' .     OK   the sidecar's
                                                               existing suites
go test -run 'TestDiag|Diagnostics' .                     OK   the contract report
go test -run 'Readyz|TestReadiness|TestHealth|Healthz' .  OK   both probes
go test -count=1 ./internal/...                           OK   no FAIL, no panic
golangci-lint run --timeout=20m --new-from-rev origin/main
                                                          OK   0 issues
python3 docs/agent-context/check.py                       OK   exit 0
```

**The targeted-suite shortcut hid a real defect, twice.** This is the round's
most transferable lesson and it cost two round trips, so it is recorded as an
outcome rather than a caveat:

1. `--new-from-rev` could not see a `noctx` finding on an unchanged line inside
   a function this change rewrote (§9.7 above).
2. **`-run 'TestChaos113_'` could not see the repository's own anti-regression
   walls.** `alerts_gui_parity_chaos_test.go` read the SPA with
   `os.ReadFile("static/index.html")` and walked `filepath.WalkDir(".")`, both
   CWD-relative. `static_read_wall_test.go`'s
   `TestTestFileReadsAreCWDIndependent` forbids exactly that — a concurrent
   test's `os.Chdir` makes such a read pick up a scratch tree, which the
   determinism and `-race` gates catch as a flake — and its own doc names "the
   source-scanning parity walls" as precisely this case. The wall never ran
   locally because every local invocation filtered to this round's own gates.
   Fixed by anchoring both to `staticIndexHTMLPath()` and `pkgSourceDir()`.

Both gaps share one cause: **a filtered local run cannot see a gate that lives
outside the filter.** The honest remedy is to run the package's walls — or the
whole package — before claiming a change verified, which is what the hosted
gate did and what this round did not.

**Not run, and why.** The full `go test -count=1 .` for package `main` was
started twice and cancelled both times: the package is ~1540 files with timing
and benchmark gates, and each attempt was invalidated by a later fix in this
same round (the lint annotations, then the never-bound threshold bug, then the
`/healthz` and `/ready` rows). Rather than report a stale pass, the targeted
suites above were run on the FINAL tree — the sidecar's own, the diagnostics
report, both probes, and all of `./internal/...` — and the hosted gate owns the
whole-package run. Stated plainly because a cancelled check is not a passing
one.

The linter is the version `pr-fast-gate.yml` installs (`v2.15.0`), built with
this module's `go.mod` toolchain (`go1.27.3`) — not the container's, which is
older than this module's language version and is the recorded cause of "local
lint is unavailable". The `--timeout` matters: the first run used the config's
5 m and reported `Timeout exceeded`, which makes a clean result meaningless, so
the gate's own `--timeout=10m` (here 20 m) is the honest budget. It found four
issues on the first pass — one G404, one G122 and two `noctx` — all fixed, and
the 0-issue result above is the re-run.

**A full-tree pass was NOT compared against the base** at first, and that gap
materialized within minutes of opening the PR — so it is recorded as an
outcome rather than a caveat. `cyclop`, `funlen` and `gocognit` attribute to a
function's DECLARATION line, so `--new-from-rev` cannot see a function this
change made more complex; the same blind spot turns out to apply to any finding
on an UNCHANGED LINE inside a rewritten function. The hosted advisory
`reviewdog` job (`filter_mode: diff_context`) immediately flagged
`scan_svc.go`'s bare `net.Listen` under `noctx` — a line byte-identical to
main's line 70, invisible to `--new-from-rev`, and one of 162 findings a
full-tree run reports on this tree (the gate's own comment records ~137 legacy
findings). It was fixed rather than deferred, because the function was rewritten
around it here and the fix is a real improvement: the bind now takes the
supervisor's context, so a shutdown during ADDRESS RESOLUTION aborts it instead
of parking the supervisor in the kernel while the drain budget runs out — which
is what the comment on that very line had always claimed and never enforced.
A full-tree run was then done, and the remaining `scan_svc.go` finding
(`whyNoLint` on `handleStatus`) is pre-existing and untouched by this round. The change adds new functions rather than growing
existing ones (the largest, `checkScanSvcListener`, is a 5-arm switch that
delegates its two long rows to helpers precisely to stay inside the 15-complexity
threshold), so the risk is low — but low is not measured, and the hosted gate is
what will measure it.

A passing local check is not a passing hosted gate. These are local results for
this SHA.

---

## 9.8 Found while watching this PR's CI — NOT this round's, and not a test problem

> **RESOLVED 2026-11-08 — escalated, fixed by someone else, merged.** The
> sudoers half below was fixed in **PR #1825** (`fix(maint): replace sudoers
> argument wildcards with a validating wrapper`, merged to `main` as `aa39119`)
> and that `main` has since been merged into this branch, so the failures it
> caused here are gone. Two corrections to what is written below, kept rather
> than rewritten so the escalation and its answer both stay legible:
>
> 1. **The precise cause is `sudo-rs`, not "a newer `sudo`".** Ubuntu 26.04
>    ships the Rust implementation, which bans wildcards in command arguments
>    outright. The substance below holds; the naming was imprecise.
> 2. **The remedy chosen was a validating wrapper** (`packaging/culvert-maint/
>    compose-cli`), not the enumerate-or-restructure options guessed at below —
>    and its author records it as *tighter* than the wildcards it replaces,
>    which is the better outcome than either guess. Their own recorded
>    follow-up: `sudo-rs` matches arguments literally, so the `[0-9a-f]`-class
>    container-inspect and pinned pull/tag rules never match on `sudo-rs` hosts
>    and fail closed there.
>
> The judgement to escalate rather than fix it inside a scan-sidecar round was
> the right one on the evidence available, and is recorded as such: the fix
> touched 20 files, added a 313-line privileged wrapper and 800+ lines of tests,
> and needed a security call about the barrier between operator input and a sudo
> argv. None of that belonged in this PR.

Several CI jobs went red on the PR. **One of them WAS this change's** — the
CWD-relative read above, which appeared in `Race · root shard 3` and in
`Deep · determinism`, and is fixed. Everything below is the remainder, which is
not this change's. The first pass over these failures examined only shards 0
and 2 and generalised from them; recording that here because the generalisation
was wrong and a corrected note was posted on the PR. Both come from the
GitHub runner image rolling to **Ubuntu 26.04**, and one of them is a real
product defect that deserves its own sweep.

**The one that matters.** `Race · root shard 0` and `shard 2` fail on
`TestCulvertMaintInstall_SudoersRender_*` with:

```
syntax error: wildcards are not allowed in command arguments
visudo: invalid sudoers file
```

`cmd/culvert-maint/internal/runner/templates_d16b.go` renders sudo rules
containing `--older-than *` and `--keep-last *`. That is deliberate — its own
comment calls it "one bounded wildcard token" and names the agent's validator as
"the only barrier between operator input and a sudo argv". A newer `sudo`
refuses wildcards in command arguments outright. **That is not a test
expectation drifting; it is the sudoers file the INSTALLER WRITES being
rejected on such a host**, so `culvert-maint` cannot be authorized for
restore-leftover cleanup or upgrade. It is a deployment break that arrives on
its own as distros roll forward, with no change on Culvert's side — exactly the
shape this register exists to catch, in a domain this round does not own.
Deliberately NOT fixed here: removing the wildcard has security consequences
given that the validator is the stated barrier, and the alternatives
(enumerating permitted values, or restructuring the rule) are an owner decision.
Recorded for its own round.

**The other.** `Admin-UI RBAC` fails in 21 s at the browser-install step:
`Playwright does not support chromium on ubuntu26.04-x64` with the pinned driver
1.60.0. The job's own summary says it does not block the PR.

**Why neither is this PR's, established rather than asserted:** PR #1821 —
unrelated work (an IdP-registry diagnostics row) — shows the IDENTICAL `visudo`
failures an hour before this PR's run, and PRs whose CI ran before the image
roll are clean. The failures name components this diff does not touch
(`cmd/culvert-maint` sudoers rendering; Playwright/Chromium install).

---

## 10. Residual risk

1. **The posture is still fail-open.** A supervised, alerting sidecar that is
   genuinely down still means unscanned traffic. This round shortens the window
   (automatic rebind) and makes it visible (gauge, row, alert); it does not
   close it. §8.2.
2. **The caller has no contract row.** The node that fails open reports a clean
   diagnostics report. §8.3.
3. **Ten alert events remain unsubscribable from the UI.** Pinned, not fixed.
   §8.1.
4. **A FLAPPING sidecar does not page, and the flap can be sub-second.** This
   is the sharpest remaining gap and it is in this round's own design, so it is
   stated plainly rather than buried. `noteScanSvcBound` closes the
   unavailability episode — clearing `firstFailure` and the `alerted` latch — at
   BIND time, before the serve has proven anything. A socket that binds and then
   dies immediately therefore never accumulates 30 s of episode, so the row
   stays `warn`, `culvert_scan_svc_listener_up` reads 1 whenever a scrape lands
   inside a serve, and nothing fires — while the sidecar is effectively down
   almost all of the time and every caller is failing open. The damage is
   bounded in rate, not in kind: `scanSvcBackoffAfterServe` retains and doubles
   the ladder when a serve lasted under `scanSvcServeStableAfter`, so the loop
   slows to one attempt per 30 s rather than spinning. The durable evidence is
   `culvert_scan_svc_serve_exits_total`, which climbs monotonically through a
   flap and is the right thing for an operator to alert on
   (`increase(...[15m]) > 3`) until this is fixed properly. **The fix is to
   close the episode when a serve proves STABLE rather than when a bind
   succeeds** — i.e. move the `firstFailure`/`alerted` reset out of
   `noteScanSvcBound` and into the post-serve path, gated on the same
   `scanSvcServeStableAfter` the ladder already uses. Deliberately not taken
   here: it is a state-machine change to the thing this round just introduced,
   it wants its own gates (a flap gate, and a control proving an ordinary
   redeploy still does not page), and shipping it unreviewed inside the round
   that created the surface is how the alert ends up wrong in the other
   direction. Recorded as §8.7.
5. **Supervision cannot fix an address that is wrong.** A typo'd
   `scan_svc.listen` now produces a FAIL row with a remedy string instead of
   silence, which is the whole improvement — but it retries forever at the
   30 s ceiling rather than refusing to start. That is deliberate: the sidecar
   shares a process with a proxy that must keep serving.
6. **The `-race` gate depends on the scheduler.** It reported 3 races in 50
   iterations pre-fix; a future regression might need more iterations to
   surface. The behavioral gates (`ShutdownBeforeServeIsHonoured`,
   `ListenAfterShutdownRefuses`) are deterministic and do not depend on it,
   which is why both shapes are present.
