# Chaos Engineering Review — 2026-08-23

## CHAOS-54 — The SOCKS5 accept loop under listener faults

**Domain:** SOCKS5 · Networking · Startup/Shutdown · Storage (log volume) ·
Metrics · Alerting
**Register rows:** PX-16, PX-17, PX-18, PX-19 (`roadmap/CHAOS-ENGINEERING-REVIEW.md` §22)
**Files:** `socks5.go`, `socks5_health.go`, `healthcheck.go`, `diagnostics.go`,
`metrics.go`, `internal/alerts/store.go`, `static/index.html`,
`socks5_accept_chaos_test.go`

---

## 1. Executive Summary

`socks5Server.serve` is the only hand-rolled accept loop in Culvert's data
plane. Every other listener in the process — the proxy port, the admin UI, the
PAC endpoint, the MCP gateway — is served by `net/http.Server.Serve`, and the
control plane by gRPC. Both apply an exponential accept backoff and stop on a
non-temporary error. The SOCKS5 loop did neither: any `Accept` error that was
not `net.ErrClosed` was logged and retried **immediately, forever**.

Under file-descriptor exhaustion that is a hot loop. Measured on the same box in
the same run, with a listener returning EMFILE:

| loop | accept attempts in 300 ms |
|---|---|
| pre-fix (log-and-retry) | **7,681,156** |
| with backoff | **6** |

The syscalls themselves are not the damage. The damage is what rides on them: a
pinned core; ~40 MB/s of log lines into a 50 MB rotating file with one archive,
which overwrites the entire retained process log — *including the evidence of
whatever exhausted the descriptors* — within about two seconds; and, because
`internal/logsink` blocks a producer on a full queue, added latency on every
proxied HTTP request, on a node whose SOCKS5 listener nobody is using.

The trigger is not exotic. FD exhaustion is the documented terminal state of two
already-registered failures — WK-11 (one leaked socket and two goroutines per
delivered alert, recorded end state `accept: too many open files` in the proxy
plane) and PX-6 (no global connection cap; the per-IP limiter ships disabled).
This loop converted a recoverable resource incident into a self-amplifying one
that destroyed the record of its own cause.

Three further defects came with it: one posture for two opposite faults
(PX-17), no health surface of any kind (PX-18), and no panic guard on the loop
(PX-19).

All four are closed in this PR. Eighteen regression gates ship with it; the two
that can be run against the pre-fix loop were verified failing, and two more
were verified failing against deliberately regressed forms of the fix.

---

## 2. Failure Scenarios

### RS-1 (PX-16) — Descriptor exhaustion spins the accept loop

**Current behavior (pre-fix).** `accept(2)` returns EMFILE when the process hits
`RLIMIT_NOFILE` and ENFILE when the system-wide table is full. Go's
`internal/poll.FD.Accept` retries only EINTR and ECONNABORTED, and waits only on
EAGAIN; EMFILE/ENFILE are handed straight back to the caller and do **not**
block. The loop therefore re-entered `Accept` at syscall speed and emitted a
`logger.Printf` per attempt.

**Expected behavior.** What `net/http.Server.Serve` does: sleep 5 ms on the
first failure, double, cap at 1 s, reset on success.

**Failure mode.** Resource exhaustion amplified into CPU exhaustion, log-volume
exhaustion, and (through `logsink` backpressure) latency on an unrelated data
path.

**Blast radius.** A subsystem that is **off by default** (`-socks5-port 0`)
degrades the primary HTTP/HTTPS path and erases the diagnostics for the whole
process.

**Monitoring visibility (pre-fix).** None, and worse than none: the flood
actively removed the log lines an operator would use to diagnose the FD
incident.

### RS-2 (PX-17) — One posture for two opposite faults

**Current behavior (pre-fix).** EMFILE (transient, clears on its own) and EBADF
on the listening descriptor (permanent, never clears) took the same branch. For
the permanent case the "retry" could never succeed, so it was a pure spin — and
the port stayed **bound**. Clients connected to a listener that would never
accept: a black hole in which they hang, which is operationally worse than
connection-refused because nothing fails fast and no health check can see it.

**Expected behavior.** Retry what can recover; stop and fail loudly on what
cannot, closing the socket so clients fail fast.

### RS-3 (PX-18) — The listener had no health surface

**Current behavior (pre-fix).** SOCKS5 appeared in `/healthz`, `/readyz`,
`/api/diagnostics` and `/metrics` exactly zero times. A listener spinning on
EMFILE and a listener that had stopped accepting entirely both produced an
unqualified healthy verdict from every probe.

**Failure mode.** Silent failure — the register's §1 theme.

### RS-5 (PX-20) — Every `net.ErrClosed` was read as an expected shutdown

*Raised by Codex review on PR #1208, against the first version of this fix.*

**Behaviour as first written.** `net.ErrClosed` means the listener is gone. It
does **not** by itself mean a shutdown was requested — `Stop` is only one of the
ways a listener can end up closed. The loop treated the two as the same thing
and returned silently, so any closure that did not come through `Stop` left the
accept loop terminated with **every probe still green**: `socks5: ready`,
`culvert_socks5_listener_up 1`, an `ok` contract row, a passing readiness row.

That is precisely PX-18 — the defect this change exists to close — reintroduced
in a narrower costume, and it is worth recording as its own row rather than
folding into the fix, because it shows the failure mode is easy to reproduce
even while deliberately fixing it.

**Expected behavior.** Ask whether `Stop` actually ran. `Stop` closes its
`stopping` channel *before* `ln.Close()`, so an in-progress shutdown is always
visible by the time `Accept` returns — the check is race-free in the direction
that matters, and errs toward silence rather than toward a false page.

### RS-4 (PX-19) — No panic guard on the accept loop

**Current behavior (pre-fix).** `handleSOCKS5` carries `recoverGoroutine`, so a
panic in connection handling is contained. `serve` itself had no guard, so a
panic there propagated to the runtime and killed the entire proxy process,
dropping every in-flight tunnel on every protocol. This is the PX-4 class one
level up.

---

## 3. Risk Matrix

| ID | Likelihood | Impact | Priority |
|---|---|---|---|
| RS-1 accept spin under EMFILE/ENFILE | Medium — reachable from WK-11, PX-6, or any ordinary descriptor-limit misconfiguration | High — pinned core, diagnostic log destroyed, HTTP latency | **P0** |
| RS-3 no health surface | Certain (structural) | Medium-High — a dead service reported healthy | **P1** |
| RS-2 permanent error retried / port left bound | Low — needs a socket-level fault | Medium-High — clients hang, no fast failure | **P1** |
| RS-4 unguarded loop panic | Low | High — whole-process kill | **P1** |
| RS-5 ErrClosed always read as shutdown | Low | Medium-High — dead listener, every probe green | **P1** |

---

## 4. Recovery Assessment

| | Pre-fix | Post-fix |
|---|---|---|
| **Automatic recovery, transient fault** | Yes, but at ~7.7 M attempts / 300 ms and at the cost of the log | Yes, at ≤1 attempt/s; state clears on an observed successful accept |
| **Automatic recovery, permanent fault** | Never — infinite spin, port bound | N/A by design: the loop stops and says so |
| **Manual recovery** | None documented; no signal to act on | `socks5_listener` row, `/readyz socks5`, alert, four metrics; restart for a DOWN listener |
| **Recovery signal** | None | Observed successful accept only — never elapsed time |

**Recovery is on evidence, never on silence.** An accept loop that stops failing
because no client is dialling it has not recovered. This is the same rule
`ca_health.go` and `storage_health.go` state, applied here.

---

## 5. Operational, Security and Data-Integrity Impact

**Operational.** Before: an FD incident cost a core, wiped the process log, and
slowed the HTTP path, with no probe, metric or alert anywhere naming SOCKS5.
After: bounded retries, bounded logging, and a health plane on four surfaces
with a clear split between *degraded* (retrying, self-heals, raise the FD limit)
and *down* (socket gone, restart required) — two states that point at different
operator actions and must not be collapsed.

**Security.** No control was disabled by this defect, so this is not a
fail-open finding. The security-adjacent cost is forensic: the log flood
destroyed the retained history of the incident that caused it, which is exactly
the window in which an operator needs it. There is also a modest availability
angle — an attacker who can drive the process toward its descriptor limit gets
CPU and log amplification for free from a subsystem the target may not even be
using.

The new surfaces were built to avoid adding disclosure. `/readyz` is
unauthenticated on the proxy port, so its detail strings are FIXED per branch:
the consecutive-error count and the accept reason would fingerprint a
resource-exhausted node and announce the window in which the gateway is least
able to serve. Both stay on the role-gated `/api/diagnostics` row, the alert and
the logs. The alert Detail is built from a BOUNDED reason class rather than the
raw error, because `alerts.Store.Dispatch` dedups on `event + ":" + Detail` and
a raw accept error embeds the listener address — the WK-12 / RS-5 defect.

**Data integrity.** None directly. Indirectly, the flood destroyed log data that
had already been written — the only integrity cost in this finding.

---

## 6. Suggested Improvements — shipped in this PR

1. Exponential accept backoff on net/http's exact schedule (5 ms → 1 s),
   reset on an observed successful accept.
2. An interruptible backoff sleep, so `Stop` never waits one out inside the 2 s
   `socks5-listener-stop` budget. Measured worst case at the ceiling: 107 µs.
3. `socks5AcceptFatal` — errno classification via `errors.As` (never string
   matching). Only EBADF/ENOTSOCK/EINVAL/EFAULT/ENOTCONN stop the loop; the
   listener is then closed so clients get connection-refused rather than a
   black hole.
4. **Unrecognised errors retry.** Backed off to one syscall per second,
   retrying an unknown error costs nothing; misclassifying a transient fault as
   fatal is a customer-visible outage. The retry is never silent, which is what
   the "avoid infinite retries" rule is actually protecting against.
5. Rate-limited logging: first error immediately, then ≤1 line per 30 s, then
   one recovery line naming what was suppressed.
6. Degradation measured as a DURATION (30 s), not a failure count — the backoff
   ceiling is reached in ~1.3 s and paging on that would page on every spike.
7. A panic guard on the loop that reports the listener DOWN. The CHAOS-24
   objection to recovering at the top of a worker goroutine — that it converts a
   loud crash into a silent stall — does not apply when the recovery path
   produces a fail row, an alert and a zeroed gauge.
8. Observability: `socks5_listener` contract row, report-only `/readyz socks5`
   row, `/healthz socks5` field,
   `culvert_socks5_{listener_up,accept_errors_total,accept_degraded,accept_backoff_seconds}`,
   and a fire-once-per-episode `socks5_listener_down` alert.
9. **Separate fire-once latches for degraded and down.** Raised in review of
   this fix: with a single shared latch, a listener that died while already
   degraded produced no page at all — the more urgent of two states that point
   at opposite actions was silenced by the less urgent one. This is
   `storage_health.go`'s "two failures must not share a rate gate" rule
   (Codex P2) in a different costume, and it is worth stating that the defect
   was introduced by the fix and caught by re-reading it, not by a test.

---

## 7. Residual Risk / deliberately left

- **SOCKS5 still does not consult the policy engine.** `handleSOCKS5` applies
  the IP filter, rate limiter, per-IP connection limiter, blocklist, plugin
  chain and SSRF guard — but never `Evaluate`, so category, GeoIP and schedule
  rules, and the default-deny posture, do not reach it. This is a
  security-posture question rather than a resilience one and is far too large
  to fold into a chaos fix. **Recorded as the next sweep's headline candidate.**
- **PX-1 / PX-5 / PX-6 / PX-7 / PX-8 are untouched.** No parent-proxy chaining
  on the SOCKS5 path, no global connection cap, QoS still not enforced on the
  data path, in-flight SOCKS5 handlers still not drained on `Stop`.

  PX-8 earned a supporting data point during this work. The first version of
  the healthy-path control gate dialled the real listener; `Stop` returned, the
  test ended, and the `handleSOCKS5` goroutine it had spawned was still reading
  the `ipf` / `rl` / `connLimiter` globals when the next test's
  `setupProxyTest` wrote them — a data race the detector caught on the full
  suite. `socks5_shutdown_test.go` already warned about exactly this in a
  comment. It is a test-harness symptom of a production property: after
  `Stop` returns, the process still has SOCKS5 handlers running against live
  shared state, and nothing waits for them. On SIGTERM that is a hard kill of
  in-flight sessions; the shutdown sequence has no way to know they exist. The
  gate was rewritten to use a stub conn and wait for the handler to finish, and
  PX-8 stays open.
- **A DOWN listener needs a restart.** Rebinding at runtime would need an owner
  decision about port reuse and about what a half-rebound listener means for
  the shutdown sequence.
- **The 30 s degradation threshold and the 30 s log interval are constants.**
  Consistent with the rest of the health plane (`storage_health.go`'s 5 min,
  `ca_health.go`'s 5 min); an operator knob here would only widen a blind spot.
- **`logsink` backpressure is unchanged.** Bounding this producer removes the
  realistic way to saturate the sink, but any future unbounded producer can
  reach the same coupling. The general fix — a per-producer rate ceiling in the
  sink — is a separate change.

---

## 8. Required Tests

`socks5_accept_chaos_test.go` — 18 gates, all green under `-race`:

| Gate | Proves |
|---|---|
| `TestChaos54_AcceptBackoffBoundsTheRetryRate` | RS-1: ratio gate against the pre-fix loop measured in the same run (7.68 M → 6 attempts / 300 ms), plus an absolute bound derived from the schedule |
| `TestChaos54_AcceptErrorLoggingIsRateLimited` | The onset is logged, the flood is not; the counter loses nothing to the gate |
| `TestChaos54_SuppressedLinesAreReportedOnRecovery` | Magnitude survives suppression; the recovery line is per-episode |
| `TestChaos54_RecoveryRequiresAnObservedAccept` | Elapsed time never clears degradation; the cumulative counter survives recovery |
| `TestChaos54_DegradedAlertFiresOncePerEpisode` | Fire-once latch; a second episode after a real recovery pages again |
| `TestChaos54_DegradationDoesNotSwallowTheDownPage` | Degraded and down carry SEPARATE fire-once latches, so a listener that dies while already degraded still pages |
| `TestChaos54_TransientBurstDoesNotPage` | Control: a 19 s burst is counted but does not page |
| `TestChaos54_AlertDetailIsBoundedForDedup` | Reason cardinality stays bounded across 12 errnos plus a non-syscall error |
| `TestChaos54_TransientErrorsAreRetriedNotFatal` | Availability half of the classification, including the unrecognised-error default |
| `TestChaos54_UnrecoverableSocketStopsTheLoopLoudly` | RS-2: loop exits, listener closed, DOWN recorded, one alert, fail row, `/healthz down`, failing `/readyz` row |
| `TestChaos54_ListenerClosedWithoutStopIsReportedDown` | RS-5: a listener closed outside the shutdown path is recorded DOWN, not treated as an expected stop |
| `TestChaos54_OrdinaryStopIsNotReportedDown` | Control for RS-5: a normal shutdown records nothing and pages nobody |
| `TestChaos54_StopIsPromptDuringAcceptBackoff` | Shutdown: worst of 4 trials at the backoff ceiling, bound 25 ms |
| `TestChaos54_StopStaysIdempotent` | The `sync.Once` around the stopping channel |
| `TestChaos54_HealthyListenerIsUnchanged` | Control: nothing recorded, nothing fired, everything reports ready |
| `TestChaos54_UnconfiguredListenerReportsNothing` | Absent-feature posture: no `/readyz` row, no metrics, `disabled` on `/healthz` |
| `TestChaos54_MetricsAppearOnlyWhenConfigured` | The other side: series present once configured; `up 0` on a dead listener |
| `TestChaos54_BackoffScheduleMatchesTheDocumentedShape` | The constants the absolute bound is derived from, incl. ceiling < shutdown budget |

**Pre-fix verification.** The pre-fix loop was restored verbatim and the suite
re-run: `TestChaos54_AcceptBackoffBoundsTheRetryRate` failed (8,003,943 attempts
against a bound of 32) and `TestChaos54_UnrecoverableSocketStopsTheLoopLoudly`
failed (`accept loop did not exit … it is spinning`).

Two more were verified against deliberately regressed forms of the *fix*:
`TestChaos54_StopIsPromptDuringAcceptBackoff` against the interruptible
`select` replaced with a bare `time.Sleep`, and
`TestChaos54_ListenerClosedWithoutStopIsReportedDown` against the bare
`if errors.Is(err, net.ErrClosed) { return }` the fix originally shipped with
(`listener closed without a shutdown request was not recorded as down; every
probe still reports a healthy node`), with its control passing throughout.

The remaining gates cover surfaces that did not exist before this change and so
have no pre-fix form to fail against; each is paired with a control gate that
fails if the surface stops reporting.

---

## 9. The process lesson

§21 of the register stated the rule for back ends: *a second implementation of a
security decision is a second posture until proven otherwise.* This sweep is the
same rule, generalised:

> **Every hand-rolled equivalent of a stdlib server loop is a place where the
> stdlib's hard-won failure handling was silently opted out of.**

`net/http`'s accept backoff is five lines long and exists because someone hit
exactly this failure. A loop that reproduces the happy path without it has
reproduced the *shape*, not the *behaviour* — and the divergence is invisible
because both versions work perfectly until the day the resource runs out.

The operational corollary, worth stating on its own:

> **When a subsystem is the only one of its kind in a process, the first
> question is what all the others do that it does not.**
