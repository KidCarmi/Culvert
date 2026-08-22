# Chaos-Engineering Review — 2026-08-22

**Domain:** the **remote scan sidecar** (`internal/secscan/remote.go`,
`scan_svc.go`, `scanning_startup.go`) — Culvert's second body-scanning back end,
selected by `-scan-svc-url` / `scan_svc.url`, under sidecar failure, slowness,
saturation, and misconfiguration.

**Id:** `CHAOS-53`, allocated at the START of the sweep per the governance note
in the register's §0.

**Why this domain:** the 2026-08-21 sweep (CHAOS-52) closed four defects in the
LOCAL body-scan pipeline and recorded, in §20.5, that the remote sidecar "is the
other fail-open scanning path, with its own 30 s per-request timeout and no
budget threading; the same findings are structurally likely to repeat there."
They do. They are also worse, because of where the runbook points operators.

**Method:** evidence-first source review, then fault injection. Every defect
below was reproduced against the pre-fix tree, and every regression gate was
re-run against the pre-fix behavior to confirm it fails there (§8).

---

## 1. Executive Summary

Culvert has two body-scanning back ends and **they disagree about what to do
when a scan does not finish in time.**

The local path bounds a scan by `ScanBodyTimeout` (10 s) and fails **closed** —
the content is blocked, the refusal is counted as `culvert_scan_timeout_total`,
logged, alerted, and memoised as a short cooldown. That posture is deliberate,
recently re-derived, and documented at length in `secscan.go`.

The remote path bounded a scan by a **private 30 s context** inside an
`http.Client` with a **60 s timeout** — three times and six times the budget the
same process gives the same decision — and, when that deadline fired, surfaced
it as an ordinary transport error. The classifier read any transport error as a
sidecar fault and took the fail-**open** branch:

> A sidecar that answers slowly causes responses to be **forwarded to the client
> unscanned**, reported as a sidecar fault, while the process's own fail-closed
> scan budget is never consulted.

This is CHAOS-52's WK-15 defect — *an inner deadline preempting an outer one and
inverting its posture* — standing in the other path, with three aggravations:

1. **It is reachable by ordinary slowness, not by a fault.** The sidecar is a
   single-threaded-per-request HTTP service in front of the same ClamAV that
   CHAOS-52 showed saturates at four concurrent scans. Queueing there is the
   normal behaviour under load, not an outage.
2. **The runbook sends operators here.** `docs/operator/scan-capacity-and-timeouts.md`
   §"Adding scanning capacity" recommends moving scanning off-box with the
   sidecar as the remedy for the local path's capacity behaviour. The
   recommended remedy silently swaps a fail-closed control for a fail-open one.
3. **It was invisible.** Not one `culvert_scan_*` metric is produced by the
   remote path — every series is structurally zero on a sidecar node — and the
   sidecar's own failure counter reached only the admin JSON API, never
   `/metrics`. The paging rules in that same runbook are dead on exactly the
   deployment it recommends.

Six further defects sit around it, five of them silent by construction. The
worst is that **any HTTP 200 whose body parsed as JSON was treated as clean** —
`{}`, `null`, a load balancer's JSON error page — with no counter, no log and no
alert. Scanning is off and no surface says so.

All seven are fixed. The fail-open posture for a genuine sidecar **fault**
(unreachable, erroring, unintelligible) is deliberately **unchanged** and remains
the recorded owner decision (register row WK-2b); what changed is that the
branch is now reached only by an actual fault.

---

## 2. Failure Scenarios

| # | Scenario | Pre-fix behavior | Expected | Posture |
|---|---|---|---|---|
| RS-1 | Sidecar answers slower than the scan budget | Forwarded **unscanned** (fail-open), counted as a sidecar fault | Blocked, like the local path | **Inverted** |
| RS-2 | Sidecar hangs | Request stalls up to 30 s (client cap 60 s) holding the buffered body | Bounded by `ScanBodyTimeout` | Divergent |
| RS-3 | Something in front of the sidecar answers 200 with non-verdict JSON | Treated as **clean**, silently | Fault: counted, logged, alerted | **Silent** |
| RS-4 | Any of the above, seen from Prometheus | Nothing. No remote scan series exists | Counters + a saturation gauge | **Invisible** |
| RS-5 | Sidecar down or resetting connections | Per-request ungated alert + per-request log; raw `err.Error()` in the 30 s dedup key | Gated, rate-limited, bounded key | Amplifying |
| RS-6 | Admin edits scan exclusions on a sidecar node | 200 OK, audited, config-version snapshot taken, **nothing written**; lists empty after restart | Persisted | **Silent** |
| RS-7 | Admin allowlists a hash to clear a false positive | Never consulted on the remote path; object stays blocked | Honoured | Silent |
| RS-8 | Compromised/buggy sidecar returns an arbitrary `hash` | Adopted verbatim into the Result that feeds the admin allowlist/evict surfaces | Computed locally | Trust |
| RS-9 | `Status()` against a wedged or wrong endpoint | Unbounded decode into the proxy heap, from an admin endpoint | Bounded | Exhaustion |
| RS-10 | `/api/security-scan/status` on a remote-mode node | Sidecar's own `scan_svc_mode:"local"` shadowed this node's, so a remote node reported "local" | This node states its own identity | Misreport |

### 2.1 RS-1 — the posture inversion (Critical)

`RemoteScanner.ScanBody` opened `context.WithTimeout(context.Background(), 30*time.Second)`
and handled `client.Do`'s error with a single classification: `remoteScanFail` →
`return nil` → the caller forwards the response.

`nil` from a scanner means *clean*. So "the sidecar did not answer in time" and
"the sidecar answered clean" became the same value at the call site. The local
path spends 130 lines of comment explaining why that exact condition must block.

The condition is not exotic. The sidecar is an HTTP front end to the same
ClamAV whose concurrency cap is four; CHAOS-52 measured five concurrent
downloads holding all four slots. Under that load the sidecar queues, and a
queue longer than the client's deadline is the normal steady state of an
under-provisioned scanner, not a failure of one.

**Fixed:** the remote scan now runs under `scanBodyTimeout()` — the same value,
the same test seam — and a budget overrun returns the same refusal object the
local path returns (`Source: "timeout"`), increments the same
`statScanTimeout`, and therefore lights up the same
`culvert_scan_timeout_total`, the same `scan_timeout` alert in `proxy_tunnel.go`,
and the same 403. One condition, one posture, whichever back end is deployed.

### 2.2 RS-2 — the private deadline (High)

Even ignoring the posture, the numbers were wrong in the direction that costs
availability: a stalled sidecar held the request goroutine, the connection and
the **entire buffered response body** for 30 s, six times over if the client
timeout were ever reached. The buffer is up to `maxScanBufferBytes` (5 MiB
default) per in-flight request. This is the CHAOS-52 WK-16 shape — abandoned
work holding a scarce resource — except nothing was abandoned: the caller
simply waited.

**Fixed** by the same change as RS-1: one budget, and the transport's context is
that budget, so the dial, the write, the response and the body read are all
inside it.

### 2.3 RS-3 — the silent clean (High)

```go
if sr.Blocked { return &Result{...} }
return nil        // ← "clean"
```

`Blocked` false meant clean. `ScanResponse` unmarshals from `{}` and from `null`
without error, so **any** 200 with a JSON body admitted the content. Realistic
producers: an ingress or service mesh returning `{"error":"upstream unavailable"}`,
a health endpoint reached because the port was mistyped, a maintenance page, a
sidecar upgraded to a newer wire format. In every case scanning is off and the
counters, logs, alerts, admin API and dashboards all say the system is healthy.

**Fixed:** a verdict must now be affirmative — `Blocked` or `Clean`. Anything
else is a fault: counted, rate-limit logged, alerted, and still fail-open per
WK-2b. The shipped sidecar sets `Clean: true` explicitly (`scan_svc.go`), so a
correct deployment is byte-identical.

### 2.4 RS-4 — no signal at all (High, monitoring)

`metrics.go` emits `culvert_scan_timeout_total`, `culvert_scan_clam_error_total`,
`culvert_clam_saturated_total`, `culvert_scan_late_discarded_total` and
`culvert_scan_inflight`. Every one is produced by `Scanner`, which a remote-mode
node never initialises. `statRemoteScanFail` — the single counter that did move
— reached only `/api/security-scan/status`.

So the operator-facing story on a sidecar node was: five scanning series pinned
at zero (indistinguishable from "no threats and no problems"), and the one real
signal available only by polling an authenticated JSON endpoint.

**Fixed:** `culvert_remote_scan_fail_total`, `culvert_remote_scan_saturated_total`
and `culvert_remote_scan_inflight`, plus `culvert_scan_timeout_total` now
covering both back ends because the remote refusal reuses it.

### 2.5 RS-5 — the alert and log amplify the fault (High)

`remoteScanFail` ran `go alerts.Fire(...)` unconditionally and `obs.Printf`
unconditionally, once per proxied response, for as long as the sidecar was
unwell. CLAUDE.md states the contract this violates, and `fireDNSFailureAlert`
carries the rationale verbatim: a producer whose rate is set by a **fault**
rather than by the operator must gate on `HasSubscriber`, because the fault puts
every request on that path and the default posture is no webhooks configured.

The dedup key made it worse rather than better. `Store.Dispatch` dedups on
`event + ":" + payload.Detail` for 30 s, and the detail was
`"transport error: " + err.Error()`. Transport errors embed the **ephemeral
local port**:

```
read tcp 127.0.0.1:54012->127.0.0.1:8484: read: connection reset by peer
```

A sidecar resetting connections therefore produced a **distinct dedup key per
request**, which the window cannot suppress by construction. The fan-out is
bounded by the 10-slot delivery semaphore and the 500-entry retry queue — which
means a scanner fault can evict **real threat alerts** from that queue. CHAOS-27
identified this exact key-cardinality class for the host-in-detail producers and
bounded the map; this producer was not converted.

**Fixed:** `remoteScanFail(class, cause)`. `class` is a bounded set (transport
error, `sidecar returned HTTP <code>`, response read/parse error, no verdict in
response) and is all the alert carries, so dedup works. `cause` carries the full
error and goes only to a `degradedLogAllowed`-gated line; the counter carries
the magnitude. The alert is gated on a new `alerts.HasSubscriber` seam
(`internal/alerts/alerts.go`), which fails toward **delivery** when no probe is
installed, so a missing wire-up can never silence a real alert.

### 2.6 RS-6 — exclusions never load, and every save is a lie (High, silent)

`loadScanning` loaded the admin exclusion file only on the `LocalEnabled`
branch. In remote mode it was never read. That is worse than a stale allowlist,
because `scanexcl.Store` learns its persistence path **from `Load`**, and
`Store.Save()` is a documented no-op without one:

```go
if path == "" {
    return nil        // ← success
}
```

So on a sidecar node the admin API's exclusion handler returned 200, wrote an
audit entry and took a config-version snapshot, and the file was never written.
The lists reverted to empty on the next restart, with the audit log recording a
change that never happened.

The **host** list is on the request path in remote mode too (`proxy_tunnel.go`,
`proxy_http.go` consult `IsHostExcluded` regardless of back end), so hosts an
admin excluded from scanning were being scanned anyway.

**Fixed:** `loadScanExclusions` runs in both modes.

### 2.7 RS-7 / RS-8 — the hash (Medium)

`Scanner.ScanBody` consults `excl.IsHashExcluded` before scanning. The remote
client never did, so a hash allowlisted to clear a false positive had no effect
— accepted, persisted, audited, and inert.

Separately, `Result.Hash` was `sr.Hash`, copied from the sidecar's reply. That
value flows to the admin allowlist and cache-evict surfaces, so a compromised or
merely buggy sidecar could name any object it liked in the operator's UI,
including one it never scanned.

**Fixed:** the hash is computed locally from the bytes actually scanned, and the
allowlist is consulted before the round trip (an allowlisted object is not even
shipped to the sidecar).

### 2.8 RS-9 / RS-10 — the admin probes (Medium)

`Status()` did `json.NewDecoder(resp.Body).Decode(...)` with no limit, on an
admin endpoint, against an operator-configurable URL. `/scan` was already capped
at 4 KiB; `/status` was not. **Fixed** with a 64 KiB limit, and `Health()` now
drains a bounded amount so connections can be reused.

`secScanStatusMap` merged the sidecar's `/status` blob over the map it had just
built. That blob **is the sidecar's own `secScanStatusMap`**, carrying
`"scan_svc_mode": "local"` and its own `"enabled"`, so a proxy running in remote
mode reported mode `local` to its own admin UI — the one field an operator uses
to confirm which back end is in use. **Fixed** by re-asserting the three keys
this node owns after the merge; genuine sidecar detail still merges through.

---

## 3. Risk Matrix

| Row | Severity | Customer impact | Security impact | Recovery | Status |
|---|---|---|---|---|---|
| RS-1 | **Critical** | None visible — that is the problem | Malware forwarded while the node reports healthy | None; steady state | Fixed |
| RS-2 | High | Up to 30 s added latency per inspected response, 5 MiB held each | Amplifies RS-1 | Sidecar recovery | Fixed |
| RS-3 | **High** | None visible | Scanning fully off, silently | None; needs a human to notice | Fixed |
| RS-4 | High | — | Fault undetectable by monitoring | — | Fixed |
| RS-5 | High | Log/alert flood during an outage | Real threat alerts evictable from the retry queue | Fault clears | Fixed |
| RS-6 | High | Admin config silently discarded | Host scan-bypass ignored; audit records a false success | Manual re-entry after every restart | Fixed |
| RS-7 | Medium | False positives cannot be cleared | — | — | Fixed |
| RS-8 | Medium | — | Sidecar-controlled identifiers in admin surfaces | — | Fixed |
| RS-9 | Medium | Admin-plane memory growth | — | Restart | Fixed |
| RS-10 | Medium | Operator misreads the deployment | — | — | Fixed |

---

## 4. Recovery Assessment

**Automatic.** All three fail-closed conditions (budget, capacity, and the
refusal's accounting) recover the instant the sidecar answers within budget
again — there is no latch and no cooldown state on the remote path. The
fail-open fault path likewise clears on the first successful verdict.

**Manual.** RS-6 needed manual re-entry of the exclusion lists after every
restart, and there was no way to discover that: the API reported success. After
the fix an operator on a sidecar node must re-enter their lists **once** if they
were lost, and they will then persist.

**Not addressed (deliberate).** There is still no circuit breaker on the
sidecar. `Health()` exists but nothing calls it periodically, so an unreachable
sidecar is discovered per-request. With the budget now bounding each attempt
this costs one budget per request rather than 30 s, but a breaker (fail fast
after N consecutive faults, half-open probe) is the natural next slice — see §7.

---

## 5. Operational, Security and Data-Integrity Impact

**Operational.** Before: on a sidecar deployment the scanning dashboard was
blank, the runbook's paging rules matched nothing, the mode field could report
the wrong back end, and the exclusion lists silently reset. After: three new
series plus `culvert_scan_timeout_total` covering both back ends, and the
existing `scan_svc_down` alert deduped correctly instead of per request.

**Security.** The material change is RS-1 and RS-3: two distinct routes by which
antivirus, YARA and DPI inspection were fully disabled while every surface
reported health. Both are now either fail-closed (slowness, capacity) or
counted, logged and alerted (fault). The fail-open posture for a genuinely
unreachable sidecar is unchanged by design.

**Data integrity.** RS-6 is the one data-integrity finding: an admin write that
returned success, was audited as success, and was discarded.

---

## 6. Suggested Improvements — shipped in this PR

1. One scan budget for both back ends; budget overrun and sidecar-reported
   capacity (HTTP 429) fail **closed** through the local path's own vocabulary.
2. A verdict must be affirmative; a 200 without one is a counted fault.
3. `alerts.HasSubscriber` seam + bounded reason classes + a rate-limited
   degradation log on the fail-open path.
4. Locally computed hash; the admin hash allowlist honoured on the remote path.
5. Scan exclusions loaded in **both** modes (which is also what gives the store
   a path to save to).
6. `culvert_remote_scan_{fail,saturated}_total`, `culvert_remote_scan_inflight`.
7. Bounded `Status()`/`Health()` reads; this node states its own identity in
   `secScanStatusMap`.

---

## 7. Residual Risk / deliberately left

- **A genuinely unreachable sidecar still fails OPEN** (WK-2b). Unchanged owner
  decision, now counted, alerted, and reachable only by an actual fault.
- **No circuit breaker and no periodic health probe.** Each request pays one
  budget to rediscover a dead sidecar. `internal/upstream`'s breaker is the
  model; a `remote_scan` operator-contract row alongside it is the natural
  shape. Next slice.
- **No hash cache on the remote path.** Identical objects are re-shipped over
  HTTP every time — which is precisely the stampede that saturates the sidecar.
  Deliberately not fixed here: caching a remote verdict needs a decision about
  TTL and about whether a sidecar-sourced verdict may be memoised at all, and
  that is a design decision, not a chaos fix.
- **No `MaxConnsPerHost` on the sidecar transport.** N concurrent requests open
  N connections to the component that is already the bottleneck. Bounding it
  would make saturation fail closed at the client too, which is the right
  direction — but choosing the number is a capacity decision, and the per-request
  budget now bounds the damage.
- **`clamMaxConcurrent` remains a hardcoded 4** inside the sidecar as well
  (CHAOS-52 §20.5). Unchanged.
- **The sidecar's `/scan` has no authentication.** It is documented as
  loopback/private-network, but nothing enforces it, and it will scan and report
  on anything posted to it. Out of scope for this sweep; recorded.

---

## 8. Required Tests — all present, each verified failing pre-fix

`internal/secscan/remote_chaos_test.go` (12 gates):

| Gate | Proves |
|---|---|
| `TestChaos_SlowSidecarFailsClosedNotOpen` | RS-1: budget overrun blocks, counts a scan timeout, is not a fault |
| `TestChaos_RemoteScanIsBoundedByTheSharedBudget` | RS-2: returns at the budget, not at a private 30 s |
| `TestChaos_SidecarCapacityRefusalFailsClosed` | HTTP 429 is capacity: fail closed, counted apart from a fault |
| `TestChaos_TwoHundredWithoutAVerdictIsAFaultNotClean` | RS-3, over `{}`, `null`, `{"status":"ok"}`, `{"clean":false}` |
| `TestChaos_AffirmativeCleanIsStillClean` | control: a correct sidecar is unaffected |
| `TestChaos_BlockedVerdictIsHonoured` | control: blocks still block |
| `TestChaos_ResultHashIsComputedLocallyNotTakenFromTheSidecar` | RS-8 |
| `TestChaos_HashAllowlistAppliesToTheRemotePath` | RS-7, incl. no round trip for an allowlisted hash |
| `TestChaos_FaultAlertIsGatedOnASubscriber` | RS-5 gate; the fault is still counted |
| `TestChaos_FaultAlertDetailIsBoundedForDedup` | RS-5 key cardinality, transport and status classes |
| `TestChaos_TransportFaultStillFailsOpenAndIsCounted` | WK-2b posture is unchanged |
| `TestChaos_FaultLogIsRateLimitedWhileTheCounterStaysExact` | RS-5 log gate; counter exact over 25 faults |
| `TestChaos_RemoteInflightGaugeRisesAndFalls` | RS-4 saturation gauge |
| `TestChaos_StatusResponseIsBounded` | RS-9, gated on latency (an unbounded read errors too, just later) |
| `TestChaos_DisabledScannerDoesNothing` | default posture stays inert |

Root: `TestChaos53_RemoteModeLoadsScanExclusions` (RS-6, including the
save-round-trip half) and `TestChaos53_SidecarStatusCannotShadowThisNodesIdentity`
(RS-10).

Pre-fix verification was done by re-introducing each original behaviour into
`remote.go` and re-running: eight gates fail on the combined pre-fix emulation,
and the two latency/cardinality gates were verified separately against their own
pre-fix forms.

---

## 9. The process lesson

CHAOS-52 §20.3 stated the rule this sweep confirms, one level up:

> When a branch is given a special rule because of what it computed under
> failure, check every sibling branch that computes under the same failure.

The sibling here is not a branch but a **back end**. `internal/secscan` gained a
budget, cancellation, timeout accounting, a cooldown, a tighten-only cache rule
and an in-flight gauge; `internal/secscan/remote.go`, twenty lines away, got
none of them, and the operator documentation written in the same change
recommended switching to it.

Stated for the next sweep:

> **A second implementation of a security decision is a second posture until
> proven otherwise.** When a control has two back ends, the invariant belongs to
> the CONTROL, not to the implementation that happened to be reviewed — and the
> deployment the docs recommend is the one to check first.
