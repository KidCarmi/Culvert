# CDR backend availability (CHAOS-66)

How Culvert behaves when the Sluice CDR backend becomes slow, unreachable
or unavailable — what it does to your traffic, what you will see, and how
it recovers.

---

## 1. What CDR does when the backend is gone

Content Disarm and Reconstruction sits on the SSL-inspected response path:
every file that matches a CDR policy is sent to an enrolled Sluice instance
and either passed, swapped for a sanitized copy, or blocked.

When Culvert cannot reach any Sluice instance it applies **`fail_mode`**:

| `cdr.fail_mode` | Behaviour when the backend is unavailable |
|---|---|
| `open` (default, also the value used when unset) | The original file is delivered, the request is logged `CDR_ERROR`, and the bypass is counted. |
| `closed` | The response is refused and the client receives a block page. |

`fail_mode` governs **both** an in-flight call that fails **and** the case
where every enrolled instance is already known to be down. Before CHAOS-66
only the first honoured it: once the per-instance circuit breaker tripped,
files were delivered regardless of `fail_mode`, silently. If you rely on
`fail_mode: closed` as a compliance control, that is the behaviour change
to be aware of — it now blocks in cases where it previously passed.

**A node with CDR enabled but *no* instance enrolled is a different event.**
That is a provisioning gap, not a backend outage: files pass
(`SKIPPED_NOT_DEPLOYED`, counted separately) and the `cdr` diagnostics row
reports a hard **FAIL** with the enrolment action attached. Blocking every
download because CDR was switched on before Sluice was deployed would turn
a configuration mistake into a site-wide outage.

---

## 2. What you will see

### Diagnostics (`GET /api/diagnostics`, `cdr` row)

| Message | Meaning |
|---|---|
| `disabled` | CDR is off. |
| `enabled-broken` | Enabled, but nothing enrolled. |
| **`enabled-dark`** | Enrolled instances exist but **none can currently serve a request**. Files are being handled per `fail_mode`. |
| `enabled-degraded` | Connected, but `fail_mode` or the default profile is unset. |
| `enabled-healthy` | Normal operation. |

`enabled-dark` is new. The row previously keyed on *how many instances are
enrolled*, so an enrolled-but-unreachable backend reported `enabled-healthy`
while every file on the node was being delivered undisarmed.

### Metrics

| Series | Meaning |
|---|---|
| `culvert_cdr_backend_available` | `1` when at least one enrolled instance can serve a request. **Emitted only when CDR is enabled and at least one instance is enrolled** — a flat `0` from an appliance that never turned CDR on is indistinguishable from one whose backend is dark. Page on `== 0`. |
| `culvert_cdr_unavailable_total` | Requests that found every enrolled instance unavailable. `fail_mode` was applied. |
| `culvert_cdr_not_deployed_total` | Requests where CDR is enabled but nothing is enrolled. |
| `culvert_cdr_fail_open_total` | Files delivered because `fail_mode` is open. **Non-zero means unscanned files reached clients.** |
| `culvert_cdr_fail_closed_total` | Responses blocked because `fail_mode` is closed. |
| `culvert_cdr_pool_breaker_state{instance}` | `0` closed, `1` open, `2` half-open. |
| `culvert_cdr_pool_breaker_trips_total{instance}` | `Allow()` denials while open. Status reads no longer inflate this. |

Suggested alert:

```
culvert_cdr_backend_available == 0 for 5m
```

### Logs

- `CDR: all N enrolled instance(s) unavailable — applying fail_mode (failOpen=…)`
- `CDR: call error reason="…": <full error>`

Both are **rate-limited to one line per minute per reason class**: onset is
logged immediately, a change of reason class logs immediately, and the
magnitude lives in the counters. A mitigation for a log-amplification
problem must not be one itself.

### Alerts

`cdr_unavailable` fires with a **bounded** reason class
(`unavailable`, `timeout`, `resource_exhausted`, `unauthenticated`,
`permission_denied`, `unimplemented`, `backend_internal`, `tls_error`,
`file_too_large`, `call_failed`, `all_instances_unavailable`).

It previously carried the raw gRPC error, which embeds the peer address and
the **ephemeral local port** — so every failure minted a distinct alert
dedup key that the 30-second suppression window could not collapse, and the
fan-out evicted real threat alerts from the 500-entry retry queue.

---

## 3. Recovery

Recovery is **automatic and requires no operator action**.

Each enrolled instance has its own circuit breaker:

```
closed ──(5 consecutive failures)──> open
open   ──(30s reset timeout)───────> half-open
half-open ─(probe succeeds)────────> closed
half-open ─(probe fails)───────────> open (fresh timer)
```

In half-open the breaker permits a **bounded number of probe requests**
(default 1) so a recovering Sluice is not hit by the full request rate at
once. The probe is a real request from the proxy path; its outcome closes
the breaker or re-opens it.

### The recovery bug this document exists for

Before CHAOS-66 that half-open probe slot was a **reservation that was
never given back** unless a call outcome was reported — and almost nothing
reported one. The admin CDR panel, the diagnostics row, the `/api/cdr/*`
status endpoints and the proxy's own pre-flight check all took a slot and
threw it away.

On a single-instance pool this was not a race but a certainty: the first
request after the reset timeout consumed the slot in its pre-flight check,
the real call then found the budget exhausted, no RPC was made, no outcome
was reported, and the breaker stayed in half-open **permanently**. CDR
never ran again on that node until the process was restarted — while the
diagnostics row still read `enabled-healthy`.

**An operator opening the CDR status panel was sufficient to trigger it.**

Two rules now prevent it:

1. **Observation never changes the control it observes.** Every status
   surface goes through a non-reserving path that takes no probe slot, does
   not advance the reset timer and does not charge the trip counter.
2. **Exactly one call site reserves, and it always releases.** The proxy's
   request path releases the slot on every exit — including the paths that
   never reach the wire (cache hit, oversize skip, `file_too_large`, a
   recovered panic).

### If the backend stays dark

1. Check `culvert_cdr_pool_breaker_state{instance}` and the per-instance
   view under **CDR → Instances**.
2. Confirm Sluice is reachable from the proxy node (mTLS certs, DNS, port).
3. The breaker retries on its own every 30 s. An admin **Reset** is
   available but should not be needed — if a reset is the only thing that
   restores CDR, capture the breaker state first and report it.

---

## 4. Residual risk

- **`fail_mode: open` is still a real exposure window.** During an outage,
  files reach clients undisarmed. That is the documented availability
  trade-off; the mitigation is the alert plus `fail_mode: closed`, not
  elimination.
- **A cache hit is served during an outage.** The CDR hash cache answers
  from a previous verdict without contacting Sluice, so identical content
  keeps its earlier decision. This is intended.
- **CDR runs on the SSL-inspected path only.** A file delivered over a
  bypassed or un-inspected connection is never offered to CDR at all.
