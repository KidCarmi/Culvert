# SIEM / syslog feed delivery health

**Applies to:** remote syslog forwarding (`-syslog` / `syslog.addr`, `POST /api/syslog`)
**Change reference:** CHAOS-66 — `roadmap/CHAOS-ENGINEERING-REVIEW.md` §36

---

## 1. What changed, and why it matters

Culvert forwards audit events and request-log entries to a remote syslog / SIEM
collector. Until this change, every surface that reported on that feed answered
a different question from the one operators were asking.

The surfaces answered **"did we ever connect?"**. What matters is **"are events
arriving?"**

Those come apart in the most ordinary way possible: the collector goes away
after Culvert has connected to it. The forwarder notices the failed write,
closes the socket, redials, fails, arms a five-second backoff, and drops
everything — for as long as the collector is away. Meanwhile the writer handle
is still non-nil and still points at the target the operator configured, so:

```
drops=1   contract status=ok   message="remote syslog/SIEM forwarding is active"
```

That line is from the reproduction against the real binary. The feed was dark
and the appliance said it was healthy.

This matters more than a normal monitoring gap, because **a dark SIEM feed and a
quiet network look identical from the collector's side.** An analyst looking at
the collector sees no Culvert events and has no way to tell "nothing happened"
from "we stopped being told". That is CWE-778 / OWASP A09:2021, and it is
exactly the state an attacker who has disrupted log forwarding wants the console
to show.

Three defects were found and closed:

| | Defect | Consequence |
|---|---|---|
| **1** | Health was inferred from a connection, not from delivery | A feed dropping 100% of events reported "active" on the diagnostics row, the admin API and the GUI |
| **2** | Reconfiguring never released the previous writer, and the pointer was unsynchronised | A leaked drain goroutine + TCP connection on every boot and every collector change; a data race on the per-request path |
| **3** | A connect failure at **startup** was permanent | An identical failure mid-life self-heals; at boot it left the feed dark until a human re-saved the target |

**Nothing about this changes what the proxy does with traffic.** Policy
enforcement, the local audit log (`/data/audit.jsonl`) and the local request log
are all unaffected by a SIEM outage. What is lost is the forwarded copy only.

---

## 2. What you can now see

### Diagnostics (`GET /api/diagnostics`, the `syslog_feed` row)

| Verdict | Meaning | Action |
|---|---|---|
| ok — "not configured" | No collector configured | none |
| ok — "forwarding is active" | Events are **arriving** | none |
| ok — "(N events dropped during earlier outages)" | Delivering now; there was an outage | review the gap in your SIEM |
| warn — "the last N deliveries failed; retrying" | A short interruption, still inside the threshold | none yet; it self-heals |
| warn — "the delivery queue overflowed" | The collector is **slower than this node's event rate** | give the collector capacity — see §4.2 |
| **fail — "connected but NOT delivering"** | The feed has been dark past the threshold | see §4.1 |
| **fail — "configured but failed to connect"** | Never reached the collector | see §4.3 |

### `/health` (proxy port, unauthenticated)

`siem_feed` is one of `disabled`, `connecting`, `ready`, `degraded`, `down`.
`ready` means events are **arriving** — not that a socket is open.

### `/metrics` (proxy port)

Emitted **only when a syslog target is configured**, so a node that has never
had a SIEM never publishes a permanently-green — or permanently-zero — series.

| Series | Meaning |
|---|---|
| `culvert_syslog_up` | 1 while deliveries are succeeding |
| `culvert_syslog_degraded` | 1 once the feed has been dark past the threshold |
| `culvert_syslog_delivered_total` | lines that reached the collector |
| `culvert_syslog_drops_total` | lines that never did (all causes) |
| `culvert_syslog_queue_drops_total` | the subset lost to queue overflow |
| `culvert_syslog_panics_total` | lines lost to a contained delivery panic |
| `culvert_syslog_last_success_timestamp_seconds` | when the last line landed |
| `culvert_syslog_reconnecting` | 1 while retrying a collector never reached |
| `culvert_syslog_reconnect_attempts_total` | attempts by the recovery campaign |

**Suggested alerting rules**

```promql
# The feed is dark. This is the one to page on.
culvert_syslog_degraded == 1

# A node that has never managed to reach its collector.
culvert_syslog_reconnecting == 1

# Belt and braces for a QUIET node: the plane reports what it has observed and
# a node with no traffic produces no evidence either way. Alert on staleness
# over a window that suits your traffic profile.
time() - culvert_syslog_last_success_timestamp_seconds > 3600
  and culvert_syslog_up == 1
```

### Alert

`siem_feed_down` fires **once per episode** — never once per dropped line —
once delivery has been failing continuously for longer than the threshold. It
is cleared only by an observed delivery. Subscribe to it on the Alert Webhooks
panel.

---

## 3. What is deliberately NOT done

- **No `/readyz` row.** A node whose SIEM feed is down is proxying traffic
  perfectly and enforcing every policy. Failing readiness would eject a healthy
  gateway from the load balancer because of a fault in its logging pipeline —
  converting a monitoring outage into a traffic outage.
- **No fail-closed option.** Refusing to proxy because a third-party collector
  is unreachable turns the SIEM's outage into the customer's.
- **UDP gets no delivery evidence, and cannot.** A UDP "connection" is a local
  operation; writes to it succeed whether or not a collector exists. On
  `udp://` targets `culvert_syslog_up` will read 1 and `..._delivered_total`
  will climb even with the collector switched off. **If you need delivery
  evidence, use a `tcp://` target.** This is a property of the transport, not
  of Culvert.
- **A quiet node produces no evidence.** Degradation is established by observed
  delivery failures, so a node carrying no traffic cannot tell you whether its
  collector is reachable. That is why
  `culvert_syslog_last_success_timestamp_seconds` is published — see the
  staleness rule above — and why `POST /api/syslog/test` exists as an active
  probe.

---

## 4. Runbooks

### 4.1 `fail` — "connected but NOT delivering"

The TCP connection is established and events are being dropped. The usual cause
is a collector that **accepts connections and stops reading them** — a SIEM
under ingest pressure, a load balancer holding a connection open in front of a
dead backend, or a firewall that dropped an established flow without a reset.
From Culvert's side that is indistinguishable from a healthy connection, which
is why this state was previously invisible.

1. Confirm from Culvert: `GET /api/syslog` reports the drop counter.
2. Confirm from the collector: is it accepting **and acknowledging** on the
   configured port? A `tcpdump` on the collector showing zero-window
   advertisements is the signature.
3. Check ingest capacity / licence limits on the SIEM — an over-quota collector
   commonly stops draining rather than refusing connections.
4. Nothing needs restarting on Culvert. Delivery resumes automatically the
   moment the collector drains, and the `SIEM_FEED_RECOVERED` log line reports
   how many events were lost during the outage.
5. **Backfill the gap from this node's local logs.** The local audit log and
   request log are complete — only the forwarded copy has a hole.

### 4.2 `warn` — the delivery queue overflowed

The collector is accepting events more slowly than this node produces them, so
events are being lost at the queue rather than at the network. The queue is
bounded on purpose (a slow SIEM must cost drops, not proxy latency).

- Give the collector more ingest capacity, or
- reduce what is forwarded (request-log volume dominates; audit events do not).

### 4.3 `fail` — "configured but failed to connect"

Culvert has never reached this collector since startup.

1. The forwarder is **already retrying** with backoff (1 s → 60 s, jittered).
   `culvert_syslog_reconnecting` is 1 and the attempt counter is climbing. No
   restart is needed — this is the case that used to require one.
2. Verify host, port and transport. Note that `udp://` is the default when no
   scheme is given; enterprise collectors usually want `tcp://`.
3. Verify the network path (firewall, route, DNS).
4. `POST /api/syslog/test` sends a single line as an active probe.
5. Re-saving the target via `POST /api/syslog` takes ownership immediately and
   validates the connection synchronously — the API returns 400 if the dial
   fails, so it is the fastest way to confirm a fix.

---

## 5. Notes for maintainers

- **Read the active writer only through `activeSyslog()`; publish only through
  `publishSyslogWriter` / `clearSyslogWriter`.** A plain package-level pointer
  reintroduces the race, the leak and the unobservable swap at once.
- **Recovery is established by evidence, never by elapsed time.** Only
  `noteSyslogDelivery(true)` clears a degradation. A feed that stopped failing
  because nothing is being written to it has not recovered.
- **`noteSyslogConnected()` must not clear a degradation.** Connecting is not
  delivering; treating a successful dial as recovery is the exact inference
  this change removes.
- **The alert detail is a bounded posture, never the transport error.**
  `Dispatch` dedups on `event + ":" + Detail`, and a transport error embeds the
  collector address and the ephemeral local port, which would mint one dedup key
  per failure and evict real threat alerts from the retry queue (WK-12/RS-5).
- Gates: `syslog_feed_chaos_test.go` (11) and
  `internal/syslog/syslog_delivery_evidence_test.go` (4). Every defect gate was
  verified failing against its reintroduced pre-fix shape; the controls fail
  against the cheapest wrong fixes (a plane that always reports the feed broken,
  and recovery on elapsed time).
