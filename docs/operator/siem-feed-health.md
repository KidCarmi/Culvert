# SIEM / syslog feed health

**Applies to:** `syslog_addr` / `POST /api/syslog` (remote syslog forwarding)
**Sweep:** CHAOS-66 · `roadmap/CHAOS-ENGINEERING-REVIEW.md` §36

Culvert forwards **every audit entry and every request-log entry** to the
configured syslog/SIEM collector. On a fleet that is the copy your SOC reads,
so a feed that stops delivering is a gap in the centralized compliance record.
This page is how you see that, and what to do about it.

> **The node's LOCAL record is unaffected by everything on this page.** The
> audit JSONL (`-audit-log`) and the request log (`-request-log`) are written
> independently. A SIEM outage means the *centralized* trail has a gap that the
> node's own files do not.

---

## 1. The one thing to know first: UDP cannot report delivery

An address with **no scheme is UDP** (`10.0.0.1:514` means `udp://10.0.0.1:514`).

A connected UDP socket's `write` succeeds **locally**, whether or not anything
is listening at the other end. Nothing in this process — or any process — can
observe that a UDP datagram was not received. So on a UDP feed:

- `culvert_syslog_up` is 1,
- `culvert_syslog_dropped_total` is 0,
- the `syslog_feed` diagnostics row is `ok`,
- `POST /api/syslog/test` succeeds,

**against a collector that does not exist.** That is a property of the
protocol, not a defect, and Culvert no longer pretends otherwise: every surface
reports `deliveryVerifiable: false` / `culvert_syslog_delivery_verifiable 0`
and says in words that delivery is not verifiable.

> **If this SIEM feed is a compliance control, use `tcp://`.** It is the only
> way an undelivered event is detectable. Everything else in this document —
> the metrics, the alert, the contract row, the probe — only carries real
> signal over TCP.

---

## 2. Surfaces

| Surface | Field | Notes |
|---|---|---|
| `/metrics` (proxy port) | `culvert_syslog_up` | 1 while the last delivery reached the collector |
| | `culvert_syslog_degraded` | 1 once delivery has been failing past the threshold — **the paging signal** |
| | `culvert_syslog_delivery_verifiable` | 0 on UDP; read every other series through this |
| | `culvert_syslog_dropped_total` | **the compliance signal** — any non-zero value means a gap |
| | `culvert_syslog_queue_dropped_total` | the subset lost to a *full queue* rather than an unreachable collector |
| | `culvert_syslog_panics_total` | lines lost to a contained panic in the delivery goroutine |
| | `culvert_syslog_outages_total` | delivery outages since startup |
| | `culvert_syslog_failing_seconds` | 0 while delivering |
| `/healthz` (admin port) | `syslogDrops`, `syslogDeliveryFailing`, `syslogFeedDegraded`, `syslogDeliveryVerifiable` | present only when relevant; **never fails the probe** |
| `GET /api/diagnostics` | `syslog_feed` row | operator-contract verdict + remedy |
| `GET /api/syslog` | `up`, `degraded`, `transport`, `deliveryVerifiable`, `lastReason`, `drops`, `queueDrops`, `outages` | admin |
| Admin UI | Settings → Syslog / SIEM Forwarding | delivery state + drop count + **Test connectivity** |
| Alert | `siem_feed_down` | fires **once per outage**, after the degradation threshold |
| Process log | `WARN syslog: SIEM delivery failing …` | onset, then ≤1/min, then one recovery line |

**All of the syslog series are emitted only when a collector is configured.** A
flat `culvert_syslog_up 0` from an appliance that never had a SIEM would be
indistinguishable from one whose feed is dead, and the paging rule below is
`== 0`.

### Suggested Prometheus rules

```yaml
- alert: CulvertSIEMFeedDown
  expr: culvert_syslog_degraded == 1
  for: 2m
  annotations:
    summary: "Culvert is not delivering audit/request events to the SIEM"

- alert: CulvertSIEMRecordGap
  expr: increase(culvert_syslog_dropped_total[1h]) > 0
  annotations:
    summary: "{{ $value }} Culvert events never reached the SIEM in the last hour"

# Read this one as a posture check, not an incident: it is 0 for as long as the
# feed is UDP, and it means the two rules above cannot see anything.
- alert: CulvertSIEMFeedUnverifiable
  expr: culvert_syslog_delivery_verifiable == 0
  for: 24h
  annotations:
    summary: "Culvert's SIEM feed is UDP — undelivered events are undetectable"
```

---

## 3. Recovery is automatic

**You do not need to restart the proxy or re-save the target** when a collector
goes away and comes back. The forwarder retries on its own at a bounded rate
(one dial attempt per 5s while down) and clears every surface on the first line
that actually lands — recovery is reported on **observed evidence**, never on
elapsed time.

This is also true at **boot**. A collector that is unreachable when Culvert
starts — a SIEM under maintenance, a DNS blip, or simply a collector container
that starts a second after the proxy beside it in the same compose file — no
longer means forwarding is off for the life of the process. The forwarder is
armed either way and connects when the collector answers.

Retries are bounded in **rate** and unbounded in **count**, deliberately: a feed
that stopped retrying would stay dark permanently after one transient fault.
They are never silent — every failure is counted in
`culvert_syslog_dropped_total`, and the log carries onset and recovery.

---

## 4. Reading the `syslog_feed` diagnostics row

| Message | Status | Meaning |
|---|---|---|
| `not configured` | ok | No remote forwarding. A valid posture. |
| `configured but no forwarder is aimed at the requested target` | fail | A reconfigure did not take. Re-save the target. |
| `delivery is failing (<reason>, failing for …, N message(s) lost)` | warn → fail | Live outage. `fail` once past the degradation threshold. |
| `sending over UDP — delivery is NOT verifiable` | ok | §1. Switch to `tcp://` if this is a compliance control. |
| `delivering — but N message(s) were lost earlier …` | ok | Recovered. The historical gap is real and does not self-repair. |
| `remote syslog/SIEM forwarding is delivering` | ok | Healthy. |

The status tracks the **live** posture. It deliberately does **not** latch on
the cumulative drop counter: one transient SIEM restart would otherwise leave
the row amber until the next process restart, with nothing you could do to
clear it. Use `increase(culvert_syslog_dropped_total[…])` for the cumulative
fact — that is what a counter is for.

`lastReason` is a **bounded class** (`connect_failed`, `write_failed`,
`panic`), never a raw error: the alert dedup key is built from it, and a
transport error embeds the collector address and an ephemeral port, which would
mint one dedup key per failure and let a SIEM outage evict real threat alerts
from the bounded retry queue. The full cause is in the rate-limited log line.

---

## 5. Testing connectivity

`POST /api/syslog/test` (admin) — or **Test connectivity** in the admin UI —
dials a **fresh** connection to the configured collector, writes one line, and
reports what actually happened. It cannot disturb live delivery and cannot be
answered by a connection that is already wedged.

```json
{"ok": true,  "verified": true,  "message": "test message delivered to the collector"}
{"ok": true,  "verified": false, "message": "test message sent over UDP — delivery is NOT verifiable …"}
{"ok": false, "verified": true,  "error": "dial tcp …: connection refused", "message": "the collector could not be reached …"}
```

`verified: false` means **the result proves nothing** — do not read it as
confirmation.

---

## 6. Two kinds of loss, two remedies

`culvert_syslog_dropped_total` is the total. `culvert_syslog_queue_dropped_total`
is the subset lost because the bounded in-process delivery queue was full.

- **`dropped − queue_dropped` climbing** → the collector is **unreachable**.
  Fix the host/port, route, firewall or the collector process.
- **`queue_dropped` climbing while `up` is 1** → the collector is **reachable
  but slower than this node's entry rate**. Fix SIEM ingest capacity, or reduce
  what is forwarded. The queue is a shock absorber, not a load shedder's
  excuse: lines past the cap are gone.
- **`culvert_syslog_panics_total` non-zero** → a delivery bug is being
  contained rather than crashing the gateway. The process log names it. Report
  it.

---

## 7. What is deliberately NOT done

- **The feed is not on `/readyz`, and `/healthz` never fails on it.** A node
  whose SIEM feed is down is proxying and enforcing policy perfectly. Failing
  readiness would eject a healthy gateway from the load balancer over its
  logging pipeline — turning an observability outage into a traffic outage.
  The same trade was refused for the category store and the admin UI listener.
- **There is no fail-closed toggle.** Culvert does not stop proxying, or start
  blocking, because a SIEM is unreachable: that converts your logging vendor's
  outage into your users' outage. The deliberate asymmetry is with the *scan*
  verdict controls, which govern content in flight rather than how a record is
  archived.
- **Lines lost during an outage are not replayed.** The queue is bounded on
  purpose — an unbounded one converts a collector outage into a memory
  exhaustion on an in-line appliance. Back-fill from the node's local audit
  JSONL if the centralized trail must be complete.
