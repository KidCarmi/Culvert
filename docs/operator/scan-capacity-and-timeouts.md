# Runbook — Content-scan capacity, timeouts, and what they mean

**Audience:** operators running Culvert with local content scanning (ClamAV
and/or YARA) enabled.
**Applies from:** CHAOS-52 (2026-08-21). Background:
`docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-21.md`.

---

## 1. The one thing to know

Culvert scans a response body under a single budget — `ScanBodyTimeout`,
**10 seconds**. If the scan does not finish inside it, the response is
**refused** (fail-closed, HTTP 403 "scan timeout"), because a gateway that
cannot inspect content must not forward it.

Local ClamAV scanning runs at most **4 concurrent scans** per node
(`clamMaxConcurrent`). Waiting for one of those four slots is charged to the
same 10-second budget. So the sequence under overload is:

```
scans queue → the budget runs out while queued → the response is REFUSED
```

not

```
scans queue → an internal 5-second timer fires → the response is FORWARDED UNSCANNED
```

The second is what earlier builds did. If you are upgrading across CHAOS-52,
expect **refusals where you previously had silent pass-throughs** on a saturated
node. That is the intended posture; the signals below tell you when it is
happening and what to do about it.

---

## 2. Signals

All are on `/metrics`, on `GET /api/security-scan/status`, and in the
**Security → Content Scanning** panel.

| Metric | Status-API field | Panel tile | Meaning |
|---|---|---|---|
| `culvert_scan_inflight` | `scan_inflight` | *Scans in flight* | Body scans running right now, **including** scans whose request already gave up. The leading indicator. |
| `culvert_clam_saturated_total` | `stat_clam_saturated` | *ClamAV at capacity* | A scan could not get a ClamAV slot within the budget. The daemon is **healthy**; the node is out of scanning capacity. |
| `culvert_scan_timeout_total` | `stat_scan_timeout` | *Scan timeouts* | Responses refused because the scan exceeded the budget. |
| `culvert_scan_late_discarded_total` | `stat_scan_late_discard` | *Late verdicts discarded* | A scan finished **after** the budget and said "clean"; the refusal stood and the verdict was thrown away. |
| `culvert_clam_scan_errors_total` | `stat_clam_scan_error` | *ClamAV scan errors* | A genuine daemon fault (unreachable, protocol error). Fires the `scan_clam_error` alert. |

**Capacity and faults are deliberately separate.** `culvert_clam_saturated_total`
does **not** raise `scan_clam_error`, because the response is different: add
capacity, don't go looking at a daemon that is working.

---

## 3. Suggested alerting

```promql
# Scanning capacity is short. Refusals are happening under load.
rate(culvert_clam_saturated_total[5m]) > 0

# Content is being decided by the deadline rather than by the engines.
# A correctness signal, not just a liveness one.
rate(culvert_scan_late_discarded_total[5m]) > 0

# Leading indicator: sustained queueing before refusals begin.
avg_over_time(culvert_scan_inflight[5m]) >= 4

# A genuine daemon fault (unchanged; also raises the scan_clam_error alert).
rate(culvert_clam_scan_errors_total[5m]) > 0
```

---

## 4. Triage

### Symptom: users report intermittent 403 "Blocked by TIMEOUT scan: scan timeout"

1. Check **`culvert_clam_saturated_total`**.
   * **Rising** → the node is out of scanning capacity. See §5.
   * **Flat** → the scans themselves are slow, not queued. Check ClamAV host CPU
     / memory / disk, and whether a signature database update is in progress
     (`clamav_version` on the status API shows the loaded database). Check
     `culvert_scan_late_discarded_total`: if it tracks the timeouts, the content
     was in fact clean and the engine is simply too slow right now.
2. Check **`culvert_clam_scan_errors_total`**. Rising means a real daemon fault —
   a down daemon still fails **open** (content is forwarded unscanned, counted
   and alerted). Fix the daemon.
3. A refusal is remembered for **30 seconds** (`scanTimeoutCooldown`) so a burst
   of requests for one hot object does not each start a doomed scan. After that
   the object is rescanned by whatever engine is healthy. **You do not need to
   clear the scan cache to recover** — that was only necessary on builds before
   CHAOS-52, where the refusal inherited the 1-hour content TTL.

### Symptom: `culvert_scan_inflight` is pinned high and never falls

Scans are being abandoned faster than they unwind. Since CHAOS-52 an abandoned
scan is cancelled at the budget and releases its ClamAV slot promptly, so a
persistently high gauge means **arrival rate**, not stuck work: more bodies are
being scanned per 10 seconds than the node can process. See §5.

### Symptom: a single object is always refused

Its scan genuinely exceeds 10 seconds — typically a very large archive on a
loaded node. Options, in order of preference: reduce load (§5); exclude the
content by SHA-256 via the admin hash allowlist if it is known-good; or reduce
`security.max_scan_bytes` so oversized bodies are skipped explicitly (they are
then counted in `stat_scan_skipped` and alerted as `scan_skipped` — a *visible*
pass-through, which is the point).

---

## 5. Adding scanning capacity

In rough order of effectiveness:

1. **Give ClamAV more resources.** The 4-slot limit protects the daemon; if the
   daemon is fast, four slots go a long way. CPU and RAM on the clamd host are
   usually the binding constraint.
2. **Reduce what must be scanned.** Host-level scan exclusions and the SHA-256
   allowlist both cut work before it reaches the queue; the hash cache already
   removes repeat scans of identical content (`cache_hits` / `cache_misses` on
   the status API).
3. **Lower `security.max_scan_bytes`** so very large bodies are skipped
   explicitly rather than occupying a slot for seconds. This trades inspection
   coverage for capacity — the skipped bodies are counted and alerted, so the
   trade stays visible.
4. **Move scanning off-box** with the remote scan sidecar
   (`-remote-scan-url`), which takes the local ClamAV/YARA legs out of the
   request path entirely. Note the sidecar has its own fail-open posture
   (register row WK-2) and its own failure counter, `stat_remote_scan_fail`.

`clamMaxConcurrent` is **not** configurable. It is deliberate: with saturation
now failing closed, a setting that raises it is a setting that trades safety for
throughput, and that belongs to a design decision rather than a runtime knob.
If your deployment needs it, raise it as a request rather than patching it —
see the follow-up recorded in `roadmap/CHAOS-ENGINEERING-REVIEW.md` §20.4.

---

## 6. Postures, stated plainly

| Condition | Posture | Why |
|---|---|---|
| Scan exceeds the budget (slow engine, or queued too long) | **Fail closed** — refuse | Transient, self-clearing in seconds, retryable by the client, and inducible on demand by anyone who wants the gap. |
| ClamAV daemon down / unreachable | **Fail open** — forward, counted + alerted | An operator-visible infrastructure state with its own alert and status surface; refusing all traffic on it is a fleet-wide outage. Recorded as an owner decision (register row WK-1b). |
| Body larger than the scan window | **Fail open** — forward, counted + alerted (`scan_skipped`) | An explicit, configured limit rather than a failure. |
| Content matched by ClamAV or YARA | Block | — |

The asymmetry between the first two rows is intentional and is the subject of
register row WK-1b. If your risk posture requires the daemon-down case to fail
closed as well, that is a product change, not a configuration one — raise it.
