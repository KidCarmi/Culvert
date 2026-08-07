# Chaos Engineering Review — 2026-08-07

**Domain:** the alert delivery plane under an alert storm
**Register item:** CHAOS-27
**Verdict:** two confirmed defects, both fixed, both with regression gates proven to fail
against the pre-fix code.

---

## Executive Summary

The alerting subsystem was reviewed as a *failure amplifier* rather than as a feature: what
does it cost the appliance when the thing it exists to report on is happening at volume?
`roadmap/CHAOS-ENGINEERING-REVIEW.md` row **WK-10** marks webhook delivery resilient — bounded
queue, bounded retry, bounded concurrency semaphore, SSRF-guarded egress, atomic persistence —
and every one of those bounds is real. The gap is that all of them bound **delivery**, and the
two things that broke under load are **not** delivery:

| # | Failure mode | Class | Bound that was assumed to cover it | Why it did not |
|---|---|---|---|---|
| 1 | One leaked FD + two goroutines **per delivered alert**, held until the receiver closes | Resource exhaustion → cross-plane outage | the 10-slot delivery semaphore | it caps *concurrent* deliveries, not *cumulative* sockets |
| 2 | Unbounded dedup map, rescanned `O(n)` under a process-wide mutex **on every dispatch** | Memory DoS + CPU/lock contention | the 30s dedup window and the 500-cap retry queue | dedup runs *before* both, and its key space is attacker-controlled |

Both are reachable from ordinary hostile traffic against any deployment that has a webhook
configured, and both get **worse the more the security controls are working** — the producers
involved (`threat_detected`, `policy_block`) fire on blocks, and block volume peaks during a
scan or beacon wave. The prior review had already noticed the shape of #2's trigger and
recorded it as accepted on the grounds that the semaphore and retry queue bound the fan-out
(`CHAOS-ENGINEERING-REVIEW-2026-07-26.md`, residual risk). That reasoning was right about
delivery and did not cover the bookkeeping in front of it.

Measured, at the flood steady state: dedup bookkeeping went from **230,603 ns/op → 745 ns/op**
(≈310×), and the pre-fix figure *grows with the map* while the post-fix figure is flat.

---

## Failure Scenarios

### FS-1 — Socket accumulation in the delivery path

**Current behavior (pre-fix).** `deliverAttempt` built its HTTP client, and with it a fresh
`http.Transport`, per attempt:

```go
client := &http.Client{
    Timeout:   5 * time.Second,
    Transport: &http.Transport{DialContext: ssrf.SafeDialContext},
}
resp, err := client.Do(req)
```

This is the documented net/http footgun, and the consequences here are exact:

- On success the response body is closed, so the keep-alive connection is returned to *that*
  Transport's idle pool.
- Nothing holds a reference to the Transport afterwards, and net/http does not finalize it. Its
  `persistConn` read/write goroutines keep both the Transport and the socket alive.
- A hand-constructed `http.Transport` has a **zero-value `IdleConnTimeout`, which means "never
  expire"** — unlike `http.DefaultTransport`, which sets 90s.

So every *delivered* alert cost one file descriptor and two goroutines, retained until the
**receiver** decided to close an idle connection. Culvert had no timer of its own that would
ever reclaim it.

**Expected behavior.** A long-lived process reuses one pooled client for a repeating outbound
call, with an idle timeout that reclaims sockets the peer leaves open.

**Failure mode.** Slow FD leak proportional to delivered alert volume. The terminal state is
`accept: too many open files` — and that limit is process-wide, so **the alert plane exhausts
the descriptors the proxy plane needs to accept client connections.** A subsystem whose entire
job is to *report* trouble becomes the cause of a data-plane outage, during the incident it was
reporting on.

**Recovery path.** None automatic pre-fix; sockets were only reclaimed by peer close or process
restart. Post-fix: the pool is capped (`MaxIdleConns: 32`, `MaxIdleConnsPerHost: 4`) and idle
connections are reclaimed after 90s.

**Why the existing bounds did not catch it.** `webhookSem` (10) is a concurrency gate: it
guarantees at most 10 deliveries are *in flight*, and says nothing about the 10,000 sockets
those 10 slots opened over the preceding hour.

### FS-2 — Unbounded, quadratically-scanned dedup map

**Current behavior (pre-fix).** `dedupSuppressed` kept `map[string]time.Time` keyed on
`event + ":" + detail`, and pruned by scanning the **entire** map on **every** dispatch, under
the process-wide `dedupMu`.

Two independent problems:

- **Key space is attacker-controlled.** `Detail` carries the requested host for the request-path
  producers, so a scan across 50,000 distinct hostnames produces 50,000 distinct keys that the
  window cannot suppress *by construction*. Map size was bounded only by (alert rate × 30s).
  This is precisely the reason `topHosts` (store.go) is already hard-capped at 10k, with the
  comment *"the hostname is attacker-controllable, so the map would otherwise grow unbounded
  (memory DoS)"*. Same input, same hazard, unguarded here.
- **The prune was O(n) per dispatch.** Cost per alert grew with the flood, while holding a
  mutex every other alert producer in the process must take.

**Failure mode.** Memory growth plus lock convoy. Producers reach `Dispatch` via
`go fireAlert(...)`, so a slow critical section does not block the request path directly — it
accumulates *goroutines* waiting on `dedupMu` instead, which is its own exhaustion path.

**Measured** (`BenchmarkDedupSuppressedUnderFlood`, map pre-warmed to the cap, 4-core):

| | ns/op | B/op | allocs/op |
|---|---|---|---|
| pre-fix | 230,603 | 158 | 1 |
| post-fix | 745 | 39 | 1 |

0.23 ms of mutex-held work per alert is ~23% of a core serialized at only 100 alerts/s, and it
degrades from there. Post-fix cost is flat in map size.

**Expected behavior.** Bounded memory and O(1)-amortised cost per dispatch, with any loss of
suppression fidelity made visible rather than silent.

---

## Risk Matrix

| ID | Scenario | Likelihood | Impact | Severity | Status |
|----|----------|-----------|--------|----------|--------|
| FS-1 | FD/goroutine leak per delivered alert → proxy cannot accept connections | Medium (any deployment with a webhook + sustained alerting) | Critical (data-plane outage from the alerting plane) | **High** | CLOSED |
| FS-2a | Dedup map memory growth on attacker-chosen keys | Medium-High (any scanning wave) | High (memory DoS) | **High** | CLOSED |
| FS-2b | O(n)-per-dispatch scan under a global mutex → lock convoy + goroutine pile-up | High (same trigger) | Medium-High | **Medium-High** | CLOSED |

Likelihood for FS-1 is *Medium* rather than High only because it needs a receiver that holds
idle connections open; a receiver that closes aggressively masks it. That is an availability
property of a third party, not a control Culvert has — which is exactly why it counts as a
defect.

---

## Fixes

### 1. One shared, pooled delivery client (`internal/alerts/store.go`)

```go
func newDeliveryTransport(dial func(context.Context, string, string) (net.Conn, error)) *http.Transport {
	return &http.Transport{
		DialContext:           dial,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

var deliveryClient = &http.Client{
	Timeout:   5 * time.Second,
	Transport: newDeliveryTransport(ssrf.SafeDialContext),
}
```

This matches the pooled-client shape already used for feed and OTLP egress
(`internal/blocklistfeed`, `internal/otlp`). The per-attempt deadline is unchanged (5s client
timeout plus the caller's request context), so no delivery gets more time than before.

**Reuse does not weaken the SSRF guard.** `ssrf.SafeDialContext` runs on every *dial*, and a
pooled connection is by definition a connection to an address that already passed
`ssrf.Control` immediately before `connect(2)`. Reuse cannot reach an address that was never
validated. What reuse *does* extend is how long a host that was public at dial time and has
since rebound to a private address stays reachable on an already-open socket — bounded by
`IdleConnTimeout` (90s), and identical to the posture of every other pooled egress client in
the tree.

### 2. Bounded, amortised dedup bookkeeping (`internal/alerts/store.go`)

- `maxDedupEntries = 4096` hard cap.
- `dedupPruneEvery = 256` — the O(len) expiry scan is amortised.
- The cap is enforced on **every** insert but costs `O(entries over cap)`, which at steady state
  is a single deletion. Keeping the cap check coupled to the expiry scan would have fixed memory
  while leaving the CPU failure mode fully intact — a full scan per alert, forever. The two
  costs are deliberately separated (`pruneExpiredLocked` vs `evictOverCapLocked`).

**Eviction fails toward more alerts, never fewer.** Dropping a live key costs at most one
duplicate delivery of an alert that is already firing, and that fan-out remains bounded by the
10-slot semaphore and the 500-cap retry queue. Silencing a real security alert to save memory
would be the wrong trade for a security control, so the design does not offer that option.
Eviction order is random (Go map iteration) rather than oldest-first: under a flood every live
entry sits inside the same 30s window, so oldest-first buys nothing for the sorting cost.

### 3. Observability (the loss must not be silent)

| Surface | Field |
|---|---|
| `GET /api/alerts/webhooks/history` | `dedup_tracked`, `dedup_evictions_total` |
| `/metrics` | `culvert_alert_dedup_evictions_total` (counter), `culvert_alert_dedup_tracked` (gauge) |
| Admin UI → Settings → webhook health line | amber "dedup window saturated (N keys evicted, duplicate suppression degraded)" |

Non-zero evictions are an operator-meaningful signal in their own right: they mean the alert
key space is being flooded with unique details, which is the signature of a scanning wave
reaching the alert plane. OpenAPI `AlertHistory` updated and the bundle regenerated
(`make api-bundle`) — the schema is `additionalProperties: false`, so the contract tests hold
the surface honest.

FS-1 gets no counter by design: the leak is gone, and a "sockets leaked" gauge would be a
metric for a state that can no longer occur.

---

## Required Tests

All in `internal/alerts/store_chaos27_test.go`.

| Test | Property |
|---|---|
| `TestChaos27_DeliveryReusesConnections` | N sequential deliveries open ≤2 sockets (counts `http.StateNew` server-side) |
| `TestChaos27_DedupMapIsBounded` | 3× cap unique attacker-shaped keys leave the map at ≤ cap, and the eviction counter is non-zero |
| `TestChaos27_DedupPruneIsAmortised` | expiry scans ≤ inserts/`dedupPruneEvery` + 1 — the CPU half, which the memory gate alone cannot see |
| `TestChaos27_DedupStillSuppressesDuplicates` | Q17 semantics intact: duplicate inside the window suppressed, distinct detail not |
| `TestChaos27_DedupPrunesExpiredEntries` | a key older than `dedupTTL` fires again — the cap never silences permanently |
| `BenchmarkDedupSuppressedUnderFlood` | per-alert cost at the flood steady state |

**Both gates were verified to fail against the pre-fix code**, which is the only thing that
makes them regression gates:

```
--- FAIL: TestChaos27_DeliveryReusesConnections
    alert delivery opened 8 connections for 8 sequential deliveries —
    each attempt is leaking a keep-alive socket (want connection reuse, ≤2)
--- FAIL: TestChaos27_DedupMapIsBounded
    dedup map grew to 12288 entries from 12288 unique attacker-supplied details
    (cap 4096) — unbounded memory growth on the alert path
```

The connection-reuse test builds its client through the **production constructor**
(`newDeliveryTransport`) with a plain dialer substituted, because `ssrf.SafeDialContext`
correctly refuses the loopback address an `httptest.Server` listens on. The pooling
configuration under test is therefore production's; only the dial target differs.

---

## Impact Assessment

**Customer impact.** Pre-fix, a long-running appliance with webhooks configured and steady
alert volume would drift toward FD exhaustion with no diagnostic pointing at the alerting
subsystem — the visible symptom is the proxy refusing connections, which sends the operator
looking at the proxy. Post-fix the socket cost is constant.

**Security impact.** Both failure modes are *reachable by an attacker* and both are *amplified
by the security controls doing their job*: more blocks → more alerts → more leaked sockets and
a larger dedup map. An attacker who could correlate the effect had a low-cost way to degrade
the gateway by attacking it. Neither fix reduces alert fidelity: dedup evictions can only
increase deliveries, and the SSRF posture is preserved at dial time.

**Operational impact.** One new amber state in the webhook health line and two new metrics. No
config surface, no CLI flag, no cluster-sync field, no persisted state — nothing to migrate,
nothing to roll back.

**Data integrity impact.** None. No persistence format changed; the retry queue file is
untouched.

---

## Review Follow-up — the phantom saturation signal

External review of the first cut (Codex, PR #1078) found the two triggers disagreeing. The expiry
prune is scheduled by **inserts**; entries expire with **time**; a quiet period has neither. A
flood that fills the map and then stops leaves 4096 stale keys in place, and the next alert to
arrive evicts one and **charges it** — a saturation signal fabricated from an entirely dead map,
on a monotonic counter driving a sticky amber state in the admin UI. It could also evict the key
it had just inserted.

That is worse than a missing signal: it trains the operator to ignore the one indicator this
change added.

Fixed on both axes — a time-based prune trigger on the over-cap path (`dedupPruneMinInterval`,
1s, rate-limited so a sustained flood still does not pay `O(len)` per alert; 745 → 783 ns/op,
still ~295× better than the 230,603 ns/op baseline), and expired keys deleted but never charged,
which makes the counter exact rather than approximately right. `evictOverCapLocked` also skips the
just-inserted key.

`TestChaos27_QuietPeriodCountsNoPhantomEvictions` drives fill-to-cap → window passes → one insert,
and fails against the first cut with `charged 1 eviction(s) against a map holding only EXPIRED
keys`.

The general lesson, and the same one as the CHAOS-24/25 sweeps: **a fix scheduled on one clock and
validated on another disagrees with itself at the boundary.** Both bounds were right; the counter
that made them observable was wrong in exactly the state — quiet after a storm — where an operator
is most likely to read it.

---

## Residual Risk

- **`maxDedupEntries` / `dedupPruneEvery` are compile-time constants**, matching the
  `topHosts` cap precedent (also a constant). Making them tunable would add a config surface,
  a durability row, and a CP→DP question for a value no operator has yet had a reason to
  change. Recorded as a deliberate deferral, revisit if a deployment reports evictions during
  normal operation.
- **Random eviction can drop a legitimately-repeating key while flood keys survive.** The cost
  is one duplicate delivery; the alternative (a heap or LRU ordering) buys accuracy that a
  30s-uniform window does not benefit from.
- **Connection reuse extends the DNS-rebinding window to `IdleConnTimeout` (90s)** on an
  already-validated public address. Same posture as every pooled egress client in the tree, and
  strictly better than the pre-fix state, where an abandoned pool's connection could stay open
  indefinitely with *no* timeout at all.
- **Dedup remains keyed on `event:detail`.** Producers that put unbounded-cardinality text in
  `Detail` still defeat suppression by design; the cap now bounds the *cost* of that, not the
  behaviour. The pre-existing note about pathological per-request error strings
  (`scan_clam_error`, 2026-07-26 review) still stands, now with a bounded blast radius and an
  eviction counter that makes it visible.
- **Other per-call `http.Transport` sites were audited** during this pass:
  `auth_oidc_flow.go` (discovery, once per provider construction), `auth_saml.go` (metadata
  fetch), `internal/supportupload` (per upload), and `internal/blocklistfeed` (per fetch, but
  with a 90s `IdleConnTimeout` so it self-heals). `internal/upstream`'s health check sets
  `DisableKeepAlives: true`, so it pools nothing. None of these is on an attacker-driven rate
  path, so none is a leak of the FS-1 class; the blocklistfeed shape is the one worth
  converging on the shared-client idiom opportunistically.
- **`webhookSem` is package-global**, so all Stores in a process share the 10 slots. Production
  has one Store; noted, not a defect.
