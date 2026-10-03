# Credential verification cost and the `auth_verify_saturated` alert

**Applies to:** Culvert nodes using a **local account** for proxy authentication
(`-user` / `auth.user`, or an admin created through the setup wizard).
Deployments that authenticate every request against LDAP, OIDC or SAML are not
governed by this control — their cost and failure modes belong to the
identity-backend health plane instead (`identity_backend`,
`docs/operator/…` and CHAOS-47).

**Design authority:** `internal/authcost` (package comment),
`auth_cost_health.go`, `roadmap/CHAOS-ENGINEERING-REVIEW.md` §25.

---

## 1. What this control is and why it exists

Culvert authenticates on **every proxied request**. When the credential is a
local account, validating it means one bcrypt comparison, and bcrypt is
expensive on purpose — that is what a password hash is for. On the reference
four-core box one comparison measures:

| | |
|---|---|
| one credential verification | **~80 ms of exclusive CPU** |
| one *cached* successful authentication | ~1.5 µs |
| amplification | **~51,000×** |

That constant is a property of the **data path**, not of a login form, and it
is reachable by anyone who can open a TCP connection to the proxy port. Before
this control existed there was no bound on it of any kind, and the three
front-door limiters that might have capped the arrival rate — the per-IP
connection limiter, the request rate limiter, and the IP filter — **all ship
disabled by default**. Measured on that same box:

- **66 requests/second (~13 KB/s) consumed 100% of all four cores.**
- Other CPU work on the appliance degraded **15.6×** under a 64-connection flood.
- No credentials, no knowledge of the deployment, and no valid username were
  needed: the wrong-username path runs a comparison too (deliberately — see
  §5), never populates the cache, and so was a guaranteed miss every time.

Culvert now bounds credential verification explicitly. **Verification can never
consume more than roughly half the machine**, and no single client can occupy
more than one verification slot.

## 2. The bounds

| Bound | Value | Why |
|---|---|---|
| Concurrent verifications (global) | `GOMAXPROCS / 2`, floored at 1 | The gateway's real work — TLS handshakes, scanning, policy, relaying — must keep running while somebody authenticates. |
| Concurrent verifications per client | 1 | Stops one source from occupying the whole ceiling and denying everybody else. A client at its cap **waits for its own** earlier verification — it is not refused on the spot — so one workstation's parallel connections serialise rather than failing. |
| Wait for a free slot | 1 s | Absorbs a legitimate burst instead of refusing it. At ~80 ms per verification this covers a burst about a dozen deep from one client; a browser pool of six to eight fits with room to spare. |
| Queue depth | 8 × the ceiling | The queue is bounded too: an unbounded one would just move the exhaustion from CPU to goroutines. |

These are **constants derived from `GOMAXPROCS`**. There is deliberately no
configuration knob: the only use for one would be to widen a denial-of-service
window, and the ceiling is far above real demand (see §3).

**When the bounds are exceeded, the request is denied — fail closed.** A denied
request receives the ordinary `407 Proxy Authentication Required`, which
clients retry.

## 3. Will this throttle my users?

Almost certainly not, and the arithmetic is worth checking against your own
deployment.

Successful verifications are **cached for 5 minutes**, and the cache is
consulted *before* the governor — a client riding a warm cache never consumes a
slot at all. So the sustained rate that actually reaches the governor is
roughly:

```
uncached verifications/sec  ≈  active users / 300
```

- 500 active users → **~1.7/s**
- The ceiling on a four-core node → **~25/s** (2 slots ÷ 80 ms)

That is better than an order of magnitude of headroom. The governor is designed
to bite under attack, not under load.

The cases that legitimately approach the ceiling are **synchronised**: a whole
client fleet whose cached results expire at the same moment, a password
rotation, or a restart that empties the cache. Those are what the bounded wait
absorbs, and they show up as `culvert_auth_verify_waited_total` climbing
*without* any refusals — which is your signal to look before users notice.

## 3a. Restart and mass reconnect — the one case that legitimately queues

The verification cache is **in memory only**. A restart empties it, so every
active client's next request is an uncached verification arriving at
approximately the same moment. This is the scenario worth understanding before
you see it at 3 a.m.

**What happens.** The queue (8 × the ceiling) absorbs the first arrivals; the
rest are refused with `queue_full` and receive a `407`, which clients retry.
Authentication drains at the ceiling rate — ~25/s on four cores, ~12/s on two —
so a 1,000-client fleet re-authenticates over roughly 40–80 seconds, with some
clients seeing one or two retried 407s on the way. You will see
`culvert_auth_verify_waited_total` and `culvert_auth_verify_refused_total`
spike and then decay to flat.

**Why this is the better outcome, not a regression.** Before this control the
same 1,000 clients put 1,000 goroutines into bcrypt simultaneously — roughly 40
seconds during which **every core was consumed and the proxy served nobody**,
including the clients that were already authenticated and just wanted to browse.
The governor trades "slower authentication for some" against "the data plane
keeps working for everyone", which is the graceful-degradation direction.

**If the retries are a problem for your clients** (some non-browser API clients
do not retry a `407`), the remedies are, in order of preference:

1. **Stagger the restart** across nodes rather than restarting the fleet's
   gateway at once.
2. **Use an external IdP** for proxy authentication. Introspection and LDAP
   binds are not governed by this control at all, and their results cache under
   the CHAOS-47 plane.
3. **Add cores.** The ceiling is `GOMAXPROCS/2`, so it scales directly.

What you should *not* do is treat a decaying post-restart spike as an incident.
A spike that does not decay is an incident — see §5.

## 4. Monitoring

### Metrics

| Series | Meaning |
|---|---|
| `culvert_auth_verify_total` | Verifications that ran a bcrypt comparison. |
| `culvert_auth_verify_refused_total{reason}` | Fail-closed denials. `reason` is one of `per_client`, `queue_full`, `timeout`. |
| `culvert_auth_verify_waited_total` | Verifications that had to queue. **Leading indicator.** |
| `culvert_auth_verify_inflight` | Running right now. |
| `culvert_auth_verify_max_concurrent` | The ceiling, so you can plot utilisation. |
| `culvert_auth_verify_queued` | Waiting right now. |
| `culvert_auth_verify_saturated` | 1 while every slot is occupied. |
| `culvert_auth_cache_evictions_total` | Cached results displaced to stay under the cache cap. Each one costs somebody a full bcrypt on their next request. |

Suggested rules:

```promql
# Users are being denied without their credential being checked.
rate(culvert_auth_verify_refused_total[5m]) > 0

# Approaching the ceiling but still absorbing — investigate before it refuses.
rate(culvert_auth_verify_waited_total[5m]) > 1

# Somebody is churning the credential cache.
rate(culvert_auth_cache_evictions_total[15m]) > 1
```

### Operator contract row

`GET /api/diagnostics` carries a **`credential_verification`** row (viewer
role). It reports counts and bounds only — never a client address; that is
admin-scoped and goes to the log line and the alert.

### `/healthz` and logs

Refusals emit `AUTH_VERIFY_REFUSED` (first occurrence immediately, then at most
one line per 30 s, then one `AUTH_VERIFY_RECOVERED` line naming the suppressed
count). The magnitude lives in the counters; the log carries the signal.

### Alert

`auth_verify_saturated` fires **once per episode** — never once per denied
request — after refusals have persisted for 30 s. Subscribe to it in
**Settings → Alert Webhooks**.

## 5. Triage runbook

Start with the `reason` breakdown, because the two point at opposite actions.

### `per_client` dominates → one source is flooding

A single client key is asking for more concurrent verifications than any real
workstation needs.

1. Find it: search the access log for a burst of `AUTH_FAIL` from one address,
   or check `culvert_auth_cache_evictions_total` (a flood using a *known*
   username also churns the cache).
2. Block it at a front-door limiter — **both ship disabled and both are worth
   enabling on any internet-adjacent deployment**:
   - **IP filter** (Security → IP Filter) — the direct block.
   - **Per-IP connection limiter** (`security.max_conns_per_ip` in config.yaml, or the "Connection Limits" panel via `/api/connlimit`) — caps concurrency.
   - **Rate limiter** (`-rate-limit`) — caps arrival rate.
3. Nothing else is required. The governor is already containing the CPU cost;
   the limiters stop the source from reaching the proxy at all.

### `queue_full` / `timeout` dominates → genuine capacity

Aggregate login demand exceeds what this node's CPU can verify.

1. Check `culvert_auth_verify_max_concurrent`. On a one- or two-core node the
   ceiling is 1, which is ~12 verifications/second.
2. Check whether the demand is **synchronised** (a fleet-wide cache expiry after
   a restart) or **sustained**. Synchronised bursts resolve themselves as the
   cache refills and are visible as a spike in
   `culvert_auth_verify_waited_total` that decays.
3. If sustained: add cores, or spread clients across more nodes. Consider
   moving authentication to an external IdP, whose per-request cost is a cached
   introspection rather than a bcrypt.

### Neither, and users complain about intermittent 407s

Check `culvert_auth_cache_evictions_total`. Heavy eviction means cached
credentials are being displaced, so users pay a full verification more often
than they should. Eviction is **fair** — a flooding source evicts its own
entries first, and a client holding a single entry cannot be displaced until
every other client is down to one — so sustained eviction means the cache is
genuinely undersized for the number of distinct (user, password) pairs in play,
which in practice means a flood using a valid username.

## 6. What this control deliberately does not do

- **It does not decide anything about the credential.** It knows nothing about
  usernames, passwords or verdicts. The admission decision is taken *before*
  the presented username is compared, so being over budget can never leak
  whether a username exists (see §7).
- **It does not govern external identity backends.** LDAP binds and OIDC
  introspections run no bcrypt; charging them a verification slot would bound
  the wrong resource and let a slow directory starve local authentication.
- **It does not govern the admin UI login.** That path is bounded by the
  brute-force lockout (`loginLimiter`) instead.

## 7. Note on username enumeration

Culvert compares a presented password against a fixed dummy hash when the
username does not match, so that a wrong username takes the same time as a
wrong password (RISK-008). The governor is consulted **before** that
comparison and its decision does not depend on the username, so an over-budget
refusal is equally fast in both cases. Applying the bound to only one branch
would make "over budget" fast for one and slow for the other — which is exactly
the enumeration oracle the equalisation removes. This is pinned by
`TestChaos57_AdmissionDecisionIsUsernameIndependent`, which is written to fail
against that asymmetric shape.

A separate, **pre-existing** oracle is recorded and not closed by this work: a
negative result for the *correct* username is cached, while one for a wrong
username is not, so repeating the same wrong pair twice is fast in the first
case and slow in the second. See `roadmap/CHAOS-ENGINEERING-REVIEW.md` row
AU-3e.
