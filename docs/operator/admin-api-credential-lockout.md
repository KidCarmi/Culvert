# Admin API credential lockout (SEC-BASICAUTH-1)

Culvert's admin plane accepts credentials in two shapes: the browser login form
(`POST /api/auth/login`) and HTTP Basic Auth for programmatic / CLI access. This
page covers the second one — what bounds it, what an operator sees when the
bound engages, and how to clear it.

## What changed

The two-tier account lockout (RISK-012) used to guard **only** the login form.
Three other paths verified the same credentials with no lockout, no failure
record, no audit entry and no rate limit:

| Path | Reachable by | Throttled before |
| --- | --- | --- |
| `uiAuthMiddleware` Basic Auth fallback | anyone who can reach the admin port, on every `/api/` route | no |
| `GET /api/auth/status` | **anyone, unauthenticated** — it is on the public allowlist | no |
| SSE mid-stream revalidation | an already-authenticated stream | no |

`securityMiddleware`'s per-IP API rate limit applies only to `POST`/`PUT`/
`DELETE`, and none of these three is a mutating request, so nothing else
throttled them either. That made `GET /api/auth/status` with an `Authorization:
Basic …` header an unauthenticated, unthrottled password-checking oracle, and it
made every attempt cost one bcrypt of CPU on the appliance.

All three now share the login form's lockout. There is **no new setting** —
same tiers, same window, same trusted-IP bypass, same `auth.lockout` audit
action, same `auth_lockout` alert.

## The bound

Unchanged from the login form (`internal/lockout`):

| Tier | Key | Trips after | Locks for |
| --- | --- | --- | --- |
| 1 (pair) | (client IP, username) | 5 failures in 10 min | 15 min |
| 2 (account) | username, across all IPs | 20 failures in 10 min | 15 min |

A client IP that has completed a **successful** authentication for that username
within the last 30 days bypasses tier 2, so an attacker's distributed flood
cannot lock the real operator out of their own appliance.

A locked attempt is refused **before** any credential verification, so it costs
no bcrypt. That is what makes the lockout a CPU bound as well as a
guessing bound.

## What a locked-out client sees

`429 Too Many Requests` with the standard lockout message naming the seconds
remaining — on any `/api/` route via the middleware fallback, and on
`GET /api/auth/status` when Basic credentials were presented.

A request with **no** `Authorization` header never consults the lockout and
never creates a key, so the login overlay's anonymous `GET /api/auth/status`
poll is unaffected.

## The per-client failure budget (SEC-BASICAUTH-2 / -3)

Recording a failure creates limiter state, and the state is keyed by a username
the *caller* chooses. On a public GET with no rate limit that is a memory
amplifier, so a client that has already burned its failure budget in the current
window is **refused before its credentials are verified** — the same
`lockout.Burst` / `lockout.RateWindow` budget the mutating admin API uses.

The admission and the charge are **one atomic step** (`Reserve`). They have to
be: the first form read a budget probe and charged after verification, which
bounded nothing when several requests arrived at once — every one of them saw
the same not-yet-incremented count and passed. Against the real admin username
that meant an unbounded number of *simultaneous* bcrypt comparisons from a
single IP, which is the CPU bound this page's "costs no bcrypt" guarantee is
about.

Three properties matter operationally:

- **Only failures are charged.** A client with valid credentials has its charge
  released as soon as verification succeeds, so it is never budgeted for work it
  is not doing, however many calls it makes.
- **An over-budget client is refused identically for a right and a wrong
  password**, so the refusal reveals nothing about the credential — and, because
  the refusal happens *before* verification, an attacker cannot use it to keep
  guessing without the account ever locking.
- **The charge is held for the duration of one verification**, so the effective
  rule is *failures + in-flight attempts < 60 per client per minute*. A client
  that issues more than 60 **simultaneous** Basic-Auth requests can therefore
  see some refused with `429` even when its credentials are correct. That is
  expected: the refusal is retryable, carries `Retry-After`, and is never
  recorded as a failure, so it cannot lock the account. A client that needs more
  parallelism should use a session cookie rather than Basic Auth on every call.

Watch `culvert_login_limiter_entries` to confirm the bound is holding: it is the
live count of tier-1 and tier-2 entries the lockout is carrying. Sustained
growth with a climbing `culvert_admin_basic_auth_fail_shed_total` means a source
is flooding the admin plane with unusable credentials and being shed.

## Signals

- **Metric** — `culvert_admin_basic_auth_lockout_refused_total` (lockout
  refusals), `culvert_admin_basic_auth_fail_shed_total` (over-budget refusals)
  and `culvert_login_limiter_entries` (the live lockout-state size). Sustained
  growth means a source is grinding credentials against the admin **API**
  rather than the login form. Pair it with
  `culvert_login_oversize_rejected_total` (CHAOS-63) when triaging a probe.
- **Audit** — one `auth.lockout` entry per trip, never one per attempt (a
  per-attempt entry would rebuild the CHAOS-63 durable-log amplifier). The actor
  is the submitted username, truncated.
- **Alert** — the existing `auth_lockout` event, `Source: auth`,
  `Detail: "admin API credential lockout"` (a fixed string, so the dispatcher's
  dedup window works).
- **Log** — one `Auth: refused admin API basic-auth from <ip>` warning at onset,
  then at most one per minute; the magnitude lives in the counter.

## Clearing a lock

A lock expires on its own after 15 minutes. There is no API to clear one; the
documented break-glass is a process restart (lockout state is deliberately not
persisted). `GET /api/auth/lockouts` lists what is currently locked.

If an automation account keeps locking itself out, it is sending a wrong
password — check for a rotated credential. A **successful** Basic Auth call
clears that client's tier-1 counter, so an occasional race with a password
rotation cannot accumulate into a lock.

## Behind a reverse proxy

The client is resolved with `realClientIP` (RISK-019), which honours
`X-Forwarded-For` **only** when the direct peer is in the configured
trusted-proxy set (`trusted_proxy_cidrs`, settable from the admin API /
Settings panel). Without that configuration every request behind an L7 proxy
presents the proxy's address, so one attacker's failures would land on the key
every admin shares. Configure the trusted-proxy CIDRs before putting the admin
panel behind a proxy.

## Known residual risk

**HTTP Basic Auth does not enforce TOTP.** `POST /api/auth/login` requires the
second factor for an enrolled user; the Basic Auth paths never have. An
attacker holding only a valid password can therefore reach the full admin API
for that user's role. This is unchanged by the lockout work and is recorded as
an open posture decision — closing it breaks every CLI/automation client
belonging to a TOTP-enrolled admin and needs a migration path (a scoped API
token, or a per-user "allow basic auth" flag).

Until it is closed, operators who rely on TOTP should restrict the admin port
with `-ui-allow-ip` / `GET,POST /api/ui-allow-ips` so a stolen password is not
sufficient from an arbitrary network.
