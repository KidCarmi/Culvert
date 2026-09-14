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

## Signals

- **Metric** — `culvert_admin_basic_auth_lockout_refused_total`. Sustained
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
