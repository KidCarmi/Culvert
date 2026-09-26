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

### One exception: the SSE re-check is read-only

The third path is not a credential *submission*. An SSE stream's Basic
credentials are captured when the connection is established and cannot change
while it is open, so each periodic re-check replays one credential that was
already accepted — it can never be a new guess. That path therefore still
applies the lockout check and still verifies the credential (so a rotated
password or a deleted user terminates the stream, and a locked pair has its
streams cut), but it **records neither a failure nor a success**.

This matters operationally in one direction you would otherwise hit:
**rotating a password does not lock you out.** Streams open at the moment of
the rotation keep replaying the old password until they are cut, and none of
those re-checks counts against the new password's lockout budget.

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

## Limiter-state growth on the public endpoint (AU-17b)

Recording a failure creates limiter state, and the state is keyed by a username
the *caller* chooses. `GET /api/auth/status` is on the public allowlist and is
not a mutating request, so nothing rate-limits it: an unauthenticated caller can
cycle distinct usernames and grow the lockout maps.

What bounds it today:

- **Per key** — the submitted username is clamped to a fixed maximum before it
  becomes a map key, so the *size* of an entry never scales with what the caller
  sends (a 4 KiB username produces the same key footprint as a short one).
- **In time** — an entry whose window has expired is swept by the background
  janitor.
- **In visibility** — `culvert_login_limiter_entries` reports the live count of
  tier-1 and tier-2 entries. Sustained growth with no corresponding
  `auth.lockout` audit activity means a source is cycling usernames rather than
  guessing passwords.

The growth is in entry **count** only, and it never affects whether a valid
credential is accepted. The planned fix is fair-share eviction — evict the oldest
entry belonging to whichever client is holding the most, so a flooding source
evicts itself — which bounds the state without refusing any request.

> **A per-client refusal was tried here and withdrawn (SEC-BASICAUTH-4).** An earlier release
> refused a client that had exceeded a per-window failure budget. Because the
> budget was keyed on the client, an unauthenticated flood from a shared egress —
> a NAT, a CGNAT range, or an L7 reverse proxy with no `trusted_proxy_cidrs`
> configured — denied *every* administrator behind that address, including ones
> presenting correct credentials. It was withdrawn for that reason. If you are
> upgrading from a build that exported
> `culvert_admin_basic_auth_fail_shed_total`, that series is gone; watch
> `culvert_login_limiter_entries` instead.

## Concurrent verification cost (AU-18)

A **locked** attempt still costs no bcrypt — that bound is the lockout check and
is unchanged. What is not bounded is how many *unlocked* attempts may verify at
the same instant, so a client below the lockout threshold can drive several
concurrent bcrypt comparisons. The planned fix is to route this path through the
same credential-cost governor the proxy credential path already uses, which makes
an over-cap client **wait** for its own earlier verification rather than refusing
it.

Until then, restricting the admin port with `-ui-allow-ip` is the operator
control, and the lockout still caps how many attempts any one client can make
per window.

## Signals

- **Metric** — `culvert_admin_basic_auth_lockout_refused_total` (lockout
  refusals) and `culvert_login_limiter_entries` (the live lockout-state size).
  Sustained growth means a source is grinding credentials against the admin
  **API** rather than the login form. Pair it with
  `culvert_login_oversize_rejected_total` (CHAOS-63) when triaging a probe.
- **Audit** — one `auth.lockout` entry per trip, never one per attempt (a
  per-attempt entry would rebuild the CHAOS-63 durable-log amplifier). Note
  which field carries what, because searching the wrong one finds nothing:
  the **object** is the submitted username, truncated, and the **actor** is the
  client IP (the attempt failed, so there is no authenticated identity for
  `auditActor` to prefix it with). Alert on `action = auth.lockout` and read the
  username out of the object.
- **Alert** — the existing `auth_lockout` event, `Source: auth`,
  `Detail: "admin API credential lockout"` (a fixed string, so the dispatcher's
  dedup window works).
- **Log** — one `Auth: refused admin API basic-auth from <ip>` warning at onset,
  then at most one per minute; the magnitude lives in the counter.

## Clearing a lock

A lock expires on its own after 15 minutes. To clear one sooner:

1. `GET /api/auth/lockouts` (admin-only) lists every lock currently in force —
   both the tier-1 (IP, username) pairs and the tier-2 account locks.
2. `POST /api/auth/lockouts` with `{"username":"alice"}` (admin-only) clears
   **every** lock for that username, both tiers and every source IP. The clear
   is audited as `auth.lockout.clear`.

Both are also in the admin UI, as the **Active Login Lockouts** panel on the
Users view (admin-only), with a per-row **Unlock** button. A process restart also clears
everything (lockout state is deliberately not persisted), but it is the
break-glass for when nobody can authenticate to reach the endpoint at all — not
the routine remedy, since it interrupts proxy traffic.

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
