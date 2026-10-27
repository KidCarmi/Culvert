# Admin API credential lockout: seeing and clearing it

Culvert's admin plane accepts credentials two ways: the browser login form
(`POST /api/auth/login`) and HTTP Basic for CLI and API clients (see
[admin-basic-auth.md](admin-basic-auth.md)). Both feed the same two-tier
brute-force lockout. This page covers what an operator sees when it engages,
how to find what is locked, and how to clear it without a restart.

## The bound

Shared by both paths (`internal/lockout`):

| Tier | Key | Trips after | Locks for |
| --- | --- | --- | --- |
| 1 (pair) | (client IP, username) | 5 failures in 10 min | 15 min |
| 2 (account) | username, across all IPs | 20 failures in 10 min | 15 min |

A client IP that completed a **successful** login for that username within the
last 30 days bypasses tier 2, so a distributed flood cannot lock the real
operator out of their own appliance. A locked attempt is refused **before** any
password check, so it costs no bcrypt.

HTTP Basic adds one more bound in front of the lockout: a per-client-IP
failure budget (60 failures per minute, `lockout.Burst` per
`lockout.RateWindow`). It is
reserved atomically before the password check, so a burst of parallel
connections gets the same number of guesses as a serial caller, and refunded
on success, so a correctly configured script is never throttled by it.

## What a refused client sees

| Path | Wrong password | Locked, or over the Basic budget |
| --- | --- | --- |
| `POST /api/auth/login` | `401` | `429` with the lockout message |
| HTTP Basic on any `/api/` route | `401` | `401` |
| `GET /api/auth/status` with Basic | `200 {"loggedIn":false}` | `200 {"loggedIn":false}` |

The Basic and status answers deliberately do not distinguish "locked" from
"wrong". `/api/auth/status` is reachable without a session, and saying "locked"
there would confirm to an anonymous caller that the account exists and is under
attack. To see what is actually locked, ask the lockout API below.

## The SSE re-check never counts as an attempt

A live dashboard stream authenticated with HTTP Basic re-checks its credential
about once a minute. Those headers were captured when the stream opened and
cannot change, so a re-check is not a guess (SEC-BASICAUTH-5). It still
refuses: a rotated password, a deleted account, an account that enrolled TOTP,
or a locked (IP, username) pair ends the stream. But it never reserves the
Basic budget and never records a failure or a success.

In practice: **rotating a password does not lock you out.** Streams still
carrying the old password are cut at their next re-check, and none of those
re-checks counts against the new password. A stream held open from a shared
egress also cannot reset another client's failure count.

## Finding and clearing a lock

A lock expires on its own after 15 minutes. To clear one sooner, as an admin:

1. `GET /api/auth/lockouts` lists every lock in force, both tier-1
   (IP, username) pairs and tier-2 account locks, with the seconds remaining.
2. `POST /api/auth/lockouts` with `{"username":"alice"}` clears **every** lock
   for that username: both tiers, every source IP. The clear is audited as
   `auth.lockout.clear`.

```sh
curl -sS -u "$ADMIN_USER" "https://$ADMIN_HOST/api/auth/lockouts"
curl -sS -u "$ADMIN_USER" -H 'Content-Type: application/json' \
  -d '{"username":"alice"}' "https://$ADMIN_HOST/api/auth/lockouts"
```

The legacy admin UI's Users view has the same data as the **Active Login
Lockouts** panel, with an **Unlock** button per row.

A process restart also clears every lock, because lockout state is not
persisted. It is the break-glass for when nobody can authenticate to reach the
endpoint, not the routine remedy, because it interrupts proxy traffic.

If an automation account keeps locking itself, it is sending a wrong password.
Check for a rotated credential.

## Signals

- **Audit**: `auth.basic.fail` on every failed Basic submission, and
  `auth.login.fail` on the login form. The **object** is the submitted
  username (truncated); the **actor** is the client IP, because a failed
  attempt has no authenticated identity. Alert on the action and read the
  username from the object. `auth.basic.refused` means a **correct** password
  for a TOTP-enrolled account was presented over Basic: a script that needs
  migrating, or a compromised first factor.
- **Metric**: `culvert_login_limiter_entries` is the live number of tier-1 pair
  plus tier-2 account entries. The keys are usernames a caller chooses, and the
  public `GET /api/auth/status` accepts Basic, so sustained growth without a
  matching rise in `auth.basic.fail` for real accounts means a source is
  cycling usernames rather than guessing a password. Pair it with
  `culvert_login_oversize_rejected_total` when triaging a probe.
- **Alert**: the `auth_lockout` webhook event (and `auth.lockout` audit entry)
  fires when a login-form attempt hits an active lock. The Basic paths raise no
  alert of their own; a lock tripped over Basic appears in the `auth.basic.fail`
  trail and on `GET /api/auth/lockouts`.

## Behind a reverse proxy

The client is resolved with `realClientIP` (RISK-019), which honours
`X-Forwarded-For` only when the direct peer is in `trusted_proxy_cidrs`.
Without that, every request behind an L7 proxy presents the proxy's address, so
one attacker's failures land on the key every admin shares. Configure the
trusted-proxy CIDRs before putting the admin panel behind a proxy.
