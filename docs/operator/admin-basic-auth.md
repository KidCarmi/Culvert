# Admin-plane HTTP Basic authentication (SEC-BASIC-1)

The admin API accepts HTTP Basic credentials as a fallback for CLI and API
clients that cannot hold a session cookie. This page describes what that path
now enforces, and the one case where it is deliberately refused.

## What changed

Basic credentials used to be checked by a bare bcrypt compare
(`cfg.VerifyUIUser`). Everything that makes the interactive login safe lives in
the login **handler**, not in that verifier, so presenting the same credentials
over Basic skipped all of it. Every Basic credential now goes through one
chokepoint (`verifyUIBasicAuth`, `ui_basic_auth.go`) that applies the same
controls, in the same order, as `POST /api/auth/login`:

| Control | Before | Now |
| --- | --- | --- |
| Two-tier account lockout (`loginLimiter`, RISK-012) | not consulted, failures not recorded | enforced and recorded |
| TOTP second factor | not consulted | Basic refused for enrolled accounts (see below) |
| Failed-attempt audit trail | nothing written | `auth.basic.fail` per failure |
| Username length bound (CHAOS-63) | unbounded | bounded, configured accounts exempt |

Three call sites shared the old verifier and all three are now routed through
the chokepoint: the admin middleware (`uiAuthMiddleware`), the SSE authorizer
(`sseAuthStillValid`), and `GET /api/auth/status` — which is on the public
allowlist, so it was reachable with no session at all.

## BREAKING: accounts with TOTP enrolled cannot use Basic

The Basic scheme carries exactly one credential, so an enrolled second factor
cannot be presented over it. The only options are to ignore the factor — which
is what happened before, making TOTP decorative for anyone holding the password
— or to refuse the scheme. Culvert refuses it.

**If your automation authenticates as a TOTP-enrolled account, it will now
receive `401`.** Choose one:

1. **Preferred** — give automation its own account without TOTP, scoped to the
   lowest role that works (`viewer` for read-only dashboards and scrapers).
   Admin RBAC roles are per user, so this narrows blast radius as well.
2. Use the interactive login flow (`POST /api/auth/login` with the `totp`
   field) and carry the returned session cookie.

Removing TOTP from a human administrator's account to unblock a script is the
wrong fix: it restores exactly the exposure this change closes.

## Recognising the two refusals in the audit log

Both appear with the caller's IP as actor and a bounded username:

- `auth.basic.fail` — wrong credentials. Counts toward the lockout. A run of
  these from one source is a password-guessing attempt; it was previously
  invisible.
- `auth.basic.refused` — **correct password**, refused because the account has
  TOTP enrolled. This is the signal that a script is using a 2FA account; it is
  deliberately *not* counted toward the lockout, so a misconfigured script
  cannot lock its own operator out of the login flow.

## Lockout behaviour

Identical to the login endpoint, because it is the same limiter: `MaxAttempts`
failures from one IP against one username lock that pair, and
`AccountMaxAttempts` failures across all IPs lock the account, with previously
successful client IPs exempt from the account-wide tier. A locked caller is
refused **before** any bcrypt runs, which is also what bounds the CPU cost of a
guessing flood — Basic over `GET` is not covered by the mutating-method API
rate limiter.

An operator locked out by a runaway script can clear the state by restarting
the node, or wait out `lockout.Duration`.

## Residual, recorded

`POST /api/auth/change-password` re-verifies the caller's **current** password
and does not consult the lockout. It is reachable only with a valid session,
takes its username from that session rather than the request (so it is not an
enumeration surface), and is a mutating method, so the per-IP API rate limiter
bounds its cost. Adding a lock there would let a session holder lock themselves
out of the login flow, so the trade is deliberate. This is pinned in
`TestSECBASIC1_VerifyUIUserHasNoOtherRequestPathCaller`, which is also the wall
that fails the build if a fourth caller of the bare verifier appears.
