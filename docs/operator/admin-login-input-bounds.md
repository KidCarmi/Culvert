# Admin login input bounds (CHAOS-58)

**Applies to:** every node running the admin UI · **Operator action required:** none
by default; one alerting rule is recommended.

`POST /api/auth/login` is a **public** endpoint — reachable with no session, no
credential and no cluster membership, because it is what the login form posts
to. Culvert bounds the username it accepts so that an unauthenticated caller
cannot use it to write attacker-chosen bytes into state that outlives the
request.

## What changed

A login whose `user` field is longer than **256 bytes** is refused with
`400 Bad Request` before any of the following runs:

- the account-lockout limiter (`internal/lockout`),
- credential verification,
- the `auth_lockout` webhook alert.

The refused attempt **is** still recorded in the audit log as
`auth.login.rejected`, with the username truncated to 64 bytes and marked
`…[truncated, N bytes]`, and the real length in the entry's detail.

**A name that already belongs to a configured account is never rejected**, however
long it is. The 1–64 character cap you see in first-time setup and the
user-creation API lives in those *handlers*, not in the user store: `-user` /
`auth.user` and `--reset-password` can persist an admin with a longer name. If
your deployment has one, it keeps working exactly as before, and Culvert logs a
warning at startup:

```
Auth: admin username is N bytes, above the 256-byte login limit — it still
authenticates, but rename it: every other credential entry point caps at 64
```

That warning is not fatal and needs no immediate action, but renaming the
account to something within 64 characters brings it in line with every other
credential path. The admin UI cannot produce a username past the limit.

## Why the bound exists

Without it, every failed login copied the caller's chosen username verbatim into
three places that outlive the request: the two lockout map keys (which the
janitor cannot sweep for at least 10 minutes), the 500-entry in-memory audit
ring, and the **durable audit JSONL**.

That last one is the important one. The audit file is a rotating file capped at
50 MB that keeps exactly one archive, so the whole retained compliance record is
100 MB. The only limits in front of the handler are the 1 MiB request-body cap
and the 60-mutating-POST-per-minute per-IP API rate limit — together, about
**60 MiB per minute** of chosen bytes from a single unauthenticated client.
That rotates the entire retained audit trail away in under two minutes, and
sustaining it keeps the window rolling, so activity an attacker wants unrecorded
can be preceded by erasing what came before.

Culvert already counts audit writes that *fail* (`culvert_audit_write_errors_total`,
the `storage_write_failed` alert, the `audit_log_persistence` contract row).
None of them fire for this, because **every one of these writes succeeds** —
there is no disk fault. The bound is what closes it.

## Monitoring

```
culvert_login_oversize_rejected_total
```

A counter of login attempts refused for an over-long username. On a healthy
deployment it stays at **0** — the admin UI cannot generate one, and no
legitimate client has a reason to.

Suggested rule:

```yaml
- alert: CulvertAdminLoginProbed
  expr: increase(culvert_login_oversize_rejected_total[15m]) > 0
  for: 5m
  annotations:
    summary: "Admin login endpoint is receiving oversized usernames"
    description: >
      Someone is submitting usernames past the 256-byte limit to
      /api/auth/login. These are refused and cost nothing, but the endpoint is
      public and this is not traffic a browser produces — treat it as an
      unauthenticated probe of the admin plane and check where it is coming
      from.
```

The process log carries the same event, rate-limited to **one line per minute**
(the first rejection logs immediately; the line names the client IP, the
observed length and the running total). The rate limit is deliberate: a
mitigation for a write-amplification defect must not become one itself, so the
magnitude lives in the counter, not in the log.

## If you see it

1. Find the source: the log line names the client IP (resolved through
   `realClientIP`, so it is the real client when a trusted proxy is configured).
   Note that a rejection means the submitted name matched **no** configured
   account — a real admin's login is never counted here.
2. The rejections themselves need no action — nothing was written, no lockout
   state was created, and the audit log recorded each attempt at constant size.
3. Treat it as reconnaissance against the admin plane. If the admin UI is
   reachable from an untrusted network, the durable fix is the IP filter
   (`/api/ip-filter`) or a network-level restriction, not a change to this
   limit.

## Related

- `roadmap/CHAOS-ENGINEERING-REVIEW.md` §25 — the full finding, the measurement,
  and what was deliberately not done.
- `docs/operator/support-bundles-and-diagnostics.md` — the audit-persistence
  health surfaces this finding sits beside.
