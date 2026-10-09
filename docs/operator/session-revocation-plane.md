# Session revocation: what it bounds, and what a refusal means

*Applies from CHAOS-73. Covers the admin-UI session revocation list, the public
`/api/auth/logout` endpoint, and the cluster revocation gossip that carries
revocations between nodes.*

## What this plane does

When an administrator logs out of the admin UI, Culvert records the session
token on a revocation list so that a replayed cookie stops working before its
natural expiry. In a cluster the list is gossiped: each Data Plane node pushes
its entries to the Control Plane every 3 seconds and merges back the entries
from every other node, so logging out invalidates the session fleet-wide.

`/api/auth/logout` is deliberately **public** (it is on the admin-UI auth
middleware's allowlist). It has to be: a session that has already expired or
been revoked cannot authenticate a request, and it must still be able to clear
its own cookie.

## The rule that makes a public endpoint safe here

A revocation key is the payload half of a cookie **this appliance signed**. So
the logout path verifies the cookie's HMAC before it retains anything. A
cookie Culvert did not sign cannot name a session of Culvert's, which means
there is nothing for it to revoke and refusing it loses nothing.

Verification does **not** break the case the public route exists to serve: the
signature is checked before the expiry, so a genuine but expired cookie still
verifies and still logs out.

A refusal is **silent to the caller**: the request still answers `200` and the
cookie is still cleared. That is deliberate. If a forged cookie produced a
different status or body than a genuine one, logout would become an oracle an
unauthenticated caller could use to test whether a captured cookie is still
valid.

## Surfaces

| Surface | What it tells you |
|---|---|
| `culvert_session_revoke_refused_total` | Logout requests carrying a cookie this appliance did not sign. **Ordinary traffic cannot produce one** — a genuine expired cookie and a replayed logout are both excluded — so any non-zero value is somebody sending forged cookies. |
| `culvert_session_revoke_rejected_total{reason}` | The per-reason breakdown. `unsigned` / `malformed` / `expired` come from the public logout endpoint; `oversize` / `capacity` come from the **untrusted-origin** paths (cluster gossip, the on-disk revocations file). |
| `culvert_session_revocations_tracked` | Entries currently held. Bounded by real logins inside one session TTL. A value that tracks *request* rate rather than *login* rate means something is inserting entries that are not sessions. |
| `culvert_cluster_revocation_drops_total` | Entries the Control Plane refused to retain from a Data Plane node. **Non-zero means a session an operator revoked may still authenticate on other nodes.** |
| `/api/diagnostics` → `session_revocation` | The operator-contract row. WARN-only; counts only, never a client address or any part of a cookie. |
| Process log | `SESSION_REVOKE_REFUSED <client-ip> {reason=… bytes=… total=… action=none}`, rate-limited to one line per minute with the cumulative count on every line. |

The two counters mean different things and point at different actions:

* **`refused` climbing** is an attacker being correctly turned away. The
  control is working; the question is why an untrusted network can reach the
  admin port.
* **`drops` climbing** is a security decision that did not take effect
  everywhere. That is the one to act on.

## Runbook

### `culvert_session_revoke_refused_total` is climbing

Ordinary traffic does not produce this, so treat it as probing of the public
logout endpoint.

1. Confirm the admin/UI port is not reachable from untrusted networks. It
   should sit behind an allowlist or a management VLAN; the proxy data path
   does not need it.
2. Read the rate-limited `SESSION_REVOKE_REFUSED` lines for the source
   address. The line carries the client IP, a bounded reason class and the
   cookie **length** — never the cookie itself.
3. Nothing is retained and nothing is written, so there is no state to clean
   up. No restart is required.

### `culvert_cluster_revocation_drops_total` is non-zero

A revocation entry was dropped because its key was longer than any cookie this
appliance could issue, or because a per-node cap was reached.

1. Treat the affected admin sessions as potentially still live. The reliable
   way to invalidate every session at once is to change the session secret
   (`CULVERT_SESSION_SECRET` / `session_secret` / `/api/session-secret`), which
   makes every existing cookie fail its signature check.
2. Check whether one cluster peer is pushing malformed revocation state — a
   node running an older build, or one whose revocations file was hand-edited
   or restored from elsewhere.
3. The cap is far above any real deployment (a node holds one entry per logout
   inside one session TTL), so reaching it means a node is malfunctioning, not
   busy.

### `culvert_session_revocations_tracked` keeps growing

Entries are reclaimed by a sweep that runs as revocations are recorded, and
each entry self-expires at its own session expiry (at most the session TTL,
capped at 7 days). A count that keeps growing past your login volume means
entries are arriving from somewhere other than logins — check the `oversize`
and `capacity` reasons above, and check the on-disk revocations file if
`--revocations-file` is configured.

## Notes and limits

* **Persistence is opt-in.** Without `--revocations-file`, revocations live in
  memory only and are lost on restart — a revoked session becomes valid again
  until its natural expiry. That is pre-existing behaviour and unchanged.
* **The revocations file is not in the backup allowlist** (recorded in
  `docs/engineering/PRODUCTION-FAILURE-MODE-AUDIT.md` F-18). A restore does not
  carry revocations forward; plan DR around re-issuing them.
* **User-level revocation is node-local.** `RevokeUser` (used when an account
  is deleted) is neither persisted nor gossiped — register row AU-19. The
  backstop is the admin-UI middleware's roster check for local provider
  sessions.
