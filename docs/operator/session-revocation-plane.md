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
| `culvert_session_revoke_unverifiable_total` | Logout requests carrying a cookie this appliance did not sign. **Ordinary traffic cannot produce one** — a genuine expired cookie and a replayed logout are both excluded — so any non-zero value is somebody sending forged cookies. |
| `culvert_session_revoke_refusals_total{reason}` | Every refused revocation entry, by reason. `unsigned` / `malformed` / `expired` come from the public logout endpoint; `oversize` / `capacity` / `far_future` come from the **untrusted-origin** paths (cluster gossip, the on-disk revocations file). `far_future` is an entry whose expiry lies beyond the maximum session lifetime (7 days plus one hour of clock skew), which no session this appliance issues can have. Revocations this node verified itself are written to the revocations file with a provenance MAC (under the session signing key) and are reloaded past the size bound and the entry cap, so a revoked large cookie stays revoked across a restart with the same key; persisted entries without a valid MAC are treated as untrusted. With a random per-start key the MAC does not verify after restart, which is harmless because the old cookies no longer verify either. |
| `culvert_session_revocations_tracked` | Entries currently held. Bounded by real logins inside one session TTL. A value that tracks *request* rate rather than *login* rate means something is inserting entries that are not sessions. |
| `culvert_cluster_revocation_drops_total` | Entries the Control Plane refused to retain from a Data Plane node. **Non-zero means a session an operator revoked may still authenticate on other nodes.** |
| `culvert_cluster_revocation_sync_deferred_total{leg}` | Entries a `SyncRevocations` message left for a later tick because the full list exceeded that leg's byte budget (`request`: Data Plane → Control Plane, budget 15 MiB under the 16 MiB inbound limit; `reply`: Control Plane → Data Plane, 127 MiB under the 128 MiB frame). Nothing is dropped: the node's own logouts go first, then account revocations, then learned tokens, and the rest rotate through later ticks (register rows AU-50, AU-71). Sustained growth means the revocation backlog no longer fits one message, so fleet-wide propagation of an older entry can take several 3 s ticks. |
| `/api/diagnostics` → `session_revocation` | The operator-contract row. The conditions on this page (dropped entries, unverifiable logouts) are WARN; the same row FAILs first on a durability fault (see [session-revocation.md](session-revocation.md)). Counts only, never a client address or any part of a cookie. |
| Process log | `SESSION_REVOKE_REFUSED <client-ip> {reason=… bytes=… total=… action=none}`, rate-limited to one line per minute with the cumulative count on every line. |

The two counters mean different things and point at different actions:

* **`unverifiable` climbing** is an attacker being correctly turned away. The
  control is working; the question is why an untrusted network can reach the
  admin port.
* **`drops` climbing** is a security decision that did not take effect
  everywhere. That is the one to act on.

### Deprecated metric names (removed in v1.1.0)

The two refusal counters were renamed by T-70 of the 2026-10-25 terminology
review. Their released names (v1.0.340 onward) keep emitting **unchanged** —
same name, same labels, same value — as deprecated aliases until **v1.1.0**,
so existing dashboards and alert rules keep working. Move them to the new
names before upgrading to v1.1.0:

| Released name (deprecated) | New name | Notes |
|---|---|---|
| `culvert_session_revoke_refused_total` | `culvert_session_revoke_unverifiable_total` | Unlabeled. Logout cookies this appliance could not verify. |
| `culvert_session_revoke_rejected_total{reason}` | `culvert_session_revoke_refusals_total{reason}` | Same six `reason` values. |

`culvert_session_revoke_refused_total` keeps its released meaning (the
unlabeled could-not-verify count) for its whole life and is **never** reused
for the per-reason series: an alert on it must not start evaluating a
different quantity under the same name. Both pairs are emitted from one
snapshot, so the old and new names always agree within a scrape. A query that
must span the rename can select both names and take one, which neither gaps
nor double-counts:
`max by (instance, reason) ({__name__=~"culvert_session_revoke_(rejected|refusals)_total"})`.

## Runbook

### `culvert_session_revoke_unverifiable_total` is climbing

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

### A key rotation makes this counter climb, and that is not an attack

`culvert_session_revoke_unverifiable_total` counts logout requests carrying a cookie
this appliance **could not verify**. It cannot distinguish a forgery from a
genuine cookie signed under a **previous** session secret, because neither
verifies under the current key.

So after a deliberate `session_secret` rotation — or a restart on a deployment
that mints a fresh random key, which is the default when no secret is
configured — every browser still holding a pre-rotation cookie produces one of
these the next time it logs out. The counter climbs, the
`SESSION_REVOKE_REFUSED` lines appear, and the `session_revocation` row goes
WARN, with no attacker involved.

**Check the key first.** If you rotated the session secret (or restarted
without a configured one) around the time the count started rising, this is
expected and self-limiting: it stops once those sessions re-authenticate.
Nothing is lost by the refusal — a cookie signed under the old key no longer
decodes, so it is already invalid and there is nothing left to revoke.

A count that keeps climbing with **no** recent key change is the signal the
counter exists for: treat it as probing of the public `/api/auth/logout`
endpoint and confirm the admin port is not reachable from untrusted networks.

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
