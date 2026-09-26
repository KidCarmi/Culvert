# Session revocation — durability, cluster reach, and recovery

**Applies to:** every Culvert deployment. **Introduced by:** CHAOS-68
(`roadmap/CHAOS-ENGINEERING-REVIEW.md` §38).

---

## 1. Why this plane matters more than it looks

A Culvert session cookie is **self-contained**. It carries the subject, the
groups and the admin role, and it is trusted on the strength of its HMAC
signature alone (`internal/session.Decode`). Nothing re-consults the user roster
on a request:

* the admin UI reads the role **out of the cookie** (`ui_middleware.go`);
* the proxy's identity arm reads the subject and groups **out of the cookie**
  (`proxy.go`), and those feed identity- and group-scoped policy rules.

So deleting an account, or disabling a user, does **not** by itself stop that
user's live session. The **revocation list** is the only mechanism that does,
and the window it would otherwise run to is the session TTL — default 8 hours,
maximum 7 days (`internal/session`'s `maxTTL`).

That makes the revocation list a security control whose *durability* and
*cluster reach* are part of its correctness, not an optimisation.

---

## 2. What is revoked, by what, and where

| Action | Revocation kind | Where it is applied |
|---|---|---|
| Admin or user logs out | **token** — that one cookie | The node serving the logout, then the fleet |
| `DELETE /api/auth/users?username=…` | **account** — every session for that user | The node serving the delete, then the fleet |

Both kinds are now persisted to the revocations file and both ride the CP↔DP
gossip. Before CHAOS-68 only the token kind did either.

**Both logout paths revoke.** The admin console (`POST /api/auth/logout`) always
did; the proxy/portal logout (`/auth/logout`) used to only *clear* the cookie,
which is a request to the browser and not a withdrawal of authority — the token
stayed replayable until its natural expiry, on this node and every other. That
is closed (register row **AU-29**). A logout whose cookie does not verify is not
revoked and does not need to be: every consumer already rejects it, and
accepting unverified values on a public endpoint is how the revocation list
itself becomes a denial-of-service target (**AU-30**).

Propagation reaches three places, and all three matter because each of them
verifies the same cookies (the session signing key is replicated to all of them):

* **Data Plane nodes** — via the `SyncRevocations` sync, every 3 s.
* **The Control Plane itself** — it both contributes its own revocations to the
  fleet and applies what Data Planes report. Before CHAOS-68 it did neither,
  which mattered because the admin UI runs on the CP.
* **An HA standby CP** — via the HA state bundle. `SyncRevocations` is fenced on
  a standby, so without this the standby held the replicated signing key and no
  revocations: a session revoked on the leader authenticated against the
  standby and kept full authority across a promotion.

**Not revoked by anything** (see §7): changing a user's **role** or **password**
via `POST /api/auth/users`. A demoted admin keeps `role: admin` in their
existing cookie until it expires, and a password change does not invalidate a
stolen session. To take either away immediately, delete the account — but
do **not** recreate it under the same username straight away: an account
revocation is keyed on the username and rejects *every* session carrying that
subject until it expires (the configured session TTL, up to seven days),
regardless of when the session was issued. Recreating the same name
immediately therefore locks the replacement account out across the fleet —
and, with persistence on, across restarts — for up to that TTL. Recreate the
account under a **different** username, or wait for the revocation to expire
before reusing the name.

---

## 3. Enabling durability — the one setting that matters

Revocation persistence is **opt-in and off by default**:

```
--revocations-file /data/revocations.json
```

With it unset, every revocation — logout and account deletion alike — is lost
on the next restart.

**This interacts with the session signing key, and the combination is what makes
it dangerous.** If the signing key is random per restart (the single-node
default), a restart invalidates every cookie anyway, so losing the revocation
list costs nothing. But the shipped `docker-compose.yml` sets
`CULVERT_SESSION_SECRET`, and **every clustered deployment must** so that admin
sessions stay valid fleet-wide. A stable key means a cookie survives the
restart that discards its revocation.

> **Rule of thumb:** if you set `CULVERT_SESSION_SECRET` (or `session_secret`),
> you must also set `--revocations-file`. One without the other is the
> configuration in which a revoked session comes back.

The `session_revocation` diagnostics row warns whenever persistence is
unconfigured and states this coupling.

---

## 4. Surfaces

### Diagnostics — `GET /api/diagnostics`, row `session_revocation`

| Status | Meaning | Action |
|---|---|---|
| `ok` | Revocations are durable; counts of tokens and accounts in force | none |
| `warn` | No revocations file configured — revocations are lost on restart | Set `--revocations-file` (§3) |
| `fail` | A revocation could not be **written** | §5 |
| `fail` | The persisted list could not be **parsed** (corrupt; quarantined) | §6 |
| `fail` | Corrupt **and could not be quarantined** — the damaged file is still in place | §6b |
| `fail` | The **directory** holding the revocations file is gone | §6c |
| `fail` | The persisted list could not be **read** (permissions, I/O, mount) | §6 |
| `fail` | The revocations file is **missing** | §6a |

The row carries counts and a remedy only. It never names a revoked username or
token — it is reachable at viewer role.

### Metrics — `/metrics`

| Series | Type | Meaning |
|---|---|---|
| `culvert_session_revocation_durable` | gauge | `1` when a revocation applied here survives a restart |
| `culvert_session_revocation_tokens` | gauge | Logout revocations in force on this node |
| `culvert_session_revocation_users` | gauge | Deleted-account revocations in force on this node |
| `culvert_session_revocation_persist_failures_total` | counter | Revocations applied in memory that could not be written |
| `culvert_session_revocation_persist_degraded` | gauge | `1` while the latest revocation save failed and none has landed since (the page signal) |
| `culvert_session_revocation_persist_refused_total` | counter | Revocations not written because overwriting the file was refused — it could not be read this boot (§6), or it is corrupt and could not be quarantined (§6b) |

These are emitted **unconditionally**, which is the deliberate exception to
Culvert's usual "omit the series when the feature is off" rule. Elsewhere a flat
`0` from a node that never enabled a feature is indistinguishable from a broken
one. Here the two causes mean the same thing to you — *a revocation applied on
this node does not survive a restart* — and that is exactly the condition worth
watching. The contract row tells you which cause applies.

Suggested rules — and note that **`_durable == 0` on its own is a warning, not
a page**:

```
# Warn: a revocation applied on this node does NOT survive a restart. On a
# default appliance this is TRUE AND EXPECTED — persistence is opt-in, so the
# unconfigured posture and an actively failing volume both report 0. Alerting
# on this alone pages every default install forever.
culvert_session_revocation_durable == 0

# Page: writes are failing RIGHT NOW — an admin was told a session was
# withdrawn and it was not written down. _persist_degraded is CURRENT write
# state: set by a failed save and cleared ONLY by a save that lands, so the
# page stays active for exactly as long as the fault is unresolved — even if
# no further logout or sync ever triggers another write. (An increase()
# window over the failure counter is NOT equivalent: it empties after the
# window and clears the page while durability is still lost.) It is 0 on an
# unconfigured default appliance, so it never pages there.
culvert_session_revocation_persist_degraded == 1

# Investigate: a durability incident happened in this process. Cumulative and
# never reset, so it stays visible after the condition above has cleared.
increase(culvert_session_revocation_persist_failures_total[1h]) > 0
```

The three are deliberately different instruments. `_durable` is **current
state** and recovers on its own when the volume is repaired, but it is
*two-valued over three causes* — unconfigured, load-degraded, and write-failing
all read 0 — so it identifies the condition and not the fault. The counter is
the **magnitude** of an incident and is never reset, so alerting on it alone
would latch until the process restarts, which is the bug this row was fixed for
(and the same one `ca_health.go` records having already fixed once). The page
therefore keys on `_persist_degraded`, which is current state for the one
cause that is a fault (writes failing) and nothing else. The contract row on
`/api/diagnostics` names the cause in words.

**The first draft of this file got this wrong** and labelled the bare
`_durable == 0` a page, which would have paged permanently on every default
installation — and contradicted `metrics.go`, whose own comment called it a
warn. Reported by Codex on PR #1437 as a P2.

**Durability is proven at boot, not assumed.** The node writes the revocations
file at startup rather than inferring that it could: a readable path and a
writable one are different claims, and the surfaces below report the second. So
a missing parent directory, a read-only mount or a permissions fault degrades
the moment the node starts, instead of staying green until some operator's
logout hours later turns out to be the first write (**AU-31**).

That applies whether or not the file already exists. A file that is present and
parses cleanly proves only that the path is *readable* — a volume remounted
read-only after an I/O error, a restore mounted read-only, or a directory whose
permissions changed all leave a perfectly good file on a path nothing can write
to. The startup write covers that case as well.

It deliberately does **not** run when the file could not be read, or when it was
read and could not be parsed. In the first case the content may be intact behind
a transient fault and a write attempt is the one action that could destroy it;
in the second the file is about to be quarantined and writing first would
overwrite the evidence. In both, the `session_revocation` row fails with the
load-failure reason instead — a different remedy from a permissions fault, which
is why the two states are kept apart.

### Cluster revocations — `GET /api/cluster/revocations`

`local_revoked` (tokens), `local_user_revoked` (accounts), `revocations_durable`.

These are on `/api/cluster/revocations`, **not** `/api/cluster/status` — an
earlier draft of this runbook named the wrong endpoint, which is a valid route
that simply does not carry these fields, so an operator following it would find
nothing and have no way to tell a missing field from a missing feature. The
OpenAPI document (`ClusterRevocations`) had it right throughout. Reported by
Codex on PR #1437 as a P2.

The counts are **live** entries: expired revocations are pruned as they are
read, so a count never reports a revocation that has already lapsed.

### Alerts and `/readyz`

A **corrupt** revocations file fires the existing `state_file_corrupt` alert and
produces the existing `state_file_session_revocations` readiness row — the same
response `ui_users.json` and `cluster.json` already get. No new alert event was
introduced, so an existing webhook subscription picks this up without a config
change.

There is deliberately **no `/readyz` row of its own** for a non-durable
revocation list. A node whose revocations are not durable is proxying and
authenticating perfectly; failing readiness would eject a healthy gateway from
its load balancer over a management-plane degradation.

---

## 5. Recovery: `session_revocation` is `fail`, persist failures non-zero

**Meaning:** a logout or an account deletion was reported to the admin as
complete, and the only durable record of it does not exist. After the next
restart those sessions are live again.

1. Check the volume backing the revocations file: free space, permissions,
   mount state. `AtomicWrite` needs to create a temp file in the same directory
   and `fsync` it.
2. **Fix the volume.** Recovery is automatic and needs no restart: the next
   successful save writes the *complete* live list, so every revocation still
   in memory becomes durable again. At that point
   `culvert_session_revocation_durable` returns to `1`,
   `culvert_session_revocation_persist_degraded` returns to `0`, and the
   `session_revocation` row returns to `ok`.
   `culvert_session_revocation_persist_failures_total` is cumulative and
   deliberately does **not** reset, so the incident stays visible on `/metrics`
   after the row has cleared — that is where you look to confirm one happened.
3. **Re-apply anything revoked during a restart in the window.** A revocation
   applied while writes were failing is recovered by the next successful save
   *if the process survived*. If the process restarted before that save, those
   revocations are gone: re-delete the accounts, and treat any session revoked
   on this node in that window as still live.

Until the volume is fixed, a restart is a security event, not a maintenance one.

## 6. Recovery: the persisted list did not load

If the file was **corrupt** (read fine, would not parse), Culvert has already
moved it aside to `<path>.corrupt.<unixnano>`, fired `state_file_corrupt`, and
booted with an empty list. The move is what stops the next save from
overwriting your evidence.

1. Inspect the quarantined file. If it is intact enough to repair, repair it,
   move it back, and restart.
2. Otherwise restore a backup and restart.
3. If neither is possible, **re-apply every revocation you rely on** — the node
   is currently honouring every cookie that was revoked before the restart.
4. Remove the `.corrupt.*` file once reconciled. It is re-surfaced on every
   boot until you do, deliberately: a later save writes a fresh empty list that
   parses cleanly, so without that reminder probes go green over a lost
   revocation list.

If the file could **not be read** (permissions, I/O, a mount that went away),
it is *not* quarantined — the content may be perfectly intact behind a
transient fault, and moving a healthy security-critical file aside is the worse
error. There is therefore **no `.corrupt.*` copy and no
`state_file_session_revocations` row** for this case; the `session_revocation`
row says so and gives its own remedy, which is to fix the permission or the
mount and restart.

**The file is protected while it cannot be read.** Every writer
(`SaveRevocations`) refuses for as long as this boot failed to read the file, so
nothing renames over content the process never saw — a restart after the repair
loads the original list. This matters because `AtomicWrite` needs only the
parent *directory* to be writable, so without the fence an unreadable file in a
writable directory would be silently replaced by whatever handful of revocations
the process happened to know about, and the repair would then load the truncated
file.

The cost is that revocations applied in the meantime are **memory-only**: they
are enforced by this node now and gone at the next restart.
`culvert_session_revocation_persist_refused_total` counts them, and the row
reports the same number — it is the size of the re-apply job. Refusals are
deliberately **not** counted as persistence failures
(`..._persist_failures_total`, `..._persist_degraded`): no write was attempted
and the volume may be perfectly healthy, so the remedy is the permission repair
above, not free space.

## 6a. Recovery: the revocations file is missing

The row reads:

> the revocations file is missing — the N token and M account revocation(s) in
> force on this node are held in memory only and are lost on the next restart

Persistence is armed and the file it writes to is not there. Nothing in the
node deleted it: startup proves the path by writing to it, so a file that is
absent afterwards was removed from outside — an operator deleting it, a restore
that did not include it, or a replaced mount.

This state is **self-healing on the next write**, and usually before you see
it:

* **On a clustered node** the next config sync rewrites the complete list
  (every 3–5 s), whether or not that sync carries anything new. The window is
  seconds.
* **On a standalone node** the next logout or account deletion recreates the
  file with the full list. Until one happens, nothing writes.

So the action is:

1. Check what happened to the mount or directory — the file vanishing is the
   symptom, not the cause, and if the mount is gone the repair write will fail
   too and the row moves to §5.
2. If the row does not clear within a few seconds on a clustered node, treat it
   as §5: the rewrite is being attempted and failing.
3. On a standalone node, confirm the file reappears after the next revocation.
   Until it does, **treat every revocation the row counts as lost on restart** —
   do not restart the node if you are relying on them.

Note the deliberate split with the metric: `culvert_session_revocation_durable`
stays `1` here, and that is correct rather than a bug. It states *a revocation
applied right now would survive* — which is true, because the write that
applies it recreates the file with everything in memory. The row states the
different and stronger claim that *the revocations already in force are on
disk*, and that is the one a missing file falsifies. Page on
`_persist_degraded` (§5) for writes that are failing; watch this row for
revocations that are not written down.

---

## 6b. Recovery: corrupt, and the quarantine failed

If the damaged file could not be renamed aside — its name is too long for the
`.corrupt.<timestamp>` suffix, or its directory is read-only — there is **no
`.corrupt.*` copy to restore**, and the damaged file is still at its own path
as the only record of what this node was enforcing.

**Writes are refused while this holds.** Saving would replace those bytes, so
`SaveRevocations` returns a refusal instead and every revocation applied in the
meantime is memory-only (counted by
`culvert_session_revocation_persist_refused_total`).

1. Copy the revocations file somewhere safe **first**.
2. Free its path — shorten the configured filename, or fix the directory's
   permissions.
3. Restart. Until then nothing is written and nothing is lost.

---

## 6c. Recovery: the directory is gone

Distinct from §6a: if the *file* is missing the next save recreates it, but if
the **parent directory or mount** is missing nothing can. `AtomicWrite` creates
its temporary file inside that directory and never creates the directory
itself, so every save fails until the mount is back.

The node reports `durable = 0` and the row fails immediately rather than
waiting for a write to discover it.

1. Restore the mount or directory.
2. Restart.
3. Re-apply any logout or account deletion that had to hold.

---

## 7. Known limits (deliberate, recorded)

* **Role and password changes do not revoke.** `POST /api/auth/users` changing a
  role or password leaves existing cookies untouched — a demotion does not take
  effect until the session expires, and a password change does not invalidate a
  stolen session. Deleting the account forces both, subject to the next bullet.
  Recorded as register row **AU-23**; closing it changes an admin workflow and
  needs its own review.
* **An account revocation locks out a same-name replacement.** `RevokeUser`
  records the *username* until `now + TTL`, and every session carrying that
  subject is rejected regardless of when it was issued — the signed cookie
  payload has no issued-at field to check, only `Exp`. So deleting an account
  and immediately recreating it under the same name produces a replacement
  whose brand-new cookies are refused on every node holding the revocation, for
  up to the session TTL, and no admin API withdraws a revocation early.
  **Recreate under a different username, or wait for the revocation to
  expire.** The behaviour predates this sweep, but the sweep made its
  consequences durable and fleet-wide — a restart or a different node used to
  end the lockout by accident and no longer does. Recorded as register row
  **AU-28**; the principled fix is an issuance-time cutoff, which is a
  wire-format change to a security control and needs its own review.
* **A user revocation crosses identity providers.** `RevokeUser` stores the
  bare username and the check in `Decode` tests it against the session's
  subject without consulting the session's provider, so deleting the **local**
  admin `alice` also rejects an OIDC, SAML or LDAP session whose subject is
  `alice`. That is an ordinary collision, not a contrived one: a SAML NameID and
  an OIDC `sub` mapped to a username claim both carry usernames, and a local
  break-glass account named after a directory account is the normal case. The
  direction is fail-closed — it denies a session it need not deny and never
  admits one it should not — and only an admin can trigger it, so the cost is
  availability for an unrelated federated user for up to the session TTL.
  **If this bites, the remedy is the same as the bullet above: wait out the
  revocation, or avoid reusing one name across the local roster and the
  directory.** Recorded as register row **AU-32**; like AU-28 the behaviour
  predates this sweep, and like AU-28 this sweep made its consequences durable
  and fleet-wide. Both candidate fixes need their own review — restricting the
  check to local sessions *loosens* a security control, and namespacing the
  revocation key by provider changes the persisted and gossiped key, which a
  node predating the change would not match.
* **Persistence is opt-in.** Defaulting `--revocations-file` to
  `<dataDir>/revocations.json` is the obvious improvement and is recorded as
  **AU-22**; it starts writing a new file on every appliance, which is a default
  change deserving owner sign-off rather than a side effect of this sweep.
* **Cluster propagation is eventually consistent**, bounded by the DP sync
  interval (3 s) plus one hop through the CP. A revocation applied on one node
  is enforced fleet-wide within a few seconds, not instantly.
* **A Data Plane that cannot reach its Control Plane stops receiving
  revocations** for the duration of the outage. It keeps enforcing the ones it
  already has (and, with `--revocations-file` set, across a restart). This is
  the same posture as every other CP-sourced state and is covered by the
  existing CP-link alerting.
* **In-flight SSO sessions survive IdP deletion** — a separate, still-open gap
  (register row **AU-2**), not addressed here.
