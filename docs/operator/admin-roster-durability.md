# Admin-roster durability (CHAOS-70)

**Applies to:** every node running the admin UI · **Operator action required:**
none by default; two alerting rules are recommended.

`ui_users.json` is the **only** durable home of the admin roster (the persisted
multi-user set of console accounts, product term **Administrators**, managed in the
console's Admin Users panel and through `/api/auth/users`; the legacy single-user
login set by `-user` / `auth.user` is not a roster row and is changed through
Settings and the startup flags, not Admin Users): every account,
password hash, role, TOTP secret, consumed-backup-code list and TOTP replay
counter. Every change to that state is applied to memory first and written to
disk second, so the two can disagree — and the disagreement is resolved at the
next restart, when the file wins.

## What changed

Four administrative mutations are now **durable-or-refused**. If the roster
cannot be written, the in-memory change is rolled back and the request fails:

| Action | Endpoint | Before | Now |
|---|---|---|---|
| Create account / set password / change role | `POST /api/auth/users` | `200 {"ok":true}` | `500`, nothing changed |
| Delete account | `DELETE /api/auth/users` | `204 No Content` | `500`, nothing changed |
| Self-service password change | `POST /api/auth/change-password` | `200 {"ok":true}` | `500`, nothing changed |
| Admin credential (Settings panel) | `POST /api/settings` | `200 {"ok":true}`, **never persisted** | persisted, or `500` with nothing changed |

### `POST /api/settings` — read this one if you have ever used the Settings panel

The first three endpoints above persisted and mis-reported only when the write
*failed*. `POST /api/settings` — the **Settings panel's Save button** — did not
write the roster at all, and there was no other writer: the admin credential is
not carried in `admin_settings.json`. Three consequences, all of which needed no
disk fault:

1. **A rotated admin password reverted at the next restart.** The panel answered
   *"Settings saved"*, the new password worked immediately, and after a restart
   the **previous password authenticated again**. If you rotated because a
   credential leaked, the leaked one came back.
2. **A blank password field installed an empty password.** Complexity was only
   checked when the field was non-empty, so saving the panel with the password
   box blank set the admin password to the empty string — and, if you had also
   edited the username, created a *new* admin account that authenticated with no
   password. Until restart.
3. **Clearing both fields disabled local admin authentication**, again behind a
   *"Settings saved"* toast.

Both input faults are now refused with `400`, and the credential change is
durable-or-refused like the other three. To run unmatched traffic without
credentials, set `defaultAuthOutcome=Exempt`
(`PUT /api/settings/default-auth-outcome`) — that endpoint is explicit about it;
blanking a text field is not.

**What to check on an appliance that used the Settings panel before this fix:**
confirm the admin credential you expect is the one in effect *after a restart*,
not just now. If a rotation was lost, redo it; if an empty or unintended password
was installed, it will already have reverted at the first restart — but any
account created by that path never existed on disk, so re-create it deliberately
through `POST /api/auth/users`.

The refusal body names the remedy and states plainly that nothing was modified:

```
the change was NOT applied: the admin roster could not be written to disk
(check disk space and the data volume's permissions, then retry).
Nothing was changed — no account, role, password or TOTP enrolment was modified.
```

The refusal is also written to the audit log as `<action>.refused` (for example
`auth.users.delete.refused`), so the compliance record carries a trace of an
attempted revocation that did not take effect. Previously the audit log recorded
the action as **successful**.

### Why this is a correctness fix, not a strictness change

Before this change, an operator responding to an incident on a node whose data
volume had gone read-only or full would:

- **delete a compromised administrator** and receive `204 No Content`. The
  account — password hash, role and TOTP enrolment intact — returned at the next
  restart.
- **downgrade a role** from admin to viewer and receive `{"ok":true}`. The
  privilege was restored at the next restart.
- **rotate a leaked password** and receive `{"ok":true}`. The old password still
  authenticated after the next restart.

In each case the HTTP response, the UI and the audit trail all reported success.
The only contemporaneous evidence was one line in the process log and the generic
`storage_write_failed` alert, neither of which says *which* administrative
decision was lost. The divergence between memory and disk then stayed invisible
until a restart materialised it — potentially weeks later, and most likely during
the same incident that filled the disk.

The same rule already governed first-time setup (`POST /api/setup/complete`
rolls back and returns non-2xx when the admin credential cannot be saved). This
change applies it to the ongoing-administration mutations of the same file.

### The rollback is exact

The primitive snapshots the whole roster before mutating and restores it wholesale
on failure, rather than asking each caller for an inverse operation. Undoing a
delete means restoring the account's password hash, role, TOTP secret, backup
codes **and** replay counter — none of which the handler still holds by the time
the write fails. A partial restore would leave an account its owner can no longer
use and an operator cannot see is broken.

Cached authentication decisions are invalidated on rollback, so a rolled-back
password change cannot leave the new password working from cache.

### One error is deliberately not a failure

`fileutil.ErrReplacedNotSynced` means the rename already landed the new content
and only the parent-directory `fsync` failed. Every future reader,
including a restart, sees the new roster, so the change **did** take effect and
the request succeeds. It is logged loudly: the write is durable across a process
crash and at risk only across a power loss in the following moments.

## What is deliberately still fail-open

Two roster writes happen on the **login** path — advancing the TOTP replay
counter, and removing a consumed single-use backup code. These are **not**
refused when the write fails: the login proceeds.

Refusing them would mean that an operator whose TOTP device is lost, on an
appliance whose volume has just gone read-only, cannot reach the admin UI at
all — during exactly the incident they need it to diagnose. That is the terminal
state CHAOS-55 and CHAOS-57 both refuse: an appliance nobody can manage. The
weakening is bounded by the outage and requires an attacker to already hold a
valid backup code or a live OTP; locking the legitimate administrator out is the
larger harm.

The residual risk is real and is owned here: **across a restart taken while the
volume was unwritable, a consumed backup code is valid again and the replay
window for an already-used OTP reopens.** The failure is no longer silent — it is
counted and logged — but the posture is availability-first. Flipping it to
fail-closed is a one-line change at the two call sites in `verifyLoginTOTP`.

## Metrics

Both counters are emitted unconditionally; a flat zero is the healthy steady
state for every appliance.

| Series | Meaning |
|---|---|
| `culvert_admin_roster_persist_failures_total` | Roster changes **refused and rolled back**. Non-zero means an operator's account/role/password change did not take effect and must be retried. |
| `culvert_admin_roster_persist_degraded_total` | Login-path roster writes that failed while the login proceeded. Non-zero means a single-use credential or replay counter may not survive a restart. |

These are deliberately distinct from the storage plane's `storage_write_failed`
alert, which says only that *some* durable write failed. These say which
administrative decision was affected, and therefore what the operator must redo.

### Recommended alerting

```yaml
- alert: CulvertAdminRosterChangeRefused
  expr: increase(culvert_admin_roster_persist_failures_total[15m]) > 0
  labels: { severity: warning }
  annotations:
    summary: "An admin account/role/password change was refused — the roster could not be written"
    description: >
      The change was rolled back and did NOT take effect. Fix the data volume
      (disk space, permissions, read-only mount) and have the operator retry.
      If the change was a revocation, treat the account as still active until it
      is redone.

- alert: CulvertAdminRosterDegraded
  expr: increase(culvert_admin_roster_persist_degraded_total[15m]) > 0
  labels: { severity: warning }
  annotations:
    summary: "A login-path admin-roster write did not persist"
    description: >
      A consumed TOTP backup code or an advanced replay counter may not survive a
      restart. Fix the data volume before restarting this node; after a restart,
      rotate the affected administrator's backup codes.
```

## What this row does and does not guarantee

The `admin_roster_durability` row reports **evidence from Culvert's own
writes**, plus the problems it can see. It does not predict that the next
save will be allowed.

- **What `ok` means:** Culvert's last admin roster save landed on disk in
  this process, and the file is still exactly that write. On Linux and macOS
  that means the same inode, unchanged since (device, inode and `ctime`). On
  other Unix systems it means the same size, SHA-256 and owner. On Windows
  only the size and SHA-256 are checked. It is a statement about the past
  write. It is not a statement that the roster "is persisting" or that the
  next change "can be saved".
- **Live checks are advisory.** The `faccessat(W_OK|X_OK, AT_EACCESS)`,
  `statfs` and immutable/append-only/bind-mount checks report the problems
  they do detect: a directory that is not writable, a read-only mount, a file
  no save can replace. When they pass, that is not a claim either way.
- **What no read-only check can predict:** whether the next save will be
  authorised. A mandatory-access-control policy (SELinux `add_name` or
  `remove_name` on the directory, or AppArmor) can deny the save's temp-file
  creation or rename while `faccessat` passes. So can an NFSv4 or server-side
  ACL evaluated only by the server, or a quota. Culvert does not run a
  self-test write to find out.
- **A refused save is reported at once.** It is refused and rolled back with
  a `500`, and audited as `<action>.refused`. It increments
  `culvert_admin_roster_persist_failures_total`; a failed login-path write
  increments `culvert_admin_roster_persist_degraded_total` instead. The very
  next read of this row shows the refused or degraded counts in place of
  `ok`, and in place of *not verified yet* after a restart. Viewers see the
  fixed "changes were refused" message.

### Which state the row shows

The row shows exactly one state: the first of these that applies, for
admins and viewers alike. A single ordered list in the code decides it, and a
test checks every pair of states against that list.

1. Initial setup not complete (`ok`).
2. No `-ui-users-file` configured.
3. Storage not responding.
4. Admin account changes refused since the last save that landed.
5. Login-time writes failed since the last save that landed. Admins only:
   a viewer sees the state below it.
6. The configured file is unusable: it failed to load at startup (until a
   save lands at that path, which replaces the file with the roster in use),
   is not a regular file, or its directory is missing.
7. The file is missing: removed after a save, or not created yet.
8. The file was replaced or edited outside Culvert.
9. The file is an identical copy owned by another account, and the next
   save's rename may be refused.
10. The file is immutable or append-only, or a mount point.
11. The directory is not writable.
12. The file was changed or replaced outside Culvert in another way.
13. The last save's directory could not be synced.
14. Not verified yet: no save since startup.
15. `ok`.

A refused change outranks every live-check finding. It is a fact, not a
prediction: the change did not take effect, and nothing retries it. The
admin remedy also names the highest-ranked problem the live checks see
below it, which is usually the cause.

An unsynced directory ranks low. The write landed and only a power loss
threatens it, and that no longer matters once the file has been changed,
replaced or removed.

The refused and failed counts on this row are counted from the last save
that landed, or from startup before the first one. A refused change stays
visible until a later save lands. That later save writes the whole roster in
use, including any login-time change whose own write failed, so it clears
both counts. The since-startup totals still appear in the message, in the
Administrators panel and in the metrics, and they clear on restart.

## Recovery

1. The Diagnostics panel (`GET /api/diagnostics`, also rendered by
   `GET /api/health/explain`) carries an `admin_roster_durability` row. It is
   `ok` while initial setup is incomplete (there is no credential to persist
   yet), and `ok` once an admin account change has been saved in this
   process and nothing below applies. That `ok` states evidence, not a
   promise: *the last admin roster save was written to disk and the file is
   unchanged since* (viewers: *an admin roster file is configured; the file on
   disk is the last one Culvert wrote, unchanged since*). See
   [What this row does and does not guarantee](#what-this-row-does-and-does-not-guarantee).

   **After every restart it is `warn` — *not verified yet* — until the first
   admin account change is saved.** Culvert does not write the roster at
   startup, and nothing short of a real save can prove one will land: a stat
   passes on a read-only mount, and a test file created beside the roster
   passes in a sticky (`1777`) or ACL-restricted directory where the roster
   belongs to another user. This state is pending, not a fault: the message
   reads *the admin roster has not been written since startup; the next admin
   account change verifies that it persists*, viewers see a fixed
   non-alarming message, no action is needed, and it never makes the contract
   verdict `fail` (the row's `warn` only colours the verdict; `/healthz` and
   readiness do not read it). The first landed save turns the row `ok`.

   Once setup is complete the row is also `warn`, and these take precedence
   over *not verified yet*, when:

   - no `-ui-users-file` is configured (changes revert at restart; on a node
     with no local administrator it also names the missing break-glass
     account);
   - the configured file failed to load at startup and no save has landed
     at that path since (a landed save clears it), or its path is not a
     usable regular file (a directory, or a missing parent directory);
   - the configured file **does not exist yet** (its accounts are only in
     memory; the first admin account change creates it and clears this);
   - the **directory no longer lets Culvert create and replace files** (a
     `chmod 0555`, an ACL revocation, or a read-only remount — checked live
     with `faccessat(W_OK|X_OK, AT_EACCESS)` and `statfs`, never by creating a
     file; on non-Unix platforms there is no such live check, and a refused
     save is what reports it). This check is advisory: it reports what it
     detects, and passing it does not mean the next save is authorised (a
     MAC policy, a server-side ACL or a quota can still refuse it, which the
     refused count then reports);
   - the roster **cannot be replaced by any save** — immutable or append-only
     (`chattr +i`/`+a`; `lsattr` shows it), a bind-mounted file, or in an
     immutable or append-only directory; checked live and read-only on Linux
     (clear the flag with `chattr -i`/`-a`), reported elsewhere only once a
     save is refused;
   - the **storage does not respond** to that check within 2 seconds (a
     stalled NFS or FUSE mount: persistence is not verified).

   After a landed save it is `warn` when the file was **removed from disk**
   (the roster in use is then only in memory and accounts that exist only in
   it are lost on restart: save an admin account change, which recreates the
   file, or restore it from backup, before the next restart), **replaced or
   edited outside Culvert** (each landed save records the size and SHA-256 of
   the bytes written, so any edit that changes them counts: a restart would
   load the file as it is now, which may restore revoked accounts or
   credentials or drop changes made since — reconcile, then either save an
   admin account change to write the roster in use back, or restart to adopt
   the file), **replaced by an identical copy owned by another account** in a
   way that makes the next save's rename be refused (a sticky directory whose
   owner is neither Culvert nor root, with Culvert not root and not the new
   owner: give the file back to Culvert's account, or run Culvert as its
   owner), **changed or replaced outside Culvert in any other way** (the
   message reads *the roster file was changed or replaced outside Culvert
   since its last save; persistence is not re-verified until the next admin
   account change*), or when the save landed but its
   **directory could not be synced** (for example a write-and-search-only
   `0300` directory that cannot be opened for the `fsync`: that write may not
   survive a power loss; the save itself succeeds, as every other store's
   does). It is also `warn` when refused or degraded roster writes have
   occurred since the last save that landed (or since startup, before the
   first one). That state outranks every file and directory problem listed
   above; only a missing `-ui-users-file` and storage that is not responding
   outrank it. See
   [Which state the row shows](#which-state-the-row-shows). The Administrators
   panel shows the since-startup refused/degraded counts, which clear on
   restart.

   A landed save is evidence only for the exact file Culvert wrote, unchanged
   since. On Linux and macOS each landed save also records that file's device,
   inode number and status-change time (`ctime`, nanoseconds), taken from the
   written file itself after the rename. Any later difference — a new inode
   (an identical re-copy, even by the same owner, or an owner-changing copy in
   a non-sticky directory), or a `ctime` change on the same inode (`touch`,
   `chmod`, `chown`, `setfacl`, a new extended attribute or SELinux label) —
   reports *changed or replaced outside Culvert*, because any of those can
   change whether the next save is allowed and no stat can tell which. This is
   deliberate: **a `touch`, a `chmod` or an identical re-copy makes the row
   `warn`, not `ok`.** If the change was intentional no
   action is needed: the next admin account change that is saved re-verifies
   persistence and clears it, with no restart. The more specific problems take
   precedence: changed contents, a refused-rename owner change, a missing
   file, an immutable file and a directory Culvert can no longer write. On
   other Unix systems only the size, SHA-256 and owner are compared, and on
   Windows only the size and SHA-256, so there a metadata-only change does not
   warn.

   Everything the row learns from the filesystem comes from one live probe,
   read once per diagnostics request (the viewer rendering reuses it). The
   probe runs on its own goroutine with no roster lock held, at most one at a
   time however many requests arrive, and its result is reused for 5 seconds
   while Culvert has not written the roster: a stalled volume costs a request
   at most one 2-second wait, and never delays admin changes or logins. The
   counts, the remedy and the degraded login-write state are shown to
   **admins only**: a viewer or operator sees a fixed message for "not
   durable", "not verified yet" or "a change was refused", and nothing for a
   degraded login-time write (SEC-DIAG-ROSTER-1).

   A symlinked roster path is used as is; a save replaces the link with a
   regular file, so point `-ui-users-file` at the real file. A save writes a
   new file at mode `0600` that does not carry the roster's own ACL or
   extended attributes over (it gets the directory's default ACL, if any);
   re-apply them after a save if you rely on them.

   **Deferred:** a boot-time in-place rewrite of `ui_users.json`, which would
   verify persistence at startup instead of at the first admin change, is
   split out of this change into its own follow-up PR.
2. `culvert_admin_roster_persist_failures_total` is climbing, or an operator
   reports a `500` from a user-management action.
3. Check the process log for `UIUsers: REFUSED` lines — each names the action and
   the account.
4. Fix the underlying volume. `storage_write_failed` and the
   `audit_log_persistence` contract row usually fire alongside and point at the
   same cause (disk full, read-only remount, permissions on `<dataDir>`).
5. **Redo the refused actions.** They did not take effect. Nothing is queued and
   nothing retries them automatically — that is deliberate: a privilege change
   replayed later, out of order, against a roster that has since changed is worse
   than one the operator reapplies deliberately.
6. If `culvert_admin_roster_persist_degraded_total` is non-zero, rotate the
   affected administrator's TOTP backup codes after the volume is healthy.

## Related

- `docs/operator/admin-login-input-bounds.md` (CHAOS-63) — the public login
  endpoint's input bounds.
- `docs/operator/credential-verification-cost.md` (CHAOS-57) — credential
  verification as a bounded resource.
- `roadmap/CHAOS-ENGINEERING-REVIEW.md` §40 — the full finding, evidence and the
  register rows it closes.
