# Admin-roster durability (CHAOS-70)

**Applies to:** every node running the admin UI · **Operator action required:**
none by default; two alerting rules are recommended.

`ui_users.json` is the **only** durable home of the admin roster: every account,
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
and only the parent-directory `fsync` failed — or the directory could not even
be opened for it (for example a write-and-search-only `0300` data directory,
which gives `EACCES`); only an `fsync` the platform reports as unsupported
counts as success. Every future reader,
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

## Recovery

1. The Diagnostics panel (`GET /api/diagnostics`, also rendered by
   `GET /api/health/explain`) carries an `admin_roster_durability` row. It is
   `ok` while initial setup is incomplete (there is no credential to persist
   yet). Once setup is complete it is `warn` when no `-ui-users-file` is
   configured (changes revert at restart; on a node with no local
   administrator it also names the missing break-glass account), when the
   configured file failed to load at startup or its path is not a usable
   regular file (a directory, or a missing parent directory), when the boot
   rewrite described below was refused, when no write to the file has landed
   since startup (a configured file that does not exist yet: the first admin
   account change creates it and clears the warning), when the file was
   **removed from disk after it was last written** (the roster in use is then
   only in memory and accounts that exist only in it are lost on restart:
   save an admin account change, which recreates the file, or restore it from
   backup, before the next restart), when the file was **replaced or edited
   outside Culvert after Culvert last wrote it** (each landed write records the
   size and SHA-256 of the bytes written, and the row compares the file with
   them, so an in-place edit counts but a `touch` or `chmod` does not: a
   restart would load the file as it is now, which may restore revoked
   accounts or credentials or drop changes made since — reconcile, then either
   save an admin account change to write the roster in use back, or restart
   to adopt the file), when it was **replaced by an identical copy owned by
   another account** in a way that makes the next save's rename be refused (a
   sticky directory whose owner is neither Culvert nor root, with Culvert not
   root and not the new owner: give the file back to Culvert's account, or
   run Culvert as its owner — an identical re-copy with the same owner, or an
   owner change in a non-sticky directory, stays `ok`), when the **directory
   no longer lets Culvert create and replace files** after the last landed
   write (a `chmod 0555`, an ACL revocation, or a read-only remount — checked
   live with `faccessat(W_OK|X_OK, AT_EACCESS)` and `statfs`, never by
   creating a file; on non-Unix platforms there is no such live check and a
   refused save is what reports it), when the **storage does not respond**
   to that check within 2 seconds (a stalled NFS or FUSE mount: persistence
   is not verified, so the row is not `ok`), or when
   refused or degraded roster writes have occurred since process start. The
   Admin Users panel shows the same refused/degraded counts. Read-only; the
   counts clear on restart. Everything the row learns from the filesystem
   comes from one live probe, which runs on its own goroutine with no roster
   lock held, at most one at a time however many requests arrive, and whose
   result is reused for 5 seconds while Culvert has not written the roster:
   a stalled volume costs one blocked check, not one per request, and never
   delays admin changes or logins. The counts, the remedy and the degraded
   login-write state are shown to **admins only**: a viewer or operator sees a fixed message
   for "not durable" or "a change was refused", and nothing for a degraded
   login-time write (SEC-DIAG-ROSTER-1).

   **On Linux, the roster file is rewritten in place once at every boot.**
   After `ui_users.json` loads, Culvert writes the exact bytes it read into a
   temp file beside it, with the file's own owner, group, full mode and
   **all of its extended attributes** (the complete list is below), and
   atomically **exchanges** that temp file with the roster (`renameat2`
   `RENAME_EXCHANGE`). None of that changes, but the file gets a **new inode
   and timestamps** at each start, as it does at each save. That write is the
   row's evidence: it is `ok` only if it landed, or a later roster save did. Nothing short of a real write to the
   real file can tell: a stat passes on a read-only mount, and a test file
   created and renamed beside the roster passes in a sticky (`1777`) or
   ACL-restricted directory where the roster belongs to another user. The
   exchange is subject to the same permission checks as the rename every save
   performs (verified as a non-root user: a root-owned roster in a `1777`
   directory refuses both with `EPERM`), so a refused exchange is exact
   evidence that saves will be refused.

   **The rewrite never overwrites a newer roster.** Culvert serialises its own
   roster writers, but a configuration manager or an operator can replace the
   file at any moment. After the exchange, Culvert compares the file it
   displaced with what it loaded (bytes, mode, owner, extended attributes).
   If they differ, it swaps the newer file straight back, logs one `UIUsers: admin roster
   "<path>" changed on disk while it was loaded at startup` line, and the row
   stays `warn`: the roster **in use** is the one loaded before that change,
   so restart to load the newer file, and make no admin account change until
   then (a save writes the roster in use over it). If swapping back fails, the
   newer content is left in a `ui_users.json.tmp.*` file beside the roster —
   never deleted — and a `CHANGED ON DISK` line names it; move it back over
   the roster and restart. A writer that keeps the old file open across the
   exchange and writes through that descriptor afterwards can still lose its
   write, exactly as it can against any save.

   **The rewrite never changes the file's metadata.** It covers every
   interface through which Linux exposes per-inode metadata to user space —
   `stat`, `statx`, `FS_IOC_GETFLAGS` (`chattr`), `FS_IOC_FSGETXATTR`
   (`xfs_io`/`chattr -p`) and the extended attributes — so this is the
   complete list (the same as `fileutil.RewriteInPlace`'s contract).

   | Preserved exactly — or the roster is not rewritten | Not preserved |
   |---|---|
   | Content, byte for byte (never re-serialised) | Inode number |
   | Owner and group | Timestamps: atime, mtime, ctime and birth time are the new inode's own |
   | All 12 mode bits, including setuid, setgid and sticky | Other hard links to the roster (they keep the old inode, with identical content) |
   | Every extended attribute Culvert can list: the POSIX access ACL (`system.posix_acl_access`), the SELinux or other LSM label (`security.*`), file capabilities, `user.*`, and `trusted.*` when Culvert has `CAP_SYS_ADMIN` | `trusted.*` attributes when Culvert lacks `CAP_SYS_ADMIN`: Linux does not list them to it, so it can neither see nor keep them |
   | Inode (`chattr`) flags such as nodump (`d`), noatime (`A`), sync (`S`), compress (`c`), nocow (`C`): compared, never set | |
   | The project quota ID (`chattr -p`, XFS/ext4 project quotas), extent-size and CoW extent-size hints, and XFS flags (`FS_IOC_FSGETXATTR`): compared, never set | |
   | `statx` attributes (compressed, immutable, append, nodump, encrypted, mount root, verity, DAX, atomic write, …): compared, never set | |

   The temp file gets them in the only order that works: `chown` (which
   clears setuid, setgid and file capabilities), then `chmod` with the full
   mode, then the extended attributes with the access ACL last (it rewrites
   the group bits), then removal of any attribute it inherited that the
   roster lacks (a directory's default ACL). It is then read back — owner,
   group, full mode, inode flags and attributes must equal the roster's
   exactly — and fsynced before the exchange. The read-back also catches a
   special bit the kernel dropped silently (an unprivileged process setting
   setgid on a file whose group it is not in) and a temp file that inherited
   an inode flag such as nodump from the directory. Only the filesystem's own
   storage flags (extents, inline data, huge file, compression internals,
   directory index), the encryption flag (inherited from the directory), the
   XFS flags that merely mirror a compared `chattr` flag or are internal
   (prealloc, has-attribute fork) and the extent count are ignored. Where an
   interface is unsupported (`ENOTTY`/`ENOTSUP`, or no `statx` at all) the
   filesystem keeps no such metadata; any other failure to read it refuses.
   An fs-verity or DAX roster is refused outright. After the exchange, the displaced file is compared on the
   same list, so a `chown`, `chmod`, `chattr`, ACL or label changed
   concurrently is swapped straight back like any other change.

   If **any** of it cannot be kept — a `chown` to another account refused
   with `EPERM` (Culvert runs unprivileged and the roster belongs to another
   account), a special bit dropped, a label this process is not allowed to
   assign (`EPERM`, `EACCES`, `ENOTSUP`), or an inode flag a new file would
   not have — **nothing is replaced**: the temp file is removed, the roster
   keeps its inode and all of its metadata, one `UIUsers: admin roster
   "<path>" was not rewritten in place at startup: its owner, group, mode,
   inode flags, extended attributes or ACL could not be kept` line names the
   cause, and the row is `warn` (*not proven that admin account changes can
   be saved*). If the roster belongs to another account than Culvert's, give
   it to Culvert's account (or run Culvert as its owner) and restart;
   otherwise the warning clears when the first admin account change is
   saved. An **immutable or append-only** roster (`chattr +i` / `+a`) is not
   rewritten either; since no save can replace it, the row reports it as a
   refused write (*every admin account change will be refused*). A roster
   owned by Culvert's account, with a plain mode, no extended attributes and
   no inode flags, is rewritten exactly as before.

   **Elsewhere, the roster is not rewritten.** Without an atomic exchange
   (macOS, Windows, other non-Linux platforms, or a Linux kernel or filesystem
   that rejects `RENAME_EXCHANGE`) a replace could destroy a concurrent change,
   so Culvert writes nothing at boot, logs one line, and the row is `warn`
   (*not proven that admin account changes can be saved*) until the first
   admin account change is saved; if that change is refused, fix the path and
   restart.

   If the rewrite is refused, boot continues and the roster is used read-only;
   one `UIUsers: admin roster "<path>" loaded, but could not be rewritten in
   place at startup` line names the cause, and the row stays `warn` (admins
   get the fix-path-and-restart remedy) until a write lands. The rewrite is
   not an admin change: no audit entry, configuration version, roster
   counter, storage-health event or alert. A symlinked roster path is not
   rewritten (a save replaces the link with a regular file); point
   `-ui-users-file` at the real file. Unlike the boot rewrite, an admin
   account **save** still writes a new file that does not carry the roster's
   own ACL or extended attributes over (it gets the directory's default ACL,
   if any, and mode `0600`); re-apply them after a save if you rely on them.
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
