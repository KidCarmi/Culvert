# Admin-roster durability (CHAOS-70)

**Applies to:** every node running the admin UI · **Operator action required:**
none by default; two alerting rules are recommended.

`ui_users.json` is the **only** durable home of the admin roster: every account,
password hash, role, TOTP secret, consumed-backup-code list and TOTP replay
counter. Every change to that state is applied to memory first and written to
disk second, so the two can disagree — and the disagreement is resolved at the
next restart, when the file wins.

## What changed

Three administrative mutations are now **durable-or-refused**. If the roster
cannot be written, the in-memory change is rolled back and the request fails:

| Action | Endpoint | Before | Now |
|---|---|---|---|
| Create account / set password / change role | `POST /api/auth/users` | `200 {"ok":true}` | `500`, nothing changed |
| Delete account | `DELETE /api/auth/users` | `204 No Content` | `500`, nothing changed |
| Self-service password change | `POST /api/auth/password` | `200 {"ok":true}` | `500`, nothing changed |

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
and only the best-effort parent-directory `fsync` failed. Every future reader,
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

1. `culvert_admin_roster_persist_failures_total` is climbing, or an operator
   reports a `500` from a user-management action.
2. Check the process log for `UIUsers: REFUSED` lines — each names the action and
   the account.
3. Fix the underlying volume. `storage_write_failed` and the
   `audit_log_persistence` contract row usually fire alongside and point at the
   same cause (disk full, read-only remount, permissions on `<dataDir>`).
4. **Redo the refused actions.** They did not take effect. Nothing is queued and
   nothing retries them automatically — that is deliberate: a privilege change
   replayed later, out of order, against a roster that has since changed is worse
   than one the operator reapplies deliberately.
5. If `culvert_admin_roster_persist_degraded_total` is non-zero, rotate the
   affected administrator's TOTP backup codes after the volume is healthy.

## Related

- `docs/operator/admin-login-input-bounds.md` (CHAOS-63) — the public login
  endpoint's input bounds.
- `docs/operator/credential-verification-cost.md` (CHAOS-57) — credential
  verification as a bounded resource.
- `roadmap/CHAOS-ENGINEERING-REVIEW.md` §40 — the full finding, evidence and the
  register rows it closes.
