# ADR-0061: Lifecycle of the maintenance agent's crash journal — report at startup, never act

- Status: Proposed for review with the implementation PR, 2026-11-22. The
  reporting half is implemented here. The acting half (boot-time reconcile) is
  NOT, and stays an owner decision: see "Decisions left to the owner".
- Numbering: ADR-0056 is the highest file on main at 5945633. Open PRs were not
  checked from this worktree; renumber if one has reserved 0061.
- Related: [RISK-022 journal plan](../../roadmap/RISK-022-crash-recovery-journal-plan.md),
  [PR-E reconcile design](../../roadmap/RISK-022-PR-E-reconcile-onstartup-design.md)
  (v2, awaiting sign-off), contract `AGT-900` (open), RISK-022 in the
  [risk register](../engineering/TECHNICAL-RISK-REGISTER.md).

## Context

The maintenance agent (`cmd/culvert-maint`) writes a journal record for every
`upgrades.apply` and `rollbacks.create` and removes it when the operation
reaches a terminal state. A record that outlives its process is the durable
evidence that an image change was cut short.

Three facts were established from the code and by killing the real binary:

1. **The reconcile decision has no production caller, on purpose.**
   `reconcileDecision` and `validateReconcileRefs` are called only from tests.
   The file header says so ("not wired into startup … the boot hook is slice E3,
   which is gated on explicit owner sign-off"), the PR-E design repeats it and
   adds "ship v1 default-OFF (mark-only)", and `AGT-900` records it as an open
   question. Startup (`main.go` `initJournal`) lists the journal and marks each
   record's operation `failed(agent_restart_interrupted)` in memory. Nothing
   else recovers: the systemd unit is `Restart=on-failure` and only restarts
   the agent; the compose file's `restart: unless-stopped` only restarts the
   existing container; the proxy does not know about the journal.

2. **The mark was all an operator got, and it was not enough to act on.**
   Measured on main at 5945633 by `TestCrashRecovery_*` (every test named below
   fails there):
   - the operation said `failed` and nothing about how far it got, so a kill
     before any Docker change and a kill between `docker tag` and `compose up`
     were indistinguishable;
   - the audit log held the operation's `started` entry and never a terminal
     one;
   - `GET /v1/status` did not mention it, and the in-memory operation is reaped
     an hour after each start;
   - `started_at` was the restart time, not the operation's;
   - the image a rollback should name (`prior_ref`) was only in a root-readable
     file on the host;
   - the record was never removed, so after the operator had fixed the
     appliance, every later agent start reported the old upgrade again as a
     fresh failure, indefinitely.

3. **The Docker consequence is real and survives restarts.** Killed between
   `docker tag` and `compose up`, the fixed tag `culvert/proxy:pinned` is on the
   target and the container still runs the previous image. A container, daemon
   or host restart keeps the container on the previous image; the next
   `docker compose up -d` from anyone — an operator, or the agent's own restore
   flow — starts the target with no health gate. Reproduced against a real
   daemon with the real agent binary (evidence in the PR description).

## Decision

Startup **reports** an interrupted operation completely and durably, and
**changes nothing** in Docker. The record's lifecycle is:

| Event | Record | Operator-visible |
|---|---|---|
| Operation admitted | written (`admitted`), advanced per phase | operation `running` |
| Operation reaches a terminal state | removed | terminal state, audit entry |
| Agent dies mid-operation | stays | — |
| Agent starts, record found | kept; first-detection time, start counter and audited flag written into it | operation `failed(agent_restart_interrupted)` with `result.interrupted`; one audit entry (first start only); listed in `GET /v1/status` `interrupted_operations` on every request |
| Agent starts again, any number of times | kept; counter grows | same report; no further audit entry |
| A later upgrade or image rollback **succeeds** having re-pinned the tag and passed the health gate and digest verify | removed, with an `…:interrupted_superseded` audit entry naming the retiring operation | list empties; the old operation is no longer re-reported |
| A later operation fails, or succeeds as already-current | kept | still listed |
| Record unreadable | — | agent refuses to serve (unchanged; see decision 2 below) |

What the report says, per record (`server.InterruptedOperation`):

- `journal_phase`, and `docker_state`: `unchanged` (an upgrade that stopped at
  or before `pulled` — the write-ahead barrier is fsynced before the tag
  moves, so the journal can vouch for this), `indeterminate` (an upgrade at or
  past `restarting`; any image rollback, which records no phase beyond
  `admitted` although it moves the tag; any kind this build does not know), or
  `data_indeterminate` (a data rollback).
- `target_ref` / `prior_ref` — only after `validateReconcileRefs` accepts the
  record. This is that function's first production use, as the gate on what
  is *shown*, which is the same gate a reconciler must pass before anything is
  *run*.
- `docker_reconciled: false`, stated, so `failed` cannot be read as "rolled
  back", and an `operator_action` sentence.
- From `GET /v1/status` only, read live and only while a record exists:
  `running_image` (`target` / `prior` / `other` / `ambiguous` / `unknown`) and
  `pinned_tag` `{image_id, matches_running}`. A failed read is `unknown`, never
  a guess. The tag read is the existing image-inspect template with the literal
  fixed tag; no sudoers line is added.

What startup must guarantee:

- It comes up whether or not Docker is reachable, and whether or not the
  journal or audit log is writable (those writes are best-effort; an audit
  entry that could not be written is retried at the next start).
- It never reports an interrupted operation as succeeded.
- It is idempotent: any number of restarts leave the same report and one audit
  entry (two only if the agent dies between the audit write and the record
  update — the order is chosen so the entry can repeat but cannot be lost).

What startup must never do: pull, tag, `compose up` or `down`; remove a record;
or repeat a string from a record to an API consumer unvalidated (the journal is
an unauthenticated file: kind and mode are matched against closed sets, image
ids against their exact shape, the actor against a safe alphabet, and the file
name — already ULID-checked — is the operation id, not the `op_id` inside).

## Why not connect the decision function now

- It is an open contract. `AGT-900` asks who ships it; the contracts workflow
  says an open entry is reported, not resolved by implementation.
- Automatic rollback at boot changes what an operator observes after a power
  cut, at the moment nobody is watching. The design's own red-team concluded
  default-off.
- Its prerequisites are not on main: the rollback paths have no write-ahead
  barrier (design P0-F), there is no local-first rollback (T1.1), no
  single-instance guard (T1.5), and the target image id it keys on is not
  trustworthy (finding F1 below).
- The reporting above is what the default-off posture needs in order to be a
  usable product state rather than a silent one, and it is what an operator
  uses in the meantime.

## Findings that bear on the acting half

**F1 — the journaled target image id is unverified (confirmed).**
`restartWithBarrier` records `TargetImageID` from whatever runs right after
`compose up` returns 0. If `up` did not recreate the proxy (for example a
compose override that pins another image), that is the *previous* image. The
real apply flow then journals `target_image_id == prior_image_id` with
different digests, and `reconcileDecision` on those facts returns
`verify_adopt_else_rollback / live_target_prior_equals_target`: it would adopt
the previous image as a completed upgrade while the fixed tag sits on the
target. With the id left empty the same facts give `reup`. The report does not
borrow the core's verdict; it classifies this record as `ambiguous`
(`TestClassifyRunning_ConflictingTargetIDIsAmbiguous`). Fix before E3: record
the id only when the captured RepoDigests contain the pinned digest (the check
`verifyRunningImage` already makes). That change is in the apply restart stage
and is left to the owner of that stage.

**F2 — a stale record would drive a reconciler to an old image.** Before this
change records were never retired. For a danger-window record whose running
image is neither its target nor its prior, the decision table returns
`rollback_to_prior`. A record left from an upgrade several releases ago would
therefore roll the appliance back to that release's prior on the first boot
with reconcile enabled. Retiring records on a later successful image change
removes the case.

**F3 — "submit the upgrade again" does not health-gate an image that is already
running.** After a kill at the health gate the target is live and ungated.
Re-submitting the same upgrade is reported already-current and skips restart,
health gate and verify. The operator action for that state therefore says to
check health by hand or roll back, and such a success does not retire the
record (`TestCrashRecovery_AlreadyCurrentUpgradeDoesNotRetire`).

**F4 — an already-current apply does not re-pin the fixed tag.** With the tag
ahead of the container, applying the image that is already running succeeds
and leaves the tag where it was. Only an image rollback, or a real upgrade,
re-pins it.

## Decisions left to the owner

1. **Boot-time reconcile (E3, `AGT-900`).** Whether the agent may run
   `docker tag` / `compose up` at startup at all, and if so whether only the
   converge half (`reup`, adopt) or also rollback. Recommended scope when it is
   taken up: default off; converge-only first; act only when
   `validateReconcileRefs` passes; a persisted per-record attempt cap (the
   start counter added here is that field's natural home); bind the socket
   before acting; F1 fixed first.

   **Taken (owner decision 1, 2026-11):** an opt-in `reconcile_on_startup =
   "converge"`, default `"off"`, which keeps everything in this ADR exactly as
   decided. "converge" may only retag to the recorded prior image while the
   container provably runs it, finish an inline rollback whose durable
   `rollback_armed` marker is set and whose tag is already on the prior image,
   finish such an armed rollback that was killed before its own `docker tag`
   (container and tag still on the target: retag to the validated prior
   reference, then the same `compose up`, fresh gate and verify by id; Docker
   is re-read immediately before each mutation and any change the reconcile's
   own steps do not explain stops it; owner decision 1, 2026-11-23, after the
   real-Docker e2e found this state left the failed image running), retire an
   armed record found on the prior image, or realigned by retag alone, only on
   a fresh ready probe,
   or adopt (no Docker change) a target recorded at `verified` that runs under
   the tag and answers ready; every other state is `recovery_required` and
   changes nothing, and an unreadable Docker defers. There is no `reup` and no
   rollback of an indeterminate image. The interrupted operation stays
   `failed(agent_restart_interrupted)`; the reconcile is its own
   `reconcile.startup` operation, and a record is retired only after verified
   convergence and an audit entry. F1 is fixed in the restart stage. Contracts:
   AGT-900 (enforced, scoped to "converge"), AGT-004 and AGT-005 amended.
   Implementation: `internal/server/startup_reconcile.go`,
   `internal/server/reconcile_decision_v2.go`.
2. **Corrupt record: refuse to serve, or quarantine.** Today one unreadable
   file stops the agent, and under `Restart=on-failure` / `RestartSec=5s` it
   restarts every five seconds with the API dark — no status, no backup, no
   rollback — until someone removes the file by hand. The v2 design calls for
   move-aside plus a loud report. This changes a documented fail-closed
   posture, so it is pinned as it is (`TestCrashRecovery_CorruptRecordRefusesToServe`)
   and not changed here.
3. **An acknowledge path.** A record whose operator verified health by hand
   (F3) stays listed until the next real image change. Options: leave it (it is
   true: the agent never gated that image); add an operator acknowledge call;
   or make an already-current apply run the health gate and verify when a
   record is outstanding.
4. **Surfacing in the Control Plane / GUI.** The proxy reads a fixed subset of
   the agent's status (`maint_agent_status_api.go`) and ignores the new fields.
   Showing `interrupted_operations` there is a follow-up in the root module.
5. **`Wants=docker.service` vs `Requires=`.** Irrelevant while startup does not
   touch Docker; part of decision 1.

## Compatibility

- Journal file: three new optional keys (`interrupted_at`, `interrupted_seen`,
  `interrupt_audited`), written only by startup. An older agent ignores them
  and drops them on its next write of that record; a newer agent reads an older
  record as never-seen. No version field is added and none was present.
- API: `GET /v1/status` gains optional `interrupted_operations`,
  `interrupted_operations_error` and `pinned_tag`; an interrupted operation
  gains `result.interrupted` and its `started_at` becomes the time it was
  started. A successful upgrade or image rollback may carry
  `result.superseded_interrupted_ops`. Nothing is removed or renamed.
- Audit: one new terminal entry per interrupted operation (`outcome: failed`,
  `failure_reason: agent_restart_interrupted`) and one
  `<kind>:interrupted_superseded` entry when a record is retired.
- Behaviour: an interrupted record is no longer reported forever; it is
  retired by the next successful image change.

## Proof

- Process level, real binary, model Docker:
  `cmd/culvert-maint/startup_crash_recovery_test.go` — SIGKILL at eight points
  of the apply flow and one of an image rollback, repeated restarts, Docker
  down at startup, forged record, corrupt record, stray files, recovery by
  upgrade and by rollback, failed recovery.
- In process: `startup_journal_test.go`, `internal/server/interrupted_test.go`,
  `internal/server/journal_retire_test.go`,
  `internal/status/status_interrupted_test.go`,
  `internal/runner/pinned_inspect_test.go`, and the additions to the journal
  and ops tests.
- Contracts `AGT-004` and `AGT-005` register the two invariants; `AGT-900` is
  unchanged and still open.
