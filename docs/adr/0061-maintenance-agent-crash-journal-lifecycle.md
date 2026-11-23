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
- From `GET /v1/status` only, read live: `running_image` (`target` / `prior` /
  `other` / `ambiguous` / `unknown`) while a record exists, and `pinned_tag`
  `{image_id, matches_running}` on every status (a record is not the only way
  the tag and the container come apart). A failed read is `unknown`, never
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

## Addendum (2026-11-23): what "no process behind it" does and does not cover

A record found at startup is treated as an operation with no process behind
it. Two things make that usable, and neither is the journal:

- **Processes.** The shipped unit kills the agent's control group and holds
  the restart until it is empty (`KillMode=control-group`). No docker command
  of the dead agent is alive when the next one starts.
- **The daemon.** dockerd finishes the last request it was sent. A container
  stop lasts as long as the proxy takes to exit, up to its
  `stop_grace_period`. On real Docker a rollback admitted in that window found
  the old container running, passed its health gate, reported success and
  retired the record; the container then exited.

Rule: nothing tags and recreates while such a request can still be pending.
`tagAndUp` waits until `agent start + interrupted_settle` (default 75s, must
exceed the proxy's `stop_grace_period`) and only then tags, runs `up`, and goes
through the health gate. A success, and the retirement of records it causes, is
therefore judged on a container no outstanding request can touch.

The bound is counted from the process start, not from a journal record, on
purpose. A stop can be left by something that records nothing (a restore's
`compose down`), records another class (a data rollback), or belongs to a
startup reconcile killed in mid-flight; and a record's `interrupted_at` is
written best-effort. The wait is not a new stage.

**When the window applies, and when it ends early (mutation marker).** Waiting
after every start made the ordinary restart (package upgrade, reboot) cost a
full window on its first operation, and kept the proxy down for a full window
in exactly the cases where it was already down. Two refinements, both built so
that every doubt falls on the waiting side:

- *Record before effect.* Before the agent runs `compose up` or `compose
  down` it writes a durable marker (`<state_dir>/mutation/pending.json`,
  fsynced) that names the command and every command begun since the marker was
  last removed. If the marker cannot be written the command is not run. A
  success removes the marker only if, **when the command started**, nothing
  earlier could still be pending:
  - no compose command of this process has ever ended in an error. After an
    error exit the marker stays (a docker CLI that was sent SIGTERM exits with
    an ordinary error status after it has asked dockerd to stop the proxy), and
    the process never removes a marker again: a CLI cut through `sudo` can
    outlive any window and send its stop later, and only the next agent start,
    whose unit kills the control group, ends that;
  - whatever the previous process left is over: it left nothing, or Docker
    showed so (below), or a window has passed since this start. A success
    inside that window proves nothing about what opened it: a restore whose
    `compose down` was cut goes straight on to `compose up`, which finds the
    proxy still `running`, changes nothing and exits 0.

  So at start, no marker means: every compose up/down any earlier process ran
  returned success with nothing before it in doubt. There is nothing for
  dockerd to be finishing and no window. A window applies when a marker is
  found or cannot be read, and whenever the journal holds a record that no
  running operation owns, or cannot be read. The first start that keeps markers
  writes an "unknown" marker at once (their absence until then proves nothing),
  so that doubt, too, lasts across restarts until a command clears it. "Past
  first use" is a sentinel file written only after that marker is durable: a
  first start that dies or fails half-way is a first use again.
  `interrupted_settle = "0s"` turns the wait off, not this bookkeeping. All
  server call sites go through one wrapper
  (`TestMutation_OnlyTheWrappersRunComposeUpDown`). Both rules above come from
  two rounds of independent adversarial review (2026-11-23).
- *Advance when completion is established.* Only when the marker found at
  start was readable and names nothing but `compose up`. While it waits, the
  agent reads `compose ps`. When two consecutive reads, one poll apart, list no
  proxy container, the stop that `up` requested on the proxy is over and the
  wait ends; whatever `up` starts next is not a container a stale request
  named. (An `up` can also be replacing a container of another service whose
  configuration changed; the `up` that follows the wait replaces that same
  container, so a stop still pending on it removes nothing the new `up`
  keeps.) If a proxy container is running (it may be the one being stopped:
  Docker reports `running` until the process is gone), Docker cannot be read,
  or the output is not understood completely, the whole window is waited out.
  A marker that names a `compose down`, or names nothing readable, is never
  ended early: `down` stops every service of the project, and "no proxy
  container" says nothing about a stop still pending on another one.

Costs accepted: a marker left by a cut command, or by a success inside a
window, stays until a later compose command succeeds with nothing in doubt;
until then every agent start opens a window, and the next upgrade or rollback
reads the proxy container once more after its `up`.

Not covered, and unchanged by the marker: inside one live agent process the
wait after a compose command that ended in an error is one window. If that
command's CLI survived behind `sudo` (a stage timeout that could not kill it)
and sends its stop later than that, an operation of the same process can
already have reported success. The marker rule above only makes sure the NEXT
process waits. And a `stop_grace_period` longer than `interrupted_settle` (not
validated: the agent does not read the compose file) defeats the window and,
with it, the time after which a marker may be cleared.

Not covered by the marker: an agent **downgraded** to a version that writes no
markers and upgraded again. The marker directory then exists, and a restore's
`compose down` cut under the older version leaves neither marker nor record.
After such a round trip, remove `<state_dir>/mutation` before starting the
newer agent; it then treats the start as a first use and waits. A state
directory that cannot be written now also stops `compose up` / `compose down`
from being run at all (including a restore's best-effort `start_stack`), as it
already stops an upgrade at its journal barrier.

The early end applies only to what a previous process left: its docker commands
are dead before the next start (the unit's control-group kill), so only single
requests are left in dockerd. It does not apply inside the window of a command
of the running process that ended in an error, below: killed through `sudo`,
that CLI may still be alive and send further requests.

The window restarts inside one process whenever a `compose up` or `compose
down` it ran ends in an error: the command may have been killed (stage timeout,
the unit being stopped, the OOM killer) after it asked dockerd to stop the
proxy. The upgrade's inline rollback therefore starts one window after a
failed `up`. An upgrade also waits before its first capture, so that "already
current" — which skips the restart and the health gate — is never concluded
from a container that may be on its way out.

Not covered: a deployment without the unit's control-group kill (a docker
command of the dead agent may then still be running at any later time), and a
`stop_grace_period` longer than the window.

The startup reconcile (`reconcile_on_startup = "converge"`) follows the same
rule and one more. It waits out the settle window before it reads Docker for a
record, and it retires a record only after a readiness probe taken at that
point succeeds. Matching container and tag identities alone are not
convergence. If the wait cannot be completed or the probe fails, the record is
kept and the outcome is `recovery_required` (`settle_wait_cut_short`,
`settle_not_established`, `not_ready_at_retirement`).

The wait applies only when Docker answered the reconcile's readability test.
When Docker is down there is nothing to observe and so nothing to wait for:
an image record is deferred (`defer` / `docker_unavailable`) at once, with no
Docker read, no change, no attempt counted and the record kept, and is decided
again at the next start, which waits out its own window. Waiting first spent
the reconcile's deadline and reported a Docker that was merely down as
`recovery_required` (`settle_wait_cut_short`); found by the real-Docker E2E.
A deadline that is already over before a record is reached is still
`deadline_elapsed`, never a deferral.
