# State-driven lifecycle reconciliation — investigation and plan

Status: investigation (2026-11-23). Owner direction: the 75 s
`interrupted_settle` window is an accepted conservative safety mechanism, not
the target architecture. The target is safe, predictable, autonomous recovery
with minimal customer intervention, built by extending the existing journal
and reconciliation, not by adding a second orchestrator.

Invariant that everything below must keep (ADR-0061 addendum):

> Never report a successful recovery or retire its durable evidence unless the
> final service state is independently verified and the recovery cannot be
> invalidated by an outstanding operation.

## 1. What goes wrong today, from measurement

All of this is from the real-Docker probe
(`test/lifecycle-conformance/orphan-probe`, results in
`test/lifecycle-conformance/README.md`), not from the model.

| # | Observation | Consequence today |
|---|---|---|
| O1 | No docker command of a dead agent survives into the next start (systemd control-group kill) | Settled; pinned by `TestShippedUnit_CrashFence` |
| O2 | `dockerd` finishes the last request it received. A container stop lasts as long as the proxy takes to exit | The agent waits `interrupted_settle` from every start before it tags and recreates. Correct, and slow: 75 s on the first operation after any agent start, crash or not |
| O3 | After a recreate interrupted between Compose's stop and delete, the next `compose up -d` only tidies up and exits 0 with nothing started | The first rollback failed its health gate and left the proxy down until a second one was submitted. **Fixed in the same change as this document (phase 1a) when the interruption left a journal record** (an agent killed during an upgrade or image rollback). Not yet covered: an `up` cut inside a live agent whose operation then failed and retired its own record; phase 1b's marker closes that |
| O4 | After a recreate interrupted between delete and rename, `up` starts the replacement under Compose's temporary name (`<id>_<name>`) | Serves the right image; `container_name` is wrong until the next recreate; nothing reports it |
| O5 | A crash between Compose's stop and start leaves the proxy down. Startup changes nothing unless `reconcile_on_startup = "converge"`, and the reconcile reports `recovery_required` for `stack_down` | Outage until an operator acts |
| O6 | The agent cannot tell a clean predecessor from a killed one | The settle wait applies after every start |

## 2. What the agent can already see, without any new privilege

Through the commands the sudoers file already allows:

- `docker compose ps --format json` — for each **running** container of the
  project: `ID`, `Name`, `Service`, `State`, `CreatedAt` (1 s resolution),
  `Status`. Verified on Compose v5.7.1.
- `inspect-image <id>` (wrapper) — the container's image id.
- `docker image inspect <ref>` — where the fixed tag is, repo digests.

What it cannot see: containers that are not running (`exited`, `created`),
whether a stop is in progress (Docker reports `running` until the process is
gone), a container's stop timeout, daemon events.

## 3. The mechanism

Three kinds of evidence, each durable or read from Docker, each answering one
question. Nothing here is a timer except the fallback.

### 3.1 Did the previous process leave a Docker mutation unfinished? (mutation marker)

Design rule from the research this work came from: *write the record of an
effect before the effect.*

Before the agent starts a mutating compose command (`up`, `down`), it writes a
small durable marker in the state directory (`mutation.json`: operation id,
command, wall-clock start, the proxy container id and `CreatedAt` it saw just
before). It removes the marker only when the command returned success. After
any error the marker stays: a docker CLI that was sent SIGTERM (a unit stop
during `up`, a stage timeout) exits with an ordinary error status after it has
asked `dockerd` to stop the proxy, so an error exit cannot be told from a cut
(independent review, 2026-11-23; same rule as `noteMutationCut`).

At startup:

- **No marker** — the predecessor had no mutating docker command in flight.
  There is nothing for `dockerd` to be finishing. **No settle wait.** This is
  the ordinary restart (package upgrade, reboot, clean stop) and removes the
  75 s from it (O6).
- **Marker present** — a mutation may be unfinished. Go to 3.2.

The marker is independent of the operation journal on purpose: restores and
data rollbacks run `compose down` and are not, or differently, journaled; the
marker covers every mutating command by construction, because it is written in
the one place that runs them (the runner call sites `tagAndUp`, restore
`stop_stack` / `start_stack`, reconcile `finish_rollback`).

Failure modes: the marker write fails → the command is not started (fail
closed, same as the journal barrier). The marker cannot be removed → it stays
and costs a conservative wait at the next start; it never causes a false "no
wait".

### 3.2 Has the unfinished mutation actually completed? (container identity)

A stale request can only hit the container it named. So, with a marker
present, completion is **positively established** when either holds, read
from `compose ps`:

- **No proxy container is running.** A stop that was in flight has finished
  (or there was none and something else took the proxy down). Proceed: `up`
  will start or recreate, and the container it leaves is not one a stale
  request named.
- **The running proxy container was created after this agent process
  started** (`CreatedAt` later than the process start, with a margin for the
  1 s resolution), or its id differs from the one in the marker. No request of
  the predecessor can name it. Proceed.

Otherwise — the same container that was running before the mutation is still
running — the state is **ambiguous**: either no stop was issued, or one is in
progress. Then, and only then, fall back to the conservative bound: poll
`compose ps`, proceed as soon as one of the two conditions above becomes true,
and at the latest when `interrupted_settle` has passed since the start.

This is "advance early when completion is positively established, keep the
conservative fallback when it is ambiguous". The 75 s remains the worst case
for exactly one situation — a crash in the middle of a recreate whose stop
never got to the container — and is zero or a few seconds otherwise.

The in-process `noteMutationCut` window is NOT replaced: a command of the
running process that ended in an error may have been killed through `sudo`
with the CLI still alive and sending further requests, so a single read of
Docker proves nothing there. Early advance applies only to what a dead
predecessor left, whose commands the unit's control-group kill has ended.

### 3.3 What state did Compose leave, and what is the bounded way out? (recovery ladder)

A recovery operation (rollback, re-apply; the startup reconcile and the
restore's `start_stack` once they are moved onto it — today they call `up`
directly, which is harmless because neither runs from a half-recreated state)
follows one ladder. Each rung is decided on what Docker says, has a budget, and ends in
either a verified success or a kept record.

1. Establish completion (3.1, 3.2).
2. `tag` + `up`.
3. **If `up` exited 0 and no proxy container is running: `up` again**, at
   most `upRetryBudget` (1) times. This is O3; the second pass is what an
   operator ran by hand. *(Phase 1a, implemented.)*
4. Health gate, then verify by image id. Unchanged.
5. If the running container's name is a Compose temporary name
   (`^[0-9a-f]{12}_`): report it in the operation result and in `/v1/status`
   (`container_name_pending`). It heals at the next recreate. Renaming it now
   would need a forced recreate, i.e. a second proxy restart, for a cosmetic
   gain; not done automatically (O4).
6. Success is reported, and other records retired, only after 4 on a
   container that 3.2 says no outstanding request can touch.

Budgets are per record and persisted, as `ReconcileAttempts` already is: a
record that used its attempts stays, with `recovery_required`.

### 3.4 Recovering without an operator (startup reconcile)

With 3.1–3.3 in place, the reconcile's decision table gains one row and loses
its timer:

- `stack_down` with a valid prior ref and an **armed** rollback or a record at
  or past the barrier: today `recovery_required`. Proposed: `restore_prior` —
  tag the prior ref, `up` (with the retry of rung 3), health gate, verify,
  then retire. This is the O5 outage recovered automatically, to the image
  that was running before the interrupted upgrade. It never starts the target
  image on its own.
- every retiring decision keeps `retireIfServing` (fresh readiness after
  completion is established).

`restore_prior` changes what startup may do with Docker, so it is a contract
change (AGT-004 / AGT-900) and an **owner decision**, behind
`reconcile_on_startup = "converge"`, which stays default-off until the
real-Docker gate is met.

### 3.5 What phase 1b implements, and what it leaves out

Implemented (ADR-0061, "When the window applies, and when it ends early"):

- the marker of 3.1, with the correction that it stays after any error exit,
  plus two conservative additions: the first start that keeps markers, and any
  interrupted journal record, count as a hazard;
- of 3.2, only the first condition: **no proxy container is running**, read
  twice one poll apart. That is every case in which the proxy is down, which
  is where waiting costs an outage;
- the `up` retry of 1a also triggers on a marker found at start, with no
  journal record needed.

Left out on purpose: the second condition of 3.2 (a running container that was
created after the cut). `CreatedAt` has 1 s resolution and Compose creates the
replacement within the same second as the command starts, so the comparison
would be ambiguous most of the time; and recording the container id before
each command would add a Docker read to every ordinary upgrade, which the
reviewed lifecycle model does not have. The cost of leaving it out is a full
window before the next *operation* in cases where the proxy is already
serving, not an outage.

## 4. What needs a decision, and what does not

| Step | Privilege | Contract | Decision |
|---|---|---|---|
| 1a. `up` retry in recovery context | none new | none (recovery only; with no interrupted record in the journal an upgrade makes the same calls; with one, of any class, it makes one extra read after `up`) | routine — implemented |
| 1b. Mutation marker + identity-based early advance | none new (uses `compose ps`) | relaxes when the settle wait applies; ADR-0061 addendum to be extended | routine implementation, but it **shortens a safety wait**: its own PR, independent review, full probe matrix before merge |
| 1c. `container_name_pending` in status / result | none new | additive status field | routine |
| 2. `restore_prior` in the startup reconcile | none new | AGT-004, AGT-900 amended | **owner** |
| 3. Seeing non-running containers (`compose ps -a`), stop timeout, so that intermediate states are named instead of inferred | one new sudoers line (read-only) and wrapper subcommand | packaging / security surface | **owner** — worth it only if 1a–2 leave a state unexplained |

Not proposed: daemon event subscription, a second state store, renaming or
force-recreating containers automatically, any change to the proxy's
`stop_grace_period`.

## 5. Qualification

Every step is qualified with the existing probe, extended as needed, before it
is trusted:

- all 14 kill points × {no follow-up, rollback, re-apply, startup reconcile};
- production-default timing (75 s / 60 s), the release image
  (`.github/workflows/lifecycle-orphan-probe.yml`, GitHub-hosted runner);
- new measures for 1b: time from operation admission to first Docker
  mutation (the wait actually paid), per kill point; a negative control in
  which the marker is removed by hand and the probe must see the false
  success come back;
- HA / control-plane shutdown paths, where the proxy's drain is longest — not
  built yet.

Properties, unchanged: no surviving docker command; no success on an
unhealthy or wrong-image state; no change after a reported success; no silent
divergence. New: **no second operator action needed** in the stop/delete window
(after 1a when a record was left, after 1b always) and no operator action in
the down window (after 2).

## 6. Open questions

1. `CreatedAt` has 1 s resolution and is wall-clock from the daemon. The
   margin and the behaviour under a clock step need a test; when in doubt the
   comparison must fall to "ambiguous", never to "created after".
2. Whether a marker should also be written around `docker tag`. A tag
   completes in milliseconds and the agent re-reads it; measured as harmless.
   Leaning no.
3. Multi-service stacks: the marker and the identity check are per proxy
   container. Other services recreated by the same `up` are not tracked.
