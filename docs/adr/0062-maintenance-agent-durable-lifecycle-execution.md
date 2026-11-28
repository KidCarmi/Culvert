# ADR-0062: Durable lifecycle execution for the maintenance agent

- Status: **Accepted** as the architectural direction, 2026-11-24 (owner
  decisions recorded below). Each slice still lands as its own production
  PR with tests, and a separate real-Docker qualification PR.
- Numbering: ADR-0061 is the highest file on main at 03241de8f. No open
  branch was found adding 0062; renumber if one has since.
- Builds on: [ADR-0061](0061-maintenance-agent-crash-journal-lifecycle.md)
  (crash journal, settle window), contract `AGT-900` (open), `AGT-004/005`,
  PR #2051 (converge plan executor), PR #2093 (`restore_prior`), #2091
  (restore journal), #2088 (durable idempotency), #2076 (mutation marker).
- Supersedes: the "runtime watchdog" proposal discussed for the
  `operator_retag_unarmed` GAP. A watchdog survives here only as a
  non-mutating observer (slice 5); it is not a recovery mechanism.

## Question

Can the agent persist enough execution context before every external
mutation that, after a crash, SIGKILL, reboot or unexpected restart, it can
reconstruct the interrupted operation and safely resume or recover it — and
what is the smallest change to the existing architecture that gets there?

## Answer in one paragraph

Yes, and without a new state store or framework. The journal already is a
durable, fsync'd, fail-closed, per-operation record with write-ahead
barriers; the mutation marker already covers the one class of command (a
container stop) the journal cannot; #2051 already has a step plan that
rechecks Docker before every mutation, writes a bounded attempt counter
ahead of acting, verifies by image id and retires exactly once. What is
missing is not a mechanism but **coverage and discipline**: the journal is
deleted at a failed terminal even when Docker is left in doubt, a health
gate's start and result are never recorded, the record has no schema
version and a startup rewrite drops fields an older agent does not know,
and recovery runs through two executors (#2051's plan and #2093's
hand-written sequence). The proposal is six small slices that close those
gaps and make the #2051 executor the single path every recovery takes.

## What exists, with evidence (main 03241de8f + #2051 1cbfa81)

| Need | Already provided by | Where |
|---|---|---|
| Durable per-op record | `journal.Record`, one fsync'd JSON per op id (ULID), fail-closed corrupt-record handling | `internal/journal/journal.go` `Write`, `atomicWrite`, `List` |
| Write-ahead before the tag move | phase `restarting`, fail-closed, recreates a missing record | `server/journal_phases.go` `writeBarrier`, `restartWithBarrier` |
| Write-ahead before a container stop | mutation marker, fail-closed, accumulate-until-proven-clear | `journal/mutation.go`, `server/mutation.go` (`composeUp`/`composeDown` only callers, test-pinned) |
| Restore stages | `RestoreStage`, fail-closed before stop and commit | `server/restore_journal.go` (#2091) |
| Durable request identity | idempotency record written before admission, terminal outcome persisted | `internal/idem` (#2088) |
| "dockerd may still be stopping something" | settle window derived from marker + journal | `server/settle.go` |
| Recovery decision | pure `reconcileDecisionV2(record facts + Docker facts + probe)` | `server/reconcile_decision_v2.go` |
| Recovery execution | `reconcilePlan` → per-step recheck (`stillDecides`) → `performStep` → `verifiedOnPrior` → `retireIfServing` → `retire` (audit once, then remove) | `server/startup_reconcile.go` (#2051) |
| Persistent retry budget | `ReconcileAttempts`, written fail-closed before acting, cap 2 | same |
| Model and conformance | lifecycle model, V2 table conformance on 145,152 inputs, crash vectors, real-Docker e2e | `internal/lifecyclemodel`, `test/agt900-e2e` |

## Gaps, ranked by risk (verified in code)

1. **A failed terminal erases durable intent while Docker is in doubt.**
   `ops.Run`'s `terminate` removes the journal record for every terminal
   state (`ops/orchestrator.go` `terminate`), including the outcomes
   `journal_phases.go` itself reports as "culvert/proxy:pinned LEFT at the
   target" or "container state is indeterminate". After a restart there is
   no record and no status entry; only the audit log shows it.
2. **Remove comes before the terminal audit.** A kill between them leaves
   no record and an audit trail that ends at `started`.
3. **No health-gate checkpoint.** The gate's start, budget and result are
   never journaled, so "gate pending", "gate failed, rollback pulling" and
   "gate passed, verify pending" are indistinguishable after a crash (all
   `restarted` → `recovery_required/target_live_ungated`). Nothing can be
   resumed forward.
4. **Two recovery executors.** #2093's `restorePrior` hard-codes tag → up →
   probe with one recheck before the whole action; #2051's plan rechecks
   before each mutating step. They also conflict on merge.
5. **No schema version; a downgrade silently drops evidence.** `initJournal`
   rewrites every record at each start; `encoding/json` drops keys the
   running agent does not know (`rollback_armed`, `restore_stage`,
   `reconcile_*`). Nothing detects it.
6. **Standalone image rollback records only admission.** No prior, no
   progress, no gate result: every moved-tag case is `recovery_required`,
   including a rollback that finished and passed its gate.
7. **Coordination is per process.** The maintenance lock is in memory; the
   instance flock is taken only in converge mode, so a second agent on the
   same `state_dir` in the default mode admits operations of its own. No
   in-agent mechanism can stop raw `docker`/`compose`, a restart policy, an
   installer or a reboot (`packaging/sudoers`, docs prescribe raw
   `docker compose up/down/restart`).
8. **Restore and data rollback skip the settle wait** before `compose
   down`/`up` (`handlers_d16b.go` stop/start stages), unlike apply and
   rollback.

## Decision: evolve, do not add

### Principles

- **The journal record is the operation's durable state.** No second store
  for lifecycle state. (The idempotency store of #2088 stays: it answers a
  different question, "has this request been admitted", and has its own
  key.) A new non-lifecycle store is allowed only for runtime health
  evidence (slice 5), which has no operation and must never rewrite one.
- **Intent before every external mutation, result after it.** A step that
  changes Docker or data writes its intent fail-closed first; a step whose
  outcome later decisions depend on (the gate) writes its result.
- **One executor for every recovery.** #2051's plan/step loop is the only
  code that mutates Docker outside the forward operation flows. New
  recovery verdicts are new plans, never new sequences.
- **Docker is truth for what is; the journal is truth for what was
  intended.** Every decision reads both, every mutating step rechecks
  Docker against the step's expected verdict, and anything the agent's own
  record does not explain is `recovery_required` — including a tag moved by
  hand, which is evidence of state, never authorization.
- **Forward resumption is a contract extension, not an implementation
  detail.** It is gated, default off, and recorded in AGT-900 as such.

### Slices (each its own PR; production and real-Docker evidence separate)

**Slice 1 — keep intent until the state is safe (gaps 1, 2).**
- `terminate` writes the terminal audit **before** removing the record,
  and the write is idempotent across a crash: the record keeps
  `terminal_outcome` until the audit is durable; a start that finds a record
  with `terminal_outcome` and no terminal audit entry for that op writes it
  (checked with `audit.HasSucceeded`-style lookup by op id, kind and
  outcome), then removes the record if the state is safe. The audit is
  never written twice and never lost.
- A failed terminal removes the record only when the op proved its end
  state safe, judged per operation class (Codex review on this ADR):
  - `upgrades.apply`: its own rollback passed its gate, or nothing was
    mutated, i.e. the record never reached the `restarting` write-ahead
    barrier (phase `admitted`..`pulled`). The phase is evidence here only
    because this flow writes that barrier before its tag move.
  - `rollbacks.create` mode `image`: its phase stays `admitted` while it
    moves the tag and runs `up`, so the phase proves nothing. Until slice 3
    gives it a barrier, its record is kept after any failure past
    admission's read-only steps (evidence: the failed stage name).
  - restore-class (`restore.commit`, `rollbacks.create` mode `data`): the
    phase stays `admitted` throughout; safety comes from `RestoreStage`. The
    record may be removed only at `admitted`/`preflight` (nothing stopped);
    from `stopping` onward it is kept unless the health check passed after
    `started`. Otherwise the record stays, gains
  `terminal_outcome` (`failed:<reason>`), and is reported by status exactly
  like an interrupted record; converge may act on it through the same
  decision table. The op's own outcome stays `failed`; nothing is rewritten
  to success.
- Compatibility: older agents see an ordinary interrupted record.
- Owner decision (approved): status and alerts show `recovery_required`
  after a failed operation whose end state is not proven safe.

**Slice 2 — schema version and lossless rewrite (gap 5).**
- Add `schema` (int, absent = 1). Records carry unknown keys through every
  rewrite (decode into the struct plus a raw remainder; re-encode both).
- A record whose `schema` is newer than the agent is reported, never acted
  on (`recovery_required/record_from_newer_agent`), and never rewritten.
- **Enforced downgrade fence** (owner: not release notes alone). While any
  record relies on a schema-2 field, the journal directory also holds a
  fence record under the fixed ULID name `00000000000000000000000000`
  whose `phase` is a value no schema-1 agent knows. Every released agent
  already treats an unknown phase as a corrupt record and refuses to serve
  (`List` → `ErrCorruptRecord`, `initJournal`), so an older agent started
  on that state directory stops instead of silently dropping evidence. The
  fence is written fail-closed before the first schema-2 field is relied
  on, and removed (after the audit) when the last such record retires. A
  schema-2 agent skips the fence by name. The fence and its effect on an
  older binary are tested by running the previous release's journal code
  against it.
- This is the precondition for every later field.

**Slice 3 — step checkpoints, starting with the gate (gaps 3, 6).**
- Add an optional `checkpoint` object: `{step, intent_at, attempts,
  epoch, result, result_at, image_id}` (amended: `budget` was ambiguous
  between "left" and "used"; `attempts` counts the gate runs begun for
  `step`, written ahead and only ever raised, like `ReconcileAttempts`.
  `epoch` is the record's `interrupted_seen` at `intent_at`, for the reason
  rule 5 gives command intents: a start that counted in between makes the
  checkpoint history, not an interruption to resume). It is written **before** a gate starts
  (`gate:target`, `gate:prior`) and best-effort after it ends (`passed` /
  `failed:<detail>`). Which write may refuse what is decided per write,
  by rule 1's test (amended; the first text made every intent
  fail-closed):
  - **`gate:target` intent: fail-closed.** A write that fails is treated
    as a failed gate, so the inline rollback runs; refusing can only lead
    to the conservative branch. `image_id` is the target's id as the
    restart captured and digest-verified it (empty when that capture
    failed; slice 7 then has nothing to resume on). The cost is
    availability, not safety: on a state directory that cannot be written
    a healthy target is rolled back. It is reported under its own
    `failure_reason` (`checkpoint_unwritable`), never as a plain gate
    failure, so an operator can tell the two apart.
  - **`gate:prior` intent: best-effort.** Fail-closed would refuse the
    inline rollback's own gate on a full disk and leave the failed target
    serving (rule 1). A missing `gate:prior` intent only withholds a later
    resumption of that gate.
  - **`gate:target` result `failed`: attempted before `rollback_pull`,
    never blocking.** Blocking would keep a target that failed its gate
    serving. If it cannot be written the record says "gate begun, no
    result" although the gate failed. Slice 7 must not read that as
    "interrupted": see its exclusions.
  - `passed` is best-effort: `verified` already records it, and a lost
    `passed` only withholds a resumption that is not needed.
- Standalone image rollback records its prior (ref, image id) at capture
  and a barrier phase before its tag move, reusing `writeBarrier`.
- The inline rollback's gate failure becomes durable in `checkpoint`
  before `rollback_pull` (today it is only an audit line until the
  best-effort arm), under the rule above.
- Decisions gain facts, not new actions: `restarted` + `checkpoint
  gate:target failed` is no longer confused with "pending". **Moved to
  slice 7** (amended): the checkpoint lands first as record-and-report,
  with no decision change, so it does not collide with slice 4's work on
  the decision table, and its only consumer arrives with the rules that
  constrain it.
- **Command attribution is first-class** (rules from three independent
  reviews of #2093; its third review found it not merge-safe and it is
  parked):
  1. Attribution lives in the operation's own journal record, never in a
     global marker or a parallel ops array, and never in a cross-record
     ownership check. Before a Docker-changing command the op writes an
     intent (`{step, command, began, epoch}`); when the command RETURNS to a live
     process, success or error, the intent is closed, in a defer so a panic
     closes it too. The intent write is best-effort, not fail-closed: an
     absent intent only withholds attribution (a death in the command is
     then reported, never acted on), so a failed write cannot cause a wrong
     action, while refusing the command on it would stop an inline rollback
     on a full disk. (Amended: the first text said fail-closed.)
  2. The first agent start that reads an open intent consumes it durably
     BEFORE deciding anything, in every mode (off included) and whether or
     not Docker is readable or the agent can act. Any conditional consume
     (on freshness, mode, readability) lets a later start act on stale
     evidence. The cost, stated: a first start that defers forfeits a
     restore the evidence would have allowed; the record is then reported.
     Unlike the intent, the consume is NOT best-effort: if it cannot be
     written, the open intent stays on disk and the next start cannot tell
     itself from the first, so a start that reported in between (and an
     operator who acted on that report) would be contradicted (case A
     through one failed write). A start that cannot make the consume durable
     therefore stops before serving or reporting, which leaves only the
     envelope this rule already accepts: changes made while no agent ran.
     The consume is written before the start's audit entry, so a refused
     start leaves neither. A record from a newer agent that carries an open
     intent is refused the same way: this build may not rewrite it (slice
     2), and reporting it would hand the newer agent's next start stale
     evidence. An older, fence-aware agent therefore does not serve on such
     a directory: the fence's purpose, reached by a second route.
  3. No wall clock in the safety argument. An age bound may only narrow
     what is allowed, never decide whether evidence is consumed (a clock
     behind `began` after power loss, or corrected backwards, defeated the
     age bound in #2093).
  4. The settle/hazard marker (#2076) keeps answering "may dockerd still be
     finishing something"; it is not an attribution source. Mixing the two
     is how a fix to #2093 broke.
  5. An open intent carries an epoch: the record's `interrupted_seen` when
     the command began. The start that takes it attributes the death only
     on epoch equality, so any start that durably counted in between (an
     older agent that carried the unknown key, for one) makes it stale.
     Attribution after the take lives only in that process's memory; on
     disk the cut is diagnostics. The epoch alone is not enough: older
     agents count best-effort, so one that serves while its count write
     fails leaves the epoch equal, and an operator acting on what it
     reported is contradicted when this build returns. While an intent is
     open the journal therefore holds a second fence (generation 2,
     `00000000000000000000000001`, phase `schema_fence`): agents before
     slice 3 do not skip that name, so every one of them, slice-2 agents
     included, refuses to serve. The fence is raised before the intent;
     if it cannot be raised, no intent is written and nothing is
     attributed (the command still runs). It is removed once no record
     holds an intent, and a fence left by a crash is removed at the next
     start of this build. The intent does not raise the record schema.
     (Amended: the first text made the intent schema 2 behind the
     generation-1 fence, which slice-2 agents skip by name.)
- Acceptance cases (repro tests from the #2093 reviews), each must start
  nothing: (A) cut after the target's `up` → report → operator `down` →
  restart; (B) two records, the newer op's `up` cut: the older record does
  nothing; (C) the reconcile's own `up` fails with the agent alive,
  operator `up` then `down` (operator on prior and on target), restart;
  (D) clock behind `began` at the first start, operator `down`, restart
  with the clock back in range; (E) first start in off mode, then converge.
  Positive: the agent dies inside the upgrade's `up`, the proxy is down; the
  next start restores the prior, gated and verified by id; a restore cut in
  its own `up` is retried once (attempt cap 2).
- Ownership: the workstream that built #2093 implements slices 3 and 4
  (record-level intent, then `restore_prior` as a plan on the slice-4
  executor), on top of slice 2's schema and fence and coordinated with
  slice 1's changes to `terminate` and startup reporting.

**Slice 4 — one executor (gap 4).**
- Extract #2051's loop from `reconcileCase` into an executor that takes a
  trusted record, a plan and a decide function; keep the step set
  (`tag:prior`, `up`, `gate`, `probe`) and add `up_again` (from
  `upAgainIfNothingRuns`).
- Express #2093's `restore_prior` as the plan `[tag:prior (expect
  restore_prior), up (expect the post-tag verdict), up_again, gate]` and
  delete `restorePrior`/`performAction`. This gives `restore_prior` the
  recheck between tag and up that it lacks today.
- Inline and standalone rollback keep their forward stages but call the
  same step functions (`tagAndUp` already shares tag/up/settle).
- Obligations of the attribution consumer (from the independent reviews
  of #2103; slice 3 records and reports, slice 4 is the first to act):
  1. The in-memory attribution is consumed once per process: the decision
     that acts on it takes it; status only shows it.
  2. "Died in `<command>`" means the intent was written, not that the
     command started or reached Docker. It never authorises a step on its
     own: the plan's steps act only when Docker's live state, read fresh
     (container id, image ids, pinned tag), matches the record's target
     and prior identities.
  3. Restore-class records (`restore.commit`, data rollback) are decided
     on kind and restore stage, not on the command alone: the stack is
     down on purpose before their `up`.
  4. Not fenced by slice 3: an agent too old to read the journal at all,
     and a state directory restored from a backup taken while an intent
     was open (its epoch still matches, the death is long past). Rule 2
     above is what keeps the second from causing a wrong restore.
  5. The recorded command names a compose command of this operation. With
     the journal unwritable across two commands of one operation (the
     close of the first and the intent of the second both lost) a death in
     the second is reported under the first's name. No flow runs `down`
     after `up` under one operation today; the consumer decides on Docker's
     state, the record's kind and phase, never on the name alone.
- **As built (`restore_prior`, slice 4):** a new verdict, decided only when
  no proxy container runs, the record is an upgrade at `restarting` or
  `restarted` (armed or not; refused at `verified`, as #2051 refuses an armed
  record there), the attribution says `compose up`, the recorded prior is
  local and identical, and the fixed tag is on the prior or the target. Its
  plan on #2051's executor is `[tag:prior, up, up_again, gate]`; every step
  that changes Docker is preceded by a fresh read that must still decide
  `restore_prior`, and `up_again` runs `up` only if a fresh read shows nothing
  running (Compose's tidy-only pass after an interrupted recreate). Then
  verification by image id and retirement through the usual readiness check.
  How the obligations are met: (1) the reconcile takes the attribution
  (`takeCommandAttribution`) when it builds a record's inputs, whatever that
  record then decides; (2) the attribution is one input among the Docker
  facts and only turns a `stack_down` report into `restore_prior` or a more
  specific report (property RV18); (3) the verdict is reached only through
  the upgrade branch, never for a restore-class or standalone record; (4)
  stated residual: a state directory restored from such a backup, with the
  stack down and the tag still on that operation's prior or target, is
  restored to that operation's recorded prior image, gated and verified; (5)
  only `compose up` counts. The reconcile's own `up` runs under the record's
  operation, so a restore that dies in its own `up` is attributable once
  more; the attempt cap (2) ends it. A start that defers (Docker unreadable)
  has taken the attribution: the record is then reported, not restored.
- **Docker's evidence (`restore_prior`, slice 4, after review B1).** The
  attribution cannot tell a death inside `compose up` from a `compose up`
  that returned while the state directory could not record it (disk full,
  read-only, until the process ended): the open intent then outlives the
  command, and an operator's later `compose down` would have been undone
  (reproduced). A restore therefore also requires Docker to list, with a
  read-only `compose ps -a` (its own sudoers rule), a proxy service
  container in state `created`: on real Docker every death inside `up` that
  left no proxy running left one (kill points 9, 10 and the held 9), a
  `compose down` removes it, and a `docker stop` never makes one. A one-off
  container (`com.docker.compose.oneoff=True`) is never evidence: a
  `compose run` without `--rm` whose start fails stays `created`, and
  `compose down` does not remove one-offs (measured, Compose v5.7.1; found by
  the second review). A `created` proxy whose one-off label cannot be read is
  treated as unreadable. A Compose whose `ps --format json` carries no
  per-container labels therefore never restores (fail-closed; not verified on
  older Compose versions, verified on v5.7.1). It is read only when the
  attribution is set and no proxy container is listed, again before every
  Docker change up to the reconcile's own first `up`, and not after it (that
  `up` removes the container itself in Compose's tidy-only pass). Unreadable
  or not understood (a sudoers file without the rule included) is never
  evidence: `up_evidence_unreadable`; absent: `stack_down_no_up_evidence`.
  Residuals that remain: an operator who changes nothing of the crashed stack,
  or only stops containers, before the next start is still indistinguishable
  from the crash, and is restored; so is one who, after the crash, runs
  `compose create` or `compose up --no-start`, or a `compose up` that fails
  at start (a port conflict, a bad mount), each of which leaves a `created`
  service container; an operator `compose down` and later `up`
  between the reconcile's own `up` and its second `up` is the same TOCTOU
  class as every other step. Liveness lost, all in the safe direction (the
  record is reported): a start whose settle wait is cut short, a start that
  dies after its write-ahead or its retag but before its own `up`, and one
  that dies between its `up` and its second `up`, have each taken the
  attribution.

**Slice 5 — runtime observation (non-mutating).**
- One loop, started like the op-log retention loop but tracked by
  `goOp`/drain, that never begins a state-changing op and never mutates
  Docker. Each tick: skip while the maintenance lock is held or the settle
  window is open; read identity (`ReadProxyContainer`, `PinnedTagImageID`),
  run the **production** gate (`HealthProbeFactory`) with a bounded budget,
  re-read identity, and discard the sample if identity changed in between.
- Evidence goes to `state_dir/health/latest.json` (atomic write, bounded),
  keyed by container id + image id: `gated|ungated|unhealthy|unknown|stale`.
- **Last-known-good is kept apart** in `state_dir/health/last_good.json`:
  written only when the production gate passes with identity unchanged
  across the probe, and never overwritten or cleared by an unhealthy,
  unknown or stale observation. It records the image id, its validated
  reference and digest, the data compatibility evidence (slice 6), and when
  and by which gate it passed. It is the only runtime source of a trusted
  recovery target.
  It never touches journal records or audit history of an interrupted
  operation.
- Status gains `runtime_health`; the main app's `/api/maintenance-agent`
  and alerting read it (latched alerts, as `release_alerts.go`); the agent
  gains no metrics endpoint of its own — the main app exports them.
- This closes the visible half of `operator_retag_unarmed` and
  `up_done_unrecorded`: an image that has not passed the gate is reported
  as `ungated`, and a late gate that passes makes it `gated`.

- Implementation (2026-11-27, agent half; contract AGT-007):
  - Off by default (`runtime_health_interval`, `1m`–`24h`): it is new
    Docker and proxy traffic on every install, and an agent upgrade should
    not start it unasked. Qualified on real Docker in its own PR before any
    default changes.
  - Identity is container id, its image id, running state and the fixed
    tag's image id; the lock and the settle window are checked again after
    the probe, so an operation that began during it discards the sample.
  - `ungated` and `stale` are derived when status is read (the running
    image from the status capture; three intervals without a reading); the
    files hold only `gated`, `unhealthy` and `unknown`.
  - An image is last-known-good only with a reference that passes the same
    repo-bound exact-digest check and allowlist as an upgrade target. A
    gated image without one is reported `gated`
    (`gate_passed_no_validated_ref`) and recorded nowhere else.
  - Status never carries the container id, as for `running_image`.
  - The main app's `/api/maintenance-agent` passes `runtime_health` through
    (closed state set; anything else is shown as unknown; strings bounded)
    and the legacy Support panel shows it (2026-11-27).
  - Not yet: latched alerts on it, which need a main-app poll of the agent
    that does not exist today; the data-compatibility evidence in
    `last_good.json` arrives with slice 6, which defines it.

**Slice 6 — policy-driven runtime recovery (default off).**
- A runtime finding becomes a **synthetic record** in the same journal
  (kind `runtime.recover`, schema 2), written fail-closed before anything
  mutates, carrying the trusted target and the evidence that justified it.
  It then goes through the slice-4 executor and the same decision function
  family. No second recovery framework.
- Required, all of them: an explicit policy key (`runtime_recovery =
  "restore_last_gated"`, default `off`); the maintenance lock (409 to
  operators while it runs); the settle window over; fresh identity; a
  **trusted target** = the image id this agent last recorded as `gated`
  (slice 5 evidence) or a journal `PriorImageID`, resolvable by a validated
  allow-listed reference — never "whatever the tag points at"; write-ahead
  attempt counter in the synthetic record; recheck before every step;
  verify by id; retire exactly once.
- A manually moved tag is a fact the decision sees; it never selects the
  target. If the tag points at an image that is not the trusted target, the
  verdict is `recovery_required`.
- **Image and data compatibility before restoring an earlier image.** The
  restore target must be proven compatible with the data the newer image
  may already have migrated: the target's declared data-schema range (image
  label) must include the data directory's current schema marker. Unknown
  on either side is `recovery_required/restore_compatibility_unknown`,
  never a restore. The same check applies to the startup executor's
  existing prior-restoring plans before they are reused at runtime.
- AGT-900 extension, recorded explicitly: "converge may restore the last
  image this agent gated, at runtime, when policy allows" — new contract
  text, its own tests, model property and real-Docker cases.
- **Scope (owner decision 2026-11-28): only images this agent installed.**
  The agent acts only when it put the unhealthy image there itself: a later
  failure of an upgrade (or image rollback) that passed, or an interrupted
  upgrade whose target is now unhealthy. It restores the image that was gated
  before that change. A hand retag or a hand `compose up` is reported, never
  acted on: a manual change is evidence of state, not authorization.
- **Design (2026-11-28), in four PRs, each production change separate from
  its real-Docker qualification:**
  1. *Provenance and gated history (data only).* When an upgrade or image
     rollback this agent ran passes its gate and verify, it writes
     `<state_dir>/health/installed.json`: the op id, the image it installed
     (id, validated ref, digest) and the image it replaced (id, ref). The
     observer keeps the last two distinct gated images in
     `<state_dir>/health/gated.json` (newest first); `last_good.json` is
     unchanged. Both are best-effort and nothing acts on them yet; a file that
     is absent or unreadable means "no provenance" and blocks every action.
  2. *Decision (pure) and lifecycle model.* A new journal kind
     `runtime.recover` (schema 2, so an agent before slice 2 is fenced off).
     Its record names the restore target as the prior (`PriorRef`,
     `PriorDigest`, `PriorImageID`), the unhealthy image as the target, and
     is written with `RollbackArmed` set before anything moves. The decision
     for it is the armed-rollback branch the startup reconcile already runs
     (`finish_rollback_retag`: tag the prior, `up`, gate, verify by id,
     audit-first retire), entered only when every condition below holds on
     fresh facts. The lifecycle model and its properties gain the kind before
     the executor relies on it.
     *As built:* `decideRuntimeRecoverV2` reports a record that is not armed
     (`runtime_recover_not_armed`) or not at `restarted`
     (`runtime_recover_unexpected_phase`); otherwise it takes the upgrade's
     danger-window decision and refuses every verdict that tags or starts the
     prior unless `dataCompat` is compatible (`restore_incompatible`,
     `restore_compatibility_unknown`). Compatibility is read with the Docker
     facts, so every pre-change recheck reads it again, the one before `up`
     included. Model properties RT1–RT4 (no move without proven
     compatibility; a compatible healthy restore completes, also after a
     crash; a retired recovery leaves the restore image running, tagged and
     ready; the recovery is its own operation), each with a mutant it kills.
     Contract: AGT-900 amendment.
  3. *Executor, trigger, policy and status.* `runtime_recovery = "off"`
     (default) or `"restore_last_gated"`, startup-only, valid only with
     `runtime_health_interval` on. A separate loop (the observer stays
     non-mutating, AGT-007) acts after **3 consecutive kept `not_ready`
     samples** of the same running container and image (in memory; a
     restart starts the count again). It begins the operation under the
     maintenance lock (operators get 409), writes the record fail-closed, and
     runs the plan through the startup executor's steps. Status reports it.
     *As built:* the observer hands each sample it kept to a counter and
     does nothing else; the worker (`runtime_recovery.go`) checks admission
     once without the lock, so a steady refusal costs no operation and no
     audit entry, then begins `runtime.recover` and checks it again under
     the lock. The attempt counter is
     `<state_dir>/health/recover_attempts.json`, keyed by (source op, X) and
     written before the record, so the cap of 2 outlives a retired record
     and a new install of the same image starts from zero. R's reference is
     its `gated.json` entry's, validated again (repo-bound exact digest,
     allowlist) and required local as R. The plan is the startup reconcile's
     `act`: the decision on fresh facts must be `finish_rollback_retag`.
     Audit: `runtime.recover` started and succeeded/failed (actor
     `agent:runtime-recovery`) around the plan's own
     `runtime.recover:reconciled` entry. Status: `runtime_recovery` (policy,
     threshold, streak, running, last attempt). Contract AGT-010 (open until
     PR 4); AGT-001 and AGT-009 amended. The main application's pass-through
     of `runtime_recovery` is a follow-up, as `runtime_health`'s was.
  4. *Real-Docker qualification* in all four cells, with negative controls.
- **Admission: checked once, on fresh facts, before the record is written.**
  - The policy is on, the lock is free and the settle window is over.
  - The container runs, and container and fixed tag are on the same image X.
  - X is the image `installed.json` names, or the target of a kept interrupted
    upgrade record of this agent.
  - The restore target R is the image that change replaced (`installed.json`
    `replaced_*`, or the record's prior). R is in `gated.json`. X may be the
    newest gated entry: an upgrade A→B that passed, was gated, and later fails
    restores A, which is the main case this slice exists for.
  - R's reference passes the repo-bound exact-digest check and the image
    allowlist, and R is local.
  - `dataCompat` (slice 6a) is compatible for R's labels and the data epoch.
  - Fewer than 2 runtime recoveries were begun for X (write-ahead counter).
  - Anything else is reported (`recovery_required/<reason>`), never acted on.
    A stack that is down, an unknown or no-container sample, or no provenance
    is reported only.
- **Each step then expects the state its predecessor leaves, as
  `reconcilePlan` already does.** Before the retag: tag and container on X.
  Before `up`: the tag on R and the container still on X (the state the
  retag leaves, decided as `verdictFinishRollback`). After `up`: a fresh gate
  of R, then container, tag and R's local image verified by id. The
  compatibility check is repeated before `up`, the step that starts R on the
  data. A state no step of this recovery explains stops it with nothing more
  changed.
- **After a crash** the record is an armed image-change record: with
  `reconcile_on_startup = "converge"` the startup reconcile decides it with
  the same branch, which already decides the post-retag state (tag on R,
  container on X) as `finish_rollback`, and with the same compatibility
  check before `up`; with `"off"` it is reported (AGT-004). A runtime recovery retires only its own record; a kept
  interrupted-upgrade record stays until an existing rule retires it.
- **Audit:** `runtime.recover:started` before the first mutation and
  `runtime.recover:succeeded|failed` at the end, audit before retire, as
  every other recovery.

- **Slice 6a (owner decision 2026-11-28): the compatibility contract comes
  first.** Culvert had no data-schema marker and no image label, so nothing
  could prove an earlier image reads the data. The owner chose to add the
  contract before slice 6 (contract UPG-003, docs/engineering/data-epoch.md):
  a data epoch marker under `/data` that only rises (absent = epoch 1), image
  labels `io.culvert.data-epoch.min/max`, and a read-only
  `culvert --print-data-epoch` the agent runs through the `cli` service. An
  image without the labels is never put back. Every build so far is epoch 1,
  so nothing is written yet; raising the epoch carries backup and restore
  obligations that a tripwire test enforces.

**Slice 7 — forward resumption of an interrupted health gate
(approved as its own, independently qualified slice).**
- Scope: a record whose open checkpoint is `gate:target` (slice 3) — the
  agent died while gating the target it had just started. Today that is
  `recovery_required/target_live_ungated`.
- Resume only if ALL hold: the durable intent names this op and this gate;
  container and pinned tag both resolve to the checkpoint's immutable image
  id, freshly read; no conflicting external change (no other open intent, no
  marker command of another op, identity unchanged across the gate); the
  settle window is over; the checkpoint's `attempts` is below the resume
  cap, raised and written ahead of the resumed gate (like
  `ReconcileAttempts`); the checkpoint's `epoch` is the record's current
  `interrupted_seen`; and a **fresh production health gate** passes.
- Never resume (amended, from slice 3's write rules and slice 4's review):
  - when `rollback_armed` is set, or container or tag is not on the
    checkpoint's `image_id`: the inline rollback was already under way;
  - when the checkpoint has no `image_id`: identity is unknown;
  - when this start's command attribution says the agent died inside that
    operation's `compose up`: the restart itself is in doubt, and a proxy
    that is down is slice 4's `restore_prior`. Amended by the owner decision
    of 2026-11-26 below: not when Compose is shown to have finished;
  - when `attempts` has reached the cap. `attempts` counts the original
    gate as one, so "gate begun, `failed` lost" (slice 3's residual) is
    resumed at most `cap - 1` times. That residual is the
    one case where a resumption can adopt a target that failed a gate
    once: the state directory could not be written when it failed, the
    agent then died before the rollback moved the tag, and the target now
    passes a fresh production gate. It is stated, not closed: closing it
    means refusing the rollback on a full disk, which rule 1 forbids.
- Then the op's remaining non-mutating steps run (verify by id and digest);
  the target is adopted and the record retired exactly once. Gate fails →
  the existing armed-rollback path (#2051) with its own gate, never a
  replay of the original `tag`/`up`.
- The interrupted operation's historical outcome is not rewritten: it stays
  `failed(agent_restart_interrupted)`; the resumption is its own audited
  `:resumed` event with its own outcome.
- AGT-900 extension text, model property and real-Docker cases ship with it.
- **Owner decision (2026-11-25): slice 7 also covers a gate that never
  began** (`up_done_unrecorded`): the agent died after the target's `up`
  returned and before `gate:target` was written, so there is no checkpoint.
  With no checkpoint there is no epoch or attempt count, so the rules below
  take them from the record instead, and are stricter.
- **As designed (amended):**
  - **Switch.** `resume_interrupted_gate`, default `false`, effective only
    with `reconcile_on_startup = "converge"`. Converge users are qualified
    without resumption; turning it on for them silently would change what
    their appliance does after a crash. It is independently qualified, as
    owner decision 4 asks.
  - **Epoch, precisely.** The start counts `interrupted_seen` before the
    reconcile decides. "No start but this one has seen the record since the
    gate began" is therefore `checkpoint.epoch == interrupted_seen - 1`; for a
    gate that never began, `interrupted_seen == 1`. At the counter's cap the
    count stops, the equality cannot hold, and nothing is resumed.
  - **Decided as `resume_gate`** (reasons `target_gate_interrupted`,
    `target_gate_not_begun`) only for an `upgrades.apply` record at
    `restarted` whose target id was digest-verified by the restart, with
    container and tag freshly read on that id, and none of the never-resume
    rules above. Every other record decides exactly as before.
  - **Its plan changes nothing in Docker until the gate has failed:**
    (1) write the checkpoint ahead, FAIL-CLOSED: `gate:target`, attempts
    raised (1 for a gate that never began), epoch = the current
    `interrupted_seen`; (2) a fresh production gate; (3) verify container and
    tag by image id and the running digest against the record's target
    digest. Each step is preceded by a fresh read that must still decide
    `resume_gate`.
  - **Gate or verify passes:** the target is adopted and the record retired
    with one `upgrades.apply:resumed` audit entry (outcome succeeded). The
    original operation stays `failed(agent_restart_interrupted)`.
  - **Gate or verify fails:** the result (`failed:<detail>`) and
    `rollback_armed` are written FAIL-CLOSED, and the reconcile decides
    again in the same start. Converge runs only at startup, so leaving the
    rollback for "the next start" would leave a target that failed its gate
    serving until some later restart. The new decision is #2051's T/T-armed
    finish, run on the same executor within the persisted attempt cap; it
    is never a replay of the original `tag`/`up`. If those writes fail, the
    record keeps its open checkpoint with an attempt spent and is reported.
  - **Attempts cap: 2 gate runs begun** per record (an interrupted original
    plus one resumption; a gate that never began gets two resumptions,
    since none had begun).
- **Correction (2026-11-25, found by the real-Docker qualification).** The
  owner decision above describes `up_done_unrecorded` correctly, but the
  design restricted `resume_gate` to records at `restarted`. In that case
  the agent died after `compose up` returned and *before* it recorded the
  restart, so the record is still at `restarting` and holds no target id:
  the restart captures the id in that same lost write. As designed, slice 7
  covered only the moment between the `restarted` write and the checkpoint
  write, not the owner's case. Amended:
  - **Identity is established on fresh facts** (`resumeIdentity`):
    container, fixed tag and the validated `TargetRef` resolve to one local
    image id, not the prior's, whose RepoDigests list the record's pinned
    digest. That is the check the restart itself makes before it records
    the id (F1), made now instead of read from the record. At `restarted`
    the recorded id must also be that id; at `restarting` none may be
    recorded yet (a recorded id there contradicts the write order).
  - The checkpoint is written ahead on that id, so "the checkpoint has no
    `image_id`" still never resumes. The record's phase and `TargetImageID`
    are not rewritten.
  - The digest condition is now checked before any gate, at both phases:
    an image that does not carry the pinned digest is reported
    (`target_live_ungated`) instead of being gated and then rolled back on
    the verify. The verify repeats the same identity check on the gate's id.
  - Everything else is unchanged: `interrupted_seen == 1` for a gate that
    never began, the epoch rule, the cap, a death inside `compose up`, an
    armed record.
- **Second finding, and owner decision (2026-11-26).** That correction was
  still not the owner's case. On real Docker, `up_done_unrecorded` is the
  agent killed while its own `compose up` had not returned *to it*, although
  Docker had finished the recreate: the start attributes a death inside
  `compose up`, and the never-resume rule above refused it. Asked whether to
  keep that rule (the case stays an operator's) or resume with proof that
  Compose finished, the owner chose the second:
  - after a death inside the operation's `compose up`, the gate is resumed
    only when the proxy container **runs** the identified target (as for
    any resume) **and** `compose ps -a` lists **no** never-started proxy
    container (slice 4's evidence, `UpEvidence` absent). A container left in
    `created`, a listing that cannot be read or is not allowed (a sudoers
    file older than slice 4), or a listing not read, resumes nothing;
  - the settle window is over before anything is read (as for every
    reconcile), so a `compose up` the dead agent left running has had the
    window to finish or to leave its evidence;
  - the listing is read only where it can decide this: with
    `resume_interrupted_gate` on and the proxy running. With the switch off
    nothing more is read than before;
  - why: the target is already serving, unchecked. Checking it, and rolling
    back if it fails, is strictly better than leaving it; the evidence is
    what keeps a recreate still in progress from being mistaken for one
    that finished.

### Not doing

- No separate watchdog per failure mode: every runtime finding is a
  record + plan through one executor.
- No blind replay of an interrupted external mutation (`tag`, `up`,
  `down`, a data swap). A cut mutation is reconciled from Docker truth;
  only the non-mutating gate is resumed (slice 7).
- No attempt to "lock out" raw Docker. Coordination for operators is
  procedural (docs: use the agent's API; `compose up` by hand only when no
  record is outstanding) plus detection after the fact.

## Coordination (gaps 7, 8)

- Take the instance flock in every mode, not only converge; a second agent
  on the same `state_dir` refuses to serve (today it only skips its
  reconcile). **Owner decision**: this changes startup behaviour for a
  misconfiguration that is otherwise silent.
- Restore and data rollback wait out the settle window before `compose
  down`, like apply and rollback.
- The documented operator workflows that bypass the agent stay supported;
  the runbook states which are safe only with no outstanding record, and
  status says when one is outstanding.

## Compatibility with deployed appliances

(See slice 2 for the enforced downgrade fence.)

- Every new field is optional; absent means today's meaning. Schema 1
  records are read and acted on exactly as today.
- Slice 2 lands before any slice that writes a field an older agent would
  drop; until then no new field is relied on for safety.
- Downgrade: an older agent drops unknown keys on rewrite (today's
  behaviour); with slice 2 in place, a newer record is never acted on by an
  older-but-slice-2 agent. Agents before slice 2 cannot be protected; the
  release notes say downgrade across slice 2 is unsupported while records
  are outstanding.

## Verification for each slice

- Unit and conformance tests beside the owner; a negative control per new
  guarantee (remove the write-ahead / recheck / audit order and see a test
  fail).
- The lifecycle model gains the new phases/fields before the code relies
  on them; the reviewed baseline changes in the same PR with its review
  block.
- Real-Docker cases in `test/agt900-e2e` (both stores, root and sudoers),
  in a separate verification PR per slice.

## Owner decisions (2026-11-24)

1. Approved: retain durable operation records until the appliance state is
   proven safe (slice 1).
2. Approved: exclusive instance lock in every operating mode.
3. Approved: policy-driven runtime recovery as an AGT-900 extension,
   disabled by default until qualified (slice 6).
4. Approved: safe forward resumption of interrupted health gates as an
   additional, independently qualified slice (slice 7), under the
   conditions listed there.
5. Required in addition: enforceable downgrade protection (slice 2 fence),
   crash-safe and idempotent terminal audit (slice 1), last-known-good
   evidence preserved across unhealthy observations (slice 5), image and
   data compatibility before restoring an earlier image (slice 6), one
   lifecycle journal and one recovery executor, and production
   implementation separate from real-Docker qualification evidence.

## Order of work

slice 2 → slice 1 and the instance lock → slice 3 → slice 4 (after #2051
merges; #2093's `restore_prior` moves onto it) → slice 7 → slice 5 →
slice 6.
