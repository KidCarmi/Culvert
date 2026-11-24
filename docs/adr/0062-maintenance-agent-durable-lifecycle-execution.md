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
- Add an optional `checkpoint` object: `{step, intent_at, budget,
  result, result_at, image_id}`. It is written fail-closed **before** a
  gate starts (`gate:target`, `gate:prior`) and best-effort after it ends
  (`passed` / `failed:<detail>`).
- Standalone image rollback records its prior (ref, image id) at capture
  and a barrier phase before its tag move, reusing `writeBarrier`.
- The inline rollback's gate failure becomes durable in `checkpoint`
  before `rollback_pull` (today it is only an audit line until the
  best-effort arm).
- Decisions gain facts, not new actions: `restarted` + `checkpoint
  gate:target failed` is no longer confused with "pending".
- **Command attribution is first-class** (rules from three independent
  reviews of #2093; its third review found it not merge-safe and it is
  parked):
  1. Attribution lives in the operation's own journal record, never in a
     global marker or a parallel ops array, and never in a cross-record
     ownership check. Before a Docker-changing command the op writes an
     intent (`{step, command, began}`) fail-closed; when the command
     RETURNS to a live process, success or error, the intent is closed, in
     a defer so a panic closes it too.
  2. The first agent start that reads an open intent consumes it durably
     BEFORE deciding anything, in every mode (off included) and whether or
     not Docker is readable or the agent can act. Any conditional consume
     (on freshness, mode, readability) lets a later start act on stale
     evidence. The cost, stated: a first start that defers forfeits a
     restore the evidence would have allowed; the record is then reported.
  3. No wall clock in the safety argument. An age bound may only narrow
     what is allowed, never decide whether evidence is consumed (a clock
     behind `began` after power loss, or corrected backwards, defeated the
     age bound in #2093).
  4. The settle/hazard marker (#2076) keeps answering "may dockerd still be
     finishing something"; it is not an attribution source. Mixing the two
     is how a fix to #2093 broke.
  5. The intent fields are schema 2 (slice 2): a pre-ADR agent would drop an
     open intent on rewrite and lose the consumed state, so the fence is up
     while any intent is open.
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

**Slice 7 — forward resumption of an interrupted health gate
(approved as its own, independently qualified slice).**
- Scope: a record whose open checkpoint is `gate:target` (slice 3) — the
  agent died while gating the target it had just started. Today that is
  `recovery_required/target_live_ungated`.
- Resume only if ALL hold: the durable intent names this op and this gate;
  container and pinned tag both resolve to the checkpoint's immutable image
  id, freshly read; no conflicting external change (no other open intent, no
  marker command of another op, identity unchanged across the gate); the
  settle window is over; the persistent resume budget is not exhausted
  (written ahead, like `ReconcileAttempts`); and a **fresh production health
  gate** passes.
- Then the op's remaining non-mutating steps run (verify by id and digest);
  the target is adopted and the record retired exactly once. Gate fails →
  the existing armed-rollback path (#2051) with its own gate, never a
  replay of the original `tag`/`up`.
- The interrupted operation's historical outcome is not rewritten: it stays
  `failed(agent_restart_interrupted)`; the resumption is its own audited
  `:resumed` event with its own outcome.
- AGT-900 extension text, model property and real-Docker cases ship with it.

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
