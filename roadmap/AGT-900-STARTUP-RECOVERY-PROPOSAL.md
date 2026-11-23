# AGT-900 startup recovery: failure matrix and implementation proposal (design only)

> **Status: proposal, awaiting owner decision.** No product behaviour is changed by this document.
> Evidence-backed investigation for the verification program (see roadmap/VERIFICATION-PROGRAM.md); lifecycle evidence: PRs #2020, #2030.

Revision read: `94cffdb`. Paths are relative to `cmd/culvert-maint/`.

## 0. Ground truth (what exists today)

- Startup only reports. `initJournal` lists the records and fails closed on a corrupt one
  (main.go:205-208). It writes one audit entry plus the start counter (main.go:235-274) and
  marks each op `failed(agent_restart_interrupted)` (main.go:214, ops/ops.go:634-667). It never
  calls Docker. AGT-004 is **enforced** and forbids "pulling, tagging or recreating containers at
  startup" and "removing a journal record at startup" (contracts/registry.yaml:685-713).
- `reconcileDecision` is pure and has no production caller (reconcile_decision.go:1-8). Its
  first-match ladder: data router :124-126, ref gate :128-130, attempt cap :132-134,
  `live_target[_prior_equals_target]` :146-151, `reup` :160-162, `already_on_prior` :165-167,
  `safe_boundary_confirmed` :170-174, `indeterminate_restore_prior` :177-179,
  `no_recovery_target` :180.
- Journal: phases admitted…verified (journal/journal.go:42-50). The set is closed on read: an
  unknown phase is `ErrCorruptRecord` (:190-192). The barrier is fail-closed and fsynced before
  the tag moves (journal_phases.go:100-122, journal.go:249-279). Progress phases are best-effort
  (journal_phases.go:89-91).
- **Inline and standalone rollback write no journal phase.** `imageRollbackStages`
  (rollback_stages.go:76-139) has no journal call. The only writers are handlers_d16b.go:281
  and the apply stages (handlers_upgrade_apply.go:223,230,277,316,427 plus the barrier). A
  standalone image rollback stays `admitted` with only TargetRef (handlers_d16b.go:192-208).
- `TargetImageID` is captured from whatever runs after `up` returns 0, with no digest check
  (journal_phases.go:147-149). That is C2/F1 (docs/adr/0061…md:127-140).
- Terminal: `Manager.Finish`, then `Journal.Remove`, then the terminal audit
  (ops/orchestrator.go:157-183).
- The health probe has **no definitive-unhealthy class**. It polls /ready until the budget runs
  out, and every failure ends as `ready_timeout` (internal/health/health.go:139-153).
  `Failed()` is `!ReadyOK` (:59). The default budget is 30s (:85-86).
- **No production source exists for the decision's `TagDigests`** (reconcile_decision.go:111,139).
  The only reader of the tag is `PinnedTagImageID`, which returns the image **Id**
  (runner/pinned_inspect.go:27-40). The conformance rig injects the tag digest directly
  (model_conformance_test.go `reconcileInputsAtCrash`, `in.TagDigests = []string{r.tag}`).
- No single-instance lock (no `flock` in the module), no metrics endpoint; the unit has `Wants=` (not `Requires=`)
  `docker.service` and `Restart=on-failure` (packaging/systemd/culvert-maint.service:46-47,58).
- Model: `restart_agent` = mark only (lifecyclemodel/model.go:258-261). Rollback stages never
  advance JR (model.go:405-440). 147 crash vectors (baseline.json `crash`). Properties: C1 PASS,
  **C2 FAIL** (trace ok,ok,skip,ok,ok_stale,crash), **O1 FAIL** (…,crash_after_tag,restart_agent),
  **O2 FAIL** (up_fail_stale, rollback skipped).
- The brief's "ADR-0057" is the MCP live-tier ADR; the crash-journal ADR is **0061**, with the design in
  roadmap/RISK-022-PR-E-reconcile-onstartup-design.md (v2, §0).

Verdict distribution over the 147 crash vectors (baseline.json, grouped by me):

| verdict | n | notes |
|---|---|---|
| noop/already_on_prior | 46 | |
| noop/safe_boundary_confirmed | 3 | |
| reup/tag_advanced_container_stale | 8 | |
| loud_stop/invalid_record_ref | 6 | all at safe phases |
| loud_stop/no_recovery_target | 2 | prior=down |
| verify_adopt/live_target | 46 | 28 with T running *during inline rollback*; 18 forward |
| verify_adopt/live_target_prior_equals_target | 36 | **all with running=P** (C2 class) |
| rollback_to_prior | **0** | reachable only in the abstract input space |

Coverage gaps: no crash vector exists at phase `verified`, in the Finish→Remove window, at
`pulled`, for `rollbacks.create`, or with Docker unreadable or running another image. The block
points skip `restart`/`report` plain crashes and skipped stages (lifecyclemodel/vectors.go:205-222),
and `ReconcileInputsForState` hard-codes `upgrades.apply` (lifecyclemodel/reconcile.go:48).

## 1. Failure matrix

Today's behaviour is the same for every row, so it is not repeated: mark-only, op `failed(agent_restart_interrupted)`,
one audit entry, `/v1/status interrupted_operations` with the live `running_image` class and
`pinned_tag.matches_running` (status/status.go:82-124). Docker is not touched.

Docker evidence available at startup, all through existing readers:
- **run**: container `.Image` id plus RepoDigests (runner/capture_running.go:91-114); its compose-ps error conflates
  "no container" with "daemon down". **tag**: the id of `culvert/proxy:pinned` (pinned_inspect.go).
- **local ids** of the validated TargetRef/PriorRef via `docker image inspect <ref>` (same runner method and sudoers
  line, templates_upgrade.go:354-369, sudoers:181). Proposed; not used today.

Journal fields: phase, refs and digests (re-validated, reconcile_validate.go:289-307), PriorImageID (trustworthy:
captured from the running container before the op), TargetImageID (trustworthy only at `verified`).

Proposed actions: `noop` (no Docker change), `realign` (retag only: `tag PriorRef culvert/proxy:pinned`, no restart),
`finish-rb` (tag already on prior: `up` → gate P → verify run==P), `adopt` (gate only, no mutation), `RR`
(recovery-required, no Docker change). [v2] needs owner decision D1(c); its v1 answer is RR.

| # | Crash window (vectors) | run / tag | Verdict today (line) | Proposed | Justification · residual risk |
|---|---|---|---|---|---|
| A1 | admitted, capture crash (4) | P or none / P | loud_stop invalid_record_ref (:128) | noop + report `unchanged` | No refs exist, and the fail-closed barrier means the tag never moved. No ref reaches Docker. · Risk: a forged safe-phase record hides nothing, because nothing acts. |
| A2 | captured, resolve crash (4) | P/P; nodigest or down | already_on_prior (:165) / invalid_record_ref (:128) | noop `unchanged` | Same as A1. Docker agrees. |
| A3 | resolved/pulled, pre_backup or pull crash (9); `pulled` has 0 vectors | P/P, none/P | already_on_prior (:165) / safe_boundary (:170) | noop. If tag == local id(TargetRef), the journal contradicts Docker: RR | An elided fsync is the only way a safe phase can coexist with an advanced tag (design §0 crash-F4). |
| A4 | restarting before tag, crash_after_barrier (6) | P/P; none/P (down) | already_on_prior; loud_stop no_recovery_target (:180) | noop; down stack → noop + `stack_down` (start nothing) | Docker equals the pre-op state. · Stack-down stays down, which is visible. |
| A5 | restarting after tag before up, crash_after_tag (6); also AGT-002 realign window (journal_phases.go:197-221) | P/T; none/T | **reup** (:160) | run==PriorImageID ∧ PriorRef valid → **realign** (prior is local because it is running). nodigest (no PriorRef) or none → RR | AGT-002 precedent: restore the tag when the container provably never moved. reup would start an image nobody gated, at boot, unwatched (ADR-0061:114-116). · Risk: the operator must resubmit the upgrade. |
| A6 | restarting after up, crash_after_up (6); also the up→capture→`restarted` gap | T/T, TID "" | live_target via digest fallback (:146,:193) | RR; [v2] adopt after a fresh gate | The target was never gated. Identity = run id == local id(TargetRef) ∧ RepoDigests ∋ TargetDigest (the verify-stage check, handlers_upgrade_apply.go:419). |
| A7 | restarted, health_gate or verify crash (10) | T/T, TID T | live_target (:150) | RR; [v2] adopt after a fresh gate | TID is not evidence (F1). The gate never passed. |
| A8 | restarted, ok_stale/F1 (C2) (8) | **P/T, TID=P** | **live_target_prior_equals_target → adopt P as the upgrade** (:147) | Treat TID as untrusted: TID==PriorImageID ∧ TargetDigest≠PriorDigest is ambiguous, so ignore TID. Then run==P ∧ tag==T → **realign** as A5 | Today's verdict is a false success and leaves the tag ahead (O1). · Fix F1 at the source too (§2 N1). |
| A9 | restarted, prior=down, ok_stale (2) | none/T, TID "" | reup (:160) | realign if PriorRef is valid and local, otherwise RR. Start nothing | |
| A10 | **verified**, crash before terminal (0 vectors) | T/T, TID T (digest-verified at :419) | live_target (:150) | **adopt** only if run==tag==local id(TargetRef) ∧ fresh probe ReadyOK. Otherwise RR | The journal is durable proof that the gate passed. The re-probe is needed because a reboot invalidates the pre-crash health. · Risk: UPG-901 says "healthy" is non-strict /ready. |
| A11 | terminal, not retired: Finish→Remove (orchestrator.go:157-165) (0 vectors) | success → as A10. Failed with rb ok → P/P. Failed with tag ahead (O2 shape) → P/T | live_target / already_on_prior / reup | as A10 / noop / realign-or-RR | The terminal audit is missing because audit runs after Remove (:167-183). Reconcile writes its own. |
| R1 | inline rb: rb_pull, rb_restart before tag (24) | T/T; P/T TID=P; P/P | live_target / prior_eq_target / already_on_prior | T/T → RR (the gate already failed, but the journal cannot show it); P/T → realign; P/P → noop. With the new `RollbackArmed` marker: T/T → finish-rb if prior is local | The journal loses the evidence that "T already failed its gate" (no rollback writes). Adopting T would reverse a decision the agent had already made. |
| R2 | inline rb: rb_restart after tag (12) | **T/P**; P/P TID=P | **live_target → adopt T** / prior_eq_target | T/P: by T2 (properties.json:160-163, only rb_restart moves the tag off target) the rollback was in progress → **finish-rb** (`up`, the tag is already P) → gate P → verify. Failure → RR. P/P → noop | The evidence is Docker identity plus the model invariant. No tag action is needed. · Risk: under ok_stale, `up` may not recreate. The verify catches it, and the attempt cap prevents a loop. |
| R3 | inline rb: rb_restart after up, rb_health, rb_verify (54) | P/P (TID P or T); T/P | already_on_prior / prior_eq_target / live_target | P/P → noop (not "adopt": P is the pre-op image). T/P → finish-rb as R2 | Today's prior_eq_target verdict would mark the *upgrade* succeeded while P runs. |
| S1 | rollbacks.create image, any crash (phase stays admitted; not modelled) | run≠tgt, tag≠tgt | safe_boundary (:170, phase-based and semantically wrong; interrupted.go:219-231 calls it indeterminate) | noop (Docker evidence only) | |
| S2 | same | tag==tgt, run≠tgt | reup (:160) | RR. After E2/P0-F: finish (operator intent) | No PriorRef to realign to, and no barrier. |
| S3 | same | run==tag==tgt | live_target (:150) | RR; [v2] adopt after a fresh gate | |
| D1 | rollbacks.create data | n/a | data_manual (:124) | unchanged: RR(data) and the existing `actionData` (interrupted.go:243-244) | Never touches Docker. |
| X1 | any; Docker unreadable (capture or tag error) | ? | not representable. A caller mapping error→"" falls to :177-180 | **defer**: no action, attempt not counted, status `deferred_docker_unavailable` | Design P1 D2. The unit only `Wants=` docker. |
| X2 | danger window; run = other image (operator change, stale record F2) | X/* | **rollback_to_prior** (:177) | RR | 0 crash vectors produce this. Only a foreign change does, so acting would override an operator. |
| X3 | tag = neither P nor T | */X | not representable (tag only intersected with target) | RR | |
| X4 | attempts ≥ cap | any | loud_stop exhausted (:132) | RR | Same as today. Needs a persisted counter (§3). |
| X5 | container present but not `running` (restarting or exited) | ? | capture does not read State (capture_running.go proxyContainerID) | count as live only when State==running, otherwise RR | |
| X6 | corrupt record | — | refuse to serve (main.go:205-208) | unchanged (ADR-0061 decision 2) | |

## 2. Where the table is not conservative enough, with the minimal tightening for each

- **N1 Adopt keyed on an unverified config id (C2/F1).** All 36 `prior_equals_target` vectors
  have running=P. Tightenings: (a) source: in restartWithBarrier, record `TargetImageID` only when
  the capture's RepoDigests contain `pinnedDigest` (journal_phases.go:147-149, as ADR-0061 F1
  recommends); (b) reconcile: take target identity from `docker image inspect <validated
  TargetRef>`.Id, and use the journal TID only at `verified`; (c) TID==PriorImageID with
  differing digests is ambiguous and is ignored (matches `ClassifyRunning`, interrupted.go:202-209).
- **N2 "Timeout while running==target adopts"** (reconcile_decision.go:40-43; design P1). A probe
  timeout is the *only* failure class (health.go:139-153), so this rule means "adopt on any
  failure". Tightening: adopt requires `ReadyOK`. Anything else is RR, and is never declared
  success.
- **N3 Adopting T during an inline rollback** (28 vectors). The decision cannot know the gate
  already failed. Tightening: a durable `RollbackArmed bool` (an optional record field, *not* a
  new phase, see D6), written fail-closed in `guardInlineRollback` before `rollback_restart` tags.
  Add the Docker rule tag==prior ∧ run==target ∧ phase≥restarting ⇒ rollback in progress. When
  `RollbackArmed` is set, T is never adopted.
- **N4 `reup` at boot** (8 vectors) starts an image that never passed the gate. Tightening:
  realign the tag to prior (retag only) when run==PriorImageID, otherwise RR. No `up` of an
  ungated target.
- **N5 `rollback_to_prior` on indeterminate running** (:177-179) acts exactly when evidence is
  weakest: an other image, a down stack, or a Docker read mapped to "". It may also need a pull.
  Tightening: RR. Docker unreadable → defer (X1).
- **N6 Tag axis.** Production has no `TagDigests`. A naive caller that passes nil makes
  `tagIsTarget` always false, so crash_after_tag (P/T) falls to `already_on_prior` → **noop with
  the tag ahead**. That is exactly the hole the comment at :152-159 warns about, and C1 would
  fail. Tightening: replace `TagDigests` with `TagImageID` (pinned_inspect.go) compared against
  local id(TargetRef) and PriorImageID.
- **N7 Digest fallback** (`sameImage` :193). Keep it only for the running axis, and only as an
  exact `TargetDigest ∈ RepoDigests` match, which is the evidence the online verify accepts
  (:419). Never use it to identify the tag, and never resolve a manifest or tag at boot (design
  P0-E). The extract/tag-scrape path (`extractDigests`) must never feed reconcile.
- **N8 Adopt with tag ≠ target** (36 adopt vectors have tag=P). The verdict ignores the tag.
  Tightening: adopt requires run==tag==target by id.
- **N9 Loosen (not a safety issue):** `invalid_record_ref` at a safe phase (6 vectors) becomes
  noop-report, because no ref reaches Docker. The ref gate stays mandatory before any action that
  passes a ref.

## 3. Implementation proposal (slice E3, gated; E1 tightenings first)

- **Switch.** Add `reconcile_on_startup = "off" | "converge" | "converge_adopt"` in config.toml,
  default `off`, which is today's behaviour bit for bit. `converge` = noop/realign/finish-rb/RR.
  `converge_adopt` adds A6/A7/S3 adopt. A10 adopt is in both, because it needs no mutation. It is
  startup-only, so record it as a GUI-parity deferral (conventions: startup-only exceptions).
- **Ordering** (main.go:148-176). Steps:
  1. `initJournal` runs unchanged, so marking still happens first and the AGT-004 report
     survives every outcome.
  2. Build the runner, status and server.
  3. If enabled and records exist: take `flock(<state_dir>/reconcile/.lock, LOCK_EX|LOCK_NB)`,
     opened `O_NOFOLLOW` (design §5; none exists today). If the lock is held, skip reconcile and
     report `skipped_second_instance`.
  4. Call `mgr.Begin("reconcile.startup", "agent:reconcile", …)` **before** `Serve`. The new kind
     goes into `stateChangingKinds` (ops.go:107-113). Operator state-changing commands then get
     409 naming the holder (AGT-001), while reads serve.
  5. Start the work through `s.goOp` only after the listener is bound (server.go:328-349 needs a
     bound-hook or ready channel). Reconcile never darkens the socket (P0-C).
- **Budgets.** One ctx: `context.WithTimeout(Background, reconcile_deadline)`, default 2 ×
  `stage_timeout` = 10m (config.go:157). It is detached from SIGTERM like ops
  (handlers_d16b.go:294-303) but drained by `drainOps` (server.go:274). Docker readiness: retry a
  read-only `compose ps` with backoff for ≤60s, else defer (X1). Health uses the configured probe
  (main.go:290-297) and only `ReadyOK` counts. On deadline: finish the current docker call, stop,
  and report `abandoned_deadline` as RR.
- **Per record, in order:**
  1. `validateReconcileRefs`.
  2. Read run, tag, local id(TargetRef) and local id(PriorRef). A typed `ErrNoProxyContainer`
     must be distinguished from a compose error (capture_running.go:91-100).
  3. Decide with the new pure `reconcileDecisionV2`.
  4. **Write-ahead:** persist `ReconcileAttempts++`, `LastReconcileAt` and `ReconcileDecision`
     fail-closed. If the write fails, do not act. These are new optional keys, ignored by older
     agents, following the journal.go:87-99 precedent.
  5. Re-read run and tag just before mutating (TOCTOU, design P2). If they changed, re-decide
     once, then RR.
  6. Act.
  7. Post-verify by id: realign/finish-rb require tag==run==PriorImageID; adopt requires
     run==tag==target and ReadyOK.
  8. Audit, then write `ReconcileOutcome`.
  - Cap `max_attempts` = 2, counted only when an action ran. A crash during reconcile re-decides
    from Docker truth next boot, so it is idempotent: realign and finish-rb converge.
- **Op state.** Never flip the interrupted op: it stays `failed(agent_restart_interrupted)` (terminal; P0-B). The
  `reconcile.startup` op carries `result.reconciled[] = {source_op_id, decision, reason, actions,
  outcome, run_class, tag_class}` and finishes `succeeded` only if every record converged or was
  noop. Any RR or deferred record makes it `failed(recovery_required)`, a new FailureReason.
- **Record retirement** (D4). Recommendation: remove the record only after a post-verified
  noop/realign/finish-rb/adopt, with an audit `<kind>:reconciled` entry written first (the
  journal_retire.go:316-330 ordering). Keep it on RR/defer, so it stays in status, AGT-005 still
  retires it on a later success, and an operator can see it.
- **Degraded surface.**
  - `/v1/status` gains `recovery_required` (bool) and `reconcile`
    `{state: disabled|in_progress|done|deferred|recovery_required|abandoned, op_id, started_at, finished_at, records[]}`.
  - Each `InterruptedOperation` gains `reconcile_outcome`. `docker_reconciled` becomes true only
    after post-verify. It is hard-coded false today (interrupted.go:93-96, AuditParams :163).
  - Audit: one event per acted-on record (actor `agent:reconcile`, ids/classes only, never raw
    inspect JSON).
  - Logs: `log.Printf` with the already-sanitized `DescribeInterrupted` fields only.
  - Metric: the agent has none. Raise `recovery_required` through the CP's fixed status subset
    (root maint_agent_status_api.go, ADR-0061 decision 4) and an alert. That is a root-module
    follow-up with its own `requireRole` and audit conventions.
  - CLI/UI: read-only. Operator steps reuse `operatorActionFor` (interrupted.go:241-276) with a
    reason-specific line: RR/target-ungated means "probe health, then POST /v1/rollbacks
    mode=image image_ref=prior_ref or resubmit"; tag-other or run-other means "compare
    `pinned_tag` with `running_image`; do not `docker compose up` by hand".
- **Privileged actions** (existing runner and sudoers only, no new line):
  - Reads: `compose ps` (sudoers:133); compose-cli `inspect-image` (:162,:186-208);
    `docker image inspect *` for the pinned tag and the validated refs (:181).
  - Mutations: compose-cli `tag <validated PriorRef> culvert/proxy:pinned`
    (ComposeTagPinned, templates_upgrade.go:307-319), only for realign; `docker compose -f …
    [-f override] up -d` (:174-175; ComposeUp templates_d16b.go:414), only for finish-rb, with
    the tag already on prior.
  - Never `pull` (a missing prior is RR), never `down`, never a TargetRef tag.

## 4. Verification plan

- **Model** (lifecyclemodel): replace the mark-only `restart_agent` step with a `reconcile` step
  driven by V2.
  - New events: docker_unreadable, probe_ok/probe_fail, retag_fail, up_fail, up_stale,
    crash_during_reconcile, re-restart.
  - New state fields: `rr`, `attempts`, `rb_armed`.
  - T4 becomes conditional on `off`.
  - O1 is reworded and promoted: `pc==recovered ⇒ ¬tag_ahead ∨ rr`.
  - C2 must PASS. It does once TID is ignored outside `verified`.
  - New properties:
    **R1** adopt ⇒ running==T ∧ tag==T ∧ serving_healthy ∧ ¬rb_armed. **R2** recovered ∧ ¬rr ⇒ tag==running ∈ {P,T}.
      **R3** no `up` unless the image under the tag is P, or T at `verified`. **R4** bounded: rr or converged within `cap`
      rounds, including crash-during-reconcile. **R5** idempotent. **R6** docker_unreadable ⇒ no mutation, attempts
      unchanged. **R7** a data rollback is never mutated.
  - Add vectors for the missing windows: `verified`, the Finish→Remove window (needs a
    journal-remove block hook in the rig), `pulled`, standalone `rollbacks.create`, other-image,
    tag-other and Docker-unreadable.
- **Conformance** (model_conformance_test.go). Today a crash point only computes the verdict
  (`reconcileInputsAtCrash` → `reconcileDecision`). Extend it: after the block, start a *second*
  real Server on the same state dir with `converge`, run the real startup reconcile against the
  fake world, and assert final (run, tag, record present/outcome, original op state, reconcile op
  state, audit kinds) against the model.
  - Extend the input space with TagImageID, RollbackArmed and DockerReadable axes; add RP8 (adopt ⇒
    live∧tag==target∧¬armed), RP9 (unreadable ⇒ no action), RP10 (ambiguous TID ⇒ not adopt).
  - Regenerate baseline.json/observed.json only through update-baseline.sh, and add mutants in
    lifecyclemutate for every new branch.
- **Process-level** (startup_crash_recovery_test.go). Keep every `killPoints` case
  (startup_crash_recovery_test.go:549-561) asserting zero mutating calls under `off`. Add an `on`
  variant per kill point asserting the exact mutating calls (`tag:P` only for A5; none for
  A6/A7 under converge), a kill *during* reconcile, a second instance (flock), and Docker
  unavailable → deferred.
- **Real Docker e2e** (extend .github/workflows/maint-agent-update-e2e.yml, which already has a
  TLS registry:2 and v1/v2 images). Use a PATH `docker` shim that delegates to real docker and
  blocks at a named argv (the startup-test technique), then SIGKILL. Kill points:
  - after `tag` before `up` (expect realign: tag id==v1 id, no recreate); after `up` (RR); after `verified` (adopt);
  - mid inline rollback with tag on v1 and container on v2 (needs a v2 build whose /ready
    returns 503; expect finish-rb then v1 healthy);
  - `systemctl restart docker` race at agent start (expect deferred);
  - **F1/C2 on real Docker**: a compose override pinning another image, so `up` does not run the
    target (expect no adopt; realign).
  - Assert by image **id** (`docker inspect -f {{.Image}}` and `docker image inspect
    culvert/proxy:pinned -f {{.Id}}`), op/status JSON and audit lines.
  - Run once with the containerd image store (U3).

## 5. Contract impact and owner decisions

**Contracts.** AGT-900 changes from open to enforced, with tests from §4. Proposed wording: "After
a crash during an image change, the next start either leaves tag and container on the same image
it can identify as the pre-change image (or a re-gated target), or reports recovery_required and
changes nothing." Other registry and record impacts:
- **AGT-004 needs an `amended` record.** Its forbidden "tagging or recreating containers at
  startup" and "removing a journal record at startup" become true only for `off`.
- AGT-005 is amended if D4 retires records at reconcile.
- AGT-001 gains the `reconcile.startup` holder.
- AGT-002 is unchanged and gets reused.
- UPG-901 (open) gates what adopt means.
- Model T4 is amended and O1 is promoted.
- A new ADR supersedes ADR-0061's "never act".

| # | Decision | Options | Recommendation |
|---|---|---|---|
| D1 | v1 scope | (a) report only (today); (b) converge: noop/realign/finish-rb/RR plus A10 adopt; (c) + adopt of ungated live target after a fresh gate; (d) + automatic rollback with restart on an unhealthy target | **(b)**. (c) after a field bake. (d) not without E2 local-first and P0-F barriers |
| D2 | default | off / on | **off** in v1 (design §0 posture). Flip after real-Docker T3 plus bake |
| D3 | target unhealthy or unverified at boot | RR / auto-rollback | **RR**. The probe cannot tell slow from bad (N2) |
| D4 | retire record after a verified reconcile | keep until a later op (AGT-005) / retire with audit | **retire with audit**, only after post-verify. Keep on RR |
| D5 | state of the original op | flip to succeeded(reconciled) / keep failed plus a separate reconcile op | **keep failed** plus the `reconcile.startup` op (one source of truth) |
| D6 | rollback evidence | new phase (an older agent refuses to serve on an unknown phase, journal.go:190) / optional `RollbackArmed` field | **optional field** (downgrade-safe) |
| D7 | single instance and docker dependency | flock; `Requires=docker.service` | flock **yes**. Keep `Wants=` plus the readiness probe and defer |
| D8 | F1 fix owner | apply restart stage (journal_phases.go:147) | land before E3 as part of E1 |

**Uncertainty to flag.**
- **U1.** The `verified`, Finish→Remove, `pulled` and `rollbacks.create` rows come from code reading, not vectors.
- **U2.** `ok_stale` was not observed on Docker 29.10 (model.go:13-16); F1 is reachable by a compose override.
- **U3 (resolved by real-Docker measurement, PR #2030).** On the containerd image store (Docker 29
  default) container `.Image` is the registry index digest and every local tag adds a synthetic
  `<repo>@sha256` RepoDigest; on the classic store `.Image` is the config digest. Running all 147 crash
  and 172 apply vectors under both identity modes gives no model mismatch, so id-to-id comparison within
  one store holds. The "config digest" wording in the agent's comments is classic-store only; N7's digest
  fallback must not treat a synthetic local RepoDigest as registry evidence.
- **U4.** Whether `compose ps --format json` lists non-running containers depends on the Compose version (X5).
