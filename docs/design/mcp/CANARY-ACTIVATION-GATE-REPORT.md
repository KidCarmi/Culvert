# MCP Canary Activation Gate & Runtime Budget — Security Posture Report

**Phase:** Culvert MCP — Canary Activation Gate & Runtime Budget
**Baseline:** `main` after PR #1249 (Canary architecture & readiness).
**Status:** Control-plane/runtime safety gates implemented and **dormant by construction**. The
execution posture remains CLOSED — no engine capable of changing the outside world is composed.

**Overall verdict (as of PR #1252): CANARY ACTIVATION GATE INCOMPLETE — AUTHORITATIVE ROLLBACK
REHEARSAL REMAINS.** PR #1252 recorded `CANARY-ROLLBACK-COORDINATOR-REHEARSAL` as an OPEN,
machine-visible HARD prerequisite (`rollback_coordinator_rehearsal_pending`).

**Follow-up landed (the authoritative rollback rehearsal PR):** the rollout coordinator is now
extracted into a single locked core (`commitRolloutTransitionCore`) that every production transition
AND the rehearsal share, and the authoritative rehearsal drives Canary→Shadow→Observe through that core
on a SCRATCH state/file (never live state), recovers to Observe, and records DISTINCT durable
build-bound evidence. So the rehearsal fails for every security reason a real rollback would fail
(Shadow preflight, emergency kill, config validity, durability) — proven by a parity wall (production
and rehearsal reach identical verdicts), a routing-is-load-bearing control, a mutation campaign, and
durable-evidence/concurrency tests. `productionCoordinatorRollbackRehearsed` reads that evidence, so
row 20 is now CLOSABLE: it closes for a build once a coordinator-routed drill succeeds (via
`POST /api/mcp/rollout/rehearse-rollback-authoritative`). The mechanics fact (row 19) and this fact
stay DISTINCT. In the shipped build the drill still requires the full shadow tier, so row 20 stays open
by default — which correctly reflects that such a node cannot yet perform a real Canary→Shadow rollback.

## The core invariant this phase satisfies

> Before Culvert is given an engine capable of changing the outside world, the system must already
> know exactly *when* that engine is allowed to start, exactly *how much* it may do, and exactly
> *how to stop it*.

- **When it may start** — §1 Shadow Exit attestation (durable, build-bound, admin-created) + §2
  authoritative Canary preflight (the single shared commit path, from authoritative state).
- **How much it may do** — §3 generation-bound runtime budget (exact-N, monotonic, concurrency +
  rate + window), fail-closed before the side-effect boundary.
- **How to stop it** — §4 whole-Canary abort controller (monotonic, per-generation) + §5 executable
  rollback rehearsal (a real demotion drill through the durable persist/restore path — rollback
  **mechanics** evidence). The *authoritative* rollback path (routed through
  `commitRolloutTransitionAt`) is NOT yet rehearsed and remains an open hard prerequisite
  (`CANARY-ROLLBACK-COORDINATOR-REHEARSAL`).

## Posture (required report)

| Fact | Value |
|---|---|
| Shadow Exit attestation implemented | **YES** |
| Canary authoritative preflight | **YES** |
| Runtime budget enforcement | **YES** |
| Whole-Canary abort controller | **YES** |
| Rollback rehearsal executable (persist/restore **mechanics**) | **YES** |
| Authoritative rollback rehearsal (through `commitRolloutTransitionAt`) | **NO — OPEN prerequisite `CANARY-ROLLBACK-COORDINATOR-REHEARSAL`** |
| Production LiveExecutor composed | **NO** |
| `markGatewayExecDepsReady` called | **NO** |
| `live_execution` approval issuable | **NO** |
| Canary enabled | **NO** |
| Production enabled | **NO** |
| Real upstream side effects | **NO** |
| Production credentials retrieved | **NO** |

## Where each gate lives

| Gate | Pure engine (`internal/mcp/canary`) | Root wiring | Durable state |
|---|---|---|---|
| §1 Shadow Exit attestation | `attestation.go` (`ShadowExitAttestation`, `ValidateAttestation`) | `mcp_canary_attestation.go`, `apiMCPShadowExitReview` | `dataDir/mcp_shadow_exit_review.json` |
| §2 Authoritative preflight | `readiness.go` (`Evaluate`/`EvaluateNode`) | `commitRolloutTransitionAt` gate + `restore()` clamp | — |
| §3 Runtime budget | `budget_enforce.go` (`BudgetEnforcer`) | `mcp_canary_runtime.go` (`reserveCanaryExecution`) | `dataDir/mcp_canary_runtime_*.json` |
| §4 Abort controller | `abort_control.go` (`AbortController`) | `mcp_canary_runtime.go` (`tripCanaryAbort`) | same runtime file |
| §5 Rollback rehearsal | `rehearsal.go` (`RollbackRehearsalRecord`) | `mcp_canary_rollback_rehearsal.go` (real drill) | `dataDir/mcp_rollback_rehearsal_*.json` |

## Fail-closed guarantees (verified)

- **One false prerequisite ⇒ NOT READY.** Every `canary.Reason` is independently load-bearing;
  the shipped build reports 13 unmet node prerequisites (including
  `rollback_coordinator_rehearsal_pending`) and is never Ready
  (`TestCanaryMatrix_*`, `TestEvaluate_EachFactIsIndependentlyLoadBearing`).
- **No activation bypass.** API, CP→DP snapshot, startup reconcile, and restart/restore all fail
  closed for a live-execution mode (`TestCanaryCommitGate_*`, `TestCanaryMutation3_*`, restore clamp).
- **Budget exactness under concurrency.** Exactly `MaxTotalExecutions` grants, no off-by-one, no
  replay, atomic under a 50-way race (`TestBudgetEnforcer_*`).
- **Abort is monotonic and per-generation.** A single whole-Canary breach stops execution
  permanently for its generation; per-request codes never latch; an abort survives a restart
  (`TestAbortController_*`, `TestCanaryRuntime_RestartPreservesAbortLatch`).
- **Rollback MECHANICS proven, not asserted; authoritative path NOT yet proven.** The self-attested
  marker no longer satisfies readiness — only a build-bound executed persist/restore drill does
  (`TestCanaryMutation9_*`, `TestRollbackRehearsal_*`). That drill is **mechanics evidence only**: it
  does not traverse `commitRolloutTransitionAt`, so a separate hard prerequisite
  (`rollback_coordinator_rehearsal_pending`) keeps readiness FALSE and no transition can become READY
  on the mechanics rehearsal alone
  (`TestCanaryRollbackCoordinatorRehearsal_OpenPrerequisiteBlocksReadiness`,
  `TestCanaryRollbackCoordinatorRehearsal_ProductionFailsClosed`).
- **Restart & generation integrity.** Budget spend and abort survive a restart; a build change
  disarms; a demotion invalidates the old generation; a stale-generation snapshot never resurrects
  (`TestCanaryRuntime_*`).

## Red-team coverage (mutation campaign)

Ten mutations, each caught by a named gate — see `mcp_canary_matrix_mutation_test.go`
(`TestCanaryMutationCampaign_Roster`): allow Canary without attestation; bypass the preflight via
CP→DP; bypass on restart/restore; permit the N+1 budget execution; race the budget counters; clear
the whole-Canary abort automatically; treat a per-request policy deny as a whole-Canary abort;
accept a corrupt/stale Exit attestation; accept a self-attested rollback without a drill; reuse an
old budget/abort generation after reactivation.

## What still gates the first real Canary (out of scope here)

Arming the live tier (compose a live executor + upstream + materialize-broker, call
`markGatewayExecDepsReady`), calling `beginCanaryActivation` from that armed path, and executing
the first Canary per `CANARY-FIRST-RUNBOOK.md` — each a **separately-reviewed activation**, none
performed here. (Making `live_execution` issuable under four-eyes governance has since landed as a
trust-only slice — ADR-0034 Addendum 2026-09 — and does not arm the live tier or change this
report's posture: LiveExecutor composed NO, Canary active NO.)

> **UPDATE (live-tier composition phase): `CANARY-ROLLBACK-LIVE-QUIESCE-REHEARSAL` is CLOSED.** The
> live tier now exists (composed behind a disabled-by-default, node-readiness-gated arming lifecycle),
> so the live-armed **quiesce-then-demote** sequence is rehearsable and is rehearsed end to end by
> `TestLiveQuiesceRehearsal_FullSequence` (`mcp_live_quiesce_rehearsal_test.go`): arm → drive
> controlled synthetic executions → QUIESCE (un-arm, reject new, drain in-flight — live now OFF) →
> emergency kill terminates the side-effect window → the authoritative coordinator `Canary→Observe`
> demotion invalidates the generation → persist/recover proving a restart does not re-arm → live trust
> is not resurrected. It records durable, build-bound evidence (`mcp_live_quiesce_rehearsal.go`,
> `liveQuiesceRehearsed`), fail-closed against a build change or corruption. The report's dormancy
> posture is UNCHANGED: composition is disabled-by-default with no production caller, arming is a
> separate explicit act, and no Canary is activated — LiveExecutor production-composed NO, Canary
> active NO. The original deferral rationale, retained below for provenance:

**Deferred to the live-tier phase — `CANARY-ROLLBACK-LIVE-QUIESCE-REHEARSAL`.** The shared Shadow
preflight forbids a Shadow target while the live-execution tier is armed
(`shadowPFLiveRequirement`/`forbidden_live_execution_requirement`, `mcp_shadow_preflight.go`). This is
the SAME gate for the production coordinator's real `Canary→Shadow` demotion AND the rehearsal drill, so
both are rejected identically when the live tier is armed — proven by
`TestCoordinatorRehearsal_LiveArmedRejectsBothPathsIdentically`, which is why the rehearsal can never
record a row-20 PASS in a posture where the real demotion would be refused. It follows that a real
`Canary→Shadow` rollback must QUIESCE the live tier before the demotion (demote with live off), and the
rehearsal legitimately runs with the live tier off, modeling that post-quiesce demotion. In the shipped
build the live tier is NEVER armed, so no real `Canary→Shadow` rollback occurs and row 20 cannot
mis-certify one. Faithfully rehearsing the live-armed **quiesce-then-demote** sequence (and coupling row
20 to that posture) requires the live tier itself to exist and is therefore a HARD prerequisite for the
live-tier phase, NOT closable here (§9 forbids composing the live tier in this PR). A naive "fail row 20
when the live tier is armed" read-guard is deliberately NOT added: Canary activation itself requires the
live tier armed, so such a guard would deadlock every activation — the live-armed rehearsal is the
correct home for this, not a read-time gate.

### OPEN hard prerequisite — `CANARY-ROLLBACK-COORDINATOR-REHEARSAL`

The current rollback rehearsal drives the scratch demotion ladder directly through
`State.SetConfig` + `persistRolloutStateTo`, proving persist/restore **mechanics**. It does NOT go
through the authoritative `commitRolloutTransitionAt` coordinator, so it does not prove parity with
that coordinator's Shadow preflight, emergency-kill, revision, durability, and rollback guards — e.g.
with the live tier armed and an active emergency kill, the real `Canary→Shadow` demotion is refused
by the shared Shadow preflight while the current mechanics drill would still succeed. Readiness
therefore carries a distinct, machine-visible reason `rollback_coordinator_rehearsal_pending`
(fail-closed by construction: `productionCoordinatorRollbackRehearsed` always returns false), so a
node whose mechanics rehearsal passed is still NOT Canary-ready.

**Status (updated): the follow-up landed.** The coordinator is extracted into a single locked core
(`commitRolloutTransitionCore`) that every production transition AND the rehearsal share; the
rehearsal drives the scratch demotion ladder through that core with an injected scratch persistence
destination, never mutates live rollout state, recovers to Observe, and records DISTINCT durable
build-bound evidence. The rehearsal FAILS whenever the real rollback would (Shadow preflight, emergency
kill, config validity, durability) — pinned by a parity wall (`TestCoordinatorRehearsalParity_*`), a
routing-is-load-bearing control, a mutation campaign, and durable-evidence + concurrency tests.
`productionCoordinatorRollbackRehearsed` now reads that evidence, so row 20 CLOSES for a build once a
coordinator-routed drill succeeds (`POST /api/mcp/rollout/rehearse-rollback-authoritative`). Fail-closed
on FRESH negative evidence: a later rehearsal that fails (drill or evidence-write) durably invalidates any
earlier PASS for the build, so a node whose most recent authoritative rehearsal failed can never activate
Canary on stale evidence (`TestCoordinatorRehearsal_FailedAttemptInvalidatesPriorPass`). When the same
fault (e.g. a read-only volume) also blocks that durable invalidation, an in-memory poison latch keeps row
20 closed against the still-readable record until a successful re-run supersedes it — parity with the
mechanics path's `write_failed` blocker, lost on restart (a documented residual still gated by the
durability-health prerequisites; `TestCoordinatorRehearsal_InvalidationFailurePoisonsRow20`). The
mechanics fact (row 19) stays distinct. Production transition semantics are byte-identical (the wrapper
just delegates to the shared core). The rehearsal's Shadow config is genuinely Shadow-ELIGIBLE: its scope
admits the WRITE risk class (tools/call is write-class, so the coordinator's usable-tool gate —
`shadowScopeHasUsableTool` → `Scope.AdmitsToolForEvaluation` — requires it), so the SOLE remaining
blocker once tools become Usable is the tool-approval slice, not a structurally read-only scope
(`TestCoordinatorRehearsal_ShadowScopeAdmitsWriteClassTool`). The shipped default therefore keeps row 20
open for exactly ONE reason — the unshipped tool-approval slice makes no catalog tool Usable, so the real
usable-tool probe yields `no_usable_shadow_tools` — which is the correct posture: such a node cannot yet
perform a real `Canary→Shadow` rollback. Once that slice ships, the coordinator-routed drill can actually
close row 20 (it is not permanently blocked by the rehearsal config).
