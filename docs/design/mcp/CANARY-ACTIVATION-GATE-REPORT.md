# MCP Canary Activation Gate & Runtime Budget — Security Posture Report

**Phase:** Culvert MCP — Canary Activation Gate & Runtime Budget
**Baseline:** `main` after PR #1249 (Canary architecture & readiness).
**Status:** Control-plane/runtime safety gates implemented and **dormant by construction**. The
execution posture remains CLOSED — no engine capable of changing the outside world is composed.

**Overall verdict: CANARY ACTIVATION GATE INCOMPLETE — AUTHORITATIVE ROLLBACK REHEARSAL REMAINS.**
The executable rollback rehearsal proves rollback *mechanics* (a real persist/restore round-trip)
but does NOT traverse the authoritative `commitRolloutTransitionAt` coordinator, so it does not prove
parity with that coordinator's Shadow preflight, emergency-kill, revision, durability, and rollback
guards. That authoritative rehearsal is tracked as an OPEN, machine-visible HARD Canary-activation
prerequisite — **`CANARY-ROLLBACK-COORDINATOR-REHEARSAL`** (readiness reason
`rollback_coordinator_rehearsal_pending`) — which keeps Canary readiness FALSE regardless of the
mechanics rehearsal, and is deferred to a dedicated follow-up (owner decision: no coordinator redesign
in this PR, and the readiness criterion is NOT weakened). See "What still gates the first real Canary".

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
`markGatewayExecDepsReady`), making `live_execution` issuable under four-eyes governance, calling
`beginCanaryActivation` from that armed path, and executing the first Canary per
`CANARY-FIRST-RUNBOOK.md` — each a **separately-reviewed activation**, none performed here.

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

**Status:** the mechanics rehearsal is preserved and described as mechanics evidence only; the
authoritative rehearsal is **not** claimed. This item is deferred to a dedicated follow-up by owner
decision — the coordinator is NOT refactored in this PR and the readiness criterion is NOT weakened.
The follow-up must: refactor the coordinator into a locked, side-effect-injectable core; route a
scratch rehearsal through the same authoritative `commitRolloutTransitionAt` gates with an injected
persistence destination; make the rehearsal FAIL whenever the real rollback would fail; avoid live
rollout-state mutation; and add parity + mutation proofs. Until then the overall Canary Activation
Gate is **INCOMPLETE — AUTHORITATIVE ROLLBACK REHEARSAL REMAINS**.
