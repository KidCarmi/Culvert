# MCP Canary-Readiness — Prerequisite & Reachability Matrix

**Phase:** Culvert MCP — Canary Architecture & Readiness
**Baseline:** `main` after PR #1248 (Shadow Exit Review PASSED; `PREREQ-MCP-KILL-1` CLOSED).
Branch `claude/mcp-canary-architecture`.
**Status of this document:** GROUND TRUTH for the Canary phase. Every prerequisite is an
individually machine-verifiable fact (`internal/mcp/canary`); "Ready" is true only when the
Unmet set is empty. Canary is architecturally defined and **NOT activatable** in this build.

## The one fact that drives the phase

**Canary is dormant by construction.** The live-execution tier is never armed
(`liveExecDepsConfigured==false`; `mcp_execution_posture_test.go`), `live_execution` approvals
are unissuable (`tooltrust.Purpose.Issuable()`), and `canary.Evaluate` therefore always returns
NOT-READY with at least `live_executor_absent`. There is no code path — API, envelope, or
restart — that makes a real MCP upstream side effect reachable.

```
Canary architecture defined         YES
Canary readiness machine-verifiable YES
Live execution production-armed      NO
Canary active                        NO
Production active                    NO
Real upstream side effect            NO
Production credential retrieved      NO
```

## Readiness contract (`internal/mcp/canary`)

Each row is a `canary.Facts` field → `canary.Reason`. A false fact adds its named reason;
`Ready` is true only when Unmet is empty. Distinct from Shadow readiness (Shadow *refuses* a
live tier; Canary *requires* it).

| # | Prerequisite (fact) | Reason when unmet | Source of truth today | Value now |
|---|---|---|---|---|
| 1 | Capability is Gateway | `capability_not_gateway` | request capability | Gateway ✓ |
| 2 | Shadow Exit Review attested | `shadow_exit_review_not_passed` | `shadowExitReviewAttested()` (no runtime surface) | **NO** |
| 3 | Scope bounded/enumerable/exact | `canary_scope_not_bounded` | `canary.ValidateScope` | activation input |
| 4 | Scope read-first only | `canary_scope_not_read_first` | `canary.ScopeReadFirst` | activation input |
| 5 | Live executor composed | `live_executor_absent` | `liveExecDepsConfigured` | **NO (dormant)** |
| 6 | Authoritative UpstreamCaller | `upstream_caller_absent` | live tier | **NO** |
| 7 | Credential path ready | `credential_path_not_ready` | live tier | **NO** |
| 8 | Durable events healthy | `durable_events_degraded` | `durableEventsHealthy()` — domain CriticalState=="normal" | node-dependent |
| 9 | Response inspection ready | `response_inspection_not_ready` | `globalMCPShadow.inspectionComposed` | node-dependent |
| 10 | Registry healthy | `registry_unhealthy` | `mcpInventory.sharedInventory()` | node-dependent |
| 11 | Catalog healthy | `catalog_unhealthy` | `mcpInventory.sharedInventory()` | node-dependent |
| 12 | Policy healthy | `policy_unhealthy` | `mcpPolicy.composed()` | node-dependent |
| 13 | Emergency kill clear | `emergency_kill_active` | `State.Killed()` | node-dependent |
| 14 | Kill-generation boundary guard | `kill_boundary_guard_absent` | live tier (PREREQ-MCP-KILL-1) | **NO** |
| 15 | Tool-freshness boundary guard | `tool_freshness_guard_absent` | live tier | **NO** |
| 16 | Exact live_execution approval (PER SCOPED TOOL) | `live_execution_approval_invalid` | `canary.ValidateScopeApprovals` (→ per-tool `SatisfiesLiveExecution`) | **unissuable** |
| 17 | Server usable | `server_not_usable` | registry/catalog | activation input |
| 18 | Tool fingerprint current | `tool_fingerprint_stale` | catalog | activation input |
| 19 | Rollback path healthy | `rollback_path_unhealthy` | `rollbackPathHealthy` — durable persist not degraded/write_failed AND rollback rehearsed | **NO (unrehearsed)** |
| 20 | Budget configured | `canary_budget_not_configured` | `canary.ValidateBudget` | activation input |

Live-tier facts (5, 6, 7, 14, 15) are all false together in this build (the guarded live
executor — whose boundary guards are pinned by `internal/mcp/execution`'s PREREQ-MCP-KILL-1
tests — composes as one unit and is never composed).

**Node vs activation readiness (two evaluators).** Rows 3, 4, 16, 17, 18, 20 (scope bounded,
scope read-first, live approval, server usable, tool fingerprint, budget) are **activation-
level**: they are meaningful only once an operator supplies a concrete scope, approval, and
budget. Every other row is **node-level**. `canary.EvaluateNode` (the `node_ready` dry run at
`GET /api/mcp/rollout` → `canary`) evaluates ONLY node-level rows, so a node that has satisfied
every node prerequisite reports `node_ready` true even before a scope is chosen, instead of
being permanently not-ready because the six activation facts default false. `canary.Evaluate`
(the full verdict, driven by `evaluateCanaryActivationPreflight` once a scope/approval/budget
exist) checks both. Pinned by `TestEvaluateNode_ExcludesActivationInputs` (Codex P2, PR #1249).

## Live-execution trust firewall (`tooltrust` + `canary.SatisfiesLiveExecution`)

| Property | Requirement | Gate |
|---|---|---|
| purpose | `live_execution` ONLY (shadow_evaluation NEVER qualifies) | `TestSatisfiesLiveExecution_ShadowApprovalNeverQualifies` |
| disjointness | no purpose permits both shadow + live | `Purpose.PermitsLiveExecution/PermitsShadowEvaluation` |
| status | active | `TestSatisfiesLiveExecution_Rejections` |
| target binding | exact tenant+server+tool+fingerprint+format (rug-pull) | same |
| expiry | present, unelapsed, ≤ 24h measured from a real, non-future approval instant | same + `TestSatisfiesLiveExecution_Rejections/{approved_in_future,approved_zero}` |
| four-eyes | distinct present requester + approver | same |
| per-(tenant,tool) coverage | EVERY admitted (tenant × tool) has its OWN approval bound to that exact tenant+tool+fingerprint; no unconstrained target; no approval outside scope (a t2 approval never covers a t1 scope) | `canary.ValidateScopeApprovals` (`approval_test.go`) |
| issuance | refused fail-closed in this build | `tooltrust.Purpose.Issuable()` |

### Read-first is TWO gates, not one (§5)

`ScopeReadFirst` (over `rollout.RiskClass`) is **necessary but not sufficient**: the four
RiskClass buckets cannot separate a control-plane operation from a read — the root `mapRisk`
folds `policy.OpControl` **and** `OpDiscovery` into `RiskRead`. The authoritative per-request
gate is `canary.IsReadFirstOperation(policy.OperationClass)`, which admits ONLY `OpRead` and
`OpDiscovery` and rejects `OpControl`/`OpWrite`/`OpDestructive`/`OpUnset`. A live executor must
enforce **both**: the scope bounds *which tools*, `IsReadFirstOperation` bounds *which operation*
as the policy engine actually classified it. Pinned by `operation_test.go`.

## First-Canary bounds (structurally incapable of fleet-wide)

| Bound | Value | Constant |
|---|---|---|
| max servers | 1 | `MaxCanaryServers` |
| max tools | 2 | `MaxCanaryTools` |
| max principals | 2 | `MaxCanaryPrincipals` |
| max tenants | 1 (concrete, required) | `MaxCanaryTenants` |
| max total executions ceiling | 1000 | `FirstCanaryMaxTotalCeiling` |
| max window ceiling | 7 days | `FirstCanaryMaxWindowCeiling` |
| max approval TTL | 24 hours | `MaxInitialCanaryApprovalTTL` |
| operation classes (scope axis) | read/discovery only | `ScopeReadFirst` |
| operation classes (per-request) | OpRead / OpDiscovery only (OpControl excluded) | `IsReadFirstOperation` |
| identity | ≥1 EXACT principal/client/agent; groups forbidden | `ScopeNoIdentity` / `ScopeUsesGroups` |

## Automatic-abort taxonomy (§16)

**Whole-Canary breach (single occurrence stops the Canary):** out_of_scope_execution,
scope_escape, tool_fingerprint_drift, server_identity_drift, outcome_evidence_loss,
credential_safety_failure, budget_exhausted, elevated_error_rate, latency_pathology,
unexpected_upstream_response.

**Per-request fail-closed (Canary survives):** policy_deny, stale_decision,
credential_not_ready, response_inspection_block, emergency_kill_for_request, allowance_consumed.

## What is already true and load-bearing (reused, not rebuilt)

- **Differential equivalence Shadow ↔ live** across all decision classes over a synthetic
  upstream: `TestShadow_LivePreSideEffectEquivalence` (execution).
- **Kill-generation + tool-freshness boundary guards** at the irreversible boundary:
  PREREQ-MCP-KILL-1 gates (execution).
- **Evidence-before-side-effect, credential Plan/gate/Materialize/zeroize, upstream
  pinning/SSRF/redirect/bounds/timeout**: existing `internal/mcp/{execution,credentials,
  upstreamclient}` with their tests.
- **Out-of-scope non-execution**: `TestAntiWeakening_OutOfScopeDoesNotExecute` (execution).
- **ShadowEvaluator holds no execute capability** even with Canary code present:
  `TestShadow_TypeGraphHasNoExecuteCapability`; canary package holds none:
  `TestCanaryPackageHoldsNoExecutionCapability`.

## What must become true before the first Canary (the prerequisite gap)

Every one is a **separately-reviewed activation**, not a config change:

1. Arm the live tier (compose a live `execution.Executor` + UpstreamCaller + materialize-broker;
   call `markGatewayExecDepsReady`) — **edits the execution-posture wall**.
2. Make `live_execution` issuable under stronger governance (four-eyes, short TTL) — edits
   `tooltrust.Purpose.Issuable()` and the issue path.
3. Wire the Canary preflight as the primary activation gate and enforce the budget at runtime.
4. Provide the Shadow-Exit attestation surface (`shadowExitReviewAttested`).
5. Execute the first Canary per `CANARY-FIRST-RUNBOOK.md` (synthetic identity, recording
   upstream, never customer traffic).
</content>
