# ADR-0035: MCP Canary Execution Architecture & Activation Prerequisites

- **Status:** Accepted (architecture only — Canary is NOT activatable)
- **Date:** 2026-08-29
- **Supersedes / relates to:** ADR-0024 (MCP Agent Security Gateway trust boundary),
  ADR-0034 (MCP tool-trust approval), PREREQ-MCP-KILL-1 (kill-boundary revalidation, PR #1248),
  `docs/design/mcp/ROLLOUT-AND-ROLLBACK.md` (mode ladder + Canary governance),
  `docs/design/mcp/SHADOW-ARCHITECTURE.md` (Shadow Exit Review).

## Context

The full 13-criterion Shadow Exit Review has passed (PR #1248 closed the last prerequisite,
`PREREQ-MCP-KILL-1`). Culvert may now *design* the Canary phase — the first time it will cause
a real, irreversible MCP upstream side effect. Shadow proved Culvert can *predict* enforcement
safely; Canary is where prediction becomes reality. The architecture must make that first real
side effect **smaller, more observable, more reversible, and harder to reach** than any normal
execution that will ever exist later.

This ADR defines the machine-verifiable readiness contract and the activation prerequisites.
It does **not** activate Canary, and the code it introduces is **dormant by construction**.

### Current posture (re-derived from `main`, independently re-read)

| Fact | Value | Evidence |
|---|---|---|
| production LiveExecutor composed | **NO** | `mcp_execution_posture_test.go` (4 AST gates); `execution.New` has no production caller |
| `markGatewayExecDepsReady` production caller | **NO** | `TestExecPosture_LiveArmingHooksHaveNoProductionCaller`; `liveExecDepsConfigured==false` |
| `live_execution` ToolApproval issuable | **NO** | `tooltrust.Purpose.Issuable()` (shadow only); `CreateRequest`+`Approve` refuse fail-closed |
| Canary activation reachable | **NO** | `modeExecReady` gates Canary/Production on the unarmed live tier |

## Decision

Introduce a pure, I/O-free **`internal/mcp/canary`** readiness engine plus a root
composition-layer preflight (`mcp_canary_preflight.go`), and extend the tool-trust firewall
with the live-execution positive half. Everything is dormant: in the shipped build the live
tier is never armed, so Canary readiness always evaluates NOT-READY with `live_executor_absent`,
and the preflight always fails closed.

### 1. Readiness is a machine-verifiable fact set, not a boolean (§2)

`canary.Facts` enumerates every prerequisite as an individually-observable positive assertion;
`canary.Evaluate(Facts) → Readiness{Ready, Unmet[]}` returns `Ready` only when the `Unmet`
reason set is empty. There is no `canaryReady=true` blob — a missing fact names itself with a
stable classified `Reason`. The 20-reason vocabulary is pinned to the Facts fields
(`TestEvaluate_EachFactIsIndependentlyLoadBearing`, `TestEvaluate_ReasonVocabularyParity`), so
no prerequisite can be silently dropped and no reason orphaned.

Canary readiness is **strictly stronger and separate** from Shadow readiness: Shadow *refuses*
a live tier; Canary *requires* it, plus a bounded read-first enumerable scope, an exact
live-execution trust approval, a blast-radius budget, and the emergency-stop invariants.

### 2. Live-execution trust firewall (§3)

`tooltrust.Purpose` already defines `shadow_evaluation` and `live_execution` with `Issuable()`
refusing the latter. This ADR adds the symmetric `Purpose.PermitsLiveExecution()` (true only
for `live_execution`), making the firewall a compile-checkable predicate: the two purposes are
disjoint, so **no approval satisfies both** — a `shadow_evaluation` approval can never authorize
a real side effect (`TestSatisfiesLiveExecution_ShadowApprovalNeverQualifies`).

`canary.SatisfiesLiveExecution(approval, target, now)` is the consumption predicate. It requires,
fail-closed: `purpose==live_execution`, `status==active`, exact current-target binding
(tenant+server+tool+fingerprint+format — the rug-pull invariant), a present, unelapsed expiry no
longer than `MaxInitialCanaryApprovalTTL` (24h) measured from the approval instant, and
**four-eyes** (distinct present requester and approver — separation of duties). Issuance stays
refused in this build; this predicate is what a future, separately-reviewed live phase's issue
path must satisfy.

### 3. Bounded, read-first Canary scope (§4/§5)

`canary.ValidateScope` requires the scope be Gateway-only, enumerable (a percentage-only scope
is rejected — "1% of everything cannot enter Canary"), bind **exact** servers and tools each
with a pinned fingerprint (no wildcard-future-tools), stay within tiny first-Canary caps
(`MaxCanaryServers=1`, `MaxCanaryTools=2`, `MaxCanaryPrincipals=2` — structurally incapable of
fleet-wide), and be **read-first** (`Operations ⊆ {read}`, `!HighRisk`). The authority for
read-first is Culvert's own `rollout.RiskClass` classification (derived by the policy engine),
**never** the server-provided MCP `readOnlyHint`. Graduation
(read/discovery → bounded write → destructive/control) raises these constants under its own
review — the edit is what a reviewer sees; existing policy-action semantics are unchanged.

### 4. Blast-radius budget (§15)

`canary.Budget` carries hard caps on total executions, rate, concurrency, principals, tools,
servers, and a time-boxed window. `ValidateBudget` fail-closes on any zero cap (a forgotten
dimension never admits unbounded execution) and clamps total/window to first-Canary ceilings
(`FirstCanaryMaxTotalCeiling=1000`, `FirstCanaryMaxWindowCeiling=7d`). The runtime enforcement of
these caps is a live-execution activation concern; this phase pins the contract.

### 5. Automatic-abort taxonomy (§16)

`canary.AbortConditions()` classifies each safety trip as `AbortRequest` (fail this request
closed; the Canary survives) or `AbortCanary` (stop the whole Canary — auto-demote / kill). The
distinction is architectural: an out-of-scope execution, scope escape, fingerprint/identity
rug-pull, evidence loss, or credential-safety failure is a **single-occurrence whole-Canary
breach**, never a per-request fault; policy deny / stale / inspection-block / kill-for-request
are ordinary per-request outcomes a healthy Canary produces and survives.

### 6. Composition firewall preserved (§6)

The `internal/mcp/canary` package **cannot** reach the side effect: it does not import
`internal/mcp/execution`, `upstreamclient`, or the credential broker/provider
(`TestCanaryPackageHoldsNoExecutionCapability`). The root preflight reasons about the live tier
through `liveExecDepsConfigured`, so wiring it can never compose a live executor. The existing
execution-posture wall (`mcp_execution_posture_test.go`) and the ShadowEvaluator type-graph wall
(`TestShadow_TypeGraphHasNoExecuteCapability`) remain green — `ShadowEvaluator` still cannot
reach `Upstream.Call` or `Materialize`, even with Canary code in the same process.

### 7. Arming stays explicit and OFF (§7)

`LiveExecutor present ≠ live execution armed ≠ Canary active`. This phase composes no live
executor and never calls `markGatewayExecDepsReady`. The preflight (`canaryActivationReady`) is
the boolean gate a future arming would consult — redundant with `modeExecReady` as
defense-in-depth — and it is always false here.

### 8. Downstream execution contracts (already proven; §9–§13, §17)

The credential (Plan→gate→Materialize→zeroize, no passthrough, power ceiling), upstream
(pinned endpoint+identity, SSRF/redirect/TLS-SPKI/bounds/timeout), evidence-before-side-effect
(durable commit before the irreversible call, both paths), outcome-evidence, and rollback
contracts already exist in `internal/mcp/{execution,upstreamclient,credentials,rollout}` and are
proven by the existing differential gate `TestShadow_LivePreSideEffectEquivalence` (Shadow
prediction ↔ live enforcement across all nine decision classes, over a synthetic upstream) and
the PREREQ-MCP-KILL-1 boundary gates. Canary does not widen any of them; it constrains *which*
requests reach them (bounded read-first scope) and *whether* the live tier may be armed at all
(the readiness contract).

## Mutation coverage (§19)

Twelve defects, each caught by a named gate:

| # | Mutation | Gate |
|---|---|---|
| 1 | shadow approval satisfies live trust | `TestSatisfiesLiveExecution_ShadowApprovalNeverQualifies` |
| 2 | missing/nil live approval still preflights | `TestSatisfiesLiveExecution_NilIsFailClosed` |
| 3 | stale fingerprint executes | `TestSatisfiesLiveExecution_Rejections` (fingerprint_mismatch) |
| 4 | scope widens to wildcard/percentage | `TestValidateScope_Rejections` (percentage/enumerable) |
| 5 | kill-generation boundary check removed | `TestCanaryPrerequisite_KillStateRevalidatedAtSideEffectBoundary` (execution) |
| 6 | tool-freshness boundary removed | `TestKillBoundary_RaceMatrix` (execution) |
| 7 | decision durability bypassed | `TestShadowSoakEvidenceCommitFailsClosed` (root) |
| 8 | Materialize before credential gate | `TestShadow_LivePreSideEffectEquivalence` + broker gate tests (execution) |
| 9 | response inspection bypassed | `finishUpstream` inspection tests (execution) |
| 10 | out-of-scope Canary executes | `TestAntiWeakening_OutOfScopeDoesNotExecute` (execution) |
| 11 | LiveExecutor armed without prerequisites | `TestExecPosture_LiveArmingHooksHaveNoProductionCaller` |
| 12 | LiveExecutor leaks into Shadow type graph | `TestShadow_TypeGraphHasNoExecuteCapability` + `TestCanaryPackageHoldsNoExecutionCapability` |

Mutations 1–4 (plus four-eyes, TTL ceiling, read-first, bound-cap, fingerprint) are mechanically
re-introduced and confirmed to fail their gate by the Canary mutation campaign; 5–12 are covered
by existing execution-plane gates.

## Consequences

- Canary is architecturally defined and machine-verifiable, and **cannot be activated**: the
  live tier is unarmed, `live_execution` approvals are unissuable, and the preflight fails closed.
- The readiness contract is observable read-only at `GET /api/mcp/rollout` (`canary` sub-view).
- Activation requires a **separately-reviewed** change that arms the live tier (editing the
  posture wall), issues four-eyes live-execution approvals under stronger governance, and wires
  the preflight as the primary gate — none of which this ADR performs.
- The first controlled Canary follows `docs/design/mcp/CANARY-FIRST-RUNBOOK.md`: one node, one
  synthetic identity, one controlled recording upstream, one exact fingerprinted read tool, a
  short-lived four-eyes approval, a bounded budget, and immediate kill+rollback controls — never
  customer traffic.
