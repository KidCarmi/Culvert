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
| `live_execution` ToolApproval issuable | **NO** _(at time of writing; see Addendum 2026-09 — now governed-issuable)_ | `tooltrust.Purpose.Issuable()` (shadow only); `CreateRequest`+`Approve` refuse fail-closed |
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

`canary.SatisfiesLiveExecution(approval, target, now)` is the per-approval consumption predicate.
It requires, fail-closed: `purpose==live_execution`, `status==active`, exact current-target
binding (tenant+server+tool+fingerprint+format — the rug-pull invariant), a present, unelapsed
expiry no longer than `MaxInitialCanaryApprovalTTL` (24h) measured from a **real, non-future**
approval instant (`ApprovedAt<=now`; a future or zero `ApprovedAt` is rejected so a
future-relative window cannot smuggle a long TTL — the unelapsed-expiry and non-future-approval
checks jointly guarantee `ExpiresAt>ApprovedAt`), and **four-eyes** (distinct present requester
and approver — separation of duties).

A Canary scope names up to two tools across one tenant, so a **single** approval must never
authorize the whole scope. `canary.ValidateScopeApprovals(scope, bindings, now)` is the
scope-level gate: EVERY admitted (tenant × tool) combination must have its OWN binding whose
target is that exact tenant+server+name AND whose target fingerprint equals the scope's declared
fingerprint (both are hex of the same 32-byte digest), each satisfying `SatisfiesLiveExecution`;
a missing, duplicate, wrong-fingerprint, wrong-tenant, or out-of-scope binding fails closed.
Keying coverage on the **tenant** is load-bearing: a rollout scope admits a subject only when its
tenant matches, so an approval for tenant `t2` can never count as coverage for a scope admitting
`t1` (Codex P1). The preflight's `LiveApprovalValid` fact is driven by this, not by an
unconstrained target supplied alongside the scope. _At the time this ADR was accepted, issuance
stayed refused; the governed issue path landed subsequently — see **Addendum 2026-09**._ These
predicates are what the live-execution issue path must satisfy.

### 3. Bounded, read-first Canary scope (§4/§5)

`canary.ValidateScope` requires the scope be Gateway-only, enumerable (a percentage-only scope
is rejected — "1% of everything cannot enter Canary"), bind **exact** servers and tools each
with a pinned fingerprint (no wildcard-future-tools), bind exactly one **concrete** tenant
(`ScopeNoTenant`/`ScopeTooManyTenants` — rollout treats an empty tenant selector as a wildcard
that admits the same subject ID from every tenant, and identities are tenant-local, so the "who"
axis is only actually bounded once a tenant is pinned; Codex P1), bind at least one **exact**
principal/client/agent with **groups forbidden** (`ScopeNoIdentity`/`ScopeUsesGroups` — a group's
membership can change without a scope edit, so the "who" axis would not be enumerable), stay
within tiny first-Canary caps (`MaxCanaryServers=1`, `MaxCanaryTools=2`, `MaxCanaryPrincipals=2`,
`MaxCanaryTenants=1` — structurally incapable of fleet-wide), and be **read-first**
(`Operations ⊆ {read}`, `!HighRisk`).

The scope must also be **realizable**: `MatchesNothing` detects only ABSENT inclusion selectors,
not CONTRADICTORY ones (a tool whose server is not in the server dimension, or an inclusion value
that is also excluded), so `ValidateScope` builds a witness subject from the scope's own inclusion
selectors and requires the compiled matcher to admit it (`scopeRealizable` → `ScopeNotRealizable`),
reusing rollout's exact `Contains` semantics rather than reimplementing them — a Canary that can
never match its own corpus must never report ready (Codex P2).

Read-first is enforced at **two** levels because `rollout.RiskClass` has only four buckets and
the root `mapRisk` folds `policy.OpControl` (and `OpDiscovery`) into `RiskRead` — so a
scope-level read-first check cannot exclude a control-plane operation. `ScopeReadFirst` is the
necessary scope axis; `canary.IsReadFirstOperation(policy.OperationClass)` is the authoritative
per-request gate a live executor must ALSO enforce, admitting only `OpRead`/`OpDiscovery` and
rejecting `OpControl`/`OpWrite`/`OpDestructive`. The authority for read-first is Culvert's own
operation classification (derived by the policy engine), **never** the server-provided MCP
`readOnlyHint`. Graduation (read/discovery → bounded write → destructive/control) raises these
constants under its own review — the edit is what a reviewer sees; existing policy-action
semantics are unchanged.

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
| 13 | one approval authorizes a multi-tool scope | `TestValidateScopeApprovals_MissingToolIsUnapproved` + `_Rejections` (outside_scope/duplicate/wrong_fingerprint) |
| 14 | control-plane op treated as read-first | `TestIsReadFirstOperation_ControlIsExcluded` |
| 15 | future/zero-dated approval passes the TTL ceiling | `TestSatisfiesLiveExecution_Rejections` (approved_in_future/approved_zero) |
| 16 | group-only / identity-less scope enters Canary | `TestValidateScope_Rejections` (no_identity/group_only_identity/uses_groups) |
| 17 | degraded durable-event plane still Canary-ready | `durableEventsHealthy` (domain CriticalState=="normal"; `mcp_canary_preflight_test.go`) |
| 18 | node dry-run conflates missing activation inputs with node deficiencies | `TestEvaluateNode_ExcludesActivationInputs` (node dry-run evaluates node-level facts only) |
| 19 | rollback readiness from coordinator existence, not durable+rehearsed health | `rollbackPathHealthy` (persist not degraded/write_failed AND `RollbackRehearsed`) |
| 20 | approval for tenant t2 covers a scope admitting tenant t1 | `TestValidateScopeApprovals_Rejections` (wrong_tenant) |
| 21 | identity-less/wildcard-tenant scope enters Canary | `TestValidateScope_Rejections` (no_tenant/empty_tenant_string/too_many_tenants) |
| 22 | contradictory scope (tool off-server / excluded inclusion) validates | `TestValidateScope_Rejections` (tool_server_not_in_scope/excluded_tenant) via `scopeRealizable` |
| 23 | rollback health read torn from an in-flight rehearsal write | `TestRollbackPathHealthy_DurableRehearsalAndRace` (both facts under `durableMu`) |
| 24 | realizability witness picks an excluded identity, rejecting a good scope | `TestValidateScope_ExcludedIdentityStillRealizable` (`firstNotExcluded`) |
| 25 | stale `write_failed` blocks rollback readiness after a durable rehearsal | `TestRollbackPathHealthy_ClearsStaleWriteFailed` (success clears the status) |

Mutations 1–4 and 13–17 (plus four-eyes, TTL ceiling, read-first, bound-cap, fingerprint,
per-tool coverage, exact identity) are mechanically re-introduced and confirmed to fail their
gate by the Canary mutation campaign; 5–12 are covered by existing execution-plane gates.

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

## Addendum — Canary Activation Gate & Runtime Budget (implemented; still dormant)

ADR-0035 pinned the readiness CONTRACT (facts, scope, budget shape, abort taxonomy) as pure,
observable data. This addendum records the control-plane/runtime safety GATES that must exist
before the live execution plane is composed. They are implemented and **dormant by construction**:
no LiveExecutor is composed, `markGatewayExecDepsReady` stays uncalled, `live_execution` approvals
stay unissuable, Canary/Production stay unreachable, and no real upstream side effect is possible.

1. **Shadow Exit attestation is durable, build-bound, and admin-created (§1).**
   `shadowExitReviewAttested()` (root `mcp_canary_attestation.go` + pure `canary.ShadowExitAttestation`)
   reads a schema-versioned JSON record under `dataDir`, created ONLY by an explicit admin
   `POST /api/mcp/canary/shadow-exit-review` — never on startup, never because tests passed. It is
   bound to the build identity (`version`), so a redeploy invalidates a prior review; a
   corrupt/unknown-schema/forged/stale record fails closed and is quarantined. `Facts.ShadowExitReviewPassed`
   is driven by it.

2. **The Canary preflight is the authoritative activation gate (§2).**
   `commitRolloutTransitionAt` — the single shared commit path used by the CP→DP apply
   (`applyMCPCapabilityEnvelope`), the startup reconcile (`reconcileRolloutWithAppliers`), and any
   future caller — refuses a transition into a live-execution mode unless the WHOLE
   `evaluateCanaryActivationPreflight` verdict (`canary.Evaluate`) is Ready: node readiness AND the
   activation-level facts (bounded read-first scope, one valid live approval per scoped tool,
   blast-radius budget, target usability/fingerprint). The scope comes from the SIGNED config
   (authoritative); the other activation inputs are resolved from authoritative node state via the
   `canaryActivationInputsProbe` seam — never a request-supplied claim — which in this build returns
   fail-closed empties (no approval/budget store exists), so the full verdict can never pass. Using
   node readiness alone would let a future armed build commit Canary without scope/approval/budget
   validation (Codex P1); the full verdict closes that. `restore()` clamps a restored executing mode
   to Disabled. There is no API, restart, CP→DP, or restore bypass; the syntactic validity of a
   signed Canary config is never sufficient. Redundant with `modeExecReady` (defense-in-depth), and
   always refuses in this build.

3. **Runtime blast-radius budget (§3).** `canary.BudgetEnforcer` is generation-bound, atomic under
   concurrency (one mutex over the whole check-then-reserve), and fail-closed: exactly
   `MaxTotalExecutions` grants then deny (no off-by-one), a MONOTONIC total that is never rolled back
   (a crash between reserve and side effect cannot replay the budget), plus concurrency, per-minute
   rate, and a time-boxed window (TTL). Restart preserves the spend via a generation-keyed snapshot;
   a stale-generation or over-cap snapshot never restores.

4. **Whole-Canary abort controller (§4).** `canary.AbortController` is a generation-bound MONOTONIC
   latch over the 10 `AbortCanary` breach codes: a single occurrence makes execution ineligible
   immediately and permanently for that generation (resuming requires a new activation/generation).
   The 6 `AbortRequest` codes NEVER latch it (an unknown code fails closed to a whole-Canary latch).
   An abort survives a restart.

5. **Executable rollback rehearsal (§5).** The self-attested `RollbackRehearsed` marker is replaced
   by a real Canary→Shadow→Observe demotion drill driven through the actual rollout persist/restore
   mechanics on a scratch state/file (`mcp_canary_rollback_rehearsal.go`), recorded as durable,
   build-bound evidence (`canary.RollbackRehearsalRecord`). `rollbackPathHealthy` requires that
   evidence to validate for the current build; the marker alone no longer satisfies readiness.

6. **Activation runtime lifecycle (`mcp_canary_runtime.go`).** A monotonic activation generation is
   bumped on each Shadow→Canary activation and keys both the budget enforcer and the abort
   controller, so a demotion/reactivation structurally invalidates the previous generation's runtime
   state (a stale reserve/trip is refused; an old snapshot never restores into a new generation).
   `beginCanaryActivation` is the future-arming seam and is **uninvoked in this build**, so no
   generation is ever bumped and no execution is ever reserved in production; restore is a no-op
   because no durable canary-runtime file exists.

Mutation coverage (10, each caught by a named gate): allow Canary without attestation, bypass the
preflight via CP→DP, bypass on restart/restore, permit the N+1 budget execution, race the budget
counters, clear the whole-Canary abort automatically, treat a per-request deny as a whole-Canary
abort, accept a corrupt/stale attestation, accept a self-attested rollback without a drill, and
reuse an old budget/abort generation after reactivation. See
`mcp_canary_matrix_mutation_test.go` for the roster.

Codex-review hardening (P1, each with a dedicated gate): the runtime budget's rate-window position
is durable generation-bound state so a restart cannot replay a `MaxExecutionsPerMinute` burst
mid-window (`TestBudgetEnforcer_RestartDoesNotReplayRateWindow`); a demotion whose persist fails
removes the durable record so a failed rollback cannot revive on restart
(`TestCanaryRuntime_FailedDemoteDoesNotReviveOnRestart`); the commit gate requires the FULL
activation verdict, not just node readiness (`TestCanaryCommitGate_RefusesWhenActivationInputsMissing`
/ `_AllowsWhenFullyReady`); and the rollback-rehearsal drill runs through the REAL production
`persistRolloutStateTo`/`restoreRolloutStateFrom` (destination path injected) rather than a parallel
persistence copy.

## Addendum (2026-09) — governed `live_execution` issuance (trust only; live tier stays dormant)

The live-execution TRUST decision is now expressible, durable, reviewable, revocable, and
machine-verifiable. This addendum records **only** a trust/authorization change; it composes no
`LiveExecutor`, wires no `UpstreamCaller`, never calls `markGatewayExecDepsReady` or
`beginCanaryActivation`, and leaves the four dormancy facts unchanged: LiveExecutor composed **NO**,
`markGatewayExecDepsReady` caller **NO**, Canary active **NO**, Production active **NO**, upstream
side effects **0**, production credential retrievals **0** (`mcp_execution_posture_test.go`,
`TestLiveTrust_NoActivationCoupling`).

- **Issuable through a dedicated governed path only.** `Purpose.Issuable()` now admits
  `live_execution`, but issuance does **not** reuse shadow request semantics: the coordinator's
  `RequestLiveApproval`+`ApproveLive` and the store's `validateLiveApproveLocked` enforce the
  stronger requirements. `ApproveShadow` refuses a non-shadow purpose and `ApproveLive` refuses a
  non-live one (`TestLiveTrust_RouteIsolation`), so a live grant can never be minted through the
  shadow promotion path (which materializes `catalog.Usable`), and a shadow request can never be
  promoted to live.
- **Four-eyes, mandatory.** `RequestedBy != ApprovedBy`, both present, compared on the **canonical
  authenticated principal** (`mcpLivePrincipal` → session `Sub`), not display names or client IP.
  A live request with no authenticated session is refused fail-closed
  (`TestLiveTrustHTTP_UnauthenticatedRequestFailsClosed`).
- **Short, mandatory TTL.** A finite expiry is required at request time (no silent default) and the
  window is capped at `tooltrust.MaxLiveExecutionApprovalTTL` (24h) — enforced at request (from now)
  and, authoritatively, at approval (from `approved_at`). One constant is the single authority,
  referenced from `canary.MaxInitialCanaryApprovalTTL`.
- **Exact-current-state approval + rug-pull.** Approval revalidates the exact reviewed target
  (server/tool exist, identity+fingerprint+format match, catalog and server revision current) and
  fails closed on any drift between request and approve; an F1→F2 fingerprint change invalidates the
  F1 grant and never auto-upgrades (`TestLiveApprove_ExactStateFingerprintDrift`,
  `TestLiveTrust_RugPull_DriftInvalidatesLiveApproval`).
- **Revocation + expiry fail closed, across restart.** A revoked or expired approval fails the
  scope preflight, does not resurrect on reload (fail-closed strict decode + `validateStored` live
  invariants), and reapproval is a new decision. `now == expires_at` fails closed.
- **Wired into the real preflight bridge.** `productionCanaryActivationInputs` builds
  `ToolApprovalBinding`s from the authoritative `tooltrust.Store` via `buildLiveApprovalBindings`,
  so `canary.ValidateScopeApprovals` consumes real grants: every admitted `(tenant, server, tool,
  fingerprint)` needs its own valid live approval. Readiness row 16
  (`live_execution_approval_invalid`) is therefore **satisfiable, not auto-satisfied** — a stock
  node with no grant still reports it unmet, and issuing a grant clears only that row.
- **Trust ≠ availability ≠ authorization.** A live grant does not make a tool `catalog.Usable`
  (that stays a shadow-only projection) and is not runtime authorization — the policy engine stays
  authoritative for every call. `CANARY-ROLLBACK-LIVE-QUIESCE-REHEARSAL` remains **OPEN**.
