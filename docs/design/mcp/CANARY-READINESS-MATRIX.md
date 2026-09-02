# MCP Canary-Readiness — Prerequisite & Reachability Matrix

**Phase:** Culvert MCP — Canary Architecture & Readiness
**Baseline:** `main` after PR #1248 (Shadow Exit Review PASSED; `PREREQ-MCP-KILL-1` CLOSED).
Branch `claude/mcp-canary-architecture`.
**Status of this document:** GROUND TRUTH for the Canary phase. Every prerequisite is an
individually machine-verifiable fact (`internal/mcp/canary`); "Ready" is true only when the
Unmet set is empty. Canary is architecturally defined and **NOT activatable** in this build.

## The one fact that drives the phase

**Canary is dormant by construction.** The live-execution tier is never armed
(`liveExecDepsConfigured==false`; `mcp_execution_posture_test.go`), so `canary.Evaluate` always
returns NOT-READY with at least `live_executor_absent` (row 5) — the node-level backstop that no
API, envelope, or restart can clear. There is no code path that makes a real MCP upstream side
effect reachable.

A `live_execution` ToolApproval **is now issuable** under strict governance (four-eyes on the
authenticated principal, a mandatory finite TTL ≤ 24h, and exact-current-state revalidation —
see the trust firewall below), so readiness row 16 (`live_execution_approval_invalid`) is
**SATISFIABLE, not automatically satisfied**: a stock node with no approval still reports it
unmet, and issuing a valid grant clears only that one row. Issuing a live approval is a TRUST
decision only — it composes no executor, calls `markGatewayExecDepsReady` NEVER, and cannot move
Canary out of `live_executor_absent`. Pinned by `TestLiveTrust_NoActivationCoupling` (a valid
live grant ⇒ `liveExecDepsConfigured==false`, Canary mode unchanged, upstream calls 0).

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
| 2 | Shadow Exit Review attested | `shadow_exit_review_not_passed` | `shadowExitReviewAttested()` — durable, schema-versioned, build-bound attestation created ONLY by admin `POST /api/mcp/canary/shadow-exit-review` (§1); fail-closed on missing/corrupt/stale | **NO (unattested)** |
| 3 | Scope bounded/enumerable/exact | `canary_scope_not_bounded` | `canary.ValidateScope` | activation input |
| 4 | Scope read-first only | `canary_scope_not_read_first` | `canary.ScopeReadFirst` | activation input |
| 5 | Live executor composed | `live_executor_absent` | `liveExecDepsConfigured` (armed). In a production build the guarded executor unit is composed ONLY by `composeProductionGatewayLiveTier` (the sole production caller of `composeGatewayLiveTierInto`, pinned by the execution-posture wall); its real per-dependency status is surfaced read-only on the tier `production_dependencies` view. | **NO (dormant)** |
| 6 | Authoritative UpstreamCaller | `upstream_caller_absent` | live tier (armed). The real dependency is the bounded `upstreamclient.Client` (system-root trust, no `InsecureSkipVerify`, Gateway destination policy) built by `composeProductionGatewayLiveTier`; readiness token `upstream_client` on the `production_dependencies` view. | **NO** |
| 7 | Credential path ready | `credential_path_not_ready` | live tier (armed). The real dependency is the `broker.Broker` (real KEK + profile store) built by `composeProductionGatewayLiveTier`; token `credential_broker` = `broker_composed_no_provider` (the honest pre-Canary gap: no production credential Provider adapter, so a credential-requiring tool fails closed at the broker). | **NO** |
| 8 | Durable events healthy | `durable_events_degraded` | `durableEventsHealthy()` — domain CriticalState=="normal" | node-dependent |
| 9 | Response inspection ready | `response_inspection_not_ready` | `globalMCPShadow.inspectionComposed` | node-dependent |
| 10 | Registry healthy | `registry_unhealthy` | `mcpInventory.sharedInventory()` | node-dependent |
| 11 | Catalog healthy | `catalog_unhealthy` | `mcpInventory.sharedInventory()` | node-dependent |
| 12 | Policy healthy | `policy_unhealthy` | `mcpPolicy.composed()` | node-dependent |
| 13 | Emergency kill clear | `emergency_kill_active` | `State.Killed()` | node-dependent |
| 14 | Kill-generation boundary guard | `kill_boundary_guard_absent` | live tier (armed, PREREQ-MCP-KILL-1) — the final kill-generation boundary guard lives inside the guarded `*execution.Executor` composed by `composeProductionGatewayLiveTier`; asserted present as one unit with the executor. | **NO** |
| 15 | Tool-freshness boundary guard | `tool_freshness_guard_absent` | live tier (armed) — the final tool-freshness (drift) boundary guard inside the same guarded executor; asserted present as one unit. | **NO** |
| 16 | Exact live_execution approval (PER SCOPED TOOL) | `live_execution_approval_invalid` | `canary.ValidateScopeApprovals` (→ per-tool `SatisfiesLiveExecution`), driven by the authoritative `tooltrust.Store` through `buildLiveApprovalBindings` in `productionCanaryActivationInputs` | **satisfiable; unmet until a valid grant is issued** |
| 17 | Server usable | `server_not_usable` | registry/catalog | activation input |
| 18 | Tool fingerprint current | `tool_fingerprint_stale` | catalog | activation input |
| 19 | Rollback path healthy (**mechanics**) | `rollback_path_unhealthy` | `rollbackPathHealthy` — durable persist not degraded/write_failed AND a build-bound EXECUTABLE rollback-rehearsal record (a real Canary→Shadow→Observe drill through the actual persist/restore path, §5) validates for the current build. **Rollback MECHANICS evidence only** — it does NOT traverse the authoritative coordinator (see row 20). | **NO (undrilled)** |
| 20 | Authoritative rollback rehearsed (coordinator) | `rollback_coordinator_rehearsal_pending` | `productionCoordinatorRollbackRehearsed` — reads DURABLE, build-bound evidence that the Canary→Shadow→Observe demotion was driven through the REAL coordinator core (`commitRolloutTransitionCore`, the same body every production transition runs) and recovered to Observe, so the rehearsal fails for every security reason a real rollback would (Shadow preflight, emergency kill, config validity, durability). Run via `POST /api/mcp/rollout/rehearse-rollback-authoritative`. Distinct from row 19 (mechanics). **CLOSABLE** by a successful coordinator-routed drill; the shipped default stays open (no drill has run — and it requires the full shadow tier, which the unshipped tool-approval slice gates). | **NO (until drilled)** |
| 21 | Budget configured | `canary_budget_not_configured` | `canary.ValidateBudget` | activation input |

Live-tier facts (5, 6, 7, 14, 15) are all false together in this build (the guarded live
executor — whose boundary guards are pinned by `internal/mcp/execution`'s PREREQ-MCP-KILL-1
tests — composes as one unit and is never composed).

**Node vs activation readiness (two evaluators).** Rows 3, 4, 16, 17, 18, 21 (scope bounded,
scope read-first, live approval, server usable, tool fingerprint, budget) are **activation-
level**: they are meaningful only once an operator supplies a concrete scope, approval, and
budget. Every other row is **node-level** (including row 20, the open coordinator-rehearsal
prerequisite, which the `node_ready` dry run surfaces). `canary.EvaluateNode` (the `node_ready` dry run at
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
| issuance | issuable ONLY through the dedicated governed path (`RequestLiveApproval`+`ApproveLive`): mandatory finite TTL ≤ 24h, four-eyes at approval on the canonical authenticated principal, exact-current-state revalidation, no shadow-request reuse, no catalog promotion | `tooltrust.Purpose.Issuable()`, `store.validateLiveApproveLocked`, `TestLiveApprove_*`, `TestLiveTrust_RouteIsolation` |

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

## Canary Activation Gate & Runtime Budget (implemented — control-plane/runtime safety)

The control-plane and runtime safety gates that MUST exist before the live execution plane is
composed are now implemented and dormant-by-construction (Execution posture stays CLOSED):

- **§1 Shadow Exit attestation** — `shadowExitReviewAttested()` reads a durable, schema-versioned,
  build-bound attestation created ONLY by an admin `POST /api/mcp/canary/shadow-exit-review`
  (never on startup, never because tests passed). Corrupt/stale/forged records fail closed +
  quarantine. Row 2's `shadow_exit_review_not_passed` disappears only when a real current-build
  attestation validates.
- **§2 Authoritative Canary preflight** — `commitRolloutTransitionAt` (the single shared commit
  path for the CP→DP apply, the startup reconcile, and any future caller) refuses any transition
  into a live-execution mode (Canary/Production) unless the FULL `evaluateCanaryActivationPreflight`
  verdict is Ready — node readiness AND the activation-level scope/approval/budget/target facts. The
  scope comes from the signed config; the other activation inputs are resolved from AUTHORITATIVE
  node state via `canaryActivationInputsProbe` (fail-closed empties in this build) — never a
  request-supplied claim. No API, restart, CP→DP, or restore path bypasses it (restore additionally
  clamps executing modes to Disabled).
- **§3 Runtime blast-radius budget** — `canary.BudgetEnforcer`: generation-bound, atomic, monotonic
  total (no replay), exact-N/deny-N+1, concurrency + per-minute rate + time-boxed window, restart
  spend preserved. Exhaustion fails closed before the side-effect boundary and trips the abort.
- **§4 Whole-Canary abort controller** — `canary.AbortController`: generation-bound monotonic latch
  over the 10 AbortCanary breach codes; a single occurrence makes execution ineligible immediately
  and permanently for that generation (resume requires a new activation/generation). The 6
  AbortRequest codes NEVER latch it (request-fails-closed ≠ Canary-stops).
- **§5 Executable rollback rehearsal (mechanics)** — the self-attested marker is replaced by a real
  Canary→Shadow→Observe drill through the actual rollout persist/restore path, recorded as durable
  build-bound evidence; readiness row 19 (`rollbackPathHealthy`) requires that evidence to validate.
  This is rollback **mechanics** evidence: it drives the scratch ladder directly (`SetConfig` +
  `persistRolloutStateTo`), NOT through the authoritative `commitRolloutTransitionAt` coordinator, so
  it does not prove parity with that coordinator's Shadow preflight, emergency-kill, revision,
  durability, and rollback guards. The authoritative rehearsal is a SEPARATE hard prerequisite
  (row 20, `rollback_coordinator_rehearsal_pending`, `CANARY-ROLLBACK-COORDINATOR-REHEARSAL`) that
  keeps Canary readiness FALSE regardless of the mechanics rehearsal — no transition can become READY
  on the mechanics rehearsal alone.
- **Authoritative rollback rehearsal (coordinator parity, row 20)** — the follow-up landed: the rollout
  coordinator is extracted into a single locked core (`commitRolloutTransitionCore`) that every
  production transition AND the rehearsal share, and the rehearsal drives the Canary→Shadow→Observe
  ladder through that core on a SCRATCH state/file (never live state), recovers to Observe, and records
  DISTINCT durable build-bound evidence (`mcp_canary_coordinator_rehearsal.go`). So the rehearsal fails
  for every security reason a real rollback would (Shadow preflight, emergency kill, config validity,
  durability), proven by the parity wall and the rejection/mutation campaign. `productionCoordinatorRollbackRehearsed`
  reads that evidence, so row 20 CLOSES for a build only after a successful coordinator-routed drill.
  The mechanics fact (row 19) and this fact stay DISTINCT.
- **Runtime lifecycle** — `mcp_canary_runtime.go` owns the monotonic activation generation and the
  durable budget/abort state; `beginCanaryActivation` (the future-arming seam) is UNINVOKED in this
  build, so no generation is ever bumped and no execution is ever reserved in production.

## What must become true before the first Canary (the remaining prerequisite gap)

Every one is a **separately-reviewed activation**, not a config change:

1. ~~Arm the live tier (compose a live `execution.Executor` + UpstreamCaller + materialize-broker;
   call `markGatewayExecDepsReady`).~~ **COMPOSITION + ARMING LIFECYCLE DONE (live-tier composition
   phase).** The real live executor is composable (`composeGatewayLiveTierInto`, `mcp_live_startup.go`)
   and the tier is explicitly ARMABLE through the single authoritative, node-readiness-gated path
   (`armLiveTier`, `mcp_live_arming.go`), with a quiesce/disarm inverse and the CANARY-ROLLBACK-LIVE-
   QUIESCE-REHEARSAL closed. **COMPOSED != ARMED != Canary ACTIVE** is pinned. **Production dependency
   composition now EXISTS (PR #1291):** `composeProductionGatewayLiveTier` (`mcp_live_production_deps.go`)
   is the single production caller, opt-in behind `CULVERT_MCP_LIVE_DEPS` (default OFF), wiring the real
   KEK / destination-resolver / profile-store / registry / catalog. What REMAINS for a real deployment:
   (a) the production **credential Provider adapter** — the broker is composed with ZERO providers
   (`broker_composed_no_provider`), so a credential-REQUIRING tool fails closed at the broker (the
   no-credential *code path* skips the broker, but whether a given request selects it depends on the
   tool's matched policy rule, so it is not an intrinsic property — see the review §4); (b) **upstream connectivity provisioning**
   — the production client uses `DefaultGatewayPolicy` (https-only, no-private) + the default SPKI
   verifier, so a controlled server needs a plain `https://` endpoint on a PUBLIC host with a base64
   SHA-256 SPKI pin; the documented `mcp+https://` scheme, `*.qual.svc` private host, and SPIFFE-format
   identity are all rejected fail-closed, and no public-HTTPS controlled MCP server is provisioned today;
   (c) a **governed production arming entry point** — `armLiveTier` (the sole caller of
   `markGatewayExecDepsReady`) has NO production caller today (only tests invoke it), so an operator
   cannot actually arm the tier in the shipped process; a startup path or admin API must wire it,
   plus the operational decision to arm on a real node; (d) a **read-first-executable
   operation** — `policyOperation` classifies every `tools/call` as `OpWrite` (refused read-first)
   and `tools/list` binds no exact tool for the live-approval revalidation, so arming does NOT by
   itself make a one-exact-tool call executable; a finer operation classifier or a designed
   discovery-trust path is required (review §6); (e) an **exactly-one-tool/principal constraint** —
   `ValidateScope` caps tools/principals at 2, not 1, so the one-of-everything shape must be imposed
   as an authorization prerequisite: **exactly one `Principals` entry, zero `Clients`/`Agents`/`Groups`,
   and exactly one tool** (or a proven 1:1 client/agent→principal mapping). A plain `count==1` check is
   INSUFFICIENT — `principalCount` sums `Principals`+`Clients`+`Agents`, so one shared client/agent with
   no `Principals` would satisfy it while leaving the principal dimension unrestricted (review §10);
   (f) a
   **per-physical-invocation budget (CODE CHANGE)** — an idempotent read retries up to `MaxReadRetries`
   times outside the single budget reservation, so one budgeted request can send the POST ~3×.
   Retry-disablement is NOT representable today (`NewLimits` coerces `MaxReadRetries==0`→2 and rejects
   negatives; `newProductionUpstreamClient` hard-codes `DefaultLimits()`), so closing this needs code —
   only two options actually bound the physical POSTs: make retry-disablement representable + wire a
   retry-free client, OR charge each attempt to the budget. A per-reservation key is not a third bound
   (it enables correlation/server-side dedup but does not stop the retry loop — review §9/§14);
   a **credential-selection resolution** (verify a matched rule with no `CredentialProfile`, or a
   working credential provider/path — the production broker has zero providers, review §4); and (g)
   two **product-defect prerequisites** — the whole-Canary auto-abort is unwired for the eight
   declared breaches beyond `budget_exhausted`/`scope_escape`, and the durable outcome record is
   success-only with an unclosable post-send crash window (review §14–§16, §18); and (h) a
   **governed operator-reachable graceful rollback** — only the emergency kill is reachable today
   (`quiesceLiveTier` has no caller; `apiMCPRolloutTransition` returns `distribution_not_configured`
   for a Canary→Shadow/Observe target), yet the review contract requires rollback AND kill (review §17).
   **Arming is NOT a promise of execution.** Composed-but-unarmed still reports
   `live_executor_absent` for the Canary facts (armed feeds them), so this does NOT by itself clear row
   5 on a stock node. The execution-posture wall was edited (evolved + strengthened) as required.
2. ~~Make `live_execution` issuable under stronger governance (four-eyes, short TTL).~~ **DONE
   (this slice).** `live_execution` is issuable through the dedicated governed path
   (`RequestLiveApproval`+`ApproveLive`): mandatory finite TTL ≤ 24h, four-eyes at approval on the
   canonical authenticated principal, exact-current-state revalidation, no shadow-request reuse, no
   catalog promotion. Row 16 is now satisfiable (not auto-satisfied). This is a TRUST decision only —
   it arms no executor and cannot clear `live_executor_absent` (row 5), which item 1 still gates.
3. ~~Call `beginCanaryActivation` from the armed live path; drive `reserveCanaryExecution` at the
   pre-side-effect boundary.~~ **WIRED (live-tier composition phase).** `beginCanaryActivation`/
   `demoteCanary` are wired into the single authoritative rollout commit gate (a production commit into
   a live mode begins the generation exactly once; a demotion invalidates it), and the live side-effect
   gate (`mcp_live_gate.go`) drives `reserveCanaryExecution` at the boundary before the executor's
   kill re-check. Still gated on the tier being armed AND a real Shadow→Canary transition committing.
4. Close **`CANARY-ROLLBACK-COORDINATOR-REHEARSAL`** (row 20) by running the authoritative rehearsal
   on a genuinely rollback-capable node (`POST /api/mcp/rollout/rehearse-rollback-authoritative`). The
   machinery landed (coordinator core extracted; the rehearsal routes the scratch demotion through it,
   fails for every real rollback gate, and records durable build-bound evidence), so row 20 CLOSES for a
   build once a coordinator-routed drill succeeds. In the shipped build this still requires the full
   shadow tier (gated by the unshipped tool-approval slice), so it stays open by default.
5. Execute the first Canary per `CANARY-FIRST-RUNBOOK.md` (synthetic identity, recording
   upstream, never customer traffic).
</content>
