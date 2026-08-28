# Controlled Shadow Activation — Dependency Graph & Design

Status: **design + implementation** (phase "Controlled Shadow Activation Preparation").
The mechanism is complete and fail-closed, but Controlled Shadow activation is **NOT
activation-ready in production**: it is gated on TWO independent hard prerequisites — (1) a tool
being `Usable` in the requested scope, which catalog ingestion never yields (tool approval is a
later slice, §8), still **OPEN**; and (2) durable per-request `ShadowDecision` evidence via a
`schema_version:2` envelope (the `SHADOW-EVIDENCE-ROUTING-1` durable-envelope addendum, §8a), now
**CLOSED** — shipped on this branch (the parent routing item stays a separate open debt). Neither absorbs the other, and prerequisite 1 remaining open keeps activation out of
reach: no production activation until it closes too — see §8b.
Predecessors: ADR-0024 (MCP Agent Security Gateway, disabled-by-default), PR #1224
(hardened MCP backend), PR #1226 (Layer B Shadow capability separation + formal
`ShadowDecision` Model 1). Baseline `main` = `e698a12`.

This document is the ground-truth trace this phase built **before** changing code
(§2 of the phase brief), plus the design that makes Shadow activatable on ONE
controlled target while keeping live execution structurally impossible.

Terminology: **live execution** = a real upstream MCP `tools/call` side effect
(`Upstream.Call`) and/or credential **materialization** (`Broker.Materialize`).
Shadow performs **neither** — it evaluates and records.

---

## 1. What blocks Shadow activation today (traced, not assumed)

Two INDEPENDENT gates block Shadow on current `main`. Both must change for Shadow
to evaluate real traffic; leaving either in place keeps Shadow inert.

### Gate A — the rollout transition gate (fail-closed)

`(rollout.Mode).RequiresExecutionPlane()` returns true for **Shadow, Canary, and
Production alike** (`internal/mcp/rollout/rollout.go:140`). Every path that commits
a rollout transition pairs it with `execDepsConfigured(...)`:

| Site | File:line | Effect |
|---|---|---|
| durable commit | `mcp_rollout.go:179` | `RequiresExecutionPlane() && !execDepsConfigured` ⇒ `errShadowExecDepsNotConfigured` |
| restore clamp | `mcp_rollout.go:249` | a recovered executing mode without exec-deps is clamped to Disabled |
| CP→DP apply | `mcp_distribution.go:269` | signed executing-mode envelope ⇒ `RejectAck(errShadowExecDepsNotConfigured)` |
| admin preflight | `ui_mcp_rollout.go:85` | surfaces `shadow_execution_dependencies_not_configured` (HTTP 409) |

`execDepsConfigured(mgmt)` reads `globalExecDeps.{gateway,management}` (two
`atomic.Bool`, `mcp_rollout_execdeps.go`). They are armed ONLY by
`markGatewayExecDepsReady` / `markManagementExecDepsReady`, which **nothing calls**
(pinned by `mcp_execution_posture_test.go`). So the flags are false and every
Shadow/Canary/Production transition is rejected fail-closed. **Startup never fails
— the transition does.**

### Gate B — the runtime composition gate (nil executor)

The shipped Gateway composition (`assembleGatewayConfig`, `mcp_observe_startup.go`)
builds `runtime.Deps` with `Keys/Registry/Catalog/Events/Policy/Replay` but **no
`Executor`**. With `Deps.Executor == nil`, `pipeline.executor` is nil
(`internal/mcp/runtime/pipeline.go:184`), and `dispatchPolicy` never consults
rollout resolution at all (`runtime/policy.go:89`) — the runtime is pure
decision-only Observe **regardless of the rollout State's mode**. So even a Shadow
mode that somehow slipped past Gate A would have no request-path effect.

### The defect this phase fixes

`markGatewayExecDepsReady` arms **live execution** (executor + upstream client +
materialize broker + inspection/DLP). After Layer B (#1226), Shadow needs **none**
of `Upstream.Call`, `Broker.Materialize`, or a live `*execution.Executor`. It needs:
`*ShadowEvaluator` + durable Events + policy/catalog/registry + an OPTIONAL
plan-only `CredentialPlanner` + request inspection + rollout State + health/metrics.
Gating Shadow on a **live-execution** readiness flag it does not require is the
historical coupling to break.

---

## 2. Injection seam & the answer to "can ShadowEvaluator be injected independently?"

`runtime.ExecutionProvider` is injected at `runtime.Deps.Executor`
(`runtime/deps.go:58`) → copied to `pipeline.executor` (`pipeline.go:185`).
`*execution.ShadowEvaluator` already satisfies `runtime.ExecutionProvider`
(`var _ runtime.ExecutionProvider = (*ShadowEvaluator)(nil)`,
`shadow_evaluator.go:114`), so **yes** — it can be assigned to `Deps.Executor`
exactly like the live `*Executor`, and the live object never has to exist. That is
the composition seam this phase uses.

`rollout.ModeShadow` → `Resolve` → `resolveShadow` → `EffectShadowEvaluate`
(`rollout/resolve.go:127,138`), a disposition DISTINCT from `EffectExecute`, which
`Executor.Execute` routes to the capability-reduced `ShadowEvaluator`
(`execution/executor.go:136`). A standalone `ShadowEvaluator` handles the same
disposition directly (`shadow_evaluator.go:155`).

---

## 3. Readiness split (the key architectural change)

`shadowDepsConfigured` is separated from `liveExecDepsConfigured`
(`mcp_rollout_execdeps.go`):

```
Shadow requires:            Canary/Production additionally require:
  ShadowEvaluator composed    live *execution.Executor
  durable Events              UpstreamCaller
  policy/catalog/registry     Broker.Materialize
  CredentialPlanner (if cfg)  final kill-switch boundary recheck
  request inspection          (every future live-side-effect prerequisite)
  rollout State
  health/metrics
```

Invariants (pinned by `mcp_shadow_readiness_test.go`):
- `markGatewayShadowDepsReady()` sets ONLY the shadow flag; `liveExecDepsConfigured`
  stays false. **Shadow readiness never implies live readiness.**
- `markGatewayExecDepsReady()` (live) sets ONLY the live flag and is still
  **uncalled** in production (pinned by the evolved execution-posture wall).
- The gate is `modeExecReady(mode, mgmt)`: Canary/Production → `liveExecDepsConfigured`,
  Shadow → `shadowDepsConfigured`, Disabled/Observe → always ready.

---

## 4. Production composition (ShadowEvaluator only)

`mcp_shadow_startup.go` is the **single** production file that imports
`internal/mcp/execution`. It composes `*execution.ShadowEvaluator` from: the Gateway
rollout `State`, the durable `Events` manager, metrics, clock, actor, and (optionally)
a plan-only `CredentialPlanner`. It receives **no** `UpstreamCaller`, **no**
materialize-capable `*broker.Broker`, **no** live `*execution.Executor`. It then
assigns the evaluator to `Deps.Executor` and calls `markGatewayShadowDepsReady()`.

The composition also wires request inspection (`Deps.Inspection`, the default gateway
schema/DLP/destination profile) so a Shadow evaluation runs against inspection — an
inspection-rejectable input is blocked or reflected in the policy decision, never
classified `would_execute`. The preflight requires it (`request_inspection_unavailable`
otherwise). A hard inspection failure still blocks in the runtime before the executor
(§10 "degrade toward Block"; the `would_fail_inspection` evidence-shape is the tracked
`SHADOW-EVIDENCE-ROUTING-1` deferral) — never a `would_execute` for a rejected input.

Disabled by default: composition happens ONLY when the operator explicitly enables
Shadow readiness (`CULVERT_MCP_SHADOW_READY`, off by default). Unset ⇒ `Deps.Executor`
and `Deps.Inspection` stay nil ⇒ byte-identical Observe/SWG path.

Observe-window evidence parity: with the evaluator composed but mode still Observe
(or an out-of-scope subject in Shadow mode), requests resolve to `EffectRecordOnly`.
The evaluator's record-only path commits the allow-class decision event
(`decisionFacts` via `Events.CommitThenAct`), preserving durable decision evidence a
nil-executor Observe node produces — no durability weakening.

---

## 5. Scope tightening — "no scope = no Shadow"

`SignedConfig.Validate` already requires an **enumerable** scope for Canary/Production
(`config.go:80`) but NOT for Shadow, so a Shadow config with an empty scope validated
and silently behaved as Observe. This phase makes `ModeShadow` **also** require an
enumerable, non-empty scope (`rollout/config.go`): an empty/percentage-only scope for
Shadow is rejected fail-closed at validation. This supports a first activation scoped
to one server + one synthetic principal, and makes "missing scope shadows everything"
structurally impossible (the empty scope matches nothing AND the config is rejected).

Note the `Operations` risk class the scope must admit: `policyOperation`
(`internal/mcp/runtime/policy.go`) classifies EVERY Gateway `tools/call` as the `write`
class (a conservative default until a finer trusted read/write classification ships), so a
Shadow scope intended to evaluate tool calls must admit the write class (`operations: [2]`
on the wire — numeric risk classes: 1=read, 2=write, 3=destructive) with `high_risk: true`;
a read-only scope admits no `tools/call` and records zero Shadow evaluations. Admitting `write` is safe because Shadow performs no upstream side effect
regardless of risk class (Layer B: no upstream client, no materialize-capable broker); the
`HighRisk` gate here selects which calls are EVALUATED, never any that are executed. The
operator runbook (`docs/operator/mcp-shadow-activation.md` §2) carries the concrete scope.

---

## 6. Activation flow (production, after this phase)

```
client → Gateway listener → authn → sender binding → identity → registry/catalog
       → policy → inspection → rollout resolution → ShadowEvaluator
       → CredentialPlanner.Plan → ShadowDecision → durable evidence → response
```

There is NO reachable branch from this flow to `Upstream.Call`, `Broker.Materialize`,
or a live `*Executor`: the ShadowEvaluator holds none of those capabilities (Layer B,
pinned structurally), and `EffectShadowEvaluate` never maps to `EffectExecute`.

Operator action for a controlled activation: (1) run a node with
`CULVERT_MCP_SHADOW_READY=1` (composes the evaluator, arms shadow-deps only), (2)
publish a signed Shadow `SignedConfig` with an explicit bounded enumerable scope via
the existing CP→DP distribution path, (3) the commit gate checks shadow-deps (not
live-exec-deps) + non-empty scope + preflight, (4) rollback to Observe is a signed
Disabled/Observe config (always accepted). See `docs/operator/mcp-shadow-activation.md`.

---

## 7. What stays impossible

Canary and Production remain gated on `liveExecDepsConfigured`, which stays false
(no production caller of `markGatewayExecDepsReady`, pinned by the evolved wall).
Production additionally stays locked behind the absent qualification issuer. Live
execution — `Upstream.Call`, `Broker.Materialize`, a composed `*Executor` — is
composed nowhere in production. This phase makes the Shadow mechanism **complete** and keeps
execution **impossible**.

---

## 8. Prerequisite for reachability: a Usable tool in scope (Codex P1, PR #1234)

The Shadow mechanism is ready, but a MEANINGFUL controlled experiment additionally requires
at least one catalog tool that is `Usable` within the requested scope. `policyOperation`
classifies every Gateway `tools/call` as write, and the policy engine hard-overrides any tool
whose eligibility is not `Usable` (Quarantined / ReviewRequired / ServerDisabled) — so Shadow
would predict `would_fail_hard_control` for all such traffic and never reach `would_execute`,
credential-readiness, or stale-decision predictions. `Usable` is **unreachable through catalog
ingestion** — "approval is a later slice" (`internal/mcp/catalog`) — so no production path
promotes a tool to `Usable` today.

The activation preflight therefore fails closed with `no_usable_shadow_tools` unless the
requested scope targets a `Usable` tool (`shadowScopeHasUsableTool` +
`Scope.AdmitsToolForEvaluation`, a principal-agnostic server/tool/write-class match). This is
deliberate: it never falsely activates an experiment that could only produce hard-control blocks.

Because this precondition is **scope-dependent**, it is split from the scope-independent node
readiness (Codex P2, PR #1234): `evaluateShadowNodeReadiness` checks only node properties
(evaluator composed, no live-exec tier, durable events, policy, inventory, inspection, live
listener, no kill) and is what the operator dry-run (`mcpShadowStatus` → `shadow.preflight`)
reports, while `evaluateShadowActivationPreflight` layers the usable-tool check on top and is
what the CP→DP apply/commit/restore paths use. Folding the usable-tool check into the node
dry-run would make it always report `no_usable_shadow_tools` before the first Observe→Shadow
activation — the active scope is the empty Observe/Disabled scope at that point — so an operator
could never see a healthy node. The apply-time gate is where the candidate scope is known and
where the precondition therefore belongs.

## 8a. Prerequisite for reachability: durable ShadowDecision evidence — SHIPPED (Codex P1, PR #1234; closed by the durable-evidence follow-up)

A real Controlled Shadow activation ALSO requires that the full per-request `ShadowDecision`
is recorded **durably**, not just returned transiently to the client. **This is now shipped**
(branch `claude/mcp-shadow-evidence-v2`): a shadow evaluation persists a `schema_version:2`
event carrying a typed `Event.Shadow *ShadowEvidence` — the enforcement-prediction sub-facts
`Outcome` (`would_execute` / `would_fail_credential_readiness` / `would_fail_stale_decision` /
…), credential-plan status, and request/response inspection readiness — so a per-request
archive row can be reconstructed and correlated, not just counted by the aggregate
`culvert_mcp_shadow_*` metric. The transient JSON-RPC response body (`shadowResult`) and the
durable event derive from ONE mapping (`execution.shadowEvidence(ShadowDecision)`), pinned by a
field-by-field parity gate, so the archived record is fact-for-fact identical to what the client
saw.

The sub-facts are deliberately NOT stamped onto v1 in place — that is why a v2 envelope was
required. A pre-change (v1-only) reader drops unknown JSON fields on unmarshal and recomputes a
different `CanonicalBytes` digest, so `VerifyDigest` would misreport a valid shadow record as
corrupted on a binary rollback (Codex P2, PR #1226). The `schema_version:2` envelope is ADDITIVE
(every non-shadow event stays v1 with a byte-identical digest, proven by golden vectors) and
carries explicit v1/v2 fail-closed recovery: a pre-v2 reader **rejects** a v2 event rather than
misverifying it (`unmarshalEvent` uses `DisallowUnknownFields`), and a v2-capable build reads
both v1 and v2. Tracked as **`SHADOW-EVIDENCE-ROUTING-1`** and delivered as a **dedicated
follow-up PR** (NOT absorbed into the #1234 composition PR and NOT into the tool-approval slice):
the v2 envelope, canonical-digest compatibility, schema/consistency validation, corruption /
fail-closed recovery tests, export round-trip, and proof that the durable record carries the SAME
`ShadowDecision` facts returned to the client. **Binary-downgrade semantics** across persisted v2
evidence are an operator procedure — `docs/operator/mcp-shadow-activation.md` §8 (archive the
Gateway spool, clear the Shadow-bearing `P-ORD` and `P-CRIT` partitions, reset both export
cursors, restart). With this prerequisite closed, the
runbook's evidence-parity / zero-gap exit criteria are now satisfiable; activation still stays
unreachable in production on prerequisite 1 (§8, a usable scoped tool) below.

## 8b. Corrected verdict — TWO hard prerequisites (one now CLOSED, one still OPEN)

**Controlled Shadow activation is NOT activation-ready in production** until BOTH prerequisites
close. Status as of the durable-evidence follow-up:

1. **A usable scoped tool** (§8) — **OPEN**. A catalog tool promoted to `Usable` within the
   requested scope; structurally unsatisfiable until the tool-approval / promotion slice ships,
   so the activation preflight fails closed with `no_usable_shadow_tools`. That slice is separate
   and is NOT delivered by the durable-evidence follow-up.
2. **Durable ShadowDecision evidence** (§8a, the `SHADOW-EVIDENCE-ROUTING-1` durable-envelope
   addendum) — **CLOSED** by the dedicated durable-evidence follow-up (branch
   `claude/mcp-shadow-evidence-v2`): the `schema_version:2` envelope now persists the full
   per-request verdict (typed `Event.Shadow *ShadowEvidence`), the durable record and the client
   response derive from one mapping, v1 digests are byte-identical, and v1/v2 recovery + rollback
   semantics are proven. (Only the addendum closes here; the parent `SHADOW-EVIDENCE-ROUTING-1`
   item — pre-dispatch fail-closed signals not routed into `shadow_evaluated` evidence — is a
   separate LOW-severity item that stays OPEN/deferred, tracked in the debt register.)

These two prerequisites are SEPARATE slices and neither absorbs the other. **No production
Controlled Shadow activation until BOTH close** — prerequisite 1 remains open, so activation stays
unreachable in production, and the runbook's evidence-parity / zero-gap exit criteria are now
satisfiable (prerequisite 2) but not yet reachable (prerequisite 1).
