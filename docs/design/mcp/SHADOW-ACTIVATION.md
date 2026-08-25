# Controlled Shadow Activation — Dependency Graph & Design

Status: **design + implementation** (phase "Controlled Shadow Activation Preparation").
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

Disabled by default: composition happens ONLY when the operator explicitly enables
Shadow readiness (`CULVERT_MCP_SHADOW_READY`, off by default). Unset ⇒ `Deps.Executor`
stays nil ⇒ byte-identical Observe/SWG path.

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
Shadow is rejected fail-closed at validation. Combined with the existing `HighRisk`
gate and read-only-by-default `Operations`, this supports a first activation scoped
to one server + synthetic principal + read-only tools, and makes "missing scope
shadows everything" structurally impossible (the empty scope matches nothing AND the
config is rejected).

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
composed nowhere in production. This phase makes Shadow **activatable** and keeps
execution **impossible**.
