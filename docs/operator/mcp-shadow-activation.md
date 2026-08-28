# Runbook — Controlled MCP Shadow Activation

**Status:** PROCEDURE ONLY. This runbook is NOT executed by the Shadow-readiness phase.
Shadow is disabled; no guarded-execution plane is composed; no executor is armed.
**Audience:** MCP gateway operators + the reviewer who authorizes a Shadow activation.
**Authority:** `docs/design/mcp/SHADOW-ARCHITECTURE.md`, ADR-0024.

> Shadow evaluates whether a real request WOULD execute and records durable evidence.
> It never crosses the irreversible side-effect boundary. This runbook describes the
> first, deliberately-tiny controlled activation and how to abort/roll back.

## 0. What must be true in code before this runbook can run at all

Shadow activation is impossible today by construction (all fail-closed):

- No executor is composed in production (`Deps.Executor` nil; AST posture wall).
- The arming hooks `markGatewayExecDepsReady` / `markManagementExecDepsReady` have no
  production caller, so `execDepsConfigured` is false and EVERY transition to
  Shadow/Canary/Production fails closed with `shadow_execution_dependencies_not_configured`.
- Shadow, once composed, routes to the non-executing `EffectShadowEvaluate` disposition
  (`shadowEvaluate`), which holds no path to `Upstream.Call` or credential `Materialize`.

Activating Shadow therefore requires a SEPARATE, explicitly-reviewed composition change
(compose the Shadow evaluator plane, arm exec-deps) that is **out of scope for the
Shadow-readiness phase** and gated on the exit criteria below being green in review.

## 1. Preflight — every condition must be green

- [ ] Controlled host only (one node), out of the production data path or clearly labelled.
- [ ] One controlled MCP server registered; identity pinned; server `Usable`.
- [ ] Synthetic / test principal identity (never a production human/workload).
- [ ] Synthetic / test credential profile pointing at a test secret — never a production secret.
- [ ] Tool allowlist is strict and **read-only**; no destructive/write tool in scope.
- [ ] Bounded request volume (rate-limit the synthetic driver).
- [ ] Rollback path verified (`Shadow → Observe` transition tested on this host).
- [ ] Monitoring dashboard open: the `culvert_mcp_shadow_*` series + health three-state.
- [ ] Evidence collection enabled (event spool healthy; export cursor advancing).
- [ ] `network_position` set correctly if the admission ADR-0033 tier-1 is deployed.
- [ ] Kill-switch reachable and tested on this host.

## 2. Activation

1. Confirm the guarded Shadow plane is composed on this host (the separate reviewed
   change) and `execDepsConfigured` reports ready for Gateway.
2. Transition Gateway rollout `Observe → Shadow`, scoped to the one controlled server and
   the synthetic principal only. Confirm the durable rollout state file records Shadow and
   the evidence window opened once.
3. Drive synthetic read-only traffic at the bounded rate.

## 3. Observation — what to watch

- `culvert_mcp_shadow_evaluations_total` climbs; `..._would_execute_total` /
  `..._would_block_total` split matches the policy you expect.
- **`up.calls`-equivalent: zero real upstream calls.** No egress to the controlled MCP
  server from the Shadow node (verify at the network layer, not just in-process).
- Every evaluation has a durable evidence record (no `..._errors_total` growth, no
  evidence gaps).
- `..._credential_not_ready_total` matches the credential fixtures you staged.
- Shadow latency within budget; no admission saturation.
- Health shows: Observe healthy · Shadow evaluator healthy · **Live execution capability
  unarmed**.

## 4. Abort conditions — trip on ANY of these

- any real upstream side effect observed (network egress to the MCP server)
- any credential materialization attempt (secret fetched/decrypted)
- an evidence gap (an evaluation with no durable record)
- an unexpected `WOULD_EXECUTE` (one that does not map to an allow-class policy decision)
- a stale-decision `WOULD_EXECUTE` (staleness must land as `WOULD_FAIL_STALE_*`)
- event spool failure / durability degraded
- admission saturation
- policy divergence from Observe on the same traffic
- health degradation on this host, or any effect on the Secure Web Gateway data path

## 5. Rollback

Transition Gateway rollout `Shadow → Observe` (immediate; narrowing is always safe). If
in doubt, engage the capability-local kill switch first (stops all admission), then demote.
Confirm the durable state file records Observe/Disabled and no evidence window remains open.
Rollback must be exercised in preflight, not discovered here.

## 6. Do NOT, under any circumstances

- enable Canary or Production
- arm exec-deps beyond the reviewed Shadow-only composition
- point Shadow at a production secret, a production server, or a destructive tool
- let MCP Shadow affect Secure Web Gateway availability
- treat a green Shadow run as authorization for Canary — that is a SEPARATE review gated
  on the exit criteria in `SHADOW-ARCHITECTURE.md` §12
</content>
