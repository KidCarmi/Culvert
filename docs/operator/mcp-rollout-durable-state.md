# MCP rollout durable state and Shadow transition mechanics

This document describes the node-local durable rollout state added to close the
mechanical blockers found by the Shadow Readiness Decision (B-MECH-1/2/3). It is an
implementation/operator reference, not an authorization to begin Shadow. Real Shadow
still requires a stable host, a real immutable scope, guarded execution plus
credential containment, decision-parity evidence, sustained monitoring, named
ownership/on-call, and fresh identity material.

## What changed

Before this change the MCP rollout mode, kill-switch state, and the continuous
evidence window lived only in process memory. A restart reset them silently, so any
claimed continuous Shadow window was mechanically invalid, and no transition ever
started the evidence window. This change wires:

1. Restart-durable rollout state. Each capability (Gateway, Management) persists a
   versioned, atomically-written, 0600 JSON file under the data directory
   (`mcp_rollout_state_gateway.json`, `mcp_rollout_state_management.json`). The file
   carries only node-local mode/scope-config/kill-switch/evidence/history. It never
   contains a bearer token, credential, private key, policy argument, or request
   payload.
2. Evidence-window coupling. An accepted transition stamps the Shadow/Canary/soak
   window exactly once per mode entry (a continuous window is preserved across an
   idempotent re-apply of the same mode; a demotion resets it).
3. A fail-closed execution-dependency precondition. A transition to an executing mode
   (Shadow, Canary, Production) is rejected unless the guarded-execution plane is
   composed. The shipped Observe-only build composes none, so an attempted Shadow
   transition fails closed.

## Durable-transition contract

Every accepted rollout transition runs through one commit path with this ordering:

1. Execution-dependency precondition. An executing target mode is rejected with
   `shadow_execution_dependencies_not_configured` unless the capability's
   guarded-execution plane is registered. No partial Shadow state is ever created.
2. Atomic in-memory install of the signed config (mode/scope authoritative).
3. Scope-change continuity. A material scope change while staying in the same
   executing mode resets the continuous window; a newly expanded scope can never
   inherit time accrued under the previous scope.
4. Evidence-window coupling (idempotent per mode).
5. Restart-durable persistence before acknowledgement. If the state cannot be
   persisted the transition is rolled back in memory and rejected. No
   externally-acknowledged transition ever exists only in memory.

## Restart recovery

At startup each capability restores its durable state:

- A missing file is a genuinely new state and keeps the safe Disabled default.
- A present file is validated and re-compiled; the recovered mode and the exact
  original window-start timestamps are restored, so elapsed time continues from the
  original start rather than the restart.
- A corrupt or invalid file fails closed to Disabled. It never silently restores a
  more permissive mode.

The kill switch is restart-durable: an emergency disable survives a restart so a
restart cannot silently re-admit traffic an operator disabled.

## Operator transition path

The signed CP to DP distribution path is the only path that installs an executing
mode; it remains signed, revisioned, and capability-isolated. The authenticated Admin
transition endpoint (`POST /api/mcp/rollout/transition`) is truthful about why a
transition cannot proceed in the current posture:

- Production is always rejected with `rollout_production_locked` (403). This build
  ships no qualification issuer.
- An executing target (Shadow, Canary) returns
  `shadow_execution_dependencies_not_configured` (409) when the guarded-execution
  plane is not composed. This is the real blocker and is surfaced before any
  distribution concern.
- A non-executing target returns `distribution_not_configured` (409) when the signed
  distribution path is not wired.

## Admin status observability

`GET /api/mcp/rollout` reports, per capability and without secrets: mode, desired
mode, scope hash and revision, kill-switch state, connector mode, evidence origin,
Shadow/Canary/soak start timestamps, rollback-rehearsed flag, and a persistence field
that distinguishes `fresh` (no durable file yet), `recovered` (restored from disk),
`degraded` (corrupt or invalid, kept Disabled), and `write_failed`. Production stays
reported as locked. `GET /api/mcp/rollout/evidence` reports the measured window
elapsed times and the synthetic-versus-production origin label; a synthetic
injected-clock figure is never reported as production evidence.

## Still required before Shadow (not delivered here)

This change fixes rollout transport, persistence, and evidence-window mechanics only.
It does not enable execution and does not authorize Shadow. Before a real Shadow
phase can begin, separate work must provide: a stable host for the full continuous
window, an operator-approved immutable real-traffic scope, the composed
guarded-execution plane with credential containment, decision-parity evidence,
sustained monitoring with a real alert destination, named ownership and on-call, and
fresh identity material covering the window plus margin.
