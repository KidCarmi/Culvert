# MCP qualification policy (QUAL-4, Gateway Observe)

This is the node-local Gateway **Observe** policy source. When configured, an
authenticated Gateway request is EVALUATED against a real compiled policy snapshot and
the true decision is recorded as durable evidence. It is evaluation and evidence only:
nothing executes, nothing is enforced, and nothing is published to a fleet.

QUAL-4 composes ONLY the policy provider. It is disabled by default: with no
`qualification_policy_file`, behavior is byte-identical to QUAL-3 (no snapshot; decision
telemetry stays `pending_policy`).

## What it does

- Compiles a static, node-local policy source ONCE at startup through the existing
  policy compiler and limits (the same compiler the admin simulator and the four-eyes
  publication workflow use), then publishes it as the node-local **active Observe
  evaluation snapshot** into the same capability-local policy store the read-only Policy
  Admin API and simulator read. There is exactly one compiled snapshot (single source of
  truth): the runtime evaluator, `GET /api/mcp/policy`, the simulator Compare baseline,
  and the decision-evidence snapshot hash all agree.
- Evaluates every authenticated decision-point request (`tools/list`, `tools/call`)
  against that snapshot and records the true action, matched rule, reason, obligations,
  policy revision, and snapshot hash.

## What it does NOT do

- It does not execute. No executor, upstream client, or credential broker is composed.
  An evaluated ALLOW returns `execution_state = not_implemented`; no credential is
  selected or materialized and no side effect runs.
- It does not enforce. This is Observe (evaluate and record), never enforcement rollout,
  never Shadow, Canary, or Production.
- It is not fleet policy. The snapshot is node-local. It is never labeled published,
  approved, fleet-effective, or distributed, and it never bypasses or weakens the
  existing four-eyes publication workflow. The candidate / validate / publication-request
  workflow remains fully separate and intact.

## The load-bearing Observe invariant

> evaluated policy action != effective execution authorization

The evaluated action (e.g. ALLOW) and the effective execution state (always
`not_implemented` in Observe) are recorded as distinct facts on every decision event.
An evaluated ALLOW is evidence a future execution stage MAY proceed, never an execution.

## Configuration

```yaml
mcp:
  gateway:
    enabled: true
    # ... TLS / OAuth / inventory / telemetry as in QUAL-1..QUAL-3 ...
    qualification_policy_file: "/etc/culvert/mcp/gateway-policy.json"
```

Startup-only and node-local: no hot reload, no admin upload, no CLI or environment
policy body. The file must be the existing accepted Gateway policy source format:

```json
{
  "schema_version": 1,
  "capability": "gateway",
  "policy_revision": 1,
  "default_action": "DENY",
  "rules": [
    {
      "id": "ALLOW_DISCOVERY",
      "priority": 10,
      "action": "ALLOW",
      "reason": "MCP.POLICY.RESOURCE_SCOPE",
      "remediation": "none",
      "conditions": [{"field": "operation.method", "op": "exact", "value": "tools/list"}],
      "obligations": {"logging": "standard"}
    }
  ]
}
```

- `capability` MUST be `gateway`. A `management` (or unset) capability fails closed - the
  Management surface can never be armed from this source.
- `default_action` MUST be `DENY` (Zero Trust default deny).
- No secret material may appear in this file.

## Load and failure behavior

Loading is atomic: read (bounded to 8 MiB, path-traversal rejected) -> compile (existing
compiler, full validation: duplicate rule ids, duplicate priorities, unknown fields, and
one bad rule all reject the WHOLE snapshot) -> verify capability -> publish into the
store.

- **Absent** -> QUAL-3 behavior preserved: no snapshot, decision telemetry
  `pending_policy`.
- **Present and valid** -> the snapshot is the active Observe evaluation snapshot.
- **Present and invalid** -> activation FAILS CLOSED: the listener does not bind, no
  partial snapshot is installed, and a bounded, secret-free reason is surfaced
  (`qualification_policy_unreadable` / `_oversize` / `_traversal` / `_empty` /
  `_uncompilable` / `_wrong_capability`). The Secure Web Gateway is unaffected.

## Decision telemetry and evidence

`decision_telemetry` on `GET /api/mcp/overview` is truthful:

- `pending_policy` - no policy composed (QUAL-3 default; only the denial lane commits).
- `pending_telemetry` - a policy is composed but durable telemetry is not, so decisions
  are evaluated but not durably recorded.
- `ready` - a policy snapshot is composed AND durable telemetry is active, so evaluated
  decisions are durably committed.

Per the accepted event model, an ALLOW-class decision commits a full decision event
(readable via `GET /api/mcp/decisions` and the Activity view); an authenticated
authorization denial (DENY / QUARANTINE / REQUIRE_*) travels the isolated denial lane as
a counted aggregate WITH the authenticated identity. Historical explanations use only the
persisted fields and are never re-evaluated against the current policy.

Tenant attribution is always the authenticated tenant from the validated token; a client
route or query value can never replace it.

## Admin surface

- `GET /api/mcp/policy?capability=gateway` - the active snapshot summary (revision, hash,
  rule count, default action, `distribution_state = local_only`).
- `GET /api/mcp/overview` - the node-local Observe posture under `policy` (state, source
  `qualification_startup`, revision, hash, rule count, default action, `evaluation_enabled`,
  `enforcement_enabled = false`, `execution_enabled = false`, `fleet_distributed = false`)
  and `telemetry.decision_telemetry`.
- The MCP Policy and Simulator panel renders the active snapshot plus the node-local
  Observe posture, and keeps active / candidate / validated / publication-request /
  published-or-fleet states distinct.

Startup loading is not an admin mutation; there is no admin action that installs or
activates the qualification policy.

## Known remaining blocker (report, do not work around)

Every tool seeded by the QUAL-2 qualification inventory is `Quarantined`, and a
quarantined tool's `tools/call` is hard-QUARANTINEd by the fixed override layer BEFORE any
user rule is consulted. There is currently no catalog promotion path to `Usable`. So:

- `tools/list` (discovery) reaches user-rule evaluation and produces ALLOW-class decision
  evidence.
- `tools/call` on a seeded tool always records a truthful hard-override QUARANTINE and can
  NOT exercise a user ALLOW rule.

QUAL-4 preserves this hard override and records it truthfully; it does NOT force-promote or
auto-approve tools. Exercising user `tools/call` ALLOW rules requires a future
catalog-promotion slice and is an explicit remaining blocker before Observe qualification.
