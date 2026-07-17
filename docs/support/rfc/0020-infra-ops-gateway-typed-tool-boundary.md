> **STATUS: PROPOSED — NOT ADOPTED.** This is an exploratory RFC for a possible cloud/AI/infra-ops direction. It is NOT an accepted architectural decision and is not ratified by merging the appliance support code. Adopting this direction requires a separate, explicitly-recorded architecture + security board decision.
>

# ADR-0020: Infrastructure Operations Gateway — narrow typed-tool boundary, no raw provider access

- **Status:** Proposed (design recorded 2026-07-13; no code moved)
- **Date:** 2026-07-13
- **Deciders:** Principal Supportability Architect (proposed); project maintainer/owner (to ratify)
- **Relates to:** ADR-0019 (operator model), ADR-0021 (approval), ADR-0022 (state). Basis: `docs/support/infra-ops/MCP-GATEWAY.md`.

## Context
Giving Claude direct access to every provider (or a shell/SQL/file/SSH escape hatch) makes the model's entire reasoning surface an attack surface and defeats auditability and least privilege. The task requires narrow, business-level operations and explicitly rejects arbitrary shell/SQL/provider/secret/file tools.

## Decision
Claude reaches the TAC platform **only** through the **Culvert Infrastructure Operations Gateway** — a deterministic MCP (typed-tool) service exposing a **fixed catalog of narrow, business-level operations** (`get_platform_health`, `plan_environment_deployment`, `apply_approved_plan`, `restart_stateless_worker`, `rotate_scoped_identity`, `detect_infrastructure_drift`, …). Every call is schema-validated → authenticated → authorized (policy engine: level + environment/tenant scope + least privilege) → rate-limited → op-tracked → executed by a scoped connector → audited. The following are **never** in the catalog and are fitness-tested absent: `run_arbitrary_shell`, `execute_arbitrary_sql`, `call_arbitrary_provider_api`, `ssh_as_root`, `read_arbitrary_secret`, `write_arbitrary_file`, `mint_long_lived_key`, `approve_own_plan`, and any free-form command/SQL/path/secret parameter. The gateway returns **secret identifiers and results, never credential values**; the identity broker mints short-lived, workload-identity (OIDC) scoped creds per operation — no persistent admin keys. Each connector has a mandatory security spec (purpose/allowed/denied/auth/identity/scope/lifetime/audit/timeout/idempotency/rate-limit/retry/rollback/approval/injection-exposure) and a conformance test harness before registration.

## Consequences
**Positive:** the attack surface is the fixed tool catalog, not the model's imagination; least privilege + short-lived creds bound any compromise; prompt injection can at most cause a *proposed* plan a human rejects; portable to any MCP model or human CLI.
**Negative:** every new capability is a deliberate, spec'd, tested connector — slower than handing over an API key, by design.
**Neutral:** mirrors Culvert's existing fixed-registry discipline (`uiRoutes`, the maintenance-agent argv registry).

## Alternatives considered
- **Broad provider API access with policy filtering.** Rejected: a filter over a broad surface is fail-open and unauditable; a narrow allowlist is fail-closed.
- **A general `run_command` with an allowlist.** Rejected: allowlisted free-form strings are brittle; typed business operations are the safe form.
