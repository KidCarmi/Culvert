> **STATUS: PROPOSED — NOT ADOPTED.** This is an exploratory RFC for a possible cloud/AI/infra-ops direction. It is NOT an accepted architectural decision and is not ratified by merging the appliance support code. Adopting this direction requires a separate, explicitly-recorded architecture + security board decision.
>

# ADR-0019: Claude as conversational operator; Git+IaC authoritative (not the model)

- **Status:** Proposed (design recorded 2026-07-13; no code moved)
- **Date:** 2026-07-13
- **Deciders:** Principal Supportability Architect (proposed); project maintainer/owner (to ratify)
- **Relates to:** ADR-0012 (cloud-first TAC), ADR-0020 (gateway), ADR-0021 (approval), ADR-0022 (durable state). Basis: `docs/support/infra-ops/`.
- **Scope:** the cloud-hosted TAC platform (Tier 3) only — NOT the on-prem appliance (ADR-0014).

## Context
The owner asked whether Claude can be the primary conversational operator for the entire TAC infrastructure lifecycle, with humans supplying connectors/policies/approvals. A model driving raw provider APIs from chat memory would be unauditable, non-repeatable, and catastrophic on error or prompt injection. But a model reasoning over authoritative state and proposing reviewed changes, with deterministic execution and gates, is safe and valuable.

## Decision
Claude is adopted as the **conversational operational interface and reasoning layer** for the TAC cloud, **not** the source of truth or the executor. The authoritative model is: **Git repository → Infrastructure-as-Code (OpenTofu) → reviewed, signed plan → controlled deterministic executor → cloud resources → drift reconciliation.** The conversation is the interface; IaC, the operation-state DB, and provider state are authoritative. Claude autonomously observes (L0), plans (L1), and takes predefined reversible actions (L2); high-impact actions (L3) require human approval and are applied by the deterministic executor, never by the model. Claude holds no desired state in chat memory, no credentials, and no signing keys.

## Consequences
**Positive:** the operator experience (speak → inspect → plan → present impact/rollback → approve → execute → validate → audit) is achievable and safe; the platform stays fully human-operable without AI; correctness/repeatability come from IaC + the executor, not model determinism.
**Negative:** requires building the deterministic spine (ADR-0020/0021/0022) before Claude adds value; some convenience (instant autonomous high-impact change) is deliberately foregone.
**Neutral:** the same interface admits any MCP-capable model or a human CLI — no lock-in to Claude.

## Alternatives considered
- **Claude as source of truth / direct API executor.** Rejected: unauditable, non-repeatable, no drift/rollback, unsafe under injection/error — the exact anti-pattern the task forbids.
- **No AI operator; humans + IaC only.** Viable and is the fallback, but forgoes the acceleration the owner wants; the chosen design keeps that fallback intact.
