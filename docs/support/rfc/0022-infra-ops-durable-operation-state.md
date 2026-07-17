> **STATUS: PROPOSED — NOT ADOPTED.** This is an exploratory RFC for a possible cloud/AI/infra-ops direction. It is NOT an accepted architectural decision and is not ratified by merging the appliance support code. Adopting this direction requires a separate, explicitly-recorded architecture + security board decision.
>

# ADR-0022: Durable operation state outside the conversation (session-loss safety)

- **Status:** Proposed (design recorded 2026-07-13; no code moved)
- **Date:** 2026-07-13
- **Deciders:** Principal Supportability Architect (proposed); project maintainer/owner (to ratify)
- **Relates to:** ADR-0019 (operator model), ADR-0020 (gateway), ADR-0021 (approval). Basis: `docs/support/infra-ops/APPROVAL-STATE-AUDIT.md`.

## Context
A chat session may stop, restart, or lose context; the executor may crash; two sessions may run concurrently. If any infrastructure state lived in the conversation, a lost session would orphan or corrupt in-flight changes. Claude must be able to reconnect and ask "what happened to operation INFRA-2026-0042?" without depending on chat memory.

## Decision
Every mutating operation is a **durable record in an operation-state DB**, keyed by a stable operation ID (`INFRA-YYYY-NNNN`), holding: desired_state (plan_id/diff_hash/git_ref), execution_state (state-machine phase), approval_state (required/collected, single/dual, review-agent verdict), class, reversibility, lease (holder/TTL/heartbeat), idempotency_key, attempts, result, and audit_ref. Guarantees: **exactly-once apply** per idempotency_key; **leases + heartbeats** so an executor crash → lease expiry → deterministic reconciler resolves PARTIAL from provider truth (never half-applied silently); **cooperative cancellation**; **persisted signed results** so `get_deployment_status(op_id)` fully answers "what happened?" with zero chat memory; **recovery after restart** of Claude (re-read by op_id) or the executor (reconciler resumes); **per-environment apply lease** so concurrent sessions cannot double-apply. Claude is stateless with respect to infrastructure — killable and restartable at any point with no loss.

## Consequences
**Positive:** session loss, model restart, executor crash, dropped responses, and concurrent operators are all non-events for correctness; every operation is resumable and auditable by ID; idempotency prevents duplicate applies.
**Negative:** requires a durable state store + reconciler + lease infrastructure before any mutating connector (part of the G0 spine).
**Neutral:** mirrors Culvert's own durable-state patterns (DP last-known-good, config-version floors, op-ID + single-flight in the maintenance agent).

## Alternatives considered
- **Keep operation state in the conversation.** Rejected outright: a lost session would orphan in-flight infrastructure changes — the exact failure the task requires designing against.
- **Fire-and-forget applies without leases/reconciliation.** Rejected: an executor crash would leave infrastructure in an unknown half-applied state with no deterministic recovery.
