> **STATUS: PROPOSED — NOT ADOPTED.** This is an exploratory RFC for a possible cloud/AI/infra-ops direction. It is NOT an accepted architectural decision and is not ratified by merging the appliance support code. Adopting this direction requires a separate, explicitly-recorded architecture + security board decision.
>

# ADR-0021: Four operating levels; dual approval for high-blast production actions

- **Status:** Proposed (design recorded 2026-07-13; no code moved)
- **Date:** 2026-07-13
- **Deciders:** Principal Supportability Architect (proposed); project maintainer/owner (to ratify)
- **Relates to:** ADR-0019 (operator model), ADR-0020 (gateway). Basis: `docs/support/infra-ops/APPROVAL-STATE-AUDIT.md`.

## Context
Autonomy must scale with reversibility and blast radius. Reads and reversible bounded actions are safe to automate; production changes and irreversible/data/security actions need human authority, and the highest-blast ones need more than one human.

## Decision
Adopt four operating levels enforced by the gateway policy engine:
- **L0 Observe** — reads/reports/drift; autonomous.
- **L1 Plan** — plans + impact + rollback; autonomous; executes nothing.
- **L2 Safe autonomous action** — a **fixed allowlist** of typed, bounded, idempotent, reversible, audited actions (retry job, recover expired lease, restart stateless worker, clear temp cache, pause failing consumer, disable uploads at hard quota); autonomous. An action qualifies for L2 only if reversible by construction and unable to affect data/cost/security; Claude cannot promote an action into L2.
- **L3 Explicit approval** — production deploy, DNS, IAM, DB migration, data deletion, secret rotation, backup restore, retention change, enabling raw-evidence access, security-policy change, infra destruction, paid-resource activation. Claude *requests*; a human approves; the deterministic executor applies.

**Dual approval (two distinct humans, four-eyes) is required in production** for: infrastructure destruction/teardown, data deletion and retention reduction, prod DB migration, IAM change, backup restoration over live/newer data, tenant/root-KMS rotation, enabling raw-evidence access, and any weakening of a security control or audit. The approver is never the plan's author (agent or human). Every level/scope/approval decision is enforced structurally and audited.

## Consequences
**Positive:** autonomy is maximized where safe and gated where not; the highest-blast actions cannot be cleared by a single person or a single agent; the boundary is explicit and testable.
**Negative:** L3/dual introduces human latency on high-impact changes — the intended safety cost.
**Neutral:** the L2 allowlist is small by design and grows only by ADR amendment + evidence of reversibility.

## Alternatives considered
- **Single approval for everything.** Rejected: a single mistaken/compromised approver could authorize irreversible data loss or destruction.
- **Model-judged risk levels.** Rejected: the level of an action must be a deterministic policy attribute, not a model inference, or injection/error could downgrade a destructive action.
