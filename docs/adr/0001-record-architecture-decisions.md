# ADR-0001: Record architecture decisions

- **Status:** Accepted
- **Date:** 2026-06-28
- **Deciders:** Chief Engineering Advisor (proposed); project maintainer (to ratify)

## Context

Culvert has made many significant, long-lived architecture decisions — the flat `package main`
layout, default-deny policy, the C2 metadata-driven RBAC layer, the `defaultAuthOutcome` contract,
the release-catalog trust scheme, fail-static Data Plane behavior — but **none of them are recorded
as decisions**. They live as code plus prose scattered across `CLAUDE.md` and 65 roadmap documents.

This has two costs:

1. **No rationale memory.** A future maintainer sees *what* the code does but not *why* the choice
   was made, what alternatives were rejected, or what would have to change to revisit it.
2. **Roadmap docs are design plans, not decisions.** They describe intended work; they are not a
   durable, append-only record of accepted trade-offs.

The Engineering Constitution requires ADR enforcement: "Whenever a decision changes long-term
architecture, recommend creating or updating an ADR. Identify architecture decisions that currently
exist only in code."

## Decision

Adopt lightweight Architecture Decision Records.

- ADRs live in `docs/adr/` as `NNNN-title.md`, numbered sequentially, never deleted.
- Each ADR has: **Status** (Proposed → Accepted → Superseded/Deprecated), **Date**, **Context**,
  **Decision**, **Consequences**, and **Alternatives considered**.
- An ADR is required for any change that alters: package/module boundaries, the proxy data path,
  auth/authorization model, the configuration or persistence model, the cluster/HA contract, the
  release/trust pipeline, or any cross-cutting invariant.
- Superseding decisions add a new ADR and flip the old one to **Superseded by ADR-NNNN**; the old
  ADR is kept for history.
- ADRs are referenced from the Risk and Debt registers and the Engineering Dashboard.

**Backfill, incrementally:** existing in-code decisions are captured as ADRs *when they are next
touched or revisited* — not in a big-bang documentation sprint (which would itself be wasteful and
quickly stale). ADR-0002 is the first, capturing the most consequential open decision.

## Consequences

- **Positive:** durable rationale; alternatives are recorded once and not re-litigated; the registers
  gain a stable anchor for architecture items.
- **Cost:** a small per-decision writing overhead. Mitigated by keeping ADRs short (one page).
- **Risk if skipped:** continued erosion — decisions keep being made in code and prose, and the
  "why" is lost as contributors rotate.

## Alternatives considered

- **Keep using roadmap docs.** Rejected: they are forward-looking plans, not an append-only decision
  log, and they are not lifecycle-tracked (Proposed/Accepted/Superseded).
- **Keep decisions in `CLAUDE.md`.** Rejected as the primary home: `CLAUDE.md` is operating guidance
  for contributors and is already very large; mixing decision history into it reduces both. It
  remains the home for *standards*; ADRs are the home for *decisions*.
