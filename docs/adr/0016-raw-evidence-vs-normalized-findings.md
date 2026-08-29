# ADR-0016: Separate raw evidence from normalized findings; short raw retention

- **Status:** Proposed (design recorded 2026-07-13; no code moved)
- **Date:** 2026-07-13
- **Deciders:** Principal Supportability Architect (proposed); project maintainer (to ratify)
- **Relates to:** ADR-0012 (cloud-first), ADR-0036 (AI input), ADR-0029 (redaction). Basis: `docs/support/TAC-CLOUD-ARCHITECTURE.md §3-4`.

## Context
An uploaded bundle is redacted + E2E-encrypted, but it is still the most sensitive artifact the platform holds: customer configuration, hostnames, masked identities, logs. TAC engineers and AI need *diagnosis*, not the raw bundle. Mixing raw bundles with derived findings in one store, or granting standing access to raw, maximizes exposure.

## Decision
The TAC Cloud keeps **two physically separate planes**:
1. **Raw evidence store** — uploaded bundles exactly as received (appliance-redacted + E2E-encrypted, re-encrypted at rest under a per-case data key). **No standing human access.** Read only by ephemeral, network-isolated **sandbox extract workers** and by audited, dual-control **exceptional (break-glass) access**. **Short retention** (e.g. 30 days default, contractually adjustable), then hard-deleted.
2. **Normalized findings store** — typed `Finding` records, timeline, correlations, known-issue matches, and evidence *excerpts approved for reuse*. This is what TAC and AI work from; longer (case-lifetime) retention.

Extraction happens once, in the sandbox, producing findings; TAC/AI never touch raw by default.

## Consequences
**Positive:** the blast radius of the raw plane is minimized (sandbox-only reads, short retention, no standing access); day-to-day TAC and AI operate on lower-sensitivity findings; deletion of raw is bounded and provable.
**Negative:** re-analysis after raw deletion requires a fresh bundle (acceptable; findings persist); two stores + a per-case key lifecycle to operate.
**Neutral:** the appliance is unaffected — it only ever produces the raw bundle.

## Alternatives considered
- **Single store, RBAC-gated raw access.** Rejected: standing human access to raw bundles is the exposure we are eliminating; RBAC is weaker than sandbox-only + break-glass.
- **Long raw retention for convenience.** Rejected: raw is the highest-sensitivity artifact; short retention + persistent findings is the safer default, extended only by contract.
