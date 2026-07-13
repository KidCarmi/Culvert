# ADR-0015: Normal product operation is independent of the TAC Cloud

- **Status:** Proposed (design recorded 2026-07-13; no code moved)
- **Date:** 2026-07-13
- **Deciders:** Principal Supportability Architect (proposed); project maintainer (to ratify)
- **Relates to:** ADR-0012 (cloud-first), ADR-0014 (outbound-only), ADR-0017 (retry/offline). Basis: `docs/support/ANALYSIS-MODEL-DECISION.md §5`, `TAC-CLOUD-ARCHITECTURE.md §10`.

## Context
Cloud-first analysis introduces a cloud dependency for the *support* value-add. It must not leak into the *product*: proxy enforcement, configuration, availability, and health must work with the cloud absent, unreachable, or decommissioned. This mirrors the existing "release management disabled ≠ product broken" and "DP serves last-known-good when CP is down" postures.

## Decision
The TAC Cloud is **strictly optional**. It is never in the traffic path and never required for enforcement, configuration, availability, or normal appliance operation. When the cloud is unavailable:
- Culvert continues operating normally (proxy, config, HA, admin UI unaffected).
- Local health diagnostics (`OperatorContract`) and evidence probes remain available.
- A generated case/bundle remains queued locally; upload retries safely later.
- Offline export remains available.

Enforced by `TestOperationWithoutCloud` (enforcement/config paths make no cloud call) and `TestHealthWithoutCloud` (health + probes answer offline). No cloud call may appear in the proxy request path, config load/reload, or startup-critical wiring.

## Consequences
**Positive:** the cloud can fail, be slow, or be intentionally disabled with zero product impact; air-gapped and cloud-averse customers get the full product; the appliance never blocks on a network the customer may not have.
**Negative:** support diagnosis (not health) is deferred while the cloud is unreachable — the accepted trade for cloud-first (mitigated by local health + offline export).
**Neutral:** the cloud dependency is confined to Tier 2/3 (upload + analysis), never Tier 1.

## Alternatives considered
- **Allow a soft cloud dependency for "enhanced" runtime features.** Rejected: any runtime coupling risks the egress path and violates the appliance promise; enhancements that need the cloud are support features, gated behind opt-in upload, not runtime behavior.
