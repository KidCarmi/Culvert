> **STATUS: PROPOSED — NOT ADOPTED.** This is an exploratory RFC for a possible cloud/AI/infra-ops direction. It is NOT an accepted architectural decision and is not ratified by merging the appliance support code. Adopting this direction requires a separate, explicitly-recorded architecture + security board decision.
>

# ADR-0012: Cloud-first support analysis (appliance collects; TAC Cloud analyzes)

- **Status:** Proposed (design recorded 2026-07-13; no code moved)
- **Date:** 2026-07-13
- **Deciders:** Principal Supportability Architect (proposed); project maintainer (to ratify)
- **Relates to:** ADR-0019 (bundle framework), ADR-0013 (no local analyzer), ADR-0014 (outbound-only), ADR-0015 (cloud independence). Decision basis: `docs/support/ANALYSIS-MODEL-DECISION.md`.

## Context
The initial supportability design placed timeline construction, incident correlation, and cluster analysis on the appliance. Culvert is an on-prem, egress-critical security appliance whose CPU/memory/disk are sized for the proxy relay hot path, and whose analyzer updates would require signed, digest-pinned releases. A structured comparison of three models (full-local / hybrid / cloud-first) across 17 dimensions scored cloud-first 72 vs hybrid 49 vs full-local 40, dominating hot-path safety, update velocity, version drift, correlation, accuracy, and blast radius.

## Decision
**Analysis is cloud-first.** The appliance's supportability responsibility ends at producing and transmitting an encrypted, redacted, consented evidence bundle. All verification, deterministic analysis, timeline correlation, CP/DP+cluster correlation, known-issue/runbook matching, AI-assisted diagnosis, and TAC workflow execute in the cloud-hosted TAC platform. Locally the appliance retains only (a) the *existing* lightweight health/`OperatorContract` checks (so health survives cloud loss) and (b) active evidence *probes* (`diagnose dns|tls|upstream|storage|policy`) that are impossible from the cloud because of the outbound-only invariant — both of which are collection/health, not analysis.

## Consequences
**Positive:** the appliance stays thin and hot-path-safe; analyzers update by deploying the cloud (no appliance release, no version-drift matrix); correlation and known-issue matching gain the cloud's full corpus and compute; blast radius of a bad analyzer moves off the customer's egress-critical box into an ephemeral cloud sandbox.
**Negative:** analysis value requires an eventual upload (mitigated: local health + offline export + queue/retry); a cloud platform must be built and operated (its complexity is out of the appliance's constrained environment).
**Neutral:** the bundle format (`csb/1`) becomes the stable contract between the two tiers.

## Alternatives considered
- **Full local** — rejected: heaviest CPU/memory/hot-path cost, slowest analyzer velocity, worst version drift and blast radius; only wins offline/privacy, which the invariants mitigate.
- **Hybrid** — rejected: worst-of-both — data leaves *and* local analyzers add surface; a partial local analyzer creates exactly the version-drift and hot-path risks cloud-first removes, for little offline gain.
