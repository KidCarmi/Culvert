# ADR-0013: No full local analyzer framework, known-issue DB, or local AI on the appliance

- **Status:** Proposed (design recorded 2026-07-13; no code moved)
- **Date:** 2026-07-13
- **Deciders:** Principal Supportability Architect (proposed); project maintainer (to ratify)
- **Relates to:** ADR-0012 (cloud-first). Basis: `docs/support/ANALYSIS-MODEL-DECISION.md §4`.

## Context
Cloud-first analysis (ADR-0012) still leaves a scoping question: how much analysis, if any, may run locally? A repository evidence review found no case requiring a local analyzer framework. A local known-issue database would require signed appliance releases to update (the release-catalog trust chain is deliberately heavy); local heavy log correlation is bounded by the 500-entry audit ring and 60-minute metric ring; local AI would enlarge the image and attack surface next to the relay hot path.

## Decision
The appliance MUST NOT contain: a full analyzer framework, a local known-issue database, local runbook search, heavy log correlation, incident clustering, case management, email processing, SLA processing, or local AI. Those belong in the TAC Cloud. The appliance keeps ONLY: lightweight health/`OperatorContract`, collector execution, evidence scope/time-range selection, source-side redaction + DataClass parity, privacy preview, consent, manifest + integrity, encryption, bounded resource budgets, local retention, resumable upload/retry, offline export, and immutable local audit — plus the network-position-bound evidence *probes* that only the appliance can run (classified as collection, not analysis).

A fitness test (`TestNoLocalAnalyzer`) asserts `internal/support` ships no analyzer engine, knowledge-base store, or model, and that its collectors produce evidence, not diagnoses.

## Consequences
**Positive:** the appliance's support surface stays minimal and reviewable; no analyzer-versioning burden on-box; the hot path is protected; the security blast radius of analysis stays in the cloud.
**Negative:** the appliance cannot answer "what is wrong and why" fully by itself — it answers health/posture locally and defers diagnosis to the cloud (acceptable given local health remains and offline export exists).
**Neutral:** future "should this specific check run locally" proposals require fresh evidence and an ADR amendment, not a default.

## Alternatives considered
- **Bake a small known-issue DB for common cases.** Rejected: updating it means a signed release; it forks per appliance version; the cloud does this better with cross-fleet data.
- **Local AI for offline hints.** Rejected: image size, attack surface, and hot-path risk on a security appliance outweigh the offline convenience; offline export + local health cover the offline need.
