# Culvert Supportability Framework (CSF) — Documentation Index

Doc set for an enterprise-grade TAC / support framework. **The appliance track
(M0–M5) is implemented** — support bundles, redaction, plugin collectors,
`diagnose`/incident-scope verbs, encrypted + sealed export, and HA/recovery
diagnostics all ship in the binary today; see
`docs/operator/support-bundles-and-diagnostics.md` for the live operator
runbook. The cloud track (M6 upload, M7 proactive/telemetry, and the
`TAC-CLOUD-ARCHITECTURE.md` tier) remains design-only. See
`SUPPORTABILITY-ROADMAP.md` for per-milestone shipped/design status.
Read in this order; the vocabulary in `SUPPORTABILITY-ARCHITECTURE.md §0` is normative across all docs.

> **Model: cloud-first (REVISION 2, 2026-07-13).** Three tiers — **(1) On-Prem Culvert Product** (self-sufficient; never depends on the cloud), **(2) Optional Outbound Support Integration** (collect→redact→consent→encrypt→upload, outbound-only), **(3) Cloud-Hosted TAC Operating System** (all analysis, correlation, known-issue matching, AI, workflow). The appliance collects and transmits evidence; it does **not** analyze. See `ANALYSIS-MODEL-DECISION.md` for the 3-model comparison and `TAC-CLOUD-ARCHITECTURE.md` for the cloud tier.

| # | Document | Purpose |
|---|---|---|
| 0 | [CURRENT-STATE-GAP-ANALYSIS.md](CURRENT-STATE-GAP-ANALYSIS.md) | Evidence-first audit: what exists/reusable/unsafe/missing; maturity score |
| 1 | [ANALYSIS-MODEL-DECISION.md](ANALYSIS-MODEL-DECISION.md) | **Local vs hybrid vs cloud-first — decision matrix (17 dims), recommendation, revised scenarios** |
| 2 | [SUPPORTABILITY-ARCHITECTURE.md](SUPPORTABILITY-ARCHITECTURE.md) | Top-level architecture, the three tiers, principles, boundaries, vocabulary |
| 3 | [TAC-CLOUD-ARCHITECTURE.md](TAC-CLOUD-ARCHITECTURE.md) | **Cloud OS: ingestion, sandbox, workers/budgets, raw-vs-normalized, AI boundary, entitlement, E2E sequences** |
| 4 | [SECURE-UPLOAD-ARCHITECTURE.md](SECURE-UPLOAD-ARCHITECTURE.md) | Tier-2 outbound integration: protocol, consent, encryption trust, retry/queue, air-gap, appliance budgets |
| 5 | [SUPPORT-BUNDLE-SPEC.md](SUPPORT-BUNDLE-SPEC.md) | `csb/1` bundle format, manifest schema, versioning, integrity, lifecycle |
| 6 | [COLLECTOR-CONTRACT.md](COLLECTOR-CONTRACT.md) | Collector interface, isolation, budgets, gating, test contract |
| 7 | [REDACTION-MODEL.md](REDACTION-MODEL.md) | Data classification, source-side redaction, fail-closed, never-export list |
| 8 | [DIAGNOSTIC-COMMAND-FRAMEWORK.md](DIAGNOSTIC-COMMAND-FRAMEWORK.md) | `culvert support`/`diagnose` verbs, RBAC, no-shell, recovery mode |
| 9 | [HEALTH-AND-EVENT-MODEL.md](HEALTH-AND-EVENT-MODEL.md) | Health (CHR) + collection halves local; timeline/correlation/cluster analysis re-homed to cloud |
| 10 | [SUPPORTABILITY-THREAT-MODEL.md](SUPPORTABILITY-THREAT-MODEL.md) | Appliance + cloud threats × control × test; attack-surface budget |
| 11 | [SUPPORTABILITY-TEST-STRATEGY.md](SUPPORTABILITY-TEST-STRATEGY.md) | Test layers, CI parity walls, the secret-leak gate |
| 12 | [SUPPORTABILITY-ROADMAP.md](SUPPORTABILITY-ROADMAP.md) | Appliance track + cloud track milestones + the first recommended slice |

**ADRs:** `0008` collector model · `0009` source-side redaction · `0010` privileged host collection · `0011` export/consent/remote · `0012` cloud-first analysis · `0013` no local analyzer framework · `0014` outbound-only integration · `0015` cloud independence · `0016` raw vs normalized · `0017` local retry/offline export · `0018` AI receives normalized evidence.

**Verdict:** primitives are strong (2.1/5 overall — see gap analysis). Cloud-first wins the analysis-location decision decisively (72 vs 49 vs 40). Build the appliance track first (redaction wall → minimal bundle → encrypt → outbound upload/export); the cloud track is built in parallel. Do not add a collector before its classification + tests exist; do not begin implementation until the local/cloud responsibility split is confirmed.
