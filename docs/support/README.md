# Culvert Supportability Framework (CSF) — Documentation Index

Design-only doc set for an enterprise-grade TAC / support framework. **No implementation yet.**
Read in this order; the vocabulary in `SUPPORTABILITY-ARCHITECTURE.md §0` is normative across all docs.

| # | Document | Purpose |
|---|---|---|
| 0 | [CURRENT-STATE-GAP-ANALYSIS.md](CURRENT-STATE-GAP-ANALYSIS.md) | Evidence-first audit: what exists/reusable/unsafe/missing; maturity score |
| 1 | [SUPPORTABILITY-ARCHITECTURE.md](SUPPORTABILITY-ARCHITECTURE.md) | Top-level target architecture, principles, boundaries, vocabulary |
| 2 | [SUPPORT-BUNDLE-SPEC.md](SUPPORT-BUNDLE-SPEC.md) | `csb/1` bundle format, manifest schema, versioning, integrity, lifecycle |
| 3 | [COLLECTOR-CONTRACT.md](COLLECTOR-CONTRACT.md) | Collector interface, isolation, budgets, gating, test contract |
| 4 | [REDACTION-MODEL.md](REDACTION-MODEL.md) | Data classification, source-side redaction, fail-closed, never-export list |
| 5 | [DIAGNOSTIC-COMMAND-FRAMEWORK.md](DIAGNOSTIC-COMMAND-FRAMEWORK.md) | `culvert support`/`diagnose` verbs, RBAC, no-shell, recovery mode |
| 6 | [HEALTH-AND-EVENT-MODEL.md](HEALTH-AND-EVENT-MODEL.md) | Explainable health (CHR), timeline, incident scopes, debug levels, cluster |
| 7 | [SECURE-UPLOAD-ARCHITECTURE.md](SECURE-UPLOAD-ARCHITECTURE.md) | Offline/online export, recipient encryption, remote support (deferred) |
| 8 | [SUPPORTABILITY-THREAT-MODEL.md](SUPPORTABILITY-THREAT-MODEL.md) | 20 threats × control × test; attack-surface budget |
| 9 | [SUPPORTABILITY-TEST-STRATEGY.md](SUPPORTABILITY-TEST-STRATEGY.md) | Test layers, CI parity walls, the secret-leak gate |
| 10 | [SUPPORTABILITY-ROADMAP.md](SUPPORTABILITY-ROADMAP.md) | M0–M7 milestones + the first recommended slice |

**ADRs:** `docs/adr/0008` (collector model), `0009` (source-side redaction), `0010` (privileged host collection), `0011` (export/consent/remote).

**Verdict:** primitives are strong (2.1/5 overall — see gap analysis); the MVP is a composition problem gated on centralized redaction and an explainable health/timeline model. Build M1 first; do not add a collector before its classification + tests exist.
