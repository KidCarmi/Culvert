# Culvert Language & Terminology Governance Review — 2026-10-26

> **Status:** Point-in-time review. **Window:** changes merged after the 2026-10-24 report
> (session-revocation plane, retained-path bounds, OCSP coverage, access-list diagnostics, DP bootstrap).

## Executive Summary

One production-worthy finding, documentation-only: the canonical glossary contradicts established usage of
"appliance". No identifier, API, metric or configuration rename is recommended.

Terminology Health Score: 95/100 (96 → 95; one glossary/usage conflict, resolved by this change).

## Finding F-1 — "Appliance" is recorded as unused but is established vocabulary (Medium)

| Field | Detail |
|---|---|
| Business Concept | One deployed Culvert system, as an operator addresses it |
| Current Names | `docs/design/PRODUCT-TERMINOLOGY.md`: "*Not used* — the UI says node or instance". Actual use: legacy GUI (27 occurrences in `static/index.html`, e.g. "restart the appliance", "This appliance authenticates…"), 23 operator runbooks, `/metrics` HELP text (`culvert_session_revoke_*`), `CONTRACTS-OWNERSHIP.md`, ~300 Go comments |
| Recommended Canonical Name | Keep **Appliance** (single deployed system) and **Node** (enrolled cluster member, `EnrolledNode`). Amend the glossary row; do not rename usage |
| Why current naming is problematic | A writer following the glossary would avoid the word and introduce "instance"/"host" synonyms, creating the drift the glossary exists to prevent; new text (e.g. `session-revocation-plane.md`) already follows real usage and so "violates" the glossary |
| Why the new wording is better | Records the real boundary: Appliance = the system an operator is on; Node = a member as seen from the Control Plane/fleet |
| Affected Code / API / GUI / Config | None changed |
| Affected Documentation | `docs/design/PRODUCT-TERMINOLOGY.md` (one row) |
| Migration Complexity | Trivial |
| Compatibility Risk | None |
| Estimated PR Size | 1 line + this report |

## Observed, no action

- `culvert_session_revoke_refused_total` and `culvert_session_revoke_rejected_total{reason}` coexist: the first
  counts logout cookies that fail verification, a subset of `rejected{unsigned,malformed}`; the second also
  covers untrusted-origin paths. The refused/rejected/dropped split is a repo-wide metric convention
  (`*_refused_total` = turned away before retention, `*_rejected_total` = failed validation, `*_drops_total` =
  lost), and `docs/operator/session-revocation-plane.md` documents the difference. Renaming shipped metric
  names has real dashboard cost and no clarity gain beyond the existing documentation.
- Other new surfaces (`culvert_retained_path_truncated_total`, `culvert_cluster_revocation_drops_total`,
  CDR fail-mode terms) follow existing families.

## Priority

Critical none · High none · Medium F-1 (applied) · Low none.
