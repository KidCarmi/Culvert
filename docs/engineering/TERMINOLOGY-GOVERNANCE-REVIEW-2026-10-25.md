# Culvert Language & Terminology Governance Review — 2026-10-25

> **Status:** Point-in-time review. **Window:** `a27cffb..4c8601d9` (first-parent merges since the
> 2026-10-24 report). Sweep covered added metric names, audit/log tokens, JSON keys, env vars and
> operator docs in non-test code.

## Executive Summary

One production-worthy finding (T-68, Low), fixed in this PR. It touches a surface that is still
`[Unreleased]` (no tag contains it), so no deprecated alias is needed.

Terminology Health Score: 96/100 (one intra-family split, now closed).

## T-68 — "refused" vs "rejected" for session revocation refusals (Low)

| Field | Value |
|---|---|
| Business concept | A session-revocation entry that the appliance declines to retain |
| Current names | `culvert_session_revoke_refused_total` (unlabeled; unverifiable logout cookies only) and `culvert_session_revoke_rejected_total{reason}` (all refusals); code, runbook and log line all say "refused" (`session.Refused`, `SESSION_REVOKE_REFUSED`) |
| Canonical name | Labeled family **`culvert_session_revoke_refused_total{reason}`**; the unlabeled subset becomes **`culvert_session_revoke_unverifiable_total`** |
| Problem | Two sibling counters in one plane differed by a near-synonym yet had different scope, so an operator could not tell which one to alert on. The metric used "rejected" while every other surface (Go API, log token, runbook, changelog) used "refused". |
| Why better | One verb for the concept; the subset is named for what it is (cookie this appliance could not verify), matching its HELP text. |
| Affected | `events.go`, `docs/operator/session-revocation-plane.md`, `CHANGELOG.md` (Unreleased). Roadmap prose is historical and unchanged. No GUI, OpenAPI or config key. |
| Migration / compat risk | None for released builds; names have not shipped. |
| PR size | XS |

Not changed: `SESSION_REVOKE_REFUSED` log token and `sessionRevokeRefused` (internal) keep their names;
`refused` vs `rejected` elsewhere in the repo (e.g. `culvert_ocsp_response_rejected_total`) are not
sibling-pairs for one concept and are shipped, so they are not renamed for uniformity.

## Other sections

- Checked and consistent: `culvert_audit_cluster_push_drops_total` / `audit_cluster_push_drops`,
  `culvert_cluster_revocation_drops_total`, `culvert_cdr_*` family, `culvert_proxy_oversize_host_rejected_total`.
- Open prior items (T-11, T-12, T-29/T-30, T-54) not re-audited here.
- Priority: Critical none · High none · Medium none · Low T-68 (fixed).
