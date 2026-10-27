# Culvert Language & Terminology Governance Review — 2026-10-25

> **Status:** Point-in-time review. **Window:** `a27cffb..4c8601d9` (first-parent merges since the
> 2026-10-24 report). Sweep covered added metric names, audit/log tokens, JSON keys, env vars and
> operator docs in non-test code.
>
> **Finding ID.** This report was drafted as T-68. Main already assigns T-68 (2026-10-17 report) and
> T-69 (2026-10-02 report), so the finding is renumbered **T-70**.

## Executive Summary

One production-worthy finding (T-70, Low), fixed in this PR with the released names kept as deprecated
aliases. The draft of this report said the names were `[Unreleased]`; that was wrong. Both shipped in
v1.0.340 (commit `0c8b548f2`, CHAOS-73), so the fix is additive: brand-new canonical names, and the
released names keep emitting unchanged until v1.1.0.

Terminology Health Score: 96/100 (one intra-family split, closed by new names; the deprecated aliases
are a recorded, time-boxed exception).

## T-70 — "refused" vs "rejected" for session revocation refusals (Low)

| Field | Value |
|---|---|
| Business concept | A session-revocation entry that the appliance declines to retain |
| Current names | `culvert_session_revoke_refused_total` (unlabeled; logout cookies this appliance could not verify) and `culvert_session_revoke_rejected_total{reason}` (all refusals). Code, runbook and log line all say "refused" (`session.Refused`, `SESSION_REVOKE_REFUSED`) |
| Canonical names | **`culvert_session_revoke_unverifiable_total`** (the unlabeled subset, named for what it counts) and **`culvert_session_revoke_refusals_total{reason}`** (the per-reason family, same six reasons) |
| Problem | Two sibling counters in one plane differed by a near-synonym yet had different scope, so an operator could not tell which one to alert on |
| Why better | One root ("refus-") for the concept; the subset is named for its meaning, matching its HELP text. `*_refusals_total` follows the plural-noun counters already in the tree (`*_drops_total`, `*_evictions_total`) |
| Affected | `events.go` (`writeSessionRevokeMetrics`), `docs/operator/session-revocation-plane.md`, `CHANGELOG.md` (`Deprecated`), `docs/design/PRODUCT-TERMINOLOGY.md`. No GUI, OpenAPI or config key |
| Migration / compat | Released names are kept as **deprecated aliases** with the same name, labels and value, emitted from the same snapshot as the canonical names, and removed in **v1.1.0**. Neither released name is ever reassigned: in particular the draft rename would have turned `culvert_session_revoke_refused_total` from the unlabeled counter into the labeled per-reason series, which a deprecated alias cannot repair because an existing alert would silently evaluate a different quantity under the same name. Gate: `session_revoke_metric_alias_test.go` |
| PR size | S |

Not changed: `SESSION_REVOKE_REFUSED` log token and `sessionRevokeRefused` (internal) keep their names;
`refused` vs `rejected` elsewhere in the repo (e.g. `culvert_ocsp_response_rejected_total`) are not
sibling pairs for one concept and are shipped, so they are not renamed for uniformity.

## Other sections

- Checked and consistent: `culvert_audit_cluster_push_drops_total` / `audit_cluster_push_drops`,
  `culvert_cluster_revocation_drops_total`, `culvert_cdr_*` family, `culvert_proxy_oversize_host_rejected_total`.
- Open prior items (T-11, T-12, T-29/T-30, T-54) not re-audited here.
- Priority: Critical none · High none · Medium none · Low T-70 (fixed; aliases until v1.1.0).
