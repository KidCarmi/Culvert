# Culvert Language & Terminology Governance Review — 2026-10-20

> **Status:** Point-in-time review. **Window:** `d3fe509..3a180e0` (since the 2026-10-15 report). Sweep
> covered operator-facing strings and metric/route names added in non-test Go (admin-roster diagnostics,
> HA, CDR, cluster).

## Executive Summary

One production-worthy finding (T-67, Low), fixed in this PR as a copy-only change. Everything else added
in the window is consistent with the glossary. Terminology Health Score: 96/100 (unchanged).

## T-67 — "admin users file" vs "admin roster file" (Low)

| Field | Value |
|---|---|
| Business concept | The persisted file holding the admin roster (`ui_users.json`, `-ui-users-file`) |
| Current names | Diagnostics operator actions: "admin users file" (10 sites, `diagnostics.go`); same rows' messages and the viewer text: "admin roster file" / "roster file" / "configured roster file"; operator doc: "admin roster" |
| Canonical name | **admin roster file** (concept: **admin roster**, per T-64) |
| Problem | One Diagnostics row named the same file two ways, and "admin users" collides with the legacy "Admin Users" panel, the glossary's Administrator term and the "Identity"/proxy-user distinction. A support engineer searching docs for the phrase in the action text finds nothing. |
| Why better | One phrase for the file across message, action, doc and metrics prefix; the flag name stays quoted in parentheses so the operator can still find it. |
| Affected | `diagnostics.go` operator-action strings only; glossary row added in `docs/design/PRODUCT-TERMINOLOGY.md`. No API field, config key, flag, metric, OpenAPI, GUI or test pinned the old phrase. |
| Migration / compat risk | None (prose). Persisted file, flag and Go names are wire/surface names and unchanged. |
| PR size | XS |

## Carried / not changed

- The "admin account" vs **Administrator** vs panel title "Admin Users" observation (2026-10-06 item 4) is
  still an open GUI-wide owner decision; not re-charged.
- Bare "roster file" shorthand inside the roster row's own messages is left: the row title and the
  surrounding text make the scope unambiguous, and many strings are pinned by tests.
- Prior backlog (T-11, T-12, T-29/T-30, T-54, T-64 operation-ID split, T-65) not re-audited.

## Priority

Critical none · High none · Medium none · Low T-67 (fixed).
