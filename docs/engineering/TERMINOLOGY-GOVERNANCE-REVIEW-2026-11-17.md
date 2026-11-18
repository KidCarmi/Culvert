# Culvert Language & Terminology Governance Review — 2026-11-17

> **Status:** Point-in-time review. **Window:** `881abf0..HEAD` (`admin_route_enforcement_shadow` diagnostics row,
> contained-panic page consolidation, alert-store atomic swap, HA compose and installer fixes).

## Executive Summary

One low-priority text drift found and fixed. Terminology Health Score: 93/100 (unchanged).

## Finding (Low)

- **Business concept:** Admin-API RBAC enforcement mode (enforce / shadow; env `CULVERT_C2_ENFORCE`).
- **Current names:** GUI banner and dashboard comment "Admin-API RBAC enforcement"; README "Admin RBAC enforcement
  mode"; the new Diagnostics row "admin-route authorization metadata"; Governance page "C2 mode".
- **Canonical name:** *Admin-API RBAC enforcement* (already the operator-visible GUI name). "C2" stays an internal and
  env-var name; the row code `admin_route_enforcement_shadow` and `CULVERT_C2_ENFORCE` are wire/config contracts and
  are unchanged.
- **Also fixed:** the GUI banner said "role checks are not blocking", which contradicted the Diagnostics row (each
  handler's own role check still applies). It now says the *route-level role gate* does not block.
- **Affected:** `static/index.html` banner, `c2_enforce_diagnostics.go` message, `README.md` env table.
- **Migration / compatibility risk:** none (display text only; no test pins the strings). **PR size:** XS.

## Checked and left alone

- `contained panic` vs `crash record`: still the deliberate split recorded on 2026-11-16.
- Dropped `component_panic` page, alert-store, ssrf, installer and compose changes: no new concept names.

## Priority

Critical none · High none · Medium none · Low 1 (fixed).
