# Culvert Language & Terminology Governance Review — 2026-10-24

> **Status:** Point-in-time review. **Window:** `9163f7e3..a27cffb` (49 first-parent merges since the
> 2026-10-23 report). Sweep covered added metric names, audit actions, JSON keys, operator docs
> (`README.md`, `config.example.yaml`, `docs/OPERATIONS.md`, `docs/operator`) and GUI strings in non-test code.

## Executive Summary

No production-worthy terminology improvements were identified.

Terminology Health Score: 96/100 (unchanged; no new drift).

## Checked in the window

- `culvert_cdr_fail_closed_total` and block reason `cdr_unavailable`: agree across `config.example.yaml`,
  `docs/OPERATIONS.md` and the CDR Diagnostics check states; "fail mode" values (`open`/`closed`) are used
  consistently with the existing `cdr.fail_mode` key.
- Audit actions `enrollment.token_created`, `enrollment.token_revoked`, `enrollment.token_revoke_unpersisted`,
  `enrollment.node_revoked`: one `<domain>.<object>_<action>` family; the `_unpersisted` outcome mirrors the
  existing roster persistence-failure naming. `cdr.instance.revoke_rpc` is a separate domain and is unchanged.
- `settings.syslog` audit action follows the existing `settings.<area>` shape.
- Security settings JSON keys (`ipFilterMode`, `ipAdd`, `ipRemove`, `rateLimitRPM`) already existed in
  `ui_policy.go`; the new request body in `ui_security.go` reuses them rather than introducing aliases.
- `roleClamped` JSON key and "Administrators" panel copy agree with the roster terminology set in T-64/T-67.
- Operator docs use "admin roster" / "Administrators" / "Admin Users" with the roles already recorded in
  `docs/design/PRODUCT-TERMINOLOGY.md`.

## Other sections

- Open prior items (T-11, T-12, T-29/T-30, T-54) not re-audited here.
- Priority: Critical none · High none · Medium none · Low none.
