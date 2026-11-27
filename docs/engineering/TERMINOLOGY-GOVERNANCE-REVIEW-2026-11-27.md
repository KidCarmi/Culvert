# Culvert Language & Terminology Governance Review — 2026-11-27

> **Status:** Point-in-time review. **Window:** `1836a2d..2fad1fb` (Maintenance Agent ADR-0062 slices 3b, 4, 5 and 7:
> gate checkpoints, `restore_prior`, resumable health gates, runtime health observer, and the runtime-health block of
> `/api/maintenance-agent`).

## Executive Summary

No production-worthy terminology improvements were identified. Terminology Health Score: 93/100 (unchanged).

## What was checked

- **Runtime health surface** (`runtime_health`, `last_good`, `last_good_error`, `gate_passed*`, `obs_*` reasons): the
  window's only operator-visible vocabulary. `last_good` is the agent's last-known-good image reference, the same
  concept the repository already calls "last-known-good" for cached IdP metadata and threat-feed intelligence
  (fall back to the most recent validated copy). The JSON field is a short form of that one concept, documented beside
  the field in `maint_agent_status_api.go` and the OpenAPI schema; no second concept shares the name. A rename of a
  field added days ago would be cosmetic.
- **Upgrade / Release / Dispatch:** the Maintenance Agent changes keep the glossary's split (Release = signed catalog,
  Upgrade = applying one, Dispatch = console action). The retired "Update" / "self-update" terms did not reappear in
  operator-facing text.
- **`backup.create` vs `backup.trigger`:** unchanged; the recorded alias rule still holds.
- **Rollback vs `restore_prior`:** `restore_prior` is an agent operation/config value with its own documented
  semantics (Docker evidence of a death inside `up`); "rollback" remains the name for the configuration-version and
  data-rollback concepts. Distinct concepts, distinct names.
- **Internal owners** (`journal`, `idem`, `lifecyclemodel`, `runtimehealth`): package names are not operator-visible and
  follow the existing pattern.

## Priority

Critical none · High none · Medium none · Low none.

No identifiers, wire fields, metrics or GUI labels were changed.
