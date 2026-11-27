# Culvert Language & Terminology Governance Review — 2026-11-25

> **Status:** Point-in-time review. **Window:** `1836a2d..f4f9379` (policy rule-key refusal and `annotations`, configuration
> import durability response, `internal/listenfault`, `internal/writerlock` single-writer lock, Maintenance agent lifecycle
> model, diagnostics policy-rule checks, SaaS-feed activation).

## Executive Summary

No production-worthy terminology improvements were identified. Terminology Health Score: 93/100 (unchanged).

## What was checked

- **Configuration import:** GUI says "Configuration imported", the API and audit action say `config.import`, logs say
  "Config import". The glossary already accepts "Config" in dense UI and keeps `config.import` as the stable wire
  identifier. The new `imported_not_durable` status names the running-vs-persisted distinction without introducing a
  second word for "import". No change.
- **Policy rules wording:** new diagnostics and API text says "rule(s)" and "policy rules" for the persisted set and
  `PolicyRule`/`policyRules` as wire names. The glossary's preference for "Rule" concerns UI prose; the `policyRules`
  backup/import key is a persisted contract and is not a rename candidate.
- **`annotations`:** one container name, defined once in the OpenAPI description, used identically in the request,
  refusal text and backup description.
- **State directory vs data directory:** "state directory" appears only for the Maintenance agent's own `state_dir`
  configuration key (ADR-0062), a different concept from the appliance data directory. No collision.
- **Single-writer lock:** "single-writer"/"instance lock" is used for the data-directory writer lock and the agent state
  lock consistently within each owner; neither is operator-facing GUI text.
- **New internal owners** (`listenfault`, `writerlock`, `pathdiffgen`, `otlp` spans): package names follow the
  `internal/<domain>` pattern; no new metric, alert, audit action or GUI label conflicts with the glossary.

## Priority

Critical none · High none · Medium none · Low none.

No identifiers, wire fields, metrics or GUI labels were changed.
