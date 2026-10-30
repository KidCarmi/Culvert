# Culvert Language & Terminology Governance Review — 2026-10-29

> **Status:** Point-in-time review. **Window:** `f6db525..7262622` (changes since the 2026-10-28 report).
> Sweep covered CHAOS-103 (`setup_bootstrap_window.go`, `datadir_writer_lock.go`), the new
> `alert_delivery` diagnostics row, `docs/OPERATIONS.md` additions, installer messages and the glossary.

## Executive Summary

One Low finding: the unauthenticated first-run period has two names in operator-visible text.
Terminology Health Score: 94/100 (95 → 94 for the new split; restored once unified).

## Finding 1 — first-run "bootstrap window" vs "setup window" (Low)

- **Business concept:** the period before first-run setup is durably recorded, during which the setup wizard is reachable without credentials.
- **Current names:** "first-run bootstrap window" (Go identifiers, comments, CHANGELOG, and the operator-visible
  `CULVERT_ALLOW_MULTIPLE_WRITERS` startup warning); "first-run setup window" (`docs/OPERATIONS.md`); "setup wizard" (UI, README, install.sh).
- **Recommended canonical name:** **first-run setup window** in operator-visible text; "bootstrap window" stays an internal/code term.
- **Why problematic:** an operator who reads the startup warning cannot find "bootstrap window" in the runbook, and neither phrase was in the glossary.
- **Why better:** matches "setup wizard" / "first-run setup", which operators already see; business meaning, not implementation.
- **Affected code:** one log string (`datadir_writer_lock.go`). `bootstrapWindowOpen`, the file name and test names are NOT renamed (internal, no benefit).
- **API / GUI / configuration:** none. **Documentation:** glossary row added. 
- **Migration complexity:** trivial. **Compatibility risk:** none (no test or parser depends on the text). **PR size:** XS.

## Checked, no change

- `alert_delivery` diagnostics row: "alert webhook" / "delivery history" match the glossary (Alert = condition, Webhook = channel).
- "single-writer lock" / "data directory": consistent between log, error and runbook; glossary already defines data directory under Backup.
- `CULVERT_ALLOW_MULTIPLE_WRITERS`, `.culvert-writer.lock`: one name each.

## Priority

Critical none · High none · Medium none · Low 1 (applied).
