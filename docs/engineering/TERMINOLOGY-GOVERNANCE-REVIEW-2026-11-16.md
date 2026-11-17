# Culvert Language & Terminology Governance Review — 2026-11-16

> **Status:** Point-in-time review. **Window:** `0b11474..881abf0` (`config_version_capture` diagnostics row,
> `panic_contained` alert and ten newly subscribable alert events, SIEM collector retry, installer symlink/RHEL fixes).

## Executive Summary

No production-worthy terminology improvements were identified. Terminology Health Score: 93/100 (unchanged).

## What was checked

- **`config_version_capture` row:** says "rollback point" and points at **Config Versions**, the GUI panel title; the
  row, CHANGELOG and code comments agree. "Rollback point" is descriptive prose for one version entry, not a second
  surface name.
- **`panic_contained` alert:** GUI label "Contained panic", the event id, `internal/alerts` docs and CHANGELOG all use
  *contained panic*. The pre-existing `culvert_crash_records_total` / `recordCrash` vocabulary is the same sink and
  was deliberately kept (see the 2026-08-06 and 2026-08-07 reviews); no parallel name was invented.
- **Ten newly subscribable alert events** (`dns_failure`, `yara_degraded`, `ha_self_fenced`, `disk_critical`, …): panel
  labels name the business condition, event ids are unchanged wire values.
- **Installer / syslog / ssrf changes:** no Culvert concept names introduced.

## Candidates considered and rejected

- "crash" (crash record, alert description "crashed and recovered") vs "contained panic" vs "crash loop" (process
  termination in operator docs): a recovered panic is stored as a *crash record*, while the operator docs use "crash"
  for process termination. The metric and support-bundle section are stable public surfaces and the alert label already
  says "Contained panic"; a rename would break scrapes and bundles for a modest gain. Revisit only if a future
  operator-facing page needs to explain the difference, and then as a documentation note.

## Priority

Critical none · High none · Medium none · Low none.

No identifiers, wire fields, metrics or GUI labels were changed.
