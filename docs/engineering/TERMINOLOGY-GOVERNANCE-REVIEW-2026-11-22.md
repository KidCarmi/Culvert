# Culvert Language & Terminology Governance Review — 2026-11-22

> **Status:** Point-in-time review. **Window:** `1836a2d..155df09` (82 commits: OTLP trace-export retention and
> shutdown ownership, `internal/writerlock`, `internal/listenfault`, `internal/mcp/livetier`,
> `internal/mcp/events/qualarchive`, crash-journal recovery in the maintenance agent, blocklist add/import
> reporting, SaaS-feed activation, lifecycle-conformance CI).

## Executive Summary

No production-worthy terminology improvements were identified. Terminology Health Score: 93/100 (unchanged).

## What was checked

- **Blocklist add/import notice (`static/index.html`):** "host(s)", "already listed", "saved but will never match a
  destination", "not saved" all follow the existing Blocklist/host vocabulary. No second name for the entry or the list.
- **OTLP trace-export health line:** the GUI now says spans were "never delivered" and lists the real causes (buffer
  overflow, rejected batch, export disabled). The exporter's logs say "dropped" (disable/endpoint change) and
  "discarded" (rejected batch / shutdown), and the Go counter is `droppedSpans`. This is three verbs for one outcome,
  but the GUI wording was changed deliberately in CHAOS-126 to stop implying a collector outage, the log lines
  always carry the cause, and the counter is not an operator-facing metric name or API field. Unifying the log verbs
  would be cosmetic and is below the bar. Watch item: if a `culvert_otlp_*` metric or an alert is later added for this
  counter, pick the name then (candidate: "never delivered", matching the GUI).
- **Maintenance agent crash-journal logs:** "interrupted op", `agent_restart_interrupted`, "journal record" are used
  consistently within the agent. The agent keeps its own `culvert-maint:` log prefix by design.
- **New internal owners** (`writerlock`, `listenfault`, `livetier`, `qualarchive`): package names follow the
  `internal/<domain>` pattern and are not operator-visible. The new `culvert_mcp_export_lag` metric is in the existing
  `culvert_mcp_export_*` family.
- **Retired-term sweep:** "unauth mode", "enrolment"/"enrol", "blacklist"/"whitelist", "UI roster", "admin users
  file", "bootstrap window" (operator text) and "Users & Roles" appear only in historical documents, generated
  OpenAPI text, code comments or identifiers the glossary records as keeping their spelling. Remaining
  "expansion ratio" and "hash cache" hits are unchanged from 2026-11-21.

## Priority

Critical none · High none · Medium none · Low none.

No identifiers, wire fields, metrics or GUI labels were changed.
