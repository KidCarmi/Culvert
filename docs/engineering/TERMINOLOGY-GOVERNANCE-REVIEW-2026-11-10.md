# Culvert Language & Terminology Governance Review — 2026-11-10

> **Status:** Point-in-time review. **Window:** `d11ed3a..ac4e223` (CHAOS-115 scan sidecar admission plane, admin-UI plain-HTTP
> fallback diagnostic, category-group membership matching, destination pseudonymizer extraction to `internal/pseudonym`,
> inspect-leg read buffer, Security Release Gate budget).

## Executive Summary

One production-worthy terminology improvement was identified and applied: the scan sidecar's new capacity-refusal counter
was named `culvert_scan_svc_at_capacity_total`, but every other capacity-refusal series in the product says *saturated*,
including the caller's counter for **the same HTTP 429**. It was renamed to `culvert_scan_svc_saturated_total` before
release (it is listed under `[Unreleased]` and no tag contains it), so the migration cost is zero.

Terminology Health Score: 93/100 (unchanged; the drift was caught before it shipped).

## Canonical Concepts

| Concept | Canonical name | Surfaces |
|---|---|---|
| A scan refused because every slot is busy (overload, not a fault) | **saturated** | `culvert_clam_saturated_total` (local ClamAV slot), `culvert_remote_scan_saturated_total` + `stat_remote_scan_saturated` + GUI `sec-remote-saturated` (caller side of the sidecar 429), `culvert_scan_svc_saturated_total` (sidecar side, **this PR**), plus the gauges `culvert_auth_verify_saturated`, `culvert_geo_warm_saturated`, `culvert_mcp_export_saturated` |
| Scan sidecar admission slots | **slots / inflight** | `culvert_scan_svc_{slots,inflight}`, `/health` `scan_slots` / `scan_inflight` |

## Finding T-1 (Medium): one sidecar 429 event counted under two names

- **Business concept:** the remote scan sidecar refused a scan because it is at capacity (HTTP 429, so the caller fails closed).
- **Current names:** `culvert_remote_scan_saturated_total` on the caller (released since CHAOS-52/53) and
  `culvert_scan_svc_at_capacity_total` on the sidecar (new, CHAOS-115, `43ea602`).
- **Recommended canonical name:** `culvert_scan_svc_saturated_total`.
- **Why the current naming is a problem:** the runbook table in `scan-capacity-and-timeouts.md` §6.2 calls these two counters
  "the caller's side of the same event", and the new series' own HELP text says "saturation, not a fault". Even so, an
  operator writing fleet alerts would have to know that *at capacity* and *saturated* are synonyms. Every other
  capacity-refusal series in `/metrics` (six of them) uses *saturated*, so this would have been the only exception.
- **Why the new name is better:** a single `*_saturated*` selector or grep finds every capacity-refusal signal on both sides
  of the sidecar hop, and the name now matches the HELP text.
- **Affected code:** `metrics.go` (HELP/TYPE/sample lines, one comment) and `scan_svc_admission_chaos_test.go` (guard test
  series list and comment).
- **Affected API / GUI / configuration:** none. The `/metrics` exposition name changes; the JSON API, OpenAPI, GUI and config are untouched.
- **Affected documentation:** `CHANGELOG.md` `[Unreleased]` entry and `docs/operator/scan-capacity-and-timeouts.md` (§6.1 note, §6.2 table and PromQL).
- **Migration complexity / compatibility risk:** none. The series has not been in any release.
- **Estimated PR size:** XS (11 lines across 4 files).

The point-in-time `CHAOS-ENGINEERING-REVIEW-2026-11-09.md` keeps the old name, because it records what was true on that date.

## Candidates considered and rejected

- **`/health` field `at_capacity_refused`:** this field follows the `<reason>_refused` pattern of its sibling
  `oversize_refused` on the same reply. The runbook table maps it to the metric explicitly. Renaming it to
  `saturated_refused` would read worse and would not make anything clearer. Kept.
- **Internal `statScanSvcAtCapacity` / `refuseScanAtCapacity` and the sidecar log text "at capacity":** these are
  unexported, or prose that describes the state rather than naming a series. The caller's log already says "sidecar reported itself at
  capacity", so the log vocabulary on both sides is consistent. Renaming them would be cosmetic.
- **Diagnostic `ui_tls_fallback_http`:** it follows the `<subject>_<condition>` diagnostic-code pattern. Its OperatorAction
  cites the real GUI labels ("Upload Custom Certificate", target "Management UI"), so the action text and the GUI agree.
- **Category groups and the `internal/pseudonym` extraction:** these add no new operator-facing names. "Destination pseudonymizer"
  matches ADR-0044 and the existing traffic-log privacy runbook.
- **Legacy-term sweep:** no new additions reintroduce "unauth mode", "whitelist"/"blacklist", "hash cache" or "expansion ratio".

## Priority

Critical none · High none · **Medium 1 (T-1, fixed in this PR)** · Low none.
