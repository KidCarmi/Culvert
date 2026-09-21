# Culvert Language & Terminology Governance Review — 2026-09-21

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `46410c3..6c46ebd` — the window since the 2026-09-11 report's merge point,
> confirmed as the current `origin/main` HEAD by a fetch immediately before this report was written (the
> DEBT-014 lesson carried forward again: sync against `main` right before opening a PR). The window covers
> 21 first-parent merges / 154 files / ~29.4k insertions, dominated by two unrelated engineering streams:
> the MCP Agent Security Gateway's "first controlled canary" execution architecture (ADR-0035 —
> `internal/mcp/canary`, `internal/mcp/execution`, `internal/mcp/tooltrust`, `internal/mcp/policy`,
> `internal/mcp/upstreamclient`, the `mcp_canary_*.go`/`mcp_live_gate.go`/`ui_mcp_tooltrust.go` root files)
> and the CHAOS-65 OCSP revocation-checking engine (`internal/ocsp`, `ocsp_coverage.go`, `ocsp_metrics.go`,
> `mtls_ocsp_startup.go`) plus release-pipeline/CI work (catalog re-sign, R2 migration, release-gating
> scripts). None of this window is admin-facing feature work in the sense prior reviews found drift in.

---

## Executive Summary

**No new terminology drift found, and no new fixes made this pass.**

Two bounded audits were run against the diff since the last review:

1. **MCP "first controlled canary" naming surface** (ADR-0035, the largest single stream in this window):
   checked whether the new vocabulary — "canary", "tool trust" (`internal/mcp/tooltrust`), "reviewed
   operation" (`ReviewedOperationClass`), "live gate" (`internal/mcp/execution/livegate.go`,
   `mcp_live_gate.go`), "permit" (`internal/mcp/canary/permit.go`, `mcp_canary_policy_permit.go`),
   "read-first" (`mcp_canary_read_first.go`), "exact scope" / "no-credential" / "catalog-usable" (the
   `scripts/mcp-first-canary-*-mutations.sh` family) — collides with anything pre-existing. It does not:
   "Canary" is already an established rollout-ladder state name (`Disabled→Observe→Shadow→Canary→
   Production`, CLAUDE.md's MCP section, and confirmed still the only "canary" usage surfaced in
   `static/index.html:20633,21003` — the mode-order map and the mode `<select>` options), so this window's
   canary-*execution* work is additive to an existing name, not a second concept reusing it. The new
   `internal/mcp/tooltrust` DTOs (`ui_mcp_tooltrust.go`) use "approval"/"reviewed operation" vocabulary on
   the wire (`ApprovalStatus`, `ApprovalID`, `ReviewedOperationClass`, `RequestedBy/ApprovedBy/RejectedBy`)
   and were confirmed to register **no independent route** of their own in this window (no
   `mux.HandleFunc`/`register*Routes` call in `ui_mcp_tooltrust.go`; it is consumed internally) — so there
   is, as yet, no GUI/API-facing "tooltrust" string to collide with anything. Consistent with the
   09-08/09-09/09-11 reports' recurring observation that a reliability/security engine landing with no
   independent admin surface is not itself a finding; flagged here as something to re-check once this
   surface grows a route of its own, since "Tool Trust" vs. "Reviewed Operation" vs. plain "Approval" would
   then need to pick one name for the admin-facing side.
2. **CHAOS-65 OCSP engine** (`internal/ocsp/ocsp.go` +655/-70, `ocsp_coverage.go`, `ocsp_metrics.go`): the
   `culvert_ocsp_*` metric family, the `ocsp_coverage`/`uncheckedEnforcingPaths` fields on
   `GET /api/ocsp`, and `docs/operator/ocsp-revocation-checking.md` were spot-checked for cross-surface
   naming and match byte-for-byte (metric names ↔ HELP text ↔ doc section headings). This is the same
   engineering sweep CLAUDE.md's Architecture Notes document at length under CHAOS-65; no new vocabulary
   was introduced outside that documented shape. Internal engine, no independent GUI panel — not a finding,
   same reasoning as item 1.

Release-pipeline changes in the window (`resign-catalog.yml`, `docs/operator/catalog-resign-runbook.md`,
`roadmap/R2-CATALOG-MIGRATION-PLAN.md`, the `.github/scripts/*` release-gating rewrite) are CI/operator-doc
surfaces already covered by CLAUDE.md's "Release catalog weekly re-sign (M1-4)" and "single origin (R2)"
notes; spot-checked the runbook title against the workflow name (`resign-catalog.yml` ↔ "Catalog Re-sign
Runbook") and the R2 terminology against CLAUDE.md's existing "R2 (`https://catalog.culvertlabs.com`)"
description — consistent, no drift.

**Spot-checked three carry-over items directly** against the current tree, as prior reports have done,
rather than assuming the backlog is unchanged just because no fix commit was seen in the window:
- **T-13**: `docs/enterprise/TLS-INSPECTION-DEPLOYMENT.md:1` is still titled "TLS Inspection Deployment"
  (in-app/API/GUI still say "SSL Inspection" throughout `static/index.html`, e.g. `healthcheck.go`'s
  `ssl_inspection` field, `policy.go`'s `SSLAction`) — unchanged.
- **T-29/T-30**: `config.go:56-57` still spells the two settings `rate_limit`/`max_conns_per_ip` in YAML
  with no `rate_limit_rpm`/`conn_limit_max_per_ip`-style alias; the live admin API (`ui_config.go`), the
  config-version/export payload (`ui_policy.go`), and `admin_settings.json` (`admin_settings.go:33`) still
  disagree on the connection-limit field's spelling exactly as the 2026-09-11 report described — unchanged.
- **T-12**: `cmd/culvert-maint/internal/server/handlers_upgrade.go:1,3,80` still exposes
  `POST /v1/upgrades/check`/`apply` with no `/v1/updates/*` alias, while the GUI still says "Dispatch
  Release" — unchanged.

**Terminology Health Score: 8.7 / 10** (unchanged from 2026-09-08 through 2026-09-11). A third consecutive
large, backend-heavy window (MCP canary execution + OCSP revocation checking + release-pipeline CI) landed
with disciplined internal naming and no new admin-facing vocabulary drift; the tracked backlog did not move
in either direction, so the score is carried forward unchanged rather than re-derived from scratch.

---

## Carried-Over Findings (unchanged)

All fourteen previously-open finding IDs (thirteen backlog entries, since T-21 and T-32 are tracked as one
paired item) remain open, unchanged, and re-confirmed against the current tree:
T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21+T-32 (paired), T-25 (residual), T-29, T-30, T-33, T-34,
T-39. Full descriptions and the priority-ordered refactoring plan are unchanged from
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md` and are not restated here to avoid drift between two
descriptions of the same open items — see that report (or its predecessors, cited therein) for the
canonical text of each.

The "Content & Scanning" (legacy GUI) vs. "Content Security" (new React frontend) soft finding — a
non-mechanical naming-policy reconciliation between two deliberate design decisions, not a numbered backlog
item — also remains unresolved, per 2026-09-09's reasoning, and was not revisited this pass.

**One item to watch, not yet a backlog entry**: if `internal/mcp/tooltrust` grows an independent admin
route in a future window, its wire vocabulary ("approval" fields vs. the package name "tool trust" vs. the
DTO name "reviewed operation") will need a single canonical admin-facing name picked before it ships, the
same way T-33 already flags the MCP policy-taxonomy overwrite problem one layer over. Recorded here so the
next review checks it rather than rediscovering it; not queued as a numbered finding because there is no
live surface yet to be inconsistent about.

---

## Stop-Condition Assessment

No production-worthy NEW terminology improvement was identified this pass: the 21-merge window audited was
two large, internally-disciplined engineering streams (MCP canary execution, OCSP revocation checking) plus
release-pipeline CI work, none of which introduced admin-facing vocabulary or collided with an existing
canonical name. The fourteen-ID (thirteen-entry) carry-over backlog is unchanged and was independently
re-confirmed (not merely assumed unchanged) for its three highest-visibility items (T-12, T-13, T-29/T-30).
No cosmetic or preference-driven renames are proposed. This report itself — the audit record, the
carry-over reconciliation, and the one watch-item for a future MCP admin surface — is the deliverable of
this pass; per the DEBT-014 process lesson, it was written only after a fresh sync against `origin/main`
immediately before opening its PR.
