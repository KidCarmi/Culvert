# Production-Qualification UX — Recommended Implementation Sequence

Small, reviewable, incremental slices. **No framework rewrite.** Preserved
throughout: single-binary deployment · CSP nonce model · server-side RBAC ·
existing APIs where adequate · stable `data-view` names and element selectors that
tests depend on · Playwright-Go · no Node runtime dependency.

Each slice is independently shippable, advisory-tested, and changes **presentation
/ workflow only** (the two exceptions expose existing APIs in the GUI per the
repo's GUI-parity rule; a few add read-only endpoints). None unlocks Production or
adds a connector / DMZ / Management mutation / qualification issuer.

Selector-preservation contract (applies to every slice): existing
`.nav-item[data-view="mcp-…"]`, `#view-mcp-…`, `#mcp-…-out`, `#mcp-…-status`,
`data-click="…"` handlers, and `#mcp-*-tenant` inputs **must keep resolving**.
New structured UI is added *alongside* the current `<pre>` (behind a container),
so existing e2e tests stay green while the new UI grows its own selectors.

---

## Slice 0 — Land this audit harness (done in this PR)
- **Files:** `ux_audit_screens_e2e_test.go`, `ux_audit_run_e2e_test.go`,
  `ux_audit_fixtures_e2e_test.go`, `ux_audit_fixtures_data_e2e_test.go`
  (all `//go:build uie2e`), assets under `docs/design/mcp/ux-audit-assets/`.
- **Routes changed:** none. **Selectors preserved:** all (read-only harness).
- **Playwright:** `TestUXAudit_Matrix` (advisory, not a gate).
- **API/OpenAPI/GUI parity:** none. **Rollback:** delete the test files + assets.

## Slice 1 — Shared foundations: state-triplet chip, status chip, as-of stamp, label map
Implements P0-3, P0-7, PQB-3 (partial). The primitives every later slice reuses.
- **Files:** `static/index.html` (new CSS tokens + small JS helpers
  `mcpTriplet()`, `mcpChip()`, `mcpAsOf()`, `mcpLabel(reasonToken)`); no Go.
- **Routes changed:** none. **Selectors preserved:** all (additive helpers).
- **Playwright:** new `ux_mcp_primitives_e2e_test.go` — triplet renders
  desired/active/fleet + pending qualifier; label map maps a known token; as-of
  turns amber past threshold.
- **API/OpenAPI/GUI parity:** none. **Rollback:** revert the helper block.

## Slice 2 — Command Center posture strip + needs-attention  (PQB-4)
- **Files:** `static/index.html` (`#view-mcp-overview`: add posture strip +
  needs-attention **above** the existing `#mcp-overview-out` `<pre>`, which stays).
- **Routes changed:** none (composes `overview`/`health`/`rollout`/`distribution`).
- **Selectors preserved:** `#mcp-overview-out`, `data-click="loadMCPOverview"`.
- **Playwright:** `ux_mcp_overview_e2e_test.go` — kill-switch/hard-fail/incompatible
  fixtures surface in needs-attention/posture with correct severity; disabled-default
  shows empty state.
- **API/GUI parity:** none. **Rollback:** hide the new container.

## Slice 3 — Activity row + detail drawer; evaluated→effective chips  (PQB-1, P0-6)
The highest-value slice: fixes the Shadow-DENY ambiguity.
- **Files:** `static/index.html` (`#view-mcp-decisions`: structured table +
  right-side drawer alongside `#mcp-decisions-out`); reuse the drawer on overview.
- **Routes changed:** none. Verify `DecisionView`/`ExplanationView` already carry
  `execution_state`/effective/override; if `effective_action`/`shadow_override`
  aren't projected onto `DecisionView`, add them to the **existing** projection in
  `internal/mcp/adminapi/decisions.go` (read-only field addition; update OpenAPI
  `MCPDecision` schema + `make api-bundle`).
- **Selectors preserved:** `#mcp-dec-tenant`, `#mcp-dec-event`,
  `data-click="loadMCPDecisions"`, `#mcp-decisions-out`.
- **Playwright:** `ux_mcp_investigations_e2e_test.go` — Shadow DENY shows two chips,
  never a lone ALLOW; drawer renders six sections; DLP-block shows finding classes;
  redaction assertion (no token/secret).
- **API/OpenAPI/GUI parity:** possibly additive read-only fields. **Rollback:**
  hide the table/drawer; revert the optional field additions.

## Slice 4 — Entity pivots + evidence chain  (PQB-5)
- **Files:** `static/index.html` (pivot chips in the drawer + tool/server drawers;
  "related calls" opens Investigations filtered by fingerprint/principal).
- **Routes changed:** optional additive filter params on
  `GET /api/mcp/decisions` (e.g. `tool_fingerprint=`, `principal=`) — read-only.
- **Selectors preserved:** all decisions/servers selectors.
- **Playwright:** `ux_mcp_pivots_e2e_test.go` — a pivot chip opens the tool drawer
  without navigation; "related calls" filters by fingerprint.
- **API/OpenAPI/GUI parity:** additive read filters. **Rollback:** chips inert →
  hidden.

## Slice 5 — Dangerous-action dialog standard + emergency framing  (P0-4, PQB-6)
- **Files:** `static/index.html` (one `mcpDangerDialog(opts)` reusing the
  `ui_dialogs` typed-confirm; wire emergency disable, quarantine, revoke, demote,
  rollback through it).
- **Routes changed:** none. **Selectors preserved:** existing `data-click`
  handlers keep working (the dialog wraps them).
- **Playwright:** `ux_mcp_danger_e2e_test.go` — emergency disable requires typed
  confirm; dialog states local-vs-fleet + reversibility + evidence.
- **API/GUI parity:** none. **Rollback:** bypass dialog → direct call.

## Slice 6 — Rollout ladder, DP ack matrix, blast-radius preview, scope editor  (PQB-2, P0-2)
- **Files:** `static/index.html` (`#view-mcp-rollout` restructure: ladder + triplet
  + DP ack matrix + preview modal + scope editor form) alongside the current
  panels. **Go:** optionally a read-only preview/counts endpoint
  (`GET /api/mcp/rollout/scope-preview?…`) computing affected #subjects/#DPs for a
  candidate scope (additive, non-mutating); a per-node ack read if not already
  exposed. Scope save uses the **existing** `PUT /api/mcp/rollout/scope`.
- **Routes changed:** additive read endpoint(s) only; existing PUT reused.
- **Selectors preserved:** `#mcp-rollout-*`, `data-click="mcpRolloutTransition"`,
  emergency/rehearse handlers.
- **Playwright:** `ux_mcp_rollout_e2e_test.go` — promote shows blast-radius preview
  (subjects/DPs/rollback target) before four-eyes; scope editor round-trips via the
  existing PUT; incompatible-DP row shows its reason; auto-load fills panels.
- **API/OpenAPI/GUI parity:** new read endpoint(s) → add to OpenAPI + `make
  api-bundle`; scope editor closes an existing GUI-parity gap. **Rollback:** hide
  new UI; the read endpoints are inert if unused.

## Slice 7 — Production Qualification checklist + real-vs-synthetic badges  (PQB-7)
- **Files:** `static/index.html` (`mcp-rollout` qualification panel → gate
  checklist with origin badges); no Go (`origin` already in
  `GET /api/mcp/rollout/evidence`).
- **Routes changed:** none. **Selectors preserved:** `data-click="loadMCPRolloutEvidence"`.
- **Playwright:** `ux_mcp_qualification_e2e_test.go` — synthetic evidence badged
  non-qualifying; locked banner present; no Production transition possible (403).
- **API/GUI parity:** none. **Rollback:** revert panel.

## Slice 8 — Publications GUI + structured approvals  (P0-5)
- **Files:** `static/index.html` (`mcp-approvals`: add publication list + create +
  four-eyes decide alongside operational).
- **Routes changed:** none (existing `publications` + `publication-decision`
  routes). **Selectors preserved:** `#mcp-appr-tenant`, `loadMCPApprovals`.
- **Playwright:** `ux_mcp_publications_e2e_test.go` — publication approvals appear
  and can be decided (admin, four-eyes, self-approve blocked).
- **API/GUI parity:** closes a GUI-parity gap (exposes existing APIs). **Rollback:**
  hide publication section.

## Slice 9 — Structured reads for servers / health / management / policy-sim; config form  (P0-1, P1-1, P1-5)
- **Files:** `static/index.html` (replace the remaining `<pre>` dumps with
  cards/tables/meters; `mcp-settings` textarea → validated form over `MCPConfig`).
- **Routes changed:** none. **Selectors preserved:** keep the `#…-out` containers
  present (empty/hidden) so legacy tests resolve.
- **Playwright:** per-view structured-render assertions; config form validates enums.
- **API/GUI parity:** none. **Rollback:** re-show the `<pre>`.

## Slice 10 — Deep-linkable state; polish; accessibility; visual-system alignment  (P0-8, P2-*)
- **Files:** `static/index.html` (URL-encode tenant/filters/selection; skeletons;
  de-dupe rollout panels; empty-state copy; aria/focus; align to
  `docs/design/DESIGN-SYSTEM.md`).
- **Routes changed:** none. **Selectors preserved:** all (URL state is additive).
- **Playwright:** `ux_mcp_deeplink_e2e_test.go` — a deep link restores
  filtered/selected state and existing selectors still resolve; a11y checks on
  chips/drawers.
- **API/GUI parity:** none. **Rollback:** ignore URL state.

---

## Sequencing rationale
1. **Slice 1** unblocks everything (shared primitives).
2. **Slices 2–3** deliver the two biggest safety wins first (posture + the
   evaluated/effective fix) — the core of qualification readiness.
3. **Slices 4–6** build the investigation thread and the promotion safety gate
   (blast radius) — the rest of the PQ-BLOCKERs.
4. **Slices 7–8** close qualification evidence + GUI-parity gaps.
5. **Slices 9–10** finish structure, polish, deep-linking, and a11y.

Each slice keeps `go test ./...` green (new work is `//go:build uie2e` for tests
and additive HTML/JS for the SPA) and keeps the shipped single binary unchanged in
behavior. Recommended review size: one slice per PR.

## Global rollback plan
Because every slice is additive UI layered over unchanged APIs and preserved
selectors, rollback for any slice is "hide the new container / revert the HTML+JS
block"; no data migration, no API removal that would break clients, and no change
to MCP admission or the Production lock at any point.
