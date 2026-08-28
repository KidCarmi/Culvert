# Culvert Language & Terminology Governance Review — 2026-08-22

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited the tree at `fdad525`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-21.md` (baseline `7df2677`). 23 commits separate the two
> reviews, dominated by one large stream: PR #1194 ("feat(ui): add modern admin frontend and
> query-driven monitor", `c1d3db5`) — an entirely new `frontend/` React application (198 files,
> ~43k lines), embedded into the binary and served at `/app`, gated off by default behind
> `CULVERT_EXPERIMENTAL_UI`. This is the single largest new terminology surface this program has
> audited in one pass, and — being brand new — has never been through a review cycle. The remaining
> commits in the window (connection-limiter sharding, DPI-scan budget accounting, urlcat fingerprint
> memoization, LDAP/CA-upload follow-ups from the 08-21 review's own companion PR) touch no new
> terminology surface; their naming was checked against the diff and found unchanged from what
> `CLAUDE.md`'s Architecture Notes already document. Method: (1) a focused audit of the new
> frontend batch specifically, cross-referencing its on-screen labels, route table, and internal API
> client against the REST endpoints it consumes (`/api/dashboard/*`, route metadata `Domain` field,
> OpenAPI) and against the legacy GUI's existing labels for the same surfaces; (2) a check of the new
> frontend's own design docs (`docs/adr/ADR-FE-002-monitor-query-model.md`,
> `docs/design/INFORMATION-ARCHITECTURE.md`, `roadmap/FRONTEND-MIGRATION-PLAN.md`) for internal
> consistency and against the shipped implementation; (3) re-confirmation of the nineteen
> previously-open carry-over findings (T-9 through T-39, all still open per 08-21) against this
> window's diff — none of their dependent files were touched, so they are not re-derived below;
> (4) a spot-check of the twenty-plus alert/metric/audit-vocabulary areas the 08-20/08-21 passes
> already covered, to confirm the new frontend introduced no *duplicate* client-side vocabulary for
> concepts those passes already named (it did not — the new frontend's API client
> (`frontend/src/api/ops.ts`) reuses the backend's existing field/endpoint names verbatim throughout,
> the one exception being the finding below).
> **Companion change:** one fix ships with this review — the new frontend's landing-page label
> disagreed with its own backing API, its own design spec, and the legacy GUI's label for the
> identical page.

---

## Executive Summary

**One high-value, genuinely new finding, fully fixed: the v2 frontend's landing page called itself
"Overview" while every contract it depends on — the REST API, route metadata, OpenAPI, the legacy
GUI, and the v2 frontend's own internal type names — already call the same page "Dashboard".**
`frontend/src/features/overview/OverviewPage.tsx` rendered `<h1>Overview</h1>` and
`frontend/src/layouts/AppShell.tsx` labeled the corresponding nav link "Overview", while the page's
own data-fetching layer imports `DashboardHealth`, `DashboardThreats`, `getDashboardHealth`, and
`getDashboardThreats` from `/api/dashboard/health` and `/api/dashboard/threats` (`ops.ts`), the
route-metadata table classifies those endpoints under `Domain: "dashboard"` with handler names
`apiDashboardHealth`/`apiDashboardThreats`/`apiDashboardTopRules` (`ui_routes_meta.go`), and the
legacy GUI's own nav item for the identical page reads "Dashboard" (`static/index.html`, view key
`dashboard`, topbar title `Dashboard`, keyboard-shortcut help text `Alt+1 Dashboard`). The project's
own frontend design spec had already settled this: `roadmap/FRONTEND-MIGRATION-PLAN.md`'s migration
mapping table states plainly `Monitor | Dashboard | Overview → Dashboard | —` — i.e. the *page* name
"Dashboard" was deliberately kept when it moved into the new "Overview" *section*; only the section
groups the item, the item itself was never meant to be renamed. The shipped implementation drifted
from its own spec, landing "Overview" at both the section and the page level — a same-word,
two-level redundancy that also happened to disagree with the backend on the page level. Compounding
it, the design doc that specifies this exact page also disagrees with itself:
`docs/adr/ADR-FE-002-monitor-query-model.md` line 5 lists the surface as "Overview" while line 27
calls the identical thing "the v2 Dashboard/Monitor surfaces" two lines apart in the same document.
A support engineer correlating a "something's wrong on the Dashboard" report from a v2 admin against
server logs, the OpenAPI spec, or `ui_routes_meta.go` would have had to know out-of-band that the
on-screen "Overview" meant `/api/dashboard/*` — exactly the cross-surface correlation failure this
program exists to catch.

**Fix, chosen for lowest migration risk:** the *page*-level label was aligned to the established
name, "Dashboard" — not the reverse. The REST paths (`/api/dashboard/*`), route-metadata `Domain`
field, OpenAPI operation IDs, and the legacy GUI's labels are all pre-existing, stable, and either
externally-versioned (OpenAPI) or referenced by many other files; renaming any of those to "overview"
would be the Medium/Medium-High-risk direction this program consistently avoids when a cheaper,
zero-risk alternative exists (the same logic T-12/T-17/T-29/T-30's deferred "alias, don't break the
wire contract" recommendations already apply elsewhere in the backlog). The brand-new v2 frontend, by
contrast, is unreleased (gated off by default, zero production traffic) and the change is confined to
two on-screen strings plus their direct test assertions. Changed: the nav-link label
(`AppShell.tsx`), the page's `<h1>` title (`OverviewPage.tsx`), the 21 Playwright `heading`/`link`
name assertions across eight `e2e/*.spec.ts` files that pinned the old text, and `ADR-FE-002`'s own
self-contradictory line 5. Left unchanged, deliberately: the nav **section** heading ("Overview" —
this one *is* correct, matching `FRONTEND-MIGRATION-PLAN.md`'s "Overview" section name and the
plan's own `Monitor | Dashboard | Overview → Dashboard` mapping, so touching it would introduce a
*new* mismatch against the spec rather than fix one); every internal-only identifier
(`OverviewPage`, `OverviewSnapshot`, `fetchOverview`, the `features/overview/` directory, the
`["ops","overview"]`query key, and code comments referencing them) — these are implementation
details invisible to an admin, support engineer, or API consumer, and this program does not
recommend renames without an external-facing payoff (the "do not rename identifiers for style"
stop-condition applies here as much as it does to backend `internal/` package names). Verified:
`npx tsc --noEmit` clean, `vitest run` 141/141 passing, `eslint` clean on every touched file,
`prettier --check` clean (one file's line-wrap shifted because "Dashboard" is one character longer
than "Overview" — reformatted, no semantic change), and `go build ./...` clean (no Go files were
touched; the frontend is embedded as a build artifact, not source-coupled to this change).

**All nineteen previously carried-over findings (T-9 through T-39, minus T-43/T-44 which the 08-21
pass already closed) were re-checked against this window's 23-commit diff and remain open,
unchanged** — none of their dependent files were touched by this window's commits.

**Terminology Health Score: 8.4 / 10** (up 0.1 from 08-21's 8.3 — the ADR-numbering
collision-prevention gap noted in that review is unchanged and still costs the same deduction, but
this pass demonstrates the program catching a brand-new, large surface's very first naming defect
before it ever reached a production build, at zero migration cost — the outcome the process is
designed to produce).

---

## Findings

### T-45 — v2 frontend's Dashboard page labeled "Overview", disagreeing with its own API client, its own design spec, and the legacy GUI (FIXED)

- **Business concept:** the appliance's snapshot landing page (posture, traffic counters, verdicts,
  threat mix) — the first screen an admin sees, in either GUI.
- **Current names before fix:**
  - New frontend (`/app`, `CULVERT_EXPERIMENTAL_UI`, default off): nav link label **and** page `<h1>`
    both **"Overview"** (`frontend/src/layouts/AppShell.tsx:54`,
    `frontend/src/features/overview/OverviewPage.tsx:108`).
  - The same file's own data layer: `DashboardHealth`, `DashboardThreats`, `getDashboardHealth`,
    `getDashboardThreats` (`frontend/src/api/ops.ts:95-187`), fetching
    `/api/dashboard/health`/`/api/dashboard/threats`/`/api/dashboard/top-rules`.
  - Backend REST API / route metadata, consumed by **both** frontends: handler names
    `apiDashboardHealth`/`apiDashboardThreats`/`apiDashboardTopRules`, `Domain: "dashboard"`
    (`ui_routes_meta.go:169-173`).
  - Legacy GUI (`/`, still primary): nav item **"Dashboard"** under nav-section **"Overview"**
    (`static/index.html:760-762`), topbar title `"Dashboard"` (`:913`), view key `'dashboard'`
    (`:5965`), keyboard-shortcut help text `"Alt+1 Dashboard"` (`:5962`).
  - The project's own frontend migration spec: `roadmap/FRONTEND-MIGRATION-PLAN.md`'s mapping table
    — `Monitor | Dashboard | Overview → Dashboard | —` (old section "Monitor", old item "Dashboard",
    new section "Overview", new item "Dashboard" — the item name is explicitly unchanged by the
    plan).
  - The page's own design ADR disagreeing with itself: `docs/adr/ADR-FE-002-monitor-query-model.md:5`
    ("Overview, Monitor → Traffic, ...") vs. `:27` ("the v2 Dashboard/Monitor surfaces").
- **Why the current naming was problematic:** every wire contract, handler name, route-metadata row,
  and the new frontend's own internal type/function names said "dashboard," while the one thing an
  admin or support engineer actually sees on the v2 screen said "Overview" — a fresh, un-reviewed
  three-way (GUI / API / design-doc) disagreement introduced in a single PR, on the appliance's
  single most-viewed page, that the shipped code's own design spec had already resolved in the other
  direction before implementation drifted from it.
- **Recommended canonical name:** "Dashboard" — already the name used by the API paths, route
  metadata, OpenAPI, the legacy GUI, the new frontend's own API-client types, and the project's own
  migration-plan spec; the outlier was the two on-screen strings in the new frontend, not the
  established name.
- **Fix:** `AppShell.tsx`'s nav-link label and `OverviewPage.tsx`'s page title changed from
  "Overview" to "Dashboard"; 21 Playwright assertions across `e2e/{fe2,fe3-auth,fe3-evidence,
  fe3-multitab,fe3-setup,fe4,smoke}.spec.ts` that pinned the old heading/link text updated to match;
  `ADR-FE-002`'s self-contradictory line 5 aligned to "Dashboard" (line 27 was already correct). The
  nav **section** heading ("Overview") and every internal-only identifier
  (`OverviewPage`/`OverviewSnapshot`/`fetchOverview`/the `features/overview/` directory/the
  `["ops","overview"]` query key) were deliberately left unchanged — the section name already matches
  the migration plan's spec, and the internal identifiers are implementation detail with no
  admin/API-consumer/support-engineer visibility.
- **Affected surfaces:** new-frontend GUI labels + their e2e test pins, one design ADR. No change to
  REST API, route metadata, OpenAPI, the legacy GUI, or any Go source file.
- **Migration complexity/risk:** None. The v2 frontend is disabled by default
  (`CULVERT_EXPERIMENTAL_UI`) with zero production traffic; the change is two on-screen strings and
  their direct test pins, with no wire-format, config-key, or stable-API impact. Verified:
  `tsc --noEmit` clean, `vitest run` 141/141, `eslint` clean, `prettier --check` clean, `go build
  ./...` clean.
- **Priority:** Medium — confined to one unreleased surface, but the appliance's primary landing
  page, so worth fixing before the frontend's first production exposure rather than after.

---

## Carried over, still open (re-confirmed this pass against the 23-commit diff)

None of T-9 through T-39's dependent files (per each finding's own file list, as re-confirmed in the
08-21 review) were touched by this window's 23 commits, which are scoped to `internal/secscan`,
`internal/urlcat`, `metrics.go`, `proxy.go`, connection-limiter sharding, LDAP/CA-upload follow-ups
already covered by 08-21's own companion fixes, and the new `frontend/` tree. All nineteen remain
open, unchanged, at the same priorities and recommended fixes listed in
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-21.md`'s "Carried over" table and "Recommended Refactoring
Plan" — not re-derived here to avoid duplicating that review's content.

---

## Soft findings — no action recommended

- Carried over unchanged from 08-21 (Bootstrap dual-meaning, T3 seed vocabulary, `culvert_decrypt_*`
  abbreviation, CDR `cb`-prefix convention, the CA-status/MCP-tool-registry shared "usable" adjective,
  and the investigated-and-refuted `ssl_inspection: "unavailable"` vs. `cluster_ca: "disabled"`
  candidate).
- **New this pass, investigated and NOT escalated:** the new frontend's MCP-Gateway API bindings use
  `getMCPOverview`/`operations["getMCPOverview"]` (`frontend/src/api/types.gen.ts`) — a bare
  "Overview" naming a *different* concept (the MCP subsystem's own summary endpoint) than the
  Dashboard finding above. Checked against CLAUDE.md's existing tolerance for screen-scoped
  shared-word reuse (the same standard applied to the CA-status/MCP-tool-registry "usable" case in the
  08-21 review): this is an OpenAPI-generated binding name in a different namespace, with no on-screen
  adjacency to the Dashboard page's "Overview"/"Dashboard" labels and no admin-facing collision.
  No fix warranted.
- **New this pass, investigated and NOT escalated:** `docs/design/INFORMATION-ARCHITECTURE.md`
  documents `data-view` names as "kept verbatim (they are pinned by Playwright tests and the
  click-dispatch code); only grouping, order, labels, and icons change" for the *legacy* GUI's
  reorganization plan — unrelated to the v2 frontend finding above (different codebase, different
  test suite, not touched by this change) but noted here as a precedent this program should keep in
  mind if a future pass considers touching legacy `data-view` identifiers: the plan already commits to
  never renaming those, only their labels.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 08-21 for the still-open carry-over items; T-45 is resolved in this pass and does not
appear on the plan.

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium-High | T-39 (carried over) | Decide the QUAL-2/3 bootstrap-fleet name and the QUAL-4 policy-source name; rename `qualification_inventory_file`/`qualification_telemetry`/`qualification_policy_file` and their operator-doc titles/GUI strings away from bare "qualification"; reserve that word for the Production receipt gate | Medium | Small-Medium (needs a naming decision first) |
| High | T-38 (carried over) | Dual-emit `CapabilityHealth.ReviewRequiredTools`/`review_required_tools` alongside the existing `DriftedTools`/`drifted_tools`; update the GUI label; add both fields to the OpenAPI spec | Low (additive) | Small |
| Medium | T-18 (carried over) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI; rename the audit-event string | Low | Small-Medium |
| Medium | T-16 + T-43 pairing (carried over) | Renumber the Supportability-track's colliding ADRs (0008–0011 → 0019–0022) | Low (docs only) | Medium |
| Medium | T-21 + T-32 (carried pairing) | Rename Cluster panel's `cp_version` and F3b's `snapshot_sha256` to unambiguous, non-colliding names | Low | Small |
| Medium | T-17 (carried over) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped names | Medium | Medium |
| Medium | T-29 (carried over) | Alias YAML/CLI `rate_limit`/`-rate-limit` to accept `rate_limit_rpm` as well | Low-Medium | Small |
| Medium | T-30 (carried over) | Alias YAML `max_conns_per_ip` / wire `MaxConnsPerIP` toward `conn_limit_max_per_ip` | Low-Medium | Small |
| Medium | T-36 (carried over) | Give `saveConfigVersion`'s rollback call a `config.rollback`-prefixed action string alongside the version number | Low | Small |
| Medium | T-37 (carried over) | Rename `security.feeds_sync` → `threatfeed.sync`; update `security_feedsync_audit_test.go`'s three literal assertions | Low | Small |
| Medium | T-33 (carried over) | Stop overwriting `PolicyAction`/`PolicyReason` for pre-/post-policy gate failures; add a dedicated field for those instead | None today (zero production consumers); rises once a consumer exists | Small |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low / Medium-large | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*` | Medium | Medium |
| Low-Medium | T-31 (carried over) | Rename `culvert_clam_scan_errors_total` → `culvert_clamav_scan_errors_total`, dual-emit | Low | Small |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

---

## Stop-Condition Assessment

Terminology is **not** fully consistent, but this was a productive pass: one genuinely new,
previously-untracked finding was identified and fully fixed at zero migration risk (the v2
frontend's landing page disagreeing with its own API client, its own design spec, and the legacy
GUI), and all nineteen previously-open findings were re-confirmed unchanged against this window's
diff. Two candidate findings surfaced by this pass's audit of the new frontend batch
(`getMCPOverview`'s unrelated "Overview" usage; the legacy-GUI `data-view` verbatim-naming
precedent) were investigated and explicitly not escalated, for reasons recorded above. No cosmetic
or preference-driven renames were proposed.
