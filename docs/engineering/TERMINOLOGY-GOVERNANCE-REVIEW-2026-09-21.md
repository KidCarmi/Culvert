# Culvert Language & Terminology Governance Review — 2026-09-21

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Snapshot scope (read this first):** this is a HISTORICAL record of `origin/main` at `6c46ebd` on
> 2026-09-21. It was merged later, after `main` had moved on, so the tree it ships in contains commits it
> never audited. It uses two states, and says which one each part describes:
> - **At the audited snapshot (`6c46ebd`)**: the tree as audited. The findings (T-59, T-59b, T-59c, T-60,
>   the T-51 recurrence) and every file:line citation describe this state. Here the panel still says
>   "OCSP / CRL Revocation" and the "appliance" text is still present.
> - **After this PR's corrections**: `6c46ebd` plus the copy fixes this PR makes (the T-59 panel title
>   and its doc/roadmap references, and the nine T-51-recurrence lines), nothing else. T-59's title and
>   the T-51 recurrence lines count as fixed here and nothing else does. To reproduce it, apply the fixes
>   listed under T-59 and the T-51 recurrence to `6c46ebd`.
>
> The **open backlog** and the **health score** are each stated for BOTH states (the convention of the
> 2026-09-16 and 2026-09-19 reports). Fixes merged to `main` after `6c46ebd` — T-57 (#1407), T-58
> (#1434) and T-17 (#1444) — are NOT applied to either state; they appear only in a clearly labelled
> "for comparison" row.
>
> **Coverage limits:** the sweeps matched **literal patterns only** (the exact strings named in each
> finding and in the glossary table below) — a synonym or paraphrase that no pattern named is not claimed
> absent. CI workflow and script output was counted only where a `docs/operator/` runbook sends the
> reader to it; other workflow/script output was not audited.
>
> Neither state is the tree this file is published in; the current governance state is whatever the
> most recent review in this series says. Later windows are audited by later reports, never
> retroactively by this one.
> **Finding-ID note:** series finding IDs are assigned in report-date order. This report's panel-title
> finding was first published as "T-40" (already used by the 2026-08-07 report) and then as "T-57"
> (assigned to the 2026-09-16 report). It is **T-59**, and the finding added in review is **T-60**.
> **Method:** Audited `46410c3..6c46ebd` — the window since the 2026-09-11 report's own branch head
> (`46410c3`, PR #1363, merged to `main` in `0665453`). The end commit `6c46ebd` was confirmed as the then-current `origin/main` HEAD by a fetch immediately before this report was written on 2026-09-21 (the
> DEBT-014 lesson carried forward again: sync against `main` right before opening a PR). The window covers
> 21 first-parent merges / 154 files / ~29.4k insertions, dominated by two unrelated engineering streams:
> the MCP Agent Security Gateway's "first controlled canary" execution architecture (ADR-0035 —
> `internal/mcp/canary`, `internal/mcp/execution`, `internal/mcp/tooltrust`, `internal/mcp/policy`,
> `internal/mcp/upstreamclient`, the `mcp_canary_*.go`/`mcp_live_gate.go`/`ui_mcp_tooltrust.go` root files)
> and the CHAOS-65 OCSP revocation-checking engine (`internal/ocsp`, `ocsp_coverage.go`, `ocsp_metrics.go`,
> `mtls_ocsp_startup.go`) plus release-pipeline/CI work (catalog re-sign, R2 migration, release-gating
> scripts).
>
> **Correction (post-publication, same day):** this report's first published revision incorrectly cleared
> both engineering streams above of any finding, on two factual errors caught by `chatgpt-codex-connector`'s
> automated PR review (KidCarmi/Culvert#1456) before merge — see "Corrections made in review" below. This
> is the corrected revision; the errors are documented rather than silently fixed, since the review program
> auditing itself is exactly the kind of thing later passes need to be able to trust.

---

## Executive Summary

**One new terminology defect found and fixed this pass (T-59)** — a live admin-UI panel title named a
revocation mechanism (CRL) Culvert does not implement. **One recurrence of a closed finding, also fixed:**
the window reintroduced "appliance" in customer-facing text (T-51 recurrence, below), which
`docs/design/PRODUCT-TERMINOLOGY.md` forbids ("Appliance: *Not used* … the UI says node or instance").
**Three new open findings:** T-60 (the tool-trust decision route's OpenAPI entry names an audit event the
handler never emits), T-59b ("verdict" outside Diagnostics in 53 visible lines, 5 emitted OCSP
strings and 1 release-gate step-summary line) and T-59c ("policy rules" in the GeoIP diagnostics warning). T-59b and T-59c are lettered
sub-items of T-59 because they came out of the same glossary check of this window's new copy; they are
separate backlog entries.

Two bounded audits were run against the diff since the last review; the second one's original conclusion
was wrong and is corrected here.

1. **MCP "first controlled canary" naming surface** (ADR-0035, the largest single stream in this window):
   checked whether the new vocabulary — "canary", "tool trust" (`internal/mcp/tooltrust`), "reviewed
   operation" (`ReviewedOperationClass`), "live gate" (`internal/mcp/execution/livegate.go`,
   `mcp_live_gate.go`), "permit" (`internal/mcp/canary/permit.go`, `mcp_canary_policy_permit.go`),
   "read-first" (`mcp_canary_read_first.go`), "exact scope" / "no-credential" / "catalog-usable" (the
   `scripts/mcp-first-canary-*-mutations.sh` family) — collides with anything pre-existing. It does not:
   "Canary" is already an established rollout-ladder state name (`Disabled→Observe→Shadow→Canary→
   Production`, CLAUDE.md's MCP section, confirmed still the only "canary" usage surfaced in
   `static/index.html:20633,21003` — the mode-order map and the mode `<select>` options), so this window's
   canary-*execution* work is additive to an existing name, not a second concept reusing it.
   **Correction**: the first revision of this report claimed the new `internal/mcp/tooltrust` DTOs register
   "no independent route of their own," reasoning from the absence of a `mux.HandleFunc` call inside
   `ui_mcp_tooltrust.go` itself. That is true only of the file boundary, not the surface — `ui_mcp.go:166-167`
   registers `/api/mcp/tool-approvals` and `/api/mcp/tool-approval-decision` against handlers
   (`apiMCPToolApprovals`, `apiMCPToolApprovalDecision`) that ARE defined in `ui_mcp_tooltrust.go`, both
   already carrying `reviewed_operation_class` as a JSON field (`ui_mcp_tooltrust.go:95,163,254-286`), and
   the route is already generated into the OpenAPI spec and the React frontend's typed client
   (`frontend/src/api/types.gen.ts:2844-2881,13415`). So this is a live, wired, already-shipped API surface
   today, not a hypothetical future one — the original "flag for a future review" framing was wrong on its
   face. Re-auditing it directly: the wire vocabulary is, in fact, already internally consistent —
   `/api/mcp/tool-approvals` (the workflow: requesting/deciding an approval) and `reviewed_operation_class`
   (a sub-field classifying what the reviewer determined about the tool's effect, `read_only`/`mutating`)
   are legitimately two different concepts, not two names for one concept. The "tool trust" name DOES reach
   customer-facing surfaces, hyphenated: the OpenAPI summaries/descriptions say "MCP tool-trust approval(s)"
   and "tool-trust request" (`api/openapi/openapi.yaml:13018-13103`, carried into
   `frontend/src/api/types.gen.ts:2854-2879`), and the audit actions are `mcp.tooltrust.request`,
   `.reject`, `.revoke`, `.approve` and `.approve-live` (`ui_mcp_tooltrust.go:304,353,361,388,402`). (The
   first correction said there were zero wire uses; it searched only the unhyphenated spellings. A second
   review round caught it.) "Tool-trust approval" is used consistently across those surfaces as the name
   of the approval workflow, so the name itself is not drift. One real mismatch did turn up, recorded as
   **T-60** below: the OpenAPI spec says the decision route emits `mcp.tooltrust.decision`, an audit
   event the handler never writes.
2. **CHAOS-65 OCSP engine** (`internal/ocsp/ocsp.go` +655/-70, `ocsp_coverage.go`, `ocsp_metrics.go`): the
   `culvert_ocsp_*` metric family, the `coverage`/`uncheckedEnforcingPaths` fields on
   `GET /api/ocsp`, and `docs/operator/ocsp-revocation-checking.md` were spot-checked for cross-surface
   naming, and the names line up (metric names ↔ HELP text ↔ doc section headings). That name check was
   correct, but it did not read the surrounding prose against the glossary; the glossary sweep below
   records the "verdict" and "appliance" wording it missed. **Correction**: the original report went on to conclude "internal engine, no
   independent GUI panel — not a finding," which is factually wrong — `static/index.html:4477` carries a live
   panel titled **"OCSP / CRL Revocation"** (the title predates this window; the window added its coverage
   counter and banners). The panel is an "Enable OCSP checking" toggle plus four counters and three status
   banners, all about OCSP. Auditing that panel directly, as it should have
   been the first time, surfaces a real finding: see **T-59** below. The same stream also added
   "appliance" to the OCSP operator runbook and to an OpenAPI field description on `GET /api/ocsp`; see
   the T-51 recurrence below.

Release-pipeline changes in the window (`resign-catalog.yml`, `docs/operator/catalog-resign-runbook.md`,
`roadmap/R2-CATALOG-MIGRATION-PLAN.md`, the `.github/scripts/*` release-gating rewrite) are CI/operator-doc
surfaces already covered by CLAUDE.md's "Release catalog weekly re-sign (M1-4)" and "single origin (R2)"
notes; spot-checked the runbook title against the workflow name (`resign-catalog.yml` ↔ "Catalog Re-sign
Runbook") and the R2 terminology against CLAUDE.md's existing "R2 (`https://catalog.culvertlabs.com`)"
description — the names are consistent. The glossary sweep below records the release-gating runbook's
"verdict" and "appliance" wording.

**Spot-checked carry-over items at their cited locations** in the audited tree (`6c46ebd`): T-12, T-13,
T-29 and T-30 (below), plus T-54, T-55, T-56, T-57, T-58 and the T-51 residual, whose checks and
reproduction commands are under "Carried-Over Findings". The other carry-over findings (T-9, T-11, T-17,
T-18, T-21+T-32, T-25, T-33, T-34, T-39) were not re-verified; they are carried over with their original
evidence.
- **T-13**: `docs/enterprise/TLS-INSPECTION-DEPLOYMENT.md:1` is still titled "TLS Inspection Deployment"
  (in-app/API/GUI still say "SSL Inspection", e.g. in `static/index.html`, `healthcheck.go`'s
  `ssl_inspection` field, `policy.go`'s `SSLAction`) — unchanged.
- **T-29/T-30**: `config.go:56-57` still spells the two settings `rate_limit`/`max_conns_per_ip` in YAML
  with no `rate_limit_rpm`/`conn_limit_max_per_ip`-style alias; the live admin API (`ui_config.go`), the
  config-version/export payload (`ui_policy.go`), and `admin_settings.json` (`admin_settings.go:36`) still
  disagree on the connection-limit field's spelling exactly as the 2026-09-11 report described — unchanged.
- **T-12**: `cmd/culvert-maint/internal/server/handlers_upgrade.go:1,3,80` still exposes
  `POST /v1/upgrades/check`/`apply` with no `/v1/updates/*` alias, while the GUI still says "Dispatch
  Release" — unchanged.

**Terminology Health Score — audited snapshot `6c46ebd`: 7.8 / 10; after this PR's corrections:
7.9 / 10** (lineage figures; they inherit an unreconciled 0.1 under-charge for T-54 — see below).

- **Rule** (unchanged from the 2026-09-08 precedent, as applied by the 2026-09-19 report): each open
  backlog item a report newly records costs 0.1, and each item it fixes gives 0.1 back, so an item found
  and fixed in the same pass nets zero. An item already charged by an earlier report is never charged a
  second time.
- **Baseline: 8.2**, the 2026-09-19 report's figure for its audited snapshot `36628eb` (T-57 and T-58
  both open). That is the right baseline for `6c46ebd`: `36628eb` is an ancestor of `6c46ebd`, and every
  fix merged since that report's snapshot — T-57 (#1407), T-58 (#1434), T-17 (#1444) — merged AFTER
  `6c46ebd`, so all three are still open in the tree this report audited. The 8.2 is the
  INHERITED, UNRECONCILED lineage figure: it charges T-55, T-56 and the reopened T-51 residual
  (2026-09-13), T-57 (2026-09-16) and T-58 (2026-09-19), but it omits T-54's 0.1 charge (2026-09-12),
  for the reason disclosed below. None of those items is charged again here, and T-54's missing 0.1 is
  not restored either.
- **Audited snapshot `6c46ebd`:** four new open IDs — T-59, T-59b, T-59c, T-60 → 8.2 − 0.4 = **7.8**.
- **After this PR's corrections:** this PR fixes T-59 → 7.8 + 0.1 = **7.9**. T-59b, T-59c and T-60 stay
  open.
- **The T-51 recurrence moves neither figure.** It is new text under an ID the backlog already carries
  as open (the T-51 residual, charged by the 2026-09-13 report), so charging it would double-charge
  T-51. Fixing the recurrence lines does not close the residual either: the residual is the "appliance"
  text in the new frontend's PAC and Policy Learning directories (12 files at `6c46ebd`), which this PR
  does not touch.
- **For comparison only (not a claim about any audited tree):** applying the same rule to "after this
  PR's corrections" plus the three later fixes (T-57, T-58, T-17) gives 7.9 + 0.3 = 8.2 (same lineage,
  same 0.1 T-54 under-charge).
- **Disclosed, not amended (carried from the 2026-09-16 and 2026-09-19 reports):** the 2026-09-13 report
  measured its drop from 8.7 rather than from the 2026-09-12 report's 8.6, so T-54's 0.1 charge was not
  carried into its 8.4. Merged reports' scores are not amended retroactively; this report takes the
  merged figures as recorded. It therefore neither restores T-54's missing 0.1 nor charges T-54 again:
  7.8 and 7.9 are lineage figures that UNDER-charge by 0.1. For transparency only, the fully charged
  equivalents are **7.7** (audited snapshot) and **7.8** (after this PR's corrections); they are not
  this report's score.
- **Disclosed, not amended — a second, parallel lineage:** the 2026-09-20 report (#1444, the T-17 fix,
  merged after `6c46ebd`) records **8.8 / 10, up from 8.7**, with twelve open backlog entries. It scores
  from the 2026-09-11 report's lineage and does not count T-54..T-58 or the T-51 residual, so its 8.8
  and this chain's figures are not comparable. This report does not amend it; reconciling the two
  lineages is left to an owner (see the PR description).

(Earlier revisions of this report said "8.3, down from 8.6" with a seventeen-entry backlog. That started
from the 2026-09-12 report's 8.6 and omitted T-55, T-56, T-57, T-58 and the T-51 residual, all of which
were open at `6c46ebd`. It is corrected here rather than silently replaced.)

---

## Corrections made in review

`chatgpt-codex-connector[bot]`'s automated review on KidCarmi/Culvert#1456 caught two factual errors in
this report's first published revision before merge, both now fixed above:

1. **P2 — "Audit the existing tool-approval routes."** Correctly identified that `ui_mcp.go:165-167`
   already registers `/api/mcp/tool-approvals` and `/api/mcp/tool-approval-decision` against handlers that
   already carry `reviewed_operation_class`, contradicting this report's claim that no route existed yet.
   Verified directly (`grep -n "tool-approval" ui_mcp.go`, `grep -rn "ReviewedOperationClass" *.go`,
   `grep -rn "tool-approval" frontend/src/`) and corrected in Executive Summary item 1 above. On
   re-investigation the underlying conclusion (not a terminology finding) still holds, but the report's
   original reasoning for reaching it — "the surface doesn't exist yet" — was simply wrong, and the
   surface should have been checked directly rather than deferred.
2. **P2 — "Account for the existing OCSP admin panel."** Correctly identified that the audited window
   modifies the live `static/index.html` panel titled "OCSP / CRL Revocation," so characterizing the OCSP
   work as "an internal engine with no independent GUI panel" was factually incorrect, and specifically
   flagged the panel's CRL label despite the operator runbook and CLAUDE.md both stating there is no CRL
   fallback. Verified directly (`Read static/index.html:4470-4499`; `grep -rn "CRL" internal/ocsp/*.go
   ocsp_coverage.go ocsp_metrics.go docs/operator/ocsp-revocation-checking.md` — the runbook's one hit is
   itself just quoting the panel title back, confirming no CRL logic exists anywhere in the subsystem) and
   promoted to a new finding, **T-59**, below.

Both errors trace to the same root cause: the original audit searched only the files the diff touched
directly for GUI/API surfacing (`ui_mcp_tooltrust.go` for routes; the diff's own `.go` files for a GUI
panel) instead of checking the actual live rendered surface (`static/index.html`, the route-registration
file, the generated OpenAPI/TS client) that a real admin or support engineer would see. Recorded as a
process note for future passes: "no GUI/API surface found" is a claim that must be verified against the
rendered surface directly, not inferred from which files a diff touched.

Later review rounds found more errors, also fixed:
- The report itself used "appliance", which the glossary forbids. It also declared the window clean of
  that word, when the window had added it to customer-facing text (now the T-51 recurrence below).
- The report reused the ID T-40 (now T-59).
- Roadmap text still described the current panel as "OCSP / CRL" (now annotated as historical or
  corrected; see T-59).
- The "zero wire uses of tool trust" claim missed the hyphenated "tool-trust" in the OpenAPI/TS text
  and the `mcp.tooltrust.*` audit actions (corrected in item 1; the check turned up T-60).
- Two citations were wrong: the admin-settings connection-limit field is `admin_settings.go:36`, not
  `:33`, and the `/api/ocsp` field is `coverage`, not `ocsp_coverage`.

---

## New Findings This Pass

### T-59 — Admin-UI panel titled "OCSP / CRL Revocation" names a capability that does not exist (High) — FIXED this pass

- **Concept**: certificate-revocation checking for upstream/inspected TLS connections, and which
  mechanisms Culvert actually uses to perform it.
- **Names found**: the live admin panel (`static/index.html:4477`, present in production, not
  experimental/behind a flag) is titled **"OCSP / CRL Revocation"**, with a toggle labeled "Enable OCSP
  checking" and four counters/banners underneath, every one of them OCSP-specific (`ocsp-cache-len`,
  `ocsp-revoked-total`, `ocsp-failclosed-total`, `ocsp-rejected-total`, the coverage/borrowed-response/
  fail-closed banners — all confirmed OCSP-only content, `static/index.html:4478-4495`). Its own operator
  runbook, `docs/operator/ocsp-revocation-checking.md:4`, quotes the panel title verbatim as
  "**OCSP / CRL Revocation** toggle in the admin UI" and then documents only OCSP behavior. CLAUDE.md's own
  CHAOS-65 Architecture Note explicitly records, as a deliberately-open item: *"no CRL fallback... a
  certificate carrying no AIA responder still accepted unchecked (OCSP-10)"*.
- **Why real, and why High**: this is not a cosmetic label mismatch — it is a security-relevant capability
  claim with no implementation behind half of it. `grep`ing the entire OCSP subsystem (`internal/ocsp/*.go`,
  `ocsp_coverage.go`, `ocsp_metrics.go`) for `CRL` returns **zero** hits outside the one line in the
  runbook that is quoting the panel's own title back. There is no CRL fetch, no CRL cache, no CRL config
  surface, no CRL toggle, no CRL counter — nothing. An admin who reads the panel title, sees "Enable OCSP
  checking" turned on, and reasonably infers "revocation checking, via OCSP or CRL as needed" now has a
  false sense of coverage for exactly the gap CLAUDE.md records as open: a certificate with no OCSP AIA
  responder at all is accepted **unchecked** today, and nothing in the CRL half of the panel's promise
  would catch that, because there is no CRL half. This is precisely the failure mode this governance
  program's brief singles out — "internal-implementation names exposed to users" runs the other direction
  here (a business-facing label promising more than the implementation delivers), but it is the same class
  of harm: an admin, a security engineer, or a support engineer trusts a label that does not describe what
  the product does.
- **Canonical direction, applied in this same PR**: renamed the panel to **"OCSP revocation"**, in sentence case per `PRODUCT-TERMINOLOGY.md`'s casing rule (dropped
  "/ CRL" until CRL fallback, register row OCSP-10, actually ships; OCSP-9 is stapling, a separate gap) and
  updated `docs/operator/ocsp-revocation-checking.md`'s one reference to match
  (`static/index.html:4477`, `docs/operator/ocsp-revocation-checking.md:4`). Roadmap text that describes the
  current UI was brought in line: `roadmap/UI-DESIGN.md`'s Certificates-panel feature list now says "OCSP
  toggle", and the two places `roadmap/CHAOS-ENGINEERING-REVIEW.md` state the panel title (register row
  OCSP-10 and the §35 residuals list) are annotated as the title at the time, since renamed. The
  historical description itself is kept. This was a pure label
  correction. No API field, metric name, config key or audit event of the OCSP revocation checker uses
  "CRL" (per the same-subsystem grep above), so there was no wire-compatibility obligation and no
  migration plan was needed. "CRL" does appear elsewhere in the tree, but not for this checker: the
  cluster enrollment revocation list for node certificates (`enrollment.go`, `controlplane_server.go`) is
  a separate mechanism; `internal/ca/ca.go` uses the stdlib `x509.KeyUsageCRLSign` constant; and code
  comments in `mtls_ocsp_startup.go`, `mtls_ocsp_startup_config.go` and `ui_security.go:1816` (the
  `apiOCSPConfig` doc comment) still say "OCSP/CRL". Those comments are internal and were not changed.
  If CRL fallback is added in the future, "OCSP / CRL Revocation" becomes accurate again and can be
  restored at that time.
- **Split out**: the OCSP copy's "verdict" wording, first recorded here as a sub-item, is now part of
  **T-59b** below, which is open.
- **Affected surfaces**: GUI (`static/index.html:4477`), one operator-doc reference
  (`docs/operator/ocsp-revocation-checking.md:4`), and three roadmap lines. No API/config/audit/metric
  surface uses "CRL."
- **Migration complexity**: trivial (label and prose only, no wire contract) — applied. **Compatibility
  risk**: none. **Actual PR size**: XS.

### T-59b — "verdict" used outside Diagnostics in this window's new copy (Low) — OPEN

- **Rule**: the glossary reserves "verdict" for Diagnostics checks (`PRODUCT-TERMINOLOGY.md`, Decision
  row). This window's new copy uses it for other things. Counts come from the "Glossary term sweep" below.
- **Scope at `6c46ebd`**: 53 visible lines, 5 strings the OCSP code emits, and 1 line of CI output that an
  operator runbook tells the reader to read (59 lines in all).
  - OCSP (13 visible lines + 5 emitted strings). Required rewording: "response" where the text means what
    the responder sent, "status" where it means `good`/`revoked`. Line numbers at `6c46ebd`:
    - `static/index.html:4484` "Fail-closed (no usable verdict)" → "(no usable response)"; `:4491`
      "revocation verdicts from the affected upstream" → "revocation responses"; `:4494` "a usable,
      affirmative verdict" → "a usable, affirmative status".
    - `api/openapi/openapi.yaml:488` (`unauthorizedResponderTotal`) "a certificate signing a verdict about
      itself" → "a response about itself" (carried into `openapi.json` and `types.gen.ts` on regeneration).
    - `docs/operator/ocsp-revocation-checking.md:39`, `:49`, `:50`, `:91`, `:95`, `:144` → "status" or
      "response" as above ("cached verdicts" → "cached statuses").
    - `CHANGELOG.md:226`, `:232`, `:259` (the CHAOS-65 entry).
    - Emitted strings: `internal/ocsp/ocsp.go:424` (error: "no responder returned a usable verdict"),
      `:573` (log line: "no usable verdict from … responder(s)"), and the `/metrics` HELP texts at
      `ocsp_metrics.go:38` ("affirmative verdict"), `:42` ("Verdicts currently cached") and `:55`
      ("without producing a verdict").
  - Outside OCSP (40 visible lines): 35 in `docs/operator/mcp-first-controlled-canary-review.md`, 3 in
    `docs/operator/release-publication-gating.md` (`:22`, `:60`, `:455`) and 2 in `CHANGELOG.md` (`:15`,
    `:391`). The file:line list and the 2 exempt identifier lines are in the sweep below.
  - Release-gate step summary (1 line): `.github/scripts/require-release-evidence.sh:94` writes the table
    header `| workflow | class | verdict |` to `$GITHUB_STEP_SUMMARY`. The release-gating runbook sends
    operators to that table ("open the step summary. It prints a table of every row and its verdict",
    `docs/operator/release-publication-gating.md:454-455`), and the runbook's own uses already count
    above. Rewording: "outcome". Found by the third sweep pass below.
- **Not fixed in this PR**: rewording the MCP review touches many lines of a document other PRs edit, and
  the OCSP HELP and error strings are code changes. It needs its own change.

### T-59c — "policy rules" in the GeoIP diagnostics warning (Low) — OPEN

- **Rule**: the glossary says "rule" for a Stage-2 `PolicyRule` ("policy rule" is listed as a term it
  replaces).
- **Found at `6c46ebd`**: the `geo_resolution` diagnostics row's warning says "country-scoped policy rules
  are not matching…" (`geoip_resolve_health.go:322`). It is the only added Go string literal containing
  "policy rule" (reproduce with the second-pass command in the sweep below).
- **Recommended action**: reword to "country-scoped rules". Not done in this report PR, because it is a
  code change.

### T-60 — The tool-trust decision route documents an audit event the handler never emits (Low) — OPEN

- **Names found**: `POST /api/mcp/tool-approval-decision` declares `x-culvert-audit-event:
  mcp.tooltrust.decision` (`api/openapi/openapi.yaml:13103`). `docs/api/API-STYLE-GUIDE.md:35` defines that
  extension as "the audit event the handler emits". The handler emits one of `mcp.tooltrust.reject`,
  `.revoke`, `.approve` or `.approve-live`, depending on the action (`ui_mcp_tooltrust.go:353,361,388,402`).
  No `mcp.tooltrust.decision` event exists. (The request route's `mcp.tooltrust.request` matches
  `ui_mcp_tooltrust.go:304`.)
- **Also in scope (same class: the tool-trust OpenAPI entries do not describe what the handlers
  return)**: `GET /api/mcp/tool-approvals` serializes `reviewed_operation_class` with
  `ReviewedOperationClass.String()`, which returns `read_only`, `mutating` or `unset`
  (`internal/mcp/tooltrust/reviewed_operation.go`; the struct comment at `ui_mcp_tooltrust.go:91-94` says
  "read_only | mutating | unset"). The spec documents only the request enum `read_only | mutating`
  (`api/openapi/openapi.yaml:13078`) and types the response as an untyped `additionalProperties: true`
  object, so an admin-visible `unset` is documented nowhere in the API. The 2026-09-24 report (#1492,
  not merged when this revision was written) recorded this; it is folded into T-60 rather than given a new ID. Fix: document the response values.
- **Why it matters**: an operator or SIEM author who takes the spec at its word and searches or alerts on
  `mcp.tooltrust.decision` finds nothing, so approvals and revocations of MCP tools look unaudited.
- **Recommended action**: make the spec name the events the handler actually writes, e.g. the family
  `mcp.tooltrust.{approve,approve-live,reject,revoke}`, if the extension grammar allows it. Otherwise
  document the four events in the operation description. Not done this pass: it is an API-contract
  change, and whether the extension may carry more than one event is a style-guide decision.
- **Compatibility risk**: none for the audit trail (the emitted events do not change). The spec text
  changes.

### T-51 recurrence — "appliance" reintroduced in customer-facing text (Low) — FIXED this pass

- **Rule**: `docs/design/PRODUCT-TERMINOLOGY.md` governs UI labels and docs: "Appliance: *Not used.*
  Culvert deploys as binary/container; the UI says **node** or **instance**." T-51 (2026-08-29) removed
  the last labeled uses and deliberately left internal names alone (code comments, the
  `x-culvert-tenant-scope: appliance` vendor-extension value, component-module names).
- **Complete inventory.** `git diff 46410c3 6c46ebd -U0 | grep -v '^+++' | grep -iE '^\+.*appliance'`
  finds 24 added lines. The `grep -v '^+++'` drops diff file headers, and the `^\+` filter drops the one
  removed line that also matches. Line
  numbers below are at `6c46ebd`. Each one is classified here:
  - **User- or operator-visible text — fixed.** The glossary defines "Node" as an enrolled cluster member,
    and none of these lines is about clustering: each describes whatever Culvert process is running,
    clustered or not. So each now says "Culvert" or "instance" (the glossary's other permitted word), not
    "node". (An earlier revision of this PR used "node"; that was corrected in review.)
    - OpenAPI `GET /api/ocsp` `uncheckedEnforcingPaths` description: `api/openapi/openapi.yaml:483` →
      "Paths where this Culvert instance validates…"; `openapi.json` regenerated by `make api-bundle`, and
      `frontend/src/api/types.gen.ts` regenerated by the pinned generator (openapi-typescript v7.13.0).
    - `docs/operator/ocsp-revocation-checking.md:22` → "Culvert states it in three places"; `:122` →
      "directly from the Culvert instance".
    - `docs/operator/geoip-resolution-health.md:36` → "on an instance with no GeoIP database".
    - `docs/operator/release-publication-gating.md:547` → "Because Culvert verifies".
    - `CHANGELOG.md:276`, the CHAOS-65 release note → "Culvert now says so".
    - `.github/workflows/publish-catalog-r2.yml:104`, an `::error::` message printed in the Actions log →
      "being served to any Culvert instance, and installed instances will go stale".
  - **Left as is — internal comments, tests and engineering records, not read by an operator in the
    product** (T-51's disposition):
    - Code comments: `geoip_resolve_health.go:292`, `ocsp_coverage.go:19` and `:84`, `ocsp_metrics.go:16`.
      None is part of an emitted string.
    - Test comments: `internal/ocsp/ocsp_chaos_test.go:1051`, `mcp_live_execution_e2e_test.go:66` and
      `:82`, `ocsp_coverage_test.go:87`.
    - Workflow YAML comments (not printed): `.github/workflows/publish-catalog-r2.yml:75`,
      `.github/workflows/resign-catalog.yml:124`.
    - `CLAUDE.md:181` and `:227`: contributor and agent instructions, not product documentation.
    - `roadmap/CHAOS-ENGINEERING-REVIEW.md:1002`, `:6107` and `:6163`: the engineering review register.
- **How the fix was verified**: `make api-bundle` regenerated `openapi.json`, and `make api-bundle-check`
  passes. `types.gen.ts` is byte-identical to the output of the pinned generator (openapi-typescript
  v7.13.0).
- **Review note**: earlier review rounds found these one at a time. This inventory is the complete list
  for the window, so a later pass can check it rather than rediscover it.
- **Compatibility risk**: none — description text and prose only; no field, path or schema changed.

---

## Glossary term sweep

The literal terms `docs/design/PRODUCT-TERMINOLOGY.md` forbids, reserves or replaces were checked against
the lines this window ADDED. The counts below come from the tool, not from hand-tallying. For each term:
`git diff 46410c3 6c46ebd -U0 | grep -v '^+++' | grep -ciE '^\+.*<pattern>'` gives "Added lines" (a case-insensitive
substring match, so identifiers such as `permitVerdictInvariant` count). The file:line lists come from
the same diff, with line numbers at `6c46ebd`. "Visible" means `static/index.html`, non-test
`frontend/src`, `api/openapi/openapi.yaml`, `docs/` outside `docs/engineering`, `docs/design` and
`docs/adr`, `CHANGELOG.md` and `README.md`. Generated copies (`openapi.json`, `types.gen.ts`) follow the
YAML and are not counted.

The sweep covers only the literal patterns in the table below: the glossary's forbidden or replaced
words, matched as substrings. It does **not** cover the glossary's context-sensitive rules, which a pattern
count cannot decide and which this pass did not check: "policy" used loosely for a single rule, bare
"profile" on the steering-profile screen, "status" used for a health roll-up, "user" where it could mean
a console account, "kill switch" without its qualifier (the table counts the literal only),
"exception"/"bypass"/"allowlist" used for the wrong kind of skip, and sentence case. A term missing from
the table, or a zero count, is not evidence that those rules hold.

| Term (pattern) | Added lines | Visible | Visible lines (file:line) | Outcome |
|---|---|---|---|---|
| appliance (`appliance`) | 24 | 6 | `CHANGELOG.md`: 276; `api/openapi/openapi.yaml`: 483; `docs/operator/geoip-resolution-health.md`: 36; `docs/operator/ocsp-revocation-checking.md`: 22,122; `docs/operator/release-publication-gating.md`: 547 | Fixed; see the T-51-recurrence list (which also counts the generated `openapi.json`/`types.gen.ts` copies and the workflow `::error::` line, for 9) |
| verdict (`verdict`) | 380 | 55 | `CHANGELOG.md`: 15,226,232,259,391; `api/openapi/openapi.yaml`: 488; `docs/operator/mcp-first-controlled-canary-review.md`: 51,392,970,1111,1124,1133,1251,1252,1253,2196,2203,2223,2228,2273,2489,2502,2533,2542,2543,2545,2558,2592,2646,2693,2702,2818,2902,2916,2992,3072,3080,3118,3293,3358,3559,3589,3635; `docs/operator/ocsp-revocation-checking.md`: 39,49,50,91,95,144; `docs/operator/release-publication-gating.md`: 22,60,455; `static/index.html`: 4484,4491,4494 | T-59b (open): 13 OCSP lines and 40 others below; 2 identifier-only lines (`:2558`, `:2592`) exempt |
| result (`result`) | 75 | 7 | `CHANGELOG.md`: 417; `docs/operator/mcp-first-controlled-canary-review.md`: 2255,2402,2908,3116; `docs/operator/ocsp-revocation-checking.md`: 77; `docs/operator/release-publication-gating.md`: 362 | None means a request's decision (campaign, query and release results) — no violation |
| incident (`incident`) | 5 | 1 | `docs/operator/mcp-first-controlled-canary-review.md`: 886 | Plain English ("during an incident"); no entity invented — no violation |
| scanner (`scanner`) | 6 | 3 | `docs/operator/mcp-first-controlled-canary-review.md`: 2967,3212,3236 | A code scanner in a test wall, not a scanning engine — no violation |
| policy rule (`policy rule`) | 6 | 1 | `docs/operator/mcp-first-controlled-canary-review.md`: 3476 | An MCP gateway policy rule, not a Stage-2 `PolicyRule` — no violation |
| exclusion (`exclusion`) | 33 | 6 | `docs/operator/mcp-first-controlled-canary-review.md`: 397,795,816,1104,1248,2807 | The MCP rollout-scope "exclusions" field, not an inspection bypass — no violation |
| kill switch (`kill.?switch`) | 2 | 0 | — | Test identifiers only (`EngageKillSwitch`/`ClearKillSwitch`) |
| unauth mode, threat engine, Cluster Nodes, blacklist/whitelist, Live Feed, Live Request Log, Recent Requests, Users & Roles, proxy pool | 0 each | 0 | — | — |

**Strings emitted by Go code.** The file-based "visible" rule does not cover strings that non-test Go
code prints to operators. A second pass, `git diff 46410c3 6c46ebd -U0 -- '*.go' ':!*_test.go' | grep -v '^+++' |
grep -iE '^\+.*"[^"]*<pattern>[^"]*"'`, checked added string literals for each term:
- "verdict": 7 lines. Five are the OCSP error, log and HELP strings (under T-59b). One is a code
  comment that quotes a phrase (`internal/ocsp/ocsp.go:485`). One is the MCP reason-code value
  `policy_verdict_not_invariant` (`internal/mcp/canary/permit.go`), a wire identifier, not prose.
- "policy rule": 1 line, and it is a hit. The GeoIP diagnostics row's warning message says
  "country-scoped policy rules are not matching…" (`geoip_resolve_health.go:322`). The glossary
  says "rule" for a Stage-2 `PolicyRule`. Recorded as **T-59c** (open); the rewording is "country-scoped
  rules".
- "exclusion": 2 lines, both identifiers (the `first_canary_exclusions_forbidden` reason code and an
  `"exclusions"` map key in the MCP scope code).
- "appliance", "result", "incident", "scanner", "kill switch": 0 lines.

**Emitted text outside Go.** Neither pass above covers text that non-Go files print: workflow
`::error::`/`::warning::` annotations, `$GITHUB_STEP_SUMMARY` writes, and shell or installer output. A
third pass covers them: `git diff 46410c3 6c46ebd -U0 -- '.github/**' 'scripts/**' 'packaging/**' '*.sh'
'Dockerfile*' 'Makefile' 'docker-compose*.yml' ':!*.json' | grep -v '^+++' | grep -iE '^\+.*(<any term
above>)' | grep -vE '^\+\s*#'` finds 11 added non-comment lines for all the terms together (JSON data files
such as the shard-timing tables are excluded; they hold test names, not printed text). Such output counts as
operator-visible only when a page under `docs/operator/` tells the reader to read it; otherwise it is CI
or contributor tooling output read by maintainers, which the glossary does not govern. The 11 lines:
- `.github/scripts/require-release-evidence.sh:94`, `summary "| workflow | class | verdict |"`: operator-
  visible under that rule (`release-publication-gating.md:454-455`). A hit, recorded under **T-59b**.
- `.github/workflows/publish-catalog-r2.yml`, the `::error::` line with "appliance": already in the T-51
  recurrence and fixed.
- 9 lines in `scripts/mcp-*-mutations.sh`: mutation-test descriptions and `sed` patterns (2 "verdict", 3
  identifier `PermitVerdictNotInvariant`, 3 "exclusion", 1 "result"). These are contributor test tooling,
  not operator output. No violation.

**Recorded under T-59b — "verdict" outside OCSP (40 visible prose lines).** These use "verdict"
for something other than a Diagnostics check, which breaks the same reservation:
- `docs/operator/mcp-first-controlled-canary-review.md`: 35 of the 37 lines listed above. The review uses
  "verdict" for its own conclusions and for policy decisions, including in the prose around test and
  function names.
- `docs/operator/release-publication-gating.md:22`, `:60`, `:455`: a CI gate's outcome.
- `CHANGELOG.md:15` (a CI gate's outcome) and `:391` (rate-limit exemption verdicts).

**Identifier-only, exempt (2 lines).** `mcp-first-controlled-canary-review.md:2558` and `:2592` contain
"verdict" only inside the backend identifiers `permitVerdictInvariant` and `PermitVerdictNotInvariant`.
The glossary exempts backend identifiers from renaming (as with `policy_verdict_not_invariant` above), so
they are not violations. They are the only two of the 37 MCP lines with no whole-word "verdict";
reproduce with `git diff 46410c3 6c46ebd -U0 -- docs/operator/mcp-first-controlled-canary-review.md |
grep -v '^+++' | grep -iE '^\+.*verdict' | grep -viE '(^|[^a-z])verdict'`. Of the 55 visible lines, 53 are
therefore violations (all under T-59b: 13 OCSP and 40 recorded here) and 2 are exempt identifiers.

None of the 53, and none of the emitted lines in T-59b, is fixed in this report PR; see T-59b.

## Carried-Over Findings

Every ID below is carried as open at the audited snapshot `6c46ebd`; the ones re-checked there are
named below, the rest were not re-verified. None is fixed by this PR, so each is also open after this
PR's corrections. Full descriptions live in the report that owns each ID and are not
restated here, to avoid two descriptions of one item drifting apart:

- T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21+T-32 (paired), T-25 (residual), T-29, T-30, T-33,
  T-34, T-39 — owned by `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md` (the last report in this chain to
  restate them in full). T-12, T-13, T-29 and T-30 were spot-checked (Executive Summary); the rest were
  not re-verified. T-17 is fixed on `main` by #1444, which merged after `6c46ebd`.
- **T-54** — owned by `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-12.md` (#1372). See "T-54 at `6c46ebd`"
  below.
- **T-55** — owned by `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-13.md` (#1380). Present at `6c46ebd`: the
  legacy GUI says "Accept to Draft" (`static/index.html`, 3 lines) and the new frontend says "Accept to
  Policy Draft" (`LearningRecommendations.tsx`, 4 lines).
- **T-56** — owned by the 2026-09-13 report (doc half fixed there; code half open). Present at
  `6c46ebd`: no file under `frontend/src/features/network/pac/` contains "steering profile".
- **T-51 (residual)** — owned by the 2026-09-13 report. Present at `6c46ebd`: "appliance" still occurs
  (comments included) in 12 non-test files under the new frontend's PAC and Policy Learning feature
  directories. Distinct from this report's T-51 recurrence (above), which is in other files.
- **T-57** — owned by `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-16.md` (#1407). Present at `6c46ebd`:
  `static/index.html:5184,6119,16205` still say "diagnostic bundle". Fixed on `main` by #1407, which
  merged after `6c46ebd`.
- **T-58** — owned by `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-19.md` (#1434). Present at `6c46ebd`:
  `frontend/src/features/policy/RuleEditor.tsx:437` ("SSL action") and `:508` ("SSL Inspect)"). Fixed on
  `main` by #1434, which merged after `6c46ebd`.

**T-54 at `6c46ebd`.** The 2026-09-12 report (audited `d378dff..2833db3`; `2833db3` is an ancestor of
`6c46ebd`) opened T-54, and nothing in this window closed it. Checked at `6c46ebd`: the admin JSON in
`ui_security.go:1843-1845` still says `malformedResponseTotal`, `staleResponseTotal` and
`unknownStatusTotal`, against the Go accessors `MalformedTotal()`/`StaleTotal()`/`UnknownTotal()`
(`internal/ocsp/ocsp.go`) and the `/metrics` labels `malformed`/`stale`/`unknown_status`
(`ocsp_metrics.go:59-61`); and `reason="responder_blocked"` (`ocsp_metrics.go:62`) is still reported in
the same "responses discarded" series. It stays open. The first revisions of this report left T-54 out
of the backlog; that was an omission, now corrected.

**Backlog count:**

| State | Open IDs | Backlog entries (T-21+T-32 counted once) |
| --- | --- | --- |
| 2026-09-19 report, its audited snapshot `36628eb` (T-57, T-58 open) | 20 | 19 |
| Audited snapshot `6c46ebd` (adds T-59, T-59b, T-59c, T-60) | 24 | 23 |
| After this PR's corrections (T-59 fixed) | 23 | 22 |
| For comparison only: after this PR's corrections plus #1407 (T-57), #1434 (T-58) and #1444 (T-17) | 20 | 19 |

The T-51 recurrence adds no row: it is new text under the already-open T-51 ID (see the score section).
T-59 stays in the numbering series as a closed ID; IDs are never renumbered.

### Reproduction commands

Run from any clone that has fetched `6c46ebd` (`git grep -c` prints one `path:count` line per matching
file):

```sh
R=6c46ebd
# T-59 (audited snapshot): expect one hit, static/index.html:4477
git grep -n 'OCSP / CRL Revocation' $R -- static/index.html
# T-58: expect RuleEditor.tsx:437 and :508
git grep -n -e 'SSL action' -e 'SSL Inspect)' $R -- frontend/src/features/policy/RuleEditor.tsx
# T-57: expect three hits, at lines 5184, 6119 and 16205
git grep -n -i 'diagnostic bundle' $R -- static/index.html
# T-54: expect one hit each
git grep -n 'func (oc \*Checker) UnknownTotal()' $R -- internal/ocsp/ocsp.go
git grep -c '"malformedResponseTotal"' $R -- ui_security.go
git grep -c '"staleResponseTotal"' $R -- ui_security.go
git grep -n 'reason=\\"responder_blocked\\"' $R -- ocsp_metrics.go
# T-55: expect static/index.html:3 and LearningRecommendations.tsx:4
git grep -c 'Accept to Draft' $R -- static/index.html
git grep -c 'Accept to Policy Draft' $R -- frontend/src/features/learning/LearningRecommendations.tsx
# T-56: expect 0
git grep -l -i 'steering profile' $R -- frontend/src/features/network/pac/ | wc -l
# T-51 residual: expect 12
git grep -l -i 'appliance' $R -- 'frontend/src/features/network/pac/*' \
  'frontend/src/features/learning/*' ':!*.test.*' | wc -l
# T-60: expect no output (no emitter of the documented event)
git grep -n 'tooltrust.decision' $R -- '*.go'
```

The "Content & Scanning" (legacy GUI) vs. "Content Security" (new React frontend) soft finding — a
non-mechanical naming-policy reconciliation between two deliberate design decisions, not a numbered backlog
item — also remains unresolved, per 2026-09-09's reasoning, and was not revisited this pass.

---

## Stop-Condition Assessment

**Does not apply cleanly this pass — a production-worthy terminology defect (T-59) was identified and
fixed**: a security-adjacent GUI label naming a revocation mechanism (CRL) that does not exist in the
implementation, corrected in this same PR (XS, no migration risk, no wire surface affected). A recurrence
of the closed T-51 ("appliance" in customer-facing text) was also fixed. Three new low-priority findings
are left open: T-60 (a documented audit event the tool-trust decision handler never emits), for an
API-contract change; T-59b ("verdict" outside Diagnostics) and T-59c ("policy rules" in the GeoIP
warning), for copy and string changes in their own PRs. Once re-audited, the MCP
canary-execution stream produced T-60 (see "Corrections made in review") and 35 of T-59b's lines.
The twenty-ID (nineteen-entry) carry-over backlog — the 2026-09-19 report's audited-snapshot backlog,
including T-54, T-55, T-56, T-57, T-58 and the T-51 residual — was open at `6c46ebd`. T-12, T-13, T-29,
T-30, T-54, T-55, T-56, T-57, T-58 and the T-51 residual were spot-checked at their cited locations; the
others were not re-verified. Backlog: 24 IDs / 23 entries at the audited snapshot, 23 / 22 after this
PR's corrections; score 7.8 and 7.9 respectively (lineage figures that omit T-54's 0.1 charge;
fully charged 7.7 and 7.8). No
cosmetic or preference-driven renames are proposed. This report's first revision contained two factual
errors, and later review rounds found more; all were caught by automated PR review before merge
and corrected above rather than silently fixed —
per the DEBT-014 process lesson, it was written only after a fresh sync against `origin/main` immediately
before opening its PR, and this revision adds a second lesson: a "no GUI/API surface" claim must be checked
against the rendered surface directly, not inferred from which files a diff touched.
