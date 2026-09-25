# Culvert Language & Terminology Governance Review — 2026-09-21

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Snapshot scope (read this first):** this is a HISTORICAL record of `origin/main` at `6c46ebd` on
> 2026-09-21. It was merged later, after `main` had moved on, so the tree it ships in contains commits it
> never audited. Its findings, carried-over backlog and health score describe `6c46ebd` only. They are
> not a statement about the tree this file is published in; the current governance state is whatever the
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
**One new open finding (T-60):** the tool-trust decision route's OpenAPI entry names an audit event the
handler never emits.

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

**Spot-checked three carry-over items (four IDs: T-12, T-13, T-29, T-30) at their cited locations** in the
then-current tree (`6c46ebd`), as prior reports have done. The other carry-over findings were not
re-verified; they are carried over with their original evidence.
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

**Terminology Health Score: 8.7 / 10** (unchanged). One new defect (T-59) was found and fixed within the
same pass — a security-adjacent admin-UI label overclaiming a capability — so, following 2026-09-08's
precedent that a single item's discovery and its resolution are symmetric ±0.1 moves, the two cancel out
rather than compounding; the T-51 recurrence was likewise fixed within the pass. The pre-existing
thirteen-entry backlog did not otherwise move. The score is not
raised above 8.7 despite the same-day fix, since a defect that reached production before this review is
not evidence of improving health, only of this review doing its job.

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
  a separate mechanism, and code comments in `mtls_ocsp_startup.go`/`mtls_ocsp_startup_config.go` still
  say "OCSP/CRL". Those comments are internal and were not changed.
  If CRL fallback is added in the future, "OCSP / CRL Revocation" becomes accurate again and can be
  restored at that time.
- **Sub-item — "verdict" in the OCSP copy (recorded, not fixed in this report PR).** The glossary
  reserves "verdict" for Diagnostics checks (`PRODUCT-TERMINOLOGY.md`, Decision row). The window's OCSP
  copy uses it for a responder's answer. Required rewording: "response" where the text means what the
  responder sent, "status" where it means `good`/`revoked`. Hits (line numbers at `6c46ebd`):
  - `static/index.html:4484` "Fail-closed (no usable verdict)" → "(no usable response)"; `:4491`
    "revocation verdicts from the affected upstream" → "revocation responses"; `:4494` "a usable,
    affirmative verdict" → "a usable, affirmative status".
  - `api/openapi/openapi.yaml:488` (`unauthorizedResponderTotal`) "a certificate signing a verdict about
    itself" → "a response about itself" (carried into `openapi.json` and `types.gen.ts` on regeneration).
  - `docs/operator/ocsp-revocation-checking.md:39`, `:49`, `:50`, `:91`, `:95`, `:144` → "status" or
    "response" as above ("cached verdicts" → "cached statuses").
  - `CHANGELOG.md:226`, `:232`, `:259` (the CHAOS-65 entry).
- **Affected surfaces**: GUI (`static/index.html:4477`), one operator-doc reference
  (`docs/operator/ocsp-revocation-checking.md:4`), and three roadmap lines. No API/config/audit/metric
  surface uses "CRL."
- **Migration complexity**: trivial (label and prose only, no wire contract) — applied. **Compatibility
  risk**: none. **Actual PR size**: XS.

### T-60 — The tool-trust decision route documents an audit event the handler never emits (Low) — OPEN

- **Names found**: `POST /api/mcp/tool-approval-decision` declares `x-culvert-audit-event:
  mcp.tooltrust.decision` (`api/openapi/openapi.yaml:13103`). `docs/api/API-STYLE-GUIDE.md:35` defines that
  extension as "the audit event the handler emits". The handler emits one of `mcp.tooltrust.reject`,
  `.revoke`, `.approve` or `.approve-live`, depending on the action (`ui_mcp_tooltrust.go:353,361,388,402`).
  No `mcp.tooltrust.decision` event exists. (The request route's `mcp.tooltrust.request` matches
  `ui_mcp_tooltrust.go:304`.)
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
- **Complete inventory.** `git diff 46410c3 6c46ebd -U0 | grep -i '^+.*appliance'` finds 24 added lines
  (the unfiltered grep also matches one removed line). Line
  numbers below are at `6c46ebd`. Each one is classified here:
  - **User- or operator-visible text — fixed to "node" or "Culvert":**
    - OpenAPI `GET /api/ocsp` `uncheckedEnforcingPaths` description: `api/openapi/openapi.yaml:483`,
      regenerated into `api/openapi/openapi.json:2735` and `frontend/src/api/types.gen.ts:6240`
      ("Paths where this node validates…").
    - `docs/operator/ocsp-revocation-checking.md:22` and `:122` → "node".
    - `docs/operator/geoip-resolution-health.md:36` → "node".
    - `docs/operator/release-publication-gating.md:547` → "Culvert" (its subject is the product).
    - `CHANGELOG.md:276`, the CHAOS-65 release note → "Culvert now says so".
    - `.github/workflows/publish-catalog-r2.yml:104`, an `::error::` message printed in the Actions log →
      "being served to any node".
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

Every term `docs/design/PRODUCT-TERMINOLOGY.md` forbids, reserves or replaces was checked against the
lines this window ADDED. Command, per term (with the term's pattern in place of `<re>`):
`git diff 46410c3 6c46ebd -U0 | grep -iE '^\+.*<re>'`. "Visible" means `static/index.html`, non-test
`frontend/src`, `api/openapi/openapi.yaml`, `docs/` outside `docs/engineering`, `docs/design` and
`docs/adr`, `CHANGELOG.md` and `README.md`. Generated copies (`openapi.json`, `types.gen.ts`) follow the
YAML and are not counted twice.

| Term (glossary rule) | Added lines | Visible | Outcome |
|---|---|---|---|
| appliance ("not used") | 24 | 6, plus one workflow `::error::` line | Fixed; the T-51-recurrence list counts 9 because it also lists the generated `openapi.json` and `types.gen.ts` copies |
| verdict (reserved for Diagnostics) | 315 | 53 | Recorded: 13 OCSP lines under T-59; 40 others below |
| result (replaced by "decision" for a request's outcome) | 63 | 7 | None means a request's decision (campaign, query and release results) — no violation |
| incident (no incident entity) | 3 | 1 | Plain English ("during an incident"), no entity invented — no violation |
| scanner (replaced by "engine") | 5 | 3 | Means a code scanner in a test wall, not a scanning engine — no violation |
| policy rule (replaced by "rule") | 6 | 1 | An MCP gateway policy rule, not a Stage-2 `PolicyRule` — no violation |
| exclusion (bypass vocabulary) | 23 | 6 | The MCP rollout-scope "exclusions" field, not an inspection bypass — no violation |
| kill switch (must be qualified) | 2 | 0 | Test identifiers only |
| unauth mode, threat engine, Cluster Nodes, blacklist/whitelist, Live Feed, Live Request Log, Recent Requests, Users & Roles, proxy pool | 0 each | 0 | — |

**Recorded, not yet numbered — "verdict" outside OCSP (40 visible lines).** These use "verdict" for
something other than a Diagnostics check, so they break the same reservation:
- `docs/operator/mcp-first-controlled-canary-review.md`: 35 lines. The review uses "verdict" for its own
  conclusions and for a policy decision.
- `docs/operator/release-publication-gating.md:22`, `:60`, `:455`: a CI gate's outcome.
- `CHANGELOG.md:15` (a CI gate's outcome) and `:391` (rate-limit exemption verdicts).

They are not fixed in this report PR. Rewording the MCP review would touch many lines of a document that
other PRs edit, so it needs its own change.

## Carried-Over Findings (unchanged)

All fourteen previously-open finding IDs (thirteen backlog entries, since T-21 and T-32 are tracked as one
paired item) remain open with their original evidence. T-12, T-13, T-29 and T-30 were spot-checked at
their cited locations in `6c46ebd` (see the Executive Summary); the rest were not re-verified:
T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21+T-32 (paired), T-25 (residual), T-29, T-30, T-33, T-34,
T-39. Full descriptions and the priority-ordered refactoring plan are unchanged from
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md` and are not restated here to avoid drift between two
descriptions of the same open items — see that report (or its predecessors, cited therein) for the
canonical text of each. **T-59 (above) was found and fixed within this same pass and does not join the
open backlog** — the thirteen-entry carry-over backlog is unchanged; T-59 is recorded here only as a closed finding
ID, for the same reason closed items stay in the numbering series rather than being silently dropped.
**T-60 (above) is new and open**, so the open backlog after this pass is fourteen entries (fifteen IDs).

The "Content & Scanning" (legacy GUI) vs. "Content Security" (new React frontend) soft finding — a
non-mechanical naming-policy reconciliation between two deliberate design decisions, not a numbered backlog
item — also remains unresolved, per 2026-09-09's reasoning, and was not revisited this pass.

---

## Stop-Condition Assessment

**Does not apply cleanly this pass — a production-worthy terminology defect (T-59) was identified and
fixed**: a security-adjacent GUI label naming a revocation mechanism (CRL) that does not exist in the
implementation, corrected in this same PR (XS, no migration risk, no wire surface affected). A recurrence
of the closed T-51 ("appliance" in customer-facing text) was also fixed. One new low-priority finding,
T-60 (a documented audit event the tool-trust decision handler never emits), is left open for an
API-contract change. The MCP
canary-execution stream produced one finding once re-audited, T-60 (see "Corrections made in review").
The fourteen-ID carry-over backlog remains open with its original evidence. T-12, T-13, T-29 and T-30 were
spot-checked at their cited locations; the others were not re-verified. No
cosmetic or preference-driven renames are proposed. This report's first revision contained two factual
errors, and later review rounds found more; all were caught by automated PR review before merge
and corrected above rather than silently fixed —
per the DEBT-014 process lesson, it was written only after a fresh sync against `origin/main` immediately
before opening its PR, and this revision adds a second lesson: a "no GUI/API surface" claim must be checked
against the rendered surface directly, not inferred from which files a diff touched.
