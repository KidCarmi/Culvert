# Culvert Language & Terminology Governance Review — 2026-09-24

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Snapshot scope (read this first):** this is a HISTORICAL record of `origin/main` at `6ec745d` on
> 2026-09-24. It was merged later, after `main` had moved on, so the tree it ships in contains commits it
> never audited. Its findings, carried-over backlog and health score describe `6ec745d` only. They are
> not a statement about the tree this file is published in; the current governance state is whatever the
> most recent review in this series says. Later windows are audited by later reports, never
> retroactively by this one.
> **Method:** Audited `574d265..6ec745d` — the window since the 2026-09-11 report's audited snapshot
> `574d265`. That report itself merged later, in `0665453` (PR #1363). The first revision started at
> `0665453`, which left two merges that landed between the two commits unaudited by either report:
> #1362 (`2d86f19`, MCP first-canary exact scope) and #1366 (`dcc6aa3`, the compose YARA rules path).
> The window was widened in review to cover them; see "Merges added in review" below. The end commit `6ec745d` was confirmed as the then-current `origin/main` HEAD by a fetch
> immediately before this report was written on 2026-09-24 (per the DEBT-014 lesson: sync against `main` right before opening a PR, not only at
> review-start, so a fix landed by a parallel branch is credited rather than re-claimed — no such
> landing occurred this pass; the branch was created directly from a synced `origin/main`, so no merge
> was needed). **Correction:** the first revision said no review dated later than 2026-09-11 existed on
> any branch. That was wrong. Four were open as unmerged PRs at the time and audited overlapping
> windows: 2026-09-12 (#1372, merged since), 2026-09-19 (#1434), 2026-09-21 (#1456) and 2026-09-23 (#1482). This report is therefore a
> parallel run of the DEBT-014 kind; see "Overlap with parallel reports" below.
>
> The window covers 34 first-parent merges / 256 files / ~55.7k insertions, dominated by two
> unrelated backend tracks: (a) CI-REDESIGN pipeline work (`cmd/cireport`, `cmd/rootshard`,
> `.github/workflows/*`, release-publication gating, the R2-only catalog-origin retirement of GitHub
> Pages; mostly CI internals, but it also adds operator-facing text: the
> `docs/operator/release-publication-gating.md` runbook and the catalog workflows' `::error::` messages)
> — and (b) MCP "first
> controlled canary" rollout hardening (`internal/mcp/canary/*`, `mcp_canary_*.go`,
> `docs/design/mcp/CANARY-READINESS-MATRIX.md`, `docs/operator/mcp-first-controlled-canary-review.md`)
> alongside the CHAOS-65 (OCSP revocation checking), CHAOS-60 (GeoIP resolution health), and CHAOS-63
> (admin-login input bounds) reliability work already described in `CLAUDE.md`.

---

## Executive Summary

**No new terminology drift found by this pass, and no new fixes made.** Parallel reports covering
parts of the same window did find drift this pass missed; see "Overlap with parallel reports" below.

1. **The new admin-facing field, row and metric names below were checked for cross-surface
   consistency. Apart from the OCSP rejection counters, which are the already-open T-54 (below), they
   are consistent.** This check covered names and their mappings only. It did not
   read description prose against the glossary, and it did not compare the OpenAPI audit-event names
   with the handlers, which is how it missed the "appliance" prose and the tool-trust audit-event
   mismatch (see "Overlap with parallel reports").
   - **OCSP (CHAOS-65):** the window added nine `/api/ocsp` fields in `ui_security.go`, each spelled
     identically in `api/openapi/openapi.{json,yaml}` and the auto-generated `frontend/src/api/types.gen.ts`.
     They map to other surfaces as follows:
     - The six rejection counters (`notForCertificateTotal`, `unauthorizedResponderTotal`,
       `malformedResponseTotal`, `staleResponseTotal`, `unknownStatusTotal`, `responderBlockedTotal`)
       correspond one-to-one with `culvert_ocsp_response_rejected_total{reason=...}` labels in
       `ocsp_metrics.go` (e.g. `notForCertificateTotal` ↔ `not_for_certificate`), but the spellings do not
       all match: `malformedResponseTotal` ↔ `malformed`, `staleResponseTotal` ↔ `stale`, and the Go
       accessor `UnknownTotal()` ↔ `unknownStatusTotal`/`unknown_status` (`ui_security.go:1843-1845`,
       `ocsp_metrics.go:59-61`). `responder_blocked` (`ocsp_metrics.go:62`) is also counted in a series
       described as discarded responses, although no response exists in that case. Both points are
       **T-54**, opened by the 2026-09-12 report (#1372, audited `d378dff..2833db3`; `2833db3` is an
       ancestor of `6ec745d`) and still open at `6ec745d`. The first revisions of this report called
       these counters consistent and left T-54 out of the backlog; both were wrong and are corrected
       here. The GUI does not show them individually. It sums them into one "Responses
       rejected" counter (`static/index.html:4485`, filled at `:17517`).
     - `respondersTruncatedTotal` ↔ `culvert_ocsp_responders_truncated_total`. It is not shown in the GUI.
     - `coverage` and `uncheckedEnforcingPaths` ↔ the separate `culvert_ocsp_path_checked{path}` gauge
       (`ocsp_metrics.go:77-84`). The path values (`upstream_transport`, `ssl_inspect_origin`,
       `connect_bypass`) come from one source, `ocspCoverage()` in `ocsp_coverage.go`, for both the API and
       the metric label. `uncheckedEnforcingPaths` lists the unchecked ones and always leaves out
       `connect_bypass` (`ocsp_coverage.go:89-93`). The GUI renders `uncheckedEnforcingPaths` as its
       coverage banner (`static/index.html:17519`).
     - Similar wording is shared between the GUI fail-closed banner ("No OCSP responder returned a usable, affirmative verdict",
       `static/index.html:4494`) and the `culvert_ocsp_fail_closed_total` HELP text ("no responder returned
       a usable, affirmative verdict", `ocsp_metrics.go:38`). Both use "verdict", which the glossary
       reserves for Diagnostics checks. That use is recorded in "Glossary term sweep" below.
   - **GeoIP (CHAOS-60):** the new `geo_resolution` diagnostics-contract row mirrors the pre-existing
     `dns_resolution` row's naming and severity convention (both emit only `diagOK`/`diagWarn`,
     `geoip_resolve_health.go:320-335`, `dns_health.go:459-484`), and `docs/operator/
     geoip-resolution-health.md` uses the same vocabulary.
   - **Admin-login bounds (CHAOS-63):** the new `/api/stats` field `loginOversizeRejected` and its GUI
     hint text both trace to the pre-existing `culvert_login_oversize_rejected_total` metric — this is
     GUI-parity work for an already-named concept, not a new name.
   - **MCP canary (`reviewed_operation_class`):** the request and response carry different value sets.
     This was corrected after review; the first revision said the values were documented identically.
     - Request (`POST /api/mcp/tool-approvals`): OpenAPI enum `read_only | mutating`
       (`api/openapi/openapi.yaml:13078`), parsed by `tooltrust.ParseReviewedOperationClass`, which accepts
       only those two (`internal/mcp/tooltrust/reviewed_operation.go`).
     - Response (`GET /api/mcp/tool-approvals`): `ui_mcp_tooltrust.go` serializes
       `ReviewedOperationClass.String()` (`ui_mcp_tooltrust.go:95,123`). That returns `read_only`,
       `mutating` or `unset`, the last for the zero value (`reviewed_operation.go:67-75`).
       A `shadow_evaluation` request may leave the class unset, so an admin can see `unset`. The OpenAPI
       response schema is an untyped `additionalProperties: true` object, so `unset` is documented only in
       the Go struct comment (`ui_mcp_tooltrust.go:91-94`, "read_only | mutating | unset").
     - The field is not shown in the legacy GUI (`static/index.html` has no occurrence).

     The name is consistent. The response's third value is undocumented in the API schema. That is a
     documentation gap. It is folded into #1456's open T-60 (the tool-trust OpenAPI entries do not
     describe what the handlers return), since the route and its Go comment were added in that report's
     window too; it gets no new ID here. The readiness-matrix row renumbering and the
     canary-review design doc are internal row-ID/function-name jargon, not administrator-facing product
     vocabulary, and stay internally self-consistent.
   - The release-publication-gating and R2-only-catalog work: its job and tag names (`promote-image`,
     `candidate-<run_id>`, `resolve-candidate`) are CI internals. Its operator runbook
     (`docs/operator/release-publication-gating.md`) and its workflow `::error::` messages are
     operator-facing text, and the glossary applies to them. Their "appliance" wording is covered in
     "Forbidden term: appliance" below.
2. **Carry-over findings were spot-checked at their cited locations, not exhaustively re-verified.**
   This pass did not trace every changed file that a carry-over finding depends on. It checked the
   cited locations of T-11, T-12, T-29 and T-30 directly (item 3 below) and of T-54 (the OCSP bullet
   in item 1, at `ui_security.go:1843-1845` and `ocsp_metrics.go:59-62`), and read the window's hunks in
   three files that hold carry-over sites (`git diff 574d265 6ec745d`):
   - `config.go` (T-11 `default_action`, T-29/T-30 rate/connection-limit keys, T-39 `qualification_*`
     keys): two hunks, both CDR server-fingerprint validation. None of those keys is touched.
   - `static/index.html` (the Cluster panel's `cp_version`/`snapshot_sha256` for T-21+T-32, and the T-39
     qualification strings): four hunks — the oversized-login hint, the OCSP panel counters and banners,
     `fetchStats` and `loadCAMgmt`. None touches the Cluster panel or a qualification string.
   - `admin_settings.go` (T-29/T-30): one hunk in `applyAdminSecurity`, which replaces the per-entry
     `AddExemption` loop for rate-limit exemptions with a bulk `AddExemptions` call. That is a
     performance change; `RateLimitRPM`, `rate_limit_rpm` and the connection-limit fields keep their names.

   Other dependency files also changed (for example `main.go` and `internal/mcp/runtime/policy.go`) and
   were not traced. Every carry-over finding therefore remains open with its original evidence, which
   this report neither re-verifies in full nor changes.

3. **Spot-checked three carry-over items directly** (rather than trusting the prior report alone), the
   same discipline the 2026-09-08/09/11 reports used: **T-11** — `config.go`'s `default_action`
   validation still accepts only `"allow"`/`"deny"` strings while `policy.go`'s `PolicyAction` enum still
   has no `Deny`/`Block` value (`ActionAllow | ActionDrop | ActionBlockPage | ActionRedirect`), unchanged.
   **T-12** — `cmd/culvert-maint/internal/server/server.go` still registers `POST /v1/upgrades/apply`
   (also unchanged in `handlers_upgrade_apply.go`, `ops.go`, `templates_upgrade.go`,
   `capture_running.go`); no `/v1/updates/apply` exists anywhere. **T-29/T-30** — `config.go` still has
   no `rate_limit_rpm` or `conn_limit_max_per_ip` YAML key; only `security.rate_limit` and
   `security.max_conns_per_ip` exist. All three confirmed exactly as the prior reports left them.

**Terminology Health Score: 8.6 / 10** (unchanged from 2026-09-12). The starting point is the 2026-09-12
report's 8.6, which already charged T-54 (backlog 13 → 14); this report does not charge it again. This
pass's checks found no new drift in a 256-file, backend-and-CI-heavy window, and no spot-checked carry-over
item moved, so the score neither rises nor falls. The first revisions of this report said 8.7 because they
started from the 2026-09-11 report and missed T-54. It does not account for the parallel reports' findings (see "Overlap with parallel reports");
the series' later reports reconcile the score.

---

## Carried-Over Findings (unchanged)

All fifteen previously-open finding IDs (fourteen backlog entries, since T-21 and T-32 are tracked as
one paired item) remain open with their original evidence, spot-checked as described in items 1–3 above: T-9, T-11, T-12,
T-13 (residual), T-17, T-18, T-21+T-32 (paired), T-25 (residual), T-29, T-30, T-33, T-34, T-39, T-54. Full
descriptions and the priority-ordered refactoring plan are unchanged from
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md` (T-9..T-39) and `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-12.md`
(T-54) and are not restated here, to avoid drift between two
descriptions of the same open items — see that report (or its predecessors, cited therein) for the
canonical text of each.

The "Content & Scanning" vs. "Content Security" soft finding (design-document reconciliation between two
deliberate, independently-documented naming decisions — legacy GUI per
`docs/design/INFORMATION-ARCHITECTURE.md`, new frontend per `docs/design/FRONTEND-MIGRATION-PLAN.md` —
not a mechanical rename) also remains unresolved and is not queued to the numbered backlog, per the
2026-09-09 report's reasoning.

---

## Glossary term sweep

The literal terms `docs/design/PRODUCT-TERMINOLOGY.md` forbids, reserves or replaces were checked against
the lines this window ADDED. The counts come from the tool: for each term,
`git diff 574d265 6ec745d -U0 | grep -v '^+++' | grep -ciE '^\+.*<pattern>'` gives "Added lines" (a case-insensitive
substring match). The file:line lists come from the same diff, with line numbers at `6ec745d`. "Visible"
means `static/index.html`, non-test `frontend/src`, `api/openapi/openapi.yaml`, `docs/` outside
`docs/engineering`, `docs/design` and `docs/adr`, `CHANGELOG.md` and `README.md`; generated copies are
not counted.

The sweep covers only the literal patterns in the table below: the glossary's forbidden or replaced
words, matched as substrings. It does **not** cover the glossary's context-sensitive rules, which a pattern
count cannot decide and which this pass did not check: "policy" used loosely for a single rule, bare
"profile" on the steering-profile screen, "status" used for a health roll-up, "user" where it could mean
a console account, "kill switch" without its qualifier (the table counts the literal only),
"exception"/"bypass"/"allowlist" used for the wrong kind of skip, and sentence case. A term missing from
the table, or a zero count, is not evidence that those rules hold.

| Term (pattern) | Added lines | Visible | Visible lines (file:line) | Outcome |
|---|---|---|---|---|
| appliance (`appliance`) | 30 | 6 | `CHANGELOG.md`: 285; `api/openapi/openapi.yaml`: 483; `docs/operator/geoip-resolution-health.md`: 36; `docs/operator/ocsp-revocation-checking.md`: 22,122; `docs/operator/release-publication-gating.md`: 547 | Same 6 lines as #1456's window; fixed there (T-51 recurrence). See "Forbidden term: appliance" below |
| verdict (`verdict`) | 783 | 55 | `CHANGELOG.md`: 15,226,232,259,400; `api/openapi/openapi.yaml`: 488; `docs/operator/mcp-first-controlled-canary-review.md`: 51,392,970,1111,1124,1133,1251,1252,1253,2196,2203,2223,2228,2273,2489,2502,2533,2542,2543,2545,2558,2592,2646,2693,2702,2818,2902,2916,2992,3072,3080,3118,3293,3358,3559,3589,3635; `docs/operator/ocsp-revocation-checking.md`: 39,49,50,91,95,144; `docs/operator/release-publication-gating.md`: 22,60,455; `static/index.html`: 4484,4491,4494 | Same 55 lines as #1456's window; recorded there as its open T-59b (13 OCSP lines and 40 others; the 2 identifier-only lines, `mcp-first-controlled-canary-review.md:2558`/`:2592`, are exempt as backend identifiers) |
| result (`result`) | 286 | 7 | `CHANGELOG.md`: 426; `docs/operator/mcp-first-controlled-canary-review.md`: 2255,2402,2908,3116; `docs/operator/ocsp-revocation-checking.md`: 77; `docs/operator/release-publication-gating.md`: 362 | Same 7 lines as #1456's window; none means a request's decision — no violation |
| incident (`incident`) | 6 | 1 | `docs/operator/mcp-first-controlled-canary-review.md`: 886 | Same line as #1456's window; plain English, no entity — no violation |
| scanner (`scanner`) | 63 | 3 | `docs/operator/mcp-first-controlled-canary-review.md`: 2967,3212,3236 | Same 3 lines as #1456's window; a code scanner — no violation |
| policy rule (`policy rule`) | 6 | 1 | `docs/operator/mcp-first-controlled-canary-review.md`: 3476 | Same line as #1456's window; an MCP gateway rule — no violation |
| exclusion (`exclusion`) | 48 | 6 | `docs/operator/mcp-first-controlled-canary-review.md`: 397,795,816,1104,1248,2807 | Same 6 lines as #1456's window; the MCP rollout-scope field — no violation |
| kill switch (`kill.?switch`) | 24 | 0 | — | Internal only (identifiers, test names) |
| unauth mode (`unauth.?mode`) | 2 | 0 | — | Internal only: two test names in `.github/qa-root-shard-timings.json` |
| threat engine, Cluster Nodes, blacklist/whitelist, Live Feed, Live Request Log, Recent Requests, Users & Roles, proxy pool | 0 each | 0 | — | — |

**Overlap with #1456.** Every visible hit above also appears, with the same file and text, among the
lines the 2026-09-21 report's window (`46410c3..6c46ebd`) adds. The check: compare the (file, line text)
pairs of both diffs; this window has 0 visible hits for any term that are not in that window. They are
therefore recorded once, in #1456's report, and not again here:
- "verdict" in OCSP copy — `static/index.html:4484`, `:4491`, `:4494`, `api/openapi/openapi.yaml:488`, six
  lines of `docs/operator/ocsp-revocation-checking.md`, three CHANGELOG lines — under its open T-59b,
  with the required "response"/"status" rewording;
- "verdict" elsewhere (the MCP canary review, the release-gating runbook, two CHANGELOG lines) — also its
  T-59b;
- "appliance" — its T-51 recurrence, fixed in that PR.

**Strings emitted by Go code.** The file-based "visible" rule does not cover strings that non-test Go
code prints. A second pass checked added string literals:
`git diff 574d265 6ec745d -U0 -- '*.go' ':!*_test.go' | grep -v '^+++' | grep -iE '^\+.*"[^"]*<pattern>[^"]*"'`.
- **Also in #1456's window, recorded there:**
  - 7 "verdict" lines: the OCSP error, log line and three `/metrics` HELP texts (`internal/ocsp/ocsp.go`,
    `ocsp_metrics.go`), under its T-59b; a code comment; and the MCP reason code
    `policy_verdict_not_invariant`.
  - 1 "policy rule" line: the GeoIP diagnostics warning "country-scoped policy rules…"
    (`geoip_resolve_health.go`), recorded there as its open T-59c.
  - 2 "exclusion" identifiers in the MCP scope code.
- **Only in this window:** 31 "verdict" and 23 "result" lines, all in `cmd/cireport` and `cmd/rootshard`.
  These are the CI performance reporter and the race-shard tool. Their output is read by maintainers in
  the Actions log and step summary, and their "verdict" is the race job's `verdict.json` artifact. The
  glossary governs what an administrator of Culvert reads, so this is CI vocabulary, not product copy,
  and not a violation. Files: `cmd/cireport/{analyze,evidence,main,model,summary,trend}.go`,
  `cmd/rootshard/{compare,completeness,main,results,verdict}.go`.
- "appliance", "incident", "scanner", "kill switch", "unauth mode": 0 lines.

**Emitted text outside Go.** A third pass covers text that non-Go files print (workflow `::error::`
annotations, `$GITHUB_STEP_SUMMARY` writes, shell and installer output), with the same method as #1456:
`git diff 574d265 6ec745d -U0 -- '.github/**' 'scripts/**' 'packaging/**' '*.sh' 'Dockerfile*' 'Makefile'
'docker-compose*.yml' ':!*.json' | grep -v '^+++' | grep -iE '^\+.*(<any term in the table>)' | grep -vE
'^\+\s*#'` finds 54 added non-comment lines. JSON data files (the shard-timing tables) are excluded; they
hold test names, not printed text. Such output counts as operator-visible only when a page under
`docs/operator/` tells the reader to read it; otherwise it is CI or contributor tooling output read by
maintainers.
- **Also in #1456's window (11 lines), recorded there:** the `| workflow | class | verdict |` step-summary
  header in `.github/scripts/require-release-evidence.sh`, which `release-publication-gating.md:454-455`
  sends operators to (its open T-59b); the `publish-catalog-r2.yml` "appliance" `::error::` line (its T-51
  recurrence); and 9 contributor mutation-test lines in `scripts/mcp-*-mutations.sh` (no violation).
- **Only in this window (43 lines):** the sharded race-gate plumbing in `pr-fast-gate.yml`, `qa-gate.yml`
  and `qa-race-shards.yml` (job and step names, artifact paths such as `race-verdict/`, `needs.*.result`
  expressions, and `::error::` lines about the race verdict), and one step-summary line in
  `security-release-gate.yml` ("Scope of this verdict"). No page under `docs/operator/` tells the reader to
  read any of them (`release-publication-gating.md:57` names `qa-gate.yml` and `security-release-gate.yml`
  as mandatory evidence but does not send the reader to their output), so they are CI vocabulary, like the
  `cmd/rootshard` output above. No violation.

This report mints no IDs and changes no product copy. Line numbers here are at `6ec745d` and can differ
from #1456's, which are at `6c46ebd`.

---

## Forbidden term: appliance

`docs/design/PRODUCT-TERMINOLOGY.md` says "Appliance: *Not used*" for UI labels and docs.
`git diff 574d265 6ec745d -U0 | grep -v '^+++' | grep -iE '^\+.*appliance'` finds 30 added lines in
this window. `grep -v '^+++'` drops diff file headers (some file names contain a searched term), and
`^\+` drops the one removed line that also matches. Line numbers
below are at `6ec745d`, so a few differ from the 2026-09-21 report's list, which uses `6c46ebd`.

**User- or operator-visible text (9 lines).** All nine were added in the 2026-09-21 report's window,
and that report's PR (#1456, its T-51 recurrence) changes them to "Culvert" or "instance" ("node" means an enrolled cluster member in the glossary). This PR does not
edit them, so the same line is never changed in two PRs:
- `api/openapi/openapi.yaml:483`, `api/openapi/openapi.json:2735`, `frontend/src/api/types.gen.ts:6240`
  (the `uncheckedEnforcingPaths` description)
- `docs/operator/ocsp-revocation-checking.md:22`, `:122`
- `docs/operator/geoip-resolution-health.md:36`
- `docs/operator/release-publication-gating.md:547`
- `CHANGELOG.md:285`
- `.github/workflows/publish-catalog-r2.yml:104` (an `::error::` line in the Actions log)

**Left as is (21 lines), with reasons:**
- Code comments, none part of an emitted string: `geoip_resolve_health.go:292`, `ocsp_coverage.go:19`,
  `:84`, `ocsp_metrics.go:16`.
- Test comments: `internal/ocsp/ocsp_chaos_test.go:1051`, `mcp_live_execution_e2e_test.go:66`, `:82`,
  `ocsp_coverage_test.go:87`, `e2e_image_recipe_test.go:8` (names the `appliance-catalog-update` workflow).
- Workflow YAML comments, not printed: `.github/workflows/publish-catalog-r2.yml:75`,
  `.github/workflows/resign-catalog.yml:124`.
- Identifiers: the test name `TestSluiceIntegration_ApplianceHandlersEndToEnd` in
  `.github/qa-root-shard-timings.json:5769` and in `cmd/cireport/testdata/evidence/comparison.json:74`
  and `:135` (test-fixture data).
- `CLAUDE.md:182`, `:228`: contributor and agent instructions, not product documentation.
- `roadmap/CHAOS-ENGINEERING-REVIEW.md:1002`, `:6107`, `:6163` and `roadmap/CI-REDESIGN.md:889`, `:907`:
  engineering records. The `CI-REDESIGN.md` lines name the `appliance-catalog-update` workflow.

---

## Merges added in review

- **#1362 (`2d86f19`, MCP first-canary exact scope)** — 13 files: `internal/mcp/canary/firstcanary_scope.go`,
  `mcp_canary_preflight.go`, tests, a mutation script, ADR-0035, `docs/design/mcp/CANARY-FIRST-RUNBOOK.md`,
  `CANARY-READINESS-MATRIX.md` and `docs/operator/mcp-first-controlled-canary-review.md`. No GUI, REST
  route, OpenAPI or config surface changed. The new vocabulary ("exact scope", `ExactScope`) is internal
  canary-review language used the same way in code and docs, and no added line uses "appliance".
  No finding.
- **#1366 (`dcc6aa3`, compose YARA rules path)** — `docker-compose.yml` comments and an example mount now
  say `/data/yara` instead of `/app/yara`, plus a test pinning it. That is a path correction, not a naming
  change. No finding.

Neither merge touches a carry-over finding location.

---

## Overlap with parallel reports

Four reports written before this one were still unmerged PRs when it was written, and each audited
part of this window. They recorded findings this pass did not:

- **2026-09-12 (#1372, since merged)**: audited `d378dff..2833db3`, a subset of this window, and opened
  **T-54** — the OCSP discarded-response reason vocabulary does not match across the `/api/ocsp` JSON
  fields, the Go accessors and the `/metrics` `reason` labels, and `responder_blocked` is counted in the
  "responses discarded" series although no response exists. It moved the score from 8.7 to 8.6. This
  report's OCSP check (Executive Summary item 1) first called those counters consistent; it now records
  the mismatches as T-54, still open at `6ec745d`, carries T-54 in the backlog, and starts its score
  from 8.6. T-54 is the 2026-09-12 report's finding, not a new one here.
- **2026-09-21 (#1456)**: the OCSP admin panel was titled "OCSP / CRL Revocation" although only OCSP
  exists (its T-59), and the OCSP work added "appliance", which the glossary forbids, to an OpenAPI field
  description and operator docs (a T-51 recurrence). It also found that the MCP tool-trust decision
  route's OpenAPI entry names an audit event, `mcp.tooltrust.decision`, that the handler never emits
  (its T-60, which also covers the `reviewed_operation_class` `unset` response value this report found).
  Its glossary sweep records the "verdict" uses outside Diagnostics as its open T-59b and the GeoIP
  "policy rules" warning as its open T-59c. This report's OCSP check compared field spellings and did not read the panel title or
  prose against the glossary, and its MCP check did not compare the spec's audit-event names with the
  handler.
- **2026-09-23 (#1482)**: T-61–T-63 (identity-backend metric prefix, Sync vs Refresh verbs, the
  decryption-exclusion audit search). All three are long-standing, not introduced in this window.
- **2026-09-19 (#1434)**: a pre-existing SSL/TLS label mismatch in the new frontend's Rule Editor (its T-58).

This report's "no new drift" conclusion covers only the checks listed above. It is not evidence
against those findings. The finding IDs above are the parallel reports' own; see each report for
their ID notes.

---

## Stop-Condition Assessment

No production-worthy NEW terminology improvement was identified by this pass's checks (parallel reports
found some in the same window; see above): the 34-merge window audited
was CI/release-pipeline engineering plus MCP-canary and reliability (CHAOS-60/63/65) work, all internally
consistent where these checks looked, apart from the OCSP counters that are the already-open T-54. The 2026-09-21 report found that the window did add "appliance"
to customer-facing docs and an OpenAPI description, which this pass missed.
The fifteen-ID (fourteen-entry) carry-over backlog, including T-54, remains open with its original
evidence. Five of its IDs (T-11, T-12, T-29, T-30, T-54) were spot-checked at their cited locations; the backlog was not exhaustively
re-verified. No cosmetic or
preference-driven renames are proposed. This report itself — the audit record and backlog
reconciliation — is the deliverable of this pass; per the DEBT-014 process lesson, it was written only
after a fresh sync against `origin/main` immediately before opening its PR, and the branch was confirmed
to be exactly `origin/main` at commit `6ec745d5` with no divergent history before this file was added. The
sync did not catch the parallel reports, because they were on unmerged branches rather than on `main`.
