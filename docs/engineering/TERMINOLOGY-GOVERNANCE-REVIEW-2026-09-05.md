# Culvert Language & Terminology Governance Review — 2026-09-05

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** The last review to actually **merge** was `2026-08-25` (PR #1229, landed as commit `403ef54`,
> `main` tip `c20c17b`) — every daily run since (`2026-08-28` through `2026-09-04`, seven PRs: #1239, #1253,
> #1260, #1284, #1294, #1302, #1309) opened correctly but none have merged. This pass therefore did two
> things: (1) a fresh terminology-drift sweep against everything that *has* landed on `main` since `c20c17b`
> (19 first-parent merges, dominated by the new MCP Canary/Live-execution/Tool-Trust subsystem —
> `internal/mcp/canary`, `internal/mcp/tooltrust`, `internal/mcp/execution`, `mcp_canary_*.go`,
> `mcp_live_*.go`, ADR-0034/0035) — full-repo grep for new GUI copy (`static/index.html`'s only diff in this
> window is the already-merged T-38 fix itself), new audit-event names, and new admin-facing API fields; (2)
> read all seven open governance PRs' bodies and diffs to determine, file by file, what each uniquely
> contains, since a week of "merge this one, close the others" recommendations having gone unactioned means
> the real risk has shifted from *finding* new drift to *losing already-found, already-fixed* drift when
> someone eventually reconciles the backlog.
> **Companion change:** one small new fix ships with this review (see Finding T-53). No re-fix of the
> ADR-0034 collision is included — it is already correctly fixed, with a CI guard, in the still-open PR
> #1309; redoing it here would be an eighth copy of the same patch.

---

## Executive Summary

**The dominant finding this cycle is not a new terminology drift — it is that this routine's own delivery
mechanism has stalled for eight consecutive days, and the compounding cost is now large enough to be the
top governance risk in the repository.** Seven PRs (#1239 2026-08-28, #1253 2026-08-29, #1260 2026-08-30,
#1284 2026-09-01, #1294 2026-09-02, #1302 2026-09-03, #1309 2026-09-04) are open, unmerged, and — per
GitHub's own mergeable-state field — at least two (#1253, #1302) can no longer even be cleanly evaluated for
conflicts. Four of the seven (#1253, #1284, #1294, #1309/#1302) independently re-solved the *identical*
`ADR-0034` numbering collision, because each day's review branches from `main`, finds the collision still
live (since no prior fix ever merged), and fixes it again. This is not a terminology-quality problem; it is
described here because three of those seven PRs (#1253 primarily) also carry small, real, still-unlanded
terminology fixes — a "kill switch" qualifier, a Steering Profiles panel consistency fix, and an
"Appliance"→"Node" rename with a regenerated OpenAPI bundle — that are at risk of being silently lost if
whoever eventually cleans up this queue closes PRs by title-similarity ("another ADR fix, superseded")
rather than by diffing their actual unique content. **This review does not attempt to merge, close, or
resolve any of the seven PRs itself** — see "Why this review does not act on the backlog" below — but
records the reconciliation map needed so a human doing that cleanup does not lose #1253's three fixes.

**One new terminology finding, fixed this pass (T-53):** the newly-landed MCP Tool-Trust subsystem
(ADR-0034, `internal/mcp/tooltrust`) introduces a fourth business concept that uses the word "approval" —
alongside the two that already existed in the MCP admin surface (`KindOperational`/`KindPublication`,
`internal/mcp/approval`) — and `docs/operator/mcp-tool-trust-approvals.md` did not cross-reference them.
The doc's own "three concepts stay separate" framing (Trust / Availability / Authorization) is accurate for
tool-trust's *internal* design, but a reader would not learn from it that a `live_execution`-trusted tool
can *still* hit a `REQUIRE_APPROVAL` policy rule at call time and need a wholly separate, pre-existing
Operational approval — both gates independently tracked and audited — before it actually runs. No GUI panel
yet exists for tool-trust approvals (confirmed by grep: zero hits for `tool-approval`/`ToolApproval` in
`static/index.html`), so there is no live UI collision today; this is a documentation-clarity fix made ahead
of that GUI panel being built, so its eventual name (recommended: "Tool Trust" / "Tool Approvals", matching
the existing API route and `ui_routes_meta.go` Notes) doesn't accidentally collide with the existing "MCP
Approvals" panel.

**No other new cross-surface terminology drift was found** in the window since `c20c17b`. Specifically
checked and cleared: the new `canary`/`live_execution`/`Production` rollout vocabulary is used consistently
across the Go source, the one live read-only API route that carries it, and every doc citing it; the new
`internal/mcp/canary` package's "quiesce"/"rehearsal" vocabulary is confined to one internal
qualification-drill doc and does not collide with the pre-existing shutdown-drain vocabulary; and
`frontend/src` still has no MCP-related UI beyond generated OpenAPI types, so there is no legacy-vs-new-GUI
parity risk to report for this feature area yet.

**Terminology Health Score: 8.6 / 10 — unchanged, and now explicitly gated on the backlog, not on new
drift.** The product's *shipped* language is not measurably worse than the 08-25 score (one small new doc
fix landed this pass, one collision remains open exactly as it was ten days ago). The score cannot honestly
move higher, though, while three real, already-authored terminology fixes (in #1253) sit unmerged and at
risk of loss, and while the routine's core value proposition — finding drift *and getting it fixed* — is
failing on the second half for the ninth day running.

---

## Why this review does not act on the backlog

This review has read enough of the seven PRs to know which ones are safe to merge, which two conflict with
each other, and which fixes would be lost by a careless close — see the reconciliation table below. It
deliberately does not merge, close, or comment "please merge" an eighth time, for the same reason #1260
(2026-08-30) gave when it first raised this: **that action is a merge/repository-hygiene decision for a
human, not a terminology-drift finding with a mechanical fix**, and this program's mandate (per its own
charter) is to find and fix language drift, not to arbitrate which of several already-open PRs a
maintainer should merge. Six consecutive days of this routine re-recommending "merge PR #N, close the
others" without effect is itself evidence that repeating the recommendation a seventh time in-PR is not the
right lever — it needs a human to actually act on GitHub, which is why this review's companion notification
(outside this document) is addressed directly to the maintainer rather than folded into another backlog row.

### Backlog reconciliation map (for whoever merges next)

| PR | Date | Unique content not superseded elsewhere | Safe to merge as-is? |
|---|---|---|---|
| #1239 | 08-28 | T-31: dual-emit `culvert_clamav_scan_errors_total` alongside `culvert_clam_scan_errors_total` | Yes — disjoint files from every other PR |
| #1260 | 08-30 | T-52: `PRODUCT-TERMINOLOGY.md` "Incident" row fix (records `IncidentScope` as a legitimate coexisting concept) | Yes — disjoint files from every other PR |
| #1253 | 08-29 | ADR-0034→0036 fix (superseded, see below) **+ three fixes found nowhere else:** bare "kill switch"→"Authentication kill switch", Steering Profiles panel's 5 GUI strings, "Appliance"→"Node" leak in the v2 login screen + `/api/settings` OpenAPI text (+ regenerated `openapi.json`) | **No — do not merge or close as-is.** The ADR-numbering hunk will conflict with #1309's newer version of the same fix. The other three fixes are real and currently exist nowhere else; they need to be cherry-picked (or the PR rebased to drop just the ADR hunk) before this is closed, or they are lost. |
| #1284, #1294 | 09-01, 09-02 | ADR-0034→0036 fix only (per #1302's own account, #1294 duplicates #1284 without the CI guard) | No — superseded by #1309; safe to close once #1309 merges, provided neither carries anything #1302's own audit missed (not independently re-verified by this review — see caveat below) |
| #1302 | 09-03 | ADR-0034→0036 fix + CI guard (`docs_adr_numbering_test.go`) + T-50 fix (`MCP-POLICY-MODEL.md` "Active"→ actual `rollout.Mode` enum value) + carries forward T-49/T-51/T-52 as backlog text | No — superseded by #1309 for the ADR fix itself, but **T-50's fix is not present in #1309** (confirmed: #1309's own diff, per its PR body, touches only the RFC renumber + citations + the CI guard file; it does not mention `MCP-POLICY-MODEL.md`). If #1302 is closed in favor of #1309, T-50 needs to be re-applied from #1302's diff first. |
| #1309 | 09-04 | ADR-0034→0036 fix (against a slightly later `main`, since the collision recurred a fifth time by the time this PR was cut) + CI guard (`adr_numbering_test.go`) | **This is the PR to merge for the ADR-numbering fix and CI guard** — newest, `mergeable_state: clean` against current `main` as of this review. |

**Caveat:** this review read PR bodies and the file lists they state, not full line-by-line diffs of all
seven branches against each other — a maintainer reconciling these should still diff #1284/#1294 directly
against #1309 before deleting them, in case either contains something its own PR body didn't mention.

**Recommended sequence:** merge #1239, then #1260 (both disjoint, trivial), then #1309 (ADR fix + CI guard),
then hand-apply #1302's T-50 fix and #1253's three unique fixes (kill switch / Steering Profiles /
Appliance→Node) as one small follow-up patch, then close #1253, #1284, #1294, #1302 as superseded with a
comment naming which of their contents were recovered and where.

---

## Finding T-53 — MCP Tool-Trust approvals doc doesn't cross-reference the pre-existing MCP Approvals workflow (new — fixed this pass)

- **Business concept:** who or what must sign off before an MCP tool call happens, across the Gateway's four
  independent sign-off mechanisms.
- **Current names found:** `internal/mcp/approval.KindOperational` (a human four-eyes sign-off on one live
  `REQUIRE_APPROVAL` policy-rule decision; `GET /api/mcp/approvals`, `POST /api/mcp/approval-decision`,
  audit events `mcp.approval.approve`/`.reject`, GUI panel "MCP Approvals" at `static/index.html:3966`,
  subtitled "Four-eyes operational approvals — never executes"); `internal/mcp/approval.KindPublication`
  (human sign-off to publish a candidate policy; audit event `mcp.publication.approve`; same GUI panel's
  "Publication" filter tab); `internal/mcp/tooltrust.ToolApproval` (new, ADR-0034 — a supply-chain trust
  decision making one tool fingerprint `usable`; `GET /api/mcp/tool-approvals`,
  `POST /api/mcp/tool-approval-decision`, audit events `mcp.tooltrust.request`/`.approve`/`.approve-live`/
  `.reject`/`.revoke`; no GUI panel yet).
- **Is this already documented as intentional in CLAUDE.md?** No — CLAUDE.md's MCP paragraphs predate the
  tool-trust addition and don't mention `internal/mcp/tooltrust` at all.
- **Why the current naming was problematic:** `docs/operator/mcp-tool-trust-approvals.md` is the only doc
  for the newest of the four "approval" concepts, and its "three concepts stay separate" framing
  (Trust/Availability/Authorization) reads as exhaustive without ever mentioning that the pre-existing
  Operational/Publication approval workflow is a *fourth*, wholly independent gate that can still apply to a
  tool this doc's own trust grant has already approved. A reader relying on this doc alone would not learn
  that `live_execution` trust plus a runtime `REQUIRE_APPROVAL` rule still needs a separate Operational
  approval to actually execute.
- **Why the new name/fix is better:** no rename — added one cross-referencing paragraph naming the existing
  workflow explicitly, stating the two gates are independent and both may be required on the same call, and
  recording a forward-looking naming recommendation ("Tool Trust" / "Tool Approvals", not bare "Approvals")
  for the GUI panel this feature doesn't have yet, so it doesn't collide with the existing "MCP Approvals"
  panel when built.
- **Affected code:** none.
- **Affected API:** none.
- **Affected GUI:** none (no panel exists yet for this feature; recommendation recorded for when one is built).
- **Affected Documentation:** `docs/operator/mcp-tool-trust-approvals.md` (one new paragraph after the
  "usable tool bypasses nothing" paragraph).
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (docs-only, one file).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Low-Medium — real future-confusion risk once a GUI panel for tool-trust approvals is built or
  support/docs writers describe the feature in isolation; zero current runtime/admin collision since the API
  routes and audit-event prefixes are already disambiguated at the code layer.

---

## Carried-Over Findings (unchanged — re-confirmed by file-list absence against the 19-merge window since `c20c17b`)

T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21 + T-32 (paired), T-25 (residual), T-29, T-30, T-31 (see
#1239 above — fix authored, unmerged), T-33, T-34, T-39. Full descriptions remain in the reports where each
was first raised; none of their dependent files appear in this window's changed-file list.

Also unchanged: the ADR-number reservation-convention recommendation first raised 2026-08-25 (a CI-enforced
version of it is now authored and ready to merge in #1309, per the table above — once merged, this
recommendation is closed).

---

## Recommended Refactoring Plan (priority order)

Unchanged from 08-25 for the still-open carry-over items (see that report and 08-24's for full descriptions).
T-53 is resolved in this pass. The backlog-reconciliation table above supersedes any prior "just merge PR #N"
recommendation as the actionable next step for the ADR-numbering item specifically.

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| **Critical (process)** | Governance PR backlog | Merge #1239, #1260, #1309 in that order; hand-recover #1302's T-50 fix and #1253's three unique fixes; close the rest as superseded with a comment | None (all docs/test-only) | N/A — repository-hygiene action, not a code change |
| Medium-High | T-39 | Decide the QUAL-2/3 bootstrap-fleet name and the QUAL-4 policy-source name; rename `qualification_*` away from bare "qualification" | Medium | Small-Medium |
| Medium | T-18 | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI; rename the audit-event string | Low | Small-Medium |
| Medium | T-21 + T-32 | Rename Cluster panel's `cp_version` and F3b's `snapshot_sha256` to unambiguous, non-colliding names | Low | Small |
| Medium | T-17 | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped names | Medium | Medium |
| Medium | T-29 | Alias YAML/CLI `rate_limit`/`-rate-limit` to accept `rate_limit_rpm` as well | Low-Medium | Small |
| Medium | T-30 | Alias YAML `max_conns_per_ip` / wire `MaxConnsPerIP` toward `conn_limit_max_per_ip` | Low-Medium | Small |
| Medium | T-33 | Stop overwriting `PolicyAction`/`PolicyReason` for pre-/post-policy gate failures; add a dedicated field | None today; rises once a consumer exists | Small |
| Medium | T-25 residual | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium | Small-Medium |
| Medium | T-9 | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium | Medium |
| Medium | T-11 | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low / Medium-large | Small / Medium-large |
| Medium | T-12 | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*` | Medium | Medium |
| Low-Medium | T-31 | Already authored in #1239 — merge it (see above) | Low | Small |
| Low | T-34 | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

---

## Stop-Condition Assessment

Terminology is **not** fully consistent, and — separately — the mechanism this program relies on to close
that gap is not currently converging. This pass found and fixed one small, genuine new documentation-clarity
gap (T-53) introduced by the new MCP Tool-Trust subsystem, confirmed no other new cross-surface drift in the
window since the last merge, and did not re-author a fix for the ADR-0034 collision because a correct one
already exists, unmerged, in #1309. The primary output of this review is the backlog reconciliation map
above: a week of correctly-functioning analysis has produced real fixes that are not reaching `main`, three
of which (in #1253) are at concrete risk of being lost if the eventual cleanup goes by PR title rather than
diff content. This is reported to the maintainer directly (see the accompanying notification) rather than
re-queued as an eighth "please merge" comment.
