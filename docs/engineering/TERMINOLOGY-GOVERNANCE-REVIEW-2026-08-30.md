# Culvert Language & Terminology Governance Review — 2026-08-30

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `3f83ca91..72a3ff5e` (36 commits, 1 on the first-parent path — the MCP Canary
> Activation Gate merge, PR #1252: `internal/mcp/canary`'s pure readiness engine, the root canary
> preflight/attestation/budget-enforcement/abort-controller/rollback-rehearsal composition layer, and
> ADR-0035). Method: (1) read `docs/adr/0035-mcp-canary-execution-architecture.md` in full and
> cross-checked its vocabulary (`AbortRequest`/`AbortCanary`, "rollback rehearsal", "attestation",
> "budget", "activation gate") against the Go identifiers in `internal/mcp/canary/*.go` and
> `mcp_canary_*.go` for the same-window collision pattern that produced T-49–T-51 in the prior review — none
> found; the ADR's own terms are used consistently and each pair of superficially-similar concepts
> (`AbortRequest` vs. `AbortCanary`, the pure `RollbackRehearsalRecord` vs. the historical self-attested
> marker it replaces) is already disambiguated in the source text; (2) diffed the new
> `/api/mcp/canary/shadow-exit-review` OpenAPI operations against `mcp_canary_attestation.go`'s field/audit-
> event names — `review_id`/`evidence_digest`/`attested`/`persisted` and the
> `mcp.canary.shadow-exit-review.{attest,revoke}` audit-event names match the ADR's "Shadow Exit Review
> attestation" vocabulary exactly, with no parallel synonym introduced; (3) `static/index.html` is
> byte-unchanged in this window (confirmed via `git diff --stat`), so there is no new GUI copy to check
> against `PRODUCT-TERMINOLOGY.md` this pass; (4) re-checked all previously-open carry-over finding IDs
> against this window's 46-file changed list — none intersect; (5) continuing the 08-29 review's
> discovery method (auditing existing `PRODUCT-TERMINOLOGY.md` rows for actual compliance rather than only
> scanning new diffs), read every row not yet re-verified this way and grepped `static/index.html` +
> `internal/support` for the **Incident** row specifically, since it is phrased as an absolute prohibition
> ("MUST NOT appear in the UI") — found a genuine, narrow drift, detailed below; also re-verified the
> **"unauth mode"** and **blacklist/whitelist** prohibitions still hold repo-wide (clean) and that
> **"Appliance"** does not appear in the legacy `static/index.html` (clean — the T-51 leaks found in the
> prior review's unmerged pass are confined to the v2 frontend and the OpenAPI spec, not the legacy GUI).
> **Companion note:** this review also checked GitHub's open-PR queue against the repository, since the
> governance program keeps its own record of prior findings in dated report files and two such files exist
> only on unmerged branches — see the Program Note below, which affected how this pass scoped its own
> "carried-over" list.

---

## Program Note: two prior governance PRs are open and unmerged, and this review does not re-do their work

`main`'s `docs/engineering/` directory currently tops out at
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-25.md` — the 2026-08-28 and 2026-08-29 runs of this program each
produced a report and a set of fixes (T-31's `culvert_clamav_scan_errors_total` dual-emit in **PR #1239**;
T-48's fourth ADR-numbering collision + a new `docs_adr_numbering_test.go` CI guard, T-49's "kill switch"
qualifier, T-50's Steering Profile wording fix, and T-51's "Appliance"→"Node" fixes, all in **PR #1253**),
but neither PR has merged. Concretely, as of this review **`main` still has the live, unfixed T-48 defect**:
`docs/adr/0034-mcp-tool-trust-approval.md` (ACCEPTED, code-wired) and
`docs/support/rfc/0034-ai-receives-normalized-evidence.md` (PROPOSED, unchanged since 2026-07-13) both
declare `# ADR-0034` on `main` right now — confirmed by grepping every `# ADR-NNNN` header in the tree
before writing this report. **This review does not re-fix it**: PR #1253 already contains the correct,
tested fix (renumber the RFC to `0036`, add a CI guard that fails the build on any future collision), and
opening a second PR with the same file rename would only hand whoever merges these two a needless conflict
to resolve by hand. The action item is to merge #1239 and #1253 (in either order — they touch disjoint
files), not to re-derive their content. This review's own "carried-over" list below is therefore stated
against **`main`'s actual current state** (so T-31 and T-48 still appear, matching what a reader of `main`
today would actually find), not against the state those two PRs would produce once merged.

This is worth flagging as a process observation rather than a fix: a daily terminology-governance PR that
routinely goes unmerged means `main`'s real backlog quietly grows regardless of how many reports say a given
item is "fixed this pass" — the fix exists on a branch, not in the product. Recommend merging the
governance program's open PRs (currently #1239, #1253, and this one) promptly, the same way any other
`docs`-only, zero-risk PR would be.

---

## Executive Summary

**No new terminology drift was found in today's actual audited window** (the MCP Canary Activation Gate
merge, PR #1252). This is a large, security-critical addition (~6,400 inserted lines across `internal/mcp/
canary` and eight new root `mcp_canary_*.go` files) but it was built under the same mutation-tested,
Codex-reviewed discipline evident elsewhere in this codebase, and its vocabulary is internally disjoint and
consistent on first read: `AbortRequest` (per-request, survivable) is never confused with `AbortCanary`
(whole-Canary, latching) in either the ADR prose or the Go identifiers; "rehearsal" always means the real
Canary→Shadow→Observe demotion drill (`RollbackRehearsalRecord`), never the retired self-attested marker
it replaces; "attestation" is reserved for the durable, admin-created Shadow Exit Review record and does not
bleed into "approval" (the separate, pre-existing `tooltrust` four-eyes concept) anywhere in the new files.
The new `GET/POST/DELETE /api/mcp/canary/shadow-exit-review` OpenAPI operations use the exact same field and
audit-event vocabulary as the Go source (`review_id`, `evidence_digest`, `attested`, `persisted`,
`mcp.canary.shadow-exit-review.attest`/`.revoke`) — no parallel synonym was introduced at the API boundary,
which is the seam where this program has most often found drift in other MCP subsystems (T-38's
`drifted_tools`/`review_required_tools` split, the 08-24 `mcp_health_plane.go` audit, etc.). `static/
index.html` is unchanged in this window, so there is no new GUI-copy compliance question to check.

**One genuine, previously-undocumented finding, fixed this pass: the `PRODUCT-TERMINOLOGY.md` "Incident"
row is stated as an absolute prohibition that the shipped product already narrowly, legitimately violates.**
The row reads *"Not a product concept. No backend entity — MUST NOT appear in the UI"* — written 2026-08-21,
well after the Supportability Framework's `IncidentScope` (`internal/support`, CLAUDE.md's own "M0–M5
shipped" framework description) was already live. `IncidentScope` is a real, tested, already-documented Go
type (`tls`/`upstream`/`policy`/`storage`/`dns`/`cluster`/`scan`) that scopes a support bundle to one
incident's relevant collectors, and it genuinely does appear in the UI: the Support panel's Scope selector
carries a tooltip reading "Incident scope: focus the bundle on collectors relevant to one incident type"
(`static/index.html`), and `resolveSupportBundlesPostParams`'s validation error is literally "unknown
incident scope" (`ui_support.go`). Read literally, the terminology doc says this MUST NOT exist; the product
has shipped it for weeks. **This is not the forbidden concept** — there is no incident list, incident ID,
incident lifecycle, or ticketing entity anywhere in Culvert, so the row's actual intent (don't invent a
generic incident-tracking object) is still sound and still true today. The row was simply written without
accounting for the one place "incident" is already used adjectivally to describe an existing, narrower,
already-shipped concept. Left as written, the row is a standing false claim about the product that the next
engineer or reviewer who takes it literally (as this review very nearly would have, before checking the
actual UI) would either act on incorrectly (flagging or removing legitimate, working `IncidentScope` copy)
or learn to distrust (if they notice the contradiction and conclude the document is unreliable). Both
outcomes are exactly what this program exists to prevent. **Fix:** the row now states the real prohibition
(no incident-tracking/ticketing entity) and explicitly carves out `IncidentScope` as a distinct, legitimate,
already-shipped concept that may keep using "incident" adjectivally — the identical pattern this same
document already uses for **Profile** (four legitimate, distinct Profile concepts recorded side by side
rather than pretending only one may exist).

**Terminology Health Score: 8.8 / 10** (unchanged from the 08-29 pass, which this review's live check of
`main` confirms is still unmerged — so `main`'s actual score has not yet risen to reflect T-48–T-51's fixes).
This pass finds one new, real, zero-risk documentation-accuracy defect (the Incident row) and confirms a
large new security subsystem shipped with no fresh terminology drift of its own. The score does not move
because the underlying carried-over backlog (below) is unchanged and because two governance-program fixes
already written remain unmerged on `main`, which is a process gap rather than a terminology one.

---

## Findings

### T-52 — `PRODUCT-TERMINOLOGY.md`'s "Incident" row is an absolute prohibition the shipped product already narrowly and legitimately violates (new — fixed this pass)

- **Business concept:** (a) a generic incident-tracking/ticketing entity — genuinely absent from Culvert, and
  rightly so; (b) the Support Bundle's collector-scope selector, `internal/support`'s `IncidentScope`
  (`tls`/`upstream`/`policy`/`storage`/`dns`/`cluster`/`scan`) — a real, shipped, distinct concept that
  happens to share the English word "incident."
- **Current names before this fix:** the terminology doc's **Incident** row said, unconditionally, "Not a
  product concept. No backend entity — MUST NOT appear in the UI." In the actual shipped product: the
  Support panel's Scope field carries the tooltip "Incident scope: focus the bundle on collectors relevant
  to one incident type" (`static/index.html:5098`), and `ui_support.go`'s `resolveSupportBundlesPostParams`
  / `buildSupportBundle` reject an unrecognized `?scope=` value with the error text "unknown incident scope."
  `IncidentScope` is also a documented struct field (`support.BuildResult`/manifest) referenced across
  `internal/support/manifest.go`, `internal/support/runner.go`, `support_scopes.go`, and four files under
  `docs/support/`.
- **Recommended canonical name:** no rename of any code, API, or GUI string — `IncidentScope`, `?scope=`,
  and the GUI "Scope" label are all correctly named and none is the forbidden generic entity. The fix is to
  `PRODUCT-TERMINOLOGY.md` itself: state the real prohibition (no incident-tracking/ticketing object — no
  list, ID, or lifecycle) and explicitly record `IncidentScope` as a distinct, legitimate, already-shipped
  concept permitted to use "incident" adjectivally, mirroring the existing **Profile** row's four-concepts-
  coexist pattern.
- **Why the current naming was problematic:** a documentation row phrased as an absolute "MUST NOT appear in
  the UI" rule that the shipped product already contradicts is worse than having no rule at all — a reader
  who trusts it literally will misdiagnose working, already-tested copy as a violation to remove; a reader
  who spots the contradiction has reason to distrust every other row in the same document. This review
  itself nearly treated the tooltip as a live violation before confirming `IncidentScope` is a real,
  intentional, already-documented (CLAUDE.md) backend concept rather than an ad hoc leak.
- **Why the new name is better:** the row now says what is actually true of the shipped product — no
  general incident entity exists, and none should be added — while correctly scoping the prohibition so it
  does not accidentally indict a legitimate, narrower, already-shipped feature. This is the same clarity
  the Profile row already provides for its four coexisting concepts.
- **Affected code:** none.
- **Affected API:** none.
- **Affected GUI:** none.
- **Affected Documentation:** `docs/design/PRODUCT-TERMINOLOGY.md` (one row).
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (one documentation row, no code/API/GUI/config surface).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Low-Medium — no functional or user-facing impact today, but a documentation-accuracy defect
  in the governance program's own canonical reference, which is exactly the kind of standing false claim
  this program exists to catch before it misleads a future reviewer (human or automated).

---

## Carried-Over Findings (unchanged on `main` — re-confirmed by file-list absence)

Stated against `main`'s actual current state (see the Program Note above — PRs #1239 and #1253 propose
fixes for two of these but have not merged): **T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21 + T-32
(paired), T-25 (residual), T-29, T-30, T-31, T-33, T-34, T-39, T-48** were all re-checked against this
window's 46-file changed list (`internal/mcp/canary`, root `mcp_canary_*.go`, `mcp_rollout*.go`,
`ui_mcp*.go`, `ui_rbac*.go`, `ui_middleware.go`, `ui_routes_meta*.go`, `version.go`, the OpenAPI/route-
classification/API-inventory artifacts, `docs/adr/0035-*`, two `docs/design/mcp/CANARY-*` docs, `.trivyignore`,
`Dockerfile`, a release-binaries CI action, and `d0_helpers_test.go`); none of their dependent files appear
in it, so all sixteen are re-confirmed open and unchanged. Full descriptions remain in the reports where each
was first raised (T-48 in the unmerged `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-29.md`; the rest in
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-25.md` and earlier), to avoid duplicating unchanged text.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 08-25/08-29 for the still-open items; T-52 is resolved in this pass and does not appear on
the plan. T-48's row is included because it is still unfixed on `main` (see Program Note); its fix already
exists, tested, on PR #1253 and should be merged rather than redone.

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| High (process) | T-48 (unfixed on `main`) | Merge PR #1253 (renumber the RFC to ADR-0036, land the `docs_adr_numbering_test.go` CI guard) | None — already written and tested | Small (merge, not new work) |
| Medium-High | T-39 (carried over) | Decide the QUAL-2/3 bootstrap-fleet name and the QUAL-4 policy-source name; rename `qualification_inventory_file`/`qualification_telemetry`/`qualification_policy_file` and their operator-doc titles/GUI strings away from bare "qualification"; reserve that word for the Production receipt gate | Medium | Small-Medium (needs a naming decision first) |
| Medium | T-18 (carried over) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI; rename the audit-event string | Low | Small-Medium |
| Medium | T-21 + T-32 (carried pairing) | Rename Cluster panel's `cp_version` and F3b's `snapshot_sha256` to unambiguous, non-colliding names | Low | Small |
| Medium | T-17 (carried over) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped names | Medium | Medium |
| Medium | T-29 (carried over) | Alias YAML/CLI `rate_limit`/`-rate-limit` to accept `rate_limit_rpm` as well | Low-Medium | Small |
| Medium | T-30 (carried over) | Alias YAML `max_conns_per_ip` / wire `MaxConnsPerIP` toward `conn_limit_max_per_ip` | Low-Medium | Small |
| Medium | T-33 (carried over) | Stop overwriting `PolicyAction`/`PolicyReason` for pre-/post-policy gate failures; add a dedicated field for those instead | None today (zero production consumers); rises once a consumer exists | Small |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low / Medium-large | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*` | Medium | Medium |
| Low-Medium (process) | T-31 (unfixed on `main`) | Merge PR #1239 (dual-emit `culvert_clamav_scan_errors_total`) | None — already written and tested | Small (merge, not new work) |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

---

## Stop-Condition Assessment

Terminology is **not** fully consistent, but today's actual audited window (the MCP Canary Activation Gate
merge) introduced no new drift of its own — a large, security-critical subsystem landed with internally
consistent, non-colliding vocabulary and an API surface that matches its Go source exactly. This pass's one
new finding (T-52) is a documentation-accuracy defect in the governance program's own canonical reference
rather than product drift: a "MUST NOT appear" rule that the shipped product already narrowly and correctly
violates, now corrected to record both concepts side by side (the same pattern already used for Profile).
All previously-open carry-over findings were re-confirmed unchanged. This review also surfaced a process
observation worth acting on promptly: two prior governance-program PRs (#1239, #1253) contain fully-written,
tested fixes that have not yet merged, so `main` still carries defects (T-31, T-48) that dated reports have
already described as "fixed." No cosmetic or preference-driven renames were proposed.
