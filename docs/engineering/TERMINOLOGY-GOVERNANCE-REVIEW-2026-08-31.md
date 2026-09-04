# Culvert Language & Terminology Governance Review — 2026-08-31

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `e698a12..0336149` (16 first-parent merges, 185 files changed, 31646 insertions / 744
> deletions — the immutable parent-commit endpoint, cited explicitly rather than as `HEAD`, since this
> review's own companion commit lands on top of it and a moving symbol would make the stated range wrong the
> moment it is pushed (the first draft used `HEAD` and was correct only at the instant it was written — a
> Codex review comment on this same PR caught the self-reference; not filed as its own finding ID, since it
> is a report-accuracy defect in this document's own method statement, not a product-terminology drift
> finding). Window dominated by the continuation of the MCP
> Shadow-readiness program into Canary: tool-trust approvals (ADR-0034), the Canary execution architecture
> (ADR-0035), rollback-rehearsal machinery (both the non-authoritative "mechanics" rehearsal and the new
> authoritative coordinator-rehearsal drill), plus a handful of unrelated small changes — `ui_tls_custom.go`
> (custom UI-TLS-certificate upload, touched again this window), `graceful-shutdown.md`, and CLAUDE.md
> maintenance. Method: (1) full-repo grep for every `# ADR-NNNN` header; (2) read the new
> `docs/operator/mcp-tool-trust-approvals.md` in full against the GUI (`ui_mcp_tooltrust.go`,
> `static/index.html`'s tool-trust panel) for the same class of same-word collision this program has caught
> before — the doc explicitly and correctly separates three adjacent concepts ("Trust" / "Availability" /
> "Authorization") that a less careful design could have blurred; no collision, recorded as a positive
> continuation pattern; (3) checked the GUI's single "Record rollback rehearsal…" control against the two
> backend rehearsal concepts this window introduces (the pre-existing non-authoritative "mechanics"
> rehearsal, `POST /api/mcp/rollout/rehearse-rollback`, and the new authoritative coordinator rehearsal,
> `POST /api/mcp/rollout/rehearse-rollback-authoritative`) — the GUI wires only the former, by name, to its
> own distinct audit event (`mcp.rollout.rehearse-rollback`); the authoritative rehearsal has no GUI surface
> yet, so no ambiguous label is presented to an admin — not drift; (4) checked all previously-open carry-over
> finding IDs' dependent files/identifiers (`sealbox`, `snapshot_sha256`, `decryption_redact_hosts`,
> `rate_limit`/`-rate-limit`, `max_conns_per_ip`, `/v1/upgrades/`, `culvert_clam_scan_errors_total`,
> `apiURLCatFeedStatus`, `qualification_`, `exportedAt`, `PolicyAction`/`PolicyReason`, the M5/M6
> recipient-registry pair) against this window's 185-file changed list — zero matches, so all are
> re-confirmed unchanged by file-list absence; (5) independent of this window's diff, walked
> `docs/design/PRODUCT-TERMINOLOGY.md`'s own canonical-vocabulary table end-to-end against the live
> `static/index.html`, specifically the "Traffic" row's three-surface mapping ("Live Feed", "Live Request
> Log", "Recent Requests" → nav / panel / dashboard-card).
> **Companion change:** two fixes ship with this review, both **corrected during this same PR's own
> automated review cycle** — see the Correction Notice immediately below before reading the rest of this
> document.

---

## Correction Notice — this review's first draft had two defects, caught by Codex's PR review

This document originally shipped (commit `721f247`) claiming (a) the ADR-header sweep was "clean — both
numbers are unique and sequential, no collision this time," and (b) the `PRODUCT-TERMINOLOGY.md` Traffic
sweep found exactly "one straggler." Both claims were wrong, and both errors were caught not by this
program's own audit but by `chatgpt-codex-connector`'s automated review of the PR this document shipped in
(PR #1277) — a second reviewer catching what the first missed, functioning exactly as the review pipeline
is supposed to. Recorded here in full rather than silently corrected, matching this program's own standing
practice (the 2026-07-24 review's superseded-note precedent) of leaving a visible trail when a prior
conclusion in this same document turns out to be wrong:

1. **The ADR sweep was not actually clean.** `docs/adr/0034-mcp-tool-trust-approval.md` (ACCEPTED,
   2026-08-28, the real tool-trust decision this window's own MCP work introduced) and
   `docs/support/rfc/0034-ai-receives-normalized-evidence.md` (PROPOSED — NOT ADOPTED, dated 2026-07-13,
   itself only renumbered to `0034` by the *previous* review cycle's T-47 fix) both declared `# ADR-0034`.
   This is the fourth occurrence of the identical recurring defect class (T-16, T-46, T-47, now T-49) — this
   time the collision was created by the very number the T-47 fix had just freed up landing back in
   collision within one review cycle, because an independent PR stream (this window's own MCP tool-trust
   work) claimed the same number by the same "grep the tree for the next free number" method that has
   caused every prior instance. The claim in the first draft's Method line was simply not re-verified against
   the actual window's own new files before being written — an error in this program's own process, not a
   subtle one. Fixed as T-49 below, same precedent a fourth time.
2. **The GUI sweep stopped after finding the first hit instead of searching exhaustively.** The first draft
   found `static/index.html:1302`'s panel title and stopped there. A full-text search for "Live Feed" (the
   other legacy name the same terminology-doc row replaces, distinct from "Live Request Log" but governed
   by the identical row) turns up two more administrator-facing stragglers this program's own audit should
   have found the first time: the Decryption Health panel's coverage hint (`static/index.html:3856`) and
   its `meta` description (`static/index.html:6007`), both still telling an admin to go find the "Live
   Feed" — a destination that has not existed under that name since the nav item was renamed to "Traffic" in
   July. Folded into T-48 below (same finding, corrected scope) rather than filed as a new ID, since it is
   the identical business concept and the identical root cause (an incomplete migration), just more
   thoroughly searched for.

Both fixes ship in this PR's follow-up commit. The remainder of this document is written as it now stands
after both corrections — the two paragraphs above are the honest record of how it got here.

---

## Executive Summary

**Two findings, both fully fixed.**

**T-48 — the "Traffic" rename left three stragglers, not one.** `docs/design/PRODUCT-TERMINOLOGY.md`'s
table prescribes an explicit three-surface mapping — "Live Feed", "Live Request Log", "Recent Requests" →
**"Traffic"** (nav), **"Live traffic"** (panel), **"Recent requests"** (dashboard card) — and the nav item
and dashboard card landed correctly in July. Three administrator-facing spots did not: the Traffic view's
own panel header (`static/index.html:1302`, "Live Request Log") and two Decryption Health strings that
told an admin to go find the "Live Feed" (`static/index.html:3856`, `:6007`) — a name that view has not
answered to since the nav rename. All three fixed to say "Traffic" / "Live traffic" as the terminology doc
prescribes. Purely GUI strings; no Go identifier, JSON field, audit event, metric, or test fixture
referenced any of the old text (verified by full-repo grep after the fix, not just before it).

**T-49 — fourth recurrence of the ADR-numbering collision, on `0034` this time.** Same root cause as T-16,
T-46, and T-47: two independent PR streams each computed "the next free number" by grepping the tree at the
moment they needed one, with no reservation mechanism, so a just-freed number (T-47 freed `0032` by moving
the RFC to `0034` in the *previous* review cycle) is exactly as available to a concurrent stream as a
genuinely fresh one — and this time the concurrent stream claimed it inside the very next window.
**Fix, same precedent a fourth time:** the established, ACCEPTED `docs/adr/0034-mcp-tool-trust-approval.md`
keeps `0034` (2026-08-28, cited twice from `docs/design/mcp/SHADOW-ACTIVATION.md` within the same window it
was created — expensive to move); the not-yet-adopted RFC
(`docs/support/rfc/0034-ai-receives-normalized-evidence.md`, still carrying its original "PROPOSED — NOT
ADOPTED" status from 2026-07-13) is renumbered again, this time to **`0036`** — the next number confirmed
clean against every `# ADR-NNNN` header in the repository as of this pass, including both new files from
this window (`0034` and `0035`). File renamed, header updated, and all five downstream citations updated to
match: `docs/support/TAC-CLOUD-ARCHITECTURE.md` (3 call sites — §3 prose, the §6 section heading, the §8
pipeline step), `docs/support/SUPPORTABILITY-THREAT-MODEL.md` (the `T-PROMPT` row), and
`docs/adr/0016-raw-evidence-vs-normalized-findings.md`'s own "Relates to" line — the identical five-file
citation set the T-47 fix touched the previous cycle, because it is the identical document being renumbered
a second time. The citations in `docs/operator/mcp-tool-trust-approvals.md`,
`docs/design/mcp/SHADOW-ACTIVATION.md` (both mentions), `docs/adr/0035-mcp-canary-execution-architecture.md`,
and `docs/engineering/TECHNICAL-DEBT-REGISTER.md` were checked and confirmed to genuinely mean the *new*
ADR-0034 (tool trust) and left untouched.

**This program's numbering-collision recommendation is now overdue for action, not another repetition.**
The 2026-08-25 review recorded a "New Recommendation" after the third occurrence, explicitly noting "a
fourth recurrence would be the point at which 'keep fixing it each time it happens' stops being the cheaper
option than 'stop it from happening.'" This is that fourth recurrence, and it arrived within one review
cycle of the third. Restated below, upgraded from a recommendation to a standing flag: this is not a
terminology-drift finding this program can fix with a rename (it needs either a CI check that fails a PR
introducing a duplicate `# ADR-NNNN` header, or a documented number-reservation practice), so it is not
added to the priority-ordered backlog, but it should not require a fifth occurrence to get owner attention.

**Terminology Health Score: 8.5 / 10** (down from 8.6). Two real, if low-severity, drift items were found
and fixed at zero migration risk — but the score moves down, not up, this pass, for a reason internal to
this program rather than the codebase: this review's own first draft under-audited on both counts (a
GUI sweep that stopped at the first hit; an ADR check that was asserted rather than freshly re-verified),
and both errors were caught by an external reviewer rather than this program's own process. The codebase's
underlying terminology health did not regress — if anything, two more stragglers are now fixed than were
before this pass began — but a governance program that needs a second reviewer to catch what its own sweep
missed, twice in the same document, is a governance regression worth reflecting in the number until the
next window demonstrates it was a one-off rather than a pattern.

---

## Findings

### T-48 — "Traffic" rename left three administrator-facing stragglers (new — fixed this pass, scope corrected mid-review)

- **Business concept:** the live-updating table of individual proxied requests (the Monitor section's
  request stream), canonically named **Traffic**.
- **Current names before this fix:** nav item — "Traffic" (`static/index.html:767`, correct); dashboard
  card — "Recent Requests" (`static/index.html:1168`, correct); Traffic view's own panel header — "Live
  Request Log" (`static/index.html:1302`); Decryption Health panel's coverage hint — "...see those sessions
  in the Live Feed" (`static/index.html:3856`); Decryption Health's `meta` description — "...drill into the
  Live Feed" (`static/index.html:6007`).
- **Why the current naming was problematic:** three administrator-facing surfaces, two of them cross-links
  *into* the correctly-renamed Traffic view from elsewhere in the product, still spoke one of the two legacy
  names ("Live Request Log", "Live Feed") the terminology doc's table explicitly lists as replaced — an
  admin following either Decryption Health cross-link would be told to go find a view that, by name, no
  longer exists.
- **Recommended (and applied) canonical name:** "Live traffic" for the panel header (the table's prescribed
  panel-level name); "Traffic" for the two Decryption Health cross-link strings (referring to the
  destination view by its nav name, matching how every other in-app cross-reference names a destination).
- **Why the new name is better:** completes a rename this program's own governance doc already decided in
  July, on all three surfaces the table specifies rather than one; removes every remaining place a reader
  saw an old name for a view now called something else.
- **Affected code:** `static/index.html` (three strings: one `panel-title` span, one `<p class="hint">`
  sentence, one JS object literal's `meta` field).
- **Affected API:** none.
- **Affected GUI:** the Traffic view's own panel header; the Decryption Health panel's coverage-hint text and
  its sidebar `meta` description.
- **Affected Documentation:** none (the terminology doc already prescribed these names; it needed no edit).
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial — three strings, no Go identifier, JSON field, audit event, metric, or
  test fixture referenced any of the old text (verified by full-repo grep, this time including both legacy
  names — "Live Request Log" and "Live Feed" — separately, after the initial single-hit search that missed
  two of the three was corrected).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Low (cosmetic GUI text, no functional impact) — carried out anyway because it closes a
  compliance gap against the project's own already-decided, already-documented terminology contract, at
  zero cost and zero risk.

### T-49 — Fourth recurrence of the ADR-numbering collision, this time on `0034` (new — fixed this pass)

- **Business concept:** the unique identifier for one architecture decision record.
- **Current names before this fix:** `# ADR-0034` claimed simultaneously by
  `docs/adr/0034-mcp-tool-trust-approval.md` (ACCEPTED, dated 2026-08-28, part of this window's MCP
  Canary-readiness work) and `docs/support/rfc/0034-ai-receives-normalized-evidence.md` (PROPOSED — NOT
  ADOPTED, dated 2026-07-13, renumbered to `0034` by the *previous* review cycle's T-47 fix after the
  identical collision on `0032`).
- **Recommended canonical name:** `docs/adr/0034-mcp-tool-trust-approval.md` keeps ADR-0034 (established,
  ACCEPTED, cited twice from `docs/design/mcp/SHADOW-ACTIVATION.md` within the same window it was created);
  the RFC becomes ADR-0036.
- **Why the current naming was problematic:** identical to T-16, T-46, and T-47 — a bare "ADR-0034" citation
  in `TAC-CLOUD-ARCHITECTURE.md` or `SUPPORTABILITY-THREAT-MODEL.md` was ambiguous between two unrelated
  decisions (the MCP tool-trust/approval-purpose binding vs. the AI-input-normalization boundary) with no
  way to disambiguate from the number alone.
- **Why the new name is better:** restores a 1:1 mapping between decision-record number and decision; `0036`
  is confirmed clean against every `# ADR-NNNN` header in the repository as of this pass, including both new
  files from this window.
- **Affected code:** none.
- **Affected API:** none.
- **Affected GUI:** none.
- **Affected Documentation:** `docs/support/rfc/0034-ai-receives-normalized-evidence.md` (renamed to
  `0036-ai-receives-normalized-evidence.md`, header updated), `docs/support/TAC-CLOUD-ARCHITECTURE.md` (3
  citations), `docs/support/SUPPORTABILITY-THREAT-MODEL.md` (1 citation),
  `docs/adr/0016-raw-evidence-vs-normalized-findings.md` (1 "Relates to" citation).
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (docs-only, 5 files, no code/API/GUI/config surface).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Medium (matches T-16's, T-46's, and T-47's own priority — a documentation-identifier
  collision with no runtime/functional impact, but a real and now-four-times-demonstrated-recurring risk of
  a reader or an AI agent citing or acting on the wrong decision record). The recurrence itself, now a
  fourth time and within one review cycle of the third, is the more urgent signal — see the Executive
  Summary's standing flag above.

---

## Re-verified, not re-litigated (no change)

**"Incident scope"** (`support_scopes.go`, `internal/support/manifest.go`'s `IncidentScope`/
`incident_scope`, and the GUI tooltip at `static/index.html:5098`) was independently re-checked against
`docs/design/PRODUCT-TERMINOLOGY.md`'s "Incident" ban and re-confirmed, consistent with the 2026-07-24 and
2026-07-31B reviews, to be the pre-existing, correct, out-of-scope M3 Support Bundle collector-scope
catalog the ban was never intended to reach — a stateless "which collectors run" concept, unrelated to the
stateful incident-management entity the ban exists to keep out of the product. No change.

---

## Carried-Over Findings (unchanged — re-confirmed by dependent-file absence)

All previously-open carry-over finding IDs — T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21 + T-32
(paired), T-25 (residual), T-29, T-30, T-31, T-33, T-34, T-39 — were re-checked against this window's
185-file changed list by grepping for each finding's dependent identifiers/paths (`sealbox`,
`snapshot_sha256`, `decryption_redact_hosts`, `rate_limit`/`-rate-limit`, `max_conns_per_ip`,
`/v1/upgrades/`, `culvert_clam_scan_errors_total`, `apiURLCatFeedStatus`, `qualification_`, `exportedAt`,
`PolicyAction`/`PolicyReason`, the M5/M6 recipient-registry pair); none intersect this window's diff, so
every carry-over item is re-confirmed open and unchanged. Full descriptions remain in the reports where each
was first raised and in `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-25.md`'s own carry-over list, to avoid
duplicating unchanged text.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 08-25 — no carry-over item's priority, risk, or size estimate changes this pass, and T-48 /
T-49 are resolved in this pass so neither appears on the plan. See
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-25.md` for the current table (T-39 through T-13 residual, Medium-High
down to Low).

---

## Stop-Condition Assessment

Terminology is **not** fully consistent (the unchanged fourteen-item carry-over backlog remains open, and
this window added one new, now-fixed instance of the recurring ADR-numbering defect). This pass fixed one
Low-priority GUI straggler (T-48, corrected mid-review to cover all three affected strings rather than one)
and one Medium-priority documentation-identifier collision (T-49) — the fourth instance of a defect class
this program has now recommended a structural fix for after its third occurrence, without one landing before
the fourth. Both fixes are docs/GUI-only, zero migration risk, zero compatibility impact. No cosmetic or
preference-driven renames were proposed beyond what completes decisions the project's own governance
documents had already made. This document also records, in the Correction Notice above, that its own first
draft under-audited on both findings and was corrected by the PR's own automated review rather than by this
program's process — read as a caution for the next window, not papered over.
