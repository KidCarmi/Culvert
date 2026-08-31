# Culvert Language & Terminology Governance Review — 2026-08-31

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `e698a12..HEAD` (16 first-parent merges, 185 files changed, 31646 insertions / 744
> deletions — dominated by the continuation of the MCP Shadow-readiness program into Canary: tool-trust
> approvals (ADR-0034), the Canary execution architecture (ADR-0035), rollback-rehearsal machinery (both
> the non-authoritative "mechanics" rehearsal and the new authoritative coordinator-rehearsal drill), plus a
> handful of unrelated small changes — `ui_tls_custom.go` (custom UI-TLS-certificate upload, touched again
> this window), `graceful-shutdown.md`, and CLAUDE.md maintenance). Method: (1) full-repo grep for every
> `# ADR-NNNN` header, continuing the check this program has run every window since the numbering-collision
> defect class first appeared (T-16), given this window lands two more `docs/adr/` files (`0034`, `0035`)
> — clean: both numbers are unique and sequential, no collision this time; (2) read the new
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
> re-confirmed unchanged by file-list absence; (5) independent of this window's diff, re-verified
> `docs/design/PRODUCT-TERMINOLOGY.md`'s own canonical-vocabulary table end-to-end against the live
> `static/index.html` for any surviving unmigrated entry — this table has stood since 2026-07-11 and no
> prior review recorded having walked every row against the shipped GUI; found one straggler (below).
> **Companion change:** one fix ships with this review.

---

## Executive Summary

**One finding, fully fixed: the "Traffic" rename (`docs/design/PRODUCT-TERMINOLOGY.md`) left one panel
title unmigrated.** The terminology doc's own table records an explicit three-surface mapping — "Live
Feed", "Live Request Log", "Recent Requests" → **"Traffic"** (nav), **"Live traffic"** (panel), **"Recent
requests"** (dashboard card) — and two of the three landed correctly (`static/index.html`'s Monitor nav
item already reads "Traffic"; the dashboard card already says "Recent Requests"). The third did not: the
Traffic view's own panel header, one level below the correctly-renamed nav item, still read "Live Request
Log" (`static/index.html:1302`), the exact legacy name the table lists as replaced. This is the same class
of finding this program has caught before in other migrations (a rename landing on most but not all of its
surfaces) — a straggler from a July migration that twenty-plus prior review passes did not catch, because
none had walked this specific table's three-surface mapping row by row against the live GUI. Fixed to
**"Live traffic"**, matching the table's own prescribed panel-level casing (sentence case, consistent with
the nav label immediately above it in the same view). Purely a GUI string; no Go identifier, JSON field,
audit event name, metric, or test fixture referenced the old panel title (verified: zero other hits for
"Live Request Log" across `*.go`, `*.html`, `*.js`, `*.md`; the one e2e test touching this panel,
`ui_ruleid_traffic_e2e_test.go`, only exercises the `#live-log` DOM id, unaffected).

**Re-verified, not re-litigated: the "Incident scope" pattern is still correctly out of scope.**
`docs/design/PRODUCT-TERMINOLOGY.md` bans "Incident" as a product concept ("no backend entity — MUST NOT
appear in the UI"), and a literal-text search independent of this window's diff turns up `support_scopes.go`
(`supportIncidentScopes`), `internal/support/manifest.go`'s `IncidentScope`/`incident_scope` field, and a
GUI tooltip reading "Incident scope: focus the bundle on collectors relevant to one incident type"
(`static/index.html:5098`). This is the same M3-era Support Bundle collector-scope catalog the 2026-07-24
and 2026-07-31B reviews already read in full and confirmed is a **pre-existing, correct, out-of-scope**
concept the glossary's ban was never intended to reach — a stateless "which collectors run" catalog,
unrelated to the stateful incident-management entity the ban exists to keep out of the product (which the
07-24 review caught and renamed to "degradation" before it ever shipped). Re-confirmed again this pass by
independently re-reading both prior conclusions and the current source before writing this paragraph,
specifically to avoid re-flagging a settled question. No change.

**Terminology Health Score: 8.6 / 10** (unchanged from 08-25). This pass fixed one confirmed straggler from
an already-decided rename — a real, if low-severity, drift item (a legacy name persisting on one of three
prescribed surfaces) — at zero migration risk and zero compatibility impact. The score does not move because
the fix is Low priority (cosmetic panel text, no functional or API surface) and the carry-over backlog is
unchanged: all previously-open finding IDs' dependent files were absent from this window's 185-file diff, so
none could be re-verified against fresh code and none were newly closed. Positive signal not reflected in the
number: the largest MCP feature push to date in a single window (185 files, tool-trust approvals + Canary
execution architecture + two rehearsal concepts landing in the same window) introduced zero new collisions —
both places a collision was most plausible (the tool-trust vocabulary, the dual rehearsal concepts) were
read in full and found cleanly disambiguated by their own authors.

---

## Findings

### T-48 — Traffic panel still reads "Live Request Log" after the nav-level rename (new — fixed this pass)

- **Business concept:** the live-updating table of individual proxied requests (the Monitor section's
  request stream), canonically named **Traffic**.
- **Current names before this fix:** nav item — "Traffic" (`static/index.html:767`, correct); dashboard
  card — "Recent Requests" (`static/index.html:1168`, correct); Traffic view's own panel header — "Live
  Request Log" (`static/index.html:1302`, **not** migrated) — the same view, one level below its own
  correctly-renamed nav entry, still speaking the pre-rename name.
- **Why the current naming was problematic:** `docs/design/PRODUCT-TERMINOLOGY.md` explicitly lists "Live
  Request Log" among the names this rename replaces, and an administrator opening the "Traffic" nav item
  landed on a panel titled with the exact legacy term the nav label had just replaced — the one surface in
  the three-surface mapping where the old and new names were shown one click apart from each other.
- **Recommended (and applied) canonical name:** **"Live traffic"**, exactly as prescribed by
  `docs/design/PRODUCT-TERMINOLOGY.md`'s own table for the panel-level surface.
- **Why the new name is better:** completes a rename this program's own governance doc already decided in
  July; removes the one place a reader saw both the old and new name for the identical concept in the same
  screen.
- **Affected code:** `static/index.html` (one `<span class="panel-title">` string).
- **Affected API:** none.
- **Affected GUI:** the Traffic view's live-log panel header only; the table columns, export buttons, and
  entry count badge below it are unchanged.
- **Affected Documentation:** none (the terminology doc already prescribed this name; it needed no edit).
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial — one string, no Go identifier, JSON field, audit event, metric, or test
  fixture referenced the old text (verified by full-repo grep).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Low (cosmetic GUI text, no functional impact) — carried out anyway because it closes a
  compliance gap against the project's own already-decided, already-documented terminology contract, at
  zero cost and zero risk; exactly the class of finding the Stop Conditions describe as worth fixing over
  one better left alone.

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

Unchanged from 08-25 — no carry-over item's priority, risk, or size estimate changes this pass, and T-48 is
resolved in this pass so it does not appear on the plan. See `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-25.md`
for the current table (T-39 through T-13 residual, Medium-High down to Low).

---

## Stop-Condition Assessment

Terminology is **not** fully consistent (the unchanged fourteen-item carry-over backlog remains open). This
pass fixed one Low-priority, zero-risk straggler (T-48) — a rename the project had already decided and
documented in July but had not fully carried through to every surface — and, despite auditing the largest
single-window MCP feature push this program has processed (185 files, two new architecture decisions, two
distinct rehearsal concepts introduced in the same window), found zero new same-window collisions: both of
the window's most collision-prone additions (the tool-trust vocabulary, the dual rehearsal concepts) were
read in full and confirmed to be cleanly disambiguated by their own authors. The "Incident scope" question
was independently re-verified rather than re-flagged. No cosmetic or preference-driven renames were
proposed beyond the one straggler fix, which itself completes — rather than second-guesses — a decision the
project's own governance document already made.
