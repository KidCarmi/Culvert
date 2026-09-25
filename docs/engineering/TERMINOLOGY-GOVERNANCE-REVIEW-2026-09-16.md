# Culvert Language & Terminology Governance Review — 2026-09-16

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Snapshot scope (read this first):** this is a HISTORICAL record of `origin/main` at `993b390` on
> 2026-09-16. It was merged later, after `main` had moved on, so the tree it ships in contains commits it
> never audited. Its findings, carried-over backlog, health score and PR-backlog recommendations describe
> `993b390` only. They are not a statement about the tree this file is published in; the current governance
> state is whatever the most recent review in this series says. Later windows are audited by later
> reports, never retroactively by this one.
> **Method:** Fetched `origin/main` immediately before writing this report and again immediately
> before opening its PR (per the DEBT-014 process lesson). `main` was then unchanged at `993b390` — the same
> tip audited by `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-15.md` (PR #1402, still open) — so the content
> audit below covers the same `574d265..993b390` window (104 files / 11 first-parent merges / ~12.5k
> insertions: CHAOS-65 OCSP revocation checking, the MCP "read-first"/"First Canary exact scope"
> classification work, and the rate-limit exempt-CIDR sharding) rather than a new one. Four focused
> cross-surface audits were run in parallel (auth/identity/session/credential; policy/traffic-filtering/
> SSL-inspection; cluster/HA/MCP/release/support-bundle infrastructure; and a targeted pass over the
> three new feature areas in the diff window above) against code, REST API, the legacy and new GUIs,
> CLI/config, docs, metrics, and audit events, cross-checked against `docs/design/PRODUCT-TERMINOLOGY.md`
> and the existing 30+ prior dated reports before anything was written up as new.

---

## Executive Summary

**One genuinely new, small finding — found and fixed this pass — plus a re-confirmed process escalation
that this report elevates directly to the repository owner rather than filing as a fourth quiet "please
merge" request.**

1. **T-57 (new, fixed this pass): the Support panel's own create-bundle controls didn't say "support
   bundle."** The legacy GUI's create-bundle button tooltip, its confirmation dialog, and the Support
   nav's own subtitle all said **"diagnostic bundle"** — a phrase that appears nowhere in the API
   (`/api/support/bundles`), the operator docs, `docs/design/PRODUCT-TERMINOLOGY.md`, or the new React
   frontend, all of which say **"support bundle"** throughout. The confirmation dialog was the sharpest
   case: its own title already read "Create support bundle?" one line above body text that switched to
   "A redacted diagnostic bundle ... will be collected." The file already had the correct fix pattern
   sitting one panel away — `static/index.html:5189`'s existing hint text reads "Diagnostic support
   bundles are redacted at source," using "diagnostic" as a modifier on the canonical noun rather than
   as a replacement for it. Fixed by aligning all three outlier strings to that existing phrasing
   (`static/index.html:5184,6119,16205`) — a wording-only change, no test pinned the old strings, no
   API/schema/audit-event surface touched.
2. **Content audit of the `574d265..993b390` window found no other new drift.** OCSP revocation
   checking (CHAOS-65) uses identical vocabulary (`path_checked`, `responder_blocked`,
   `not_for_certificate`, coverage row names) across `ocsp_metrics.go`, `/api/ocsp`, the GUI panel, the
   generated frontend types, and `docs/operator/ocsp-revocation-checking.md`. The MCP "read-first"/
   "First Canary"/"exact scope"/"reviewed operation" vocabulary introduced across ~13 files and a
   611-line operator-doc expansion stays internally consistent, and "canary" is not overloaded against
   the pre-existing `update_cluster.go` staged-rollout sense (which `release_alerts.go` explicitly
   documents avoiding). The new `rlExemptView` (rate-limit exempt-CIDR sharding) does not collide with
   the pre-existing `ipFilterView` — distinct types, no shared doc/GUI surface. The auth/identity and
   policy/traffic-filtering domains were independently re-swept end to end (not just diffed) and turned
   up nothing beyond the two already-tracked carry-over items (T-11, T-13) described below.
3. **Process finding, re-confirmed rather than re-discovered: DEBT-014 (documentation-governance PR
   backlog) is still unresolved, one day after the routine's own prior pass diagnosed it in detail.**
   `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-15.md` (PR #1402) read the actual review threads — not just
   `mergeable_state`/CI — on every open `docs(governance)` PR and correctly found **#1372 and #1373
   genuinely merge-ready** (every review thread resolved, verified follow-up commits, disjoint files)
   while **#1380 and #1395 are correctly held** (their own review threads dispute the accuracy of the
   content they add). This pass re-verified that split against the live PR list rather than trusting
   yesterday's report: `main` has not moved, and none of #1372, #1373, #1380, #1395, or #1402 itself has
   received a new commit or been merged in the interim. The two merge-ready PRs have now sat correctly
   identified as ready for **4 days**, and the PR that identified them has sat unactioned for a day on
   top of that. Filing a fifth "no new content, please merge #1372/#1373" PR into the same queue would
   reproduce the exact failure mode DEBT-014 already names, so this pass instead (a) shipped a real,
   independently-useful fix (T-57 above) rather than a pure report, (b) appended a dated status update
   to the DEBT-014 entry itself rather than restating it, and (c) surfaces the recommendation directly to
   the repository owner outside the PR queue. **Recommended action: merge #1372 and #1373 now** (they
   are independent of each other and of this PR); leave #1380 and #1395 open until their disputed
   content is corrected.

**Terminology Health Score: 8.7 / 10** (unchanged). One small, genuinely new GUI-copy inconsistency was
found and fixed; the thirteen-entry `main`-backlog is unchanged; the score is not lowered for the
process-backlog finding, consistent with 2026-09-05's and 2026-09-15's reasoning (it reflects the state
of documentation *content*, and the fixes for the still-open PRs already exist and are already correct —
what's missing is a merge, not more auditing).

---

## Findings

### T-57 — Support panel create-bundle controls said "diagnostic bundle" instead of "support bundle" (new — fixed this pass)

- **Business concept:** the exportable, redacted diagnostic artifact Culvert generates for support/TAC
  (`csb/1` format, `internal/support`, `/api/support/bundles`).
- **Current names before this fix:** canonical everywhere else — "Support Bundle" / "support bundle" —
  in `docs/support/SUPPORT-BUNDLE-SPEC.md`, `docs/adr/0028-supportability-framework-collector-model.md`,
  `ui_support.go`, the generated `frontend/src/api/types.gen.ts` (`"Create support bundle"`, `"Get
  support bundle"`), the new frontend's `HistoryPage.tsx`, `static/index.html:16204,16700` (dialog
  titles "Create support bundle?"/"Delete support bundle?") and `static/index.html:5262` ("Support-bundle
  store health"). Three outliers in the same file used **"diagnostic bundle"** instead:
  `static/index.html:5184` (the primary "＋ Create bundle" button's own tooltip: *"Collect a redacted
  diagnostic bundle for support"*), `static/index.html:6119` (the Support nav's subtitle: *"Collect
  redacted diagnostic bundles and review the collector inventory"*), and `static/index.html:16205` (the
  create-confirmation dialog body: *"A redacted diagnostic bundle (scope: ...) will be collected..."* —
  directly beneath a dialog **title** that already said "Create support bundle?").
- **Why the current naming was problematic:** this is the one GUI surface where an admin actually
  triggers artifact creation, and its own tooltip and confirmation dialog avoided the product's own noun
  in favor of a phrase that appears in no API response, no doc, and no other GUI string — including,
  in the dialog case, the very title one line above it. An admin who reads the tooltip before clicking
  could reasonably wonder whether "diagnostic bundle" is a different artifact from the "support bundle"
  named everywhere else (the same panel also hosts a genuinely separate feature, the no-input
  `diagnoseAll`/`diagnoseSupport` local checks, which do produce a "diagnostic" verdict — the ambiguity
  had a plausible neighboring concept to be confused with).
- **Why the new name is better:** removes an orphaned synonym with zero net renaming — the fix reuses a
  compound phrasing ("diagnostic support bundle") that was already established one panel away
  (`static/index.html:5189`: *"Diagnostic support bundles are redacted at source"*), so "diagnostic" is
  kept as an accurate descriptive modifier while the canonical noun "support bundle" is restored as the
  head of the phrase everywhere in this file.
- **Affected code:** `static/index.html` (3 lines: `5184`, `6119`, `16205`).
- **Affected API:** none — no field, endpoint, or schema name involved.
- **Affected GUI:** the legacy Support panel's create-bundle button tooltip, nav subtitle, and
  confirmation dialog body. The new React frontend was already consistent and needed no change.
- **Affected Documentation:** none.
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (three strings, no compat surface, no test pinned the old wording —
  confirmed by grepping every `*_test.go` for the changed phrases before editing).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Low (cosmetic, single-panel, no cross-surface or API ambiguity — consistent with this
  program's prior "Low" tier for panel-copy alignment fixes, e.g. 2026-09-09's Access Rules/Authentication
  Rules panel-title fix).

---

## Process Finding — DEBT-014 recurrence, re-confirmed (not re-discovered)

See the Executive Summary above and the dated update appended to
`docs/engineering/TECHNICAL-DEBT-REGISTER.md`'s DEBT-014 entry (2026-09-16) for the full detail. In
short: PR #1402 (2026-09-15) already did the correct per-PR triage this entry has asked for since
2026-09-05 — reading actual review threads rather than trusting `mergeable_state` — and found #1372/
#1373 genuinely ready and #1380/#1395 correctly held. Nothing has changed since: `main` is at the same
tip, and none of the five open governance PRs (#1372, #1373, #1380, #1395, #1402) has moved. This report
does not re-derive that triage; it re-verifies the PR list is unchanged and escalates the same
recommendation directly rather than adding a sixth open PR asking for the same thing.

---

## Carried-Over Findings (unchanged)

All fourteen previously-open finding IDs (thirteen backlog entries, T-21 and T-32 tracked as one paired
item) remain open, unchanged, and re-confirmed against the current tree: T-9, T-11, T-12, T-13
(residual), T-17, T-18, T-21+T-32 (paired), T-25 (residual), T-29, T-30, T-33, T-34, T-39. Full
descriptions and the priority-ordered refactoring plan are unchanged from
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md` (the last report to restate them in full) and are not
repeated here to avoid two descriptions of the same open items drifting apart.

Two of these (T-11: `PolicyAction` enum vs. the two-value `allow`/`deny` default-action vocabulary; T-13:
"SSL Inspection" vs. "TLS Inspection" branding) were independently re-verified against fresh `grep`
output during this pass's auth/policy sweep, not merely assumed unchanged.

**Not yet part of the `main` backlog** (exist only inside still-open PRs, per 2026-09-15's report, and
should be folded into the canonical list once their PRs merge): T-54 (OCSP metric-name mismatches,
#1372 — resolved in-PR, ready to merge), T-55 and T-56 (Policy Learning wording split and PAC "steering
profile" gap, #1380 — held pending a follow-up fix per its own open review threads).

The "Content & Scanning" vs. "Content Security" soft finding (a design-document reconciliation between
two deliberate naming decisions, not a mechanical rename) also remains unresolved and is not queued to
the numbered backlog, per 2026-09-09's reasoning.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent, but the gap found this pass was small: one genuinely new,
low-priority GUI-copy inconsistency (T-57), found and fixed with zero compatibility risk. The
`574d265..993b390` diff window's three new feature areas (OCSP revocation checking, MCP "read-first"/
First-Canary classification, rate-limit exempt-CIDR sharding) were audited end to end and show
disciplined, internally consistent naming — no new backlog item warranted. The fourteen-ID `main`
carry-over backlog is unchanged. No cosmetic or preference-driven renames were proposed, and none of the
larger carry-over items (T-11, T-12, T-17, T-18, T-21+T-32, T-29, T-30, T-39) were force-fixed without
the naming decision or migration-cost review their own entries already call for.

The one process item — DEBT-014's continued recurrence — is, per its own 2026-09-05 and 2026-09-15
conclusions, a merge/triage action item for the repository owner and not something a further automated
pass can resolve by writing another report; this pass's contribution is a real fix (T-57) plus a direct
escalation, deliberately choosing not to add a sixth unmerged "please merge" PR to the pile it is
reporting on.
