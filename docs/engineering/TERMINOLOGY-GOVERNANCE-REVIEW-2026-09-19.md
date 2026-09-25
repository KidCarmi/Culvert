# Culvert Language & Terminology Governance Review — 2026-09-19

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Snapshot scope (read this first):** this is a HISTORICAL record of `origin/main` at `36628eb` on
> 2026-09-19. It was merged later, after `main` had moved on, so the tree it ships in contains commits it
> never audited. Its findings, carried-over backlog and health score describe `36628eb` only. They are
> not a statement about the tree this file is published in; the current governance state is whatever the
> most recent review in this series says. Later windows are audited by later reports, never
> retroactively by this one.
> **Finding-ID note:** this report's finding was first published as "T-54". Series IDs are assigned
> in report-date order, and T-54 belongs to the 2026-09-12 report, so it is renumbered **T-58** here.
> **Method:** Audited `574d265..36628eb` — the window since the previous report's audited snapshot
> (`574d265`, the `origin/main` endpoint the 2026-09-11 report names; that report itself merged later, in `0665453`).
> The end commit `36628eb` was confirmed as the then-current `origin/main` HEAD by a fetch immediately before this report was written on 2026-09-19 (the
> DEBT-014 lesson: sync against `main` right before opening a PR, not only at review-start). Targeted
> re-checks of the seven previously-declared-clean categories (SSL/TLS naming, blocklist/blacklist
> cleanup, allowlist/exempt/bypass vocabulary, upstream/parent-proxy naming, node/CP/DP naming, category
> naming, GUI panel-title-vs-nav mismatches) plus the standing carry-over backlog, rather than a full
> re-derivation of `docs/design/PRODUCT-TERMINOLOGY.md` from scratch.

---

## Executive Summary

**One small, real finding, new to the backlog — fixed this pass.** It is PRE-EXISTING, not
introduced in the audited window: `RuleEditor.tsx` is identical at `574d265` and `36628eb`, and the window
changed no rule-editing copy. The targeted SSL/TLS re-check of the `36628eb` snapshot found it. The new
admin frontend's Rule Editor
(`frontend/src/features/policy/RuleEditor.tsx`) named its own "TLS / Decryption" fieldset legend
correctly but used "SSL action" for the control inside that fieldset, and — in a separate "Logging"
fieldset further down the same dialog — described the same mechanism as "SSL Inspect." (Corrected from
this report's first draft, which mischaracterized both strings as controls of the same fieldset; a
reviewer caught it — see the Process Note below. The two labels are in different fieldsets of the same
Rule Editor dialog, which is the correct, narrower framing.) It is still a same-dialog self-contradiction
of the kind `docs/design/PRODUCT-TERMINOLOGY.md`'s "Inspection" row already warns about ("SSL inspection
acceptable; be consistent per screen") and the same defect class T-13 fixed once before in
`static/index.html` (2026-07-19). This is a narrower issue than T-13's still-open
residual (whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" — a
larger, deliberately deferred branding call): here the fix required no branding decision at all, because
the component already disagreed with **itself** — its "TLS / Decryption" fieldset's own legend, its own
inline comment (`RuleEditor.tsx:5`, "TLS/decryption controls"), and its own sibling help text ("inline TLS
toggles below," line 455) all said "TLS," and only the two visible labels (one in that fieldset, one in
the dialog's separate "Logging" fieldset) said "SSL." The decryption-specific surfaces enumerated
below (`DecryptionPage.tsx`, `AutoExclusionsTab.tsx`, `DestinationPrivacyTab.tsx`, `api/decryption.ts`,
`api/types.gen.ts`) also use TLS-based terminology ("TLS inspection", or "TLS-decryption" on
`DecryptionPage.tsx`) — but not every page does: `DecryptionProfilesPage.tsx`,
the PAC bypass explainer and the component gallery still say "SSL" (listed in the next paragraph). The two
outlier labels were changed to match — "TLS action" / "TLS Inspect" — bringing the component back into
agreement with itself and with those enumerated TLS-using surfaces, without touching the wire field name
(`sslAction` stays `sslAction`, per the API-stability rule below), the legacy GUI (`static/index.html`,
which consistently says "SSL" and is out of scope here), or the T-13 residual's larger question.

Two more standalone "SSL" mentions were found nearby during this pass (`DecryptionProfilesPage.tsx:2,160`
comment/subtitle prose, and `pacShared.tsx:19`'s PAC-bypass explainer) and one on the disabled-by-default
component gallery page (`GalleryPage.tsx:216`, a demo `<Switch>` with no real API binding). None of these
are self-contradictions the way `RuleEditor.tsx` was — each is an isolated, internally-consistent mention
— so they are recorded here as **observed but not fixed**, and are exactly the shape of question T-13's
residual already covers (a repo-wide SSL-vs-TLS branding decision, not a mechanical same-screen fix). They
are not added as a new backlog item; they are noted so a future pass doesn't re-discover them as if new.

**Terminology Health Score: 8.8 / 10** (up from 8.7 in the 2026-09-08/09/11 reports). The increment
reflects one genuinely new, verified, zero-risk fix with no compatibility surface (see Migration
Complexity below); it is not raised further because the carry-over backlog of thirteen entries (fourteen IDs) is otherwise
unchanged and the broader SSL-vs-TLS branding question (T-13 residual) remains open by deliberate choice.

---

## Findings

### T-58 — New admin frontend's Rule Editor disagreed with itself, across two fieldsets of the same dialog, about what to call the TLS-inspection mechanism (new to the backlog; pre-existing in code — fixed this pass)

- **Business concept:** the TLS-MITM decrypt/inspect action a policy rule applies to matching tunnels
  (`docs/design/PRODUCT-TERMINOLOGY.md`'s "Inspection" row: TLS MITM / "SSL inspect"; wire field
  `sslAction`, values `Inspect`/`Bypass`).
- **Current names before this fix**, all inside one component (`RuleEditor.tsx`), across two of its
  fieldsets — the "TLS / Decryption" fieldset (lines 434-481) and the separate "Logging" fieldset further
  down the same dialog (lines 498-514):
  - `frontend/src/features/policy/RuleEditor.tsx:435` — `<legend>TLS / Decryption</legend>`
  - `frontend/src/features/policy/RuleEditor.tsx:437` (before fix) — `label="SSL action"` — inside the
    "TLS / Decryption" fieldset itself.
  - `frontend/src/features/policy/RuleEditor.tsx:508` (before fix) — `label="Log the full request URI
    (HTTPS requires SSL Inspect)"` — inside the separate "Logging" fieldset, referring back to the same
    action the "TLS / Decryption" fieldset governs.
  - Contrast within the *same file*: `RuleEditor.tsx:5` (comment, "TLS/decryption controls") and
    `RuleEditor.tsx:455` (help text, "inline TLS toggles below," itself inside the "TLS / Decryption"
    fieldset) both already said "TLS."
  - Contrast with other surfaces of the *same frontend* (not all of them — see "Observed, not fixed"
    below for the ones that still say "SSL"): `DecryptionPage.tsx:40`, `AutoExclusionsTab.tsx:597`,
    `DestinationPrivacyTab.tsx:790,820`, `api/decryption.ts:8`, and `api/types.gen.ts:4339` use TLS-based
    terminology in prose ("TLS inspection" everywhere except `DecryptionPage.tsx:40`, which says
    "TLS-decryption coverage").
- **Recommended canonical name (for this fix's scope):** "TLS" — the "TLS / Decryption" fieldset's own
  legend, the file's own surrounding comments/help text, and the enumerated TLS-using surfaces above all
  already agreed on it; the two "SSL"-labeled controls were the outliers, not the legend.
- **Why the current naming was problematic:** an admin editing a policy rule would read a fieldset
  labeled "TLS / Decryption," configure an "SSL action" inside it, then scroll to an unrelated-looking
  "Logging" fieldset and be told that behavior needs "SSL Inspect" — three names (two of them "SSL," one
  "TLS") for one setting inside a single editing dialog, with no indication they are the same thing. The
  exact "be consistent per screen" violation the glossary's Inspection row calls out, reproduced in a
  newer surface than the one T-13 originally fixed.
- **Why the new name is better:** removes the in-component self-contradiction with a same-file, same-PR,
  zero-risk copy change; does not touch or attempt to resolve the larger, already-tracked, deliberately
  deferred T-13 residual (in-app "SSL" vs. doc-branding "TLS Inspection").
- **Affected Code:** `frontend/src/features/policy/RuleEditor.tsx` (2 lines, in two different fieldsets).
- **Affected API:** none — `sslAction` (the wire field name, `PolicyRule.SSLAction` in `policy.go:110`) is unchanged; this is
  display-copy only.
- **Affected GUI:** the Rule Editor dialog's "TLS / Decryption" fieldset (one label) and its separate
  "Logging" fieldset (one label); rebuilt `frontend/dist`
  (pinned toolchain Node v24.19.0/npm 11.17.0, matched exactly rather than approximated; `npm run verify`
  — 787 tests, lint, format, typecheck, license/vulnerability policy, generated-type and generated-dist
  drift gates — and an independent two-build determinism check (`sha256sum` over `dist/index.html`,
  `dist/manifest.json`, and every `dist/assets/*.{js,css}`, byte-identical across both builds) all passed
  before commit; re-confirmed against `origin/main` HEAD `36628eb` immediately before writing this report,
  per the DEBT-014 lesson, with no parallel branch found to have touched this file or a prior copy of this
  report in the interim).
- **Affected Documentation:** none.
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (two strings, no compat surface — the experimental new frontend ships
  disabled by default via `CULVERT_EXPERIMENTAL_UI`, and the changed labels carry no persisted state).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Medium (a real, visible same-screen contradiction in a rule-editing surface, confined to a
  disabled-by-default preview surface with no external consumers yet — same priority band as T-53).

### Observed, not fixed — isolated (non-contradictory) "SSL" mentions near the T-58 fix

Recorded so a future pass recognizes these rather than re-discovering them:

- `frontend/src/features/objects/DecryptionProfilesPage.tsx:2` (comment) and `:160` (a `subtitle` prop) —
  "SSL-inspected traffic" / "How SSL-inspected tunnels are decrypted."
- `frontend/src/features/network/pac/pacShared.tsx:19` — a PAC `DIRECT`-bypass explainer: "matching
  traffic skips SSL inspection, content scanning (ClamAV/YARA/DPI), CDR, ...".
- `frontend/src/features/gallery/GalleryPage.tsx:216` — a component-gallery demo `<Switch label="SSL
  inspection" defaultChecked />` with no backing API call (a design-system showcase page, not a real
  settings surface).

None of these contradict a sibling string in the same component the way `RuleEditor.tsx` did before this
fix — each reads consistently on its own. Folding them into "TLS" would be the same repo-wide branding
call T-13's residual already tracks as an open, deliberately-deferred Low-priority item (the in-app
"SSL" vs. doc-branding "TLS Inspection" question), not a new, independent finding. Not queued as a new
backlog entry; carried here as context for T-13's residual instead.

---

## Carried-Over Findings (unchanged)

All fourteen previously-open finding IDs (thirteen backlog entries, since T-21 and T-32 are tracked as one
paired item) remain open, unchanged, and re-confirmed against the then-current tree (`36628eb`):
T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21+T-32 (paired), T-25 (residual), T-29, T-30, T-33, T-34,
T-39. Full descriptions and the priority-ordered refactoring plan are unchanged from
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md` (and re-confirmed as unchanged by the 2026-09-11 report) and
are not restated here to avoid drift between two descriptions of the same open items.

The "Content & Scanning" vs. "Content Security" soft finding (design-document reconciliation between two
deliberate naming decisions, not a mechanical rename) also remains unresolved and is not queued to the
numbered backlog, per 2026-09-09's reasoning.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 2026-09-09/09-11 for the still-open carry-over items; T-58 is resolved in this pass and
does not appear on the plan.

| Priority | Item | Business impact if left unfixed | Compatibility risk | Est. size |
|---|---|---|---|---|
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" — now with three more observed (non-contradictory) in-app "SSL" mentions noted above as context | Low | Small |

The rest of the carry-over plan (T-9, T-11, T-12, T-17, T-18, T-21+T-32, T-25, T-29, T-30, T-33, T-34,
T-39) is unchanged from `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md`; see that report for the full table.

---

## Process Note — UI-hierarchy claim corrected after review

This report's first draft (as opened in the PR) described T-58 as one fieldset's two controls
disagreeing with the fieldset's own legend. `chatgpt-codex-connector`'s automated PR review correctly
flagged that only the "TLS action" control is inside the "TLS / Decryption" fieldset
(`RuleEditor.tsx:434-481`); the full-request-URI-logging checkbox that says "SSL Inspect" is in a
separate "Logging" fieldset starting at line 498. The underlying finding and fix (T-58 itself — two
outlier "SSL" labels relabeled to "TLS," no code beyond the two-string change) are unaffected: the
component still disagreed with itself, just across two of its fieldsets rather than within one. Verified
directly against the source (`RuleEditor.tsx:434-514`) before revising this report's every claim of
common fieldset scope to the more precise "same dialog, two fieldsets" framing. No code change was
needed — this is a documentation-accuracy correction only, applied in the same PR before merge rather
than left for a future review pass to catch.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. The ~8-day audited window (2026-09-11 → 2026-09-19, 15
first-parent merges) was dominated by the MCP-first-canary work plus a few CHAOS-series reliability fixes,
per `CLAUDE.md` and the PR titles in the window, and introduced no new drift; it changed no admin-facing
rule-editing copy at all. The one finding, small and zero-compatibility-risk, is PRE-EXISTING: the
targeted SSL/TLS re-check of the `36628eb` snapshot found it, and `RuleEditor.tsx` is identical at both
ends of the window. It was fixed in this pass: `RuleEditor.tsx`'s two outlier "SSL" labels — one inside
its "TLS / Decryption" fieldset, one in its separate "Logging" fieldset — now read "TLS," matching that
first fieldset's own legend, the file's own surrounding comments, and the enumerated TLS-using
decryption surfaces of the new frontend (not every page — see "Observed, not fixed") — with zero effect on the wire API, the legacy GUI, or the
separately-tracked, deliberately-deferred T-13 branding residual. No cosmetic or preference-driven
renames were proposed. All thirteen carry-over backlog entries (fourteen IDs, T-21+T-32 paired) are
unchanged and were re-confirmed, not merely assumed unchanged, against the then-current tree (`36628eb`).
