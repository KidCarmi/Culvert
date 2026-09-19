# Culvert Language & Terminology Governance Review — 2026-09-19

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `574d265..36628eb` — the window since the 2026-09-11 report's merge point,
> confirmed as the current `origin/main` HEAD by a fetch immediately before this report was written (the
> DEBT-014 lesson: sync against `main` right before opening a PR, not only at review-start). Targeted
> re-checks of the seven previously-declared-clean categories (SSL/TLS naming, blocklist/blacklist
> cleanup, allowlist/exempt/bypass vocabulary, upstream/parent-proxy naming, node/CP/DP naming, category
> naming, GUI panel-title-vs-nav mismatches) plus the standing carry-over backlog, rather than a full
> re-derivation of `docs/design/PRODUCT-TERMINOLOGY.md` from scratch.

---

## Executive Summary

**One new, small, real finding — fixed this pass.** The new admin frontend's Rule Editor
(`frontend/src/features/policy/RuleEditor.tsx`) named its own "TLS / Decryption" fieldset legend
correctly but labeled the two controls inside that same fieldset "SSL action" and "SSL Inspect" — a
same-screen self-contradiction of the kind `docs/design/PRODUCT-TERMINOLOGY.md`'s "Inspection" row
already warns about ("SSL inspection acceptable; be consistent per screen") and the same defect class
T-13 fixed once before in `static/index.html` (2026-07-19). This is a narrower issue than T-13's still-open
residual (whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" — a
larger, deliberately deferred branding call): here the fix required no branding decision at all, because
the component already disagreed with **itself** — its own fieldset legend, its own inline comment
(`RuleEditor.tsx:5`, "TLS/decryption controls"), and its own sibling help text ("inline TLS toggles
below," line 455) all said "TLS," and only the two visible labels said "SSL." Every other page in the same
frontend that discusses this feature in prose (`DecryptionPage.tsx`, `AutoExclusionsTab.tsx`,
`DestinationPrivacyTab.tsx`, `api/decryption.ts`, `api/types.gen.ts`) also says "TLS inspection." The two
outlier labels were changed to match — "TLS action" / "TLS Inspect" — bringing the component back into
agreement with itself and with the rest of the new frontend, without touching the wire field name
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
Complexity below); it is not raised further because the fourteen-item carry-over backlog is otherwise
unchanged and the broader SSL-vs-TLS branding question (T-13 residual) remains open by deliberate choice.

---

## Findings

### T-54 — New admin frontend's Rule Editor disagreed with its own "TLS / Decryption" fieldset about what to call the fieldset's own controls (new — fixed this pass)

- **Business concept:** the TLS-MITM decrypt/inspect action a policy rule applies to matching tunnels
  (`docs/design/PRODUCT-TERMINOLOGY.md`'s "Inspection" row: TLS MITM / "SSL inspect"; wire field
  `sslAction`, values `Inspect`/`Bypass`).
- **Current names before this fix**, all inside one `<fieldset>` in one component:
  - `frontend/src/features/policy/RuleEditor.tsx:435` — `<legend>TLS / Decryption</legend>`
  - `frontend/src/features/policy/RuleEditor.tsx:437` (before fix) — `label="SSL action"`
  - `frontend/src/features/policy/RuleEditor.tsx:508` (before fix) — `label="Log the full request URI
    (HTTPS requires SSL Inspect)"`
  - Contrast within the *same file*: `RuleEditor.tsx:5` (comment, "TLS/decryption controls") and
    `RuleEditor.tsx:455` (help text, "inline TLS toggles below") both already said "TLS."
  - Contrast within the *same frontend*: `DecryptionPage.tsx:40`, `AutoExclusionsTab.tsx:597`,
    `DestinationPrivacyTab.tsx:790,820`, `api/decryption.ts:8`, and `api/types.gen.ts:4339` all say "TLS
    inspection" in prose.
- **Recommended canonical name (for this fix's scope):** "TLS" — the fieldset's own legend, its own
  surrounding comments/help text, and the rest of the frontend's prose all already agreed on it; the two
  labels were the outliers, not the legend.
- **Why the current naming was problematic:** an admin editing a policy rule would read a section
  labeled "TLS / Decryption" and then be asked to configure an "SSL action" one line below, with no
  indication these are the same setting — the exact "be consistent per screen" violation the glossary's
  Inspection row calls out, reproduced in a newer surface than the one T-13 originally fixed.
- **Why the new name is better:** removes the in-component self-contradiction with a same-file, same-PR,
  zero-risk copy change; does not touch or attempt to resolve the larger, already-tracked, deliberately
  deferred T-13 residual (in-app "SSL" vs. doc-branding "TLS Inspection").
- **Affected Code:** `frontend/src/features/policy/RuleEditor.tsx` (2 lines).
- **Affected API:** none — `sslAction` (the wire field name, `ui_policy.go`) is unchanged; this is
  display-copy only.
- **Affected GUI:** the Rule Editor's "TLS / Decryption" fieldset (two labels); rebuilt `frontend/dist`
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

### Observed, not fixed — isolated (non-contradictory) "SSL" mentions near the T-54 fix

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
paired item) remain open, unchanged, and re-confirmed against the current tree:
T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21+T-32 (paired), T-25 (residual), T-29, T-30, T-33, T-34,
T-39. Full descriptions and the priority-ordered refactoring plan are unchanged from
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md` (and re-confirmed as unchanged by the 2026-09-11 report) and
are not restated here to avoid drift between two descriptions of the same open items.

The "Content & Scanning" vs. "Content Security" soft finding (design-document reconciliation between two
deliberate naming decisions, not a mechanical rename) also remains unresolved and is not queued to the
numbered backlog, per 2026-09-09's reasoning.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 2026-09-09/09-11 for the still-open carry-over items; T-54 is resolved in this pass and
does not appear on the plan.

| Priority | Item | Business impact if left unfixed | Compatibility risk | Est. size |
|---|---|---|---|---|
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" — now with three more observed (non-contradictory) in-app "SSL" mentions noted above as context | Low | Small |

The rest of the carry-over plan (T-9, T-11, T-12, T-17, T-18, T-21+T-32, T-25, T-29, T-30, T-33, T-34,
T-39) is unchanged from `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md`; see that report for the full table.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent, but this pass found only one small, genuinely new,
zero-compatibility-risk issue in a ~25-day, low-admin-facing-change window (the audited window was
dominated by the CHAOS-50–65 reliability/observability sweep and the MCP-first-canary work per `CLAUDE.md`
and the PR title at the window's tip, neither of which touch admin-facing rule-editing copy except for
this one instance). It was fixed in this pass: `RuleEditor.tsx`'s two outlier "SSL" labels now read "TLS,"
matching the fieldset's own legend, the file's own surrounding comments, and the rest of the new
frontend's established prose convention — with zero effect on the wire API, the legacy GUI, or the
separately-tracked, deliberately-deferred T-13 branding residual. No cosmetic or preference-driven
renames were proposed. All thirteen other carry-over backlog entries (fourteen IDs, T-21+T-32 paired) are
unchanged and were spot-checked, not merely assumed unchanged, against the post-sync tree.
