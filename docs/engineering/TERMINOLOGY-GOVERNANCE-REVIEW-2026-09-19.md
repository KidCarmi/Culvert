# Culvert Language & Terminology Governance Review — 2026-09-19

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Snapshot scope (read this first):** this is a HISTORICAL record of `origin/main` at `36628eb` on
> 2026-09-19. It was merged later, after `main` had moved on, so the tree it ships in contains commits it
> never audited. It is not a statement about the tree this file is published in; later windows are
> audited by later reports, never retroactively by this one. Exactly which state each claim describes
> (the convention of the 2026-09-16 report):
> - **Findings** (T-58 and every carried-over ID) describe the **audited snapshot `36628eb`**, before
>   this PR's correction. Line numbers cited for T-58 are `36628eb` line numbers.
> - **Backlog** and **health score** are each stated twice, for two states: (a) the **audited snapshot**
>   (`36628eb`, T-58 still open) and (b) **after this PR's correction** (`36628eb` plus this PR's T-58
>   fix, nothing else). Neither figure is a statement about the merged tree.
> **Coverage limits:** the sweeps matched **literal patterns only** (the exact strings named in each
> finding; the SSL/TLS re-check searched for the literal tokens `SSL` and `TLS`) — a synonym or paraphrase
> that no pattern named is not claimed absent. CI workflow and script output was counted only where a
> `docs/operator/` runbook sends the reader to it; other workflow/script output was not audited. Every
> carried-over count below is reproducible from the commands in "Reproduction commands".
> **Finding-ID note:** this report's finding was first published as "T-54". Series IDs are assigned
> in report-date order, and T-54 belongs to the 2026-09-12 report (T-55/T-56 to 2026-09-13, T-57 to
> 2026-09-16, all now merged), so it is renumbered **T-58** here. IDs are never renumbered after that.
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
out of scope here), or the T-13 residual's larger question. The legacy GUI's policy-rule editor says
"SSL" for this mechanism ("SSL Action", "Inspect (MITM / SSL decryption)", `static/index.html:3162,3165`)
and uses "TLS" there only for the protocol itself ("Skip TLS Verify", the TLS fingerprint note). The
legacy GUI as a whole is NOT uniform: 19 lines say "SSL inspect…", but the Decryption Coverage panel
says "How much of this node's TLS is actually being inspected" (`static/index.html:3873`) and a
request-log badge tooltip says "TLS decryption handshake failed" (`:8483`). That split is part of the
same repo-wide question the T-13 residual tracks.

Two more standalone "SSL" mentions were found nearby during this pass (`DecryptionProfilesPage.tsx:2,160`
comment/subtitle prose, and `pacShared.tsx:19`'s PAC-bypass explainer) and one on the disabled-by-default
component gallery page (`GalleryPage.tsx:216`, a demo `<Switch>` with no real API binding). `pacShared.tsx`
and `GalleryPage.tsx` contain no other SSL or TLS wording, so their mentions are isolated;
`DecryptionProfilesPage.tsx` is not (see "Observed, not fixed" below). All are recorded here as
**observed but not fixed**, and are exactly the shape of question T-13's
residual already covers (a repo-wide SSL-vs-TLS branding decision, not a mechanical same-screen fix). They
are not added as a new backlog item; they are noted so a future pass doesn't re-discover them as if new.

**Terminology Health Score — audited snapshot `36628eb`: 8.2 / 10; after this PR's correction:
8.3 / 10.**

- **Scoring rule** (the rule the 2026-09-16 report states, applied unchanged): starting from the latest
  score recorded on merged `main`, each open backlog item a report newly records costs 0.1 and each item
  it closes restores 0.1. An item already charged by an earlier merged report is never charged again,
  and process findings do not move the score.
- **Baseline: 8.3**, the 2026-09-16 report's figure for a tree in which T-57 is still open. That is the
  right baseline for `36628eb`, because the T-57 fix (#1407) merged after this snapshot: the
  2026-09-16 report's 8.4 describes a tree with T-57 fixed, which `36628eb` is not. Its 8.3 already
  charges T-54 (2026-09-12), T-55, T-56 and the reopened T-51 residual (2026-09-13) and T-57
  (2026-09-16); none of them is charged again here.
- **Audited snapshot:** T-58 is new and open → 8.3 − 0.1 = **8.2**.
- **After this PR's correction:** this PR fixes T-58 → 8.2 + 0.1 = **8.3**. T-57 is still open in
  that state (this PR does not touch it).
- **Consistency with the merged series (not a claim about the merged tree):** the merged tree carries
  both the T-57 fix (#1407) and this PR's T-58 fix, so applying the same rule to it gives
  8.4 − 0.1 + 0.1 = 8.4, the 2026-09-16 report's post-correction figure, unchanged.
- **Disclosed, not amended:** the 2026-09-13 report measured its drop from 8.7 rather than from the
  2026-09-12 report's 8.6, so T-54's 0.1 charge was not carried into its 8.4. As the 2026-09-16 report
  did, this report does not retroactively amend a merged report's score; it takes the merged figures as
  recorded and does not charge T-54 a second time.

(An earlier draft of this report said "8.8, up from 8.7" and a thirteen-entry backlog. That was computed
before the 2026-09-12, 2026-09-13 and 2026-09-16 reports had merged and ignored the findings they had
already recorded against the audited window; corrected here.)

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

### Observed, not fixed — other in-app "SSL" mentions near the T-58 fix

Recorded so a future pass recognizes these rather than re-discovering them:

- `frontend/src/features/objects/DecryptionProfilesPage.tsx:2` (comment) and `:160` (a `subtitle` prop) —
  "SSL-inspected traffic" / "How SSL-inspected tunnels are decrypted."
- `frontend/src/features/network/pac/pacShared.tsx:19` — a PAC `DIRECT`-bypass explainer: "matching
  traffic skips SSL inspection, content scanning (ClamAV/YARA/DPI), CDR, ...".
- `frontend/src/features/gallery/GalleryPage.tsx:216` — a component-gallery demo `<Switch label="SSL
  inspection" defaultChecked />` with no backing API call (a design-system showcase page, not a real
  settings surface).

These, plus `RuleEditor.tsx:437,508`, are every user-visible "SSL" string under `frontend/src` at
`36628eb` outside tests and `api/types.gen.ts` (`git grep -n SSL 36628eb -- frontend/src ':!*.test.*'
':!frontend/src/api/types.gen.ts'`, ignoring the `sslAction`/`SSL_ACTIONS` identifiers).

`pacShared.tsx:19` and `GalleryPage.tsx:216` are the only SSL/TLS wording in their files.
`DecryptionProfilesPage.tsx` is different, and an earlier draft of this report wrongly called it
"internally consistent": most of its "TLS" strings name the protocol (TLS 1.2/1.3, "Minimum TLS version",
"origin TLS cannot be inspected"), but `:64` labels the inherit option "Inherit (rule's TLS setting)",
calling the rule's inspection setting "TLS" on the same page whose subtitle (`:160`) says
"SSL-inspected". That is a same-page mix of the kind T-58 fixed. This report does not assign it an ID or
charge it to the score; it is flagged here so the next pass can decide whether to number it. Folding them into "TLS" would be the same repo-wide branding
call T-13's residual already tracks as an open, deliberately-deferred Low-priority item (the in-app
"SSL" vs. doc-branding "TLS Inspection" question), not a new, independent finding. Not queued as a new
backlog entry; carried here as context for T-13's residual instead.

---

## Reconciliation with the 2026-09-12, 2026-09-13 and 2026-09-16 reports

Four reports in this series cover overlapping windows (every start commit below is an ancestor of
`36628eb`; `git merge-base --is-ancestor` confirms each):

| Report | Audited window | Findings recorded |
| --- | --- | --- |
| 2026-09-12 (#1372, merged) | `d378dff..2833db3` | T-54 (new) |
| 2026-09-13 (#1380, merged) | `2833db3..993b390`, plus a scope extension to the new frontend's PAC and Policy Learning screens | T-55, T-56 (new); T-51 residual (reopened) |
| 2026-09-16 (#1407, merged) | `574d265..993b390`, plus four domain sweeps | T-57 (new; fixed by #1407 after this snapshot) |
| 2026-09-19 (this report) | `574d265..36628eb` (a superset of all three windows above; `993b390..36628eb` adds 4 first-parent merges: three MCP First-Canary merges (#1378, #1422, #1423) and #1431, a policy benchmark-gate test change touching only `policy_srcprefix_benchgate_test.go`) | T-58 (new) |

This report's sweeps were the targeted re-checks listed under Method; they did not re-derive T-54,
T-55, T-56, T-57 or the T-51 residual, and did not re-audit the OCSP admin JSON, the new frontend's PAC
or Policy Learning screens, or the legacy Support panel. Its "no new drift" statements below are
therefore limited to what it examined and do not contradict those findings. Each was instead checked
directly at `36628eb` with the reproduction commands below, and all five are still present there, so
all are carried. IDs are never renumbered.

---

## Carried-Over Findings

Every ID below was open at the audited snapshot `36628eb`. None is fixed by this PR, so each is also
open after this PR's correction. Full descriptions live in the report that owns each ID and are not
restated here, to avoid two descriptions of one item drifting apart:

- T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21+T-32 (paired), T-25 (residual), T-29, T-30, T-33,
  T-34, T-39 — owned by `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md` (the last report to restate them
  in full), re-confirmed against `36628eb`.
- **T-54** — owned by `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-12.md`. Present at `36628eb`: the Go
  accessor is still `UnknownTotal()` while its label is `unknown_status`, the admin JSON fields are still
  `malformedResponseTotal`/`staleResponseTotal`, and `responder_blocked` is still a `reason` of
  `culvert_ocsp_response_rejected_total`.
- **T-55** — owned by `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-13.md`. Present at `36628eb`: the legacy GUI
  says "Accept to Draft" and the new frontend says "Accept to Policy Draft".
- **T-56** — owned by the 2026-09-13 report (doc half fixed there; code half open). Present at
  `36628eb`: no file under `frontend/src/features/network/pac/` contains "steering profile".
- **T-51 (residual)** — owned by the 2026-09-13 report. Present at `36628eb`: "appliance" still occurs
  (comments included) in 12 non-test files under the new frontend's PAC and Policy Learning feature
  directories.
- **T-57** — owned by `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-16.md`. Present at `36628eb`: its fix
  (#1407) merged after this snapshot, and `static/index.html:5184,6119,16205` still say "diagnostic
  bundle". It is carried as open for both states below.

**Backlog count:**

| State | Open IDs | Backlog entries (T-21+T-32 counted once) |
| --- | --- | --- |
| 2026-09-16 report, T-57 still open (its audited snapshot) | 19 | 18 |
| Audited snapshot `36628eb` (adds T-58) | 20 | 19 |
| After this PR's correction (T-58 fixed; T-57 still open) | 19 | 18 |

For comparison only (not a claim about the merged tree): once #1407's T-57 fix and this PR are both
applied, the count is the 2026-09-16 report's post-correction 18 IDs / 17 entries.

### Reproduction commands

Run from any clone that has fetched `36628eb` (`git grep -c` prints one `path:count` line per matching
file):

```sh
R=36628eb
# T-58 (audited snapshot): expect RuleEditor.tsx:437 and :508
git grep -n -e 'SSL action' -e 'SSL Inspect)' $R -- frontend/src/features/policy/RuleEditor.tsx
# T-58 (after this PR's correction; run on this PR's branch): expect no output
git grep -n -e 'SSL action' -e 'SSL Inspect)' HEAD -- frontend/src/features/policy/RuleEditor.tsx
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
```

The "Content & Scanning" vs. "Content Security" soft finding (design-document reconciliation between two
deliberate naming decisions, not a mechanical rename) also remains unresolved and is not queued to the
numbered backlog, per 2026-09-09's reasoning.

---

## Recommended Refactoring Plan (priority order)

Unchanged for the still-open carry-over items: see `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md` for
T-9 through T-39 and `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-13.md` for T-54, T-55, T-56 and the T-51
residual. T-57 is closed by #1407 (after this snapshot) and T-58 by this PR, so neither appears on the
plan.

| Priority | Item | Business impact if left unfixed | Compatibility risk | Est. size |
|---|---|---|---|---|
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" — now with the other in-app "SSL" mentions, the legacy GUI's own SSL/TLS split and the `DecryptionProfilesPage.tsx` same-page mix noted above as context | Low | Small |

The rest of the carry-over plan (T-9, T-11, T-12, T-17, T-18, T-21+T-32, T-25, T-29, T-30, T-33, T-34,
T-39; T-54, T-55, T-56, T-51 residual) is unchanged from the reports named above; see them for the full
tables.

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
first-parent merges; `git log --first-parent 574d265..36628eb`) was dominated by the MCP First-Canary
work — five merges (#1362, #1370, #1378, #1422, #1423) carrying most of the window's insertions. The other
ten are: #1363 (a correction to the 2026-09-11 governance report), #1364 (`trust_forwarded_headers`
documentation), #1365 (oversize-username login rejections in the legacy GUI), #1366 (the
`docker-compose.yml` YARA-directory doc fix), #1367 (SOCKS5/plugin log sanitisation), #1368 (rate-limit
exempt-view sharding), #1369 (CHAOS-65 OCSP/SSRF), #1371 (a GeoIP diagnostics fix), #1374 (a CDR
flag-merge fix) and #1431 (a policy benchmark-gate test). Within the targeted re-checks this pass ran, it found no
new drift, and it changed no admin-facing rule-editing copy at all; the same window also contains the
drift the 2026-09-12, 2026-09-13 and 2026-09-16 reports recorded (T-54, T-55, T-56, T-51 residual, T-57),
which this pass did not re-derive and which is carried above. The one finding, small and zero-compatibility-risk, is PRE-EXISTING: the
targeted SSL/TLS re-check of the `36628eb` snapshot found it, and `RuleEditor.tsx` is identical at both
ends of the window. It was fixed in this pass: `RuleEditor.tsx`'s two outlier "SSL" labels — one inside
its "TLS / Decryption" fieldset, one in its separate "Logging" fieldset — now read "TLS," matching that
first fieldset's own legend, the file's own surrounding comments, and the enumerated TLS-using
decryption surfaces of the new frontend (not every page — see "Observed, not fixed") — with zero effect on the wire API, the legacy GUI, or the
separately-tracked, deliberately-deferred T-13 branding residual. No cosmetic or preference-driven
renames were proposed. The backlog is twenty IDs (nineteen entries, T-21+T-32 paired) at the audited
snapshot, including T-58, and nineteen IDs (eighteen entries) after this PR's correction; each carried
ID was re-confirmed at `36628eb`, not merely assumed unchanged.
