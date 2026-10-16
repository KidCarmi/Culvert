# Culvert Language & Terminology Governance Review — 2026-09-13

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Snapshot scope (read this first):** this is a HISTORICAL record of `origin/main` at `993b390` on
> 2026-09-13. It was merged later, after `main` had moved on, so the tree it ships in contains commits it
> never audited. Its findings, carried-over backlog and health score describe `993b390` only. They are
> not a statement about the tree this file is published in; the current governance state is whatever the
> most recent review in this series says. Later windows are audited by later reports, never
> retroactively by this one.
> **Method:** Audited `2833db3..993b390` — the window since the 2026-09-12 report's audited base,
> confirmed as the then-current `origin/main` HEAD by a `git fetch` immediately before this report was
> written on 2026-09-13 (per the DEBT-014 lesson recorded in the 2026-09-09 report: sync against `main` right before
> opening a PR). The window covers 2 first-parent merges / 9 files / ~281 insertions (PR #1371: a
> CDR `-cdr-server-fingerprint` CLI/YAML validation-parity fix, with a same-window Codex-review
> follow-up correcting the flag's own name in a log message and trimming whitespace before the
> CLI/YAML merge; PR #1374: a new `geo_resolution` operator-contract row surfacing the existing
> CHAOS-60 GeoIP warm-pool state on `GET /api/diagnostics`, with a same-window Codex-review
> follow-up dropping a false-positive comparison). Part A audits this window directly. **Part B is a
> scope extension**: this pass checks the new React admin frontend's (`frontend/src/**`, gated by
> `CULVERT_EXPERIMENTAL_UI`) **PAC and Policy Learning screens** against
> `docs/design/PRODUCT-TERMINOLOGY.md`'s already-established canonical vocabulary. The frontend as a
> whole is not new to this series — the 2026-08-22 report audited it when it first landed (PR #1194),
> and the 2026-08-29 report fixed an `AuthScreen.tsx` violation — but these two feature surfaces were
> added or reworked after those passes and had not been checked against the canon since; see Part B
> for the two genuine findings this surfaced.

---

## Program Note: two prior governance PRs are still open and unmerged; a third governance-adjacent PR is also open

`docs/engineering/TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-12.md` (T-54: the OCSP discarded-response
reason vocabulary) is not yet merged — it is **PR #1372**, `mergeable_state: clean`, reviewed and
corrected three times in place by `chatgpt-codex-connector` before this report was written, per its
own text. A separate, non-terminology governance PR, **#1373** ("docs: add missing CDR operator guide
+ publish documentation governance review"), is also open. Neither blocks this report: this pass's
audited window (`2833db3..993b390`) is defined against `origin/main`'s actual merged history, which
does not include #1372 or #1373's changes, so there is no risk of this report re-deriving their
content. Per the 2026-08-30 report's precedent, this is recorded as a process observation rather than
re-litigated: a terminology-governance report is only real to the next reviewer once it merges, and
`main`'s actual open count now stands at two unmerged reports from this program (2026-09-12 and this
one, once opened) plus one unmerged fix (T-54's code/API half, still queued rather than written, so
there is no PR for it yet). Recommend merging #1372 promptly — it is docs-only and has already passed
three rounds of automated review.

---

## Executive Summary

**Part A (the audited merge window): no new terminology drift.** Both PRs are correctness fixes, not
naming changes, and both are already internally self-consistent as merged:

- **PR #1371** (`cdr_startup_config.go`, `config.go`, `main.go`) closes a CLI/YAML validation-parity
  gap for the CDR server-fingerprint pin. Its own same-window Codex-review follow-up (`35b3c77`)
  caught and fixed a real naming defect **before** it reached `main`: the initial fix's `log.Fatalf`
  message and comments named a flag, `-cdr-fingerprint`, that has never existed (the registered flag
  is `-cdr-server-fingerprint`, `main.go:353`) — this is exactly the class of drift this program
  exists to catch, and it was caught and corrected inside the same PR, so it never became a
  merged-main defect for this report to find. Spot-checked directly: `config.go`'s
  `validCDRServerFingerprint` doc comment, `main.go`'s `initCDR` log message, and
  `main_config_precedence_test.go`'s test names and comments all now consistently say
  `-cdr-server-fingerprint`.
- **PR #1374** (`geoip_resolve_health.go`, `diagnostics.go`, `docs/operator/geoip-resolution-health.md`)
  adds a `geo_resolution` operator-contract row. Its naming is consistent with the sibling
  `checkDNSResolution()`/`dns_resolution` row it explicitly mirrors (`dns_health.go`), and with the
  existing `culvert_geo_*` metric family (CLAUDE.md's CHAOS-60 entry) it reports on — no new vocabulary
  was introduced. A same-window Codex-review follow-up (`3ca1ba6`) removed a false-positive warning
  condition; this is a correctness fix (the check would have latched `warn` on any node ever serving
  one geo-scoped request) with no naming dimension.

**Part B (scope extension): two new findings, one fixed on the spot, plus one reopened residual (T-51).** This program's methodology
notes (e.g. 2026-08-30: *"`static/index.html` is byte-unchanged in this window ... so there is no new
GUI copy to check"*) show that "check the GUI" has, in routine window passes, usually meant grepping
`static/index.html`. `frontend/src/**` is a second, independently-maintained GUI surface governed by
the exact same `docs/design/PRODUCT-TERMINOLOGY.md` canon; it was audited when it landed (2026-08-22)
and again partially on 2026-08-29 (`AuthScreen.tsx`), but its PAC (`features/network/pac/`) and Policy
Learning (`features/learning/`) screens have not been checked against the canon since. A direct audit
of those two surfaces against the canon found two
genuine, previously-undocumented mismatches (and, separately, a residual of the already-recorded
"Appliance: not used" rule, T-51 — listed after them) between the legacy GUI (canonical, per CLAUDE.md and
`PRODUCT-TERMINOLOGY.md`) and the new frontend:

- **T-55** (new): the Policy Learning "accept a recommendation into Policy Draft" action is labeled
  **"Accept to Draft"** in the legacy GUI (`static/index.html:7030,7044-7045`) — matching CLAUDE.md's
  own frozen spec text verbatim (*"GUI: 'Accept to Draft' ... house confirm stating 'Creates a
  disabled rule in Policy Draft...'"*) — but **"Accept to Policy Draft"** in the new frontend
  (`frontend/src/features/learning/LearningRecommendations.tsx:6,447,475,485`), for the identical
  admin-only action, the identical `policy_learning.accept` audit event, and the identical API call —
  wording the frontend's own design contract (`FRONTEND-FEATURE-PARITY.md` FE-V18,
  `FRONTEND-MIGRATION-PLAN.md:713-718`) also specifies, so this is a naming decision between two
  recorded contracts, not a mechanical fix.
- **T-56** (new): PAC's named traffic-steering ruleset is the **"steering profile"** in
  `docs/design/PRODUCT-TERMINOLOGY.md`'s canonical table (*"the fourth distinct 'Profile' concept ...
  always say 'steering profile,' never bare 'profile,' on this screen"*). The legacy GUI applies it in its
  titles and editor labels since T-50 (`static/index.html:2311-2312,2323,2347,2394`) but NOT in its panel
  description, which still says "Each profile" and "The **default** profile" (`:2316-2317`), nor in much
  of its script-rendered PAC copy — the DIRECT-inventory summary and empty state, both "Profile" table
  headers, "No custom profiles yet", "(profile pool)", the DIRECT-path confirmation, and the
  "Profile saved/deleted/validation failed", "Profile PAC URL copied" and "Delete profile?" toasts and
  dialogs (`static/index.html:14398,14408,14412,14496,14720,14761,14770,14908,14932,14937,14943,14951,15040`; an earlier draft of this report called the legacy labels T-50-compliant —
  found in review); the new
  frontend's PAC screens say bare **"PAC profile"** / **"profile"** throughout, with no "steering"
  qualifier anywhere — `frontend/src/features/network/pac/ProfilesTab.tsx:1,297,324,384`,
  `ProfileDetail.tsx:1`, `ProfileDraftEditor.tsx:1`, `PACPage.tsx:39`, and also user-facing copy in
  `ExceptionsTab.tsx:182,237,250,253`, `PoolsTab.tsx:173,196,236-237,266,381-382,406,410` and
  `pacShared.tsx:22` (an earlier draft of this report listed only the first four files — found in
  review). This is the exact defect class T-50 fixed in the
  legacy GUI, reintroduced independently in a surface T-50's own audit never covered — `docs/operator/
  pac-traffic-steering.md`, the operator runbook for this same feature, had the identical drift in its
  own prose (mixing a "## Steering profiles" heading with bare "a **profile** is..." sentences
  immediately under it) despite being written after T-50 shipped; **fixed in this pass** (doc-only,
  zero risk — see below).
- **T-51 (residual — reopened, not a new ID):** `PRODUCT-TERMINOLOGY.md:28` rules that "Appliance" is
  *not used* and UI copy says **node** or **instance**; T-51 (2026-08-29) fixed the leaks known then. At
  `993b390` both re-checked surfaces render "appliance" again in user-visible copy — e.g.
  `ProfileDetail.tsx:381,464,472-473,624,632,639`, `pacShared.tsx:22,55-56,93`,
  `LearningRecommendations.tsx:254,282` and `PolicyLearningPage.tsx:187,212,246,269,299,401,605` (full
  inventory in the finding below). An earlier draft of this report missed this rule entirely (found in
  review). Queued, not fixed here — it is frontend copy and needs a `frontend/dist` rebuild.

Both new findings are cosmetic (neither changes any API, JSON field, config key, or backend behavior —
both surfaces call the identical endpoints) but real: an admin, support engineer, or documentation
author moving between the legacy and new admin UIs — which coexist by design, per CLAUDE.md, with the
new one opt-in via `CULVERT_EXPERIMENTAL_UI` — sees two different names for the same object or action
depending on which UI build is active, with nothing telling them the two labels refer to one thing.

**Fixed this pass (doc-only, zero risk):** `docs/operator/pac-traffic-steering.md` now consistently
says "steering profile" throughout its prose (previously "a **profile**...", "Custom profiles...",
"the same profiles", "Each profile carries", "Profile PACs", "Profiles and pools", and ~40 further bare
uses across the lifecycle, simulator, and DIRECT-governance sections — code identifiers, API paths,
metric/alert names and file names are left as-is), plus its Part 2 heading, matching the already-canonical term this
same document's own heading already used, and now carries an explicit note recording the new
frontend's outstanding wording gap (T-56) so a reader of the runbook is not misled into thinking the
two UIs use consistent language today.

**Not fixed this pass, queued to the backlog:** the code/GUI-string halves of T-55 and T-56. Both are
naming decisions (see each finding), and what they cost depends on the direction chosen: a direction
that changes the new frontend needs a `frontend/src/**` edit plus a `frontend/dist` rebuild (the
committed, deterministic production bundle CLAUDE.md documents as the only frontend artifact embedded
into the binary); a direction that keeps the frontend's wording changes the legacy GUI and the
canonical docs instead and needs no rebuild. Either way it is more than a same-PR drive-by text edit,
so both are queued rather than decided here. This mirrors how this
program has always treated a rename that needs more than a documentation edit to land (see T-29/T-30/
T-12, and T-54's own code half in the still-open 2026-09-12 report).

**Process recommendation:** future passes of this routine should explicitly include `frontend/src/**`
in the standard "check the GUI" step alongside `static/index.html`, not only when a diff happens to
touch it. Both are live, user-facing surfaces governed by the same canonical terminology document, and
this pass shows feature screens added to the second one after its initial audit have accumulated at
least two real mismatches.

**Terminology Health Score: 8.4 / 10** (down from 8.7, the score last recorded on merged `main` by the
2026-09-11 report; the 2026-09-12 report proposes 8.6 but remains unmerged — see the Program Note).
The drop reflects two new, real, well-evidenced findings (T-55, T-56) and one reopened residual (T-51)
surfaced by extending this
program's own audit scope to a previously under-checked surface, not new drift introduced by the
window's two merged PRs (which introduced none). Both findings are Low-Medium priority, cosmetic-only,
and one is now partially fixed.

---

## Findings

### T-55 — Policy Learning's "Accept to Draft" action has a different label in the new admin frontend (new — a NAMING DECISION, not a mechanical fix; not fixed this pass)

- **Business concept:** the admin-only action that translates an accepted Policy Learning
  recommendation into a disabled rule in the shared Policy Draft (`policy_learning_accept.go`'s
  `plTranslateRecommendation`; audit event `policy_learning.accept`).
- **Current names:**
  - Legacy GUI (matches CLAUDE.md's M5B spec text): **"Accept to Draft"** — the
    button (`static/index.html:7030`), the confirm-dialog title and confirm-button label
    (`static/index.html:7044-7045`).
  - New frontend: **"Accept to Policy Draft"** — the button
    (`frontend/src/features/learning/LearningRecommendations.tsx:447`), the confirm-dialog title
    (`:475`) and confirm-button label (`:485`), and the file's own top-of-file comment, which asserts
    this exact wording is a deliberate choice (`:6`, *"Accept — 'Accept to Policy Draft' (never
    Apply/Enforce/Allow/Deploy)"*).
  - The new frontend's own design contract, at the audited snapshot, ALSO specifies **"Accept to Policy
    Draft"**: `docs/design/FRONTEND-FEATURE-PARITY.md:40` (row FE-V18) and
    `docs/design/FRONTEND-MIGRATION-PLAN.md:713-718` both name it and describe it as preserving the M5B
    contract. (An earlier draft of this report said nothing recorded a reason for the frontend wording;
    that was wrong — found in review.)
- **Why the current naming is problematic:** two recorded contracts disagree about one action —
  CLAUDE.md's M5B text and the legacy GUI say "Accept to Draft", while the frontend's design documents
  and implementation say "Accept to Policy Draft". The result: the identical button, calling the identical API with the
  identical audit event, reads differently depending on which of Culvert's two coexisting admin UIs an
  administrator or a support engineer happens to be looking at — exactly the kind of mismatch that
  makes a screenshot in one doc look wrong against the other UI, or makes a support script written
  against one UI's wording confusing when read against the other.
- **Recommended resolution:** decide ONE canonical label first, then change the losing side AND its
  written contract in the same change — never the implementation alone. Both options are defensible:
  "Accept to Draft" is shorter and is the CLAUDE.md/legacy wording; "Accept to Policy Draft" names the
  object explicitly and is what the frontend contract specifies. This report does not pre-decide it.
- **Affected code:** whichever UI loses — `frontend/src/features/learning/LearningRecommendations.tsx`
  (3 UI strings + 1 comment) or `static/index.html:7030,7044-7045`. These are the product strings, not an
  exhaustive change list: tests pin the current wording too (e.g.
  `frontend/src/test/policy-learning-page.test.tsx` matches "Accept to Policy Draft" in 12 places), so the
  implementing change must grep the losing wording across `frontend/src`, `static/`, the Go tests and
  `docs/`, and update every reference — including selectors that would otherwise silently stop matching.
- **Affected API:** none — no field, route, or payload shape changes.
- **Affected GUI:** the new frontend's Policy Learning recommendations screen (button label, confirm
  dialog title, confirm button label).
- **Affected Documentation:** the losing side's contract — either `docs/design/FRONTEND-FEATURE-PARITY.md`
  FE-V18 + `docs/design/FRONTEND-MIGRATION-PLAN.md:713-718`, or CLAUDE.md's M5B text and the operator guide
  (`docs/operator/policy-learning-mode.md:127`). Not exhaustive — see Migration Complexity.
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial in code either way (3 string literals). If the frontend's wording
  loses, add the `frontend/dist` rebuild + its verification (build, lint, the existing Playwright/Vitest
  Policy-Learning coverage); if the legacy wording loses, no rebuild is involved but the change is NOT
  confined to `static/index.html` and CLAUDE.md — the operator guide (`docs/operator/policy-learning-mode.md:127`)
  and a Go wording pin (`policy_learning_m5b_test.go:506-523`, `TestM5B_GUIDecisionWording`) carry it too.
  In EITHER direction the implementing change must grep the losing wording repo-wide (Go and frontend
  source and tests, `static/`, `docs/`, CLAUDE.md) and converge every reference; the files named in this
  finding are evidence, not the change list.
- **Compatibility Risk:** None — display-only text behind an experimental, disabled-by-default flag
  (`CULVERT_EXPERIMENTAL_UI`); no external consumer depends on the exact button string.
- **Estimated PR Size:** Small.
- **Priority:** Low — cosmetic, single-screen, no functional impact, but a real and easily-confirmed
  mismatch between Culvert's two coexisting admin UIs for the same action.

### T-56 — PAC's canonical "steering profile" term is missing entirely from the new admin frontend's PAC screens (new — doc half fixed this pass, code half queued)

- **Business concept:** the named PAC traffic-steering ruleset assigning client networks to proxy
  pools (`internal/pac`, `Profile` struct, `/api/pac/profiles`) — `docs/design/PRODUCT-TERMINOLOGY.md`'s
  own canonical table already names this **"steering profile"** and states the rule explicitly:
  *"the fourth distinct 'Profile' concept alongside file/decryption/CDR profiles — always say
  'steering profile,' never bare 'profile,' on this screen."*
- **Current names:**
  - Legacy GUI (T-50-compliant only in its static titles and editor labels): "Steering Profiles" (panel
    title, `static/index.html:2311`), "+ New Steering Profile" (`:2312`), "Steering Profile ID"
    (`:2323`), "Save Steering Profile" (`:2347`), "Steering Profile" (simulator dropdown label,
    `:2394`). Its panel description still says bare "Each profile" and "The **default** profile"
    (`:2316-2317`), and its script-rendered PAC copy says bare "profile" throughout: "profiles can emit
    DIRECT" (`:14398`), "No profile can emit DIRECT" (`:14408`), the "Profile" column headers
    (`:14412`, `:14496`), "No custom profiles yet" (`:14720`), "Profile PAC URL copied" (`:14761`),
    "(profile pool)" (`:14770`), "This profile introduces new DIRECT path(s)" (`:14908`), "Profile
    validation failed" / "Profile saved" (`:14932`, `:14937`), "Delete profile?" (`:14943`), "Profile
    deleted" (`:14951`) and "Profiles referencing it block deletion" (`:15040`). The legacy screen is
    therefore far from compliant; an earlier draft of this report listed only the description lines
    (found in review).
  - New frontend (`frontend/src/features/network/pac/`): bare **"PAC profile(s)"** / **"profile"**
    throughout, with the word "steering" appearing nowhere. Beyond the four files below, user-facing bare
    "profile" copy also appears in `ExceptionsTab.tsx:182,237,250,253`,
    `PoolsTab.tsx:173,196,236-237,266,381-382,406,410` and `pacShared.tsx:22` —
    `ProfilesTab.tsx:1` ("2F-E — PAC profiles: the listing..."), `:297` ("The PAC profiles could not be
    read."), `:324` ("PAC profiles" table caption), `:384` ("New PAC profile" dialog title);
    `ProfileDetail.tsx:1` ("2F-E — one PAC profile's lifecycle..."); `ProfileDraftEditor.tsx:1` ("2F-E
    — the node-local draft editor of one PAC profile..."); `PACPage.tsx:39` ("Per-site PAC profiles
    with a node-local draft → publish → history lifecycle...").
  - Operator runbook (`docs/operator/pac-traffic-steering.md`): had the identical bare-"profile" drift
    in its prose under its own "## Steering profiles" heading — **fixed in this pass**.
- **Why the current naming is problematic:** `PRODUCT-TERMINOLOGY.md`'s own stated reason for the
  qualifier still applies here word for word — "profile" alone is already claimed by three *other*
  legitimate Culvert concepts (file-block profile, decryption/CDR profile, IdP profile) documented in
  the same table, so a bare "profile" on a PAC screen is genuinely ambiguous to a reader who has seen
  Culvert's other profile types. The new frontend's own source comments consistently write "PAC
  profile" as if it were a settled, intentional term (not a shorthand slip in one place), which means
  this is a naming choice made independently during the React port rather than a copy-paste artifact —
  and it directly reintroduces the exact defect T-50 already spent a fix closing in the legacy GUI,
  in a surface that fix's own audit never reached.
- **Why the new name is better:** converging the new frontend on "steering profile" (or at minimum
  "PAC steering profile" on first mention per screen, matching the legacy GUI's pattern) removes the
  three-and-growing distinct "profile" concepts problem `PRODUCT-TERMINOLOGY.md` was written to solve,
  and restores the property that an admin moving between Culvert's two coexisting UIs sees the same
  vocabulary for the same object. Alternatively, if the product decision is that the new frontend's
  shorter "PAC profile" should become the going-forward canonical term instead (it is arguably no less
  clear, and CLAUDE.md's own file-structure notes already describe this frontend surface using "PAC
  profile" language) — that is a legitimate directional choice, but it is a **decision**, not a
  mechanical fix: it would mean updating `PRODUCT-TERMINOLOGY.md` itself, the legacy GUI (the five
  "Steering Profile" strings, re-touching T-50's fix, while its already-bare rendered copy could stay), and the operator runbook fixed in this same pass, which is why this report
  does not unilaterally pick a direction and instead records both options for whoever picks up the
  backlog item.
- **Affected code:** if the "steering profile" direction is chosen — every PAC file in
  `frontend/src/features/network/pac/` carrying bare "profile" copy (`ProfilesTab.tsx`, `ProfileDetail.tsx`,
  `ProfileDraftEditor.tsx`, `PACPage.tsx`, `ExceptionsTab.tsx`, `PoolsTab.tsx`, `pacShared.tsx`, and
  `pacLifecycle.ts:241`, whose bare-"profile" refusal sentence `ProfileDetail.tsx:519-520,932-934` shows
  verbatim) AND every rendered bare-"profile" string in the legacy PAC panel — the description at
  `static/index.html:2316-2317` plus `static/index.html:14398,14408,14412,14496,14720,14761,14770,14908,14932,14937,14943,14951,15040`; alternatively, if the "PAC profile" direction
  is chosen, `static/index.html` (the five titled strings) + `docs/design/PRODUCT-TERMINOLOGY.md` (1 row).
  Either list is the product copy only, not an exhaustive change list: frontend tests select controls by
  their current labels (e.g. `frontend/src/test/pac-2fe-c-red-page.test.tsx:441-445` "All profiles", and
  `pac-2fe-red-page.test.tsx:359-386` "New profile", where a renamed label would make a forbidden-control
  check silently stop matching). The implementing change must grep every changed label across source AND
  tests and keep each test's intent — especially negative assertions — rather than letting it pass
  vacuously.
- **Affected API:** none either way — `/api/pac/profiles` and the `Profile` JSON shape are unaffected.
- **Affected GUI:** the new frontend's PAC screens (or, under the alternative direction, the legacy
  GUI's PAC panel).
- **Affected Documentation:** `docs/operator/pac-traffic-steering.md` — **fixed in this pass**
  (prose now says "steering profile" consistently, plus a note recording the frontend gap); under the
  alternative ("PAC profile") direction, `docs/design/PRODUCT-TERMINOLOGY.md`'s Steering profile row would
  need updating AND this runbook's ~50 "steering profile" occurrences would have to be converged back, or the
  canonical term and the operator documentation would disagree. In either direction the implementing change
  must grep the losing term repo-wide (source, tests, GUI, docs) and converge every reference.
- **Affected Configuration:** none.
- **Migration Complexity:** Small in either direction (a batch of string/comment edits in roughly ten files plus their dependent tests);
  Small-Medium once the "steering profile" direction's required `frontend/dist` rebuild + verification
  is counted, or once the "PAC profile" direction's canonical-doc update + legacy-GUI re-edit is
  counted.
- **Compatibility Risk:** None — display-only text; no API, JSON, or config surface changes either way.
- **Estimated PR Size:** Small (doc fix, done) + Small (code direction, once decided).
- **Priority:** Low-Medium — cosmetic and single-feature-scoped, but it is the second occurrence of
  the exact defect class T-50 already fixed once, which is worth resolving before a third surface
  (a doc, a training deck, a support macro) independently invents a third spelling.

### T-51 (residual) — "Appliance" is rendered again in the new frontend's PAC and Policy Learning copy (reopened residual — queued, not fixed this pass)

- **Rule:** `docs/design/PRODUCT-TERMINOLOGY.md:28` — "**Appliance** | *Not used.* Culvert deploys as
  binary/container; the UI says **node** or **instance** | avoid inventing appliance language". T-51
  (2026-08-29 report) fixed the two leaks known then and is recorded there as fixed; this is a residual of
  the same rule in surfaces that pass did not re-check, so it reuses T-51 rather than minting a new ID.
- **Current rendered copy at `993b390`** (source comments excluded):
  - PAC (`frontend/src/features/network/pac/`): `ProfileDetail.tsx:381,464,472,473,624,632,639,648,657,
    667,669,673,727,883,884,968,972,979,1409,1458,1510,1540,1573,1603`, `pacShared.tsx:22,55,56,93`,
    `pacLifecycle.ts:239,241,333`, `ProfileDraftEditor.tsx:133,138,398`, `ProfilesTab.tsx:254`,
    `PoolsTab.tsx:406`, `LegacyPacTab.tsx:119`, `discardGuard.tsx:34` — e.g. "The appliance answered for
    operation …", "Outcome ambiguous on the appliance", "… live on this appliance only".
  - Policy Learning (`frontend/src/features/learning/`): `LearningRecommendations.tsx:254,282` and
    `PolicyLearningPage.tsx:187,212,246,269,299,401,605` — e.g. "The appliance refused the accept.",
    "… refused by the appliance.".
  - The line list is a grep of these two directories for "appliance" outside comments; a few hits may be
    non-rendered string literals, and the implementing change must re-grep rather than trust it.
- **Scope limit:** this pass re-checked only the PAC and Policy Learning screens; `frontend/src/features/**`
  contains "appliance" (including comments) in 61 non-test files at `993b390`, so the same rule is very
  likely violated elsewhere in the new frontend. That wider sweep is left to the next pass and is NOT
  claimed clean here.
- **Recommended wording:** "node" where the text means this Culvert instance's own state ("… live on
  this node only", "Outcome ambiguous on the node"), or "the server" where it means an HTTP refusal
  ("The server refused the accept.").
- **Affected code:** the files above, plus frontend tests that assert on these strings (grep source and
  tests together, keep each test's intent), and a `frontend/dist` rebuild.
- **Affected API / Configuration:** none. **Compatibility Risk:** None — display-only text.
- **Estimated PR Size:** Small-Medium (many strings, mechanical once the replacement words are agreed).
- **Priority:** Low — cosmetic, but it is a rule the canon states explicitly and T-51 already enforced once.

---

## Carried-Over Findings (unchanged)

All fifteen previously-open finding IDs (fourteen backlog entries, since T-21 and T-32 are tracked as
one paired item) remain open and unchanged, re-confirmed where the audited window could have touched
them (it did not): T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21+T-32 (paired), T-25 (residual),
T-29, T-30, T-33, T-34, T-39, and T-54 (queued on the 2026-09-12 report, which was still unmerged at
this snapshot — see the Program Note — and has since merged to `main`). Full descriptions and the priority-ordered refactoring plan for all of these are
unchanged from `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md` (T-9 … T-39) and
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-12.md` (T-54 — added by PR #1372, merged to `main` before this report;
that file is the authoritative text for T-54) and are not restated here to avoid drift between
two descriptions of the same open items. **T-55 and T-56 (above) are new this pass, and T-51 is
reopened as a residual (above)**, bringing the open count to eighteen IDs (seventeen backlog entries).

The "Content & Scanning" vs. "Content Security" soft finding (design-document reconciliation between
two deliberate naming decisions, not a mechanical rename) also remains unresolved and is not queued to
the numbered backlog, per 2026-09-09's reasoning.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 2026-09-09/09-12 for the carried-over rows — no carried-over item moved this pass. Two rows
added for the new findings, and one for the reopened T-51 residual:

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
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
| Low-Medium | T-54 (carried over; defined in the 2026-09-12 report, PR #1372) | Add OCSP admin JSON fields `malformedTotal`/`staleTotal` alongside the old names and deprecate those per `API-DEPRECATION-POLICY.md` (a plain rename is breaking); rename Go accessor `UnknownTotal`→`UnknownStatusTotal`; move `responder_blocked` into its own metric series and carry that through the GUI and runbook. The 2026-09-12 report is authoritative for the details | Medium | Small |
| Low-Medium | **T-56 (new)** | Decide "steering profile" vs. "PAC profile" as the going-forward canonical term for the new frontend's PAC screens; converge the losing surface (new frontend, or legacy GUI + `PRODUCT-TERMINOLOGY.md`) onto the winner. Doc half already fixed. | Low | Small |
| Low | **T-55 (new)** | Naming decision: pick one of "Accept to Draft" (legacy GUI + CLAUDE.md M5B text) or "Accept to Policy Draft" (frontend implementation + FRONTEND-FEATURE-PARITY FE-V18 + FRONTEND-MIGRATION-PLAN), then change the losing UI and its written contract together (rebuild `frontend/dist` if the frontend loses) | None | Small (after the decision) |
| Low | **T-51 residual (reopened)** | Replace rendered "appliance" copy in the new frontend's PAC and Policy Learning screens with "node" (or "server" for HTTP refusals), update dependent tests, rebuild `frontend/dist`; then sweep the rest of `frontend/src/features/**` for the same rule | None | Small-Medium |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

Also flagged (design-document reconciliation, not a numbered backlog item): "Content & Scanning" vs.
"Content Security" — see the 2026-09-09 report's soft finding.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass's audited merge window (`2833db3..993b390`, PR
#1371 + PR #1374) introduced no new drift — both PRs are correctness fixes with internally consistent
naming, and PR #1371's own same-window Codex review caught and fixed a real flag-name mismatch before
it ever reached `main`. Re-checking the new frontend's PAC and Policy Learning screens — surfaces of
`frontend/src/**` governed by the same `docs/design/PRODUCT-TERMINOLOGY.md` canon as `static/index.html`
but added or reworked after the frontend's initial 2026-08-22 audit — found two genuine, well-evidenced,
previously-undocumented mismatches between Culvert's two coexisting admin UIs (T-55: "Accept to Draft"
vs. "Accept to Policy Draft"; T-56: "Steering Profile" vs. bare "PAC profile", the same defect class
T-50 already fixed once, elsewhere) — plus a residual of the explicit "Appliance: not used" rule (T-51,
reopened; only the two re-checked screens were inventoried). The doc-only half of T-56 was fixed on the spot at zero risk,
consistent with this program's established practice for trivial, zero-compatibility-risk gaps; both
findings' code/GUI halves are queued to the backlog rather than rushed into this documentation PR,
since both are naming decisions this report does not make unilaterally (and a direction that changes the
new frontend additionally needs a `frontend/dist` rebuild). No cosmetic or preference-driven renames are
proposed — both new findings are real, cross-checked against the codebase's own established canonical
terminology document, and are things a real administrator moving between Culvert's two admin UIs would
actually notice. This report recommends future passes fold `frontend/src/**` into the routine audit
scope rather than treating it as a special case, since a single direct re-check of two feature
surfaces surfaced two real items. This report was written after a fresh sync against `origin/main` immediately before
opening its PR, per the DEBT-014 process lesson.
