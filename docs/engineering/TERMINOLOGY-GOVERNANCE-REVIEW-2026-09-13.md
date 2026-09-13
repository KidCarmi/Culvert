# Culvert Language & Terminology Governance Review — 2026-09-13

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `2833db3..993b390` — the window since the 2026-09-12 report's audited base,
> confirmed as the current `origin/main` HEAD by a `git fetch` immediately before this report was
> written (per the DEBT-014 lesson recorded in the 2026-09-09 report: sync against `main` right before
> opening a PR). The window covers 2 first-parent merges / 9 files / ~281 insertions (PR #1371: a
> CDR `-cdr-server-fingerprint` CLI/YAML validation-parity fix, with a same-window Codex-review
> follow-up correcting the flag's own name in a log message and trimming whitespace before the
> CLI/YAML merge; PR #1374: a new `geo_resolution` operator-contract row surfacing the existing
> CHAOS-60 GeoIP warm-pool state on `GET /api/diagnostics`, with a same-window Codex-review
> follow-up dropping a false-positive comparison). Part A audits this window directly. **Part B is a
> scope extension**: this pass is the first in this series to systematically check
> `frontend/src/**` (the new React admin frontend, gated by `CULVERT_EXPERIMENTAL_UI`) against
> `docs/design/PRODUCT-TERMINOLOGY.md`'s already-established canonical vocabulary, rather than only
> `static/index.html` (the legacy GUI) — see the Program Note below for why this gap existed and two
> genuine findings it surfaced.

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

**Part B (scope extension): two new findings, one fixed on the spot.** This program's methodology
notes (e.g. 2026-08-30: *"`static/index.html` is byte-unchanged in this window ... so there is no new
GUI copy to check"*) show that "check the GUI" has, in practice, meant grepping `static/index.html`
only. `frontend/src/**` is a second, independently-maintained GUI surface governed by the exact same
`docs/design/PRODUCT-TERMINOLOGY.md` canon, and it has apparently never been checked against that
canon by this series. A direct audit of it against two already-established canonical rules found two
genuine, previously-undocumented mismatches between the legacy GUI (canonical, per CLAUDE.md and
`PRODUCT-TERMINOLOGY.md`) and the new frontend:

- **T-55** (new): the Policy Learning "accept a recommendation into Policy Draft" action is labeled
  **"Accept to Draft"** in the legacy GUI (`static/index.html:7030,7044-7045`) — matching CLAUDE.md's
  own frozen spec text verbatim (*"GUI: 'Accept to Draft' ... house confirm stating 'Creates a
  disabled rule in Policy Draft...'"*) — but **"Accept to Policy Draft"** in the new frontend
  (`frontend/src/features/learning/LearningRecommendations.tsx:6,447,475,485`), for the identical
  admin-only action, the identical `policy_learning.accept` audit event, and the identical API call.
- **T-56** (new): PAC's named traffic-steering ruleset is the **"steering profile"** in
  `docs/design/PRODUCT-TERMINOLOGY.md`'s canonical table (*"the fourth distinct 'Profile' concept ...
  always say 'steering profile,' never bare 'profile,' on this screen"*), consistently applied in the
  legacy GUI since T-50 (2026-08-29, confirmed still live: `static/index.html:2311-2312,2323,2347,2394`)
  — but the new frontend's PAC screens say bare **"PAC profile"** / **"profile"** throughout, with no
  "steering" qualifier anywhere in the four files that make up that surface
  (`frontend/src/features/network/pac/ProfilesTab.tsx:1,297,324,384`, `ProfileDetail.tsx:1`,
  `ProfileDraftEditor.tsx:1`, `PACPage.tsx:39`). This is the exact defect class T-50 fixed in the
  legacy GUI, reintroduced independently in a surface T-50's own audit never covered — `docs/operator/
  pac-traffic-steering.md`, the operator runbook for this same feature, had the identical drift in its
  own prose (mixing a "## Steering profiles" heading with bare "a **profile** is..." sentences
  immediately under it) despite being written after T-50 shipped; **fixed in this pass** (doc-only,
  zero risk — see below).

Both new findings are cosmetic (neither changes any API, JSON field, config key, or backend behavior —
both surfaces call the identical endpoints) but real: an admin, support engineer, or documentation
author moving between the legacy and new admin UIs — which coexist by design, per CLAUDE.md, with the
new one opt-in via `CULVERT_EXPERIMENTAL_UI` — sees two different names for the same object or action
depending on which UI build is active, with nothing telling them the two labels refer to one thing.

**Fixed this pass (doc-only, zero risk):** `docs/operator/pac-traffic-steering.md` now consistently
says "steering profile" in the prose under its "## Steering profiles" heading (previously "a
**profile**...", "Custom profiles...", "the same profiles"), matching the already-canonical term this
same document's own heading already used, and now carries an explicit note recording the new
frontend's outstanding wording gap (T-56) so a reader of the runbook is not misled into thinking the
two UIs use consistent language today.

**Not fixed this pass, queued to the backlog:** the code/GUI-string halves of T-55 and T-56 both
require a change to `frontend/src/**` followed by a `frontend/dist` rebuild (the committed,
deterministic production bundle CLAUDE.md documents as the only frontend artifact actually embedded
into the binary) to take effect — this is a real build step with its own verification burden, not a
same-PR drive-by text edit, so both are queued rather than rushed in here. This mirrors how this
program has always treated a rename that needs more than a documentation edit to land (see T-29/T-30/
T-12, and T-54's own code half in the still-open 2026-09-12 report).

**Process recommendation:** future passes of this routine should explicitly include `frontend/src/**`
in the standard "check the GUI" step alongside `static/index.html`, not only when a diff happens to
touch it. Both are live, user-facing surfaces governed by the same canonical terminology document, and
this pass shows the second one has accumulated at least two real mismatches while going unchecked.

**Terminology Health Score: 8.5 / 10** (down from 8.7, the score last recorded on merged `main` by the
2026-09-11 report; the 2026-09-12 report proposes 8.6 but remains unmerged — see the Program Note).
The drop reflects two new, real, well-evidenced findings (T-55, T-56) surfaced by extending this
program's own audit scope to a previously under-checked surface, not new drift introduced by the
window's two merged PRs (which introduced none). Both findings are Low-Medium priority, cosmetic-only,
and one is now partially fixed.

---

## Findings

### T-55 — Policy Learning's "Accept to Draft" action has a different label in the new admin frontend (new — not fixed this pass)

- **Business concept:** the admin-only action that translates an accepted Policy Learning
  recommendation into a disabled rule in the shared Policy Draft (`policy_learning_accept.go`'s
  `plTranslateRecommendation`; audit event `policy_learning.accept`).
- **Current names:**
  - Legacy GUI (canonical, matches CLAUDE.md's own frozen M5B spec text): **"Accept to Draft"** — the
    button (`static/index.html:7030`), the confirm-dialog title and confirm-button label
    (`static/index.html:7044-7045`).
  - New frontend: **"Accept to Policy Draft"** — the button
    (`frontend/src/features/learning/LearningRecommendations.tsx:447`), the confirm-dialog title
    (`:475`) and confirm-button label (`:485`), and the file's own top-of-file comment, which asserts
    this exact wording is a deliberate choice (`:6`, *"Accept — 'Accept to Policy Draft' (never
    Apply/Enforce/Allow/Deploy)"*).
- **Why the current naming is problematic:** the comment's own parenthetical shows what it was
  actually guarding against — the wrong *verb* (never implying the rule is applied, enforced,
  allowed, or deployed) — not a deliberate choice of "Policy Draft" over "Draft" as the object noun.
  Nothing in the new frontend's source, CLAUDE.md, or any prior governance report records a reason for
  that second divergence. The result: the identical button, calling the identical API with the
  identical audit event, reads differently depending on which of Culvert's two coexisting admin UIs an
  administrator or a support engineer happens to be looking at — exactly the kind of mismatch that
  makes a screenshot in one doc look wrong against the other UI, or makes a support script written
  against one UI's wording confusing when read against the other.
- **Why the new name is better:** "Accept to Draft" is shorter, is the string CLAUDE.md's own frozen
  M5B specification already fixes as canonical, and loses no meaning — "Draft" on this screen already
  and unambiguously means the Policy Draft (the confirm dialog's body text, unchanged either way,
  already spells out "Creates a disabled rule in Policy Draft"). Converging on it needs no
  reinterpretation of user-facing meaning, only three string literals changed in one file.
- **Affected code:** `frontend/src/features/learning/LearningRecommendations.tsx` (3 UI strings + 1
  comment).
- **Affected API:** none — no field, route, or payload shape changes.
- **Affected GUI:** the new frontend's Policy Learning recommendations screen (button label, confirm
  dialog title, confirm button label).
- **Affected Documentation:** none required (CLAUDE.md and the operator doc already say "Accept to
  Draft").
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial in code (3 string literals); Small once the required
  `frontend/dist` rebuild + its own verification (build, lint, the existing Playwright/Vitest
  Policy-Learning coverage) is counted.
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
  - Legacy GUI (canonical, T-50-compliant, confirmed live today): "Steering Profiles" (panel title,
    `static/index.html:2311`), "+ New Steering Profile" (`:2312`), "Steering Profile ID"
    (`:2323`), "Save Steering Profile" (`:2347`), "Steering Profile" (simulator dropdown label,
    `:2394`).
  - New frontend (`frontend/src/features/network/pac/`): bare **"PAC profile(s)"** / **"profile"**
    throughout, with the word "steering" appearing nowhere in any of the four files —
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
  mechanical fix: it would mean updating `PRODUCT-TERMINOLOGY.md` itself, the legacy GUI (five strings,
  re-touching T-50's fix), and the operator runbook fixed in this same pass, which is why this report
  does not unilaterally pick a direction and instead records both options for whoever picks up the
  backlog item.
- **Affected code:** `frontend/src/features/network/pac/ProfilesTab.tsx`, `ProfileDetail.tsx`,
  `ProfileDraftEditor.tsx`, `PACPage.tsx` (comments + user-visible strings) if the "steering profile"
  direction is chosen; alternatively `static/index.html` (5 strings) + `docs/design/
  PRODUCT-TERMINOLOGY.md` (1 row) if the "PAC profile" direction is chosen instead.
- **Affected API:** none either way — `/api/pac/profiles` and the `Profile` JSON shape are unaffected.
- **Affected GUI:** the new frontend's PAC screens (or, under the alternative direction, the legacy
  GUI's PAC panel).
- **Affected Documentation:** `docs/operator/pac-traffic-steering.md` — **fixed in this pass**
  (prose now says "steering profile" consistently, plus a note recording the frontend gap); under the
  alternative direction, `docs/design/PRODUCT-TERMINOLOGY.md`'s Steering profile row would need
  updating instead.
- **Affected Configuration:** none.
- **Migration Complexity:** Small in either direction (a batch of string/comment edits in 4-5 files);
  Small-Medium once the "steering profile" direction's required `frontend/dist` rebuild + verification
  is counted, or once the "PAC profile" direction's canonical-doc update + legacy-GUI re-edit is
  counted.
- **Compatibility Risk:** None — display-only text; no API, JSON, or config surface changes either way.
- **Estimated PR Size:** Small (doc fix, done) + Small (code direction, once decided).
- **Priority:** Low-Medium — cosmetic and single-feature-scoped, but it is the second occurrence of
  the exact defect class T-50 already fixed once, which is worth resolving before a third surface
  (a doc, a training deck, a support macro) independently invents a third spelling.

---

## Carried-Over Findings (unchanged)

All fifteen previously-open finding IDs (fourteen backlog entries, since T-21 and T-32 are tracked as
one paired item) remain open and unchanged, re-confirmed where the audited window could have touched
them (it did not): T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21+T-32 (paired), T-25 (residual),
T-29, T-30, T-33, T-34, T-39, and T-54 (still queued on the still-unmerged 2026-09-12 report — see the
Program Note). Full descriptions and the priority-ordered refactoring plan for all of these are
unchanged from `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md` (T-9 … T-39) and
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-12.md` (T-54) and are not restated here to avoid drift between
two descriptions of the same open items. **T-55 and T-56 (above) are new this pass**, bringing the
open count to seventeen IDs (sixteen backlog entries).

The "Content & Scanning" vs. "Content Security" soft finding (design-document reconciliation between
two deliberate naming decisions, not a mechanical rename) also remains unresolved and is not queued to
the numbered backlog, per 2026-09-09's reasoning.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 2026-09-09/09-12 for the carried-over rows — no existing item moved this pass. Two rows
added for the new findings:

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
| Low-Medium | T-54 (carried over, still unmerged) | Rename OCSP admin JSON fields `malformedResponseTotal`→`malformedTotal` and `staleResponseTotal`→`staleTotal`, and Go accessor `UnknownTotal`→`UnknownStatusTotal`; regenerate the OpenAPI bundle; update GUI references; resolve `responder_blocked`'s metric-family scope mismatch | Low | Small |
| Low-Medium | **T-56 (new)** | Decide "steering profile" vs. "PAC profile" as the going-forward canonical term for the new frontend's PAC screens; converge the losing surface (new frontend, or legacy GUI + `PRODUCT-TERMINOLOGY.md`) onto the winner. Doc half already fixed. | Low | Small |
| Low | **T-55 (new)** | Change `LearningRecommendations.tsx`'s "Accept to Policy Draft" (3 strings + 1 comment) to "Accept to Draft" to match the legacy GUI and CLAUDE.md's frozen spec; rebuild `frontend/dist` | None | Small |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

Also flagged (design-document reconciliation, not a numbered backlog item): "Content & Scanning" vs.
"Content Security" — see the 2026-09-09 report's soft finding.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass's audited merge window (`2833db3..993b390`, PR
#1371 + PR #1374) introduced no new drift — both PRs are correctness fixes with internally consistent
naming, and PR #1371's own same-window Codex review caught and fixed a real flag-name mismatch before
it ever reached `main`. Extending this program's audit scope to `frontend/src/**` for the first time —
a surface governed by the same `docs/design/PRODUCT-TERMINOLOGY.md` canon as `static/index.html` but
evidently never checked against it directly by this series — found two genuine, well-evidenced,
previously-undocumented mismatches between Culvert's two coexisting admin UIs (T-55: "Accept to Draft"
vs. "Accept to Policy Draft"; T-56: "Steering Profile" vs. bare "PAC profile", the same defect class
T-50 already fixed once, elsewhere). The doc-only half of T-56 was fixed on the spot at zero risk,
consistent with this program's established practice for trivial, zero-compatibility-risk gaps; both
findings' code/frontend halves are queued to the backlog rather than rushed into this documentation PR,
since both require a `frontend/dist` rebuild to take effect and T-56 additionally requires a naming
direction decision this report does not make unilaterally. No cosmetic or preference-driven renames are
proposed — both new findings are real, cross-checked against the codebase's own established canonical
terminology document, and are things a real administrator moving between Culvert's two admin UIs would
actually notice. This report recommends future passes fold `frontend/src/**` into the routine audit
scope rather than treating it as a special case, since a single direct check surfaced two real items on
a first pass. This report was written after a fresh sync against `origin/main` immediately before
opening its PR, per the DEBT-014 process lesson.
