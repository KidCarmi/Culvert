# Culvert Language & Terminology Governance Review — 2026-09-23

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Snapshot scope (read this first):** this is a HISTORICAL record of `origin/main` at `3febe59` on
> 2026-09-23. It was merged later, after `main` had moved on, so the tree it ships in contains commits it
> never audited. It uses two states, and says which one each part describes:
> - **At the audited snapshot (`3febe59`)**: the tree as audited. The findings (T-61, T-62, T-63) and
>   every file:line citation describe this state.
> - **After this PR's corrections**: `3febe59` plus the copy and comment changes this PR makes (the T-62
>   legacy-GUI wording and the T-61 code comment), nothing else. Neither change closes a backlog ID.
>
> The **open backlog** and the **health score** are each stated for BOTH states (the convention of the
> 2026-09-16, 2026-09-19 and 2026-09-21 reports). Fixes merged to `main` after `3febe59` — T-57 (#1407),
> T-58 (#1434), T-17 (#1444), and T-59 with the T-51 recurrence lines (#1456) — are NOT applied to either
> state; they appear only in a clearly labelled "for comparison" row.
>
> **Coverage limits:** the checks behind each finding matched **literal patterns only** (the exact
> strings each finding names) — a synonym or paraphrase that no pattern named is not claimed absent. The
> window glossary check (Method, below) matched the same literal terms as the 2026-09-21 report's sweep
> ("appliance", "verdict") and none of the glossary's context-sensitive rules. CI workflow and script
> output was not audited.
>
> Neither state is the tree this file is published in; the current governance state is whatever the
> most recent review in this series says. Later windows are audited by later reports, never
> retroactively by this one.
> **Finding-ID note:** series finding IDs are assigned in report-date order. This report's three
> findings were first published as T-54, T-55 and T-56, which belong to earlier reports in the series.
> They are renumbered **T-61** (identity-backend metric prefix), **T-62** (Sync vs Refresh) and **T-63**
> (decryption-exclusion audit search).
> **Method:** this report follows the 2026-09-21 report (#1456), whose audited snapshot `6c46ebd` is an
> ancestor of `3febe59`. The window `46410c3..6c46ebd` is audited by that report and is not re-audited
> here; this report's window is `6c46ebd..3febe59` — 10 first-parent merges, confirmed as the
> then-current `origin/main` HEAD by a fetch immediately before this report was written (the DEBT-014
> lesson: sync against `main` right before opening a PR). All 10 are CI and test work: `CI-REDESIGN`
> stages 2B–6B (incl. `cmd/cireport`), two test de-flakes and the restore size-bound test fixtures. Outside `.github/`, `cmd/`, `test/` and
> test files, the window touches `CHANGELOG.md`, `CLAUDE.md`, `roadmap/`, two MCP operator runbooks
> (6 lines), `internal/feedsync/feedsync.go` (a `Wait` method, no user-visible string) and `restore.go`
> (a refactor that keeps its error text byte-identical). None of it changes a GUI label, API field,
> audit action, metric or alert name. Glossary check of the lines the window added: "appliance" and
> "verdict" occur only in `roadmap/CI-REDESIGN.md`, `roadmap/QA-GATE.md` and `CLAUDE.md` (internal
> engineering docs, not customer-facing); none in the two runbooks. This pass then ran a cross-surface
> audit (GUI ↔ REST API ↔ audit log ↔ Prometheus metrics ↔ alerts ↔ CLI/config) independent of the
> window, since drift can be long-standing rather than newly introduced; all three findings came from
> that audit, not from the window.
>
> **Correction (before merge):** the first revisions of this report audited `46410c3..3febe59` and said
> none of it touched admin-facing terminology. That window includes `46410c3..6c46ebd`, where the
> 2026-09-21 report found T-59, T-59b, T-59c, T-60 and the T-51 recurrence, so the claim was false. They
> also scored from the 2026-09-11 report's 8.7 with a fourteen-ID backlog, which omitted every item
> opened from 2026-09-12 on. Both are corrected below; see the Process Note.

---

## Executive Summary

**Three findings not carried as open backlog IDs by any earlier report (T-61, T-62, T-63).** Each had
been seen by an earlier report without being recorded as a finding: the `culvert_auth_backend_*` metrics
were named beside the `identity_backend` alert and contract row by the 2026-08-07 and 2026-08-18
reports, which raised no finding; the feed audit-verb split (`sync` vs `refresh`) was noted by T-37
(2026-08-04) as a "lower-priority nice-to-have" and set aside when T-37 closed (2026-08-18); and the
2026-07-12 report judged "Decryption Exclusions" vs `decryption.autoexclude.*` "all aligned". Two are
partially addressed now with zero-risk changes; the compat-sensitive halves of both, plus T-63 in full,
are recorded to the backlog rather than force-fixed, consistent with this program's standing rule to
weigh migration cost before renaming anything with a compatibility surface (Prometheus metric names,
audit action strings, generated OpenAPI operation IDs).

1. **T-61 — CHAOS-47 identity-backend outage: metric prefix disagrees with its own alert and
   operator-contract row.** `culvert_auth_backend_unavailable{,_total}` / `culvert_auth_backend_gated_denials_total`
   (metrics.go) name the exact condition the `identity_backend_unreachable` alert
   (`internal/alerts/store.go:28`, `auth_backend_health.go`) and the `identity_backend` operator-contract
   row (`diagnostics.go:648` `checkIdentityBackend`) both deliberately name "identity_backend" — the
   alert-store comment even explains *why* ("identity_backend_unreachable... Deliberately not
   `idp_unreachable`..."), showing the authors chose this vocabulary carefully everywhere except the
   metric prefix, which was left as the older "auth_backend" spelling. **Done this PR:** a
   terminology-note comment at the metric-emission site (metrics.go, ahead of the three `culvert_auth_backend_*`
   `HELP`/`TYPE` lines) cross-referencing the alert and contract-row names, naming this finding, and
   stating that a rename would need a dual-emission window. **Not fixed:** the prefix itself. A rename
   is possible — the T-31 ClamAV fix (2026-08-28) renamed a metric by dual emission — but it changes a
   published series name and needs a deprecation window, so it stays on the backlog.

2. **T-62 — "manually re-fetch this feed now" uses two different verbs across four peer feed panels
   in the same admin UI.** Blocklist feed and Threat feed panels said "Sync" (GUI buttons *and* their
   audit actions `blocklist.feed.sync` / `threatfeed.sync`); the SaaS URL-category feed and Release
   Catalog panels already say "Refresh" (GUI buttons *and* audit actions `saasfeed.refresh` /
   `release.catalog.refresh`). These are structurally the same admin action ("pull fresh data from an
   external source on demand") on peer panels, so the verb an admin learns on one page does not carry to
   another — and the legacy threat-feed button's own icon (`#i-refresh`) already pointed at "refresh".
   **Fixed this PR, GUI-copy only:** `static/index.html`'s "Sync All Now" → "Refresh All Now" (blocklist
   feed) and "Sync Feeds Now" → "Refresh Feeds Now" (threat feed), the per-feed row button, toast and
   status messages those two flows display, plus the one doc-comment in
   `internal/blocklistfeed/blocklistfeed.go` that quoted the old button label. Route paths, JS handler
   names and audit action strings are unchanged. **Not fixed, recorded as residual:** the audit action
   strings (`blocklist.feed.sync` / `threatfeed.sync` vs `saasfeed.refresh` / `release.catalog.refresh`)
   still disagree. The Audit Log filter matches `action`, `object`, `objectId`, `actor` and `detail`; the
   two sync events carry the feed URL or `manual` as object and an empty detail, so a search for
   "refresh" finds them only if the feed URL or the actor happens to contain it. The **new React admin
   frontend** (`frontend/src/features/security/ThreatIntelTab.tsx`) independently uses "Sync" — button
   label ("Sync feeds now"), component state (`syncing`/`syncError`/`syncNote`), and user-visible copy
   ("Sync completed…", "The sync request failed."). Those literals live in the component itself; it
   imports only the hand-written `syncThreatFeeds` wrapper from `frontend/src/api/contentsec.ts`, not
   `types.gen.ts`. Realigning that copy needs a full `npm run verify` + two-build determinism-gate cycle
   (the T-53 fix's precedent) — out of scope for a zero-risk-only fix. Separately and optionally, the
   OpenAPI operation IDs `syncThreatFeeds` and `syncBlocklistFeed` (`api/openapi/openapi.yaml`, with
   generated copies in `types.gen.ts` that no hand-written frontend code imports) carry the same verb;
   renaming them is not needed to fix the React copy.

3. **T-63 — "Decryption Exclusions" (GUI/API) vs `decryption.autoexclude.*` (audit action prefix):
   the one event the feature exists for is not findable by the feature's displayed name.** The nav label
   (`static/index.html:773`, `data-view="decexclusions"`), the REST route (`/api/decryption-exclusions`,
   `ui_policy.go:3014`) and its JSON response field (`"exclusions"`, `ui_policy.go:970`) all say
   "exclusions", while all six audit actions the feature emits are prefixed `decryption.autoexclude.*`.
   CLAUDE.md documents "autoexclude" as the *deliberate internal engine/package name*. The Audit Log's
   text filter (`renderAuditLog`) matches `detail` as well as `action`, and most of this feature's
   detail strings do say "exclusion" (manual evict, clear, tunables, surge, rescue), so a search for
   "exclusion" finds them. It misses two: `decryption.autoexclude.learn` — the automatic promotion of
   a host into the cache, whose detail reads "SSL inspection auto-disabled…" — and an evict request for
   an entry that was not present. (Corrected from this report's first draft, which claimed zero hits
   for every event; see the Process Note.) **Not fixed this PR**, recorded to the backlog as a narrow,
   low-priority item. The 2026-07-12 report judged these names "all aligned"; it compared the names, not
   what the Audit Log search returns.

**A candidate considered and declined:** a hand-coded "exclusion" ↔ "autoexclude" synonym in the Audit
Log's client-side filter. Declined as a one-term workaround rather than a naming decision that
generalizes; see T-63's recommended action.

**Terminology Health Score — audited snapshot `3febe59`: 7.5 / 10; after this PR's corrections:
7.5 / 10** (lineage figures; they inherit the unreconciled 0.1 under-charge for T-54 — see below).

- **Rule** (unchanged from the 2026-09-08 precedent, as applied by the 2026-09-19 and 2026-09-21
  reports): each open backlog item a report newly records costs 0.1, and each item it fixes gives 0.1
  back. An item already charged by an earlier report is never charged a second time.
- **Baseline: 7.8**, the 2026-09-21 report's figure for its audited snapshot `6c46ebd` (T-59 still
  open). That is the right baseline for `3febe59`: `6c46ebd` is an ancestor of `3febe59`, nothing in
  `6c46ebd..3febe59` closed a backlog item, and every fix merged since — T-57 (#1407), T-58 (#1434),
  T-17 (#1444), T-59 (#1456) — merged AFTER `3febe59`. The 2026-09-21 report's 7.9 is NOT the baseline:
  it describes `6c46ebd` plus #1456's T-59 fix, which `3febe59` does not contain.
- **Audited snapshot `3febe59`:** three new open IDs — T-61, T-62, T-63 → 7.8 − 0.3 = **7.5**.
- **After this PR's corrections:** **7.5**. The T-61 comment and the T-62 GUI copy leave both IDs open
  (T-61's prefix, T-62's audit strings and React copy), so nothing is given back.
- **For comparison only (not a claim about any audited tree):** applying the same rule to "after this
  PR's corrections" plus the four later fixes (T-57, T-58, T-17, T-59) gives 7.5 + 0.4 = 7.9 (same
  lineage, same 0.1 T-54 under-charge).
- **Disclosed, not amended (carried from the 2026-09-16, 2026-09-19 and 2026-09-21 reports):** the
  2026-09-13 report measured its drop from 8.7 rather than from the 2026-09-12 report's 8.6, so T-54's
  0.1 charge was not carried into its 8.4. Merged reports' scores are not amended retroactively; this
  report takes the merged figures as recorded. It neither restores T-54's missing 0.1 nor charges T-54
  again: 7.5 and 7.5 are lineage figures that UNDER-charge by 0.1. For transparency only, the fully
  charged equivalents are **7.4** (audited snapshot) and **7.4** (after this PR's corrections), and 7.8
  for the comparison row; they are not this report's score.
- **Disclosed, not amended — a second, parallel lineage:** the 2026-09-20 report (#1444, the T-17 fix,
  merged after `3febe59`) records **8.8 / 10, up from 8.7**, with twelve open backlog entries. It scores
  from the 2026-09-11 report's lineage and does not count T-54..T-60 or the T-51 residual, so its 8.8
  and this chain's figures are not comparable. This report does not amend it; reconciling the two
  lineages is left to an owner (see the PR description).

(Earlier revisions of this report said "8.7 / 10, unchanged" with a fourteen-ID backlog. That is the
2026-09-11 lineage, which omits T-54 through T-60 and the T-51 residual, all open at `3febe59`. It is
corrected here rather than silently replaced.)

---

## Findings

### T-61 — CHAOS-47 identity-backend metric prefix diverges from its own alert and operator-contract row (new — OPEN; cross-reference comment added)

- **Business concept:** an external identity backend (LDAP/OIDC) being unreachable, causing proxy
  authentication to fail closed (CHAOS-47).
- **Current names:** alert `identity_backend_unreachable` (`internal/alerts/store.go:28`,
  `auth_backend_health.go:41,58,161,172,175`); operator-contract row `Code: "identity_backend"`
  (`diagnostics.go:648-668`, func `checkIdentityBackend`); Prometheus metrics
  `culvert_auth_backend_unavailable`, `culvert_auth_backend_unavailable_total`,
  `culvert_auth_backend_gated_denials_total` (`metrics.go`, same CHAOS-47 comment block).
- **Recommended canonical name:** "identity_backend" is already the deliberately-chosen name everywhere
  except the metric prefix (the alert-store comment explicitly records *why* "identity_backend" was chosen
  over "idp_unreachable" — the authors were not indifferent to this vocabulary). The metric prefix should
  eventually read `culvert_identity_backend_*` to match.
- **Why the current naming is problematic:** an operator writing a Prometheus alerting rule for the
  `identity_backend_unreachable` alert or reading the `identity_backend` operator-contract row has no
  textual hint that the corresponding PromQL series is `culvert_auth_backend_*` — the two vocabularies look
  unrelated on the page unless the operator already knows the CHAOS-47 history.
- **Why the new name is better:** removes a name that otherwise looks like independent, uncorrelated
  telemetry for the same condition, which is exactly the kind of cross-surface mismatch this program
  exists to catch.
- **What was actually done:** a terminology-note comment was added at the metric-emission site
  (`metrics.go`, immediately before the `culvert_auth_backend_*` HELP/TYPE block) that states the
  cross-reference explicitly, names this finding, and says a rename would need a dual-emission window.
  The prefix is not renamed in this PR: dashboards and alerting rules key off published series names.
  Unlike an alert-event name (which has a load-time rename path, `normalizeEventNames`), a metric can
  only be renamed by emitting both names for a deprecation window — which this repo has done once
  already (T-31, 2026-08-28: `culvert_clam_scan_errors_total` + `culvert_clamav_scan_errors_total`,
  pinned by `clamav_metrics_dualemit_test.go`). (The first revisions of this comment and report said
  metric names have "no safe aliasing seam" and that the prefix was "NOT drift"; the T-31 precedent
  makes the first false, and the second contradicted this report's own finding. Both are corrected.)
- **Affected code:** `metrics.go` (comment only, this pass).
- **Affected API:** none (comment-only change).
- **Affected GUI:** none.
- **Affected Documentation:** none beyond the added code comment.
- **Affected Configuration:** none.
- **Migration Complexity:** High, if ever executed as an actual rename (every deployed Grafana
  dashboard/Prometheus alerting rule referencing `culvert_auth_backend_*` would need to add the new series
  name, via a dual-emission transition period spanning at least one release, as T-31 did).
- **Compatibility Risk:** High (published metrics are a monitoring contract; CLAUDE.md calls one such
  label set "a monitoring contract, pinned by test").
- **Estimated PR Size:** Small for the documentation fix shipped this pass; Medium-Large for an eventual
  metric rename (would need a deprecation window, likely a doubled-emission period, and its own dedicated
  review — not a terminology-only change).
- **Priority:** Low for the rename itself (compat risk exceeds the confusion it resolves, given the
  comment now bridges the gap for a reader). The ID stays open until the prefix is renamed or an owner
  closes it as accepted.

### T-62 — "Sync" vs "Refresh" for the same manual-refetch action across four peer feed panels (new — OPEN; legacy-GUI half fixed this PR)

- **Business concept:** an admin manually forcing an on-demand re-fetch of an externally-sourced feed
  (blocklist feed, threat-intel feed, SaaS URL-category feed, or the release catalog) outside its normal
  periodic cadence.
- **Current names (before this fix):** "Sync All Now" (blocklist feed button, `static/index.html`) /
  `blocklist.feed.sync` (`ui_policy.go:384`); "Sync Feeds Now" (threat feed button, `static/index.html`) /
  `threatfeed.sync` (`ui_security.go:790`); "Refresh now" (SaaS feed button, `static/index.html:3474`) /
  `saasfeed.refresh` (`saas_feed_status_api.go:110`); "⟳ Refresh catalog" (release catalog button,
  `static/index.html:5125`) / `release.catalog.refresh` (`release_api.go:472,482`).
- **Recommended canonical name:** "Refresh" — already the verb on two of the four panels, and the threat-feed panel's own pre-existing icon (`#i-refresh`) was
  already pointing at "refresh" as the intended concept ahead of the button's own label text.
- **Why the current naming is problematic:** identical admin intent, described with two different verbs
  depending on which panel happens to host it; an admin who learns "Sync" on the blocklist panel has no
  reason to look for "Refresh" on the SaaS feed panel for the equivalent action, and vice versa.
- **Why the new name is better:** one verb for one concept across every peer panel that offers it.
- **What was actually done (zero-risk half):** `static/index.html` button labels: "Sync All Now" →
  "Refresh All Now" (blocklist feed), "Sync Feeds Now" → "Refresh Feeds Now" (threat feed), plus the
  labels and status messages coupled to those two flows, so the same panel does not rename the button
  and then report "Sync complete": the per-feed row button ("Sync" → "Refresh"), the blocklist toast
  ("Sync complete - …" → "Refresh complete - …"), and the threat-feed status line ("Syncing threat
  feeds…"/"Sync complete."/"Sync failed:" → "Refreshing…"/"Refresh complete."/"Refresh failed:"). A
  failed blocklist refresh used to toast the server's raw "Error: sync failed: …" body; the client now
  shows "Refresh failed: …" and drops the server's prefix, leaving the API error text unchanged. The
  periodic-schedule wording ("Blocklist Feed Auto-Sync", "Sync Interval", "Last Sync") describes the
  automatic cadence, not the manual action, and is left as is. (The coupled strings were added after
  review; see the Process Note.) Updated the one Go doc-comment quoting the old label
  (`internal/blocklistfeed/blocklistfeed.go`, `SyncAll`'s doc comment). No route, JS handler name, or
  audit action string was touched.
- **What remains (recorded, not fixed):**
  - The audit action strings `blocklist.feed.sync` / `threatfeed.sync` still disagree with
    `saasfeed.refresh` / `release.catalog.refresh`. The Audit Log filter matches `action`, `object`,
    `objectId`, `actor` and `detail`; the two sync events have an empty detail and the feed URL or
    `manual` as object, so this PR's GUI fix alone does not make the Audit Log searchable by one verb.
    This half was first noted under T-37 (2026-08-04) as a "lower-priority nice-to-have" and left
    open when T-37 closed (2026-08-18), because T-37's harm was the threat-feed action's prefix, not the
    verb. It is recorded here, under T-62, rather than by reopening T-37.
  - `frontend/src/features/security/ThreatIntelTab.tsx` (the new React admin frontend, disabled by default
    behind `CULVERT_EXPERIMENTAL_UI`) independently says "Sync" — button label, component state
    (`syncing`/`syncError`/`syncNote`), and user-visible strings ("Sync completed — N entries.", "The sync
    request failed."). These literals and state names are written directly in the component
    (`ThreatIntelTab.tsx:37-77,153,163`); it imports only the hand-written `syncThreatFeeds` wrapper from
    `frontend/src/api/contentsec.ts:142`, not `types.gen.ts`. Realigning this copy needs a full frontend
    text/state-variable pass plus the `npm run verify` (unit tests, lint, format, strict typecheck) +
    two-build determinism-gate cycle the 2026-09-09 report's T-53 fix required — not a same-pass,
    zero-risk change. It needs no OpenAPI change.
  - Optional and separate: the OpenAPI operation IDs `syncThreatFeeds` (`api/openapi/openapi.yaml:8479`)
    and `syncBlocklistFeed` (`:10640`) carry the same verb. Their generated copies in
    `frontend/src/api/types.gen.ts` are not imported by any hand-written frontend code. Renaming them
    would need a bundle regeneration and changes a published API identifier; it is not required to fix
    the React copy, and is recorded only as an option. (An earlier revision said the React copy was
    "sourced from" these generated IDs and listed `syncBlocklistFeed` in the React residual; corrected
    after review.)
- **Affected code:** `static/index.html` (2 button labels + the coupled row button, toast and status
  strings), `internal/blocklistfeed/blocklistfeed.go`
  (1 doc comment) — this pass. Residual: `frontend/src/features/security/ThreatIntelTab.tsx` (and,
  optionally, the `contentsec.ts` wrapper name), for a future pass.
- **Affected API:** none this pass (optional: the two OpenAPI operation IDs, if ever renamed).
- **Affected GUI:** blocklist feed and threat feed panels (legacy `static/index.html`) fixed this pass; new
  React frontend's Threat Intelligence tab is residual.
- **Affected Documentation:** none.
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial for the shipped GUI-copy fix. Medium for the audit-action-string
  alignment (needs a rename-with-compat-aliasing approach, not a blind rename, given SIEM-forwarding
  consumers). Medium for the React frontend text/state pass (contained to one disabled-by-default preview
  surface, but gated behind the full frontend verify pipeline).
- **Compatibility Risk:** None for the shipped fix. Medium for the audit-string alignment (SIEM
  correlation rules external to this repo may already key on the existing action strings). Low for the
  React frontend pass (experimental, default-off surface, no external consumers yet — same risk class the
  2026-09-09 report assigned to T-53).
- **Estimated PR Size:** Small (shipped). Small-Medium for the audit-string alignment. Medium for the React
  frontend pass (mostly mechanical, but gated by the full verify/determinism pipeline).
- **Priority:** Medium (the two GUI-copy panels are now consistent with the two newer ones; the residual
  audit-string and frontend work is worth doing but is not urgent — the feature works correctly today, the
  drift is discoverability/documentation-grade confusion, not a functional defect).

### T-63 — "Decryption Exclusions" (GUI/API) vs `decryption.autoexclude.*` (audit action) — the learn event can't be found by the feature's displayed name (new — OPEN)

- **Business concept:** the volatile, runtime-learned decryption-exclusion cache (fail-open auto-learn,
  `internal/autoexclude`) — the same subsystem T-53 (2026-09-09) touched from the opposite angle (a
  same-frontend internal-naming contradiction, already fixed).
- **Current names:** nav label "Decryption Exclusions" (`static/index.html:773-774`,
  `data-view="decexclusions"`); REST route `/api/decryption-exclusions` and JSON field `"exclusions"`
  (`ui_policy.go:3014`, `ui_policy.go:970`); audit actions `decryption.autoexclude.evict`,
  `decryption.autoexclude.clear`, `decryption.autoexclude.tunables` (`ui_policy.go:995,1000,1100`), plus
  the system-emitted `decryption.autoexclude.learn`, `.rescue` (`autoexclude_resolve.go:276,369`) and
  `.surge` (`autoexclude_surge.go:101`).
- **Recommended canonical name:** not force-decided by this report — see recommended action below.
  CLAUDE.md already documents "autoexclude" as the deliberately-chosen *internal/package/metric*
  vocabulary (`internal/autoexclude`, `culvert_decrypt_autoexclude_*`), so unlike T-61/T-62 this is not a
  case of two competing business names; it is one deliberately-named internal concept whose vocabulary
  happens to also be the only vocabulary present in the one admin-visible surface — the Audit Log — that
  is supposed to be searchable by the *displayed* feature name.
- **Why the current naming is problematic:** the Audit Log UI text-filters on `action`, `object`,
  `objectId`, `actor` and `detail` (`static/index.html`, `renderAuditLog`). None of the six action strings contains
  "exclusion", but most details do: evict ("manual eviction of a learned exclusion"), clear ("cleared N
  learned exclusion(s)"), tunables ("updated adaptive decryption-exclusion tunables"), surge ("…SSL-inspection
  exclusions promoted…") and rescue ("…the persistent exclusion still requires…"). A search for
  "exclusion" therefore finds those. It misses `decryption.autoexclude.learn` — the automatic promotion
  of a host into the cache, the event an operator most needs to find — whose detail says "SSL inspection
  auto-disabled for this profile+host until TTL", and an evict request for an absent entry ("eviction
  requested; entry was not present"). The gap is narrow: one system event and one no-op admin event.
- **Why a fix would be better:** makes every event of the feature's audit trail discoverable by the
  name an admin sees on the page, without touching the deliberately-chosen internal engine vocabulary
  CLAUDE.md documents.
- **Why this pass declined both an audit-string rename and a client-side synonym patch:** an audit-action
  rename carries the same SIEM/audit-trail compatibility caution this program has consistently applied to
  every other audit-string finding (see T-18's carried-over recommendation, and the caution taken with
  T-62's residual half above). A narrow client-side synonym special-case in the Audit Log's text filter
  (treating "exclusion" and "autoexclude" as equivalent search terms) was considered and declined as a
  band-aid for one term rather than a canonical naming fix — see the note above the findings table.
- **Recommended action (for the backlog, not executed this pass):** the smallest fix is (a) to word the
  `learn` (and absent-entry evict) detail strings so they mention the exclusion, matching their siblings —
  a detail-text change that leaves the action strings SIEM rules key on untouched. A lower-effort
  alternative is (b), a one-line note in `docs/operator/decryption-auto-exclusions.md` that the audit
  trail is also searchable under "autoexclude". An action-string rename (a `decryption.exclusion.*`
  spelling behind an audit-action alias seam, the audit-log analogue of `normalizeEventNames`) is not
  justified by a gap this narrow.
- **Affected code:** `autoexclude_resolve.go` (the `learn` detail) and `ui_policy.go` (the
  absent-entry evict detail), if option (a) is taken.
- **Affected API:** none (the REST route/JSON field are not the mismatch; only the audit actions are).
- **Affected GUI:** the Audit Log's rendered/filtered detail text, if option (a) is taken.
- **Affected Documentation:** `docs/operator/decryption-auto-exclusions.md` (stop-gap option).
- **Affected Configuration:** none.
- **Migration Complexity:** Low for option (a) or (b). An action-string rename would be Medium (audit
  actions are forwarded to external SIEM via syslog, so it would need an alias/compat period, the same
  reasoning applied to T-18).
- **Compatibility Risk:** Low for (a) — detail text is free-form and not a keyed identifier — and none for
  (b).
- **Estimated PR Size:** Small.
- **Priority:** Low (the internal vocabulary is deliberate and documented; this is a narrow,
  audit-log-search-only consequence of that choice, not a cross-cutting business-concept collision).

---

## Carried-Over Findings

Every ID below is carried as open at the audited snapshot `3febe59`, taken from the 2026-09-21 report's
audited-snapshot backlog (24 IDs / 23 entries at `6c46ebd`). None is fixed by this PR, so each is also
open after this PR's corrections. Full descriptions live in the report that owns each ID and are not
restated here, to avoid two descriptions of one item drifting apart:

- T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21+T-32 (paired), T-25 (residual), T-29, T-30, T-33,
  T-34, T-39 — owned by `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md`. T-17 is fixed on `main` by #1444,
  which merged after `3febe59`.
- T-54 — owned by the 2026-09-12 report (#1372).
- T-55, T-56 (code half) and the T-51 residual — owned by the 2026-09-13 report (#1380).
- T-57 — owned by the 2026-09-16 report (#1407); fixed on `main` by #1407, merged after `3febe59`.
- T-58 — owned by the 2026-09-19 report (#1434); fixed on `main` by #1434, merged after `3febe59`.
- T-59, T-59b, T-59c, T-60 — owned by the 2026-09-21 report (#1456). T-59 (and the T-51 recurrence
  lines, which carry no ID of their own) is fixed on `main` by #1456, merged after `3febe59`.

**Re-checked at `3febe59`** (the 2026-09-21 report's reproduction commands with `R=3febe59`, plus three
more): T-59 (`static/index.html:4477` still "OCSP / CRL Revocation"), T-59b (`verdict` still in
`internal/ocsp/ocsp.go`, `ocsp_metrics.go` and `docs/operator/ocsp-revocation-checking.md`), T-59c
(`geoip_resolve_health.go:322`), T-60 (no Go emitter of `tooltrust.decision`), T-58
(`RuleEditor.tsx:437,508`), T-57 (`static/index.html:5184,6119,16205`), T-54 (`ui_security.go`
`"malformedResponseTotal"`, `ocsp_metrics.go:62`), T-55 (3 and 4 lines), T-56 (0 files), T-51 residual
(12 files), T-12 (`handlers_upgrade.go:1,80`), T-29 and T-30 (`rate_limit_rpm` and
`conn_limit_max_per_ip` absent from `config.go`). The other carried IDs were not re-verified. Since
`6c46ebd..3febe59` touches no GUI, API, audit, metric or alert string (see Method), none of them could
have been closed in the window.

**Backlog count:**

| State | Open IDs | Backlog entries (T-21+T-32 counted once) |
| --- | --- | --- |
| 2026-09-21 report, its audited snapshot `6c46ebd` | 24 | 23 |
| Audited snapshot `3febe59` (adds T-61, T-62, T-63) | 27 | 26 |
| After this PR's corrections (no ID closed) | 27 | 26 |
| For comparison only: after this PR's corrections plus #1407 (T-57), #1434 (T-58), #1444 (T-17) and #1456 (T-59) | 23 | 22 |

The comparison row agrees with the 2026-09-21 report's own comparison row (20 / 19) plus this report's
three new IDs.

### Reproduction commands

Run from any clone that has fetched `3febe59`:

```sh
R=3febe59
# T-61: the metric prefix and the alert name (expect hits in both)
git grep -n 'culvert_auth_backend_unavailable ' $R -- metrics.go
git grep -n '"identity_backend_unreachable"' $R -- auth_backend_health.go
# T-62: expect Sync at :1427 and :1610, Refresh at :3474 and :5125
git grep -n -e 'Sync All Now' -e 'Sync Feeds Now' -e 'Refresh now' -e 'Refresh catalog' $R -- static/index.html
git grep -n -e '"blocklist.feed.sync"' -e '"threatfeed.sync"' -e '"saasfeed.refresh"' -e '"release.catalog.refresh"' $R -- '*.go' ':!*_test.go'
# T-63: expect six decryption.autoexclude.* actions, none containing "exclusion"
git grep -n 'decryption\.autoexclude\.' $R -- '*.go' ':!*_test.go'
# Carried items: the 2026-09-21 report's commands, with R=3febe59
```

The "Content & Scanning" vs. "Content Security" soft finding (design-document reconciliation between two
deliberate naming decisions, not a mechanical rename) also remains unresolved and is not queued to the
numbered backlog, per 2026-09-09's reasoning.

---

## Recommended Refactoring Plan (priority order)

Carried-over items keep the plans of the reports that own them (see the Carried-Over list). New backlog
entries from this report:

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium | T-62 residual | Align `blocklist.feed.sync`/`threatfeed.sync` audit actions to the `.refresh` verb (needs a safe audit-action alias approach, not a blind rename); separately, realign the new React frontend's Threat Intelligence tab wording/state to "Refresh" (component literals only; no OpenAPI change needed). Optional: rename the `syncThreatFeeds`/`syncBlocklistFeed` operation IDs with a bundle regeneration | Medium (audit strings); Low (frontend, default-off) | Small-Medium (audit); Medium (frontend, gated by full verify pipeline) |
| Low | T-63 | Mention the exclusion in the `decryption.autoexclude.learn` (and absent-entry evict) audit detail text so a search for "exclusion" finds them; or cross-reference "autoexclude" in `docs/operator/decryption-auto-exclusions.md` | Low | Small |
| Low | T-61 | Rename `culvert_auth_backend_*` → `culvert_identity_backend_*` with a dual-emission deprecation window (the T-31 precedent), only if a dedicated metrics-naming pass is ever scoped; otherwise an owner may close it as accepted, relying on the `metrics.go` cross-reference | High | Medium-Large |

Process-level (owned by DEBT-014, not restated here as a fresh recommendation): sync against `main`
immediately before opening a PR, not only at review-start, to catch a mid-review landing before writing a
redundant fix. Re-applied this pass: the pre-write fetch found no new commits past `3febe59` and no
overlap between this report's three findings and any file touched in the audited window.

---

## Process Note — claims corrected before merge

The automated PR review (`chatgpt-codex-connector`) found two errors in this report's first draft,
both verified against the source and corrected before merge:

- T-63 claimed a search for "exclusion" returns zero hits for every event of the feature. The Audit
  Log filter also matches `detail`, and most of the feature's details contain the word; only the
  `learn` event and the absent-entry evict are missed. T-63 was narrowed to that, and its recommended
  action and risk scaled down to match.
- T-62 renamed two buttons but left the flows they start reporting "Sync complete"/"Sync failed" and a
  per-feed "Sync" row button on the same panel, which created a same-panel mismatch. The coupled labels
  and status messages now say "Refresh" as well, including the failed-refresh toast, which used to
  echo the server's "sync failed:" prefix. API paths, JS handler names and audit action strings
  are unchanged.

---

A later reconciliation with the merged 2026-09-21 report (#1456) corrected four more:

- The audited window was `46410c3..3febe59`, declared free of admin-facing terminology changes. It
  overlapped the 2026-09-21 report's window, where that report found T-59, T-59b, T-59c, T-60 and the
  T-51 recurrence. The window is now `6c46ebd..3febe59`, and the earlier part is left to that report.
- The score (8.7, unchanged) and the backlog (fourteen IDs) came from the 2026-09-11 lineage and omitted
  T-54 through T-60 and the T-51 residual. They now follow the 2026-09-21 report's lineage and
  disclosure convention.
- "None previously tracked" was true of the backlog but not of the reports: each finding had been seen
  earlier without being recorded (see the Executive Summary).
- The `metrics.go` comment and T-61 said a metric name has "no safe aliasing seam" and that the prefix
  mismatch is "NOT drift". The T-31 dual-emission rename is a working precedent, and "not drift"
  contradicted the finding. Both are reworded. A stale "787 unit tests" count was also removed.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This report records three new open findings (T-61, T-62,
T-63). Two were partially addressed with zero-risk changes that close neither ID: a cross-referencing
code comment for T-61, and the legacy-GUI copy plus one doc-comment for T-62. They add no API, audit, or
metrics compatibility surface. The compatibility-sensitive halves (a Prometheus metric rename, the feed
audit-action alignment, the React frontend's "Sync" copy) and T-63's audit-detail wording are recorded
to the backlog with an explicit recommended action rather than force-fixed. Backlog: 27 IDs / 26
entries at the audited snapshot `3febe59` and after this PR's corrections; score 7.5 in both states
(lineage figures that omit T-54's 0.1 charge; fully charged 7.4). For comparison only, with the four
fixes merged after `3febe59` (T-57, T-58, T-17, T-59): 23 / 22 and 7.9 (fully charged 7.8). The
parallel 8.8 lineage of the 2026-09-20 report (#1444) is disclosed, not reconciled. The checks matched
literal patterns only (see Coverage limits). No cosmetic or preference-driven renames were proposed.
