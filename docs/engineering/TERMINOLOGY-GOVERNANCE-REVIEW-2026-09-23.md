# Culvert Language & Terminology Governance Review — 2026-09-23

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Snapshot scope (read this first):** this is a HISTORICAL record of `origin/main` at `3febe59` on
> 2026-09-23. It was merged later, after `main` had moved on, so the tree it ships in contains commits it
> never audited. Its findings, carried-over backlog and health score describe `3febe59` only. They are
> not a statement about the tree this file is published in; the current governance state is whatever the
> most recent review in this series says. Later windows are audited by later reports, never
> retroactively by this one.
> **Finding-ID note:** T-54–T-56 were numbered from the reports on `main` at `3febe59`. The 2026-09-19
> report (PR #1434, unmerged at the time) independently used **T-54** for an unrelated Rule Editor
> SSL/TLS label finding. Cite this report's identity-backend finding as "T-54 (2026-09-23)" to keep
> the two apart.
> **Method:** Audited `46410c3..3febe59` — the window since the 2026-09-11 report's own branch head
> (`46410c3`, PR #1363, merged to `main` in `0665453`),
> confirmed as the then-current `origin/main` HEAD by a fetch immediately before this report was written on 2026-09-23 (per
> the DEBT-014 lesson: sync against `main` right before opening a PR, not only at review-start, so a fix
> landed by a parallel branch is credited rather than re-claimed — re-confirmed clean this pass: `HEAD` is
> an ancestor of `origin/main` with zero unmerged local work). The window covers 31 first-parent merges,
> almost entirely CI-pipeline redesign work (`CI-REDESIGN` shard-adoption stages 1–5C) and the MCP-first
> canary rollout slices, plus the CHAOS-65 OCSP revocation-checking engine and a GeoIP-resolution
> operator-contract row addition — none of it admin-facing terminology surface. This pass then ran a
> fresh cross-surface audit (GUI ↔ REST API ↔ audit log ↔ Prometheus metrics ↔ alerts ↔ CLI/config),
> independent of the diff window, since terminology drift can be long-standing rather than newly
> introduced — this is how the 2026-09-09 report's T-53 and this report's three new findings were both
> found: neither was in the prior window's diff.

---

## Executive Summary

**Three genuinely new findings this pass (T-54, T-55, T-56), none previously tracked.** Two are partially
addressed now with zero-risk fixes; the underlying compat-sensitive halves of both, plus T-56 in full, are
recorded to the backlog rather than force-fixed, consistent with this program's standing rule to weigh
migration cost before renaming anything with a compatibility surface (Prometheus metric names, audit
action strings, generated OpenAPI operation IDs).

1. **T-54 — CHAOS-47 identity-backend outage: metric prefix disagrees with its own alert and
   operator-contract row.** `culvert_auth_backend_unavailable{,_total}` / `culvert_auth_backend_gated_denials_total`
   (metrics.go) name the exact condition the `identity_backend_unreachable` alert
   (`internal/alerts/store.go:28`, `auth_backend_health.go`) and the `identity_backend` operator-contract
   row (`diagnostics.go:648` `checkIdentityBackend`) both deliberately name "identity_backend" — the
   alert-store comment even explains *why* ("identity_backend_unreachable... Deliberately not
   `idp_unreachable`..."), showing the authors chose this vocabulary carefully everywhere except the
   metric prefix, which was left as the older "auth_backend" spelling. **Fixed this pass:** added a
   terminology-note comment at the metric-emission site (metrics.go, ahead of the three `culvert_auth_backend_*`
   `HELP`/`TYPE` lines) cross-referencing the alert and contract-row names and stating explicitly that the
   metric prefix is *not* renamed — a published Prometheus series name is a live dashboard/alerting-rule
   contract with no safe aliasing seam (unlike an internal alert-event string, which this codebase already
   has a documented rename path for via `normalizeEventNames`). **Not fixed:** the underlying prefix
   mismatch itself remains; renaming it is a genuine compatibility break and is left to the backlog as a
   deliberate, considered non-action rather than an oversight.

2. **T-55 — "manually re-fetch this feed now" uses two different verbs across four peer feed panels
   in the same admin UI.** Blocklist feed and Threat feed panels said "Sync" (GUI buttons *and* their
   audit actions `blocklist.feed.sync` / `threatfeed.sync`); the SaaS URL-category feed and Release
   Catalog panels — the two newest additions — already say "Refresh" (GUI buttons *and* audit actions
   `saasfeed.refresh` / `release.catalog.refresh`). These are structurally the same admin action
   ("pull fresh data from an external source on demand") on peer panels, so the verb an admin learns on
   one page does not carry to another — and the legacy threat-feed button's own icon (`#i-refresh`) already
   pointed at "refresh" as the more natural word before this fix. **Fixed this pass, GUI-copy only:**
   `static/index.html`'s "Sync All Now" → "Refresh All Now" (blocklist feed) and "Sync Feeds Now" →
   "Refresh Feeds Now" (threat feed), the per-feed row button, toast and status messages those two
   flows display, plus the one doc-comment in `internal/blocklistfeed/blocklistfeed.go` that quoted the
   old button label. Zero API/audit/compat
   surface — button text only; the underlying route paths, JS handler names, and audit action strings are
   unchanged. **Not fixed, recorded as residual:** the audit action strings themselves
   (`blocklist.feed.sync` / `threatfeed.sync` vs `saasfeed.refresh` / `release.catalog.refresh`) still
   disagree, so an admin who now clicks "Refresh All Now" and later searches the Audit Log for "refresh"
   still gets zero hits for the blocklist/threat-feed events — same class of compatibility caution this
   program already applies to audit/metric names, not force-fixed here. The **new React admin frontend**
   (`frontend/src/features/security/ThreatIntelTab.tsx`) independently uses "Sync" throughout — button
   label, component state (`syncing`/`syncError`/`syncNote`), and user-visible copy ("Sync completed…",
   "The sync request failed") — and its OpenAPI-generated operation IDs (`syncBlocklistFeed`,
   `syncThreatFeeds` in `frontend/src/api/types.gen.ts`, generated from the backend's OpenAPI bundle) carry
   the same verb. Realigning the new frontend requires a full `npm run verify` + 2-build determinism-gate
   cycle (the T-53 fix's own precedent) and, if the generated operation IDs are ever touched, a bundle
   regeneration — out of scope for this pass's zero-risk-only fix; recorded to the backlog as the larger
   half of this finding.

3. **T-56 — "Decryption Exclusions" (GUI/API) vs `decryption.autoexclude.*` (audit action prefix):
   the one event the feature exists for is not findable by the feature's displayed name.** The nav label
   (`static/index.html:773`, `data-view="decexclusions"`), the REST route (`/api/decryption-exclusions`,
   `ui_policy.go:3014`) and its JSON response field (`"exclusions"`, `ui_policy.go:970`) all say
   "exclusions", while every audit action for the feature is prefixed `decryption.autoexclude.*`.
   CLAUDE.md documents "autoexclude" as the *deliberate internal engine/package name*. The Audit Log's
   text filter (`renderAuditLog`) matches `detail` as well as `action`, and most of this feature's
   detail strings do say "exclusion" (manual evict, clear, tunables, surge, rescue), so a search for
   "exclusion" finds them. It misses two: `decryption.autoexclude.learn` — the automatic promotion of
   a host into the cache, whose detail reads "SSL inspection auto-disabled…" — and an evict request for
   an entry that was not present. (Corrected from this report's first draft, which claimed zero hits
   for every event; see the Process Note.) **Not fixed this pass**, recorded to the backlog as a
   narrow, low-priority item (see below).

**A candidate considered and declined:** a hand-coded "exclusion" ↔ "autoexclude" synonym in the Audit
Log's client-side filter. Declined as a one-term workaround rather than a naming decision that
generalizes; see T-56's recommended action.

**Terminology Health Score: 8.7 / 10** (unchanged from 2026-09-08 through 2026-09-11). The carry-over
backlog (fourteen IDs, thirteen entries) is unchanged (three of its higher-visibility items — T-12, T-29,
T-30 — were directly spot-checked against the then-current tree (`3febe59`) this pass, not merely assumed unchanged) and this pass's own two
small GUI-copy fixes are real but modest against it, matching the same reasoning the 2026-09-09 report gave
for holding the score rather than moving it for a small net-positive pass.

---

## Findings

### T-54 — CHAOS-47 identity-backend metric prefix diverges from its own alert and operator-contract row (new — partially fixed this pass)

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
  cross-reference explicitly and states — as a considered decision, not an omission — that the prefix is
  **not** being renamed, because a published Prometheus series name is a live dashboard/alerting-rule
  contract for deployed customers with no safe aliasing seam (unlike the alert-event-name rename path this
  codebase already documents via `normalizeEventNames`, which exists precisely because alert names *can*
  be migrated safely and metric series names generally cannot).
- **Affected code:** `metrics.go` (comment only, this pass).
- **Affected API:** none (comment-only change).
- **Affected GUI:** none.
- **Affected Documentation:** none beyond the added code comment.
- **Affected Configuration:** none.
- **Migration Complexity:** High, if ever executed as an actual rename (every deployed Grafana
  dashboard/Prometheus alerting rule referencing `culvert_auth_backend_*` would need to add the new series
  name, likely via a rename-with-both-names-exported transition period spanning at least one release).
- **Compatibility Risk:** High (published metrics are a monitoring contract; this program's own CLAUDE.md
  repeatedly calls metric/label names "a monitoring contract, pinned by test").
- **Estimated PR Size:** Small for the documentation fix shipped this pass; Medium-Large for an eventual
  metric rename (would need a deprecation window, likely a doubled-emission period, and its own dedicated
  review — not a terminology-only change).
- **Priority:** Low for the rename itself (compat risk exceeds the confusion it resolves, given the
  comment now bridges the gap for a reader); the documentation half is already resolved.

### T-55 — "Sync" vs "Refresh" for the same manual-refetch action across four peer feed panels (new — partially fixed this pass)

- **Business concept:** an admin manually forcing an on-demand re-fetch of an externally-sourced feed
  (blocklist feed, threat-intel feed, SaaS URL-category feed, or the release catalog) outside its normal
  periodic cadence.
- **Current names (before this fix):** "Sync All Now" (blocklist feed button, `static/index.html`) /
  `blocklist.feed.sync` (`ui_policy.go:384`); "Sync Feeds Now" (threat feed button, `static/index.html`) /
  `threatfeed.sync` (`ui_security.go:790`); "Refresh now" (SaaS feed button, `static/index.html:3474`) /
  `saasfeed.refresh` (`saas_feed_status_api.go:110`); "⟳ Refresh catalog" (release catalog button,
  `static/index.html:5125`) / `release.catalog.refresh` (`release_api.go:472,482`).
- **Recommended canonical name:** "Refresh" — already the verb on two of the four panels (including both
  of the more recently added ones), and the threat-feed panel's own pre-existing icon (`#i-refresh`) was
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
  feeds…"/"Sync complete."/"Sync failed:" → "Refreshing…"/"Refresh complete."/"Refresh failed:"). The
  periodic-schedule wording ("Blocklist Feed Auto-Sync", "Sync Interval", "Last Sync") describes the
  automatic cadence, not the manual action, and is left as is. (The coupled strings were added after
  review; see the Process Note.) Updated the one Go doc-comment quoting the old label
  (`internal/blocklistfeed/blocklistfeed.go`, `SyncAll`'s doc comment). No route, JS handler name, or
  audit action string was touched. `go build ./...` and `go vet
  ./...` both pass clean after the change; `gofmt -l` reports no diff.
- **What remains (recorded, not fixed):**
  - The audit action strings `blocklist.feed.sync` / `threatfeed.sync` still disagree with
    `saasfeed.refresh` / `release.catalog.refresh` — the Audit Log UI text-filters on the raw action
    string, so this pass's GUI fix alone does not make the Audit Log searchable by one consistent verb.
  - `frontend/src/features/security/ThreatIntelTab.tsx` (the new React admin frontend, disabled by default
    behind `CULVERT_EXPERIMENTAL_UI`) independently says "Sync" — button label, component state
    (`syncing`/`syncError`/`syncNote`), and user-visible strings ("Sync completed — N entries.", "The sync
    request failed.") — sourced from the OpenAPI-generated `syncThreatFeeds`/`syncBlocklistFeed` operation
    IDs in `frontend/src/api/types.gen.ts`, which are themselves generated from the backend's OpenAPI
    bundle. Realigning this surface needs a full frontend text/state-variable pass plus the `npm run
    verify` (787 unit tests, lint, format, strict typecheck) + two-build determinism-gate cycle the
    2026-09-09 report's T-53 fix required, and, only if the operation IDs themselves are renamed, an
    OpenAPI bundle regeneration — none of which is a same-pass, zero-risk change.
- **Affected code:** `static/index.html` (2 button labels + the coupled row button, toast and status
  strings), `internal/blocklistfeed/blocklistfeed.go`
  (1 doc comment) — this pass. Residual: `frontend/src/features/security/ThreatIntelTab.tsx` and the
  OpenAPI bundle, for a future pass.
- **Affected API:** none this pass (residual: OpenAPI operation IDs, if ever renamed).
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

### T-56 — "Decryption Exclusions" (GUI/API) vs `decryption.autoexclude.*` (audit action) — the learn event can't be found by the feature's displayed name (new — not fixed this pass)

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
  vocabulary (`internal/autoexclude`, `culvert_decrypt_autoexclude_*`), so unlike T-54/T-55 this is not a
  case of two competing business names; it is one deliberately-named internal concept whose vocabulary
  happens to also be the only vocabulary present in the one admin-visible surface — the Audit Log — that
  is supposed to be searchable by the *displayed* feature name.
- **Why the current naming is problematic:** the Audit Log UI text-filters on `action`, `object`,
  `objectId`, `actor` and `detail` (`static/index.html`, `renderAuditLog`). No action string contains
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
  T-55's residual half above). A narrow client-side synonym special-case in the Audit Log's text filter
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

## Carried-Over Findings (unchanged)

All fourteen previously-open finding IDs (thirteen backlog entries, since T-21 and T-32 are tracked as one
paired item) remain open, unchanged, and were re-confirmed against the then-current tree (`3febe59`): T-9, T-11, T-12,
T-13 (residual), T-17, T-18, T-21+T-32 (paired), T-25 (residual), T-29, T-30, T-33, T-34, T-39. Three were
spot-checked directly rather than assumed (`T-12`: `cmd/culvert-maint/internal/server/handlers_upgrade.go`
still serves `/v1/upgrades/check` unchanged; `T-29`: `rate_limit_rpm` is still absent from `config.go`;
`T-30`: `conn_limit_max_per_ip` is still absent from `config.go`). Full descriptions and the priority-
ordered refactoring plan for these are unchanged from `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md` (most
recently re-confirmed in the 2026-09-11 report) and are not restated here to avoid drift between two
descriptions of the same open items.

The "Content & Scanning" vs. "Content Security" soft finding (design-document reconciliation between two
deliberate naming decisions, not a mechanical rename) also remains unresolved and is not queued to the
numbered backlog, per 2026-09-09's reasoning.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 2026-09-09/09-11 for the carried-over items (see that report for the full table); T-54 and
the shipped half of T-55 are resolved to the extent zero-risk action allows and do not appear on the
priority table below. New backlog entries from this pass:

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium | T-55 residual | Align `blocklist.feed.sync`/`threatfeed.sync` audit actions to the `.refresh` verb (needs a safe audit-action alias approach, not a blind rename); separately, realign the new React frontend's Threat Intelligence tab wording/state to "Refresh" and regenerate the OpenAPI bundle only if the operation IDs are touched for another reason | Medium (audit strings); Low (frontend, default-off) | Small-Medium (audit); Medium (frontend, gated by full verify pipeline) |
| Low | T-56 | Mention the exclusion in the `decryption.autoexclude.learn` (and absent-entry evict) audit detail text so a search for "exclusion" finds them; or cross-reference "autoexclude" in `docs/operator/decryption-auto-exclusions.md` | Low | Small |
| Low | T-54 residual | Rename `culvert_auth_backend_*` → `culvert_identity_backend_*` with a doubled-emission deprecation window, only if a dedicated metrics-naming pass is ever scoped | High | Medium-Large |

The full carried-over priority table (T-9 through T-39) is unchanged from 2026-09-09 and is not repeated
here — see that report.

Process-level (owned by DEBT-014, not restated here as a fresh recommendation): sync against `main`
immediately before opening a PR, not only at review-start, to catch a mid-review landing before writing a
redundant fix. Re-applied this pass: the pre-write fetch found no new commits past `3febe59` and no
overlap between this pass's three findings and any file touched in the audited window.

---

## Process Note — two claims corrected after review

The automated PR review (`chatgpt-codex-connector`) found two errors in this report's first draft,
both verified against the source and corrected before merge:

- T-56 claimed a search for "exclusion" returns zero hits for every event of the feature. The Audit
  Log filter also matches `detail`, and most of the feature's details contain the word; only the
  `learn` event and the absent-entry evict are missed. T-56 was narrowed to that, and its recommended
  action and risk scaled down to match.
- T-55 renamed two buttons but left the flows they start reporting "Sync complete"/"Sync failed" and a
  per-feed "Sync" row button on the same panel, which created a same-panel mismatch. The coupled labels
  and status messages now say "Refresh" as well. API paths, JS handler names and audit action strings
  are unchanged.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass found three genuinely new findings (T-54, T-55, T-56),
none previously tracked by any prior review in this program. Two were partially addressed with small,
zero-risk fixes (a cross-referencing code comment for T-54; two GUI button-label edits plus one doc-comment
correction for T-55) that add no API, audit, or metrics compatibility surface — confirmed via a clean
`go build ./...`, `go vet ./...`, and `gofmt -l` after the change. The compatibility-sensitive halves of
all three findings (a Prometheus metric rename, the feed audit-action-string alignment, T-56's audit
detail wording, and one React-frontend text/state pass) were deliberately **not** force-fixed, consistent with this program's standing rule to
weigh migration cost — each is recorded to the backlog with an explicit recommended action rather than
silently dropped. The carry-over backlog (fourteen IDs, thirteen entries: T-9, T-11, T-12, T-13, T-17,
T-18, T-21+T-32, T-25, T-29, T-30, T-33, T-34, T-39) is unchanged, with three higher-visibility items
independently spot-checked against the then-current tree (`3febe59`) rather than assumed. No cosmetic or preference-driven renames were proposed.
