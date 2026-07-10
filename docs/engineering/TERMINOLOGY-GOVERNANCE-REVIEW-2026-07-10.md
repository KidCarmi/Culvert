# Culvert Language & Terminology Governance Review — 2026-07-10

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Three parallel concept-cluster audits — (1) authentication/identity/session,
> (2) release catalog/cluster/HA, (3) policy engine/blocklist/content scanning/SSL — each
> cross-referencing source code, REST API, GUI copy (`static/index.html`), CLI/env, audit/log
> messages, metrics, and docs. Findings verified against the tree at `8e88a40`, following up on
> the prior review at `ea0f2ff` (`TERMINOLOGY-GOVERNANCE-REVIEW-2026-07-07.md`).
> **Companion change:** two low-risk fixes ship with this review (see "Fixed in this change").
> One prior deferred item (T-8) is partially closed. One new finding (T-10) is documented and
> deferred, matching the migration-risk bar the prior review set for T-9.

---

## Executive Summary

This pass re-verified all "clean" clusters from the 2026-07-07 review still hold at `8e88a40`
(they do — no drift reintroduced) and extended coverage to the newer M1-3 release-alerting code,
which hadn't existed at the time of the prior review. Two small issues were found and fixed; one
prior deferred item (T-8) was investigated in detail and partially closed; one new, larger finding
(T-10) is documented for a future deliberate pass rather than folded in here, consistent with how
T-9 was handled last time.

Notably, investigating T-8 (`listAccessRules`/`validateAccessRule` vs. the GUI's "Policy Rule"
label) surfaced a **fix that turned out to be wrong on the first attempt**: `ui_helpers.go`
already has a `validatePolicyRule` dispatcher that validates *both* Stage-1 and Stage-2 rules and
delegates to the Stage-2-only helper. Renaming the Stage-2 helper to the same name collides
(confirmed by a failed `go build`). This means the "access rule" name is not pure drift — it's
partly load-bearing to stay distinct from the umbrella dispatcher. `listAccessRules` (no such
collision) was renamed to `listPolicyRules`; `validateAccessRule` was kept, with a comment
explaining why.

**Terminology Health Score: 8.5 / 10** (unchanged — this pass found nothing that shifts the prior
score; the new finding, T-10, is real but was already latent at the last review's cutoff and is
appropriately sized for a dedicated follow-up, not a same-day fix).

**Fixed in this change:** 2 items — 1 comment/identifier clarification (T-8, partial), 1
doc-comment disambiguation in the new release-alerting file (F-1). **No renames of stable REST API
routes, JSON fields, CLI flags, config keys, or exported Go types were made** — every fix in this
pass is a private-identifier rename or a comment change with zero compatibility risk.

---

## Re-verified clean (no new drift since 2026-07-07)

`defaultAuthOutcome`/`UnauthMode`, session-cookie naming (`ps_session` vs `ps_ui_session`), IdP/SSO
terminology, threat-feed vs blocklist vs blocklist-feed, URL category naming, CDR, Zero
Trust/default-deny, bandwidth/QoS, node groups, CP/DP/enrollment naming, fencing-lease/term
equivalence (the T-5 GUI note from the prior review is still present and accurate at
`static/index.html:3135-3138`), config-version/export/snapshot three-surface split, and Policy Rule
naming in the GUI/API/metrics layer (audited independently this pass, no drift found — see
Findings, T-8).

---

## Findings

### F-1 — "Canary" reused for an unrelated concept in the new release-alerting code (FIXED)
- **Business concept:** the M1-3 release-catalog staleness/failure alerting feature
  (`release_alerts.go`), new since the 2026-07-07 review.
- **Current names before fix:** the file's own header comment called itself "Release-catalog
  detection / canary / alerting," but the file implements no staged rollout — only
  staleness/failure alerts. `update_cluster.go` already owns "canary" for its real staged-rollout
  mechanism (`CanaryCount`, `CanarySoak`, phase `"canary"`/`"canary_soak"`). The design doc
  (`roadmap/M1-DETAILED-DESIGN.md:59,72-73`) already disclaims the redefinition, but the word
  survived in the source file header.
- **Fix:** reworded the `release_alerts.go` header to "detection / freshness alerting" and added a
  one-line note explaining why "canary" is deliberately avoided here.
- **Why this matters:** low admin-facing risk (the word never reaches the GUI or `/api/releases`
  JSON — verified by grep), but a real developer-facing trap: someone who knows
  `update_cluster.go`'s canary feature and then reads this file's header in the same
  release-management domain could expect staged-rollout semantics that don't exist.
- **Priority:** Low. **Migration risk:** none — comment-only.

### T-8 — `PolicyRule`/"access rule" internal-vs-external naming split (PARTIALLY FIXED)
- **Business concept:** Stage-2 FQDN/category/GeoIP/schedule matching rule, called "Policy Rule"
  in the GUI/API (`/api/policy`, "Add Policy Rule" — `static/index.html:2168`) and specifically
  "access rule" (vs. Stage-1 "auth rule") in internal code/comments.
- **Investigation this pass:** confirmed the GUI cleanly separates "Policy Rule" (Stage-2 only,
  `data-view="policy"`) from "Auth Rule"/"Auth Policy Rule" (Stage-1 only,
  `data-view="authpolicy"`) — so "Policy Rule" in the GUI/API genuinely means the same thing as
  internal "access rule," confirming the prior review's read of the split.
- **Fix applied:** `listAccessRules` (`ui_policy.go:1070`, no name collision) renamed to
  `listPolicyRules` to match the GUI/API term; its two call sites updated.
- **Fix NOT applied, and why:** `validateAccessRule` (`ui_helpers.go:155`) was **not** renamed to
  `validatePolicyRule` — that name is already taken by the dispatcher at `ui_helpers.go:105`,
  which validates *both* Stage-1 and Stage-2 rules and calls the Stage-2-only helper internally.
  A same-name rename fails to compile (confirmed). Instead, `validateAccessRule`'s doc comment now
  explains the naming split is intentional (distinct from the two-rule-type dispatcher), so a
  future reader doesn't rediscover this the hard way.
- **Assessment:** the "access rule" internal name is not pure drift — for the validator it is
  partly a necessary disambiguator from the dispatcher's name. For the lister, no such constraint
  existed, so that half of T-8's original recommendation was completed. **T-8 is now closed** —
  the remaining "access rule" occurrences (in `policy.go`, `authpolicy.go`, `ui_authpolicy.go`,
  and test files) consistently mean "the Stage-2 half of a `PolicyRule`," which is accurate,
  intentional, and now documented at the one place (`ui_helpers.go:151-154`) where it could be
  mistaken for drift.
- **Priority:** Low. **Migration risk:** none (private Go identifiers only).

### T-10 — `content_scan_*` config/API naming vs. "DPI" GUI/log/metrics naming (new — documented, not fixed)
- **Business concept:** the regex-based response-body signature scanning engine.
- **Current names:**
  - Config/YAML: `content_scan_file`, `content_scan_patterns` (`config.go:29-30`;
    `config.example.yaml:36-37`) — and the `config.go` field comment itself says "DPI signature
    patterns," i.e. the source-of-truth struct field is documented using the *other* name.
  - Go type: `ContentScanner` (`scanner.go:18-21`).
  - REST API: `/api/content-scan`, `/api/content-scan/bypass` (`ui_security.go:1307`); JSON
    fields `contentScanPatterns`, `contentScanBypassHosts` (`ui_policy.go:747,825`); audit events
    `content_scan.add`/`content_scan.remove` (`ui_security.go:344,361`).
  - GUI labels: "DPI Signatures" (`static/index.html:568`), "DPI-Only Bypass Hosts"
    (`static/index.html:1166`).
  - Logs/metrics: `"DPIScan: ..."` (`inspection_rules.go:71,78`), `DPI_BLOCKED` (`scanner.go:61`),
    `culvert_dpi_blocked_total` (`metrics.go:338`).
- **Why this is real drift:** an admin editing `config.yaml` finds `content_scan_*` keys but sees
  "DPI" everywhere in the UI/logs; grepping logs for "content_scan" or the config file for "dpi"
  both fail. This is a genuine same-concept/two-names split spanning a config file, a REST API, and
  an operator-facing log stream — likely accidental (the config/API layer kept an early internal
  name while the UI/observability layer independently adopted the more precise industry term "DPI"
  for the same feature).
- **Why it is NOT fixed in this pass:** unlike F-1 and T-8, this touches externally-visible
  contracts — YAML config keys an operator may have in a deployed `config.yaml`, JSON API field
  names a scripted integration may parse, and audit-event-name strings a SIEM rule may match on.
  That crosses the same risk threshold the prior review used to defer T-9 (a wire/on-disk field
  rename) rather than fold it into a same-day, zero-risk pass.
- **Recommendation:** pick "DPI" as canonical (it's already unanimous across GUI, logs, and
  metrics — only config/API/audit lag behind) and, in a dedicated follow-up PR: (1) add `dpi_file`/
  `dpi_patterns` as the primary YAML keys with `content_scan_file`/`content_scan_patterns` accepted
  as a deprecated, logged-on-use alias; (2) mirror the same alias pattern for the JSON API fields
  (`dpiPatterns`/`dpiBypassHosts` primary, old names accepted on read); (3) rename the audit event
  names to `dpi.add`/`dpi.remove` (audit event names are not currently treated as a stable external
  contract elsewhere in the codebase, so this one is lower-risk than the config/API alias work);
  (4) update `config.example.yaml` and any operator docs referencing `content_scan_*`.
- **Priority:** Medium (genuine operator/support/SIEM-integration confusion; no functional bug).
  **Estimated PR size:** medium — touches `config.go` (resolver + alias), `ui_policy.go`,
  `ui_security.go`, `scanner.go` comments, `config.example.yaml`, and needs a config-load test
  proving the deprecated alias still works.

### Soft findings — no action recommended
- **OIDC names two unrelated auth mechanisms** (`auth_oidc.go`'s legacy proxy-CONNECT token
  introspection vs. `auth_oidc_flow.go`'s IdP-profile Authorization-Code+PKCE flow): both
  legitimately called "OIDC" since both implement parts of the OIDC spec, for genuinely different
  flows. The legacy `proxy.oidc` config block has no GUI exposure, so admin-facing confusion risk
  is low; `CLAUDE.md` already disambiguates by filename for developers. No change recommended.
- **Three similarly-shaped "feed" concepts** (blocklist feed / threat feed / SaaS-category feed)
  are cleanly named and technically distinct in code and GUI, but rely entirely on GUI prose
  (rather than the names themselves) to stay distinct for a first-time admin. Worth a future
  glossary callout in operator docs; not urgent enough to be a standalone finding.

---

## Recommended Refactoring Plan (priority order)

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium | T-10 (new) | Alias `content_scan_*` config/API/audit names to `dpi_*`, keep old names as deprecated read-compat aliases | Medium (config file + API + SIEM-facing audit strings) | Medium |
| Medium | T-9 (carried over, still open) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium (on-disk format, parity-test surface) | Medium |
| Informational | T-1 (carried over, no action) | `/api/settings/unauth-mode` route name — already a documented, deliberate decision | N/A | N/A |

T-8 is now closed (partially fixed this pass, remainder reclassified as intentional and
documented). F-1 is fixed in this change.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent — one new, real finding (T-10) surfaced this pass, plus
two small fixes shipped (F-1, T-8-partial). T-10 and the carried-over T-9 are both correctly sized
for a dedicated follow-up rather than a same-day fix, per the same migration-cost bar the prior
review applied. No cosmetic or preference-driven renames were proposed or made; every change in
this pass traces to a genuine cross-surface naming question, including one (T-8's
`validateAccessRule`) that on investigation turned out to be *not* worth changing — recorded here
so a future pass doesn't re-attempt the same collision.
