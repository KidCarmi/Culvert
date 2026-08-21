# Culvert Language & Terminology Governance Review — 2026-07-17

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Three parallel audits — (1) source code / REST API / config-surface naming,
> (2) admin GUI vs. operator docs vs. roadmap reference docs, (3) audit log / metrics / alerts /
> SSE event naming — cross-referencing `static/index.html`, `ui_routes_meta.go`, `docs/`,
> `roadmap/`, and the relevant Go packages. Builds on the prior review at
> `docs/engineering/TERMINOLOGY-GOVERNANCE-REVIEW-2026-07-07.md` (tree `ea0f2ff`); findings
> already resolved or explicitly triaged there (T-1 through T-9) are not re-litigated here.
> **Companion change:** three low-risk fixes ship with this review (see "Fixed in this change").

---

## Executive Summary

The 2026-07-07 review found Culvert's product language "unusually disciplined," and this pass
confirms that holds up two weeks later — no new drift was found in the core business-concept
clusters (auth/session/RBAC, policy engine, cluster/CP-DP, scanning). The drift found this pass is
narrower and falls into two categories: **stale reference documentation** (roadmap docs that
described an earlier GUI milestone and were never refreshed after subsequent renames) and **alert
vocabulary that diverges from the log/metric vocabulary for the same event**, both lower-severity
than anything found in the prior pass.

**Terminology Health Score: 8.5 / 10** (unchanged — the discipline is holding; this pass finds
maintenance debt in reference docs rather than genuine new naming conflicts).

**Fixed in this change:** 3 items, all zero compatibility risk (2 doc-only, 1 comment + GUI-copy
tooltip). **No renames of stable identifiers, API routes, JSON/wire fields, CLI flags, alert event
names, or Go types were made.**

---

## Findings

### T-10 — `roadmap/UI-DESIGN.md` and `roadmap/FEATURE-COVERAGE.md` stale against the live sidebar (FIXED)
- **Business concept:** the admin GUI's panel inventory (names, `data-view` ids, backing API
  routes).
- **Current names before fix:** both files documented an 18-panel sidebar from an earlier
  milestone using labels since renamed in the live GUI — "Live Feed" (now "Traffic"), "Policy
  Rules"/"Policy" (now "Access Rules"), "File Blocking" (now "File Control"), "Users" (now
  "Administrators") — and a standalone "HA Failover" panel (`data-view="ha"`, routes
  `/api/ha/status`/`/api/ha/enable`/`/api/ha/promote`) that no longer exists in any form: HA is
  now a section inside the single "Cluster" panel, and the routes it documented have been
  replaced by `/api/cluster/ha` and `/api/cluster/ha/promote`. The live sidebar has grown to 27
  items (9 panels — Decryption Exclusions, Authentication Rules, CDR, Category Groups, Decryption
  Profiles, CA Management, Releases, Diagnostics, Support, Governance — were entirely missing from
  both files).
- **Why this is a genuine problem:** CLAUDE.md itself directs readers to these exact two files
  ("`roadmap/UI-DESIGN.md` for panel design reference", "`roadmap/FEATURE-COVERAGE.md` for GUI
  coverage audit") with no superseded caveat. A support engineer, new contributor, or
  documentation writer following CLAUDE.md's own pointers to correlate a GUI screen with its name
  or backing API would land on renamed or deleted panel names and dead API routes — exactly the
  cross-surface correlation failure this review exists to catch, one level removed (it hit the
  project's own reference docs rather than user-facing operator docs).
- **Fix:** both files refreshed to the current 27-panel sidebar (verified against
  `static/index.html` and `ui_routes_meta.go`), with a note pointing at CLAUDE.md's project
  structure table and `ui_routes_meta.go`'s `uiRoutes` as the canonical sources of truth going
  forward, so this table is understood as a refreshable snapshot rather than the primary
  reference.
- **Priority:** Medium (real correlation-failure risk for anyone following CLAUDE.md's pointers).
  **Migration risk:** none — doc-only, no code/API/GUI change.

### T-11 — Alert event `threat_detected` uses different vocabulary than every other surface for the same event (FIXED, copy-only)
- **Business concept:** a request body blocked by ClamAV, YARA, or the DPI/threat-feed scanner.
- **Current names:** log entries say `THREAT_BLOCKED` / `SCAN_BLOCKED` / `DPI_BLOCKED`
  (`proxy.go`, `proxy_http.go`, `scanner.go`); Prometheus metrics say
  `culvert_{clamav,yara,dpi,threat_feed}_blocked_total` (`metrics.go`); the GUI's own webhook
  event checkbox said "Threat detected" — every surface but the alert event name itself says
  **"blocked."** The alert event name `threat_detected` is the one outlier using "detected."
  A security engineer correlating a firing alert against Prometheus dashboards or the audit/log
  feed for the same incident has to know, out of band, that "detected" here means "blocked," not
  merely observed.
- **Why no wire rename:** `threat_detected` is a value administrators actively select when
  configuring alert webhooks (`Security → Alert Webhooks`, persisted in each webhook's `events`
  list). Renaming the wire string would silently break every existing webhook subscription on
  upgrade — this fails the "always consider migration cost" bar for a cosmetic-vocabulary fix, so
  the event name itself is being **left exactly as-is**, matching the T-1 precedent (URL/wire
  stability over an internal-naming nicety).
  **Recommendation for a future major version:** if the alert-event surface is ever revisited for
  a breaking reason, fold a `threat_detected` → `threat_blocked` rename into that batch (with a
  read-compat alias on webhook config load), rather than shipping it standalone.
- **Fix shipped now (zero risk):** the GUI checkbox label changed from "Threat detected" to
  "Threat blocked" (display-only; the underlying `value="threat_detected"` — and therefore every
  persisted webhook subscription — is unchanged) with an added tooltip stating exactly which log
  statuses trigger it. The `internal/alerts/store.go` event-catalog comment was expanded to name
  the log statuses and metrics explicitly and to record why the event name itself wasn't touched.
- **Priority:** Low (display/comment clarity only — the wire contract is untouched).
  **Migration risk:** none.

### T-12 — `RateLimitExempt` / `ConnLimitMaxPerIP` carry different JSON keys across the three config surfaces that are supposed to represent the same field (no action — documented for future reference)
- **Business concept:** (a) the rate-limit exemption list (IPs/CIDRs skipped by the limiter) and
  (b) the per-IP connection cap — both are single logical settings synced across three surfaces:
  `configBackup` (export/rollback), `AdminSettings` (restart durability), and `ConfigSnapshot`
  (CP→DP sync).
- **Current names:**
  - Rate-limit exemptions: `configBackup.RateLimitExempt` → `json:"rateLimitExempt"`
    (`ui_policy.go`); `AdminSettings.RateLimitExemptions` → `json:"rate_limit_exemptions"`
    (`admin_settings.go`); `ConfigSnapshot.RateLimitExempt` → `json:"rate_limit_exempt"`
    (`controlplane_snapshot.go`) — three different spellings (camelCase, pluralized snake_case,
    singular snake_case) for the same list.
  - Per-IP connection cap: YAML config and `ConfigSnapshot` agree on `max_conns_per_ip`, but
    `AdminSettings`/`configBackup` uses `ConnLimitMaxPerIP` → `json:"conn_limit_max_per_ip"`
    (`admin_settings.go`) — an operator diffing a `config.yaml` against a config export would not
    find the same key for the same setting.
- **Why this looks like drift but is architecturally understood:** `config_surfaces.go` — "the
  anti-drift wall" per CLAUDE.md — already declares these three surfaces' field *membership* and
  is enforced by `config_surfaces_test.go`. What the registry does not (and by design cannot,
  since it's a Go reflection parity test, not a JSON-schema linter) catch is *naming* drift
  between the three JSON representations of the same logical field.
- **Why no action was taken:** `rate_limit_exemptions` is the persisted `admin_settings.json` key
  and `rate_limit_exempt` is the live CP→DP wire key for existing clusters; `conn_limit_max_per_ip`
  is likewise persisted. Renaming any of them breaks restart durability or cluster sync for
  currently-running deployments on upgrade — a real, non-cosmetic migration cost, and exactly the
  kind of change this routine's charter says to flag rather than execute unilaterally.
- **Recommendation:** if these surfaces are ever touched for another reason, align the JSON key
  spelling (pick one casing/pluralization convention) with a read-compat fallback for the old
  key(s) on load — mirroring the T-9 `exportedAt`→`capturedAt` recommendation from the prior
  review, which faces the identical persisted-format constraint.
- **Priority:** Low (naming-only; the registry already prevents membership/semantic drift; no
  admin-facing surface shows two of these three JSON forms side by side today).
  **Estimated PR size:** medium — touches `admin_settings.go`, `controlplane_snapshot.go`,
  `ui_policy.go`, `config_surfaces.go`, `config_surfaces_test.go`, plus a read-compat path for
  on-disk `admin_settings.json` and in-flight `ConfigSnapshot` messages from older DP nodes.

### Reviewed, no action warranted
- **`cert_expiry` alert reused for CP rotation-success and DP renewal-failure.** A real
  vocabulary tension (the CP path fires it on every successful rotation; the DP path fires it only
  when renewal is genuinely failing near expiry) — but this is **not new drift**: it is already a
  tracked, named gap (**GAP-PKI-05**) in `docs/engineering/ENTERPRISE-IMPLEMENTATION-GAP-REGISTER.md`,
  `docs/engineering/ENTERPRISE-FEATURE-OPPORTUNITIES.md`, and multiple chaos-engineering reviews,
  with its own recommended remediation on file (implement the missing independent ≤30-day startup
  watchdog; fix the stale doc claim) — and `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-07-11.md`
  records that reusing the `cert_expiry` event type for the DP path was a **deliberate** choice so
  a single existing webhook subscription covers both. Renaming or splitting the event now would
  cut across that already-decided remediation plan. Out of scope for a terminology-only pass;
  deferred to whoever picks up GAP-PKI-05.
- **`internal/scanexcl` ("exclusion") vs. `internal/scanner.ContentScanner` bypass-host list
  ("bypass") using different verbs for "skip scanning this host."** These are genuinely two
  separate engines (full ClamAV+YARA skip vs. DPI-only skip), and the admin-facing risk this
  naming split could cause was already the subject of the prior review's T-3 fix: the GUI panel
  (`static/index.html`) labels them "Full Content Scan Exclusions (ClamAV + YARA)" and
  "DPI-Only Bypass Hosts" with each description explicitly cross-referencing and scoping the
  other ("Broader than the DPI-only bypass below" / "Narrower than the full content scan
  exclusions above"). The remaining "exclusion" vs. "bypass" split is confined to internal Go
  identifiers (`IsHostExcluded` vs. `BypassHosts()`) never surfaced to an admin, and does not meet
  this review's bar for a recommended change.

---

## Recommended Refactoring Plan (priority order)

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Low | T-12 | Align `RateLimitExempt`/`ConnLimitMaxPerIP` JSON key spelling across `configBackup`/`AdminSettings`/`ConfigSnapshot`, with read-compat aliases | Medium (persisted file + CP→DP wire format) | Medium |
| Informational | `cert_expiry` | No action — already tracked as GAP-PKI-05 with its own remediation plan | N/A | N/A |
| Informational | `scanexcl`/bypass | No action — admin-facing risk already resolved by prior T-3 fix; internal-only split remaining | N/A | N/A |

T-10 and T-11 are fixed in this change (doc refresh + copy/comment clarification, zero
compatibility risk) and require no further action.

---

## Stop-Condition Assessment

Terminology is **not** already fully consistent — two concrete, zero-risk fixes shipped with this
review (T-10, T-11), and one further finding (T-12) is recommended for a deliberate follow-up PR
given its persisted/wire-format migration surface, consistent with how the prior review handled
T-9. No cosmetic or preference-driven renames are proposed, and no stable API, JSON wire field, or
alert event name was renamed in this pass.
