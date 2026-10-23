# Culvert Language & Terminology Governance Review — 2026-09-20

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Re-verified the tree at `3d8c9bb` (the current `origin/main` HEAD, confirmed by a fetch
> immediately before this report was written, per the DEBT-014 process lesson) against the open backlog
> the 2026-09-11 report carried forward, sampling the feature areas most likely to have drifted since
> (Upstream Proxies, PAC, CDR, Decryption Exclusions, Release Management, MCP Gateway, Policy Learning,
> HA/Cluster, Alerts/Webhooks, Support Bundles). No new drift was found in that sample. This pass instead
> **fixes T-17**, the longest-standing "documented, not fixed" item in the backlog (open since
> 2026-07-19, carried unchanged across roughly thirty subsequent reports), using the exact additive/
> backward-compatible alias strategy the backlog entry itself specified — the T-10 DPI precedent.
> **Companion change:** this report's fix is landed in the same PR as the report.

---

## Executive Summary

No new terminology drift was found in the sampled feature areas. **T-17 is fixed in this pass**: the
traffic-log destination-privacy admin surface now has a canonical name (`/api/traffic/redaction`)
matching its actual scope, with the prior name (`/api/decryption/redaction`) retained as a fully
supported, non-deprecated alias — zero breaking changes, mirroring exactly how T-10 (`/api/dpi` vs.
`/api/content-scan`) was resolved.

**Terminology Health Score: 8.8 / 10** (up from 8.7 — the oldest open item in the backlog is now fixed;
the remaining twelve backlog entries are unchanged in scope and priority).

**Fixed in this change:** T-17 — the destination-privacy REST route now has a canonical name consistent
with its true, fleet-wide-per-sink scope, via an additive alias with zero breaking changes.

---

## Findings

### T-17 — Traffic-log destination-privacy config key still says "decryption" after its scope expanded (FIXED — route half)

- **Business concept:** the destination-privacy (pseudonymization) toggle for traffic-log entries.
- **Before:** the toggle governs **every** traffic-log sink (plain HTTP and `TUNNEL_CLOSED` entries
  included, not just decrypted sessions — see `roadmap/PR3-privacy-posture-v2-DECISION.md`'s Option B),
  but the only user-facing identifier that still said "decryption" instead of "traffic" was the REST
  route: `GET/PUT /api/decryption/redaction`. The GUI label ("Pseudonymize destination in traffic logs")
  and the API's own `scope`/`scope_fields` response fields (`"traffic_destination"`) already described
  the true scope correctly — this was a route-name-only mismatch for anyone reading the config/API
  surface without the GUI label in view.
- **Fix (additive, zero breaking changes):**
  1. **REST API:** added the canonical route `/api/traffic/redaction` (same handler,
     `apiDecryptionRedaction`, registered a second time in `ui_policy.go`); `/api/decryption/redaction`
     remains registered as a permanent, fully supported alias — not deprecated for removal, per
     `docs/api/API-DEPRECATION-POLICY.md`'s "Legacy aliases" section, which explicitly names the
     `/api/content-scan` → `/api/dpi` pair as the model to follow. `ui_routes_meta.go` route count
     245 → 246 (mirrors the T-10 precedent of adding a canonical route alongside a retained legacy
     alias); `d0KnownRoutes`/`TestD0_RouteInventory_Locked141` and
     `TestC1_RouteMetadata_Locked141` bumped and re-verified green, along with C1 reverse parity and
     C1.5 AST-based `MinRole`/`Mutating`/`AuditExpected` parity.
  2. **OpenAPI contract:** `/api/traffic/redaction` carries the full canonical operation definitions
     (`getTrafficRedaction`/`setTrafficRedaction`) in `api/openapi/openapi.yaml`;
     `/api/decryption/redaction` keeps its existing operation IDs
     (`getDecryptionRedaction`/`setDecryptionRedaction`, unchanged so nothing downstream that keys on
     them breaks) with summaries/descriptions marked "(legacy alias)", mirroring the
     `/api/dpi` ↔ `/api/content-scan` spec pattern exactly. `api/route-classification.yaml` gained the
     two new rows; `make api-bundle` regenerated the derived JSON/HTML/inventory artifacts; the full
     `make api-verify` gate (bundle-check, style-lint, Gate 1–3 route/spec/manifest coverage, contract
     tests) passes.
  3. **Regression test:** `TestApiDecryptionRedaction_CanonicalRouteAlias`
     (`decryption_redaction_test.go`) wires the real admin mux and asserts both paths resolve to the
     identical handler and produce a byte-identical `GET` response.
  4. **Operator doc:** `docs/operator/traffic-log-destination-privacy.md` now leads with the canonical
     `/api/traffic/redaction` path throughout (TL;DR, §3 enable, §4 rotate, §5 verify, §10 quick
     reference) with an explicit note that `/api/decryption/redaction` remains a fully supported alias
     for existing scripts/integrations.
- **Deliberately NOT touched in this pass** (per the backlog entry's own scoping, and the same boundary
  T-10 drew around its own persisted-field residual): the `AdminSettings.DecryptionRedactHosts`
  persisted `admin_settings.json` field (`json:"decryption_redact_hosts"`) and the internal Go
  identifiers (`decRedactHostsFlag`, `decRedactHosts()`, `setDecRedactHosts()`). Both interact with the
  `config_surfaces.go` reflection registry (this field is an `AdminDurable`-only row), and renaming them
  safely needs the same shadow-field/alias-on-read treatment T-10 left open for its own
  `contentScanPatterns`/`contentScanBypassHosts` `configBackup` residual — still a separate, correctly
  smaller follow-up. Audit event names (`decryption.redaction`, `decryption.redaction.key-rotated`) are
  also unchanged; the backlog finding never called these out as drift (unlike T-10, which had a genuine
  audit-event-naming split to fix), so renaming them is out of scope here.
- **Migration risk:** none. Every change is additive (a second route registration, a second OpenAPI
  path, two new manifest rows) or documentation. No existing consumer (the legacy `static/index.html`
  GUI, the new frontend's `frontend/src/api/decryption.ts`, or any external script) needs to change —
  all continue working against `/api/decryption/redaction` unmodified. Neither was touched in this pass;
  migrating them to the canonical path is optional future cleanup, not required by this fix.
- **Verification:** `go build ./...`; the full root-package suite subset touching this surface
  (`TestD0_RouteInventory_Locked141`, `TestC1_RouteMetadata_Locked141`,
  `TestC1_RouteMetadata_Reverse_AllMuxRegistrationsHaveMetadata`, `TestC15_MinRole_MetadataMatchesHandler`,
  `TestC15_Mutating_MetadataMatchesHandler`, `TestC15_AuditExpected_MetadataMatchesHandler`, every
  `TestApiDecryptionRedaction*`/`TestDecRedaction*` test); `make api-verify` (bundle-check, style-lint,
  Gate 1–3, contract tests) — all green.

---

## Carried-Over Findings (unchanged)

The remaining twelve previously-open finding IDs (twelve backlog entries, since T-21 and T-32 are
tracked as one paired item) remain open, unchanged: T-9, T-11, T-12, T-13 (residual), T-18,
T-21+T-32 (paired), T-25 (residual), T-29, T-30, T-33, T-34, T-39. Full descriptions and the
priority-ordered refactoring plan are unchanged from `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md`/
`-2026-09-11.md` and are not restated here to avoid drift between two descriptions of the same open
items. T-12 (Maintenance Agent `/v1/upgrades/*` vs. "Release"/"Update" product vocabulary) and T-39
(MCP Gateway `qualification_*` YAML keys colliding with the unrelated Production-readiness
"Qualification" concept) were spot-checked directly against `3d8c9bb` and confirmed still live and
unchanged from the prior report's description.

The "Content & Scanning" vs. "Content Security" soft finding (design-document reconciliation between two
deliberate naming decisions, not a mechanical rename) also remains unresolved and is not queued to the
numbered backlog, per prior reports' reasoning.

---

## Stop-Condition Assessment

Terminology is not yet "already sufficiently consistent" — twelve backlog items remain open — so this
pass acted rather than stopping, fixing the single oldest, best-risk-adjusted (additive/alias-only,
zero breaking changes, direct precedent already established by T-10) item among the areas sampled.
No cosmetic or preference-driven renames are proposed; T-12 and T-39 remain correctly deferred (T-12
touches a scriptable cross-module wire contract with packaging/sudoers references and needs the same
alias treatment on a separate, larger follow-up; T-39 needs a naming decision before any mechanical
change, per the 2026-07-19 report's original reasoning, unchanged since). This report and its
accompanying PR are the deliverable of this pass.
