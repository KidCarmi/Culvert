# Culvert Language & Terminology Governance Review — 2026-07-18

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Four parallel concept-cluster audits — (1) authentication/identity/session/RBAC,
> (2) SSL/TLS inspection, decryption exclusion, and SSL Bypass, (3) cluster CP-DP/HA/node
> management, (4) release catalog/trust and config versioning — each cross-referencing source
> code, REST API, GUI copy (`static/index.html`), CLI/env, audit/log messages, metrics, and docs.
> Findings verified against the tree at `800e4c7`, following up on the four prior reviews at
> `ea0f2ff` (2026-07-07), `8e88a40` (2026-07-10), `b0dd056` (2026-07-12), and `d5585d5`
> (2026-07-16).
> **Companion change:** four zero-risk GUI-copy/GUI-parity fixes ship with this review (see
> "Fixed in this change"). No API, config, wire-protocol, or exported-identifier renames were made.

---

## Executive Summary

This pass re-verified every cluster the four prior reviews marked clean (still holds — no drift
reintroduced), reconfirmed that all four still-open carried-over findings (T-9, T-10 residual,
T-11, T-12) remain correctly deferred with no change in their risk profile, and found four new,
small, genuinely-confusing instances — three isolated GUI copy inconsistencies and one GUI-parity
gap where the API already computes a distinction the GUI never displays. All four are fixed in
this change; none touch a wire contract, on-disk format, or exported API/config surface.

1. **SSL Bypass panel title still said "SSL Inspection Bypass" while every other surface for the
   same feature — the export-section button, both confirm dialogs, the fail-open warning copy, the
   JS function/variable names, and current operator docs — call it "SSL Bypass."** T-4 (2026-07-07)
   fixed the panel's *body copy* to stop saying "TLS interception," but never re-examined whether
   the panel *title* itself matched the rest of the feature's naming — it didn't. This completes
   T-4's intent the same way G-2 (2026-07-16) completed T-7.
2. **The Cluster panel's empty-state copy called a Data Plane node a "Data Plane worker" one line
   away from calling the identical entity a "Data Plane node"** — an isolated word choice inside a
   single rendering function, echoing the master/worker split pattern this routine watches for.
3. **The admin-only "Governance" (C3) page rendered raw internal counter/axis keys verbatim**
   (`would_deny`, `missing_meta`, `no_policy`, `audit_missing`, `enforce_denied`,
   `metadata_parity`, `audit_completion`, `enforce_consistency`) with no plain-language label — an
   admin with no context on the internal C2/C3 rollout program saw cryptic snake_case strings
   instead of what they mean.
4. **The Release Management panel never displayed `trust_schemes`** — the field the backend
   (`release_wiring.go`, `release_api.go`) already computes specifically to let an operator tell
   ed25519-key trust apart from Sigstore-identity trust — even though `/api/releases` has exposed
   it since P2b-1. The GUI showed only the overall `verify_mode` badge.

**Terminology Health Score: 9 / 10** (unchanged from 2026-07-12/07-16 — the carried-over items are
still correctly sized for a dedicated follow-up, and this pass's four findings are all same-day,
zero-risk copy/display fixes with no open residual).

**Fixed in this change:**
- `static/index.html` — SSL Bypass panel title (`SSL Inspection Bypass` → `SSL Bypass`); the
  two enterprise docs that name the panel (`docs/enterprise/TLS-INSPECTION-DEPLOYMENT.md`,
  `docs/enterprise/ENTERPRISE-DEPLOYMENT-GUIDE.md`) updated to match.
- `static/index.html` — Cluster panel empty-state copy (`Data Plane worker` → `Data Plane node`).
- `static/index.html` — Governance (C3) panel: the five counters and three health axes now render
  a human-readable label (e.g. "Routes missing metadata" instead of bare `missing_meta`), with the
  original snake_case key kept as a `title` tooltip attribute so an admin cross-referencing
  CLAUDE.md's or the `/api/governance/control-plane` documentation can still find the exact name.
- `static/index.html` — Release Management panel: added a `trust_schemes` badge next to the
  existing verify-mode badge, rendering `ed25519`/`sigstore`/`ed25519+sigstore`/`none` as
  "ed25519 keys" / "Sigstore identity" / "ed25519 keys + Sigstore identity" / "none." No backend
  change — the field was already computed and exposed by `/api/releases`.

**No renames of stable REST API routes, JSON fields, CLI flags, config keys, exported Go
identifiers, or wire-protocol routes were made** — every fix in this pass is GUI copy or a GUI
display addition reading an already-exposed API field, with zero compatibility risk.

---

## Re-verified clean (no new drift since 2026-07-16)

`defaultAuthOutcome`/`UnauthMode` retirement (still zero leftover live references outside
historical review docs and the documented read-only migration input); RBAC role naming
(`admin`/`operator`/`viewer`) across code/API/GUI; IdP/OIDC/SAML/LDAP terminology including the
G-1 `DisplayName()` fix; session/cookie naming (`ps_session` vs `ps_ui_session`, deliberately
distinct); manual SSL Bypass vs. adaptive decryption-exclusion (autoexclude) — the two engines
remain clearly and consistently distinguished in code, API routes (`/api/ssl-bypass` vs.
`/api/decryption-exclusions`), docs, and log-line prefixes (`SSL_BYPASS_PATTERN` vs.
`SSL_AUTOEXCLUDE_BYPASS`); `OnInspectError` fail-open/fail-close vocabulary; certificate
terminology (Root CA / leaf cert); CP/DP/enrollment/node-group/bandwidth-QoS naming; HA
fencing-lease term/epoch equivalence note; release catalog vs. "release index"; legacy "updater"
terminology (fully retired, all current references correctly point to "Maintenance Agent"); config
version/export/snapshot three-surface split (still cleanly disambiguated in GUI copy, per
2026-07-16's re-verification).

---

## Findings

### G-3 — SSL Bypass panel title didn't match the rest of the feature's naming (FIXED — completing T-4)
- **Business concept:** the admin-configured always-bypass list for SSL/TLS inspection
  (`/api/ssl-bypass`, `internal/sslbypass`).
- **Current names before fix:** panel title `static/index.html:2015` read "SSL Inspection Bypass."
  Every other surface for the identical feature said "SSL Bypass": the export-section button
  (`static/index.html:2159`, `data-arg="sslbypass"`), the fail-open warning copy
  (`static/index.html:3141`, "manual SSL Bypass list"), the remove-confirmation dialog
  (`static/index.html:7725`, "Remove SSL Bypass"), every JS identifier (`_sslBypassList`,
  `loadSSLBypass`, `renderSSLBypass`, `addSSLBypass`, `removeSSLBypass`), and current operator docs
  (`docs/operator/decryption-auto-exclusions.md`, `docs/product/adaptive-decryption-exclusions.md`)
  which repeatedly contrast "manual SSL Bypass" against "auto-exclusion." Only the panel title and
  two enterprise docs referencing it by name (`TLS-INSPECTION-DEPLOYMENT.md:60`,
  `ENTERPRISE-DEPLOYMENT-GUIDE.md:156`) used the longer "SSL Inspection Bypass."
- **Why this is real drift:** T-4 (2026-07-07) fixed this panel's *explanatory copy* ("bypass TLS
  interception" → "bypass SSL inspection") but did not re-examine the panel's own *title* against
  the rest of the feature's naming, so the one-word divergence ("Inspection") survived three
  further review passes untouched, on the one surface (the panel header itself) an admin actually
  reads first when looking for this feature.
- **Fix:** panel title changed to "SSL Bypass," matching every other surface. The two enterprise
  docs that named the panel are updated to match, so an admin following either doc still finds the
  panel by the name printed on the page.
- **Priority:** Low. **Migration risk:** none — copy-only, no field/API/route change.

### G-4 — Cluster panel: "Data Plane worker" vs. "Data Plane node" for the identical entity (FIXED)
- **Business concept:** an enrolled Data Plane member of the cluster.
- **Current names before fix:** `static/index.html:15132` ("...to add a Data Plane node") and
  `static/index.html:15138` ("...start managing Data Plane nodes") both say "node" — the term used
  everywhere else in code, API JSON, other GUI copy, and `roadmap/CLUSTER-GAPS.md`.
  `static/index.html:15137`, six lines away in the same rendering branch, called the identical
  entity a "Data Plane worker" instead — the only place in the entire tree this concept is called
  "worker."
- **Why this is real drift:** an admin who reads "Data Plane node" in the enroll button and the
  node table, then "Data Plane worker" in the very next empty-state message for the same concept,
  could reasonably wonder whether "worker" denotes some other node subtype — the same
  master/worker-style split this routine's methodology explicitly watches for, even though here
  it's an isolated word choice rather than a systemic naming split.
- **Fix:** line reworded to "This node is a Data Plane node," matching the surrounding copy.
- **Priority:** Low. **Migration risk:** none — copy-only.

### G-5 — Governance (C3) admin page rendered raw internal counter/axis keys with no plain-language label (FIXED)
- **Business concept:** the RBAC-enforcement rollout health counters and axes the C3 governance
  surface (`GET /api/governance/control-plane`) computes for an admin auditing the metadata-driven
  authorization rollout.
- **Current names before fix:** `static/index.html:14978-14988` rendered the five counters
  verbatim as `would_deny:`, `enforce_denied:`, `missing_meta:`, `no_policy:`, `audit_missing:`;
  `static/index.html:14997-15000` rendered the three health axes (`metadata_parity`,
  `audit_completion`, `enforce_consistency`) the same way inside status badges. These are
  internal, engineering-rollout-program-derived names (documented in CLAUDE.md's "C2/C3/C4"
  section for developers), not language written for an admin/support engineer reading a GUI page.
- **Why this is real drift:** CLAUDE.md itself frames the C3 surface as something "an admin" reads
  ("Every audience should understand the same concept using the same name" — this routine's own
  charter), but the only surface an admin actually sees rendered raw machine-readable field names
  with no explanation — e.g. `no_policy: 0` gives no admin, unaided by source code or CLAUDE.md,
  any way to know this means "a request's method had no matching enforcement policy."
- **Fix:** each counter and axis now renders a plain-language label (e.g. "Routes missing
  metadata" for `missing_meta`, "Enforcement consistency" for `enforce_consistency`), with the
  original snake_case key preserved as a `title` tooltip attribute — an admin who wants to
  correlate the displayed value against CLAUDE.md's or the API's exact field name still can, but no
  longer has to in order to understand the page at a glance. The existing `kill_switch_env` display
  (which already carries an explanatory "Kill switch:" label ahead of the raw env-var name) was
  left as-is — showing the exact `CULVERT_C2_ENFORCE` string there is the actionable, correct
  behavior, not jargon leakage.
- **Priority:** Low-Medium (admin-only diagnostic page, not a mainstream feature, but exactly the
  "internal terminology leaking into a user-facing surface" pattern this routine's charter names).
  **Migration risk:** none — GUI rendering only; the underlying API field names, CLAUDE.md's
  documented counter names, and `/api/governance/control-plane`'s JSON shape are unchanged.

### G-6 — Release Management GUI never displayed `trust_schemes`, a distinction the API already computes (FIXED)
- **Business concept:** which signature-trust mechanism(s) — ed25519 keys
  (`CULVERT_RELEASE_CATALOG_TRUST_KEYS`) vs. Sigstore keyless identity
  (`CULVERT_RELEASE_SIGSTORE_TRUSTED_ROOT`) — currently back the release catalog's signature
  verification.
- **Current names/surfaces before fix:** `release_wiring.go:379` (`trustSchemes(cfg)`) and
  `release_api.go:341-356` compute and expose a clean `trust_schemes` API field
  (`"ed25519"`/`"sigstore"`/`"ed25519+sigstore"`/`"none"`) specifically so an operator can tell the
  two trust mechanisms apart. `static/index.html`'s `renderReleaseTrustBadge` (the function that
  renders the Release Management panel's trust badge) only ever read `verify_mode`, rendering
  "Trust: ENFORCE" — with no reference to `trust_schemes` anywhere in the GUI.
- **Why this is real drift (a GUI-parity gap, not a naming collision):** per CLAUDE.md's GUI-parity
  convention ("Every new CLI flag or config option MUST have a corresponding admin API endpoint AND
  a UI panel/section so the user can manage it from the GUI"), the backend already named and
  computed this distinction for exactly the purpose of surfacing it to an admin, but the GUI never
  displayed it — an admin looking at "Trust: ENFORCE" has no way to tell, without reading logs or
  the raw API response, whether that trust rests on their own configured ed25519 keys, the baked
  Sigstore root, or both.
- **Fix:** added a `rel-trust-schemes` badge next to the existing trust-mode badge in the Release
  Management panel, rendering the four possible values as "ed25519 keys" / "Sigstore identity" /
  "ed25519 keys + Sigstore identity" / "none." Purely additive — reads an already-exposed API
  field, no backend change.
- **Priority:** Medium (a genuine display gap for a security-relevant distinction the backend
  already names correctly). **Migration risk:** none — GUI-only, additive.

### Carried over — no change this pass (re-verified, still correctly deferred)

- **T-9** (`exportedAt` → `capturedAt` rename, first flagged 2026-07-07) — still open; confirmed
  `exportedAt` remains the live field name across `ui_config.go`/`ui_policy.go` and the
  config-export-taxonomy test surface. Deferred for the same on-disk-format/parity-test reason as
  the last three reviews.
- **T-10 residual** (`contentScanPatterns`/`contentScanBypassHosts` JSON field names on the
  export/import/config-version-rollback surface, first flagged 2026-07-10, operator-visible half
  fixed 2026-07-12) — still open; confirmed these two field names remain unchanged in
  `ui_policy.go`/`configversion.go`. Deferred pending the same shadow-type/alias-on-read treatment
  as T-9, per 2026-07-12's own assessment.
- **T-11** (`allow`/`deny` default-action fallback vocabulary vs. the four-value `PolicyAction`
  enum, 2026-07-16) — still open; confirmed the GUI's Default Action control
  (`static/index.html:2788-2858`) still renders the bare two-state toggle with no clarifying note
  cross-referencing `Drop`/`Block_Page`. Deferred per 2026-07-16's own recommendation to route this
  through a dedicated small follow-up rather than a same-day pass.
- **T-12** ("upgrade" — Maintenance Agent wire API/packaging — vs. "Dispatch"/"update" — GUI/API,
  2026-07-16) — still open; independently reconfirmed this pass (`/v1/upgrades/apply`,
  `/v1/upgrades/check`, `culvert-maint.service`, `config.example.toml`, and
  `roadmap/D1.6-maintenance-agent-design.md` all still say "upgrade" while the GUI/API layer calls
  the identical operation "Dispatch"/"update"). Deferred for the same rolling-update
  compatibility-window reason as 2026-07-16 — a same-day pass on a live wire contract used during
  rolling updates carries more downside than another review cycle's worth of written specification.

### Soft findings — no action recommended

- Re-confirmed from 2026-07-16: "Role" labeling two unrelated enums (RBAC permission level vs.
  cluster topology role) across different GUI panels, and "Profile"/"Group" reused across
  unrelated domains — both remain intentional-by-context (every surface qualifies the term where
  ambiguity would matter), not drift. No change recommended.

---

## Recommended Refactoring Plan (priority order)

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium | T-10 residual (carried over) | Alias `contentScanPatterns`/`contentScanBypassHosts` JSON fields on the export/import/rollback surface | Medium (config-surfaces registry, on-disk format) | Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium (on-disk format, parity-test surface) | Medium |
| Medium | T-11 (carried over) | Clarify/reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum (GUI copy first) | Low for the GUI-copy option | Small (copy) |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*`, rename packaging/config comments to "update" | Medium (agent wire protocol, needs rolling-update-safe compat window) | Medium |
| Informational | T-1 (carried over, no action) | `/api/settings/unauth-mode` route name — already a documented, deliberate decision | N/A | N/A |

G-3 through G-6 are fixed in this change and require no further action.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent, but the remaining gaps are the same four carried-over
items (T-9, T-10 residual, T-11, T-12) already correctly sized for a dedicated follow-up across
four consecutive prior review passes, plus four new same-day, zero-risk GUI copy/display fixes
made in this change. No cosmetic or preference-driven renames were proposed or made — G-3 completes
an already-committed decision (T-4) rather than reversing it, G-4 and G-5 are copy/display-only
clarity fixes with no compatibility surface, and G-6 is an additive GUI display of an
already-computed, already-named API field. No new large-migration finding was identified this pass.
