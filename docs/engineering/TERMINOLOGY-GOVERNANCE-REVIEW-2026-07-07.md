# Culvert Language & Terminology Governance Review — 2026-07-07

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Four parallel concept-cluster audits — (1) authentication/identity/session/RBAC,
> (2) security scanning/content inspection, (3) policy engine/config versioning/bandwidth-QoS,
> (4) cluster CP-DP/HA/release-update — each cross-referencing source code, REST API, GUI copy
> (`static/index.html`), CLI/env, audit/log messages, metrics, and docs. Findings verified
> against the tree at `ea0f2ff`.
> **Companion change:** eight low-risk fixes ship with this review (see "Fixed in this change").

---

## Executive Summary

Culvert's product language is unusually disciplined for a codebase of this size — the
`defaultAuthOutcome`/`UnauthMode` retirement, the `configBackup`/`ConfigSnapshot`/config-version
three-surface split, and the `SessionSecret`→`SessionHMAC` gosec-driven rename are all evidence of
prior, deliberate terminology governance that held up under this review. Most concept clusters
audited (roles, session cookies, IdP/SSO, node groups, bandwidth/QoS, CDR, threat-feed vs
blocklist-feed, category naming, CP/DP/enrollment naming, default-deny/Zero Trust) showed **no
significant drift** — one name per concept, held consistently across code, API, GUI, and docs.

Where drift exists, it clusters in three themes:

1. **Legacy words surviving in comments after the public-facing terms already migrated.**
   "Whitelist" persisted in five doc-comments on the rate-limit exempt-list API even though the
   JSON field, GUI label, and every other reference already say "exempt"/"exemption" (fixed in
   this change). One doc file (`CLUSTER-GAPS.md`) and two CI workflow comment blocks used
   "upgrade"/"host agent" against an otherwise unanimous "update"/"Maintenance Agent" (fixed).
2. **Same GUI panel, two similarly-worded but functionally different bypass features.** The
   Security panel exposes both a DPI-only bypass and a full-body (ClamAV+YARA) bypass with
   labels ("DPI Bypass Hosts" / "bypass all body scanning") close enough in wording that an
   admin skimming the panel could apply an exclusion to the wrong scope (fixed in this change —
   both labels now state their scope explicitly and cross-reference each other).
3. **A real number shown twice under two different names with no stated equivalence.** The HA
   panel renders "Term" and "Fencing Lease" (body text: `epoch N`) as if they were two
   independent counters; ADR-0005 defines them as the same counter (`term = epoch`), and the
   operator runbook says so, but the GUI never did until this change (fixed).

One item initially flagged as drift — the `/api/settings/unauth-mode` route/handler retaining the
retired "UnauthMode" name — turned out to be a **deliberate, already-documented decision**: the
handler carries an explicit comment ("Route name is legacy; the contract is the
`defaultAuthOutcome` string") to avoid an unnecessary breaking API rename. No action taken; see
Finding T-1.

**Fixed in this change:** 8 items (5 whitelist→exempt-list comment fixes, 1 roadmap-doc wording
fix, 2 CI-workflow "host agent"→"Maintenance Agent" fixes, 2 GUI bypass-label clarifications, 1
SSL-inspection GUI-copy consistency fix, 1 HA-panel term/epoch clarifying note — see table below
for exact mapping). **No renames of stable identifiers, API routes, JSON fields, CLI flags, or Go
types were made** — every fix in this pass is a comment, doc, or GUI-copy change with zero
compatibility risk.

**Terminology Health Score: 8.5 / 10** (unchanged in spirit from the discipline already evident in
CLAUDE.md's documented migrations; the deductions are the three themes above, all now addressed or
explicitly triaged).

---

## Canonical Concepts Verified Clean (no drift found)

| Concept | Canonical name | Verified consistent across |
|---|---|---|
| Admin RBAC roles | `admin` / `operator` / `viewer` | Go (`store.go`), GUI dropdowns/governance panel, docs |
| Admin session | "session cookie" (`ps_ui_session` vs proxy `ps_session`) | `session.go`, `ui_session.go`, GUI |
| External auth provider | "Identity Provider" / "IdP" | `auth_idp.go`, GUI panel, docs |
| Traffic identity vs admin user | "Identity (username/email)" vs "Admin Users" | GUI labels kept distinct |
| Threat feed vs blocklist feed | "Threat Feed" (URLhaus/OpenPhish) vs "Blocklist Feed" (domain sync) | `threatfeed.go`, `blocklistfeed`, GUI, with an in-GUI explainer |
| URL category | "URL Category" / "Category Group" | `catdb.go`/`urlcat`, `policy.go`, GUI |
| CDR | "Content Disarm & Reconstruction" / "CDR" | code, GUI nav, roadmap docs |
| Default-deny / Zero Trust | "Zero Trust" + "default-deny"/"fail-closed" | `policy.go`, GUI, `docs/architecture.md` |
| Bandwidth/QoS | "Bandwidth Policy" | `bandwidth.go`, API, GUI |
| Node groups | "Node Group" | `nodegroup.go`, API, GUI |
| CP/DP/enrollment | "Control Plane"/"CP", "Data Plane"/"DP", "enroll(ment)" | `controlplane.go`, `enrollment.go`, `dp_enrollment.go`, GUI |
| Self-update / rolling update | "self-update" (single node), "rolling update" + "canary" (cluster) | `update.go`, `update_cluster.go` |
| Config-version rollback vs export vs CP→DP snapshot | "Config Versions" (GUI), `/api/config/export` (export), `ConfigSnapshot` (internal wire-only) | Kept as three distinct surfaces per `config_surfaces.go`; GUI never blurs "snapshot" into a competing feature name |

---

## Findings

### T-1 — `unauth-mode` route name (no action — deliberate, documented)
- **Business concept:** global Stage-1 fallback for unmatched traffic (`defaultAuthOutcome`).
- **Current names:** URL path `/api/settings/unauth-mode`, Go handler `apiUnauthMode`
  (`ui_config.go:1136`, `ui_routes_meta.go:409`) vs. wire contract and every other reference
  using `defaultAuthOutcome` / "Default Authentication Outcome".
- **Why it looks like drift:** CLAUDE.md states `UnauthMode` is "fully retired" at the Go
  level — the route is the one place the old name visibly survives.
- **Why no change is warranted:** the handler already carries an explicit comment
  (`ui_config.go:1131-1135`) stating the route name is intentionally kept for URL stability
  while the request/response contract fully uses `defaultAuthOutcome`. Renaming a live admin
  API route is a breaking change for any existing automation/scripts hitting this endpoint,
  and the maintainers already made and documented this tradeoff. **Recommendation: none.**
  If a future major-version API cleanup is ever justified, fold this into that batch rather
  than a standalone terminology fix.
- **Priority:** Low (informational only).

### T-2 — "Whitelist" surviving in rate-limit-exempt doc comments (FIXED)
- **Business concept:** rate-limit exemption list (IP/CIDR entries skipped by the limiter).
- **Current names before fix:** JSON field/GUI/API already said "exempt"/"exemption"
  (`RateLimitExempt`, `AddExemption`, GUI "Rate Limit Exemptions"), but five doc-comments in
  `security.go` (`IsExempt`, `AddExemption`, `RemoveExemption`, `ReplaceExemptions`,
  `ListExemptions`) and one in `configversion.go:389` still said "whitelist".
  "Whitelist" is legacy/deprecated industry terminology.
- **Fix:** all six comments now say "exempt list" instead of "whitelist". No functional,
  API, or GUI change — comment-only.
- **Priority:** Low. **Migration risk:** none (doc comments only).

### T-3 — Two similarly-labeled scan-bypass features in one GUI panel (FIXED)
- **Business concept:** two genuinely different "skip this scan" exclusions in the Security
  panel — a DPI-only bypass (regex scan skipped, ClamAV+YARA still run) and a full-body
  bypass (ClamAV+YARA both skipped).
- **Current names before fix:** "Scan Exclusions" (full-body) directly above "DPI Bypass
  Hosts" (DPI-only), with copy ("bypass all body scanning" vs. "skip DPI regex scanning
  entirely") close enough in wording that an admin skimming could misjudge scope —
  especially confusing since "DPI Bypass Hosts" sounds narrower in name but the panel order
  and similar phrasing don't make the width difference obvious at a glance.
- **Fix (`static/index.html`):** relabeled to "Full Content Scan Exclusions (ClamAV + YARA)"
  and "DPI-Only Bypass Hosts", with each description now explicitly cross-referencing the
  other ("Broader than the DPI-only bypass below" / "Narrower than the full content scan
  exclusions above").
- **Priority:** Medium (this is the one finding with genuine admin-facing misconfiguration
  risk — applying the narrow bypass when the broad one was intended, or vice versa).
  **Migration risk:** none — copy-only, no field/API change.

### T-4 — "TLS interception" vs "SSL Inspection" in the same GUI panel (FIXED)
- **Business concept:** MITM decryption of HTTPS traffic via the internal CA.
- **Current names before fix:** panel titled "SSL Inspection Bypass" but its own
  explanatory copy said "bypass **TLS interception** entirely" one line below — CLAUDE.md
  and the rest of the codebase (`ca.go`, `policy.go`, `docs/architecture.md`) treat "SSL
  inspect" as canonical; "MITM"/"TLS interception" are meant to stay developer-facing.
- **Fix:** GUI copy now says "bypass SSL inspection entirely", matching the panel title.
- **Priority:** Low. **Migration risk:** none — copy-only.

### T-5 — HA panel shows "Term" and "Fencing Lease epoch" as unrelated numbers (FIXED)
- **Business concept:** the leadership generation counter — ADR-0005 explicitly defines
  `term = epoch` (the etcd `create_revision`).
- **Current names before fix:** `static/index.html` renders a "Term" stat tile and a
  separate "Fencing Lease" tile whose body reads `epoch N` — same value, two labels, no
  cross-reference in the GUI (the equivalence is documented only in
  `docs/operator/ha-lease-failover.md` and the ADR, not surfaced to the operator watching
  the panel).
- **Fix:** the lease note (shown whenever a lease is armed, i.e. whenever both tiles are
  populated) now states: "The **Term** tile above and the fencing lease's epoch are the
  same counter (ADR-0005: term = epoch) — they will always match."
- **Priority:** Medium (an operator debugging a failover event who sees two numbers that
  happen to always be equal, with no stated reason, may reasonably suspect a bug rather
  than confirm expected behavior). **Migration risk:** none — copy-only, no field rename
  (both `term` and `epoch` JSON keys are kept, matching CLAUDE.md's note that the API
  intentionally exposes both).

### T-6 — "Rolling upgrade" vs "rolling update" (FIXED)
- **Business concept:** CP-orchestrated staged rollout of DP/CP binaries (canary → 10% →
  100%).
- **Current names before fix:** `roadmap/CLUSTER-GAPS.md:38` was the sole place saying
  "Rolling upgrade orchestration"; `update_cluster.go`, `update.go`, `docs/OPERATIONS.md`,
  and the GUI panel title ("Cluster Rolling Update") were unanimous on "update".
- **Fix:** doc line changed to "Rolling update orchestration".
- **Priority:** Low. **Migration risk:** none — doc-only.

### T-7 — "Host agent" / "host-side maintenance agent" vs "Maintenance Agent" (FIXED)
- **Business concept:** the local `culvert-maint` privileged helper process.
- **Current names before fix:** canonical everywhere ("Maintenance Agent" / `maint-agent` /
  `culvert-maint`) except two CI-workflow comment blocks
  (`install-lifecycle-e2e.yml:13`, `appliance-catalog-update-e2e.yml:259,293,317`) which
  said "host-side maintenance agent" / "the host agent".
- **Fix:** both workflow files now say "Maintenance Agent" consistently.
- **Priority:** Low. **Migration risk:** none — CI comment text only, not a step `name:`
  contract any other job depends on by string-matching (verified no downstream job greps
  these specific strings).

### T-8 — `PolicyRule`/"access rule" internal-vs-external naming split (no action taken; documented here for future reference)
- **Business concept:** Stage-2 FQDN/category/GeoIP/schedule matching rule.
- **Current names:** GUI/API say "Policy Rule" (`/api/policy`, "Add Policy Rule"); internal
  code/comments and several handler names say "access rule" (`listAccessRules`,
  `validateAccessRule`, `authpolicy.go`). One Go type (`PolicyRule`) backs both Stage-1 auth
  rules and Stage-2 access rules, disambiguated by `RuleType`.
- **Assessment:** internal-only split (never reaches an admin), but a real onboarding trap
  for a developer or API integrator reading handler names next to API docs. Renaming
  `listAccessRules`/`validateAccessRule` etc. is straightforward and low-risk (private Go
  identifiers, no wire impact) but touches enough call sites that it was left out of this
  pass's zero-risk-only scope.
- **Recommendation:** rename the handful of internal `*AccessRule*` helper identifiers to
  `*PolicyRule*` in a follow-up PR, or at minimum add one glossary comment next to the
  `PolicyRule` struct definition (`policy.go:91`) stating the GUI/API-vs-internal name
  split explicitly.
- **Priority:** Low. **Estimated PR size:** small (rename-only, mechanical, single package).

### T-9 — `exportedAt` field shared by true export and automatic config-version capture (no action taken)
- **Business concept:** timestamp on the `configBackup` payload, used by three surfaces
  with different semantics per CLAUDE.md (export/import, config-version rollback,
  admin_settings durability).
- **Current names:** JSON field is `exportedAt` (`ui_policy.go:740`) whether the payload
  came from a real `/api/config/export` call or an automatic version-capture on every
  config mutation (`configversion.go:46`); the import-audit message then says "from backup
  exported %s" even for version-originated files.
- **Assessment:** this is a genuine, if minor, naming leak between two of the three
  surfaces CLAUDE.md says are deliberately kept distinct — but `configBackup` field
  membership and semantics are governed by the `config_surfaces` registry and enforced by
  `config_surfaces_test.go` (reflection-based parity tests). Renaming the JSON field
  touches that registry, its parity tests, and any on-disk version file ever written with
  the old key. Not zero-risk; left for a deliberate follow-up rather than folded into this
  pass.
- **Recommendation:** rename the field to a neutral `capturedAt` (keep `exportedAt` as a
  read-accepted legacy alias on import for on-disk files written before the change), and
  adjust the import-audit message to say "captured" vs. "exported" based on provenance.
- **Priority:** Medium (developer/audit-log clarity; no admin-GUI exposure today).
  **Estimated PR size:** medium — touches `ui_policy.go`, `configversion.go`,
  `config_surfaces.go`, `config_surfaces_test.go`, and needs a read-compat path for
  existing version files.

---

## Recommended Refactoring Plan (priority order)

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium | T-9 | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium (on-disk format, parity-test surface) | Medium |
| Low | T-8 | Rename internal `*AccessRule*` helpers → `*PolicyRule*` | None (private identifiers) | Small |
| Informational | T-1 | No action — already a documented, deliberate decision | N/A | N/A |

Items T-2 through T-7 are already fixed in this change (comment/doc/GUI-copy only, zero
compatibility risk) and require no further action.

---

## Stop-Condition Assessment

Terminology is **not** already fully consistent — six concrete, low-risk fixes shipped with this
review, and two further findings (T-8, T-9) are recommended for a deliberate follow-up PR given
their slightly larger (but still small) migration surface. No cosmetic or preference-driven
renames are proposed; every recommendation traces to a genuine cross-surface naming
inconsistency that would confuse an administrator, support engineer, or new contributor.
