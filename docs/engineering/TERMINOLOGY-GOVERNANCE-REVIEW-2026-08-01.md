# Culvert Language & Terminology Governance Review — 2026-08-01

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Four parallel concept-cluster audits against the tree at `33bf8f7`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-07-24.md` (baseline `2eef667`). One lane re-verified the six
> clusters the 07-07 through 07-24 reviews already certified clean (auth/session/RBAC/TOTP/lockout/CA,
> SSL-inspection/decryption/autoexclude, policy/blocklist/threat-feed/URL-category, cluster CP-DP/HA/
> release-catalog/config-versioning, GUI-vs-API-vs-docs cross-surface consistency) — no regression.
> Three more targeted the 263 commits that landed *after* the 07-24 review and have never been through
> a governance pass: (1) the config/CLI/YAML/wire naming family for security settings, (2) audit-event/
> log/metric naming across the proxy and scan engines, and (3) the two major features that shipped in
> this window — the MCP Agent Security Gateway going from 100%-design-doc to a real PR-1..PR-6
> implementation, and the blocklist/URL-category SaaS feed's F3b-1/2/3 generation-activation-GC
> subsystem.
> **Companion change:** none. Three findings touch a live YAML config key, wire field
> (`ConfigSnapshot`/admin-settings JSON), or already-shipped Prometheus metric (T-29, T-30, T-31); the
> fourth (T-32) touches an already-persisted on-disk field name feeding code paths that other F3b
> subsystems already depend on, with a live API exposure explicitly scoped as the *next* development
> slice. None meet this program's zero-compatibility-risk bar for a same-day fix (that bar has
> consistently meant doc/comment/design-doc-only changes; see T-22/T-23/T-24/T-26/T-27/T-28 in the 07-24
> review). All four new findings are documented for dedicated follow-up, the same treatment already given
> to T-9/T-17/
> T-12/T-21.

---

## Executive Summary

The re-verification lane found nothing new — every cluster the 07-07 through 07-24 reviews already
certified clean still holds, including the five previously-open carried-over findings (T-9, T-11, T-12,
T-16, T-18) and the two Medium items from last pass (T-21, T-25 residual). The three new-territory lanes
surfaced four new, genuine findings, all following the same shape: **a business concept that already has
one canonical name on most surfaces, with exactly one surface — usually the operator-facing YAML/CLI
layer, or a metric/field added most recently — left as the outlier.** Notably, the MCP Agent Security
Gateway's transition from a 100%-design-doc baseline (praised in 07-24 as "unusually disciplined") to a
real six-PR implementation **held that discipline** — all nine policy actions, the full `MCP.*` reason-code
taxonomy, and the credential-broker Plan→Materialize vocabulary shipped verbatim from design doc to code,
and the design doc itself was proactively kept in sync. That is the governance program working as
intended on a feature built with the review cadence already in mind.

The four new findings are smaller in scope than 07-24's crop (no glossary violations, no ADR
collisions, no functional dead ends) — three are config/metric naming splits inherited from ordinary
incremental development, and one (T-32) is a fresh subsystem reusing an already-overloaded term
("snapshot") on day one, which is exactly the kind of thing this review exists to catch early, before
`/api/urlcat/feed-status` gets more consumers.

**Terminology Health Score: 8.5 / 10** (unchanged from 07-19 and 07-24 — four new small findings on 263
commits of feature work, none rising above Low-Medium priority and none a glossary violation or GUI
contradiction, is consistent with the expected background rate of drift at this program's cadence, not a
regression).

**Fixed in this change:** none. Unlike 07-24 (which found ten doc/copy-only issues cheap to fix
same-day), three of this pass's findings touch already-shipped config keys, wire fields, or metrics, and
the fourth (T-32) touches on-disk/internal identifiers already depended on by sibling code — none are
pre-implementation design-doc corrections or copy-only GUI strings, so none clear this program's
same-day bar. All four are sized and documented below for dedicated follow-up PRs.

---

## Wave 1 — Re-verified clean (no new drift since 2026-07-24)

Independently re-audited and confirmed still holding: authentication/session/RBAC/lockout/TOTP/CA/PSCA
naming; SSL-inspection/decryption/autoexclude naming; policy-engine/blocklist/threat-feed/URL-category
naming (pre-F3b surfaces); Control Plane/Data Plane/enrollment/node-group/HA-lease naming;
release-catalog/maintenance-agent naming (the "updater" retirement holds); and full GUI-label-vs-API-
field-vs-documentation cross-surface consistency, including the five still-open carried-over findings
(T-9, T-11, T-12, T-16, T-18 — T-18's blast radius did not grow further this pass, since the only new
code touching sealing, `internal/mcp/credentials/broker/materialize.go`'s `sealHandle`, correctly reuses
the existing `internal/secret.Seal` primitive rather than introducing a fourth meaning) and the two
Medium items opened last pass (T-21, T-25 residual, both unchanged — neither lane this pass touched
`cluster_convergence.go`, `configversion.go`'s rollback surface, or `support_recipients.go`/
`support_tac_trust.go`).

## Wave 2 — New territory audited this pass (263 commits since `2eef667`)

**MCP Agent Security Gateway (PR-1 through PR-6, ~15 commits): clean, no findings.** The deterministic
policy engine (`internal/mcp/policy`), credential broker (`internal/mcp/credentials/broker`), and
bounded listeners shipped with terminology matching the MCP design-doc set verbatim — the nine policy
actions (`ALLOW`/`DENY`/`MONITOR`/`QUARANTINE`/`REQUIRE_CONFIRMATION`/`REQUIRE_APPROVAL`/`ALLOW_ONCE`/
`ALLOW_FOR_SESSION`/`ALLOW_WITH_REDACTION`), the full `MCP.*` reason-code taxonomy, and the
Plan→Materialize/`PreMaterializationGate`/non-secret-lease vocabulary all match
`docs/design/mcp/MCP-POLICY-MODEL.md` and `AUTH-AND-CREDENTIAL-MODEL.md` exactly, and the design doc was
proactively annotated "PR-6 IMPLEMENTED (dormant)" pointing at the real package. No new GUI/API surface
has shipped yet (self-declared deferral), so there is no on-screen collision surface to audit yet.

**Blocklist/URL-category SaaS feed F3b-1/2/3 (~19 commits): one new finding (T-32).** "Floor,"
"activation," "candidate," and "generation" are used consistently within F3b and don't collide with
pre-existing uses of those English words elsewhere (the release-catalog rollback "floor" is a distinctly
grounded, explicitly-cited precedent, not a naming collision). "Snapshot," however, now has a third,
unrelated meaning — see T-32 below.

**Config/CLI/YAML/wire naming (all-surface sweep): two new findings (T-29, T-30).** See below.

**Audit/log/metric naming (all-surface sweep): one new finding (T-31).** See below.

---

## Findings

### T-29 — Per-IP rate limit: the operator-facing config surface is the lone outlier on "RPM" naming (new — documented, not fixed)
- **Business concept:** the per-IP request-rate-limit threshold, expressed as requests per minute.
- **Current names:**
  - YAML: `security.rate_limit` — `config.go:53` (`RateLimit int`)
  - CLI flag: `-rate-limit` — `main.go:241`
  - Admin-settings persistence / JSON API: `rate_limit_rpm` — `admin_settings.go:32`
  - Live settings POST body: `rateLimitRPM` — `ui_security.go:176`
  - CP→DP wire (`ConfigSnapshot`): `rate_limit_rpm` — `controlplane_snapshot.go:39`
  - Config-version diff key: `rate_limit_rpm` — `configversion.go:377,741`
  - Prometheus metric: `culvert_rate_limit_rpm` (`metrics.go`, ~line 498) — already RPM-qualified
- **Why this is real drift:** six of seven surfaces agree on `rate_limit_rpm`/`rateLimitRPM`. Only the
  YAML/CLI operator-facing surface — the one most likely to be grepped or hand-edited when writing a
  `config.yaml` or systemd unit, and the one CLAUDE.md's own env/flag table would need to describe —
  drops the unit qualifier. An operator correlating a `config.yaml` key against the API response, a
  config-version diff, or `/metrics` output will not find `rate_limit` by searching for either.
- **Recommended canonical name:** `rate_limit_rpm` (the majority name across every live API/wire/metric
  surface). Add a YAML/CLI read-compat alias (accept both `rate_limit` and `rate_limit_rpm`, canonicalize
  internally) rather than a blind rename of an operator-authored config key — the same compatibility bar
  this program applied to T-9 and T-17.
- **Priority:** Medium. **Migration risk:** Low-Medium (YAML/CLI key needs an accept-both compat window).
  **Est. PR size:** Small.

### T-30 — Per-IP connection cap: two disjoint name families, `max_conns_per_ip` vs `conn_limit_*` (new — documented, not fixed)
- **Business concept:** the per-IP concurrent-connection cap.
- **Current names:**
  - YAML: `security.max_conns_per_ip` — `config.go:54`
  - CP→DP wire (`ConfigSnapshot`): `MaxConnsPerIP`/`max_conns_per_ip` — `controlplane_snapshot.go:57`
  - Admin-settings persistence / JSON API / export-import (`configBackup`, shared struct):
    `ConnLimitMaxPerIP`/`conn_limit_max_per_ip` — `admin_settings.go:34`, `ui_policy.go:1253`. **Not** on
    the config-version rollback/diff surface — `config_surfaces.go:267-272`'s `conn_limit_max_per_ip` row
    carries no `Rollback`/`Diffed` flag (contrast the neighboring `category_groups` row, which does), and
    `configversion.go` never captures or diffs this field. An earlier draft of this finding mischaracterized
    it as a rollback-surface name; corrected after review.
  - `config_surfaces.go:267-272` explicitly cross-binds all three spellings under one logical field
    (YAML/wire vs. admin-persistence/export-import) — it documents *that* the names differ, not *why*.
- **Why this is real drift:** the inverse split from T-29 — YAML and the CP→DP wire agree on
  `max_conns_per_ip`; admin-settings persistence, the live API, and export/import all use the
  `conn_limit_*` family instead. Nothing in `config_surfaces.go` or CLAUDE.md documents this split as
  deliberate (unlike the explicitly-rationalized four-name Session Secret case).
- **Recommended canonical name:** `conn_limit_max_per_ip` — it already matches the sibling
  `ConnLimitEnabled` field it is always read/written alongside on the admin/API side. Add a read-compat
  alias for the YAML `max_conns_per_ip` key and the `ConfigSnapshot` wire field name, same treatment as
  T-29.
- **Priority:** Medium. **Migration risk:** Low-Medium (same class as T-29). **Est. PR size:** Small.

### T-31 — ClamAV metric family: `clamav` everywhere except one error counter (new — documented, not fixed)
- **Business concept:** ClamAV antivirus scan-outcome counters — block count and error count on the same
  integration, meant to be read together (e.g. a block-rate dashboard dividing blocked by
  blocked+errors).
- **Current names:** `culvert_clamav_blocked_total` (`metrics.go:518-520`) vs.
  `culvert_clam_scan_errors_total` (`metrics.go:526-528`, added 2026-07-26 per
  `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-07-26.md`). Every sibling scan-outcome metric in the
  same block uses its full subsystem name (`culvert_dpi_blocked_total`, `culvert_yara_blocked_total`,
  `culvert_threat_feed_blocked_total`); the OTLP export (`otlp.go:70`) and the UI JSON key
  (`ui_config.go:139`) both say `clamav`. Only the errors counter drops the "av".
- **Why this is real drift:** a `culvert_clamav_*` prefix query — the pattern every other metric family
  here supports for its own subsystem — silently misses this one counter for the identical integration.
  Nothing documents "clam" vs "clamav" as deliberate; the internal `ClamBlocked` Go field name and the
  `clam_vars.go` shim file suggest "clam" is internal shorthand that leaked into the one metric added most
  recently.
- **Why not fixed this pass:** it is a live, already-shipped Prometheus metric (~6 days old) cited by
  exact name in three internal engineering docs (`CHAOS-ENGINEERING-REVIEW-2026-07-26.md`,
  `PRODUCTION-FAILURE-MODE-AUDIT.md`, `FAILURE-INJECTION-TEST-PLAN.md`) and exposed on `/metrics`. No
  in-repo Grafana panel or alert rule references it yet (`culvert_clamav_blocked_total` is the only clam
  metric in `deploy/grafana/dashboards/culvert-overview.json`), but a scraped counter name is exactly the
  class of already-shipped wire surface this program has consistently deferred rather than blind-renamed
  same-day (cf. T-9, T-17).
- **Recommended canonical name:** `culvert_clamav_scan_errors_total`. Expose both names for one release
  (dual-emit, or a documented breaking-change note in the release) rather than a silent rename, given
  external scrapers are unknown even though no in-repo consumer was found.
- **Priority:** Low-Medium. **Migration risk:** Low (narrow, ~6-day-old metric, no in-repo dashboard
  consumer found) but nonzero. **Est. PR size:** Small.

### T-32 — F3b's per-generation content digest reuses the already-overloaded term "snapshot" (new — documented, not fixed)
- **Business concept:** the canonical per-generation, host→category content digest that the new
  blocklist/URL-category SaaS feed's F3b activation record and admin-visible feed-status view carry.
- **Current names / collision:** F3b (merged today, 2026-08-01) names this `SnapshotSHA256` /
  `snapshot_sha256` in three places — `saas_feed_activation.go:112,139` (the durable, on-disk activation
  record), `saas_feed_view.go:70` (`effectiveCategoryView`, an in-memory struct field with no JSON tag —
  **not currently API-exposed**), and the on-disk filename `snapshot.normalized.json`
  (`saas_feed_genstore.go:72`). Correction after review: `GET /api/urlcat/feed-status`
  (`apiURLCatFeedStatus`, `ui_policy.go:1158-1183`) does **not** return this field today — it only emits
  the legacy configured/count/timing/failure fields, and `effectiveCategoryView` isn't read anywhere in
  that handler. Wiring `SnapshotSHA256` (or whichever field the F0 §14 spec settles on) into that endpoint
  is explicitly the *next*, not-yet-shipped slice — F3b-4, per `roadmap/FEEDS-DISTRIBUTION-F3-DESIGN.md`
  (§ F3b-3's own "Non-goals: GUI telemetry polish (F3b-4)"; F3b-4 lists "extend `apiURLCatFeedStatus`
  (`ui_policy.go:1158-1184`) with the F0 §14 fields" as its own scope). "Snapshot" already has two
  established, unrelated meanings this program tracks: the CP→DP `ConfigSnapshot` struct
  (`controlplane_snapshot.go`) and the informally-named rollback "config snapshot" that T-21 (07-24
  review) already flags as confusable with a *different* "Config Version" concept in the same admin UI.
  F3b's own `saas_feed_api.go` header comment uses two of the three meanings side by side in one
  paragraph ("snapshots a config version... republishes the cluster snapshot"), in the same file that
  introduces the third.
- **Why this is real drift, not cosmetic:** even though `snapshot_sha256` is not yet API-exposed, it is
  already a persisted on-disk field name (the durable activation record) that other F3b code
  (`saas_feed_activate.go`, `saas_feed_reverify.go`, `saas_feed_recover.go`) reads and writes by that
  name, and F3b-4 is already scoped to carry it (or an equivalent field) onto the live admin API. An
  operator or engineer reading "snapshot" there, once F3b-4 ships, could reasonably (and wrongly)
  associate it with the `ConfigSnapshot`/config-version-rollback machinery T-21 already flags as
  ambiguous, when it is actually a content-integrity digest of one immutable feed generation with no
  relationship to either existing "snapshot." This is precisely the pattern this review's Wave-2
  methodology exists to catch — new code reusing an already-overloaded term — caught here *before* the
  F3b-4 API-exposure step, which is the cheapest point to fix it.
- **Recommended canonical name:** rename the F3b field/filename to something scoped to the feed content —
  e.g. `content_sha256` or `normalized_sha256` — leaving `SnapshotSHA256`'s two pre-existing meanings
  (`ConfigSnapshot`, rollback "config snapshot") untouched. Land this *before* F3b-4 wires the field onto
  `apiURLCatFeedStatus`, and consider resolving it alongside T-21's own recommended fix, since both are
  about reclaiming "snapshot"/"Config Version" as unambiguous terms in the same admin surface area.
- **Priority:** Medium (not urgent from an external-compatibility standpoint — nothing external reads
  this today — but time-sensitive: F3b-4 is the very next planned slice for this subsystem, and once it
  wires `snapshot_sha256` onto a live GET response, this becomes a wire-API rename with the same
  compatibility bar as T-29/T-30/T-31 instead of an internal one). **Migration risk:** Low today (only
  internal Go identifiers + one on-disk activation-record field, both younger than a day; zero API/GUI
  exposure yet). **Est. PR size:** Small.

---

## Carried over, still open (re-confirmed this pass)

| Finding | Business concept | Status |
|---|---|---|
| T-9 | `exportedAt` → `capturedAt` rename | Open since 07-07. On-disk format + parity-test surface; still correctly deferred. |
| T-11 | `allow`/`deny` default-action vocabulary vs. 4-value `PolicyAction` | Open since 07-16. Re-confirmed unchanged; `policy.go`/`ui_policy.go` core untouched by MCP/F3b work. |
| T-12 | Maintenance-Agent wire API "upgrade" vs. GUI/API "update"/"Dispatch" | Open since 07-16. Re-confirmed unchanged. |
| T-16 | ADR numbering collision: 0008–0011 (decryption-exclusion track vs. Supportability track) | Open since 07-19. Unchanged in scope; recommended renumber target remains 0019–0022. |
| T-17 | Traffic-log destination-privacy config key/route still says "decryption" | Open since 07-19. Unchanged. |
| T-18 | "Seal" names two unrelated cryptographic operations | Open since 07-19, grew 07-24. **Unchanged this pass** — the one new call site touching sealing (MCP credential broker's `sealHandle`) correctly reuses `internal/secret.Seal`, not `internal/sealbox.Seal`, so the collision did not widen further. Still recommended as the next dedicated terminology PR given its security sensitivity. |
| T-21 | "Config Version" names two unrelated, independently-incrementing counters | Open since 07-24. Unchanged; **T-32 (new, this pass) compounds the same underlying "snapshot"/"version" ambiguity** in a different admin surface — recommend scoping one follow-up PR to cover both. |
| T-25 residual | Two disjoint "recipient"/"TAC trust key" registries need unification or a save-time validation guard | Open since 07-24 (GUI-copy half already fixed). Unchanged. |

## Soft findings — no action recommended

- Carried over unchanged from 07-24: "Bootstrap" covering two unrelated features (no on-screen
  collision yet); the T3 "seed"/`CULVERT_PROXY_SEED_REF`/"pinned digest" vocabulary (internally
  consistent, no finding).
- **New this pass:** the MCP design-doc set's discipline held through implementation — worth noting as a
  positive pattern rather than a finding. No action.

---

## Recommended Refactoring Plan (priority order)

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium | T-18 (carried over) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI (4+ strings); rename the audit-event string | Low (young feature, ~7 call sites, unchanged this pass) | Small-Medium |
| Medium | T-16 (carried over) | Renumber the Supportability-track's colliding ADRs (0008–0011 → 0019–0022) and their cross-references | Low (docs only, 40+ files to check meaning before touching any) | Medium |
| Medium | T-21 + T-32 (new pairing) | Rename Cluster panel's `cp_version`/"CP Config Version" to a cluster-sync-scoped name (e.g. `sync_version`), and F3b's `snapshot_sha256` to a feed-content-scoped name (e.g. `content_sha256`), reclaiming "Config Version"/"snapshot" for the rollback feature only | Low (GUI label + two JSON fields, no known external consumers) | Small |
| Medium | T-17 (carried over) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped canonical names (T-10 DPI pattern) | Medium (config + API + admin-settings field) | Medium |
| Medium | T-29 (new) | Alias YAML/CLI `rate_limit`/`-rate-limit` to accept `rate_limit_rpm` as well, canonicalize on read | Low-Medium (operator-authored config key, needs compat window) | Small |
| Medium | T-30 (new) | Alias YAML `max_conns_per_ip` / wire `MaxConnsPerIP` toward the `conn_limit_max_per_ip` family already used on the admin/API side | Low-Medium (same as T-29) | Small |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium (touches `/api/support/tac-trust` contract or upload-config validation) | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium (on-disk format, parity-test surface) | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low (GUI copy) / Medium-large (schema) | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*`; rename packaging/config comments | Medium (agent wire protocol, rolling-update compat window) | Medium |
| Low-Medium | T-31 (new) | Rename `culvert_clam_scan_errors_total` → `culvert_clamav_scan_errors_total`, dual-emit for one release | Low (6-day-old metric, no known in-repo or external dashboard) | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with the in-app "SSL" terminology | Low (doc titles only, externally linked) | Small |

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass re-confirmed six previously-audited cluster groups
are still clean (including the full GUI-vs-API-vs-docs sweep and the five carried-over findings), found
the MCP Agent Security Gateway's transition from design to implementation held its documented
discipline (a positive result, not a finding), and surfaced four new findings in the 263 commits of
feature work since 07-24 — three ordinary config/metric naming splits (T-29, T-30, T-31) and one fresh
subsystem reusing an already-overloaded term on day one (T-32, which compounds the still-open T-21).
None of the four met this program's same-day fix bar (T-29/T-30/T-31 touch already-shipped config keys,
wire fields, or metrics; T-32 touches on-disk/internal identifiers other F3b code already depends on,
with live API exposure scoped as the very next slice — none are pre-implementation design-doc or
GUI-copy corrections), so all four are documented here for dedicated follow-up at the same priority bar
as the program's existing backlog.
No cosmetic or preference-driven renames were proposed; every new finding here is a genuine cross-surface
naming split an operator, engineer, or support agent would trip over when correlating one surface against
another.
