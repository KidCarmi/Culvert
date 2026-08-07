# Culvert Language & Terminology Governance Review — 2026-08-06

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited the tree at `6a2960eb`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-04.md` (baseline `3d13f7a`). Two days and ~170 commits separate
> the two reviews — the largest window this program has audited, dominated by a new "MCP Qualification"
> feature (PR sequence `mcp-qual-1-inventory` → `mcp-qual-2-*` → `mcp-qual-3-telemetry`: a bounded
> pre-production inventory/catalog/telemetry surface for the Gateway's Observe listener) plus a CHAOS-24
> panic-containment sweep (`obs.SafeCall`/`runGuarded` wrapping periodic sync/persist loops across
> `internal/threatfeed`, `internal/blocklistfeed`, `internal/saasfeed`, `internal/configver`, `metrics.go`,
> `connlimit_startup.go`), a new `docs/operator/traffic-log-destination-privacy.md` runbook, and RFC 9728
> OAuth Protected Resource Metadata support in `internal/mcp/runtime`. Method: (1) checked
> `git diff --name-only 3d13f7a..HEAD` against every file each of the seventeen carried-over open findings
> (T-9, T-11, T-12, T-13 residual, T-16, T-17, T-18, T-21, T-25 residual, T-29 through T-34, T-36, T-37)
> depends on, and for every finding whose files WERE touched, diffed the actual cited lines (not just the
> file) to confirm the collision itself — not merely the file — was unchanged; (2) read every new
> MCP-Qualification file in full and cross-checked new field/label names against the pre-existing
> `adminapi.InventoryCounts`/`CapabilityHealth` contract and the pre-existing `catalog.Eligibility`
> vocabulary, rather than assuming new code is clean by default; (3) checked the new
> `traffic-log-destination-privacy.md` runbook and the pre-existing ADR-0011 cross-reference addition
> against T-17/T-16 respectively; (4) audited the CHAOS-24 sweep and the RFC 9728 addition for new naming
> surface (none found — see Wave 2).
> **Companion change:** none fixed same-day this pass — see T-38/T-39 below for why both are queued rather
> than blind-renamed.

---

## Executive Summary

**No regressions: all seventeen carried-over open findings are re-confirmed unchanged.** For every finding
whose dependent files intersected this unusually large 170-commit window (T-11, T-13 residual, T-16, T-17,
T-21/T-32/T-36 via `internal/configver`, T-29, T-30, T-31, T-33, T-34, T-37 via the CHAOS-24 sweep), the
actual cited lines/strings were diffed and confirmed byte-identical to 08-04 — the touches were unrelated
edits (panic-containment wrappers, comment updates, an unrelated integrity-scan feature, a doc-count bump)
landing in the same files, not fixes or worsenings of the collisions themselves. T-17's only touch is a
one-line comment restating the same drift it doesn't resolve; T-16's ADR-0011 pre-dates this window and
only gained two additive cross-reference lines.

**Two new findings, both on code that shipped in this window's MCP Qualification feature (T-38, T-39).**
**T-38 (High)** is the most concrete collision this program has found to date: `GET /api/mcp/overview`
returns the identical `catalog.ReviewRequired` tool count under **two different field names in the same
JSON response** — `health.gateway.drifted_tools` (pre-existing `adminapi.CapabilityHealth` field, tested, now wired
to real data for the first time this window) and `inventory.review_required_tools` (brand-new
`InventoryStatus` field, this window). The same author, same file (`mcp_inventory.go`), same window, names
one local accumulator `drifted` and the sibling struct field `ReviewRequiredTools` — because "drifted" was
already load-bearing in the interface it was implementing, while "review_required" is what every other
layer of the codebase (the `catalog` package itself, the per-tool disposition DTO, four separate GUI chip
labels) already calls this state. **T-39 (Medium)** is a namespace collision: "Qualification" now names two
unrelated concepts inside the identical `mcp.gateway.*`/`/api/mcp/*` surface — the pre-existing Production
Qualification receipt-gate (`internal/mcp/rollout`) and the new QUAL-2/3 pre-production inventory/telemetry
bootstrap fleet — landing in the same window from two independent PR streams that never cross-reference
each other; the qualification-inventory doc's own text already needs a footnote disclaiming the collision.

**Neither finding clears this program's same-day-fix bar.** T-38 looks superficially cheap (it reads like
T-35 — a same-file, same-window naming slip) but `health.gateway.drifted_tools` is not new: it is a pre-existing,
tested REST API field (`ui_mcp_ux_e2e_test.go` asserts the literal string, introduced in `cf5e0c9e`, well
before this window) now carrying real data for the first time. Per this program's standing compatibility
bar for live, externally-visible wire fields with an existing test assertion (the same bar T-31/T-34/T-37
were held to), this is queued for a dedicated follow-up that updates the field, its one GUI label, and the
one test assertion together — not folded into a governance pass. T-39 needs a design decision (which config
keys/doc titles to rename, and whether QUAL-2/3 needs its own vocabulary entirely) before any mechanical
change.

**Terminology Health Score: 8.3 / 10** (down slightly from 8.5 — this is the first pass in the series to
close with zero same-day fixes despite finding a High-priority item, because the concrete, wired collision
this window produced happens to sit on a pre-existing tested wire field rather than pure GUI copy; the
underlying discipline signal is still strong — seventeen carried-over findings had their largest-ever
window re-confirmed with zero drift, and the new MCP Qualification feature's harder problems — fail-closed
activation, single-source-of-truth registry/catalog sharing, evidence-truth modeling — all held).

---

## Wave 1 — Carried-over findings re-confirmed unchanged

`git diff 3d13f7a..HEAD` (170 commits) was checked against every file each of the seventeen open findings
depends on, and — unlike a pure file-touch check — every finding whose files *were* touched had its actual
cited lines/strings diffed to confirm the collision itself is unchanged, not just co-located with unrelated
edits.

| Finding | Files it depends on | Touched this window? | Collision status |
|---|---|---|---|
| T-9 | export/import + parity-test surface (`exportedAt`) | No | Unchanged |
| T-11 | `policy.go`'s default-action vocabulary, `ui_policy.go` core | `ui_policy.go` touched | Touch is a route-registration comment at line 2263 only; default-action vocabulary code untouched — unchanged |
| T-12 | Maintenance-Agent `/v1/upgrades/*` wire routes | `scripts/install.sh` touched, no `/v1/upgrades` references in the diff | Unchanged |
| T-13 residual | README/enterprise-doc "TLS Inspection" vs. in-app "SSL" | `README.md` touched | Touch is a doc-link fix + package-count bump; "TLS/SSL inspection" strings untouched — unchanged |
| T-16 | ADR numbering (0008–0011) | `docs/adr/0011-decryption-observability.md` touched | ADR pre-dates this window (ratified 07-16); only gained two additive cross-reference lines — unchanged |
| T-17 | `decryption_redact_hosts` / `/api/decryption/redaction` | `admin_settings.go`, `ui_policy.go` comments touched; new `docs/operator/traffic-log-destination-privacy.md` | Underlying identifiers (`DecryptionRedactHosts`, `/api/decryption/redaction`) byte-identical; new runbook documents the behavior under its correct business name without renaming the code — unchanged, more visibly documented |
| T-18 | `internal/sealbox.Seal`/`Open` call sites | No | Unchanged |
| T-21 | `cluster_convergence.go`, `configversion.go`'s rollback `cp_version` surface | `internal/configver/configver.go` touched (new unrelated integrity-scan feature) | `configversion.go`/`cp_version` untouched — unchanged |
| T-25 residual | `support_recipients.go` / `support_tac_trust.go` | No | Unchanged |
| T-29 | YAML `rate_limit` (`config.go`/`main.go`) vs. `rate_limit_rpm` (API/wire/metric) | `config.go`, `main.go` touched | Diffs contain zero `rate_limit`-adjacent lines — unchanged |
| T-30 | YAML `max_conns_per_ip`/wire `MaxConnsPerIP` vs. `conn_limit_max_per_ip` | `connlimit_startup.go` touched | Touch is `runGuarded` panic-containment wrapping only — unchanged |
| T-31 | `culvert_clamav_blocked_total` vs. `culvert_clam_scan_errors_total` | `metrics.go` touched | Touch is `runGuarded` wrapping + an MCP-telemetry `Fprint` addition — unchanged |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` overloads "snapshot" | `internal/configver/configver.go` touched | No `SnapshotSHA256`/`snapshot_sha256` in the touched area — unchanged |
| T-33 | MCP `PolicyAction`/`PolicyReason` mixing three vocabularies | `internal/mcp/runtime/config.go`, `internal/mcp/policy/condition.go`, `internal/mcp/events/denial.go` touched (RFC 9728 metadata, empty-value validation, force-flush — all unrelated); `internal/mcp/runtime/policy.go`/`events.go`/`observe.go` untouched | Grepped the new MCP telemetry/observe/inventory subsystem for new consumers of `PolicyAction`/`PolicyReason` — zero matches; "no consumers today" caveat still holds despite a large new subsystem landing |
| T-34 | SaaS feed status field-name split (`saas_feed_status_api.go`, `ui_policy.go`) | `internal/saasfeed/saasfeed.go` touched (CHAOS-24 wrap only) | `failures_since_start`/`last_successful_activation` vs. `syncFailures`/`lastSuccess` split unchanged |
| T-36 | `config.rollback` audit token vs. freeform config-version-history action string | `internal/configver/configver.go` touched (unrelated) | `configversion.go:293,295` unchanged |
| T-37 | "Manual feed sync" naming split across blocklist/SaaS/threat feeds | `internal/threatfeed`, `internal/blocklistfeed`, `internal/feedsync`, `ui_security.go` all touched (CHAOS-24 wraps + unrelated alerts-test hunk) | `blocklist.feed.sync` / `saasfeed.refresh` / `security.feeds_sync` all unchanged |

## Wave 2 — New territory audited this pass (170 commits since `3d13f7a`)

**The MCP Qualification feature (QUAL-1/2/3) holds strong discipline on its hardest problems.**
Fail-closed activation, a single shared registry/catalog source of truth between the runtime pipeline and
the read-only Admin API (`mcpAdminInventorySources`), bounded/secret-free error classification, and a
genuinely careful evidence-truth model in `mcp_evidence_readmodel.go` (`not_started` vs.
`synthetic_non_qualifying` vs. `unavailable` are real, load-bearing distinctions, not synonyms) — all
verified clean. `docs/operator/mcp-qualification-inventory.md` and `mcp-qualification-telemetry.md` are
internally consistent with their own wire fields.

**The CHAOS-24 panic-containment sweep (`internal/obs/guard.go`, `runGuarded`/`obs.SafeCall`) introduces no
naming collision.** It wires deliberately into the pre-existing `recordCrash`/`culvert_crash_records_total`
product-facing vocabulary rather than inventing a parallel "panic" concept, matching the file's own header
comment. `internal/mcp/adminapi/health.go`/`publication.go`'s diffs (new `EnableRequested`, `Reason`,
`Posture`, `ExecutionEnabled` fields, a Management-non-mutation guard) are additive with no reused names.
The RFC 9728 OAuth Protected Resource Metadata addition to `internal/mcp/runtime/config.go` introduces
standard external vocabulary (`resource_metadata`) with no internal collision. The support panel's
pre-existing "Telemetry (opt-in)" feature and the new MCP Qualification Telemetry are on different routes,
different screens, and never adjacent in the GUI today — noted as a soft/no-action item, not a finding
(PRODUCT-TERMINOLOGY.md already tolerates screen-scoped reuse of generic nouns like "Profile").

**Two genuine findings, both in the new inventory/health surface — see Findings below.**

---

## Findings

### T-38 — `GET /api/mcp/overview` returns the identical tool-eligibility count under two different field names in the same response (new — queued, not fixed)

- **Business concept:** a tool whose observed schema/behavior has semantically drifted from its last known
  fingerprint and now needs human review — `catalog.ReviewRequired` (`internal/mcp/catalog/catalog.go:23`,
  `:42` → `"review_required"`).
- **Current names / collision:** `apiMCPOverview` (`ui_mcp.go:232-256`) returns one JSON object carrying
  BOTH (and `apiMCPHealth`, `ui_mcp.go:258-267`, serves the `"health"` side directly at `GET /api/mcp/health`
  under the same field name):
  - `"health"` → `m.svc.Health.Snapshot()`, a `HealthView` (`internal/mcp/adminapi/health.go:75-80`) whose
    `Gateway CapabilityHealth \`json:"gateway"\`` field nests `DriftedTools int \`json:"drifted_tools"\``
    (`internal/mcp/adminapi/health.go:56`) — the wire path is `health.gateway.drifted_tools`, confirmed
    against the pinned fixture in `ui_mcp_ux_e2e_test.go:30-33`. This window's new
    `mcpInventoryCounts.Counts()` (`mcp_inventory.go:135-151`) populates it for the first time with real
    data — the local accumulator is literally named `drifted` (line 147: `case catalog.ReviewRequired:
    drifted++`), inherited from the pre-existing `adminapi.InventoryCounts` interface signature
    (`internal/mcp/adminapi/health.go:88`, `Counts(capability string) (servers, quarantined, drifted int)`)
    it implements.
  - `"inventory"` → `inventoryStatus()` (`mcp_inventory.go:187-217`), a brand-new `InventoryStatus` struct
    whose `ReviewRequiredTools int \`json:"review_required_tools"\`` field (line 180) is populated by the
    *same switch statement over the same `catalog.Eligibility` enum*, two functions later in the *same
    file*, using the name every other layer of the codebase already uses for this state: the `catalog`
    package's own `String()` method (`catalog.go:42`), the per-tool inventory DTO
    (`internal/mcp/adminapi/inventory.go:49,51` → `"disposition":"review_required"`,
    `"review_required":true/false`), and four separate GUI chip labels in `static/index.html` (lines 18578,
    19665, 19725, 19774 — all render literal text `'review required'`).
  - The GUI surfaces both under different words too: `static/index.html:19951` renders the `health` side as
    the KV row **"Drifted tools: N"** on the MCP Command-Center health card, while the `inventory` side's
    counterpart chips elsewhere on the same admin surface all say "review required."
- **Why this is real drift, not cosmetic:** this is not a doc-vs-doc or nav-vs-title disagreement — it is
  the *same API response* naming the identical undelying count two different things in sibling top-level
  keys, authored by the same change in the same file. An admin or a support engineer building tooling
  against `/api/mcp/overview` (or just reading it in a browser devtools tab while triaging MCP tool health)
  has to already know these are the same number to correlate `health.gateway.drifted_tools` with
  `inventory.review_required_tools` — nothing in the response says so. "review_required" is unambiguously
  the codebase's established name for this state (five independent sites predate or land alongside this
  window using it); "drifted" is the outlier, present only in the older `CapabilityHealth` field, its one
  GUI label, and the test that pins it.
- **Why not fixed this pass:** `health.gateway.drifted_tools` is not new. It is a pre-existing, tested REST
  API field, live on both `GET /api/mcp/overview` and `GET /api/mcp/health` — `ui_mcp_ux_e2e_test.go:32`
  asserts the literal string `"drifted_tools":2`, introduced in `cf5e0c9e` well before this window's
  `3d13f7a` baseline. This window is what makes the field carry real (non-zero) data for the first time,
  not what introduced the name. Per this program's standing compatibility bar for live, externally-visible
  wire fields (the same bar T-31, T-34, and T-37 were held to), an outright rename is not the right
  same-day move even setting the test aside: `CapabilityHealth` is a stable, already-shipped response shape
  with no documented consumer inventory, so a straight field removal risks breaking any external tooling
  built against it, however unlikely — the same reasoning this report already applies to T-29/T-30's
  YAML/wire aliasing recommendations.
- **Recommended canonical name / fix:** dual-emit rather than rename: keep `CapabilityHealth.DriftedTools`/
  `drifted_tools` (`internal/mcp/adminapi/health.go:56`) for wire compatibility and add a second field
  `ReviewRequiredTools int \`json:"review_required_tools"\`` alongside it, populated from the same
  `mcpInventoryCounts.Counts()` value (`mcp_inventory.go:135-151`) — mirroring what
  `mcp_inventory.go`'s own `InventoryStatus.ReviewRequiredTools` already does one struct over. Update
  `static/index.html:19951`'s GUI label "Drifted tools" → "Review-required tools" to read the new field
  (cosmetic, no wire dependency) and add both fields to the OpenAPI spec, which currently documents neither.
  Deprecate `drifted_tools` in a doc comment; a hard removal, if ever justified, is a separate,
  compatibility-reviewed change — not this program's call to make unilaterally.
- **Priority:** High (a live, wired, admin-visible collision inside a single API response an operator reads
  directly, present on two endpoints). **Migration risk:** Low for the dual-emit addition itself (purely
  additive, no existing field or test touched); a future removal of `drifted_tools` would be a separate,
  higher-risk, dedicated compatibility decision. **Est. PR size:** Small.

### T-39 — "Qualification" now names two unrelated concepts inside the same `mcp.gateway.*` config namespace and `/api/mcp/*` admin surface (new — queued, not fixed)

- **Business concept A (pre-existing):** **Production Qualification** — a cryptographically-verified
  receipt gating promotion of an MCP rollout-mode capability to Production
  (`internal/mcp/rollout.ProductionQualificationVerifier`, `QualificationBinding`,
  `mcperr.ReasonRolloutQualificationInvalid`). This window's `mcp_evidence_readmodel.go` (PR-UX-6) and its
  GUI card (`static/index.html:19301`, "Production Qualification - …") build a new read-model directly over
  this pre-existing concept.
- **Business concept B (new this window):** a bounded, disposable pre-production test/staging fleet used to
  bootstrap and validate the Observe listener itself, from the independent `mcp-qual-1/2/3` PR sequence —
  `qualification_inventory_file`/`QualificationInventoryFile` (`config.go:223-234`),
  `qualification_telemetry`/`QualificationTelemetry` (`config.go:235-261`), the "qualification tenant"
  concept (`mcp_inventory.go:224-227`), and `local-qualification-archive` (`mcp_telemetry.go:49`).
  `docs/operator/mcp-qualification-telemetry.md:150` names "a defined qualification environment" as a
  still-missing *future* deliverable — a third sense layered on top of the first two.
- **Why this is real drift:** both concepts live under the identical `mcp.gateway.*` YAML namespace and
  `/api/mcp/*` admin surface, both shipped in this window from independent PR streams, and neither
  cross-references the other. The qualification-inventory doc's own closing line already has to disclaim
  the collision explicitly: *"Loading an inventory does not change any QUAL-1 guarantee... Production stays
  qualification-locked"* — the authors needed a footnote to keep readers from conflating the two, which is
  itself evidence the names collide. An admin or support engineer reading "qualification" anywhere in the
  MCP admin area has no signal, absent the surrounding sentence, which of two unrelated things is meant.
- **Why not fixed this pass:** this needs a real design decision — what to call the QUAL-2/3 bootstrap
  fleet (environment-scoped language like "staging"/"pilot" vs. some other umbrella), and whether the
  config-key rename should carry a read-compat alias for the one config surface it touches
  (`qualification_inventory_file`, `qualification_telemetry` are new-this-window YAML keys with, per a
  targeted grep, no shipped admin deployment depending on them yet — the cheapest point to rename them is
  now, before they accrue users, but the naming choice itself is a product call, not a mechanical rename).
- **Recommended canonical name / fix:** rename the QUAL-2/3 config block and both operator-doc titles to an
  environment-scoped name (e.g. `staging_inventory_file`, `pilot_telemetry`, or "bootstrap fleet") and
  reserve bare "Qualification"/"qualification-locked" exclusively for the pre-existing Production-promotion
  receipt gate, matching `internal/mcp/rollout`'s established usage.
- **Priority:** Medium (not yet GUI-visible for QUAL-2/3 specifically — no admin panel consumes
  `InventoryStatus`/`mcpTelemetryStatus()` under the word "qualification" itself, only under
  "inventory"/"telemetry" — so today this is a config-key/doc-level collision, not a live GUI one).
  **Migration risk:** Medium (a checked-in YAML config key and two doc titles; genuinely cheapest to change
  now, before deployment, rather than later). **Est. PR size:** Small-Medium (needs a naming decision
  first).

---

## Carried over, still open (re-confirmed this pass, see Wave 1 table for evidence)

| Finding | Business concept | Status |
|---|---|---|
| T-9 | `exportedAt` → `capturedAt` rename | Open since 07-07. Unchanged. |
| T-11 | `allow`/`deny` default-action vocabulary vs. 4-value `PolicyAction` | Open since 07-16. Unchanged. |
| T-12 | Maintenance-Agent wire API "upgrade" vs. GUI/API "update"/"Dispatch" | Open since 07-16. Unchanged. |
| T-13 residual | README/enterprise-doc "TLS Inspection" vs. in-app "SSL" | Open since 07-24 (soft/low). Unchanged. |
| T-16 | ADR numbering collision: 0008–0011 | Open since 07-19. Unchanged. |
| T-17 | Traffic-log destination-privacy config key/route still says "decryption" | Open since 07-19. Unchanged; now more visibly documented under its correct business name by the new runbook, without being fixed. |
| T-18 | "Seal" names two unrelated cryptographic operations | Open since 07-19, grew 07-24. Unchanged. |
| T-21 | "Config Version" names two unrelated, independently-incrementing counters | Open since 07-24. Unchanged; still compounded by T-32. |
| T-25 residual | Two disjoint "recipient"/"TAC trust key" registries | Open since 07-24. Unchanged. |
| T-29 | Per-IP rate limit: `rate_limit` (YAML/CLI) vs. `rate_limit_rpm` (API/wire/metric) | Open since 08-01. Unchanged. |
| T-30 | Per-IP connection cap: `max_conns_per_ip`/`MaxConnsPerIP` vs. `conn_limit_max_per_ip` | Open since 08-01. Unchanged. |
| T-31 | ClamAV metric family: `clamav` everywhere except `culvert_clam_scan_errors_total` | Open since 08-01. Unchanged. |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` reuses the overloaded term "snapshot" | Open since 08-01. Unchanged; still not wired onto any live GET response. |
| T-33 | MCP `PolicyAction`/`PolicyReason` observation fields mix three vocabularies | Open since 08-02. Unchanged; re-verified zero consumers even after a large new subsystem landed this window. |
| T-34 | SaaS feed status field-name split across two admin endpoints | Open since 08-02. Unchanged. |
| T-36 | `config.rollback` audit token vs. freeform config-version-history action string | Open since 08-04. Unchanged. |
| T-37 | "Manual feed sync" audit-action naming split across blocklist/SaaS/threat feeds | Open since 08-04. Unchanged. |
| T-38 | `drifted_tools` vs. `review_required_tools` — same count, same API response, two names | **New, open.** See Findings. |
| T-39 | "Qualification" names two unrelated concepts in the same config/admin namespace | **New, open.** See Findings. |

## Soft findings — no action recommended

- Carried over unchanged from 07-24 onward: "Bootstrap" covering two unrelated features (no on-screen
  collision yet); the T3 "seed"/`CULVERT_PROXY_SEED_REF` vocabulary (internally consistent).
- Carried over unchanged from 08-03: the `culvert_decrypt_*` metric prefix vs. the fully-spelled
  `decryption`/`decryption-profile` API/audit/alert namespace — internally consistent on each side and
  already documented verbatim in `CLAUDE.md`'s autoexclude section; read as a deliberate abbreviation.
- Carried over unchanged from 08-04: `roadmap/google-captcha-swg-investigation.md:177`'s speculative
  `culvert_connlimit_rejections_total` metric citation for a counter that shipped as a REST field only —
  still not a collision (no second live name exists).
- **New this pass:** `drifted_tools` does not appear anywhere in `api/openapi/openapi.json`/`.yaml` despite
  being a live, tested field on `GET /api/mcp/overview` — an OpenAPI-spec coverage gap, not a naming
  collision by itself, but worth closing in the same change that fixes T-38 (see that finding).
- **New this pass:** the support panel's pre-existing "Telemetry (opt-in)" feature and the new MCP
  Qualification Telemetry are a third generic sense of "telemetry" alongside the pre-existing OTLP export —
  different routes, different admin screens, no on-screen adjacency today. Consistent with how
  PRODUCT-TERMINOLOGY.md already tolerates screen-scoped reuse of generic nouns (e.g. "Profile"); noted for
  completeness, not a finding.
- **New this pass:** the MCP Qualification feature's harder design problems (fail-closed activation,
  single-source-of-truth registry/catalog sharing between runtime and Admin API, bounded/secret-free error
  classification, and the `not_started`/`synthetic_non_qualifying`/`unavailable` evidence-truth distinctions
  in `mcp_evidence_readmodel.go`) all held discipline under direct verification — continued positive
  pattern, not a finding.

---

## Recommended Refactoring Plan (priority order)

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| High | T-38 (new) | Dual-emit `CapabilityHealth.ReviewRequiredTools`/`review_required_tools` alongside the existing `DriftedTools`/`drifted_tools` (keep the old field for wire compatibility); update the GUI label; add both fields to the OpenAPI spec | Low (additive) | Small |
| Medium | T-18 (carried over) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI; rename the audit-event string | Low | Small-Medium |
| Medium | T-16 (carried over) | Renumber the Supportability-track's colliding ADRs (0008–0011 → 0019–0022) | Low (docs only) | Medium |
| Medium | T-21 + T-32 (carried pairing) | Rename Cluster panel's `cp_version` and F3b's `snapshot_sha256` to unambiguous, non-colliding names | Low | Small |
| Medium | T-17 (carried over) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped names | Medium | Medium |
| Medium | T-29 (carried over) | Alias YAML/CLI `rate_limit`/`-rate-limit` to accept `rate_limit_rpm` as well | Low-Medium | Small |
| Medium | T-30 (carried over) | Alias YAML `max_conns_per_ip` / wire `MaxConnsPerIP` toward `conn_limit_max_per_ip` | Low-Medium | Small |
| Medium | T-36 (carried over) | Give `saveConfigVersion`'s rollback call a `config.rollback`-prefixed action string alongside the version number | Low | Small |
| Medium | T-37 (carried over) | Rename `security.feeds_sync` → `threatfeed.sync`; update `security_feedsync_audit_test.go`'s three literal assertions | Low | Small |
| Medium | T-39 (new) | Decide the QUAL-2/3 bootstrap-fleet name; rename `qualification_inventory_file`/`qualification_telemetry` and both operator-doc titles away from "qualification"; reserve that word for the Production receipt gate | Medium | Small-Medium |
| Medium | T-33 (carried over) | Stop overwriting `PolicyAction`/`PolicyReason` for pre-/post-policy gate failures; add a dedicated field for those instead | None today (re-verified zero consumers); rises once a consumer exists | Small |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low / Medium-large | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*` | Medium | Medium |
| Low-Medium | T-31 (carried over) | Rename `culvert_clam_scan_errors_total` → `culvert_clamav_scan_errors_total`, dual-emit | Low | Small |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass re-confirmed, via a diff check against every cited line
(not just file) across all seventeen previously-open findings, that none of them regressed across the
largest window this program has audited — 170 commits over two days. It then applied the same level of
scrutiny to the window's dominant new feature (MCP Qualification) that the 08-04 pass first applied to the
MCP UX legs, and found the program's cleanest-yet piece of concrete evidence: a single API response
(`GET /api/mcp/overview`) naming the identical count two different things in two sibling keys, introduced by
the same file in the same window. Unlike 08-04's T-35, this finding does not clear the same-day-fix bar,
because the older of the two colliding names is a pre-existing, tested wire field rather than pure GUI copy
— consistent with how this program has always treated live, externally-visible strings with test coverage
(T-31, T-34, T-37). A second finding (T-39) surfaced a namespace collision between the pre-existing
Production Qualification receipt gate and the new pre-production "qualification" bootstrap fleet, queued
pending a naming decision. No cosmetic or preference-driven renames were proposed.
