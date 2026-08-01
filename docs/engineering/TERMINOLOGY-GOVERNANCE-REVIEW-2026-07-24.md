# Culvert Language & Terminology Governance Review — 2026-07-24

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Six parallel concept-cluster audits against the tree at `2eef667`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-07-19.md` (baseline `6349722`). Three lanes re-verified the
> clusters prior reviews already covered (auth/session/RBAC/TOTP/lockout/CA, SSL-inspection/
> decryption/autoexclude, policy/blocklist/threat-feed/URL-category/content-scanning, cluster CP-DP/
> HA/release-catalog/config-versioning) to confirm no regression. Three more targeted the ~112 commits
> that landed *after* the 07-19 review and have never been through a governance pass: the M6 TAC
> secure-upload feature, the M7 proactive-support/telemetry design (landed *today*, still 100%
> unimplemented), the MCP Agent Security Gateway PR-0 design baseline, the new OpenAPI contract
> program (ADR-0007/0018), the T3 10M-scale config-sync project, and the catalog-driven fresh-install
> hardening work.
> **Companion change:** ten zero-risk, copy/doc/comment-only fixes ship with this review (see "Fixed
> in this change"). No REST route, JSON field, CLI flag, config key, audit-event name, or exported Go
> identifier was renamed — one design-doc's *proposed, not-yet-shipped* field/filename vocabulary was
> corrected before it could calcify into any of those.

---

## Executive Summary

The three re-verification lanes found nothing new — every cluster the 07-07 through 07-19 reviews
already certified clean still holds, and the DPI/T-10 residual, "updater" retirement, and CP/DP/HA
naming remain intact. The three new-territory lanes surfaced real drift, concentrated (as expected)
in the youngest features: a design doc that reintroduced the glossary's explicitly-banned "Incident"
concept days before implementation was due to start, a second ADR-numbering collision (a variant of
the still-open T-16), a GUI security-bypass dialog citing a scanning engine ("DLP") that does not
exist in this product, a functional dead-end between two same-screen "recipient" registries, and two
smaller doc/doc and doc/CLAUDE.md self-contradictions.

**Terminology Health Score: 8.5 / 10** (unchanged from 07-19 — new-code/new-doc findings on ~112
commits of fresh feature work is the expected rate of drift for a program at this cadence, not a
regression; the one item that would have moved the score — M7's "Incident" — was caught and fixed
*before* it shipped, which is exactly what this review cadence exists to do).

**Fixed in this change (all copy/comment/doc-only or pre-implementation design-doc corrections, zero
compatibility risk — nothing shipped depends on any of the old names):**

- **T-22 — Second ADR-0007 collision.** `docs/adr/ADR-0007-openapi-contract.md` (landed 2026-07-19,
  Accepted) collided with the pre-existing `docs/adr/0007-secret-containment-boundary.md`
  (2026-07-06, Proposed) — the same failure class as the still-open T-16 (0008–0011), now recurring at
  0007 because the new file also broke the established `NNNN-slug.md` naming convention (all 17 prior
  ADRs use a bare number prefix; this one prefixed with a literal `ADR-`, which is likely how it slid
  past review). Renamed to `docs/adr/0018-openapi-contract.md` (next unclaimed number) and updated its
  own H1 plus all 12 citing locations (`docs/api/API-IMPLEMENTATION-PLAN.md`,
  `API-IMPLEMENTATION-REPORT.md` ×2, `API-STYLE-GUIDE.md`, `API-OPENAPI-RESEARCH.md` ×2,
  `API-CONSISTENCY-RISK-REGISTER.md`, `api/README.md`, `.github/CODEOWNERS`, and three MCP design docs
  that cite it — `ADR-PROPOSAL-mcp-trust-boundary.md`, `VERIFIED-REPOSITORY-CONTEXT.md` ×3,
  `SSDLC-CONTROL-MAPPING.md`). Confirmed disjoint from the unrelated, correctly-unrenamed
  `ADR-0007-secret` citation in `VERIFIED-REPOSITORY-CONTEXT.md:54`, which still means
  `0007-secret-containment-boundary.md`. **Note for the still-open T-16 fix:** its recommended target
  range (0018–0021, for renumbering the Supportability-track's own 0008–0011 collision) must shift to
  **0019–0022** now that 0018 is claimed — updated in the Recommended Refactoring Plan table below.
- **T-23 — DIRECT-bypass warning dialogs cited a scanning engine that does not exist.** The two most
  security-critical confirmation dialogs in the product (`static/index.html:1805` and `:12725`, shown
  immediately before a full security-path bypass is published) warned that DIRECT traffic "skips SSL
  inspection, **DLP**, CDR, **URL filtering**, **threat inspection**, authentication, policy, and all
  proxy logging." Culvert has no DLP feature (confirmed by full-repo grep — the string never appears
  outside prose/roadmap docs), and "URL filtering"/"threat inspection" are, respectively, always
  "Blocklist/URL Category" and "Threat Feed" everywhere else in the product (`docs/design/
  PRODUCT-TERMINOLOGY.md`'s canonical engine list: ClamAV, YARA, DPI, Threat Feeds, CDR, GeoIP). The
  sibling SSL-bypass confirm dialog on the same screen (`:7783`) already gets this right ("Content
  scanning (ClamAV/YARA/DPI/CDR)"). Reworded both DIRECT-bypass strings to match: "SSL inspection,
  content scanning (ClamAV/YARA/DPI), CDR, Blocklist/URL Category enforcement, Threat Feed,
  authentication, policy, and all proxy logging." Copy only.
- **T-24 — M7 design doc reintroduced the glossary-banned "Incident" concept (caught pre-implementation).**
  `docs/design/PRODUCT-TERMINOLOGY.md` states plainly: *"Incident | Not a product concept. No backend
  entity — MUST NOT appear in the UI."* `roadmap/M7-proactive-telemetry-plan.md` §11 (landed *today*,
  2026-07-24, as the implementation-authoritative contract for the next milestone) specified exactly
  that: a durable **"incident state machine"**, `proactive_incidents.json`, fields
  `incident_fingerprint`/`incident_start`, and a Slice-4 GUI for it. The same section's prose also
  conflated this *new* stateful entity with the *pre-existing*, unrelated, stateless "incident scope"
  catalog (`support_scopes.go`, M3-era) in the same sentence ("pre-stages an incident-scoped bundle").
  M7 has shipped zero code (confirmed: `supportMetricRegistry`, `proactiveCheckDescriptor`,
  `proactive_incidents.json`, and every other new identifier in the doc have zero hits in `*.go` or
  `static/index.html`), so this was fixable as a pure design-doc edit at the cheapest possible moment
  — before an implementer turns the doc's exact field/filenames into shipped Go identifiers, JSON
  fields, and GUI strings. Renamed the new entity **"degradation"** throughout §11, §14 (Slice 4
  title), §16 (red-team), §17–18 (definition-of-done), and the two test names that referenced it
  (`TestProactiveRecoveryClosesIncident` → `...ClosesDegradation`), while leaving every correct,
  pre-existing "incident scope" reference (the `support_scopes.go` catalog) untouched. Added an
  explicit one-line disambiguation in §11 itself so a future reader — or implementer — cannot
  re-collapse the two concepts, and an explicit instruction that the eventual Slice-4 GUI must say
  "degradation," never "incident." Also fixed the same section's `support_uptime_bucket` metric ID,
  which was the one exception to the registry's own `support_health_*` naming convention (§7) —
  renamed to `support_health_uptime_bucket` in the design doc, before it ships as a real metric ID.
  Design-doc-only; zero code, wire, or persisted-field impact (nothing has shipped yet to be
  compatibility-broken).
  > **SUPERSEDED (2026-07-31, M7 Slice 2.5-A contract sync).** The rename described in the
  > preceding two lines (`support_uptime_bucket` → `support_health_uptime_bucket`) did **not**
  > ship. When the registry was implemented, the metric shipped as **`support_uptime_bucket`**
  > (`support_telemetry_registry.go`; golden fixture `testdata/telemetry/v1/inner_sample.json`;
  > `registry_hash 061fe684…`). The `support_health_uptime_bucket` spelling above is therefore an
  > **erroneous historical proposal**, retained only as the record of this review; the authoritative
  > id is `support_uptime_bucket`, and `roadmap/M7-proactive-telemetry-plan.md` §7 has been corrected
  > to match the shipped registry.
- **T-25 (partial) — Two disjoint "recipient" registries reachable from the same GUI panel create a
  functional dead end (GUI copy fixed now; deeper unification deferred).** M5's admin-CRUD named
  recipient registry (`support_recipients.go`, GUI section "Sealing recipients," feeds only the manual
  "Seal" download) and M6's separate baked/env "TAC trust key" store (`support_tac_trust.go`, GUI
  section "TAC trust keys," feeds only the automated "Upload to TAC" button) are entirely blind to each
  other, yet the M5 section's own placeholder text explicitly suggested naming an entry `tac-prod` —
  and the two sections sit stacked in one GUI panel (`static/index.html:4402-4425`). An admin
  following that placeholder's own example and then clicking "Upload to TAC" gets a `409 "no TAC
  recipient trust key configured"` — a functional dead end, not just a wording ambiguity. Relabeled
  the M5 section "Sealing recipients (manual export only)," reworded its hint to state explicitly that
  it is separate from "TAC trust keys" below and feeds only the manual *Seal* download (never
  *Upload to TAC*), and changed the misleading `tac-prod` placeholder example to a neutral name.
  **Not fixed this pass:** actually unifying the two registries (so a manually-registered recipient
  could also serve the upload path) is a design decision touching the `/api/support/tac-trust`
  read-only contract, not a terminology fix — documented below as a dedicated follow-up, same bar as
  T-9/T-11/T-12/T-17/T-18.
- **T-26 — T3 design doc contradicted itself: "drift hash" (decision D1) vs. "synced fingerprint"
  (the doc's own later "P1 IMPLEMENTATION STATUS" section, and everything actually shipped).**
  `roadmap/T3-config-sync-scale-plan.md`'s original design decision D1 (line ~56) named the
  CP-vs-DP blocklist integrity check "the drift hash." Every shipped identifier
  (`internal/blocklist/delta.go`'s `SyncedFingerprint`/`syncedFP`, `controlplane.go`'s `synced_fp`
  JSON field, `cluster_convergence.go`'s `FPMismatch`) calls it "synced fingerprint" — and the same
  design doc's own P1-status addendum, written after the code shipped, already switched to "synced
  fingerprint" without going back to fix D1. Corrected D1's two "drift hash" references to "synced
  fingerprint" so the document no longer disagrees with itself (or the shipped code) depending which
  section is read. Doc-only, two lines.
- **T-27 — CLAUDE.md's own documented install seed-precedence went stale.** CLAUDE.md's P1.4 section
  (unchanged text across all 112 commits since the 07-19 review) stated the fresh-install image-seed
  precedence as `CULVERT_PROXY_SEED_REF` → running-container image → `ghcr.io/kidcarmi/culvert:latest`
  → local build. The actual shipped precedence in `scripts/install.sh` (the recent catalog-bootstrap
  hardening work) is now `CULVERT_PROXY_SEED_REF` → running-container image → the **signed release
  catalog** (the new trusted default, resolving to a verified immutable digest) → **no tag
  enumeration, no `:latest`, no local build in the trusted path** (legacy tag discovery survives only
  behind an explicit, disabled-by-default `CULVERT_INSTALL_ALLOW_TAG_DISCOVERY=1` break-glass). Since
  CLAUDE.md is this repository's own "OVERRIDE any default behavior" authoritative doc, a stale claim
  here is higher-stakes than an ordinary operator-doc drift — a reader (human or agent) trusting it
  would believe a registry-unreachable host silently falls back to `:latest` or a local build, the
  opposite of the new fail-closed design. Updated the one sentence to name the catalog step and the
  removal of `:latest`/local-build from the trusted path.
- **T-28 — "G1"/"G3"/"G4" now named two unrelated gap-finding series (same failure class as T-16,
  different identifier family).** `docs/design/M3-POLICY-ARCH-REVIEW.md` already uses bare `G1`/`G3`/
  `G4` as durable, actively-cross-referenced rulebase-UX gap IDs (`G4` is cited in shipped code,
  `policy_draft.go:426`). The brand-new `docs/operator/catalog-bootstrap-install-runbook.md` introduced
  `[G3] Release cutover checklist` and `[G4] Pinned-identity rotation` as unrelated release-engineering
  checklist headers, and `release_bootstrap_provenance.go:1` added a `(G1)` comment tag for yet another
  unrelated concept (bootstrap provenance). Dropped the colliding bracketed-letter tags from the three
  new-doc/comment sites (they were decorative, not cross-referenced by number anywhere else) and added
  a one-line note in the runbook pointing at `M3-POLICY-ARCH-REVIEW.md` so a future author doesn't
  reintroduce the same G-numbers for a third unrelated feature. Comment/doc-only; the `policy_draft.go`
  `G4` comment (the original, correct usage) is untouched.
- **Minor — MCP `AUTH-AND-CREDENTIAL-MODEL.md` claimed to "mirror" a table it actually extends.**
  Line 38 said its 8-row principal-type table "mirrors" `BLUEPRINT.md` §10's 7-row identity table; the
  8th row (**Tenant**) is correctly `[INFER]`-tagged as net-new in the table itself, but the surrounding
  prose's word choice implied an exact match. One-word-class fix: "mirror" → "extend ... with Tenant
  elevated from a field ... to its own principal type."

**Documented, not fixed this pass (sized for a dedicated follow-up, same bar as T-9/T-11/T-12/T-17/T-18):**

- **T-21 (new) — "Config Version" now labels two unrelated, independently-incrementing counters.**
  The admin rollback feature's "Config Versions" panel (`configversion.go`, `saveConfigVersion()`,
  ~17 curated call sites) and the Cluster panel's "CP Config Version" stat tile
  (`cluster_convergence.go`'s `CPVersion = globalConfigStore.Version()`, incremented on *every* CP
  snapshot publish) are both integers labeled "Config Version" in the same admin UI, tracking
  completely different things that will diverge in practice. A support engineer troubleshooting "the
  DP is stuck on an old config version" using the Cluster panel's number would look it up in the wrong
  list. See Findings for detail.
- **T-16 (carried over, target range updated) — ADR numbering collision at 0008–0011,** between the
  decryption-exclusion track and the Supportability-framework track. Unchanged in scope; its
  recommended renumber target is now **0019–0022** (was 0018–0021 — 0018 is now claimed by this
  pass's T-22 fix).
- **T-25 residual (new) — unifying the two "recipient"/"TAC trust key" registries** so a
  manually-registered recipient can also serve the automated upload path (or, short of that, a
  stronger runtime check that rejects the upload-config save when no TAC trust key exists, so the
  `409` at click-time becomes a `400` at save-time). Design decision, not a terminology fix.
- **T-9, T-11, T-12, T-17, T-18** — re-confirmed still open, unchanged in scope from 07-19. T-18
  ("Seal" naming two unrelated crypto operations) specifically **grew** this pass: M6 added several
  new bare-"Seal" call sites and GUI strings (`sealBundleToTAC`, the "Upload to TAC" tooltip/confirm
  dialog/toast) without introducing any new *class* of collision — see Findings for the delta, still
  deferred as a coordinated exported-API+GUI+audit-event rename.

See "Findings" below for full detail, including the four carried-over already-open items this pass
re-confirmed still open.

---

## Wave 1 — Re-verified clean (no new drift since 2026-07-19)

Independently re-audited by three separate lanes and confirmed still holding: authentication/session/
RBAC/lockout/TOTP/CA/PSCA naming (including the `UnauthMode` retirement — the one surviving legacy URL
`/api/settings/unauth-mode` remains a deliberately-noted URL-stability exception, not drift);
SSL-inspection/decryption/autoexclude naming (the T-13 in-screen fix from 07-19 holds; the
README-vs-in-app SSL/TLS document-brand residual remains open exactly as documented, no new action);
policy-engine/blocklist/threat-feed/URL-category naming (T-11 re-confirmed open, unchanged); content
scanning (T-10's operator-visible layer remains fixed, the `configBackup` field-name residual remains
open at Low priority, unchanged); Control Plane/Data Plane/enrollment/node-group naming; the HA
fencing-lease "term"/"epoch" pairing (still intentionally disambiguated, per ADR-0005 and its own GUI
tooltip); release-catalog/maintenance-agent naming (the "updater" retirement holds — zero live
GUI/API/route references remain; every surviving mention is explicitly marked deprecated/legacy).

## Wave 2 — New territory audited this pass (~112 commits since `6349722`)

M6 TAC secure-upload (support-bundle sealed export + automated upload, PR-1 through PR-6, ~19
commits); M7 proactive-support & opt-in telemetry design (Rev 0→3, landed today, 100%
design-doc-only, zero shipped code); the MCP Agent Security Gateway PR-0 design baseline (28 files,
~6,955 lines, also 100% documentation, zero shipped code); the OpenAPI contract program (ADR-0007/
0018, the Go-native enforcement engine, and its CI gates); the T3 10M-scale config-sync project
(incremental blocklist delta sync, CP-side marshal cache, the "Config Sync Convergence" GUI panel);
catalog-driven fresh-install hardening (`bootstrap-resolve`, signed-catalog seed precedence, cosign
verification chain, anti-rollback floor). Findings T-21 through T-28 below are new to this pass.

---

## Findings

### T-21 — "Config Version" names two unrelated counters (new — documented, not fixed)
- **Business concept:** an integer identifying a captured configuration state — but there are two
  independent such integers in the product today.
- **Current names:** Concept A — the admin **rollback** feature: `static/index.html:2186-2194` panel
  "Config Versions" ("Every configuration change creates a numbered snapshot"), backed by
  `configversion.go` (`configver.New("/data/config_versions", 0)`), incremented only via the curated
  `saveConfigVersion()` call sites (~17, per CLAUDE.md). Concept B — the Cluster panel's **CP→DP sync
  generation**: `static/index.html:3961` stat tile labeled **"CP Config Version"** (`id="conv-version"`,
  in the "Config Sync Convergence" section), populated from `cp_version` →
  `cluster_convergence.go:41`'s `CPVersion = globalConfigStore.Version()` — the `ConfigSnapshot`'s
  publish version, incremented on every CP snapshot publish (`controlplane_snapshot.go`), independent
  of the curated rollback call sites.
- **Why this is real drift:** both are integers labeled "Config Version" and both are visible in the
  same admin UI, yet Concept A only advances on the curated action list and Concept B advances on
  every snapshot publish — they will diverge in normal operation, not just in a corner case. A support
  engineer using the Cluster panel's "CP Config Version" number to look up the corresponding entry in
  the Config Versions rollback list will find a mismatched or nonexistent one.
- **Recommended canonical name:** rename the Cluster-panel label/JSON field to something namespaced to
  cluster sync — e.g. "Cluster Sync Version" / `sync_version` — mirroring how `catalog_version` is
  already namespaced for the unrelated release-catalog concept, reserving "Config Version" exclusively
  for the rollback feature. A secondary, same-root-cause nit: `configversion.go` comments and GUI copy
  (`static/index.html:9536`, "restored config snapshots") informally call the rollback payload a
  "snapshot," which is also the literal name of the distinct `ConfigSnapshot` CP→DP struct — the same
  rename would resolve this too by simply not reusing "snapshot" for the rollback feature's copy.
- **Why not fixed this pass:** the Cluster-panel field (`cp_version` in the API response) is a live,
  externally-observable API surface even though it appears to be CP-UI-only telemetry not consumed by
  DPs — renaming any JSON field warrants the same care as T-17's alias-on-read treatment, not a
  same-day blind rename.
- **Priority:** Medium (support/ops confusion; no security or correctness bug — both systems function
  correctly, only the shared label misleads). **Estimated PR size:** Small (one GUI label + one JSON
  field + its one consumer).

### T-22 — Second ADR-0007 collision (FIXED)
- **Business concept:** the unique identifier for an Architecture Decision Record.
- **Current names before fix:** `docs/adr/0007-secret-containment-boundary.md` (2026-07-06) and
  `docs/adr/ADR-0007-openapi-contract.md` (2026-07-19) both claimed ADR-0007, actively cross-referenced
  by 6 and 12 files respectively with no sentence-level interleaving between the two meanings (unlike
  T-16, which does interleave and is why T-16 remains deferred).
- **Fix:** renamed the newer file to `docs/adr/0018-openapi-contract.md` (next unclaimed number) and
  updated all 12 citing locations plus its own H1. See "Fixed in this change" above for the full file
  list.
- **Priority:** was Medium; now closed. **Note:** shifts T-16's recommended renumber target from
  0018–0021 to 0019–0022.

### T-23 — DIRECT-bypass dialogs cited a nonexistent "DLP" engine (FIXED)
See "Fixed in this change" above. **Priority:** was Medium (admin-facing confusion on a high-stakes
security-bypass confirmation dialog). **Migration risk:** none — copy only, two near-identical string
literals.

### T-24 — M7 design doc reintroduced the glossary-banned "Incident" concept (FIXED pre-implementation)
See "Fixed in this change" above. **Priority:** was High for a shipped feature; caught at the design
stage, where the fix is free. **Migration risk:** none — the doc had shipped zero code.

### T-25 — Two "recipient" registries create a functional GUI dead end (partial fix; residual documented)
See "Fixed in this change" and "Documented, not fixed this pass" above. **Priority:** Medium (real
admin-facing functional dead end, not just wording). **Fixed-this-pass migration risk:** none — GUI
copy/placeholder text only. **Residual:** Medium-sized follow-up (touches `/api/support/tac-trust`
or the upload-config save path).

### T-26 — T3 design doc self-contradicted "drift hash" vs. "synced fingerprint" (FIXED)
See "Fixed in this change" above. **Priority:** was Low (doc-only self-contradiction, code was already
consistent). **Migration risk:** none.

### T-27 — CLAUDE.md's install seed-precedence claim went stale (FIXED)
See "Fixed in this change" above. **Priority:** Medium (CLAUDE.md is the repo's own
override-authoritative doc; a stale claim here misleads both humans and agents about a fail-closed
security property). **Migration risk:** none — one sentence, doc-only.

### T-28 — "G1"/"G3"/"G4" collision between M3-POLICY-ARCH-REVIEW.md and the new install runbook (FIXED)
See "Fixed in this change" above. **Priority:** was Medium (same class as T-16, smaller footprint — 3
sites, none load-bearing outside their own new doc/comment). **Migration risk:** none — the tags were
decorative in the new doc, not cited elsewhere by number.

---

## Carried over, still open (re-confirmed this pass)

| Finding | Business concept | Status |
|---|---|---|
| T-9 | `exportedAt` → `capturedAt` rename | Open since 07-07. On-disk format + parity-test surface; still correctly deferred. |
| T-11 | `allow`/`deny` default-action vocabulary vs. 4-value `PolicyAction` | Open since 07-16. Re-confirmed unchanged this pass (policy.go/ui_policy.go untouched by the last 112 commits). |
| T-12 | Maintenance-Agent wire API "upgrade" vs. GUI/API "update"/"Dispatch" | Open since 07-16. Re-confirmed unchanged; release-catalog re-audit this pass found no new drift in this specific item. |
| T-16 | ADR numbering collision: 0008–0011 (decryption-exclusion track vs. Supportability track) | Open since 07-19. Unchanged in scope; **recommended renumber target updated to 0019–0022** (see T-22). |
| T-17 | Traffic-log destination-privacy config key/route still says "decryption" | Open since 07-19. Unchanged — lane not touched by this pass's commits. |
| T-18 | "Seal" names two unrelated cryptographic operations | Open since 07-19. **Grew this pass:** M6 added `sealBundleToTAC`, `sealAndEnqueueUpload`, the `upload.csb.sealed` filename, and new GUI copy ("Upload to TAC" tooltip, confirm dialog, toast) all using bare "Seal"/"sealed" for the one-way NaCl operation — no new *class* of collision (M6 never touches `internal/secret.Seal`), but the deferred rename's blast radius roughly doubled. Recommend prioritizing this one in the next dedicated terminology PR before it grows further. |

## Soft findings — no action recommended

- **"Bootstrap" now covers two unrelated features** (pre-existing cluster DP auto-enrollment
  "One-Click Bootstrap" vs. the new catalog-resolution `bootstrapDecision`/`/api/releases`
  `"bootstrap"` field) — no current on-screen collision (the new field isn't GUI-surfaced yet). Not
  actioned; flagged so a future pass doesn't have to re-derive it once/if the provenance record gets a
  GUI surface (per CLAUDE.md's GUI-parity rule, it likely will eventually).
- **T3's "seed"/`CULVERT_PROXY_SEED_REF`/"pinned digest"/"catalog origin"/"install channel" →
  "catalog channel"** vocabulary is internally consistent between `bootstrap_resolve.go`,
  `scripts/install.sh`, and the operator runbook — no finding.
- **The MCP design-doc set** (28 files, ~6,955 lines) is unusually disciplined: threat IDs, trust
  boundaries, and component names map 1:1 with no synonym drift across BLUEPRINT/RECOMMENDED-
  ARCHITECTURE/THREAT-MODEL/traceability-matrix; its own deliberate divergence from
  `PRODUCT-TERMINOLOGY.md`'s "Action" (a distinct 9-value MCP-policy schema) is explicitly
  self-declared, not silent drift. Only the one trivial wording nit (fixed above) was found.

---

## Recommended Refactoring Plan (priority order)

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium | T-18 (carried over, grown) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI (now 4+ strings, up from 1); rename the audit-event string | Low (young feature, now ~7 call sites) | Small-Medium |
| Medium | T-16 (carried over, target updated) | Renumber the Supportability-track's colliding ADRs (0008–0011 → **0019–0022**) and their cross-references | Low (docs only, but 40+ files to check meaning before touching any) | Medium |
| Medium | T-17 (carried over) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped canonical names (T-10 DPI pattern) | Medium (config + API + admin-settings field) | Medium |
| Medium | T-21 (new) | Rename Cluster panel's `cp_version`/"CP Config Version" to a cluster-sync-scoped name (e.g. `sync_version`/"Cluster Sync Version") | Low (GUI label + one API field, CP-UI-only) | Small |
| Medium | T-25 residual (new) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store (or reject upload-config save when no trust key exists) | Medium (touches `/api/support/tac-trust` contract or upload-config validation) | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium (on-disk format, parity-test surface) | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low (GUI copy) / Medium-large (schema) | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*`; rename packaging/config comments | Medium (agent wire protocol, rolling-update compat window) | Medium |
| Low | T-13 residual (carried over since 07-19) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with the in-app "SSL" terminology | Low (doc titles only, but externally linked) | Small |

T-22, T-23, T-24, T-26, T-27, T-28, the T-25 GUI-copy half, and the MCP "mirror" wording nit are fixed
in this change and require no further action.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass re-confirmed four previously-audited cluster groups
are still clean, fixed ten zero-risk copy/doc/comment issues found in the ~112 commits of new feature
work since the last review — including catching a glossary violation (M7's "Incident") in a design doc
*before* any code, field, or GUI string shipped, which is the cheapest point in the lifecycle to fix
it — and surfaced two new Medium-priority findings sized for dedicated follow-up (T-21 Config-Version
collision, T-25 residual recipient-registry unification) plus one already-open finding whose blast
radius grew this pass (T-18 "Seal," now recommended as the next dedicated terminology PR given its
security-sensitivity and growing surface). No cosmetic or preference-driven renames were proposed or
made in this pass; every fix shipped here closes a genuine self-contradiction, a glossary violation, a
factual staleness in an authoritative doc, or a numbering collision — not a stylistic preference.
