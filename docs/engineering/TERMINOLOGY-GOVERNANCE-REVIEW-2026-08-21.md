# Culvert Language & Terminology Governance Review — 2026-08-21

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited the tree at `7df2677`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-20.md` (baseline `b697cf3`). 330 commits separate the two
> reviews — the largest window this program has seen, dominated by two independent, large streams that
> landed on the SAME DAY: LDAP/Active Directory as a first-class Identity Provider (ADR-0025-as-filed,
> `auth_ldap_provider.go`, `ui_auth_ldap.go`, `docs/adr/0025-ldap-first-class-idp.md`) and the Policy
> Learning Mode M5A/M5B accept/reject trust boundary landing its final PR #1181 (`policy_learning_accept.go`,
> `docs/adr/0025-policy-learning-advisory-boundary.md`), plus CHAOS-50/51 cluster-CA deadlock-avoidance
> hardening (`cluster_ca_health.go`, `cluster_ca_validity.go`, `rootca_recovery.go`), root-CA load-failure
> recovery (`rootca_recovery.go`), and `internal/catfeeddb`'s CHAOS-50 resilient-open path
> (`catfeeddb_health.go`). Method: (1) three independent parallel audits — alert/log/metric vocabulary,
> GUI/API/config-key parity, and the two newest feature areas (MCP Gateway, Policy Learning Mode) — each
> cross-referencing source, REST API, GUI copy, docs, and tests, instructed to exclude anything CLAUDE.md
> already documents as deliberate; (2) a full ADR-directory listing (`docs/adr/*.md`) to check for numbering
> collisions, since the two same-day feature streams both plausibly claimed the next sequential number; (3)
> a full-repo grep of every `ADR-0025` occurrence (59 files) classified by which of the two colliding
> features each specific line actually names, to scope a safe mechanical fix; (4) targeted code reads to
> verify or refute each of the three candidate findings surfaced by (1) before acting on any of them.
> **Companion change:** two fixes ship with this review — a genuine, same-day ADR-numbering collision
> (`docs/adr/0025-*` → resolved) and a stale GUI security claim on the MITM CA-upload panel.

---

## Executive Summary

**One high-value, genuinely new finding, fully fixed: a live ADR-number collision, introduced today, at
0025.** `docs/adr/0025-ldap-first-class-idp.md` (committed 09:20 UTC) and
`docs/adr/0025-policy-learning-advisory-boundary.md` (committed 07:19 UTC, same day) both claimed ADR-0025
— two unrelated, large features (a new IdP type; a new advisory recommendation engine) sharing one decision
number, referenced as canonical by name in 59 files including CLAUDE.md itself, both feature's own extensive
in-code documentation, and a third ADR (`0026-single-access-policy-evaluator-core.md`) that cites "ADR-0025
(policy learning advisory boundary)" — i.e. the very next ADR already resolved the ambiguity in prose
because the number alone no longer identified a single decision. This is the same defect class as the
already-tracked T-16 (the 0008–0011 Supportability-track collision), but fresher, larger (330 commits vs.
T-16's cold multi-week-old backlog item) and with a much higher blast radius (both colliding ADRs are
actively cited in CLAUDE.md's canonical file-by-file map, not just in an internal roadmap doc). **Fixed in
this change**: the later-landed file (`ldap-first-class-idp`) is renumbered to ADR-0027 (the first fully
free slot after the highest number in use, 0026) — file renamed, its own header updated, and every one of
the ~30 LDAP-context `ADR-0025` references across code comments, test comments, `CLAUDE.md`, and
`static/index.html` updated to `ADR-0027`; the ~24 Policy-Learning-context references (including the second
same-day ADR, `0025-policy-learning-advisory-boundary.md`, which landed first) are untouched and keep 0025.
Seven files that legitimately mix both concepts in different lines/comments (`admin_settings.go`,
`d0_helpers_test.go`, `ui_routes_meta_test.go`, `static/index.html`, `CLAUDE.md`, `config_surfaces.go`,
`proxy.go`) were edited line-by-line rather than by blanket substitution, to avoid renumbering the wrong
concept. `go build ./...`, `go vet ./...`, and the route-inventory/D0 test suites were run clean after the
change — every edit is a comment, doc header, filename, or one string-literal `Note` field with no test
asserting on its exact text (`config_surfaces_test.go` checks structure/parity, not note-string content).

**Second finding, fixed: a stale, incorrect security claim on the MITM CA-upload panel.**
`static/index.html`'s "Upload Custom Certificate" panel labeled the private-key field "stored in memory
only, never logged" for BOTH targets in its dropdown (`mitm` and `ui`). That claim was true before CHAOS-50
but is now wrong for the `mitm` target: `ui_security.go`'s `apiCertsUpload` (CHAOS-50) now *persists* an
uploaded MITM CA to the configured bundle path on success — that was the entire point of the fix (an admin
who uploaded their enterprise MITM signing key used to get it silently discarded on the next restart). The
static label was never updated to match, so it told the admin the opposite of what happens to their private
key for the more commonly-used target. Fixed: the label now states the true, per-target behavior (persisted
for MITM, per the confirmation the response already returns; validate-only/never-persisted for UI) instead
of a blanket, now-false "memory only" claim. Copy-only; the backend's `persisted`/`warning` JSON fields were
already correct and are unchanged.

**All nineteen previously carried-over findings were re-checked against this window's diff and remain open,
unchanged**, with one exception noted below. Given the unusually large 330-commit window, each finding's
dependent files were checked against `git diff --stat b697cf3..HEAD` before being marked unchanged, not
assumed stable from staleness alone.

**Terminology Health Score: 8.3 / 10** (down 0.1 from 08-20's 8.4 — not because discipline regressed, but
because this window is the first time the program has caught a *same-day* collision between two
independently-developed, both fully-legitimate ADRs; the score reflects that the ADR-numbering convention
itself has no collision-prevention mechanism — e.g. a shared sequence file or pre-merge check — and instead
relies entirely on this program's own periodic sweeps to catch it after the fact. That is a process gap
worth a small deduction even though this instance is now fixed).

---

## Findings

### T-43 — ADR-0025 claimed by two unrelated, same-day features (FIXED)
- **Business concept:** the architecture-decision-record identifier is meant to be a stable, unique
  citation key — "ADR-0025" should resolve to exactly one decision, the same contract T-16 already
  established for the 0008–0011 range.
- **Current names before fix:** `docs/adr/0025-ldap-first-class-idp.md` ("LDAP / Active Directory as a
  first-class Identity Provider") and `docs/adr/0025-policy-learning-advisory-boundary.md` ("Policy
  Learning Mode is advisory and never an enforcement authority") — two unrelated ADRs, committed roughly
  two hours apart on the same day, both claiming 0025. Cross-referenced from CLAUDE.md's canonical
  file-by-file map (`auth_ldap_provider.go — LDAP as a first-class IdP (ADR-0025)` vs. `Policy Learning
  Mode (ADR-0025, slices M1–M3 — DISABLED infrastructure)`), from each feature's own extensive in-code
  documentation (`auth_idp.go`, `policylearn_wall_test.go`, `internal/policylearn/*.go`,
  `ui_auth_ldap.go`, etc. — ~30 LDAP-context hits, ~24 Policy-Learning-context hits across 59 files
  total), and even from a third ADR (`0026-single-access-policy-evaluator-core.md`) whose own "Related"
  line already had to disambiguate by writing out "ADR-0025 (policy learning advisory boundary)" in prose
  because the bare number was no longer sufficient.
- **Why this is a real problem, not stylistic:** an ADR number is a citation key. A developer, reviewer,
  or auditor who greps "ADR-0025" or opens `docs/adr/` alphabetically gets two files answering to the
  same name with no way to tell which one a given code comment means without reading the surrounding
  prose every time — exactly the confusion this program's own T-16 finding already flagged as
  unacceptable for the 0008–0011 Supportability range, except this instance is larger (two entire feature
  areas, not one track) and was caught same-day rather than sitting stale.
- **Fix:** the later-committed file (`0025-ldap-first-class-idp.md`, 09:20 UTC vs. the Policy Learning
  ADR's 07:19 UTC) is renamed to `docs/adr/0027-ldap-first-class-idp.md` (the first slot after the
  highest ADR number currently in use, 0026 — deliberately NOT backfilling T-16's already-reserved
  0019–0022 range, so this fix and T-16's still-open renumbering recommendation don't collide with each
  other). Its own header (`# ADR-0025: ...` → `# ADR-0027: ...`) and every LDAP-context `ADR-0025`
  citation were updated to `ADR-0027`: `CLAUDE.md` (4 lines), `static/index.html` (3 lines),
  `admin_settings.go` (2 of 6 lines — the other 4 are Policy-Learning and were left alone),
  `config_surfaces.go` (1 of 2 lines), `proxy.go` (1 of 2 lines), `d0_helpers_test.go` and
  `ui_routes_meta_test.go` (1 phrase each, on a shared comment line that names both features), plus 24
  single-concept files (`auth_idp.go`, `auth_ldap.go`, `auth_ldap_provider.go`, `ui_auth_ldap.go`,
  `ui_auth.go`, `store.go`, `diagnostics.go`, `diagnostics_auth_sso.go`, `proxy_portal.go`,
  `controlplane_snapshot.go`, `legacy_auth_providers_startup.go`, `authpolicy.go`,
  `api/openapi/openapi.yaml`, `docs/operator/ldap-identity-provider.md`, and ten `*_test.go` files whose
  entire ADR-0025 content is LDAP-only) plus two stale filename citations in
  `roadmap/LDAP-IDP-MODERNIZATION-PLAN.md`. The Policy Learning ADR keeps 0025 unchanged (it has the
  earlier commit timestamp and the larger, harder-to-safely-touch cross-reference surface —
  `internal/policylearn`'s ~10 files, `CLAUDE.md`'s single large M1–M5B paragraph, `docs/adr/0026`'s own
  citation of it by name). Verified via a full re-grep after the change: zero remaining files mix both
  concepts under one number, `go build ./...` and `go vet ./...` are clean, and the `TestD0_*`/route
  metadata suite (which the touched `d0_helpers_test.go`/`ui_routes_meta_test.go` comments sit inside)
  passes unchanged.
- **Priority:** High (a live citation-key collision, not a backlog item). **Migration risk:** none — every
  changed reference is a code/doc comment, an ADR filename + its own header, or one admin-facing `Note`
  string with no test asserting its exact text; zero API/wire/JSON-field/CLI impact.

### T-44 — MITM CA-upload panel's private-key label contradicts actual (CHAOS-50) persistence behavior (FIXED)
- **Business concept:** what happens to an admin-uploaded custom CA private key — is it persisted to
  disk, or does it live only in process memory?
- **Current names before fix:** `static/index.html`'s single, target-independent label above the
  "Upload Custom Certificate" form: `Private Key (PEM) <span>- stored in memory only, never logged</span>`,
  shown identically regardless of whether the admin selected the `mitm` or `ui` target in the dropdown
  above it.
- **Why this is a real problem, not stylistic:** `ui_security.go`'s `apiCertsUpload` handler carries an
  explicit CHAOS-50 comment stating the behavior was deliberately changed: for `target=="mitm"` (the
  default, first option in the dropdown), `installAndPersistCustomMITMCA` now WRITES the uploaded CA to
  the configured bundle path on success — the response even returns a `persisted:true/false` field and a
  `warning` string precisely because the previous "memory only" behavior was itself the bug CHAOS-50
  fixed (an admin's uploaded enterprise CA silently reverting on the next restart). The static GUI label
  was never updated to match and now asserts the opposite of what happens to the admin's private key for
  the primary use case — a trust-relevant claim an admin deciding whether to paste a real signing key into
  a browser form would reasonably rely on. (The `/ready`/`/healthz`-style "no row when not applicable"
  convention this codebase otherwise follows doesn't apply here since this is a static, unconditional
  label, not a runtime-computed status field — confirmed via `document.getElementById('cert-target').value`
  being read once at submit time with no corresponding conditional copy above the form.)
- **Fix:** the label now reads: `never logged; persisted to the CA bundle path for the MITM target (see
  confirmation after upload), validate-only (never persisted) for the UI target` — matching what
  `apiCertsUpload` actually does for each target, including the UI target's genuinely-correct "not
  persisted" case (the UI-cert branch only validates the pair and never writes it anywhere; a restart is
  required and the key is not retained by the server at all).
- **Priority:** Medium (an admin-facing trust claim, one panel, no functional change) — one step below
  T-43 because it's contained to a single label rather than a citation key spanning many files.
  **Migration risk:** none — copy-only; the JSON `persisted`/`warning` response fields the fix references
  were already correct and are untouched.

---

## Carried over, still open (re-confirmed this pass against the 330-commit diff)

Every dependent file for each of the nineteen findings below was checked against `git diff --stat
b697cf3..HEAD` (343 files across 330 commits); only files that were actually touched had their cited
lines/identifiers re-diffed rather than assumed stable.

| Finding | Business concept | Files touched this window? | Status |
|---|---|---|---|
| T-9 | `exportedAt` → `capturedAt` rename | `ui_policy.go` touched (111 lines) — diffed; the touched hunks are M5B/policy-draft additions, not the `exportedAt` field/call sites | Unchanged |
| T-11 | `allow`/`deny` default-action vocabulary vs. 4-value `PolicyAction` | No | Unchanged |
| T-12 | Maintenance-Agent wire API "upgrade" vs. GUI/API "update"/"Dispatch" | No | Unchanged |
| T-13 residual | README/enterprise-doc "TLS Inspection" vs. in-app "SSL" | No | Unchanged |
| T-16 | ADR numbering collision: 0008–0011 | No (the new 0025/0026/0027 numbers added this window are additive, don't touch 0008–0011) | Unchanged; now joined by the fixed T-43 as a second instance of the same defect class |
| T-17 | Traffic-log destination-privacy config key/route still says "decryption" | No | Unchanged |
| T-18 | "Seal" names two unrelated cryptographic operations | No | Unchanged |
| T-21 | "Config Version" names two unrelated, independently-incrementing counters | No | Unchanged; still compounded by T-32 |
| T-25 residual | Two disjoint "recipient"/"TAC trust key" registries | No | Unchanged |
| T-29 | Per-IP rate limit: `rate_limit` (YAML/CLI) vs. `rate_limit_rpm` (API/wire/metric) | No (`config.go` untouched this window) | Unchanged |
| T-30 | Per-IP connection cap: `max_conns_per_ip`/`MaxConnsPerIP` vs. `conn_limit_max_per_ip` | No | Unchanged |
| T-31 | ClamAV metric family: `clamav` everywhere except `culvert_clam_scan_errors_total` | No (`metrics.go` untouched) | Unchanged |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` reuses the overloaded term "snapshot" | No | Unchanged |
| T-33 | MCP `PolicyAction`/`PolicyReason` observation fields mix three vocabularies | No | Unchanged; still zero production consumers |
| T-34 | SaaS feed status field-name split across two admin endpoints | `saas_feed_download.go`, `saas_feed_activate.go`, `saas_feed_view.go` touched — diffed; the touches are F3b-4 taxonomy-recompose additions (new files `saas_feed_f3b4_taxonomy_recompose_test.go`, `saas_feed_view_membership_test.go`), not the status-field-name split `apiURLCatFeedStatus` depends on | Unchanged |
| T-36 | `config.rollback` audit token vs. freeform config-version-history action string | No | Unchanged |
| T-37 | "Manual feed sync" audit-action naming split across blocklist/SaaS/threat feeds | `security.go` touched (2 lines), `security_feedsync_audit_test.go` touched (10 lines) — diffed; the touch is unrelated (a comment fix from the T-2 "whitelist"→"exempt" pass carried in this merge, and a test assertion adjustment for the same), zero `feeds_sync`/`threatfeed.sync` action-string lines changed | Unchanged |
| T-38 | `drifted_tools` vs. `review_required_tools` — same count, same API response, two names | No | Unchanged; dual-emit remains the recommended fix |
| T-39 | "Qualification" names four unrelated concepts in the same config/admin namespace | `docs/engineering/POLICY-LEARNING-PREVIEW-QUALIFICATION-2026-08-21.md` (new) uses "Qualification" for a fifth context (the Policy Learning MVP's own pre-release qualification pass) — checked directly: this document is an *internal engineering report*, not GUI/API/config surface, and its own text is explicit about which qualification it means (of the ADR-0025 Policy Learning MVP) with no bare-"qualification" GUI/API/config-key exposure; not counted as a fifth *collision* since it never reaches an admin surface, but flagged here as a fifth *usage* worth the eventual T-39 fix bearing in mind | Unchanged in substance; noted for awareness |

---

## Soft findings — no action recommended

- Carried over unchanged: "Bootstrap" covering two unrelated features (no on-screen collision yet); the
  T3 "seed"/`CULVERT_PROXY_SEED_REF` vocabulary (internally consistent); the `culvert_decrypt_*` metric
  prefix vs. the fully-spelled `decryption`/`decryption-profile` namespace (deliberate abbreviation per
  CLAUDE.md); the CDR per-instance circuit-breaker `cb`-prefix wire-key convention vs. the sibling
  `internal/upstream.Status` breaker's differently-named fields; CHAOS-28's `/api/ca/status` `"usable"`
  boolean sharing a bare adjective with the unrelated MCP tool-registry `disposition` value `"usable"`
  (different JSON namespaces, no on-screen adjacency, same screen-scoped tolerance as "Policy"/"Telemetry").
- **New this pass, investigated and NOT escalated (candidate surfaced by this window's alert/metric audit,
  then refuted by reading the actual code path):** `/healthz`'s `ssl_inspection` field returns
  `"unavailable"` when `!certMgr.Ready()`, while the sibling `cluster_ca` field returns `"disabled"` for
  its analogous "not configured" case, with an explicit code comment explaining the "disabled" choice
  avoids a false-alarm reading. On its face this looked like the same class of drift as T-3/T-4 (two
  fields, same struct, same concept, different words). It is NOT, once `rootca_startup.go`'s
  `initInspectionCA` is read: unlike the cluster CA, an inspection CA is ALWAYS initialized — either
  persisted (`-ca-path` set) or in-memory-only (`-ca-path` unset, the common case) — so `certMgr.Ready()`
  is essentially always true on a running node; the `!Ready()` branch is reached only in the narrow window
  between process start and `loadRootCA` completing, or on the rare case where even in-memory `InitCA()`
  itself fails (which is *also* independently captured as `"load_failed"`, checked first in the same
  switch). So `"unavailable"` here is a genuine, rare, fault-adjacent transient — not, as with `cluster_ca`,
  the ordinary default state of an optional feature nobody turned on. Renaming it to "disabled" would be
  actively *wrong* (it would describe a boot race or a real init failure as if the admin chose not to use
  SSL inspection). No fix warranted; recorded here so a future pass doesn't re-flag it without re-deriving
  this.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 08-20 for the still-open carry-over items; T-43 and T-44 are resolved in this pass and drop
off the plan.

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium-High | T-39 (carried over) | Decide the QUAL-2/3 bootstrap-fleet name and the QUAL-4 policy-source name; rename `qualification_inventory_file`/`qualification_telemetry`/`qualification_policy_file` and their operator-doc titles/GUI strings away from bare "qualification"; reserve that word for the Production receipt gate | Medium | Small-Medium (needs a naming decision first) |
| High | T-38 (carried over) | Dual-emit `CapabilityHealth.ReviewRequiredTools`/`review_required_tools` alongside the existing `DriftedTools`/`drifted_tools`; update the GUI label; add both fields to the OpenAPI spec | Low (additive) | Small |
| Medium | T-18 (carried over) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI; rename the audit-event string | Low | Small-Medium |
| Medium | T-16 + T-43 pairing (carried over + this pass) | Renumber the Supportability-track's colliding ADRs (0008–0011 → 0019–0022, T-16's original recommendation, still unclaimed and now proven safe by T-43's precedent of a clean same-day fix) | Low (docs only) | Medium |
| Medium | T-21 + T-32 (carried pairing) | Rename Cluster panel's `cp_version` and F3b's `snapshot_sha256` to unambiguous, non-colliding names | Low | Small |
| Medium | T-17 (carried over) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped names | Medium | Medium |
| Medium | T-29 (carried over) | Alias YAML/CLI `rate_limit`/`-rate-limit` to accept `rate_limit_rpm` as well | Low-Medium | Small |
| Medium | T-30 (carried over) | Alias YAML `max_conns_per_ip` / wire `MaxConnsPerIP` toward `conn_limit_max_per_ip` | Low-Medium | Small |
| Medium | T-36 (carried over) | Give `saveConfigVersion`'s rollback call a `config.rollback`-prefixed action string alongside the version number | Low | Small |
| Medium | T-37 (carried over) | Rename `security.feeds_sync` → `threatfeed.sync`; update `security_feedsync_audit_test.go`'s three literal assertions | Low | Small |
| Medium | T-33 (carried over) | Stop overwriting `PolicyAction`/`PolicyReason` for pre-/post-policy gate failures; add a dedicated field for those instead | None today (zero production consumers); rises once a consumer exists | Small |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low / Medium-large | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*` | Medium | Medium |
| Low-Medium | T-31 (carried over) | Rename `culvert_clam_scan_errors_total` → `culvert_clamav_scan_errors_total`, dual-emit | Low | Small |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

---

## Stop-Condition Assessment

Terminology is **not** fully consistent, but this was a productive pass: two genuinely new,
previously-untracked findings were identified and fully fixed at zero migration risk (a live same-day
ADR-numbering collision, and a stale GUI security claim contradicted by CHAOS-50's own persistence fix),
and all nineteen previously-open findings were re-confirmed unchanged against the largest diff window this
program has audited (330 commits, 343 files). One candidate finding surfaced by this pass's alert/metric
audit (`ssl_inspection: "unavailable"` vs. `cluster_ca: "disabled"`) was investigated by reading the actual
CA-initialization code path and refuted — the two fields describe genuinely different situations (a rare
transient/fault state vs. an ordinary unconfigured-feature state), not the same concept under two names, so
no change was made. No cosmetic or preference-driven renames were proposed.
