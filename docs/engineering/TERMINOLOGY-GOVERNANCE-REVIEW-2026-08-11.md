# Culvert Language & Terminology Governance Review — 2026-08-11

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited the tree at `bc67b7b`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-07.md` (baseline `d2c5a51`). 58 commits separate the two
> reviews, dominated by CHAOS-27 (alert-storm dedup bounding), CHAOS-28's actual shipping implementation
> (Root-CA fail-closed-when-unusable + rotation-persistence gating — previously only narrated in
> CLAUDE.md, now landed as code), CHAOS-47 auth-backend cooldown/probe-gate hardening (LDAP + OIDC),
> syslog panic-loss surfacing on the SIEM panel, a DP config-snapshot-apply diagnostics addition, a
> `cdr.server_fingerprint` hex-validation tightening, an install-script `allow_peers` comment-quoting fix,
> a `hostutil.StripHostPort` allocation cleanup, the release runtime-version-identity enforcement work, and
> a batch of dependency bumps. Two independent passes covered this window: (1) every one of the nineteen
> carried-over open findings — T-9, T-11, T-12, T-13 residual, T-16, T-17, T-18, T-21, T-25 residual, T-29
> through T-34, T-36, T-37, T-38, T-39 — was re-verified by diffing the actual cited lines/identifiers (not
> just file touches) between `d2c5a51` and `bc67b7b`; (2) the six commit-groups most likely to introduce new
> vocabulary (alert-storm bounding, CA fail-closed, auth-backend cooldown, syslog panic-loss, config-snapshot
> diagnostics, and the MCP QUAL-6.1 acceptance-harness work) were read in full and checked against every
> existing vocabulary they sit next to.
> **No companion change this pass.** Unlike 08-07 (which found and same-day-fixed T-40), this window
> introduced zero new terminology drift and nothing among the carried-over findings crossed into
> same-day-fixable territory — T-39, the one finding whose evidence changed, still requires a product-naming
> decision rather than a mechanical rename (unchanged reasoning from 08-06/08-07). This report is a
> re-verification pass, consistent with this program's practice of publishing evidence on unchanged windows
> rather than only on windows with a fix to ship.

---

## Executive Summary

**Seventeen of nineteen carried-over findings are byte-for-byte unchanged.** T-37's dependent file
(`ui_security.go`) was touched this window (64 lines), but the touch is entirely CHAOS-27/28 work landing in
the same file — the three cited literal audit-action strings (`security.feeds_sync`, `blocklist.feed.sync`,
`saasfeed.refresh`) are untouched. No finding regressed and no finding was fixed.

**T-39 did not gain a fifth independent concept, but its fourth (previously speculative) sense shipped as
real code.** The 08-07 review noted that `docs/operator/mcp-qualification-telemetry.md:150`'s "a defined
qualification environment" was still aspirational doc language (business concept D). This window's QUAL-6.1
acceptance-harness work (`internal/mcpacceptance/spec.go`, commits `07322ca` through `86ec811` plus the
reconcile commit `8562433`) makes it literal, shipped Go: `spec.go:74`'s doc comment reads *"EnvSpec is the
operator-provided **qualification environment**."* The same harness references concepts B (QUAL-2/3's
`Telemetry`, described in its own doc comment as "the operator-owned QUAL-3 durable-telemetry custody
boundary") and C (QUAL-4's `QualificationPolicyFile`, described as "the SAME production format the binary
consumes at `mcp.gateway.qualification_policy_file`") by direct reference rather than renaming them, so no
new collision was introduced — but for the first time one artifact (`EnvSpec`) sits at the intersection of
three of the four senses, which is evidence the accumulating overload is real infrastructure now, not just
parallel documentation drift. The harness also introduces "authoritative" (`ModeAuthoritative`/`ModeDev`) as
a source-of-truth modifier distinguishing real-operator-infra acceptance runs from dev-fixture ones; this is
the same generic, already-tolerated sense of the word used elsewhere in the codebase (`admin_settings.go`,
`store.go`), not a new collision. No GUI surface was touched by this work, so T-39's "no same-screen
collision" mitigating factor still holds.

**No new terminology drift found anywhere else in the 58-commit window.** The alert-storm/dedup work
(CHAOS-27), the CA fail-closed-when-unusable + rotation-persistence-gating implementation (CHAOS-28), the
LDAP/OIDC auth-backend cooldown hardening (CHAOS-47 follow-through), the syslog panic-loss counter, and the
config-snapshot-apply diagnostic addition all reuse their subsystems' established vocabulary exactly and
introduce no names that collide with anything elsewhere. The CHAOS-28 work in particular is the actual
shipping implementation of a feature CLAUDE.md has narrated since an earlier window — every identifier the
narrative already promised (`Usable()`, `ErrCAUnusable`, `failClosedUnusableCA`, `clampLeafValidity`,
`RotationPersistFailureObserver`/`RotationPersistSuccessObserver`, `caRotationPersistDegraded()`,
`RotationObserver`, `caClockSkewTolerance`) landed unchanged from the doc's description — a clean
narrative-to-code handoff, not drift.

**Terminology Health Score: 8.4 / 10** (unchanged from 08-07 — zero regressions across a 58-commit window
and zero new drift found, but T-39's fourth sense crystallizing from speculative doc language into shipped,
cross-referenced code is a reminder that the pending naming decision is not getting cheaper to defer).

---

## Wave 1 — Carried-over findings re-confirmed

`git diff d2c5a51..HEAD` (58 commits) was checked against every file each of the nineteen open findings
depends on; the one finding whose file was touched had the actual cited identifiers diffed, not just the
file.

| Finding | Files it depends on | Touched this window? | Collision status |
|---|---|---|---|
| T-9 | export/import + parity-test surface (`exportedAt`) | No | Unchanged |
| T-11 | `policy.go`'s default-action vocabulary, `ui_policy.go` core | No | Unchanged |
| T-12 | Maintenance-Agent `/v1/upgrades/*` wire routes | No | Unchanged |
| T-13 residual | README/enterprise-doc "TLS Inspection" vs. in-app "SSL" | No | Unchanged |
| T-16 | ADR numbering (0008–0011) | No | Unchanged |
| T-17 | `decryption_redact_hosts` / `/api/decryption/redaction` | New `decryption_observability.go` added (ADR-0011 `DecryptionOutcome` logging schema, dark/unwired) is a distinct file; the cited redaction field/route untouched | Unchanged |
| T-18 | `internal/sealbox.Seal`/`Open` call sites | No | Unchanged |
| T-21 | `cluster_convergence.go`, `configversion.go`'s rollback `cp_version` surface | No | Unchanged |
| T-25 residual | `support_recipients.go` / `support_tac_trust.go` | No | Unchanged |
| T-29 | YAML `rate_limit` (`config.go`/`main.go`) vs. `rate_limit_rpm` (API/wire/metric) | `config.go` touched (`cdr.server_fingerprint` hex validation) | Unrelated touch — unchanged |
| T-30 | YAML `max_conns_per_ip`/wire `MaxConnsPerIP` vs. `conn_limit_max_per_ip` | Same `config.go` touch | Unrelated — unchanged |
| T-31 | `culvert_clamav_blocked_total` vs. `culvert_clam_scan_errors_total` | No | Unchanged |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` overloads "snapshot" | No | Unchanged |
| T-33 | MCP `PolicyAction`/`PolicyReason` (`internal/mcp/runtime/policy.go`, `events.go`, `observe.go`) | No | Unchanged; still zero production consumers |
| T-34 | SaaS feed status field-name split (`saas_feed_download.go`, `ui_policy.go`) | No | Unchanged |
| T-36 | `config.rollback` audit token vs. freeform config-version-history action string | No | Unchanged |
| T-37 | "Manual feed sync" naming split across blocklist/SaaS/threat feeds | `ui_security.go` touched (64 lines, CHAOS-27/28) | Touch is unrelated CHAOS-27/28 code; the three cited literal action strings are byte-identical — unchanged |
| T-38 | `ui_mcp.go`, `internal/mcp/adminapi/health.go`, `mcp_inventory.go`, `static/index.html` (`drifted_tools`/`review_required_tools`) | `static/index.html` touched (55 lines: CA/alerts/syslog GUI) | Zero MCP-panel hits in the touched lines; the three Go files are untouched — unchanged |
| T-39 | `internal/mcp/rollout` (Production Qualification), QUAL-2/3/4 config/docs | QUAL-6.1 (`internal/mcpacceptance`) lands adjacent, referencing B/C by name and crystallizing D | **Evidence updated — see Findings below, not newly compounded by a fifth concept** |

## Wave 2 — New territory audited this pass (58 commits since `d2c5a51`)

**CHAOS-27 (alert-storm/dedup bounding), CHAOS-28 (CA fail-closed-when-unusable), CHAOS-47 follow-through
(LDAP/OIDC cooldown hardening), syslog panic-loss surfacing, and the config-snapshot-apply diagnostic: all
clean, no new drift.** "Alert storm" is commit-message language only — a repo-wide grep for `storm` in
non-test `.go` files returns zero hits, so no wire/GUI term was actually introduced under that name; the
real new vocabulary (`dedupMap`/`dedupTTL`/`dedup_tracked`/`culvert_alert_dedup_evictions_total`) is
self-contained and consistent with the existing `culvert_alert_*` metric family. The CA work's shipped
identifiers match CLAUDE.md's pre-existing CHAOS-28 narrative exactly (see Executive Summary), including the
GUI's collapse of "expired" and "not-yet-valid" into one "Expired — inspection blocked" label, which mirrors
a pre-existing, deliberate choice already made on `/healthz`. The LDAP (`errLDAPAccountRejected`,
`ldapUserBindIsUnreachable`) and OIDC legs of the CHAOS-47 hardening use matching vocabulary
(`recordReachable`/`recordUnavailable`/gate/cooldown) with no divergence between them. The syslog panic-loss
counter (`SetPanicObserver`, `panics`) follows the exact `SetWriteFailureObserver` pattern already used by
`fileutil`/`internal/audit`, and is clearly distinguished in the GUI from the unrelated `sync_panics`
(`ha.go`) and `culvert_crash_records_total` (`crashguard.go`) counters. The new config-snapshot-apply
diagnostic code (`dp_config_snapshot_apply`) is distinct from the pre-existing
`dp_last_known_good_config`/`ConfigSnapshot`/`applyConfigSnapshot` vocabulary it sits next to, with no
relation to T-21's unrelated `cp_version` overload.

**QUAL-6.1 (`internal/mcpacceptance`) is a CI/test acceptance-harness package with no GUI/API/metric
surface.** Its internal vocabulary (`operator_policy_digest`, `POLICY_SCENARIO_REQUIREMENT_UNSATISFIED`,
`environment.bind_host_effective`, `ModeAuthoritative`/`ModeDev`) is self-contained and does not collide with
anything else in the codebase. Its effect on T-39 (crystallizing concept D, cross-referencing B and C) is
covered above and in the Findings section — worth tracking as evolving evidence, not a new standalone
finding.

**No dependency-bump commit in this window (`getkin/kin-openapi`, `klauspost/compress`, `dgraph-io/badger`,
`step-security/harden-runner`, `docker/login-action`) touches any product-facing terminology surface** —
verified each is a version bump only.

---

## Findings

### T-39 — "Qualification" still names four unrelated concepts across independent PR streams in the same `mcp.gateway.*`/`/api/mcp/*` surface (carried over — evidence updated this window, not newly compounded by a fifth concept, still not fixed)

- **Business concept A (pre-existing):** **Production Qualification** — the cryptographically-verified
  receipt gating promotion of an MCP rollout-mode capability to Production
  (`internal/mcp/rollout.ProductionQualificationVerifier`).
- **Business concept B (pre-existing, QUAL-2/3):** a bounded, disposable pre-production
  inventory/telemetry bootstrap fleet used to validate the Observe listener itself
  (`qualification_inventory_file`, `qualification_telemetry`).
- **Business concept C (QUAL-4, carried over from 08-07):** a node-local, Observe-only policy source file,
  never fleet-published and never Production-enforced (`qualification_policy_file`/`QualificationPolicyFile`,
  `mcp_policy.go`).
- **Business concept D — crystallized this window:** as of 08-06/08-07 this was speculative doc language
  ("a defined qualification environment," `docs/operator/mcp-qualification-telemetry.md:150`). This window's
  QUAL-6.1 acceptance harness makes it real, shipped code: `internal/mcpacceptance/spec.go:74`'s doc comment
  — *"EnvSpec is the operator-provided **qualification environment**"* — backs a real Go struct
  (`EnvSpec`) that is constructed, validated, and consumed by the acceptance-test runner.
- **What changed this window:** `EnvSpec` doesn't invent a new concept collision on its own — it explicitly
  documents itself as consuming concept C's `QualificationPolicyFile` in "the SAME production format the
  binary consumes at `mcp.gateway.qualification_policy_file`" and concept B's `Telemetry` as "the
  operator-owned QUAL-3 durable-telemetry custody boundary." So this is reference, not renaming — no fifth
  independent sense was introduced, and no GUI surface was touched (T-39's "no same-screen collision"
  mitigating factor still holds, unchanged from 08-07). What did change: a single artifact now sits at the
  intersection of three of the four senses of "qualification" (B, C, and the newly-real D), and layers a
  fourth modifier ("authoritative" vs. "dev") on top to distinguish real-operator-infra acceptance runs from
  fixture-backed ones. "Authoritative" itself reuses the codebase's existing generic, tolerated
  source-of-truth sense of the word (`admin_settings.go`, `store.go`) and is not a new collision.
- **Why this still isn't fixed:** unchanged reasoning from 08-06/08-07 — this needs a real product-naming
  decision (what to call the QUAL-2/3 bootstrap fleet and the QUAL-4 node-local policy source; whether to
  reserve bare "Qualification" exclusively for the Production receipt gate), not a mechanical rename. The
  acceptance harness adding a cross-referencing consumer of three senses at once is a signal that a naming
  decision is becoming more valuable, not a reason to attempt one unilaterally in a terminology-review pass.
- **Recommended canonical name / fix:** unchanged from 08-07 — rename the QUAL-2/3/4 config keys and
  operator-doc titles to an environment-scoped vocabulary (e.g. "staging"/"pilot"/"bootstrap fleet" for
  QUAL-2/3, "local policy source" or "Observe-only policy" for QUAL-4) and reserve bare
  "Qualification"/"qualification-locked" exclusively for the Production-promotion receipt gate, matching
  `internal/mcp/rollout`'s usage.
- **Priority:** held at **Medium-High** (unchanged from 08-07 — the underlying design ambiguity has not
  worsened by a new independent stream this window, but the fact that a cross-referencing consumer now spans
  three senses at once means the eventual rename's blast radius keeps growing). **Migration risk:** Medium
  (unchanged). **Est. PR size:** Small-Medium, needs a naming decision first (unchanged).

---

## Carried over, still open (re-confirmed this pass, see Wave 1 table for evidence)

| Finding | Business concept | Status |
|---|---|---|
| T-9 | `exportedAt` → `capturedAt` rename | Open since 07-07. Unchanged. |
| T-11 | `allow`/`deny` default-action vocabulary vs. 4-value `PolicyAction` | Open since 07-16. Unchanged. |
| T-12 | Maintenance-Agent wire API "upgrade" vs. GUI/API "update"/"Dispatch" | Open since 07-16. Unchanged. |
| T-13 residual | README/enterprise-doc "TLS Inspection" vs. in-app "SSL" | Open since 07-24 (soft/low). Unchanged. |
| T-16 | ADR numbering collision: 0008–0011 | Open since 07-19. Unchanged. |
| T-17 | Traffic-log destination-privacy config key/route still says "decryption" | Open since 07-19. Unchanged. |
| T-18 | "Seal" names two unrelated cryptographic operations | Open since 07-19, grew 07-24. Unchanged. |
| T-21 | "Config Version" names two unrelated, independently-incrementing counters | Open since 07-24. Unchanged; still compounded by T-32. |
| T-25 residual | Two disjoint "recipient"/"TAC trust key" registries | Open since 07-24. Unchanged. |
| T-29 | Per-IP rate limit: `rate_limit` (YAML/CLI) vs. `rate_limit_rpm` (API/wire/metric) | Open since 08-01. Unchanged. |
| T-30 | Per-IP connection cap: `max_conns_per_ip`/`MaxConnsPerIP` vs. `conn_limit_max_per_ip` | Open since 08-01. Unchanged. |
| T-31 | ClamAV metric family: `clamav` everywhere except `culvert_clam_scan_errors_total` | Open since 08-01. Unchanged. |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` reuses the overloaded term "snapshot" | Open since 08-01. Unchanged. |
| T-33 | MCP `PolicyAction`/`PolicyReason` observation fields mix three vocabularies | Open since 08-02. Unchanged; zero production consumers. |
| T-34 | SaaS feed status field-name split across two admin endpoints | Open since 08-02. Unchanged. |
| T-36 | `config.rollback` audit token vs. freeform config-version-history action string | Open since 08-04. Unchanged. |
| T-37 | "Manual feed sync" audit-action naming split across blocklist/SaaS/threat feeds | Open since 08-04. Unchanged. |
| T-38 | `drifted_tools` vs. `review_required_tools` — same count, same API response, two names | Open since 08-06. Unchanged. |
| T-39 | "Qualification" names four unrelated concepts in the same config/admin namespace | Open since 08-06, compounded 08-07. **Evidence updated this pass** — see Findings; concept D crystallized from speculative doc language into shipped, cross-referencing code, no fifth concept introduced. |

*T-40 is not listed here — fixed 08-07, see that report.*

## Soft findings — no action recommended

Carried forward unchanged from 08-07 (no new soft findings identified this pass):

- "Bootstrap" covering two unrelated features (no on-screen collision yet); the T3 "seed"/`CULVERT_PROXY_SEED_REF` vocabulary (internally consistent).
- The `culvert_decrypt_*` metric prefix vs. the fully-spelled `decryption`/`decryption-profile` API/audit/alert namespace — internally consistent, documented as a deliberate abbreviation in CLAUDE.md.
- `roadmap/google-captcha-swg-investigation.md:177`'s speculative `culvert_connlimit_rejections_total` metric citation for a counter that shipped as a REST field only.
- `drifted_tools`'s absence from `api/openapi/openapi.json`/`.yaml` despite being a live, tested field — an OpenAPI-spec coverage gap, worth closing in the same change that fixes T-38.
- The pre-existing "Telemetry (opt-in)" support-panel feature vs. MCP Qualification Telemetry as a third generic sense of "telemetry" — different routes/screens, no on-screen adjacency.
- The CDR per-instance circuit-breaker fields (`cdr_ui.go` — `cbState`/`cbConsecFails`/`cbTotalOpens`/`cbTotalTrips`) using an ad hoc `cb`-prefix wire-key convention the sibling `internal/upstream.Status` breaker fields (`circuit`/`failures`/`openedAtMs`/`retryAfterMs`) do not share — same concept, no collision, just an inconsistent key-naming convention across two similar endpoints.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 08-07 — no findings were added, fixed, or reprioritized this pass.

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium-High | T-39 (carried over) | Decide the QUAL-2/3 bootstrap-fleet name and the QUAL-4 policy-source name; rename `qualification_inventory_file`/`qualification_telemetry`/`qualification_policy_file` and their operator-doc titles/GUI strings away from bare "qualification"; reserve that word for the Production receipt gate | Medium | Small-Medium (needs a naming decision first) |
| High | T-38 (carried over) | Dual-emit `CapabilityHealth.ReviewRequiredTools`/`review_required_tools` alongside the existing `DriftedTools`/`drifted_tools` (keep the old field for wire compatibility); update the GUI label; add both fields to the OpenAPI spec | Low (additive) | Small |
| Medium | T-18 (carried over) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI; rename the audit-event string | Low | Small-Medium |
| Medium | T-16 (carried over) | Renumber the Supportability-track's colliding ADRs (0008–0011 → 0019–0022) | Low (docs only) | Medium |
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

Terminology is **not** fully consistent. This pass re-confirmed, via a cited-line diff against every one of
nineteen previously-open findings, that seventeen are unchanged across a 58-commit window, one (T-37) had its
dependent file touched by unrelated code with the cited literals untouched, and one (T-39) had its evidence
meaningfully updated — a previously-speculative fourth sense of "qualification" shipped as real,
cross-referencing code — without introducing a fifth independent concept or a same-screen collision. No new
terminology drift was found in a targeted read of every notable new-code area this window (CHAOS-27 alert
dedup, CHAOS-28 CA fail-closed, CHAOS-47 auth-backend cooldown hardening, syslog panic-loss, config-snapshot
diagnostics, MCP QUAL-6.1). Nothing crossed into same-day-fixable territory this pass — T-39 continues to
require a product-naming decision, and every other open finding is unchanged from its prior assessment. No
cosmetic or preference-driven renames are proposed.