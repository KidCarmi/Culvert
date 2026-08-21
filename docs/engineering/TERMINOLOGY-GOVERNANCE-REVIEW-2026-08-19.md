# Culvert Language & Terminology Governance Review — 2026-08-19

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited the tree at `b697cf3` (`b697cf3a4148ac7d90347c2a09043ada6884ba15`), following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-07.md` (baseline `d2c5a51`). 80 commits separate the two reviews
> (121 files, ~14.9k insertions), dominated by MCP PR-12 (the CP/DP signed-distribution + node-local
> rollout durable-state transaction — `mcp_distribution.go`, `mcp_distribution_startup.go`,
> `mcp_distribution_startup_config.go`, `mcp_rollout.go`, `mcp_rollout_persist.go`,
> `mcp_rollout_execdeps.go`), CHAOS-28 (root-CA fail-closed usability + rotation-persistence gating),
> CHAOS-27 (alert-plane bounding under a dedup storm), a new `store_logclock.go` (per-second timestamp
> render memoization), syslog panic-loss surfacing on the SIEM panel, two new `/readyz`
> unauthenticated-disclosure hardening commits, a runtime release-version self-report integrity gate
> (`assert-release-ref.sh`/`assert-runtime-version.sh`), and assorted LDAP/OIDC identity-backend hardening.
> Method: (1) re-verified all 19 previously-open findings (T-9 through T-39) against the actual cited
> lines/identifiers in the 80-commit diff, not just file touches; (2) audited every new subsystem in the
> window for internal-vs-external naming collisions, cross-checking against CLAUDE.md's already-recorded
> deliberate-naming decisions; (3) traced the one new finding (T-41) across every surface it touches
> (shell scripts, CI workflow, Go tests, roadmap doc) before fixing it.
> **Companion change:** T-41 (new — the runtime version-self-report guard reused the bare phrase "release
> identity", already the established name for the unrelated Sigstore signer-trust concept, in this same
> release-engineering surface) fixed same-day: brand new this window, zero test dependency on the literal
> phrase, zero deployed/customer-facing surface (CI script text and comments only), and the same
> "cheapest before a consumer depends on it" reasoning this program applied to T-35 and T-40.

---

## Executive Summary

**All 19 carried-over findings re-verified unchanged — zero regressions, zero collateral drift.** This is
the cleanest carried-over window the program has recorded: despite 80 commits and a large MCP subsystem
landing directly adjacent to T-33's and T-39's territory, none of the touched files this window intersected
any finding's actual cited identifiers. Most notably, **T-39 ("qualification" naming four unrelated
concepts) did NOT compound this window** — after three consecutive reviews (08-02 → 08-06 → 08-07) in
which independent PR streams kept reusing the word, this window's MCP work (`71e2631`'s "qualification PKI"
hardening) stayed inside the pre-existing QUAL-2/3 acceptance-harness sense and never touched the QUAL-4
node-local-policy files (`mcp_policy.go`) that caused the prior compounding. That is a genuine, positive
signal, not just an absence of new evidence — worth noting for whoever eventually makes T-39's naming
decision.

**One new finding, fixed same-day (T-41): the new runtime-version self-report guard reused "release
identity," the established name for a different, pre-existing concept, in the same pipeline.** Culvert's
release-engineering vocabulary already has a large, load-bearing sense of "release identity" — the
cosign/Sigstore signer-trust identity (issuer + SAN regex) that `install.sh`, `bootstrap_resolve.go`,
`release_dispatch.go`, and the operator runbooks all verify artifacts against. This window's new
`assert-release-ref.sh`/`assert-runtime-version.sh` guards (added to catch a real production defect — a
signed v1.0.202 binary whose `/healthz` silently omitted its own version) are a distinct, unrelated
property: proving *what version* a binary self-reports, not *who signed it*. Several of the new guards'
comments and log lines dropped to the bare phrase "release identity" for this second, unrelated sense —
including inside `ci.yml`, which now has both senses within ~500 lines of each other. Renamed the new
sense to "version stamp" everywhere it appeared (verified: no test asserts the literal phrase; only
structural markers like script filenames and env-var names are pinned).

**Terminology Health Score: 8.5 / 10** (up from 8.4 — the carried-over backlog held with zero regressions
across the largest commit window yet reviewed, T-39's negative trend broke for the first time, and this
window's one new collision was caught and fixed before any release shipped with it — offset only by the
same unresolved backlog of 18 findings, several of which (T-38, T-39) are now overdue for the design
decisions their reports have repeatedly recommended rather than another deferral).

---

## Wave 1 — Carried-over findings re-confirmed unchanged

`git diff d2c5a51..HEAD` (80 commits) was checked against every file each of the 19 open findings depends
on; every finding whose files *were* touched had the actual cited lines/identifiers diffed, not just the
file.

| Finding | Files it depends on | Touched this window? | Collision status |
|---|---|---|---|
| T-9 | `exportedAt` export/import + parity-test surface | `ui_config.go` touched | Touch is an unrelated syslog `panics` field added to `apiSyslogConfig`; `exportedAt`/`ExportedAt` untouched — unchanged |
| T-11 | `policy.go`'s default-action vocabulary, `ui_policy.go` core | No | Unchanged |
| T-12 | Maintenance-Agent `/v1/upgrades/*` wire routes | No | Unchanged |
| T-13 residual | README/enterprise-doc "TLS Inspection" vs. in-app "SSL" | No | Unchanged |
| T-16 | ADR numbering (0008–0011) | No | Unchanged |
| T-17 | `decryption_redact_hosts` / `/api/decryption/redaction` | `decryption_observability.go` touched | Touch is CHAOS-28's `caUnusableOutcome`; zero "redact" lines — unchanged |
| T-18 | `internal/sealbox.Seal`/`Open` call sites | No | Unchanged |
| T-21 | `cluster_convergence.go`, `configversion.go`'s rollback `cp_version` surface | No | Unchanged |
| T-25 residual | `support_recipients.go` / `support_tac_trust.go` | No | Unchanged |
| T-29 | YAML `rate_limit` (`config.go`/`main.go`) vs. `rate_limit_rpm` (API/wire/metric) | Both touched | `config.go`'s only change is a CDR fingerprint hex-validity check; `main.go`'s only change wires `initMCPDistribution`. Zero rate-limit lines — unchanged |
| T-30 | YAML `max_conns_per_ip`/wire `MaxConnsPerIP` vs. `conn_limit_max_per_ip` | Same files as T-29 | Same diffs — unchanged |
| T-31 | `culvert_clamav_blocked_total` vs. `culvert_clam_scan_errors_total` | No | `metrics.go` absent from the diff (only the distinct `ca_metrics.go` was touched, for CHAOS-28) — unchanged |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` overloads "snapshot" | No | Unchanged |
| T-33 | MCP `PolicyAction`/`PolicyReason` mixing three vocabularies (`internal/mcp/runtime/policy.go`, `events.go`, `observe.go`) | Root `events.go` touched, not the MCP package | Touch is the unrelated SSE/Prometheus shim adding `culvert_alert_dedup_*` metrics; `internal/mcp/runtime/*` untouched — unchanged |
| T-34 | SaaS feed status field-name split (`saas_feed_download.go`, `ui_policy.go`) | No | Unchanged |
| T-36 | `config.rollback` audit token vs. freeform config-version-history action string | No | Unchanged |
| T-37 | "Manual feed sync" naming split across blocklist/SaaS/threat feeds | No | Unchanged |
| T-38 | `ui_mcp.go`, `internal/mcp/adminapi/health.go`, `mcp_inventory.go`, `static/index.html` (`drifted_tools`/`review_required_tools`) | `static/index.html` touched | Touch is CHAOS-28 CA banners, syslog-panics rendering, alert-dedup health UI; zero hits for `drifted_tools`/`review_required_tools`. The three Go files are entirely absent from the diff — unchanged |
| T-39 | `internal/mcp/rollout` (Production Qualification), QUAL-2/3 config/docs | `mcp_rollout*.go`, `mcp_distribution*.go` touched heavily | **Unchanged — the negative trend broke.** All "qualification" hits in the diff are business-concept-A usage (the pre-existing Production-Qualification receipt gate / its evidence-window vocabulary); `mcp_policy.go` (QUAL-4, the file that caused the last three compoundings) is absent from the diff — see Wave 2 |

## Wave 2 — New territory audited this pass (80 commits since `d2c5a51`)

**MCP PR-12 (CP/DP signed-distribution + rollout durable-state transaction) holds discipline throughout —
no collision found.** The window's two halves keep strictly separate vocabularies: the distribution engine
(`internal/mcp/cpdp/apply`) uses `Apply`/`Persist`/`Activate`/`Rollback`/`AbortApplied`/`RejectAck` for the
signed CP→DP envelope; the rollout engine (`mcp_rollout.go`) uses `commitRolloutTransition` for the
node-local mode/scope transition, and the two never blur even inside the coordinating function
(`applyMCPCapabilityEnvelope`, `mcp_distribution.go:234`, calls each engine by its own verb). GUI/API/wire
parity is exact for `distribution_state` values and the `shadow_execution_dependencies_not_configured`
error string, reused byte-identically across `mcp_rollout.go`, `mcp_distribution.go`, and
`ui_mcp_rollout.go`. T-39 is not compounded by this stream (see Wave 1).

**`store_logclock.go` (new file) is a narrow perf concept, not a collision.** It memoizes
`time.Now().Format("15:04:05")` for `LogEntry.Time` within the same wall-clock second — a formatting-cost
optimization, not a write-path or persistence concept. It shares no vocabulary with the pre-existing
`internal/logsink` (async process-log write decoupling) or `internal/reqlog` (async request-log
persistence) systems CLAUDE.md documents; `store.go`'s 10-line diff wires it in cleanly with no stray old
call sites left behind.

**Syslog panic-loss surfacing, `/readyz` disclosure hardening, and the LDAP/OIDC identity-backend hardening
commits are all clean, consistent extensions of already-documented vocabulary.** The new syslog `Panics()`
counter mirrors the existing `Drops()`/`SetWriteFailureObserver` pattern with no new terms; the two
`security(readyz)` commits replace raw internal strings with fixed, role-appropriate messages using terms
(`ca_load_failed`, `clamav_status`) that already exist exactly as documented; the LDAP-bind and
OIDC-introspection hardening commits (`ae59e26`, `38ce79e`, `2d5b757`, `1886594`) reuse the CHAOS-47
`identity_backend`/`authProbeGate` vocabulary exactly, changing only *when* the gate arms, not any naming.
The `idp_unreachable`→`identity_backend_unreachable` migration T-40 fixed on 08-07 was also verified
**fully closed** this pass: `92c3352` and `bea241e` extended the migration to `Store.Init`, `Add`, *and*
`Update` (closing the config-import/DR-restore gap the 08-07 report flagged as a residual risk), and a
repo-wide grep confirms zero live wire paths still emit or accept the retired name — every remaining hit is
the migration table entry itself, historical doc prose, or test fixtures.

---

## Findings

### T-41 — The new runtime version-self-report guard reused the unrelated "release identity" (Sigstore signer-trust) vocabulary (new — fixed same-day)

- **Business concept:** proving that an official signed release binary's self-reported `/healthz` version
  string matches the git tag it was built from (a *what version does this binary claim to be* integrity
  check), landed to catch a real production defect: the signed `v1.0.202` binary stamped `main.version`
  correctly at build time but its `/healthz` handler omitted the `version` field entirely, so the first
  live authoritative MCP Observe Acceptance run failed its `artifact.version` criterion with no version to
  check against.
- **Current names / collision (before this fix):** the new guard's shell scripts, `ci.yml` step names and
  comments, and one Go test error message all named this concept "release identity" or "version identity"
  interchangeably with the bare phrase "release identity" — `assert-release-ref.sh`'s header ("Release-
  identity fail-closed guard"), `assert-runtime-version.sh`'s header ("Runtime version-identity gate" /
  "actually surface their release identity at runtime" / "release identity is unverifiable at runtime"),
  `ci.yml`'s step names ("Assert release version identity" ×2, "Gate runtime version identity") and inline
  comments ("Release-identity fail-closed guard", "SAME fail-closed release-identity guard"), and
  `ha_healthz_version_test.go:38`'s failure message ("signed release identity is unverifiable at runtime").
- **Why this is real drift, not cosmetic:** Culvert already has a large, pervasive, load-bearing sense of
  "release identity" — the cosign/Sigstore **signer-trust** identity (issuer + SAN regex pinned in
  `release_identity.env` and the `officialSigstoreIssuer`/`officialSigstoreSANRegex` Go constants,
  cross-checked by `TestReleaseIdentitySSOT`) that `scripts/install.sh` (6 occurrences), `bootstrap_resolve.go`,
  `release_dispatch.go`, `install_catalog_bootstrap_contract_test.go`, and
  `docs/operator/catalog-bootstrap-install-runbook.md` all use consistently to mean "the identity an
  artifact's signature is checked against." `ci.yml` now contains **both senses within roughly 500 lines of
  each other**: line 501's "Verify pushed image signature matches the pinned release identity" (sense
  A — signer trust) sits in the same file as the new lines 839/863/1065's "Assert release version identity"
  / "Gate runtime version identity" (sense B — self-reported version stamp). A reader skimming the workflow
  log or `ci.yml` diff has no textual cue that "release identity" just changed meaning between adjacent
  jobs — exactly the same class of collision T-40 fixed for `idp_unreachable`/"IdP", just inside CI tooling
  rather than a customer-facing alert name.
- **Why same-day-fixable:** brand new this window (the guard and its test file did not exist before
  `744ceba`), so there is no prior release and no external dependency on the phrasing. `release_version_identity_test.go`
  and `TestReleaseVersion_*` assert **structural** markers — script filenames (`assert-release-ref.sh`),
  env-var names (`REF_NAME`), and literal code patterns (`if [ -z "$REF_NAME" ]`, the semver regex) — never
  the prose phrase "release identity" itself; confirmed by re-running the targeted tests after the rename
  (`TestHealthz_ReportsRuntimeVersion`, `TestReleaseIdentitySSOT`, all three `TestReleaseVersion_*` tests —
  all pass unchanged). No operator runbook or customer-facing surface references the phrase in this
  context — it is entirely internal CI script/comment text.
- **Fix applied:** renamed the self-report concept to **"version stamp"** everywhere it appeared this
  window, reserving "release identity" exclusively for the Sigstore signer-trust sense:
  `.github/scripts/assert-release-ref.sh` (header, both echo/error lines, plus an added explanatory note
  distinguishing the two concepts so this collision cannot silently recur),
  `.github/scripts/assert-runtime-version.sh` (same pattern), `.github/workflows/ci.yml` (3 step names, 2
  inline comments), `ha_healthz_version_test.go:38`'s failure message, `release_version_identity_test.go`'s
  header comment (with the same added disambiguation note), and `roadmap/CI-REDESIGN.md`'s "F2" section
  title and body. Verified via `go build ./...`, `bash -n` on both scripts, YAML validation on `ci.yml`, a
  manual run of `assert-release-ref.sh` against empty/valid/invalid refs (all three exit codes and messages
  correct post-rename), and the targeted Go test run above — all clean.
- **Priority:** was High-if-unfixed (a fast-growing CI/release-engineering surface where "release identity"
  already carries real security weight — an admin or auditor reading a workflow log needs the two concepts
  to stay textually distinct). **Migration risk:** None (pre-release phrasing, zero test/doc dependency on
  the literal string, verified by build + targeted tests). **Est. PR size:** Trivial (already applied this
  pass).

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
| T-38 | `drifted_tools` vs. `review_required_tools` — same count, same API response, two names | Open since 08-06. Unchanged; still a pre-existing tested wire field, dual-emit remains the recommended fix. |
| T-39 | "Qualification" names four unrelated concepts in the same config/admin namespace | Open since 08-06, compounded 08-07. **This pass: not compounded further** — see Wave 2. Still needs a design decision. |

*T-41 is not listed here — fixed same-day, see Findings.*

## Soft findings — no action recommended

- Carried over unchanged from 07-24 onward: "Bootstrap" covering two unrelated features (no on-screen
  collision yet); the T3 "seed"/`CULVERT_PROXY_SEED_REF` vocabulary (internally consistent).
- Carried over unchanged from 08-03: the `culvert_decrypt_*` metric prefix vs. the fully-spelled
  `decryption`/`decryption-profile` API/audit/alert namespace — internally consistent, documented as a
  deliberate abbreviation in CLAUDE.md.
- Carried over unchanged from 08-04: `roadmap/google-captcha-swg-investigation.md:177`'s speculative
  `culvert_connlimit_rejections_total` metric citation for a counter that shipped as a REST field only.
- Carried over unchanged from 08-06: `drifted_tools`'s absence from `api/openapi/openapi.json`/`.yaml`
  despite being a live, tested field — worth closing in the same change that fixes T-38.
- Carried over unchanged from 08-07: the CDR per-instance circuit-breaker wire fields
  (`cbState`/`cbConsecFails`/`cbTotalOpens`/`cbTotalTrips`) use an ad hoc `cb`-prefix convention the sibling
  `internal/upstream.Status` breaker fields don't share — same concept, no collision, just an inconsistent
  key-naming convention across two similar endpoints. Not touched this window.

---

## Recommended Refactoring Plan (priority order)

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

*T-41 is omitted — already fixed this pass.*

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass re-confirmed, via a cited-line diff against every one of
19 previously-open findings, that all 19 are unchanged across an 80-commit window — the largest window this
program has reviewed, and the first in which zero previously-open findings moved in either direction. It
found and same-day-fixed one new finding (T-41) on code that shipped this window, before any release could
depend on the collision — the same "catch it, the earlier the cheaper" pattern this program has followed
since T-35 and applied most recently to T-40. It also recorded, for the first time, that T-39's
three-review compounding trend broke: no new PR stream reused "qualification" for a fifth concept this
window. The backlog itself — particularly T-38 and T-39, both flagged High/Medium-High and both requiring
either a mechanical dual-emit or a product-naming decision rather than a same-day fix — remains the
program's main open item; this review continues to surface the evidence rather than making that product
call unilaterally. No cosmetic or preference-driven renames were proposed.
