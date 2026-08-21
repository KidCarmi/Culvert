# Culvert Language & Terminology Governance Review — 2026-08-18

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited the tree at `b697cf3`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-07.md` (baseline `d2c5a51`). 80 commits separate the two
> reviews, dominated by MCP PR-12 (production DP-applier composition + the durable rollout/distribution
> apply transaction — `mcp_distribution_startup.go`, `mcp_rollout_persist.go`,
> `mcp_distribution_transaction_test.go`), CHAOS-49 IdP-registry auth-path hardening (`auth_oidc_flow.go`),
> CHAOS-28 Root-CA fail-closed usability (`internal/ca/validity.go`, `ca_health.go`), CHAOS-27 alert-plane
> flood bounding (`internal/alerts/store.go`), the `idp_unreachable` webhook-subscription migration-on-load
> follow-up to T-40 (`92c3352`), and install-script/CI hardening.
> Method: (1) diffed every file each of the eighteen carried-over open findings (T-9, T-11 through T-13
> residual, T-16 through T-18, T-21, T-25 residual, T-29 through T-34, T-36 through T-39) depends on against
> `d2c5a51..HEAD`, reading the actual touched lines rather than assuming file-touch implies drift — five
> dependent files were touched this window (`config.go`, `main.go`, `events.go`, `ui_security.go`,
> `static/index.html`) and in every case the touch was unrelated code (a CDR fingerprint hex-validation
> check, MCP-distribution startup wiring, CHAOS-27 dedup metrics, CHAOS-28 CA-usability fields, and CA/alert
> panel additions respectively — grepped `static/index.html`'s diff for both `drifted_tools`/
> `review_required_tools` and `qualification`, zero hits); (2) independently re-verified T-36 and T-37
> against the current call sites before fixing them; (3) spot-checked the session-secret four-name surface,
> the retired `UnauthMode`, and the `idp_unreachable` → `identity_backend_unreachable` rename per CLAUDE.md
> — all unchanged/still resolved.
> **Companion changes:** T-36 and T-37 (both carried over from 08-04, queued at Medium priority with Low
> migration risk in every review since) fixed same-day this pass — see Findings.

---

## Executive Summary

**All eighteen carried-over findings re-verified at the cited-line level; sixteen are unchanged.** Two —
T-36 and T-37 — are fixed this pass (see below). T-39 remains open and unchanged this window (no new
"qualification"-naming PR stream landed since 08-07; still needs the design decision recommended there).
T-38 remains queued (unchanged; `static/index.html`'s diff this window has zero hits for either
`drifted_tools` or `review_required_tools`).

**Two findings fixed same-day: T-36 and T-37.** Both have sat at Medium priority / Low migration risk
in the Recommended Refactoring Plan since 08-04 without ever being the *newest* finding in a given window
(the slots each review's "fix same-day" judgment went to were T-35, then T-40, both brand-new-that-window
collisions on live GUI/webhook surfaces judged more urgent). With no new same-window collision competing
for attention this pass, and both fixes matching this program's own stated bar (no wire/public-API-key
surface, verified zero test dependency beyond call sites updated in the same change, mechanical not
design-level), they are fixed now rather than deferred a further review cycle:

- **T-36** — `configversion.go`'s rollback handler passed a stable, namespaced `"config.rollback"` token to
  `auditEvent` but a freeform, unprefixed `"rollback to v%d"` string to `saveConfigVersion` — the sole
  config-mutating handler among 30+ call sites where the two differ; every other handler (`policy.add`,
  `blocklist.add`, `urlcat.create`, etc.) passes the identical action string to both. Fixed by giving the
  config-version-history entry the same `config.rollback` prefix: `fmt.Sprintf("config.rollback v%d",
  req.Version)`. No test asserted the old string (grepped `*_test.go`, zero hits); the only other repo
  references to `"rollback to v` are two roadmap design docs and two prior terminology-review entries
  describing the pre-fix behavior as history, left as-is.
- **T-37** — three feed subsystems named their "admin-triggered manual sync now" audit action with three
  unrelated patterns: `blocklist.feed.sync`, `saasfeed.refresh`, and `security.feeds_sync` — the last for
  the threat-feed (URLhaus/OpenPhish) sync, whose *other* actions in the same file already use the
  `threatfeed.` prefix (`threatfeed.allowlist.update`, `threatfeed.allowlist.update_unpersisted`), making
  the manual-sync action invisible to a `threatfeed.`-prefixed audit search that finds every sibling
  threat-feed action. Fixed by renaming `security.feeds_sync` → `threatfeed.sync`
  (`ui_security.go:567`), which required no design decision — the codebase already had the correct prefix
  convention next to it. `security_feedsync_audit_test.go`'s three literal assertions plus its two
  descriptive comments were updated in the same change (all five instances renamed, tests re-run and
  passing). `docs/C15_UNKNOWN_AUDIT.md`'s recommendation section — which cited the pre-fix
  `security.feeds_sync` name as what to implement — was updated with a status note pointing at this
  review. Blocklist and SaaS-feed sync naming were left untouched (not this finding's scope; each already
  carries its own subsystem prefix and neither collides with a sibling action namespace the way
  `security.feeds_sync` did).

**Terminology Health Score: 8.5 / 10** (up from 8.4 — two previously-queued, low-risk findings closed with
zero regressions across an 80-commit window; T-39 unchanged rather than worsened this pass, since no new PR
stream reused the overloaded word this window).

---

## Wave 1 — Carried-over findings re-confirmed unchanged

`git diff d2c5a51..HEAD` (80 commits) was checked against every file each of the eighteen open findings
(excluding T-36/T-37, fixed this pass — see Findings) depends on; every finding whose files *were* touched
had the actual cited lines/identifiers diffed, not just the file.

| Finding | Files it depends on | Touched this window? | Collision status |
|---|---|---|---|
| T-9 | export/import + parity-test surface (`exportedAt`) | No | Unchanged |
| T-11 | `policy.go`'s default-action vocabulary, `ui_policy.go` core | No | Unchanged |
| T-12 | Maintenance-Agent `/v1/upgrades/*` wire routes | No | Unchanged |
| T-13 residual | README/enterprise-doc "TLS Inspection" vs. in-app "SSL" | No | Unchanged |
| T-16 | ADR numbering (0008–0011) | No | Unchanged |
| T-17 | `decryption_redact_hosts` / `/api/decryption/redaction` | No (`decryption_observability.go` touched, unrelated CHAOS-28 wiring — a distinct file) | Unchanged |
| T-18 | `internal/sealbox.Seal`/`Open` call sites | No | Unchanged |
| T-21 | `cluster_convergence.go`, `configversion.go`'s rollback `cp_version` surface | No (`configversion.go` touched only by this pass's own T-36 fix, unrelated to `cp_version`) | Unchanged |
| T-25 residual | `support_recipients.go` / `support_tac_trust.go` | No | Unchanged |
| T-29 | YAML `rate_limit` (`config.go`/`main.go`) vs. `rate_limit_rpm` (API/wire/metric) | `config.go` (+9), `main.go` (+2/-1) touched | `config.go`'s touch is a CDR `server_fingerprint` hex-validity check; `main.go`'s is `initMCPDistribution` startup wiring — zero `rate_limit`-adjacent lines in either — unchanged |
| T-30 | YAML `max_conns_per_ip`/wire `MaxConnsPerIP` vs. `conn_limit_max_per_ip` | No | Unchanged |
| T-31 | `culvert_clamav_blocked_total` vs. `culvert_clam_scan_errors_total` | No (`ca_metrics.go` is a new, unrelated file) | Unchanged |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` overloads "snapshot" | No | Unchanged |
| T-33 | MCP `PolicyAction`/`PolicyReason` mixing three vocabularies (`internal/mcp/runtime/policy.go`, `events.go`, `observe.go`) | Root `events.go` touched (+4) | Touch is a new CHAOS-27 `culvert_alert_dedup_*` Prometheus export block; zero `PolicyAction`/`PolicyReason` lines, and `internal/mcp/runtime/{policy,observe}.go` untouched — unchanged |
| T-34 | SaaS feed status field-name split (`saas_feed_download.go`, `ui_policy.go`) | No | Unchanged |
| T-38 | `ui_mcp.go`, `internal/mcp/adminapi/health.go`, `mcp_inventory.go`, `static/index.html` (`drifted_tools`/`review_required_tools`) | `static/index.html` touched (+41/-14) | Diff greped for `drifted_tools`/`review_required_tools` — zero hits; the touch is CHAOS-28 CA-usability banner fields and CHAOS-27 alert-dedup stats, unrelated screens. `ui_mcp.go`, `internal/mcp/adminapi/health.go`, `mcp_inventory.go` untouched — unchanged |
| T-39 | `internal/mcp/rollout` (Production Qualification), QUAL-2/3/4 config/docs | `mcp_rollout.go` (+238/-14), `mcp_distribution.go` (+107/-9) touched | Both touches are PR-12's durable rollout-commit/distribution-apply transaction plumbing (`applyMCPCapabilityEnvelope`, `AbortApplied`/`RejectAck` wiring) — zero new "qualification"-word occurrences; `static/index.html`'s diff has zero `qualification` hits (the existing MCP-Policy-panel string at line ~20296, up from 20255 in the 08-07 review, shifted only because unrelated insertions earlier in the file pushed it down — content byte-identical) — unchanged, not compounded further this window |

## Wave 2 — Spot-checks outside the open-findings list

**CHAOS-49 (`auth_oidc_flow.go`, IdP-registry hardening) reuses CHAOS-47's existing `identity_backend`
vocabulary correctly, not the retired `idp_unreachable` string T-40 fixed.** CLAUDE.md's own updated
CHAOS-49 section (added this window) documents the registry path landing on "the existing `identity_backend`
row, `culvert_auth_backend_*` metrics, and `identity_backend_unreachable` alert with NO new config and NO
new operator vocabulary" — verified: `auth_oidc_flow.go`'s new cooldown/cache code calls the same
`noteAuthBackend*`/`authProbeGate` primitives CHAOS-47 already established, and introduces no second wire
alert name for the same failure class. Positive continuation of the T-40 fix, not a new finding.

**The `idp_unreachable` → `identity_backend_unreachable` webhook-subscription migration (`92c3352`,
`internal/alerts/store.go`'s `legacyEventNames` map, referenced in the 08-07 review's T-40 write-up as
"applied") is confirmed present and unchanged** — `Init` still migrates any webhook persisted under the old
name on every process start, so T-40's fix stays durable across this window's alert-plane changes
(CHAOS-27's dedup-cap bounding touches the same file but a different code path).

**Session-secret four-name surface and the retired `UnauthMode` — both unchanged per CLAUDE.md, confirmed
by grep (`SessionHMAC`, `SigningKey`, `unauth_mode` legacy-field handling all at their previously-recorded
locations, no new call sites).**

---

## Findings

### T-36 — `config.rollback` audit token vs. freeform config-version-history action string (carried over — fixed this pass)

- **Business concept:** an admin rolled the running configuration back to a previously-captured version.
- **Names found (before this fix):** `configversion.go:293` — `auditEvent(r, "config.rollback", "system",
  auditDetail)`, a stable namespaced token identical in form to every other config-mutating handler's audit
  action (`policy.add`, `blocklist.add`, `urlcat.create`, `decryption-profile.update`, …) — vs.
  `configversion.go:295` (before fix) — `saveConfigVersion(actor, fmt.Sprintf("rollback to v%d",
  req.Version))`, a freeform sentence with no shared prefix or substring with `config.rollback`. Every one
  of the 30+ other `saveConfigVersion` call sites across the codebase (`ui_policy.go`, `ui_security.go`,
  `ui_authpolicy.go`, `pac.go`, `saas_feed_api.go`, …) passes the *same literal string* to both `auditEvent`
  and `saveConfigVersion` for a given action; rollback was the sole exception.
- **Why this was real drift, not cosmetic:** an admin or support engineer correlating the audit ring
  against the Config Versions history list (`GET /api/config/versions`, whose entries carry the
  `saveConfigVersion` action string as their `Action` field) had no stable token to filter or report on for
  rollback events specifically, unlike every other action family, which supports exactly that via a shared
  string.
- **Fix applied:** `configversion.go:295` now reads `saveConfigVersion(actor, fmt.Sprintf("config.rollback
  v%d", req.Version))` — the stable `config.rollback` prefix is preserved (so a search/filter on
  `config.rollback` now finds both the audit entry and the version-history entry for the same rollback) while
  the version number stays in the string, since the config-version-history UI displays the action text
  directly and losing the version number there would be a regression.
- **Migration risk:** None realized — no test asserted the old `"rollback to v%d"` string (grepped every
  `*_test.go`); the two remaining repo references to `"rollback to v` are a roadmap design doc and two prior
  terminology-review write-ups describing pre-fix behavior as history, both left untouched since they are
  accurate as historical record.
- **Priority:** Medium (as carried since 08-04). **Est. PR size:** Trivial (already applied this pass).

### T-37 — "Manual feed sync" audit-action naming split across blocklist/SaaS/threat feeds (carried over — fixed this pass)

- **Business concept:** an admin triggered an immediate, out-of-cadence refresh of a feed-backed data
  source.
- **Names found (before this fix):** `ui_policy.go:381` — `"blocklist.feed.sync"`;
  `saas_feed_status_api.go:110` — `"saasfeed.refresh"`; `ui_security.go:567` (before fix) —
  `"security.feeds_sync"`, for `POST /api/security-scan/feeds/sync` (the threat-feed / URLhaus-OpenPhish
  manual sync). The threat feed's own *other* audit actions in the same file already use the `threatfeed.`
  prefix (`ui_security.go:609,638` — `threatfeed.allowlist.update_unpersisted`,
  `threatfeed.allowlist.update`).
- **Why this was real drift, not cosmetic:** blocklist and SaaS-feed manual syncs were each findable by
  their own subsystem's audit prefix; the threat-feed manual sync was not, despite living in the same file
  and admin surface as its sibling threat-feed actions that were — an admin building an audit report
  scoped to `threatfeed.*` would silently miss every manual-sync event.
- **Fix applied:** `ui_security.go:567` now reads `auditEvent(r, "threatfeed.sync", "manual", "")`.
  `security_feedsync_audit_test.go` — the test pinning this exact audit call — had its two descriptive
  comments and three literal string assertions (`hasMatchingAuditEntry(...)` calls plus the corresponding
  `t.Fatalf`) updated to the new name in the same change; `go build ./...`, `go vet ./...`, and a targeted
  `go test -run TestSecFeedsSync` run all pass. `docs/C15_UNKNOWN_AUDIT.md:137`, which had recorded
  `security.feeds_sync` as the recommended (at-the-time not-yet-implemented) fix for a separate, older
  missing-audit finding, gained a status note pointing at this review so the doc reflects what actually
  shipped. Blocklist's `blocklist.feed.sync` and SaaS-feed's `saasfeed.refresh` were left as-is — each is
  internally consistent within its own subsystem's prefix and the finding was specifically the threat-feed
  action's mismatch with its own siblings, not a demand to unify all three feed families onto one shared
  verb.
- **Migration risk:** Low, as assessed in every prior review carrying this finding — not a wire/public
  config key, an audit-event string with exactly one test dependency, updated in the same change.
- **Priority:** Medium (as carried since 08-04). **Est. PR size:** Small (already applied this pass).

### T-39 — "Qualification" names four unrelated concepts across independent PR streams in the same `mcp.gateway.*`/`/api/mcp/*` surface (carried over — unchanged this window, not further compounded)

Unchanged from the 08-07 write-up in every particular — no new PR stream reused the word this window; the
80-commit MCP PR-12 window (`mcp_distribution.go`, `mcp_rollout.go`, `mcp_distribution_startup.go`) is
durable-state/transaction plumbing for the *existing* Production Qualification receipt-gate concept
(business concept A) and introduces no new sense of the word. Re-stated for continuity rather than
reproduced in full — see `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-07.md`'s T-39 entry for the complete
four-concept breakdown, evidence, and recommended fix (a product-naming decision, not a mechanical rename:
reserve bare "Qualification" for the Production receipt gate; rename the QUAL-2/3 bootstrap fleet and
QUAL-4 node-local policy source to distinct, environment-scoped names).

- **Priority:** Medium-High (unchanged from 08-07 — the underlying ambiguity did not worsen this window,
  but it also has not been resolved, and it remains the highest-priority open item in this program's
  backlog). **Migration risk:** Medium. **Est. PR size:** Small-Medium (needs a naming decision first).

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
| T-38 | `drifted_tools` vs. `review_required_tools` — same count, same API response, two names | Open since 08-06. Unchanged; still a pre-existing tested wire field, dual-emit remains the recommended fix. |
| T-39 | "Qualification" names four unrelated concepts in the same config/admin namespace | Open since 08-06. Unchanged this pass (not further compounded — see Findings). |

*T-36 and T-37 are not listed here — fixed this pass, see Findings.*

## Soft findings — no action recommended

Carried over unchanged from prior reviews (see `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-07.md`'s Soft
findings section for full detail): "Bootstrap" covering two unrelated features; the T3 "seed"/
`CULVERT_PROXY_SEED_REF` vocabulary; the `culvert_decrypt_*` metric-prefix abbreviation (documented
deliberate in CLAUDE.md); a speculative metric citation in `roadmap/google-captcha-swg-investigation.md`;
`drifted_tools`'s absence from the OpenAPI spec; the "Telemetry (opt-in)" support-panel feature vs. MCP
Qualification Telemetry as a third generic sense of "telemetry" (screen-scoped, no on-screen adjacency);
the CDR per-instance circuit-breaker `cb`-prefix wire-key convention vs. the sibling upstream-pool breaker's
differently-prefixed fields (same concept, same word, no collision — just an unaligned key-naming
convention, not queued while `cdr_ui_test.go` pins the current field names as a live wire contract).

None of these were touched this window (verified via the same `d2c5a51..HEAD` diff pass); no new soft
findings surfaced.

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
| Medium | T-33 (carried over) | Stop overwriting `PolicyAction`/`PolicyReason` for pre-/post-policy gate failures; add a dedicated field for those instead | None today (zero production consumers); rises once a consumer exists | Small |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low / Medium-large | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*` | Medium | Medium |
| Low-Medium | T-31 (carried over) | Rename `culvert_clam_scan_errors_total` → `culvert_clamav_scan_errors_total`, dual-emit | Low | Small |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

*T-36 and T-37 are omitted — already fixed this pass.*

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass re-confirmed, via a cited-line diff against every one of
eighteen previously-open findings, that sixteen are unchanged across an 80-commit window — including four
findings whose dependent files were touched by unrelated code in the same window, each verified by reading
the actual diff rather than assuming file-touch implies drift. It fixed two long-queued, low-risk findings
(T-36, T-37) that had sat at Medium priority since 08-04 without ever being the newest same-window
collision competing for a same-day fix slot. T-39, this program's highest-priority open item, is unchanged
this window — genuinely stable rather than worsened, since no new PR stream reused the overloaded word — and
still requires the design decision recommended since 08-06. No cosmetic or preference-driven renames were
proposed; every fix applied this pass matches an existing multi-review-cycle recommendation at Low migration
risk with verified zero test/doc/wire dependency beyond what was updated in the same change.
