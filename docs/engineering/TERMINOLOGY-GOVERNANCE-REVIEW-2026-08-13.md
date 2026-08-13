# Culvert Language & Terminology Governance Review — 2026-08-13

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited the tree at `a4f9ee1`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-07.md` (baseline `d2c5a51`). Six days and 73 commits separate the
> two reviews (105 files, +12,778/-419 lines) — dominated by CHAOS-28 (Root-CA usability made fail-closed
> and observable), CHAOS-27 (alert-plane dedup bound under an alert storm), CHAOS-49 follow-up hardening
> (an attacker-provokable LDAP bind / a stuck auth-backend cooldown), the syslog delivery-panic observer +
> GUI surfacing, a DP config-snapshot-content-rejection operator-contract row, an HA `/healthz` `version`
> field, a request-log wall-clock render memoisation, and a PKI-lifetime pre-run gate for the pre-existing
> MCP Observe acceptance harness. Method: (1) `git diff --stat d2c5a51..HEAD` enumerated every touched file
> and checked it against every one of the nineteen carried-over open findings (T-9, T-11, T-12, T-13
> residual, T-16, T-17, T-18, T-21, T-25 residual, T-29 through T-34, T-36, T-37, T-38, T-39); where a cited
> file appeared in the diff, the actual hunk (not just the file touch) was read to confirm it falls outside
> the specific field/route/identifier each finding is about; (2) read every new or substantially-grown file
> in the window in full (`ca_health.go` new, `internal/ca/validity.go` new, `internal/mcpacceptance/pki.go`
> new, `store_logclock.go` new) for new naming surface; (3) traced each new field end-to-end — code identifier
> → JSON wire key → GUI variable → OpenAPI schema (where applicable) — for the CHAOS-28 CA-usability fields
> (`usable`/`unusableReason`/`inspectBlocked`/`signRefused`/`rotationPersistDegraded`), the CHAOS-27 dedup
> fields (`dedup_tracked`/`dedup_evictions_total`, both the per-endpoint JSON keys and the new
> `culvert_alert_dedup_*` Prometheus pair), the syslog panic counter (`Panics()` → `"panics"` → `sl.panics`),
> and the new HA `/healthz` `version` field; (4) grepped the full diff for "qualification" to check T-39's
> territory and traced every hit to its source — all resolved to either the carried-over 08-07 review
> document's own prose (added verbatim as a file in this window) or a PKI-lifetime fix inside the
> pre-existing `internal/mcpacceptance` package that consumes the already-flagged QUAL-2/3/4 config-key
> vocabulary rather than introducing a new sense; (5) spot-checked that the new `CAStatus` fields' absence
> from `api/openapi/openapi.yaml` is not a T-38-style coverage gap — the schema is `additionalProperties:
> true` by deliberate design ("opaque superset; fields depend on rotation/dual-CA mode"), unlike the closed
> schema T-38 depends on.
> **Companion change:** none. No new finding cleared this program's same-day fix bar this pass.

---

## Executive Summary

**No regressions, no new findings.** All nineteen carried-over open findings are re-confirmed unchanged
across a 73-commit, 105-file window. Of the files they cite, only `config.go`, `decryption_observability.go`,
and `static/index.html` appear in this window's diff (Wave 1 table below); each was read at the hunk level
and every touch lands outside the specific field/route/identifier the corresponding finding depends on.

**CHAOS-28 (Root-CA fail-closed usability) shipped a large amount of new surface this window and holds
discipline end-to-end.** The business concept — "can this node currently mint a leaf certificate a client
will accept, distinct from merely having a CA loaded" — gets exactly one vocabulary throughout: the Go
predicate `certMgr.Usable()` / `caInspectionUsable()`, the `/api/ca/status` JSON fields `usable` /
`unusableReason` / `inspectBlocked` / `signRefused` / `rotationPersistDegraded` / `rotationPersistError`,
the Prometheus metrics `culvert_ca_{usable,sign_refused_total,inspect_blocked_total,
rotation_persist_failures_total}`, the `/healthz` `ssl_inspection: expired` state and `/readyz`
`checks["ca"]` report-only row, and the GUI's `ca.usable` / `ca.unusableReason` / `ca.inspectBlocked` /
`ca.rotationPersistDegraded` reads in the new CA-unusable banner — no synonym drift anywhere on this path,
and the naming matches the shape already recorded in `CLAUDE.md`'s (unchanged this window) CHAOS-28
section, confirming the feature's documentation and its actual field names never diverged.

**CHAOS-27's alert-storm dedup bound is equally clean.** `internal/alerts.Store.DedupTracked()` /
`DedupEvictionsTotal()` surface identically as `dedup_tracked` / `dedup_evictions_total` on
`GET /api/alerts/delivery-history` (now a required field per the updated OpenAPI schema) and as the new
`culvert_alert_dedup_tracked` / `culvert_alert_dedup_evictions_total` Prometheus pair — one concept, one
name, three surfaces, checked bit-for-bit.

**T-39's territory grew by one data point, but it is not new drift.** `internal/mcpacceptance/pki.go` (new
this window, the CHAOS/incident-class fix "reject stale qualification PKI before acceptance") reuses
"qualification" repeatedly — but every use refers to the *same* QUAL-2/3/4 bootstrap/policy environment the
finding already tracks (its PKI is read from the fixture's existing `qualification_inventory_file` /
`qualification_policy_file` config surface), not a fifth independent sense of the word. Unlike 08-07's
QUAL-4 compounding (a genuinely new concept reusing the word), this is the *same* concept's own test
harness validating its own certificates — consistent with the finding's existing scope, not an escalation.
T-39's priority and recommendation are left unchanged.

**Everything else new this window — CHAOS-49's cooldown-hardening (`auth_ldap.go`, `auth_oidc_flow.go`),
the syslog panic observer (`internal/syslog/syslog.go`, `syslog.go`, GUI), the DP
`dp_config_snapshot_apply` operator-contract row (`diagnostics.go`, sibling-named to the pre-existing
`dp_last_known_good_config` row), the HA `/healthz` `version` field, and the request-log clock
memoisation (`store_logclock.go`) — introduces no new externally-visible vocabulary at all, or reuses
existing vocabulary correctly (CHAOS-49 reuses the CHAOS-47 `authProbeGate`/`noteAuthBackend*` primitives
exactly as `CLAUDE.md` already documents).**

**Terminology Health Score: 8.4 / 10** (unchanged — no new findings, no regressions, and a
disproportionately large window of new development, including a big new observable-fault feature
(CHAOS-28) and its full API/metrics/GUI surface, held discipline throughout).

**Fixed in this change:** none — nothing crossed the same-day fix bar this pass. This review itself is the
change (a documentation-only continuation of the series).

---

## Wave 1 — Carried-over findings re-confirmed unchanged

| Finding | Files it depends on | Touched this window? | Collision status |
|---|---|---|---|
| T-9 | export/import + parity-test surface (`exportedAt`) | No | Unchanged |
| T-11 | `policy.go`'s default-action vocabulary, `ui_policy.go` core | No | Unchanged |
| T-12 | Maintenance-Agent `/v1/upgrades/*` wire routes | No | Unchanged |
| T-13 residual | README/enterprise-doc "TLS Inspection" vs. in-app "SSL" | No | Unchanged |
| T-16 | ADR numbering (0008–0011) | No | Unchanged |
| T-17 | `decryption_redact_hosts` / `/api/decryption/redaction` | `decryption_observability.go` touched (+37 lines) | Touch is a new `caUnusableOutcome` helper for CHAOS-28's ADR-0011 outcome recording; zero `redact`-adjacent lines — unchanged |
| T-18 | `internal/sealbox.Seal`/`Open` call sites | No | Unchanged |
| T-21 | `cluster_convergence.go`, `configversion.go`'s rollback `cp_version` surface | No | Unchanged |
| T-25 residual | `support_recipients.go` / `support_tac_trust.go` | No | Unchanged |
| T-29 | YAML `rate_limit` (`config.go`/`main.go`) vs. `rate_limit_rpm` (API/wire/metric) | `config.go` touched (+9 lines) | Touch is a CDR `server_fingerprint` hex-validity check; zero `rate_limit`-adjacent lines — unchanged |
| T-30 | YAML `max_conns_per_ip`/wire `MaxConnsPerIP` vs. `conn_limit_max_per_ip` | No | Unchanged |
| T-31 | `culvert_clamav_blocked_total` vs. `culvert_clam_scan_errors_total` | No | Unchanged |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` overloads "snapshot" | No | Unchanged |
| T-33 | MCP `PolicyAction`/`PolicyReason` mixing three vocabularies (`internal/mcp/runtime/policy.go`, `events.go`, `observe.go`) | No | Unchanged |
| T-34 | SaaS feed status field-name split (`saas_feed_download.go`, `ui_policy.go`) | No | Unchanged |
| T-36 | `config.rollback` audit token vs. freeform config-version-history action string | No | Unchanged |
| T-37 | "Manual feed sync" naming split across blocklist/SaaS/threat feeds | No | Unchanged |
| T-38 | `ui_mcp.go`, `internal/mcp/adminapi/health.go`, `mcp_inventory.go`, `static/index.html` (`drifted_tools`/`review_required_tools`) | `static/index.html` touched (+~230 lines, CA-unusable banner + syslog panic surfacing) | Zero new hits for `drifted_tools`/`review_required_tools` in the diff — unchanged |
| T-39 | `internal/mcp/rollout` (Production Qualification), QUAL-2/3 config/docs | No production files touched (`mcp_policy.go`, `mcp_inventory.go`, `internal/mcp/rollout` all absent from the diff); `internal/mcpacceptance/pki.go` (new) reuses the existing QUAL-2/3/4 vocabulary for its own PKI check | Same concept, own test harness — see Executive Summary; not a new sense, not escalated |

## Wave 2 — New territory audited this pass (73 commits since `d2c5a51`)

**CHAOS-28 (Root-CA fail-closed usability, `ca.go`/`ca_health.go` new/`ca_metrics.go`/`internal/ca/ca.go`/
`internal/ca/validity.go` new/`proxy_tunnel.go`/`decryption_observability.go`/`ui_security.go`/
`healthcheck.go`/`static/index.html`): clean end-to-end.** Traced the full chain for every new field —
`certMgr.Usable()` (internal/ca) → `caInspectionUsable()`/`noteCAUsable()` (ca_health.go) →
`apiCAStatus`'s `usable`/`unusableReason`/`inspectBlocked`/`signRefused`/`rotationPersistDegraded`/
`rotationPersistError` (ui_security.go) → `ca.usable`/`ca.unusableReason`/`ca.inspectBlocked`/
`ca.rotationPersistDegraded` reads in the new CA-unusable banner (static/index.html) — one name per concept
at every layer, matching `CLAUDE.md`'s pre-existing CHAOS-28 section verbatim. The companion
`failClosedUnusableCA`/`caUnusableOutcome` pair (proxy_tunnel.go, decryption_observability.go) that records
the ADR-0011 outcome for the refused CONNECT also holds the documented invariant (no fail-open branch, no
autoexclude-learner feed) without inventing new vocabulary. `CAStatus`'s absence from the closed part of the
OpenAPI spec was checked and is not a T-38-style gap: the schema is deliberately
`additionalProperties: true` ("opaque superset; fields depend on rotation/dual-CA mode"), a pre-existing,
documented design choice distinct from the closed schema T-38 depends on.

**CHAOS-27 (alert-plane dedup bound, `internal/alerts/store.go`/`events.go`/`ui_security.go`): clean.**
`DedupTracked()`/`DedupEvictionsTotal()` surface identically as `dedup_tracked`/`dedup_evictions_total` on
the delivery-history admin endpoint (now required fields in the updated OpenAPI schema) and as the new
`culvert_alert_dedup_tracked`/`culvert_alert_dedup_evictions_total` Prometheus pair (events.go) — one
concept, one name, three surfaces.

**CHAOS-49 follow-up hardening (`auth_ldap.go`, `auth_oidc_flow.go`): clean, no new vocabulary.** Both
fixes (an attacker-provokable non-49 LDAP bind result must not arm the provider-wide cooldown; an answered
backend must clear a stuck cooldown, not just avoid re-arming it) are pure behavior corrections on the
pre-existing `authProbeGate`/`noteAuthBackend*`/`identity_backend` primitives `CLAUDE.md` already documents
for CHAOS-47/49 — `a.gate.recordReachable()`/`recordUnavailable()` reuse the exact same gate vocabulary,
no new name introduced.

**Syslog delivery-panic observer (`internal/syslog/syslog.go`, `syslog.go`, `static/index.html`): clean.**
`Writer.Panics()` → the `/api/config/syslog` JSON key `"panics"` → the GUI's `sl.panics` read in
`renderSyslogDrops` — one name at every layer, and the GUI's own inline comment ("panics is a subset of
drops") correctly documents the two counters' relationship rather than conflating them.

**DP config-snapshot-content-rejection operator-contract row (`diagnostics.go`,
`dp_last_good_config_test.go` new): clean.** The new `Code: "dp_config_snapshot_apply"` check is
deliberately sibling-named to (and explicitly doc-commented as distinct from) the pre-existing
`dp_last_known_good_config` row — one covers CP-polling failure, the other covers a reachable CP sending
content the DP could not apply. Both keep the established `dp_`-prefixed operator-contract-code convention;
no collision.

**HA `/healthz` `version` field (`ha.go`, `ha_healthz_version_test.go`, `release_version_identity_test.go`):
clean.** A single new key, added identically to all three `/healthz` response branches (standalone, leader,
standby), reusing the existing `version` package variable — no synonym introduced.

**Request-log wall-clock memoisation (`store_logclock.go` new, `store.go`): clean, no external surface.**
`logClockStamp`/`logEntryTimeLayout` are internal-only cache-plumbing for the pre-existing `LogEntry.Time`
field; the wire field name, JSON shape, and GUI consumption are all byte-identical to before this change —
a pure performance optimization with zero naming footprint.

---

## Soft findings — no action recommended

- Carried over unchanged from 07-24 onward: "Bootstrap" covering two unrelated features (no on-screen
  collision yet); the T3 "seed"/`CULVERT_PROXY_SEED_REF` vocabulary (internally consistent).
- Carried over unchanged from 08-03: the `culvert_decrypt_*` metric prefix vs. the fully-spelled
  `decryption`/`decryption-profile` API/audit/alert namespace — internally consistent, documented as a
  deliberate abbreviation in `CLAUDE.md`.
- Carried over unchanged from 08-04: `roadmap/google-captcha-swg-investigation.md:177`'s speculative
  `culvert_connlimit_rejections_total` metric citation for a counter that shipped as a REST field only.
- Carried over unchanged from 08-06: `drifted_tools`'s absence from `api/openapi/openapi.json`/`.yaml`
  despite being a live, tested field (see T-38); the pre-existing "Telemetry (opt-in)" support-panel
  feature vs. MCP Qualification Telemetry as a third generic sense of "telemetry" — different
  routes/screens, no on-screen adjacency, consistent with `PRODUCT-TERMINOLOGY.md`'s tolerance for
  screen-scoped generic-noun reuse.
- Carried over unchanged from 08-07: the CDR per-instance circuit-breaker fields' ad hoc `cb`-prefix
  wire-key convention vs. the sibling `internal/upstream.Status` breaker field names — same concept, same
  word, no collision, just an inconsistent key-naming convention across two similar per-instance-health
  endpoints; not queued (would be a live-field change).

---

## Recommended Refactoring Plan (priority order)

Unchanged from the 08-07 review — no new findings this pass to insert, and no carried-over finding's
priority moved.

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
| Medium | T-33 (carried over) | Stop overwriting `PolicyAction`/`PolicyReason` for pre-/post-policy gate failures; add a dedicated field for those instead | None today (zero production consumers) | Small |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low / Medium-large | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*` | Medium | Medium |
| Low-Medium | T-31 (carried over) | Rename `culvert_clam_scan_errors_total` → `culvert_clamav_scan_errors_total`, dual-emit | Low | Small |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

---

## Stop-Condition Assessment

Terminology is **not** fully consistent — nineteen findings remain open from prior passes. This pass
re-confirmed, via a cited-line diff against every one of them, that all nineteen are unchanged across a
73-commit window, including three findings whose dependent files were touched by unrelated code (verified
by reading the actual diff, not assuming file-touch implies drift). It found **zero new findings** despite
auditing a large amount of genuinely new, externally-visible surface (CHAOS-28's full CA-usability
API/metrics/GUI stack, CHAOS-27's dedup-bound observability, the syslog panic counter, a new DP
operator-contract row, and a new `/healthz` field) — every one of them traced end-to-end from code
identifier to wire field to GUI variable with no synonym drift found. No cosmetic or preference-driven
renames were proposed.
