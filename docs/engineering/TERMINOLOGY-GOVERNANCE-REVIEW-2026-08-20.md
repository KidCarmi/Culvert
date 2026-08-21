# Culvert Language & Terminology Governance Review — 2026-08-20

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited the tree at `b697cf3`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-07.md` (baseline `d2c5a51`). 80 commits separate the two
> reviews — a materially larger window than the series' recent 1-2 day cadence, dominated by the MCP
> PR-12 distribution/rollout transaction stream (`mcp_distribution_startup.go`, `applyMCPCapabilityEnvelope`
> in `mcp_distribution.go`, `internal/mcp/cpdp/apply`'s `AbortApplied`/`RejectAck`, durable rollout state),
> a "qualification PKI lifetime guard" for the MCP Observe acceptance harness (`internal/mcpacceptance/pki.go`),
> CHAOS-49 IdP-registry auth hardening (`auth_oidc.go`/`auth_oidc_flow.go`), CHAOS-28 CA fail-closed
> usability (`internal/ca/validity.go`, `ca_health.go`, `ca_metrics.go`), CHAOS-27 alert-storm dedup bounding
> (`internal/alerts/store.go`), syslog panic-loss surfacing (`internal/syslog/syslog.go`), `/readyz` posture
> hardening (dropping the enforcement-posture statement and CA-path/AV-address disclosure), install-script
> CA/log-passphrase fixes, and new operator diagnostics for DP config-snapshot rejection
> (`checkConfigSnapshotApply`). Method: (1) diffed the actual cited lines/identifiers (not just file
> touches) for every one of the nineteen carried-over open findings — T-9, T-11, T-12, T-13 residual, T-16,
> T-17, T-18, T-21, T-25 residual, T-29 through T-34, T-36, T-37, T-38, T-39 — against `git diff --stat
> d2c5a51..HEAD` (121 files) and every file each depends on; (2) traced the PR-12 stream's new
> envelope/transaction/reconcile/Ack vocabulary against every pre-existing use of those same English words
> elsewhere in the codebase (the PSCA "envelope," five unrelated `reconcile*` functions) to rule out a
> silent namesake; (3) checked the new "qualification PKI lifetime guard" (commit `71e2631`) against the
> four already-tracked senses of "qualification" (T-39) to see whether it introduces a fifth; (4) verified
> CHAOS-49 actually reuses the CHAOS-47 `identity_backend` vocabulary end-to-end rather than reintroducing
> the `idp_unreachable` collision T-40 fixed on 2026-08-07; (5) verified CHAOS-27, CHAOS-28, the syslog
> panic/drop split, the `/readyz`/`/healthz`/diagnostics CA-status triad, the install-script passphrase
> fix, and the new config-snapshot-rejection diagnostic code each name their concept once, consistently,
> across API/GUI/metrics/audit, with no stray synonym or accidental reuse of an existing name.
> **Companion change:** none. No new finding cleared this program's same-day fix bar this window.

---

## Executive Summary

**No regressions, no new findings.** All nineteen carried-over findings (T-9, T-11, T-12, T-13 residual,
T-16, T-17, T-18, T-21, T-25 residual, T-29 through T-34, T-36, T-37, T-38, T-39) are re-confirmed
unchanged at the cited-line level. Of the files they depend on, only `config.go` (a new, unrelated
`cdr.server_fingerprint` hex-validity check — T-29/T-30's territory but zero `rate_limit`/`max_conns_per_ip`
lines touched) and `static/index.html` (CA-usability banners, syslog-panic messaging, alert-dedup health
text, and the already-applied T-40 checkbox rename — zero new `drifted`/`review_required` hits) appear in
this window's diff; both were read at the hunk level and fall outside the specific field each finding is
about. `metrics.go` itself was not touched this window (the new CA metrics live in an additive
`ca_metrics.go`), so T-31's `culvert_clam_scan_errors_total` collision is untouched as well.

**T-39 is unchanged — genuinely unchanged, not just unworsened.** This window's largest MCP-adjacent
change, the PR-12 distribution/rollout transaction stream (`mcp_distribution_startup.go`,
`mcp_distribution.go`, `internal/mcp/cpdp/apply`), was grepped directly for "qualification" end to end:
zero hits. The other MCP change that does touch qualification vocabulary — commit `71e2631`'s "qualification
PKI lifetime guard" (`internal/mcpacceptance/pki.go`) — adds PKI-freshness validation *for* the
already-tracked QUAL-6 acceptance-harness environment (T-39's business concept B/QUAL-6 sense), not a fifth
concept; it never reaches the GUI (`static/index.html`'s "qualification" hits are still only the two
pre-existing senses: the Production Qualification receipt gate and the QUAL-4 policy-source card). T-39's
priority and recommendation are unchanged from 08-07; the design decision it depends on is still
outstanding.

**Every other new feature this window names its concept once and cross-references its siblings
explicitly** — the same discipline the program has praised before (CLAUDE.md's Session-Secret paragraph is
the standing bar). CHAOS-27's alert-dedup counters (`DedupEvictionsTotal`/`dedup_evictions_total`) are one
name end-to-end across the store, `/metrics`, and the GUI. CHAOS-28's CA-usability vocabulary
(`culvert_ca_usable`, `ssl_inspection: expired`) matches CLAUDE.md's own documentation exactly, with no
stray synonym. The new syslog "panics" counter explicitly documents itself in the GUI as "a subset of
drops" rather than a competing counter. The new `checkConfigSnapshotApply` diagnostic explicitly
cross-references its sibling `checkDPLastGoodConfigSnapshot` in its own doc comment, and uses the
established "config snapshot" wire-sync vocabulary rather than adding a new instance of T-21/T-32's
"Config Version"/"snapshot" overload. The install-script CA/log-passphrase fix is careful to name which
env var is which (`CULVERT_LOG_PASSPHRASE` vs. `CULVERT_CA_PASSPHRASE`) at every step of bridging them. One
soft, non-actionable observation: CHAOS-28's new `/api/ca/status` field `"usable"` (a CA-lifecycle boolean)
shares its bare English adjective with the pre-existing, unrelated MCP tool-registry `disposition` value
`"usable"` (`internal/mcp/registry/record.go`) — different JSON namespaces, different screens, no
on-screen adjacency, the same screen-scoped generic-word tolerance `PRODUCT-TERMINOLOGY.md` already grants
"Policy" and "Telemetry." Not escalated.

**Terminology Health Score: 8.4 / 10** (unchanged from 08-07 — a materially larger-than-usual, 80-commit
window produced zero new findings and zero regressions, including on the exact subsystem, T-39, most at
risk of a fifth "qualification" collision. The backlog itself is unchanged: T-38 and T-39 remain the two
highest-priority open items, both still awaiting the same fixes/decisions recommended on 08-06/08-07).

---

## Wave 1 — Carried-over findings re-confirmed unchanged

`git diff --stat d2c5a51..HEAD` (121 files across 80 commits) was checked against every file each of the
nineteen open findings depends on; every finding whose files *were* touched had the actual cited
lines/identifiers diffed, not just the file.

| Finding | Files it depends on | Touched this window? | Collision status |
|---|---|---|---|
| T-9 | export/import + parity-test surface (`exportedAt`) | No | Unchanged |
| T-11 | `policy.go`'s default-action vocabulary, `ui_policy.go` core | No | Unchanged |
| T-12 | Maintenance-Agent `/v1/upgrades/*` wire routes | No | Unchanged |
| T-13 residual | README/enterprise-doc "TLS Inspection" vs. in-app "SSL" | No | Unchanged |
| T-16 | ADR numbering (0008–0011) | No | Unchanged |
| T-17 | `decryption_redact_hosts` / `/api/decryption/redaction` | No | Unchanged |
| T-18 | `internal/sealbox.Seal`/`Open` call sites | No | Unchanged |
| T-21 | `cluster_convergence.go`, `configversion.go`'s rollback `cp_version` surface | No | Unchanged |
| T-25 residual | `support_recipients.go` / `support_tac_trust.go` | No | Unchanged |
| T-29 | YAML `rate_limit` (`config.go`/`main.go`) vs. `rate_limit_rpm` (API/wire/metric) | `config.go` touched (10 lines) | Touch is a new `cdr.server_fingerprint` hex-validity check; zero `rate_limit`-adjacent lines — unchanged |
| T-30 | YAML `max_conns_per_ip`/wire `MaxConnsPerIP` vs. `conn_limit_max_per_ip` | Same `config.go` touch | Same verdict — zero `max_conns_per_ip` lines — unchanged |
| T-31 | `culvert_clamav_blocked_total` vs. `culvert_clam_scan_errors_total` | No (`metrics.go` untouched; new `ca_metrics.go` is additive/distinct) | Unchanged |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` overloads "snapshot" | No | Unchanged |
| T-33 | MCP `PolicyAction`/`PolicyReason` mixing three vocabularies (`internal/mcp/runtime/policy.go`, `events.go`, `observe.go`) | No (all three untouched; PR-12 lives in `internal/mcp/cpdp/apply`, a different package) | Unchanged — still zero production consumers |
| T-34 | SaaS feed status field-name split (`saas_feed_download.go`, `ui_policy.go`) | No | Unchanged |
| T-36 | `config.rollback` audit token vs. freeform config-version-history action string | No | Unchanged |
| T-37 | "Manual feed sync" naming split across blocklist/SaaS/threat feeds | No | Unchanged |
| T-38 | `ui_mcp.go`, `internal/mcp/adminapi/health.go`, `mcp_inventory.go`, `static/index.html` (`drifted_tools`/`review_required_tools`) | `static/index.html` touched (55 lines); the other three untouched | Touch is CA-usability banners, syslog-panic messaging, alert-dedup health text, and the already-shipped T-40 checkbox `value` rename — zero new hits for `drifted`/`review_required` — unchanged |
| T-39 | `internal/mcp/rollout` (Production Qualification), QUAL-2/3/4 config/docs | `internal/mcpacceptance/pki.go` (new), `mcp_rollout.go`/`mcp_rollout_persist.go` touched | New PKI-guard code is QUAL-6's own "concept B" sense (not a fifth); `mcp_rollout*.go` hits are correct pre-existing "concept A" (Production receipt gate) usage — see Wave 2 — **unchanged, not further worsened** |

## Wave 2 — New territory audited this pass (80 commits since `d2c5a51`)

**PR-12's distribution/rollout transaction vocabulary is a clean reuse, not a namesake collision.**
`applyMCPCapabilityEnvelope` (`mcp_distribution.go:234`) coordinates distribution activation with the
node-local rollout commit; its "envelope" is `internal/mcp/cpdp.Envelope`, the same signed CP→DP message
type introduced in PR-10 and already covered by prior reviews — not a new collision with the unrelated
PSCA "envelope" (the encrypted-CA-key-at-rest wrapper in `ca.go`/`cluster_ca_keyatrest.go`/`restore.go`),
which is a distinct crypto-key-wrapper concept in a distinct file family with no shared screen or field
name. `reconcileRolloutWithDistribution` (`mcp_distribution_startup.go:145`) uses "reconcile" as a plain
English verb, matching five other unrelated `reconcile*` functions already in the repo
(`policy_draft.go`, `config.go`, `saas_feed_genstore.go`) — not a branded, collidable concept. `AckApplied`/
`AckRejected` (`internal/mcp/cpdp/apply/ack.go`) introduce no prior "Ack" vocabulary to collide with.
Grepped `mcp_distribution*.go` and `internal/mcp/cpdp/apply/*.go` directly for "qualification": zero hits.

**The MCP "qualification PKI lifetime guard" (commit `71e2631`) is more instances of an
already-tracked sense, not a new one.** `internal/mcpacceptance/pki.go`'s `validateFixturePKI` rejects
stale X.509 fixture material before an acceptance run — this is PKI *for* the QUAL-6 acceptance-harness
environment T-39 already logs as "business concept B," not a new fifth sense. It never surfaces in the
GUI: `static/index.html`'s "qualification" hits remain confined to the two pre-existing GUI-visible senses
(the Production Qualification receipt-gate card and the QUAL-4 policy-source card). `mcp_rollout.go:339`
("externally-verified qualification") and `mcp_rollout_persist.go:17` ("claimed ≥14-day continuous Shadow
qualification window") both correctly refer to business concept A (the Production receipt gate) — not new
drift. T-39's fact pattern is unchanged this window; its priority and recommendation carry forward as-is.

**CHAOS-49, CHAOS-27, CHAOS-28, syslog panic-loss, `/readyz` posture hardening, the install-script
passphrase fix, and the new config-snapshot-rejection diagnostic: all clean.** CHAOS-49
(`auth_oidc.go`/`auth_oidc_flow.go`) reuses the CHAOS-47 `identity_backend` vocabulary verbatim with no new
alert/label string — `diagnostics.go`'s `checkIdentityBackend` was itself updated this window to the
post-T-40 `identity_backend_unreachable` name, reinforcing rather than reopening that fix. CHAOS-27's
`DedupEvictionsTotal`/`dedup_evictions_total` is one name end-to-end across `internal/alerts/store.go`,
`events.go`'s `/metrics` exposition, `ui_security.go`, and `static/index.html`, with no collision against
the unrelated dedup logic elsewhere (PAC host-list dedup, release-catalog idempotency dedup — different
structures, not GUI/API-facing under the same name). CHAOS-28's `culvert_ca_usable`,
`culvert_ca_expires_in_seconds`, `culvert_ca_sign_refused_total`, `culvert_ca_inspect_blocked_total`,
`culvert_ca_rotation_persist_failures_total` (`ca_metrics.go`) and `ssl_inspection: expired`
(`healthcheck.go`) match CLAUDE.md's own documentation exactly. The new syslog `panics` counter
(`internal/syslog/syslog.go`) is explicitly documented in its own GUI tooltip as "a subset of drops," not a
competing counter — the Session-Secret-style cross-referenced pattern, not drift; it is also unrelated to
the pre-existing, differently-scoped `sync_panics` HA/cluster field. The `/readyz`/`/healthz`/diagnostics
CA-status triad all agree on when the CA is degraded via the same `certMgr.Usable()`/
`caRotationPersistDegraded()` predicates, despite each surface intentionally exposing a different shape
(status enum vs. gating report vs. redacted detail) for its own security posture. The install-script fix
(`c86e44c`/`4940c6e`) is careful to name `CULVERT_LOG_PASSPHRASE` and `CULVERT_CA_PASSPHRASE` distinctly at
every step of bridging them — no conflation. The new `checkConfigSnapshotApply` diagnostic
(`diagnostics.go`) explicitly cross-references its sibling `checkDPLastGoodConfigSnapshot` in its own doc
comment and reuses the established "config snapshot" vocabulary rather than adding a new instance of
T-21/T-32's "Config Version"/"snapshot" overload; it has no dedicated GUI label to collide with anything.

---

## Findings

No new findings this pass. See "Carried over, still open" below for the full re-confirmed backlog.

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
| T-33 | MCP `PolicyAction`/`PolicyReason` observation fields mix three vocabularies | Open since 08-02. Unchanged; still zero production consumers. |
| T-34 | SaaS feed status field-name split across two admin endpoints | Open since 08-02. Unchanged. |
| T-36 | `config.rollback` audit token vs. freeform config-version-history action string | Open since 08-04. Unchanged. |
| T-37 | "Manual feed sync" audit-action naming split across blocklist/SaaS/threat feeds | Open since 08-04. Unchanged. |
| T-38 | `drifted_tools` vs. `review_required_tools` — same count, same API response, two names | Open since 08-06. Unchanged; dual-emit remains the recommended fix. |
| T-39 | "Qualification" names four unrelated concepts in the same config/admin namespace | Open since 08-06, compounded 08-07. Unchanged this pass — the new PKI guard adds instances of an already-tracked sense, not a fifth. |

## Soft findings — no action recommended

- Carried over unchanged from 07-24 onward: "Bootstrap" covering two unrelated features (no on-screen
  collision yet); the T3 "seed"/`CULVERT_PROXY_SEED_REF` vocabulary (internally consistent).
- Carried over unchanged from 08-03: the `culvert_decrypt_*` metric prefix vs. the fully-spelled
  `decryption`/`decryption-profile` API/audit/alert namespace — internally consistent, documented as a
  deliberate abbreviation in CLAUDE.md.
- Carried over unchanged from 08-04: `roadmap/google-captcha-swg-investigation.md:177`'s speculative
  `culvert_connlimit_rejections_total` metric citation for a counter that shipped as a REST field only.
- Carried over unchanged from 08-06/08-07: `drifted_tools`'s absence from
  `api/openapi/openapi.json`/`.yaml` despite being a live, tested field (worth closing alongside T-38); the
  CDR per-instance circuit-breaker fields' ad hoc `cb`-prefix wire-key convention vs. the sibling
  `internal/upstream.Status` breaker's differently-named fields (same concept, no collision, just an
  inconsistent key-naming convention — noted for a future pass).
- **New this pass:** CHAOS-28's `/api/ca/status` boolean field `"usable"` shares its bare adjective with
  the pre-existing, unrelated MCP tool-registry `disposition` value `"usable"`
  (`internal/mcp/registry/record.go`). Different JSON namespaces (`ca.usable` vs. MCP tool
  `disposition`), different screens, no on-screen adjacency — fits `PRODUCT-TERMINOLOGY.md`'s existing
  tolerance for screen-scoped generic-word reuse (the same bar applied to "Policy" and "Telemetry"
  previously). Not escalated.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 08-07 — no findings were resolved or added this pass, so the plan carries forward as-is.

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

Terminology is **not** fully consistent. This pass re-confirmed, via a cited-line diff against every one
of nineteen previously-open findings across an unusually large 80-commit window, that all nineteen are
unchanged — including T-39, the finding most exposed to further compounding, whose largest adjacent change
this window (the PR-12 distribution/rollout transaction stream) was grepped directly and confirmed to
carry zero "qualification" vocabulary at all. No new findings were identified despite auditing nine
distinct new features/fixes in detail (MCP PR-12, the qualification-PKI guard, CHAOS-49, CHAOS-27,
CHAOS-28, syslog panic-loss, `/readyz` posture hardening, the install-script passphrase fix, and the new
config-snapshot-rejection diagnostic) — each named its concept once and, in several cases, went out of its
way to cross-reference sibling concepts in its own comments or GUI tooltip, the same discipline this
program has praised before. No cosmetic or preference-driven renames were proposed.
