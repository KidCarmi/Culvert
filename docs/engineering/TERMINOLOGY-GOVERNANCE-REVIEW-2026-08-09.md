# Culvert Language & Terminology Governance Review — 2026-08-09

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited the tree at `1c24311c`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-07.md` (baseline `d2c5a51`). 25 commits separate the two
> reviews, dominated by CHAOS-27 alert-storm dedup bounding (`internal/alerts/store.go`), two CHAOS-47
> LDAP/OIDC auth-backend-health hardening fixes (an answered backend must clear its cooldown; an
> attacker-provokable LDAP bind must not gate every user), a `StripHostPort` allocation-free refactor
> (`internal/hostutil`), the QUAL-6.1 MCP Observe acceptance-harness "authoritative controls" addition
> (`internal/mcpacceptance`), a CodeQL init-pin realignment, and a `docker-compose` CA-passphrase forwarding
> fix for the `cli` service. Method: (1) diffed the actual cited lines/identifiers (not just file touches)
> for every one of the nineteen carried-over open findings — T-9, T-11, T-12, T-13 residual, T-16, T-17,
> T-18, T-21, T-25 residual, T-29 through T-34, T-36, T-37, T-38, T-39 — against every file each depends on;
> (2) verified T-40's fix (`idp_unreachable` → `identity_backend_unreachable`) and its same-day review
> addendum (the `legacyEventNames` webhook migration map) both landed intact and are exercised by this
> window's own new dedup-metrics code, which correctly reuses `identity_backend_unreachable` rather than
> reintroducing the retired name; (3) read the QUAL-6.1 acceptance-harness diff in full, since it consumes
> `environment.qualification_policy_file` verbatim and lands directly in T-39's territory, to confirm it is
> reusing the existing QUAL-4 sense rather than introducing a fifth independent one; (4) audited the new
> CHAOS-27 dedup vocabulary (`dedup_tracked`, `dedup_evictions_total`, `culvert_alert_dedup_*` metrics, the
> GUI's "dedup window saturated" copy) end-to-end for internal consistency; (5) spot-checked the two
> CHAOS-47 auth-hardening commits' new comments for any drift in the established "gate"/"cooldown"/"identity
> backend" vocabulary.

---

## Executive Summary

**All nineteen carried-over findings re-verified at the cited-line level; all nineteen are unchanged.**
None of this window's 25 commits touch any file a carried-over finding depends on in a way that changes the
collision itself. Three findings had a dependent file touched, and in every case the touch was unrelated
code in the same file: T-33 (`events.go`, root) gained only the new CHAOS-27 Prometheus export lines, zero
`PolicyAction`/`PolicyReason` code; T-37 (`ui_security.go`, `internal/threatfeed/threatfeed_bench_test.go`)
gained only the new dedup-health JSON fields and a set of read-only lookup benchmarks, zero
`feeds_sync`/`blocklist.feed.sync`/`saasfeed.refresh` code; T-39 (`docs/operator/mcp-observe-acceptance-*`,
`internal/mcpacceptance`) gained substantial new QUAL-6.1 "authoritative controls" content, but every new
reference to "qualification" resolves to the existing QUAL-4 `environment.qualification_policy_file` /
`mcp.gateway.qualification_policy_file` sense (passed through verbatim into the harness), not a new fifth
sense — consistent with QUAL-6's already-verified pattern of careful reuse rather than reinvention.

**No new findings this pass.** This is the first window since 2026-08-04 to close with a fully clean
Wave 2 sweep: zero new terminology collisions were introduced by 25 commits that included a security-
sensitive rewrite of the CHAOS-47 auth-backend gate (LDAP bind + OIDC introspection cooldown handling) and a
brand-new observability surface (CHAOS-27's alert-dedup metrics). The new dedup vocabulary is a positive
example of the discipline this program has been asking for: `dedupEvicted` (Go variable) →
`dedup_evictions_total` (JSON field) → `culvert_alert_dedup_evictions_total` (Prometheus metric) → "dedup
window saturated" (GUI copy) name the identical concept with the same word at every layer, differing only by
the naming *convention* each surface requires (camelCase / snake_case / metric-prefixed / prose) — exactly
the distinction this program's brief treats as non-drift.

**T-40's fix continues to hold under new load.** This window's CHAOS-27 work is the first new alert-plane
feature to ship since the `idp_unreachable` → `identity_backend_unreachable` rename, and it correctly
references only the new name (`static/index.html:17624`'s webhook checkbox retains `value="identity_backend
_unreachable"`, confirmed unchanged this window); no new code anywhere in the diff reintroduces the retired
string.

**Terminology Health Score: 8.5 / 10** (up from 8.4 — a full clean window with zero new drift, including
across a meaningfully-sized security hardening change and a new observability feature that got its own
cross-surface naming right on the first attempt; the carried-over backlog is unchanged in both count and
severity, so the score improves on discipline signal rather than backlog progress).

---

## Wave 1 — Carried-over findings re-confirmed unchanged

`git diff d2c5a51..1c24311c` (25 commits) was checked against every file each of the nineteen open findings
depends on; every finding whose files *were* touched had the actual cited lines/identifiers diffed, not
just the file.

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
| T-29 | YAML `rate_limit` (`config.go`/`main.go`) vs. `rate_limit_rpm` (API/wire/metric) | No | Unchanged |
| T-30 | YAML `max_conns_per_ip`/wire `MaxConnsPerIP` vs. `conn_limit_max_per_ip` | No | Unchanged |
| T-31 | `culvert_clamav_blocked_total` vs. `culvert_clam_scan_errors_total` | No | Unchanged |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` overloads "snapshot" | No | Unchanged |
| T-33 | MCP `PolicyAction`/`PolicyReason` mixing three vocabularies (`internal/mcp/runtime/policy.go`, `events.go`, `observe.go`) | Root `events.go` touched (+5 lines) | Touch is the new CHAOS-27 `culvert_alert_dedup_*` Prometheus export block only; zero `PolicyAction`/`PolicyReason` lines — unchanged |
| T-34 | SaaS feed status field-name split (`saas_feed_download.go`, `ui_policy.go`) | No | Unchanged |
| T-36 | `config.rollback` audit token vs. freeform config-version-history action string | No | Unchanged |
| T-37 | "Manual feed sync" naming split across blocklist/SaaS/threat feeds | `ui_security.go` touched (+6 lines); new `internal/threatfeed/threatfeed_bench_test.go` | `ui_security.go`'s only change is the new CHAOS-27 `dedup_tracked`/`dedup_evictions_total` JSON fields on `apiAlertsDeliveryHist`; the bench file adds only read-only `CheckDomain`/`CheckURL` benchmarks. Zero `feeds_sync`/`blocklist.feed.sync`/`saasfeed.refresh` lines touched — unchanged |
| T-38 | `ui_mcp.go`, `internal/mcp/adminapi/health.go`, `mcp_inventory.go`, `static/index.html` (`drifted_tools`/`review_required_tools`) | `static/index.html` touched (+4/−0 net) | The touched lines are the CHAOS-27 delivery-history health copy and the T-40 webhook checkbox value (already migrated); zero new hits for `drifted_tools`/`review_required_tools` — unchanged |
| T-39 | `internal/mcp/rollout` (Production Qualification), QUAL-2/3/4 config/docs | `docs/operator/mcp-observe-acceptance-runbook.md` (+301/−?), `docs/operator/mcp-observe-acceptance-decisions.md` (+65), `internal/mcpacceptance/*` (new/expanded, QUAL-6.1) | See Wave 2 — substantial new content, but every occurrence resolves to the pre-existing QUAL-4 `qualification_policy_file` sense passed through verbatim; no fifth sense introduced — unchanged in substance |

## Wave 2 — New territory audited this pass (25 commits since `d2c5a51`)

**QUAL-6.1's "authoritative controls" addition to the MCP Observe acceptance harness
(`internal/mcpacceptance/spec.go`, `authoritative.go`, `fixture.go`, and companions) holds discipline on the
T-39 boundary.** The new `spec.go` documents its `QualificationPolicyFile` field as "the operator-owned
Culvert qualification policy file (`mcp.gateway.qualification_policy_file`)... [the harness] passes THIS
file into the spawned [primary] verbatim" — i.e. it is a pass-through consumer of the existing QUAL-4
config key, not a new naming decision. The expanded runbook and decisions doc repeatedly write
"OPERATOR-selected qualification policy" and "OPERATOR-selected qualification environment," language that,
read together with QUAL-6's pre-existing "Production remains qualification-locked throughout" disclaimer
(unchanged this window, still in the same runbook), continues the pattern of QUAL-6 explicitly scoping
itself against the Production Qualification receipt gate rather than colliding with it. T-39 remains open
and unchanged in substance — this window neither worsens nor improves the underlying four-concept overload,
it simply adds a fifth *consumer* of the existing third sense (QUAL-4) without adding a new sense.

**CHAOS-27's alert-dedup bounding (`internal/alerts/store.go`, `events.go`, `ui_security.go`,
`static/index.html`) is internally consistent end-to-end and correctly reuses the T-40 rename.** The
concept — dedup keys evicted from the bounded suppression window under an alert flood — is named
identically in word choice at every layer it appears: the Go accumulator/accessor (`dedupEvicted`,
`DedupEvictionsTotal()`, `DedupTracked()`), the JSON field names on `GET /api/alerts/delivery-history`
(`dedup_evictions_total`, `dedup_tracked`), the Prometheus metrics (`culvert_alert_dedup_evictions_total`,
`culvert_alert_dedup_tracked`), and the GUI's health-line copy ("dedup window saturated ... duplicate
suppression degraded"). The store's new `legacyEventNames` migration map (T-40's review addendum) is
exercised correctly — `internal/alerts/store_persist_test.go`'s `TestStore_Init_MigratesLegacyEventNames`
remains the pinning test, unchanged this window, and no new code path reintroduces `idp_unreachable`.

**The two CHAOS-47 auth-hardening commits (`auth_ldap.go`, `auth_oidc.go`, `auth_backend_health.go`) extend
the existing "gate"/"cooldown"/"identity backend" vocabulary without inventing a parallel one.** Both
"an answered backend must clear the cooldown, not just avoid arming it" and "an attacker-provokable LDAP
bind must not gate every user" add substantial new comments and logic (`a.gate.recordReachable()`,
`a.gate.recordUnavailable()`, "provider-wide cooldown") that consistently reuse the CHAOS-47 nouns CLAUDE.md
already documents (`authProbeGate`, "cooldown," "identity backend") rather than introducing new near-synonym
terms for the same mechanism — no collision.

**The `internal/hostutil` `StripHostPort` allocation-free refactor and the CodeQL/docker-compose fixes
carry no admin- or API-facing vocabulary** (pure internal Go performance/CI/ops work) — out of scope for
this review by the program's own "reviewed from the perspective of an admin/security engineer/support
engineer" framing, and confirmed to introduce no new exported names, config keys, or GUI/API strings.

---

## Findings

No new findings this pass — see Wave 2 above for what was checked and cleared.

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
| T-39 | "Qualification" names four unrelated concepts in the same config/admin namespace | Open since 08-06, compounded 08-07. Unchanged this pass — QUAL-6.1 is a new *consumer* of the existing QUAL-4 sense, not a fifth sense. |

*T-40 is not listed here — fixed 08-07, re-verified holding under new load this pass (see Executive Summary).*

## Soft findings — no action recommended

All soft findings carried over unchanged from prior reviews (07-24 "Bootstrap"/`CULVERT_PROXY_SEED_REF`;
08-03 `culvert_decrypt_*` metric-prefix abbreviation; 08-04 the speculative `culvert_connlimit_rejections_
total` roadmap citation; 08-06 `drifted_tools`'s absence from the OpenAPI spec, the "Telemetry (opt-in)"
support-panel vs. MCP Qualification Telemetry screen-scoped reuse, and the CDR `cb`-prefix wire-key
convention vs. `internal/upstream.Status`'s convention). No new soft findings this pass — the CHAOS-27 dedup
vocabulary and the CHAOS-47 gate/cooldown extensions were both checked in detail (see Wave 2) and found
fully consistent, not merely soft-acceptable.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 2026-08-07 — no new findings this pass to add, no carried-over finding's risk/size estimate
changed. Reproduced here for continuity; see the 08-07 review for the full per-row rationale.

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

Terminology is **not** fully consistent — nineteen findings remain open. This pass re-confirmed, via a
cited-line diff against every one of them, that all nineteen are unchanged across a 25-commit window,
including a security-sensitive CHAOS-47 auth-hardening change and the QUAL-6.1 acceptance-harness expansion
that lands directly in T-39's namespace. It found **zero new drift** — the first fully clean window since
2026-08-04 — with the window's two most terminology-relevant additions (CHAOS-27's alert-dedup vocabulary
and the QUAL-6.1 harness's `qualification_policy_file` reuse) both independently verified to extend existing
naming correctly rather than introduce new collisions. T-40's rename was verified to be holding under new
load with no regression. No cosmetic or preference-driven renames were proposed, and no code changes were
made this pass, consistent with this program's standing practice of only same-day-fixing brand-new,
zero-migration-cost findings rather than folding the dedicated-follow-up backlog into a routine review.
