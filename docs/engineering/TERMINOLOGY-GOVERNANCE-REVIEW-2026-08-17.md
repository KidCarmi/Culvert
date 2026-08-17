# Culvert Language & Terminology Governance Review — 2026-08-17

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited the tree at `b697cf3`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-07.md` (baseline `d2c5a51`). 80 commits / 122 files separate the
> two reviews, dominated by the PR-12 MCP CP/DP durable rollout transaction (`mcp_rollout*.go`,
> `mcp_distribution_startup*.go`, `internal/mcp/cpdp/apply/applier.go`), CHAOS-28 root-CA fail-closed
> usability (`internal/ca/validity.go`, `ca_health.go`, `ca_metrics.go`), CHAOS-27 alert-storm dedup
> bounding (`internal/alerts/store.go`), CHAOS-49 IdP-registry auth hardening, a `/readyz`
> information-disclosure reduction, and a new per-request log-timestamp memoization (`store_logclock.go`).
> Method: (1) diffed the actual cited lines/identifiers (not just file touches) for every one of the
> nineteen carried-over open findings — T-9, T-11, T-12, T-13 residual, T-16, T-17, T-18, T-21, T-25
> residual, T-29 through T-34, T-36, T-37, T-38, T-39 — against every file each depends on; (2) checked
> `internal/mcpacceptance/pki.go` (new, commit `71e2631`, "reject stale qualification PKI before
> acceptance") explicitly against T-39's four already-tracked senses of "qualification," since a fifth
> independent stream reusing the word would have been a material escalation; (3) audited the CHAOS-28
> CA-usability surface end-to-end (`/api/ca/status`, `/healthz`, `/readyz`, GUI) for internal consistency
> beyond the `Ready()`/`Usable()` split CLAUDE.md already documents as deliberate; (4) re-verified T-40's
> `idp_unreachable` → `identity_backend_unreachable` migration holds under a full repo grep; (5) checked the
> new CHAOS-27 dedup-bounding vocabulary and `store_logclock.go` for collisions with pre-existing terms.
> **No code changes this pass** — see Stop-Condition Assessment.

---

## Executive Summary

**All nineteen carried-over findings re-verified at the cited-line level; all nineteen are unchanged.**
Sixteen had zero activity in any dependent file across the 80-commit window. T-29 and T-38 each had a
same-file touch (`config.go`/`main.go` for T-29; `static/index.html` for T-38) that, read line-by-line, is
unrelated code (CDR-fingerprint validation and `initMCPDistribution` wiring; CA-panel banners and
syslog-panic wording, respectively) — the cited identifiers themselves are byte-identical. T-39's core
files (`mcp_policy.go`, `internal/mcp/adminapi/health.go`, `mcp_inventory.go`, `config.go`'s
`QualificationPolicyFile` line) were also untouched.

**No fifth "qualification" stream landed.** The one new file that warranted a direct check —
`internal/mcpacceptance/pki.go` (commit `71e2631`) — reuses "qualification" for PKI material belonging to
the *same* QUAL-2/3 bootstrap/acceptance environment T-39 already tracks as concept B, not an independent
fifth concept. It deepens T-39's existing compounding rather than adding a new stream, so T-39's
priority/urgency is carried forward unchanged from 08-07 (Medium-High) rather than escalated further.

**Zero new findings.** This window's dominant new features — the PR-12 durable rollout transaction, the
CHAOS-28 CA-usability surface, CHAOS-27's alert-dedup bounding, and the new log-timestamp memoization — were
each audited end-to-end and found internally consistent: same predicate names across `/api/ca/status`,
`/healthz`, `/readyz`, and the GUI for the CA work; the dedup-bounding additions are a same-word,
same-concept extension of the pre-existing `dedupTTL`/`dedupMap` mechanism; `store_logclock.go`'s "clock"
usage doesn't collide with the unrelated `catalogClockSkew` constant (a tolerance duration, not a caching
mechanism). T-40's rename (`idp_unreachable` → `identity_backend_unreachable`, fixed 08-07) holds under a
fresh full-repo grep — the only surviving reference is the `legacyEventNames` migration-map entry itself.

**Terminology Health Score: 8.4 / 10** (unchanged from 08-07 — no regressions across an 80-commit window,
but also no forward progress: the nineteen-item backlog held steady rather than shrinking, and T-38/T-39
remain the two highest-priority open items).

---

## Wave 1 — Carried-over findings re-confirmed unchanged

`git diff d2c5a51..b697cf3` (80 commits, 122 files) was checked against every file each of the nineteen open
findings depends on; findings whose files *were* touched had the actual cited lines/identifiers diffed, not
just the file.

| Finding | Files it depends on | Touched this window? | Collision status |
|---|---|---|---|
| T-9 | export/import + parity-test surface (`exportedAt`) | No | Unchanged |
| T-11 | `policy.go`'s default-action vocabulary, `ui_policy.go` core | No | Unchanged |
| T-12 | Maintenance-Agent `/v1/upgrades/*` wire routes | No | Unchanged |
| T-13 residual | README/enterprise-doc "TLS Inspection" vs. in-app "SSL" | No | Unchanged |
| T-16 | ADR numbering (0008–0011) | No | Unchanged |
| T-17 | `decryption_redact_hosts` / `/api/decryption/redaction` | No (new `decryption_observability.go::caUnusableOutcome` is an unrelated ADR-0011 outcome-projection helper) | Unchanged |
| T-18 | `internal/sealbox.Seal`/`Open` call sites | No | Unchanged |
| T-21 | `cluster_convergence.go`, `configversion.go`'s rollback `cp_version` surface | No | Unchanged |
| T-25 residual | `support_recipients.go` / `support_tac_trust.go` | No | Unchanged |
| T-29 | YAML `rate_limit` (`config.go`/`main.go`) vs. `rate_limit_rpm` (API/wire/metric) | `config.go` (+10), `main.go` touched | Touch is CDR-fingerprint hex validation + `initMCPDistribution` wiring; zero `rate_limit`-adjacent lines — unchanged |
| T-30 | YAML `max_conns_per_ip`/wire `MaxConnsPerIP` vs. `conn_limit_max_per_ip` | No | Unchanged |
| T-31 | `culvert_clamav_blocked_total` vs. `culvert_clam_scan_errors_total` | No (`metrics.go` not in this window's diff) | Unchanged |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` overloads "snapshot" | No | Unchanged |
| T-33 | MCP `PolicyAction`/`PolicyReason` mixing three vocabularies (`internal/mcp/runtime/policy.go`, `events.go`, `observe.go`) | No — `internal/mcp/runtime/` has an empty diffstat this window | Unchanged (root `events.go`, which *was* touched, is the unrelated SSE/`/metrics` shim) |
| T-34 | SaaS feed status field-name split (`saas_feed_download.go`, `ui_policy.go`) | No | Unchanged |
| T-36 | `config.rollback` audit token vs. freeform config-version-history action string | No | Unchanged |
| T-37 | "Manual feed sync" naming split across blocklist/SaaS/threat feeds | No | Unchanged |
| T-38 | `ui_mcp.go`, `internal/mcp/adminapi/health.go`, `mcp_inventory.go`, `static/index.html` (`drifted_tools`/`review_required_tools`) | `static/index.html` (+55) touched; other three untouched (0 lines) | Touch is CA-panel banners (CHAOS-28) and syslog-panic wording; zero new `drifted`/`review_required` hits — unchanged |
| T-39 | `internal/mcp/rollout` (Production Qualification), QUAL-2/3/4 config/docs | Core files untouched; adjacent `internal/mcpacceptance/pki.go` (new) reuses the word | Deepens existing concept-B (QUAL-2/3) footprint — not a new independent stream, see Wave 2 |

**Zero findings regressed.** Sixteen of nineteen had no dependent-file activity at all. T-29 and T-38 had
incidental same-file touches, verified unrelated line-by-line.

## Wave 2 — New territory audited this pass (80 commits since `d2c5a51`)

**`internal/mcpacceptance/pki.go` (commit `71e2631`) does not introduce a fifth sense of
"qualification."** Its error strings ("qualification server certificate," "qualification client
certificate expired") name TLS material belonging to `Fixture`'s pre-existing "ephemeral, harness-owned
qualification environment" (concept B, the QUAL-2/3 bootstrap fleet) — new surface area within an existing
concept, not a new independent PR stream reusing the bare word unprompted. This was the one change in the
window most likely to compound T-39 further and it was checked explicitly; the verdict is that it deepens
the already-tracked compounding rather than adding a fifth stream, so T-39's priority stays Medium-High
(unchanged from 08-07) rather than escalating again.

**CHAOS-28 root-CA fail-closed usability (`ca_health.go`, `ca_metrics.go`, `internal/ca/validity.go`,
`healthcheck.go`, `ui_security.go::apiCAStatus`, `static/index.html`): clean end-to-end.** `/api/ca/status`
(`ready`/`usable`/`unusableReason`/`rotationPersistDegraded`/`rotationPersistError`/`inspectBlocked`), the
GUI (`ca.ready`, `ca.usable`, `ca.unusableReason`, `ca.rotationPersistDegraded`), `/healthz`'s
`ssl_inspection` enum (`ready`/`load_failed`/`unavailable`/`expired`), and `/readyz`'s new
`appendCAReadinessCheck` all key off the same `certMgr.Usable()`/`certMgr.Ready()` predicates CLAUDE.md
documents as a deliberate, non-foldable distinction. No inconsistency beyond that documented split.

**CHAOS-27 alert-storm dedup bounding (`internal/alerts/store.go` +296): additive, same-word-same-concept.**
Extends the pre-existing `dedupTTL`/`dedupMap`/`dedupSuppressed` mechanism with a cap (`maxDedupEntries`),
an eviction counter (`dedupEvicted`/`DedupEvictionsTotal()`), and pruning
(`dedupPruneEvery`/`dedupPruneMinInterval`) — no collision with the unrelated, unambiguous "dedup" usages
elsewhere (`support_tac_trust.go`, `internal/blocklist/delta.go`, `internal/mcp/limits/events.go`).

**`store_logclock.go`'s new `logClockStamp`/`logEntryTimeLayout` memoization: no collision, on a corrected
full-tree accounting.** *Correction: an earlier draft of this section understated the "clock" compounds in
the tree to a single example — a fuller grep surfaces `catalogClockSkew` (`release_catalog_freshness.go`),
`caClockSkewTolerance` (`internal/ca/validity.go`, new this window), `capClockSkew`/`ClockSkew`
(`internal/mcp/limits/auth.go`), and the DI clock-seam pattern `schedClock`/`realSchedClock`
(`saas_feed_scheduler.go`) / `mcpTelemetryClock` (`mcp_telemetry.go`).* On inspection these split into two
pre-existing, internally consistent, non-colliding idioms — permitted-clock-skew tolerance constants
(`catalogClockSkew`/`caClockSkewTolerance`/`capClockSkew`, all naming the identical generic concept across
three unrelated subsystems) and injectable time-source seams for testability
(`schedClock`/`mcpTelemetryClock`, the standard Go DI pattern) — neither of which shares any surface,
meaning, or reader with `logClockStamp`'s per-request timestamp-render memoization. None of these
identifiers reach an API field, GUI label, config key, or audit/metric name, so there is no admin/support-
facing collision; still worth naming precisely rather than asserting exhaustiveness from a narrow grep, per
review feedback on this report.

**T-40 re-verified live under a fresh full-repo grep — correction to scope this precisely.** No production
code path fires, checks, or exposes `idp_unreachable` as a live event value: the wire alert-event string,
its `HasSubscriber` gate, and every webhook `Events` entry (via `legacyEventNames`, `internal/alerts/store.go:227`)
are `identity_backend_unreachable`. The string `idp_unreachable` does still appear — correctly — as
explanatory text in three places: `internal/alerts/store.go:29`'s catalog comment (documenting why the name
was deliberately avoided), CLAUDE.md:174's CHAOS-47 section (same explanation), and several dated
`docs/security-reviews/`/`docs/engineering/` files predating or documenting the 08-07 rename itself. None of
these are live values a webhook or client would match against; the earlier "sole surviving reference"
phrasing overstated this and is corrected here.

**CHAOS-49 (`auth_oidc_flow.go`, `auth_ldap.go`, `auth_oidc.go`) and the `/readyz` info-disclosure
reduction:** both confirmed clean — CHAOS-49 reuses the `identity_backend`/`culvert_auth_backend_*`
vocabulary exactly as CLAUDE.md describes with no stray terms, and the `/readyz` redaction work introduces
no new field/label names that diverge from `/healthz`'s existing vocabulary.

---

## Findings

No findings this pass. Every priority area in the 80-commit window was checked and found either internally
consistent, an extension of pre-existing correctly-scoped vocabulary, or reuse of an already-tolerated
generic term under `docs/design/PRODUCT-TERMINOLOGY.md`'s screen-scoped precedent. No cosmetic or
preference-driven renames are proposed.

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
| T-38 | `drifted_tools` vs. `review_required_tools` — same count, same API response, two names | Open since 08-06. Unchanged; dual-emit remains the recommended fix. |
| T-39 | "Qualification" names four unrelated concepts in the same config/admin namespace | Open since 08-06, compounded 08-07. Unchanged this pass — new PKI surface deepens concept B, no fifth stream. |

## Soft findings — no action recommended

Carried over unchanged from prior passes: "Bootstrap" covering two unrelated features (no on-screen
collision); the `CULVERT_PROXY_SEED_REF` "seed" vocabulary (internally consistent); the `culvert_decrypt_*`
metric prefix vs. the fully-spelled `decryption`/`decryption-profile` namespace (documented deliberate
abbreviation); the CDR `cb`-prefix wire-key convention vs. `internal/upstream.Status`'s breaker-field naming
(same concept, inconsistent convention — still not queued, still not a live regression).

---

## Recommended Refactoring Plan (priority order)

Unchanged from the 08-07 report — no new evidence changed any priority or migration-risk assessment this
pass. See `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-07.md`'s table for the full ordered plan (T-39 and T-38
remain the top two items; both still require either a product-naming decision or an additive dual-emit
rather than a same-day mechanical rename).

---

## Stop-Condition Assessment

Terminology is **not** fully consistent — nineteen findings remain open, unchanged from 08-07. However,
this pass found **zero new drift** across an 80-commit, 122-file window, including a targeted check of the
one change (`internal/mcpacceptance/pki.go`) most likely to compound the program's highest-priority open
item (T-39) into a fifth independent stream — it did not. No finding met this program's "same-day fixable"
bar (brand new this window, zero deployed dependency, no test/doc dependency on the literal being changed),
so, consistent with the program's established practice of only mechanically renaming under that bar, **no
code changes are made this pass.** This report is filed to keep the audit trail current and to record that
the backlog held steady with zero regressions; no cosmetic or preference-driven renames were proposed.
