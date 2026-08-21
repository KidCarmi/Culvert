# Culvert Language & Terminology Governance Review — 2026-08-10

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited the tree at `bc67b7b`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-07.md` (baseline `5982f44`). 58 commits (92 files,
> +9440/-351) separate the two reviews, dominated by CHAOS-28 (Root-CA usability fail-closed —
> two brand-new files, `ca_health.go`/`ca_metrics.go`, plus a rotation-persistence gating fix),
> CHAOS-27 (alert-plane storm bounding — dedup-eviction counters), a hardening follow-up to the
> 08-07 T-40 fix (webhook event-name migration extended from load-time-only to every store
> ingress), syslog panic-loss surfacing, release-binary runtime-version-identity enforcement (a
> new `version` field on the admin `/healthz`), and the QUAL-6.1 MCP Observe acceptance-test
> harness (`internal/mcpacceptance`) reaching "authoritative" mode. Method: (1) diffed the actual
> cited lines/identifiers (not file touches) for every one of the nineteen carried-over open
> findings — T-9 through T-39 — against every file each depends on; (2) characterized every new
> admin-facing identifier/label/event/metric/config-key introduced in the window and checked each
> against the words this program already tracks as overloaded (qualification, IdP, policy,
> snapshot, seal, rate_limit, sync, backpressure, circuit breaker); (3) spot-verified the two
> highest-signal new surfaces (CHAOS-28's health-plane vocabulary, and the `92c3352` webhook
> event-name migration's relationship to the just-shipped T-40 fix) by reading the actual code and
> full commit diffs, not just commit subjects.
> **Companion change:** T-41 (new — CHAOS-28's brand-new health-plane comments, CLAUDE.md, and the
> live root-CA-expiry operator runbook all wrote the admin-only `/healthz` path when they meant the
> proxy's `/health`) fixed same-day in its most consequential instances: the authoritative
> `CLAUDE.md`, the incident-response runbook `docs/operator/root-ca-expiry.md`, the CHAOS-28 design
> doc written the same day, and the two brand-new source files that introduced the wording
> (`ca_health.go`, `ca_metrics.go`). A much larger, pre-existing instance of the same habit
> (dozens of older Go comments, test-file prose, and a handful of older docs, none of it new this
> window) is queued rather than swept in this pass — see Findings and the Refactoring Plan.

---

## Executive Summary

**All nineteen carried-over findings re-verified at the cited-line level; eighteen are
byte-identical.** T-9, T-11, T-12, T-13 residual, T-16, T-17, T-18, T-21, T-25 residual, T-30,
T-31, T-32, T-33, T-34, T-36, T-37, and T-38 had zero touches to their dependent files this
window. T-29 and T-38 each had an *unrelated* touch to a dependent file (a new CDR-fingerprint
validation branch in `config.go`; CA-panel/syslog/alert-dedup GUI additions in `static/index.html`)
— read in full, neither touched the cited vocabulary. T-39 is unchanged in **business-concept
terms** (still exactly A/B/C from 08-07, no fifth sense), but this window's QUAL-6.1 acceptance
harness became a much heavier *consumer* of two of those senses at once inside one operator
document pair without cross-referencing them — more evidence of the same underlying ambiguity,
not a new independent collision. Priority is left unchanged (Medium-High, per 08-07) pending the
design decision that finding has needed since 08-06.

**One new finding, fixed same-day in its highest-stakes instances (T-41): CHAOS-28's new
health-plane code, CLAUDE.md, and the CA-expiry operator runbook all wrote the wrong endpoint
name.** Culvert genuinely has two different, unrelated endpoints that differ only by a trailing
"z": the proxy port's `/health` (rich liveness/posture report — `ssl_inspection`, `ca_expires_days`,
`clamav`, `threat_feed_entries`) and the admin/UI port's `/healthz` (an unauthenticated,
HA-only leader-election probe with no CA/SSL-inspection field at all). This window's CHAOS-28 work
— the mechanism that makes an expired Root CA visible and fail-closed instead of a silent,
fleet-wide outage — landed its own explanation of that exact failure using the *wrong* endpoint
name throughout: two brand-new source files (`ca_health.go`, `ca_metrics.go`), a same-day design
doc (`docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-09.md`), and — most consequentially — the
step-by-step incident-response runbook an operator is told to follow during exactly this outage
(`docs/operator/root-ca-expiry.md`) all instructed `GET /healthz` to see `ssl_inspection`, a field
that endpoint does not have. `CLAUDE.md`'s own file-list entry for `healthcheck.go` and its CHAOS-28
paragraph carried the same error. This is not a hypothetical mixup: two *other*, older engineering
docs (`docs/engineering/PRODUCTION-FAILURE-MODE-AUDIT.md`, `docs/engineering/DAY2-OPERATIONS-READINESS.md`)
already worked out and carefully documented the correct `/health` vs `/healthz` distinction — this
window's CHAOS-28 work simply didn't reuse it, showing the collision is a documentation-consistency
gap, not a genuine ambiguity nobody has resolved. Fixed same-day in the newest, most consequential
locations (all landed or touched this exact window, none previously depended upon in the field).
The larger, pre-existing footprint of the same habit — reaching back to at least
`CHAOS-ENGINEERING-REVIEW-2026-07-09.md` and spread across dozens of Go test-file comments,
`ha.go`/`ha_lease.go`/`rootca_startup.go` doc comments, and `docs/support/HEALTH-AND-EVENT-MODEL.md`
— is queued as a Medium-priority follow-up rather than sHwept in this pass; see Findings.

**Terminology Health Score: 8.4 / 10** (unchanged from 08-07 — a real, previously-uncaught
operator-runbook accuracy defect was found and fixed in its most dangerous instances before this
window's own new code could entrench it further, which is a genuine catch; offset by the fact that
the same habit already has a large pre-existing footprint this program had not previously surfaced,
and T-39 still awaits the design decision it has needed for three prior passes).

---

## Wave 1 — Carried-over findings re-confirmed unchanged

`git diff 5982f44..HEAD` (58 commits, 92 files, +9440/-351) was checked against every file each of
the nineteen open findings depends on; every finding whose files *were* touched had the actual
cited lines/identifiers diffed, not just the file.

| Finding | Files it depends on | Touched this window? | Collision status |
|---|---|---|---|
| T-9 | export/import + parity-test surface (`exportedAt`) | New *consumer* only (`alerts_event_rename_import_test.go`, from the T-41-adjacent `bea241e`) | Field name unchanged; new test fixture uses the literal `exportedAt` key as-is — unchanged |
| T-11 | `policy.go` default-action vocabulary, `ui_policy.go` core | No | Unchanged |
| T-12 | Maintenance-Agent `/v1/upgrades/*` wire routes | No | Unchanged |
| T-13 residual | README/enterprise-doc "TLS Inspection" vs. in-app "SSL" | No | Unchanged |
| T-16 | ADR numbering (0008–0011) | No | Unchanged |
| T-17 | `decryption_redact_hosts` / `/api/decryption/redaction` | No | Unchanged |
| T-18 | `internal/sealbox.Seal`/`Open` call sites | No | Unchanged |
| T-21 | `cluster_convergence.go`, `configversion.go`'s rollback `cp_version` surface | No | Unchanged |
| T-25 residual | `support_recipients.go` / `support_tac_trust.go` | No | Unchanged |
| T-29 | YAML `rate_limit` (`config.go`/`main.go`) vs. `rate_limit_rpm` (API/wire/metric) | `config.go` touched (+10, `cdr.server_fingerprint` hex validation) | Zero `rate_limit` lines touched — unchanged |
| T-30 | YAML `max_conns_per_ip`/wire `MaxConnsPerIP` vs. `conn_limit_max_per_ip` | No | Unchanged |
| T-31 | `culvert_clamav_blocked_total` vs. `culvert_clam_scan_errors_total` | No (one incidental doc-only hit, a compose `depends_on: clamav` note — not the metric surface) | Unchanged |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` overloads "snapshot" | No | Unchanged |
| T-33 | MCP `PolicyAction`/`PolicyReason` (`internal/mcp/runtime/policy.go`, `events.go`, `observe.go`) | No | Unchanged; zero production consumers |
| T-34 | SaaS feed status field-name split | No | Unchanged |
| T-36 | `config.rollback` audit token vs. freeform config-version-history action string | No (one incidental doc-prose hit, not the identifier) | Unchanged |
| T-37 | "Manual feed sync" naming split across blocklist/SaaS/threat feeds | No | Unchanged |
| T-38 | `ui_mcp.go`, `internal/mcp/adminapi/health.go`, `mcp_inventory.go`, `static/index.html` (`drifted_tools`/`review_required_tools`) | `static/index.html` touched (+47/-6, unrelated CA-panel/syslog/alert-dedup GUI) | Zero `drifted_tools`/`review_required_tools` hits anywhere in the diff — unchanged |
| T-39 | `internal/mcp/rollout` (Production Qualification), QUAL-2/3/4 config/docs | `internal/mcpacceptance` (QUAL-6.1 authoritative-mode rewrite) heavily consumes concepts A + C | Business concepts unchanged; new *volume* of consumption — see Wave 2 |

## Wave 2 — New territory audited this pass (58 commits since `5982f44`)

**CHAOS-28 Root-CA usability (`c40925d`, `fb71c0c`) is the largest new surface and holds discipline
everywhere except the endpoint-name error fixed as T-41.** The new metrics
(`culvert_ca_usable`, `culvert_ca_expires_in_seconds`, `culvert_ca_sign_refused_total`,
`culvert_ca_inspect_blocked_total`, `culvert_ca_rotation_persist_failures_total`), the new
`/api/ca/status` fields (`usable`, `unusableReason`, `inspectBlocked`, `signRefused`,
`rotationPersistFailures`, `rotationPersistDegraded`, `rotationPersistError`), and the new
`/healthz`/`/readyz`-adjacent operator-contract row all reuse the pre-existing `culvert_ca_*` /
`root_ca` vocabulary CLAUDE.md already documented for this feature — zero collision with
qualification/IdP/policy/snapshot/seal/rate_limit/sync/backpressure/circuit-breaker. The one defect
was literally which endpoint the comments and runbook named, corrected as T-41 below.

**CHAOS-27 alert-plane storm bounding (`53367bc`, `bf720e5`) is clean.** New `dedup_tracked` /
`dedup_evictions_total` fields on `GET /api/alerts/webhooks/history` and the matching OpenAPI
schema entries are a genuinely new admin-facing term ("dedup") but collide with nothing already
flagged; noted only as a term to watch if a future subsystem reaches for "dedup" for something
unrelated.

**The `92c3352`/`bea241e` pair is a same-window hardening of the 08-07 T-40 fix, not new drift.**
`92c3352` added an `Init`-time `legacyEventNames` migration map so a webhook already persisted
under the retired `idp_unreachable` string keeps firing after the rename — explicitly modeled on
this codebase's own `"threat_detected"` never-rename precedent, per the commit's own reasoning.
`bea241e` closed a gap a reviewer caught two days later (the migration ran only at `Init`, so a
config-import or admin edit could reintroduce the retired name) by extending it to every store
ingress (`Init`/`Add`/`Update`) via `normalizeEventNames` — now documented in CLAUDE.md's CHAOS-47
paragraph. No new wire string was introduced by either commit; `identity_backend_unreachable`
remains the only current name.

**Syslog panic-loss surfacing (`0660fa0`, `719658d`) and release runtime-version-identity
enforcement (`744ceba`, `9b3e9ea`) are clean, with one soft note each.** The new `panics` field on
`GET /api/syslog` (paired with the pre-existing `drops`) collides with nothing. The new `version`
field on the admin `/healthz` (`ha.go:1093,1108,1120`, backed by the linker-stamped `main.version`)
carries the identical value as the pre-existing `Version` field already served on the proxy's
`/health` (`healthcheck.go:17`) — same concept, correctly reused word, just two independently-coded
handlers on two differently-scoped ports now both carrying it; not a collision, but recorded below
as a soft finding alongside the `diagnostics.go` `dp_config_snapshot_apply` row (new this window,
correctly reuses the pre-existing CP→DP `ConfigSnapshot` sense, landing adjacent to but not
overlapping the open T-21/T-32 "snapshot" findings).

**QUAL-6.1 (`07322ca`, `86ec811`, `8562433`) is an operator-run acceptance CLI, not a shipped
admin surface, and introduces no new business concept** — see T-39 discussion above; it is a
heavier consumer of existing "qualification" senses A and C, in one document pair, without
cross-referencing them.

**Everything else in the window** (CodeQL init-pin realignment, LDAP-bind/OIDC cooldown-gating
fixes, `hostutil.StripHostPort` perf, install.sh `allow_peers` TOML-comment parsing fixes, the
`cdr.server_fingerprint` hex-validation branch, reqlog `LogEntry.Time` memoization, the
`CULVERT_CA_PASSPHRASE` compose-forwarding fix) **adds no new admin-facing vocabulary** — confirmed
by reading each full commit diff.

---

## Findings

### T-41 — CHAOS-28's new health-plane code, CLAUDE.md, and the CA-expiry runbook named the wrong endpoint (new — fixed same-day in its highest-stakes instances)

- **Business concept:** which HTTP endpoint reports the Root-CA/SSL-inspection health fields
  (`ssl_inspection`, `ca_expires_days`) an operator needs during a CA-expiry incident.
- **The actual routes (verified against `pac.go:124-139`, `diagnostics.go:1244-1249`,
  `ui_routes_meta.go:706`, `ha.go:1082-1120`):**
  - **`GET /health`** (proxy port, `handleHealth` in `healthcheck.go`) — the rich liveness/posture
    report: `status`, `uptime`, `version`, `clamav`, `ca_expires_days`, `ssl_inspection`,
    `threat_feed_entries`. This is the endpoint every CA-expiry symptom actually appears on.
  - **`GET /ready`** (proxy port, `handleReady`) — the load-shedding readiness gate, includes a
    `ca` check row.
  - **`GET /healthz`** (admin/UI port, `apiHealthz` in `ha.go`) — an unrelated, unauthenticated
    HA leader-election probe: `status`, `role`, `leader`, `write_authority`, `version`, `term`,
    `auto_failover`, plus fencing-lease fields. **No `ssl_inspection` or CA field of any kind.**
  - There is **no `/readyz` route at all** anywhere in the codebase (confirmed: zero matches for
    the literal string `"/readyz"` in any `mux.HandleFunc`/route table).
- **Why this is real drift, not cosmetic:** two *other* engineering documents already worked out
  and correctly recorded this exact distinction — `docs/engineering/PRODUCTION-FAILURE-MODE-AUDIT.md`
  ("Now visible: proxy `/health` `ssl_inspection` field + proxy `/ready` `ca` row + `ca_load_failed`
  alert … admin `/healthz` is HA-only, no `/readyz` route") and
  `docs/engineering/DAY2-OPERATIONS-READINESS.md` (an explicit comparison table: `/healthz` = "Admin/CP
  … HA leadership only"; `/health` = "Proxy (data) … reports `ca_expires_days`, `ssl_inspection`,
  `clamav` as info"). The enterprise-facing `docs/enterprise/OPERATIONS-RUNBOOK.md` and
  `ENTERPRISE-PREREQUISITES.md` also have it right (`:8080/health`, `:8080/ready`, `:9090/healthz`
  distinguished by port). This window's CHAOS-28 work — landing in the same repository, the same
  general subject area, written by the same program — simply didn't reuse the already-correct
  vocabulary, and instead wrote `/healthz`/`/readyz` throughout when it meant `/health`/`/ready`.
  That is a documentation-consistency failure, not an unresolved ambiguity.
- **Concrete operator harm:** `docs/operator/root-ca-expiry.md` is the step-by-step runbook Culvert
  tells an operator to follow *during* a live, fleet-wide inspected-HTTPS outage (CLAUDE.md's own
  CHAOS-28 paragraph names it as "Runbook:"). Before this fix, step 2 of "How to confirm it" read
  `GET /healthz` → `"ssl_inspection": "expired"` and step 5 ("Verify") read `/healthz` returns to
  `"ssl_inspection": "ready"`. An operator following that instruction during an actual incident
  would query the admin port's real `/healthz`, get a 200 with no `ssl_inspection` field at all, and
  have no way to tell from that response alone whether recovery succeeded — exactly the kind of
  silent-confusion failure mode CLAUDE.md's own CHAOS-28 section was written to eliminate.
- **Why same-day-fixable for the instances fixed:** `ca_health.go` and `ca_metrics.go` are
  brand-new files (`git log --diff-filter=A`: added whole in `c40925d`, this exact window) with no
  prior release depending on their comment text. `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-09.md`
  is a same-day design doc (committed `fb71c0c`, one day before this review). `CLAUDE.md` and
  `docs/operator/root-ca-expiry.md` are prose-only corrections to text that was already incorrect —
  fixing it carries no wire/API/test-compatibility cost (confirmed: `go build ./...`, `go vet
  ./...`, and the CA/health test suite all pass unchanged after the edit, since no test asserts on
  comment or markdown prose).
- **Fix applied (this pass):** corrected every `/healthz`/`/readyz` → `/health`/`/ready` (with an
  explicit note distinguishing the real, unrelated admin `/healthz`) in: `CLAUDE.md` (the
  `healthcheck.go` file-list entry and the CHAOS-28 architecture paragraph), `docs/operator/root-ca-expiry.md`
  (the confirmation table and the verification step), `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-09.md`
  (7 occurrences), `ca_health.go` (2 doc comments), and `ca_metrics.go` (1 doc comment).
- **Why not swept further this pass:** the same habit has a much larger, **pre-existing** footprint
  that predates this window and is not the product of any recent PR stream — reaching back to at
  least `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-07-09.md` (over a month old) and spread
  across dozens of Go doc comments and test-name/`t.Fatalf` prose (`ha.go`, `ha_lease.go`,
  `ha_healthz_version_test.go`, `ha_split_brain_failover_evidence_test.go`, `ha_term_test.go`,
  `rootca_startup.go`, `ca_expiry_failclosed_test.go`, `rootca_failure_visibility_test.go`,
  `internal/audit/audit.go`, `internal/reqlog/reqlog.go`, `diagnose.go`, `ui.go`, `ui_cluster.go`,
  `version.go`) plus `docs/support/HEALTH-AND-EVENT-MODEL.md` and several older
  `CHAOS-ENGINEERING-REVIEW-*.md` snapshots. Unlike the instances fixed above, this is entrenched,
  multi-week-old text that this program had not previously surfaced — sweeping dozens of files in
  one unattended pass without individual review is a worse trade than queuing it for a scoped
  follow-up PR. **Note:** a meaningful fraction of these are genuinely correct uses of the real
  admin `/healthz` (e.g. `ha_lease.go`'s fencing-lease fields, `ha.go`'s HA/split-brain material,
  `internal/audit/audit.go`'s `auditLogWriteErrors` — confirmed present on `apiHealthz` via
  `addRequestLogHealth`) — a follow-up must classify each site individually rather than
  find-and-replace.
- **Recommended canonical fix:** for each of the queued sites, replace `/healthz`/`/readyz` with
  `/health`/`/ready` only where the cited field is verified to live on the proxy-port handler
  (`ssl_inspection`, `ca_expires_days`, `clamav`, `threat_feed_entries`, the `ca`/readiness-gate
  rows); leave `/healthz` as-is where the cited field is genuinely HA/write-authority/fencing-lease
  material. `docs/engineering/DAY2-OPERATIONS-READINESS.md`'s comparison table is the correct
  reference to align every other document to.
- **Priority:** High for the instances fixed this pass (operator-runbook accuracy during the
  highest-documented-severity failure mode in the codebase). Medium for the remaining queued
  footprint (older, comment/test-prose only, no operator-doc instance left unfixed).
  **Migration risk:** None (prose/comment-only; zero wire, API, or test-literal dependency —
  verified by full build + vet + targeted test run). **Est. PR size:** Small (fixed this pass) /
  Medium (queued sweep — many files, each edit mechanical but requires per-site classification).

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
| T-39 | "Qualification" names four unrelated concepts in the same config/admin namespace | Open since 08-06, compounded 08-07. Unchanged in business-concept terms this pass; QUAL-6.1 consumed two existing senses more heavily without cross-referencing — evidence noted, priority unchanged. |

*T-41 is not listed here — fixed same-day in its highest-stakes instances, remaining footprint
queued in the Refactoring Plan below.*

## Soft findings — no action recommended

- Carried over unchanged from 07-24 onward: "Bootstrap" covering two unrelated features (no
  on-screen collision yet); the T3 "seed"/`CULVERT_PROXY_SEED_REF` vocabulary (internally
  consistent).
- Carried over unchanged from 08-03: the `culvert_decrypt_*` metric prefix vs. the fully-spelled
  `decryption`/`decryption-profile` API/audit/alert namespace — internally consistent, documented
  as a deliberate abbreviation in CLAUDE.md.
- Carried over unchanged from 08-04: `roadmap/google-captcha-swg-investigation.md:177`'s
  speculative `culvert_connlimit_rejections_total` metric citation for a counter that shipped as a
  REST field only.
- Carried over unchanged from 08-07: the CDR per-instance circuit-breaker `cb`-prefix wire-key
  convention vs. the sibling `internal/upstream.Status` breaker field names — same concept, same
  word, no collision, just an inconsistent key-naming convention across two similar endpoints.
- **New this pass:** the new `version` field on the admin `/healthz` (`ha.go`, backed by
  `main.version`) carries the identical value as the pre-existing `Version` field already served on
  the proxy's `/health` (`healthcheck.go:17`) — same concept, correctly named, just two
  independently-coded response builders on two differently-scoped ports now both happen to carry
  it. Not a collision (no confusion risk — both are correctly "version"), but the same
  "same-word-different-code-path" shape as the CDR soft finding above; worth a future consistency
  pass if either handler's `version` semantics ever needs to diverge.
- **New this pass:** `diagnostics.go`'s new `dp_config_snapshot_apply` operator-contract row
  correctly reuses the pre-existing CP→DP `ConfigSnapshot` sense of "snapshot" (not F3b's
  `snapshot_sha256` sense from T-32, not T-21's `cp_version` sense) — landing adjacent to, but not
  overlapping, two already-open "snapshot"-family findings. No action; noted for awareness only.
- **New this pass:** CHAOS-27's new `dedup_tracked`/`dedup_evictions_total` fields introduce
  "dedup" as an admin-facing term for the first time; clean today, worth watching if a future
  subsystem reaches for the same word for something unrelated.

---

## Recommended Refactoring Plan (priority order)

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium-High | T-39 (carried over) | Decide the QUAL-2/3 bootstrap-fleet name and the QUAL-4 policy-source name; rename `qualification_inventory_file`/`qualification_telemetry`/`qualification_policy_file` and their operator-doc titles/GUI strings away from bare "qualification"; reserve that word for the Production receipt gate | Medium | Small-Medium (needs a naming decision first) |
| High | T-38 (carried over) | Dual-emit `CapabilityHealth.ReviewRequiredTools`/`review_required_tools` alongside the existing `DriftedTools`/`drifted_tools` (keep the old field for wire compatibility); update the GUI label; add both fields to the OpenAPI spec | Low (additive) | Small |
| Medium | T-41 residual (new) | Sweep the pre-existing (pre-08-10) `/healthz`/`/readyz` misnomers for `/health`/`/ready` in `ha.go`, `ha_lease.go`, `rootca_startup.go`, the HA/CA test-file comments, `internal/audit/audit.go`, `internal/reqlog/reqlog.go`, `diagnose.go`, `ui.go`, `ui_cluster.go`, `version.go`, and `docs/support/HEALTH-AND-EVENT-MODEL.md`/older `CHAOS-ENGINEERING-REVIEW-*.md` snapshots — classify each site individually (some are genuinely HA-only `/healthz` references and must stay); align to `docs/engineering/DAY2-OPERATIONS-READINESS.md`'s comparison table | None (prose/comment-only) | Medium (many files, mechanical per-site edits, needs individual classification) |
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

*T-41's highest-stakes instances are omitted — already fixed this pass.*

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass re-confirmed, via a cited-line diff against
every one of nineteen previously-open findings, that all nineteen are unchanged in business-concept
terms across a 58-commit window — T-39 gained new volume of an existing collision (QUAL-6.1
consuming two established senses in one document pair) but no new independent sense, so its
priority is left unchanged. It found and same-day-fixed one new finding (T-41) in its highest-stakes
instances: two brand-new source files, a same-day design doc, and — most importantly — a live
incident-response operator runbook and CLAUDE.md itself all named the wrong health-check endpoint
for the CA-expiry failure mode this exact window's CHAOS-28 work was built to make visible. Unlike
prior same-day fixes (T-35, T-40), this finding also surfaced a materially larger *pre-existing*
footprint of the same habit that predates this window and was not created by any recent PR stream;
that residual is queued as a Medium-priority, low-risk follow-up rather than swept mechanically in
this pass, since correctly classifying genuine HA-`/healthz` references from misnamed
proxy-`/health` ones requires per-site judgment this program has not yet applied file-by-file. No
cosmetic or preference-driven renames were proposed.
