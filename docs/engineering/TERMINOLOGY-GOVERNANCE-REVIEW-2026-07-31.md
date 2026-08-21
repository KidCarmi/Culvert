# Culvert Language & Terminology Governance Review — 2026-07-31

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Three parallel concept-cluster audits against the tree at `f837bf6`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-07-24.md` (baseline `2eef667`). One lane audited CLI flag / env
> var / YAML config key / REST API field consistency for settings with admin-GUI parity. One lane
> audited GUI label vs REST API field vs operator-doc vs audit/log-message consistency for admin-facing
> features. One lane audited metric name / alert name / audit-event name / log-message consistency for
> recurring runtime events (HA, upstream failover, autoexclude, release catalog).
> **Companion change:** one zero-risk, copy/client-validation-only fix ships with this review (see
> "Fixed in this change"). No REST route, JSON field, CLI flag, config key, audit-event name, or
> exported Go identifier was renamed.

---

## Executive Summary

This pass re-confirmed the clusters prior reviews already certified — `UnauthMode`→`DefaultAuthOutcome`,
the session-secret four-name split, HA `term`/`epoch`, autoexclude's `scopeID`/`securityGen` vocabulary,
and the release-catalog/maintenance-agent naming all remain intentional and unchanged — and found no new
drift in those areas. It surfaced one new admin-facing description-accuracy defect (fixed in this
change, zero compatibility risk) and two new naming-drift findings in the config/API surface, both
sized for a dedicated follow-up because they touch live YAML keys and/or a live REST API field rather
than copy alone.

**Terminology Health Score: 8.5 / 10** (unchanged from 07-24 — one new Medium finding surfaced, one
Low finding surfaced, one description defect fixed same-day; no regression in any previously-certified
cluster).

**Fixed in this change:**

- **T-32 — Admin-UI password hints under-described the server-enforced complexity rule.**
  `validatePasswordComplexity` (`store.go:654-674`) requires ≥8 characters **and** at least one
  uppercase letter, one lowercase letter, and one digit — enforced on every credential-creation path
  (setup wizard, Add/Edit User, config-auth API). All four GUI surfaces that describe this rule to an
  admin only mentioned the length: the setup wizard's field hint (`su-pass` label, "minimum
  8 characters") and its client-side pre-check (setup-form submit handler, only `pass.length < 8`);
  the Add/Edit User modal's field hint (`um-pass-hint-group` label, "min 8 characters") and its
  client-side pre-check in `saveUser()`, only a length guard. An admin who typed an 8-character,
  all-lowercase password would pass every on-screen
  hint and every client-side check, then get rejected by the server with a rule that was never
  mentioned anywhere in the GUI. Updated both hint strings to state the real rule ("min 8 chars, incl.
  uppercase, lowercase & a digit") and added a matching client-side complexity check (mirroring the
  server's `hasUpper`/`hasLower`/`hasDigit` logic, using Unicode property classes with ASCII fallback)
  to both the setup wizard's submit handler and
  `saveUser()`, using the same requirement wording as the server's error (`store.go:673`) so the two surfaces
  never disagree. Copy + client-side validation only — no change to the server-enforced rule, no wire
  format change, `go build` confirmed green.

**Documented, not fixed this pass (sized for a dedicated follow-up, same bar as the carried-over T-9/
T-11/T-12/T-16/T-17/T-18/T-21/T-25-residual items from prior reviews):**

- **T-29 (new) — HA promotion/failover metric name disagrees with every other surface for the same
  event.** See Findings for detail.
- **T-30 (new) — the per-IP connection-limit setting is spelled four different ways across YAML, the
  live admin API, and two persistence surfaces.** See Findings for detail.
- **T-31 (new, Low) — the per-IP rate-limit YAML key omits the `_rpm` unit suffix used everywhere
  else.** See Findings for detail.

All previously-open findings (T-9, T-11, T-12, T-16, T-17, T-18, T-21, T-25 residual) were spot-checked
against the ~15 commits landed since 07-24 (dependency bumps, an MCP CI-gate hardening pass, and a
session-secret documentation clarification) and are unchanged in scope — none of that work touched the
affected files.

---

## Wave — Re-verified clean (no new drift since 2026-07-24)

Independently re-audited: authentication/session/RBAC/lockout/TOTP/CA/PSCA naming (the session-secret
four-name split gained an explicit cross-referencing doc comment this period — commit `5efd518`,
"clarify session-secret naming split across GUI/API/engine/wire layers" — which is exactly the kind of
documentation this guardian recommends for a deliberate multi-name concept, not a new finding); HA
fencing-lease `term`/`epoch` pairing (still intentionally disambiguated per ADR-0005); SSL-inspection/
autoexclude `scopeID`/`securityGen`/`(scopeID,gen,host)` vocabulary (uniform across code, metrics,
audit, and CLAUDE.md); release-catalog/Sigstore/maintenance-agent naming (`catalog_version`,
`trust_schemes`, `verify_mode` all consistent between `/api/releases`, the admin panel, and the
resign-runbook). No regressions found in any cluster the 07-07 through 07-24 reviews already certified.

---

## Findings

### T-29 — HA promotion/failover metric name disagrees with every other surface (new — documented, not fixed)
- **Business concept:** a standby node taking over as cluster leader — whether triggered automatically
  by the fencing lease or manually by an admin.
- **Current names:** the Prometheus counter for this event is `culvert_ha_failovers_total`
  (`cluster_metrics.go:105-107`), incremented inside `promote()` (`ha.go:758`) — whose own code comment
  reads *"count standby→leader promotions only,"* i.e. the code that increments the metric already
  calls the event a "promotion," not a "failover." Every other surface agrees with the comment, not the
  metric name: the automatic path is named `leaseAutoPromote` (`ha_failover.go:77`) with log lines
  `"HA: auto-promotion suppressed..."` / `"...auto-promotion refused..."` (`ha_failover.go:86,94,98`);
  the manual path is `PromoteManually()` (`ha.go:785`), its API handler is `apiClusterHAPromote`
  (`ha.go:1088`), and its audit event is `Action: "cluster.ha-promote"`,
  `Detail: "manual standby→leader promotion (term=%d)"` (`ha.go:1109-1111`).
- **Why this is real drift:** an operator who sees `culvert_ha_failovers_total` increment and greps
  logs or the audit trail for "failover" to find out what happened will find nothing — every other
  surface says "promotion." More importantly, the single counter conflates two operationally different
  events under a name that implies an outage: a deliberate admin-triggered `cluster.ha-promote` (an
  intentional, healthy action) increments the exact same "failovers" counter as an automatic
  lease-driven takeover following a real leader loss — a dashboard/alert built on this metric cannot
  tell "the leader is down" from "an admin just ran a planned promotion," and the name itself
  mischaracterizes the manual case as a failure event.
- **Recommended canonical name:** `culvert_ha_promotions_total`, matching `promote()`/`PromoteManually`/
  `leaseAutoPromote`/`cluster.ha-promote` — ideally split by trigger,
  `culvert_ha_promotions_total{trigger="auto|manual"}`, which would also resolve the conflation problem
  above for free.
- **Why not fixed this pass:** `culvert_ha_failovers_total` is a live, externally-scraped Prometheus
  metric name — any existing Grafana dashboard, Prometheus alert rule, or SLO query referencing it by
  name would silently stop matching on a blind rename. This needs the same alias-on-read treatment as
  T-17 (expose both names for a deprecation window, or add the new name additively and mark the old one
  deprecated in `docs/operator/`), not a same-day rename.
- **Priority:** Medium (operational/SRE confusion; a manual action being labeled a failure event is a
  minor but real support/on-call cost). **Estimated PR size:** Small-Medium (one metric definition, one
  or two call sites, a deprecation note in operator docs; larger if the trigger-label split is
  included).

### T-30 — Per-IP connection-limit setting spelled four ways across live surfaces (new — documented, not fixed)
- **Business concept:** the maximum number of concurrent connections allowed from one source IP.
- **Current names:**
  - YAML config: `max_conns_per_ip` (`config.go:54`)
  - CP→DP wire (`ConfigSnapshot`, also externally observable via cluster sync): `max_conns_per_ip`
    (`controlplane_snapshot.go:49`) — matches YAML
  - The live admin toggle an operator actually calls from the GUI, `GET/POST /api/connlimit`:
    `maxPerIP` (`ui_config.go:1763,1772,1785`)
  - Config-version rollback / config-export payload (`configBackup`): `connLimitMaxPerIP`
    (`ui_policy.go:1253`)
  - Persisted admin settings (`admin_settings.json`) and the support bundle: `conn_limit_max_per_ip`
    (`admin_settings.go:33`, `support_collectors_reused.go:59`)
  - `config_surfaces.go:267-272`'s own registry row has to bind these under one `ID` precisely because
    the Go field names disagree (`ConfigSnapshot.MaxConnsPerIP` vs. `AdminSettings.ConnLimitMaxPerIP`)
    — the registry documents the mapping, but (unlike the session-secret case) there is no rationale
    comment saying this multiplicity is deliberate; it reads as the byproduct of the setting being
    added to each surface independently over time, not a designed audience-specific naming choice.
- **Why this is real drift:** an admin who reads `config.yaml` (`max_conns_per_ip`), calls the live
  toggle endpoint from a script (`maxPerIP`), and then pulls a support bundle or config export
  (`conn_limit_max_per_ip`) sees three different spellings of the identical value with nothing
  cross-referencing them for a reader (the registry comment is for maintainers of `config_surfaces.go`,
  not for an admin reading `/api/connlimit`'s response). This is the same failure class T-9 and T-17
  already document for other fields — external-facing name drift on a config value with no unifying
  documentation.
- **Recommended canonical name:** standardize on `conn_limit_max_per_ip` (snake_case, matching the
  majority of surfaces and the setting's own feature name "Connection Limit" used in the GUI,
  `ui_config.go:824`) for the YAML key and the live `/api/connlimit` JSON body, aliasing the old
  `max_conns_per_ip` YAML key and `maxPerIP` JSON field for backward compatibility.
- **Why not fixed this pass:** touches a live YAML config key (breaks existing `config.yaml` files on a
  blind rename) and a live REST API JSON field consumed by any existing automation calling
  `/api/connlimit` directly — this needs the alias-on-read pattern already used for T-10/T-17, not a
  same-day fix.
- **Priority:** Medium (real support/onboarding confusion; no correctness bug — every surface
  functions correctly today). **Estimated PR size:** Medium (YAML key alias + API field alias + docs).

### T-31 — Rate-limit YAML key omits the unit suffix used everywhere else (new, Low — documented, not fixed)
- **Business concept:** the maximum requests-per-minute allowed from one source IP.
- **Current names:** YAML config: bare `rate_limit` (`config.go:53`). Every other surface —
  `AdminSettings.RateLimitRPM` (`json:"rate_limit_rpm"`, `admin_settings.go:31`),
  `ConfigSnapshot.RateLimitRPM` (`json:"rate_limit_rpm"`, `controlplane_snapshot.go:31`), the
  config-version diff key `"rate_limit_rpm"` (`configversion.go:505`), the rollback/export payload
  (`ui_policy.go:1209`, `json:"rateLimitRPM"`), and the live `/api/security` body
  (`ui_security.go:176`, `json:"rateLimitRPM"`) — all disambiguate with the `_rpm`/`RPM` unit suffix.
- **Why this is real drift, but mild:** only one surface (the on-disk YAML file) diverges from an
  otherwise-unanimous convention; an operator hand-editing `config.yaml`'s `security.rate_limit` has to
  already know it means "requests per minute" (documented in a code comment, `config.go:53`, but not in
  the key name itself) to correctly correlate it with what the admin UI, API, and diff engine all call
  "Rate Limit (RPM)."
- **Recommended canonical name:** `rate_limit_rpm` in YAML, aliasing the legacy `rate_limit` key for
  backward compatibility (same pattern as T-30's recommendation, smaller scope — one surface, one
  alias).
- **Why not fixed this pass:** still a live YAML config key; a blind rename breaks existing
  `config.yaml` files without a read-compat alias.
- **Priority:** Low (single-surface, well-commented-in-code divergence; unlike T-30 there is no
  three-way spelling collision, just one outlier). **Estimated PR size:** Small.

---

## Recommended Refactoring Plan (priority order)

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium | T-18 (carried over) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI (4+ strings); rename the audit-event string | Low | Small-Medium |
| Medium | T-16 (carried over) | Renumber the Supportability-track's colliding ADRs (0008–0011 → 0019–0022) and cross-references | Low (docs, 40+ files to check) | Medium |
| Medium | T-17 (carried over) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped canonical names | Medium | Medium |
| Medium | T-21 (carried over) | Rename Cluster panel's `cp_version`/"CP Config Version" to a cluster-sync-scoped name | Low | Small |
| Medium | T-29 (new) | Alias `culvert_ha_failovers_total` → `culvert_ha_promotions_total` (optionally split by `trigger`) with a deprecation window | Medium (external dashboards/alerts) | Small-Medium |
| Medium | T-30 (new) | Canonicalize the per-IP connection-limit key/field on `conn_limit_max_per_ip`, alias `max_conns_per_ip` (YAML) and `maxPerIP` (API) | Medium (YAML + live API) | Medium |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-Medium | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low / Medium-large | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*` | Medium | Medium |
| Low | T-31 (new) | Alias YAML `rate_limit` → `rate_limit_rpm` | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" terminology | Low | Small |

T-32 is fixed in this change and requires no further action.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent, but this pass found no regression in any previously-certified
cluster, fixed one zero-risk description-accuracy defect same-day, and surfaced two new findings (one
Medium, one Low) in the config/API layer that are appropriately deferred pending an alias-based
migration — consistent with this program's standing rule that live YAML keys, REST API fields, and
Prometheus metric names are never blind-renamed regardless of how clear the business case, only aliased
with a deprecation window. No cosmetic or preference-driven renames were proposed or made in this pass.
