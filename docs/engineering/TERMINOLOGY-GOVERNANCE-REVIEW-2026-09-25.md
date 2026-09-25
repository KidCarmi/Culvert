# Culvert Language & Terminology Governance Review — 2026-09-25

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Re-verified the tree at `e355949` (the current `origin/main` lineage HEAD at review time)
> against the open backlog the 2026-09-20 report carried forward. A broad codebase survey (source,
> REST API, GUI, CLI, config, docs, audit logs, metrics, alerts — the full surface list this program
> tracks) was run first, specifically sampling the feature areas most likely to have drifted since the
> last pass (Upstream Proxies, PAC, CDR, Decryption Exclusions, Release Management, MCP Gateway, Policy
> Learning, HA/Cluster, Alerts/Webhooks, Support Bundles), plus a fresh sweep of every already-documented
> "intentional multi-name" case in `CLAUDE.md` to confirm none had silently regressed into genuine drift.
> **No new drift was found.** This pass instead **fixes T-29**, the oldest-standing "documented, not
> fixed" item in the backlog with a clean additive/backward-compatible path (open since 2026-08-01,
> carried unchanged across roughly thirty subsequent reports), using the exact alias strategy the backlog
> entry itself specified — the same T-10/T-17 precedent. **Companion change:** this report's fix is
> landed in the same PR as the report.

---

## Executive Summary

No new terminology drift was found in the sampled feature areas, and every CLAUDE.md-documented
"multiple names, by design" case (the Session Secret quartet, the retired `UnauthMode`, the IdP vs.
Identity Backend distinction, `Ready()` vs. `Usable()` on both CA health surfaces) remains internally
consistent — none of these are re-flagged here.

**T-29 is fixed in this pass**: the per-IP rate-limit setting's YAML key and CLI flag now have a
canonical name (`rate_limit_rpm` / `-rate-limit-rpm`) matching every other live surface — the admin-API
JSON body, the persisted `admin_settings.json`, the CP→DP `ConfigSnapshot` wire field, the config-version
diff key, and the `culvert_rate_limit_rpm` Prometheus metric all already said `rate_limit_rpm`; only the
operator-facing config surface — the one most likely to be hand-written into a `config.yaml` or a
systemd/compose unit — dropped the unit qualifier. The prior key/flag (`rate_limit` / `-rate-limit`) are
retained as fully supported, non-deprecated-for-removal aliases — zero breaking changes.

**Terminology Health Score: 8.9 / 10** (up from 8.8 — the oldest cleanly-fixable open item in the
backlog is now fixed; ten backlog entries remain, unchanged in scope and priority).

**Fixed in this change:** T-29 — the per-IP rate-limit YAML key and CLI flag now have a canonical name
consistent with every other live surface, via an additive alias with zero breaking changes.

---

## Findings

### T-29 — Per-IP rate limit: the operator-facing config surface was the lone outlier on "RPM" naming (FIXED)

- **Business concept:** the per-IP request-rate-limit threshold, expressed as requests per minute.
- **Before:**
  - YAML: `security.rate_limit` (`config.go`)
  - CLI flag: `-rate-limit` (`main.go`) — bound to a Go field already named `rateLimitRPM`, i.e. the
    *identifier* had already migrated to the RPM-qualified name; only the flag string and the YAML key
    had not.
  - Admin-settings persistence / JSON API: `rate_limit_rpm` (`admin_settings.go`)
  - CP→DP wire (`ConfigSnapshot`): `rate_limit_rpm` (`controlplane_snapshot.go`)
  - Config-version diff key: `rate_limit_rpm` (`configversion.go`)
  - Prometheus metric: `culvert_rate_limit_rpm` (`metrics.go`)
  - Six of seven live surfaces already agreed on `rate_limit_rpm`/`rateLimitRPM`. Only the YAML/CLI
    operator-facing surface — the one most likely to be grepped or hand-edited when writing a
    `config.yaml` or a systemd/compose unit, and the one this program's own tables and CLAUDE.md's
    env/flag references describe — dropped the unit qualifier.
- **Why this was real drift:** an operator correlating a hand-written `config.yaml` against the admin
  API's response, a config-version diff, or `/metrics` output would search for `rate_limit_rpm` (the
  name every other surface uses) and not find it in the one place they are most likely to be reading
  or writing it by hand.
- **Fix (additive, zero breaking changes), following the T-10 DPI precedent exactly:**
  1. **YAML:** added the canonical key `security.rate_limit_rpm` (`config.go`, `FileConfig.Security`);
     `security.rate_limit` remains a fully supported, non-deprecated-for-removal alias. A new
     `FileConfig.reconcileDeprecatedRateLimitKey()` method — called from `loadFileConfig` immediately
     after the existing `reconcileDeprecatedDPIKeys()` — resolves the two: the canonical key wins when
     both are set to a nonzero value, and the deprecated key still works but emits the same one-line
     startup notice format (`"[Culvert] config: %q is deprecated, use %q instead"`) the DPI reconciler
     already established. Downstream code keeps reading `fc.Security.RateLimit` unchanged — this is the
     single reconciliation point, mirroring `reconcileDeprecatedDPIKeys` field-for-field.
  2. **CLI flag:** added the canonical `-rate-limit-rpm` flag (`main.go`) alongside the existing
     `-rate-limit`, which stays supported and now documents itself as the deprecated alias in its own
     `-h` usage text. Both flags, plus the (already-reconciled) YAML value, are merged via the existing
     `firstNonZero(*s.rateLimitRPMCanonical, *s.rateLimitRPM, s.fc.Security.RateLimit)` precedence chain
     — the same idiom every other CLI/YAML-merged setting in `main.go` already uses.
  3. **Validation:** `FileConfig.validateLimits` now checks both `security.rate_limit` and
     `security.rate_limit_rpm` for a negative value, each with its own error message naming the offending
     key.
  4. **Docs:** `config.example.yaml` and `README.md`'s quick-start example now lead with
     `rate_limit_rpm`, each noting `rate_limit` as a supported deprecated alias; `README.md`'s CLI-flags
     summary table now lists `-rate-limit-rpm`; `docs/operator/cluster-rate-limit-freshness.md`'s
     "Applies to" line (the one existing operator doc that names this setting) now leads with the
     canonical flag/key and calls out the alias explicitly; the commented-out example flag in
     `docker-compose.yml` was updated to the canonical spelling (it was never active, so this is
     documentation-only).
  5. **Regression tests:** `TestLoadFileConfig_RateLimitRPMCanonicalWins` and
     `TestLoadFileConfig_DeprecatedRateLimitKeyStillWorks` (`logger_ca_clam_test.go`, placed directly
     alongside the three existing DPI-alias tests they mirror) assert the precedence and the
     back-compat path at the YAML-parsing layer.
- **Deliberately NOT touched in this pass**, per the same boundary the T-10/T-17 precedents drew around
  their own residuals: `AdminSettings.RateLimitRPM`, `ConfigSnapshot.RateLimitRPM`, and the
  config-version diff key were already canonical and needed no change; this fix touches only the
  YAML/CLI ingestion layer, the one layer the backlog entry identified as the outlier.
- **Process note (out of scope for this pass, flagged for a future one):** while re-deriving this
  entry's history to confirm the current ID mapping, an unrelated live metric, `culvert_ha_failovers_
  total` (`cluster_metrics.go`), was found to disagree with every other HA-promotion surface — the
  incrementing code's own comment, the function name (`promote()`), the automatic-path identifier
  (`leaseAutoPromote`), the manual-path API/audit-event naming (`PromoteManually`/`apiClusterHAPromote`/
  `cluster.ha-promote`) all say "promotion", while the externally-scraped counter alone says "failover"
  and conflates a deliberate admin-triggered promotion with an automatic lease-driven takeover under the
  same name. This exact finding was documented once, in the 2026-07-31 report, under what was then T-29
  before that ID was reassigned to the present rate-limit finding in the very next (2026-08-01) report —
  it does not appear to have been carried forward under a new ID since, which looks like a bookkeeping
  gap in this program's own renumbering rather than a resolved finding (the metric is unchanged in the
  current tree). Not re-verified end-to-end or fixed here — flagged so the next pass can decide whether
  to reinstate it as a numbered backlog item rather than have it stay lost to a renumbering.
- **Migration risk:** none. Every change is additive (a second YAML key, a second CLI flag, a second
  validation check) or documentation. No existing consumer — a deployed `config.yaml`, a systemd unit or
  compose file passing `-rate-limit`, the legacy `static/index.html` GUI, or an external script — needs
  to change; all continue working against the deprecated names unmodified. Migrating them to the
  canonical spelling is optional future cleanup, not required by this fix.
- **Verification:** `go build ./...`, `go vet .`, `gofmt -l .` clean; the full `RateLimit|ConfigSurfaces|
  FileConfig` test subset (`go test . -run 'RateLimit|ConfigSurfaces|FileConfig'`) — 60+ tests, including
  every pre-existing `TestRateLimit*`/`TestLoadFileConfig*`/config-snapshot rate-limit test — all green,
  along with the four `main_config_precedence_test.go` `startupState` literals that construct a
  `loadFileConfigAndFlags` call directly (updated to populate the new CLI-flag pointer field alongside
  the existing one, the same way every other `firstNonZero`-merged flag pair in that test file is
  populated).

---

## Carried-Over Findings (unchanged)

The remaining ten previously-open finding IDs remain open, unchanged: T-9, T-11, T-12, T-13 (residual),
T-18, T-21+T-32 (paired), T-25 (residual), T-30, T-33, T-34, T-39. Full descriptions and the
priority-ordered refactoring plan are unchanged from `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-01.md`
(where T-29/T-30 were both last fully restated) through `-2026-09-20.md`, and are not restated here to
avoid drift between two descriptions of the same open items. T-30 (per-IP connection cap: `max_conns_per_
ip`/`MaxConnsPerIP` vs. `conn_limit_max_per_ip`) is the natural next fix on the same additive-alias
pattern this pass and T-17 both used, and remains the lowest-risk item left in the backlog — deferred
here only so this pass stays scoped to one mechanical change with its own clean verification, per this
program's established one-fix-per-pass practice. T-12 (Maintenance-Agent `/v1/upgrades/*` vs. product
vocabulary) and T-39 (MCP Gateway `qualification_*` colliding with the unrelated Production-Qualification
concept) were spot-checked directly against `e355949` and confirmed still live and unchanged from the
prior report's description.

The "Content & Scanning" vs. "Content Security" soft finding (design-document reconciliation between two
deliberate naming decisions, not a mechanical rename) also remains unresolved and is not queued to the
numbered backlog, per prior reports' reasoning.

---

## Stop-Condition Assessment

Terminology is not yet "already sufficiently consistent" — ten backlog items remain open — so this pass
acted rather than stopping, fixing the single best-risk-adjusted item among those sampled (additive/
alias-only, zero breaking changes, direct precedent already established twice by T-10 and T-17). No
cosmetic or preference-driven renames are proposed. T-30 is correctly queued as the next pass's likely
target (same pattern, same risk profile); T-12 and T-39 remain correctly deferred for the reasons the
2026-07-19/2026-08-01 reports originally gave, unchanged since. This report and its accompanying PR are
the deliverable of this pass.
