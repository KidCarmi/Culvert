# Culvert Language & Terminology Governance Review — 2026-09-24

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Snapshot scope (read this first):** this is a HISTORICAL record of `origin/main` at `6ec745d` on
> 2026-09-24. It was merged later, after `main` had moved on, so the tree it ships in contains commits it
> never audited. Its findings, carried-over backlog and health score describe `6ec745d` only. They are
> not a statement about the tree this file is published in; the current governance state is whatever the
> most recent review in this series says. Later windows are audited by later reports, never
> retroactively by this one.
> **Method:** Audited `0665453..6ec745d` — the window since the 2026-09-11 report's merge point (PR
> #1363). The end commit `6ec745d` was confirmed as the then-current `origin/main` HEAD by a fetch
> immediately before this report was written on 2026-09-24 (per the DEBT-014 lesson: sync against `main` right before opening a PR, not only at
> review-start, so a fix landed by a parallel branch is credited rather than re-claimed — no such
> landing occurred this pass; the branch was created directly from a synced `origin/main`, so no merge
> was needed). **Correction:** the first revision said no review dated later than 2026-09-11 existed on
> any branch. That was wrong. Three were open as unmerged PRs at the time and audited overlapping
> windows: 2026-09-19 (#1434), 2026-09-21 (#1456) and 2026-09-23 (#1482). This report is therefore a
> parallel run of the DEBT-014 kind; see "Overlap with parallel reports" below.
>
> The window covers 31 first-parent merges / 248 files / ~53.1k insertions, dominated by two
> unrelated backend tracks: (a) CI-REDESIGN pipeline work (`cmd/cireport`, `cmd/rootshard`,
> `.github/workflows/*`, release-publication gating, the R2-only catalog-origin retirement of GitHub
> Pages) — CI/release-engineering internals with no operator-facing surface — and (b) MCP "first
> controlled canary" rollout hardening (`internal/mcp/canary/*`, `mcp_canary_*.go`,
> `docs/design/mcp/CANARY-READINESS-MATRIX.md`, `docs/operator/mcp-first-controlled-canary-review.md`)
> alongside the CHAOS-65 (OCSP revocation checking), CHAOS-60 (GeoIP resolution health), and CHAOS-63
> (admin-login input bounds) reliability work already described in `CLAUDE.md`.

---

## Executive Summary

**No new terminology drift found by this pass, and no new fixes made.** Parallel reports covering
parts of the same window did find drift this pass missed; see "Overlap with parallel reports" below.

1. **Every new admin-facing name this window introduced was checked for cross-surface consistency and
   found internally consistent:**
   - **OCSP (CHAOS-65):** the window added nine `/api/ocsp` fields in `ui_security.go`, each spelled
     identically in `api/openapi/openapi.{json,yaml}` and the auto-generated `frontend/src/api/types.gen.ts`.
     They map to other surfaces as follows:
     - The six rejection counters (`notForCertificateTotal`, `unauthorizedResponderTotal`,
       `malformedResponseTotal`, `staleResponseTotal`, `unknownStatusTotal`, `responderBlockedTotal`)
       correspond one-to-one with `culvert_ocsp_response_rejected_total{reason=...}` labels in
       `ocsp_metrics.go` (camelCase field ↔ snake_case label, e.g. `notForCertificateTotal` ↔
       `not_for_certificate`). The GUI does not show them individually. It sums them into one "Responses
       rejected" counter (`static/index.html:4485`, filled at `:17517`).
     - `respondersTruncatedTotal` ↔ `culvert_ocsp_responders_truncated_total`. It is not shown in the GUI.
     - `coverage` and `uncheckedEnforcingPaths` ↔ the separate `culvert_ocsp_path_checked{path}` gauge
       (`ocsp_metrics.go:77-84`). The GUI renders `uncheckedEnforcingPaths` as its coverage banner
       (`static/index.html:17519`).
     - The wording "no responder returned a usable, affirmative verdict" is reused verbatim between the
       GUI fail-closed banner (`static/index.html:4494`) and the `culvert_ocsp_fail_closed_total` HELP text
       (`ocsp_metrics.go:38`).
   - **GeoIP (CHAOS-60):** the new `geo_resolution` diagnostics-contract row mirrors the pre-existing
     `dns_resolution` row's naming and severity convention exactly, and `docs/operator/
     geoip-resolution-health.md` uses the same vocabulary.
   - **Admin-login bounds (CHAOS-63):** the new `/api/stats` field `loginOversizeRejected` and its GUI
     hint text both trace to the pre-existing `culvert_login_oversize_rejected_total` metric — this is
     GUI-parity work for an already-named concept, not a new name.
   - **MCP canary (`reviewed_operation_class`, `read_only|mutating`):** documented identically in the Go
     struct comments, `api/openapi/openapi.{json,yaml}`, and `frontend/src/api/types.gen.ts`. It is **not
     yet surfaced in the MCP Command Center GUI** in this window, so there is no cross-surface GUI-vs-API
     name to compare yet, and therefore nothing to flag. The readiness-matrix row renumbering and the
     canary-review design doc are internal row-ID/function-name jargon, not administrator-facing product
     vocabulary, and stay internally self-consistent.
   - The release-publication-gating and R2-only-catalog work (`promote-image`, `candidate-<run_id>`,
     `resolve-candidate`) is CI/release-engineering internals with no operator-GUI or config-surface
     exposure, out of this glossary's scope.
2. **None of this window's 248 changed files touch any of the fourteen carry-over finding locations**
   (`docs/enterprise/TLS-INSPECTION-DEPLOYMENT.md`, `internal/sealbox`, the Cluster panel's `cp_version`/
   `snapshot_sha256` sites, `internal/support`'s recipient/TAC-trust-key stores, the `PolicyAction`/
   `PolicyReason` overwrite sites in `policy.go`, `apiURLCatFeedStatus`, or the
   `qualification_inventory_file`/`qualification_telemetry`/`qualification_policy_file` trio) — cross-
   checked against `git diff --stat 0665453..origin/main`'s full file list. None was touched, so none was
   incidentally resolved or worsened.
3. **Spot-checked three carry-over items directly** (rather than trusting the prior report alone), the
   same discipline the 2026-09-08/09/11 reports used: **T-11** — `config.go`'s `default_action`
   validation still accepts only `"allow"`/`"deny"` strings while `policy.go`'s `PolicyAction` enum still
   has no `Deny`/`Block` value (`ActionAllow | ActionDrop | ActionBlockPage | ActionRedirect`), unchanged.
   **T-12** — `cmd/culvert-maint/internal/server/server.go` still registers `POST /v1/upgrades/apply`
   (also unchanged in `handlers_upgrade_apply.go`, `ops.go`, `templates_upgrade.go`,
   `capture_running.go`); no `/v1/updates/apply` exists anywhere. **T-29/T-30** — `config.go` still has
   no `rate_limit_rpm` or `conn_limit_max_per_ip` YAML key; only `security.rate_limit` and
   `security.max_conns_per_ip` exist. All three confirmed exactly as the prior reports left them.

**Terminology Health Score: 8.7 / 10** (unchanged from 2026-09-08/09/11). This pass's checks found no new
drift in a 248-file, backend-and-CI-heavy window, and no carry-over item moved, so the score neither rises
nor falls. It does not account for the parallel reports' findings (see "Overlap with parallel reports");
the series' later reports reconcile the score.

---

## Carried-Over Findings (unchanged)

All fourteen previously-open finding IDs (thirteen backlog entries, since T-21 and T-32 are tracked as
one paired item) remain open, unchanged, and re-confirmed against the then-current tree (`6ec745d`): T-9, T-11, T-12,
T-13 (residual), T-17, T-18, T-21+T-32 (paired), T-25 (residual), T-29, T-30, T-33, T-34, T-39. Full
descriptions and the priority-ordered refactoring plan are unchanged from
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md` and are not restated here, to avoid drift between two
descriptions of the same open items — see that report (or its predecessors, cited therein) for the
canonical text of each.

The "Content & Scanning" vs. "Content Security" soft finding (design-document reconciliation between two
deliberate, independently-documented naming decisions — legacy GUI per
`docs/design/INFORMATION-ARCHITECTURE.md`, new frontend per `docs/design/FRONTEND-MIGRATION-PLAN.md` —
not a mechanical rename) also remains unresolved and is not queued to the numbered backlog, per the
2026-09-09 report's reasoning.

---

## Overlap with parallel reports

Three reports written before this one were still unmerged PRs when it was written, and each audited
part of this window. They recorded findings this pass did not:

- **2026-09-21 (#1456)**: the OCSP admin panel was titled "OCSP / CRL Revocation" although only OCSP
  exists (its T-57), and the OCSP work added "appliance", which the glossary forbids, to an OpenAPI field
  description and operator docs (a T-51 recurrence). This report's OCSP check compared field spellings
  and did not read the panel title or prose against the glossary.
- **2026-09-23 (#1482)**: T-54–T-56 (identity-backend metric prefix, Sync vs Refresh verbs, the
  decryption-exclusion audit search). All three are long-standing, not introduced in this window.
- **2026-09-19 (#1434)**: a pre-existing SSL/TLS label mismatch in the new frontend's Rule Editor (its T-54).

This report's "no new drift" conclusion covers only the checks listed above. It is not evidence
against those findings. The finding IDs above are the parallel reports' own; see each report for
their ID notes.

---

## Stop-Condition Assessment

No production-worthy NEW terminology improvement was identified by this pass's checks (parallel reports
found some in the same window; see above): the 31-merge window audited
was CI/release-pipeline engineering plus MCP-canary and reliability (CHAOS-60/63/65) work, all internally
consistent where these checks looked. The 2026-09-21 report found that the window did add "appliance"
to customer-facing docs and an OpenAPI description, which this pass missed.
The fourteen-ID (thirteen-entry) carry-over backlog is unchanged and was independently re-confirmed (not
merely assumed unchanged) for three of its items via direct file inspection. No cosmetic or
preference-driven renames are proposed. This report itself — the audit record and backlog
reconciliation — is the deliverable of this pass; per the DEBT-014 process lesson, it was written only
after a fresh sync against `origin/main` immediately before opening its PR, and the branch was confirmed
to be exactly `origin/main` at commit `6ec745d5` with no divergent history before this file was added. The
sync did not catch the parallel reports, because they were on unmerged branches rather than on `main`.
