# Culvert Language & Terminology Governance Review — 2026-09-22

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `46410c3..origin/main` — the window since the 2026-09-11 report's merge point
> (`46410c3` is that report's own PR branch tip; the merge commit integrating it into `main`, `0665453`,
> sits inside this range with zero unique diff — a git-topology artifact, not new content). Confirmed as
> current `origin/main` HEAD by a fetch immediately before writing this report (the DEBT-014 lesson: sync
> against `main` right before opening a PR, not only at review-start). The window covers 24 first-parent
> merges / 162 files / 31,426 insertions / 1,003 deletions — two themes, matching the branch-name
> evidence: (1) the MCP Agent Security Gateway's "First Controlled Canary" admission-control work
> (`internal/mcp/canary`, `internal/mcp/execution`, `internal/mcp/tooltrust`, `internal/mcp/policy`, ~40
> `mcp_canary_*`/`mcp_live_*` root files, ADR-0035, two design docs, one very large operator review log)
> and (2) a multi-stage CI/build-pipeline overhaul (`.github/workflows/ci.yml`'s release-publication/
> candidate-resolution jobs, `resign-catalog.yml`, the R2-only catalog-origin retirement of GitHub Pages,
> `roadmap/CI-REDESIGN.md`) plus a small, unrelated tail of CHAOS-65 (OCSP) and CHAOS-63 (login-bounds)
> GUI/metrics follow-ups.
>
> **A note on this review's own process, worth recording for the next run.** This pass started with a
> full-repository sweep (not diff-scoped against the prior report) and it surfaced five candidate
> findings — the `allow`/`deny` vs. four-value `PolicyAction` vocabulary, the Maintenance Agent's
> `/v1/upgrades/*` wire routes, two colliding "Config Version" counters, `internal/sealbox`'s `Seal`/
> `Open` naming two different trust properties, and `decryption_redact_hosts`'s scope no longer matching
> its own name. Before writing any of these up as new, this review checked them against the existing
> numbered backlog in `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md`/`-2026-09-11.md` and found **all five
> were already tracked** — as T-11, T-12, T-21+T-32, T-18, and T-17 respectively, each independently
> re-derived with the same reasoning and (for T-11/T-17/T-18) near-identical citations to the reports that
> first raised them. Nothing from that sweep is reported below as new; it is folded into the carry-over
> confirmation instead. This is precisely the DEBT-014 pattern (independent rediscovery of the same
> defect across runs) applied to *findings* rather than *fixes*, and the lesson is the same one DEBT-014
> already draws: **a full-repo sweep on this series should always be reconciled against the standing
> backlog before anything is written up as new**, not just diff-scoped runs. This report's substantive
> content below comes from the properly diff-scoped second pass.

---

## Executive Summary

**No new terminology drift found, and no new fixes made this pass.**

Three bounded audits were run against the diff:

1. **The MCP canary admission-control vocabulary** (`internal/mcp/canary/{operation,permit,readiness,
   reviewed,scope,credfree,firstcanary_scope}.go`, `internal/mcp/tooltrust/reviewed_operation.go`,
   `internal/mcp/policy/*`, `ui_mcp_tooltrust.go`'s new `reviewed_operation_class` field). This window
   introduces a genuinely new two-layer concept — the human reviewer's binary
   `tooltrust.ReviewedOperationClass` (`read_only`/`mutating`/unset, wire field
   `reviewed_operation_class`) versus the richer `policy.OperationClass` enum (`OpRead`/`OpDiscovery`/
   `OpWrite`/`OpDestructive`/`OpControl`/`OpUnset`) the canary engine evaluates against — and it is
   **deliberately, not accidentally, two names**: `canary.OperationClassFromReviewed()` is the one
   explicit conversion function, heavily commented on exactly why the narrower reviewed vocabulary maps
   onto the broader policy one and why the two must never be conflated (`reviewed.go:138-150`,
   `operation.go:1-27`). No JSON/GUI/metric surface exists yet for the canary engine itself — the review
   doc's own verdict is `BLOCKED — NO SAFE FIRST CANARY TARGET`, so there is nothing live to name
   inconsistently across surfaces. `reviewed_operation_class` itself is spelled identically across the Go
   field (`ReviewedOperationClass`), the JSON tag, the request-body comment, and the parse function
   (`ParseReviewedOperationClass`) — no drift.
2. **New Prometheus/JSON surfaces added this window** — scanned every `culvert_*` metric name and every
   new `json:"..."` tag added by the diff. All of it is CHAOS-65 (OCSP) continuation
   (`culvert_ocsp_path_checked`, `culvert_ocsp_response_rejected_total`, the new `ocspPathCoverage{Path,
   Checked, Detail}` struct with path identifiers `upstream_transport`/`ssl_inspect_origin`/
   `connect_bypass`) and one CHAOS-63 field (`loginOversizeRejected` newly exposed on `GET /api/stats`).
   Every one of these matches byte-for-byte across its Go var name, JSON tag, GUI DOM id/JS accessor
   (`static/index.html`'s new `ocsp-coverage-*`/`oversize-login-*` elements read
   `ocsp.notForCertificateTotal` / `s.loginOversizeRejected` verbatim), and its `/metrics` HELP text. Zero
   new MCP-canary metrics, zero new audit event names, zero new CLI flags/YAML keys/env vars anywhere in
   the diff.
3. **The CI/build-pipeline overhaul** (`ci.yml`'s new `resolve-candidate`/`promote-release-channels`/
   `attach-provenance` jobs, `resign-catalog.yml`, `.github/scripts/resolve-release-candidate.sh`, the
   R2-only catalog-origin retirement). This is GitHub Actions job/script naming, not an operator-facing
   business concept spanning API/GUI/docs the way this series has tracked drift before — it is out of this
   review's established scope, and no finding was manufactured by treating CI job-graph names as a new
   "concept." Two spot checks against it were still worth recording: the GitHub Pages catalog retirement
   is fully and accurately reflected in `CLAUDE.md`'s "The release catalog has ONE origin: R2" bullet
   (`publish-catalog-pages.yml` is in fact deleted at `origin/main`, confirmed directly), and `CLAUDE.md`'s
   pre-existing `ci.yml` bullet (`candidate-<run_id>`, `promote-image`, `require-release-evidence.sh`) is
   unaffected by and consistent with the new `resolve-candidate`/`promote-release-channels` jobs it
   doesn't yet name — a documentation-completeness gap at most, not a naming collision, and not queued as
   a new backlog item.

**Spot-checked three carry-over items directly against the current tree** (not trusted from the prior
report):
- **T-12** — `cmd/culvert-maint/internal/server/server.go:405-406` and `handlers_upgrade.go:1,3,80` still
  register and document only `/v1/upgrades/check` and `/v1/upgrades/apply`; no `/v1/updates/*` alias
  exists anywhere in `cmd/culvert-maint/`. Unchanged.
- **T-17** — `admin_settings.go:234` still `DecryptionRedactHosts bool
  \`json:"decryption_redact_hosts,omitempty"\``; `ui_policy.go:3013` still registers
  `/api/decryption/redaction`. Unchanged.
- **T-18** — `internal/sealbox/sealbox.go:100,119` still exports `Seal`/`Open` (not, e.g.,
  `SealToRecipient`/`OpenAsRecipient`). Unchanged.

`docs/engineering/TECHNICAL-DEBT-REGISTER.md` is byte-untouched in this window (not in the 162-file
diff) — **DEBT-014 is unchanged**, still describing the same unmerged-governance-PR backlog as of
2026-09-05. None of the five PR numbers DEBT-014 names as ready-to-merge (#1239, #1250, #1253/#1284/
#1294/#1302/#1309, #1293, #1300, #1308) landed in this window. No newer-dated
`TERMINOLOGY-GOVERNANCE-REVIEW-*.md` exists on `main` — 2026-09-11 remains the prior latest, and this
report is its successor.

**Terminology Health Score: 8.7 / 10** (unchanged from 2026-08-08 through 2026-09-11). No new drift was
introduced by a 162-file, mostly-backend/mostly-CI window, and no carry-over item moved — so the score
neither rises nor falls.

---

## Carried-Over Findings (unchanged)

All fourteen previously-open finding IDs (thirteen backlog entries, since T-21 and T-32 are tracked as one
paired item) remain open, unchanged, and — for T-12/T-17/T-18 — re-confirmed directly against the current
tree above: T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21+T-32 (paired), T-25 (residual), T-29, T-30,
T-33, T-34, T-39. Full descriptions and the priority-ordered refactoring plan are unchanged from
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md`/`-2026-09-11.md` (and their predecessors, cited therein) and
are not restated here to avoid drift between two descriptions of the same open items.

The "Content & Scanning" vs. "Content Security" soft finding also remains unresolved and unqueued, per
prior reasoning.

---

## Stop-Condition Assessment

No production-worthy NEW terminology improvement was identified this pass. An initial full-repo sweep
independently re-derived five items already on the standing backlog (T-11, T-12, T-17, T-18, T-21+T-32)
and contributed nothing new once reconciled against it — itself a useful confirmation that those five
findings remain live and independently rediscoverable, and a process lesson (recorded above) for keeping
this series' full-repo passes reconciled against the backlog before writing anything up. The properly
diff-scoped audit of the 24-merge window since 2026-09-11 covered two disciplined engineering efforts — MCP
canary admission-control internals with no live operator-facing surface yet, and a CI/release-pipeline
restructuring outside this series' established scope (business-concept naming across API/GUI/docs/metrics,
not GitHub Actions job graphs) — plus a small, cleanly cross-surface-consistent tail of CHAOS-65/CHAOS-63
GUI and metrics additions. The fourteen-ID (thirteen-entry) carry-over backlog is unchanged and was
independently re-confirmed (not merely assumed unchanged) for its three highest-visibility items. DEBT-014
and its named PR backlog are unchanged; no new dated report superseded this one before it was written. No
cosmetic or preference-driven renames are proposed. This report itself is the deliverable of this pass,
written after a fresh sync against `origin/main` immediately beforehand, per the DEBT-014 process lesson.

**One process note for a human, not a content finding of this pass:** DEBT-014's already-open PR backlog
(#1239, #1250, the T-48 quintet, #1293, #1300, #1308) is still unmerged per the register as of its last
update. If those PRs are still open, merging them — not another audit pass — is the highest-leverage
terminology-governance action available; this review did not re-verify their live GitHub state, since that
is DEBT-014's tracking responsibility, not this series'.
