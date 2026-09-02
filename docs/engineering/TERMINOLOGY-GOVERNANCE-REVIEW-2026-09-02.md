# Culvert Language & Terminology Governance Review — 2026-09-02

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `403ef54..c20c17b` (232 commits, 19 on the first-parent path, 201 files changed —
> the second-largest first-parent window this program has processed, dominated by the MCP Agent Security
> Gateway's Canary and Live/Production rollout tiers: 19 new root `mcp_canary_*.go`/`mcp_live_*.go` files,
> two new ADRs, five new `docs/design/mcp/CANARY-*.md`/`LIVE-PRODUCTION-DEPS-REPORT.md` design docs, and
> four new `docs/operator/mcp-*.md` runbooks). Method: (1) full-repo grep for every `# ADR-NNNN` header —
> the same check that has caught three prior same-class collisions (T-16, T-46, T-47) — given this window
> added two more numbered ADRs (`0034`, `0035`); (2) diffed and read every non-MCP changed file individually
> (`ha_lease.go`, `logguard.go`, `ui_middleware.go`, `ui_rbac.go`, `ui_tls_custom.go`,
> `controlplane_server.go`, `internal/fileblock/fileblock.go`) against the vocabulary CLAUDE.md and prior
> reports already certified for each subsystem; (3) delegated a dedicated deep read of the new MCP
> Canary/Live wave (root `mcp_canary_*.go`/`mcp_live_*.go`/`mcp_shadow_*.go`/`mcp_tooltrust.go` files, the
> `ui_mcp*.go` API surface, the new ADRs and design/operator docs, and `CLAUDE.md`'s MCP section) — see the
> findings folded into the Non-MCP-surface section below; (4) checked every one of the
> fourteen still-open carry-over finding IDs' dependent files against this window's changed-file list.
> **Companion change:** one fix ships with this review — a fourth occurrence of the ADR-numbering
> collision defect class, this time on `0034`, caught before it was cited from any code path but after nine
> documentation cross-references had already accumulated on both sides of the collision.

---

## Executive Summary

**One finding, fully fixed: a fourth recurrence of the ADR-numbering-collision defect class, on `0034`,
worse than the previous three because it went undetected long enough to accumulate nine live citations
split across both meanings.** The 08-25 review's own fix renumbered
`docs/support/rfc/0032-ai-receives-normalized-evidence.md` to `0034` after confirming that number was
clean against every `# ADR-NNNN` header in the repository. Three days later, `docs/adr/0034-mcp-tool-trust-approval.md`
(an ACCEPTED architecture decision, part of the MCP Canary-readiness work) claimed the identical number —
the same root cause T-16, T-46, and T-47 each independently identified, now demonstrated a fourth time:
this codebase's decision-record numbering has no reservation mechanism, so a just-renumbered document is
exactly as available to a concurrent stream as a genuinely fresh number. Unlike the prior three instances,
this one was not caught same-day: by the time this review ran, five documents (`docs/operator/mcp-tool-trust-approvals.md`,
`docs/design/mcp/CANARY-ACTIVATION-GATE-REPORT.md`, `docs/design/mcp/SHADOW-ACTIVATION.md` twice,
`docs/adr/0035-mcp-canary-execution-architecture.md`, `docs/engineering/TECHNICAL-DEBT-REGISTER.md` twice)
had cited "ADR-0034" meaning the MCP tool-trust decision, while four others (`docs/adr/0016`'s own
"Relates to" line, `docs/support/TAC-CLOUD-ARCHITECTURE.md` three times, `docs/support/SUPPORTABILITY-THREAT-MODEL.md`'s
`T-PROMPT` row) still cited it meaning the AI-normalized-evidence RFC — a live, bidirectionally-ambiguous
citation, not merely a filename collision.

**Fix, same precedent a fourth time:** the established, ACCEPTED `docs/adr/` decision keeps `0034`; the
not-yet-adopted RFC-track document (`docs/support/rfc/`, still carrying its original "PROPOSED — NOT
ADOPTED" status from 2026-07-13, itself already renumbered twice before — `0018` → `0032` → `0034`) is
renumbered a third time, to `0036` — confirmed clean against every `# ADR-NNNN` header in the repository as
of this pass, including both files that caused this collision.
`docs/support/rfc/0034-ai-receives-normalized-evidence.md` → `0036-ai-receives-normalized-evidence.md`,
header updated, and the four downstream citations that genuinely mean the RFC's topic (AI receives
normalized findings, not raw bundles) updated to match: `docs/adr/0016-raw-evidence-vs-normalized-findings.md`'s
own "Relates to" line, and `docs/support/TAC-CLOUD-ARCHITECTURE.md` (three call sites: the raw-plane
paragraph, the pipeline-step list, and the §6 section heading), and
`docs/support/SUPPORTABILITY-THREAT-MODEL.md`'s `T-PROMPT` row. The five citations that genuinely mean the
*new* `docs/adr/0034-mcp-tool-trust-approval.md` decision were verified accurate and left untouched. The
two occurrences inside `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-25.md` itself are a dated historical record
of that pass's own fix and are deliberately not rewritten, matching this program's standing practice of
never editing past reports. No code, API, GUI, or config surface is affected — confirmed by grep across
`*.go`/`*.yml`/`*.yaml` for the old filename and bare number before making the change.

**Terminology Health Score: 8.6 / 10** (unchanged from 08-25 — a fourth same-class collision, this time
slower to catch, was found and fixed at zero migration risk, but the underlying process gap this program
flagged after the third recurrence — no reservation/allocation mechanism for ADR numbers — is now
demonstrated a fourth time, and the fact that this instance accumulated nine citations before being caught
is itself new evidence the "catch it in the next review" mitigation is wearing thin as the pace of parallel
PR streams increases. Repeating the prior recommendation with a raised urgency: a CI check that fails a PR
introducing a duplicate `# ADR-NNNN` header would have caught this collision at review time on either PR,
before any citation was written against it, rather than after nine had accumulated across the fleet's
documentation.)

---

## Findings

### T-48 — Fourth recurrence of the ADR-numbering collision, this time on `0034`, with nine accumulated citations (new — fixed this pass)

- **Business concept:** the unique identifier for one architecture decision record.
- **Current names before this fix:** `# ADR-0034` claimed simultaneously by
  `docs/adr/0034-mcp-tool-trust-approval.md` (Accepted, dated 2026-08-28, part of the MCP Canary-readiness
  architecture — "MCP Tool Trust — source of truth and approval-purpose binding") and
  `docs/support/rfc/0034-ai-receives-normalized-evidence.md` (PROPOSED — NOT ADOPTED, dated 2026-07-13,
  itself renumbered to `0034` by the immediately preceding review after the identical collision on `0032`).
- **Why this is real drift, and worse than the prior three instances:** a bare "ADR-0034" citation was
  genuinely ambiguous between two unrelated decisions (MCP tool-trust approval-purpose binding vs. the
  AI-input normalized-findings boundary), and — unlike T-16, T-46, and T-47, each caught same-day or
  within the reviewing pass that created the collision — this one had already accumulated live citations on
  *both* sides by the time it was caught: nine total, five meaning the MCP decision and four meaning the
  RFC, including one ADR's own "Relates to" line (`docs/adr/0016`) and one ADR's own "Supersedes / relates
  to" line (`docs/adr/0035`) pointing at different targets under the identical number.
- **Recommended canonical name:** `docs/adr/0034-mcp-tool-trust-approval.md` keeps ADR-0034 (established,
  Accepted, cited from a sibling Accepted ADR's own header field, expensive to renumber); the RFC becomes
  ADR-0036.
- **Why the new name is better:** restores a 1:1 mapping between decision-record number and decision;
  `0036` is confirmed clean against every `# ADR-NNNN` header in the repository as of this pass, including
  both files that caused this collision and the just-created `0035`.
- **Affected code:** none.
- **Affected API:** none.
- **Affected GUI:** none.
- **Affected Documentation:** `docs/support/rfc/0034-ai-receives-normalized-evidence.md` (renamed to
  `0036-ai-receives-normalized-evidence.md`, header updated), `docs/adr/0016-raw-evidence-vs-normalized-findings.md`
  (1 "Relates to" citation), `docs/support/TAC-CLOUD-ARCHITECTURE.md` (3 citations), `docs/support/SUPPORTABILITY-THREAT-MODEL.md`
  (1 citation, the `T-PROMPT` row).
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (docs-only, 5 files touched, no code/API/GUI/config surface; verified
  by grepping `*.go`/`*.yml`/`*.yaml` for both the old filename and the bare number before the change).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Medium (matches T-16's, T-46's, and T-47's own priority — a documentation-identifier
  collision with no runtime/functional impact, but now a four-times-recurring, and this time
  slower-to-catch, risk of a reader or an AI agent citing or acting on the wrong decision record).

---

## Repeated Recommendation: an ADR-number reservation convention (raised urgency)

Raised after the third recurrence in the 08-25 review; now recorded a second time after a fourth,
qualitatively worse instance. All four collisions (T-16 → `0008`–`0011` vs. the main sequence; T-46 → the
first `0018` collision; T-47 → the second `0032` collision, within about a day of the fix that freed the
slot; T-48 → this `0034` collision, this time undetected across an entire review cycle and nine
citations) share one root cause: two independent PR streams each computed "the next free number" by
grepping the tree at the moment they needed one, with no mechanism to claim a number before the document
merges. The 08-25 review declined to add a mechanical fix for this in a docs-only terminology pass; this
review does not add one either, for the same reason — a CI check or a placeholder-file claiming convention
is an engineering-process change, not a terminology-drift finding, and belongs with whoever owns
`docs/adr/0001-record-architecture-decisions.md`. It is repeated here, with raised urgency, because the
qualitative shape of the defect has changed: the first three recurrences were caught before any citation
accumulated against the collision; this one was not, meaning the "catch it in the next review" safety net
is no longer closing the window before real damage (nine cross-references requiring correction) accrues.
Not added to the priority-ordered backlog below because it remains a process recommendation, not a
terminology-drift finding with a mechanical fix available to this program.

---

## Non-MCP surface — independently re-verified clean

Every non-MCP file changed in this window was read against its already-certified vocabulary and found
consistent, no new drift:

- **`ha_lease.go`** — a self-fence failover-ring recording race fix (M5); reuses the existing
  `leader`/`standby`/`self-fence` vocabulary CLAUDE.md's HA-lease-recovery section already documents,
  unchanged.
- **`logguard.go`** — introduces a `diskUsageFn` test seam over the existing `diskUsage` function; no new
  business-facing term.
- **`ui_middleware.go` / `ui_rbac.go`** — adds Basic-auth actor attribution (`uiUserKey`/`uiUser`) so
  `sessionAdmin` resolves a real username instead of `"unknown"` on the cookie-less auth path; consistent
  with the existing `sessionAdmin`/session-cookie vocabulary, no renaming.
- **`ui_tls_custom.go`** — adds `customUITLSPairValid` (a boot-time cert/key-pair integrity check); names
  follow the existing `customUITLS*` family exactly.
- **`controlplane_server.go`** — the CHAOS-56 bounded-`GracefulStop` fix for the CP↔DP gRPC server; reuses
  `cpGRPCGracefulStopBudget`/`gracefulStopBounded`, matching CLAUDE.md's own CHAOS-56 shutdown-sequence
  section (already updated in this window, verified consistent) term-for-term.
- **`internal/fileblock/fileblock.go`** — a lock-free published-view read-path optimization; adopts the
  same `publishLocked`/immutable-view vocabulary CLAUDE.md documents for `internal/threatfeed`, the IP
  filter, and `internal/connlimit` — a positive continuation of an established pattern, not a new dialect.

The bulk of this window's diff — the new MCP Canary and Live/Production-tier subsystem (19 root
`mcp_canary_*.go`/`mcp_live_*.go`/`mcp_shadow_*.go`/`mcp_tooltrust.go` files, ~85 files under
`internal/mcp/`, two new ADRs, five new design docs, four new operator runbooks) — received a dedicated
deep-read pass rather than a surface scan, given how much brand-new vocabulary a subsystem this size coins
in one window (arming, quiesce, preflight, rehearsal, attestation, tier, kill boundary, execution trust,
production deps) and how easily that vocabulary can fork before it settles. That pass is what surfaced
T-48 above (the `0034` collision straddles this exact wave). Beyond T-48, this is an unusually disciplined
subsystem: every coined term was cross-checked across code identifiers, JSON field names, `ADR-0035`
prose, and `docs/design/mcp/CANARY-READINESS-MATRIX.md`'s 21-row table (spot-checking ~25
`internal/mcp/canary` `Reason` constants against the matrix rows and `mcpCanaryStatus()`'s
`all_prerequisites` dump found no divergence), and the pairs that look superficially like drift — Shadow's
"mechanics" rehearsal vs. Canary's "coordinator/authoritative" rehearsal, "composed" vs. "armed" vs.
"active" — are explicitly documented as distinct concepts by design, not the same one under two names.
Shadow, Canary, and Production remain consistently treated as distinct rollout modes across the new root
files, the `ui_mcp*.go`/`ui_mcp_tooltrust.go` API surface, and the new design/operator docs, matching the
existing Disabled→Observe→Shadow→Canary→Production ladder CLAUDE.md already documents. Two things outside
this program's mandate were noted but deliberately left unqueued, consistent with prior reviews' practice
of recording documentation-completeness gaps without treating them as naming drift: (1) the wave shipped
with no GUI surface at all (`static/index.html` has zero diff in this range) — not a collision, since there
is no second name to collide with; (2) `CLAUDE.md`'s ADR-0024 Architecture Notes section still describes
only the pre-Canary Disabled→Observe→Shadow→Canary→Production ladder and mentions none of this wave's new
vocabulary — since it says nothing about these concepts at all, there is no competing name to flag, only a
staleness gap for whoever next updates that section.

---

## Carried-Over Findings (unchanged — re-confirmed by file-list absence)

All fourteen remaining previously-open finding IDs were re-checked against this window's 201-file changed
list; none of their dependent files intersect it (the window is dominated by new MCP Canary/Live files with
no prior naming history to drift from, plus the seven non-MCP files individually re-verified above), so
each is re-confirmed open and unchanged: T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21 + T-32 (paired),
T-25 (residual), T-29, T-30, T-31, T-33, T-34, T-39. Full descriptions remain in the reports where each was
first raised and in `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-25.md`'s carry-over list, to avoid duplicating
unchanged text.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 08-25 for the still-open carry-over items; T-48 is resolved in this pass and does not appear
on the plan.

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium-High | T-39 (carried over) | Decide the QUAL-2/3 bootstrap-fleet name and the QUAL-4 policy-source name; rename `qualification_inventory_file`/`qualification_telemetry`/`qualification_policy_file` and their operator-doc titles/GUI strings away from bare "qualification"; reserve that word for the Production receipt gate | Medium | Small-Medium (needs a naming decision first) |
| Medium | T-18 (carried over) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI; rename the audit-event string | Low | Small-Medium |
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

Also queued (process-level, not a mechanical rename, raised urgency this pass): the ADR-number reservation
convention discussed above.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass caught and fixed a fourth recurrence of the
ADR-numbering collision defect class (T-48) — the first instance of this class to escape same-pass
detection and accumulate real citation debt (nine cross-references) before being caught, which is treated
as a signal worth escalating rather than a routine fix. It independently re-verified, file by file, that
none of the seven non-MCP files changed in this window introduced new drift, and gave the large new MCP
Canary/Live-tier wave a dedicated deep read rather than a surface scan, finding the new rollout-mode
vocabulary (Shadow/Canary/Production, arming, quiesce, preflight, rehearsal, attestation) internally
consistent across code, API, GUI, and docs — with the one exception being T-48, which is a numbering
collision at the wave's boundary rather than vocabulary drift within it. All fourteen carry-over findings
were re-confirmed open and unchanged. No cosmetic or preference-driven renames were proposed or made.
