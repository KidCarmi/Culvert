# Culvert Language & Terminology Governance Review — 2026-09-12

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `d378dff..2833db3` — the window since the 2026-09-11 report's merge point,
> confirmed as the current `origin/main` HEAD by a fetch immediately before this report was written (per
> the DEBT-014 lesson recorded in the 2026-09-09 report: sync against `main` right before opening a PR,
> not only at review-start). The window covers 9 first-parent merges / 95 files / ~12,100 insertions,
> dominated by the new MCP-First Controlled Canary feature (ADR-0035: `internal/mcp/canary`,
> `internal/mcp/execution`, `internal/mcp/runtime`, `internal/mcp/tooltrust`,
> `internal/mcp/upstreamclient`, the root `mcp_canary_*.go`/`mcp_live_*.go`/`mcp_tooltrust.go` wiring,
> `ui_mcp_tooltrust.go`, and three new docs) plus the already-CLAUDE.md-documented CHAOS-65 OCSP
> revocation-checking hardening, a rate-limit exempt-view internal refactor, and a SOCKS5 log-injection
> fix — reliability/security engineering rather than admin-facing feature naming.

---

## Executive Summary

**No new terminology drift found, and no new fixes made this pass.**

Two bounded audits were run against the diff since the last review:

1. **Full naming audit of the new MCP-First Controlled Canary surface**, the largest new user/operator-
   facing vocabulary introduced since the last review. Three concept groups that could plausibly have
   collapsed into loose synonyms were checked end-to-end across Go internals, root wiring, the admin API
   (`ui_mcp_tooltrust.go`), and all three new docs (`docs/adr/0035-mcp-canary-execution-architecture.md`,
   `docs/design/mcp/CANARY-FIRST-RUNBOOK.md`, `docs/operator/mcp-first-controlled-canary-review.md`), and
   each turned out to be genuinely distinct, consistently-applied concepts rather than drift:
   - **"Canary"** (the overall architecture/phase) vs. **"First Canary"** (the deliberately narrower,
     exact-scope gate for the one initial experiment — explicitly called out in the ADR itself as "a
     SEPARATE predicate on purpose," `docs/adr/0035-mcp-canary-execution-architecture.md:96-106`) vs. the
     **"MCP First Controlled Canary Review"** document (the authorization gate for that same First-Canary
     experiment). All three are used consistently for their own, distinct referents everywhere checked.
   - **"Tool Trust"** (the subsystem, `internal/mcp/tooltrust`) vs. **"Tool Approval"** (the reviewed grant
     record, `tooltrust.ToolApproval`, exposed at `/api/mcp/tool-approvals`) vs. **"Reviewed Operation
     Class"** (a narrower field *on* a Tool Approval — the read/write/control classification stated at
     review time, `ToolApproval.ReviewedOperationClass`) — three altitudes of one coherent hierarchy, not
     rival names for one thing. Test-file phrases like "trust binding" / "atomic binding" describe
     behavior, not a fourth noun; no production code or doc promotes them to first-class vocabulary.
   - **"Live Gate"** (the execution-layer admission check, `internal/mcp/execution/livegate.go`) vs. **"Live
     Execution"** (a `tooltrust.Purpose` value/tier name) vs. **"Read-First"** (the classifier in
     `mcp_canary_read_first.go`, used uniformly ~30+ times in the operator doc) — no cross-contamination
     found between the three.
   No new `culvert_mcp_*` metrics were introduced in this window (the only `metrics.go` change wires
   pre-existing OCSP counters), so there was nothing new to check on that surface.
2. **Spot-check of the smaller, already-CLAUDE.md-documented changes** for any new user-facing vocabulary:
   OCSP's new admin JSON fields (`unauthorizedResponderTotal`, `responderBlockedTotal`, etc. in
   `ui_security.go`) are consistent camelCase renderings of the exact Go method/metric names already
   documented in `docs/operator/ocsp-revocation-checking.md` — casing only, not a wording difference, and
   therefore out of this program's scope by its own established rule. The rate-limit exempt-view change
   (`security.go`'s `rlExemptView`/`loadExemptView`) and the SOCKS5 log-injection fix are both internal-only
   with no new GUI/API/doc/metric surface, so — per the 2026-09-11 report's rule that internal reliability
   engines with no independent admin surface are not findings — neither is in scope.

**Carry-over backlog re-verified, one item's evidence base updated (no change to its finding or priority).**
T-29 (`rate_limit`/`rate_limit_rpm`) was re-checked directly against the current tree and is unchanged
(`config.go:56` vs. `admin_settings.go:34`/`config_surfaces.go:214-221`). T-39 (bare "qualification" config
keys) is also unchanged in its core citations (`config.go:237,250,261-277`), but this window added more
reason-code strings sharing the same unqualified "qualification" prefix (`mcp_observe_startup.go:171-213`,
`mcp_policy.go:145-341`: `qualification_inventory_invalid`, `qualification_policy_uncompilable`,
`qualification_policy_traversal`, etc.) — the same underlying naming gap, now with a slightly larger
footprint, not a new finding and not a change to T-39's recommended action or priority.

**Terminology Health Score: 8.7 / 10** (unchanged from 2026-09-08 through 2026-09-11). A 95-file,
security/reliability-heavy window — including a brand-new, multi-layer MCP feature with real potential
for concept-name collapse — introduced no new drift, which is itself a notable data point in the new
frontend/MCP work's naming discipline. The unchanged carry-over backlog means the score does not move.

---

## Carried-Over Findings (unchanged)

All fourteen previously-open finding IDs (thirteen backlog entries, since T-21 and T-32 are tracked as one
paired item) remain open, unchanged, and re-confirmed against the current tree:
T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21+T-32 (paired), T-25 (residual), T-29, T-30, T-33, T-34,
T-39 (evidence base for T-39 grew slightly this pass — see above; its finding, name, and priority are
unchanged). Full descriptions and the priority-ordered refactoring plan are unchanged from
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md` and are not restated here to avoid drift between two
descriptions of the same open items — see that report (or its predecessors, cited therein) for the
canonical text of each.

The "Content & Scanning" vs. "Content Security" soft finding (design-document reconciliation between two
deliberate naming decisions, not a mechanical rename) also remains unresolved and is not queued to the
numbered backlog, per 2026-09-09's reasoning.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 2026-09-09/09-11 — no item moved this pass. See either report for the full table.

---

## Stop-Condition Assessment

No production-worthy NEW terminology improvement was identified this pass: the 9-merge window audited
introduced a substantial new admin/operator-facing feature (MCP-First Controlled Canary, ADR-0035) whose
naming was checked in depth across code, API, and three new docs, and found internally consistent
throughout — the Canary/First-Canary/Review trio, the Tool-Trust/Tool-Approval/Reviewed-Operation trio, and
the Live-Gate/Live-Execution/Read-First trio are each genuinely distinct concepts used consistently, not
drift. The remaining window (OCSP, rate-limit exempt-view, SOCKS5 logging) introduced no new user-facing
vocabulary. The fourteen-ID (thirteen-entry) carry-over backlog is unchanged; T-39's evidence was refreshed
without changing its finding or priority. No cosmetic or preference-driven renames are proposed. This
report itself — the audit record and backlog reconciliation — is the deliverable of this pass; per the
DEBT-014 process lesson, it was written only after a fresh sync against `origin/main` immediately before
opening its PR.
