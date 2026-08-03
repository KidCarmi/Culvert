# MCP UX Prototype - Independent Review Log

Independent reviewer: a fresh principal product / UX architect agent that did not
author the prototypes. It inspected all 23 renders + 5 comparison sheets at real
resolution and verified every data claim against the real Go handlers and DTOs.

Copy rule in effect from this round on: no em dash characters in new UI copy or
new documentation (hyphen, colon, comma, or parentheses instead).

## Round 1

**Verdict: APPROVED WITH REQUIRED CHANGES.** Core direction approved (evaluated to
effective two-chip model, durability meters, real vs synthetic evidence badge,
blast-radius-before-promote, Production-LOCKED framing, calm/compact Culvert
identity). 11 required changes, concentrated on truthfulness, copy, accessibility,
and 1280px density.

Resolutions (all applied to the isolated prototype files only, then re-rendered):

1. **Per-node DP matrix / fleet counts must not be invented.** Added an honest
   `local only` empty-state to Command Center, Rollout, and Health (new renders
   `*-local-only.png`) shown when no CP to DP distribution is configured. The
   populated matrix is captioned as backed by an additive `GET /api/mcp/distribution/acks`
   over the real `publication.AckTracker`; node rows are never invented.
2. **Activity drawer fabricated per-call telemetry removed.** Deleted Latency,
   Upstream HTTP status, DP/node, Environment, and split request/response
   inspection rows (no source in the event store). Kept only fields present on
   `ExplanationView`. Added a source caption stating what is not shown and why.
3. **Non-existent actions removed.** Dropped Quarantine tool, Quarantine server,
   Revoke allowance, and Revoke credential profile from the drawer and the
   Emergency screen (no endpoint in V1). Kept only actions with real routes; added
   a caption saying so.
4. **68 em dashes removed** from all prototype copy (hyphen / colon / parentheses).
5. **Color-only severity fixed.** Needs-attention items now carry a text token
   (CRIT / WARN / INFO) beside the dot.
6. **1280 table density fixed.** Activity table now ellipsizes only the free-text
   columns (never the evaluated-to-effective column) and the detail panel is an
   overlay drawer so the table keeps full width. Added `activity-shadow-1280.png`
   and `command-center-1280.png` proofs: no mid-token wrapping.
7. **Accessibility.** Interactive elements use real buttons/links; a
   `:focus-visible` ring (the previously-unused `--focus-ring` token) and an
   `aria-live` region were added.
8. **Scope decomposition / blast counts** captioned as backed by an additive
   `POST /api/mcp/rollout/scope-preview`; hash/revision remain backed by the
   existing scope GET.
9. **Unbacked qualification gates** (supply-chain, privacy/support/ops readiness)
   are shown as a neutral "not measured in this build" state, not GO/NO-GO. The
   backed gates keep real GO/NO-GO and the real/synthetic badge.
10. **Recent important changes / approvals.** Removed the fabricated
    "tool quarantined" row; the feed is captioned as backed by an additive
    projection of `rollout.State.History()`, and pending-approval count is sourced
    from `GET /api/mcp/approvals`.
11. **Snapshot freshness.** "Snapshot: fresh" replaced with the real snapshot hash
    chip; a timestamp-based freshness label is noted as a minor additive field.

Additive read-only endpoints identified for production (bounded, RBAC, OpenAPI,
tests, redacted): `GET /api/mcp/distribution/acks`, `POST /api/mcp/rollout/scope-preview`,
decision entity filters on `GET /api/mcp/decisions`, and derived
`effective_action` / `shadow_override` on the decision list projection (computed
from the already-stored `action` + `execution_state`, no new telemetry).

Removed (cannot be truthful, no source and not planned for V1): per-call latency,
upstream HTTP status, DP-node attribution, and environment in the decision drawer;
quarantine and revoke actions.

## Round 2

**Verdict: APPROVED FOR IMPLEMENTATION.** The reviewer re-inspected all refined
renders and the changed source and confirmed every one of the 11 required changes
is resolved: fabricated-telemetry components are removed or gated behind an
honestly-labeled additive endpoint with a visible source caption, and the
local-only empty-states structurally prevent invented fleet data. No truthfulness
or safety blocker remains.

Three non-blocking nits (folded into the production implementation, not gating):
1. Add a "derived from reason_code" note to the drawer "Hard failure class" line
   (like the effective / shadow-override derivation note).
2. Mirror Health's per-field rollback-target caption in the blast-radius modal.
3. Keep a Playwright a11y proof at implementation (keyboard opens the drawer,
   focus ring visible, aria-live announces the confirm) since live-region behavior
   cannot be confirmed from a static render.

### Integration record (production gate passed)
- Latest main SHA at gate: `e0c2935` (origin/main)
- Prototype approval commit (audit branch): `e6204d6`
- Reviewer verdict: `APPROVED FOR IMPLEMENTATION`
- Approved render set: the 23 renders + 5 comparison sheets under
  `docs/design/mcp/ux-audit-assets/target-prototypes/` at commit `e6204d6`
- Production branch: `claude/mcp-ux-production-integration` (from `e0c2935`)
- The audit branch remains design evidence; production is NOT built on it.

### Approved components mapped to production PRs

| Component | Data source | PR |
|---|---|---|
| Status chips, desired/local/fleet triplet, as-of/stale, operator token labels, loading/empty/error/stale | presentation over existing GETs | PR-UX-1 |
| Command Center posture strip, needs-attention, recent-changes, next actions | composes `GET /api/mcp/{overview,health,rollout,distribution,approvals}` | PR-UX-2 |
| Activity table, evaluated to effective, detail drawer, DLP + hard-fail | `GET /api/mcp/decisions` + `/decision-explain`; effective/shadow_override derived client-side from real `action`+`execution_state` | PR-UX-2 |
| Entity pivots, evidence chain, related activity | additive decision entity filters on `/api/mcp/decisions` | PR-UX-3 |
| Dangerous-action dialog (quarantine/revoke deferred; demote/rollback/emergency/scope/promote) | existing mutation routes | PR-UX-4 |
| Mode ladder, triplet, scope editor, blast-radius preview, DP ack matrix, freshness | additive `GET /api/mcp/distribution/acks`, `POST /api/mcp/rollout/scope-preview`; existing scope PUT | PR-UX-5 |
| Qualification checklist, real/synthetic badge, publications + four-eyes | `GET /api/mcp/rollout/evidence`; existing publications routes | PR-UX-6 |
| Structured servers/tools, durability meters, management catalog, sim, config form | existing GET/PUT | PR-UX-7 |
| Deep-linking, a11y, responsive, token alignment, remove duplicate raw panels | presentation | PR-UX-8 |

Removed from production scope (no truthful source): per-call latency, upstream
HTTP status, DP-node attribution, environment in the decision drawer; quarantine
and revoke actions (would require new bounded mutations before appearing).
