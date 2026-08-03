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
