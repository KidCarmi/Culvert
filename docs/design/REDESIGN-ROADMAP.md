# Culvert GUI Redesign Roadmap

Status: Phase 5 deliverable of the GUI redesign program
Date: 2026-07-11

> **2026-08-21 — Strategy statement below SUPERSEDED (pending review).** The
> "framework rewrite is rejected" position was recorded here in prose and never
> as an ADR. `docs/adr/ADR-FE-001-frontend-platform.md` (Proposed) re-evaluates
> it under changed premises (no production customers; DOM compatibility and
> markup-pinned tests explicitly non-binding) and proposes a React+TS+Vite
> replacement; see `docs/design/FRONTEND-MIGRATION-PLAN.md`. The milestone
> history and the M4/M5 open items below remain accurate as a record and as
> backlog input. Rationale preserved intact below.

Strategy: **incremental redesign inside the existing single-file vanilla-JS
architecture.** A framework rewrite is rejected: the SPA is embedded via
`go:embed` with a CSP-nonce pipeline, multiple Go test suites pin exact markup
substrings and Playwright selectors, and there is no node toolchain in CI.
Incremental migration is objectively safer and preserves every workflow.

Global constraints for every milestone (from `CURRENT-UI-AUDIT.md` §6):
keep `.nav-item[data-view=…]` + `data-min-role` mechanics; keep element IDs
consumed by JS; do not reformat the JS regions pinned byte-wise by
`authpolicy_phase*_test.go` / `ui_idp_secret_redaction_test.go`; no route or
policy-semantics changes without their own metadata + tests; `go build` +
`go test` green per batch.

---

## M1 — Foundation: tokens, shell, dashboard, safety fixes  ← FIRST SLICE

**Scope**
1. Design-token layer (`DESIGN-SYSTEM.md` §2) with legacy aliases; fixes the
   `--card`/`--danger`/`--surface1` undefined-token bugs and the undefined
   `.btn.primary/.accent/.warn` variants; system font stack; chart theming
   helper.
2. App shell: sidebar regrouped to the new IA (`INFORMATION-ARCHITECTURE.md`
   §2 — same `data-view` names, new sections/labels/order), SVG icon sprite
   replacing emoji, keyboard-accessible nav (`tabindex`, `role`,
   `aria-current`, Enter/Space), topbar polish.
3. Overview dashboard: posture strip ("operational / traffic / engines / CA /
   logging / updates" from existing endpoints only), restructured metric
   cards (definitions via `title`, drill-down links), consistent panels,
   inline-style removal on this screen; all existing element IDs kept.
4. Safety fixes: `apDeleteRule` broken `confirmDialog` → `confirmAction`
   (restores auth-rule deletion); `toast()` HTML-escaping; `governance` entry
   added to `viewMeta`; skeleton/empty-state components.

**User value**: first-screen posture answers "do I need to act?"; professional
shell raises perceived (and real) product maturity; one actual broken workflow
repaired.
**Complexity**: medium (CSS-heavy, minimal JS surgery). **Risk**: low —
behavior-preserving, selector-preserving. **Dependencies**: none.
**Acceptance**: `go build` ok; `go test` UI suites green (D0, C1, e2e static
substrings); nav keyboard-operable; dashboard shows posture strip with live
data; dark and light themes both render the confirm dialog correctly (bug
regression check).
**Migration**: single PR, screen-level review with before/after screenshots.

## M2 — Interaction layer: tables, modals, confirmations, monitor

**Scope**: shared `renderTable()` helper adopted by users/lockouts/top-rules/
audit first; shared modal mechanics (focus trap, Esc, aria); danger-tier
confirmation system (typed confirm for Tier 3 — default auth outcome,
blocklist mode, session secret, admin IP allowlist, cluster enable/HA/CA,
upstream replace); Traffic (livefeed) triage upgrade: row expand → detail
drawer, action/engine badges, rule chip → policy drill-down; audit log
server-side paging params already supported (`offset/limit/from/to`) wired
into the UI; hash-based deep links (`#/view/<name>`); unsaved-changes warning
on policy/authpolicy forms; reorder commit/undo.
**User value**: daily triage and safe change management.
**Complexity**: medium-high. **Risk**: medium (touches many views) — mitigated
by per-view adoption. **Dependencies**: M1 tokens/components.
**Acceptance**: zero native `confirm()`/`prompt()`; all Tier-3 actions show
impact statements; livefeed row → drawer works with keyboard; e2e suites green.

## M3 — Policy suite: rule list, editor, tester integration

**Scope**: Access Rules list redesigned (scope/match/action/hits columns,
disabled-rule treatment, per-rule History → filtered audit view, "Test this
rule" → prefilled Policy Tester); editor with human-readable rule summary and
validation before save; decision-trace viewer shared by tester + livefeed
drawer; Authentication Rules aligned to the same patterns.
**Backend dependencies (explicitly out of UI scope, need design records):**
draft/staged policy state; shadow-rule/conflict detection; per-rule
modified-at timestamps.
**Acceptance**: policy CRUD/reorder/test flows covered by Playwright e2e;
`authpolicy_phase*` substring tests updated only where copy changes are
deliberate.

## M4 — Platform & settings decomposition

**Scope**: Settings split per `INFORMATION-ARCHITECTURE.md` §5; Certificates +
CA Management merged into one "Certificates & CA" view; cluster screen
restructured (nodes table + health roll-up per `PRODUCT-TERMINOLOGY.md`
Health scale); diagnostics feeds the dashboard posture strip; Updates/
Releases visual alignment (M3 backend direction decides an eventual merge).
**Risk**: high pinned-ID density in settings — done view-by-view.

## M5 — Consistency sweep & hardening

**Scope**: remaining inline-style migration; legacy token-alias removal;
accessibility audit against `UX-PRINCIPLES.md` §12 floor; terminology sweep
against `PRODUCT-TERMINOLOGY.md`; Playwright coverage for every dangerous
workflow's confirmation; visual regression baseline (playwright screenshots
in `proxy-ui-e2e.yml`).

## Future product concepts (NOT in scope; require backend design records)

- Reports section (generation/scheduling backend does not exist)
- Incident entity/lifecycle
- Policy draft/approval workflow
- Real-time streaming of request rows over SSE (today counters only)
- Session-expiry warning requires a session-TTL introspection endpoint

## Risks & open decisions

| Risk | Mitigation |
|---|---|
| Pinned-substring tests break on JS edits | Batches never reformat pinned regions; run the four pinning test files per batch |
| 635 KB single file grows further | CSP allows same-origin assets; M2 may extract `app.css` via a second embedded file — decision deferred until M1 measures diff pain |
| Playwright e2e are nightly, not per-PR | run `ui_*_e2e_test.go` locally per batch (they skip without a browser; CI has one in `proxy-ui-e2e.yml`) |
| Emoji→SVG changes visual diffs massively | screenshots attached per PR; sprite ids stable |
| Renamed nav labels confuse existing users | `viewMeta` keeps old names in panel meta line for one release ("formerly Live Feed") — cheap, removable |
