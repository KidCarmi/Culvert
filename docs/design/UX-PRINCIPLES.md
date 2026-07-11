# Culvert UX Principles

Status: Phase 3 deliverable of the GUI redesign program
Date: 2026-07-11

These are Culvert-specific rules. Each cites the current behavior it corrects.
"MUST" rules gate redesign PRs; "SHOULD" rules guide but don't block.

---

## 1. Security posture is ambient, not buried

Security-critical state MUST be visible without opening multiple screens:

- The dashboard opens with a **posture strip** (traffic flowing? engines
  healthy? CA valid? logs persisting? updates current?) computed from real
  endpoints only: `/api/stats.logWriteErrors`, `/api/dashboard/health.logStore`,
  `/api/ca-cert.notAfter`, SSE `updateAvailable`, `/api/diagnostics`.
- Degradations that today live only in Diagnostics (risky-mode warnings) or in
  raw JSON (`logWriteErrors`) surface as dashboard "needs attention" items with
  a drill-down link.
- The LIVE/STALE pill stays global (topbar). When the tick loop pauses after
  repeated failures (`TICK_MAX_ERRORS`), the UI MUST show a visible banner, not
  just a paused counter (today: silence).

## 2. Policy rows state their full contract

Every policy list (Access Rules, Authentication Rules) MUST show per rule:
**priority · name · scope (source) · match (destination/conditions) · action ·
enabled state · hit count**. The backend already provides all of these
(`PolicyRule`: `priority, name, sourceIP/Identity/Group, destFQDN/Category,
action, enabled, hitCount`). "Last modification" is NOT shown as a column —
`PolicyRule` has no timestamp field; the Audit Log is the truthful source and
each rule row links to its audit trail instead (label: "History"). Do not
fabricate a modified-at.

A rule whose `enabled=false` MUST be visually distinct in *shape* (dimmed +
"Disabled" badge), not color alone.

## 3. Danger tiers: confirmation must scale with blast radius

Three tiers, applied consistently (today coverage is inverted — see
`CURRENT-UI-AUDIT.md` §5):

- **Tier 1 — routine destructive** (delete one host/rule/webhook): standard
  `confirmAction` modal naming the object.
- **Tier 2 — service-impacting** (default action flip, upstream chain change,
  SSL-bypass add, engine enable/disable, purge): `confirmAction` with an
  explicit **impact statement** ("All traffic not matching a rule will be
  DENIED starting immediately"), the affected scope, and the rollback path.
- **Tier 3 — lockout/trust-breaking/outage-capable** (default auth outcome,
  blocklist↔allowlist mode, session-secret regen, admin IP allowlist, CA
  rotation, cluster CA import, HA enable/promote, control-plane enable):
  **typed confirmation** (the CA-rotation two-phase pattern at
  `static/index.html:10290` generalized — dry-run/preview response where the
  backend supports it, otherwise type-the-word confirm via `confirmDanger`) +
  statement of the recovery path ("You will be signed out. All admins must
  sign in again.").

Native `confirm()`/`prompt()` are banned; the 4 remaining sites migrate to the
shared dialog.

## 4. Empty states teach

Every table/panel empty state MUST say (a) what this list is, (b) the first
step to populate it, with an inline action or link. Model: the existing
Getting-Started banner (line 483). Anti-model: bare "No policy rule hits yet".
One shared `.empty-state` component; no hand-rolled `<td colspan>` variants.

## 5. Errors say what/why/next/state

Error surfaces MUST answer: what failed, likely cause, what the user can do,
and whether config was preserved. Concretely:

- `api()` error toasts keep the server text but get a prefix naming the
  operation ("Saving rule failed: …").
- Silent `catch(_){}` on user-initiated actions is banned (background polling
  may stay silent but must flip the STALE indicator).
- Import/rollback/update flows MUST state persistence outcome explicitly —
  the backend is fail-closed almost everywhere ("existing catalog untouched",
  "config preserved"); the UI must say so instead of leaving doubt.
- Toast text MUST be HTML-escaped (today `toast()` injects raw `err.message`).

## 6. Tables are operational instruments

Standard table contract (shared component, M1+): search where >10 rows are
realistic; column sort where the data is client-side; pagination consistent
with the endpoint (server paging for `/api/logs` store mode and blocklist;
client paging elsewhere); bulk actions only where the backend supports bulk
(blocklist bulk delete exists; policy bulk does NOT — don't fake it with N
serial calls in M1); CSV/JSON export where the endpoint exists (`/api/logs`,
`/api/config/export`) — no client-side fake exports of truncated data.

## 7. Policy editing: visible consequences before persistence

- Reorder via drag persists immediately today. MUST add: an explicit
  "Save order / Revert" commit step, or (interim, M1) a confirmation toast with
  one-click Undo that restores the previous permutation (the full permutation
  is already known client-side).
- The editor MUST keep an unsaved-changes warning when switching views with a
  dirty form (today: silent loss).
- Simulation: the Policy Tester stays one click away from any rule (prefilled
  with that rule's conditions). Draft/staging state and conflict detection
  need backend support → recorded as *backend dependency* in the roadmap, not
  faked client-side.

## 8. Monitoring rows lead with triage fields

Request/event rows: **time · source (IP/identity) · destination · action badge
· rule (as drill-down chip) · engine/reason · level**. Reason strings come from
the backend's `ruleMatched`/scan verdicts — never synthesized. Every row
expands to a detail panel (full URI when `logFullUri`, bytes, duration,
country) instead of truncating into tooltips.

## 9. Never color alone

Every status indicator pairs color with a text label or distinct glyph. Badges
already carry text — keep. The `dot` health indicators and `levelBadge` gain
text/shape. Charts get direct labels/legends, not color-only series.

## 10. No decoration, no theater

- No gradients, glassmorphism, or oversized hero cards. Neutral surfaces,
  1px borders, restrained radius (see `DESIGN-SYSTEM.md`).
- No metric appears without: definition (tooltip/`title`), real data source,
  timeframe, drill-down, and an explicit empty/unavailable state.
- If data is delayed, partial, or sampled (e.g. `topHosts` decay past 10k cap,
  audit ring bounded at 500), the UI says so inline ("approximate beyond 10k
  hosts", "in-memory ring — last 500 events; full history in file source").

## 11. Progressive disclosure by role

Viewers see read-only surfaces with controls hidden by `data-min-role` (status
quo) — but M2 replaces *hiding entire nav sections* with visible-but-labeled
"view only" for monitor-class content, so a viewer can still see posture. The
server's `requireRole` remains the enforcement layer; the client never treats
hiding as security.

## 12. Keyboard and screen-reader floor

M1 floor (enforced by the redesign quality gate):
- Nav items focusable and Enter/Space-activatable (`tabindex="0"`,
  `role="button"`, delegated keydown), `aria-current="page"` on the active item.
- Modals: `role="dialog"`, `aria-modal`, initial focus, Esc close, focus return.
- Toasts render into an `aria-live="polite"` region.
- Focus-visible ring on every interactive element (token `--focus-ring` exists;
  apply to nav/selects/chips, not just `.btn`/`.input`).
- All form labels associated via `for`/`id`.
