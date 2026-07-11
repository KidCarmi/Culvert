# Culvert Design System

Status: Phase 4 deliverable of the GUI redesign program
Date: 2026-07-11
Implementation: the token layer lives at the top of the main `<style>` block in
`static/index.html` (`:root` + `html[data-theme="light"]`). No build step; no
external assets beyond the existing Chart.js CDN. Legacy token names are kept
as aliases so the ~1,386 existing inline styles keep resolving while they are
migrated screen-by-screen.

---

## 1. Principles

- **Semantic tokens only in components.** Components reference `--crit`, never
  `#ef4444`. Raw values live only in the token block.
- **Dark is the primary theme** (operations rooms), light is fully supported.
  Every token is defined in **both** themes — the `--card`/`--danger`
  dark-mode gap class of bug is structurally prevented by keeping the two
  blocks field-for-field parallel.
- **Dense but readable**: 13–14px operational text, 4px spacing grid,
  restrained radius, 1px borders over shadows.
- **No decoration**: no gradients, no glassmorphism, shadows only on floating
  layers (modals, menus).

## 2. Token reference

### Typography

| Token | Value | Use |
|---|---|---|
| `--font-ui` | `system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif` | everything (the phantom, never-loaded `Inter` reference is removed) |
| `--font-mono` | `ui-monospace, 'SF Mono', 'Cascadia Mono', Menlo, Consolas, monospace` | hosts, IPs, hashes, code |
| `--fs-xs` | `.72rem` | table headers, badges, captions |
| `--fs-sm` | `.8rem` | secondary text, dense table cells |
| `--fs-md` | `.875rem` | body, inputs, buttons |
| `--fs-lg` | `1rem` | panel titles, topbar title |
| `--fs-xl` | `1.25rem` | page headings |
| `--fs-2xl` | `1.75rem` | metric values |

Metric values use `font-variant-numeric: tabular-nums`.

### Spacing (4px grid)

`--sp-1: 4px` · `--sp-2: 8px` · `--sp-3: 12px` · `--sp-4: 16px` ·
`--sp-5: 20px` · `--sp-6: 24px` · `--sp-8: 32px`

### Radius & elevation

| Token | Value | Use |
|---|---|---|
| `--r-sm` | `4px` | badges, chips, code spans |
| `--r-md` | `6px` | buttons, inputs, selects |
| `--r-lg` | `10px` | cards, panels, modals |
| `--r-full` | `999px` | pills |
| `--shadow-1` | subtle | dropdown menus |
| `--shadow-2` | pronounced | modals only |
| (alias) `--radius` | `= --r-lg` | legacy compat |
| (alias) `--shadow` | `= --shadow-2` | legacy compat |

### Color — surfaces & text

| Token | Dark | Light | Use |
|---|---|---|---|
| `--bg` | `#0b0f1a` | `#f3f4f6` | app background |
| `--surface` | `#111827` | `#ffffff` | panels, cards, sidebar |
| `--surface1` | `#151d2e` | `#f9fafb` | modal bodies, inset sections (**was undefined — bug fix**) |
| `--surface2` | `#1a2235` | `#f9fafb` | hover, nested wells |
| `--card` | `= --surface` | `#ffffff` | legacy alias (**was light-only — bug fix**) |
| `--border` | `#1e2d42` | `#e5e7eb` | default 1px lines |
| `--border-hi` | `#2d3f5a` | `#d1d5db` | hover/emphasis borders |
| `--text` | `#e2e8f0` | `#1f2937` | primary text |
| `--muted` / `--text-muted` | `#8892a8` | `#6b7280` | secondary text |

### Color — brand & status

| Token | Dark | Light | Meaning |
|---|---|---|---|
| `--accent` | `#14b8a6` | `#0d9488` | brand/primary actions |
| `--accent2` | `#2dd4bf` | `#0f766e` | brand emphasis text |
| `--accent-hover` | `#0ea395` | `#0f766e` | button hover (**was hardcoded**) |
| `--ok` (alias `--green`) | `#22c55e` | `#16a34a` | healthy / allowed |
| `--warn` (alias `--yellow`) | `#eab308` | `#ca8a04` | degraded / caution |
| `--crit` (aliases `--red`, `--danger`) | `#ef4444` | `#dc2626` | down / blocked / destructive (**`--danger` was light-only — bug fix**) |
| `--orange` | `#f97316` | `#ea580c` | auth failures / high severity |
| `--info` | `#60a5fa` | `#2563eb` | informational |
| Tints: `--accent-tint`, `--ok-tint`, `--warn-tint`, `--crit-tint`, `--orange-tint`, `--info-tint` | `rgba(x,.12)` | `rgba(x,.10)` | badge/pill/banner backgrounds (replaces dozens of literal `rgba()`) |

**Status → color mapping is fixed product-wide**: Healthy/Allowed = ok,
Degraded/Warning = warn, Down/Blocked/Destructive = crit, Auth = orange,
Info/Neutral = info/muted. Never color-only: every status pairs with a text
label (see `UX-PRINCIPLES.md` §9).

### Layout

`--sidebar-w: 232px` · content max-width: none (operational screens use full
width); prose-heavy panels cap at `72ch`. Breakpoints stay as today: 1200px
(card grid 3-col), 860px (sidebar off-canvas, 2-col), 640px (tight padding),
500px (1-col).

### Focus / disabled / motion

- `--focus-ring: 0 0 0 3px rgba(20,184,166,.25)` applied via `:focus-visible`
  on **all** interactive elements (buttons, inputs, nav items, chips, rows
  with actions).
- Disabled: `opacity:.45; cursor:not-allowed` (existing `.btn:disabled`).
- Motion: 150ms ease transitions on background/border/color only. No movement
  animations except sidebar slide and toast entry. Respect
  `prefers-reduced-motion: reduce` by disabling non-essential transitions.

## 3. Component inventory

Existing components to keep (already classes in `index.html`): `.panel`,
`.panel-header`, `.panel-title`, `.panel-body`, `.card`, `.cards`, `.badge`,
`.pill`, `.btn` (+ `ghost`, `danger`, `sm`), `.input`, `.select`, `.filter-bar`,
`.form-group`, `.form-label`, `.tbl-wrap`, `.empty-state`, `.nav-item`,
`.nav-section`, `.toast`, `#confirm-dialog`.

Fixed in M1 (were referenced in markup but undefined in CSS):
`.btn.primary` (= solid accent, explicit), `.btn.accent` (outlined accent),
`.btn.warn` (solid warn).

New/normalized components (introduced with their first consuming slice):

| Component | Class | Slice |
|---|---|---|
| App shell (sidebar + topbar + content) | existing ids, restyled | M1 |
| Nav item with SVG icon | `.nav-item` + `<svg class="nav-ico">` | M1 |
| Posture strip | `.posture-strip`, `.posture-item` | M1 |
| Status badge | `.badge.{ok,warn,crit,info,neutral,auth}` | M1 |
| Metric card | `.card` + `.card-label/.card-value/.card-sub` | M1 |
| Health indicator (dot + label) | `.health` + `.health-dot` | M1 |
| Section heading | `.section-title` | M1 |
| Alert banner | `.banner.{info,warn,crit}` | M1 |
| Skeleton loader | `.skeleton` | M1 (replaces dead `.spinner`) |
| Data table (shared renderer) | `renderTable()` JS helper | M2 |
| Drawer (event/rule details) | `.drawer` | M2 |
| Modal (shared open/close/focus) | `.modal` | M2 |
| Confirmation dialog w/ impact + typed confirm | `#confirm-dialog` extension | M2 |
| Filter bar w/ chips | `.filter-bar` upgrade | M2 |
| Policy action badge | `.badge.action-{allow,deny,redirect,exempt,cr,sso}` | M2 |
| Rule reorder control (commit/revert) | `.reorder-bar` | M3 |
| Decision trace viewer | `.trace` | M3 |
| Where-Used list (generic dependency entries) | `whereUsedList(entries)` → `.where-used` | M3 contract, renders when the references endpoint lands |
| Timeline / audit metadata panel | `.timeline` | M3 |
| Code/JSON viewer | `.codeview` | M3 |
| Combobox / multi-select | upgrade of chip pickers | M3 |

### The Where-Used contract (dependency presentation)

Dependency surfaces are **generic by construction** — Culvert will
eventually answer "what depends on this object?" for any shared resource,
and the UI must not need a redesign when consumers beyond policy rules
appear. Binding rules:

- Input is always a list of generic consumer entries:
  `{consumerType, id, name, detail, view}` (see
  `POLICY-ARCHITECTURE-FUTURE.md` §3). `consumerType` is an open enum
  rendered as a type badge (`access-rule`, `auth-rule`, and later
  `pac`, `report`, `node-group`, …) — components switch on nothing.
- `whereUsedList(entries)` renders: type badge + name (navigates to `view`,
  anchored by `id` when deep links exist) + muted `detail` (which field
  references the object). Empty state: "Not referenced by anything".
- "Used by N" chips show a total across ALL consumer types, never a
  rules-only count.
- The same entry shape feeds delete-impact dialogs (the danger dialog's
  impact slot lists referents) — one contract, three surfaces.
- Outbound dependencies (what a rule/object itself references, with
  liveness) use the same visual row but are client-computed; do not fork
  the presentation.

## 4. Iconography

Emoji icons are replaced by an inline **SVG sprite** (`<svg style="display:none">
<symbol id="i-…">` at the top of `<body>`, referenced via `<svg class="ico">
<use href="#i-…"/></svg>`). 24×24 viewBox, `stroke="currentColor"`,
`stroke-width="2"`, `fill="none"` — consistent weight, inherits text color,
themes automatically. No icon font, no external requests (CSP-safe).

## 5. Charts

Chart.js colors move to a `chartTheme()` helper reading
`getComputedStyle(document.documentElement)` for token values, re-applied on
theme toggle. Grid/tick colors from `--border`/`--muted`. Doughnut/segment
palettes: ok/crit/orange for allowed/blocked/authfail (matches badges).

## 6. Migration rules

1. New/touched markup uses tokens + classes; inline styles are removed
   from any line a PR touches (boy-scout rule), never added.
2. Raw hex/rgba in JS-generated markup is migrated to badge/tint classes when
   the generating function is touched.
3. The token block is the only place raw color values may appear.
4. Legacy aliases (`--green`, `--red`, `--radius`, `--shadow`, `--card`,
   `--danger`, `--surface2`) are kept until the last consumer is migrated,
   then removed in one sweep with a grep-verified PR.
