# M1+M2 Implementation Report — Culvert Admin Console Redesign

Status: foundation slices complete, awaiting review (no PR opened)
Date: 2026-07-11
Branch: `claude/culvert-gui-redesign-1qo2n8`

---

## 1. Files changed

| Commit | Files | What |
|---|---|---|
| `80e6cab` | `docs/design/*` (7 new docs) | Discovery + design program documentation |
| M1 slice | `static/index.html` | Design tokens, app shell, dashboard posture strip, safety fixes |
| M2 slice | `static/index.html` (+435/−71 net with M2), `static/chart.umd.js` (new, 205 KB), `ui_middleware.go` (1 line), `docs/design/UX-PRINCIPLES.md` (tier table sync) | Air-gap, shared component layer, danger-tier confirmations |

No route, handler, policy-semantics, or data-model changes. The only Go change
is the CSP header losing `https://cdn.jsdelivr.net` from `script-src`.

## 2. Technical debt removed

- **CDN runtime dependency eliminated** — Chart.js 4.4.0 is embedded
  (`static/chart.umd.js` via the existing `//go:embed static`); CSP tightened
  to pure same-origin scripts. The admin UI now has **zero external runtime
  dependencies** (verified: page loads and charts draw with all outbound
  traffic blocked).
- **Undefined CSS tokens fixed**: `--surface1` (never defined), `--card` and
  `--danger` (light-mode only — dark-mode dialogs rendered broken).
- **Undefined button variants** `.btn.primary/.accent/.warn` now exist.
- **Native `confirm()`/`prompt()` fully eliminated** (4 sites → shared dialog).
- **Two functional bugs fixed** that made features throw before their API call:
  `apDeleteRule` (undefined `confirmDialog`) and `toggleBlocklistMode`
  (undefined `next` variable) — auth-rule deletion and blocklist-mode toggle
  were both broken in production.
- **CDN-failure fragility fixed**: a missing Chart.js no longer kills the whole
  init chain (SSE/polling survived only by accident before; now guarded).
- Copy-paste empty-row markup replaced by `tableRows`/`emptyRow` in the
  adopted views; the never-used `.spinner` gap replaced by `.skeleton`.
- Phantom `Inter` font reference removed (system font stack token).
- Hardcoded Chart.js colors → token-driven `chartTheme()` with live re-theme.

## 3. Remaining technical debt (tracked in REDESIGN-ROADMAP.md)

- ~1,300 inline `style="` attributes outside the M1/M2-touched regions
  (migrating opportunistically per the boy-scout rule; bulk sweep is M5).
- Most list views still use bespoke row renderers — `tableRows` adopted in
  users/lockouts as the reference implementation; per-view adoption is M2+
  continuing work (policy/cluster/CDR renderers are pinned-region-adjacent
  and migrate with their own slices).
- IdP modal not wired to the shared modal mechanics (its JS is byte-pinned by
  `ui_idp_secret_redaction_test.go`; needs a coordinated test-update slice).
- No URL routing/deep links yet (M2 backlog), no draft state or shadow-rule
  detection (M3, backend dependency), Settings still one monolithic view (M4).
- 500-line `data-click` dispatch switch remains (works, CSP-safe, but a
  maintainability bottleneck).

## 4. UX improvements

- **Danger-tier confirmation system** (see §6) with impact / rollback /
  typed-word gating in one consistent dialog.
- `promptAction` input dialog replaces browser prompts — styled, labeled,
  Enter-to-submit, Esc-to-cancel; node revocation now explains that the
  reason is recorded in the revocation log.
- Posture strip answers "is Culvert operational / do I need to act" on the
  first screen, from real endpoints only; degraded states are text + color.
- Connection-loss banner when polling gives up (was silent).
- Consistent empty states with next-step hints (users/lockouts reference).
- Getting-started, CA-expiry, and metric cards carry definitions and
  drill-downs.

## 5. Security improvements

- **CSP hardened**: `script-src 'self' 'nonce-…'` only — no third-party
  script origin left. Removes the jsdelivr supply-chain and availability
  dependency from a security appliance's admin console.
- **Air-gapped operation verified end-to-end** (deployment environments
  without internet no longer lose charts or — pre-M1 — the whole dashboard
  init).
- **Lockout-class actions now require typed confirmation** (§6) — misclicks
  can no longer flip the global auth gate, rotate the session key, or
  restrict admin IPs.
- `toast()` HTML-escapes server-provided error text (CWE-79 hardening).
- Broken confirmations fixed means two destructive paths (auth-rule delete,
  blocklist-mode flip) now actually execute *with* their guard instead of
  throwing.

## 6. Danger-tier coverage (the audit's high-blast-radius list)

| Action | Tier | Confirmation | Impact & rollback stated | Audit note |
|---|---|---|---|---|
| Default auth outcome | 3 | type `OPEN`/`REQUIRE` | ✅ | "recorded in audit log" |
| Blocklist↔allowlist mode | 3 | type `ALLOWLIST`/`BLOCKLIST` | ✅ | ✅ |
| Session signing key rotation | 3 | type `ROTATE` | ✅ (self-logout called out) | ✅ |
| Admin IP allowlist | 3 | type `RESTRICT`/`OPEN` | ✅ (lockout recovery path) | ✅ |
| Enable Control Plane | 3 | type `ENABLE` | ✅ | ✅ |
| Enable HA | 3 | type `ENABLE` | ✅ | ✅ |
| Import cluster CA | 3 | type `IMPORT` | ✅ | ✅ |
| HA promote (was native confirm) | 3 | type `PROMOTE` | ✅ (split-brain) | ✅ |
| Root CA rotation | 3 | existing two-phase server token flow (kept) | ✅ | ✅ |
| Default action flip | 2 | impact confirm | ✅ | ✅ |
| Upstream add/remove | 2 | impact confirm (last-proxy case called out) | ✅ | — |
| SSL-bypass add | 2 | impact confirm | ✅ | — |
| Node revoke | 2 + reason | promptAction with recorded reason | ✅ | reason persisted via `/api/cluster/revoke` |
| Config rollback/import, purge, deletes | 1/2 | existing `confirmAction` (kept) | partial | — |

## 7. Performance impact

- One extra same-origin request on first load (`chart.umd.js`, 205 KB,
  replacing the same bytes from the CDN); served from the embedded FS.
- Shell size +~9 KB (icons sprite + component CSS/JS). No new polling, no new
  endpoints, no change to tick/SSE cadence. Charts unchanged (`update('none')`).
- Focus-trap listeners attach only while a modal is open.

## 8. Accessibility improvements

- Nav: `role="button"`, `tabindex="0"`, Enter/Space activation,
  `aria-current="page"`, focus-visible rings; `<nav aria-label="Primary">`.
- Dialogs: `role="dialog"`, `aria-modal`, focus trap (Tab/Shift-Tab wrap),
  initial focus, focus restore on close, Esc-to-close — including from a
  focused input (Esc previously dead inside inputs).
- Toasts: `aria-live="polite"` region.
- Status is never color-only: posture/badges/dialog tiers pair color with
  text; typed-confirm gate is a labeled input.
- `prefers-reduced-motion` honored.

## 9. Regression evidence

- `go build` ✅ · `go vet` ✅ · full root-package `go test` ✅ (~80 s, includes
  D0/C1/C1.5/C2/C2c/C4 governance suites and the four markup-pinning test
  files).
- Browser regression (Playwright driving the real binary):
  CSP contains no CDN origin ✅ · `chart.umd.js` 200 + canvas draws pixels ✅ ·
  typed-gate disabled → wrong word disabled → correct word enabled ✅ ·
  Esc cancels from focused input ✅ · promptAction round-trip creates a
  category ✅ · user modal initial focus + Esc ✅ · keyboard nav + aria-current
  ✅ · dark and light themes ✅ · zero page errors ✅.
- Screenshots: dashboard (dark/light, live data), Tier-3 dialog, prompt
  dialog, blocklist-mode dialog, Traffic view, Administrators view.

## 10. Ready-for-review checklist

- [x] Air-gapped: zero external runtime dependencies
- [x] Shared components: dialog (3 tiers + prompt), modal mechanics, table
      rows/empty/skeleton, status badges
- [x] Every audit-identified lockout-class action typed-confirmed
- [x] All pinned tests green; no backend contract changes
- [ ] Draft PR — awaiting reviewer decision
