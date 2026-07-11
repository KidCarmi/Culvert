# M1+M2 Foundation — Adversarial Self-Review

Reviewer stance: Staff Engineer reviewing another team's work, hunting for
reasons NOT to merge. Date: 2026-07-11. Scope: commits `9f80e86` (M1),
`69e7ac2` (M2), plus the fix commit produced by this review.

Verdict up front: **no blockers remain — mergeable as a Draft for review.**
One Blocker and four other issues were found *by this review* and fixed
before the PR was opened (§1). One High issue (modal stack) must be
redesigned **before M3's broad modal adoption**, but not before this merge
(§2-H1). The review actively exercised the running binary (browser probes,
header inspection, regex sweeps), not just the diff.

---

## 1. Found by this review and FIXED before the PR

| Sev | Finding | Fix |
|---|---|---|
| **Blocker** | `enableControlPlane` read `const btn = event.target` *after* the newly inserted `await confirmDanger(...)`. The ambient `window.event` only exists during dispatch, so after the await it is `undefined` → TypeError → **Control Plane enablement was broken by the M2 commit**. Found by grepping for ambient-event usage in every function I had inserted an await into. | Button gets an id; lookup by id. Lesson recorded: adding an `await` above existing lines requires auditing them for dispatch-scoped state. |
| High | **Zero test coverage for the new invariants.** Nothing pinned the CSP air-gap, the embedded chart asset, the native-dialog ban, or the Tier-3 coverage — all could regress silently in a repo whose culture is wall-tests for exactly this. | `ui_redesign_foundation_test.go`: CSP has no external origin (via the real middleware chain), markup has no external src/href, chart asset served + >100 KB + cached, shell `no-store`, component-layer markers, native-dialog regex ban, one marker per Tier-3 confirmWord. |
| Medium | **Posture strip lied when logged out**: a 401 from `/api/stats` rendered "Proxy: Unreachable" — the proxy was fine; the session was expired. Violates the project's own honest-state rule (UX-PRINCIPLES §1/§10). | 401 now renders `unknown / "Sign-in required"`; only transport/server failures render crit. |
| Medium | **No cache policy on the new 205 KB asset**: the embed FS has zero mod-times, so `http.FileServer` emits no validators — every dashboard load re-downloaded `chart.umd.js` in full. Conversely the nonce-bearing shell had no `no-store`; a cached shell would carry a dead nonce and block every script. | `Cache-Control: public, max-age=86400` on `/chart.umd.js`; `no-store` on the shell. Both pinned by the wall test. |
| Medium | **Supply-chain provenance of the vendored Chart.js was undocumented.** | Recorded here: `chart.js@4.4.0` from registry.npmjs.org (tarball integrity `sha512-vQEj6d+z0dcsKLlQvbKIMYFHd3t8W/7L2vfJIbYcfyPcRx92CsHqECpueN8qVGNlKyDcr5wBrYAYKnfu/9Q1hQ==`, verified by npm on fetch); `static/chart.umd.js` SHA-256 `321e3a3fa98da4aaa957d10be57cbb514de0989eed8f9d726b5d05902cd01904`; MIT header retained in-file. |

## 2. Open findings (classified, none blocking)

### High

- **H1 — Modal mechanics don't support nesting.** `_modalPrevFocus` is a
  single slot, and the Esc handler hardcodes the list of shared-managed
  modals (user/webhook/release-dispatch) — hidden coupling. I traced every
  current call site: **no flow opens a dialog on top of an open modal
  today**, so nothing is broken — but the first nested flow (e.g. a delete
  confirm inside the future policy editor drawer) will restore focus wrong
  and Esc will close the wrong layer. **Explicit call: redesign into a small
  modal stack/registry as the first task of M3, before any new modal
  consumers.** Not redesigned now because doing it without a consumer would
  be speculative API design.
- **H2 — The new interaction layer is not covered by CI browser tests.**
  My Playwright regression (typed gate, Esc-from-input, focus restore,
  air-gapped chart rendering) ran locally; `proxy-ui-e2e.yml` (nightly)
  doesn't know about the dialogs. Follow-up: port those assertions into the
  nightly suite. The Go wall tests cover the static invariants only.

### Medium

- **M1** — Background content is not `aria-hidden`/`inert` while a modal is
  open: keyboard focus is trapped, but a screen-reader virtual cursor can
  still wander behind the dialog. Fix alongside H1.
- **M2** — `tableRows` is adopted in only two renderers (users, lockouts);
  ~20 bespoke renderers remain, so two idioms coexist. Deliberate (each
  view migrates with its own slice; several are adjacent to byte-pinned JS),
  but it is real inconsistency until M3–M5 complete.
- **M3** — Danger-dialog copy (impact/rollback text) lives inline at call
  sites. At 12+ actions a drift risk; a `dangerousActions` metadata registry
  (uiRoutes pattern) would centralize it. Revisit when M3 adds more actions.
- **M4** — Color contrast has not been formally audited (`--muted` on dark
  surfaces is likely borderline AA for small text). M5 carries the audit;
  no *new* contrast pairs were introduced beyond the token values already
  shipping.
- **M5** — Charts have no non-visual alternative (no aria-label summary or
  data-table fallback).
- **M6** — CSP still carries `style-src 'unsafe-inline'` (pre-existing;
  ~1,300 inline styles make nonce'd styles a multi-slice program, not a
  quick fix — tracked in the roadmap M5).
- **M7** — Single `_confirmResolver` slot: two overlapping `confirmAction`
  calls would leak one unresolved promise. Pre-existing pattern; the dialog
  is visually modal so probability is low, but the M3 modal-stack redesign
  should absorb it.

### Low

- **L1** — SVG sprite uses `<use href>` (not `xlink:href`): requires
  Safari ≥12.1 / evergreen browsers. Acceptable baseline for a 2026 admin
  console; documented here as the compatibility floor. Same class:
  optional chaining, `:focus-visible`, `inset`.
- **L2** — `renderCountryChart` interpolates the GeoIP country name into a
  `title` attribute unescaped (MaxMind-sourced, not attacker-controlled;
  escape in the M3 sweep anyway) and keeps hardcoded teal rgba.
- **L3** — Posture-item `title` tooltips are mouse-only; the state text
  itself is accessible, so no information is lost.
- **L4** — Doughnut fill alphas are not re-themed on toggle (borders are);
  hues are identical across themes.
- **L5** — Emoji remain in toasts (✅/❌) and the theme toggle (🌙/☀️);
  consistent-iconography sweep is M5.

### Nice to have

- **N1** — Version-stamped chart filename (`chart-4.4.0.umd.js`) +
  `immutable` caching would make upgrades cache-perfect.
- **N2** — `badge()` helper adoption across the legacy `badgeHTML`/
  `levelBadge` call sites.
- **N3** — A `make update-chartjs` script documenting the vendoring
  procedure end-to-end.

## 3. Dimensions reviewed with no findings

- **Backward compatibility / upgrade-rollback**: no persisted-format, API,
  route, or cookie changes; `localStorage` key unchanged; downgrade to an
  old binary serves the old CDN-based shell independently. Legacy token
  aliases keep all untouched inline styles resolving.
- **Security regressions**: CSP strictly narrowed (removed an origin, added
  nothing); no new endpoints; RBAC untouched (all `requireRole` intact,
  `data-min-role` semantics preserved); `escHtml` coverage extended
  (toast, table helpers); no secrets in the diff.
- **Performance**: net-positive — CDN request eliminated, chart asset now
  cached, no new polling/endpoints, focus-trap listeners attach only while
  a modal is open. Shell grew ~9 KB (sprite + component CSS/JS).
- **Air-gap**: verified by running the binary with all outbound traffic
  blocked (charts render, zero console errors) and now pinned by tests.
- **Hidden coupling beyond H1**: pinned-test regions untouched (all four
  pinning suites green); `viewMeta`/nav/`data-view` contracts preserved and
  exercised by the existing Playwright selectors.

## 4. Trade-offs defended (alternatives considered and rejected)

- **Stay single-file** rather than extract `app.css`/`app.js` now:
  extraction is mechanical but would move every byte-pinned JS region and
  turn a reviewable diff into a whole-file rewrite. Scheduled as M3
  pre-work with a coordinated pinned-test update. Rejecting it *for this
  PR* is a reviewability decision, not an endorsement of 12.5k-line files.
- **Vendor the built chart.umd.js** rather than add an npm build pipeline:
  the repo has no node toolchain and CI has no npm lane; one MIT-licensed
  minified file with recorded integrity follows the existing
  `trusted_root.json` vendoring precedent. A build pipeline is a real
  architectural decision that deserves its own design record.
- **Typed-word client confirmation** rather than server-side two-phase
  tokens for all Tier-3 actions: the CA-rotation two-phase flow is the
  stronger pattern but requires per-action backend endpoints (dry-run +
  token verify). That is a backend scope decision recorded in the roadmap;
  the typed gate is the strongest purely-client control and never weakens
  the existing server-side RBAC/audit path.
- **Keep the `data-click` dispatch switch**: it is the CSP architecture
  (no inline handlers), and replacing it is orthogonal to the redesign.
