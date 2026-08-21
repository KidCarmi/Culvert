# ADR-FE-001: Frontend Platform for the CULVERT Admin UI

- **Status**: Proposed (design round — awaiting external review; no implementation has begun)
- **Date**: 2026-08-21
- **Deciders**: awaiting review
- **Supersedes**: the un-ratified "no framework / vanilla JS" position recorded in prose in
  `docs/design/REDESIGN-ROADMAP.md` (lines 6–10), `docs/design/CURRENT-UI-AUDIT.md` (§0), and
  `docs/design/mcp/PRODUCTION-INTEGRATION.md` (§ non-negotiables). No ADR ever recorded that
  decision; `docs/design/M1-M2-SELF-REVIEW.md` itself notes a build pipeline "deserves its own
  design record". This is that record.
- **Related**: `docs/design/FRONTEND-CURRENT-STATE.md`, `docs/design/FRONTEND-MIGRATION-PLAN.md`,
  `docs/design/FRONTEND-SECURITY-CONTRACT.md`, `docs/design/FRONTEND-FEATURE-PARITY.md`,
  ADR-0018 (OpenAPI contract).

## Context

The admin UI is one embedded file, `static/index.html`: 21,565 lines / 1.26 MB — ~15,900 lines of
inline JS (833 functions, ~158 top-level mutable globals), ~840 lines of CSS across 5 `<style>`
blocks, ~4,800 lines of markup — plus a vendored Chart.js v4.4.0 (`static/chart.umd.js`, 205 KB)
and a 4.16 MB logo PNG. It implements 38 views, 189 API endpoints, a delegated `data-click`
dispatcher with a 324-case `switch`, two coexisting rendering styles (escaped-`innerHTML`
templates in the main script; `createElement`/`textContent` in the MCP script), 327 `innerHTML`
assignments, and 1,999 inline `style=` attributes that force `style-src 'unsafe-inline'` in the
CSP. There are no components, no modules, no types, no bundler, and no Node toolchain anywhere in
the repository.

The prior "no framework rewrite" position was rational when written: markup-pinned Go tests,
Playwright `#id` selectors, and no npm lane in CI made a rewrite look unsafe. The premises have
changed: there are no production customers, exact DOM compatibility is explicitly not required,
markup-pinned tests may be replaced, and the file has since grown ~1.8× past what that audit
measured. The single-file architecture is now the primary obstacle to the open items in the
repo's own design docs (M4 settings decomposition, M5 consistency/a11y sweep, inline-style
elimination, modal-stack completeness, per-panel URL routing) and to safe AI-assisted change: a
21k-line file with global mutable state has no isolation boundary for any edit.

Hard constraints that do NOT change (from `CLAUDE.md`, ADR-0018, and the CI contract):

1. **Single Go binary, air-gapped appliance.** All assets ship via `//go:embed` (`ui.go:35`).
   No Node, npm, CDN, external fonts, or remote assets at runtime — ever.
2. **Byte-reproducible release builds.** `pr-deep-gate.yml` builds the binary twice and
   sha256-compares. The frontend bundle is embedded in the binary, so the frontend build must be
   deterministic.
3. **Backend authority.** `uiRoutes` metadata (229 rows), the C2 enforcement middleware,
   handler-level `requireRole`, CSRF-by-Origin, session cookies, audit, and config versioning
   are untouched. The UI is presentation, not an authorization boundary.
4. **No backend API rewrite.** ADR-0018's hand-authored OpenAPI 3.0.4 contract over the existing
   handlers stands; its route-coverage exemptions expire 2027-01-31.
5. **CSP posture may only strengthen** (target: drop `style-src 'unsafe-inline'`, keep or tighten
   the script nonce model).
6. **"No Node in the fast gate"** (ADR-0018) is renegotiated by this ADR, not silently ignored:
   see "Build-time vs runtime" below for how Node enters CI without entering the appliance.

## Decision

Adopt the following platform for a clean parallel replacement of the embedded frontend:

| Concern | Decision |
|---|---|
| UI framework | **React 18/19** (function components + hooks only) |
| Language | **TypeScript, `strict: true`** (plus `noUncheckedIndexedAccess`) |
| Build | **Vite** (Rollup production build), pinned via `package-lock.json`; deterministic config |
| Styling | **CSS Modules + a shared design-token stylesheet** (custom properties); zero runtime CSS-in-JS |
| Server state | **TanStack Query** (polling, caching, invalidation, cancellation) |
| Client state | React context + reducers per feature; **no global store** (Redux/Zustand) without a demonstrated need |
| Routing | **React Router** (hash-free, real paths under the SPA fallback) |
| Forms | Local component state + a small shared form-field contract; no form library initially |
| Headless a11y primitives | Evaluate **Radix UI primitives** for Dialog/Menu/Tabs only; adopt per-component with justification, else hand-roll on the ARIA Authoring Practices |
| Charts | Keep **Chart.js v4** (already vendored, 2 charts today) as an npm dep, lazy-loaded with the dashboard chunk |
| API layer | One typed client in `frontend/src/api/`; **types generated from the committed ADR-0018 `api/openapi/openapi.json`** (334 of 343 live method-rows documented; deterministic, offline-consumable), with hand-authored types only for the 9 exempt rows until their exemptions close |
| Unit/component tests | **Vitest + Testing Library** (role/label queries only) |
| E2E | **Playwright (TS)** against the real Go binary with the embedded bundle; replaces the playwright-go `uie2e` suite incrementally |
| Lint/format | ESLint (typescript-eslint) + Prettier, both pinned |
| Node version | Pinned via `.nvmrc` + `package.json engines`; CI uses the same pin; **build-time only** |

### Why React + TypeScript + Vite (vs. the alternatives)

Evaluated against the required axes:

- **Svelte/SvelteKit, SolidJS, Vue**: all produce fine bundles; none offers a *materially
  stronger* case on the axes that matter for a 5–10-year security appliance: hiring pool and
  contributor accessibility (React's is the largest by a wide margin), AI-assisted engineering
  reliability (React+TS has the deepest training corpus and the most predictable idiom), a11y
  ecosystem (Radix/ARIA patterns, Testing Library), and TypeScript depth. Svelte 5 runes and
  Solid signals are attractive but smaller ecosystems with faster-moving idioms — a churn risk
  over a decade. Bundle-size deltas (~30–60 KB gz framework overhead for React) are immaterial
  for a same-host LAN admin UI that is served from the appliance itself and cached.
- **Lit / Web Components**: closest to "no framework", but weak form/routing/server-state
  ecosystem and materially worse AI/contributor familiarity; shadow-DOM styling complicates a
  token-based design system and Playwright/Testing Library ergonomics.
- **Preact**: React-compatible with a smaller runtime, but compat-layer risk against Radix/
  TanStack over years outweighs ~30 KB on an appliance-served asset.
- **Continue vanilla JS with incremental modularization**: rejected. The repo has already run
  this program (M1–M3); inline styles *grew* during it (1,386 → 1,999), and the remaining debt
  (typing, components, state isolation, testability, CSP style posture) is structural, not
  incremental. With no customers and no DOM contract, this is the cheapest moment a rewrite
  will ever be.
- **Next.js or any SSR/meta-framework**: rejected, confirmed by repository evidence. The UI is
  served by a Go binary on an air-gapped appliance to authenticated admins; there is no SEO, no
  public content, no Node production runtime, and the serving layer is ~100 lines of Go
  (`ui_static.go`). SSR would *add* a runtime dependency the appliance forbids.
- **htmx / server-rendered partials from Go**: would put presentation logic back into the Go
  binary and couple 189 JSON endpoints to HTML fragments; the admin API is JSON-first and
  consumed by tests and (per ADR-0018) a documented contract. Rejected.

### State-class separation (doctrine §8)

- **Server state**: TanStack Query exclusively (queries keyed per endpoint; polling via
  `refetchInterval` gated on route + document visibility — fixing today's always-on background
  polling; mutation invalidation replaces today's manual re-fetch calls).
- **Form state**: local to feature components; a dirty-tracking hook replaces today's single
  `viewLeaveGuards.policy` entry and extends leave-guards to every editor.
- **Navigation state**: React Router URL (making all 38 views deep-linkable; today only MCP has
  hash routing).
- **Ephemeral visual state**: component `useState`; toasts and dialogs via small context
  providers with a real stack (superseding `_modalStack` + 6 legacy non-stack modals).
- **Long-running operations**: dedicated hooks per workflow (release dispatch polling with its
  ticket semantics, MCP transition ticketing, support-bundle lifecycle) owning start/poll/stop.
- **Event-stream state**: one SSE hook owning the `/api/events` EventSource, jittered backoff
  (preserving today's ±25% jitter and 30-retry cap semantics, but resumable without reload),
  publishing into query cache.

### Build-time vs runtime; ADR-0018 "no Node in the fast gate"

Node is a **build-time dependency only**. The appliance never runs Node. The Dockerfile gains a
pinned `node:<version>-alpine` builder stage producing `frontend/dist`, which is copied to the
embed path before the Go builder stage; the bare `go build` path is served by a committed-`dist`
strategy (below). ADR-0018's "no Node in the fast gate" clause was written to keep *optional
docs tooling* out of the required lane; this ADR amends it deliberately: the fast gate gains one
pinned `npm ci && npm run build` step (or none at all under the committed-dist option — see
Open Question OQ-1) — recorded here, not slipped in.

### Generated `dist`: committed vs release-built (recorded trade-off)

Two viable strategies; **the recommendation is (A) committed dist**, with the trade-off recorded
so review can overturn it:

- **(A) Commit `frontend/dist` to the repo** (regenerated by CI check, not by hand).
  - Pros: `go build -o culvert .` keeps working with zero toolchain (preserves today's
    contributor experience and the `hygiene` build steps unchanged); byte-reproducibility gate
    trivially satisfied (the bytes are in git); air-gapped source builds need no npm registry;
    the Docker builder stage needs no Node at all.
  - Cons: generated bytes in git (review noise — mitigated by `linguist-generated` and a CI
    **drift gate** that rebuilds and byte-compares, making hand-edits or stale dist a hard
    failure); requires the Vite build itself to be deterministic (also required by (B)).
- **(B) Build `dist` in CI/Docker only, never commit.**
  - Pros: clean history; no drift class.
  - Cons: every build path (fast-gate hygiene ×2, deep-gate determinism ×2, ci.yml test job,
    Dockerfile both arches, developer `go build`) must grow a Node stage; bare `go build` from a
    tarball fails without Node + registry access — hostile to air-gapped source builds; the
    determinism gate then depends on Vite determinism *inside* the required lane.
- Either way, **Vite build determinism is mandatory** (stable chunk hashing, no timestamps,
  sorted emission; verified by a build-twice-compare CI step) because the deep-gate compares
  binaries. This is a gate in FE-1 of the migration plan.

### Dependency policy

- `package-lock.json` committed; `npm ci` only; Dependabot/renovate cadence aligned with Go deps.
- Every dependency license-reviewed at introduction (MIT/Apache-2/BSD/ISC allowlist); a
  `license-checker`-class scan joins the deep gate next to `go-licenses`.
- `npm audit` (or osv-scanner, which already understands lockfiles) joins the security lane.
- Runtime dependency budget: framework + router + query + chart + (optionally) Radix primitives.
  Anything beyond requires a one-paragraph justification in the PR. No utility packages
  (lodash, moment, axios, uuid, clsx-alikes) — small stable helpers are written in-repo.
- `.dockerignore` and `.gitignore` gain `node_modules/`; gitleaks allowlist reviewed for
  lockfile/bundle false positives.

### Explicit rejections

- **Service worker / PWA**: rejected. A stale cached UI across an appliance upgrade is an
  operational hazard; `index.html` stays `no-store`, hashed assets `immutable`. Reopening this
  requires its own ADR.
- **Microfrontends**: rejected; one Vite app, one embed.
- **Permanent dual UI**: rejected; the legacy file has a deletion gate (FE-9).
- **CSS-in-JS runtimes** (styled-components, emotion): rejected; they reintroduce runtime style
  injection that fights a strict `style-src` and adds bundle weight for nothing tokens can't do.
- **A large pre-styled component library** (MUI, AntD, Mantine): rejected; visual identity,
  bundle weight, and theming debt outweigh speed; CULVERT builds its own thin design system on
  tokens + (at most) headless primitives.

## Consequences

- Two frontends coexist during migration (legacy embedded file + new app behind a dev flag /
  parallel route), bounded by the FE-9 deletion gate — no permanent dual mode.
- ~29 markup-string-scanning Go tests are progressively replaced by behavior-level tests
  (component/E2E) as their features migrate; the *intent* tests (no inline handlers, no external
  origins, no native dialogs, typed-confirm coverage, CSP posture) are re-expressed against the
  new bundle in FE-1/FE-2 rather than deleted.
- CI grows: Node setup + `npm ci` caching, frontend lint/type/test/build jobs, dist drift gate
  (option A), npm license + vulnerability scanning, Playwright-TS lane; `proxy-ui-e2e.yml` path
  filters updated to include `frontend/**`.
- `ui_static.go` is rewritten for hashed-asset serving + SPA fallback (design in
  `FRONTEND-MIGRATION-PLAN.md` FE-1); the `__CSP_NONCE__` substitution contract is preserved for
  the shell only.
- Browser support floor formalized: evergreen Chrome/Edge/Firefox + Safari ≥ 16 (supersedes the
  incidental Safari ≥ 12.1 floor recorded in M1-M2-SELF-REVIEW L1).

## Open questions for review

- **OQ-1**: Committed vs release-built `dist` (recommendation: committed, with drift gate).
- **OQ-2**: Radix primitives vs fully hand-rolled a11y primitives (recommendation: Radix for
  Dialog/Popover/Tabs only; decide per component in FE-2 with a bundle-size check).
- **OQ-3**: OpenAPI-generated types now vs hand-authored-incremental. Discovery closed most of
  this question: `api/route-classification.yaml` shows 334/343 method-rows documented and
  `openapi.json` is committed + deterministic, so `openapi-typescript` can run offline against a
  committed artifact with no network and no drift (a CI gate compares generated output).
  Recommendation: **generate from day one**; hand-author only the 9 exempt rows. Residual
  decision for review: whether generated `types.gen.ts` is committed (mirroring the dist
  decision in OQ-1) — recommended yes, with the same rebuild-and-compare drift gate. One caveat
  the spec itself records: API errors are `text/plain` via `http.Error`, not a JSON envelope —
  the typed client must model errors as `(status, text)` and not invent an error schema.
