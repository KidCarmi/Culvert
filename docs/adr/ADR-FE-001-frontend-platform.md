# ADR-FE-001: Frontend Platform for the CULVERT Admin UI

- **Status**: **Accepted** (2026-08-21)
- **Date**: 2026-08-21 (proposed and accepted same day; accepted after the external
  architecture review's correction round was incorporated)
- **Deciders**: project owner, on the recommendation of the external architecture review
  (2026-08-21). Implementation proceeded under this ADR through FE-4 (see
  `docs/design/FRONTEND-MIGRATION-PLAN.md` §3 for the current per-phase status); the new
  frontend stays disabled by default in shipped builds (`CULVERT_EXPERIMENTAL_UI`) until FE-8
  cutover.
- **Supersedes**: the un-ratified "no framework / vanilla JS" position recorded in prose in
  `docs/design/REDESIGN-ROADMAP.md` (lines 6–10), `docs/design/CURRENT-UI-AUDIT.md` (§1
  verdict), and `docs/design/mcp/PRODUCTION-INTEGRATION.md` (§ non-negotiables). No ADR ever
  recorded that decision; `docs/design/M1-M2-SELF-REVIEW.md` itself notes a build pipeline
  "deserves its own design record". This is that record.
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
3. **Backend authority.** `uiRoutes` metadata (229 routes / 343 method rows), the C2
   enforcement middleware, handler-level `requireRole`, CSRF-by-Origin, session cookies, audit,
   and config versioning are untouched. The UI is presentation, not an authorization boundary.
4. **No backend API rewrite.** ADR-0018's hand-authored OpenAPI 3.0.4 contract over the existing
   handlers stands (334 of 343 method rows documented; 9 non-REST exemptions).
5. **CSP posture may only strengthen.** The new application targets a nonce-free strict CSP
   (see "CSP and the nonce decoupling" below); the legacy shell keeps its nonce model until
   cutover.
6. **"No Node in the fast gate"** (ADR-0018) is renegotiated by this ADR, not silently ignored:
   Node enters CI as a verification/drift lane only, never the appliance runtime and never the
   Go-only build path (see "Build-time vs runtime").

## Decision

Adopt the following platform for a clean parallel replacement of the embedded frontend.

### Locked baseline (exact pins — no caret/tilde ranges for direct dependencies)

Every version below was verified against the official npm registry dist-tags and
`nodejs.org/dist/index.json` on **2026-08-21** (evidence recorded beneath the table). Direct
dependencies are declared with **exact versions**; `package-lock.json` is mandatory and
`npm ci` is the only install command.

| Component | Pinned version | Verification evidence (2026-08-21) |
|---|---|---|
| Node.js | **24.19.0** (LTS "Krypton") | `nodejs.org/dist/index.json`: newest v24 LTS entry `v24.19.0`, bundled npm 11.17.0 |
| npm | **11.17.0** | bundled with Node 24.19.0 (same source) |
| react / react-dom | **19.2.8** (identical versions) | registry dist-tag `latest: 19.2.8` for both packages |
| typescript | **6.0.3**, `strict: true` + `noUncheckedIndexedAccess` | newest stable release inside typescript-eslint's supported range (see rejection of TS 7 below) |
| vite | **8.2.2** | registry dist-tag `latest: 8.2.2`; `engines.node: "^20.19.0 \|\| >=22.12.0"` (Node 24.19.0 satisfies); dependency graph confirms `rolldown ~1.2.4` — Vite 8 production bundling is **Rolldown-based** |
| react-router | **8.3.0**, **client-side (library/data) mode only** | registry dist-tag `latest: 8.3.0`; peer `react >=19.2.7` (satisfied by 19.2.8); `engines.node: ">=22.22.0"` (satisfied) |
| @tanstack/react-query | **5.101.4** | registry dist-tag `latest: 5.101.4`; peer `react ^18 \|\| ^19` |
| vitest | **4.1.11** | registry dist-tag `latest: 4.1.11`; `engines.node: "^20.0.0 \|\| ^22.0.0 \|\| >=24.0.0"` |
| @playwright/test | **1.62.1** | registry dist-tag `latest: 1.62.1`; `engines.node: ">=20"` |
| typescript-eslint | **8.67.0** (lint toolchain anchor) | registry `latest: 8.67.0`; peer `typescript >=4.8.4 <6.1.0`, `eslint ^8.57.0 \|\| ^9.0.0 \|\| ^10.0.0` |

**Effective minimum Node across the toolchain**: react-router 8.3.0's `>=22.22.0` is the
strictest engine; the canonical environment pins Node **24.19.0**, recorded identically in
`frontend/.node-version`, `frontend/package.json` `engines` (`node: "24.19.0"`,
`npm: "11.17.0"`), CI workflow setup steps, and the canonical deterministic-build environment
definition (FE-1A). Patch upgrades to any pin are ordinary reviewed PRs that update all four
places atomically.

**Why TypeScript 6.0.3, not 7.0.2**: the registry's `latest` TypeScript is 7.0.2 (the native
compiler major), but typescript-eslint 8.67.0 — the only maintained TS lint toolchain — supports
`typescript >=4.8.4 <6.1.0`. Pinning 7.x would leave the mandatory lint gate unsupported.
6.0.3 is the newest stable inside the supported range (5.9.3 is the fallback if FE-1A surfaces
a 6.0.x incompatibility, recorded then). Revisit TS 7 when typescript-eslint declares support.

### Explicitly rejected for the initial baseline

- **React Compiler** — not enabled; revisit only with its own evaluation after the app exists.
- **React Server Components** — no server React runtime exists or is permitted.
- **React Router Framework Mode** — library/data mode only; no file-system routing, no SSR
  manifest, no framework plugin.
- **SSR of any form** — the Go binary serves static assets; there is no Node at runtime.
- **React 18 compatibility** — the app targets React 19.2.x APIs exclusively; no compat
  shims, no dual-version testing.
- Also rejected (unchanged from the first round): Next.js/meta-frameworks, htmx/server
  partials, microfrontends, service worker/PWA (own-ADR required), CSS-in-JS runtimes, large
  pre-styled component libraries, Preact, Lit/Web Components, Svelte/Solid/Vue (evaluated
  against the required axes in the first round; none materially stronger for a 5–10-year
  security appliance on hiring, AI-assisted reliability, a11y ecosystem, and idiom stability).

### Platform summary

| Concern | Decision |
|---|---|
| UI framework | React 19.2.8 (function components + hooks only) |
| Language | TypeScript 6.0.3, `strict: true` |
| Build | Vite 8.2.2 (**Rolldown** production bundling), deterministic configuration (FE-1A gate) |
| Styling | CSS Modules + shared design-token stylesheet; **zero inline styles, zero runtime style injection** (see the inline-style ban in `FRONTEND-SECURITY-CONTRACT.md` §4) |
| Server state | TanStack Query 5.101.4 under the mandatory security profile (`FRONTEND-SECURITY-CONTRACT.md` §6) |
| Client state | React context + reducers per feature; no global store without demonstrated need |
| Routing | React Router 8.3.0, client-side mode, real paths under the SPA fallback |
| Forms | Local component state + shared form-field contract; no form library initially |
| Headless a11y primitives | **OQ-2, deferred to FE-2**: Radix evaluated component-by-component (Dialog/Popover/Tabs candidates) vs internal primitives on the ARIA Authoring Practices; every adoption individually justified with bundle + CSP + supply-chain checks |
| Charts | **Conditional** — Chart.js 4.x passes the FE-2 gate (zero CSP violations under the strict nonce-free policy, zero runtime style mutation, CSS/attribute-controlled dimensions, lazy chunk, accessible table/text equivalent, budget) **or is replaced by a thin internal SVG/CSS implementation**. CSP is never weakened to retain a library. |
| API layer | One typed client in `frontend/src/api/`; **committed generated types** `frontend/src/api/types.gen.ts` from the committed `api/openapi/openapi.json` (334/343 rows documented); runtime decoders at the boundary per `FRONTEND-SECURITY-CONTRACT.md` §7 — generated types are compile-time only |
| Unit/component tests | Vitest 4.1.11 + Testing Library (role/label queries only) |
| E2E | @playwright/test 1.62.1 (TS) against the real Go binary with the embedded bundle |
| Lint/format | ESLint (typescript-eslint 8.67.0) + Prettier, exact-pinned in FE-1A |

### CSP and the nonce decoupling

The new application is built to need **no nonce and no HTML mutation**:

- zero inline scripts, zero inline styles, zero runtime style injection;
- no `__CSP_NONCE__` placeholder, no Vite post-processing plugin rewriting `index.html`,
  no per-request shell substitution;
- served under a route-specific strict policy: `script-src 'self'; script-src-attr 'none';
  style-src 'self'; style-src-attr 'none'; object-src 'none'; base-uri 'none';
  form-action 'self'; frame-ancestors 'none'` plus the existing same-origin image/connect
  constraints.

The legacy shell keeps its current nonce + `style-src 'unsafe-inline'` policy unchanged until
cutover; at cutover the nonce generation and shell-substitution code are removed with the
legacy UI. Full contract: `FRONTEND-SECURITY-CONTRACT.md` §3.

### State-class separation (doctrine §8)

- **Server state**: TanStack Query exclusively, under the security profile (no persistence
  plugin, no offline queue, classified retries only, `refetchOnWindowFocus: false`, sensitive
  queries `gcTime: 0`); polling via `refetchInterval` gated on route + document visibility.
- **Form state**: local to feature components; a dirty-tracking hook extends leave-guards to
  every editor (today only `policy` has one).
- **Navigation state**: React Router URL — all 38 views deep-linkable.
- **Ephemeral visual state**: component `useState`; toasts/dialogs via context providers with a
  real stack. Dynamic visual state renders through classes / `data-*` attributes /
  predeclared CSS — never style mutation.
- **Long-running operations**: dedicated hooks per workflow (release dispatch, MCP transition
  ticketing, support-bundle lifecycle) owning start/poll/stop.
- **Event-stream state**: one SSE hook owning `/api/events`, jittered backoff preserved,
  resumable without reload; torn down on route unmount and on any authentication boundary.
- **Authentication boundary rule** (corrects the first draft): on 401/logout/user or role
  change, all requests are cancelled, the query cache cleared, SSE closed, timers stopped,
  Blob URLs revoked, and secret-bearing forms/candidates cleared. Only non-sensitive route
  intent and the theme preference survive re-authentication.

### Build-time vs runtime; ADR-0018 "no Node in the fast gate"

Node is a **build/verification-time dependency only**. The appliance never runs Node, and —
because build output is committed (below) — the normal Go-only build paths (`go build`,
the Dockerfile, the release image) never run Node either. The frontend verification/drift lane
is the only *required* CI lane that installs and verifies the new frontend dependency/build
toolchain (lint, typecheck, unit tests, type generation, build, byte-compare against the
committed output); the advisory playwright-go UI-E2E lane separately uses npm to stage its
browser driver until the legacy UI retires at FE-8/FE-9. ADR-0018's "no Node in the fast gate"
posture is amended to admit that single required lane, recorded here.

### OQ-1 + OQ-3 — CLOSED (review decision, 2026-08-21)

**Committed generated output.** `frontend/dist/` is the one canonical output directory,
committed to the repository together with `frontend/src/api/types.gen.ts`:

```
frontend/
  src/            (incl. src/api/types.gen.ts — committed, generated)
  package.json
  package-lock.json
  dist/           (committed, generated)
    index.html
    manifest.json (Vite build.manifest configured to emit at dist/manifest.json)
    assets/
```

- `go build -o culvert .` keeps working with zero toolchain; air-gapped source builds need no
  npm registry; the deep-gate binary byte-comparison is satisfied because the embedded bytes
  are in git.
- **The Docker release build consumes the reviewed committed dist and does not introduce a
  Node build stage.**
- Generated paths are marked `linguist-generated` in `.gitattributes`; hand-edits are
  impossible to land because the drift lane rebuilds and byte-compares (full contract:
  `FRONTEND-MIGRATION-PLAN.md` §"Drift & determinism contract").
- Production sourcemaps are disabled; `dist/manifest.json` is embedded for Go-side validation
  but never publicly served.
- Frontend dependencies and licenses are included in release notices and the SBOM.
- The earlier `webdist/` proposal is withdrawn; `frontend/dist/` is embedded directly
  (`//go:embed all:frontend/dist` — a root-relative subdirectory, valid for the root-package
  embed).

**Lifecycle scripts**: `npm ci --ignore-scripts` is the *target* posture but is **not mandated
until FE-1A proves the pinned toolchain builds correctly under it**. Grounds for expecting it
to pass: Vite 8's Rolldown and esbuild distribute prebuilt platform binaries via
`optionalDependencies`, not install scripts. If validation fails, FE-1A enumerates the exact
lifecycle scripts that must execute, with per-script justification, in the migration plan —
never a blanket allowance.

### Dependency policy

- Direct dependencies: **exact versions only** (no `^`/`~`); lockfile committed; `npm ci`
  exclusively; upgrade cadence aligned with Go deps and always a reviewed PR touching pin +
  lockfile + evidence note together.
- Every dependency license-reviewed at introduction (MIT/Apache-2/BSD/ISC allowlist); a
  Node license scan joins the deep gate next to `go-licenses`; lockfile-aware vulnerability
  scanning (osv-scanner or `npm audit`) joins the security lane; both outputs feed notices +
  SBOM.
- Runtime dependency budget: react, react-dom, react-router, @tanstack/react-query,
  (conditionally) chart.js, (per-component, OQ-2) Radix primitives. Anything beyond requires a
  one-paragraph justification in the PR. No utility packages — small stable helpers are
  written in-repo. No library that requires inline style mutation (contract §4) may be
  adopted at all.
- `.dockerignore` and `.gitignore` gain `node_modules/`; gitleaks allowlist reviewed for
  lockfile/bundle false positives.

## Consequences

- Two frontends exist in the tree during migration; the new app's `/app/` preview route is
  **disabled by default** and available only under an explicit experimental development/test
  flag — the shipping product never exposes an unfinished second frontend. No `/legacy/`
  route ever ships: at cutover the new frontend takes `/` and the legacy frontend is removed
  from the shipping tree in the same release; rollback is image/commit rollback.
- ~29 markup-string-scanning Go tests are progressively replaced by behavior-level tests; the
  intent tests (no inline handlers, air-gap, no native dialogs, typed-confirm coverage, CSP
  posture) are re-expressed against the new bundle in FE-1A/FE-2.
- CI grows one required frontend verification/drift lane (the only required lane installing
  the new frontend toolchain; Fast Gate member via `workflow_call`) plus license/vuln scanning;
  `proxy-ui-e2e.yml` path filters gain `frontend/**`.
- The serving layer is rewritten per the hardened contract (`FRONTEND-MIGRATION-PLAN.md` §2,
  `FRONTEND-SECURITY-CONTRACT.md` §9): hashed assets, manifest validation, strict resolution
  order, and **frontend-subsystem-unavailable = explicit 503 + degraded readiness + critical
  log/metric — never a process-wide startup failure** (a frontend asset problem must not
  become a proxy outage; making it process-fatal would require its own ADR).
- Browser support floor: evergreen Chrome/Edge/Firefox + Safari ≥ 16 (supersedes the
  incidental Safari ≥ 12.1 floor in M1-M2-SELF-REVIEW L1).

## Open questions

- **OQ-1**: CLOSED — committed `frontend/dist/` (review decision above).
- **OQ-2**: OPEN, deferred to FE-2 by review approval — Radix vs internal primitives, decided
  component-by-component with recorded justification.
- **OQ-3**: CLOSED — committed `frontend/src/api/types.gen.ts` generated from the committed
  `openapi.json`, same drift gate as dist. Runtime decoders remain mandatory at the boundary
  (types are compile-time only); API errors are modeled as `(status, text)` because the
  contract documents `text/plain` errors.
