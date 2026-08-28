# Frontend Migration Plan

- **Status**: Accepted with ADR-FE-001 (2026-08-21, external architecture review corrections
  incorporated). **Implementation has not begun**; FE-1A starts only on explicit go-ahead.
- **Shape**: clean parallel replacement. The legacy `static/index.html` keeps serving `/` until
  cutover; the new app is developed under `frontend/` and its `/app/` preview route is
  **disabled by default**, available only under an explicit experimental development/test flag
  (`CULVERT_EXPERIMENTAL_UI=1`, or the test harness). The shipping product never exposes an
  unfinished second frontend. No mega-PR; every phase is individually shippable and
  reversible. No permanent dual frontend and **no `/legacy/` route ever**: at cutover the new
  frontend takes `/` and the legacy frontend is removed from the shipping tree in the same
  release; rollback is image/commit rollback.
- **Gates are evidence-based, not calendar-based** (there are no production customers): no
  "N days green" or "one release cycle" criteria anywhere in this plan.

## 0. Source layout (canonical — one layout across all five documents)

```
frontend/
├── package.json                    # exact-version direct deps (ADR-FE-001 baseline)
├── package-lock.json
├── .node-version                   # 24.19.0
├── tsconfig.json / vite.config.ts / eslint.config.js / .prettierrc
├── index.html                      # Vite entry — no nonce placeholder, no inline script/style
├── dist/                           # COMMITTED generated output (linguist-generated)
│   ├── index.html
│   ├── manifest.json               # build.manifest: 'manifest.json' (emitted at dist root,
│   │                               #   not under .vite/ — Go embeds and validates it;
│   │                               #   it is never publicly served)
│   └── assets/                     # hashed js/css/svg/woff2 …
└── src/
    ├── app/                        # bootstrap, router, providers (query client, toasts, dialogs, session)
    ├── api/                        # ONE typed client; types.gen.ts (COMMITTED, generated
    │                               #   from api/openapi/openapi.json); runtime decoders
    ├── design-system/              # tokens.css + primitives (FE-2 component list)
    ├── layouts/                    # AppShell, auth/setup overlays
    ├── features/
    │   ├── setup/  auth/  dashboard/  traffic/  audit/  diagnostics/  governance/
    │   ├── policy/ authpolicy/ policy-tester/ policylearn/
    │   ├── objects/ (urlcat, catgroups, decprofiles, rewrite, fileblock)
    │   ├── blocklist/  security-scan/  cdr/  decryption/ (exclusions, health)
    │   ├── network/ (upstream, pac)   cluster/   identity/ (idp, users)
    │   ├── certificates/ (certs, ca-mgmt)   settings/   releases/  support/
    │   └── mcp/ (overview, servers, decisions, policies, approvals, health, rollout, management, settings)
    ├── shared/                     # hooks (useSSE, usePoll, useDirtyGuard, useOperation), utils, test helpers
    └── test/                       # vitest setup, typed API fixtures from the OpenAPI schemas
```

Feature modules align with product domains; no generic `components/` dump. The Go embed is
`//go:embed all:frontend/dist` in the root package. The former `webdist/` proposal is
withdrawn everywhere.

## 1. Build, drift & determinism contract (OQ-1/OQ-3 closed: committed output)

Committed generated artifacts: `frontend/dist/**` and `frontend/src/api/types.gen.ts`, both
marked in `.gitattributes` as `linguist-generated` (plus `-diff` optional for dist assets).
Production sourcemaps are **disabled**. Frontend dependencies + licenses are included in
release notices and the SBOM.

The **frontend verification/drift lane** (the only *required* CI lane that installs and
verifies the new frontend dependency/build toolchain — the advisory playwright-go UI-E2E lane
still uses npm for its browser driver until FE-8/FE-9; wired into the Fast Gate aggregate as
the `frontend` job of `pr-fast-gate.yml`, reusable via `workflow_call`)
executes, in one canonical pinned Linux environment (same container image recorded in the
workflow — this is the deterministic-build environment of record):

1. `rm -rf frontend/dist frontend/src/api/types.gen.ts` (remove the prior outputs completely)
2. `npm ci` (see lifecycle-scripts stance below)
3. Generate OpenAPI types from the committed `api/openapi/openapi.json`
4. `npm run build` (Vite 8 / Rolldown production build)
5. `git diff --exit-code -- frontend/dist frontend/src/api/types.gen.ts` — **empty diff or
   fail** (drift gate: committed output ≡ regenerated output)
6. Build a second time into an isolated clean directory (fresh checkout or out-of-tree
   `--outDir`)
7. Compare the two builds: complete file inventory identity + SHA-256 of every file —
   **byte-identical or fail** (determinism gate)
8. Lint, typecheck (`tsc --noEmit`, strict), unit/component tests (Vitest)

The deep gate's existing binary-reproducibility check then passes by construction (embedded
bytes are in git). The Docker release build and every `go build` path consume the reviewed
committed dist; **no Node stage is added to the Dockerfile**.

**Lifecycle scripts**: target posture is `npm ci --ignore-scripts`, but it is **not mandated
until FE-1A proves the pinned toolchain builds correctly under it** (expected to pass:
Rolldown/esbuild ship prebuilt platform binaries via `optionalDependencies`, not install
scripts). If any script proves necessary, FE-1A records the exact script list with per-script
justification here, and the lane runs with scripts enabled only for that enumerated set.

Toolchain pins (Node 24.19.0 / npm 11.17.0 / all direct deps exact — see ADR-FE-001) are
recorded consistently in `frontend/.node-version`, `frontend/package.json` (`engines` +
dependency versions), the CI workflow, and the canonical build environment. A pin bump is one
PR updating all of them plus the evidence note.

## 2. Go embedding & serving design (implemented in FE-1B)

Replaces the 3-file assumption in `ui_static.go` for the new app. The legacy shell path
(`serveUIShell`, nonce substitution, `no-store`) is **unchanged until cutover**.

- **Embed**: `//go:embed all:frontend/dist` in package main. At startup the embedded
  `manifest.json` is parsed and every referenced asset verified present.
- **Invalid/corrupt embedded frontend ⇒ frontend subsystem unavailable, not process failure**:
  the UI routes for the new app return an explicit **503** with a plain diagnostic body;
  readiness reports control-plane degradation; a critical structured log line and metric fire
  once. The proxy data plane continues on its last-known-good configuration. (Making a
  frontend asset problem process-fatal would require its own ADR — a UI defect must never
  become a full proxy outage.)
- **No nonce, no HTML mutation**: the new shell is served byte-identical from the embed. No
  `__CSP_NONCE__`, no per-request substitution, no index-rewriting Vite plugin. Route-specific
  strict CSP per `FRONTEND-SECURITY-CONTRACT.md` §3.
- **Resolution order (exact, tested)**:
  1. Existing generated asset (`/app/assets/…` during preview; `/assets/…` at cutover) →
     serve the asset.
  2. Unknown path under the asset namespace → **404** (never the shell; a missing `.js`,
     `.css`, image, or font must never fall back to HTML).
  3. Known reserved route (`/api/*`, `/auth/*`, `/healthz`, `/metrics`, `/proxy.pac`,
     `/pac/*`, and any future reserved namespace — the test derives the reserved set from the
     live route inventory, so a new backend namespace cannot silently fall into SPA fallback)
     → normal server routing.
  4. Unknown **GET or HEAD** UI path → SPA shell (deep links work).
  5. Unknown path with a **mutating method** → 404/405, never the SPA shell.
- **Headers & hygiene**: shell `Cache-Control: no-store`; hashed assets
  `public, max-age=31536000, immutable`; fixed MIME allowlist (js/css/svg/png/woff2 —
  anything outside the allowlist is not served); correct HEAD behavior (same headers, no
  body); path traversal rejected (stdlib `http.FS` semantics preserved); **no directory
  listing; `manifest.json` and any `.map` files are never publicly served** (sourcemaps are
  disabled anyway); explicit base-path handling for `/app/` during preview (`base` config)
  and `/` at cutover.
- **Preview gating**: the `/app/` route registers only when the experimental flag is set;
  default builds do not expose it.
- **Local development**: `vite dev` proxies `/api`, `/auth`, `/healthz` to a running
  `culvert` (documented `server.proxy` config). No Go changes needed for dev.

## 3. Phases

Sizes: S ≈ ≤1 engineer-week, M ≈ 1–2, L ≈ 2–4. Every phase's **security gate** includes: CSP
posture unchanged-or-stronger, no new public routes, no secrets in browser storage, ESLint
bans (`dangerouslySetInnerHTML`, native dialogs, `eval`, all inline-style forms per contract
§4) green. Every phase's **browser proof** is a Playwright-TS spec in CI (advisory until
FE-8, then required). All gates are evidence gates.

### FE-0 — Architecture & parity inventory — DONE
Design artifacts produced; external review received; corrections incorporated; ADR-FE-001
Accepted. Exit: this round.

### FE-1A — Frontend Build Foundation (no Go changes)
- **Objective**: `frontend/` scaffold with the exact ADR baseline pins; strict TypeScript;
  ESLint rules (incl. the contract §4 inline-style bans and §7 no-cast rules); generated +
  committed `types.gen.ts`; deterministic committed `dist/`; the full drift & determinism
  lane (§1) wired into the fast gate; npm license + vulnerability scanning; `.gitignore` /
  `.dockerignore` / `.gitattributes` / gitleaks-allowlist entries; lifecycle-scripts
  validation (§1).
- **Contains no Go serving change and no backend change.**
- **DoD / exit gate (evidence)**: **five consecutive identical hermetic builds** (file
  inventory + per-file SHA-256) in the canonical environment; drift gate red-team check (a
  hand-edit to dist fails CI); `ignore-scripts` outcome recorded.
- **Rollback**: revert the PR — nothing outside `frontend/` + CI is touched.

### FE-1B — Embedded Static Serving — IMPLEMENTED (this branch)

> **Implemented contract (FE-1B round).** Engine: `ui_frontend_v2.go`
> (`//go:embed all:frontend/dist`, validation-once at init, status model
> disabled/ready/invalid). Flag: `CULVERT_EXPERIMENTAL_UI` (opt-in parser per
> the `CULVERT_CLUSTER_GRPC_COMPRESSION` convention; read once, never
> per-request). Routes `/app`, `/app/`, `/assets/` are registered
> unconditionally (deterministic C1/D0 walls, counts 229→232) with the
> default-off gate in the handlers (disabled ⇒ plain 404, indistinguishable
> from unregistered). **Asset-namespace decision: Option A — stable
> `/assets/`** (collision-proven against the live route inventory; survives
> cutover unchanged; no base rebuild, no HTML rewriting). Strict nonce-free
> CSP is route-scoped to the new surface; the legacy nonce CSP is untouched.
> Invalid artifact ⇒ 503 text/plain no-store + one critical log + report-only
> `frontend_v2` /ready row; the data plane continues. Real-binary Playwright
> smoke: `frontend/e2e/smoke.spec.ts` via `frontend/scripts/e2e-smoke.sh`,
> wired as the `smoke` job of `frontend-verify.yml` (Fast Gate member).
- **Objective**: Go embed of `frontend/dist`; flag-gated `/app/` preview route; route-specific
  strict CSP; manifest validation with the 503-unavailable behavior; cache policy; SPA
  fallback per the §2 resolution order; static-serving Go tests (each §2 property, incl.
  reserved-route derivation and mutating-method fallback refusal); Playwright
  production-bundle smoke test (loads `/app/` under the flag, asserts zero CSP violations).
- **Dependency**: FE-1A. **Contains no backend security fixes** (see SEC-* below).
- **DoD / exit gate (evidence)**: all serving tests green; **two identical final binaries per
  supported target** (amd64/arm64) from the deep-gate determinism job; smoke test green with
  the strict CSP; D0/C1 route locks updated by the normal convention.
- **Rollback**: revert — the route is flag-gated and default-off; legacy `/` untouched.

### Security work items (separate PRs, may run in parallel; never bundled into FE-1A/1B)

- **SEC-C2** — C2 metadata matching for Go wildcard patterns. Finding (stated precisely):
  the metadata index files `{param}` paths under their literal string, so the 10 wildcard
  routes resolve to the public `/` catch-all and **skip the C2 metadata-enforcement layer**
  — a defense-in-depth bypass, **not a proven authentication bypass** (handler-level
  `requireRole` still gates every affected handler). Fix the matcher; prove every wildcard
  route resolves to its own metadata; preserve handler-level `requireRole`; add the missing
  wildcard coverage to `ui_metadata_enforcement_test.go`.
- **SEC-PATCH** — include `PATCH` in the mutating-method classification (CSRF, 1 MiB body
  cap, rate limit) with regression tests for all three, plus a test that a hypothetical PATCH
  route cannot bypass them.
- **SEC-PROXY** — trust `X-Forwarded-Host` / `X-Forwarded-Proto` only under the existing
  trusted-proxy doctrine (the `realClientIP` RISK-019 mechanism); tests for direct,
  trusted-proxy, and spoofed-untrusted paths for both `isSameOrigin` and `isSecureRequest`.
- **SEC-HSTS** — separate decision + PR, not a trivial header: define behavior for
  self-signed bootstrap, IP-address access, custom certificates, direct TLS, and trusted
  reverse proxies; **no `preload`, no `includeSubDomains` by default**; document the
  interaction with the dynamic cookie-`Secure` flag.

The new frontend does not gate on SEC-* landing, except FE-8 cutover requires SEC-C2 (the new
UI leans on C2 semantics and must not cut over onto a known enforcement gap).

### FE-2 — Design system & application shell — IMPLEMENTED (this branch)

> **OQ-2 CLOSED (component-by-component, FE-2 round).** No overlay/positioning
> dependency was added; Radix was rejected per-component on hard evidence: its
> Dialog/Tooltip/Popover presence+positioning layers write inline `style`
> attributes and runtime style properties, which the CULVERT contract bans
> outright (§4.Y1 — the ban is on the practice, independent of CSP
> enforcement paths). Decisions:
>
> | Primitive | Decision | Basis |
> |---|---|---|
> | Dialog | **Native `<dialog>` + internal wrapper** | top layer, focus containment, inert background, `::backdrop`, Esc-cancel from the platform; wrapper adds ceremony-aware Esc policy + state sync; browser-proven (focus lifecycle, containment, return-to-invoker) |
> | Tooltip | **Internal, CSS-positioned** | static above-center placement needs no measurement ⇒ no style attrs; `aria-describedby` semantics |
> | Popover / Menu | **Deferred to first consumer**; designated approach = native HTML `popover` attribute (top layer, CSP-clean) | no FE-2 consumer; pre-deciding a library without a use case violates the dependency policy |
> | Tabs | **Deferred to first consumer**; designated approach = internal APG roving-tabindex | no FE-2 consumer |
> | Select | **Native `<select>`, token-styled** | correct semantics free; custom listboxes wait for a real need |
>
> **CHART DECISION = REJECT (Chart.js).** Hard-requirement failure with
> concrete evidence: the shipped v4.4.0 bundle performs runtime style
> mutation (`.style.height=` / `.style.width=` in its responsive canvas
> path — `grep -o '\.style\.[a-zA-Z]*\s*=' static/chart.umd.js` → 2 writes),
> violating "zero runtime style mutation" (§17/§4). CSP/contract was not
> weakened; the two dashboard chart shapes are covered by thin internal SVG
> primitives (`design-system/charts.tsx`: LineChart + DonutChart, geometry
> via SVG attributes, visible-legend/sr-only non-visual equivalents),
> browser-proven under the strict CSP. Chart.js will not be a dependency of
> the new frontend; the legacy vendored copy retires with the legacy UI.
>
> **Icon strategy**: internal 16-icon SVG set (`design-system/icons.tsx`),
> `aria-hidden` by default, labeled when icon-only — no dependency, no CDN.
> **Theme**: `system|dark|light`; `design-system/theme.ts` is the single
> sanctioned `localStorage` module (ESLint ban lifted for exactly that file);
> stamped via `data-theme`, live `prefers-color-scheme` tracking, no reload.
- **Objective**: tokens (seeded from `DESIGN-SYSTEM.md`, both themes, CULVERT identity),
  primitives (AppShell, Navigation, PageHeader, DataTable, FormField, Dialog,
  ConfirmationDialog incl. Tier-3 typed-word + two-phase-token variants, StatusBadge,
  HealthCheck, DiagnosticsResult, ConfigDiff, OperationProgress, RollbackBanner,
  AuditTimeline, EmptyState, ErrorState, LoadingState, Toast), the SSE hook, the poll hook
  (route+visibility-gated), the dirty-guard hook, the typed API client + runtime decoders,
  and **two decision gates**:
  - **OQ-2 (per component)**: Radix vs internal primitive, justified individually.
  - **Chart.js gate**: Chart.js 4.x stays only if a real production build proves zero CSP
    violations under the strict policy, zero runtime style mutation, no unsafe-inline need,
    CSS/attribute-controlled dimensions, lazy dashboard chunk, an accessible table/text
    equivalent per chart, and budget compliance. Otherwise the two charts are replaced by a
    thin internal SVG/CSS implementation. CSP is never weakened to keep the library.
- **Dependency**: FE-1A (+FE-1B for in-situ serving proof). **Size**: L.
- **DoD**: component tests (role/label queries only); axe checks per primitive;
  per-component bundle budget recorded; both gate outcomes recorded in this document.
- **Exit gate (evidence)**: primitives reviewed against UX-PRINCIPLES MUST rules;
  strict-CSP browser run over the component gallery with zero violations.

### FE-3 — Setup, auth, session, RBAC navigation — IMPLEMENTED (this branch)
- **Objective**: first-run setup, login/logout with the in-band TOTP state machine, 401
  handling with the full authentication-boundary teardown (contract §6), role-gated router +
  nav, session-expiry UX.
- **Dependency**: FE-2. **Size**: M.
- **DoD**: viewer/operator/admin navigation differences proven; bootstrap window works;
  teardown proven (cache cleared, SSE closed, timers stopped, Blob URLs revoked, secret
  forms cleared).
- **Browser proof**: first-setup, login/logout, expiry, role-difference specs.
- **Exit gate**: security review against `FRONTEND-SECURITY-CONTRACT.md` §1–§2, §6.

> **FE-3 implementation record (2026-08-22, externally reviewed).**
> - **Authoritative boot ordering**: one machine (`src/auth/machine.ts`) —
>   `booting → GET /api/setup/status` FIRST (the pre-setup bootstrap
>   `{loggedIn:true,user:"",role:"admin"}` shape is never a human session),
>   then `GET /api/auth/status`; phases `setup_required | unauthenticated |
>   authenticated | auth_error`. Login/setup responses are never trusted
>   alone — every entry to `authenticated` goes through a fresh dual read.
> - **401 policy**: `RequestOptions.unauthorizedPolicy` — `"expected"` for
>   auth-flow calls (invalid password / invalid TOTP are form errors),
>   `"boundary"` (default) for everything else; boundary 401s enter ONE
>   idempotent collapsed transition.
> - **Boundary collapse**: every teardown-carrying transition (boundary 401,
>   revalidation-discovered logout/identity change/invalid identity,
>   refresh-discovered replacement) joins one in-flight boundary — exactly
>   one teardown, one final transition.
> - **Identity/role continuity (hardening round)**:
>   `revalidateAuthenticatedSession()` re-reads `/api/auth/status` at v2
>   route transitions and window focus/visibility restoration (never
>   TanStack refetchOnWindowFocus, no polling). Server loggedOut → teardown
>   → login with a memory-only "Management session ended" reason; different
>   user OR role → FULL teardown FIRST, then the new identity renders
>   (multi-tab cookie replacement proven in a same-context two-page spec);
>   same user+role → no teardown; transport failure preserves the current
>   identity. The earlier `/api/stats` probe was REMOVED in its favor.
> - **TOTP**: strictly in-band — `totp_required` (no cookie) → same
>   credentials re-POSTed with the code/backup code; no enrollment surface
>   (backend GAP-2).
> - **Open Mode**: setup-time `{unauth:true}` WITHHELD from the v2 UI —
>   see FRONTEND-FEATURE-PARITY.md FE-X02 and FRONTEND-CURRENT-STATE.md
>   GAP-9 (SETUP-OPEN-MODE).
> - **Boundary unification (final hardening)**: explicit logout joins the
>   SAME collapsed boundary coordinator as sessionExpired and identity
>   replacement (authoritative join — the deliberate sign-out UX wins any
>   race); the coordinator is the sole caller of the auth teardown and runs
>   it at most once per authenticated episode, so FE-4 cleanup owners
>   (SSE, timers, Blob/draft owners) never need to be idempotent.
> - **Qualification checkpoint**: FE-3-FROZEN branch history
>   `claude/culvert-frontend-modernization-qnyqb6` (FE-3.1–FE-3.11: .1–.9
>   implementation + continuity hardening, .10 durable docs, .11 boundary
>   unification);
>   real-binary Playwright suite across three appliance states + the
>   multi-tab identity-switch spec; unit matrix incl. §6 A–G continuity
>   proofs.

### FE-4 — Snapshot operations & Monitor — IMPLEMENTED (this branch)
- **Objective (as revised by ADR-FE-002, Accepted)**: FE-V01 (Overview as a SNAPSHOT
  dashboard), FE-V02 (Traffic as a QUERY-DRIVEN history console), FE-V03 (audit),
  FE-V34 (diagnostics), FE-V38 (governance).
- **Dependency**: FE-3. **Size**: L.
- **Product decision (authoritative — `docs/adr/ADR-FE-002-monitor-query-model.md`)**:
  the CULVERT Monitor is query-driven, not stream-driven. Explicit queries, mandatory
  time ranges, server-side filtering, bounded server-side pagination, explicit refresh,
  visible snapshot freshness. The v2 client consumes **no SSE and no polling ticks**:
  no `EventSource`, no `/api/events` request, no auto-refresh (deferred; if ever added
  it is opt-in, OFF by default, ≥30 s, route+document-visible only, never persisted).
  The backend SSE surface is retained untouched for the legacy UI.

> **FE-4 implementation record (2026-08-22, externally reviewed).**
> - **Backend scale contract (FE-4.1)**: `internal/logstore` gained
>   `QueryPage` — keyset (cursor) pagination newest-first over the
>   `(timestamp, seq)` total order; scans only one page + one look-ahead
>   match, computes NO exact total, stable under concurrent appends.
>   `GET /api/logs?source=store` gained an opaque stateless cursor mode
>   (`ui_logs_cursor.go`): base64url `{v,ts,seq,fp}` where `fp` is a bounded
>   fingerprint of the filtering query — a cursor minted for query A is a
>   controlled 400 against query B; malformed/oversized cursors are 400;
>   page default 100 / max 500; response carries `has_more` + `next_cursor`
>   and deliberately no total. The legacy offset mode is byte-compatible.
>   Deterministic scale proof via the `Scanned` seam: page 40 of a
>   5000-entry store costs the same scan count (≤ limit+1) as page 1.
>   The qualification-hardening round added the bounded scan-continuation
>   contract (`scan_limited` + a last-SCANNED continuation cursor issued
>   even for zero-row segments), so sparse filters have guaranteed forward
>   progress — a proven non-matching range is never rescanned, and the UI
>   distinguishes "no matches in this scanned segment / Continue search"
>   from the true terminal empty window. Engine + API + browser proofs:
>   `logstore_page_sparse_test.go`, `ui_logs_cursor_sparse_test.go`,
>   fe4.spec.ts. Per-verb diagnose decoders (all NINE backend verbs incl.
>   support/all), network-layer auth-boundary cancellation for every FE-4
>   request (queries consume TanStack's AbortSignal; the diagnose mutation
>   owns an AbortController wired to registerAuthCleanup), and the
>   truthful Overview time-scope labels landed in the same round.
> - **Snapshot freshness contract (§17)**: one `useSnapshot` hook + one
>   `SnapshotBar` implement loading → fresh → refreshing → error-with-
>   previous-snapshot → error-empty. "Updated HH:MM:SS" advances ONLY on a
>   successful response; a failed refresh keeps the old snapshot behind an
>   explicit "Refresh failed — showing previous snapshot" indicator
>   (browser-proven with a network-abort fixture).
> - **Overview**: ONE snapshot fetch set (`/api/stats`, `/api/timeseries`,
>   `/api/dashboard/{health,threats,top-rules}`) so the page carries a
>   single honest freshness timestamp; persistence/degraded warnings
>   (audit/request-log persistence inactive, write errors, cluster publish
>   rejected) render above the grid; manual Refresh only.
> - **Traffic**: draft→Apply query console (no per-keystroke queries);
>   mandatory time presets 15m/1h/6h/24h/custom (from<to validated);
>   Previous/Next over an in-memory cursor stack (reload ⇒ page 1 —
>   documented §22 choice; safe query state lives in the URL, the opaque
>   cursor never does); truthful availability states — disabled store ≠
>   error ≠ empty, and the in-memory RECENT-ring fallback is an explicit
>   button and clearly labelled as a different, volatile source; superseded
>   in-flight queries are aborted (proven at the network layer).
> - **Audit**: bounded time-windowed pages over `/api/audit` (offset
>   pagination is honest here — the backend computes a real total and the
>   read is bounded); sources labelled truthfully (500-entry volatile ring
>   vs durable JSONL); before/after snapshots render as text, never HTML.
> - **Diagnostics**: viewer snapshot with `operator_action` first-class on
>   warn/fail rows; `/api/diagnose/{verb}` runs ONLY on explicit operator
>   action (browser-proven: zero diagnose requests on page load), gated to
>   operator+ in UI with the server authoritative; results decode
>   `schema_version` fail-closed (unsupported schema ⇒ controlled error,
>   never guessed rendering).
> - **Governance**: admin-only snapshot of `/api/governance/control-plane`
>   presented operator-first (enforcement mode, health, findings with
>   hints, counters); viewer direct navigation fails closed into an
>   explicit error state via the server's 403 (no nav entry, no crash).
> - **DoD deviations from the original FE-4 text (all deliberate,
>   ADR-FE-002)**: no SSE reconnect/LIVE-STALE pill, no tick
>   pause/resume, no polling, and the polling/SSE memory-soak exit gate is
>   replaced by (a) the deterministic scan-count proof above and (b) the
>   browser-proven no-stream posture (zero `/api/events` requests across
>   every FE-4 flow). Charts remain the FE-2 internal SVG primitives.
> - **Qualification checkpoint**: real-binary Playwright suite over 150
>   seeded `POLICY_DEFAULT_DENY` history entries (Zero-Trust `default_action:
>   deny` harness, Badger store provisioned via `log_store_path`), plus the
>   history-disabled FRESH appliance; viewports 1440/1024/640(≈200% zoom);
>   §25 evidence set delivered as artifacts (never committed).

### FE-5 — Policy, security, network features — BATCH 2 (approved decomposition)

> **Batch-2 program record (2026-08-22, planning gate accepted).** Batch 1
> (FE-1A→FE-4) is merged (`main` @ `fdad5254`, delivery `c1d3db57`, closeout in
> `docs/engineering/FRONTEND-BATCH-1-CLOSEOUT.md` on the retained Batch-1
> evidence branch `claude/culvert-frontend-modernization-qnyqb6`). Batch 2 is
> developed on `claude/culvert-frontend-batch2` (granular commits, no squash).
> The FE-5 domain is decomposed into SEVEN slices:
>
> | Slice | Scope | Status |
> |---|---|---|
> | **2A** | Policy Read & Explainability: Access Rules read surface, Policy Tester, Where Used (generic read consumer), Traffic → Policy stable-rule-ID deep links, 500-rule scale qualification | this round |
> | **2A-M** | Monitor residue micro-slice: Traffic retention / purge / export (destructive mutation + retention configuration + Blob/download ownership — deliberately SPLIT out of 2A; no architectural dependency on the Policy read surface) | this round |
> | **2B** | Policy Write: rule create/edit/delete/bulk, staged reorder + move, draft commit/revert, Require Commit toggle, multi-admin actor warning, shadow warnings, `ifVersion` fencing UX, default-action mutation, dirty-route guard | pending |
> | **2C** | Authentication Policy (Stage-1 rules + default-auth-outcome T3 ceremony) + Policy Learning (advisory panel, accept-to-draft, reject) | pending |
> | **2D** | Objects & Taxonomy: URL categories (+hosts, lookup, feed status), SaaS feed settings/overrides/refresh, category groups (+rename), decryption profiles (+rename, cert-enum lockstep), file profiles, rewrite | pending |
> | **2E** | Scanning / Content Security / Decryption / CDR: blocklist (+feeds/exceptions/mode T3), Content & Scanning (YARA/DPI/exclusions/threat feeds/cache/saturation), decryption exclusions + tunables + health (pulled forward from FE-6 for cohesion with 2D profiles), CDR | pending |
> | **2F** | Network: PAC (profiles/pools/lifecycle/simulator/analyze/posture/exceptions + server-named DIRECT-bypass T3 ceremony) + Upstream (write-only credentials, direct-fallback banner) | pending |
>
> FE-6/FE-7/FE-8 remain outside Batch 2. ADR-FE-001 and ADR-FE-002 remain
> authoritative; no new ADR. Parity rows are updated only for capabilities a
> slice actually proves — FE-V16 stays partial until 2B completes the write
> surface.
- **Objective**: FE-V16..V26 (policy + draft/commit + staged reorder + tester + authpolicy +
  policylearn + blocklist + security-scan + fileblock + cdr + objects), FE-V31/V32 (upstream,
  PAC incl. governance + T3 bypass ceremony), FE-X06 (where-used).
- **Dependency**: FE-4. **Size**: L (slices 2A–2F above).
- **DoD**: draft multi-admin actor warning, shadow warnings, version fencing, ref-guarded
  deletes, cert-enum lockstep re-expressed from a shared constant.
- **Browser proof**: policy mutation, failed (version-fenced) mutation, destructive
  confirmation, PAC simulator + bypass ceremony.
- **Exit gate (evidence)**: parity rows checked; policy table renders 500 rules within the
  interaction budget.

> **Slice 2A implementation record (this branch, 2026-08-22).**
> - **Routes**: `/app/policies/access-rules` + `/app/policies/tester` (real v2
>   routes, viewer floor; nav entries under Policies; route-intent entries).
>   Authentication Rules stays a planned, non-interactive nav item until 2C.
> - **Access Rules (FE-V16 READ)**: `GET /api/policy` envelope decoded
>   fail-closed (`rules/count/version/updatedAt/draft`); ruleType classified
>   explicitly (`""|"access"` → access, `"auth"` → excluded-but-counted,
>   anything else → explicit unknown callout, never an access rule); server
>   priority order preserved (no column sorting; filter hides, never
>   reorders); snapshot/refresh per ADR-FE-002 (SnapshotBar, failed refresh
>   keeps the previous rulebase, AbortSignal to the wire); in-memory
>   client-side filter for the bounded 500-rule target; row-detail expansion
>   for secondary metadata; draft/running truthfulness from the server's
>   `draft` flag (candidate callout, no 2B mutation UX); `?rule=<id>` deep
>   link resolved by data equality (bounded parameter, scroll/focus +
>   temporary data-state highlight + polite announcement; honest
>   not-in-snapshot callout).
> - **Policy Tester (FE-V06)**: explicit Run-test over the viewer dry-run
>   `POST /api/policy/test`; discriminated decoder (matched union, trace,
>   hostCategory, exact `simulateAuthOutcome` auth block, rulebase
>   `running|draft` only); the tested-rulebase truth leads the result; no
>   input/result persistence; read-only proven (no version/hit/rule change,
>   no mutating API call).
> - **Where Used (FE-X06)**: one reusable read-only consumer of
>   `GET /api/objects/references`; explicit-interest fetch; server `view`
>   strings are data — navigation only through the reviewed
>   consumer→route mapping (access-rule/policy by stable ID; others
>   information-only until migrated).
> - **Traffic deep link (FE-V02 partial)**: rows with a stable `ruleId` link
>   to the Access Rules deep link (ID-authoritative); Traffic
>   query/cursor/snapshot semantics untouched. Retention/purge/export remain
>   2A-M.
> - **Shared explicit-run owner**: the FE-4 diagnostics AbortController owner
>   extracted verbatim to `src/shared/runOwner.ts` (second real consumer);
>   diagnostics import path re-exports it, FE-4 cancellation tests unchanged.
> - **Scale**: no virtualization; 502-rule real-binary browser proof at
>   1024×768 / 1440×900 / 640×800(zoom-proxy) with a ≤1 s filter and
>   deep-link interaction budget.
> - **Qualification checkpoint**: granular commits B2.0 + 2A.1–2A.4 on
>   `claude/culvert-frontend-batch2`; unit matrix + real-binary Playwright
>   suite (FE-1B/2/3/4 + the 20-flow 2A spec) green; canonical-container
>   verify + tamper + determinism ×5; Go contract suites; binary determinism
>   ×2 + arm64.

> **Slice 2A-M implementation record (this branch, 2026-08-22).**
> - **Route**: `/app/monitor/history` — Monitor → History & Storage (viewer
>   floor; nav between Audit Log and Diagnostics; route-intent entry).
>   Snapshot-driven per ADR-FE-002 (one GET, manual Refresh, no polling/SSE).
> - **Retention contract**: ONE `RetentionView` runtime decoder serves
>   `GET /api/logs/retention`, the `PUT` mutation response, and
>   `POST /api/logs/purge` (all return `logStoreRetentionView()`); absent
>   optional statistics decode to undefined, never invented zeros.
> - **RBAC**: viewer/operator = full read + recent-memory export; ONLY admin
>   mounts Edit/Enable-Disable/Threshold/Purge (uiRoutes truth; no
>   decorative disabled controls).
> - **Mutations**: explicit edit state, one Save, retry=false, no optimistic
>   update; success renders only the server's returned view. Disable states
>   plainly that retained data stays on disk; the encryption-key-mismatch
>   409 surfaces distinctly with purge-then-enable as two deliberate
>   actions. Purge is a T2 ConfirmationDialog naming exactly what is and is
>   NOT deleted. Network/timeout outcomes are STATE UNKNOWN: prior snapshot
>   kept, unconfirmed declared (purge uses the required copy), further
>   mutations blocked until a fresh successful GET.
> - **Export**: `GET /api/export` labelled truthfully as **Export recent
>   memory** — the in-memory ring (`reqlog.MaxRing` = 5000 entries), never
>   persistent history; JSON/CSV via a bounded download client
>   (`apiDownloadRequest`: target gate, media-type allowlist, 32 MiB cap
>   with streaming enforcement, boundary-401) + an owned Blob/download
>   primitive (`createDownloadOwner`: supersession, deterministic client
>   filenames, revoke-on-deliver/unmount/auth-boundary).
> - **Harness isolation (§19)**: every e2e premise is established through
>   the supported admin API; mutation flows run on the FRESH appliance so
>   the AUTH store's seeded Traffic evidence is never disabled or purged;
>   FRESH ends disabled. Recorded harness debt: `dataDir` is the fixed
>   absolute `/data` shared by all local instances (and any stray local
>   process can hold the Badger lock on `/data/logstore`) — premises must
>   be API-established, never assumed.

> **Slice 2B implementation record (this branch, 2026-08-28).**
>
> **Entry-gate delta review**: `origin/main` advanced 183 commits past the
> Batch-2 base `fdad5254` (merge-base unchanged). No Policy / Policy Draft /
> PolicyStore / route-metadata changes; the auth surface changed twice —
> (1) the pre-auth surfaces (`/api/auth/status`, `/api/setup/status`) now send
> `ui_tls_fallback` WITHOUT `ui_tls_fallback_reason` (unauthenticated-surface
> redaction), reconciled here by making the reason OPTIONAL in
> `decodeSetupStatus`/`decodeAuthStatus` (default `""`; the flag alone drives
> the warning UI); (2) open-mode setup persistence is fail-closed on main
> (backend-only, no frontend contract impact).
>
> **2B.0 backend hardening (precedes all write UI):**
> - **2B.0a atomic fencing** (`policy_mutation.go`): when `?ifVersion=` is
>   asserted, the effective-generation comparison, the first-write draft
>   fork, and the store mutation run under ONE coordinator critical section
>   (`fencedMutate`) — the documented two-writers-both-pass window is closed.
>   `ifVersion` stays optional (absent = legacy last-write-wins, unchanged).
>   Version-stream continuity: the draft fork SEEDS the candidate counter
>   from the running generation (first staged write lands at vN+1, so a stale
>   pre-fork vN deterministically conflicts), and candidate retirement
>   (commit/revert/no-op reconcile) advances running past every candidate
>   generation — stale tokens can only ever produce a conservative conflict,
>   never a false pass. Proofs: `policy_mutation_fence_test.go` (concurrent
>   edit/edit, create/create, reorder/edit, first-write-opens-draft incl. the
>   deterministic fork version-collision regression, commit-vs-mutation,
>   legacy compatibility, retired-token revival), green under `-race`.
> - **2B.0b durable-or-nothing** : a 2xx ordinary policy write now means the
>   mutation is durably persisted in the current mode's domain
>   (`policy_rules.json` live / `policy_draft.json` staged); a pre-replacement
>   persistence failure fails the request AND rolls the semantic state back
>   (memory and restart-visible file agree the mutation never happened);
>   `ErrReplacedNotSynced` counts as landed per the commitActivate doctrine.
>   Proofs: `policy_mutation_durability_test.go` (real AtomicWrite failures
>   via the directory-blocker technique + restart-reload verification through
>   the real recovery paths).
>
> **PolicyRule field classification matrix (§11 — the write contract).**
> PUT `/api/policy` is FULL REPLACEMENT; the v2 editor submits exactly the
> EDITABLE set below (`AccessRuleWrite`, `frontend/src/api/policyWrite.ts`)
> and never the rest. Tri-state fields (`*bool` on the wire) preserve ABSENT
> as a distinct value.
>
> | Wire field | Class | Notes |
> |---|---|---|
> | `name` | EDITABLE | required |
> | `priority` | EDITABLE (create hint) / SERVER-OWNED (edit) | position is reorder/move-owned; `UpdateByID` preserves the stored slot; create may request a slot (collision ⇒ server reassigns) |
> | `enabled` | EDITABLE tri-state | absent ⇒ enabled; absent preserved unless the operator flips the control |
> | `sourceIP`, `sourceIdentity`, `sourceGroup`, `authSource` | EDITABLE | empty = any |
> | `destFQDN`, `destCategory`, `destCountry` | EDITABLE | empty = any |
> | `destCategoryGroup` | EDITABLE (NAME) | authoritative id stamped server-side |
> | `destCategoryGroupId` | SERVER-OWNED | `stampObjectRefIDs` discards client values |
> | `schedule` | EDITABLE | days/timeStart/timeEnd/timezone preserved exactly; absent = always active |
> | `sslAction` | EDITABLE | `Inspect`\|`Bypass` only |
> | `fileFiltering`, `fileProfile` | EDITABLE | server auto-enables filtering when a profile is set |
> | `logFullUri` | EDITABLE | |
> | `logTraffic` | EDITABLE tri-state | absent/true = log; false = stats only; absent preserved |
> | `stripAlpn` | EDITABLE tri-state | absent/true = HTTP/1.1 downgrade; false = native H2 — PRESENCE-AWARE server-side; absent preserved |
> | `tlsSkipVerify` | EDITABLE | |
> | `decryptionProfile` | EDITABLE (NAME) | authoritative id stamped server-side |
> | `decryptionProfileId` | SERVER-OWNED | |
> | `action`, `redirectURL` | EDITABLE | `Allow`\|`Drop`\|`Block_Page`\|`Redirect`; redirectURL used by Redirect |
> | `comment` | EDITABLE | the one admin-authored metadata field |
> | `id` | SERVER-OWNED | stable ULID minted server-side; an ADDRESS (`?id=`), never form content |
> | `hitCount`, `lastHit` | DERIVED | runtime counters, never submitted |
> | `createdAt`, `modifiedAt`, `modifiedBy` | SERVER-OWNED | stamped in `stampRuleMetadataForWrite`; client values ignored |
> | `ruleType` | STAGE-1 GATE | only `""`/`"access"` representable in the DTO; `"auth"` structurally impossible (2C) |
> | `auth`, `subjectMatch` | STAGE-1 ONLY / RESERVED | never in the write DTO |
> | (priority-addressed update/delete, `{priorities:[…]}` bulk delete) | DEPRECATED/compat | backend-only for legacy callers; the v2 client is exclusively id-addressed — v2 bulk delete DEFERRED (stable-ID bulk contract does not exist; recorded parity residue) |
>
> **2B write surface (2B.1–2B.7)** — `/app/policies/access-rules` gains the
> full Access Rule write story on top of the frozen 2A read surface:
> - **Write contract** (`policyWrite.ts`/`policyDraft.ts`): `AccessRuleWrite`
>   DTO + serializer (tri-state absent preservation, zero server-owned
>   leakage), fenced mutation client (every call sends `ifVersion`),
>   structured-409 decoder, discriminated draft-state decoder (active shape
>   fails closed; stranded shape decodes), read-only reference option
>   sources (categories / groups / file profiles / decryption profiles).
> - **Editor** (`RuleEditor`): semantic field groups, server-validator
>   mirror (Redirect URL, timezone), Inspect-only TLS controls that
>   PRESERVE hidden values, option selects that keep values a stale list
>   does not carry. Conflict keeps the form and blocks resubmit until
>   fresh truth; unknown outcomes latch the page.
> - **Draft Bar** (`DraftBar`): states A–D from BOTH server contracts;
>   stranded recovery is never hidden and never blindly committable
>   (admin resumes review via the arm ceremony; operators get safe
>   revert); Require Commit is an explicit mode-change ceremony; the
>   shared-actor warning states one shared candidate.
> - **Staged reorder**: local permutation with deterministic
>   First/Up/Down/Last controls (no drag, no virtualization), filter
>   paused, create/edit/delete blocked while staged, fenced apply, 409 =
>   visible discard with the required copy, membership-change discard.
> - **Commit review** (`CommitReview`): fresh draft+policy capture on
>   open; the reviewed candidate generation fences the commit; diff
>   counts + names, shadow findings with the advisory disclaimer and a
>   Policy Tester link, required comment; success only after refreshed
>   truth agrees (else a controlled inconsistency posture); known
>   failures surface the server's bounded detail (incl. draft-retained
>   persistence failures) and clear nothing.
> - **Default action** (`DefaultActionControl`): separate immediate-live
>   T2 ceremony (never staged, even with Require Commit armed), its own
>   unknown latch resolved only by a fresh successful GET.
> - **Cross-cutting**: one policy-mutation request owner per surface;
>   page-level unknown latch resolved only when BOTH policy and draft
>   refetches succeed with advanced stamps; auth-boundary cleanup clears
>   editor/reorder/dialog/conflict state; targeted dirty-route guard
>   (react-router blocker + beforeunload) for editor + staged reorder.
> - **Real-binary proofs** (`e2e/policy-2b.spec.ts`): 500-rule-scale
>   edit/create/delete and reorder cycles, two-client live fencing (real
>   server 409), shared-draft actor warning + stale-draft conflict +
>   commit-fence refusal of unreviewed changes, draft/commit/live reload
>   durability, revert ceremony, default-action ceremony with restore.
>   §19 discipline: every mode-touching test restores live mode + no
>   draft + fixture order + default action (RequireCommit persists in the
>   SHARED `/data` admin settings). The STRANDED draft state is not
>   constructible through supported public APIs by design (disarm refuses
>   while dirty), so its posture is proven at component level against the
>   decoded real contract — recorded, not papered over.

### FE-6 — Cluster, identity, certificates, settings, releases, support, MCP, decryption
- **Objective**: FE-V27..V30, FE-V33, FE-V35, FE-V36 (settings decomposed per IA §5),
  FE-V37, FE-V04/05, FE-V07..V15.
- **Dependency**: FE-5. **Size**: L (~12 PR slices).
- **DoD**: config export/import/rollback truth-telling (dry-run preview, partial-failure,
  `runtime_only_surfaces`, redaction disclosure); release degraded states; support-bundle
  lifecycle with in-app passphrase dialog; MCP ticket/unknown-state semantics.
- **Browser proof**: release operation (fake-agent fixture), config rollback, support bundle
  create→approve→download, MCP rollout rehearsal.
- **Exit gate (evidence)**: parity matrix 38/38 rows DONE or descoped-with-sign-off.

### FE-7 — Destructive & security ceremonies hardening
- **Objective**: sweep every T1/T2/T3 + MCP-D + 2P ceremony against contract §6; add the two
  new ceremonies (release dispatch T3, cert upload T2); replace the 5 native-dialog flows;
  failure-injection UX (network error mid-ceremony ⇒ unknown-state rendering).
- **Dependency**: FE-6. **Size**: S–M.
- **Exit gate (evidence)**: **destructive-ceremony mutation suite green** — automated specs
  proving the typed-word gate cannot be bypassed (Enter, double-submit, stale ticket) and
  every ceremony's failure path renders unknown-state, per ceremony in the parity §C list;
  checklist signed.

### FE-8 — Parity, hardening, cutover
- **Objective**: the new app moves to `/`; **the legacy frontend
  (`static/index.html` + its serving path, nonce generation, and shell substitution) is
  removed from the shipping tree in the same release** — no `/legacy/` route, no transition
  release. The legacy-coupled tests (the ~29 markup-scan tests and the playwright-go `uie2e`
  suite, which read or drive that file) are removed **in the same PR** as the file they
  depend on — the tree must never contain tests for a UI it no longer ships. A11y pass (axe + manual keyboard/SR walkthrough per UX-PRINCIPLES §12, contrast
  audit closing M4); performance budgets enforced in CI; malformed-API-response and
  backend-unavailable behavior; the strict CSP becomes the `/` policy; the Playwright lane
  flips from advisory to required.
- **Dependency**: FE-7 + parity complete + **SEC-C2 landed**. **Size**: M.
- **Exit gate (all evidence, no elapsed time)**:
  - five identical hermetic frontend builds (FE-1A lane, re-proven at cutover commit);
  - two identical final binaries per supported target;
  - **full required E2E suite green across three clean runs** (all 16 required flows: first
    setup, login/logout, expiry, role differences, diagnostics, policy mutation, failed
    mutation, destructive confirmation, release operation, SSE reconnection, polling
    cleanup, refresh/deep link, backend unavailable, malformed response, CSP enforcement,
    theme) against the real binary with the embedded bundle;
  - automated polling/SSE memory soak green;
  - **rollback rehearsal**: build N−1 image restored over a data dir written by N, admin UI
    functional (documents that rollback is image/commit rollback);
  - 38/38 parity rows signed;
  - destructive-ceremony mutation suite green;
  - strict-CSP production-browser run with zero violations.
- **Rollback**: image/commit rollback (rehearsed above). There is no runtime legacy route.

### FE-9 — Legacy residue sweep
- **Objective**: FE-8 already removed the shipping legacy UI **and** its coupled tests (the
  markup-scan tests, the `uie2e` suite, `static_read_wall_test.go` /
  `static_index_path_test.go` — all read or drive `static/index.html` and go with it). FE-9
  sweeps the residue: the `uie2e` npm-driver workaround in `proxy-ui-e2e.yml`, the
  experimental `/app/` flag plumbing (the flag disappears once `/` is the app); replaces any
  remaining `static/logo.png` usage with the optimized assets; updates
  `roadmap/FEATURE-COVERAGE.md`, `qualification_manifest_test.go` citations, D0/C1 counts;
  marks superseded design docs historical.
- **Dependency**: FE-8 exit gate. **Size**: S.
- **Exit gate**: repository grep proves no reference to `static/index.html` remains outside
  historical docs; maintainer sign-off recorded in the PR.

## 4. Test migration disposition

| Current test family | Disposition |
|---|---|
| D0 / C1 / C1.5 / C2 / C2c / C4 / C3, `config_surfaces_test.go`, `apicontract_*`, `data_surfaces_test.go` | **Keep untouched** (backend contracts). Route-count locks updated only via the normal four-place convention when FE-1B adds serving routes. SEC-C2 adds wildcard coverage to the C2 suite. |
| `ui_redesign_foundation_test.go` (air-gap, no-inline-handlers, no-native-dialogs, typed-confirm coverage, chart caching, CSP) | **Re-express intent** against the new bundle in FE-1A/FE-2: bundle-scan test (no external origins, no inline scripts/styles at all), ESLint bans, ceremonies-coverage component test, strict-CSP browser assertion. Delete the markup form with the legacy UI in FE-8. |
| `ui_danger_quiet_test.go`, `pac_exceptions_uicontract_test.go`, `authpolicy_phase*` UI funcs, `policy_learning_m5*` GUI funcs, `*_gui_test.go` panel-render funcs, `ui_idp_secret_redaction_test.go`, `decryptprofile_cert_contract_test.go` | **Replace with behavior tests** in the owning feature's FE-5/FE-6 slice (component tests for copy/roles/secret-redaction; a shared-constant test for the cert enum). API-only funcs in the same files are kept. Delete markup funcs with the legacy UI in FE-8. |
| playwright-go `uie2e` (32 specs, `#id` selectors, httptest-mounted) | **Superseded** by @playwright/test 1.62.1 TS specs against the real binary (role/label selectors), written per phase. Legacy suite keeps running against the legacy UI until FE-8 removes both together; FE-9 sweeps its CI workflow residue. |
| `static_read_wall_test.go`, `static_index_path_test.go` | Retire with the legacy UI in FE-8 (their premise disappears with the file). |

## 5. Performance & dependency budgets (CI-enforced from FE-2)

| Budget | Target |
|---|---|
| Initial JS (shell + app core, gz) | ≤ 250 KB |
| Initial CSS (gz) | ≤ 40 KB |
| Per-feature lazy chunk (gz) | ≤ 150 KB (charts chunk ≤ 90 KB incl. Chart.js, if it passes its gate) |
| Images | logo re-exported ≤ 30 KB (SVG or ≤128 px PNG) + proper favicon set; replaces the 4.16 MB PNG |
| Interaction readiness (appliance-served, LAN) | shell → interactive dashboard < 1 s on a mid laptop |
| Long-running memory | automated dashboard soak: stable heap (no per-tick growth) |
| Runtime deps | react, react-dom, react-router, @tanstack/react-query, chart.js (conditional), radix per-component (OQ-2) — anything else needs written justification |

Feature-level lazy loading is mandatory where it moves the initial budget (MCP suite, charts,
support, cluster). Exact-pinned direct deps + lockfile; licenses + vulns scanned in CI
(FE-1A); notices + SBOM include frontend deps; every dep replaceable; no dep that requires
inline style mutation.

## 6. Risks (ranked) and mitigations

1. **Ceremony fidelity** (MCP rollout, T3 words, 2P rotate) — contract §6 checklist + FE-7
   mutation suite + failure-injection specs.
2. **Silent capability loss** across 38 views / 189 endpoints — parity matrix as a hard FE-8
   evidence gate; per-PR parity-row updates.
3. **Build determinism** (Rolldown output vs the deep-gate binary comparison) — FE-1A proves
   five identical hermetic builds before any serving change; committed dist keeps Go-only
   paths inert.
4. **Auth/session edges** (TOTP state machine, bootstrap window, SSE re-auth, boundary
   teardown) — FE-3 security-review gate; real-binary E2E.
5. **Policy draft/reorder concurrency semantics** — version-fence component tests + E2E
   conflict spec.
6. **npm supply-chain introduction** — exact pins, lockfile, `ignore-scripts` target posture
   (validated FE-1A), license/vuln lanes, drift gate, SBOM/notices coverage.
7. **CSP regressions from tooling** (inline preload polyfills, dev-mode HMR, chart library
   style writes) — FE-1B/FE-2 strict-CSP browser proofs assert zero violations in the
   production bundle; Chart.js is conditional on passing exactly this.
