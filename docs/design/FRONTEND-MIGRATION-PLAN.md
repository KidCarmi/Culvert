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
> | **2D** | Objects & Taxonomy: URL categories (+hosts, lookup, feed status), SaaS feed settings/overrides/refresh, category groups (+rename), decryption profiles (+rename, cert-enum lockstep), file profiles, rewrite. **Internal review decomposition (2026-08-28, checkpoint boundaries only — product scope unchanged): 2D-A** Category Groups + Decryption Profiles (shipped — see the 2D-A record below); **2D-B** URL Categories + SaaS feed/settings/overrides/status/refresh; **2D-C** File Profiles + Rewrite Rules. Two already-discovered later gates, recorded here and deliberately NOT solved in 2D-A: **(2D-B)** the URL-category PUT path needs the same 10,000-host cap the POST path enforces, and taxonomy writes need truthful durability (the urlcat store's Save is still best-effort); **(2D-C)** File Profiles are ID-bearing objects but Policy references them by NAME (`FileProfile`), and Rewrite Rule IDs are process-local integers, not durable identities — both need their reference/identity model settled before a v2 write surface. | 2D-A shipped |
> | **2E** | Scanning / Content Security / Decryption / CDR: blocklist (+feeds/exceptions/mode T3), Content & Scanning (YARA/DPI/exclusions/threat feeds/cache/saturation), decryption exclusions + tunables + health (pulled forward from FE-6 for cohesion with 2D profiles), CDR | pending |
> | **2F** | Network: PAC (profiles/pools/lifecycle/simulator/analyze/posture/exceptions + server-named DIRECT-bypass T3 ceremony) + Upstream (write-only credentials, direct-fallback banner) | **2F-0 entry gate shipped — contract approved (see the 2F-0 record below)** |
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
> - **Harness debt addendum (2B.7a/b)**: two more shared-`/data` premises
>   are now API-established by `e2e-smoke.sh` before seeding — the AUTH
>   log-store ENABLEMENT (boot state inherits the previous run's
>   `admin_settings.json`) and the disk-guard threshold
>   (`criticalDiskPct=99`: the dev machine's session disk allowance makes
>   statvfs read ~91% used permanently, so the default 90% threshold made
>   the LogGuard — correctly — engage emergency minimal logging and clean
>   retained history mid-suite, destroying the seeded evidence).

> **Slice 2C implementation record (this branch, 2026-08-28).**
>
> **2C.0 backend hardening (2C.0a/0b/0c)** — the Stage-1 auth-policy API
> gains the 2B write discipline, transposed to the RUNNING domain:
> - **`fencedRunningMutate`** (policy_mutation.go) is the EXPLICIT
>   running-domain seam: the `?ifVersion=` fence, the mutation, and the
>   durable persist share ONE coordinator critical section, ALWAYS against
>   the running store. It never resolves to the draft candidate, regardless
>   of Require Commit — the domain choice is the function name, not a mode
>   flag. The 2B primitive's live branch is factored into the shared
>   `runningMutateLocked` (durable-or-nothing; `ErrReplacedNotSynced`
>   counts as landed, commit doctrine).
> - **Stable-ID addressing**: `PUT/DELETE /api/authpolicy?id=<ULID>`
>   (strict — malformed 400, unknown 404, access-rule 400, never a priority
>   fall-through), legacy `?priority=` kept for the deprecation window; the
>   target is re-verified INSIDE the fenced section. `GET /api/authpolicy`
>   serves `version`/`updatedAt` from the RUNNING generation (never a
>   candidate's). Reorder accepts the stable-ID `{ids:[…]}` shape (every
>   auth rule exactly once; duplicate/partial/unknown/malformed/access-rule
>   entries rejected; resolved against ONE fenced running snapshot; access
>   ordering untouched by construction) alongside legacy `{priorities}`.
> - **`GET /api/policy/draft` gains `baseStale`** (active drafts only) —
>   the SAME backend truth as the commit's fail-closed base-generation
>   guard, surfaced for the UI (§8).
> - **2C.0c**: `PUT /api/settings/default-auth-outcome` is
>   durable-or-nothing via `setDefaultAuthOutcomeChecked` (it used to 200
>   after a persist failure that would silently revert on restart).
> - **Proofs**: concurrency pairs (edit/edit, create/create, delete/edit,
>   reorder/edit — exactly one winner, structured 409 loser), strict-ID
>   matrix, running-domain invariant end-to-end (auth mutation lands live
>   under an active Stage-2 draft; candidate untouched; draft baseStale;
>   commit 409), durable-or-nothing fault injection + restart-visibility
>   for all four mutation classes, default-outcome rollback.
>
> **2C.1–2C.3 Authentication Rules surface** —
> `/app/policies/authentication-rules` (nav: Policies → Access Rules,
> Authentication Rules, Policy Tester, Policy Learning); viewer+ read,
> **ADMIN-only writes** (backend is intentionally stricter than the Stage-2
> operator surface; viewer AND operator mount zero mutation controls).
> Dedicated `AuthRuleView`/`AuthRuleWrite` DTOs derived exactly from Go
> (`SubjectMatch` cidr-only predicates, `AuthRuleSpec`); unknown outcomes
> and unknown predicate types FAIL CLOSED into explicit markers — degraded
> read-only rendering, `writeSeedFromAuthView` refuses to seed. Exempt is
> presented as a warning-class waiver with the server's note verbatim —
> never green "allowed" semantics. SSORequired provider references come
> from the authoritative IdP read API (no secrets; dangling refs marked
> "unresolved", preserved, never silently dropped). Server warnings render
> verbatim. Every save is labeled LIVE; with an Access-Policy Draft active
> the editor warns the save invalidates that draft's baseline (§9), and the
> 2B DraftBar gains the critical "Draft baseline is stale" state that
> withholds the commit entry (revert stays). The global default outcome is
> a TIER-3 typed ceremony in both directions (OPEN → Exempt, REQUIRE →
> Default, exact §19 copy); an unrecognized current value blocks all change
> (fail closed).
>
> **2C.4–2C.6 Policy Learning surface** — `/app/policies/learning`:
> NODE-LOCAL and ADVISORY ONLY rendered from the server's own notes;
> factual quality signals only (no invented health/confidence); snapshot
> model (no polling/SSE/auto-generate/auto-accept). Governance (admin):
> enable/disable T2 with the active-session 409 verbatim, guardrail
> category allowlist editor, thresholds READ-ONLY (no sliders — M5A).
> Sessions (operator+): start/complete T1, cancel T2, generate as an
> explicit action with the engine's factual summary. Recommendations:
> full-fidelity decode (evidence/coverage/policy transparency/baseline/
> SERVER-computed staleness/decision metadata). **Accept to Policy Draft**
> preserves the M5B contract exactly: admin-only, fresh + `generated` +
> `draft_mode_armed` only (absent otherwise; the page never arms Require
> Commit), body exactly `{id, action:"accept", if_version}`, success
> renders server truth + a "Review created rule" deep link, §33
> post-accept agreement check (disabled rule in the active draft, else a
> controlled inconsistency). Reject is operator+, decision-only, bounded
> reason. An unconfirmed Accept latches and is never blindly repeated.
>
> **Real-binary proofs** (`e2e/policy-2c.spec.ts`): admin CRUD journey,
> operator read-only posture, two-client fencing (real 409 + reorder/edit
> one-winner), the flagship §39 proof (LIVE auth mutation → draft
> `baseStale` → DraftBar critical → commit 409 → revert recovery), both
> T3 ceremonies with restore, and the honest learning journey (enable →
> session → proxied traffic → complete → generate: unauthenticated
> traffic lands in the synthetic `s:unauth` scope, so ZERO generated
> recommendations is the honest outcome; the accept path is proven by the
> M5B backend suite + the unit contract tests — no production fake data).
> The first full-suite run caught three real defects the mocked layers
> could not (recorded in the 2C.7 commit): the default-outcome read
> surface is `GET /api/settings` (not `/api/security`), `KNOWN_ROUTES`
> needed the 2C routes, and the shared-`/data` logstore boot race needed
> per-instance `log_store_path` premises (harness debt addendum: the
> FRESH/SETUPFAIL instances now carry their own paths, making the history
> journeys deterministic).
>
> **2E-C — CDR / Sluice Integration (this branch, 2026-08-30).** Final
> sub-slice of the 2E decomposition: `/app/security/cdr` (Overview &
> Health / Instances / Policies / Test — four sections because the actual
> contract is that simple: the only runtime-mutable configuration is the
> `enabled` boolean, so it lives on Overview instead of a forced
> Configuration tab). Every CDR surface is NODE-LOCAL by recorded backend
> design (no export/import, no rollback, no CP→DP sync; mutations are
> audited but deliberately never create config versions — the revoke path
> pins that as a security invariant: a rollback must never un-revoke).
>
> **Backend corrections (RED-first at the 2E-B frozen predecessor
> 42296756; matrix `cdr_2ec_red_test.go`, R1–R5 each verified failing
> there, R3 under `-race`):** (R1) PUT /api/cdr/config metadata hid the
> audit event the handler emits (`AuditExpected` now true); (R2) DELETE
> shredded the client cert without recording its SHA-256 fingerprint —
> the ONLY key Sluice accepts for revocation — anywhere durable, leaving
> an untraceable trust orphan; the fingerprint is now recorded at enroll
> (fail-closed: an unfingerprintable issued cert refuses the enrollment),
> refreshed on renewal, surfaced on GET, preferred by revoke, and carried
> in the DELETE audit + response; (R3) the health poller mutated registry
> entries through shared pointers with no lock while the instances GET
> rendered them (data race) — locked mutators + value-snapshot reads;
> (R4) registry/policy Save ran outside the mutation lock, so a
> concurrent poller Save could resurrect a deleted/revoked instance in
> the durable file — mutate+persist is now one critical section with
> durable-or-nothing rollback; (R5) policy names (the sole DELETE key)
> accepted duplicates — now a 409 identity conflict. OpenAPI corrected to
> the implemented surface (real audit-event names, enroll documented
> NON-idempotent — the Sluice token is consume-and-delete single-use,
> proven from the engine source — revoke documented idempotent-at-Sluice
> with the second-instance 503, response codes and request shapes fixed).
>
> **Trust semantics the UI states exactly:** DELETE is local-only (Sluice
> keeps trusting the fingerprint until expiry or a Sluice-side
> revocation; the T3 typed ceremony and the completion notice both carry
> it, and steer compromise cases to Revoke BEFORE delete forecloses it);
> REVOKE is irreversible, requires a second enrolled instance, and is
> safe to retry after an unknown outcome (idempotent at Sluice);
> enrollment consumes its token even when the response is lost, so the
> unknown-outcome path clears the token, forbids blind retry, and gives
> the exact recovery (fresh list = landed; otherwise new token + possible
> orphaned cert in the engine ledger). Fail-mode is rendered verbatim
> with the server-derived `failOpen` and a fail-open warning; "engine
> answered its last probe" is never widened into a production-traffic
> claim, and the cached health snapshot is flagged stale via the live
> poller's consecutiveFailures.
>
> **Secret hygiene finding from the e2e journey:** a controlled password
> input's value is serialized into the DOM, so a dispatched single-use
> enrollment token was reconstructable from `document.body.innerHTML`
> after a failed dispatch. The token field is now cleared on EVERY
> dispatch outcome; the e2e proof sweeps both storages and the serialized
> DOM. Proofs: Go red/green matrix + full CDR suites, frontend unit
> suites (cdr-api 9, cdr-page 6), real-binary Playwright journey
> (5 tests: viewer GET-only posture, T2 toggle round-trip restored,
> truthful 502 enrollment with residue sweep, policy
> add/409/transport-lost-latch/delete with /data hygiene in finally,
> bounded no-active-client test) + cross-surface sweep pinned to
> /api/cdr/*.
>
> **Deferrals (recorded):** 2F and everything beyond stay OUT of this
> slice — no FE-6/FE-7/FE-8 work, no Batch-2 PR mechanics, and the
> legacy `static/index.html` CDR panels are untouched. A live-Sluice e2e
> (real enroll/renew/revoke through the browser) is deferred with the
> harness note that the Go suites cover those RPC flows against an
> in-process fake engine. Instance disable/enable (the registry's soft
> `enabled` flag) has no admin API endpoint — surfaced read-only,
> recorded as a backend gap for a future slice, not invented client-side.
>
> **2E-C TRUST-LIFECYCLE CORRECTION (this branch, 2026-09-02).** External
> review REJECTED candidate 978f95b5: five trust-lifecycle defects, each
> pinned RED-first at exactly that SHA (`cdr_2ec_tl_red_test.go`, 8 tests,
> plus the frontend `cdr-enroll-recovery.test.tsx`, 4 tests) and closed
> with a protocol change on the engine side (Sluice v0.3 contract,
> `KidCarmi/Sluice` branch `claude/culvert-2ec-trust-lifecycle`, pinned as
> `v0.2.1-0.20260902055746-d6d4394ab74f`) — not with UI copy.
>
> **R6 — revocation proves an effective durable deny.** The appliance
> discarded `RevokeClientResponse.Revoked`, and the engine treated an
> unknown fingerprint as a no-op, so a response that proved NOTHING still
> produced 200, a pruned registry, shredded PEMs and a success audit.
> Sluice now returns an explicit outcome (`REVOKED` / `ALREADY_REVOKED` /
> `TOMBSTONED` — an unknown fingerprint becomes a durable deny tombstone),
> every ledger mutation is persist-before-publish under one lock (a failed
> write leaves memory and disk unchanged and is retried; a restart
> preserves every acknowledged deny; a revoked/tombstoned fingerprint can
> never be re-recorded as issued). The appliance prunes/shreds/audits ONLY
> on that proof (or a v0.2 `revoked=true`); anything else is 502 and
> changes nothing, and "unknown fingerprint" is never presented as
> "already safely revoked".
>
> **R7 — renewal preserves the complete credential lineage.** RenewCert
> does not retire the presented certificate, yet the appliance overwrote
> the PEMs and the ONE recorded fingerprint, so the still-valid predecessor
> became unidentifiable; a renewal decided before a delete resurrected
> PEMs; a persistence failure after the swap left new PEMs + an old
> durable fingerprint. Option B implemented (`cdr_lineage.go`): a bounded
> (16) durable generation list per instance with per-generation state
> (`renewing → staged → active / superseded / orphaned / revoked`); only
> revoked/expired generations are ever pruned and renewal is REFUSED when
> the cap holds live ones. Renewal is a recoverable transaction: the
> intent (operation id) is durable BEFORE the RPC, the issued fingerprint
> is durable BEFORE any PEM is written, activation is the last durable
> step, and `reconcileCredentialLineage` finishes or abandons an
> interrupted swap at boot (each crash boundary pinned); a lost RPC
> response is resolved by the poller through `EnrollStatus` (issued ⇒
> orphaned + audited, not issued ⇒ dropped). Renewal, revoke, delete and
> enroll of the same instance are serialized on a per-instance lifecycle
> lock and the renewal re-validates the immutable instance identity under
> it. Revoke covers every live generation with durable per-generation
> progress; delete's audit + response name every orphaned fingerprint.
>
> **R8 — identifiable unknown-outcome recovery for enrollment.** Every
> dispatch carries a 128-bit operation id (client-minted, server-minted
> when absent) that Sluice binds durably to the issued fingerprint before
> responding (`EnrollRequest.operation_id`, `EnrollStatus`, at-most-once
> refusal with the fingerprint, bundle discarded when the durable record
> fails). The appliance persists a NON-SECRET receipt BEFORE the RPC (no
> receipt ⇒ 503, nothing sent), upgrades it to `issued_not_stored` WITH
> the fingerprint + an audit record on a local commit failure, and
> exposes `POST /api/cdr/instances/enroll/recover` (fresh authoritative
> classification `LANDED_AND_STORED` / `ISSUED_BUT_NOT_STORED` — with the
> exact revocation path: API by fingerprint or the Sluice-host CLI — /
> `NOT_ISSUED` / `AMBIGUOUS`), `GET|DELETE …/enroll/receipts`, and revoke
> by fingerprint. The browser writes a verified, subject-bound marker
> (`culvert.cdr.enroll-recovery.v1`, never the token) BEFORE the POST —
> no marker ⇒ nothing is sent — keeps it across reload for an unresolved
> outcome, resolves it against the engine, and offers the orphan
> revocation T3 ceremony (proof required) or an explicit abandon.
>
> **R9 — strict config action contract.** `PUT /api/cdr/config` decoded
> `{}` as `enabled=false` (a silent disable). Presence-aware decoding now
> refuses `{}`, `null`, a missing/non-boolean `enabled`, unknown fields,
> trailing JSON and an empty body with 400 and provably mutates nothing
> (runtime flag, sentinel, audit); valid bodies stay idempotent.
>
> **R10 — policy identity across restart.** Uniqueness lived only in
> `Add`; a pre-2E-C durable file with duplicate/empty names loaded and
> DELETE silently chose a victim. Identity (trimmed, non-empty, unique)
> is enforced in Load/Replace/Add; a legacy file loads VERBATIM as
> DEGRADED (`integrity` on GET), adds are refused, delete by an ambiguous
> name is refused, and the operator repairs by fenced position
> (`DELETE ?name=<verbatim>&position=<n>`, only while degraded); the
> Policies tab renders the degraded state and the repair ceremony.
>
> **Proofs:** RED matrix at 978f95b5 (each test fails for the named
> reason; evidence logs in the report), post-fix Go suites incl. `-race`,
> `cdr_2ec_tl_green_test.go` (13: proof matrix, lineage revoke progress,
> crash boundaries, lost-response reconciliation, cap, receipts before
> dispatch, storage failure, duplicate operation, handler persist failure,
> recovery classification, auth boundary, orphan revoke, degraded repair +
> restart), `cdr_sluice_integration_test.go` (the PINNED Sluice daemon
> built from the module cache and driven end to end with a restart —
> outcomes, tombstone, bindings and the deny survive), Sluice's own v0.3
> suites, frontend unit suites (29) and the rewritten real-binary e2e
> proof 4 (unresolved outcome → resolve AMBIGUOUS → abandon; receipts
> removed in finally). Route count 238 → 240; OpenAPI + generated types
> reconciled.
>
> **2E-C TRUST-LIFECYCLE CORRECTION — ROUND 2 (this branch, 2026-09-02).**
> Review of candidate d567f4d5 found two remaining ways the appliance could
> forget the only identity of a credential Sluice may trust. RED-first at
> exactly d567f4d5 (`cdr_2ec_tl2_red_test.go` 13/13 FAIL,
> `cdr_sluice_integration_tl2_test.go` FAIL on the pinned daemon,
> `cdr-tl2-red.test.tsx` 8 FAIL / 5 baseline), then corrected.
> **R11 — unresolved renewals block destructive lifecycle operations:** a
> `renewing` generation (durable operation id, no fingerprint yet) is a
> trust identity; DELETE and revoke-by-name now resolve every one of them
> SYNCHRONOUSLY and AUTHORITATIVELY through `EnrollStatus` over the
> credential-less bootstrap channel (works with CDR disabled, no pool, no
> poller, right after a restart) under the lifecycle lock BEFORE any
> mutation — NOT_ISSUED drops the intent, ISSUED binds the fingerprint
> durably (orphaned / revoked) and it is then reported as still trusted or
> included in the whole-lineage revocation with proof; unreachable,
> unsupported, malformed or unpersistable outcomes return 503/409 with
> zero prune, zero shred, zero success audit, zero loss of the id.
> **R12 — the enrollment operation binding is immutable:** receipt
> creation is an atomic create-if-absent (plus an operation-id lock around
> check+create), so a repeated dispatch of an operation id — concurrent or
> serial, any name, any endpoint, an exact retry included — performs NO
> RPC and is refused (409 naming the state + recovery path); Update can
> change only state/fingerprint/note; recovery uses the bound endpoint +
> pin and refuses conflicting caller values before any network activity
> (receipt-less recovery still accepts explicit values); DELETE refuses
> unresolved receipts (409) and only terminal ones are removable; a
> receipt file with duplicate ids, bad grammar, impossible states, missing
> identity fields or more than the cap loads DEGRADED (integrity on GET,
> creation refused, fenced positional repair); a failed receipt
> transition is reported (`receiptRecorded`/`receiptUpdated` false with
> the error) and the previous durable state is kept. Browser Abandon
> clears only the marker. **R13 — truth:** the enrollment result carries
> the ACTUAL post-operation facts (stored, cdrEnabled, clientActive,
> autoEnable attempted/succeeded/error, receipt state) — a sentinel write
> failure is rendered as "CDR is still disabled … Do not re-enroll", never
> as "auto-enabled"; the browser marker read-back compares every written
> field and validates the full grammar (operation id, non-empty identity
> fields, SHA-256 pin form, finite timestamp). The e2e harness now runs
> the PINNED Sluice daemon (real mTLS, first-boot token) so the browser
> enrollment journey is a genuine exchange, a genuine definite refusal, a
> lineage-aware delete and the receipt-immutability/AMBIGUOUS proofs on
> the real appliance. Recorded harness debt: the deliberately unresolved
> receipt created by that proof is, by contract, not removable and stays
> on the shared /data (bounded by the receipt cap; terminal receipts are
> pruned first).
>
> **2E-C FINAL QUALIFICATION CORRECTION — full-suite Playwright gate (this
> branch, 2026-09-02).** Review of candidate 5a2e948c held the complete
> real-binary Playwright suite as the remaining blocker: the policy-learning
> journey in `policy-2c.spec.ts` failed in three consecutive full runs (twice
> at the session-start assertion, once at the enable assertion) while
> passing 8/8 in isolation. **Root cause (harness identity sharing, not a
> product defect):** the admin plane refuses more than `lockout.Burst` (60)
> mutating API requests per `lockout.RateWindow` (one minute, FIXED window)
> from one real client IP — a deliberate, hard-coded security posture that
> stays fully armed. `realClientIP` honours X-Forwarded-For only from a
> trusted proxy, and the harness establishes loopback as one (RISK-019)
> through the supported network-settings API; the multi-client API specs
> already presented their own identities, but every BROWSER context the
> suite opened presented the bare loopback peer, so that one budget was a
> suite-length shared resource across all page-driven specs. A traced full
> run showed the server window opening during `policy-2b` and holding 50
> loopback mutations when the enable PUT arrived (54 by the end of the
> journey, all inside one window); faster untraced runs (1.9–2.1 min vs
> 3.1 min traced) pushed the count past 60 exactly at the journey's first
> page-driven mutations — the enable PUT or the session-start POST, the two
> assertion sites observed — and the page rendered the refusal truthfully
> (dialog alert "Action failed Too Many Requests") while the 5 s assertion
> waited for the success text. Not shared-/data contamination, not the CDR
> receipt, not readiness, not learning-state reset, not eventual consistency.
> **RED regression, committed before the fix:**
> `e2e/admin-budget-isolation.spec.ts` spends the loopback budget through
> the supported login endpoint until the appliance refuses, then requires
> the enable ceremony to succeed in the browser — RED at 5a2e948c AND at the
> rejected predecessor d567f4d5 with the identical failure text as the
> full-suite runs (round 2 did not change the behaviour; the sensitivity
> predates it). **Correction (harness only, production unchanged):**
> `e2e/test.ts` is the suite base every spec imports `test` from; it derives
> a DETERMINISTIC per-test client identity (private-range, from Playwright's
> stable testId) and overrides the `extraHTTPHeaders` option so the default
> context, `page.request`, and — because Playwright applies the test's
> context options to every `browser.newContext()`/`request.newContext()`
> call that does not name the option — additional contexts present it too;
> the two specs that open explicit contexts pass it visibly through
> `identityHeaders(clientIdentity)`; a client that must be the bare loopback
> peer names `extraHTTPHeaders: {}`. Sessions are signed cookies, not
> IP-bound, so the shared storageState still authenticates; FRESH/SETUPFAIL
> trust no proxy and ignore the header by construction. Not done, by
> directive: no timeout widening, no retries, no skip/quarantine, no weaker
> assertion, no production-API receipt deletion, no suite reordering — and
> no product change: the rate posture is correct; only the harness compressed
> hours of admin activity from one address into one minute. **Separately
> observed, recorded, not corrected here:** once, with the regression running
> immediately before `policy-2c`, the two-client auth-fencing proof's
> concurrent reorder-vs-edit race returned `[200, 400]` instead of the
> accepted `[200, 409|404]`: `apiAuthPolicyUpdate` pre-validates the edit
> (target resolution + `validatePolicyRule`) OUTSIDE the coordinator fence,
> so a reorder that lands between its unfenced version pre-check and its
> fenced mutate makes the stale edit fail validation (400) instead of
> receiving the structured 409. Exactly one mutation lands either way (the
> fence holds); only the loser's status is untruthful. A deterministic
> reproduction needs an interleaving seam the handler does not expose;
> recorded as a candidate product correction (move target resolution and
> validation inside the fenced closure), not silently widened in the test.
>
> **2E-C CONCURRENCY-STATUS CORRECTION — rule mutations validated inside
> the coordinator fence (this branch, 2026-09-02).** Review of candidate
> efafc9f9 held the product race disclosed in its report as the blocker: a
> concurrent reorder-versus-edit returned `[200, 400]` instead of the
> fenced `[200, 409]`. **Exact root cause:** every Stage-1
> (`/api/authpolicy`) and Stage-2 (`/api/policy`) rule-mutation handler
> resolved its target and ran its state-dependent validation OUTSIDE the
> coordinator's critical section — target existence and rule type,
> `validatePolicyRule`'s duplicate-name/priority checks against a list
> read before the fence, the reorder/move set and permutation computed on
> the pre-fence order, the bulk-delete auth-rule guard — and only then
> entered `fencedMutate`/`fencedRunningMutate`. The fence held (exactly one
> mutation landed, never a partial write), but a competitor landing in that
> window made the loser fail VALIDATION against changed state: the edit's
> stale exclusion slot let the duplicate-name check see the rule itself at
> its new priority ("rule name already exists", 400 — "your request is
> malformed" — for a request that had lost a state race); at the fence
> window the same pattern let two same-name creates both succeed, a
> priority-addressed delete audit the wrong rule, an unasserted reorder
> apply a stale permutation over a changed set, a move honour a stale
> relation, and an operator bulk delete remove an admin-managed auth rule
> that had taken a freed priority. **Deterministic RED (committed first,
> `policy_fence_interleaving_test.go`, no sleeps):** the test-only
> `policyWriteStateDecision` seam lets a test park one request at the
> "resolved" (structural work done, about to validate) or "fence" (about
> to enter the coordinator) stage while a competitor commits through the
> real handler, then release it; 8 of 9 cases were RED on exactly the
> defects above, the fenced delete-by-id control green. **Correction:**
> `validatePolicyRule` is split into `validateRuleShape` (state-independent,
> pre-fence 400) and `validateRuleUniqueness` (in-fence); every handler
> resolves its target, checks rule type, uniqueness, the order set and the
> move relation INSIDE its fenced closure against that snapshot, and reports
> refusals through `fencedRefusal` → `writeFencedRefusal`. **Status
> semantics:** 400 only for input that is wrong on its own terms (grammar,
> shape, a missing name, a duplicate entry inside the client's own list, an
> id that belongs to the other rule type — an id never changes type) or, WITH
> a matching `ifVersion`, a request that conflicts with the very rulebase it
> asserted (reloading would change nothing); 404 when the addressed identity
> does not exist at the authoritative moment; 409 for the version fence
> (`{error, currentVersion, yourVersion}`) and, WITHOUT an assertion, for a
> request that conflicts with the CURRENT rulebase (`{error, currentVersion}`
> — refresh and reapply). The loser performs zero mutation, records no
> success audit, advances no version, and the priority-addressed delete
> audit names the rule that actually vanished. The one recorded contract
> shift: unasserted PRIORITY-addressed wrong-type refusals (an auth rule
> addressed through `/api/policy`, an access priority in an auth reorder)
> were 400 and are now 409 + currentVersion, because a priority can change
> type under a concurrent reorder; the corresponding legacy tests were
> updated to assert both the unasserted 409 and the asserted 400, plus zero
> mutation. The v2 frontend always asserts `ifVersion`, so its verdicts are
> unchanged except that a lost race is now the structured 409 it already
> handles. OpenAPI 400/404/409 descriptions updated for all seven paths.
> Gates: the interleaving suite ×100 under `-race`; the two-client auth
> fencing proof unchanged. R11–R13 and the per-test browser identity harness
> are untouched.
>
> **2E-B FINAL STORAGE-READ FAIL-CLOSED CLOSURE (this branch, 2026-08-30).**
> External review of the freeze candidate (465316df) found the last
> lifecycle defect: the recovery read collapsed "cannot read / cannot
> interpret the recovery store" into `null`, and `null` meant "no pending
> recovery" — a transient sessionStorage failure or an unsupported/
> malformed record forgot a pending operation and re-armed Rotate (the
> write-side fail-closed rule cannot help once storage recovers and a NEW
> operation writes its own valid marker). Red-before at the exact candidate
> (`decryption-recovery-storage.test.tsx`, 4 red + the true-absence control
> green). Closure: `readRotationRecovery` is RESULT-TYPED
> (`none | valid | unavailable | unreadable`) — "none" (storage readable,
> key absent) is the ONLY entry to the ordinary no-recovery state;
> "unavailable" blocks Rotate with the mandated copy and an explicit
> "Retry storage check"; "unreadable" (existing but malformed /
> unsupported-version record) blocks Rotate, never silently deletes, and is
> retired ONLY by the new admin-only T3 typed ceremony "Discard unreadable
> recovery record…" (word DISCARD; NO appliance mutation; VERIFIED removal
> — a removal whose read-back cannot prove absence keeps everything
> blocked; then re-inspection + authoritative refresh). No future-version
> migration logic. The subject-isolation rule is unchanged (a well-formed
> v1 foreign-subject marker still discards to "none"), and
> `writeRotationRecovery` verifies through the typed reader (read must be
> VALID with the exact operationId/preSeq). Frontend-only; backend,
> OpenAPI, receipts, freshness gate, and SPA-navigation semantics
> untouched.
>
> **2F-0 — PAC + Upstream ENTRY GATE AND APPROVED EXECUTION CONTRACT (this branch, 2026-09-02).** Slice 2F begins from the frozen 2E-C predecessor `220740b8` with an evidence-preserving merge of `origin/main@32eac4e7` (18 MCP live-tier commits since the merge base `12854863`; no PAC, upstream, frontend, OpenAPI or route-metadata file on either side; route pin unchanged at 241). 2F-0 records the externally approved C1–C12 execution contract below and implements NO PAC or upstream behaviour. Sub-slices 2F-A onward implement it verbatim; any deviation needs a recorded amendment here.
>
> **Discovery truth the contract corrects (frozen source, not the earlier plan wording).** PAC: profile/pool IDs are client-supplied immutable strings, rules have no identity, PUT carries `revision` with a `0` skip path and a plain-text 409, DELETE is unfenced, the lifecycle API (`save_draft|publish|rollback`) has NO legacy-UI consumer, publish writes the cluster-synced active store then the node-local lifecycle record (torn on second-write failure), and both `ProfileStore.Set` and `LifecycleStore.Put` swap memory BEFORE the durable write. The DIRECT confirmation is server-named (`confirmValue` = profile id) but the value is predictable and unbound to the reviewed candidate. Upstream: credentials live inline in the URL, `GET` redacts to `xxxxx`, `POST` replaces the whole list unfenced with an async save and drops invalid entries silently, export emits the redacted list and import writes `xxxxx` back as the password, the legacy UI re-POSTs the redacted list (any edit destroys every stored password), the pool is wired into the plain-HTTP transport only (PX-1: CONNECT/WebSocket/SOCKS5 dial directly), the probe runs only with a YAML interval, a new entry starts `Healthy`, and the probe classifier ignores the HTTP status (a 407 counts as healthy). Contradictions with the parity doc: both panels are ADMIN-only on every mutating route (parity row said operator); "lifecycle" is new surface, not parity.
>
> **C1 — Publish/rollback commit point and state machine.** The durable write of the cluster-synced active profile store is the ONLY authority; node-local lifecycle history is a projection. Both stores become persist-before-swap. A node-local `PendingOp{OperationID, Action, ProfileID, ExpectedActiveRevision, ExpectedActiveSpecDigest, CandidateSpecDigest, ChallengePoolDigest, ChallengeArtifactDigest, TargetN, Actor, TS, State}` is persisted BEFORE the active mutation; fence, pool snapshot, publish guard and the mutation are one serialized decision under `pacProfilesAPIMu`. After the mutation: proven failure ⇒ abort the intent (500, nothing changed); proven success ⇒ finalize history (revision appended once, keyed by `OperationID`); unknown ⇒ classify by reading the in-memory authoritative snapshot under the lock, never a recompiled artifact and never `ModTime`. A finalization failure after a proven commit responds 200 `{published:true, operationId, activeRevision, activeSpecDigest, historyState:"pending_reconciliation", scope:"node-local-history"}` and is never "not published"; there is no compensating rollback. `operationId` is client-supplied (UUID), required on publish/rollback/repair, at-most-once via a bounded per-profile decided-op ring that returns the recorded result. Crash proofs are required at every boundary: before intent persist, after intent before `Set`, after the active `AtomicWrite` before the memory swap, after `Set` before finalize, during finalize, and lifecycle-file corruption (existing quarantine; active store stays authoritative; `history_reset` acknowledged on the next publish).
>
> **C2 — Candidate-bound DIRECT confirmation.** The 409 challenge carries `code:"confirm_required"`, `confirmField:"confirm"`, an opaque `challenge` (versioned SHA-256 of the canonical binding, no secret), `confirmValue:"<profileId>:<candidateSpecDigest[0:8]>"`, and the full `binding{profileId, action, targetN, candidateSpecDigest, expectedActiveRevision, expectedActiveSpecDigest, poolDigest, artifactDigest, newDirectPaths sorted}`. The retry echoes `confirm{challenge, value}`; under the publish lock the server recomputes every bound fact and answers a fresh 409 `challenge_stale` naming the changed fields if any differ. A challenge is single-use for a commit; replay returns the recorded decision. Rollback uses the identical contract. Legacy `confirmDirect=<profileId>` stops being accepted when 2F-B lands (legacy JS switched in the same commit).
>
> **C3 — PAC fencing model (every mutation).** Profile: `revision` (stored) on PUT/DELETE/`save_draft`/publish/rollback (as `expectedActiveRevision`). Pool: `etag` = digest of canonical pool JSON on PUT/DELETE. Collection create (profile or pool): `collectionEtag` = digest of canonical `ProfilesConfig`. Legacy config: new monotonic `revision` on POST `/api/pac-config`. Exception record: new per-record `revision` (schema v2 tolerant) on PUT/DELETE. Draft: `draftRevision` on `save_draft`. Absent/zero token ⇒ 428 `precondition_required` carrying the current token (the `revision:0` skip path is removed; profiles loaded with revision 0 are bumped to 1). Mismatch ⇒ 409 `{error, code:"stale", current}` with zero mutation, no audit, no config version. Vanished ⇒ 404. Exceptions stay OFF config-version rollback and cluster sync but are fenced ("off rollback" ≠ "unfenced"). The shipping legacy `static/index.html` is patched in the SAME commit that introduces each 428 (`deletePACProfile`, `deletePACPool`, `savePacGov`, `savePACProfile` challenge echo); external callers omitting tokens get 428 with the current token, never a silent bypass.
>
> **C4 — Upstream entry, authority and credential model.** `UpstreamEntry{ID (server ULID, immutable, collision-checked), Scheme, Host (normalized), Port (effective), Username, Revision, Credential *Sealed{AuthorityHash, Ciphertext, KeyID, SetAt, SetBy}}`; `authority = scheme://username@host:port`; `credentialState ∈ none|configured|unusable|mismatch` (`unusable` = ciphertext present, node-local key cannot unwrap; `mismatch` = credential authority ≠ entry authority; neither is ever sent). Credentials are sealed at rest under `.upstream_cred_key` (RISK-003 webhook pattern: never archived, never minted on a failed read). The authenticated proxy URL is constructed ONLY inside `ProxyFunc` from a `configured` credential whose authority hash matches; nothing else holds a URL with a password. Authority change while a credential exists ⇒ 409 `credential_bound` (clear via T3 first, edit, then replace; no combined transaction). Credentials are keyed by entry ID + authority hash only; never copied by name, position, URL similarity or client-supplied ID. `credentialState`/`credential_configured` are derived; a request carrying them ⇒ 400. Replace, clear, edit and delete are `revision`-fenced, durable-before-respond (error-returning save core, not the fire-and-forget `adminSettingsSave`), and audited as `upstream.entry.create|update|delete` / `upstream.credential.replace|clear` with ID + authority, never the secret. New entries start `unprobed`.
>
> **C5 — Export/import/backup secret contract.** Export emits `upstream_proxies_v2` entries `{id, scheme, host, port, username, credentialState}` plus `upstream_credentials:"omitted"`; no `password`, no `xxxxx`, no legacy key; export schema version bumps. Import v2: a credential is preserved only when the ID resolves to exactly one existing entry AND the authority hash is unchanged; otherwise `requiresReplacement`. Legacy `xxxxx` key: versioned compatibility rule, preserve only on an exact-authority match to exactly one entry; a legacy key carrying a real password ⇒ 400 `credentials_not_importable`. Duplicate IDs ⇒ 400. Import report = counts only `{preserved, omitted, cleared, requiresReplacement}`. Backup posture: ordinary AND encrypted backups OMIT upstream credentials (tar writer strips `Credential`, manifest `credentialsOmitted:true`; key file never archived); secret-inclusive backups deferred. Leak assertions cover API bodies, error bodies, audit ring, captured logs, export file, import report, `diagnose upstream`, support collectors, config-version files, cluster snapshot, both backup modes, and the browser (network capture + storage/query-cache dump).
>
> **C6 — Legacy compatibility (additive v2 + safe v1 adapter, legacy UI switched atomically).** v2 endpoints: `POST /api/upstream/entries`, `PUT|DELETE /api/upstream/entries/{id}`, `POST /api/upstream/entries/{id}/credential {action:replace,password,revision | action:clear,revision,confirm:<id>}`. v1 `POST /api/upstream` survives for credential-free lists only: 400 on any userinfo; 409 `credentialed_entries_present` if any entry holds a credential; never mutates an individual credentialed entry. v1 `GET` keeps `url` (always without userinfo) and adds `credentialState`. The legacy UI is switched to v2 per-entry endpoints in the same commit (write-only add-credential form). Boot migration of raw legacy URLs is durable-or-nothing (C10). Downgrade is handled by `prepare-downgrade` (C10). No commit leaves a mutation route able to bypass the credential endpoint or destroy/rebind a secret.
>
> **C7 — Fixed decisions.** PAC and upstream mutations are admin-only (parity doc corrected in 2F-G). PX-1 stays deferred only because every surface reports `coverage.summary:"plain_http_only"`; no "protected"/"fully chained" wording anywhere. PX-2 stays fail-open with the effective DIRECT-fallback state prominent, persistent and backend-derived. Manual probe is admin-only, bounded and audited. Lifecycle, exceptions and probe results are labelled node-local everywhere. No frontend copy compensates for unresolved backend truth.
>
> **C8 — Configuration identity vs artifact identity.** Three canonical SHA-256 digests: `ProfileSpecDigest` (the `Profile` struct without `revision`), `PoolDigest` (the referenced pool), `ArtifactDigest` (compiler output, the existing `art.Digest`, kept as `PublishedRevision.Digest`). Commit and reconciliation compare `(activeRevision, ProfileSpecDigest)` ONLY; the challenge additionally binds `PoolDigest`, `ArtifactDigest` and the sorted `newDirectPaths`. Outcome classification never uses an artifact recomputed against a later pool. The spec-digest cache is keyed by `(revision, ProfileSpecDigest)` inside the lock; `ModTime` is display-only. A profile whose active spec equals the candidate stays `committed` if the pool later changes; the pool change is its own fenced mutation + posture event, surfaced as `poolChangedSince:true`. Reconciliation (startup, lifecycle GET, every publish): `(Expected+1, Candidate)` ⇒ finalize idempotently; `(Expected, ExpectedSpec)` ⇒ abort; other ⇒ `ambiguous`, publish/rollback 503 `lifecycle_ambiguous` until the admin `repair{operationId, resolution:"accept_active"}` (T2) records the OBSERVED spec digest as a new revision (`repaired:true`); repair never rewrites the active store.
>
> **C9 — No destructive bypass around credential clear.** `DELETE` of an entry with `credentialState ∈ {configured, unusable, mismatch}` ⇒ 409 `credential_present`; only `none` entries are deletable (clear T3 first). The v1 adapter provides no delete/clear path while any credential exists. Import is two-phase and atomic: an `importPlan` (`preserve|create|update|requiresReplacement` per incoming entry, `retain|remove` per existing) is computed over the whole file; any remove/update/authority change of a credentialed entry sets `credentialClearRequired:[ids]` and the import fails 409 `credential_clear_required` with the plan BEFORE any store (routing, PAC, anything) is touched. The existing Tier-2 import confirm is not digest-bound and therefore not equivalent T3 authorization; no new authorization path is added. `POST /api/config/import?dryRun=1` returns the plan (with `importDigest`) and applies nothing. Omitting a credentialed ID is a `remove`, never a silent clear.
>
> **C10 — YAML ownership, boot migration, downgrade.** YAML-seeded entries are READ-ONLY through the API/UI (`source:"yaml"`, 409 `yaml_owned` on any mutation), identity `"yaml-" + base32(SHA-256(authority)[0:16])` (128 bits), collision-checked against every managed and YAML ID at boot (collision fails YAML validation, fail-closed); no adopt transaction in 2F. Boot migration is durable-or-nothing: (1) if `upstream_proxies_v2` exists load it and ignore the legacy key; (2) parse every legacy URL, any failure ⇒ refuse (`migration.state:"degraded", reason:"parse_failed"`, legacy runtime unchanged); (3) open the key, create it ONLY when no v2 state and no ciphertext exist anywhere, never mint when ciphertext exists (`key_unusable`); (4) seal every credential in memory first; (5) `AtomicWrite` the complete v2 document once (managed ULIDs, sealed credentials, `revision:1`, legacy key rewritten credential-free); (6) swap memory only after a nil write (`persist_failed` otherwise); (7) degraded state on `GET /api/upstream`, the operator-contract row, a storage-class alert and a blocking banner; fault tests at every step plus crash before/after the rename. Downgrade: CLI-only `culvert --prepare-downgrade --target-schema <n> --confirm <word>` (T3 word = data-dir basename + target schema, printed by a preceding dry-run; bound to the predecessor schema version and frozen SHA), refuses on any `unusable`/`mismatch` credential or unreadable key, unseals in memory and atomically writes the predecessor file (0600, fsync, rename) with full legacy URLs, removes `upstream_proxies_v2`, logs counts only; the next 2F boot re-migrates. Real-binary proofs: upgrade → configure → prepare-downgrade → boot the frozen predecessor against a stub parent requiring Proxy-Authorization (prove it chains), and a deliberately corrupted-credential variant recording the predecessor's actual behaviour (407 → breaker → PX-2 direct fallback). The phrase "no bypass" is withdrawn from the downgrade contract.
>
> **C11 — Data-plane eligibility and authentication truth.** `eligible(e) = (credentialState==none || credentialState==configured && credential.authorityHash==e.authorityHash) && (probe==unprobed || probe==healthy) && circuit.Allow()`; `unhealthy`, `unusable`, `mismatch` and circuit-open are skipped; the userinfo URL is built only after `eligible`. One probe classifier for periodic and manual probes: dial/TLS error or deadline ⇒ `unhealthy/connect_failed|timeout`; HTTP 407 ⇒ `unhealthy/proxy_auth_failed`; 2xx/3xx ⇒ `healthy/none`; other status ⇒ `unhealthy/probe_http_error`; credential-ineligible entries are not probed. Bodies are drained unread (1 KiB) and discarded; only the reason enum is stored. `effective.mode`: `no_pool` (empty/disabled) · `chained` (≥1 eligible) · `no_eligible_parent` (0 eligible, no request has fallen back yet) · `direct_fallback` (0 eligible and a request fell back — existing alert/counter). Both of the last two render the red banner; only `direct_fallback` says traffic is bypassing.
>
> **C12 — Restore with omitted credentials.** A restore taking `admin_settings.json` from the tarball never yields `configured` entries: `credentialsOmitted:true` maps every formerly credentialed entry to the distinct state `requiresReplacement` (ineligible under C11 ⇒ `no_eligible_parent`, never unauthenticated chaining, never silent DIRECT). The restore dry-run prints the count; commit uses the existing `--confirm` with no new secret input; `.upstream_cred_key` is never archived, restored or removed. After boot, `credentialsRequiringReplacement:N` is surfaced on `GET /api/upstream`, the operator-contract row and the upstream page banner until each entry is replaced (T2) or cleared (T3).
>
> **Binding clarification 1 — effective-pool authority uniqueness.** The complete effective pool (YAML-owned + admin-managed) must have unique canonical authorities. Duplicates are detected across YAML/YAML, admin/admin and YAML/admin, independently of entry-ID collision detection; a duplicate fails validation BEFORE the effective pool is published, existing runtime state stays unchanged, and the DEGRADED reason (`duplicate_authority`, with a count only) carries no username or credential. RED coverage lands in 2F-C.
>
> **Binding clarification 2 — no raw transport errors in logs.** A Go transport/proxy error can embed a credential-bearing URL, so `err.Error()` is never logged, persisted, audited or returned on any upstream credential, dial or probe path. Only the bounded reason enum and a redacted canonical authority are recorded; no nested transport errors, URLs, headers or proxy responses. A test injects an error string containing the exact password and proves it absent from logs, API responses, audit and diagnostics.
>
> **RED-before matrix (implementation must reproduce each on its predecessor before fixing).** R1 `Set` write failure leaves memory at the candidate · R2 lifecycle Put failure reports "published but…" · R3 crash after active write, before finalize, never records · R4 neither-digest state accepted by the next publish · R5 repeated `operationId` commits twice · R6–R8 draft/pool/active change between challenge and retry still publishes · R9 replayed challenge · R10 rollback with stale challenge · R11 `revision:0` bypass · R12 DELETE/`save_draft`/exception mutations unfenced · R13 409 without current token · R14 same-ID create race · R15 password in GET/export/audit/log/diagnose/support/backup · R16 redacted import overwrites the password · R17 legacy UI re-POST destroys credentials · R18 authority change keeps the credential · R19 client-supplied `credentialState` accepted · R20 invalid entry silently dropped · R21 save failure after 200 · R22 concurrent upstream edits, loser wins · R23 new entry not `unprobed` · R24 manual probe unaudited/unbounded · R25 missing key reports `configured` · R26 downgrade file contract · R27 pool change after commit must not flip reconciliation · R28 classification must not consult `ModTime` · R29 same spec, changed pool ⇒ `challenge_stale` · R30 credentialed DELETE · R31 v1 bulk omission · R32 authority-changing import (plan, zero mutation) · R33 import removal · R34 dry-run applies nothing · R35 407 marked healthy · R36 missing key ⇒ never selected, URL never built · R37 authority mismatch never selected · R38 all-ineligible ⇒ `no_eligible_parent` · R39 first fallback ⇒ `direct_fallback` + one alert · R40 restore boots into `requiresReplacement` · R41 duplicate authority (clarification 1) · R42 injected password-bearing error absent from every sink (clarification 2).
>
> **Decomposition (append-only, no unsafe intermediate shipping state).** 2F-0 this entry gate · 2F-A PAC fencing model (C3) + structured 409/428 + legacy-JS token patch (R11–R14) · 2F-B persist-before-swap stores, intent state machine, reconciliation + repair, `operationId`, three digests, bound challenge + legacy-JS challenge echo (R1–R10, R27–R29) · 2F-C upstream v2 model, sealing, authority binding, uniqueness, v2 endpoints, v1 adapter, boot migration, YAML read-only, tri-state health + classifier, eligibility predicate, effective mode, legacy-UI switch, minimal import preserve rule, credentialed-DELETE refusal, log hygiene (R15–R23, R25–R26, R30–R31, R35–R39, R41–R42) · 2F-D export schema, import plan + dry-run, backup strip + manifest, restore reporting, `prepare-downgrade` + real-binary downgrade proofs, probe audit, full leak sweep (R24, R32–R34, R40) · 2F-E PAC React (`/app/network/pac`) · 2F-F Upstream React (`/app/network/upstream`) · 2F-G Playwright journeys, docs (parity admin-only correction, node-local labels), dist, final qualification. 2F-A/B and 2F-C/D are independent chains; 2F-C freezes as one unit because splitting model, adapter and legacy-UI switch would expose a credential-destroying interval. Deferred and recorded: PX-1 data-plane chaining, refusing the legacy empty-host fail-open PAC, rule-level identity inside profiles, cluster-synced lifecycle/exceptions, breaker/probe-interval GUI settings, YAML adopt transaction, secret-inclusive backups.
>
> **2F-B CORRECTION RECORD (this branch, 2026-09-04).** External review of the
> 2F-B candidate (`ae61ac78`) found two C1 contract failures; RED-before at the
> exact candidate (`pac_lifecycle_correction_test.go`, C-1..C-8, 8/8 red).
> **(1) Lifecycle corruption silently erased trust state.** `LifecycleStore.Load`
> quarantined a corrupt file and started empty, so pending intents and prior
> history vanished into an ordinary idle lifecycle and the next publish proceeded
> unacknowledged. Now: the reset is a DURABLE store-level record
> (`<dataDir>/pac_profiles_lifecycle.reset.json` — written BEFORE the corrupt
> file is moved aside to a timestamped `.corrupt.<unixnano>`; a boot that cannot
> record it leaves the file in place and repeats; the sidecar is in the backup
> inventory), scoped at load to the profiles active at the reset (an unscoped
> record affects every active profile — the conservative reading). The active
> store stays the sole authority. Affected profiles report
> `historyState: history_reset` (GET carries the `historyReset` record), and
> publish/rollback are refused `409 history_reset` until an admin
> `acknowledge_history_reset` (UUID `operationId`) bound to the current
> `expectedActiveRevision` + `expectedActiveSpecDigest` (`409
> history_reset_stale` with `current` + `changed` otherwise). The
> acknowledgement is per profile, persist-before-swap (a failed write leaves the
> reset in effect and answers 500), idempotent on replay, audited
> (`pac.profile_history_reset_ack`, no config version — nothing configured
> changed), and never rewrites the active store; it survives restarts until
> durable. **(2) `committed` was not durable and recovered commits lost
> audit/version truth.** The intent went from durable `pending` straight to
> `recorded`, so a crash after the active write left a committed profile with no
> success audit and no config version that reconciliation never completed. Now
> the approved progression is durable: `pending → committed → recorded`, with a
> persisted `OpProgress` marker advanced AFTER each post-commit effect lands —
> history revision (idempotent by operationId), config version (keyed by
> `operationId=<uuid>` in the version note; the version store is its own dedup
> record), cluster publication (content-idempotent), then the success audit
> (`operationId=… revision=… activeRevision=… activeSpecDigest=…
> historyState=recorded [reconciled=true]`, ring-deduplicated by operationId)
> and the terminal decided record. Any lifecycle write failure after the proven
> commit answers `published:true, historyState: pending_reconciliation`;
> reconciliation (lifecycle GET, before every operation, and at startup)
> completes ONLY the missing effects. Startup is two-phase and the split is
> load-bearing: the PAC loader (`initPAC`, before policy/rewrite/etc. load)
> settles intents and the node-local history only; `main.go` runs
> `pacReconcileAllLifecycles` once every store is loaded, because a config
> version captured earlier would snapshot a partial configuration that a later
> rollback treats as authoritative. Aborted and ambiguous intents emit no
> success audit and no config version. Residual, recorded: the success audit is
> emitted before its terminal marker is persisted, so a real crash inside that
> window is at-least-once (in-process retries are ring-deduplicated); the
> alternative (marker first) loses the compliance record on the same crash.
> Test seams: stage names `committed_persisted`, `history_recorded`,
> `version_recorded`, `cluster_published`, `finalized`; persist stages
> `committed`, `finalize`, `progress`, `record`, `ack`. GUI parity: the legacy
> `static/index.html` has no publish/rollback lifecycle surface (CRUD only), so
> the acknowledgement ceremony is an API + new-frontend (2F-E) contract —
> recorded, not a regression. Contract artifacts regenerated (`openapi.yaml` →
> bundle + `types.gen.ts`); route count unchanged (241).
>
> **2F-E CORRECTION RECORD, ROUND 4 (this branch, 2026-09-05).** External
> freeze review of the round-3 candidate (`d510d6c1`) accepted the migration
> durability and recorded-delete corrections and found two residual blockers;
> each was red-before on the untouched candidate (`41726989`:
> `pac_lifecycle_writer_boundary_red_test.go` H1/H2/G1/G2 4/4 failing —
> channel-controlled, through the PRODUCTION entry points, no test-side
> mutex) and corrected append-only (`8b2bcd89`). **(1) The production writer
> boundary was incomplete.** The lifecycle publish built its whole-config
> candidate and committed it under `pacProfilesAPIMu`, but the production
> config IMPORT (`apiConfigImport`) and config-version ROLLBACK
> (`applyPACFromBackup`) wrote the active store WITHOUT that mutex — so a
> publish parked between its durable intent (`intent_persisted`) and its
> commit overwrote their completed changes to UNRELATED profiles and pools
> with its stale candidate (the round-3 sequential helpers had hidden the gap
> by taking the mutex themselves; corrected transparently, assertions
> unchanged, the import helper now goes through the production handler).
> Corrected contract: every writer of the active profile store builds its
> candidate AND commits it under `pacProfilesAPIMu` — import, rollback and the
> CP→DP snapshot apply enter the shared boundary through
> `pacProfilesWriterLock` around exactly their PAC read-modify-write. Lock
> order reviewed and recorded on the helper: `objectReferenceMutationGate` →
> `configRollbackMu` → `pacProfilesAPIMu` (taken LAST by the bulk writers;
> nothing reachable under `pacProfilesAPIMu` acquires the gate or
> `configRollbackMu` — the post-commit effects reach `saveConfigVersionMu` and
> `ConfigStore.mu`, which `Update` releases before notifying subscribers).
> Behind the mutex the lifecycle commit is a compare-and-swap on a new
> `ProfileStore` GENERATION (`GetWithGeneration`/`SetIfGeneration`): the
> candidate is written only while the store is still at the generation it was
> built from, atomically under the store lock; a writer outside the boundary is
> detected at the commit and refused `409 concurrent_write` — recorded as the
> operation's aborted outcome (a re-send replays it), nothing written, the
> intervening change intact (wall W1; W2 covers the snapshot apply waiting at
> the boundary, with the wholesale rewind observed as an epoch rotation).
> Proofs H1/H2 park the publish, start the production writer, release only once
> it has reached the store or is WAITING at the boundary, and require the
> valid serial outcome with both changes present. **(2) The create ordering
> destroyed recovery evidence on failure.** Round 3 replaced the whole
> lifecycle record (`Recreate`) BEFORE the active create, so a refused or
> crashed active creation had already destroyed the draft, revisions, decided
> operations and intents that legitimately exist beside an absent profile (a
> rollback removed it; a draft saved before a first publication). Corrected
> contract: the create is a RECOVERABLE two-write transition — `PrepareCreate`
> durably records `CreatePending` + a `PreparedIncarnation` while the existing
> identity and every piece of evidence stay untouched; the active create
> commits; `FinalizeCreate` makes the prepared identity the epoch (evidence
> kept). A refused active create withdraws the preparation (evidence and
> identity intact, truthful failure, no success audit, no config version —
> G1); a crash between the writes is finished by the next access/boot from the
> durable transition alone (`ObserveActive`: profile present ⇒ finalize,
> absent ⇒ withdraw; the boot reconciliation covers create and delete
> transitions — G2), and an access that cannot finalize durably reports no
> identity — the old epoch is never exposed beside a created profile; a later
> successful recreation still refuses a request reviewed against the old epoch
> and keeps the evidence (G3). No frontend change: the accepted recovery,
> ceremony context, marker immutability, migration and delete-transition
> behaviour are unchanged; a `concurrent_write` refusal reaches the page as an
> ordinary refused dispatch. OpenAPI documents the new refusal (bundle + types
> regenerated).
>
> **2F-E CORRECTION RECORD, ROUND 3 (this branch, 2026-09-05).** External
> freeze review of the round-2 candidate (`33f6f21c`) accepted the round-2
> corrections and found two residual blockers about whether the new
> continuity guarantee survives EVERY relevant state transition; each was
> red-before on the untouched candidate (`dc16c2e2`:
> `pac_lifecycle_transition_red_test.go` F1a/F1b/F2/F3/F4a/F4b/F5 6/6
> failing, `pac-2fe-c3-red.test.ts` D9a/D9b 2/2, `pac-2fe-c3-red-page.test.tsx`
> P22/P23 2/2, real-binary `e2e/pac-2fe-c3.spec.ts` R12/R13 2/2 — R12 showed
> "Published — Active revision 2", R13 "history evidence is bounded" with the
> re-send OFFERED) and corrected append-only. **(1) Replace-import and config
> rollback reused active revisions without changing the history epoch.**
> `importPACProfilesCandidate` (replace mode) and `applyPACFromBackup` install
> profiles wholesale keeping positive revisions, so a request reviewed at
> (epoch E, revision N, spec A) and delayed until spec B sat at the SAME
> revision N passed the epoch check and the revision fence (the classifier
> had even declared `not_landed / fence_moved` and cleared the marker), and a
> committed operation evicted from both bounded histories could be replayed
> after a rollback restored its original base — equality of the present
> history UUID alone was insufficient. Corrected contract: the epoch is now a
> **durable transition of the observed active identity** — every lifecycle
> record carries `ObservedActiveRevision`/`ObservedActiveSpecDigest`, the
> authoritative identity it was last consulted against; `LifecycleStore.
> ObserveActive` (the single place an epoch is minted, rotated or retired,
> persist-before-swap) runs on every lifecycle read and before every
> operation, and the commit/repair paths record their own observation. An
> observed REWIND, or a DIFFERENT spec at the SAME revision, ROTATES
> `historyIncarnation` while every piece of evidence (revisions, decided
> operations, draft, intents) is preserved, so a dispatch or re-send reviewed
> in the earlier epoch is refused `409 history_incarnation_mismatch` whatever
> writer performed the transition (replace-mode import, config rollback,
> CP→DP snapshot). Independently, `expectedActiveSpecDigest` is now a
> publish/rollback fence beside `expectedActiveRevision` (`409 stale`,
> `current.expectedActiveSpecDigest` + `current.revision`; optional for API
> callers, always sent by the admin frontend — `PacPublishArgs`/`PacRollbackArgs`
> carry it and the page dispatches it from the reviewed lifecycle). A
> retained committed operation is still resolved by the lookup across a
> rotation (the ring survives), so the conservative refusal costs no
> resolution. **(2) Epoch transitions were not crash-safe, and migration
> could expose an unpersisted epoch.** `pacProfileDelete` removed the active
> profile before its lifecycle record, logged a record-removal failure and
> still returned 204 — the same durable state a crash between the writes
> leaves — and a recreate then inherited the surviving old epoch; `Load`
> assigned freshly minted identities into memory before persisting them, so
> a failed write advertised an identity nothing could be proven against.
> Corrected: the delete records `DeletePending` DURABLY as its FIRST write (a
> failed first write refuses the delete with nothing changed), then removes
> the active profile, then the record (a failure is logged; 204 still reports
> the committed active mutation); a flagged record whose profile is absent is
> finished by the next access or boot (`pacReconcilePendingDeletes`), one
> whose profile is still present has its epoch rotated, and a deleted
> profile's leftover record never advertises its epoch. Profile create calls
> `LifecycleStore.Recreate` BEFORE the active create (a fresh record + fresh
> identity replacing whatever survives under the id; a failed epoch write
> refuses the create), so a recreated profile can never be exposed beside the
> old epoch even when a later write fails. `Load` mints into a candidate map
> and swaps only once persisted; on failure the identity stays EMPTY — the
> GET reports "", a dispatch naming any epoch is refused, the next access
> retries the durable mint and a restart keeps it. The admin frontend
> WITHHOLDS publish/rollback (callout "History epoch identity not durable")
> for an existing profile whose `historyIncarnation` is "" — an operation
> reviewed against no epoch could never be resolved if its response were
> lost. Test seam: `pac.LifecycleWriteHook` (nil in production, the sibling
> of `ResetWriteHook`) fails one specific lifecycle write. Fixture
> completions (transparent, assertions unchanged): the accepted
> `TestPACIntent_IntentPersistFailure_ChangesNothing` captures its baseline
> after one lifecycle read has recorded the epoch's observation; three
> round-1/2 frontend fixtures carry the now-required
> `expectedActiveSpecDigest` / `historyIncarnation`. The real-binary journey
> R13 draws its eviction from three synthetic client identities because the
> admin plane allows 60 mutations per minute per client IP. Retained from
> round 2: the ceremony context, immutable markers, version-1 marker handling,
> committed identity fields and the apicontract fixture repair. Contract
> artifacts regenerated; route count unchanged (241).
>
> **2F-E CORRECTION RECORD, ROUND 2 (this branch, 2026-09-05).** External
> freeze review of the corrected candidate (`db6f4d35`) executed the pure
> recovery functions and found three residual blockers; each was red-before
> on the untouched candidate (`3f74eaa0`: `pac-2fe-c2-red.test.ts` D1–D8
> 11/14 failing with 3 controls, `pac-2fe-c2-red-page.test.tsx` P17–P21 4/5
> with 1 control, `pac_lifecycle_continuity_red_test.go` E5–E8 3/4 with 1
> control, real-binary `e2e/pac-2fe-c2.spec.ts` R9–R11 3/3) and corrected
> append-only. **(1) Non-commit was declared without proven history
> continuity.** The round-1 rule ordered a server-stamped history reset
> against the browser-stamped dispatch (15-minute skew), so a server clock
> sufficiently behind the browser dismissed an acknowledged reset that
> happened AFTER the dispatch; and a profile DELETE discards the lifecycle
> record while a recreate under the same id restarts revision numbers at 1,
> so a recreated profile that climbed to or past the reviewed revision
> bypassed `history_missing` and its EMPTY new ring read as complete evidence
> — both answered `not_landed`. Worse, a recreate reproducing the original
> base revision and spec (same draft restored) read as `not_observed` and
> OFFERED the re-send: the original operationId has no decision record in
> the new history, so the appliance would have run it AGAIN. Corrected
> contract: the appliance now carries a **durable history-epoch identity**
> (`ProfileLifecycle.HistoryIncarnation`, a UUID minted when a record is
> created — existing records are minted one at load and persisted — stable
> across draft saves, publishes and restarts, ROTATED by a profile delete (+
> recreate) and by a history reset; exposed as the lifecycle GET's
> `historyIncarnation`, "" when neither a profile nor a record exists). The
> recovery marker (version 2) records the epoch it was dispatched in plus the
> collection fence; `classifyRecovery` reads anything into absence ONLY with
> continuity — the same known epoch on both sides — and otherwise keeps the
> operation UNRESOLVED as `history_discontinuity` (a deleted, never-recreated
> profile is `history_missing`; an unacknowledged reset stays
> `history_reset`). Clocks and revision-number comparisons are gone from the
> classifier. Re-send is **refused** without continuity (`resendContinuityRefusal`;
> the button is withheld with the reason), and the appliance enforces it too:
> publish/rollback/repair carry `expectedHistoryIncarnation` and are refused
> `409 history_incarnation_mismatch` (current identity named) BEFORE the
> at-most-once replay is consulted, committing nothing. The field is optional
> for an API caller that omits it (it reviewed no epoch and has no re-send
> semantics; the legacy panel never calls the lifecycle publish); the admin
> frontend always sends it. **(2) "Currently active" followed the history
> pointer.** `activeN === revisionN` said "It is the active revision" after a
> direct profile PUT had replaced the spec — the PUT advances the
> authoritative active store without touching the lifecycle. Every revision
> now records the store revision its commit produced (`storeRevision`;
> `FinalizeCommitted`/`Repair`), the operation lookup carries the committed
> identity (`specDigest`, `storeRevision`), and `currentlyActive` is derived
> from that identity against `activeSpecDigest` + `activeRevision` (an
> identical-spec re-PUT still moves the store revision and reads as no longer
> active; a pre-field revision falls back to the pointer for the revision
> half only). Historical commitment stays separate and is reported first
> ("committed as history revision N"). Real-handler proof E7 and real-binary
> R9 cover publish → lost response → direct PUT → Recover. **(3) The DIRECT
> challenge continuation dropped the re-send context and the marker could
> be rebound.** The confirmation callback re-ran the operation without the
> re-send options, so it restamped the dispatch time and treated a later
> refusal as a fresh attempt (clearing the earlier, still-unresolved
> marker); and `writePacRecovery` accepted a same-id rewrite of every
> binding field. The run context is now an explicit `RunOpts { marker,
> resend }` carried through the challenge ceremony — the attempt's ORIGINAL
> marker verbatim (dispatch time, candidate digest, fences, epoch) and its
> re-send posture — so a refused or lost confirmation keeps the marker and,
> on a re-send, is followed by the authoritative read; the store refuses any
> same-id write whose bindings differ (an identical re-persist is the only
> allowed one). Page proofs P17–P21 cover unresolved → re-send → challenge →
> confirmation → stale-refused / transport-lost / reload; the round-1 P3/P4
> challenge journeys still pass with the carried context. **Assertion
> corrections (transparent; original commits preserved):** the accepted C1c
> acknowledged-reset case expected `history_reset` from the timestamp rule
> and now expects `history_discontinuity` with the post-reset epoch (the
> case comment records the original and why it was wrong). **Fixture
> completions** (no assertion change): the round-1 fixtures gained the epoch
> identity and the marker's two continuity bindings (C1i's deleted profile
> reports "" as the appliance does; C5a's lookup expectation gained the two
> new identity fields at their absent values; the publish request fixture
> names its epoch). **Harness repair:** the extra-path coverage test's
> positive fixture used `/api/thing` as both the primary and the extra path;
> it now documents a second path only the extra mapping can cover and proves
> the mapping is necessary (passes on the baseline — the implementation was
> right, the fixture was not). **Limitations recorded.** A version-1 marker
> (from the previous build) reads with an unknown epoch: it is never resolved
> to "not landed" and is never re-sent — only Recover (a positive appliance
> record still lands it) or the typed Abandon. Revisions recorded before
> `storeRevision` existed fall back to the history pointer for the
> revision half of current-active truth (their spec digest is still
> compared). The lifecycle GET mints and persists the epoch identity for a
> pre-existing profile the first time it is read (the same GET already
> reconciles pending intents durably); when that write fails the GET reports
> "" and every client verdict is unresolved. The 2E-C enrollment marker
> remains outside this round (recorded for 2F-G). 2F-F/2F-G untouched.

> **2F-E CORRECTION RECORD (this branch, 2026-09-05).** External freeze
> review of the 2F-E candidate (`39e2cfdb`) found five blockers; each was
> red-before on the untouched candidate (`d6214d98`: `pac-2fe-c-red.test.ts`
> C1–C5 17/20 failing with 3 controls, `pac-2fe-c-red-page.test.tsx` P7–P16
> 11/11, `pac_lifecycle_evidence_red_test.go` E1–E3 3/3, real-binary
> `e2e/pac-2fe-c.spec.ts` R1–R8 8/8) and corrected append-only.
> **(1) Recovery mistook absence for proof of non-commit.** `classifyRecovery`
> answered `not_landed` whenever the operation was absent from the 20 listed
> decisions, the pending intent and the ambiguity record — but the appliance
> retains 64 decisions and lists 20, a history reset empties the ring, and a
> request that has not reached intent persistence is absent while it can
> still commit; the success copy also read a historical record as "the
> candidate is the active profile". Corrected contract (`pacLifecycle.ts`):
> the classifier takes the appliance's word when it has it — the new
> `?operationId=` lookup over the FULL retained ring and the revision
> history (revisions carry the operationId that produced them), the listed
> decisions, the pending intent, the ambiguity record — and declares
> non-commit ONLY with authoritative evidence: retained ring complete
> (`operationsRetained < operationsCap`, or fewer than 20 listed without a
> lookup), no history reset touching the dispatch window (unacknowledged, or
> stamped at/after the dispatch with a 15-minute skew tolerance), the
> operation absent, AND the reviewed fence moved (active revisions are
> monotonic, so the appliance can no longer commit it). Everything else stays
> UNRESOLVED with a named reason — `not_observed` (base unchanged: the
> request may still be in flight), `history_bounded`, `history_reset`,
> `history_missing` (the profile is gone or its revision went BELOW the
> reviewed one: delete + recreate) — and the identity is retained. A landed
> resolution distinguishes "committed as history revision N" from "currently
> active" (N is `activeN`) and from decided-aborted. Resolution of an
> unresolved operation is deliberate: **Re-send same operation** (Tier 2; the
> SAME operationId, candidate — refused when the saved draft's
> `draftSpecDigest` no longer matches the marker — and fences; at most once on
> the appliance: replayed if landed, refused if stale, else it lands now; a
> refusal is followed by a fresh authoritative read, never by a clear) or the
> typed Abandon. The accepted A6 assertion that endorsed the absence rule was
> corrected transparently (original values recorded in the case comment).
> **The backend half, explicitly identified** (`3dc88637`, the only Go change
> of the round): the lifecycle GET now carries `draftSpecDigest`,
> `operationsRetained`, `operationsCap` and answers `?operationId=<uuid>` with
> `operation {found, state, status, ts, revisionN}` (pure read; malformed id
> 400). **(2) One marker key, no ownership.** Corrected (`pacRecovery.ts`):
> ONE outstanding operation across the whole PAC surface — a write never
> overwrites a different operation's marker and never succeeds over an
> unreadable/unavailable store (only the same operation may be re-persisted
> for a re-send); `clearPacRecovery(operationId)` is ownership-matched so a
> late completion cannot erase another marker; the authentication boundary
> is the one unconditional purge; a marker of ANOTHER profile, or an
> unreadable/unavailable store, withholds publish and rollback on every
> profile (named on the listing and the detail); an unknown subject (auth
> state still hydrating) reads as unavailable and never discards a marker as
> foreign — found by the page matrix: the first render discarded a valid
> marker before the identity was known, which would have broken the reload
> guarantee. **(3) Unproven responses cleared the identity.** Corrected: a
> 2xx that cannot be decoded or has the wrong content type, and an
> intermediary 5xx without a structured PAC decision, classify as UNKNOWN
> (marker kept); a decoded 2xx is a proven commit only when it names the
> dispatched operationId AND carries the action's positive flag
> (`published`/`rolledBack`), else the marker is kept and the page says the
> response could not be tied to the operation; proven commit with pending
> reconciliation stays distinct from unknown. **(4) Local navigation lost
> dirty drafts; Refresh re-armed stale edits.** Corrected: PAC tabs and
> "← All profiles" are guarded by a local discard dialog ("Discard unsaved
> changes?" — Cancel keeps the editor); the draft editor binds an edit to
> the draft revision it started from and Save sends THAT base revision, so
> a stale edit is refused 409 (rendered) instead of overwriting another
> admin's newer draft; a Refresh revealing a newer server draft under
> pending edits surfaces "Draft changed on the appliance" and is resolved
> only by an explicit "Keep my edits (re-base to revision M)" or "Discard my
> edits". **(5) Contract artifacts.** The lifecycle GET is documented
> (`PACLifecycle`, `PACOperationLookup`, the evidence limits and the
> non-commit proof rule), the POST documents the per-action request contract
> and at-most-once replay, the profile/pool/exception DELETEs are documented
> as 204 (the handlers always answered 204); bundle, offline docs, inventory
> and `types.gen.ts` regenerated; conformance coverage
> (`pac_lifecycle_evidence_red_test.go` E3: GET response validated, publish
> request validated, DELETE 204 without a 200). The classification manifest
> gained `openapi_extra_paths` (further contract paths served by the SAME
> registered route + method — the lifecycle GET shares the `/api/pac/profiles/`
> GET registration; the manifest forbids a second row per route + method).
> **Real-binary proofs** (`pac-2fe-c.spec.ts`): R1 lost response + 25 further
> API publishes (20 listed) → Recover proves "committed as revision 1, no
> longer active"; R2 request never received (aborted before dispatch) → "not
> observed", publish withheld, re-send lands with the same operationId
> (exactly two POSTs); R3/R4/R5 gateway 502 / malformed 200 / wrong-identity
> 200 AFTER the appliance committed → unresolved, marker kept, Recover proves
> the commit; R6 A → B navigation and reload → B withheld and named until A
> is resolved; R7 two-admin draft → stale save refused with the current
> token, server draft untouched, explicit re-base then saves; R8 dirty editor
> asks before a tab switch. **Harness completions** (disclosed, no expected
> value changed): the original page fixture serves the lookup URL; the
> Pools-tab discriminator and the success-notice discriminator in the
> correction page matrix; the fetch spy typing; the A7 clear call names the
> operation. **Found by the real-binary run and fixed in-round**: the
> `history_missing` rule first misclassified a created-but-never-published
> profile (`2c30a3ca`). **Limitations recorded.** The marker is
> sessionStorage (per tab; a second tab cannot see it — the established
> session lifecycle, same as the 2E-B/2E-C markers). The reset-ordering
> tolerance (15 min) errs toward UNRESOLVED. A `history_bounded` operation
> whose base moved and whose record was evicted can only be abandoned
> deliberately after reviewing the publish history. A re-send carries no
> history reason (the original reason is not part of the non-secret marker).
> The 2E-C enrollment marker (`enrollRecovery.ts`) reads with the same
> possibly-empty subject on first render and is NOT changed here (outside
> the 2F-E findings; recorded for 2F-G). 2F-F/2F-G untouched.

> **2F-E IMPLEMENTATION RECORD (this branch, 2026-09-05).** PAC React at
> `/app/network/pac` under the approved C1–C12 contract; frontend-only
> (no Go, no OpenAPI change). **Entry gate.** `origin/main` had advanced
> from the 2F-D freeze (`d6bdd622`) to `290e3768` (MCP canary work); the
> approved evidence-preserving merge `e8ae527a` carried one textual
> conflict in `shadow_soak_test.go` (both sides introduced a locked clock
> swap for the tool-trust coordinator — resolved to `soakSwapToolTrustClock`
> at both soak sites, main's `swapToolTrustNowFn` retained in
> `mcp_tooltrust_clock_test.go`); the merge commit's message was amended
> with the trailers BEFORE it was ever pushed (disclosed; frozen history
> untouched). Reconciliation gates on the merged head: route pin 243, lint
> 0, contract tests, full non-race sweep PASS. **RED-before.**
> `b976566c` commits the coverage on the merged head and the baseline
> evidence was executed there: `src/test/pac-2fe-red.test.ts` (A1–A7:
> decoder, fence/challenge/history-reset classifiers, request shapes with
> no `confirmDirect`, recovery classification, marker grammar/subject/
> corruption), `src/test/pac-2fe-red-page.test.tsx` (P1–P6: viewer
> posture, stale write, challenge + stale challenge, lost response →
> marker → Recover, history_reset ack body, admin controls) and
> `e2e/pac-2fe.spec.ts` (five real-binary journeys) — all red on the
> baseline (the page/e2e matrices fail on the missing module/route).
> **Surface.** `src/api/pac.ts` (decoders + requests for profiles, pools,
> lifecycle, exceptions, posture inventory, legacy config, simulate; every
> fence token explicit — `revision`, `draftRevision`, `etag`,
> `collectionEtag`, `expectedActiveRevision`/`expectedActiveSpecDigest`;
> UUID `operationId`; refusal classifiers for 428/409 fences, the bound
> DIRECT challenge (`confirm:{challenge,value,binding}` echoed verbatim,
> `challenge_stale` renders the `changed` bindings), `history_reset`,
> `operation_pending`, `lifecycle_ambiguous`, `outcome_unknown`/
> `active_write_failed`, validation issues), `pacRecovery.ts` (NON-SECRET
> sessionStorage marker `culvert.pac.lifecycle-recovery.v1` — operation
> identity + bound expectations, subject-bound, read-back verified,
> written BEFORE dispatch, cleared only on a terminal outcome or the auth
> boundary), `pacLifecycle.ts` (recovery classification against the
> authoritative lifecycle GET: `landed` — the operation appears decided with
> its state, `pending`, `ambiguous`, `not_landed` + whether the base moved;
> only an unknown outcome keeps the marker), and the tabs Profiles / Pools
> / DIRECT Exceptions / Legacy PAC. **Lifecycle guarantees in the
> browser.** The reviewed CANDIDATE is the saved node-local draft, else the
> current active spec (an initial publish records the profile as served;
> the backend keeps no draft until one is saved); publish/rollback carry
> the reviewed candidate + `expectedActiveRevision` so a concurrent publish
> is a rendered 409 with the current token and never an auto-retry; the T3
> DIRECT ceremony is typed against the server's `confirmValue` and re-sent
> with the SAME `operationId` + candidate; a stale challenge lists the
> changed bindings and requires a fresh review; proven commit
> (`historyState: recorded`), pending reconciliation, ambiguity (Repair —
> accept active) and history reset (acknowledge with
> `expectedActiveRevision` + `expectedActiveSpecDigest`) are rendered as
> distinct states; an unknown outcome latches on the persisted operation
> identity and the page offers only Recover (authoritative lifecycle read)
> or the typed Abandon ceremony before any fresh dispatch. RBAC C7: every
> mutation control is admin-only; the viewer sees read-only facts.
> Node-local ownership/scope, the CP-managed data-plane refusal and the
> evidence class are rendered verbatim. **Found only against the real
> binary** (corrected in `c05f0fc8`, fixtures corrected to the wire
> contract with no expected value changed): `draftDiff.rulesAdded/
> rulesRemoved` are description strings; the lifecycle GET serialises a
> zero Profile for a never-saved draft and for a missing active (now
> decoded as absent); `Profile.rules` is `omitempty`. **Harness
> completions** (disclosed, not assertion changes): the page fixture serves
> `/api/pac/posture/inventory`; the legacy default-profile card title no
> longer contains "PAC" (ambiguous heading locator). **Deferred /
> limitations.** The lifecycle GET/POST body is not in the OpenAPI document
> (the typed client is hand-written against the handler; documenting it is
> a backend artifact change outside this frontend-only slice); profile/
> pool/exception DELETEs answer 204 while OpenAPI says 200 (the client
> treats both as success); the "Upstream Proxies" nav entry is a planned
> placeholder (2F-F); 2F-F/2F-G untouched.

> **2F-D CORRECTION RECORD (this branch, 2026-09-04).** External freeze
> review of the 2F-D candidate (`4b60d810`) found two source-level
> contract blockers; each is red-before against the untouched `4b60d810`
> (`upstream_v2_portability_red2_test.go`, CR1–CR8: six defect gates
> FAIL on the baseline, CR3/CR4 are controls) and corrected append-only.
> **(1) `requiresReplacement` could be cleared without T2/T3.** The C12
> rule — and the candidate's own `ManagedEntry` comment — say the durable
> marker is resolved only by an explicit Tier-2 replace or Tier-3 clear on
> the credential endpoint, yet `upstreamPlanV2` guarded on
> `Credential != nil` alone: a same-id import with a changed authority and
> `credentialState:"none"` ran the ordinary update path and assigned
> `RequiresReplacement=false`, and a replace-mode omission classified the
> entry as `remove` and dropped it. The refusal predicate is now
> `upstreamEntryProtected` (material OR marker): both shapes refuse 409
> `credential_clear_required` with the complete plan (`incoming:
> requiresReplacement`, `existing: remove`, `credentialClearRequired`
> naming the id) and zero disk/runtime/audit/config-version mutation;
> identity-keyed preserve (v2) and exact-authority preserve (legacy
> `xxxxx`) keep the marker verbatim, and it survives a restart-shaped
> reload. Only the T2/T3 credential endpoint resolves it (CR4 control).
> **(2) The versioned credential-omission schema was not validated.**
> `declared := state != "" && state != "none"` read ANY unknown value as
> credential evidence and an absent value as `none`, and nothing required
> the `upstream_credentials` marker or a coherent version. Validation now
> runs BEFORE planning or any mutation: every v2 entry must carry one
> recognized `credentialState` (`none|configured|unusable|mismatch|
> requiresReplacement`; otherwise 400 `invalid_credential_state` naming
> the offending INDEX only — the value is never echoed); a
> `upstream_proxies_v2` section requires backup version 2 and the exact
> `upstream_credentials:"omitted"` marker (400
> `invalid_upstream_credentials_marker` when missing or any other value);
> a v2 section under another version, a legacy `upstreamProxies` list
> outside version 1 or carrying the marker, or a marker without a section
> is 400 `schema_mismatch`. A refusal mints no key, audits no success and
> advances no config version. Entry-level 400s are now structured JSON
> `{error, code, index}` (OpenAPI `UpstreamImportRefusal` extended;
> bundle + `types.gen.ts` regenerated). Everything else reviewed in that
> round — backup sanitization, node-local-key exclusion, downgrade
> binding, the manual-probe contract — is unchanged.
>
> **2F-D IMPLEMENTATION RECORD (this branch, 2026-09-04).** Portability,
> recovery and complete secret containment for the Upstream v2 sealed
> credentials, appended to the frozen 2F-C head `ef9cb045` (RED matrix
> `upstream_v2_portability_red_test.go` — R24, R24b, R32–R34, R40, the
> versioned export shape and the complete R15 sink matrix — committed at
> `c7073753` and executed on the untouched baseline: 8/8 FAIL; a
> lint-only range-form touch to its `pdAuditCount` helper at `e40e3fce`
> was re-executed on the baseline with the same 8/8 FAIL before the
> product commit `d254ede8`; no RED assertion was changed).
> **(1) Export contract, schema 2.** `configBackup.version` is now
> `configBackupVersion = 2` (config-version snapshots carry the same
> number; import accepts 1..2). The export carries
> `upstream_proxies_v2: {entries:[{id, scheme, host, port, username,
> credentialState}]}` (managed entries only, stable server IDs, bounded by
> the document cap) plus `upstream_credentials: "omitted"`; it NEVER carries
> a password, the sealed `credential` record, ciphertext, key id, the
> legacy `xxxxx` echo or a legacy URL. The credential-free legacy
> `upstream_proxies` list left the export surface (it stays an
> import-only input: `configSurfaces` rows `upstream_proxies` Import-only,
> `upstream_proxies_v2` Export+Import, Redacted).
> **(2) Atomic import plan + dry-run.** `upstreamPlanImport` classifies
> every incoming entry as `preserve` (same ID AND unchanged authority
> hash — the only shape that keeps a sealed credential), `create`,
> `update` (authority change on an uncredentialed entry) or
> `requiresReplacement`, and every existing managed entry as `retain` or
> `remove` (replace mode only, for the identity-bearing v2 document; the
> identity-free legacy list can never remove — the 2F-C rule — and its
> `xxxxx` echo preserves an exact unique authority match only). Duplicate
> incoming IDs → 400; a real password → 400 `credentials_not_importable`;
> both sections present → 400 `ambiguous_upstream_sections`; YAML-owned
> authorities are skipped and counted. Any plan that would destroy a
> credential (authority change or removal of a credentialed entry) is
> refused 409 `credential_clear_required` carrying the COMPLETE plan and
> `credentialClearRequired: [ids]` BEFORE any store is touched — the
> import confirm word stays Tier-2 and never substitutes for the Tier-3
> clear. `?dryRun=1` (`1`/`true`/`yes`) answers the plan plus a
> deterministic `importDigest` (`sha256:` over the plan JSON and the
> current document's `{revision, rows{id, authorityHash, material,
> flag}}`) with zero mutation; the commit carries `?importDigest=` and
> revalidates it under the authoritative save lock
> (`saveAdminSettingsWithOverrides{upstreamMutate}` — validate → persist →
> publish), answering 409 `import_stale` if the document moved. Upstream
> is applied FIRST in the apply region; the commit summary carries counts
> only: `upstream: {preserved, omitted, cleared, requiresReplacement}`.
> **(3) Backup secret stripping, both modes.** `packOne` sanitizes
> `data/admin_settings.json` on the bytes it packs
> (`stripUpstreamCredentialsFromSettings`: every `credential` record
> removed, `requiresReplacement: true` set, and the output verified free
> of `ciphertext`/`keyId`/`authorityHash` keys); the manifest records
> `credentialsOmitted: true` unconditionally; `.upstream_cred_key` joins
> the never-archived node-local key set. The live file and pool are
> untouched; there is no secret-inclusive mode.
> **(4) Restore semantics.** A restore boots each formerly credentialed
> entry into the DISTINCT durable state `requiresReplacement`
> (`ManagedEntry.RequiresReplacement`, meaningful only with no
> `credential`; cleared by T2 replace or T3 clear) — ineligible, never
> probed, never sent unauthenticated, so the effective mode is
> `no_eligible_parent` before any traffic and `direct_fallback` only after
> a real fallback. The dry-run prints the exact count (`credentials
> requiring replacement: N`, both plain and encrypted archives); the
> commit keeps the existing `--confirm`; an archive that carries a
> node-local key file is refused; an existing `.upstream_cred_key` is
> preserved byte-for-byte in every restore mode. Surfaces:
> `credentialsRequiringReplacement` on `GET /api/upstream` (also folded
> into `credentialsIneligible`), the `upstream_credentials`
> operator-contract row (count only) and the legacy panel badge + banner.
> **(5) `culvert --prepare-downgrade --target-schema <n> [--confirm
> <word>]`.** Target = the frozen 2F-B predecessor's admin-settings
> schema 1 (`adminSettingsSchemaPredecessor`), bound in code to its SHA
> `1e3578d93021563df61685f5c669f6742fc72081`
> (`downgradePredecessorSHA`); the current file carries
> `admin_settings_schema: 2`. Dry-run is mandatory and prints counts plus
> the confirmation word (`<data-dir basename>-schema<n>`, e.g.
> `data-schema1`); the commit refuses on an unsupported target, an
> unreadable/invalid file, an already-prepared file, nothing to prepare,
> a missing/unusable key, and any `requiresReplacement`/`mismatch`/
> `unusable` credential. Credentials are unsealed in memory only and the
> predecessor-compatible file (full legacy URLs, `upstream_proxies_v2`
> and the schema stamp removed, `upstream_prepared_downgrade` marker with
> counts) is written atomically 0600 + fsync + rename; output, log and
> audit carry counts only. The next boot of the CURRENT binary consumes
> the marker and re-migrates, reporting `migration.reason:
> re-migrated_after_prepare` once. **Real-binary proofs**
> (`portability.py`, 38/38 on the candidate): current binary → two
> credentialed parents on 127.0.0.1 requiring Proxy-Authorization →
> export/import plan/dry-run/commit/stale/refusals → manual probe →
> plain + encrypted backup → restore dry-run + commit → boot into
> `requiresReplacement`/`no_eligible_parent` → direct egress with parents
> silent → T2 replace → chained again → prepare-downgrade dry-run/refusals/
> commit → **the frozen predecessor `1e3578d9` boots the prepared file
> and chains through both parents WITH the correct Proxy-Authorization** →
> current binary re-migrates (`re-migrated_after_prepare`, 2 sealed,
> plaintext gone) → next boot silent. **Corrupted-credential variant,
> recorded as observed and not laundered:** with a wrong password in the
> prepared file the predecessor forwards the parent's 407 to the client on
> every request (8/8 attempts, the parent saw all 8, no direct egress) —
> the 2F-B breaker trips on transport ERRORS only, a 407 is a well-formed
> response, so the predecessor never falls back to DIRECT and never
> reaches the parent unauthenticated; the failure is loud (407) rather
> than silent. Nothing in 2F-D changes the predecessor.
> **(6) Manual probe lifecycle.** `POST /api/upstream/health` is
> admin-only, bounded at 5 s per entry (the existing probe deadline),
> single-flight (`probe_in_flight`) and rate-limited to one accepted run
> per 10 s (`ManualProbeWindow`, `probe_rate_limited`, 429 with
> `Retry-After` + `retryAfterSeconds`); an accepted run is audited as
> `upstream.probe.manual` with `probed=/healthy=/unhealthy=/skipped=` and
> `scope=node-local`, a refused run leaves no success audit, raw errors
> never reach the response; the classifier and the periodic loop are
> unchanged (the periodic loop is never gated). Route metadata
> `AuditExpected: true`; route count unchanged (243).
> **(7) Leak sweep.** RED `R15_CompleteSinkMatrix` (canary password +
> ciphertext across API bodies, audit, logs, export/import reports,
> `diagnose upstream`, support bundle, config-version files, cluster
> snapshot, both backup archives, restore/downgrade dry-run output) is
> green; `portability.py` L1 sweeps the same needles over the real
> binary's artifacts; the browser half is `frontend/e2e/upstream-2fd.spec.ts`
> (legacy panel — the new SPA has no upstream route until 2F-E): every
> same-origin response body, every request URL, the DOM, localStorage,
> sessionStorage and the page URL are swept for the canary and the
> on-disk ciphertext after create → seal → list → Health Check → export.
> **(8) Scope exclusions honoured:** no 2F-E/2F-F/2F-G, no PX-1, no YAML
> adoption, no secret-inclusive backups, no alert-store cleanup.
> Contract artifacts regenerated (`openapi.yaml` → bundle + `types.gen.ts`
> + `route-classification.yaml`). Operator runbook:
> `docs/operator/upstream-proxies.md` §7–§10.
>
> **2F-C CORRECTION ROUND 2 RECORD (this branch, 2026-09-04).** External
> review of the corrected candidate (`42336a8e`) found one remaining blocker:
> **a mutable published `Proxy` raced live traffic.** `rebuildLocked` reused
> the existing `*Proxy` whenever its `id|authorityHash` was unchanged and
> wrote `up.Entry = e` under `Pool.mu`, while `ProxyFunc`/`authenticatedURL`,
> `probeProxySelector` and `Attribution.Record` read `up.Entry` with no lock —
> a data race across every credential replace/clear and same-authority PUT,
> able to hand an in-flight request a MIXED binding (old eligibility verdict,
> new credential). RED-before at exactly `42336a8e`
> (`internal/upstream/publication_race_red_test.go`, PR1–PR6, committed before
> the fix): channel-controlled seams park a request AFTER selection and
> BEFORE URL construction while a credential replace (PR1), clear (PR2),
> same-authority revision bump (PR3) or probe-selector interleaving (PR4)
> publishes; PR5 spins unsynchronized readers under `-race`; PR6 is the
> control (no direct fallback, mode `chained`, no password on any read
> surface). PR1–PR4 failed and PR5 reported a data race on the rejected head;
> all six pass ×20 under `-race` after the fix. **Publication linearization
> rule (now the contract):** every publication constructs a NEW `*Proxy` for
> every entry under `Pool.mu` and swaps the slice; a published `Proxy` is
> never written again — `Entry`, `URL` and the credential verdict are fixed
> at construction — so an in-flight request/probe/attribution holds the
> COMPLETE old generation or observes the COMPLETE new one, never a mix.
> Continuity across generations flows only through independently
> synchronized state: the circuit breaker is shared by pointer (own mutex) so
> real request outcomes keep driving the same breaker, and the probe verdict
> is copied via the old proxy's own mutex (`Probe()`); a probe landing on a
> superseded generation is not carried forward. Persist-before-publish and
> every round-1 semantic are unchanged. **Contract-artifact cleanup in the
> same fix:** the OpenAPI port default and the operator runbook said
> `80/443/1080` (1080 is the socks5 default; socks5 is outside the
> `http|https` grammar) — now `80/443`; stale source comments that bound a
> credential only to its authority hash, or said YAML inline credentials are
> refused, are rewritten (entry id + authority hash; retained in memory).
> Scheme grammar unchanged; no previously accepted RED assertion changed.
>
> **2F-C CORRECTION RECORD (this branch, 2026-09-04).** External freeze
> review of the 2F-C candidate (`02b97716`) found six source-level contract
> breaks; RED-before at the exact candidate (`upstream_v2_correction_red_test.go`
> C-R1..C-R6, 7/7 red). **(1) Credential binding omitted the entry ID**: the
> AEAD bound only the authority hash, so ciphertext from a removed entry A
> transplanted onto a new entry B with the same authority reported
> `configured` and was selected. `Sealed` now carries the immutable
> `entryId`; `Seal`/`Unseal` bind `entryID || 0 || authorityHash` as AAD;
> `credentialStateLocked` checks both structurally before any unseal; a
> transplant is `mismatch` — never unsealed, probed or sent; migration seals
> with the newly assigned ID. **(2) YAML inline credentials were refused
> wholesale**: an existing `config.yaml` parent with userinfo now becomes a
> read-only `yaml-<digest>` entry whose credential is retained in memory
> only (`ManagedEntry.yamlSecret`, never serialized, never in the managed
> document, API, audit, diagnostics or logs), `configured`, probed and
> selected normally, still 409 `yaml_owned` on every API mutation. **(3) The
> stored-document failure path was not fail-closed**: a rejected
> `upstream_proxies_v2` left mutations enabled and let a later save (or
> key mint) overwrite it. The rejected document + legacy list are now
> RETAINED (`upstreamSetRejected`): every managed mutation, the v1 adapter,
> config import and key creation are refused (409 `document_rejected`),
> every unrelated save persists the retained sections verbatim, the pool
> stays untouched and `degraded` stays visible until repair + restart; a
> refused YAML seed is a separate `yamlDegraded` that a loading managed
> document never clears. **(4) The grammar had been widened to `socks5`**:
> restored to the approved C4 `http|https` on normalization, v2, v1, YAML,
> import, migration, OpenAPI, generated types, the legacy panel and the
> operator doc. **(5) The read model was incomplete**: added
> `coverage {plainHttp: chained, connect: direct, websocket: direct,
> socks5: direct, summary}`, top-level `probe {configured, interval}`,
> per-entry `health {status, reason, lastProbeAt, source: periodic|manual}`
> (`probe` kept as a compatibility alias) and `effective.since`
> (re-stamped only on a mode transition, injected clock). **(6)
> Authenticated URL construction was broader than claimed**: `HealthCheck`
> built it directly. The probe path now resolves the authenticated URL only
> inside a per-probe transport proxy selector (`probeProxySelector`) after
> the eligibility re-check, exactly like `ProxyFunc`; the test seam receives
> `scheme://host:port` only; the AST wall
> `TestWall_AuthenticatedURLIsConstructedOnlyInsideSelectors` pins exactly
> two call sites; GET `url` carries no userinfo (username is its own field)
> while the persisted legacy list keeps `user@host:port` for downgrade
> compatibility and export carries the username-bearing authority so a
> re-import preserves identity. The C4 text above is unchanged and is the
> contract the implementation now matches.
>
> **2F-C IMPLEMENTATION RECORD (this branch, 2026-09-04).** Upstream v2
> backend + safe legacy transition, append-only on the frozen 2F-B baseline
> (`1e3578d9`); RED matrix R15–R23, R25–R26, R30–R31, R35–R39, R41–R42
> committed and executed red on that baseline BEFORE the engine
> (`upstream_v2_red_test.go`). **Model** (`internal/upstream/entry.go`,
> `credkey.go`, `probe.go`, `upstream.go`): server ULID identity, canonical
> normalized authority `scheme://[username@]host:port` (scheme/host
> lower-case, trailing dot, IDNA, bracketed IPv6, effective port), YAML
> entries as `yaml-<128-bit authority digest>` read-only with a boot
> collision check, effective-pool authority uniqueness validated before any
> publish (`duplicate_authority` + count only). **Credentials**: write-only
> `POST /api/upstream/entries/{id}/credential` (replace T2 / clear T3 with
> `confirm == id`), AES-GCM sealed under the node-local `.upstream_cred_key`
> keyed by entry id + authority hash, never plaintext in
> `admin_settings.json`, never minted after a failed read or while
> ciphertext exists (missing/unreadable ⇒ `unusable`, hash mismatch ⇒
> `mismatch`, neither unsealed/selected/probed/sent), `credentialState`
> derived (a body asserting it ⇒ 400), authority change while bound ⇒ 409
> `credential_bound`, credentialed delete ⇒ 409 `credential_present`. The
> authenticated URL is built only in `authenticatedURL` inside `ProxyFunc`
> after eligibility. **Endpoints** (`ui_upstream.go`): GET read model
> (`mode`, `effective`, `coverage: plain_http_only`, `revision`, entries,
> migration/key/degraded, `credentialsIneligible`, `scope: node-local`),
> POST create, PUT/DELETE `{id}`, credential POST, `/health` with the shared
> classifier; every managed mutation runs inside
> `saveAdminSettingsWithOverrides{upstreamMutate}` (validate → persist →
> publish; save failure ⇒ non-2xx, zero mutation) and is revision-fenced
> (428 missing / 409 stale + current / 404 vanished); audit carries entry id +
> redacted authority + action only. **v1 adapter**: `POST /api/upstream` is
> credential-free — 409 `credentialed_entries_present` (state gate, first),
> 400 `userinfo_not_allowed` / `invalid_entry` (whole list refused, nothing
> dropped), YAML-owned authorities skipped, omission can never remove a
> credentialed entry; GET URLs never carry userinfo; the legacy
> `static/index.html` panel was switched to the per-entry endpoints in the
> SAME commit (write-only credential form, T3 clear typed against the entry
> id, fence refusals rendered via the 2F-A helper). **Boot migration**
> (`upstream_v2.go`): durable-or-nothing — v2 document wins; else parse ALL
> legacy URLs first (parse failure ⇒ `degraded/parse_failed`, file
> untouched, runtime unchanged), key only when a password exists, seal in
> memory, atomic write of the complete v2 doc + credential-free legacy list,
> swap after durable success, bounded degraded reason on the read model.
> **Behaviour change recorded**: YAML entries now coexist read-only with the
> managed set (a saved empty managed list no longer wipes the YAML seed).
> **Import** keeps the minimal preserve rule (merge by authority,
> credentialed entries retained on omission or a redacted echo, a real
> password refused 400 `credentials_not_importable`, pre-validated before any
> store mutation). **Health/eligibility/modes**: tri-state probe with the
> bounded classifier (dial/TLS ⇒ `connect_failed`, deadline ⇒ `timeout`, 407
> ⇒ `proxy_auth_failed`, 2xx/3xx ⇒ healthy, other ⇒ `probe_http_error`; new
> entries `unprobed`; credential-ineligible entries never probed; bodies
> bounded/drained/discarded); eligibility `(none OR configured+matching hash)
> AND (unprobed OR healthy) AND circuit.Allow()`; modes
> `no_pool|chained|no_eligible_parent|direct_fallback` with the first real
> fallback firing the existing alert once. **Log hygiene**: raw transport
> errors are never logged/persisted/audited/returned (R42 injects a
> password-bearing error and proves its absence from logs, GET, health,
> diagnose and audit). Route count 241 → 243 (`/api/upstream/entries`,
> `/api/upstream/entries/`); OpenAPI `UpstreamEntry`/`UpstreamConfig`/
> `UpstreamEntrySpec`/`UpstreamCredentialRequest`/`UpstreamRefusal` +
> three new paths, bundle + inventory + generated types regenerated;
> `upstream_proxies_v2` added to `configSurfaces` (AdminDurable, Sensitive,
> off export/rollback/CP→DP). Exclusions honoured: no 2F-D import
> planning/dry-run/export schema/backup strip/restore reporting/
> prepare-downgrade/manual-probe audit, no PAC/Upstream React, no PX-1
> chaining, no YAML adoption, no secret-inclusive backups. Operator doc:
> `docs/operator/upstream-proxies.md`.
>
> **2F-B CORRECTION ROUND 2 RECORD (this branch, 2026-09-04).** External review
> of the corrected candidate (`16858885`) named three blockers; RED-before at
> the exact candidate (`pac_lifecycle_round2_test.go` R2-1..R2-6 and
> `mcp_tooltrust_harness_test.go`, 5/5 red — the clock-swap test reproduces
> the root-gate DATA RACE itself under `-race`). **(1) An unreadable reset
> sidecar could lose the reset permanently**: the loader renamed the only
> durable evidence aside BEFORE its replacement was proven and ignored the
> replacement write error, so a later boot found no reset and reopened
> publish. Now the unreadable bytes are COPIED aside as evidence and the
> replacement is written over the record path atomically (temp + rename); if
> the copy or the write fails the original stays in place, the reset stays
> fail-closed in memory, and the next boot repeats — there is no instant
> without durable reset evidence. **(2) Progress markers could claim effects
> that failed**: `saveConfigVersionNote` was best-effort and
> `publishCurrentConfigSnapshot`'s error was discarded, yet both markers were
> persisted as done. Now `saveConfigVersionNoteResult` is the error-returning
> core (refusal by the rewrite-identity gate, marshal failure, write failure;
> the wrapper keeps every best-effort caller unchanged) and each marker
> advances ONLY on proven success; a failed or refused effect leaves the
> operation committed + `pending_reconciliation`, and reconciliation retries
> exactly that effect (idempotent by `operationId` in the version note and by
> snapshot content), never repeating a completed one; `operation_pending` now
> names the pending state and progress. **(3) The root `-race` gate**: the
> MCP tool-trust harness leaked a reconcile loop across gap environments and
> swapped the coordinator clock without its mutex. Repaired in an isolated
> harness-correctness commit: the loop carries a per-composition cancel +
> done channel, `resetMCPToolTrustForTest` (every gap/soak environment's
> cleanup) stops AND joins it, `startToolTrustReconcileLoop` stops a previous
> loop first, and the soak's clock swap goes through `swapClockForTest` under
> the coordinator mutex. MCP production behavior is unchanged (one loop,
> started at init, stopped by the lifecycle context).
>
> **2E-B TRUE FINAL RECOVERY-FRESHNESS CLOSURE (this branch, 2026-08-30).**
> External source review of the lifecycle candidate (3669666e) found two
> remaining frontend defects; red-before at the exact candidate
> (`decryption-recovery-freshness.test.tsx`, 5/5 red — including the literal
> false "Rotation did not land" rendered from the warm TanStack cache, and a
> rotation PUT dispatched under a throwing sessionStorage.setItem).
> **(1) Stale-cache resolution.** `useSnapshot` caches with
> staleTime:Infinity and SPA navigation keeps the QueryClient alive, so a
> restored marker could be classified against the PRE-operation snapshot —
> a landed operation read as NOT-LANDED, marker cleared, Rotate re-armed.
> The tab now carries a RECOVERY-HYDRATION GATE
> (inspecting → stale → fetch-failed | fresh): Rotate is withheld from the
> first committed render until marker inspection completes; a restored
> marker forces a fresh GET, and ONLY a successful fetch whose
> dataUpdatedAt is strictly newer than the pre-recovery stamp opens the
> gate — deliberately NOT the recovery refetch's own promise, because a
> refetch cancelled by an unmount (StrictMode's simulated one included)
> resolves "success" while ECHOING the cached result. Until then cached
> data renders for context only ("Verifying an unresolved rotation…") and
> cannot classify, clear the marker, or enable Rotate; a failed recovery
> GET retains marker + latch with an explicit "Retry verification"; nothing
> auto-mutates. **(2) Fail-closed marker persistence.**
> `writeRotationRecovery` now verifies its own write (setItem + strict
> subject-bound read-back) and returns a result; `runRotation` refuses the
> irreversible dispatch without a provably recoverable marker ("The browser
> could not create the recovery record required for a safe key rotation. No
> rotation was sent.") — no memory-only or localStorage fallback, retry
> possible once storage works. Real-binary SPA-navigation e2e added (same
> app instance and QueryClient, no reload): a post-return GET is observed,
> the receipt resolves LANDED, the marker clears only then, exactly one
> rotation total. Backend, receipts, command contract, and every other
> surface untouched.
>
> **2E-B FINAL LIFECYCLE CLOSURE — the T3 recovery identity survives the
> client lifecycle (this branch, 2026-08-30).** External review of the
> corrected candidate (7f9206b6) accepted the operation-identity design but
> found its CLIENT lifetime wrong: the unresolved-rotation latch lived only
> in component React state, so navigating away or reloading before
> authoritative resolution forgot operation X and re-armed Rotate — if X had
> landed, a "retry" is a NEW operation id backend idempotency cannot stop.
> Red-before at the exact candidate (`decryption-rotation-lifecycle.test.tsx`,
> 6/6 red: operation forgotten after remount, Rotate re-enabled, no marker
> at dispatch). Closure: `rotationRecovery.ts` — ONE narrow sessionStorage
> marker (`culvert.decryption.rotation-recovery.v1`, a sanctioned per-site
> exception to the frontend contract's §9.B1 storage ban) holding ONLY
> non-secret facts `{version, operationId, preSeq, startedAt, subject}`
> (field allowlist pinned; never key material/key ids/config drafts),
> WRITTEN BEFORE the network dispatch (load-bearing order, pinned),
> subject-bound (a foreign-identity marker is discarded, never inherited),
> cleared at the auth boundary via a module-level `registerAuthCleanup` —
> deliberately NOT on component unmount. On remount/reload the tab restores
> the latch (an effect, not a state initializer — StrictMode's simulated
> unmount runs the boundary cleanup between effect passes), keeps Rotate
> withheld, and resolves the stored operation with the accepted server
> matrix: LANDED / NOT-LANDED clear the marker terminally (as do a confirmed
> response and an authoritative server error); AMBIGUOUS retains it and now
> has an EXPLICIT admin recovery ceremony ("Resolve ambiguous rotation…",
> typed ABANDON, T3-strength) that dispatches NO mutation — it abandons
> attribution for the old operation so a future rotation is a completely new
> deliberate T3 with a new identity. The v2 operation id widened from 64 to
> 128 bits (32 hex; server contract and receipt semantics unchanged).
> Real-binary lifecycle e2e on the throwaway appliance: a deterministic
> transport-loss seam (route interception executes the PUT, drops the
> response) + full page reload recovers the SAME operation, resolves it from
> the appliance's receipt with zero second rotation; the ambiguous ceremony
> is exercised with key/sequence/posture verified byte-identical. Backend,
> receipts, sequence, command contract, and every other 2E-B surface are
> untouched.
>
> **2E-B FINAL CORRECTION — rotation operation truth, redaction command
> presence, recovery unlatch (this branch, 2026-08-30).** External review of
> the 2E-B candidate (56c23e64) found the rotation unknown-outcome contract
> untruthful under concurrent admins and the redaction PUT's command decode
> unsafe; three coupled corrections landed with red-before evidence captured
> against that exact candidate (`decryption_2eb2_red_test.go`: 10 red + 1
> green control; `decryption-rotation.test.tsx`: 3 red — the candidate
> literally rendered "landed exactly once" for ANOTHER admin's rotation).
> **(A) Rotation operation identity.** "key_id changed" cannot attribute a
> generation transition to the caller's own operation. Every rotation now
> carries a REQUIRED client-minted opaque `operation_id` (1–64 chars,
> `[A-Za-z0-9._-]`) plus the fence; the appliance persists — atomically with
> the key, in the same persist-before-apply AdminSettings transaction — a
> durable monotonic key-generation sequence (`traffic_key_rotation_seq`,
> advanced by EVERY new-key install so "sequence unchanged" soundly proves
> not-landed) and a bounded (32, FIFO) NON-SECRET receipt
> `{op_id, key_id, seq, ts}` (`traffic_key_rotation_receipts`; allowlist
> pinned key-material-free; both restored on load, config_surfaces rows
> added, deliberately not Sensitive). The idempotency lookup runs BEFORE the
> stale fence, so a replay of an already-landed `operation_id` is answered
> from its receipt (`200 already_applied:true`, zero additional rotations)
> while a DIFFERENT operation on stale truth stays the structured 409. GET
> serves `rotation_seq` + `rotation_receipts`; the client matrix is exactly:
> our receipt present ⇒ LANDED exactly once; sequence == pre-operation
> anchor ⇒ NOT LANDED; sequence advanced without our receipt ⇒ AMBIGUOUS
> (stay latched, no claim, never rotate again blindly — covers both the
> concurrent-admin case and receipt-window aging; the stronger
> "window-coverage proves not-landed" inference was deliberately NOT taken).
> **(B) Command presence.** `redact_hosts` decoded as a bare bool, so
> `PUT {}` and `{"rotate_key":false}` silently DISABLED an enabled posture,
> and a combined posture+rotation body silently ignored the explicit posture
> field while OpenAPI advertised "and/or". The decode is now presence-aware
> (`*bool`) under an EXACTLY-ONE-ACTION contract: posture = `redact_hosts`
> alone (ifRevision optional — the legacy GUI, which only ever sends
> `{redact_hosts: bool}`, keeps its last-writer-wins contract); rotation =
> `rotate_key:true` + `operation_id` + `ifRevision` alone; empty bodies,
> `rotate_key:false` alone, identity-less rotations, and combined bodies are
> 400 with no mutation. OpenAPI/SetRedaction now states the runtime contract
> exactly. **(C) Recovery unlatch.** A proven LANDED / NOT-LANDED resolution
> now converts into a durable local notice and CLEARS the unresolved-
> operation latch (previously the button stayed disabled beside "you may
> start it again"), so a deliberate NEW rotation — with a NEW operation id,
> the old one never reused — is possible from fresh truth; AMBIGUOUS renders
> "cannot yet be proven" and stays latched; nothing is ever re-dispatched
> automatically, and the auth boundary clears every candidate/latch/notice.
> Preserved unchanged: node-local ownership, persist-before-apply, coherent
> revision snapshots, both fences, volatile-cache semantics, health labels,
> the T1/T2/T3 ceremony model, RBAC exact-mounting, and the secret boundary.
>
> **2E-B — Decryption Operations (this branch, 2026-08-30).** Second slice of
> the 2E decomposition: the OPERATIONAL decryption surface at
> `/app/security/decryption` (Health & Coverage · Destination Privacy ·
> Auto-Exclusions). 2E-C (CDR/Sluice) stays deferred; Decryption Profiles
> CRUD (2D-A) and CA/certificate management are linked, never duplicated.
> **Authoritative endpoint inventory (from source, 2E-B.0):**
> `GET /api/decryption/health` (viewer, side-effect-free; PROCESS-LIFETIME
> in-memory counters + a 360×1-minute volatile delta trend);
> `GET/PUT /api/decryption/redaction` (viewer/admin; the ADR-0011 §4
> destination-privacy posture + pseudonym key — governs what destination
> data is RETAINED in logs/observability, never whether traffic is
> decrypted); `GET/DELETE /api/decryption-exclusions` (viewer/operator; the
> VOLATILE learned-exclusion cache); `GET/PUT
> /api/decryption-exclusions/tunables` (viewer/admin; durable engine
> parameters). **Ownership:** all three write surfaces are NODE-LOCAL
> AdminDurable-only (config_surfaces rows `decryption_redact_hosts`,
> `traffic_pseudonym_key`, `traffic_pseudonym_key_id`, `autoexclude_*` — no
> ClusterSynced row), so the 2E-A managed-DP CP-authority model deliberately
> does NOT apply; the UI labels the scope "Node-local". **Backend
> corrections (red-before against 25a80a5e, `decryption_2eb_red_test.go` —
> 9 deterministic red + 2 green pins):** (§A) the redaction PUT was a
> fenceless whole-object write mutating live state OUTSIDE adminSettingsMu
> (apply-then-rollback); it now builds its target INSIDE the save's
> precondition with an optional body `ifRevision` fence and applies
> persist-before-apply under one serialized section; the GET is ONE
> coherent snapshot under the writer domain with a content-derived revision
> over (posture, key_id). (§B) rotation exposed no non-secret fact, so a
> lost response was unresolvable and a blind retry rotated twice;
> `TrafficPseudonymKeyID` — random, never key-derived, persisted beside the
> key, restart-stable, minted for legacy files on load — is exposed as
> `key_id` and folded into the revision, making a fenced retry a 409 that
> cannot rotate twice; rotation is durable BEFORE its success response and
> the restart observes the rotated generation. (§C) persist-failure truth
> (500 + running posture unchanged) pinned. (§D) the tunables PUT gains the
> `?ifRevision=` fence inside the save precondition; the exclusions GET
> serves `tunables_revision` derived from the SAME Stats snapshot as the
> current values; the PUT answers with the installed set + revision. (§E/§I)
> the evict audit records the true outcome (absent entry ⇒ "entry was not
> present"); the exclusions GET gains a bounded `?limit=` read with an
> explicit `truncated` fact. **Frontend:** snapshot semantics only; health
> counters labeled "since process start" (never re-labeled as a window;
> the prior cumulative-as-window mistake is not repeated), taxonomy keys
> verbatim, no derived health score; destination privacy separates
> retention from decryption in copy, enable = T1 confirm, disable = T2
> ceremony, rotation = T3 typed ROTATE ceremony bound to the reviewed
> generation with explicit "NOT the TLS inspection Root CA / not a
> certificate rotation" copy; rotation unknown-outcome LATCHES and resolves
> LANDED/NOT-LANDED by comparing key_id against fresh GET truth — never a
> blind repeat (rotation is excluded from every generic retry path);
> auto-exclusions labeled volatile/runtime-generated with drop-and-relearn
> copy ("does not delete Decryption Profiles or policy rules"), bounded
> list (limit 500 + truncated notice), evict/clear ceremonies; tunables are
> a structured form driven by server defaults/bounds, fenced, conflict
> preserves the form, and ONLY a guardrail-relaxing change gets a ceremony
> (`tunablesRelax`). RBAC-exact mounting (viewer zero controls; operator
> exactly the volatile actions; admin adds privacy/rotation/tunables);
> fail-closed decoders refuse a pre-2E-B appliance rather than mounting
> unfenced writes. **Evidence:** 12 API + 11 page unit tests; real-binary
> e2e journey (`decryption-2eb.spec.ts`) incl. ONE real rotation on the
> per-run throwaway harness appliance (isolated mktemp WORK dir, workers=1
> — never shared /data) verified by key_id change, plus the isolated
> temp-data-dir Go proof (`TestDec2EB_RotationDurableAcrossRestart`) for
> durable/restart/exactly-once truth. No new ADR needed — every decision
> fits the accepted appliance/frontend doctrine.
>
> **2E-A FINAL transaction & fleet-truth closure (this branch, 2026-08-29 —
> correction slice against candidate b60d4ed6).** Four blockers, each with a
> deterministic red-before (`secscan_2ea2_*_test.go` +
> `internal/scanner/scanner_writer_domain_test.go`; interleavings driven by
> the `contentSecGETPauseHook` GET seam and the scanner
> `SetWriteFileForTest` publication seam — never sleeps; the §2 select
> valve's other arm is lock-impossible at the fixed tree). **(§1) COHERENT
> FENCED READS:** the four fenced GETs assembled state and revision from
> separate store reads, so a writer landing between them made the GET emit
> `{data A, revision(B)}` — a token that let a stale A-based write PASS the
> fence against B. Every fenced GET (and PUT success response) now derives
> its revision from the ONE committed snapshot it returns (pure
> `*RevisionOf` derivations over the single-lock store copies; YARA
> settings snapshot under `adminSettingsMu`, the writer domain, so the six
> engine values can never serialize torn; the settings PUT responds/audits
> with the posture it installed). **(§2) ONE WRITER DOMAIN FOR THE SHARED
> DPI ENVELOPE:** `content_scan.json` carries patterns AND bypass hosts,
> but Save snapshotted under RLock and published after unlock — two
> successful mutation+Save sequences could publish in reverse order (both
> callers told success; restart trusts the STALE envelope).
> `ContentScanner.saveMu` now holds across snapshot+publication, so
> publication order equals snapshot order; every writer (interactive
> handlers, rollback, CP→DP apply, inspection seed, import) already
> funnels through Save. Hot-path pattern publication, mutators, and the
> Save API are unchanged. **(§3) FENCED DESTRUCTIVE YARA DELETE:** DELETE
> ignored concurrency (a delete reviewed against v1 destroyed v2) and a
> missing target was a 400. It now joins the POST/PUT contract — optional
> `?ifRevision=` (v2 always asserts), compared inside `contentSecMu`,
> truthful 404 first, structured 409 with the rule preserved
> byte-identical; the reload handler joins the same domain (LoadDir reads
> the dir outside `y.mu` — an unserialized reload could install a stale
> read last). The v2 delete ceremony fetches the authoritative rule on
> open, binds to that reviewed revision, and a conflict forces fresh
> truth. **(§4) CP/DP OWNERSHIP + FLEET TRUTH:** the 2E-0 inventory's
> "node-local" classification of DPI patterns was WRONG — DPI patterns and
> the threat-domain allowlist are ClusterSynced (`config_surfaces.go`), so
> the established F3a-2 managed-DP posture now applies (write refusal
> BEFORE mutation + `editable` on the GETs; bypass/exclusions/YARA stay
> node-local and writable), the allowlist PUT no longer discards the
> publish error (the established `cluster_publish_rejected` fact; local
> mutation kept per doctrine), and DPI mutations publish a fresh snapshot
> (DELETE keeps 204 on full success; 200-with-fact only when rejected).
> The v2 UI renders "saved on this node / fleet publication rejected" as
> two distinct facts and mounts the synced surfaces read-only on a
> managed DP. OpenAPI updated truthfully (editable, publish facts, DELETE
> ifRevision + 404/409, coherent-pair wording).
>
> **2E-A — Content Security & DPI (this branch, 2026-08-29).** First slice
> of the 2E decomposition (2E-0 inventory + 2E-A implementation; 2E-B
> Decryption Operations and 2E-C CDR/Sluice are inventoried but explicitly
> deferred — nothing decryption-operational or CDR ships here, and the
> 2D-owned Decryption Profiles / File Profiles surfaces are untouched).
> **Backend hardening (red-before against ac0e16f2,
> `secscan_2ea_red_test.go`):** (1) STALE-WRITER FENCES on the whole-set
> configuration writes — threat-feed domain allowlist, YARA engine
> settings, scan exclusions, DPI bypass — and the per-file YARA rule
> create/update: GETs serve a content-derived `revision`
> (`ui_security_fence.go`; no new persisted state, restart-stable for
> identical content), writes accept an optional `ifRevision` whose
> mismatch is the ONE structured 409 with no mutation; a fenced YARA
> CREATE asserts the `new` sentinel so an existing rule file is never
> silently replaced; absent fence = legacy last-writer-wins verbatim;
> `contentSecMu` (or the settings save's own adminSettingsMu precondition
> for YARA settings) makes compare+apply atomic; bulk doors
> (import/rollback/CP snapshot/seeds) deliberately bypass, matching 2D.
> (2) DURABILITY TRUTH: `ContentScanner.Save` returns its write error; DPI
> pattern add/remove, DPI bypass replace, and the scan-exclusions replace
> answer a truthful 500 on persist failure (applied in memory — fail-safe
> — with distinct `*_unpersisted` audit actions, the domain-allowlist
> precedent); the YARA settings PUT is persist-before-apply via a
> dedicated adminSaveOverrides target — its 500 leaves the live engine
> posture untouched. (3) SECRET BOUNDARY: the scan-service URL is
> userinfo-redacted on every viewer read surface (svc + both status-map
> sites). DPI pattern POST/DELETE stay item-level (no fence — commuting
> ops); imperative actions (feed sync, YARA reload, cache clear, validate)
> carry no fence by design. OpenAPI documents revisions, fences, 409s,
> durability 500s, and the redaction.
> **Frontend:** one Security-domain surface at /app/security/content-security
> (nav: Security → Content Security) with Overview / Threat Intelligence /
> YARA / DPI / Exclusions & Cache sections; dedicated `api/contentsec.ts`
> (fail-closed decoders, verbatim-preserved posture strings rendered as
> unrecognized when unknown, read/write DTO separation, canonical /api/dpi
> only — the deprecated /api/content-scan aliases are never requested,
> pinned by unit + e2e). RBAC-exact mounting (viewer zero write controls;
> Operator exactly DPI patterns + validate dry-run; Admin the rest).
> Ceremonies state effect and scope: whole-set replaces confirm with exact
> add/remove counts and the surface's real consequence; YARA delete,
> reload (cache cleared), coverage-reducing settings changes, pattern
> removal, and whole-cache clear are T2; validate is explicitly
> validation-only. Structured 409 → fresh-truth notice; transport-lost
> mutations latch until an advanced successful refetch (useObjectPage).
> **Proofs:** 20 new unit tests (391 total); real-binary
> `content-security-2ea.spec.ts` — viewer/operator posture, admin
> reversible bypass round trip with API verification and restore, live
> stale-fence 409, validate-only, ceremonial YARA rule delete against a
> per-run LOCAL rules directory (new harness premise in e2e-smoke.sh),
> truthful feed-sync refusal with feeds disabled, zero external-origin
> requests, zero deprecated-alias requests, full state restore at exit.
>
> **2D-C FINAL two-defect closure (this branch, 2026-08-29 —
> external-review follow-up on the 86c9c17a candidate).** Both red-before
> against 86c9c17a (`dc_final5_red_test.go`):
> **(1) Rollback dry-run identity leak.** The dry-run preview diffed the
> target against `captureConfigBackup()`'s live `rewriter.List()`, and
> `diffRewriteRules` is identity-aware — a degraded node exposed the
> KNOWN-ephemeral StableIDs through a healthy 200 preview. The dry-run
> branch now answers the ONE structured rewrite-identity 503
> (authorization first; no blanking/substitution/partial diff); the real
> rollback of a durable artifact stays available (its response carries no
> live-identity diff), and `apiConfigDiff` was checked: it diffs two
> STORED versions only. Healthy dry-run unchanged; OpenAPI documents the
> 503.
> **(2) Legacy install was not restart-stable.**
> `installRewriteRulesDurable` persisted an ID-less legacy target AS-IS
> and `SetRules` backfilled UUIDs only into its internal published copy —
> disk="" vs runtime=UUID, re-minting on every restart (the historical
> proof uses a genuine pre-extension artifact, because an artifact
> carrying SaaS-feed fields was incidentally repaired by the LATER feed
> slice's settings write — exactly the later-save dependency the invariant
> forbids). Legacy identity is now canonicalized on a copy of the target
> BEFORE the durable write, and that exact canonical slice is persisted
> AND published — identity generated once, modern IDs verbatim, persist
> failure publishes nothing, CP follower path untouched. Proven for
> direct install, historical rollback, and import replace + merge-append,
> each across restart.
>
> **2D-C FINAL identity egress & persistence closure (this branch,
> 2026-08-29 — external-review follow-up on the eec0ca44 candidate).** The
> accepted state/legacy-GET closures left the KNOWN-ephemeral StableIDs
> flowing out through egress and durability paths while the rewrite
> management-identity degradation was latched; the governing invariant is
> now enforced at every sink the §3 inventory found: WHILE LATCHED, NO NEW
> DURABLE ARTIFACT MAY RECORD THE LIVE EPHEMERAL StableIDs AS
> AUTHORITATIVE. Each fix red-before against eec0ca44
> (`dc_final4_red_test.go`):
> **(1) Config export.** `apiConfigExport` (admin-authorized FIRST, then
> the disclosure) answers the ONE structured `{error,
> degraded:"rewrite-identity", reason}` 503 for the `rewrite` section AND
> for any request the default arm serves as the full export
> (empty/`all`/unrecognized sections) — never a 200 backup carrying
> ephemeral identity, never a silently partial "full" backup. Sections
> with no rewrite identity export unchanged. OpenAPI documents the 503.
> **(2) Config-version capture.** `saveConfigVersionNote` refuses while
> latched with a named operator log line — an unrelated admin mutation's
> best-effort versioning no longer persists an artifact whose valid-UUID
> ephemeral IDs a later rollback would promote through
> `installRewriteRulesDurable`. The triggering mutation stays complete.
> **(3) Omnibus settings save.** `saveAdminSettingsWithOverrides` carries
> the existing file's rewrite fields (rules + sentinel + seed ledger)
> VERBATIM while latched instead of snapshotting the live set +
> `RewriteRulesSaved=true` — preserving the refused-but-recoverable
> operator slice; no readable file ⇒ no rewrite claim; unreadable ⇒ the
> save refuses rather than overwrite what it cannot carry
> (`carryFileRewriteFields`). Rewrite-mutating saves stay exempt (their
> targets carry durable-artifact identities; interactive mutations are
> already refused upstream).
> **(4) CP→DP publication.** `ConfigStore.Update` gains Gate 0: while
> latched the publish is REJECTED through the existing commit-time
> rejection contract (`rejectPublish` → log/alert/LastPublishError; the
> fleet keeps the last valid snapshot) — the rewrite slice is never
> silently omitted or re-minted. HA carries only leader-publish-gated
> bundles (`seedReplicatedSnapshot` seeds from the leader's replicated
> snapshot), so the gate covers that path by construction.
>
> **2D-C FINAL recovery trust-boundary correction (this branch, 2026-08-29 —
> external-review follow-up on the 161eb79e candidate).** Three gaps, each
> red-before against 161eb79e (`dc_final2_red_test.go`):
> **(A) Settings-owned rewrite restore bypassed the UUID contract.** The
> restore published whatever admin_settings.json carried; SetRules only
> regenerates empty/duplicate IDs, so a malformed non-empty stableId
> ("hello") became live authoritative identity that /api/rewrite/state
> exposed and the newer trust doors later rejected. The restore now runs
> the SAME validateRewriteStableIDs seam: empty = the one legacy migration
> input (backfilled as before); malformed non-empty or duplicate refuses
> the WHOLE rewrite slice — nothing published, the previously-seeded
> runtime source stays live per startup ownership, and the named
> management-identity degradation latches. No silent re-mint of a
> malformed identity.
> **(B) A failed identity migration still exposed ephemeral StableIDs.**
> finalizeRewriteSeedIdentities logged and continued when the ledger (or
> the legacy backfill) could not persist — identities KNOWN to re-mint on
> restart were presented as durable management identity. A rewrite
> management-identity durability LATCH now holds instead (re-evaluated by
> every settings load): traffic rewrite enforcement and legacy runtime
> semantics continue, but GET /api/rewrite/state answers a structured 503
> ({error, degraded:"rewrite-identity", reason}) — ephemeral IDs are never
> exposed at all — and v2 rewrite mutations refuse until durable identity
> is established (fix the file/volume, restart). The unreadable-file and
> quarantined-corrupt settings load paths run the same finalize judgment.
> The Header Rewrite page recognizes the structured 503 (strict
> marker-checked decoder) and renders the dedicated degraded state naming
> the appliance's reason, mounting no write controls.
> **(C) The interactive write door could manufacture ID-less legacy
> references.** validateRuleObjectRefs let the compiled fileProfileExts
> map satisfy a NEW create/update, so after a built-in was renamed or
> deleted a modern rule persisted with FileProfile=legacy name and
> FileProfileID="" — legacy-fallback enforcement, bypassing the promotion.
> The interactive door now requires LIVE store resolution (structured
> dangling-reference 400; the stamp always lands); a write against the
> renamed profile's NEW name binds to the SAME built-in stable ID. The
> compiled map remains the EVALUATOR fallback for historical ID-less
> rules, and the bulk doors keep their documented trust-domain
> classification (modern exports judged by ID; historical ID-less backups
> and untouched live rules legitimately reach the compiled-map arm;
> rollback/CP snapshots verbatim) — the invariant is that the interactive
> modern door can never mint another ID-less reference.
>
> **2D-C FINAL identity / recovery / fail-closed correction (this branch,
> 2026-08-29 — external-review follow-up on the dc638a22 candidate).** Six
> defects, each red-before against dc638a22 (matrix rows A–H,
> `dc_final_red_test.go` + `internal/fileblock/fileprofile_final_red_test.go`):
> **(A) Dangling authoritative FileProfileID was FAIL-OPEN.** The reviewed
> `FileProfileBlocked` returned false when a non-empty authoritative ID no
> longer resolved — the configured file control silently disappeared (and
> the path is reachable: profile-store Load errors are non-fatal). It now
> FAILS CLOSED for exactly the transactions any profile could ever block —
> paths carrying a file extension — while extension-less transactions stay
> untouched (an extension set can never match them, so blocking those would
> invent semantics). Anti-rebinding is preserved: still no name/legacy
> retarget. The degradation is operator-visible:
> `culvert_fileprofile_unresolved_block_total` + a rate-limited WARN naming
> the unresolved ID. Legacy ID-less rules keep byte-identical historical
> resolution (control-pinned).
> **(B) Boot reconciliation ran before the FileProfile store loaded.**
> `reconcileObjectRefNames()` preceded `initFileBlocking(s)` in main.go, so
> the FileProfile rename crash-recovery pass consulted an EMPTY store and a
> stale denormalized name survived every restart. The single pass now runs
> AFTER initFileBlocking — every store it reads (policy+draft, groups,
> decryption profiles, file profiles) is loaded first, and no listener has
> started. Pinned by a source-order gate plus a permanent defect-mechanism
> proof and the loaded-store recovery proof (running name converges,
> identity + enforcement unchanged).
> **(C) YAML-only rewrite StableIDs were not durable.** With no
> admin_settings.json and no admin write, every boot re-identified the
> YAML-seeded rules. `finalizeRewriteSeedIdentities` (run from
> LoadAdminSettings on BOTH the loaded and file-absent paths, before the
> admin listeners start) now records the minted identities in a durable
> IDENTITY LEDGER (`rewrite_seed_identities`, AdminSettings — no second
> file) and re-attaches them per position+content each boot: an unchanged
> YAML file presents the SAME StableIDs every restart, an edited position
> is a new object with fresh identity, and YAML stays the source of the
> RULES (the ledger claims ownership of nothing — not even the rewrite
> sentinel). All migration writes go through a TARGETED writer
> (`persistRewriteIdentityMutation`) that preserves every unrelated field
> and ownership sentinel; the earlier in-file legacy backfill migration was
> converted off the omnibus SaveAdminSettings for the same reason (it
> stamped unrelated surfaces saved-authoritative). Admin-persisted explicit
> empty (sentinel) still never resurrects YAML rules.
> **(D) fpv1 fingerprint ambiguity.** The profile row joined extensions
> with "," while normExts permits a comma inside an extension, so
> [".a",".b"] and [".a,.b"] collided into one revision (stale-editor
> false-pass). fpv2 length-frames every user-controlled string and the
> extension count (no reserved delimiters); profile ordering stays
> canonicalized by sorting encoded rows; extension ordering is PRESERVED
> as stored (documented choice — the fence distinguishes every observable
> difference).
> **(E) FileProfile identity invariants now validated at every boundary.**
> `fileblock.ValidateProfiles` (one seam): non-empty unique IDs, non-empty
> case-insensitively-unique names — applied at disk Load (refusal keeps
> the store empty; ID-bearing rules then fail closed), at the CP snapshot
> preflight (whole snapshot rejected BEFORE any slice applies), and at
> ReplaceAll (candidate validity separate from follower durability).
> Audit verdict: FileExtProfile was BORN with the ID field, the
> deterministic `builtin-*` IDs and a uuid-minting Create, so missing IDs
> are corruption → refuse (no migration; IDs deliberately NOT required to
> be UUIDs — the built-ins are not).
> **(F) Rewrite StableID format contract.** `validateRewriteStableIDs` now
> enforces what the prose always said: empty = legacy candidate (migrated
> at install), non-empty must parse as a UUID, duplicates AND malformed
> non-empty values reject the whole candidate — at import, rollback and CP
> snapshot (one shared seam). A hand-edited seed LEDGER failing the same
> validation is discarded (re-mint), never trusted.
> **(G) Rollback operator truth.** rewrite_rules left
> `rollbackRuntimeOnlySurfaces` — the 2D-C rollback slice persists through
> the AdminSettings owner, and a restart-simulation proof
> (`TestDCFin_RewriteRollbackSurvivesRestart`) pins that a successful
> rewrite rollback survives restart with the same identities.
> **(H) Identity-aware rewrite history diff.** `diffRewriteRules` now
> detects add/remove by StableID, operation/host changes on the SAME
> identity, and pure ordering changes (order is semantics); legacy entries
> without stable identity get a conservative ordered content comparison
> that can never report a changed set as "no change".

> **Slice 2D-C implementation record (this branch, 2026-08-29).**
>
> **2D-C.0 backend hardening — two identity promotions before any
> write-capable control mounted (§3 order held).**
> **File Profiles (0A/0B):** `PolicyRule.FileProfileID` promoted alongside
> the existing group/decrypt-profile IDs (JSON per repo convention;
> DecryptionProfile-scale precedent, so the §5 STOP condition did not
> fire). Name = intent: `stampObjectRefIDs` derives the ID server-side
> from the submitted name and a client-supplied `fileProfileId` is never
> trusted (a mismatched pair binds to the NAME). Enforcement resolves
> ID-first; a rule carrying a non-empty authoritative ID whose profile is
> gone FAILS CLOSED (2D-C final correction — see the record above; the
> as-reviewed candidate returned false here, which was fail-OPEN for the
> configured control, and it is NEVER retargeted to a same-named object)
> — deliberately STRICTER than the
> group precedent's name fallback because the legacy built-in name space is
> compiled-in; the Where Used walk agrees with enforcement (no
> dangling-name fallback), divergence documented at both sites and in
> OBJECT-REFERENCES-BY-ID.md. ID-less legacy rules keep byte-identical
> behavior (store name, then the compiled `fileProfileExts` map).
> `internal/fileblock` moved to copy-on-write immutable publication (also
> closing an in-place `Update` data race against the lock-free
> `Extensions` read path) with durable-or-nothing commits (persist target
> THEN swap; hard failure = old memory + old disk; `ErrReplacedNotSynced`
> = landed-content doctrine), a content-derived restart-stable revision
> (`fpv1` over sorted id/name/extensions rows), one-lock
> `SnapshotWithRevision`, and fenced CRUD (`ifRevision` compared inside
> the critical section; `ReplaceAll` documented as the CP→DP follower
> path only). Rename is a TRUE rename: `CascadeFileProfileRename` updates
> the denormalized display name on running rules (by ID; by name for
> ID-less rules, stamping the ID) and the active draft candidate, with a
> truthful 500 on cascade-persist failure. Built-ins (deterministic
> `builtin-*` IDs) remain fully mutable — the inspected pre-slice product
> behavior, preserved and made safe by ID promotion (§14: documented, no
> silent product change).
> **Header Rewrite (0C/0D):** the integer `Rule.ID` is process-local and
> reassigned by `SetRules` — NOT product identity (§19: no deep links, no
> fencing on it). `internal/rewrite` gained `StableID` (server-owned UUID;
> `yaml:"-"`), backfilled once at load and made durable through the REAL
> AdminSettings owner (§24: `RewriteRules` + `RewriteRulesSaved` sentinel
> — saved-authoritative including empty; no second configuration file);
> one narrow writer domain: interactive mutations run read-current + fence
> + build inside `adminSettingsMu` (`rewriteMutate` override), bulk
> installs go through `publishRewriteRules` (runtime-only follower: SIGHUP
> reload, boot seed, CP→DP snapshot) or `installRewriteRulesDurable`
> (rollback + import — fixing a REAL pre-existing durability hole where
> rollback's rewrite slice was runtime-only). Restart-stable content
> revision `rwv1` (position + stableId + host + all ops, deterministic map
> canonicalization, length-framed); `GET /api/rewrite/state` returns
> {rules, revision} from one coherent snapshot; create/delete assert
> `?ifRevision=`. Create ignores any caller stableId (server mints);
> delete addresses `?stableId=` (legacy `?id=` retained). ORDER IS
> SEMANTICS (§23): evaluation order preserved verbatim everywhere; no
> reorder invented. Identity trust at the bulk doors (§20–22/§36–39):
> import replace preserves modern IDs, merge upserts in place by stableId
> with ID-less appends minted fresh; duplicate stableIds reject the WHOLE
> candidate (import 400 / rollback 400 / snapshot validation) — never a
> silent single-side regeneration; rollback/CP-snapshot identities are
> applied verbatim (a restored version never mints fresh identities);
> legacy integer IDs are never reinterpreted as stable IDs.
> **Bulk graph closure (0E):** the FileProfile edge joined
> `bulkCandidate` (`CheckRuleFileProfiles`): an ID-bearing rule must
> resolve within the candidate ID set (no name fallback — matching
> enforcement), an ID-less rule by candidate name or the legacy compiled
> map; `canonicalizeCandidateRuleRefs` stamps FileProfileID from the
> candidate set so the validator judges the EXACT rule the path installs.
> File profiles are deliberately NOT on the export/import/rollback
> surfaces (ConfigSnapshot-only per the Finding 10.3 registry), so those
> candidates use the LIVE store; the CP→DP snapshot judges both-sides-
> carried `snap.FileProfiles`.
> **Shared 409 dialect:** both new fenced surfaces render the established
> `{error, currentRevision, yourRevision}` revision conflict — one dialect
> across every fenced admin surface; the existing client recognizer
> applies unchanged.
>
> **2D-C.1 File Profiles page** (`/app/objects/file-profiles`, viewer+
> read / operator+ writes): coherent `GET /api/fileblock/profiles/state`
> snapshot; list with built-in badges and extension counts; stable-ID row
> detail + Where Used; create/edit dialog with the rename truth callout,
> one-extension-per-line editor and a normalization preview (server
> authoritative — the saved profile shows the appliance's normalization);
> fenced mutations with the shared structured 409 notice; T2 delete with
> the Where Used preflight (information only) and the authoritative
> referencedBy 409; unknown-outcome latch; dirty guard; auth-boundary
> cleanup; `?id=` deep link. The Access Rule File Profile selector now
> reads the coherent state endpoint (§32) — names in a rule stay intent,
> the server stamps the ID at rule save.
>
> **2D-C.2 Header Rewrite page** (`/app/policies/header-rewrite` — a
> POLICY surface, §29: not under Objects): evaluation-order table
> (position, host scope, per-direction ops summaries) with the ordering
> note ("multiple matching rules are applied in the displayed order");
> stableId only in the row detail (legacy integer id labeled process-local
> — not an identity); Create + Delete only (no backend update primitive →
> no Edit offered; no reorder invented); structured editor sections (host
> scope; request/response Set / Add / Remove as Header-Name: value lines)
> — not a JSON textbox; zero-op creates refused locally mirroring the
> server contract; fenced mutations; unknown-outcome latch; dirty guard.
>
> **Proofs:** `dc_identity_red_test.go` (11 red-before at the 69f53bea
> checkpoint + the honest green control: the file-profile delete gate was
> ALREADY closed by 2D-B) + `dc_identity_test.go` (12 green contracts);
> frontend `dcobjects-api.test.ts` + `dc-pages.test.tsx` (21 tests:
> decoders incl. order preservation and pre-backfill tolerance, viewer
> posture, fenced bodies, create-never-submits-stableId, delete-by-
> stableId, zero-op refusal, conflict notices, unknown-outcome latch);
> real-binary `e2e/dc-2dc.spec.ts` (server normalization, rename keeps
> identity + cascades onto the referencing rule, referenced delete
> refused with the authoritative consumer, delete after unreference,
> UI-created rule receives a server-owned stableId, truthful order,
> delete by stableId, stale-fence 409 leaves the appliance unchanged) —
> no external traffic; the data-plane rewrite effect stays proven by the
> Go suites against deterministic local fixtures (§42).
> **Recorded postures:** YAML-only no-settings-file deployments carry
> process-local rewrite IDs until the first settings save (backfill
> persists once a durable owner exists); pre-promotion config-version
> captures backfill at publication (one-time migration, documented).
>
> **Slice 2D-B implementation record (this branch, 2026-08-28).**
>
> **2D-B.0 backend hardening** — the URL-category store (`internal/urlcat`)
> joined the durable/fenced mutation doctrine WITHOUT a new on-disk format:
> the optimistic fence is the existing restart-stable `ContentFingerprint`
> (§7 decision — ABA equality accepted; the on-disk file stays the legacy
> bare array), evaluated inside the store's new mutMu/saveMu serialization
> domain (fence → memory mutation → durable publish, rollback to the
> pre-mutation taxonomy on persist failure, landed-content doctrine,
> publication ordering + commit boundary per 2D-A). Legacy mutators became
> memory-only cores + best-effort wrappers; `ReplaceAll` (cluster apply /
> import / rollback) holds the mutation domain; the 10,000-host bound is
> enforced at the store boundary on EVERY write path (the legacy PUT and
> single-host add were uncapped); fenced create is STRICT. The v2 read seam
> is `GET /api/urlcat/state` ({categories, revision}) — the legacy raw-array
> GET is byte-identical; `?ifRevision=` mutations recompose the signed
> effective view ONLY after durable success. Overrides gained
> `catoverride.ReplaceAllDurable` (fenced full-set replacement over the
> `saasFeedOverridesFingerprint` durable authority revision, same
> serialization/rollback doctrine; empty set stays the deliberate
> clear-all). SaaS settings gained a content-derived configuration revision
> fenced INSIDE the serialized AdminSettings save domain via the extended
> persist-before-apply pattern (`precondition` + `saasFeed` target override:
> comparison, durable target write and runtime apply under one
> `adminSettingsMu` section — a persist failure never applies the target).
>
> **2D-B.1–5 frontend** — `frontend/src/api/urlcat.ts` (fail-closed decoders
> for state/lookup/feed-status/signed status/settings/overrides/refresh;
> the shared string-revision conflict recognizer; null semantics preserved;
> the nine-state signed vocabulary with an unknown bucket never coerced
> healthy) + `/app/objects/url-categories` (five sections: Categories with
> the bounded one-host-per-line editor and no rename affordance — category
> NAMES stay authoritative, §3; Lookup manual-run with "Uncategorized" as
> taxonomy truth; Feed Status with UT1 corpus semantics labeled "UT1
> community feed"; Signed SaaS Feed with stale = LKG-serving copy,
> official-endpoint-only settings, T2 enablement ceremonies, managed-DP
> read-only posture, `cluster_publish_rejected` as local-saved/fleet-
> rejected, §30 manual refresh; Overrides with subtree-scope ceremony and
> counted clear-all). Browser proofs: unit matrices (urlcat-api,
> urlcat-page) + real-binary `urlcat-2db.spec.ts` incl. the two-client
> stale-write 409 and a per-test guard that the browser never contacts the
> public signed-feed hostname (§31). §47: the Policy Learning category
> epoch moves on an admin semantic edit, is restart-stable over identical
> persisted taxonomy, and the override fingerprint moves the signed
> identity; the UT1 community DB stays OUTSIDE the epoch (recorded
> limitation, stated nowhere as covered). Recorded residual: the v2
> downgrade posture and release-rollback lifecycle notes from 2D-A carry
> forward unchanged.
>
> **2D-B final coherency / reference-integrity / ownership correction
> (this branch, 2026-08-28 — external-review follow-up on the first 2D-B
> candidate).** Five defects, each with red-before evidence against the
> prior frozen candidate:
> **(A) Coherent fenced reads.** `GET /api/urlcat/state` assembled rows and
> revision from two independent store reads; `urlcat.SnapshotWithRevision()`
> now captures both under one read-lock hold (fpMu → mu, memo single-flight
> preserved) and is the only read the v2 state contract uses; the UT1
> enrichment layers over the captured rows. **POST-2D-A COHERENT-READ
> CORRECTION DISCOVERED DURING 2D-B REVIEW:** the Category Groups and
> Decryption Profiles list GETs had the same defect as three reads
> (List/Names/Version) — each engine gained `SnapshotView()` (rows + names +
> fence version from one lock hold; response shapes unchanged), and the SaaS
> settings view resolves its effective block from the SAME captured durable
> value (`resolveSaaSFeedConfigFrom`). Proofs: `coherent_read_2db_test.go`
> (engine-identity fingerprints over returned rows; the directional
> version invariant — a fence token AHEAD of returned rows is the dangerous
> pair).
> **(B) Reference-integrity transaction.** The recorded POLICY-REFS-PLAN
> TOCTOU (scan-then-delete) is closed by `objectReferenceMutationGate`
> (narrow RWMutex, NOT a config-transaction framework): deletes + bulk
> installs exclusive over scan+durable-delete, reference writers shared;
> lock order and the audited non-holder classification live at the gate;
> proofs in `object_reference_gate_test.go` (structural mutual exclusion
> through the real handlers + §7 A–E semantic pins incl. the active draft
> candidate).
> **(C) Per-category 10k cap on bulk paths.** `urlcat.ValidateEntries` is
> the canonical full-set seam and `ReplaceAllChecked` the checked installer;
> cluster snapshot apply, config import (pre-apply, whole-import 400) and
> rollback (pre-apply, whole-rollback 400) reject an over-cap candidate
> wholesale — never truncated, never partial. Explicit legacy decision:
> startup Load grandfathers a pre-cap on-disk file; no runtime path may
> re-create one.
> **(D) Signed-feed ownership truth.** `signedFeedOwnsBuiltInCategories()`
> derives built-in mutability from the live effective view's SOURCE
> (embedded/nil = local; downloaded/cached/resumed = signed-feed — covers
> stale/disabled-recovery by construction); `/api/urlcat/state` carries
> `builtInAuthority` + per-row `writable`; v2 mutations on a feed-owned
> built-in refuse with the structured 409 pointing at SaaS Overrides
> (legacy unfenced callers keep compatibility, pinned); the Categories tab
> renders the server truth — "Signed-feed owned" badge, no Edit/Delete,
> "Manage with Overrides" tab switch, page-level authority callout.
> **(E) SaaS settings writer domain.** `installSaaSFeedDurable` puts config
> import and the rollback feed slice inside the SAME adminSettingsMu
> transaction as the fenced settings PUT (derive → durable write → holder
> publish; rollback's unlocked post-apply save removed); the CP→DP apply is
> a separate managed-DP ownership domain and startup is pre-listener —
> audited at the helper. Proofs: `saas_feed_writer_domain_test.go` (paused
> transaction blocks import/rollback; three-surface agreement on the
> serialized winner; the reverse-direction fenced-PUT 409).
>
> **2D-B transactional-read / referential-integrity / ownership-linearization
> correction (this branch, 2026-08-29 — external-review follow-up on the
> five-blocker candidate).** Three transaction-boundary defect families,
> each red-before against e221106d:
> **(A) Committed fenced reads.** MutateDurable's fn mutates under the inner
> lock and releases it before the version bump/publication, and a persist
> failure rolls back at the SAME version — so a management GET inside that
> window captured phantom rows at the unbumped version, and an edit derived
> from them PASSED the ifVersion fence against the rolled-back tree. The
> three snapshot readers (`SnapshotWithRevision`, both `SnapshotView`s) now
> acquire the store's mutation serializer first (urlcat: mutMu → fpMu → mu;
> catgroup/decryptprofile: mutMu → mu): a fenced management read waits for
> the open transaction to reach success or rollback and describes committed
> truth only; no hot-path lookup takes mutMu. Proofs:
> `committed_snapshot_2db_test.go` (real GETs, fn-seam pause + ENOTDIR
> publication fault — the red runs demonstrated the ifVersion=N false-pass
> err=nil) + `urlcat_committed_snapshot_test.go`.
> **(B) Delete-first referential integrity.** Reference writers validate
> their targets UNDER the shared gate before committing
> (`policy_ref_validation.go`): access/auth-rule create+edit, group
> create/membership edit, PL Accept-to-Draft (new 409 sentinel). Predicates
> match runtime resolution (§9): a category name resolves via ANY current
> authority (catStore object, live signed view class — new
> `HasCategoryName`, UT1 mapped name); groups/profiles ID-first with name
> fallback; file profiles via store-then-legacy-map exactly as
> `FileProfileBlocked`. Bulk installs stay exclusive, validated by their
> leaf-first whole-candidate application. Both serial orders proven
> (`reference_delete_first_test.go`: A–E + the raced queued-writer shape +
> the feed-authority vocabulary pin); writer-first 409 proofs retained.
> **(C) Ownership linearization.** `taxonomyAuthorityGate`:
> `feedLiveStore.Swap` (the one production transition point) is exclusive;
> `beginV2CategoryMutation` holds the shared side across [ownership read →
> durable catStore mutation], released before the recompose (a later
> transition is a legitimately ordered supersession — §14; admin-created
> rows never take the gate — §13; `Current()` stays lock-free). The state
> GET captures the ownership fact ONCE and derives `builtInAuthority` and
> every `row.writable` from it (§15). Proofs: `taxonomy_authority_test.go`
> (transition-waits, mutation-waits→truthful 409, §13/§14 pins, GET
> tear-proof). API shape unchanged — no frontend source change.
>
> **2D-B trust-boundary / policy-read / bulk-integrity correction (this
> branch, 2026-08-29 — external-review follow-up on the 244a846e
> candidate).** Five defect families, each red-before against 244a846e:
> **(1) Interactive reference trust boundary.** `validateRuleObjectRefs`
> used to run BEFORE server canonicalization and accepted "supplied ID
> exists OR name exists" — a payload naming a MISSING object while
> smuggling a valid unrelated object's ID passed validation, the stamp then
> discarded the ID, and a dangling rule landed. The pipeline is now decode
> → structural validation → SERVER canonicalization
> (`stampRuleMetadataForWrite`/`stampObjectRefIDs`, client IDs discarded) →
> reference validation of the FINAL canonical rule → persistence, at all
> five interactive rule sites + PL Accept; validation keys on NAMES only.
> A mismatched name/ID pair binds to the NAME's object (doctrine pin, not
> an error). Proofs: `reference_trust_boundary_test.go`.
> **(2) Runtime-faithful category resolvability.**
> `referencedCategoryResolvable` now mirrors `resolveFusion` exactly: view
> installed ⇒ catStore BuiltIn=false admin tier + the CURRENT view's
> classes + UT1; a BuiltIn=true catStore-only name the view does not serve
> is NOT referenceable; no view ⇒ full catStore + UT1.
> **(3) Policy fenced reads.** `PolicyStore.SnapshotWithVersion()` (rules +
> version + updatedAt under ONE read lock) + the coordinator-locked
> `effectiveManagementSnapshot()`: GET /api/policy and GET /api/authpolicy
> no longer pair a rule list with a version read from a second call — the
> stale-rows/successor-token pair that let an edit pass the ifVersion fence
> against content the client never saw. `CurrentConfigSnapshot`'s
> PolicyRules/PolicyVersion capture fixed the same way (§13 audit).
> **(4) Draft review snapshot.** GET /api/policy/draft assembles
> state/diff/pendingCount/version/shadows/baseStale from ONE
> `reviewSnapshot()` capture; diff/shadows derived from the captured
> slices by pure functions (`diffRuleSets`), so the returned commit token
> identifies exactly the reviewed candidate — a commit with it can never
> activate a rule the review never showed (deterministic §12 proof kept as
> the load-bearing 2B regression gate). Proofs:
> `policy_fenced_read_test.go`.
> **(5) Bulk candidate reference integrity + whole-snapshot 10k.**
> `bulk_ref_validation.go`: a PURE candidate-graph validator
> (rule→group/profile ID-or-name within the candidate; category names via
> candidate entries ∪ live view/UT1 closure; FileProfile deferred to
> 2D-C) applied at the three bulk doors — config import constructs the
> EFFECTIVE merged/replaced candidate and 400s the whole import inside the
> exclusive gate before any mutation; rollback validates the restored
> candidate (nil-section = live) beside the 10k gate; CP→DP
> `validateConfigSnapshot` gains the deterministic both-sides-carried
> graph checks AND `urlcat.ValidateEntries` so one over-cap category now
> rejects the ENTIRE snapshot (no more mixed new-rulebase/old-taxonomy
> apply; `ReplaceAllChecked` stays as defense in depth). Proofs:
> `bulk_ref_integrity_test.go`. API shapes unchanged — no frontend source
> change.
>
> **2D-B final bulk canonicalization + effective-authority correction (this
> branch, 2026-08-29 — external-review follow-up on the f29f652d candidate).**
> Two remaining bulk-validation defects, each red-before against f29f652d:
> **(A) Import validated a different rule than it installs.** The candidate
> validator judged incoming rules AS SUBMITTED (name-or-ID), while
> importPolicyRules later discards client IDs and re-derives from names — a
> backup naming a MISSING group/profile while smuggling a valid unrelated
> object's ID passed pre-validation and landed a dangling rule.
> `canonicalizeCandidateRuleRefs` is the PURE candidate analogue of
> stampObjectRefIDs: incoming/updated import rules are canonicalized against
> the CANDIDATE object sets (which may be supplied by the same backup and
> are not live yet) before validation, so the validator judges the rule the
> import will actually install; untouched live rules in merge/never-wipe
> candidates retain their ID-authoritative semantics. §10 distinction
> recorded in-code: rollback/CP-snapshot rules are applied VERBATIM (no
> restamp) and legitimately keep authoritative IDs — judged ID-or-name as
> captured, never re-canonicalized.
> **(B) Post-apply category authority.** The bulk closure treated every
> candidate URLCategories row as authority regardless of BuiltIn and
> unioned the CURRENT effective view. `postApplyCategoryClosure` now
> previews the POST-APPLY authority per the runtime source model (§8): no
> view ⇒ full candidate + UT1; embedded ⇒ candidate BuiltIn baseline
> recomposed; downloaded/cached/resumed ⇒ candidate BuiltIn=false admin
> names + the candidate override set composed over the RAW pre-override
> signed base + UT1 — a candidate BuiltIn=true row is NOT authority merely
> for being present. The raw base is retained on the effective view at
> composition time (`effectiveCategoryView.base`, set by buildEffectiveView
> from rg.SnapshotEntries and by composeEmbeddedForOverrides — the
> production recompose's own input), and the preview composes candidate
> overrides via the runtime's own pure seams
> (catoverride.ComposeMembership), never over the already-composed entries
> (no double-apply, §7). Per-path candidate override semantics mirrored
> exactly: import merge/replace/absent-skips, rollback nil-keeps/non-nil-
> replaces, snapshot nil-keeps/non-nil-authoritative-replacement. Signed-
> feed protocol untouched (§9). Proofs: `bulk_canonical_authority_test.go`
> (ID-smuggling both kinds, BuiltIn-only false acceptance on import +
> snapshot, override-introduced category false refusal, tombstone-removed
> last-instance false acceptance on import + snapshot — all red at
> f29f652d; mismatched-pair name binding, same-import object resolution,
> and the §7 raw-base/no-double-apply controls).
>
> **Slice 2D-A implementation record (this branch, 2026-08-28).**
>
> **2D-A.0 backend hardening** — the shared-object stores
> (`internal/catgroup`, `internal/decryptprofile`) were the last mutation
> surfaces behind the v2 program still on best-effort persistence. They now
> carry the 2B/2C-class contract: error-returning `SaveErr`, a serialized
> `MutateDurable` primitive (optional `?ifVersion=` fence + mutation +
> persist + rollback in ONE critical section; confirmed 2xx =
> restart-durable; `ErrReplacedNotSynced` follows the landed-content
> doctrine), a durable per-store generation persisted ATOMICALLY WITH the
> content in a single `storeEnvelope` write (fence-durability correction:
> the earlier `.meta` sidecar could diverge from the objects file across a
> landed-content success — the envelope makes the ABA generation alias
> structurally impossible; legacy bare-array files + sidecar still load and
> migrate on first save; `ReplaceAll`/bulk installs hold the SAME mutation
> serializer as `MutateDurable`, so every runtime writer orders against the
> fence; publication-ordering correction: `SaveErr` additionally runs
> snapshot→marshal→AtomicWrite under a store-local `saveMu`, so an older
> in-flight `Save` can never resume and rename a stale envelope over a
> later acknowledged publication; commit-boundary correction: public
> `Save`/`SaveErr` enter `mutMu` and delegate to the internal
> `saveErrLocked`, so a standalone save can never observe or publish an
> in-flight `MutateDurable` transaction's memory (uncommitted content +
> old epoch) and a failed-and-rolled-back mutation exists on disk at no
> epoch, and the envelope loader enforces
> `schema_version == 1` fail-closed — `{}`, unknown/future schemas, and
> negative persisted versions refuse to load; served on list reads; the
> same structured 409 conflict contract as
> the policy fence), and name-collision
> refusals under the store lock (409, `ErrNameTaken`). Rename is an
> explicitly composed cross-store operation (object domain → running
> cascade → draft-candidate cascade, each persist error-aware; a cascade
> failure after the durable object rename is a truthful 500 naming the
> failed domain, never a false 2xx) with deterministic recovery:
> `reconcileObjectRefNames()` at boot re-derives stale denormalized names
> from the ID-authoritative object stores, converging every crash point —
> enforcement is ID-linked and provably unchanged throughout. The
> `objectReferences` walk now also covers an ACTIVE draft candidate (a
> staged reference blocks delete and appears in Where Used). Authority:
> `docs/design/OBJECT-REFERENCES-BY-ID.md` §13.
>
> **2D-A.1–2D-A.4 frontend** — `frontend/src/api/objects.ts` (fenced
> stable-ID clients; strict security-enum decoders with a per-profile
> DEGRADED state — unknown values never coerce to inherit/fail-open;
> tri-state `inspectHttp2` fidelity with inherit-by-omission
> serialization; reference-block 409 recognizer), enum lockstep pinned
> three ways (OpenAPI enum vocabularies → generated-union compile-time
> `satisfies`/exhaustiveness, and `objects_enum_lockstep_test.go` probing
> every frontend value through `decryptprofile.Validate` both directions;
> "permissive" tripwired). Surfaces: `/app/objects/category-groups`
> (membership from the authoritative URL-category name list, dangling
> members preserved and badged, rename truth callout, T1 ref-guarded
> delete) and `/app/objects/decryption-profiles` (security-precise copy:
> skip = "verification DISABLED", the pre-save fail-open
> adaptive-exclusion warning, distinct onUnsupported/onInspectError
> copy, degraded read-only rows). Shared `ObjectDeleteDialog`: Where Used
> preflight is information only; the server's structured 409 renders the
> REAL consumers with stable-ID deep links. Where Used route map extended
> for the routes that now exist (auth-rule → `?rule=` deep link with
> not-in-snapshot truth; category-group → `?id=`); Access Rules' explicit
> refresh now refetches the editor option lists (§20). Unknown-outcome
> latch, run-owner mutations, auth-boundary cleanup, dirty guard on both
> pages.
>
> **Draft interplay (derived from the implementation, §28)**: a rename
> cascading onto RUNNING rules advances the running generation, so an
> active draft truthfully reads base-stale and commit is fenced until
> review; a draft-only reference follows the rename (same object ID) and
> commits cleanly. Both shapes are proven at the Go layer and against the
> real binary (policy-2d.spec.ts).

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
