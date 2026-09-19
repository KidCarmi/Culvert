# Frontend Migration Plan

- **Status**: Accepted with ADR-FE-001 (2026-08-21, external architecture review corrections
  incorporated). **Implementation is underway**: FE-0 through FE-4 are IMPLEMENTED (see the
  phase table in §3, each carrying its own implementation record); FE-5 onward have not
  started. The new frontend stays disabled by default in shipped builds — see the FE-1B entry
  below and `CULVERT_EXPERIMENTAL_UI` — until FE-8 cutover.
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

### FE-1A — Frontend Build Foundation (no Go changes) — IMPLEMENTED (this branch)

> **Implemented contract (FE-1A round).** The `frontend/` scaffold (package.json,
> package-lock.json, `.node-version`, tsconfig/vite/eslint/prettier configs, committed
> `dist/`, `src/`) is in the tree at the pins recorded in ADR-FE-001. The frontend
> verification/drift lane is wired as `frontend-verify.yml`, invoked as the `frontend` gate
> job of `pr-fast-gate.yml` (path-classified on `frontend/*`, `ui_frontend_v2*`,
> `api/openapi/openapi.json`, and the two workflow files themselves). This entry is
> evidenced by the two files, not asserted from the phase objective below.
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
> | **2F** | Network: PAC (profiles/pools/lifecycle/simulator/analyze/posture/exceptions + server-named DIRECT-bypass T3 ceremony) + Upstream (write-only credentials, direct-fallback banner) | **2F-A … 2F-F shipped and frozen (2F-F at `77acdd67`); 2F-G closure this round — see the 2F-G record below** |
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
> **2F-G IMPLEMENTATION RECORD (this branch, 2026-09-08 — the closure
> slice of Batch 2F; not a feature-expansion slice).** Baseline: the frozen
> 2F-F head `77acdd67` (accepted by external review). **Entry gate:**
> `origin/main` re-fetched before any change = `1b3d0e6a`, already an
> ancestor — no entry merge. Append-only chain: `fe8bd067` (RED matrix on
> the exact baseline) → `92b51b06` (RED harness typecheck correction, verdicts
> unchanged) → `844c78f4` (product correction) → `938bfeaf` (dist) →
> `edae409e` (closure journeys + harness) → this record + the parity /
> contract / runbook corrections. No Go, OpenAPI, generated-type, route or
> inventory artifact changed (no authoritative source changed), so none was
> regenerated.
>
> **A. CDR recovery-marker correction (the defect recorded in the 2F-E
> correction record).** `readEnrollRecovery(subject)` compared an EMPTY
> subject as a foreign identity: a render before the authenticated subject
> was known read the marker with `""`, classified it foreign and DELETED it —
> a recoverable enrollment destroyed by a transient state. RED matrix
> `frontend/src/test/cdr-2fg-red.test.tsx`, executed on `77acdd67` before
> the correction (a deferred `/api/auth/status` answer is the
> channel-controlled "subject not yet known" window; no timing): G1
> unresolved read must neither classify nor delete — FAILED (marker gone);
> G2 marker survives the unresolved first render and surfaces once the owner
> is authoritative — FAILED; G3 control, a confirmed mismatch clears and
> never surfaces — passed; G4 nothing dispatched while unresolved, ceremony
> opens on resolution — FAILED (the ceremony was armed against an unknown
> identity); G5 a real logout through the auth machine clears the surfaced
> marker — FAILED on the baseline only because the marker was already gone
> (the clear itself is 2E-C behaviour); G6 control, the unresolved render
> triggers no recovery call and claims no outcome — passed. Correction
> (`enrollRecovery.ts` + `CDRInstancesTab.tsx`): an empty or blank subject
> is NOT an identity — the read reports `unresolved` BEFORE touching storage
> (nothing classified, nothing deleted); the tab keeps the enrollment
> ceremony closed (`canEnroll` requires `none`), shows neither the recovery
> surface nor a store error while unresolved, and re-reads when the subject
> becomes authoritative — a matching owner surfaces the marker, a confirmed
> mismatch discards it, logout / the auth boundary clear it exactly as
> before. The write path was already fail-closed (the grammar refuses an
> empty subject, so no dispatch without an identity); marker contents are
> unchanged (non-secret, ownership-bound). G1–G6 green; the accepted 2E-C
> recovery suites are untouched and green (63 files / 710 unit tests). The
> accepted CDR trust-lifecycle backend is not touched. **Reachability
> disclosure:** through the shipped `AuthGate` the authenticated shell
> renders only in the `authenticated` phase, whose identity decoder refuses
> an empty user, so the empty-subject render is prevented by ordering today;
> the component contract no longer depends on that ordering.
>
> **B. Final journey closure (`frontend/e2e/network-2fg.spec.ts`, nine
> journeys, real appliances, 9/9).** Inventory first: the accepted PAC
> (`pac-2fe*`), Upstream (`upstream-2ff*`, `upstream-2fd`) and CDR
> (`cdr-2ec`) specs already prove publish / refusal / recovery / reload
> continuity, viewer posture, create/edit, T2 replace, T3 clear, probe
> behaviour, UNPROVEN handling and the Upstream/CDR leak sweeps — none of
> those assertions is duplicated or changed. Added only what was missing:
> N1 sidebar navigation to both surfaces (`expectNavLinkReachable`), the
> routes served as the SPA document, unauthenticated deep links returning to
> the intended route after sign-in (admin for Upstream, the viewer floor for
> PAC); N2 admin-only made server-authoritative — an OPERATOR sees zero
> mutation controls on PAC and Upstream and issues no non-GET request, and
> nine operator and viewer mutation shapes (upstream create / update / delete
> / credential / manual probe; PAC profile create / publish / delete /
> exception governance) are refused 403 with the document revision, entry
> revision, credential state, profile collection etag and active revision
> unchanged; N3 YAML read-only posture on a FOURTH, config.yaml-seeded
> appliance (`YAMLUP`, `scripts/e2e-smoke.sh`; one parent under the
> `.invalid` TLD so its periodic probe fails deterministically and nothing is
> dialled — a separate instance because a config.yaml parent chains every
> allowed plain-HTTP request of the appliance carrying it, which would change
> the data-plane premise of every other journey): the row is labelled
> `config.yaml` / read-only with zero controls and "edit the YAML and
> reload", survives a reload, and PUT / DELETE / credential replace are
> refused `409 yaml_owned` with the entry unchanged; N4 CDR marker survival —
> a lost enrollment answer (aborted in the browser; the appliance never
> receives it and lists no such instance) leaves the non-secret,
> ownership-bound marker, which survives a FULL reload (the app boots with an
> unresolved subject until the status read lands) and SPA navigation,
> surfaces "Resolve enrollment" naming the operation for its owner, never
> carries the token in storage or the DOM, keeps the ceremony closed, and is
> cleared by Sign out with nothing but the theme key left; N5 PAC marker at
> the auth boundary — a publish that never left the browser latches the
> marker and disables Publish, Sign out clears it, a re-login finds no marker,
> Publish open and the lifecycle unmoved (`activeRevision`/`activeN` equal to
> the captured baseline); N6 a raw 500 body carrying a canary never reaches
> the DOM, URL or storage, the outcome stays unresolved (marker kept, Publish
> disabled), no "Published" claim, lifecycle unmoved; N7 node-local labels on
> the PAC lifecycle ("Publish history (node-local)"), the DIRECT exceptions
> tab ("Node-local governance records") and Upstream health after a manual
> probe ("Manual probe complete (node-local)", source `manual`) stay after
> `page.reload()` and after the in-page Refresh, and Upstream leaves nothing
> in browser storage. **Harness corrections found by the real-binary runs
> (recorded):** the two journeys that end in a real Sign out authenticate
> explicitly under an empty storage state — a sign-out revokes the server
> session behind the suite-wide admin storage state, which the first run
> exposed as three later journeys landing on the sign-in page; and the
> lifecycle comparison reads a captured baseline (`activeRevision` of a
> freshly created profile is 1, `activeN` 0) instead of assuming zero. No
> retry, timeout, skip or weakened assertion. **Restart disclosure:** the
> browser suite proves label and verdict continuity across reload and
> in-page Refresh; an appliance RESTART is not exercised from the browser
> (the harness starts each instance once) — restart continuity of the
> upstream document, credentials and probe state is proven by the Go
> integration / portability harnesses (54/54, 38/38) that run in the same
> qualification.
>
> **C. Parity and documentation closure.** `FRONTEND-FEATURE-PARITY.md`
> FE-V31 / FE-V32: the Role cells said `operator` — a documentation error
> against the backend truth (every PAC and Upstream mutation, including the
> manual probe, is `RoleAdmin` in `ui_routes_meta.go`); both rows now read
> "viewer (mutations admin-only)", carry the MIGRATED annotation every other
> Batch-2 row carries, list the v2 upstream entry routes and the PAC
> lifecycle / analyze / `/pac/` routes, and state the current T3 form (the
> server-bound `<profileId>:<candidateSpecDigest[0:8]>` challenge; the
> pre-2F "word = profile id" is no longer accepted); the stale "§7 accounting
> table" pointer (also in `FRONTEND-CURRENT-STATE.md`) now names the real pin
> (243 routes, `ui_routes_meta_test.go`) and the generated inventory
> (`api/route-classification.yaml`). `FRONTEND-SECURITY-CONTRACT.md`: D1's
> Tier-3 count corrected (10 since 2F-C) and a D15 row records the 2F
> enforcement posture (fenced, admin-only, UNPROVEN discipline, node-local
> key, non-secret ownership-bound markers never classified against an
> unresolved subject). Node-local labelling verified consistent: the UI
> labels the PAC draft / history / exception governance and the Upstream
> entries / credentials / probe verdicts / effective mode node-local with one
> meaning (this appliance only, never cluster-synced, never on
> config-version rollback); `docs/operator/pac-traffic-steering.md` gains the
> `/app/network/pac` paragraph it lacked (admin-only mutations, the same
> node-local meaning, backup-surface note, pools and the ACTIVE spec as the
> cluster-synced part) and `docs/operator/upstream-proxies.md` §4 gains the
> node-local statement the UI already made (entries, credentials, health,
> effective mode; manual probe `(node-local)` / `scope=node-local`; labels
> and verdicts re-read from the appliance, never from browser storage). The
> repository contract pointer (`CLAUDE.md`, frontend line) records the
> unresolved-subject rule, the admin-only parity correction and the closure
> spec + fourth appliance. UI strings unchanged (three parallel node-local
> phrasings share the same meaning; the PAC page subtitle scopes "node-local"
> to the lifecycle while the Legacy PAC tab correctly carries no node-local
> claim — recorded, not reworded, to keep the accepted `/node-local/i`
> assertions stable).
>
> **Scope exclusions honoured:** no PX-1 chaining expansion, no YAML
> adoption, no breaker / probe-interval UI, no secret-inclusive backups, no
> scheme-grammar change, no CDR backend change, and neither the inherited
> 50-finding PR-base lint inventory nor the inherited main-side `funlen`
> finding (both stay with the dedicated pre-PR hygiene gate). Qualification
> of the candidate head is reported in the 2F-G candidate report.
>
> **2F-F CORRECTION RECORD (this branch, 2026-09-07; external review of
> `d391b12f` REJECTED — one append-only round).** The rejected candidate
> is untouched; the round is `4f28a221` (RED) → `71329312` / `97686d39`
> (correction) → `89eb49b4` (fixture completions) → `492c914d` (dist).
> **Blocker 1 — an untrusted 2xx was reported as a failure.** After
> `aff12f91` removed the Content-Type trigger, the FRONTEND invariant was
> still missing: `apiRequest` throws `contenttype`/`decode` with a 2xx
> status, `unknownOutcome` recognised only transport deaths, and the page
> rendered "Action failed" while the mutation was durably committed and
> every control stayed live. **Blocker 2 — success was not bound to the
> action.** Every mutation shared `decodeUpstreamConfig`, where `ok`,
> `entry`, `summary` were optional and `deleted` was ignored, so a
> schema-valid generic view was accepted as proof of any mutation and the
> success notice was written from request-side values. **Adjacent —
> refusal boundary.** `asUpstreamRefusal` accepted a known code under any
> status with an arbitrary `current`; the fence callout stringified the
> record; the server's `error` line and selected `current` strings were
> rendered verbatim.
> **RED (`4f28a221`, executed on `d391b12f`: 62 failed / 7 positive
> controls; both K journeys red).** `upstream-2ff-c-red.test.ts` B1–B7
> (action binding through the existing wrappers), R1–R4 (status/code
> binding, malformed fence, required facts, userinfo-password dropped);
> `upstream-2ff-c-red-unproven.test.ts` U1–U3 (classifier);
> `upstream-2ff-c-red-page.test.tsx` Q1 (5 actions × wrong media type /
> malformed JSON / generic view), Q2 (probe), Q3a–d (secret-bearing refusal,
> 400 echoing the T2 password, malformed 2xx carrying it, failed GET body),
> Q4 (malformed fence never stringified, never a verdict), Q5 (status/code
> mismatch); `e2e/upstream-2ff-c.spec.ts` K1–K4 — the REAL appliance's
> answers corrupted in flight by a Playwright route (the mutation lands
> durably): media type stripped, generic view, password-bearing refusals,
> status/code mismatch.
> **Correction.** `src/api/upstream.ts`: `REFUSAL_CONTRACT` binds every
> code to its contracted HTTP status and REQUIRED safe facts (numeric
> `revision` for the fences; safe id for `vanished`/`yaml_owned`/the
> credential codes; enum `credentialState`; numeric `retryAfterSeconds`;
> `confirmValue == id`); the renderable part is the typed, allowlisted
> `facts` (an authority carrying a userinfo password is dropped; `current`
> and `error` are kept for tests and never rendered); `unprovenOutcome`
> classifies transport deaths, every unverifiable 2xx and every
> unrecognised non-2xx as UNPROVEN (only a recognised refusal, 401 and 403
> are verdicts); every wrapper binds the 2xx to its action — create: a
> MANAGED `entry` with the submitted `canonicalAuthority` (scheme/host
> lower-cased, trailing dot stripped, IDNA via the URL parser, default
> port) present in the returned list; update: the requested id with the
> submitted authority; replace/clear: the exact id as
> `configured`/`none` in DTO and row; delete: `deleted` equals the id and
> the list no longer carries it; probe: `ok: true` + `summary`. Page: the
> classifier renders a verdict only from a well-formed refusal or a 403;
> everything else closes the ceremony (the password is released with the
> dialog), latches UNKNOWN, blocks every mutation and the probe, re-reads
> the authoritative model exactly once (a TRANSPORT death instead REQUIRES
> the operator's Refresh — the directive's "perform or require"; the
> network is not known to be back, and the accepted P10 assertion pins
> that the latch holds), never retries, and clears the latch only after a
> genuinely successful read-back (`useObjectPage`); the fence callout
> renders the numeric revision, the refusal callout the code + status +
> typed facts, the read-error state a bounded class + status — no server
> body or line reaches the DOM anywhere on the surface.
> **Fixture completions / harness corrections (`89eb49b4`, recorded, no
> accepted assertion changed):** the A4 request-shape stub and the page
> tests' default mutation answer served a generic view — they now serve
> each action's own evidence (the appliance's shapes); in the new RED page
> file the success-notice words matched the snapshot bar's "Updated
> HH:MM:SS" freshness stamp (not a verdict) and Q3c did not hold the
> read-back down — corrected, assertions unchanged; the K journeys hold the
> read-back down (GET → 500 by a route) while the latched state is
> asserted, then release and Refresh, because the latch→resolved
> transition against the real appliance is otherwise a race.
> **Requalification finding (harness environment, recorded):** both full
> Playwright runs on the corrected head failed exactly one unrelated
> journey — `policy-2a` "real Traffic ruleId deep-links to the exact
> highlighted Access Rule" — with the Traffic page reporting an EMPTY
> retained history. Root cause (reproduced on the real binary, not a
> flake): the appliance measures disk usage from statfs `Bavail`, and the
> qualification host's session disk allowance read 99.02 % used (2.6 GB
> available of 270 GB) — at the harness's `criticalDiskPct: 99` ceiling,
> which is the product's maximum configurable threshold. At the retention
> janitor's first 60 s tick `handleDiskCritical` deleted the appliance's
> own retained history (`LogGuard: cleanup (critical disk usage (overrides
> retention)) removed N entries`) and engaged emergency minimal mode —
> correct product behaviour that destroyed the seeded newest-history
> premise minutes into the run, after the early Traffic journeys had
> already read it. Remedy: freed the runner (stale build cache), and the
> harness now PREFLIGHTS the appliance's own guard reading from
> `GET /api/logs/retention` and refuses to start within one point of the
> threshold, naming the cause, instead of letting the premise decay
> mid-suite. No product, test-assertion, timeout or skip change.
> **Scope:** frontend only (no Go, no OpenAPI, no route change); 2F-G,
> PX-1, CDR untouched.
>
> **2F-F IMPLEMENTATION RECORD (this branch, 2026-09-07).** Upstream React
> at `/app/network/upstream` under the approved C1–C12 contract (C4, C6, C7,
> C9, C11, C12), append-only on the FROZEN 2F-E baseline `ba2d852b`.
> **Entry gate.** `origin/main` unchanged at `290e3768` (already integrated
> by the 2F-E entry-gate merge); head = remote = `ba2d852b`, tree clean.
> **RED-before.** `61a4cc34` commits the matrix on the frozen baseline and
> the baseline evidence was executed there: `src/test/upstream-2ff-red.test.ts`
> (A1–A7: read-model decoder with enum rejection, fence + bounded-refusal
> classification from structured bodies, request shapes — document vs
> entry revision, DELETE token in the query only, T2 password in the body
> only, T3 confirm without a password key, bodiless probe, never
> `credentialState` — fail-closed decoder on credential material, probe
> summary, enum-derived mode/credential/coverage facts),
> `src/test/upstream-2ff-red-page.test.tsx` (P1–P10: viewer posture, YAML
> read-only rows, stale/precondition rendering without auto-retry,
> `credential_bound` / `credential_present` as server facts, T2 password
> hygiene across DOM/URL/storage, T3 typed entry id, probe rate-limit
> rendering, `no_eligible_parent` + `requiresReplacement` banner vs the
> `direct_fallback` bypass wording, `document_rejected`, unknown-outcome
> latch) and `e2e/upstream-2ff.spec.ts` (J1–J5 real-binary journeys) — all
> red on the baseline (both vitest files fail at import resolution; the five
> journeys fail on the missing route, auth-setup alone passes).
> **Surface.** `src/api/upstream.ts`: the credential-free v2 read model
> through total decoders (`entries` nullable on the wire), a FAIL-CLOSED
> guard that refuses an entry carrying `password` / `credential` /
> `ciphertext` or a userinfo password in `url`/`authority` (a misbehaving
> server can never put a secret into the DOM), `asUpstreamRefusal` /
> `asUpstreamFence` over the bounded 2F-C/2F-D code set (unknown codes,
> text bodies and transport deaths are never classified), and request
> wrappers with the exact wire shapes. `features/network/upstream/`:
> `upstreamFacts.ts` (facts derived from the server enums only — both
> `no_eligible_parent` and `direct_fallback` are critical, only
> `direct_fallback` says traffic is bypassing (C11); coverage is always
> plain-HTTP-only and no copy says "protected" or "fully chained" (C7);
> `requiresReplacement` is a distinct ineligible state (C12)),
> `UpstreamPage.tsx` (effective mode with `since`, eligible/entries,
> direct-fallback count, coverage line, periodic-probe cadence, key state,
> migration state, scope node-local; the critical banners — mode,
> `credentialsRequiringReplacement`, unusable/mismatch, rejected stored
> document, refused YAML seed, degraded migration, missing/unreadable key;
> the entries table with `data-entry-id` / `data-source` /
> `data-credential-state` rows; managed rows carry the admin controls,
> YAML rows are read-only), `upstreamEditors.tsx` (create/edit Tier 2 fenced
> on the document / entry revision, delete Tier 2 with the token in the
> query, replace credential Tier 2 — `type=password`, sent once in the body,
> released with the dialog — clear credential Tier 3 built on the raw
> `Dialog` so the typed input is labelled "Type the entry id (…) to confirm"
> and the exact id is echoed verbatim under `confirm`), `upstreamShared.tsx`
> (the fence callout and the bounded-refusal callout rendering `code` + the
> server line + the facts under `current` — authority, credential state,
> duplicate count, `retryAfterSeconds`, degraded reason). Manual probe is
> admin-only, bodiless, and renders the counts-only `summary`; a 429
> `probe_in_flight` / `probe_rate_limited` renders `retryAfterSeconds` and
> is never retried. A transport death latches the page UNKNOWN (2A-M
> doctrine) until a fresh successful refresh; the page persists NOTHING (no
> storage, no recovery marker — an upstream mutation is refetch-idempotent
> and the read model is the only truth, unlike the PAC lifecycle's
> client-minted operation identity). RBAC C7: every mutation control is
> admin-only; the viewer mounts zero write controls. Route `/network/upstream`
> registered in the router, the Network nav section and the route-intent
> table (viewer floor, matching `GET /api/upstream`).
> **Server-fact rendering decisions (recorded, not compensations):** a
> `requiresReplacement` entry keeps its Delete control because the appliance
> permits the delete (only sealed material refuses `credential_present`);
> Clear credential is offered whenever `credentialState ≠ none`
> (`requiresReplacement` is T3-clearable by contract); an entry whose
> credential is `unusable`/`mismatch` still offers Replace (T2 resolves it).
> **Contract defect found ONLY against the real binary (backend correction,
> explicitly identified).** J2/J3/J5 failed on the first real-binary run:
> every successful `upstreamMutate` answer (create 201, update / delete /
> credential 200) reached the browser WITHOUT `Content-Type:
> application/json` — the handler wrote the status before `jsonWrite` set
> the type, so the header snapshot went out untyped and the server's
> sniffer labelled the JSON body `text/plain`; the v2 client's boundary
> refuses any non-JSON media type by construction, while the legacy panel
> never checked it (which is why 2F-C/2F-D did not observe it). RED
> `63135d7d` (`upstream_mutation_content_type_red_test.go`, asserting the
> WriteHeader-time header snapshot via `rec.Result()`, the refusal path as a
> passing control; 5/5 answers untyped on `49f4182e`); correction
> `aff12f91` sets the type before the status in `upstreamMutate` — no
> schema, route or body change (the OpenAPI already declared
> `application/json`). Second real-binary run: 7/7 (five 2F-F journeys +
> the 2F-D legacy leak sweep + auth-setup).
> **Transparent correction of the RED files (`3d85b832`, recorded):** the
> repository lint bans `as` assertions in authored source, so three
> `Object.keys(x as object)` key-list reads became `isRecord(x) ?
> Object.keys(x) : []` and Prettier formatting was applied; every assertion,
> fixture and expected value is byte-for-byte the same and `61a4cc34`
> remains the baseline evidence.
> **Harness note (J4, disclosed):** the manual-probe journey primes an
> ACCEPTED run through the API (polling the appliance's own 10 s window —
> a refused run does not re-arm it), proves the page's probe inside that
> window is refused 429 and never retried, then waits exactly the
> SERVER-DECLARED `Retry-After` before the accepted run — the protocol's own
> instruction, not a guessed sleep.
> **Scope exclusions honoured:** no 2F-G, no PX-1 data-plane chaining, no
> YAML adopt transaction, no breaker/probe-interval GUI settings, no
> secret-inclusive backups, no parity-doc correction (2F-G), no OpenAPI or
> route-metadata change (route count unchanged at 243), no CDR work.
>
> **2F-E CORRECTION RECORD, ROUND 8 (this branch, 2026-09-06).** External
> freeze review of the round-7 candidate (`bde20ba1`) accepted the ancestry
> and qualification and found one source-level contract break; it was
> red-before on the untouched candidate (`109371c6`:
> `pac_lifecycle_candidate_only_red_test.go` V1/V2a/V2b/V2c/V3 failing) and
> corrected append-only (`82b39900`). **Candidate-only profile ids bypassed
> the pre-write settlement.** `pacChangedProfileIDs` built a map of the
> candidate profiles but iterated over the BEFORE profiles only, so an id
> absent from the active store and present in the candidate — an ADDITION —
> was never settled. An absent profile can still carry a durable pending
> first-publish lifecycle intent (the publish died after `intent_persisted`),
> so the POST create (whose `PrepareCreate` keeps that intent), a
> merge/replace config import, a config-version rollback and a CP→DP
> snapshot all installed the profile while the earlier intent stayed
> unsettled (V1 on the candidate: 200, profile installed, success audit,
> config version and cluster publication; V2: the PAC slice applied), and
> the later reconciliation read AMBIGUOUS from the replaced content (V3).
> Corrected contract: **the settled set is the deterministic union of every
> profile whose PRESENCE or CONTENT differs between before and candidate** —
> removed, content-changed and candidate-only added, sorted; untouched
> profiles stay excluded and pools are never listed. The settlement, its
> refusal (CRUD `503 lifecycle_unsettled`) and its deferral surfaces (import
> `pac_profiles_not_applied`, rollback error, snapshot next sync) are
> unchanged. For the POST create the settlement runs after `PrepareCreate`
> inside `pacApplyProfilesMutation`, and the transition stays recoverable on
> every failure boundary as proven in round 4 (G2/G3): a refusal withdraws
> the preparation, and a withdrawal that cannot persist is finished at the
> next access/boot — V1 exercises exactly that boundary (lifecycle
> persistence failing after `create_prepared`): the create is refused
> fail-closed with no active mutation, no success audit, no config version
> and no cluster publication, the earlier intent stays durably recoverable,
> and once persistence recovers the create succeeds with the earlier intent
> settled exactly once as aborted (it never wrote) across a repeated GET and
> restart. V2a/V2b/V2c pin the deferral on the three bulk paths with the
> target absent and the intent recoverable (the snapshot applies at the next
> sync, settling it once); V3 pins the controls (a genuinely new id with no
> pending intent stays creatable; untouched-profile and pool-only writes stay
> unblocked while the history cannot be written). X1, Y1/Y2, Z1–Z3 and W3/W4
> stay green. OpenAPI documents the 503 on the profile POST and the addition
> case on the import field (bundle + types regenerated).
>
> **2F-E CORRECTION RECORD, ROUND 7 (this branch, 2026-09-05).** External
> freeze review of the round-6 candidate (`b1495ea8`) accepted X1/Y1/Y2 (a
> commit's provenance survives unrelated-profile and pool-only writes) and
> found the remaining target-profile case; it was red-before on the untouched
> candidate (`352ef3cb`: `pac_lifecycle_target_provenance_red_test.go`
> Z1/Z2/Z3 failing — channel/fault controlled through the production
> handlers, restart from the durable files) and corrected append-only
> (`d7fafd0a`). **Per-profile provenance is still last-writer provenance.**
> Publish X persisted its intent, committed for real (target stamped X), and
> its committed lifecycle write failed (the truthful `published: true` /
> `pending_reconciliation` answer, the durable record still pending). A later
> legitimate write of the SAME target replaced X's identity: with the target
> on the later content, `ClassifyOutcome` was ambiguous and X was settled as
> AMBIGUOUS (Z1); a replace-import (Z2) or config rollback (Z3) returning the
> target to X's exact revision/spec under another identity settled X as
> `concurrent_write`. Either way the historical fact already proven to the
> client — X performed the authoritative commit — was lost, with X's history
> revision, success audit and operation-keyed config version never
> completed. Corrected contract: **an unresolved lifecycle intent is settled
> durably BEFORE anyone changes its profile — historical authorship is never
> inferred from current content or the current profile's last writer.**
> `pacSettlePendingBeforeWrite` (`pac_profiles_api.go`) runs in every writer
> of the active profile store, under `pacProfilesAPIMu`, immediately before
> its own write: for every profile whose content the writer CHANGES or
> removes (`pac.ProfileContentEqual`, the store's own change test), a pending
> lifecycle intent is reconciled in node-local mode — a genuine commit becomes
> a durable COMMITTED record with its history revision, an intent that never
> wrote becomes a durable aborted / refused / ambiguous decision — and the
> durable truth is re-read: an intent still pending and not committed was not
> settled, and the writer is REFUSED or DEFERRED with nothing written (CRUD
> `503 lifecycle_unsettled`; config import applies the rest and reports
> `pac_profiles_not_applied`; config-version rollback skips the PAC slice and
> returns the error through the persist-error surface, the boundary mutex
> released before the SaaS slice; the CP→DP snapshot defers the slice to the
> next sync). Untouched profiles and pools are never settled, so an unrelated
> write is never blocked; config version, cluster publication and the success
> audit complete at the next full reconciliation from the durable markers (no
> config-version capture or cluster publish inside another writer's
> transaction; lock order unchanged). Z1/Z2/Z3 now reconcile X as COMMITTED
> exactly once across a restart, a repeated GET and a second restart (Z1 with
> the later target authoritative and X committed-but-not-currently-active —
> `storeRevision` 2 / its spec digest against a different active identity);
> W3/W4 (`pac_lifecycle_settle_before_write_test.go`) pin the refusal and the
> deferral while the history cannot be written (nothing changed, X's
> provenance intact, unrelated write unblocked) and the same write succeeding
> once it can, with X still committed exactly once. X1 stays the
> false-attribution control, Y1/Y2 the unrelated-write controls. OpenAPI
> documents the 503 on the profile PUT/DELETE and the import field (bundle +
> types regenerated). The shared writer boundary, generation CAS,
> terminal-only-when-durable refusal, create/delete transitions,
> history-incarnation fencing, marker semantics and every accepted RED
> assertion are untouched.
>
> **2F-E CORRECTION RECORD, ROUND 6 (this branch, 2026-09-05).** External
> freeze review of the round-5 candidate (`51ee2549`) accepted the X1
> correction (a refused compare-and-swap is never attributed as committed
> from identical content; the terminal refusal is withheld until durable) and
> found the INVERSE attribution failure; it was red-before on the untouched
> candidate (`18c3c8eb`: `pac_lifecycle_commit_provenance_red_test.go` Y1 + Y2
> failing — channel/fault controlled through the production admin handlers,
> restart from the durable files) and corrected append-only (`5c1bfb06`).
> **Round 5's writer identity belonged to the whole profiles document.**
> Publish X persisted its intent, committed for real (`active_committed`,
> `lastWriteId = X`), and its committed lifecycle write failed — the truthful
> `published: true` / `historyState: pending_reconciliation` answer, with the
> durable lifecycle record still carrying the pre-commit pending intent. A
> legitimate later write of an UNRELATED profile (Y1) or of a POOL only (Y2)
> preserved X's active profile byte-for-byte but replaced the document-level
> identity with a random one, so the restart reconciliation saw "target
> content present, written by someone else" and recorded the proven commit as
> `aborted` / `concurrent_write` (status 409) — contradicting the response and
> losing X's history revision, success audit and operation-keyed config
> version. Corrected contract: **commit provenance is PER PROFILE and is
> co-written atomically with the authoritative content.** The profiles file
> carries `profileWriteIds` (profile id → identity of the writer that last
> CHANGED that profile; `internal/pac/profiles.go` `nextProvenance`): the
> lifecycle commit (`CommitIfGeneration`, now naming its target profile)
> stamps its operationId on its target; any writer stamps a fresh random
> identity on each profile whose content it changed (canonical-JSON
> comparison) and PRESERVES the provenance of every profile it left untouched
> — a pool-only or unrelated-profile write never erases a commit's provenance;
> a removed profile drops its entry; an older file, or a profile without an
> entry, is unknown and an identity is never invented for content nobody
> changed. `pacClassifyReconcile` attributes a content-level "committed"
> verdict by the TARGET PROFILE's provenance (`ProfileWriteID`); the round-5
> verdicts are unchanged (another writer's identical content ⇒ the durable
> `concurrent_write` refusal, unknown ⇒ ambiguous, never guessed), and the
> round-5 document-level `lastWriteId` key is retired (a file carrying only it
> loads as unknown provenance). Y1/Y2 now reconcile X as COMMITTED exactly
> once across restarts (one history revision, one success audit, one
> operation-keyed config version, operation found as a commit, `recorded`)
> with the unrelated mutation intact; X1 stays green as the opposite control;
> the store rule is pinned by `internal/pac/profiles_provenance_test.go`. No
> wire change (no OpenAPI/types regeneration); the shared writer mutex,
> generation CAS, terminal-only-when-durable refusal, create/delete
> transitions, history-incarnation fencing, marker semantics and every
> accepted RED assertion are untouched.
>
> **2F-E CORRECTION RECORD, ROUND 5 (this branch, 2026-09-05).** External
> freeze review of the round-4 candidate (`3f9877fe`) accepted the writer
> transaction boundary and the recoverable create transition and found one
> final durability blocker; it was red-before on the untouched candidate
> (`3b25315d`: `pac_lifecycle_cas_durability_red_test.go` X1 failing — a
> deterministic, channel-controlled fault-injection + restart proof through
> the production handlers) and corrected append-only (`75537b24`). **A
> compare-and-swap refusal was answered as a terminal decision even when its
> decision record had not been persisted.** `pacWriteConflict` cleared the
> pending intent, appended the aborted decision, only LOGGED a failed
> `pacLifecycle.Put` and still answered `409 concurrent_write` — so the
> durable file kept the pending intent while the browser cleared its marker,
> and the next reconciliation (`pacReconcileLocked` on the next access or a
> restart) classified that intent from the active revision + candidate digest
> ALONE. An intervening out-of-boundary writer that installed the candidate's
> exact target revision/spec plus an unrelated change therefore made the
> operation "committed": a history revision, a success audit and a config
> version were minted for an operation that never performed the active write
> (X1 on the candidate: committed attribution at the very first GET). Three
> coupled corrections, nothing weakened. **(1) Durable writer identity.** The
> profiles file carries `lastWriteId` beside the config
> (`internal/pac/profiles.go`): every `Set`/`SetIfGeneration` stamps a fresh
> random id, and the lifecycle commit stamps its operationId through the new
> `CommitIfGeneration` — the same store-generation compare-and-swap under the
> same `pacProfilesAPIMu`, plus the identity. An older file loads with an
> unknown identity; an older binary ignores the key. **(2) Attribution by
> identity, never by content.** `pacClassifyReconcile` turns the content
> verdict of `pac.ClassifyOutcome` into COMMITTED only when the store's writer
> identity is the intent's operationId; identical target content installed
> by another writer is settled as the durable `concurrent_write` refusal (a
> new `conflict` verdict in `pacReconcileLocked`: pending cleared, aborted
> decision recorded, no history/audit/config-version, the intervening
> configuration intact); an unknown identity is AMBIGUOUS — refused until an
> admin repair — never a guessed commit. **(3) Terminal only when durable.**
> The `409 concurrent_write` decision is answered only after its record
> persisted; a failed persist answers the NON-TERMINAL `500 outcome_unknown`
> with `detail: refusal_not_durable` and `state: pending`, which is exactly
> the outcome shape the accepted frontend already keeps its marker for
> (`failureKeepsMarker`: `server_outcome` + `outcome_unknown`) — no frontend
> change; the pending intent stays the durable truth across the restart with
> persistence still failing, and once persistence recovers the reconciliation
> records the same refusal durably (`historyState: recorded`, operation
> `aborted`) and a repeat of the operationId replays `409 concurrent_write`.
> The CAS, the shared writer mutex, the create transition, the epoch fencing,
> the ceremony context and every accepted RED assertion are untouched (the X1
> "never attributed as committed" closure was extracted verbatim into a
> top-level helper for the gocognit gate, assertions unchanged, original
> commit preserved). OpenAPI documents the `refusal_not_durable` detail on the
> lifecycle POST 500 (bundle + types regenerated).
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

#### Batch 2 PR correction round (PR #1340, append-only on the PR branch)

The frozen Batch 2F head (`8e73a619`) was opened as a draft PR and the real
CI matrix plus the repository's automated reviewer found what a root-run,
single-order qualification could not. Every product correction below was
preceded by a RED proof executed on the tree immediately before it; the
frozen program branch is untouched.

> **PR-C1 — the browser smoke depended on a writable `/data`.** The
> appliance's persisted-state root was the fixed absolute `/data`; a CI
> runner's unprivileged user cannot read or create it, so every
> `/data`-backed mutation (admin settings, object stores, PAC profiles, CDR
> state, drafts) answered `persist_failed`/503 while file-path-backed
> stores kept working — 45 failed / 102 passed / 3 skipped, reproduced
> verbatim on the PR head inside a private mount namespace with an empty
> read-only tmpfs over `/data` (the exact CI premise: ENOENT on read, EROFS
> on write). Correction: `CULVERT_DATA_DIR` (`data_dir.go`), a
> startup-scoped, env-only override resolved once in `main()` before flag
> parsing and any one-shot command (blank ⇒ `/data`, byte-identical;
> otherwise an absolute, cleaned, non-root path, else FATAL; recorded
> GUI-parity deferral of the HA-lease-endpoint class); the harness gives
> every appliance instance its own root under the harness tmp dir, which
> also retires the recorded "shared `/data` across instances and runs"
> debt, and exports the AUTH root so the on-disk ciphertext needle checks
> run everywhere instead of annotating a skip. **Qualification rule going
> forward: the smoke is run at least once with `/data` unwritable** (the
> `unshare -m` + read-only tmpfs shape) so a root-only premise can never
> pass again.
>
> **PR-C1b — five roots ignored the override.** The read-only-`/data`
> re-run after PR-C1 still failed the PAC lifecycle journeys (409
> `operation_pending`, `progress.configVersion=false`): the config-version
> store, registry settings, the CDR enrollment certs root, the CDR runtime
> marker and the alert retry queue were package-level literals spelled as
> `/data/...`, bound at init time before any env was consulted. Correction:
> `rebindDataDirPaths()` re-derives every one of them from the effective
> root after the override resolves, the CDR startup resolver takes the data
> root as a parameter (pure, no global read), and the committed RED
> (`data_dir_paths_red_test.go`) asserts each rebound root so a new literal
> cannot land unnoticed. The PAC, network and CDR journeys pass under the
> read-only-`/data` shape after this.
>
> **PR-C1c — the Go race gate had the same dependence.** The frozen head's
> `Gate · go test -race + coverage floors` run failed four
> `TestAPIPACLifecycle_*` journeys with `409 operation_pending`: their
> environment helper isolated every PAC store but left the config-version
> store on the process default `/data/config_versions`, which the CI
> runner's unprivileged user cannot create, so the first publish's version
> capture failed and the next publish was refused. A root-run qualification
> never saw it. Correction: `resetPACPublishGlobals` swaps the
> config-version store to the test's temp dir (the shape `pacFenceEnv`
> already used), pinned by `pac_publish_env_red_test.go` (the store must
> never sit under the process data root and must be writable), and the
> root suite is now also qualified under `-race` with `/data` unwritable.
>
> **PR-C3b — advisory reviewdog findings on the corrected head.** The
> `Code Review` workflow's inline golangci pass (advisory, `diff_context`
> filter — it reports a finding whose line sits near a changed line, where
> the blocking Fast-Gate run reports only findings ON changed lines) posted
> nine findings on the corrected head: cyclomatic complexity 20 on
> `apiCDRRevokeRPC`, cognitive complexity 33 on `apiFileblockProfiles` and
> 35 on `diffRewriteRules`, nested-block complexity 20 on the category-group
> stable-ID PUT branch and 5 on the no-persistence branch of
> `saveAdminSettingsWithOverrides`, a shadowed `copy` builtin in the CDR
> store, and three gosec G101 hits on fixture URLs in tests. Correction:
> pure helper extraction with no behaviour change — the handler role gates
> stay in the method switch so the C1.5 AST parity keeps seeing them
> (`apiCategoryGroupUpdateByID` + `cascadeCategoryGroupRenameDurable`,
> `apiFileblockProfileUpdate` + `apiFileblockProfileDelete`,
> `cdrRevokeTargets` / `cdrRevokeGenerations` / `cdrPruneRevokedInstance`,
> `rewriteRuleStableIDs` / `diffRewriteRulesLegacy` / `rewriteRulesReordered`,
> `applyAdminSettingsOverridesUnpersisted`), the rename, and reasoned
> `//nolint:gosec` on the three test fixtures (the repository's lint
> suppression convention). No accepted RED assertion changed. The pass
> widened the review context and surfaced three more of the same class on
> the next head (cognitive complexity 58 on `apiRewrite`, which this
> program grew from 48 to 145 lines, and two more fixture-URL G101 hits):
> the POST/DELETE branches are `apiRewriteAdd` / `apiRewriteRemove` with
> the removal selector `rewriteRulesWithout`, and the fixtures carry the
> same reasoned suppression.
>
> **PR-C2 — determinism gate.** Under `-shuffle -count=2` the
> process-global "stored document rejected at load" latch armed by the R3
> rejected-document test outlived its environment and handed a 409
> `document_rejected` to the next upstream test. `upEnv` now resets the
> latch and the degradation surface with the rest of the upstream process
> state (`upstream_v2_env_isolation_red_test.go`).
>
> **PR-C7 — two more order dependencies under the same seed.** With the
> PR-C2 latch cleared, `-shuffle=1788866999688368609 -count=2` reached the
> next two: `TestLoadAdminSettings_CorruptFileQuarantinedNotOverwritten`
> asserts the settings file is absent after the corrupt copy is quarantined,
> but `LoadAdminSettings` finalizes the YAML-seeded rewrite identities on
> every load path and deliberately writes a fresh minimal ledger there
> whenever a predecessor left rules in the global rewriter
> (`TestAPIRewrite_Add` added one through the API and never restored it);
> `TestAPIPolicyReorder_Post_Success` sends a two-rule list, which the 2E-C
> reorder contract refuses with `409` whenever a predecessor left another
> access rule in the global policy store. Both were rebuilt deterministically
> in-process (`test_order_isolation_red_test.go`: seed the leaked state, run
> the victim unchanged), and the corrections are isolation only — the
> quarantine tests own an EMPTY rewriter (`isolateRewriterForTest`, a
> snapshot/restore), the reorder test owns its policy store
> (`withFreshPolicyStore`), and the leaking rewrite test restores the
> rewriter it mutated. No product code changed and no accepted assertion
> changed.
>
> **PR-C7b — the same seed, one more.** With PR-C7's two isolated, the
> seeded run reached `TestLegacyLDAP_RetirementSentinelDurableRoundTrip`
> ("sentinel did not survive the admin_settings.json round trip"). Two
> process-global leaks meet there: a predecessor's best-effort
> admin-settings save (`adminSettingsSave` spawns a goroutine on every
> admin mutation) was still in flight when the test pinned and rewrote its
> fixture with the flag already reset, so the stale save landed on the
> fixture and the load read `legacy_ldap_retired:false`; and the same load
> logged `duplicate_authority`, because `upEnv` cleared the R3
> rejected-document latch at ENTRY only (PR-C2), which protects the next
> upstream test and nobody else — a non-upstream successor's save carried
> the rejected sections forward verbatim. Both are pinned in
> `test_order_isolation_red_test.go` (a held-open pending save that the
> fixture helper must wait out; R3 as a subtest whose cleanup must clear
> the latch and the degradation surface), and the corrections are isolation
> only: the LDAP fixture helper drains `adminSettingsSaveWG` before it hands
> the path to the test and the victim drains again before the rewrite (the
> drain the upstream suites already use), and `upEnv` resets the latch and
> state at cleanup as well as at entry. No product code changed and no
> accepted assertion changed.
>
> **PR-C8 — the root package's `-race` run overran the CI per-binary
> budget.** `Gate · go test -race + coverage floors` on the PR-C7 head
> ended in `panic: test timed out after 25m0s` (FAIL at 1502.7s, one test
> 1s into its run — a budget overrun, not a hang); the run before it had
> cleared the same budget by well under a minute. Measured per test
> (`-race -json`, same box, both runs under the same background load):
> `origin/main` alone is 1445s against the 1500s budget — 3.7% of
> headroom, and the QA gate's main-push run of that suite already takes
> 24m35s end to end — and this PR adds 58s of new root tests (445, the
> RED matrices and harnesses of the program) plus ~20s on the OpenAPI
> conformance slices for the larger contract, 1553s in total. This is
> CI-01 (`docs/engineering/security-reviews/2026-08-25-mcp-overnight-hardening-run.md`)
> two weeks on: the budget that was raised from 15m to 25m has been
> consumed by `main` itself, and removing every test this PR adds would
> leave a coin flip. The correction is the same decision with today's
> numbers — the per-binary budget in `pr-fast-gate.yml` and `qa-gate.yml`
> (which must move together) goes to 40m with the measurements recorded
> beside the step; no test was shortened, skipped or weakened, and the
> durable fix the record already names (split the root package) is
> unchanged and remains an owner decision. Two related observations are
> recorded, not changed: `security-release-gate.yml` still runs the same
> suite under `-timeout=15m` on tags and the weekly cron, which `main`
> exceeds today; and the root copy of `TestMatchDPIRegexWithTimeout_TimeoutReturnsTrue`
> (`scanner_test.go`) keeps the racy 1 ns-timer shape the
> `internal/scanner` test replaced with a blocking-fn seam, and failed
> once here under three concurrent test runs (it has passed in every CI
> run; it is not this PR's).
>
> **PR-C3b, round 3 — the three reviewdog threads still open.** The
> advisory pass on the frozen head had also posted `cyclop` findings on
> three functions this program grew — `applyAdminServices` (18),
> `propagateServerRotation` (16), `apiAuthPolicyReorder` (17) — which the
> diff-scoped gate never sees (their declaration lines are outside the
> diff). Pure helper extraction, no behaviour change, the role gate stays
> in the handler for the C1.5 parity: `applyAdminTrafficPseudonym` +
> `applyAdminLogStore`, `reconcileMemberRotation` (per member, reports
> whether the registry changed), `validateAuthReorderBody` (the
> state-independent grammar check). The full linter no longer reports the
> three; the diff-scoped gate stays at 0. The pass on that head then
> reached two `noctx` findings in `admin_settings_upstream_test.go` (bare
> `httptest.NewRequest` on lines this program's edits brought into the
> review context); both use the repo's `NewRequestWithContext(t.Context(), …)`
> convention now.
>
> **PR-C9 — the owner-triggered Codex review of the PR head (three P2s).**
> Each was confirmed against the code, pinned in
> `frontend/src/test/pr-c9-codex-red.test.tsx` on the untouched head
> (K1–K3, ten failing cases and one control), then corrected. (K1) The
> route-intent allowlist (`routeIntent.ts`) never learned the three routes
> the program added last — `/policies/header-rewrite`,
> `/objects/url-categories`, `/objects/file-profiles` — so a deep link or a
> re-authentication on them landed on Overview; they are known viewer
> routes now. (K2) The Upstream client bound a create/update success to a
> client-rebuilt authority string, while the appliance renders the
> username percent-escaped inside `authority` (`url.PathEscape`: `?`, `#`,
> `%`, `;`, non-ASCII), so a genuine success with such a username was
> classified UNPROVEN and latched the page; the success is now bound FIELD
> BY FIELD (`canonicalSpec` + `matchesSpec` on scheme/host/port/username,
> the fields the appliance already returns), never through a rebuilt or
> re-escaped string, and the control keeps a different username, host or
> port unproven. (K3) The appliance runs a manual probe SEQUENTIALLY at 5 s
> per eligible entry while the page dispatched it under the 30 s default
> request deadline, so eight or more entries aborted a run the appliance
> was still executing into an unproven outcome; `runUpstreamProbe` now
> sizes its deadline from the read model (`probeDeadlineMs`: never below
> the default, never below entries × 5 s + 10 s), the 5 s constant is
> `PROBE_PER_ENTRY_MS` and is pinned to the engine's `ProbeTimeout` by
> `upstream_probe_deadline_lockstep_test.go` (the engine constant is
> exported for that test only; engine behaviour is byte-identical). No
> Go handler changed; `frontend/dist` regenerated.
>
> **PR-C10 — the second Codex round (two P2s).** Both confirmed against
> the code and pinned in `frontend/src/test/pr-c10-codex-red.test.tsx`
> (K4–K5, nine failing cases and three controls) before the correction.
> (K4) The appliance brackets a bare IPv6 literal and keeps the literal AS
> TYPED (lower-cased, never compressed — `internal/upstream` `normalizeHost`),
> while the client's canonical host went through the URL parser, which
> throws on a bare literal and compresses a bracketed one, so a genuine
> success on `2001:db8::1`, `2001:DB8::1`, `2001:0db8::1` or
> `[2001:0db8::1]` was classified UNPROVEN; `canonicalSpec` now brackets
> and lower-cases an IPv6 literal itself and never hands it to the URL
> parser, and a different literal still stays unproven. (K5) A manual
> probe and every mutation share one run owner (`begin()` aborts the
> predecessor), but `canMutate` ignored `probing`, so New entry / Edit /
> Delete entry / the credential ceremonies stayed live during a probe and
> a confirmed mutation would abort the probe's request into an unproven
> outcome while the appliance kept probing; `canMutate` now includes the
> in-flight probe, the page test drives the real page with the probe
> answer held open and proves the controls are disabled until it lands
> and re-enabled after. Frontend only; `frontend/dist` regenerated.
>
> **PR-C11 — the third Codex round (one P2).** Confirmed against both
> sides (the Go normaliser and the browser's URL parser) and pinned in
> `frontend/src/test/pr-c11-codex-red.test.tsx` (K6, eight failing cases,
> three companions and one control) before the correction. The
> appliance's `normalizeHost` recognises only a full dotted-quad as IPv4
> and otherwise keeps the UTS-46 mapping of what was typed, so `127.1`,
> `2130706433` and `0x7f.1` are stored and returned VERBATIM and
> full-width `１２７.１` becomes `127.1`; the PR-C10 `canonicalSpec` mapped
> every non-IPv6 host through the WHATWG URL parser, which treats a last
> label that ends in a number as an IPv4 literal and collapses all four
> to `127.0.0.1`, so a genuine create/update success on such a host was
> classified UNPROVEN. `canonicalSpec` now asks the parser to map the
> host with a sentinel trailing label appended (never a last label, never
> numeric) and strips the sentinel again, which keeps the IDNA punycode
> mapping the parser was used for (`bücher.example` →
> `xn--bcher-kva.example`) and mirrors the appliance on every spelling; a
> different numeric host still stays unproven. Frontend only;
> `frontend/dist` regenerated.
>
> **PR-C12 — the fourth Codex round (one P2).** Confirmed against both
> sides and pinned in `frontend/src/test/pr-c12-codex-red.test.tsx` (K7,
> eight failing cases, four companions and one control) before the
> correction. The appliance lower-cases with Go's SIMPLE Unicode case
> mapping (`strings.ToLower`: U+0130 `İ` → `i`, `Σ` → `σ` always) and
> strips exactly ONE trailing dot before the IDNA mapping, so `İ.example`
> is returned as `i.example` and `example.com..` as `example.com.`; the
> client used JavaScript's FULL mapping (`İ` → `i̇`, which the IDNA mapping
> turns into `xn--i-9bb`) and stripped every trailing dot, so a genuine
> create/update success on such a host was classified UNPROVEN.
> `canonicalSpec` now maps the two full-mapping specials to Go's result
> before lower-casing (`lowerAsGo`) and strips a single trailing dot; an
> answer keeping a dot the appliance would have stripped still stays
> unproven. Frontend only; `frontend/dist` regenerated.
>
> **PR-C13 — the fifth Codex round (one P2).** Confirmed against both
> sides and pinned in `frontend/src/test/pr-c13-codex-red.test.tsx` (K8,
> four failing cases, five companions and two controls) before the
> correction. `ℵx.example` is mapped by UTS-46 to `אx.example`, a label
> mixing right-to-left and left-to-right letters that the browser's URL
> parser refuses while the appliance's IDNA tables accept it and return
> `xn--x-zhc.example`; the client kept the raw spelling on a parser
> failure and refused the genuine success as UNPROVEN. The appliance's
> tables cannot be reproduced exactly in the browser, so the binding no
> longer tries: `matchesSpec` accepts a returned host when it equals the
> client's ASCII form OR when its punycode-decoded, NFC-normalised form
> (`hostUnicodeKey`, an RFC 3492 decoder that yields no key for a
> malformed label) equals the typed host's mapped form — the browser's
> own mapping when it succeeds, NFKC plus Go-style lower-casing when the
> browser refuses the host. Scheme, port and username stay exact; a host
> that decodes to different letters, or carries a malformed punycode
> label, stays unproven. Frontend only; `frontend/dist` regenerated.
>
> **PR-C14 — the sixth Codex round (one P2).** Confirmed against both
> sides and pinned in `frontend/src/test/pr-c14-codex-red.test.tsx` (K9,
> ten failing cases, four companions and one control) before the
> correction. Go's `strings.TrimSpace` and JavaScript's `trim()` use
> different whitespace sets: the appliance strips U+0085 NEXT LINE (and
> U+00A0, U+2028, U+3000) from a username or host and KEEPS U+FEFF, while
> `trim()` keeps U+0085 and strips U+FEFF, so a username pasted with a
> NEXT LINE was returned as `svc` and the client's binding refused the
> genuine success as UNPROVEN; the editor sent the untrimmed value for the
> same reason. `trimAsGo` now trims exactly Go's set and is used by
> `canonicalSpec` (scheme, host, username) and by the editor's
> `draftToSpec` (host, username), so what is sent is what the appliance
> keeps; a character neither side trims (U+200B) still binds only to
> itself. Frontend only; `frontend/dist` regenerated.
>
> **PR-C15 — the seventh Codex round (two P2s).** Both confirmed and
> pinned before the correction (`upstream_codex_r7_red_test.go`,
> `frontend/src/test/pr-c15-codex-red.test.tsx`). (R7-A) `normalizeHost`
> accepted hosts with EMPTY labels (`.example`, `parent..example`) — the
> IDNA mapping passes them through unchanged — so an invalid DNS name was
> persisted and published as an eligible parent; `validateHostLabels` now
> refuses any empty label after the mapping while keeping the single
> trailing FQDN dot, and the endpoints answer `invalid_entry`. (R7-B) The
> manual probe's client deadline was sized from the page's entry count,
> which is not an upper bound (the appliance probes the CURRENT entries
> sequentially, so entries added by another admin after the page's read
> outran the deadline and the completed run latched as unproven). The
> read model now exposes the node-local single-flight state
> (`probe.manualInFlight`, additive; OpenAPI + bundle regenerated), and
> the page resolves a timed-out probe against the appliance: it polls the
> read model until no run is in flight and counts the run as completed
> only when at least one eligible entry's health advanced with the manual
> source; nothing in flight and nothing advanced stays unproven,
> fail-closed. Backend + frontend; `frontend/dist` regenerated.
>
> **PR-C16 — the CI-shaped seeded shuffle on the PR-C15 head.** The
> `-shuffle=1788873409540952482 ./... -count=2` run under a read-only
> `/data` failed `TestIdentityIngress_NoBackendSpoofDenied` on a request-log
> entry attributed to `alice` while the test's own request was logged with
> an empty identity: the assertion judged every ring entry whose host
> matched the backend's ephemeral port, and an earlier test that
> authenticated alice against a backend on the same recycled port had left
> its entry in the process-global ring. Reproduced deterministically
> without the shuffle (`TestOrder_IdentityIngressAttributionIsScopedToOwnRequest`,
> RED-before) and corrected in the fixture only: `logEntriesSince(prev)`
> yields the entries recorded after a ring snapshot, and the three ingress
> tests judge only what their own request produced (the positive
> attribution test included). No assertion weakened; test-only.
>
> **PR-C17 — the eighth Codex round (one P1, one P2).** Both confirmed
> and pinned before the correction (`upstream_codex_r8_red_test.go`).
> (R8-A, P1) A backup taken in the prepared-downgrade state — after
> `--prepare-downgrade`, before the next boot re-migrates — packed the
> legacy `upstream_proxies` URLs, which then carry the unsealed passwords
> by design, verbatim while the manifest asserted `credentialsOmitted:
> true`; a pre-v2 file never booted on this binary has the same shape.
> The sanitizer now REFUSES such a body (a password in any legacy URL, or
> the prepared-downgrade marker) with a counts-only error the packer
> turns into a failed backup; a password-free legacy list still archives
> unchanged; runbook §8 updated. (R8-B, P2) `validateHostLabels` checked
> emptiness only; it now enforces the DNS length limits on the A-label
> form (63 octets per label, 253 per name, trailing FQDN dot excluded)
> with `invalid_entry`. Backend only.
>
> **PR-C30 — the seeded determinism run on the corrected head (two test
> defects).** The root-package shuffle that failed the gate on `8e73a619`
> (`-shuffle=1788866999688368609 -count=2`), re-run on `7fd9c852`, failed
> two tests; both were pinned RED-first
> (`test_order_isolation_c30_red_test.go`, executed on `7fd9c852` before the
> correction) and neither is a product defect. (C30-A)
> `TestDCFin5_LegacyImportReplaceAndMergeAreDurable` read `[]` back from a
> settings file it had just proven to carry both imported identities: the
> restart helper `dcFinBoot` reset the live rewriter to "fresh process" and
> loaded the file, and a best-effort admin-settings save still in flight
> (`adminSettingsSave` spawns one on every admin mutation, the merge import's
> own included) landed inside that window, serializing the empty live list
> as saved-authoritative — the PR-C7b class. RED: with a save held open the
> helper returned anyway, and the loss itself reproduced; a mechanism
> control (green at both trees) documents the erasure. Correction: `dcFinBoot`
> drains `adminSettingsSaveWG` BEFORE the fresh-process reset and
> `dcFinYAMLBootEnv` drains it before handing over the settings path;
> isolation only, no assertion changed. (C30-B)
> `TestMatchSchedule_InvalidTimezone` asserted a `"00:00"`–`"23:59"` window
> against the wall clock; the matcher is half-open, so the claim is false
> for the last minute of every day and the run crossed 23:59 UTC. Main's own
> commit `08545fa5` corrected the two sibling tests to `"24:00"` and left
> this one and `TestPolicyPrecompute_ScheduleTimezone` (the same window in
> America/New_York, asserted through `Evaluate`'s per-scan clock) behind.
> RED: a source wall over the root test files refuses a full-day schedule
> built as `"00:00"`–`"23:59"` (two offenders on the untouched tree).
> Correction: both windows close at `"24:00"`, exactly as `08545fa5` did;
> the engine is unchanged. Test-side only.
>
> **PR-C29 — the nineteenth Codex round (one P1).** Confirmed and pinned
> before the correction (`upstream_codex_r19_red_test.go`; seven of its
> eight shapes were accepted on the untouched head — the document-level
> `Credential` object was already refused by the exact-case `ciphertext`
> key inside it). (R19-A, P1) `walkV2Keys` compared the sealed-record key
> names and the `credential` key EXACTLY, and the duplicate-key walker
> folds case only for the keys BOUND at a structural role — so a
> case-variant sealed field placed OUTSIDE its normal role (a
> document-level `Ciphertext`, an entry-level `KeyId`, a nested
> `AuthorityHash`, a misplaced `CREDENTIAL`) passed both and the
> zero-strip branch archived the field unchanged while the manifest
> asserted `credentialsOmitted`. The verifier now folds case for the
> v2-owned key names at every depth (`strings.EqualFold`); a VALUE equal
> to a case variant stays ordinary (PR-C27) and a case variant IN its
> bound role stays refused by the walker (PR-C22). Backend only.
>
> **PR-C28 — the eighteenth Codex round (one P2).** Confirmed and pinned
> before the correction (`upstream_codex_r18_red_test.go`). (R18-A, P2)
> `stripUpstreamCredentialsFromSettings` decoded the settings body into a
> `map[string]any`, and the JSON literal `null` decodes into a NIL map
> without error — so the duplicate-key walk, the trailing-data check, the
> legacy gate and the v2 strip all saw an empty document and the
> zero-strip branch handed the original `null` back to be archived, though
> the function's contract is that a non-object root is refused; a restore
> of such an archive silently boots zero-valued settings. A nil root is now
> refused after decoding, like every other non-object root (the
> array/string/number/bool controls stay refused and `{}` stays a sound,
> unchanged settings file). Backend only.
>
> **PR-C27 — the seventeenth Codex round (one P2).** Confirmed and pinned
> before the correction (`upstream_codex_r17_red_test.go`). (R17-A, P2)
> `verifyV2CredentialsRemoved` searched the re-serialized v2 document's
> BYTES for the quoted sealed-record key names, so a sound entry whose
> VALUE equals one of them — an uncredentialed parent whose username is
> `keyId` or `ciphertext`, a host spelled `authorityhash`, a document-level
> note — matched the same quoted bytes though no sealed-record key
> remained, and because PR-C26 runs the verifier for every present
> document such a settings file refused every backup. The verifier now
> walks the document's object KEYS at every depth (`walkV2Keys`) and
> refuses a sealed-record key or a surviving `credential` key; values are
> never inspected. The fail-closed controls (an entry-level `keyId` key, a
> document-level `ciphertext` key, a nested `authorityHash` key) stay
> refused. Backend only.
>
> **PR-C26 — the sixteenth Codex round (one P1).** Confirmed and pinned
> before the correction (`upstream_codex_r16_red_test.go`). (R16-A, P1)
> The PR-C25 v2-document verification ran only AFTER at least one
> credential object had been stripped, so a v2 document carrying
> misplaced sealed fields with no recognized `credential` object — a
> document-level `ciphertext` or `keyId`, an entry-level `authorityHash`
> or `ciphertext`, a nested object inside the document — returned the
> ORIGINAL bytes at the zero-strip branch before the verifier ran, and
> the material was archived under `credentialsOmitted: true`. The
> verification now runs whenever a v2 document is present, before the
> zero-strip return; a sound document with no credential and the sealed
> names outside the document stay ordinary (pinned as controls). Backend
> only.
>
> **PR-C25 — the fifteenth Codex round (one P2).** Confirmed and pinned
> before the correction (`upstream_codex_r15_red_test.go`). (R15-A, P2)
> After stripping a v2 credential the sanitizer scanned the WHOLE
> re-serialized settings document for the sealed-record key names
> (`ciphertext`, `keyId`, `authorityHash`) and refused the backup on any
> hit, so an OTLP header or an unrelated section using one of those names
> combined with a real v2 credential refused a sound backup after the
> credential had already been removed. The post-strip check now verifies
> removal within the v2 document alone (`verifyV2CredentialsRemoved`
> re-serializes that subtree and refuses any surviving name inside it — the
> document is upstream-owned in full, so the fail-closed posture there is
> kept, pinned by two controls) and unrelated sections may use any name.
> Backend only.
>
> **PR-C24 — a newly published dependency advisory in the generator
> workspace.** `Gate · frontend / Frontend · verify + determinism` failed on
> the PR-C23 head at the last verify step — `npm audit --audit-level=high`
> in `frontend/tools/openapi-gen` — because GHSA-2883-xcg3-v3hh (js-yaml
> `4.0.0`–`4.3.1`, CPU exhaustion on empty merge sources) was published
> between two runs of the same gate on the same generator lockfile, which
> has been unchanged since the workspace was created and is identical on
> `main`. `openapi-typescript@7.13.0` requires `@redocly/openapi-core
> ^1.34.6`, whose latest `1.34.19` pins `js-yaml` to exactly `4.3.1`, so no
> in-range update exists and `npm audit fix` is a no-op; the workspace now
> carries an npm `overrides` entry pinning `js-yaml` to the patched `4.3.2`
> (lockfile regenerated with `--package-lock-only`, integrity recorded).
> The generator's YAML parsing is the only consumer; the canonical
> `npm run verify` proves the regenerated `src/api/types.gen.ts` and
> `frontend/dist` are byte-identical (drift gates pass) and both audits are
> clean. Frontend workspace only; no product code changed.
>
> **PR-C23 — the fourteenth Codex round (one P1, one P2).** Both
> confirmed and pinned before the correction
> (`upstream_codex_r14_red_test.go`). (R14-A, P1) The sanitizer asserted
> the v2 document to an object and its `entries` to an array and on any
> other shape fell through to the no-op path, which hands back the
> ORIGINAL bytes — so an `entries` object or string, a non-object item, an
> array/string/`null` document, or a non-object `credential` carried
> sealed material into the archive under `credentialsOmitted: true`. A
> present document, `entries`, item or `credential` of any other shape
> now refuses the archive. (R14-B, P2) The PR-C22 case-variant and
> case-collision checks ran for every object at every depth, so a
> legitimate operator-controlled map key — an OTLP header named `URL` or
> `KeyId` under `otlp_headers`, a case-colliding header pair, or an
> unrelated section using those names — refused every backup even with no
> upstream credential anywhere. The token walker now tracks the
> STRUCTURAL ROLE of every container (`jsonRole`: root, legacy list/item,
> v2 document/entries/entry/credential, other) and applies the alias check
> and the case-fold collision check only where the settings loader binds
> the key to an upstream field (`upstreamBoundKeys`); an exact duplicate is
> still refused anywhere. Runbook §8 updated. Backend only.
>
> **PR-C22 — the thirteenth Codex round (one P1).** Confirmed and pinned
> before the correction (`upstream_codex_r13_red_test.go`, with a
> loader-evidence test proving `encoding/json` reads the variants into
> `AdminSettings`). (R13-A, P1) The sanitizer looked every key up by EXACT
> spelling while the settings loader matches struct fields
> case-insensitively, so a legacy list under `UPSTREAM_PROXIES`, a v2
> document under `Upstream_Proxies_V2`, `entries`/`credential`/
> `requiresReplacement` under case variants, a case-variant
> prepared-downgrade marker, and a case-only key collision (`upstream_proxies`
> beside `UPSTREAM_PROXIES`) all bypassed the gate or the strip and the
> original bytes were archived under `credentialsOmitted: true`. The token
> walker now refuses, at any depth, a key repeated under case folding and
> any key that equals one the sanitizer reads (`sanitizerReadKeys`)
> without being its exact spelling — the appliance never writes a variant,
> so one is a hand-edited file the sanitizer cannot read as the loader
> does; canonical spellings and unrelated keys in any case stay ordinary
> (pinned as a control). Runbook §8 updated. Backend only.
>
> **PR-C21 — the twelfth Codex round (one P1).** Confirmed and pinned
> before the correction (`upstream_codex_r12_red_test.go`). (R12-A, P1)
> The backup sanitizer asserted the legacy `upstream_proxies` value to a
> JSON array and silently skipped the credential gate on any other shape
> (an object, a string, `null`, a number, a nested array) and, inside a
> well-formed array, on an item that is not an object, an object whose
> `url` is not a string, and an object with no `url` — every one of which
> carried the plaintext material past the gate into a verbatim archive
> under `credentialsOmitted: true`. The container shape is now part of
> what the gate reads: the persisted shape of
> `AdminSettings.UpstreamProxies` is an array of objects each carrying a
> non-empty `url` string (the settings loader can read nothing else), and
> a present key of any other shape is counted as malformed and refuses the
> archive (counts only); an absent key and the persisted shape stay
> ordinary (pinned as controls). Runbook §8 updated. Backend only.
>
> **PR-C20 — the eleventh Codex round (one P1).** Confirmed and pinned
> before the correction (`upstream_codex_r11_red_test.go`). (R11-A, P1)
> The backup sanitizer decoded the settings object into a map, and
> `encoding/json` keeps only the LAST value of a repeated key, so a
> settings object repeating `upstream_proxies` (a credential-bearing list
> first, an empty list last), a repeated nested `url`, or a repeated
> `upstream_proxies_v2` document had the credential gate inspect only the
> surviving value while the no-op path handed back the ORIGINAL bytes,
> secret included, under `credentialsOmitted: true`. The sanitizer now
> walks the raw token stream first (`rejectDuplicateJSONKeys`) and refuses
> any object that repeats a key at any nesting level — never decoding
> into the representation that discards the earlier value — before the
> PR-C19 EOF check and the map decode; the same key in different objects
> stays ordinary (pinned as a control). Runbook §8 updated. Backend only.
>
> **PR-C19 — the tenth Codex round (one P1, one P2).** Both confirmed
> and pinned before the correction (`upstream_codex_r10_red_test.go`).
> (R10-A, P1) The backup sanitizer decoded ONE JSON value and never
> looked at the bytes after it, so a settings body whose leading object
> is credential-free followed by a second value or trailing garbage
> carrying a plaintext legacy upstream URL was returned UNCHANGED (the
> no-op path hands back the original body) and packed verbatim while the
> manifest asserted `credentialsOmitted: true`. The sanitizer now requires
> the decoder to reach EOF after the settings object (trailing whitespace
> stays accepted) and refuses anything else before inspecting it; runbook
> §8 updated. (R10-B, P2) `normalizeHost` decided "IPv6" by
> `net.ParseIP(host).To4() == nil`, so an IPv4-mapped spelling
> (`::ffff:192.0.2.1`, whose `To4()` is non-nil) was left unbracketed:
> `Authority()` produced a URL `url.Parse` refuses and the pool rebuild
> silently omitted the persisted entry, and the bracketed spelling was
> refused by the same test. IPv6 URL SYNTAX now decides (`isIPv6Literal`:
> a colon and a `net.ParseIP` parse), `To4()` never does, a bare literal
> is bracketed as typed and the PR-C18 single-bracket-pair rule is kept;
> the client already binds every colon-bearing host to its bracketed
> form, so no frontend change was needed. Backend only.
>
> **PR-C18 — the ninth Codex round (one P1, one P2).** Both confirmed
> and pinned before the correction (`upstream_codex_r9_red_test.go`).
> (R9-A, P1) The PR-C17 backup refusal skipped a legacy `upstream_proxies`
> URL that `url.Parse` could not parse (a malformed escape in the
> password) or that parsed as an opaque, host-less scheme-less
> `user:pw@host` spelling, treating a parse failure as "no password" —
> so exactly the material the gate exists to keep out of an archive was
> packed verbatim under `credentialsOmitted: true`. The gate now fails
> CLOSED: every legacy URL must parse to an absolute URL with a host, and
> an unreadable one is counted as unparseable and refuses the archive
> (counts only; runbook §8 updated). (R9-B, P2) `normalizeHost` stripped
> EVERY outer bracket with `strings.Trim(host, "[]")` before parsing the
> IPv6 literal, so `[[::1]]` and a mismatched pair (`[[2001:db8::1]`,
> `[2001:db8::1]]`) passed normalization and were persisted; the pool
> rebuild cannot parse the resulting authority and silently omitted the
> entry, so an update could remove a working parent from the effective
> pool. Exactly one bracket pair is now required — a host that starts or
> ends with a bracket must be `[` + an IPv6 literal without brackets +
> `]` — and every other bracket shape is `invalid_entry` before it can
> reach the store. Backend only.
>
> **PR-C5 — reviewer findings.** (P1) The credential-free v1 adapter and
> the per-entry DELETE keyed their refusals on credential material only,
> so an entry in the durable `requiresReplacement` state (Credential nil,
> marker set) could be omitted or deleted without the exact-id Tier-3
> clear; both now use the same `upstreamEntryProtected` predicate as the
> import planner and name every protected entry. (P2)
> `culvert --prepare-downgrade` audited into the in-memory ring of a
> process that exits immediately; `runPrepareDowngradeCommand` opens the
> `-audit-log` sink before the command and refuses to run when the
> configured sink cannot be opened. Proofs in
> `upstream_v2_codex_red_test.go`, the P2 one driving the real one-shot
> dispatcher in a re-executed test binary.
>
> **PR-C3/C4 — hygiene.** The 50 diff-scoped lint findings and the three
> staticcheck findings inherited from the program's earlier slices are
> cleared (helpers extracted for the complexity findings; dead draft
> helpers removed; test-only nolint directives carry their reason), and
> the eleven CodeQL log-injection alerts on new code are closed with the
> repository's `sanitizeLog` + `%q` convention.
>
> **PR-C6 — API contract.** oasdiff against `main` reports 36 breaking
> changes, all the documented behaviour of the Batch 2 backend
> corrections (JSON refusals instead of `text/plain`, 204 deletes, required
> revision fences and identity parameters, closed security enumerations).
> The contract takes the MAJOR bump the versioning policy requires
> (1.2.0 → 2.0.0; the eleven operations this PR introduces are tagged
> `x-culvert-introduced-version: 2.0.0`), the entry is recorded in
> `CHANGELOG.md`, and the PR body carries the `Breaking-Change-Rationale:`,
> `Migration-Instructions:` and `Version-Impact:` sections. The
> `api-breaking-approved` label and the CODEOWNER approval are the owner's.

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

> **FE-6-0 — ENTRY GATE, SURFACE AUDIT, BINDING CONTRACT AND APPROVED DECOMPOSITION (this branch, 2026-09-09). PLANNING/CONTRACT GATE ONLY — implements NO FE-6 product behaviour.** Sub-slices FE-6A onward implement this record verbatim; any deviation needs a recorded amendment here. External contract review is required before FE-6A starts.
>
> **A. Program-record correction.** Batch 2 consisted of 2A, 2A-M, 2B, 2C, 2D (2D-A/2D-B/2D-C), 2E (2E-A/2E-B/2E-C) and 2F (2F-0 … 2F-G). There is NO remaining Batch 2 slice: Batch 2 is complete and frozen at `claude/culvert-frontend-batch2` @ `8e73a619e4fa34b7b6446d8be9df383b5619b573` (permanently frozen; never to be advanced). The Batch 2 slice table above still shows the 2E row as `pending` and the 2F row as "2F-G closure this round"; both are historical wording superseded by this correction (append-only record — the table is not rewritten). One consequence already discovered by this gate: **FE-V04/FE-V05 (decryption exclusions + tunables + health) were pulled forward into 2E-B and are effectively MIGRATED** at `/app/security/decryption` (`DecryptionPage.tsx`, `DecryptionHealthTab.tsx`, `ExclusionsCacheTab.tsx`, `AutoExclusionsTab.tsx`, `DestinationPrivacyTab.tsx`, `src/api/decryption.ts`), with fenced writes, T1/T2/T3 ceremonies, exact RBAC mounting, and Go + vitest + real-binary proof; the parity rows FE-V04/FE-V05 (`FRONTEND-FEATURE-PARITY.md:26-27`) and the FE-6 objective line above are stale and are corrected by FE-6L (§F), not by this gate.
>
> **B. Branch custody and entry-gate ancestry (verified, not inferred).**
> - Frozen predecessor: `origin/claude/culvert-frontend-batch2` = `8e73a619` (tip: "test(e2e): stop the YAML-seeded appliance in the harness exit trap"). Untouched.
> - `origin/main` re-fetched at the gate = `3f7d0640` (merge of PR #1348, grpc v1.83.2 / CVE-2026-84445; the Batch 2 program itself merged as PR #1340 at `c9c68566` from `claude/culvert-frontend-batch2-pr`, carrying the correction rounds PR-C9 … PR-C30).
> - Ancestry, on FULL history: `8e73a619` IS an ancestor of `origin/main`; main-only commits since the frozen tip: 94; frozen-only commits: 0. (Recorded because the session's shallow clone first reported a merge base of `1b3d0e6a` and a 70-file add/add conflict set — a shallow-history artefact, discarded after `git fetch --unshallow`; no conflict resolution occurred.)
> - FE-6 branch: created from `8e73a619` exactly, then ONE evidence-preserving no-fast-forward merge of `origin/main@3f7d0640` (`cfb48e81`, parents `8e73a619` + `3f7d0640`). The merged tree is BYTE-IDENTICAL to `origin/main` (`git diff origin/main` empty); the merge commit records the two-parent ancestry and changes nothing. No amend, squash, rebase or history rewrite; no PR opened.
> - **Branch-name deviation, flagged for the reviewer:** the directive asked for `claude/culvert-frontend-fe6`; the session's harness custody rule binds pushes to the designated branch `claude/culvert-frontend-fe6-hyagdj`, so the FE-6 branch carries that name. No `claude/culvert-frontend-fe6` ref was created. Creating it as an alias of the same SHA is the owner's call.
> - Changed-file classification for FE-6-0: the entry merge changes NO file relative to `origin/main`; the FE-6-0 commit changes exactly ONE file — `docs/design/FRONTEND-MIGRATION-PLAN.md` (this record, append-only under the FE-6 heading). No product code, frontend source, generated artifact, OpenAPI bundle, route metadata or committed `frontend/dist` is touched (none was required by entry-gate reconciliation).
> - Qualification of the merged baseline (its tree is `origin/main`'s): `go build ./...` and `go vet ./...` clean on `cfb48e81`; `frontend` `npm run verify` under the pinned toolchain (node 24.19.0 / npm 11.17.0) passed ALL nine gates — toolchain identity, clean install + ignore-scripts policy in both npm trees, OpenAPI type generation with zero drift, lint + format, strict typecheck, unit tests (70 files / 787 tests), production build with ZERO committed-dist drift, bundle security scan, license + audit policy — and left the tree clean. `origin/main` CI on `c9c68566` (PR #1340 merge): Test & Build, Compose Smoke, Docker Build & Publish, Release catalog gate all green; the `CI` workflow's only red job is `Auto-Tag Release` → "Require Security + QA gate approval on this SHA", because the QA Gate run for that SHA was cancelled by the superseding push of #1348 (not a code failure); CI + QA Gate for `3f7d0640` were in progress at gate time. Route pin unchanged at 243 (`ui_routes_meta_test.go:101`, `d0_helpers_test.go:195`); OpenAPI contract 2.0.0; `static/index.html` 21,955 lines; `frontend/e2e` 29 specs.
>
> **C. Cross-cutting facts the audit established (every claim read in code; CONFIRMED unless marked).**
> - **SEC-C2 has NOT landed.** `buildMetadataIndex` (`ui_metadata_enforcement.go:178-200`) files `{param}` paths literally; the ten wildcard routes in `uiRoutes` are exactly the ten Support per-bundle / per-recipient routes (`ui_routes_meta.go:821-884`), so C2 is skipped there and handler `requireRole` is the only gate. No other FE-6 surface has a `{param}` route (IdP uses the trailing-slash prefix `/api/idp/`, MCP/cluster/settings use query parameters).
> - **Refusal vocabulary is `text/plain http.Error` on essentially every FE-6 mutation.** Typed JSON refusals exist only where Batch 2 created them (upstream plan refusals, PAC `{error, issues}`, rewrite-degraded 503, the shared `409 {error, currentRevision, yourRevision}` fence conflict of `writeContentSecRevisionConflict`, the LDAP preflight 422 `{error, test}`, rollback `rolled_back_not_durable`, the MCP 500 persist-failure bodies). The v2 `REFUSAL_CONTRACT` pattern (contracted status + typed allowlisted facts, no server prose) therefore has nothing to bind to on IdP, Administrators, Certificates/CA, Cluster, Releases, Support, Settings or MCP today.
> - **`x-culvert-audit-event` names drift from the emitted audit actions on every surface** and nothing pins them (`internal/apicontract` checks presence only): IdP (`idp.discover` declared, never emitted), Administrators (`auth.user.upsert/delete`, `auth.password.change` vs `auth.users.set/delete`, `auth.password_change`), CA (`certs.upload` vs `certs.upload_mitm|_ui`, `ocsp.set` vs `ocsp.toggle`), Cluster (every route), Releases (`release.dispatch.resume`, `release.catalog_refresh` vs `release.dispatch`/`.outcome`, `release.catalog.refresh`), MCP (`mcp.publication.decision` vs `.approve/.reject`), Decryption (`decryption.exclusion.evict`, `decryption.redaction.set`, `decryption.tunables.set` vs `decryption.autoexclude.evict/.clear`, `decryption.redaction(.key-rotated|.key-rotate-replay)`, `decryption.autoexclude.tunables`). Danger levels disagree between `openapi.yaml` and `api/route-classification.yaml` on `ca/cache-clear`, `certs/upload`, `releases/dispatch(+resume)`.
> - **Generated types are opaque exactly where the v2 T3 decoders are mandatory**: `CAStatus`, `rotateCA` 200, `uploadCerts` 200, `DispatchStatus`, `ReleaseCurrent`, `ClusterHA`, `ClusterTokens`, `ClusterTokenInput`, `NodeGroupInput`, `BandwidthPolicies`, `IdPList` items, `oidc`/`saml` sub-configs, `LockoutsList` items, `DecryptionExclusions`, `TunablesPatch` are `additionalProperties: true`; `/api/idp/{id}` and `/api/idp/{id}/groups` are undocumented (intentionally-undocumented non-REST rows). Hand-authored decoders remain the runtime contract, as `FRONTEND-SECURITY-CONTRACT.md` §7 already requires.
> - **Node-local vs cluster-synced.** Cluster-synced (CP→DP via `ConfigSnapshot`): IdP registry (Sensitive; redacted for unenrolled callers; wipe-to-empty is WIRE-DEAD — `omitempty` + nil-skip, `controlplane_snapshot.go:96,1229`), session HMAC, node groups + bandwidth policies (rows are ClusterSynced but the handlers NEVER publish), cluster-CA fingerprint, `base_url`, `trust_forwarded_headers`, `otlp_endpoint`, `conn_limit_max_per_ip`, plus the Batch 2 policy/object surfaces. Node-local: admin users + lockouts + session revocations, inspection Root CA (+ its bundle, `ui_tls_*.pem`, OCSP toggle), every appliance setting in `admin_settings.json`, config versions, release catalog + dispatch slot, the whole `support/` tree, all MCP durable files, decryption tunables + pseudonym key, cluster.json (CP), `ha_config.json`.
> - **Backup manifest (`backup.go:64-112`) omits**: `idp_profiles.json`, `ui_tls_cert.pem`/`ui_tls_key.pem`, `ha_config.json`, `cp_config_version.json`, `dp_last_seen_epoch.json`, the entire `support/` tree (bundles, recipients, upload/telemetry configs with RAW bearer credentials, upload queue, debug level), and every MCP durable file (`mcp_rollout_state_*.json`, `mcp_distribution/`, `mcp_shadow_exit_review.json`, `mcp_tooltrust/approvals.json`); it archives `ca.bundle` by FIXED name regardless of `-ca-path`, and `admin_settings.json` with `metrics_token`, `otlp_headers` and the pseudonym key RAW (only the upstream sealed records are stripped). Key files are never archived (correct). A React restore-truth surface must say exactly this.
>
> **D. Surface inventory (authoritative handlers, roles from `uiRoutes` — the truth the parity matrix defers to — persistence, identity, ceremony, secrets, audit, lifecycle, proofs, parity, and the backend truth gaps that block a React WRITE surface). "Legacy" = `static/index.html`; "uie2e" = the playwright-go legacy suite (`//go:build uie2e`).**
>
> **D1. FE-V27 Identity Providers** (`auth_idp.go`, `ui_auth.go:568-877`, `ui_auth_ldap.go`; meta `ui_routes_meta.go:130-149`). Routes: `GET /api/idp` viewer · `POST` admin (audit) · `POST /api/idp/discover` admin, `AuditExpected:false` · `POST /api/idp/test` admin (non-mutating, audited category-only) · `GET /api/idp/legacy-ldap` viewer · `POST …/import` admin · `/api/idp/` `MethodAny` VIEWER → `apiIdPItem` GET viewer / PUT admin / DELETE admin and `apiIdPGroups` GET viewer (the recorded C4 divergence; a trailing-slash prefix, NOT a GAP-1 wildcard; `AuditExpected:true` on the catch-all makes viewer item GETs count as audit-missing — noise). Persistence: `idpRegistry` file `-idp-profiles-file` (compose `/data/idp_profiles.json`; NO flag ⇒ in-memory, surfaced as `persisted:false`); `persist()` atomic 0600 but PLAINTEXT secrets; Upsert/Delete/ReplaceAll are persist-before-publish and transactional (500, nothing published, no audit on persist failure — `auth_idp_registry_txn_test.go`); a corrupt file is BOOT-FATAL (`auth_idp.go:170-172` → `main.go:664-666`, no quarantine). **`Upsert` compiles under the registry WRITE lock with network I/O** (OIDC discovery 10 s, SAML metadata 15 s) so every proxy-path reader blocks. Enabling an LDAP profile side-effects `enforceLegacyLDAPShadowing` → an IRREVERSIBLE node-local legacy-LDAP retirement persisted to `admin_settings.json`. Identity/fencing: NONE — `PUT /api/idp/{id}` is an UPSERT that creates on an unknown id; `before` is read outside the lock; DELETE is unfenced and has no reference guard (SSORequired `providerRefs` dangle); `?preflight=connection` (LDAP only) is a gate (422 JSON) not a fence; `legacy-ldap/import` mints a new profile per POST. Secrets: `publicIdPProfile` allowlist projection — OIDC `clientSecret` omitted with NO configured-indicator, SAML `metadataXml` omitted (`metadataUrl==""` is the inline indicator), LDAP `bindCredentialConfigured`; update preserve is decided by RAW-BODY KEY PRESENCE (omitted ⇒ keep, present-empty ⇒ clear; a `metadataUrl` clears stored XML); audit diff uses the public projection; not on export/import/rollback/backup; CP→DP Sensitive with wire-dead wipe; the DP persists the full snapshot (secrets) to `dp_last_config_snapshot.json` 0600; the SAML SP key pair is per-process in-memory (`auth_saml.go:400-429`). Audit: `idp.create/update/delete/import/test`; discover unaudited; no `saveConfigVersion`. Legacy: delete = T1 `confirmAction` (`:14163`); enable / LDAP cutover no ceremony; clear-secret checkboxes (`:1959`, `:1991`, `:2067`); raw text toasts. Proofs: `ui_idp_secret_redaction_test.go` (10, incl. two markup scans), `auth_idp_ldap_persistence_test.go`, `auth_idp_persistence_test.go`, `auth_idp_registry_txn_test.go`, `auth_idp_registry_test.go`, `ui_auth_saml_config_test.go`, `ui_auth_ldap_api_test.go`, `ui_idp_fileblock_test.go`, `auth_ldap_provider_test.go`; uie2e `ui_idp_ldap_e2e_test.go` (2). v2 today: read-only `getIdPProviders` (`src/api/policyAuth.ts:448-500`, the 2C SSORequired selector); no feature.
>
> **D2. FE-V37 Administrators** (`ui_auth.go:249-431`, `store.go`). Routes: `GET/POST/DELETE /api/auth/users` admin (POST/DELETE audited) · `GET/POST /api/auth/lockouts` admin · `POST /api/auth/change-password` viewer + `sessionAdmin` identity gate; no divergence; TOTP has NO API (GAP-2 confirmed; dead public-allowlist prefix `/api/auth/totp`, `ui_middleware.go:237`). Persistence: `ui_users.json` (empty flag ⇒ in-memory); `SaveUIUsersFile` is AtomicWrite 0600 but PUBLISH-THEN-PERSIST BEST-EFFORT — save errors are logged and a 2xx is returned (`ui_auth.go:294-297,309-311,418-420`), and the audit fires regardless. **`SetUIUser` with a password REPLACES the struct and silently DROPS the TOTP secret, backup codes and counter** (`store.go:768`) via admin POST and self change-password. Guards: last-admin DELETE only (409 text); NO last-admin demotion guard; no self-delete guard; POST is a silent upsert (no conflict); DELETE 204 for a never-existing user. Sessions: delete revokes (in-memory user revocation + durable `UIUserExists`); role/password change NEVER revoke and the role is trusted from the cookie until TTL. Lockouts in-memory, node-local, countdown without server timestamp. Backups archive `ui_users.json` with hashes + TOTP secrets cleartext; restore has a TOTP-counter rollback guard; not on any config surface (deliberate). Legacy: delete T1 (`:6477`), unlock T1 (`:6517`), create/edit no confirm; change-password has NO legacy UI; TOTP no UI. Proofs: `ui_test.go`, `ui_extra_test.go`, `final_coverage_test.go`, `d0_auth_safety_test.go`, `apicontract_conformance_test.go:133-166`; uie2e `ui_rbac_e2e_test.go`, `ui_login_e2e_test.go`. v2 today: `src/api/auth.ts` login/setup/status only.
>
> **D3. FE-V28 Certificates** (`ui_security.go:245-370`, `ui_tls_custom.go`, `ui_config.go:1919-1988`). Routes: `GET /api/ca-cert` viewer (PEM attachment; the JSON `CACertInfo` branch on `Accept: application/json` — `{ready, subject, issuer, notBefore, notAfter, fingerprint}` — is UNDOCUMENTED and the legacy panel depends on it; 503 "CA not initialised" vs OpenAPI 404) · `GET /api/ca/download` viewer · `POST /api/certs/upload` admin (multipart `cert`/`key`/`target ∈ ui|mitm`, 1 MiB) · `GET/POST /api/settings/network` viewer/admin (`ui_custom_cert_uploaded/active`, `ui_tls_fallback(+reason)`, `ui_sans`). MITM target: `installAndPersistCustomMITMCA` under `caMutationMu` — `LoadCustomCA` installs LIVE FIRST (ECDSA only, `IsCA` required, NO validity-window check), then `SaveCA`; persist failure or no bundle path ⇒ 200 `{persisted:false, warning}` with the live signer already replaced; no dual-CA overlap. UI target: `ParseTLSPair` then TWO atomic writes (`ui_tls_cert.pem` 0644 + `ui_tls_key.pem` 0600), 200 `{persisted:true, note:"… Restart the proxy to activate"}` — restart-only activation, shadowed by `-tls-cert/-tls-key`, no delete/revert endpoint, NOT backed up. `settings/network` POST publishes in memory then `adminSettingsSave()` fire-and-forget; its comment claims UI-cert regeneration that never happens (`selfSignedTLS` only at `startUI`, ephemeral P-256 key per process). No fence; audit in every branch; no `saveConfigVersion`. Legacy: upload has NO confirm (`:13319-13342`); `loadCACertInfo` interpolates `subject` into `innerHTML` unescaped (`:13307`). Proofs: `ui_tls_custom_test.go`, `ui_tls_fallback_preauth_test.go`, `ui_morecoverage_test.go`, `final_coverage_test.go`; uie2e `ui_ca_e2e_test.go` `TestUIE2E_CAPanelShowsRoot`. v2 today: none (`AppShell.tsx:138` planned "Certificates" entry).
>
> **D4. FE-V29 CA Management** (`ui_security.go:1499-1842`, `ca.go`, `internal/ca`, `ca_health.go`, `rootca_recovery.go`). Routes: `GET /api/ca/status` viewer (schema opaque; fields `ready…fingerprint`, `cacheSize/cacheMax 10000/cacheTTL 1h/leafValidity 24h`, `autoRotation:true`, `rotationOverlapDays:30`, `keyProvider` (always `local`), `expiresIn` (Go duration string), CHAOS-28 `usable/unusableReason/inspectBlocked/signRefused`, `rotationPersistFailures/rotationPersistDegraded/rotationPersistError`, CHAOS-50 `loadFailed/loadFailureReason` (embeds the bundle PATH + raw error on a VIEWER route), `inspectBypassed`, `loadRecoveryAttempts/GaveUp/Error`, `dualCAActive`, `secondaryCA{subject,notAfter,overlapEnd,expiresIn}`) · `POST /api/ca/rotate` admin · `POST /api/ca/cache-clear` admin · `GET /api/ca/key-provider` viewer (typed) · `GET/POST /api/ocsp` viewer (GET has NO handler `requireRole`) / admin. **Two-phase rotate as implemented:** step 1 (`confirm` absent/false — or ANY undecodable body) mints a 16-byte hex token into ONE process-global slot (`pendingCARotation`, `ui_security.go:22-27`), 60 s expiry, audits `ca.rotate_requested`, answers `{status:"pending_confirmation", confirmation_token, expires_in_seconds:60, warning}`; step 2 CONSUMES the slot BEFORE validation (`:1670-1675`): missing/expired → 400 text, mismatch → 403 text (indistinguishable from RBAC 403), then `InitCA` installs the new root LIVE IMMEDIATELY (no overlap, leaf cache wiped, ticket keys rotated) and `persistRotatedCA`; persist failure ⇒ 200 `CACertInfo + persisted:false + warning`; success ⇒ 200 `CACertInfo` with NO `persisted` key. The token is NOT bound to the issuing actor/session, NOT bound to the CA fingerprint, is overwritten by any other admin's probe, and a re-probe + re-confirm after a lost response mints a SECOND root. OCSP POST toggles `globalOCSP` + `swapUpstreamTransport` and answers `ok:true` with NO durability (no AdminSettings field, no `configSurfaces` row; YAML `ocsp_check` only). Async plane the UI observes only by re-reading `/api/ca/status`: 24 h rotation ticker (immediate first round), `RotateIfNeeded` ≤30 d dual-CA, CHAOS-50 recovery campaign, `caMutationMu`. Inspection CA is NODE-LOCAL (a CP rotation never propagates); all CA/OCSP/cert mutations are OFF export/rollback by design (`roadmap/CA-CLUSTER-ROLLBACK-CLASSIFICATION.md`). Legacy: `forceRotateCA` = server warning in a T2 `confirmAction` (no typed word) and toasts SUCCESS on `persisted:false` (`:17328-17345`); cache-clear T2; OCSP checkbox posts immediately, no confirm/try-catch; the Dual-CA panel copy claims "zero-downtime" though the manual paths have no overlap. Proofs: `ui_security_coverage_test.go` (rotate steps, status, download, cache-clear, key-provider, OCSP), `cert_rotation_metrics_test.go`, `ca_expiry_failclosed_test.go` (`TestForceRotate_UnpersistedRotationDoesNotReportSuccess` …), `rootca_recovery_test.go` (`TestChaos50_*` ×10), `rootca_failure_visibility_test.go`, `internal/ca/validity_test.go`, `d0_rbac_safety_test.go:44-50`; markup `ui_danger_quiet_test.go:190-198`; uie2e `ui_dialogs_e2e_test.go` (word `ROTATE` as a fixture, not wired to CA). v2 today: none; `src/features/security/rotationRecovery.ts` is the 2E-B PSEUDONYM-key marker (pattern reusable, not CA).
>
> **D5. FE-V30 Cluster** (`ui_cluster.go:580-600`, `enrollment.go`, `ha.go`, `ha_lease*.go`, `nodegroup.go`, `bandwidth.go`, `bootstrap.go`; meta `:682-740`; no `{param}`; `/api/cluster/bootstrap/` is a public exempt prefix). Routes: `status` GET viewer · `mode` POST admin (`auditAdd cluster.enable-cp`) · `tokens` GET viewer / POST admin / DELETE admin (DELETE emits NO audit though OpenAPI declares `cluster.token.delete`) · `nodes` GET · `revoke` POST admin · `labels` POST admin · `node-groups` GET/POST/DELETE (+`/membership`) · `drain` POST admin · `metrics`, `convergence`, `rate-limits`, `audit`, `revocations`, `rotation` GET viewer · `ca` GET viewer / POST admin · `ha` GET viewer / POST admin (`auditAdd` AFTER the response, `token[:8]` in detail) · `ha/promote` POST admin · `bandwidth` GET/POST/DELETE; no C4 divergence; every refusal `text/plain`. **`GET /api/cluster/ha` (VIEWER) returns `deploy_cmd` embedding the FULL HA shared token** (`ha.go:1200-1202,1341-1342`; unpinned; `ha_config.json` stores it plaintext; the legacy panel writes it into the DOM every 3 s). Lease posture (`lease_mode/lease_valid/epoch/lease_recovering`) is on `/api/cluster/ha` and `/healthz` only, not on `/status.ha`; a standby CP reports `status.role:"standalone"` with `ha.role:"standby"` (posture is TWO fields). **No HTTP cluster mutation consults `WriteAllowed()`/`haIssuanceAllowed()`** (only the gRPC Enroll/RenewCert/SyncRevocations sites do), so on a fenced ex-leader or a standby every write lands in the local `cluster.json` and is overwritten by the next `HASync ImportFullState` — the runbook's "read-only" claim holds for gRPC issuance only. Persistence: `cluster.json` mutated in MEMORY FIRST then `Save()` (token create: save failure → 400 but the token stays valid; token delete/revoke: memory changed then 500; labels whole-map LWW; undrain forces `connected` regardless of liveness; geo labels re-added on heartbeat; `ClusterState.version` never incremented — no fence anywhere); `ha_config.json` written with errors IGNORED (`_ = saveHAConfig`); node-groups/bandwidth persist failures SWALLOWED (2xx non-durable) AND never `publishCurrentConfigSnapshot` (DPs learn of them only after an unrelated publish or CP restart); GUI "Enable Control Plane" is NOT durable (role re-derived from CLI/YAML at boot; handler comment `:55` and legacy dialog `:18362` claim otherwise) and a `data-plane` node can be made CP. Cluster CA: GET `Info()` carries no key material; POST `{cert,key}` write-only ECDSA, `commitImport` writes cert then key (not one transaction; mismatch fails closed at boot), no expected-fingerprint precondition; rotation progress on `/rotation` is DP-driven. Tokens: GET hash-only; the POST response is the ONLY plaintext exposure (`token`, `enroll_url`, `enroll_cmd`, `bootstrap_cmd = curl -k …/api/cluster/bootstrap/<token> | sudo bash`), shown once; GC by the heartbeat monitor. Async: legacy 3 s tick fans out ~12 requests; DP heartbeat 60 s, `disconnected` after 90 s; convergence via the 30 s DP config poll; promote synchronous (5 s lease op), lost response ⇒ `GET /api/cluster/ha`; drain has no progress. Legacy ceremonies: Enable CP T3 `ENABLE` (`:18358-18366`), Enable HA T3 `ENABLE` (`:18394-18402`), Promote T3 `PROMOTE` (`:18421-18428`), CA import T3 `IMPORT` (`:18036-18043`), revoke `promptAction` reason (`:18608`), token delete / bulk expired (N sequential DELETEs) / drain / node-group + bandwidth delete T1, labels `promptAction` free text, creates + token generate no ceremony. Proofs: `enrollment_test.go` (44), `cluster_audit_test.go` (17), `cluster_features_test.go` (11), `ha_test.go` (29), `ha_promote_test.go` (9), `ha_fencing_test.go` (5), `ha_lease_test.go` (8), `ha_failover_test.go` (11), `ha_lease_recovery_chaos_test.go` (20), `cluster_ca_chaos_test.go` (21), `chaos51_clusterca_deadlock_test.go`, `cluster_ca_keyatrest_test.go`, `ha_split_brain_failover_evidence_test.go`, `ha_failback_test.go`, `nodegroup_test.go` (10), `bandwidth_test.go` (5), `bootstrap_test.go` (11), `cluster_convergence_test.go`, `cluster_persistence_atomic_test.go`, `coldstart_*`, `cluster_apply_persist_test.go` (10), `d0_rbac_safety_test.go:51-60`, `internal/halease`, `internal/bootstrap`; NO markup scan, NO uie2e for any cluster ceremony (`ui_e2e_smoke_test.go:338` touches `/api/cluster/status` only). v2 today: `AppShell.tsx:153` placeholder; `src/api/diagnose.ts:341-384` `decodeCluster` (the FE-4 diagnose verb, read-only).
>
> **D6. FE-V33 Releases** (`release_api.go:296-826`, `release_wiring.go`, `release_dispatch*.go`, `backups_api.go`, `cmd/culvert-maint`; meta `:787-807`; no `{param}`). Routes: `GET /api/releases` viewer · `GET /api/releases/current?agent=` viewer · `GET /api/releases/dispatch/status?agent=` viewer · `POST /api/releases/dispatch` admin, `Mutating`, **`AuditExpected:false`** (audited by `DispatchService` via `auditAdd`, invisible to C2c) · `POST …/dispatch/resume` admin, `AuditExpected:false` · `POST …/catalog-refresh` admin (audit `release.catalog.refresh`) · `GET /api/backups` viewer (agent pass-through, 15 s cache, never non-2xx). Persistence: catalog dir + `release_catalog_state.json` floor durable; refresh status in-memory; **the dispatch record (`dispatchStore`, one slot per agent key) is IN-MEMORY ONLY** (`release_api.go:223-231`), never re-hydrated at boot, `Resume` reachable only from the HTTP handler; the only durable trace is the free-text `release.dispatch` audit line. Agent side (`cmd/culvert-maint`): op registry + idempotency cache in memory (empty after restart), terminal ops reaped after 1 h (→ 404), fail-closed write-ahead journal + fsync'd `audit.jsonl`; a restart marks orphans `failed(agent_restart_interrupted)`; the Docker reconcile boot hook is NOT wired (E3); `/v1/status.last_operation_*` never populated. Identity: `dispatch_id` (CP ULID), `op_id` (agent), `idempotency_key` (client-supplied or `rel-<release>-<ulid>`; agent dedup 24 h soft TTL, 200 `deduped:true` vs 202). `pre_backup ⇔ passphrase_ref` (`env:NAME`, allowlisted; never a secret, never surfaced); `BackupSkipped` is planned silently when no ref is given and appears nowhere on the API. **Dispatch is UNFENCED to catalog identity**: the body is `{release_id | channel, agent, pre_backup, no_rollback, passphrase_ref, idempotency_key}` — no `catalog_version`/`expected_pinned_ref`; a `channel:` target re-resolves at plan time; the catalog can swap (6 h refresh or manual) between what the UI rendered and the POST. Reply matrix: 202 `{dispatch_id, agent, op_id, status:"dispatched", status_location}`; 200 `already_current`; 409 `in_flight` | `stale_replan_required`; 400/404/503 `refused{kind,detail}`; 503 `unavailable`; 502 `failed terminal`; text/plain for 400/403/404/405 and the not-configured 503. Status: `{agent, phase:none|dispatched|terminal, terminal: succeeded|already_current|failed_rolled_back|failed_needs_attn}`. Resume answers 202 `resuming` BEFORE anything is known, silently drops an in-flight rejection (`:811-815`), and `dispatch_id` resume is impossible after a CP restart. The watch polls the agent every 2 s, 30 min cap → `failed_needs_attn: watch_timeout`. **The single-node op recreates the container hosting the CP** (`release_dispatch_exec.go:72-84`): the slot is lost, `phase:none` is indistinguishable from "never dispatched", and the `compose_override_configured` hazard the agent exposes is not surfaced by the CP. Wiring is unconditional on every node (CP, DP, standby); only agent key `local` resolves; no fleet dispatch; no lease fence. Secrets: catalog origin host-only for overrides; `/current` 503 and `/api/backups` `reason` carry raw transport error strings incl. the socket path; backup entries expose host paths to viewers. Legacy: dispatch is a plain modal with NO confirm (`:5345-5375`, `:17079`); resume/refresh none; no CP rollback-to-previous route; the passphrase placeholder omits the mandatory `env:` prefix (`:5366`); the 2.5 s poll stops on the first fetch error. Proofs: `release_api_test.go` (25), `release_gui_test.go` (7, HTTP-level), `release_dispatch_service_test.go` (18), `release_dispatch_exec_test.go`, `release_dispatch_e2e_test.go` (HTTP fake agent `e2eMaintAgent` with a hold channel — reusable for a browser fixture), `release_e2e_test.go`, wiring/refresh/watchdog/alerts tests, `backups_api_test.go`, agent tests; NO uie2e, NO frontend. v2 today: generated types only (`DispatchStatus`/`ReleaseCurrent` untyped).
>
> **D7. FE-V35 Support** (`ui_support.go`, `support_*.go`, `internal/support`, `internal/redaction`, `internal/supportupload`; meta `:805-897`). Routes (the ten `{id}`/`{name}` rows are the GAP-1 set): `status`, `health/explain`, `bundles` GET viewer · `bundles` POST admin · `bundles/{id}` GET OPERATOR (`AuditExpected` — download is an exfil event) / DELETE operator · `…/redaction-report` GET viewer (`retained_preview` attached only for operator+ — a role-conditional shape) · `…/approve` POST admin · `…/validate`, `…/exports`, `…/manifest` GET viewer · `…/download-encrypted`, `…/download-sealed` POST operator · `recipients` GET viewer / POST admin · `recipients/{name}` PUT admin / DELETE OPERATOR · `debug-level` GET viewer / POST admin / DELETE operator · `retention` GET viewer / PUT admin · `upload/config` GET viewer / PUT admin · `tac-trust` GET viewer · `uploads` GET viewer · `…/{id}/upload` GET viewer / POST admin · `telemetry/preview` GET ADMIN · `telemetry/config` GET ADMIN / PUT admin; no C1.5 divergence. **Custody as implemented**: `state.json` `{state pending|ready, approved_at, approved_by}` written first at create; NO `created_by`; approve is an UNCONDITIONAL overwrite by any admin including the creator (`ui_support.go:642-645`), re-approval rewrites the approver, no pending check, no fence; `approved_by` is never surfaced; an ABSENT `state.json` reads as READY (grandfather, `:594-598`); download audits BEFORE streaming; delete is `os.RemoveAll` with NO state/evidence/queue guard (a queued upload's entry is orphaned). **Create is SYNCHRONOUS in the handler** under `r.Context()` — no job id, no idempotency key, no in-flight lock (a lost response leaves an orphan pending bundle; a retry duplicates); the tgz is a plain `os.WriteFile`, the manifest (tmp+rename) is the commit marker; a crash between them leaves an invisible, never-evicted dir (SUSPECTED). Exports: passphrase 12–512 chars length-only, body-only, never persisted/logged/audited (`backupcrypt` CVRTBK01); sealed = exactly one of `recipient_name|recipient_public_key` (NaCl box; the appliance holds no private key); errors echo `err.Error()` text/plain; the whole tgz is buffered. **Upload consent POST writes `WriteHeader(202)` BEFORE `jsonOK`** (`support_upload_wire.go:170-171`) ⇒ NO `Content-Type`, sniffed `text/plain` — the exact `upstreamMutate` defect class; no test asserts it; the case bind before enqueue is BEST-EFFORT (state-write failure logged, upload proceeds, `:152-157`); queue states `queued|uploading|uploaded|deferred|rejected` (6 attempts, 2 s…10 min; 4xx ⇒ `rejected` terminal); worker 30 s tick, system-actor audits; `receipt.sig` is stored and displayed but NEVER verified. Stores under `<dataDir>/support/` (tmp+rename, no fsync, except `telemetry_config.json` via `fileutil.AtomicWrite`): `recipients.json` (name identity, public keys, rotate LWW), `debug_level.json` (TTL 1 m…24 h, 30 s auto-revert watchdog; L2 adds the runtime collector only, L3/L4 accepted but empty), `upload_config.json` + `telemetry_config.json` (RAW bearer credentials 0600, never echoed, preserve/replace/clear), TAC trust env/baked read-only (a malformed env answers 200 `{configured:false, error}`). Retention is the ONLY support setting on `configSurfaces` (AdminDurable-only, `:512-520,548`), persist-before-apply under the save lock, 409 `confirm_evict=<exact projected count>` recomputed server-side (+`X-Evict-Count`). No telemetry sender exists. Everything is node-local, outside export/import/rollback and outside backup. OpenAPI drift: bundle GET documented JSON vs gzip attachment + undocumented 409; approve/delete/debug-level DELETE documented 200 vs 204; create 507 and retention 409 undocumented. Legacy ceremonies: create/approve/delete `confirmAction`, consent `promptAction` (case id), retention 409 → `confirmAction`; debug set/clear, add recipient, upload/telemetry consent NONE; **rotate recipient native `window.prompt` (`:16592`), remove recipient native `window.confirm` (`:16609`), sealed export native `prompt` (`:16627`), passphrase native `prompt` (`:16651`)**; the 3 s tick refreshes `#support-uploads` only. Proofs: 34 `support_*_test.go` (~230 tests; `TestSupportBundle_PreviewGate` covers 409/204/403/grandfather/404 but NOTHING pins approve-twice, creator=approver, delete of pending/evidence, approve concurrency, the 202 Content-Type, or wildcard C2), `internal/support` (14), `internal/redaction` (18), `internal/supportupload` (7), `support_upload_gui_test.go` (2); NO uie2e, NO frontend. v2 today: none (`src/features/diagnostics` covers only the `/api/diagnose/*` registry; `apiDownloadRequest` exists in `client.ts:306-360`).
>
> **D8. FE-V36 Settings and configuration portability** (`ui_config.go`, `configversion.go`, `config_surfaces.go`, `admin_settings.go`, `ui_security.go:30-171`, `internal/alerts`). Routes: `/api/settings` GET viewer (no handler `requireRole`, noted) / POST admin · `settings/network` viewer/admin · `settings/log-level` viewer/admin · `session-secret` viewer/admin · `session-timeout` viewer/admin · `ui-allow-ips` ADMIN/admin · `syslog` ADMIN/admin (+`syslog/test` admin, unaudited) · `logger` GET viewer · `metrics-config` viewer/admin · `otlp` ADMIN/admin · `geoip` `MethodAny` viewer (a POST is served as a read) · `blockpage` viewer/admin (Domain `policy`) · `connlimit` viewer/admin · `alerts/webhooks` GET viewer, POST/PUT/DELETE OPERATOR (`?id=`), `/test` operator unaudited, `/history` viewer · `config/export` admin (audited read) · `config/import` admin · `config/versions` GET viewer / POST admin (`config.rollback` audited by the handler) · `config/diff` viewer · `logs/retention` viewer/admin (Domain `dashboard`; ALREADY v2 via 2A-M). No divergence; all documented; refusals text/plain except the four JSON cases. **Durability**: every settings POST in `ui_config.go` is apply → 2xx → `adminSettingsSave()` fire-and-forget with the error DISCARDED (`admin_settings.go:1163-1169`); `POST /api/session-secret` rotates in memory only (no `AdminSettings` field; restart reverts; the GET reports env presence only; rotation is a hard swap that kills every cookie including the caller's; no key-id); `POST /api/settings` (proxy-auth user/pass) never writes `ui_users.json` (`user:""` clears auth in memory); syslog disable, OTLP disable and metrics-token clear do NOT survive restart on a YAML/CLI-seeded node (`omitempty` + non-empty-only apply `admin_settings.go:491-505` + seed-before-load `main.go:206,212` vs `:240`; no sentinels); webhook `save()` errors are logged only; `PUT /api/blockpage` has no reset primitive (empty = 400). **Fencing**: NONE on any settings PUT/POST (the `precondition` + `?ifRevision=` mechanism of `saas_feed_api.go:215-247` / `ui_security_fence.go` is unused here); webhook PUT is a whole-object LWW. **Portability**: `POST /api/config/import?dryRun=1` previews everything but the digest (`importDigest`) binds ONLY the upstream sub-plan (`:951-953,:1135`) — every other section is re-applied against live stores at commit (TOCTOU); the legacy commit re-POSTs the same body with no digest; store `Save()` errors are swallowed and a rewrite-slice persist failure is log-only (`:1178-1180`) — NO import-level "not durable" state exists; 200 carries `cluster_publish_rejected` and `pac_profiles_not_applied` (the latter ignored by legacy). Rollback (`configversion.go`): serialized by `configRollbackMu`, NO fence on the current version; `dry_run:true` exists (`{status:"dry_run", version, warnings, changes, valid}`) but is unbound and NEVER called by legacy; success 200 `{status:"rolled_back", version, warnings, applied:true, stores_persisted:true, runtime_only_surfaces:[default_action, ip_filter_mode, ip_list, rate_limit_rpm, rate_limit_exempt]}`; partial durability is HTTP **500** `{status:"rolled_back_not_durable", applied:true, stores_persisted:false, persist_errors, error}`, which the legacy client renders as "Rollback failed" without refreshing although the running config changed; legacy never renders `runtime_only_surfaces`/`warnings`. `saveConfigVersion` is called by import and rollback only — no settings handler versions (network pinned deliberate). Secrets: session key never in `admin_settings.json` (synced as `SessionHMAC`, redacted for unenrolled callers); webhook secrets AES-GCM under `.alert_webhook_key`, `List()` blanks + `signing_degraded`, import re-adds hooks UNSIGNED; OTLP auth header and metrics token RAW in `admin_settings.json` (GETs return `hasAuth`+name / `tokenSet`); export carries `upstream_proxies_v2` + `upstream_credentials:"omitted"`; versions/diff (viewer) carry no secret material; there is no `/api/config/versions/{n}` route. Races on plain globals written by handlers and read on the request path (`metricsToken`, `trustForwardedHeaders`, `proxyExternalBaseURL`, `uiExtraSANs`, `globalSyslog`; SUSPECTED); `InitSyslog` never closes the previous writer; no self-lockout guard on `ui-allow-ips`; `settings/network` discards its publish error. Legacy ceremonies: session rotate T3 `ROTATE` (`:10613-10640`); allow-IPs T3 `RESTRICT` / `OPEN` (`:10677-10704`); import dry-run → `confirmAction` `Replace|Import` (no typed word); rollback `confirmAction` (no dry-run); webhook delete T1; syslog/OTLP disable, metrics clear, block-page reset (client fiction), conn-limit, proxy-auth, network, log-level NONE; `saveOTLP` throws `ReferenceError: auth` after a SUCCESSFUL save (`:10908-10932`). Proofs: `config_surfaces_test.go` (12 walls), `configversion_test.go` (14), `configversion_rollback_durability_test.go`, `configversion_{category_groups,dpi_bypass,rate_limit_exempt,url_categories}_test.go`, `dc_final*_test.go`, `config_export_taxonomy_test.go` (6), `config_import_preview_test.go` (5), `alerts_event_rename_import_test.go`, `alert_webhook_signing_test.go`, `ui_alerts_unauth_test.go`, `admin_settings_*_test.go`, `metrics_token_startup_test.go`, `settings_network_no_versioning_test.go`, `apicontract_*`; `internal/alerts` suites; uie2e `ui_configversion_e2e_test.go` (rollback cross-plane), `ui_import_preview_e2e_test.go`, `ui_dialogs_e2e_test.go`; no direct Go test for the session-secret/syslog/OTLP/metrics-config/connlimit/blockpage handlers. v2 today: `src/api/retention.ts` (2A-M), `src/api/policyAuth.ts:418-440` (settings read + default-auth-outcome, 2C), `src/api/auth.ts` network read.
>
> **D9. FE-V07 … FE-V15 MCP** (`ui_mcp.go`, `ui_mcp_rollout.go`, `ui_mcp_tooltrust.go`, `mcp_canary_attestation.go`, `mcp_rollout*.go`, `mcp_distribution*.go`, `internal/mcp/{adminapi,approval,rollout,cpdp,management,tooltrust}`; meta `:927-1016`, 29 paths, all documented, no `{param}`, no C4 divergence; `policy-simulate` (operator) and `rollout/scope/validate` (viewer) are `Mutating:true` but pure). **There is NO server-side ticket model**: the "tickets" in the parity rows and D3 are the legacy client's in-page request counters (`mcpxDlg.ticket` etc., `index.html:20050,20448,20825`); "supersede" is client-side; the server mints no operation id, no idempotency key and no fence token for any MCP mutation (the only ids are `appr_<32hex>` request ids and tool-trust `approval_id`s). **Stubs on this build**: `rollout/transition` is always 403 `rollout_production_locked` or 409 (`distribution_not_configured` / `shadow_execution_dependencies_not_configured`; `base_revision` decoded and never read), `rollout/scope` PUT always 409, `/api/mcp/rollback` always 409 (`reason` unused; no current-hash fence), `publication-decision {action:"publish"}` always 503; approve/reject (publication AND operational) are wired to `mcpDisabledCommitter` (`ui_mcp.go:104`) so EVERY decision answers 503 `event_durability_degraded` before any state change; no `publication.Coordinator` is constructed in production; the ack read model is always `configured:false`. **Real, durable, node-local mutations**: `rollout/emergency` (disable/clear, idempotent, monotonic `killGen`, persist-before-ack with the in-memory disable retained on persist failure → 500 JSON `{killed, persisted:false}`; `actor = r.RemoteAddr`, NOT the admin identity), `rehearse-rollback` (+`-authoritative`; build-bound evidence, 409 on a non-unique build), `canary/shadow-exit-review` POST/DELETE (`AttestedBy = sessionAdmin`, build-bound, POST last-writer-wins), `tool-approvals` POST (operator; fingerprint + `catalog_revision`) and `tool-approval-decision` (admin; the LIVE path enforces four-eyes on the canonical `sess.Sub`, idempotent). **In-memory-only mutations**: `config` PUT (`adminapi/config.go:194-202`, answers `stored:true`, no revision fence, lost on restart) and `publications` POST (pending map; NOT idempotent — a retry duplicates; fence `expected_base == CurrentRevision`, `policy_revision == base+1`; management 403). Four-eyes identity for publications/operational approvals is the `auditActor` string `"<sub>@<ip>"` (`ui_mcp.go:601,647,722`), contradicting `approval.go:80-83`; the operational-approval TOCTOU fence is unarmed (`Revisions{}` at `:727`). All refusals are `text/plain` bare codes via `mcpErr` (`self_approval`, `stale_revision`, `expired`, `stale_base`, `not_approved`, `binding_mismatch` all fall to the 400 default — the legacy client sniffs body text `:20989`). Audit: publication create/approve/reject after success; rollback/transition/scope audited BEFORE their unconditional 409 (intent, not effect); emergency audited before the persist verdict; rehearsal identical detail on success and failure; attestation distinguishes outcomes. Persistence: `mcp_rollout_state_{gateway,management}.json`, rehearsal record, `mcp_shadow_exit_review.json`, `mcp_tooltrust/approvals.json`, DP envelopes under `mcp_distribution/` (all AtomicWrite) — NONE backed up; no MCP object on export/import/rollback (only two wire fields in `configSurfaces`). No timers in legacy (on-view loads: overview 3 GETs, rollout 5). Restart: `initMCPRollout` clamps executing modes; `initMCPDistribution` → `reconcileRolloutWithAppliers` (the operator doc names it `reconcileRolloutWithDistribution` — drift). Legacy danger dialog (`:20039-20240`): typed phrases `DISABLE|CLEAR <GATEWAY|MANAGEMENT>`, `PROMOTE <CAP>` (promotion only), `ROLLBACK <CAP>` (disabled without `previous_hash`); double-submit guard `:20187`; Esc blocked `:20170`; UNKNOWN copy `:20215` ("Network error - the action state is UNKNOWN. Refresh the rollout status to see the real state; do not assume it did or did not take effect."); Retry re-POSTs with a new counter; native `window.confirm` on capability switch `:21584`; vestigial `X-CSRF-Token` on 9 sites; GAP-6 `viewMeta['mcp-rollout']` missing. Proofs: `ui_mcp_test.go` (7), `ui_mcp_ux4_test.go` (10), `mcp_ux5/6/7_test.go`, `ui_mcp_tooltrust_live_test.go`, `mcp_tooltrust_test.go` (30+), `mcp_canary_attestation_test.go` (12), `mcp_distribution_transaction_test.go` (10), `mcp_rollout_durable_test.go` (23), the `internal/mcp` adminapi/approval/rollout/cpdp/management/tooltrust suites; uie2e `ui_mcp_ux4_e2e_test.go` (typed-phrase gating incl. case mismatch → no POST, forced viewer POST → RBAC, cancel-mid-flight reconcile) + `ux5/6/7/8` + `ui_mcp_ux_e2e_test.go`; NO frontend (types only).
>
> **D10. FE-V04/FE-V05 Decryption exclusions + health** — MIGRATED (2E-B), see §A. Routes: `GET /api/decryption/health` viewer; `GET/PUT /api/decryption/redaction` viewer/admin (posture PUT fenced by body `ifRevision = contentSecRevision("dec-redaction")`; rotation REQUIRES `operation_id` + `ifRevision`, receipts idempotent, T3 `ROTATE` with a write-before-dispatch recovery marker and LANDED/NOT-LANDED/AMBIGUOUS classification); `GET/DELETE /api/decryption-exclusions` viewer/operator (DELETE unfenced by design — volatile cache; v2 T2 dialogs report `removed:false` truthfully); `GET/PUT …/tunables` viewer/admin (`?ifRevision= contentSecRevision("autoexclude-tunables")`, derived from the SAME stats snapshot as the values; T2 only when relaxing). Tunables + redaction are AdminDurable-only rows (`config_surfaces.go:483-509,544-545`), persist-before-apply; the cache is volatile and labelled so. Proofs: `decryption_2eb_red_test.go` (11), `decryption_2eb2_red_test.go` (11), `autoexclude_tunables_api_test.go` (11), `decexcl_tunables_gui_test.go` (5, legacy markup), `decryption_health_api_test.go` (4), `decryption_redaction_test.go` (5); vitest 6 files / 44 cases; `frontend/e2e/decryption-2eb.spec.ts` (5) + `decryption-2eb-lifecycle.spec.ts` (3). Residue (presentation only, no backend blocker): health `sessions.total`, per-outcome share, `surge_total` (absent from the decoder), a whole-window trend; health → Traffic drill-down needs `dec_outcome`/`dec_fail_category` filters in the v2 Traffic query model (the backend accepts them, `ui_config.go:307-310`); exclusions table Rules (`scope_rule_counts`) / Clients (`client_count`) / Learned (`learned_at`) columns + the provable-OFF headline; an explicit Reset-to-defaults (zeros PUT under the fence, T2 only if relaxing); retire `TestDecTunablesGUI_PanelAndWiringRender` at FE-8. Housekeeping: the three audit-event names in `openapi.yaml` (`:3237`, `:6011`, `:8099`) and the open `DecryptionExclusions`/`TunablesPatch` schemas.
>
> **E. Backend contract blockers (consolidated; each must be fixed — RED-first at the exact predecessor — BEFORE the React write surface that depends on it; UI copy is never a remedy).**
> - **B-SEC-C2 (P0, FE-6H precondition, FE-8 cutover precondition):** land `{param}`-aware C2 metadata matching so the ten Support wildcard routes are enforced; extend the C2 suite with wildcard coverage.
> - **B-REF (P0, every write slice):** one typed refusal dialect per operation family — contracted status + `{error, code, …typed allowlisted facts}` JSON, never server prose — on IdP, Administrators, CA/certs/OCSP, Cluster, Releases, Support, Settings/portability and MCP; the `text/plain` `http.Error` shape survives only for legacy callers where a method/route has no v2 consumer. The shared fence conflict stays the Batch 2 `409 {error, currentRevision, yourRevision}`.
> - **B-IDP (P0, FE-6A):** (1) compile OUTSIDE the registry write lock (compile-then-swap, as `ReplaceAll` already does); (2) per-profile `revision` fence on PUT/DELETE, PUT no longer creates (404 on unknown id), 409 `stale`; (3) reference guard on DELETE (`409 referenced_by`); (4) `has_secret`-class indicators for OIDC `clientSecret` and SAML inline XML; (5) the legacy-LDAP cutover exposed as an explicit, ceremonied, admin-only transition, never a side effect of enable; (6) empty-registry propagation to DPs (wire-wipe capable `idp_profiles`, or an explicit generation); (7) `idp_profiles.json` quarantine-on-corrupt instead of boot-fatal, and inclusion in the backup manifest (or an explicit restore-truth row); (8) document `/api/idp/{id}` + `/groups` and type the `oidc`/`saml` sub-configs, or hand-author the decoder with a pinned shape test.
> - **B-ADM (P0, FE-6A):** (1) `SetUIUser` preserves TOTP material on a password set (or refuses without an explicit `clearTotp`); (2) durable-or-nothing on users/change-password/lockout-clear (persist failure ⇒ non-2xx and memory rolled back — the `apiSetupComplete` shape); (3) role change and password change revoke the affected user's sessions (or the middleware re-reads the role from the roster); (4) last-admin demotion refused; explicit create vs update (409 on create of an existing user); (5) GAP-2 stays DESCOPED (no TOTP enrollment screen; never faked).
> - **B-CA (P0, FE-6B):** (1) rotation token bound to the issuing actor/session AND the current CA fingerprint, keyed by a client-supplied `operationId`, single-use, with structured `409 stale` / `410 expired` refusals and a success body that ALWAYS states `persisted`; a repeat of the same `operationId` replays the recorded outcome (never a second root); (2) `/api/ocsp` POST persisted (AdminDurable row + sentinel) or made read-only in v2; (3) `persisted:false` on rotate/upload declared as a DEGRADED SUCCESS state in the contract (the live signer already changed); (4) typed `CAStatus`/rotate/upload schemas; (5) viewer-role `/api/ca/status` stops embedding the bundle path and raw errors (fixed detail strings, cause in the log — the `/ready` rule); (6) UI-cert upload gains a delete/revert primitive and a restore-truth row (not backed up); (7) `settings/network` stops claiming runtime regeneration.
> - **B-CLU (P0, FE-6C read precondition + FE-6D):** (1) `deploy_cmd` (HA token) removed from the viewer GET — a write-once admin-only reveal at enable time, or an admin-only endpoint; (2) every `/api/cluster/*` HTTP mutation gated on `WriteAllowed()`/lease authority with a structured 409 `not_write_authoritative` (standby, fenced ex-leader, DP); (3) node-groups/bandwidth persist-before-respond AND publish to the fleet; (4) GUI "Enable Control Plane" durable (or the API declares it session-scoped and v2 says so); refuse mode change on a `data-plane` node; (5) `cluster.json` mutations persist-before-swap with a document `revision` fence; (6) token DELETE audited; `saveHAConfig` errors surfaced; (7) `ha_config.json`/`cp_config_version.json`/`dp_last_seen_epoch.json` on the backup manifest or an explicit restore-truth row; (8) lease posture on `/api/cluster/status.ha` (one read for one posture) or a documented two-read rule.
> - **B-REL (P0, FE-6G):** (1) durable dispatch record under `<dataDir>/release_dispatch/` (persist-before-`Apply`, re-hydrated at boot, `Resume` driven from it), so `phase:none` after a restart is impossible for a real dispatch; (2) an explicit `unknown` terminal class distinct from `failed_needs_attn` for CP death / `watch_timeout` / dropped in-flight resume; (3) dispatch fenced to catalog identity — the body carries `catalog_version` + `expected_pinned_ref` (or a `plan_digest` from a preview), 409 `catalog_changed` when the plan differs; (4) resume answers only after acquisition (202 with the record, 409 `in_flight`/`no_resumable_op`); (5) `BackupSkipped` and `compose_override_configured` surfaced in the reply and status; (6) mixed text/plain refusals and raw agent/transport strings removed from viewer-visible bodies; (7) OpenAPI documents the real 202/404/409/502/503 matrix and types `DispatchStatus`/`ReleaseCurrent`.
> - **B-SUP (P0, FE-6H):** (1) B-SEC-C2; (2) `state.json` gains `created_by`, `revision`; approve requires `expected_state:"pending"` (409 `already_approved` carrying `approved_by/at`), refuses `creator == approver` (`409 self_approval`), surfaces `approved_by/at` on list + manifest; (3) the consent 202 sets `Content-Type` BEFORE `WriteHeader` (pin it with a red test, as `upstream_mutation_content_type_red_test.go` does); (4) create takes a client `requestId` (dedup ring ⇒ the same bundle id on retry) or returns the id in a durable intent record; (5) delete refuses pending/evidence/queued bundles without an explicit `force` + typed ceremony and reconciles the upload queue; (6) case bind before enqueue is durable-or-refuse; (7) OpenAPI custody responses corrected (gzip + 409, 204s, 507, retention 409); (8) `receipt.sig` labelled "recorded, unverified"; support tree restore-truth row.
> - **B-SET (P0, FE-6E):** (1) session-secret rotation persisted (AdminDurable Sensitive + sentinel) with a non-secret `keyId`, or declared env/YAML-only and READ-ONLY in v2 — a v2 rotate ceremony is not offered until one of the two is true; (2) `POST /api/settings` writes `ui_users.json` durable-or-nothing; (3) every settings mutation moves to `saveAdminSettingsWithOverrides` with `precondition(?ifRevision=)` + `applyOnSuccess` (persist-before-apply, structured 409/5xx, no fire-and-forget); (4) `*Saved` sentinels for syslog/OTLP/metrics-token so a GUI disable/clear survives a seeded restart; (5) webhook persist errors surfaced; per-hook `revision`; (6) `ui-allow-ips` self-lockout refusal; (7) block-page reset primitive; (8) `InitSyslog` closes the previous writer; the plain-global races resolved (atomic/mutex) — SUSPECTED class, prove first.
> - **B-PORT (P0, FE-6F):** (1) whole-file `importDigest` over the dry-run plan (the `upstreamImportPlanned` precedent extended), 409 `import_stale`; (2) an import-level durability report (`stores_persisted`, `persist_errors`, per-section `applied|skipped|not_durable`) — never a bare 200 over a swallowed `Save()`; (3) rollback fenced on `expectedLatestVersion` + the current policy content hash, with a mandatory bound `dry_run` (`rollbackDigest`); (4) the `rolled_back_not_durable` state keeps its distinct status but is a CONTRACTED partial-success shape the v2 client renders as "applied, NOT durable", never "failed".
> - **B-MCP (P0, FE-6J/6K):** (1) stable principal identity for four-eyes and for the emergency actor (canonical `sess.Sub`, the `mcpLivePrincipal` precedent), never `sub@ip`/`RemoteAddr`; (2) `config` PUT durable (AtomicWrite + revision fence) or declared runtime-only in v2; (3) publications POST idempotent on `(tenant, candidate_hash, expected_base)`; (4) rollback/transition/scope audit AFTER the outcome; rehearsal detail distinguishes success from failure; (5) MCP durable files on the backup manifest or a restore-truth row; (6) the signed-path actions (transition, scope PUT, rollback, publish) and the approval committer remain stubs — v2 renders their REFUSED posture from the server facts and offers NO ceremony until a coordinator + operation id + fence + 202 lifecycle exist (owner decision, outside FE-6); (7) `Mutating:false` (with note) on `policy-simulate` and `scope/validate` or a client special-case.
> - **B-DOC (P1, ride-along per slice):** align `x-culvert-audit-event` names and danger levels with the emitted actions on each surface (pin with a presence+name test), and declare the opaque schemas; regen `make api-bundle` + `types.gen.ts` per the four-place convention.
>
> **F. Decomposition — assessment of the proposed twelve slices (APPROVED WITH REVISIONS).** Three structural rules govern every slice and settle the "no unsafe intermediate commit" requirement: **(R1) backend-truth first** — each slice with a write surface opens with a `.0` sub-slice that lands its B-* fixes RED-first on the exact predecessor and regenerates the contract artifacts, then a `.1` read surface, then a `.2` write surface; a `.2` never ships while its `.0` is open; **(R2) read before write** — a read-only React surface may ship only when every secret field is refused by its decoder AND the backend no longer serves that secret on the read model (a decoder is defence-in-depth, not the remedy); **(R3) ceremony travels with the mutation** — no commit exposes a destructive mutation without its tier (existing T3 words verbatim, the two NEW ceremonies included — see §H). Revisions to the proposal:
> - **FE-6A Identity Providers + Administrators — APPROVED, ordered 6A.0 (B-IDP + B-ADM + B-REF for both) → 6A.1 (IdP list/detail read, hand-authored decoder; Administrators list + lockouts read) → 6A.2 (IdP create/update/delete/test/discover/legacy-import with write-only secrets + explicit-clear semantics re-expressed as component tests; Administrators create/update/delete/unlock/change-password; the LDAP-cutover ceremony). GAP-2 descoped.
> - **FE-6B Certificates + CA lifecycle — APPROVED, 6B.0 (B-CA + B-REF) → 6B.1 (`/api/ca/status`, `/api/ca-cert` JSON+PEM download, key-provider, OCSP read, UI-cert posture) → 6B.2 (two-phase rotate with the token contract, cache-clear, OCSP toggle, cert upload with its T2 ceremony, UI-cert delete).** The rotate ceremony is D2-exact (client never invents the token) PLUS the D6 unknown-state marker pattern of `rotationRecovery.ts` re-used for the CA operation id.
> - **FE-6C Cluster read — APPROVED, but NOT before B-CLU(1) lands (the HA token must leave the viewer GET at the source): 6C.0 (B-CLU(1)(8) + typed `ClusterHA`/`ClusterTokens`/… schemas) → 6C.1 (topology, status, HA + lease posture derived from `status.role` + `ha.role`, convergence, metrics, rate-limits, audit, revocations, rotation, CA info, node-groups/bandwidth read, tokens hash-only).**
> - **FE-6D Cluster mutations, enrollment, HA — APPROVED, 6D.0 (B-CLU(2)–(7) + B-REF) → 6D.1 (enrollment token generate with once-only display + bootstrap command, token delete, revoke, drain, labels, node-group + bandwidth CRUD with fleet publish) → 6D.2 (Enable CP `ENABLE`, Enable HA `ENABLE`, Promote `PROMOTE`, cluster-CA import `IMPORT` — the four T3 ceremonies word-for-word, each with its unknown-state read-back).**
> - **FE-6E Core appliance settings — APPROVED with the IA §5 mapping: General (log level, logger/GeoIP read, proxy-auth), Access & Sessions (session timeout, session-secret rotate `ROTATE`, admin IP allowlist `RESTRICT`/`OPEN`, network & trusted proxies), Integrations (syslog + test, alert webhooks + test + history, Prometheus token, OTLP), plus block page + connection limit; retention stays under Monitor (2A-M). 6E.0 (B-SET + B-REF) → 6E.1 (reads) → 6E.2 (writes, each fenced; session-secret rotate offered only once B-SET(1) resolves it as persisted or as read-only).**
> - **FE-6F Configuration portability — APPROVED, 6F.0 (B-PORT + B-REF) → 6F.1 (export with the registry disclosure and `upstream_credentials:"omitted"`, versions list, diff) → 6F.2 (import dry-run → digest-bound commit with per-section effect table, replace-vs-merge; rollback bound dry-run → fenced commit rendering `runtime_only_surfaces`, warnings and the `rolled_back_not_durable` partial state distinctly).**
> - **FE-6G Release catalog + dispatch — APPROVED, 6G.0 (B-REL + B-REF) → 6G.1 (catalog, trust/verify posture, `available:false` variants, current, backups list, dispatch status incl. `unknown`) → 6G.2 (catalog refresh; dispatch with the NEW T3 ceremony — moved INTO FE-6 from FE-7, see §H — bound to catalog identity, `pre_backup`/`passphrase_ref` env-ref only, forced status polling, resume-by-record, "Unknown maintenance agent" copy; a fake-agent browser fixture derived from `e2eMaintAgent`).**
> - **FE-6H Support — APPROVED, 6H.0 (B-SEC-C2 + B-SUP + B-REF) → 6H.1 (status, bundle list with custody facts, manifest, redaction report incl. the role-conditional preview, validate, exports, recipients, retention, debug level, upload/telemetry config, TAC trust, uploads) → 6H.2 (create → approve (four-eyes, expected-state) → download plain/encrypted/sealed with the IN-APP masked passphrase and recipient dialogs (contract D5/B4 — these native-dialog replacements are FE-6, not FE-7), delete with guard, recipient add/rotate/remove, debug-level set/clear, retention with the projected-eviction confirm, upload consent, telemetry consent).**
> - **FE-6I MCP read + management access — APPROVED as proposed** (overview, health, servers, tools, decisions + explain, policy read, publications/approvals/tool-approvals read, distribution + acks, rollout + scope + evidence read, executions, upstream-health, management-access visibly read-only, shadow-exit-review read, plus the two pure POSTs `policy-simulate` and `scope/validate` as explicit-run reads).
> - **FE-6J MCP policy, approvals, settings — REVISED into 6J.0 (B-MCP(1)(3)(7) + B-REF) → 6J.1 tool-trust write (request, approve/reject/revoke; four-eyes on the canonical subject; GET-recoverable) → 6J.2 policy candidate workflow (draft in memory, validate/simulate/compare, create publication request, never persisted client-side) → 6J.3 approvals + config: RENDERED AS SERVER-REFUSED POSTURE ONLY (503 durability-degraded, 409 not-configured) with NO ceremony until the committer/coordinator exists; `config` PUT offered only after B-MCP(2).**
> - **FE-6K MCP rollout, emergency, rollback — REVISED into 6K.0 (B-MCP(1)(4)(5) + B-REF) → 6K.1 node-local durable actions with the D3 danger dialog verbatim (emergency disable/clear `DISABLE|CLEAR <CAP>`, rehearse-rollback ×2, shadow-exit-review attest/revoke) → 6K.2 signed-path actions (transition `PROMOTE <CAP>`, scope PUT, rollback `ROLLBACK <CAP>`) RENDERED AS REFUSED POSTURE from server facts (`production_locked`, `distribution_not_configured`, no rollback target), no ceremony armed until the coordinator + operation id + fence + 202 lifecycle ship (outside FE-6).**
> - **FE-6L Decryption + FE-6 closure — REVISED: FE-V04/V05 are already migrated, so FE-6L is (a) the parity-matrix + plan-objective correction, (b) the D10 presentation residue, (c) the FE-6 closure qualification (full Playwright journeys across every FE-6 surface, dist regeneration, parity 38/38 or descoped-with-sign-off, contract §7 accounting refresh).**
> - **Dependency graph.** `6A`, `6B`, `6E`, `6F`, `6G`, `6I` are mutually independent chains. `6C.0 → 6C.1 → 6D`. `6E.0 → 6F.0` share `admin_settings.go`'s persist-before-apply refactor (6E.0 lands it; 6F.0 consumes it). `6H.0` depends on B-SEC-C2 (a standalone security PR that may land first and independently). `6I → 6J → 6K` (the MCP read model and refusal dialect are shared). `6L` depends on ALL. Recommended order: SEC-C2 and 6I first (lowest blocker surface, highest read value), then 6C.0/6C.1, 6B, 6A, 6E, 6F, 6G, 6H, 6D, 6J, 6K, 6L. Every `.0` is backend-only with RED proofs and contract regeneration; every `.1`/`.2` regenerates `frontend/dist` in its own commit.
>
> **G. Binding FE-6 contract (C1–C15). Deviation needs an amendment here.**
> - **C1 — One status + refusal vocabulary per operation family.** A mutation answers exactly one of: `2xx` + action-specific evidence (`entry`/`revision`/`operationId`/`persisted:true`/`deleted:true`); a contracted refusal `{error, code, …typed facts}` with its documented status (`400 invalid_*`, `403 role`/`not_write_authoritative`, `404 vanished`, `409 stale|conflict|<state-code>`, `410 expired`, `412/428 precondition_required`, `503 <subsystem>_unavailable`); or `5xx` with `{error, code:"persist_failed"|"outcome_unknown", detail}`. The client renders ONLY allowlisted typed facts, never server prose. An unverifiable 2xx (media type, JSON, evidence) is UNPROVEN: ceremony closes, page latches, one authoritative read-back, never a retry (the 2F-F rule).
> - **C2 — Server-owned identity and fencing tokens.** Every fenced write asserts a server-minted token the browser never reproduces: document/entry `revision` (IdP, cluster.json, recipients, webhooks, bundles), content hash `?ifRevision=` (settings rows via `precondition`), `expectedFingerprint` (CA rotate, cluster-CA import), `catalog_version`+`expected_pinned_ref`/`plan_digest` (dispatch), `importDigest`/`rollbackDigest` (portability), `expected_state` (approve). Mismatch ⇒ the structured 409 with the current value; absent ⇒ 428 carrying it; never a silent overwrite.
> - **C3 — Persist-before-publish.** A 2xx means the durable write landed in the owning store before the in-memory swap (or, where the runtime must change first — CA install, emergency kill — the reply states `persisted:false` as a contracted DEGRADED SUCCESS). Fire-and-forget saves are retired on every FE-6 write path.
> - **C4 — At-most-once for asynchronous operations.** Dispatch (CP record + `idempotency_key`), CA rotate (`operationId` + replayed outcome), bundle create (`requestId`), publications (candidate-hash dedup) and consent (queue-state idempotency) replay the recorded outcome on repeat; nothing executes twice.
> - **C5 — Lost-response recovery and explicit UNKNOWN.** Every asynchronous or non-idempotent ceremony writes a non-secret, subject-bound, auth-boundary-cleared recovery marker BEFORE dispatch (the 2E-B/2F-E pattern) and resolves it ONLY from server evidence (durable dispatch record, CA fingerprint + operation replay, bundle id, approval state); an unresolvable marker renders UNKNOWN with the exact copy family already used ("the action state is UNKNOWN …"), never success and never failure; a transport death requires the operator's Refresh.
> - **C6 — Config import dry-run digest binding.** The dry-run reply carries a deterministic `importDigest` over the complete plan; the commit requires it and is revalidated under the save lock (409 `import_stale`); replace-vs-merge is part of the digest; the commit reply is a per-section effect + durability table.
> - **C7 — Partial failure and `runtime_only_surfaces` truth.** Rollback and import replies enumerate applied / skipped / not-durable / runtime-only surfaces from the registry; the v2 client renders each as a distinct state (never a generic toast) and the `rolled_back_not_durable` partial state as "applied, not durable — repair storage" with the version list refreshed.
> - **C8 — Release dispatch identity, resume, degraded states.** `dispatch_id` + `op_id` + `idempotency_key` durable on the CP; `phase ∈ none|dispatched|terminal|unknown`; resume answers only after acquisition; `available:false` reasons, `BackupSkipped`, `compose_override_configured` and the agent-unknown 404 are rendered as facts; the dispatch T3 word is the exact `release_id` (server-named, echoed from the bound plan).
> - **C9 — Support custody.** `pending → approved(ready) → downloaded|exported|uploaded` with `created_by`, `approved_by/at` durable and surfaced; approve fenced on `expected_state` and refusing `creator == approver`; download/export only from `ready`; passphrases and recipient keys live only in component state for the request (masked in-app dialogs; `gcTime: 0`); Blob URLs revoked after use and at the auth boundary; `receipt.sig` shown as recorded-unverified.
> - **C10 — Write-only secrets.** IdP client secret / SAML XML / LDAP bind password, certificate private keys, HA/enrollment tokens (write-once reveal), passphrases, recipient keys, OTLP auth header, metrics token, webhook secrets are never read back, never echoed, never stored in the browser; explicit-clear is an explicit user action re-expressed as component tests; a read model that still carries a secret (HA `deploy_cmd`) is REFUSED by the decoder and its fix is a `.0` precondition.
> - **C11 — MCP authority.** Four-eyes = canonical subject inequality enforced server-side; emergency/rehearsal/attestation carry the admin identity; the danger dialog (typed phrase, double-submit guard, Esc blocked while committing, UNKNOWN copy) migrates intact for the node-local actions; signed-path actions and the approval committer render server-refused posture and arm no ceremony.
> - **C12 — Node-local vs cluster-synced labels.** Every FE-6 surface labels each object with its scope from §C (node-local / cluster-synced / CP-only / runtime-only) and every write on a non-write-authoritative node is refused server-side (409) and withheld client-side.
> - **C13 — Audit and redaction.** Every mutation audits AFTER its durable outcome with a bounded detail; secrets never appear in audit before/after diffs; refusals audit nothing except where the legacy contract already does; viewer-role read models carry fixed detail strings, never paths or raw errors.
> - **C14 — Backup, restore, downgrade truth.** Each FE-6 surface states what its objects do under backup/restore (§C manifest facts) and `--prepare-downgrade`; a restore that cannot carry a secret boots into a DISTINCT durable state (`requiresReplacement`, `signing_degraded`, `unusable`) rendered as such.
> - **C15 — Route/OpenAPI accounting.** Any new route follows the four-place convention (`register*Routes`, `uiRoutes`, `route-classification.yaml`, OpenAPI) with `x-culvert-audit-event` equal to the emitted action and a typed schema; the route pin and §7 accounting table are refreshed in the same commit.
>
> **H. Ceremonies: FE-6 (functional parity) vs FE-7 (global hardening sweep).** FE-6 ships, word-for-word: session key `ROTATE`; admin IP allowlist `RESTRICT`/`OPEN`; cluster Enable CP `ENABLE`, Enable HA `ENABLE`, Promote `PROMOTE`, CA import `IMPORT`; the two-phase Root-CA rotation (server token, D2); MCP `DISABLE|CLEAR <GATEWAY|MANAGEMENT>` and the D3 dialog semantics for the node-local actions; the T2 confirms for delete/evict/clear families; the projected-eviction retention confirm; and — moved INTO FE-6 because R3 forbids shipping the mutation without its tier — the two NEW ceremonies contract D4 assigned to FE-7: **release dispatch T3** (word = the bound `release_id`) and **cert upload T2** (impact copy naming the persisted target). The Support native `prompt`/`confirm` sites (passphrase, sealed recipient, recipient rotate/remove) are replaced by in-app masked dialogs IN FE-6H (contract D5/B4; the FE-6 DoD already names the passphrase dialog); the MCP `window.confirm` on capability switch is replaced in FE-6J. **Reserved for FE-7:** the mutation-suite proofs per ceremony (Enter cannot confirm, double-submit, stale token/ticket, failure injection ⇒ UNKNOWN rendering), the cross-surface `ConfirmationDialog` audit against contract §6/§8, any ceremony tier UPGRADE beyond parity (e.g. promoting IdP delete or cluster token delete to T3), and the retirement of the legacy dialog primitives with the legacy UI at FE-8.
>
> **I. RED-before matrix (each sub-slice must reproduce its rows on the exact predecessor before fixing; verdicts recorded in the slice record).**
> - **6A.0:** R1 IdP `Upsert` blocks a concurrent `RouteByDomain` reader for the discovery timeout · R2 `PUT /api/idp/{id}` creates on an unknown id · R3 concurrent PUT/DELETE resurrects a deleted profile · R4 DELETE of a provider referenced by an SSORequired rule succeeds · R5 deleting the last profile never reaches a DP · R6 OIDC secret configured-state indistinguishable from none on GET · R7 enabling LDAP retires legacy LDAP durably with no ceremony · R8 corrupt `idp_profiles.json` is boot-fatal · R9 `SetUIUser` with a password drops TOTP · R10 users POST/DELETE/change-password answer 2xx on a failed `SaveUIUsersFile` · R11 demoted admin keeps admin authority until TTL · R12 last admin demoted to viewer · R13 POST users overwrites an existing user silently · R14 every refusal on both surfaces is `text/plain`.
> - **6B.0:** R15 second admin's probe overwrites the first token · R16 token confirmed by a different session than the prober · R17 token survives a CA change between probe and confirm · R18 garbage body re-probes · R19 re-probe + confirm after a lost response mints a second root · R20 success body omits `persisted` · R21 OCSP POST `ok:true` lost on restart · R22 viewer `ca/status` embeds the bundle path · R23 expired custom CA installs live · R24 `settings/network` claims regeneration.
> - **6C.0 / 6D.0:** R25 viewer GET `/api/cluster/ha` returns the HA token · R26 standby/fenced node accepts `POST tokens|revoke|labels|drain|node-groups|bandwidth|ca` · R27 node-group/bandwidth 2xx on a persist failure · R28 node-group change absent from the next DP snapshot until an unrelated publish · R29 GUI-enabled CP reverts on restart · R30 `data-plane` node becomes CP · R31 token delete 500 with the token gone from memory · R32 revoke 500 with the CRL already appended · R33 token DELETE unaudited · R34 `saveHAConfig` failure invisible · R35 lease fields absent from `/status.ha`.
> - **6E.0:** R36 session-secret rotate lost on restart; GET reports env only · R37 `/api/settings` credentials memory-only · R38 any settings POST 2xx with the save goroutine failing · R39 syslog/OTLP disable + metrics clear revert on a seeded restart · R40 two admins' network POSTs — loser silently overwritten · R41 webhook save failure invisible · R42 allow-IPs locks the requester out · R43 blockpage cannot reset · R44 `saveOTLP` legacy ReferenceError (documentation control).
> - **6F.0:** R45 dry-run preview at T0, live stores changed at T1, commit applies the T1 truth under the T0 preview · R46 import 200 over a swallowed store `Save()` · R47 rollback with no fence against a newer version · R48 rollback dry-run unbound from commit · R49 `rolled_back_not_durable` rendered as failure (documentation control) · R50 `pac_profiles_not_applied` ignored.
> - **6G.0:** R51 dispatch record gone after CP restart, `phase:none` · R52 CP death mid-op collapses to `failed_needs_attn`/none · R53 catalog swapped between preview and POST, dispatch proceeds · R54 channel target re-resolved to an unseen release · R55 resume 202 with a silently dropped in-flight rejection · R56 `BackupSkipped` invisible · R57 raw agent error in a viewer body · R58 dispatch without ceremony (documentation control).
> - **6H.0:** R59 wildcard support route skips C2 · R60 creator approves own bundle · R61 re-approve rewrites approver · R62 consent 202 has no Content-Type · R63 create retry duplicates the bundle · R64 delete of a pending/evidence/queued bundle · R65 case bind fails, upload proceeds · R66 bundle GET 409 undocumented / 204 vs 200 drift · R67 native prompts (documentation control).
> - **6I:** none (read-only) beyond decoder shape pins.
> - **6J.0 / 6K.0:** R68 four-eyes compares `sub@ip` · R69 emergency actor is `RemoteAddr` · R70 `config` PUT `stored:true` lost on restart · R71 publications POST duplicates on retry · R72 rollback/transition/scope audited before the 409 · R73 rehearsal audit identical on failure · R74 `self_approval` mapped to 400 with a bare body · R75 pure POSTs flagged mutating.
> - **6L:** R76 parity rows FE-V04/05 stale (documentation) · R77 `surge_total` dropped by the decoder · R78 legacy drill-down filters absent from v2.
>
> **J. Deferrals and non-goals (recorded, not solved by FE-6).** TOTP enrollment (GAP-2); SETUP-OPEN-MODE (GAP-9); SEC-HSTS, SEC-PROXY, SEC-PATCH (separate PRs); MCP coordinator / signed-path lifecycle / approval committer (owner decision); a CP-level release rollback-to-previous, remote (non-`local`) agents and agent mTLS; fleet dispatch; secret-inclusive backups; a SAML SP key that survives restart; encrypted-at-rest IdP profiles; cluster-synced support/MCP/CA state; a telemetry sender (Slice 3); the E3 Docker reconcile boot hook; a persistent-history export; the legacy `static/index.html` fixes (`saveOTLP`, `loadCACertInfo` escaping, `forceRotateCA` toast) — the legacy UI retires at FE-8 and is not patched for parity beyond the `.0` contract changes that a shipping legacy caller needs (the 2F-A precedent: legacy JS switched in the same commit as any new 428/409).
>
> **K. Pre-PR lint hygiene gate (inventory only — NOT repaired in FE-6-0).** Toolchain: golangci-lint v2.5.0 rebuilt with go1.26.6 (the preinstalled binary was built with go1.25 and panics on this module), repo `.golangci.yml`. **Exact baseline on `cfb48e81` (tree == `origin/main`):** (a) the PR gate's own form, `--new-from-rev origin/main`: **0** findings; (b) `--new-from-rev 1b3d0e6a` (the Batch 2 program's last main integration): **0** — the inherited 50-finding PR-base inventory was cleared by PR-C3/C4 inside #1340 before it merged; (c) `--new-from-rev fdad5254` (everything since the Batch 1 merge, i.e. the whole frontend-program era including main-side work merged in): **5**, all main-side MCP live-tier code, none frontend-program — `cyclop` `mcp_canary_runtime.go:621` `restoreCapability` (16>15), `cyclop` `mcp_rollout.go:328` `commitRolloutTransitionCore` (16>15), `funlen` `internal/mcp/execution/run.go:42` `runExecute` (54>50), `funlen` `internal/mcp/runtime/policy.go:39` `dispatchPolicy` (55>50), `unparam` `mcp_live_arming.go:83` `armLiveTier`; (d) the full run (the main-push QA-gate form): **144 repo-owned** findings (147 raw; 3 in `frontend/node_modules/flatted` exist only because `node_modules` was installed locally and are not repository content) across 77 files — 97 product / 47 `_test.go`; **mechanical 84** (gocritic 38, noctx 14, errcheck 8, gosec 6, unparam 6, staticcheck 5, bodyclose 3, dupl 2, unconvert 2) / **structural 60** (cyclop 25, gocognit 18, nestif 9, funlen 8). The eight `funlen` rows: `configversion.go:251 rollbackConfigVersion (53)`, `controlplane_snapshot.go:1342 CurrentConfigSnapshot (56)`, `internal/mcp/execution/run.go:42 runExecute (54)`, `internal/mcp/runtime/policy.go:39 dispatchPolicy (55)`, `main.go:170 main (56)`, `main.go:262 parseFlags (91)`, `main.go:365 handleOneShotCommands (60)`, `socks5.go:422 handleSOCKS5 (60)`; the "main-side `funlen`" the 2F-G record deferred is one of the two MCP rows in (c). FE-6-surface product files carrying pre-existing findings: `ui_policy.go` 8, `restore.go` 6, `ui_config.go` 6, `controlplane_snapshot.go` 5, `ui_cluster.go` 4, `ui_security.go` 4, `auth_oidc_flow.go` 4, `auth_saml.go` 3, `configversion.go` 3, `release_api.go` 2, `ui_auth.go` 2, `ui_authpolicy.go` 2, `enrollment.go` 1, `admin_settings.go` 1, `release_wiring.go` 1. **Ownership classification:** (i) frontend-program-introduced: 0; (ii) main-side post-Batch-1: 5 (owner: MCP live-tier); (iii) pre-Batch-1 legacy debt: 139. **Sequencing:** (1) the `.0` sub-slice of each FE-6 slice may not ADD findings on its diff (the PR gate) and should clear the mechanical findings in the files it rewrites (errcheck/noctx/gocritic/unparam/staticcheck — behaviour-preserving, one commit per file family, no `nolint` without a reason); (2) structural findings (cyclop/gocognit/nestif/funlen) are repaired ONLY where the `.0` already restructures the function (persist-before-apply refactors in `ui_config.go`, `configversion.go`, `ui_cluster.go`, `ui_security.go`, `ui_auth.go`) — helper extraction, never semantic change, RED-covered by the slice's tests; (3) the five main-side MCP findings belong to the MCP owner and are not touched by FE-6 unless 6J.0/6K.0 rewrites those functions; (4) `main.go`/`socks5.go`/`controlplane_snapshot.go` `funlen` rows stay out of scope (a dedicated hygiene PR, if wanted, after FE-6L). **Qualification after any cleanup commit:** `gofmt`, `go vet`, `golangci-lint run --new-from-rev origin/main` = 0 plus the full run showing a monotonically non-increasing count, `go test -race -count=1 ./...` with the coverage floors, the determinism lane (`-count=2 -shuffle=on`) for any `_test.go` change, and — where a frontend file changed — `npm run verify`.
>
> **L. FE-6-0 exit and qualification.** Deliverable = this record only (append-only). Qualification of the candidate head: the merged baseline is `origin/main`'s tree (§B); the FE-6-0 commit is documentation-only, so no Go, frontend, OpenAPI, route or dist artifact is regenerated and the route pin, contract version and committed `frontend/dist` are unchanged. **STOP for external contract review; FE-6A does not start until this record is approved or amended.**
>
> **FE-6-0 MAIN-REFRESH AND CONTRACT-CORRECTION RECORD (this branch, 2026-09-09; external review of the FE-6-0 candidate `1b321f5a` REJECTED — one append-only round). PLANNING/CONTRACT GATE ONLY — still implements nothing.** The FE-6-0 record above stays intact and is corrected ONLY by the sections below; where they disagree, this record wins. The repository audit and the twelve-slice decomposition were accepted in principle.
>
> **R-A. Branch custody (reviewer decisions, recorded).** `claude/culvert-frontend-fe6-hyagdj` is the canonical FE-6 branch; no alias branch is created; `claude/culvert-frontend-batch2` stays frozen at `8e73a619` (re-verified untouched). The rejected candidate `1b321f5a` is untouched; the round is append-only: `212aaf29` (entry merge) → this record.
>
> **R-B. Blocker 1 — `origin/main` advanced during review.** Re-fetched `origin/main` = `361b1ee1` (merge of PR #1332 "security(mcp): atomically bind Canary drift to activation"), a strict descendant of the previous gate's `3f7d0640` and NOT an ancestor of `1b321f5a`. Integrated by ONE evidence-preserving no-fast-forward merge onto `1b321f5a`: `212aaf29` (parents `1b321f5a` + `361b1ee1`), no conflicts, and `git diff origin/main` on the merged head is exactly the FE-6-0 record (109 added lines of `docs/design/FRONTEND-MIGRATION-PLAN.md`) — nothing else differs from main. **Merge changed-file classification (25 files, `3f7d0640..361b1ee1`):** production Go 9 — NEW `mcp_canary_admission.go`; MODIFIED `mcp_live_gate.go`, `mcp_canary_runtime.go`, `mcp_canary_preflight.go`, `mcp_observe_startup.go`, `internal/mcp/runtime/{deps,execute,policy}.go`, `internal/mcp/tooltrust/store.go`; tests 12 — NEW `mcp_canary_atomic_binding_test.go`, `mcp_canary_preadmission_e2e_test.go`, `mcp_canary_admission_helpers_test.go`, `internal/mcp/tooltrust/liveview_test.go`; MODIFIED `mcp_live_gate_trust_binding_test.go`, `mcp_live_codexfix_test.go`, `mcp_live_execution_e2e_test.go`, `mcp_live_race_redteam_test.go`, `mcp_live_tier_test.go`, `internal/mcp/runtime/{canary_drift_breach,toctou}_test.go`, `internal/mcp/tooltrust/export_test.go`; DELETED `mcp_canary_autostop_test.go`; docs 2 — `docs/design/mcp/CANARY-READINESS-MATRIX.md`, `docs/operator/mcp-first-controlled-canary-review.md`; script 1 — NEW `scripts/mcp-canary-atomic-binding-mutations.sh`. **Files it did NOT touch (verified by `git diff --quiet`):** `ui_mcp.go`, `ui_mcp_rollout.go`, `ui_mcp_tooltrust.go`, `mcp_canary_attestation.go`, `mcp_rollout.go`, `mcp_rollout_persist.go`, `mcp_distribution*.go`, `mcp_scope_readmodel.go`, `mcp_ack_readmodel.go`, `internal/mcp/{adminapi,approval,rollout,cpdp,management}/`, `ui_routes_meta.go` (pin still 243), `api/openapi/openapi.yaml`, `api/route-classification.yaml`, `backup.go`, `config_surfaces.go`, `static/index.html`, `frontend/**`. No non-MCP FE-6 surface's authoritative file changed, so no other surface is re-audited (reviewer rule).
>
> **R-C. Blocker 1 — MCP re-audit of the MERGED implementation (source-grounded on `212aaf29`; supersedes D9/B-MCP/C11/R68–R75 where stated; everything not restated stands).**
> - **Scope of what changed.** PR #1332 is a RUNTIME ADMISSION change, not an admin-API change: it makes the Canary live-execution trust verdict, the drift latch and the budget reservation ONE critical section under the activation lock (`admitLiveExecution`, `mcp_canary_admission.go:137-190`: requires an active runtime with a non-zero generation, refuses an aborted Canary, runs the injected trust probe UNDER the lock, trips the abort against the CAPTURED generation on a drift code (`tripLockedForGeneration` + persist, `:165-172, :199-210`), denies untrusted-without-drift latching nothing, then reserves budget under the same generation via the extracted `reserveLocked` (`mcp_canary_runtime.go:427-483`)); binds the pre-executor drift latch to the activation it was observed under (`latchDriftUnderActivation`, `:297-341`: refuses generation 0, a publication gap, and a generation mismatch, re-derives drift live under the lock); replaces `mcpLiveTrustRevalidate` with `mcpLiveTrustPrecheck` (inventory-only drift/eligibility) + `mcpLiveApprovalSatisfied` (rug-pull detection: an ACTIVE live approval for the same tenant/server/tool with a DIFFERENT fingerprint ⇒ `tool_fingerprint_drift`; no approval at all stays request-scoped, never drift — `mcp_live_gate.go` ≈`:239-349`); and gives `tooltrust.Store` a copy-on-write lock-free `ActiveLiveApprovals` snapshot republished from `Load` and from `persistLocked` AFTER the durable write (`internal/mcp/tooltrust/store.go` `liveView`, `publishLiveViewLocked`), so a revoke is effective against an admission in flight and a stuck disk can no longer sit in front of the controls that stop the experiment. Runtime deps renamed (`CanaryBreach` → `CanaryDriftObserved` carrying `CanaryDriftTarget{Generation, Code, Tenant, ServerID, ToolName, DecisionFP}`); `resolveUnderStableGeneration` deleted, the generation is captured BEFORE `Resolve` (`internal/mcp/runtime/policy.go:99-104`); `mcp_observe_startup.go` wires `Deps.CanaryDriftObserved = canaryPreAdmissionDrift`.
> - **The eleven D9 admin-surface findings, re-verified on the merged tree:** (1) no server-side ticket/operation id/idempotency key/fence — **OPEN** (the only new "transaction" object, `canaryAdmission`, is runtime-internal and never serialized); (2) transition 403/409 with `base_revision` unread (`ui_mcp_rollout.go:76, :88-93, :113, :117`), scope PUT 409, rollback 409 (`ui_mcp.go:337`), publish 503 (`:664-668`) — **OPEN**; (3) `mcpDisabledCommitter` (`ui_mcp.go:104`), in-memory `approval.Store` (`:102`), `adminapi.PublicationService` pending map, no production `publication.Coordinator` (parameter type only at `mcp_distribution_adapters.go:120`), ack `configured:false` — **OPEN**; (4) four-eyes principal `auditActor` `sub@ip` (`ui_mcp.go:601, :647, :722`), operational `Revisions{}` (`:727`), tool-trust live path on `sess.Sub` (`ui_mcp_tooltrust.go:285-291, :350-365`) — **OPEN, byte-identical**; (5) emergency actor `r.RemoteAddr` (`ui_mcp_rollout.go:216`), runtime-first kill with 500 `{killed, persisted:false}` — **OPEN** (now the C3 exception, §R-D); (6) `config` PUT in-memory `stored:true`, publications POST non-idempotent — **OPEN**; (7) `text/plain` `mcpErr` with the lossy status map (`ui_mcp.go:190-213`) — **OPEN**; (8) audit-before-outcome on rollback/transition/scope/emergency, rehearsal identical detail — **OPEN**; (9) MCP durable files outside `backup.go:64-112` — **OPEN**, and the list gains `mcp_canary_runtime_{gateway,management}.json` (`mcp_canary_runtime.go:93-97`); (10) tool-trust admin contract — **UNCHANGED at the API** (create still bound to fingerprint + `catalog_revision`, `ui_mcp_tooltrust.go:149-150, :254-255`; the GET list still reads `mcpToolTrust.List`, not the live view), CHANGED underneath: a live revoke now takes effect on an in-flight admission; (11) rollout runtime callers unchanged (`mcp_distribution.go:310`, `mcp_distribution_startup.go:198`, the rehearsal's synthetic origin), CHANGED only on the Canary admission path. **No prior finding was resolved by the merge; none was invalidated.**
> - **Admin-visible delta (exact):** ONE new read-model field — `GET /api/mcp/rollout` → `canary.activation_runtime.pre_admission_drift`: an object of `uint64` counts keyed `"tool_fingerprint_drift" | "server_identity_drift" | "other"`, empty when nothing was observed, Gateway capability only (`mcpCanaryStatus` is Gateway-scoped, `mcp_canary_preflight.go:360, :395`; served at `ui_mcp_rollout.go:56`), a process-local counter (reset on restart, never persisted, "nothing consults it" — evidence, not authority). No other GET or POST field on any `/api/mcp/*` route changed; `/api/mcp/tool-approvals`, `/executions`, `/upstream-health`, `/canary/shadow-exit-review` are untouched. The `canary` subtree of the rollout GET was already `additionalProperties: true` in OpenAPI (`openapi.yaml:13111`), so nothing drifted formally — but FE-6I's decoder must be hand-written for the whole subtree, and `auto_stop` (`aborted`, `first_abort_reason`, `aborted_at_unix`, `execution_authority`) stays AUTHORITATIVE over the sibling `generation`/`execution_eligible`, which are taken under separate lock acquisitions and may disagree transiently. **Activation identity** is the per-capability strictly-monotonic `uint64` generation (`beginCanaryActivation`, `mcp_canary_runtime.go:245-252`; restored at `:648`); zero now means "no activation" everywhere and is refused as an attribution; it is exposed read-only as `canary.activation_runtime.generation` and `auto_stop.generation`; no admin route accepts a generation as input, so **no FE-6 ceremony can or should bind to it** — the emergency kill remains capability-wide and generation-free.
> - **Proof-inventory delta (CONFIRMED):** NEW `mcp_canary_atomic_binding_test.go` (19 gates, e.g. `TestAtomicBinding_A_DriftLatchesTheActiveGeneration`, `_B_DemotionRacingTheObservationNeverLatchesTheReplacement`, `_D_PublicationGapDeniesAndPoisonsNothing`, `_E_TrustAndReservationShareOneGeneration`, `_ApprovalIsEvaluatedInsideTheTransaction`, `_RugPullLatchesAtAdmission`, `_MissingApprovalIsNotDrift`, `_PreAdmissionDriftReachesTheOperatorSurface` — the one that pins the new field), NEW `mcp_canary_preadmission_e2e_test.go` (4), NEW `mcp_canary_admission_helpers_test.go`, NEW `internal/mcp/tooltrust/liveview_test.go` (5, incl. `TestLiveView_EveryMutatorRepublishes`, `_PersistFailureDoesNotPublish`) + `export_test.go`, NEW `scripts/mcp-canary-atomic-binding-mutations.sh` (25 mutations M01–M27 less the retired M15/M17, each bound to a named gate); CHANGED `internal/mcp/runtime/canary_drift_breach_test.go` (−4 generation-carrying gates, +2 target-carrying gates), `mcp_live_gate_trust_binding_test.go` (+2 rug-pull tests; `liveTrustVerdict` is a TEST helper, not production), seam renames in `mcp_live_codexfix_test.go`, `mcp_live_execution_e2e_test.go`, `mcp_live_race_redteam_test.go`, `mcp_live_tier_test.go`, `toctou_test.go`; `mcp_canary_autostop_test.go` is NOT deleted — it shrank by two gates (`TestAutoStop_StaleGenerationPreExecutorBreachCannotStopTheNextActivation`, `TestAutoStop_ZeroGenerationBreachCannotStopALiveActivation`, superseded by the atomic-binding gates) and keeps 46 test functions. No uie2e, Playwright, `frontend/e2e` or GUI test changed.
> - **Docs delta an admin UI must respect:** `docs/operator/mcp-first-controlled-canary-review.md:1782-1835` now records blocker 7 as "REOPENED; closure pending a clean adversarial review round" with the round-20/21/22 corrections, while `:804/:807/:810` and the `§25a` heading `:866` still say CLOSED, and `docs/design/mcp/CANARY-READINESS-MATRIX.md:127-140` says REOPENED — an admin surface may cite NEITHER status as authoritative until the ledger is reconciled (new **B-MCP(9)**, documentation, owner MCP); after a latch the truth is `execution_authority`, never the mode.
> - **B-MCP, corrected:** every existing row (1)–(7) stands. Added: **(8)** emergency CLEAR is runtime-first (`clearEmergency`, `mcp_rollout.go:641-654`) and must become refuse-with-zero-runtime-change on persist failure (§R-D); **(9)** the blocker-7 ledger self-contradiction; **(10)** `mcp_canary_runtime_*.json` joins the not-backed-up list; **(11)** the rollout GET's `canary` subtree needs a declared schema (or a pinned hand-written decoder shape) now that it carries `pre_admission_drift`.
> - **C11 MCP authority, corrected (supersedes C11):** four-eyes = canonical subject inequality enforced server-side (`sess.Sub`, the `mcpLivePrincipal` precedent), never `sub@ip`; emergency, rehearsal and attestation carry the admin identity; a live tool-trust approval is evaluated INSIDE the Canary admission transaction, so its revoke is effective immediately and the v2 tool-trust surface may state that fact; the danger dialog (typed phrase, double-submit guard, Esc blocked while committing, UNKNOWN copy) migrates intact for the node-local actions; the emergency DISABLE is the single runtime-first exception under §R-D and renders `applied/persisted/repair` facts as a non-terminal degraded lifecycle; emergency CLEAR is persist-before-effect; signed-path actions (transition, scope PUT, rollback, publish) and the approval committer render server-refused posture and arm no ceremony; no ceremony binds to an activation generation.
> - **FE-6I/J/K boundaries and order, re-validated:** UNCHANGED — (I) reads + management access + the two pure POSTs; (J1) tool-trust write; (J2) publication + approvals + config as refused posture; (K1) emergency, rehearse-rollback ×2, shadow-exit-review; (K2) transition/scope/rollback refused posture. Deltas: FE-6I decodes `pre_admission_drift` and treats `auto_stop` as authoritative; FE-6J1 may state the in-flight revoke fact; FE-6K.0 gains B-MCP(8). Dependency order unchanged (`6I → 6J → 6K`).
> - **RED rows R68–R75, re-validated on the merged tree:** all eight still reproduce (R68 `sub@ip`, R69 `RemoteAddr`, R70 config `stored:true` lost on restart, R71 publications duplicate, R72 audit-before-409, R73 rehearsal detail, R74 `self_approval` → 400, R75 pure POSTs flagged mutating). Added: **R79** emergency CLEAR takes effect in memory when the persist fails; **R80** the rollout GET decoder must accept an absent, empty and populated `pre_admission_drift` and never treat it as authority (`execution_authority` decides); **R81** `mcp_canary_runtime_*.json` absent from the backup manifest.
>
> **R-D. Blocker 2 — C3 persist-before-publish, corrected (supersedes contract C3 and the CA rows of B-CA(3)/D3/D4 that tolerated a runtime-first 2xx).**
> - **C3 (binding, all FE-6 write surfaces):** a 2xx means the durable write landed in the owning store BEFORE the runtime swap. **Certificate and CA installation/rotation persist the recoverable candidate or a durable intent BEFORE activating it**: the inspection-CA rotate and the MITM-target custom-CA upload write the new bundle (or a durable intent record keyed by the operation id) first, then swap the live signer; the UI-target upload writes both PEM files (as one recoverable pair) before it is ever eligible for activation; the cluster-CA import keeps its write-then-swap shape. **A persistence failure BEFORE activation performs ZERO runtime publication** — the live signer, the pending-rotation slot and the leaf cache are untouched, the reply is a contracted `5xx {code:"persist_failed"}`, and no audit claims a change. Consequently `persisted:false` is REMOVED from the CA success vocabulary: a CA reply is either a proven durable `2xx {persisted:true, fingerprint, operationId}` or a refusal. The present `installAndPersistRotatedCA`/`installAndPersistCustomMITMCA` order (install live, then `SaveCA`, 200 with `persisted:false` on failure — `ui_security.go:1721-1761`) is therefore a **6B.0 blocker** (B-CA(3) restated: the order is inverted, not merely reported), RED rows R20a "rotate installs the new root before the bundle write" and R20b "upload installs the custom CA before the bundle write" join the 6B.0 matrix, and `TestForceRotate_UnpersistedRotationDoesNotReportSuccess` is re-expressed as "persist failure ⇒ no rotation at all". The in-memory-CA posture (no bundle path configured) is not a persistence failure: rotation/upload on such a node is REFUSED (`409 ca_not_persistable`) rather than half-applied, and the v2 page withholds the ceremony while `/api/ca/status` reports no bundle path.
> - **The single documented exception — MCP emergency disable (`POST /api/mcp/rollout/emergency`, action disable only):** refusing to kill the guarded execution plane because the rollout-state file could not be written would be unsafe, so the kill switch stays runtime-first (`emergencyDisable`, `mcp_rollout.go:621-636`: `EngageKillSwitch` under `durableMu`, then `persistRolloutState`; on failure `persistStatus=write_failed` and `errRolloutPersistFailed` is returned; the handler answers 500 `{capability, killed:true, persisted:false, error:"rollout_persist_failed"}`, `ui_mcp_rollout.go:222-231`). The exception is narrow and explicit: the reply MUST carry `applied:true`, `persisted:false`, the bounded `persistStatus` (`write_failed`), the recovery/repair facts (`persistence.path`-free reason, `repair: "re-issue the emergency disable once storage recovers; the kill is in force in memory only and does NOT survive a restart"`), and the operation enters a NON-TERMINAL degraded lifecycle (`killed:true, persisted:false`) that the read model (`GET /api/mcp/rollout` `.killed` + `.persistence`) keeps reporting until a later durable write lands or a restart loses it — the v2 page renders it as a degraded/UNKNOWN-durability state with its own copy, never as ordinary success, and re-arms the ceremony for the repair. Emergency CLEAR is NOT covered by the exception: a clear that cannot persist must be refused with zero runtime change (a clear that survives only in memory silently re-arms the kill at the next restart, in the wrong direction). Today `clearEmergency` (`mcp_rollout.go:641-654`) clears in memory FIRST and only then persists, answering the same 500 `{killed:false, persisted:false}` — a **6K.0 blocker** (B-MCP(8), new) with RED row R79 "emergency clear takes effect in memory when the persist fails". **The exception is not an escape hatch**: no CA, certificate, settings, cluster, release, support, identity or portability mutation may adopt runtime-first behaviour; any future candidate needs its own recorded amendment naming the safety argument.
>
> **R-E. Blocker 3 — section H rewritten (supersedes H).** Release dispatch **T3** (word = the bound `release_id`, server-named from the catalog-bound plan) ships WITH the FE-6G.2 dispatch surface, and certificate upload **T2** (impact copy naming the persisted target and the restart-only activation of the UI target) ships WITH the FE-6B.2 upload surface. Both ceremonies are FE-6 deliverables; contract D4's "[STRENGTHEN]" rows are satisfied inside FE-6, and no FE-6 commit exposes either mutation without its tier. The Support native `prompt`/`confirm` sites (passphrase, sealed recipient, recipient rotate/remove) and the MCP `window.confirm` on capability switch are likewise replaced inside FE-6H.2 / FE-6J.2 (contract D5/B4). The existing typed words (`ROTATE`, `RESTRICT`/`OPEN`, `ENABLE`, `ENABLE`, `PROMOTE`, `IMPORT`, the MCP `DISABLE|CLEAR <CAP>` phrases) and the two-phase Root-CA token migrate verbatim inside their FE-6 slices. **FE-7 retains ONLY the global, cross-surface hardening and adversarial ceremony sweep**: the per-ceremony mutation suite (Enter cannot confirm, double-submit, stale token/ticket/fence, failure injection ⇒ UNKNOWN rendering), the `ConfirmationDialog` audit against contract §6/§8 across every surface, any tier UPGRADE beyond legacy parity (e.g. IdP delete or cluster token delete to T3), and the removal of the legacy dialog primitives with the legacy UI at FE-8. FE-7 adds no new ceremony and owns no mutation surface.
>
> **R-F. Lint inventory and ownership, re-run on the refreshed head (`212aaf29`, tree = `origin/main@361b1ee1` + this record; supersedes the counts in §K, the sequencing there stands).** Same toolchain (golangci-lint v2.5.0 rebuilt with go1.26.6, repo `.golangci.yml`). (a) `--new-from-rev origin/main`: **0**. (b) `--new-from-rev 3f7d0640` (exactly PR #1332's scope): **0** — its two `fix(lint)` commits (`5070248a` gocritic `unnamedResult`, `57cdd7c9` dead wrapper) hold. (c) `--new-from-rev fdad5254` (since the Batch 1 merge): **5**, the same five main-side MCP rows, `restoreCapability` now at `mcp_canary_runtime.go:630` and `dispatchPolicy` now 56 statements (`internal/mcp/runtime/policy.go:39`); still none frontend-program. (d) full run: **144 repo-owned** (unchanged count; 96 product / 48 `_test.go`; 77 files; mechanical 84 / structural 60 with the same per-linter split; the eight `funlen` rows unchanged except `dispatchPolicy` 55→56). Ownership classification unchanged: frontend-program 0 / main-side post-Batch-1 5 / pre-Batch-1 139.
>
> **R-G. Requalification of the refreshed head (`212aaf29` + this record; tree = `origin/main@361b1ee1` + the two FE-6-0 records).** Custody: clean tree, remote equality re-proven at push, `origin/main@361b1ee1` an ancestor of HEAD (re-fetched at the exit gate: unchanged). Go: `gofmt -l` empty; `go build ./...` and `go vet ./...` clean. Targeted suites under `-race -count=1`: `./internal/mcp/...` — all 40 packages `ok` (runtime, tooltrust, canary, rollout, approval, adminapi, cpdp, execution, events, credentials, management and the rest); the root package with `-run 'MCP|Mcp|Canary|Live|ToolTrust|Tooltrust|Rollout|Approval|Distribution|Attestation|Emergency'` — `ok` (252.9 s; covers `mcp_canary_atomic_binding_test.go`, `mcp_canary_preadmission_e2e_test.go`, `mcp_canary_autostop_test.go`, `mcp_live_*`, `mcp_rollout_durable_test.go`, `mcp_distribution_transaction_test.go`, `ui_mcp*_test.go`, `mcp_tooltrust_test.go`, `mcp_canary_attestation_test.go`), no race reports, no panics. Route/OpenAPI/conformance/contract gates with `-run 'Route|D0|Conformance|Contract|OpenAPI|Classification|Apicontract|C1|C2|C4|Metadata|Governance'` — `ok` (route pin 243, classification 1:1, apicontract conformance, C1/C1.5/C2/C2c/C4 suites). Frontend `npm run verify` under node 24.19.0 / npm 11.17.0 — ALL nine gates passed (types drift none, 70 files / 787 tests, dist drift none, tree clean afterwards); a first run executed concurrently with the `-race` suites failed exactly one vitest case (`pac-2fe-c3-red-page.test.tsx` P22, a `flushUntil` timeout while "Loading lifecycle…" was still rendered) which passed 3/3 in isolation and in the uncontended rerun — CPU starvation, not a regression, recorded so the number is not mistaken for a flake in the product. Lint: §R-F. **FE-6-0-owned diff remains documentation-only:** `git diff origin/main` on the candidate head is exactly the two FE-6-0 records in `docs/design/FRONTEND-MIGRATION-PLAN.md`; no product code, frontend source, generated artifact, route metadata or committed `frontend/dist` changed. **STOP for external contract review; FE-6A and FE-6I do not start until this correction record is approved or amended.**
>
> **FE-6-0 SECOND MAIN-REFRESH RECORD (this branch, 2026-09-11; append-only, per the standing exit-gate rule "if `origin/main` advances again, integrate append-only and requalify the affected scope"). PLANNING/CONTRACT GATE ONLY — still implements nothing.** The FE-6-0 record and the first correction record above stay intact; this record corrects them ONLY where it says so, and where they disagree the later record wins.
>
> **R2-A. Custody and ancestry.** The correction candidate `48812355` (the head the external review was asked to review) is untouched. After its exit gate `origin/main` advanced from `361b1ee1` to `31f7d134` — 462 commits, about 80 merged PRs (the chaos-engineering sweeps CHAOS-57…64 with their id-collision renumberings, dependabot Go/Actions bumps, MCP canary identity anti-vacuity #1349, the HA standby token flag fix #1337, new health planes for auth cost / DNS / GeoIP / logstore / admin-UI listener / cluster rate-limit freshness / threat-feed freshness / tunnel drain, admin-login input bounds, the maintenance-agent health route, the Auth Exempt runtime kill-switch route, terminology-governance and security-review documentation). Integrated by ONE evidence-preserving no-fast-forward merge onto `48812355`: `28b42ee0` (parents `48812355` + `31f7d134`), auto-merged with NO conflicts (main's own edit to `docs/design/FRONTEND-MIGRATION-PLAN.md` is the status line and the FE-1A "IMPLEMENTED" wording, far from the FE-6 records). On the merged head `git diff origin/main` is exactly the FE-6-0 records (136 added lines of the plan); nothing else differs from main. `claude/culvert-frontend-batch2` re-verified frozen at `8e73a619`; no alias branch; no history rewrite; no PR.
>
> **R2-B. Merge changed-file classification (271 files, `361b1ee1..31f7d134`: 104 added, 162 modified, 5 renamed).** Production Go 96 files; test Go 100; workflows 4 (`codeql.yml`, `pr-deep-gate.yml`, `pr-fast-gate.yml`, `security-release-gate.yml`); build/deps (`Dockerfile`, `go.mod`, `go.sum`, `docker-compose.ha.yml`, `scripts/install.sh`); contract artifacts (`ui_routes_meta.go`, `api/route-classification.yaml`, `api/openapi/openapi.{yaml,json}`, `api/openapi/index.html`, `frontend/src/api/types.gen.ts`); frontend source 5 (`AppShell.tsx`, `api/diagnose.ts`, `features/auth/AuthScreen.tsx`, `features/objects/DecryptionProfilesPage.tsx`, `shared/dirtyGuard.tsx`) + the regenerated `frontend/dist`; legacy `static/index.html`; docs (`CLAUDE.md`, `README.md`, `CHANGELOG.md`, ADR-FE-001, six ADRs, the plan, operator runbooks, engineering registers, security reviews, terminology reviews, support docs, roadmap). **FE-6 authoritative files that changed and therefore triggered a diff-scoped re-audit (reviewer rule):** IdP/Administrators — `ui_auth.go`, `ui_auth_ldap.go`, `auth_ldap.go`, `auth_startup.go`, `auth_state_client.go`, `login_input_bounds.go`, `store.go`, `internal/lockout`, `internal/authcost`; Cluster — `ui_cluster.go`, `enrollment.go`, `ha.go`, `ha_lease.go`, `dp_enrollment.go`, `controlplane_client.go`, `cluster_ratelimit_freshness.go`, `bandwidth_health.go`; Settings/CA/portability — `ui_config.go`, `ui_security.go`, `ui_security_fence.go`, `ui_tls_custom.go`, `backup.go`, `restore.go`, `alerts.go`, `internal/alerts/store.go`, `config.go`, `main.go`, `keyatrest_diagnostics.go`, `mtls_ocsp_startup.go`; Releases/Support — `maint_agent_status_api.go` (NEW), `diagnose.go`, `diagnostics.go`, `internal/redaction/urlcred.go`; Decryption — `ui_policy.go`; MCP — `mcp_canary_attestation.go`, `mcp_canary_rollback_rehearsal.go`, `mcp_canary_runtime.go`, `mcp_live_gate.go`, `mcp_live_tier.go`, `mcp_observe_health.go`, `mcp_rollout_execdeps.go`, `internal/mcp/adminapi/health.go`, `internal/mcp/execution/{livegate,run}.go`; accounting — `ui_routes_meta.go` (pin 243 → **245**), `route-classification.yaml`, OpenAPI, `types.gen.ts`, `static/index.html`. **Verified directly:** `ui_metadata_enforcement.go` is UNCHANGED — SEC-C2 has still NOT landed (B-SEC-C2 stands). The two new `uiRoutes` rows are `/api/authpolicy/killswitch` (Domain `policy`; GET viewer "break-glass status: env + runtime Auth Exempt kill switch layers"; PUT admin, Mutating, AuditExpected, "engage/release the runtime layer only; env layer is read-once"; handler `apiAuthPolicyKillSwitch`) and `/api/maintenance-agent` (Domain `support`; GET viewer, read-only pass-through of the CP-local maintenance agent's `/v1/status` — version, privilege posture, compose-stack health; handler `apiMaintAgentStatus`). `backup.go`'s manifest now ARCHIVES `idp_profiles.json` and `fileprofiles.json` (the IdP half of B-IDP(7) is resolved by main; the boot-fatal-on-corruption half is re-checked in R2-C).
>
> **R2-C. Diff-scoped re-audit of the changed FE-6 authoritative files (every claim read in the merged tree; CONFIRMED unless marked). Verdict first: NO recorded blocker of any surface was resolved by the advance; every `.0` list stands; one backup half-resolution, several read-model additions, two new routes, and a handful of new same-class findings are recorded below.**
> - **IdP + Administrators (D1/D2, B-IDP, B-ADM, R1–R14).** `auth_idp.go`, `auth_ldap_provider.go`, `auth_saml.go`, `auth_oidc*.go`, `controlplane_snapshot.go`, `controlplane_server.go`, `ui_middleware.go`, `ui_session.go`, `session.go`, `internal/session`, `internal/totp` are byte-identical; `ui_auth.go` changed by seven login-only lines. B-IDP(1)–(6),(8) OPEN. **B-IDP(7) PARTIALLY resolved:** `backup.go` now archives `idp_profiles.json` (with its PLAINTEXT OIDC secrets and LDAP bind credentials — the runbook says so; pinned by `TestBackup_IdPProfiles_IncludedWithContent`); the boot-fatal-on-corruption half stays OPEN (`ui_access_policy_startup.go:59-62`, `auth_idp.go:165-170`), so B-IDP(7) is re-worded to "quarantine-on-corrupt + a restore-truth note that the archive carries IdP secrets in cleartext, the same class as `ui_users.json`'s TOTP secrets". B-ADM(1)–(5) OPEN (`store.go:1241-1258` still replaces the struct; `ui_auth.go:297,316,424` still best-effort). RED R1–R14 all still reproduce; R14 grew by two `text/plain` refusals (login oversize 400, `login_input_bounds.go:174`; kill-switch 400/405, `ui_authpolicy.go:507,516`). New adjacent facts for 6A: `/api/idp/test` is now bounded by `ldapTestTotalBudget` = 45 s (`ui_auth_ldap.go:205`) — the v2 test ceremony needs a matching client timeout and UNPROVEN handling; `auditActor` now attributes an authenticated Basic-auth username (`ui_helpers.go:37-56`, `ui_audit_actor_basicauth_test.go`), so audit rows on every FE-6 mutation may read `user@ip` for Basic callers; `--reset-password` became `runResetPasswordCommand` (refuses an unreadable roster, `main.go:456-500`) and is a second `SetUIUser` caller the B-ADM(1) fix must cover; lockout keys are bounded (`internal/lockout` `MaxUsernameKeyLen` 256, injective SHA-256 suffix — `GET /api/auth/lockouts` may show a clamped `prefix…<16hex>` key, SUSPECTED); the CHAOS-57 bcrypt-cost governor can refuse local proxy-auth fail-closed (407) before checking the credential (`store.go` `authCostAdmit`); OpenAPI `LoginRequest.user` gained `maxLength: 256`; the new `auth.login.rejected` audit action is not declared in OpenAPI (SUSPECTED). Proofs added: `login_input_bounds_test.go` (10), `internal/lockout/lockout_keybound_test.go` (9), `auth_cost_chaos_test.go` (19) + `internal/authcost` (15), `auth_ldap_stall_chaos_test.go` (9), `ui_audit_actor_basicauth_test.go` (11), `authz_identity_*` (+7), `backup_test.go` (+2). Legacy IdP/Users/Authentication panels unchanged.
> - **The Auth Exempt runtime kill switch (NEW, adjacent to 6A, owned by the Authentication Policy surface that 2C migrated).** `PUT /api/authpolicy/killswitch {disabled:bool}` → `setAuthExemptDisabled` flips a process-local `atomic.Bool` (`authpolicy.go:366-370`): engaged, every Auth Exempt rule and the global Open default fail closed to auth-required at Stage 1; the env layer `CULVERT_AUTHBYPASS_DISABLE` is read-once and reported beside it; `GET /api/authpolicy` gains the REQUIRED field `killSwitch {envDisabled, runtimeDisabled, engaged}` (`openapi.yaml:397-417`). **Persistence: NONE** — not in `AdminSettings`, not on `configSurfaces`, no `saveConfigVersion`, not CP→DP; a restart silently RELEASES an engaged switch; no fence, no idempotency token; refusals `text/plain`; legacy engage = native `window.confirm`, release = no confirm (`static/index.html:15392-15435`, panel `#ap-killswitch-panel` `:3369-3377`). It is exactly the shape rules R3/B-REF forbid a v2 surface to ship without a `.0`: a durability decision (persist, or declare runtime-only and render "released on restart"), a typed refusal, and a ceremony tier. **Assignment:** recorded as **FE-6L residue item L-KS** (the 2C successor owns `/app/policy/auth`), with RED rows **R82** "engaged kill switch released by a restart with no trace on the read model" and **R83** "release needs no confirmation while engage needs a native one"; the 2C strict decoder for `GET /api/authpolicy` must be checked against the new required field (`frontend/src/api/policyAuth.ts`, SUSPECTED impact — a ride-along for the first slice that touches it).
> - **Cluster (D5, B-CLU, R25–R35).** Merged tree equals main for every cluster file. B-CLU(1) HA token on the viewer GET OPEN (`ha.go:1181-1184, :1203-1205`; legacy still writes it into the DOM `:18761`); B-CLU(2) no `WriteAllowed` gate on any HTTP mutation OPEN (`haIssuanceAllowed` callers still only `controlplane_server.go:349,392,625`); B-CLU(3) node-group/bandwidth persist swallowed and never published OPEN (`nodegroup.go:133-142`, `bandwidth.go:197-205`) — with NEW CONTEXT: `bandwidth_health.go:6-24` records that QoS policies have NO data-path consumer (PX-7), surfaced as the operator-contract row `bandwidth_qos_enforcement` ("configured but not enforced") and a permanent legacy banner (`:4904-4907`) — so **B-CLU(9) (new)**: FE-6D must render bandwidth as not-enforced posture or defer the bandwidth mutation surface, and B-CLU(3)'s urgency is durability-only (SUSPECTED until node groups gain a consumer). B-CLU(4)–(8) OPEN (Enable CP still non-durable `main.go:1359-1364`; memory-before-persist unchanged; token DELETE still unaudited; `_ = saveHAConfig` at `ha.go:219,291,377,414,951`; `ha_config.json`/`cp_config_version.json`/`dp_last_seen_epoch.json` still off the manifest; lease posture still two reads). Cluster routes and roles unchanged; no new fence or typed refusal. New viewer-visible read-model fields: `GET /api/cluster/rate-limits` `remote_counts_stale/applied/max_age_secs/stale_episodes` (+`remote_counts_age_secs` only when applied; `ui_cluster.go:375-390`, `cluster_ratelimit_freshness.go:88-124`; typed in OpenAPI `:1492-1519` but still `additionalProperties: true`); `GET /api/cluster/ha` `lease_reacquire_attempts`, `lease_reacquired_total` only when `lease_mode=="lease"` (`ha_lease.go:396-409`) — UNDOCUMENTED (`ClusterHA` stub, drift widened); `/healthz` `auditClusterPushDrops`; operator-contract rows `key_at_rest` + `plaintext_key_backup` (`keyatrest_diagnostics.go:111-211`); `diagnose cluster` `sync_panics` (the v2 diagnose decoder already accepts it). Durability changes: a stale CP rate-limit broadcast contributes 0 (`security.go` `FreshCount`, fail-open toward the local limit); the DP→CP audit push queue is bounded at 1000 with counted oldest-drop (`internal/audit/audit.go:409,437-469`); `docker-compose.ha.yml` now exits 1 on an empty `HA_TOKEN` with `HA_JOIN` (#1337, compose + test only). Legacy: `#ha-lease-recovery-banner`, `#crl-stale-banner`, ceremonies unchanged. Proofs added: `cluster_ratelimit_freshness_chaos_test.go` (17), `bandwidth_health_test.go` (4), `docker_compose_ha_join_token_flagvalue_test.go` (2), `dp_enrollment_ca_fp_warning_test.go` (2), `diagnose_cluster_test.go` (+1), `ha_lease_recovery_chaos_test.go` extended. Impact: 6C.0's typed-schema item grows (`ClusterHA` lease-mode-only fields; `ClusterRateLimits` `remote_counts_*`); 6C.1 adds the rate-limit stale banner, the HA recovering-vs-stuck banner (derived from `role` + `lease_valid` + `lease_recovering`) and the audit push-drop signal; 6D gains B-CLU(9). R25–R35 still reproduce (no mutation path changed).
> - **Settings, portability, Certificates/CA, backup/restore (D3/D4/D8, B-SET, B-PORT, B-CA, R15–R24, R36–R50).** `configversion.go`, `admin_settings.go`, `config_surfaces.go`, `session.go`, `syslog.go`, `otlp.go`, `internal/ca` byte-identical. B-SET(1)–(8) OPEN (`adminSettingsSave` still fire-and-forget at 16 call sites; the only `ui_security_fence.go` change is `redactURLUserinfo` → `redaction.URLUserinfo`); B-SET(8) gains a member: `uiCustomTLSCorrupt` is a new plain global (`ui_tls_custom.go:59,:167`, `ui_security.go:378`, read `ui_config.go:2024`). B-PORT(1),(3),(4) OPEN; **B-PORT(2) PARTIAL:** the import commit 200 now carries `warnings []string` (skipped policy rules, rejected content-scan patterns, invalid IP-filter entries, rejected block page — `ui_config.go:1024-1082, 1293-1296, 1325-1335, 1404-1409, 1448-1455`) but still no `stores_persisted`/`persist_errors` (`policyStore.Save()` at `:1241` swallowed), and `ConfigImportResult` in OpenAPI (`:1236-1262`) does not declare `warnings` (new drift for B-DOC). **B-CA ALL OPEN, and the R-D order is still inverted:** `installAndPersistRotatedCA` (`ui_security.go:1750-1763`) runs `InitCA` live THEN persists; `installAndPersistCustomMITMCA` (`:1767-1790`) runs `LoadCustomCA` live THEN persists; an empty `caRuntime.path` answers 200 `persisted:false` (`:1781`), not `409 ca_not_persistable`; the rotate success body still carries no `persisted` key (`:1737-1739`); the token slot is unchanged (`:25-27, :1683-1686, :1699-1714`). The R-D line references (`:1721-1761`) are now `:1750-1790`. **New R22b (B-CA(5) widened):** `GET /api/ocsp` (viewer, no handler `requireRole`) now embeds `mtlsClientCertFile` (a filesystem path) and `mtlsClientCertLastError` (the raw `tls.LoadX509KeyPair` error, itself carrying the path) — `ui_security.go:1836-1849`, `mtls_ocsp_startup.go:73-77,:96-102`, documented in OpenAPI `:457-462` and rendered by the legacy Certificates panel's new "Upstream mTLS Client Certificate" block; the 6B.1 decoder refuses both fields until R22b lands. UI-cert upload: `persistCustomUITLS` (`ui_tls_custom.go:109-129`) now rolls the cert half back on a key-write failure, leaves the pair on `ErrReplacedNotSynced` and reports `errUITLSRollbackFailed`; the handler (`ui_security.go:351-378`) STILL answers 200 `persisted:false` (three server outcomes now — all collapse into the R-D refusal shape in 6B.2, none is rendered as degraded success); still two writes, still no delete, still not backed up; new read field `ui_custom_cert_corrupt` on the network GET (documented). OCSP toggle still non-durable. Other read-model/API facts: `GET /api/audit?format=csv|json&source=file` (limit 10000, `ui_config.go:56-99`) is UNDOCUMENTED and `writeAuditExport` writes cells unescaped (CSV formula injection — adjacent P2, dashboard domain); retention enable can answer 409 "salt file missing" (`:585-594`); alert vocabulary gained `auth_verify_saturated`, `threat_feed_stale`, `admin_ui_unavailable` (the last SUSPECTED absent from the legacy webhook checklist) and `dns_failure` carries a bounded detail class; diagnostics rows `plaintext_key_backup`, `admin_ui_listener`, `oidc_base_url`, `credential_verification`, `dns_resolution`, threat-feed, request-history and bandwidth QoS; the admin UI listener now retries instead of killing the process (`serveAdminUIWithRetry`, `/ready admin_ui` report-only row); an empty `config.yaml` is no longer fatal; `scripts/install.sh` persists a host-env `CULVERT_SESSION_SECRET` into `.env` (install-side only — does not change B-SET(1)); OpenAPI tags and shell copy moved from "Appliance" to "Node" (carry into every FE-6 slice's copy). **Backup manifest:** +`fileprofiles.json`, +`idp_profiles.json` (`backup.go:111-133`); still absent: `ui_tls_*.pem`, the mTLS client cert, `ha_config.json`, `cp_config_version.json`, `dp_last_seen_epoch.json`, the `support/` tree, every MCP file; `ca.bundle` still by fixed name. **Restore:** decompression-bomb bounds (256 MiB per entry, 512 MiB aggregate, `restore.go:56-68,:317-329`); and a **NEW pinned, unfixed defect (B-PORT(5), restore-truth):** `TestRestoreCommit_DataDirIsMountPoint_FailsInsteadOfCommitting` (`restore_mountpoint_test.go`, privileged in `pr-fast-gate.yml`) proves `runRestoreCommit`'s `os.Rename(dataDir, bakPath)` (`restore.go:912-962`) fails EBUSY when `/data` is a mount point — the shipped `cli` topology (`docker-compose.yml:256`); data is left untouched but the documented compose restore-commit path cannot commit; the runbook is not updated. RED R15–R24 (+R22b), R36–R50 all still reproduce (R44 `saveOTLP` `:10995-11017`; R50 `pac_profiles_not_applied` still unrendered). Legacy ceremonies unchanged (new line refs: `ROTATE` `:10708`, `RESTRICT/OPEN` `:10774`, `deleteWebhook` `:11115`, `forceRotateCA` `:17553-17566`, `uploadCustomCert` `:13401`, `toggleOCSP` `:17572`). Proofs added: `ui_tls_custom_partial_write_test.go` (3), `ui_tls_custom_test.go` (+2), `ui_security_coverage_test.go` (+4 OCSP mTLS), `mtls_ocsp_startup_test.go` (+5), `backup_test.go` (+2), `restore_decompression_bomb_test.go` (3), `restore_mountpoint_test.go` (1), `config_import_warnings_test.go` (2), `config_empty_file_test.go` (5), `install_script_session_secret_host_env_test.go` (6), `main_reset_password_test.go` (+2), `main_config_precedence_test.go` (+6), `keyatrest_diagnostics_test.go` (+4), `admin_ui_listener_chaos_test.go` (18); still no direct test for the session-secret/syslog/OTLP/metrics-config/connlimit/blockpage handlers, the rotate token binding or OCSP durability.
> - **Releases, Support, Decryption (D6/D7/D10, B-REL, B-SUP, B-SEC-C2).** `release_api.go`, `release_dispatch*.go`, `release_wiring.go`, `backups_api.go`, `cmd/culvert-maint/**`, `ui_support.go`, every `support_*.go`, `internal/support`, `internal/supportupload`, `decryption_redaction.go`, `autoexclude*`, `internal/decryptprofile`, `config_surfaces.go`, `ui_metadata_enforcement{,_test}.go`, `internal/apicontract`, `frontend/e2e` are byte-identical in the range; zero release/support/decryption tests changed. **B-REL(1)–(7) OPEN; B-SEC-C2 OPEN; B-SUP(1)–(8) OPEN; the D10 residue is intact** (its audit-name line refs moved to `ui_policy.go:995,1000,1100` / `openapi.yaml:3301,6075,8163`). Deltas: **`GET /api/maintenance-agent`** (`maint_agent_status_api.go`; Domain `support`, viewer, unaudited read; classification and OpenAPI rows present, schema `MaintAgentStatus` is `additionalProperties: true` — one more opaque schema for B-DOC) answers always-200 `{available:false, reason}` or `{available:true, agent_version, privilege_mode, compose_stack_up[, privilege_warning, compose_error, last_operation_kind, last_operation_state]}` from the agent's `/v1/status`, cached 15 s under a mutex HELD ACROSS the 10 s agent fetch (`:111-119`; SUSPECTED: a hung agent stalls every concurrent viewer), and its `reason` is the raw `err.Error()` including the socket path on a VIEWER route (`:139-142`) — **B-REL(6) widened**; it reads the same document `RunningDigests` already fetches, adds no agent capability, and does NOT cover `BackupSkipped`/`compose_override_configured` (B-REL(5) OPEN); the agent's `last_operation_*` fields are still never populated, so the new route forwards absent values (B-REL P1 stands, now viewer-visible). The `release_dispatch_attention` alert being unsubscribable from the GUI is now **CONFIRMED** (the legacy `wh-event` checklist of 22 values lacks it; the store filters on the exact name or `*`). The legacy Support panel renders the maintenance-agent card beside Backups (`static/index.html:5195-5205`, `:15782-15820`); **assignment decision:** the route is a maintenance-agent read like `/api/backups`, so 6G.1 owns its decoder (hand-written; `reason` untrusted prose) and 6H.1 renders nothing for it — one owner, recorded here. Support ADRs 0028/0029/0031 moved to "Accepted — partially implemented" (0030 stays Proposed and records that `/v1/collect` does not exist on the agent); the support RFC renumbered 0034→0036; documentation only.
> - **MCP (D9, R-C, B-MCP, C11, R68–R81).** 20 MCP files changed (+1574/−51), 10 production: `internal/mcp/adminapi/health.go`, `internal/mcp/execution/{livegate,run}.go`, `mcp_canary_attestation.go`, `mcp_canary_rollback_rehearsal.go`, `mcp_canary_runtime.go`, `mcp_live_gate.go`, `mcp_live_tier.go`, `mcp_observe_health.go`, `mcp_rollout_execdeps.go`. UNCHANGED: `ui_mcp.go`, `ui_mcp_rollout.go`, `ui_mcp_tooltrust.go`, `mcp_rollout.go`, `mcp_rollout_persist.go`, `mcp_distribution*.go`, `internal/mcp/{approval,rollout,cpdp,management}`, both blocker-7 documents, every MCP row of `uiRoutes` (the MCP path count is 30 at both revisions — the "29" in D9/R-C was a miscount, not a delta), no MCP file on the backup manifest. PR #1349 "mcp-canary-identity-antivacuity" is NOT an MCP change (proxy `X-User-Identity` anti-vacuity controls); the MCP deltas come from the SRR-01, four-Canary-gate-gaps, SEC-MCP-AUX-1 and health-counter commits. **The eleven R-C findings all stand; B-MCP(1)–(11) all OPEN; R68–R75, R79–R81 all still reproduce.** Two are CHANGED underneath without being resolved: (a) `auditActor` (`ui_helpers.go:37-56`) now falls back to the authenticated Basic-auth username when no session cookie is present, so two Basic-auth admins behind one IP are distinct principals — but the identity is still `name@ip`, so B-MCP(1) is not satisfied and **R68 gains the Basic-auth-caller case**; (b) `modeExecReady` treats an unknown mode as not ready (`mcp_rollout_execdeps.go:143-155`). The emergency actor line is `ui_mcp_rollout.go:219` (the R-C record's `:216` was off by three). Admin-visible delta: `GET /api/mcp/health` gains eight additive `uint64` fields under `gateway.runtime.*` and `management.runtime.*` — `requests_total, requests_rejected, queued, timeouts, auth_failures, ambiguous_headers, host_origin_failures, observe_drops` (`adminapi/health.go:50-57`, `mcp_observe_health.go:52-59`; undeclared, the health schema is still open); `GET /api/mcp/rollout` `live_tier.gate_denials` may now carry the key `rollout_mode_invalid` (auxiliary-traffic lifecycle denial, `mcp_live_gate.go:282-286`, and the fail-closed default `:192-209`); `POST /api/mcp/canary/shadow-exit-review` gains a bare `text/plain` 400 `shadow_exit_review_id_too_long` for a `review_id` over 256 bytes (`mcp_canary_attestation.go:34,:242-244`; the bound is description-only in OpenAPI `:13508-13517`, so the v2 client hard-codes 256); the attestation and rehearsal durable-record decoders now fail closed on trailing bytes (`strictDecodeSingleJSONValue`, `mcp_canary_runtime.go:753-763`; a corrupt record is quarantined and reads as absent). Emergency/kill-switch semantics: NONE changed (runtime-first DISABLE and CLEAR both stand — B-MCP(8) OPEN). Tool-trust API and identity unchanged; a store-level wall (`tooltrust/projection_purpose_test.go`) proves a `live_execution` grant never reaches the Shadow `Usable` projection and vice versa, and the runbook (`docs/operator/mcp-tool-trust-approvals.md:21-35`) now calls tool trust "a fourth, independent gate" — 6J1 may state both facts and must never imply a trust approval satisfies a `REQUIRE_APPROVAL` rule. Runtime-only (unreachable in a stock build): `LiveExecutionGate.AdmitAuxiliary`, the lifecycle-only admission with a read-only boundary `Revalidate`, and the fail-closed default denial. Proofs added: `mcp_canary_gate_hardening_test.go` (9+2), `mcp_live_gate_auxiliary_test.go` (5), `mcp_live_gate_denial_exhaustive_test.go` (3), `ui_audit_actor_basicauth_test.go` (11), `internal/mcp/execution/livegate_boundary_order_test.go` (6), `internal/mcp/tooltrust/projection_purpose_test.go` (3), `+2` in `mcp_shadow_readiness_test.go` and `execution/auxiliary_admission_test.go`; none deleted; no mutation script added; no uie2e/Playwright/frontend MCP change. Four new security-review documents (2026-08-28, 09-02, 09-04, 09-05) leave blocker 7's ledger contradiction (B-MCP(9)) in place and add: F-1 (KEK adopted from an unvalidated parent directory, Medium, unreachable — owner decision pending) and the stale doc comments D-1/D-2 (to which the `reconcileRolloutWithAppliers`/`reconcileRolloutWithDistribution` drift is added). **FE-6I/J/K boundaries and the `6I → 6J → 6K` order are UNCHANGED**; 6I's health decoder accepts the eight numeric fields and treats `gate_denials` as an open `string → uint64` map; 6K1's attestation ceremony carries the 256-byte client bound and the new code in its typed-refusal shim.
> - **Cross-cutting accounting (§C), corrected.** Route pin 243 → **245** (`ui_routes_meta_test.go:104`, `d0_helpers_test.go:196`); classification 1:1 (`API-INVENTORY.md` 363 → 366 method entries); SEC-C2 still unlanded (`ui_metadata_enforcement.go` byte-identical); both new routes speak the old `text/plain` dialect; audit-event drift and danger-level disagreements untouched; opaque-schema list +`MaintAgentStatus`; **backup-manifest omission list corrected:** `idp_profiles.json` is now archived (with cleartext secrets) and `fileprofiles.json` joins it — the remaining omissions are `ui_tls_cert.pem`/`ui_tls_key.pem`, the mTLS client cert, `ha_config.json`, `cp_config_version.json`, `dp_last_seen_epoch.json`, the `support/` tree, every MCP durable file (now including `mcp_canary_runtime_*.json`), and `ca.bundle` still by fixed name. `frontend/src` changed in six files — "appliance" → "node" copy in `AppShell.tsx`, `AuthScreen.tsx`, `dirtyGuard.tsx`; the cluster diagnose decoder gained `sync_panics` (`api/diagnose.ts:380-389`); `types.gen.ts` regenerated; `DecryptionProfilesPage.tsx:496-497` callout now points at the Auto-Exclusions tab — no FE-6 surface, no new nav entry, no structural shell change; `frontend/dist` was regenerated consistently (a scratch-outDir Vite build on the merged tree is byte-identical to the committed bundle). `static/index.html` (+301/−18): Support maintenance-agent card, HA lease-recovery banner, rate-limit stale banner, Certificates mTLS block + `ui_custom_cert_corrupt` state, webhook checklist +`threat_feed_stale` +`auth_verify_saturated` (still no `release_dispatch_attention`), Audit CSV/JSON export, the kill-switch panel, PAC "Steering Profile" wording + `degraded` badge, panel retitles, bandwidth not-enforced banners, config-import warnings, MCP runtime counters — none alters a recorded ceremony tier.
>
> **R2-D. Consolidated corrections to §E/§F/§I (the `.0` blocker lists and RED matrix) — everything not listed stands verbatim.** B-IDP(7) re-worded (quarantine-on-corrupt + restore-truth note on cleartext IdP secrets in the archive); B-ADM(1) also covers `runResetPasswordCommand`; 6A.0 gains the 45 s `/api/idp/test` bound (client timeout + UNPROVEN handling) and the Basic-auth audit-actor attribution note. **B-CLU(9) (new, 6D):** bandwidth QoS is not enforced on the data path (PX-7) — render the not-enforced posture from the `bandwidth_qos_enforcement` contract row or defer the bandwidth mutation surface; B-CLU(3) urgency is durability-only. 6C.0's typed schemas gain the lease-mode-only `lease_reacquire_*` fields and `remote_counts_*`. **B-CA(5) widened to `/api/ocsp`** (R22b: viewer-visible `mtlsClientCertFile` path + raw `mtlsClientCertLastError`); the R-D line references become `ui_security.go:1750-1790`; 6B.2's upload contract has three server outcomes today, all collapsing into the R-D refusal shape. **B-SET(8)** gains `uiCustomTLSCorrupt`. **B-PORT(2)** keeps the new `warnings[]` but still requires the per-section durability shape and its OpenAPI declaration; **B-PORT(5) (new, restore-truth):** the pinned mount-point restore-commit defect (`restore_mountpoint_test.go`, `restore.go:912-962`) — the compose `cli` restore path cannot commit on a mounted `/data`; the 6F restore-truth surface must say so until the runbook or the code changes. **B-REL(6)** widened to the maintenance-agent route's raw `reason`; **B-REL(7)/B-DOC** add `MaintAgentStatus` and `ConfigImportResult.warnings` and the undocumented `GET /api/audit?format=` to the opaque/drift list; the attention-alert GUI gap is CONFIRMED. **B-MCP(1)** unchanged in substance (R68 adds the Basic-auth case); 6K1 adds the `review_id` bound + `shadow_exit_review_id_too_long`; B-MCP(10)'s file list adds `mcp_canary_runtime_*.json` (already noted in R-C). **New RED rows:** R22b (OCSP path/raw error on a viewer GET), R82/R83 (Auth Exempt kill switch: released by restart; asymmetric ceremony) under **FE-6L residue L-KS** (the kill switch is a Batch-2 2C surface extension landed on main with no v2 control — a new parity gap recorded here for the 2C successor, not an FE-6 write slice), R84 (`/api/maintenance-agent` `reason` carries the socket path to viewers), R85 (mount-point restore commit cannot land). **Decomposition and dependency order: UNCHANGED** — twelve slices, the `.0 → .1 → .2` rule, the `6I → 6J → 6K` and `6C.0 → 6C.1 → 6D` chains, `6E.0 → 6F.0`, SEC-C2 as 6H's standalone precondition, and 6L last.
>
> **R2-E. Lint inventory and ownership on the refreshed head (`28b42ee0`, tree = `origin/main@31f7d134` + the records; same toolchain; supersedes R-F's counts, §K's sequencing stands).** (a) `--new-from-rev origin/main`: **0**. (b) `--new-from-rev fdad5254` (since the Batch 1 merge): **6** — the five main-side MCP rows as before (`restoreCapability` `mcp_canary_runtime.go:630`, `commitRolloutTransitionCore` `mcp_rollout.go:328`, `runExecute`, `dispatchPolicy` 56, `armLiveTier`) plus one new main-side row, `unparam ha_lease_recovery.go:482 jitterDuration — frac always receives 0.2`; still none frontend-program. (c) full run: **146 repo-owned** (99 product / 47 `_test.go`; 79 files; gocritic 38, cyclop 25, gocognit 19, noctx 14, nestif 9, errcheck 8, funlen 7, unparam 7, gosec 6, staticcheck 5, bodyclose 3, dupl 3, unconvert 2). Net movement against the previous baseline is main's, not the program's: resolved — `cyclop metrics.go handleMetrics`, `funlen main.go handleOneShotCommands`, `gocognit ui_config.go apiConfigImport (91)`; new — `cyclop internal/threatfeed/threatfeed.go loadFromDisk (16)`, `dupl diagnostics.go:960-1023 ≙ :1046-1107`, `gocognit metrics.go handleMetrics (39)`, `gocognit ui_config.go apiConfigImport (93)`, `unparam ha_lease_recovery.go jitterDuration`, and `funlen socks5.go handleSOCKS5` grew 60 → 66 (the two `whyNoLint` rows merely swapped files between runs). The `funlen` set is now seven rows (`handleOneShotCommands` cleared on main). Ownership: frontend-program 0 / main-side post-Batch-1 6 / pre-Batch-1 140.
>
> **R2-F. Requalification of the refreshed head (`28b42ee0` + this record).** Custody: clean tree; remote equality re-proven at push; `origin/main@31f7d134` an ancestor of HEAD (re-fetched at the exit gate). Go: `gofmt -l` empty; `go build ./...` and `go vet ./...` clean. **Full `go test -race -count=1 ./...`** (the CI mode, not only the targeted MCP suites, because the advance touched authoritative files on every FE-6 surface): all 107 non-root packages `ok`; the root package hit the CI 15-minute `-timeout` on this 4-core box (the alarm fired while an ordinary 6 s test was running — a cumulative-duration timeout, not a hang; the runner's own budget is the same 15 minutes on faster hardware), and was re-run alone with a 60-minute budget: **`ok github.com/KidCarmi/Culvert 1794.1 s`, zero failing tests, no race reports, no panics.** This covers the targeted MCP runtime/tool-trust/canary/rollout/approval suites, the route/OpenAPI/conformance/contract gates (route pin 245, classification 1:1, apicontract conformance, C1/C1.5/C2/C2c/C4, D0) and every surface's own suites at once. Frontend `npm run verify` under node 24.19.0 / npm 11.17.0: ALL nine gates passed (generated-types drift none, 70 files / 787 tests, committed-dist drift none — the merged tree's regenerated `frontend/dist` reproduces byte-for-byte — tree clean afterwards). Lint: §R2-E. **FE-6-0-owned diff remains documentation-only:** `git diff origin/main` on the candidate head is exactly the three FE-6-0 records in `docs/design/FRONTEND-MIGRATION-PLAN.md`; no product code, frontend source, generated artifact, route metadata or committed `frontend/dist` changed. **STOP for external contract review; FE-6A and FE-6I do not start until the FE-6-0 record chain is approved or amended.**

> **FE-6A.0 IMPLEMENTATION RECORD — Identity Providers + Administrators backend-truth gate (this branch, 2026-09-11; append-only after the frozen FE-6-0 chain at `8087bd0a`).** Scope exactly as directed: the backend contract and durability correction for FE-V27 and FE-V37 and their session/RBAC/persistence/audit/secret-redaction/CP→DP interactions (B-IDP, B-ADM, B-REF); no React pages; legacy callers patched only where the corrected contract required it. **FE-6A.1/6A.2 not started. STOP for external review at the end of this record.**
>
> **6A0-A. Execution-order decision (recorded, not re-litigated).** FE-6I/6J/6K (MCP) are DEPENDENCY-BLOCKED: the MCP backend is under active development on `main` (PR #1360 landed between the FE-6-0 freeze and this entry gate, again all-MCP) and the owner has not declared the MCP contracts stable; FE-6 therefore begins with 6A.0 and the MCP frontend slices wait for that declaration. Nothing in the FE-6-0 records is rewritten by this decision.
>
> **6A0-B. Custody and entry gate.** Canonical branch `claude/culvert-frontend-fe6-hyagdj`; `claude/culvert-frontend-batch2` frozen at `8e73a619` (re-verified untouched); `8087bd0a` untouched. Entry: `origin/main` had advanced `31f7d134 → 574d265f` (PR #1360 mcp-canary-reviewed-target-binding; 35 files, +5309/−426) and was NOT an ancestor → ONE no-ff merge `b3f8090b` (tree == `origin/main` + the FE-6-0 records, proven by `git diff --stat origin/main HEAD` = the plan file only). Changed-file classification of the merge: 35 files, every one MCP-owned (`internal/mcp/canary|runtime`, `mcp_canary_*`, `mcp_live_*`, `mcp_rollout.go`, `mcp_tooltrust.go`, `mcp_observe_startup.go`, `scripts/mcp-canary-*`, two MCP docs); **zero** FE-6A.0 authority files changed (`auth_idp.go`, `ui_auth.go`, `ui_auth_ldap.go`, `auth_ldap_provider.go`, `store.go`, `controlplane_snapshot.go`/`_delta.go`/`_server.go`, `config_surfaces.go`, `ui_routes_meta.go`, `ui_middleware.go`, `ui_session.go`, `internal/session`, `backup.go`, `restore.go`, `main.go`, `ui_access_policy_startup.go`, `api/openapi/openapi.yaml`, `api/route-classification.yaml`, `static/index.html`, `frontend/src/api/types.gen.ts` — all byte-identical across the merge), so the FE-6-0 audit facts for 6A stand verbatim.
>
> **6A0-C. RED-before (commit `396e785f`, on the exact merged baseline, before any product change).** `fe6a0_red_test.go`: 18 test functions / 32 leaf assertions for R1–R14, every row failing at the assertion its defect predicts — R1 a registry READER blocked behind Upsert's discovery dial for the full bound (channel-held `ssrfSafeDialContext`); R2 `PUT /api/idp/ghost` → 200 and a created profile; R3 GET exposed no revision, an unfenced PUT/DELETE was accepted, delete-then-stale-PUT resurrected, second stale writer overwrote; R4 DELETE of an SSORequired-referenced provider → 204; R5 the emptied registry vanished from the wire (`omitempty`) and the DP kept the deleted profile; R6 no `clientSecretConfigured`/inline-metadata indicator and `clientSecret:""` present on the read model; R7 the enabling POST answered 200 with the cutover recorded in memory over a failed sentinel write, actor `system`; R8 a corrupt `idp_profiles.json` returned the boot-fatal parse error; R9 a password set destroyed the TOTP secret and replay counter (self-service and admin paths); R10 create/update/delete/change-password answered 2xx over a failed roster save; R11 no update verb (405) — the demoted admin's cookie kept admin authority; R12 `SetUIUser` demoted the last admin; R13 POST overwrote an existing user (200); R14 all 14 sampled refusals were `text/plain`. Seams: channel-controlled dial (R1), parent-is-a-regular-file persist injection (R7/R10), sequential stale-fence replays for the concurrency rows, the real middleware chain with a cookie jar (R11); no sleeps as correctness evidence (the one timer bounds only R1's failure branch).
>
> **6A0-D. Correction mapping (product commit `695e15c4`).**
> - **R1 / B-IDP(1)** — `auth_idp.go`: `prepareProfile` compiles (OIDC discovery, SAML metadata, LDAP) OUTSIDE every lock; every mutation is a transaction on the new `idpMutationMu` (`mutate`: snapshot → build candidate → `persist` → optional pre-publish step → swap under `r.mu`); `r.mu` is held only for swaps and reads, never across a compile or a disk write. `Load` compiles before publishing as well.
> - **R2/R3 / B-IDP(2)** — `IdPProfile.Revision` (server-minted: 1 on create, +1 per replace; persisted; carried CP→DP; caller values ignored via `normalizeIdPProfileWriteInput`; `idpEntryRevision` floors at 1), registry `DocumentRevision()` (content-derived); `Update(p, expectedRev)`/`DeleteFenced(id, rev)` decide the fence INSIDE the transaction (`errIdPVanished`, `*idpStaleError{Current}`); the handlers pre-check for a fast refusal and re-decide authoritatively. `PUT` never creates.
> - **R4 / B-IDP(3)** — `policy_refs.go` gains the `idp` object type (exact id match on `Auth.ProviderRefs`, running rules + the draft candidate); `apiIdPDelete` answers `409 referenced` with `current.references` (consumerType/id/name/detail/view) — code chosen as `referenced` (the RED matrix's name; B-IDP(3)'s `referenced_by` is the same fact). The Where-Used endpoint now answers `type=idp` too (its `IdpRejected` test inverted).
> - **R5 / B-IDP(6)** — `ConfigSnapshot.IdPProfiles` loses `omitempty` (row `idp_profiles` declared `WireWipeCapable`, note updated); `All()` is never nil; `syncSnapshotIdPProfiles` treats nil (an older CP) as skip and an explicit `[]` as the instruction; `ReplaceAll` also REBUILDS a degraded DP registry (a CP snapshot is the authoritative repair on a data plane).
> - **R6 / B-IDP(4)** — `OIDCProfileConfig.ClientSecretConfigured` and `SAMLProfileConfig.InlineMetadataConfigured` (derived in `publicIdPProfile`, zeroed on write; named without the `metadataXml` stem so secret-absence scans never false-positive); `clientSecret` is now `omitempty` so no read model carries the key at all; `TestPublicIdPProfile_ProjectionParity` lists both as derived.
> - **R7 / B-IDP(5)** — the enabling write's pre-publish step (`idpLegacyCutoverHook`): registry candidate persisted → `saveAdminSettingsWithOverrides{legacyCutover}` writes `legacy_ldap_retired:true` + the new `legacy_ldap_cutover` record (`LegacyLDAPCutover{operationId, profileId, profileName, registryRevision, actor, trigger, at}`, bound to the candidate's document revision) with the runtime sentinel flipped only in `applyOnSuccess` (`markLegacyLDAPRetiredWith`, at-most-once, audited `idp.legacy_ldap.retired` with the ADMIN actor and the operation id) → registry publish → `enforceLegacyLDAPShadowing` deactivates the legacy provider. A failed sentinel write restores the registry file to its EXACT prior bytes (`readPersisted`/`restorePersisted`, including "no file yet") and answers `500 persist_failed` with the legacy authenticator still wired and nothing published; a failed rollback is the NON-terminal `500 outcome_unknown {current.detail: registry_persisted_sentinel_not_durable}` — nothing published, the next boot reconciles from disk (existing `applyLegacyLDAPRetirement`). The record is surfaced on `GET /api/idp/legacy-ldap` (`cutover`, plus `scope:node-local`) and round-trips through `admin_settings.json` (row `legacy_ldap_retired` binds `LegacyLDAPCutover`). The observed/boot/CP-sync path (`markLegacyLDAPRetired`) keeps actor `system`, trigger `observed`. **Deferred to 6A.2 (recorded):** the explicit CEREMONY word before an enabling LDAP write on a node with an un-retired legacy block — the read model already exposes `retired`/`shadowed`/`cutover` to gate it; the server-side confirm fence lands with the client ceremony so legacy and v2 switch in one commit (the 2F-A rule).
> - **R8 / B-IDP(7)** — `Load` quarantines a corrupt file (`quarantineCorruptStateFile("idp_profiles", …)`, `<path>.corrupt.<unixnano>`, CHAOS-05 vocabulary incl. `noteResidualQuarantine`) and returns nil with the registry EMPTY and `degraded` (`reason corrupt_quarantined|corrupt_not_quarantined`, detail, `quarantineEvidence`); every write is `503 registry_degraded` until `POST /api/idp/repair {confirm:<quarantine base name>}` (admin, audited `idp.repair`; `409 not_degraded|confirm_mismatch(current.confirmValue)|repair_unavailable`) clears the posture (registry stays empty; nothing written). Boot: `loadUIAccessPolicy` no longer fails (`TestLoadUIAccessPolicy_IdPProfilesParseErrorSurfaces` and `TestIdPRegistry_Load_BadJSON` inverted to the corrected behaviour). Restore-truth (unchanged code, recorded fact for C14): `backup.go` archives `idp_profiles.json` WITH its cleartext secrets and `ui_users.json` with TOTP secrets — the 6F restore-truth surface must state it.
> - **R9 / B-ADM(1)** — `SetUIUser`/`applyRosterSet` replace only the credential (TOTP secret, backup codes, replay counter preserved); `SetAuth` mirrors the same way; covers `runResetPasswordCommand` (it calls `SetUIUser`).
> - **R10 / B-ADM(2)** — `store_roster.go`: `commitRoster` = snapshot the live roster into a candidate copy → optional fence → mutate the candidate → persist (`roster_revision` in the envelope) → publish (roster, revision, auth cache, legacy mirror) under `saveUIUsersMu`; `CreateUIUser`/`UpdateUIUser`/`DeleteUIUserFenced`/`ChangeUIUserPassword` ride it; a failed write is `errRosterPersistFailed` → `500 persist_failed` with memory, sessions and the revision untouched. Lockout-clear is node-local in-memory state — there is nothing to persist (recorded).
> - **R11 / B-ADM(3)** — `PUT /api/auth/users` (new verb; POST is create-only): after the durable commit a role or credential change revokes the user's sessions issued at or before the change (`internal/session.RevokeUserIssuedBefore` on the new `Session.Iat` unix-nanos field; legacy cookies read as issued at `Exp − TTL`), while a login AFTER the change is honoured — deletion keeps `RevokeUser` (full TTL block). Responses carry `sessionsRevoked` and `selfAffected` (actor == target).
> - **R12/R13 / B-ADM(4)** — last-admin guard in `applyRosterSet`/`applyRosterDelete` (store level, decided against the candidate under the mutation lock; `409 last_admin`); POST is `409 user_exists` for an existing name; DELETE of an unknown user is `404 not_found` (never a silent 204) and success is `200 {deleted:true, username, revision, persisted, sessionsRevoked, selfAffected}`. The legacy single-user mirror (`c.user/passHash`, what `IsConfigured`/`AuthEnabled`/`LoginNameConfigured` read) is kept TRUTHFUL by `syncLegacyMirrorLocked`: a deleted mirrored admin cannot authenticate through the fallback, and the mirror is re-pointed deterministically (lowest admin username) so deleting the bootstrap admin never reopens first-time setup.
> - **R14 / B-REF** — `ui_refusal.go`: `writeRefusal` (`{error, code, current?}`), `requireRoleJSON` (same C4 divergence hook; recognised by the C1.5 scanner beside `requireRole`), `revisionFence`/`checkRevisionFence` (the 2F-A shape: query wins over body; 428 `precondition_required` / 409 `stale`, both with `current.revision`). Bounded codes: `invalid_input` 400; `forbidden`/`invalid_credentials` 403; `not_found`/`vanished` 404; `stale`/`last_admin`/`user_exists`/`referenced`/`confirm_mismatch`/`not_degraded`/`repair_unavailable` 409; `precondition_required` 428; `persist_failed`/`outcome_unknown` 500; `upstream_error` 502; `registry_degraded` 503; `method_not_allowed` 405. Every 6A handler (`apiAuthUsers*`, `apiAuthLockouts`, `apiAuthChangePassword`, `apiIdPList`, `apiIdPItem`/`apiIdPUpdate`/`apiIdPDelete`, `apiIdPGroups`, `apiIdPDiscover`, `apiIdPRepair`, `apiIdPTest`, `apiIdPLegacyLDAP`, `apiIdPLegacyLDAPImport`) uses it; no raw filesystem/network/LDAP/OIDC error reaches a body (discovery failure is `502 upstream_error`, cause in the log).
> - **Identity/fencing/refusal contracts, one line each:** IdP entry = `id` + integer `revision` (fence on PUT/DELETE); IdP registry = string content revision (list read model); roster = integer `revision` (fence on PUT/DELETE); refusal = `{error, code, current}`; success = action-bound evidence (`revision`, `deleted:true`, `repaired:true`, `persisted`, `sessionsRevoked`, `selfAffected`).
> - **Audit:** emitted names now equal the declarations — `auth.users.create` / `auth.users.update` / `auth.users.delete` (replacing `auth.users.set`), `auth.password_change`, `auth.lockout.clear`, `idp.create` / `idp.update` / `idp.delete` / `idp.import` / `idp.test` / `idp.repair` / `idp.discover` (now emitted: issuer host + `ok|failed`) / `idp.legacy_ldap.retired`; pinned by `TestFE6A0_Green_AuditDeclarationsMatchEmittedNames`.
> - **Route/OpenAPI accounting (C15):** `uiRoutes` — `/api/auth/users` gains `PUT` (admin); `/api/idp/` becomes PER-METHOD (`GET` viewer, `PUT`/`DELETE` admin — the recorded C4 divergence on the `MethodAny=viewer` row is CLOSED; the three C4 chain-proof tests now ride a synthetic dispatcher fixture and a fourth pins that C2 itself denies a viewer PUT on `/api/idp/`); `/api/idp/discover` `AuditExpected:true`; NEW `/api/idp/repair` (POST admin) — route pin **246** (C1 + D0). Classification: PUT users row; `/api/idp/` rows GET/PUT/DELETE documented via `openapi_path: /api/idp/{id}` (+ `openapi_extra_paths: /api/idp/{id}/groups`) — the prefix exemption is RETIRED; repair row. OpenAPI 2.0.0: `AuthRefusal` + seven reusable refusal responses, `UpdateUserRequest`/`UserMutationResult`/`UserDeleteResult`, `IdPProfileRead`/`IdPDeleteResult`/`IdPRepairRequest`/`IdPRepairResult`, `UserList.revision`, `IdPList.{degraded,…,revision}`, `LockoutsList.scope`, the users PUT op, `/api/idp/{id}` GET/PUT/DELETE, `/api/idp/{id}/groups`, `/api/idp/repair`, typed refusals on every 6A op; `make api-lint`, `api-route-coverage`, `api-bundle` regenerated (`openapi.json`, `index.html`, `index.public.html`, `API-INVENTORY.md`); `frontend/src/api/types.gen.ts` regenerated by the canonical script; **`frontend/dist` unchanged** (types are erased at build). B-IDP(8) is closed for the paths; the `oidc`/`saml` sub-configs stay `additionalProperties:true` objects — 6A.1 hand-authors the decoder with a pinned shape test (the B-IDP(8) alternative).
> - **Legacy UI (`static/index.html`, minimal, contract-required):** `openIdPModal` records the loaded `revision`, `saveIdP` echoes it on PUT (`&preflight=connection` preserved), `deleteIdP` reads the current revision then deletes fenced, `fetchUsers` records the roster revision, `saveUser` uses PUT for edits, `deleteUser` sends the revision, `api()` renders a typed refusal's `error` text; 409/428 on the IdP modal reload the list. Pinned by `TestFE6A0_Green_LegacyUISendsFencesAndTypedRefusals`. The Playwright suites exercise the v2 SPA, not the legacy shell, so the legacy patches are proven by the real-binary journey (6A0-F) and the markup pins.
> - **Not changed (recorded):** `idp_profiles.json` and `ui_users.json` still store their secrets in cleartext (encryption-at-rest stays a §J deferral); `runResetPasswordCommand`'s one-shot ordering is unchanged (its `SaveUIUsersFile` error is returned, not logged); the 45 s `/api/idp/test` server bound stands, the client timeout + UNPROVEN handling is 6A.2; TOTP enrollment (GAP-2) stays descoped.
>
> **6A0-E. Proofs (GREEN).** `fe6a0_red_test.go` (R1–R14, 18 functions) and `fe6a0_green_test.go` (18 functions): fenced PUT race with 8 writers → exactly one 200 / seven 409 and one revision step; DELETE-vs-PUT race → one of the two contracted outcomes, never a resurrection; mutual demotion of the two admins under one fence → exactly one succeeds and one admin remains on disk, then `last_admin` on the survivor; concurrent deletes of both admins → one succeeds, setup never reopens; revision/roster-revision/cutover-record restart durability; the `outcome_unknown` branch publishes nothing and leaves the durable candidate for boot reconciliation; `RevokeUserIssuedBefore` semantics (before-cutoff rejected, later login honoured, legacy cookie rejected, deletion blocks all); secret absence on create/delete responses, the process log, audit before/after/detail, the config-version snapshot and the legacy-LDAP read model; explicit `idp_profiles:[]` on the wire vs nil-is-skip control; a CP snapshot rebuilds a degraded DP registry durably; `SetUIUser`/`SetAuth` preserve TOTP; the deleted mirrored admin cannot use the legacy fallback; the cutover mark is at-most-once; response conformance of users GET/POST/PUT/PUT-409/PUT-428/DELETE, idp GET list/item, PUT-428, DELETE and lockouts GET against the OpenAPI schemas; audit-declaration parity (9+ declared events, each emitted); legacy-UI markup pins. Existing suites adapted, not weakened: 17 unfenced PUT/DELETE sites now echo the fence (`fencedIdPPath`/`fencedUsersPath`/`fencedDeleteReq`, `fe6a0_helpers_test.go`), two boot-fatal pins inverted (R8), the `type=idp` Where-Used pin inverted (R4), DELETE 204 pins → 200, the projection-parity filler extended to `int64` + the two derived indicators, the C1.5 scanner recognises `requireRoleJSON`.
>
> **6A0-F. Qualification of the candidate head (`695e15c4` + this record).** Custody: clean tree; local == remote at every push; `origin/main@574d265f` re-fetched at the exit gate and still an ancestor (no further advance); `8087bd0a` and `8e73a619` untouched. Changed-file classification since the RED commit (40 files, +4625/−665): production Go 12 (`admin_settings.go`, `auth_idp.go`, `auth_ldap_provider.go`, `config_surfaces.go`, `controlplane_snapshot.go`, `internal/session/session.go`, `policy_refs.go`, `store.go`, NEW `store_roster.go`, `ui_auth.go`, `ui_auth_ldap.go`, NEW `ui_refusal.go`, `ui_routes_meta.go`, `ui_session.go`); test Go 20 (NEW `fe6a0_green_test.go`, NEW `fe6a0_helpers_test.go`, `fe6a0_red_test.go`, 17 adapted suites); contract artifacts 5 (`openapi.yaml`, regenerated `openapi.json`/`index.html`, `route-classification.yaml`, `API-INVENTORY.md`); generated frontend types 1 (`frontend/src/api/types.gen.ts`, canonical script); legacy UI 1 (`static/index.html`); `frontend/dist` unchanged; no MCP, cluster, CA, releases, support or settings file touched. Go: `gofmt -l .` empty; `go vet ./...` and `go build ./...` clean; **diff-scoped lint** `golangci-lint run --new-from-rev origin/main` (v2.5.0 built with go1.26.6): **0 issues** (seven mechanical findings of the first pass — two unnamed results, three `rangeValCopy`, two gosec G101 identifier hits — fixed in the same commit); no unrelated lint debt repaired. Tests: R1–R14 + GREEN **`-race -count=3`** ok (140.6 s), the affected-suite shuffle lane (`-count=2 -shuffle=on`) ok; **full root `go test -race -count=1`**: `ok github.com/KidCarmi/Culvert 2054.9 s` (60-minute budget on the 4-core box; zero failures, no race reports, no panics — includes the route pin 246, classification 1:1, apicontract conformance, C1/C1.5/C2/C2c/C4, D0, the projection-parity gate, the wire-wipe parity gate and every surface's own suites); **every non-root `-race` package** (`./internal/...`, `./cmd/...`) ok; the `cmd/culvert-maint` module `-race` ok; `make api-lint`, `make api-route-coverage`, `make api-bundle` (regenerated, committed). Cross-compile `GOOS=linux GOARCH=arm64 go build` ok; **binary determinism**: two `-trimpath -buildvcs=false` amd64 builds byte-identical (sha256 `825baf00…a66b8`). Frontend `npm run verify` under node 24.19.0 / npm 11.17.0 after the commit: ALL nine gates passed (generated-types drift none, 70 files / 787 tests, committed-dist drift none). **Real-binary integration with restart** (the built binary, HTTPS admin UI, a fresh `CULVERT_DATA_DIR`, `-ui-users-file`/`-idp-profiles-file`/`-revocations-file`): setup → login → user create (revision 2) → fenced PUT demote (200, `sessionsRevoked:true`) → unfenced DELETE 428 → POST existing 409 → IdP create (revision 1, secret absent from the response) → fenced PUT (revision 2, `bindCredentialConfigured:true`) → stale PUT 409 → unfenced DELETE 428 → **restart** → roster `{alice viewer, root admin}` at revision 3 and the profile at revision 2 survive, the demoted user's fresh login is a viewer (403 on the admin route) → the registry file corrupted → **restart** → the node boots, `degraded:true corrupt_quarantined` with the evidence name, writes 503, wrong confirm 409, repair 200, write 200; the process log never carried the bind credential. **Playwright, two consecutive full runs** of `frontend/scripts/e2e-smoke.sh` (real binary + pinned Sluice, four appliance instances; `CULVERT_PW_CHROMIUM=/opt/pw-browsers/chromium` because this container ships Chromium r1194 while `@playwright/test` 1.62.1 expects r1234 — the config's documented override, no download): **147 passed / 3 skipped, twice** (3.4 m, 3.3 m). **`/data` restoration:** NOT byte-identical, and this is recorded rather than glossed — the root suite's PRE-EXISTING tests persist config versions into the default `/data/config_versions` store (capped at 50; it rotated from v135–v184 to v367–v416, the last 36 the same fixture sizes one-for-one) and rewrote `alert_retry_queue.json`; no FE-6A.0 test writes there (`withConfigVersionsDir` isolates the two that touch versions) and the pre-round baseline already carried 50 such rotated fixtures; a hygiene item for the test suite, outside this slice.
>
> **6A0-G. Deferrals and remaining 6A work (recorded).** 6A.1 (read): hand-authored IdP list/detail decoders over `IdPProfileRead` with a pinned shape test (the `oidc`/`saml` sub-configs stay open objects on the contract), degraded-posture + quarantine-evidence rendering, Administrators list + lockouts (node-local label), the `cutover` facts on the legacy-LDAP card. 6A.2 (write): the fenced ceremonies (PUT/DELETE with the loaded revision, 428/409 as typed facts, `referenced` rendering with the rule links, `user_exists`/`last_admin`), the explicit legacy-LDAP cutover ceremony with its server-side confirm fence (landing together with the client, the 2F-A rule), the `/api/idp/test` 45 s client timeout + UNPROVEN handling, the repair ceremony (T2 word = `quarantineEvidence`), `selfAffected` sign-out handling, and the UNPROVEN-2xx latch (2F-F rule) on every mutation. Not solved by 6A.0 and recorded: cleartext IdP/TOTP secrets at rest and in the archive (restore-truth row for 6F); TOTP enrollment (GAP-2); the pre-existing root-suite writes into `/data/config_versions`. **STOP for external review of FE-6A.0; 6A.1/6A.2 do not start until this record is approved or amended.**

> **FE-6A.0 CORRECTION RECORD — external review REJECTED → one append-only correction round (this branch, 2026-09-12; `e3c0d5d7` untouched).** Ten blockers, each with a deterministic correction RED row committed on exactly `e3c0d5d7` BEFORE any product change (`447f3d67`, `fe6a0c_red_test.go` CR1–CR10, every row failing at the assertion its blocker predicts, with `CR3_LegacySingleUserChangeMigratesDurably` as the passing control), the product correction in ONE commit (`310d2868`), and this record. Custody unchanged: `claude/culvert-frontend-batch2` frozen at `8e73a619`; `8087bd0a`, `b3f8090b`, `396e785f`, `695e15c4`, `e3c0d5d7` untouched; no PR; no history rewrite. **FE-6A.1/6A.2 not started. STOP for external review at the end of this record.**
>
> **6A0C-A. Blocker → correction, one entry each (product commit `310d2868`).**
> - **B1 — self-service password change.** `apiAuthChangePassword` is bound to the caller's per-user SECURITY GENERATION (`?generation=`/body, read from `GET /api/auth/status` which now exposes `securityGeneration` for the authenticated caller): order decode → account exists (404 `not_found` when deleted) → verify current password (403 `invalid_credentials`) → durability (503) → fence (428 `precondition_required` / 409 `stale`, both `current.generation`) → `ChangeUIUserPassword(user, pass, expectedGen)`, ONE `commitRoster` transaction that REVALIDATES the generation under the roster lock (a competing admin update ⇒ `*rosterGenStaleError` → 409 stale; a competing delete ⇒ `errRosterNotFound` → 404; zero mutation) and commits persist-before-publish. After the durable commit every session issued under the previous generation is invalid (B2) and the caller's own UI session is re-issued at the new generation (Set-Cookie; a Basic-auth caller gets no cookie). Result: `{ok, revision, persisted, sessionsRevoked:true, selfAffected:true, securityGeneration}` (`ChangePasswordResult`). No legacy JS caller exists for this route (verified: `static/index.html` has none).
> - **B2 — durable per-user authentication generation.** `uiAdminUser.securityGen` minted from a ROSTER-WIDE monotonic counter (`security_counter` in the `ui_users.json` envelope; per-user `security_generation`; floor 1 on a pre-correction file; never reused, so a delete+recreate never inherits an old cookie's generation); `applyRosterSet` advances it on every role/credential change inside the roster commit; `Session.Gen` is embedded at login (`setUISessionCookie`); `uiAuthMiddleware` validates EVERY local cookie session against the durable record (`cfg.UserRoleAndGeneration`: user must exist, `Gen>0`, `Gen==current`; the ROLE is the record's, never the cookie's — a legacy cookie without a generation fails closed) and `apiAuthStatus` (public route, outside the middleware) applies the same rule. The in-memory `RevokeUserIssuedBefore`/`Session.Iat` mechanism of `695e15c4` is REMOVED (it did not survive a restart); `RevokeUser` (deletion, full TTL block) stays. `GET /api/auth/users` and every user mutation result carry `securityGeneration`.
> - **B3 — legacy single-user change is one transaction.** The `SetAuth` pre-call is gone: `ChangeUIUserPassword` migrates a mirror-only identity INSIDE `commitRoster` (`tx.legacyUser`, generation 1 by definition, admin role) — `cfg.user`/`passHash`, the auth cache and sessions change only in the publish step after the durable write; a failed write leaves the old credential usable, the new one unusable, no roster entry, `AuthEnabled` intact (CR3, verified against a parent-is-a-regular-file path).
> - **B4 — every mutation fenced.** IdP create: `?documentRevision=` (= `IdPList.revision`) — 428 `precondition_required {current.documentRevision}` / 409 `stale {current.documentRevision}`, pre-checked in the handler and DECIDED AGAIN inside the transaction (`Create(p, expectedDocRev, …)`, `*idpDocStaleError`). Administrator create: `?revision=`/body against the roster revision (428/409 `current.revision`), decided inside `commitRoster`. Password change: the target's security generation (B1). Lockouts: `GET /api/auth/lockouts` exposes a server-owned lock-set `generation` (advances under the limiter lock on every failure/success/reset/cleanup that changed the set); `POST` asserts it (`?generation=`/body): 428 absent, 409 `stale {current.generation}`, 404 `not_found` when the username holds no state — `LoginLimiter.ResetUserIfGeneration` checks and clears under ONE lock acquisition (N concurrent resets ⇒ exactly one `ResetOK`, pinned in `internal/lockout`). Legacy JS patched accordingly (`saveUser` create carries the roster revision; `fetchLockouts`/`unlockUser` carry the generation; `loadIdPList`/`saveIdP` carry the document revision + a client `operationId`).
> - **B5 — shared reference-integrity boundary.** `apiIdPDelete` runs the reference scan AND `DeleteFenced` (+ publication) under `refScanDeleteLock` — the EXCLUSIVE side of `objectReferenceMutationGate`, which every SSORequired `providerRefs` writer (`apiAuthPolicyCreate`/`Update` — `validateSSOProviderRefsLive` → `fencedRunningMutate`) already holds on the shared side. Both interleavings proven with real handlers: writer-first ⇒ the delete waits, then sees the committed reference (409 `referenced`, provider kept, rule exists); delete-first (`idpDeletePauseHook` test seam between scan and delete) ⇒ the writer waits, revalidates against the post-delete registry and is refused (400), no dangling rule, no store generation advance. CR5 pins the blocking itself.
> - **B6 — validation vs dependency.** `prepareProfile` returns `*idpValidationError` (400 `invalid_input`, Culvert's own wording; the OIDC `client_id`/config presence checks and an inline SAML `metadataXml` that does not parse are intrinsic) or `*idpCompileError{reason}` (502 `provider_compile_failed`, `current.reason ∈ {oidc_discovery, saml_metadata, ldap_provider, unsupported}`); the provider's error text is DROPPED at that seam — the process log carries `reason=` only, the audit trail nothing, `writeIdPRefusal`'s default branch is a fixed message. The LDAP directory-test / preflight report's per-step `error` is now a bounded class (`timeout|tls_failed|unreachable|invalid_credentials|no_such_object|insufficient_access|directory_error`) with the existing `action` hints; raw hostnames/TLS/transport text no longer reach the 422 body. Canary proofs on response + log + audit for OIDC discovery (CR6), SAML metadata fetch and LDAP preflight (GREEN). Trade recorded: the admin diagnostic loses the directory's verbatim message.
> - **B7 — non-persistable stores.** `requireDurableIdP` (POST/PUT/DELETE `/api/idp*`, legacy import) and `requireDurableRoster` (users POST/PUT/DELETE, change-password) refuse with 503 `persistence_not_configured` BEFORE any runtime mutation, no audit; reads keep reporting `persisted:false`; setup and the reset-password one-shot keep their bootstrap contract; the CP→DP sync and boot loaders are not administrative mutations. The test process binds the package-global roster/registry to files under the test data dir (`TestMain`) and the shared test registries (`withTestIdPRegistry`, `swapIdPRegistry`, `makeIdPRegistryDurable`) are durable; `setupProxyTest` now restores the global `cfg` it replaced.
> - **B8 — cluster publication facts.** `idpPublishFleet` → `cluster:{publication: published|rejected, version | reason}` on every IdP mutation result (create/update/delete/import), `reason` a BOUNDED class from the new typed `publishRejectedError` in `ConfigStore.Update` (`identity_degraded|snapshot_invalid|marshal_failed|wire_size_exceeded`); audit detail carries ` fleet=published vN` / ` fleet=rejected:<class>` beside the local commit; `GET /api/idp` carries `cluster:{state: published|pending, publishedVersion, lastRejection{reason,at}}` derived by comparing the published snapshot's registry document revision with the authoritative local one; a rejected publication never advances the store version; the empty-registry publication (last delete) follows the same contract (CR8).
> - **B9 — operation-identified cutover.** Client UUID `?operationId=` on `POST /api/idp`: REQUIRED (428 `operation_id_required`) when the write carries the legacy-LDAP cutover, honoured otherwise. `idp_operations.go`: a bounded (256) atomically-written intent ring beside the registry file (`idp_operations.json`; in-memory only with an in-memory registry, which B7 refuses anyway) — `Begin` persists `{operationId, action, actor, pre-minted profileId, public-spec digest, fenced registry revision, cutover}` as `pending` BEFORE the first irreversible write; `Finish` records `committed` (with the exact response the client received + the committed document revision) / `aborted` (refusal code) / `outcome_unknown`; a duplicate operationId REPLAYS the recorded response (`replayed:true`, never a second create or cutover; same spec required — 409 `operation_mismatch`; pending ⇒ 409 `operation_in_progress`; aborted ⇒ 409 `operation_aborted`; unknown ⇒ 409 `operation_outcome_unknown`); NEW `GET /api/idp/operations/{operationId}` (admin, route pin **247**) is the authoritative lookup; `IdPRegistry.Load` RECONCILES every non-terminal record against the registry file (profile present ⇒ committed, absent ⇒ aborted `reconciled_absent`) so a process death mid-operation is settled from durable truth. The 6A.2 ceremony stays unimplemented. Observed cutover truth: `markLegacyLDAPRetired` records its `SaveAdminSettings` OUTCOME (`legacyLDAPCutoverDurableFlag`); `GET /api/idp/legacy-ldap` reports `cutover.durable` and `cutoverDurability ∈ {not_retired, durable, pending_reconciliation}` — a failed sentinel save keeps the runtime cutover (safety first) but never claims durability; the flag is set by a file load and by any later successful settings save.
> - **B10 — operator `/data`.** `TestMain` calls `rebindDataDirPaths()` after choosing the temp root, so the config-version store, registry settings, CDR paths and the alert retry queue follow it (CR10 pins `configVersions.Dir()` under the test root). `/data` was snapshotted (tar + sha256 of all 51 files) before the qualification below and compared after both full runs: **byte-identical, zero diff**.
>
> **6A0C-B. Accepted R1–R14 rows.** Assertions unchanged. Request construction only: creates carry the document/roster fence and (cutover rows) an operationId through `fencedIdPCreatePath`/`fencedUsersPath`/`fencedChangePasswordPath`/`fencedLockoutsPath`/`testOperationID` (`fe6a0_helpers_test.go`); `TestFE6A0_Green_IssuedBeforeRevocationHonoursLaterLogins` is REPLACED by `…SecurityGenerationSupersedesEarlierSessions` (the mechanism it pinned was removed by B2, its property is re-pinned on the durable generation); the audit watermark helper `fe6aSince()` spins until the millisecond advances (the TS-only watermark counted a same-millisecond legitimate write as "after" — a harness alignment, not evidence) and CR9 uses an exact ring snapshot for the replay's no-audit assertion. Pre-existing suites adapted: 17 request sites gained the create fence; in-memory test registries made durable; `TestAPIIdPListGet_RedactsClientSecret` keeps its path-less registry (reads still report `persisted:false`).
>
> **6A0C-C. Proofs.** RED (CR1–CR10, 15 functions) + GREEN (`fe6a0c_green_test.go`, 11 functions; `internal/lockout/lockout_generation_test.go`, 2): self-change vs concurrent admin update (409) / delete (404); durable invalidation across restart + fresh login valid + legacy cookie fail-closed; legacy-single-user failure boundary; missing/stale create fences on both stores; lockout-reset generation race (16 concurrent, one winner); IdP delete vs SSORequired create in BOTH directions; OIDC/SAML/LDAP canaries absent from response/log/audit; refusal on non-durable stores (registry POST/PUT/DELETE/import, roster POST/PUT/DELETE/change-password); rejected publication as a structured fact on create/update/delete + read-model recovery; cutover lost response (replay), duplicate operationId (mismatch), aborted replay, in-progress replay, restart reconciliation (present ⇒ committed, absent ⇒ aborted) and replay across restart; observed-cutover durability truth; per-user scope of invalidation; legacy-UI pins; contract conformance (users POST now documents 428/503).
>
> **6A0C-D. Contract artifacts.** OpenAPI: `AuthStatus.securityGeneration`, `User.securityGeneration`, `CreateUserRequest.revision` + users POST `revision` param/428/503, `ChangePasswordRequest.generation` + `ChangePasswordResult` + 404/409/428/503, `LockoutsList.generation`/`ClearLockoutBody.generation`/`ClearLockoutResult` + 404/409/428, IdP POST `documentRevision`/`operationId`/`preflight` params + 409/428/502 + `IdPMutationResult` (also on PUT), `IdPClusterState`/`IdPClusterPublication`/`IdPOperation`, `IdPList.cluster`, `IdPDeleteResult.cluster`, NEW `/api/idp/operations/{operationId}`, `AuthRefusalProviderCompileFailed`, the extended `AuthRefusal` code list; classification row for the lookup route; `make api-lint`/`api-route-coverage`/`api-bundle` regenerated; `frontend/src/api/types.gen.ts` regenerated by the canonical script; `frontend/dist` unchanged.
>
> **6A0C-E. Qualification — twice: the correction head, then the exit-gate merge.** Custody: clean tree; local == remote at every push; `8087bd0a`, `8e73a619`, `e3c0d5d7`, `447f3d67` untouched. **(1) Correction head `310d2868` (+ the pin commit `2ef69bb9`).** `gofmt -l .` empty; `go vet ./...`/`go build ./...` clean; diff-scoped lint `golangci-lint run --new-from-rev 574d265f` (v2.5.0 / go1.26.6): **0 issues** (the pass's own findings — `apiIdPCreate` cyclomatic 23 → split into four helpers, unused sentinels, goimports grouping, revive comment forms, an unconvert, unnamed results — fixed before the commit; no unrelated lint debt repaired). FE-6A.0 + correction matrices **`-race -count=3`: ok (356.6 s)**; the affected-suite shuffle lane (`-count=2 -shuffle=on`): ok (121.9 s); **full root `go test -race -count=1`: `ok github.com/KidCarmi/Culvert 2196.9 s`**, zero failures, no race reports (the first attempt under the CI 25-minute budget on this 4-core box hit the cumulative timeout while an ordinary test was running — re-run alone with a 60-minute budget, the 6A0-F precedent); `./internal/...` + `./cmd/...` `-race`: 107 packages ok, 0 races; the `cmd/culvert-maint` module `-race`: 10 ok. Cross-compile `GOOS=linux GOARCH=arm64` ok; binary determinism: two `-trimpath -buildvcs=false` builds byte-identical (sha256 `e591be5c…7f47d4`). Frontend `npm run verify` (node 24.19.0 / npm 11.17.0): all nine gates passed (generated-types drift none, 70 files / 787 tests, committed-dist drift none). **Real-binary journeys with restart** (the built binary, HTTPS admin UI, fresh `CULVERT_DATA_DIR`): (a) the correction journey — users POST unfenced 428 / fenced 200 (`securityGeneration` 2); two bob devices; change-password unfenced 428 (`current.generation` 2) / stale 409 / fenced 200 with `sessionsRevoked`, `selfAffected`, generation 3, revision 3 and a re-issued cookie; the caller stays logged in, the other device reads `loggedIn:false` and 401 on a gated route; IdP POST unfenced 428 (`current.documentRevision`) / fenced+operationId 200 (`cluster.publication published v1`, secret absent) / same operationId replayed (`replayed:true`, same id, one profile) / stale documentRevision 409 / lookup `committed` / unknown 404; read model `cluster.state published`; six failed logins → lockout listing with `generation`, reset unfenced 428 / fenced 200 (generation advanced) / stale 409; **restart** → the pre-change cookie still `loggedIn:false` and 401, a fresh login with the new credential valid, the operation lookup still `committed`, the replay still answers the recorded result, one profile, `idp_operations.json` beside the registry; the process log never carried the bind credential (27/27 checks); (b) the 6A0-F journey re-run with the create fences added: identical outcomes (fenced PUT `sessionsRevoked:true` → 428 → 409 → IdP create/PUT/stale/428 → restart → roster + profile survive, demoted user is a viewer → corrupt registry → restart → `corrupt_quarantined` + evidence, 503, 409, repair 200, write 200). **Playwright** (`frontend/scripts/e2e-smoke.sh`, `CULVERT_PW_CHROMIUM=/opt/pw-browsers/chromium`): 147 passed / 3 skipped — the second consecutive run was REFUSED by the harness's own disk-guard precondition, and the cause was the harness, not the product: `start_instance` backgrounded a SUBSHELL, so `$!` named the subshell, cleanup's SIGTERM killed only that, the four appliances were reparented to init and kept their fixed ports, and the next run's readiness probes and seed login hit the PREVIOUS run's instances (verified: the lingering appliances answered 200 and exited 13 s after a SIGTERM sent to the real PID). Fixed with `exec` in the harness (`12a2ef6c`); with it, two consecutive runs: **147 passed / 3 skipped, twice** (3.8 m, 3.9 m), no lingering appliance. **(2) Exit gate: `origin/main` had advanced `574d265f → 0046feed`** (PRs #1362/#1363/#1366/#1368: MCP first-canary exact scope, the lock-free rate-limit exempt view, the compose YARA-dir doc fix, a governance review; 23 files, ONE overlapping FE-6A.0 authority file, `admin_settings.go`, in an unrelated hunk — `rl.AddExemptions`) and was not an ancestor → ONE no-ff merge `7b080181`, clean, then the FULL qualification again on the merged head: build/vet clean; lint `--new-from-rev origin/main` **0 issues** (a first attempt hit golangci-lint's default deadline under the concurrent race-run load — exit 4, re-run with `--timeout 40m`); **full root `-race`: `ok github.com/KidCarmi/Culvert 2167.3 s`**, zero failures, no race reports; `./internal/...` + `./cmd/...` `-race` 107 ok, 0 races; `cmd/culvert-maint` `-race` 10 ok; arm64 ok; determinism byte-identical (sha256 `ecbf6b91…`); frontend verify all nine gates (70 files / 787 tests, no drift); both real-binary journeys identical (27/27; `INTEGRATION_DONE`); Playwright 147/147 twice (above). `origin/main` re-fetched after the last run: still `0046feed`, an ancestor. **`/data` restoration: byte-identical zero diff** — sha256 of all 51 files under `/data` taken before the first qualification and compared after BOTH full runs: identical (the one file whose mtime moved, `alert_retry_queue.json`, was rewritten with its exact prior bytes — contents preserved; noted for the test-suite hygiene item, not this slice).
>
> **6A0C-F. Deferrals (recorded).** The 6A.2 cutover ceremony (client) and the T2 word stay unimplemented; the LDAP directory diagnostic now reports classes, not the directory's message; `outcome_unknown` replay is refused until the next restart reconciles it (no runtime repair path); cleartext IdP/TOTP secrets at rest unchanged. **STOP for external review of the FE-6A.0 correction candidate; 6A.1/6A.2 do not start until this record is approved or amended.**

>
> **FE-6A.0 ROUND-3 CORRECTION RECORD — external review of `08c972c3` REJECTED → one append-only correction round (this branch, 2026-09-12; `08c972c3` untouched).** Three blockers, each with deterministic correction RED rows committed on exactly `08c972c3` BEFORE any product change (`99125808`, `fe6a0d_red_test.go` DR1a–DR3b, 7 functions, every row verified failing at the assertion its blocker predicts), the product correction in ONE commit (`9ce999ea`), and this record. Custody unchanged: `claude/culvert-frontend-batch2` frozen at `8e73a619`; `e3c0d5d7`, `310d2868`, `08c972c3` untouched; `origin/main = 0046feed` re-fetched at the exit gate and still an ancestor (no merge needed); no PR; no amend/squash/rebase. **FE-6A.1/6A.2 not started. STOP for external review at the end of this record.**
>
> **6A0D-A. Blocker → correction, one entry each (product commit `9ce999ea`).**
> - **B1 — the IdP operation ledger is authoritative only when durable.** (i) `idpOperationStore.Finish`/`MarkAudited`/`Begin` build a CANDIDATE ring, persist it atomically and swap it in ONLY on success; a persist failure changes nothing in memory and returns `errIdPOperationPersist`. `apiIdPCreate` therefore reports a terminal result only once its durable proof exists: a failed terminal persist after the registry commit answers the NON-terminal `500 outcome_unknown` with `current.detail: operation_record_not_durable` + `operationId` + `id`, emits NO success audit, and leaves the durable `pending` intent as the truth (`idpRecordCommittedOperation`). (ii) Historical attribution is PROVENANCE, never presence: `Create(p, docRev, operationID, …)` stamps the client operationId on the profile (`IdPProfile.OperationID`, persisted, ignored on input by `normalizeIdPProfileWriteInput`, preserved across replaces by `applyProfileCandidate`, projected on reads, carried CP→DP verbatim) in the SAME atomic registry write as the profile. `IdPRegistry.settleOperation` decides a pending intent durably from the registry's own evidence — target present with matching provenance ⇒ `committed` (+ the success audit from the recorded facts), present without it ⇒ `aborted <why>_unproven`, absent ⇒ `aborted <why>_absent`; `why ∈ {reconciled (boot), lookup (GET), settled_before_write (a later writer)}`; the verdict is persisted BEFORE it is reported. (iii) Every writer settles first: `mutate(allowDegraded, activeOp, …)` runs `settleBeforeWrite(cur, next, activeOp)` after the candidate is built and BEFORE anything is persisted — for each current profile the candidate removes or replaces (pointer inequality), every unresolved intent on it other than the transaction's own is settled durably; a settlement that cannot be made durable refuses the whole transaction with `errIdPOperationUnsettled` and NOTHING is written (admin PUT/DELETE ⇒ `503 operation_unsettled`; CP→DP `ReplaceAll` ⇒ error, snapshot deferred to the next sync, previous set stays live). Untouched profiles and pure adds are never blocked. (iv) The success audit is part of the operation: the record carries `auditDetail`/`auditAfter` (public projection) and a durable `audited` flag; the handler emits the audit after the durable terminal record and marks it (`MarkAudited`); `reconcileOperations` (boot), the lookup and settle-before-write complete an owed audit EXACTLY ONCE (`emitOperationAudit`, then the durable mark); a replay of an audited commit never audits again. Residual trade recorded: a crash between the audit emission and its durable mark repeats that one audit entry at the next settlement (at-least-once for that window; never a second mutation).
> - **B2 — the ledger fails closed.** `evictDecidedLocked` evicts ONLY durably decided records (`aborted`, or `committed` with `audited:true`), oldest first, and only as many as needed; `pending`/`outcome_unknown` are never evicted; when the unresolved population fills the 256-slot ring, `Begin` refuses (`503 operation_ledger_full`, nothing created; the read model shows `unresolved == capacity`). A corrupt or unreadable `idp_operations.json` at load is a DURABLE degraded posture (`idpOpsDegradation{reason: corrupt|unreadable}`): the file is left exactly in place as evidence (never moved, never rewritten, nothing written to that path), every operation-identified write and every lookup is refused (`503 operation_ledger_degraded`), every write that would change or remove an EXISTING profile is refused (a degraded ledger cannot say whether an intent is outstanding), a pure add still lands, reconciliation settles nothing, and `GET /api/idp` carries `operations{degraded, degradedReason, degradedDetail, retained, unresolved, capacity}`. Recovery is the operator's: restore or remove the file and restart.
> - **B3 — one bounded compile seam.** `compileBounded(p)` is the single classification seam every provider compilation crosses — the admin write path (`prepareProfile`), the boot `IdPRegistry.Load` (previously `logger.Printf("IdP %q compile error: %v")` with the raw cause) and the CP→DP `ReplaceAll` (previously `fmt.Errorf("… compile error: %w")`, logged raw by the snapshot apply path). The cause is dropped at the seam; only `reason ∈ {oidc_discovery, saml_metadata, ldap_provider, unsupported}` reaches the process log, the returned `*idpCompileError`, and therefore every audit, diagnostic and read model downstream. Canary proofs (DR3a boot Load, DR3b `applyConfigSnapshot`): the dial-seam canary, the origin IP and the TLS text are absent from logs and errors, and the snapshot rejection is `errors.As`-typed to `*idpCompileError`.
>
> **6A0D-B. RED matrix (`99125808`, on `08c972c3`).** DR1a (terminal persist failure after the registry commit answered 2xx / GET claimed `committed` from memory), DR1b (a durable pending intent whose profile is later deleted reconciled to `aborted` from PRESENCE; no writer settled it; the audit lost), DR1c (crash after the durable terminal record, before the audit: reconciliation emitted nothing), DR2a (the ring truncated the oldest record regardless of state: a pending intent evicted and its operationId accepted again), DR2b corrupt + unreadable (a damaged ledger became an empty authoritative ledger: evidence moved aside, id accepted as new, lookup 404), DR3a (boot Load logged the raw compile error), DR3b (ReplaceAll wrapped the raw error and the snapshot path logged it). **Harness correction recorded:** DR1b's crash simulation as first committed rewrote the ledger FILE behind the running process (memory `committed`, file `pending`) — a divergence no process reaches and one the corrected ledger cannot produce (memory never claims what disk does not hold); it now injects the fault at the ledger write itself (the DR1a seam: `fileutil.SetWriteSuccessObserver` fires after the registry commit and makes the next ledger write impossible; the durable pending bytes are captured and put back once the "volume" recovers). Assertions unchanged; verified still RED against `08c972c3` at the predicted assertion (`aborted` via presence) with the pre-correction `Get` signature. No sleeps anywhere in the matrix.
>
> **6A0D-C. Proofs (GREEN, `fe6a0d_green_test.go`, 7 functions).** DG1 lookup settles a lost terminal record from provenance (durable `committed`/`lookup_committed`, `audited:true` on disk before it is reported, exactly one audit, second lookup / restart / replay never re-audit or re-create); DG2 a later PUT settles the outstanding intent BEFORE writing (`settled_before_write_committed`, one audit), the replace lands with the ORIGINAL provenance, a caller-supplied `operationId` on the body is ignored, the read model exposes it, restart keeps the verdict; DG3 an unsettleable intent (ledger unwritable) refuses PUT and DELETE `503 operation_unsettled` with the registry file byte-identical, memory/revision untouched, nothing audited, the pending record still the durable truth, and an unrelated add unblocked; DG4 CP→DP `ReplaceAll` defers (`errIdPOperationUnsettled`, nothing applied) when it cannot settle and settles first (committed, audited once) when it can; provenance survives the wire; DG5 degraded ledger: read model `degraded/corrupt`, lookup / identified create / PUT / DELETE all `503 operation_ledger_degraded` with zero mutation, unidentified add lands, the damaged file left byte-identical in place; DG6 capacity at the handler (`503 operation_ledger_full`, nothing created, read model counts, one settlement frees exactly one slot); DG7 durable-first `Finish`/`MarkAudited` leave memory `pending`/unaudited on a persist failure. Adapted: `TestFE6A0C_Green_PendingIntentIsReconciledFromTheRegistryFileAtBoot` seeds the present profile THROUGH `Create(…, opPresent, …)` so it carries provenance (presence alone is no longer a commit — the point of B1); `fe6a0_green_test.go`'s split-outcome test passes the new `activeOp` argument. R1–R14 and CR1–CR10 assertions unchanged.
>
> **6A0D-D. Contract artifacts.** OpenAPI: `IdPOperationLedger` (+ `IdPList.operations`), `IdPOperation.audited` (required) + `state`/`code` semantics, `IdPProfileRead.operationId`, `AuthRefusal` code list + `AuthRefusalDegraded`/`AuthRefusalPersistFailed` descriptions (`operation_ledger_degraded`, `operation_ledger_full`, `operation_unsettled`; `outcome_unknown` with `operation_record_not_durable`), lookup `503`, create description; `make api-lint api-route-coverage api-bundle` regenerated (`openapi.json`; route pin stays 247 — no new route); `frontend/src/api/types.gen.ts` regenerated by the canonical script; `frontend/dist` unchanged. Legacy JS (`static/index.html`, IdP create only): `500 outcome_unknown` is handled as NON-terminal (no success claimed; list reloaded; the toast names the lookup); the three new 503 codes surface through the existing server-fact error text.
>
> **6A0D-E. Qualification of the candidate head (`9ce999ea` + this record).** Custody: clean tree; local == remote at every push; `origin/main` re-fetched at the exit gate = `0046feed`, still an ancestor — no merge, no second qualification. `gofmt -l .` empty; `go build ./...`/`go vet ./...` clean; diff-scoped lint `golangci-lint run --new-from-rev origin/main` (v2.5.0): **0 issues** (the pass's own findings — `apiIdPCreate` cyclomatic 18 → `idpReplayKnownOperation`/`idpRecordCommittedOperation`/`idpMarkOperationAudited`, three `rangeValCopy`, a `nestif` in `Finish` → `recordCommitFacts`, two test-side gocritic — fixed before the commit; no unrelated lint debt repaired). FE-6A.0 + correction + round-3 matrices (`TestFE6A0_|TestFE6A0C_|TestFE6A0D_`) **`-race -count=3`: ok (294.2 s)**; the affected-suite shuffle lane (`-race -count=2 -shuffle=on`, FE-6A.0/IdP/snapshot/D0/C1/OpenAPI/apicontract suites): ok (246.8 s); **full root `go test -race -count=1` (60-minute budget, the 6A0-F precedent): `ok github.com/KidCarmi/Culvert 1883.0 s`**, zero failures, no race reports, no panics; `./internal/...` + `./cmd/...` `-race`: 109 packages ok, 0 races — one package, `internal/logstore` (untouched by this round: `git diff 08c972c3..HEAD -- internal/` is empty), failed `TestLogStore_SizeRetentionPrunesOldest` (retention count 0, want 10) while the root race lane was running on the same 4-core box, and passed alone (`ok 68.1 s`, the whole package, one re-run — a load-induced failure in code this round did not touch, recorded rather than hidden); the `cmd/culvert-maint` module `-race`: 10 packages ok. Cross-compile `GOOS=linux GOARCH=arm64`: ok; determinism (`-trimpath -ldflags='-s -w -buildid='`, two builds): byte-identical (`42b98a3f…`). Frontend `npm run verify` (node 24.19.0 / npm 11.17.0): ALL nine gates passed (generated-types drift none after the commit, 70 files / 787 tests, committed-dist drift none — `frontend/dist` unchanged, tree clean). Real-binary journeys against the current build: the correction journey (`integration2.sh`, extended with the round-3 facts: lookup `state/audited == committed/true`, the profile's `operationId` provenance on `GET /api/idp/{id}`, the `operations` ledger read model on `GET /api/idp`, and — via the persisted JSONL audit log across a restart — EXACTLY one `idp.create` audit for the profile) **32/32**; the 6A0-F journey (`integration1b.sh`) complete; the process log free of the bind secret. Playwright real-binary smoke (`frontend/scripts/e2e-smoke.sh`, four appliances, `CULVERT_PW_CHROMIUM=/opt/pw-browsers/chromium`) **twice: 147 passed / 3 skipped, 147 passed / 3 skipped** (same skip set as the round-2 runs); no listener left behind. **Operator `/data`: sha256 of all 51 files byte-identical to the pre-qualification snapshot — zero diff.** Everything above ran on the committed head; the tree was clean before and after every lane.
>
> **6A0D-F. Deferrals (recorded).** The audit-then-mark window (at-least-once audit on a crash between the two; no second mutation); the degraded-ledger remedy is operator-driven (restore/remove + restart — no runtime repair endpoint, deliberately: the file is the only at-most-once evidence); the 6A.2 cutover ceremony and T2 word stay unimplemented; cleartext IdP/TOTP secrets at rest unchanged. **STOP for external review of the FE-6A.0 round-3 candidate; 6A.1/6A.2 do not start until this record is approved or amended.**

>
> **FE-6A.0 ROUND-4 CORRECTION RECORD — external review of `0b2046de` REJECTED on one remaining blocker → one focused append-only correction (this branch, 2026-09-12; `0b2046de` untouched).** Blocker: success-audit completion was neither exactly-once nor durably proven (the round-3 record deferred it as at-least-once; not accepted). Deterministic RED rows committed on exactly `0b2046de` BEFORE any product change (`186ece82`, `fe6a0e_red_test.go` ER1–ER5, 4 functions with ER4 folded into each, every row verified failing at the assertion its blocker predicts), the product correction in ONE commit (`a8b004f3`; plus `22944917`, a revive comment-form fix found by the lint pass, comment-only), and this record. Custody unchanged: `claude/culvert-frontend-batch2` frozen at `8e73a619`; `08c972c3`, `0b2046de` untouched; `origin/main = 0046feed` re-fetched at the exit gate and still an ancestor (no merge); no PR; no amend/squash/rebase. **FE-6A.1/6A.2 not started. STOP for external review at the end of this record.**
>
> **6A0E-A. The correction (product commit `a8b004f3`).** The success audit of an operation-identified IdP write now crosses ONE operation-keyed, idempotent, durability-reporting boundary, and the durable `audited` marker is set only after the durable audit exists:
> - **Structured identity.** `audit.Entry.OperationID` (`operationId`, omitempty) is the exactly-once key — the client operationId of the write — never text inside `Detail`. It is present on the persisted JSONL line, the in-memory ring and every audit read model (`GET /api/audit`, memory and `source=file`).
> - **`audit.AppendOperation(e) (durable bool, err error)`** — serialised on its own mutex — checks the DURABLE record first (`audit.HasOperation`: the current JSONL file AND its rotated `.1` archive, decoded per line, keyed on `(action, operationId)`; an unreadable record is an ERROR, never "absent", so an unknowable answer can never become a second append), appends only when absent (`persistEntryErr`, the loss-charging write now returning its outcome), and adds to the volatile fan-out (ring, SIEM, DP push queue) ONLY after the durable write and only once. Outcomes: durable (appended now or already there — nothing re-appended); no durable sink configured (the ring is that appliance's whole audit record and holds the entry once); or an error, in which case NOTHING was added anywhere and the caller retries the whole append later. `Add` keeps its best-effort contract for every other audit.
> - **Marker after durability.** `idpOperationStore.emitOperationAudit` (the handler's `idpCompleteOperationAudit`, the lookup, `settleOperation` and boot `reconcileOperations` all call it) runs the append and persists `audited:true` ONLY after a non-error outcome; either failure returns `errIdPOperationAuditPending` and the operation stays `committed` with `audited:false` + `auditState: "pending"` (lookup read model; also on the create response, which stays 2xx because the registry commit and its terminal record ARE durable and provable). Each retry re-runs only the missing step: after a crash between append and marker the append finds the entry and only the marker is written; after an append failure the append is retried and then the marker; after a marker failure the append is skipped and the marker retried. Replay of the operationId performs no mutation and, being answered from the record, never audits. A pending audit never refuses the writer that settled the intent (the verdict is durable; the audit is owed and recoverable). Marking before appending was deliberately NOT done (it converts duplicate risk into permanent missing-audit risk, as the review states).
> - **Posture fact.** `IdPList.operations.auditSink` (`file` | `memory`) says whether "audited" means durably present in the JSONL log or present once in the ring of a node with no audit log configured.
>
> **6A0E-B. RED matrix (`186ece82`, on `0b2046de`).** ER1 crash after the durable append, before the marker ⇒ the restart reconciliation appended the same success audit again (JSONL 2 entries); ER2 append persistence failure ⇒ `audited:true` persisted while the JSONL never received the entry; ER3 marker persistence failure after a successful append ⇒ lookups + two restarts duplicated the audit; ER4 (in every row, after recovery) replay ⇒ zero mutation, no additional audit; ER5 the durable JSONL carried no structured operation identity (0 keyed entries; the read model none). Seams: the real durable sink (`audit.Init` on a temp JSONL), `audit.SetPersistForTest` (append fault), the `fileutil` write-success observer armed on the ledger write that follows the registry commit (marker fault, with the committed record's bytes captured and restored), fresh `IdPRegistry` loads (restarts). No sleeps. **Harness correction recorded:** ER2 originally restored the failing sink BEFORE its first lookup, which — the lookup being itself a recovery path — legitimately completes the audit once the sink works; the row now probes the pending state (lookup `audited:false`, JSONL still 0) while the sink still fails, then restores it. Assertions unchanged; verified still RED against `0b2046de` (+`186ece82`) at the predicted assertion.
>
> **6A0E-C. Proofs (GREEN).** `fe6a0e_green_test.go` (4): EG1 append failure through the full middleware chain ⇒ 200 `auditState: pending`, C2c `audit_missing` NOT incremented (the boundary owns the request's audit), the ring holds nothing for the operation, lookup `audited:false`/`auditState: pending`; recovery via the lookup ⇒ exactly one durable keyed entry, marker set, restart re-audits nothing. EG2 settle-before-write (a later PUT on a profile with a lost terminal record) with the sink failing ⇒ the write lands, the verdict is durable, the audit stays pending; after recovery the lookup completes it once and a later DELETE + restart add nothing. EG3 memory sink ⇒ `auditSink: memory`, ring holds the entry once, replay/restart never duplicate, marker durable. EG4 file sink posture + the structured key on both audit read models. `internal/audit/operation_test.go` (6): exactly-once across three retries (file + ring), found-in-rotated-archive ⇒ no re-append, write failure adds nothing anywhere and is charged then recovers to exactly one, memory sink once, key required, unreadable archive ⇒ error not absent. ER1–ER5 GREEN; DR/DG (round 3), CR (round 2) and R1–R14 assertions unchanged.
>
> **6A0E-D. Contract artifacts.** OpenAPI: `IdPOperation.audited` semantics + `auditState`, `IdPMutationResult.auditState`, `IdPOperationLedger.auditSink` (required); `make api-lint api-route-coverage api-bundle` regenerated (`openapi.json`; route pin 247 unchanged — no new route); `frontend/src/api/types.gen.ts` regenerated by the canonical script. **No frontend source, `frontend/dist` or legacy `static/index.html` change** — the audit entry schema is `additionalProperties: true` and the new facts are additive.
>
> **6A0E-E. Qualification of the candidate head (`22944917` + this record).** Custody: clean tree; local == remote at every push; `origin/main` re-fetched at the exit gate = `0046feed`, still an ancestor. `gofmt -l .` empty; `go build ./...`/`go vet ./...` clean; diff-scoped lint `golangci-lint run --new-from-rev origin/main` (v2.5.0): **0 issues** on the head (the first pass found one revive comment-form finding in the new `ErrOperationIDRequired` doc comment — fixed in `22944917`, comment-only; no unrelated lint debt repaired). Contract gates on the head: OpenAPI conformance (`TestFE6A0_Green_ResponsesConformToContract`), audit-declaration parity, D0 route pin 247, C1/C1.5/C2/C4, route classification, `internal/apicontract`: ok. FE-6A.0 + rounds 2–4 matrices (`TestFE6A0_|TestFE6A0C_|TestFE6A0D_|TestFE6A0E_`) **`-race -count=3`: ok (369.6 s)** and `internal/audit` `-race -count=3`: ok; the affected-suite shuffle lane (`-race -count=2 -shuffle=on`, FE-6A.0/IdP/snapshot/D0/C1/C2/OpenAPI/apicontract/audit suites): ok (308.8 s); **full root `go test -race -count=1` (60-minute budget): `ok github.com/KidCarmi/Culvert 1940.8 s`**, zero failures, no race reports, no panics; `./internal/...` + `./cmd/...` `-race`: 109 packages ok, 0 races — `internal/logstore` (untouched by this round) again failed `TestLogStore_SizeRetentionPrunesOldest` while the root race lane ran concurrently and again passed alone (`ok 68.4 s`; the same load-sensitive pre-existing shape recorded in round 3, twice observed, both times passing in isolation — a candidate for its own hardening, out of this round's scope); the `cmd/culvert-maint` module `-race`: 10 packages ok. Cross-compile `GOOS=linux GOARCH=arm64`: ok; determinism (`-trimpath -ldflags='-s -w -buildid='`, two builds): byte-identical (`b0eb247f…`). Frontend `npm run verify` (node 24.19.0 / npm 11.17.0) on the committed tree: ALL nine gates passed (generated-types drift none, 70 files / 787 tests, committed-dist drift none — `frontend/dist` unchanged, tree clean). Real-binary restart journey (`integration2.sh`, extended: after the restart the raw persisted `audit.jsonl` holds EXACTLY one entry keyed `operationId == <op>` for the create, `GET /api/audit?source=file` reports exactly one `idp.create` for the profile, the lookup reports `committed`/`audited:true`, and `GET /api/idp` reports `operations.auditSink == file`) **34/34**; process log free of the bind secret. **Operator `/data`: sha256 of all 51 files byte-identical to the pre-qualification snapshot — zero diff.** Every lane ran on the committed head; the tree was clean before and after each. **Playwright scoped OUT with justification:** the changed files are Go (`internal/audit`, `idp_operations.go`, `auth_idp.go`, `ui_auth.go`), OpenAPI/bundle, the generated TypeScript types and tests; nothing under `frontend/src` (runtime), `frontend/dist` or `static/index.html` changed, so the browser journeys exercise byte-identical UI code — the round-3 runs (147 passed / 3 skipped, twice) stand for it; the frontend `verify` lane (drift gates, typecheck against the regenerated types, 787 tests, committed-dist drift) was re-run and passed.
>
> **6A0E-F. Deferrals (recorded).** The exactly-once guarantee is scoped to the durable audit record of THIS node (JSONL + rotated archive); the SIEM forward and the DP→CP push are at-most-once fan-outs of a durably-appended entry and inherit their own documented drop semantics. The degraded-ledger remedy stays operator-driven; the 6A.2 cutover ceremony and T2 word stay unimplemented; cleartext IdP/TOTP secrets at rest unchanged. **STOP for external review of the FE-6A.0 round-4 candidate; 6A.1/6A.2 do not start until this record is approved or amended.**

>
> **FE-6A.0 ROUND-5 CORRECTION RECORD — external review of `ac19a25b` REJECTED on one narrowly scoped durability blocker → one append-only correction (this branch, 2026-09-12; `ac19a25b` untouched).** Blocker: `audit.AppendOperation` acknowledged "durably present" on a successful `io.Writer.Write`, i.e. once the bytes reached the page cache — `fileutil.RotatingFile.Write` never fsyncs and its rotation never synchronises the directory — while the ledger's `audited:true` marker IS atomically durable, so a power loss between the two left a durable marker for an audit that no longer existed and nothing repaired. RED rows committed on exactly `ac19a25b` BEFORE any product change (`f5e1484a`, `fe6a0f_red_test.go` FR1–FR5, FR4 the passing control; the only non-test addition a no-op observability seam, `fileutil.SetSyncObserverForTest`, that nothing called at that SHA — which is exactly what FR3 demonstrates), the product correction in ONE commit (`4c8c9c82`), and this record. Custody unchanged: `claude/culvert-frontend-batch2` frozen at `8e73a619`; `08c972c3`, `0b2046de`, `ac19a25b` untouched; `origin/main = 0046feed` re-fetched at the exit gate and still an ancestor (no merge); no PR; no amend/squash/rebase. **FE-6A.1/6A.2 not started. STOP for external review at the end of this record.**
>
> **6A0F-A. The correction (`4c8c9c82`).**
> - **A production append primitive whose success means "on stable storage".** `fileutil.RotatingFile.WriteSync(p)` appends under the sink's mutex, refuses a short write, fsyncs the current file, and — when THIS write rotated — fsyncs the archive (`path.1`) and the parent directory (which carries the rename and the new file's existence) before returning nil. Any failure, write or fsync, is returned: the bytes may sit in the page cache, the caller must not treat them as durable. `fileutil.SyncPath(path)` fsyncs one file or directory (the retry's "synchronise the containing file" step). Both report every completed synchronisation to the test observer. `Write` keeps its best-effort contract — the process log, request log and every other caller are unchanged.
> - **The boundary is coordinated with the rotating sink.** `audit.AppendOperation` type-asserts the configured sink for `WriteSync`; a sink that cannot synchronise is refused with `ErrSinkNotSyncable` (nothing appended anywhere; the operation stays audit-pending — an acknowledgement that cannot be made durable is never given). The operation-key check, the append and the durability acknowledgement stay one serialised sequence: `findOperation` (current file, then archive) → if absent, `persistEntryDurable` through `WriteSync` (its loss, write OR fsync, is charged to `WriteErrors`/the storage-health observer exactly like a best-effort loss) → the volatile fan-out only after that; if PRESENT, the containing file is synchronised again (`SyncPath`) before `durable:true` — a readable entry with an uncertain synchronisation is not enough.
> - **Marker after fsync.** Unchanged in shape from round 4 — `emitOperationAudit` persists `audited:true` only after a non-error outcome — but the outcome now means fsync'd. The `auditSink: memory` posture is preserved and its OpenAPI wording now says explicitly that it is NOT disk-durable (lost on restart by design); `auditSink: file` states the fsync guarantee (file; archive + directory on rotation).
>
> **6A0F-B. RED matrix (`f5e1484a`, on `ac19a25b`).** FR1 full write, synchronisation fails ⇒ the ledger FILE said `audited:true` (RED); FR2 the unsynchronised bytes are removed by a simulated power loss (`os.Truncate` to the pre-write length) before the restart ⇒ the marker survived, the JSONL held 0 entries, nothing repaired (RED); FR3 the append crosses a 1 MB rotation boundary ⇒ zero file/directory synchronisations before `durable:true` (RED); FR4 CONTROL durable append + marker failure ⇒ no duplicate across lookups and two restarts (passes on `ac19a25b`, as round 4 already fixed it); FR5 in every row ⇒ the final JSONL set (current + archive) holds exactly one `(action, operationId)` entry and the ledger says `audited:true`. Seams: the real durable sink (`audit.Init`), a sync-controllable writer appending to the SAME JSONL path (`audit.SetPersistForTest`), a 1 MB `fileutil.RotatingFile`, the sync observer, fresh `IdPRegistry` loads. No sleeps. **Harness correction recorded:** FR1 as first committed read the acknowledgement through the lookup, which is itself a recovery path and — post-fix — legitimately recovers by synchronising the containing file even while the writer's own fsync keeps failing; the row now reads the acknowledgement from the ledger FILE before any recovery path runs, and asserts (via the observer) that the lookup's recovery synchronised the file before marking. Assertions' meaning unchanged; verified still RED against `f5e1484a` at the predicted assertion (`ledger file says audited=true`).
>
> **6A0F-C. Proofs (GREEN).** FR1–FR3 GREEN, FR4 control. `fe6a0f_green_test.go` (3): an unsyncable sink ⇒ 200 `auditState: pending`, nothing in the JSONL, nothing in the ring, ledger file `audited:false`, then the real synchronising sink recovers to exactly one entry; a synchronisation failure is charged to `audit.WriteErrors` (the storage-health plane sees it); the memory-sink posture unchanged. `internal/fileutil/rotating_sync_test.go` (3): `WriteSync` synchronises the current file exactly once; a rotating `WriteSync` synchronises the new current file, the archive and the directory before returning and the archive holds exactly the pre-rotation bytes; `SyncPath` reports file/dir and refuses a missing path. `internal/audit/operation_test.go`: non-syncable sink refused (nothing appended), synchronising-sink write failure adds nothing anywhere and is charged, then recovers to exactly one; the round-4 rows (exactly-once across retries, archive hit, memory sink, key required, unreadable record ⇒ error) unchanged. ER/DR/DG/CR and R1–R14 assertions unchanged.
>
> **6A0F-D. Contract artifacts.** OpenAPI: `IdPOperationLedger.auditSink` descriptions (`file` = fsync'd before the marker; `memory` = not disk-durable); `make api-lint api-route-coverage api-bundle` regenerated (`openapi.json`; route pin 247 unchanged); `frontend/src/api/types.gen.ts` regenerated by the canonical script (description comment only). **No frontend source, `frontend/dist` or legacy `static/index.html` change.**
>
> **6A0F-E. Qualification of the candidate head (`4c8c9c82` + this record).** Custody: clean tree; local == remote at every push; `origin/main` re-fetched at the exit gate = `0046feed`, still an ancestor. `gofmt -l .` empty; `go build ./...`/`go vet ./...` clean; diff-scoped lint `golangci-lint run --new-from-rev origin/main` (v2.5.0): **0 issues** (no lint-driven change this round). Contract gates on the head: OpenAPI conformance, audit-declaration parity, D0 route pin 247, C1/C1.5/C2/C4, route classification, `internal/apicontract`, the audit and rotating-file consumer suites: ok. FE-6A.0 + rounds 2–5 matrices (`TestFE6A0_|TestFE6A0C_|TestFE6A0D_|TestFE6A0E_|TestFE6A0F_`) **`-race -count=3`: ok (363.0 s)**, `internal/audit` + `internal/fileutil` `-race -count=3`: ok; the affected-suite shuffle lane (`-race -count=2 -shuffle=on`): ok (295.0 s); **full root `go test -race -count=1` (60-minute budget): `ok github.com/KidCarmi/Culvert 1957.7 s`**, zero failures, no race reports, no panics; `./internal/...` + `./cmd/...` `-race`: **107 packages ok, 0 races, no re-run needed** (the load-sensitive `internal/logstore` row of rounds 3–4 passed in-lane this time); the `cmd/culvert-maint` module `-race`: 10 packages ok. Cross-compile `GOOS=linux GOARCH=arm64`: ok; determinism (`-trimpath -ldflags='-s -w -buildid='`, two builds): byte-identical (`0501b07e…`). Frontend `npm run verify` (node 24.19.0 / npm 11.17.0) on the committed tree: the first run, taken while five Go race lanes shared the 4-core box, timed out ONE untouched vitest (`objects-decryptprofiles-page` `waitFor`, 134 s total run) — the file passes alone in 3.7 s and the full lane was re-run: ALL nine gates passed (generated-types drift none, 70 files / 787 tests, committed-dist drift none — `frontend/dist` unchanged, tree clean); recorded rather than hidden. Real-binary restart journey (`integration2.sh`, the round-4 extension: after the restart the raw persisted `audit.jsonl` holds EXACTLY one entry keyed to the operation, the lookup says `committed`/`audited:true`, `GET /api/idp` says `operations.auditSink == file`) **34/34** on the new build; process log free of the bind secret. **Operator `/data`: sha256 of all 51 files byte-identical to the pre-qualification snapshot — zero diff.** Every lane ran on the committed head; the tree was clean before and after each. **Playwright scoped OUT with the accepted justification:** the changed files are Go (`internal/fileutil`, `internal/audit`), OpenAPI/bundle, the generated TypeScript types and tests; nothing under `frontend/src` (runtime), `frontend/dist` or `static/index.html` changed — the round-3 browser runs (147 passed / 3 skipped, twice) stand for byte-identical UI code; the frontend `verify` lane was re-run and passed.
>
> **6A0F-F. Deferrals (recorded).** The fsync guarantee is that of the host filesystem and device (a volume that lies about fsync is outside any userland contract); `Write`'s best-effort callers (process log, request log, the audit `Add` path for every non-operation event) keep their documented no-fsync posture — hardening them is a separate program decision, not this gate's; the SIEM forward and DP→CP push keep their own drop semantics; the degraded-ledger remedy stays operator-driven; 6A.2 cutover ceremony and T2 word unimplemented; cleartext IdP/TOTP secrets at rest unchanged. **STOP for external review of the FE-6A.0 round-5 candidate; 6A.1/6A.2 do not start until this record is approved or amended.**

>
> **FE-6A.0 ROUND-6 CORRECTION RECORD — external review of `e5d66a59` REJECTED on three source-level gaps of the durable acknowledgement → one append-only correction (this branch, 2026-09-12; `e5d66a59` untouched).** Custody, ancestry and the round-5 qualification were accepted; the fsync direction was confirmed. RED rows committed on exactly `e5d66a59` BEFORE any product change (`40ed9c53`: GR1 in `internal/audit/boundary_red_test.go`, GR2–GR3 in `fe6a0g_red_test.go`; the only non-test addition a behaviour-neutral before-sync seam, `fileutil.SetSyncHookForTest` — nil unless a test installs it, consulted before each fsync — that GR2 uses to fault a directory fsync and GR3 to schedule an ordinary rotation between "found" and "sync"; the FR test sinks gained the `FindAndSync` method the correction requires, ignored by the pre-correction code), the product correction in ONE commit (`46a39372`; plus `4b01f74a`, a test-only fix pinning the concurrent-rotation gate on the ordering the lock actually guarantees — found by `-race -count=3`), the standing exit-gate merge (`ceb88097`, see 6A0G-E), and this record. Custody unchanged: `claude/culvert-frontend-batch2` frozen at `8e73a619`; `08c972c3`, `0b2046de`, `ac19a25b`, `e5d66a59` untouched; no PR; no amend/squash/rebase. **FE-6A.1/6A.2 not started. STOP for external review at the end of this record.**
>
> **6A0G-A. Gap → correction (`46a39372`).**
> - **Gap 1 — boundary-repair state lost after a zero-byte retry.** `persistEntryDurable` consumed `needsBoundaryRepair` before `WriteSync` and, unlike `persistEntryErr`, did not hand it back when the attempted repair moved zero bytes, so a later successful retry glued the record onto the fragment and `AppendOperation` acknowledged `durable:true` for a line that is neither parseable nor keyed. It now preserves the `repaired` result and re-derives the boundary state from `(n, len)` exactly as the best-effort path does (`n == 0` ⇒ hand the repair back; `0 < n < len` ⇒ a new fragment).
> - **Gap 2 — a retry after a rotation directory-fsync failure could falsely acknowledge.** `WriteSync` correctly failed when the rotation's directory fsync failed, but the retry found the readable entry, synchronised only its containing file (`SyncPath(holder)`) and returned `durable:true` — a readable file does not prove the rename / new-file directory entries survive power loss. The retry now goes through the sink-owned primitive below, which synchronises the holder AND the directory before reporting found; a failed directory sync keeps the operation pending.
> - **Gap 3 — find-then-sync raced ordinary rotation.** `AppendOperation` held `opMu`, `audit.Add` does not, so between "found in the current pathname" and `SyncPath(pathname)` an ordinary audit write could rotate and the recovery would synchronise a DIFFERENT generation and persist `audited:true` on it. **`fileutil.RotatingFile.FindAndSync(match)`** is the sink-owned atomic find-and-sync: under the sink's own rotation mutex it scans the CURRENT file then the archive for the keyed line and, when found, fsyncs the file that holds it and the directory before returning found — no `Write` can rotate between the scan and the proof, a scan error is returned (never "absent"), and a failed synchronisation returns not-proven. `audit.AppendOperation` requires the sink to offer it (`durableSink` = `WriteSync` + `FindAndSync`; anything less is `ErrSinkNotSyncable`) and never re-opens a pathname after the scan. Check, append and acknowledgement remain one `opMu`-serialised sequence; the scan/sync step is additionally serialised with every rotation by the sink's mutex.
>
> **6A0G-B. RED matrix (`40ed9c53`, on `e5d66a59`).** GR1 scripted sink (partial write → zero-byte failure → success): attempt 3 was acknowledged durable while the file held 0 independently parseable keyed entries (RED); GR2 1 MB rotating sink, directory fsync faulted through the seam: the write stayed pending (both trees), but the retry acknowledged after a file-only sync while the directory still could not be synchronised (RED); GR3 1 MB rotating sink, the seam fires between "found at pathname" and "sync" and performs an ordinary `audit.Add` that rotates: the recovery synchronised the empty new generation (observer: `file:audit.jsonl` holding 0 keyed entries) and marked `audited:true` on it (RED). FR1–FR5, ER1–ER5, DR/DG, CR and R rows retained unchanged and passing on both trees. No sleeps: GR3's interleaving is a synchronous schedule point, not a race.
>
> **6A0G-C. Proofs (GREEN).** GR1–GR3 GREEN. `internal/fileutil/rotating_sync_test.go` (+4): `FindAndSync` synchronises the holder then the directory (observer order), finds the ARCHIVE generation and synchronises it, a directory fault ⇒ not found + error, and a channel-ordered concurrent-rotation gate — a `Write` that would rotate is issued while the match function is parked inside `FindAndSync` and completes only AFTER the found generation was synchronised and `FindAndSync` returned (observer/return/rotation order pinned; the entry lands in the archive intact). `internal/audit/operation_test.go` (+1): a repair consumed by a zero-byte failed attempt is handed back and the retry carries the boundary newline; the round-4/5 rows (non-syncable sink refused, sync failure charged, exactly-once, archive hit, memory sink, key required, unreadable record ⇒ error) unchanged.
>
> **6A0G-D. Contract artifacts.** None changed: no OpenAPI, bundle, generated-type, frontend or legacy-UI change (`make api-lint api-route-coverage` re-run on the head: ok; the round-5 `auditSink` wording already states the guarantee this round makes true on every path).
>
> **6A0G-E. Exit-gate merge and qualification of the merged head (`ceb88097` + this record).** `origin/main` re-fetched at the exit gate had ADVANCED `0046feed` → `4316d6d4` (5 commits, 9 files: SOCKS5 + plugin CWE-117 destination sanitisation with their gates, and the admin GUI surfacing of oversize-username login rejections in `static/index.html`); per the standing rule it was merged `--no-ff` (`ceb88097`, no conflicts, no FE-6A.0 authoritative Go/OpenAPI/frontend-source file touched upstream) and the qualification below was run on the MERGED head — the pre-merge candidate `4b01f74a` had been qualified identically (lint 0, root race ok 1980.8 s, non-root 107 + 10 ok, matrices ok 416.1 s with the gate fix verified 10× under race, shuffle ok 358.8 s, arm64/determinism ok, frontend verify 787/787 after one load-timed-out run, journey 34/34, `/data` zero diff). Custody: clean tree; local == remote at every push. `gofmt -l .` empty; `go build ./...`/`go vet ./...` clean; diff-scoped lint `golangci-lint run --new-from-rev origin/main` (v2.5.0): **0 issues** against `origin/main@4316d6d4` (no lint-driven change this round). Contract gates: OpenAPI conformance, audit-declaration parity, D0 route pin 247, C1/C1.5/C2/C4, route classification, `internal/apicontract`, `make api-lint api-route-coverage`, plus the audit, rotating-file, SOCKS5 (incl. the merged CWE-117 gates) and plugin suites: ok. FE-6A.0 + rounds 2–6 matrices (`TestFE6A0_|…C_|…D_|…E_|…F_|…G_`) **`-race -count=3`: ok (423.3 s)**, `internal/audit` + `internal/fileutil` `-race -count=3`: ok; the affected-suite shuffle lane (`-race -count=2 -shuffle=on`): ok (360.1 s); **full root `go test -race -count=1` (60-minute budget): `ok github.com/KidCarmi/Culvert 2012.3 s`**, zero failures, no race reports, no panics; `./internal/...` + `./cmd/...` `-race`: 107 packages ok, 0 races; the `cmd/culvert-maint` module `-race`: 10 packages ok. Cross-compile `GOOS=linux GOARCH=arm64`: ok; determinism (`-trimpath -ldflags='-s -w -buildid='`, two builds): byte-identical (`336af302…`). Frontend `npm run verify` (node 24.19.0 / npm 11.17.0): the run taken while five Go race lanes shared the 4-core box timed out ONE untouched vitest (`policy-editor` `waitFor`; passes alone in 3.1 s), the lane was re-run: ALL nine gates passed (generated-types drift none, 70 files / 787 tests, committed-dist drift none — `frontend/dist` unchanged, tree clean); recorded rather than hidden. Real-binary restart journey (`integration2.sh`: exactly one operation-keyed entry in the raw `audit.jsonl` across a restart, lookup `committed`/`audited:true`, `operations.auditSink == file`) **34/34** on the merged build; process log free of the bind secret. **Operator `/data`: sha256 of all 51 files byte-identical to the pre-qualification snapshot — zero diff.** Every lane ran on the committed merged head; the tree was clean before and after each; `origin/main` re-fetched once more after the last lane = `4316d6d4`, an ancestor. **Playwright back IN scope for the merged head** — the legacy `static/index.html` changed upstream, so the browser journeys exercise changed UI code: `frontend/scripts/e2e-smoke.sh` (four appliances, `CULVERT_PW_CHROMIUM=/opt/pw-browsers/chromium`) **twice: 147 passed / 3 skipped, 147 passed / 3 skipped** (the same skip set as rounds 2–3); no listener left behind.
>
> **6A0G-F. Deferrals (recorded).** Unchanged from round 5: the guarantee is that of the host filesystem's fsync; best-effort `Write` callers keep their documented no-fsync posture; SIEM forward and DP→CP push keep their own drop semantics; degraded-ledger remedy operator-driven; 6A.2 ceremony and T2 word unimplemented; cleartext IdP/TOTP secrets at rest unchanged. **STOP for external review of the FE-6A.0 round-6 candidate; 6A.1/6A.2 do not start until this record is approved or amended.**

> **FE-6A.1 IMPLEMENTATION RECORD — Identity Providers + Administrators React READ surfaces (this branch, 2026-09-12; append-only after the frozen FE-6A.0 chain at `8be90030`).** Scope exactly as directed: FE-V27 and FE-V37 read-only surfaces at the routes and navigation placement the FE-6-0 record approves (Objects → Identity Providers at `/objects/identity-providers`; Administration → Administrators at `/administrators`), no create/update/delete/repair/test/cutover/credential control (not even a disabled one), no native confirm, no ceremony, no local speculative state, no polling. Entry gate: `origin/main` had advanced `4316d6d4 → de2a4584` (19 commits: CHAOS-65 OCSP hardening, SAML/base_url docs, a regenerated `types.gen.ts`) and was integrated by ONE evidence-preserving no-ff merge (`3b6ba325`; the only conflict, `openapi.json` + `types.gen.ts`, resolved by regenerating both with `make api-bundle` and the canonical script). Chain: `3b6ba325` (entry merge) → `0258886f` (RED matrix) → `5d92d01e` (product) → `0e97447c` (lookup re-key + harness corrections from the first real-binary run) → `eb7bb7ca` (regenerated `frontend/dist`) → the exit-gate merge and this record (6A1-E). Custody unchanged: `claude/culvert-frontend-batch2` frozen at `8e73a619`; the frozen FE-6A.0 history untouched; no PR; no amend/squash/rebase. **FE-6A.2 not started. STOP for external freeze review at the end of this record.**
>
> **6A1-A. Read surfaces and role matrix.** Minimum read roles follow uiRoutes evidence (the AppShell convention recorded at `layouts/AppShell.tsx:7`), not the legacy panel's nav gate: Identity Providers is **viewer** (`GET /api/idp`, `GET /api/idp/legacy-ldap`, `GET /api/objects/references` = viewer) with ONE admin-only sub-read (`GET /api/idp/operations/{id}` = admin, because the record names the actor — issued only when the session role is admin, and a non-admin is told the lookup is admin-only); Administrators is **admin** (`GET /api/auth/users`, `GET /api/auth/lockouts` = admin — the server's 403 renders as a bounded state and a viewer/operator route intent for `/administrators` resolves to Overview). The IA's "(admin)" annotation on `Identity Providers → idproviders` describes the legacy console's gate and is not carried into v2 (recorded, not edited here). Navigation: both entries are real links (Administrators is no longer "planned"); a viewer's shell carries no Administrators entry at all. `KNOWN_ROUTES` carries both paths at those roles.
>
> **6A1-B. RED matrix (`0258886f`, on exactly `3b6ba325`; every row failing at import resolution or at an unserved route BEFORE product code).** Pure (`fe6a1-red.test.ts`, A1–A10): the five read models decoded exactly as `idpListReadModel` / `publicIdPProfile` / `idpClusterReadModel` / `lookupReadModel` / `readModel` / `apiIdPLegacyLDAP` / `UIUserInfo` / `LockedEntry` answer them; unknown scope/type/degradedReason/cluster state/auditSink/operation state/auditState/cutoverDurability/trigger/tier/role REFUSED; any secret-bearing key at ANY depth refused (clientSecret, client_secret, bindPassword, bind_password, metadataXml, password, secret, ciphertext, sealed; pass_hash, passHash, totp_secret, totpSecret, backup_codes, backupCodes, totp_last_counter); a path-bearing `quarantineEvidence` refused; derived roster facts; route intent; every read helper one bodiless GET with the operation id encoded. Pages (`fe6a1-red-page.test.tsx`, P0–P8): navigation placement per role; populated / degraded / referenced / cutover postures from structured facts; outcome_unknown never a guess; raw error bodies never in the DOM; the admin-only lookup never issued below admin; the Administrators 403 as a bounded state; roster and lock set as independent snapshots; the lookup's 404 / 503 as bounded states; zero controls beyond Refresh, zero non-GET. Real-binary (`e2e/fe6a1.spec.ts`, J1–J9) with the harness premises they need: AUTH and YAMLUP arm a per-run `-idp-profiles-file`; YAMLUP carries a legacy YAML `ldap:` block (a `.invalid` directory, never dialled; canary `bind_password`) so the spec can commit the once-ever operation-identified cutover through the supported admin API; a FIFTH appliance IDPQ (`:19094`) boots on a corrupt registry file (quarantined at boot — a boot-time truth no API can produce on a running node) with a present, active, not-retired legacy block.
>
> **6A1-C. Product (`5d92d01e`, `0e97447c`).** `src/api/idp.ts` and `src/api/admins.ts` are GET-only modules (no mutation call exists in either, so a read surface cannot reach one by accident); `oidc`/`saml`/`ldap` stay open objects on the contract and only the rendered facts are decoded from them after the secret sweep. **Redaction boundaries:** no server `error` line is ever rendered — a failed read shows the error CLASS and HTTP status (`shared/readErrorSummary.ts`), a typed refusal shows its bounded `code` only; the quarantine evidence is rendered as "recorded"/"not recorded" (the base name is decoded — refused if path-shaped — and never displayed: this slice offers no repair ceremony, so the confirm word has no use in the browser); the legacy directory URL and bind DN are rendered (non-secret configuration identity), the bind credential only as its indicator. **Rendering rules:** enabled ⇒ "Enabled"/"Disabled" badges; write-only material ⇒ "Client secret / Inline metadata / Bind credential: configured | not configured"; references ⇒ "Referenced by N authentication rule(s) — a delete would be refused" with the rule names, "Not referenced", or "References unavailable" when that walk failed (never "not referenced" by default); fleet ⇒ "Published (config version N)" or "Pending publication — last rejection <class> at <time>"; ledger ⇒ retained/capacity/unresolved/audit sink + a degraded callout with the bounded reason; cutover durability ⇒ Durable / Pending reconciliation / Not retired. **Finding from the first real-binary run (`0e97447c`):** the legacy cutover record carries its OWN server-minted identity (`newLegacyLDAPCutover`) while the operation LEDGER is keyed on the enabling create's client `operationId`, co-written as that profile's provenance; looking the cutover id up in the ledger answered 400 `invalid_input` (rendered truthfully, but the wrong question). The card now shows both facts as supplied — "Cutover identity" and "Ledger key (enabling create)" — and keys the admin lookup on the ledger key (a join over two server facts); when no key exists (profile gone, or created without an operationId) no lookup is issued and that is said. Auth boundary: both surfaces hold no subject-bound state beyond the query cache the machine's teardown clears; nothing is written to web storage (J9 pins an empty storage after sign-out).
>
> **6A1-D. Backend truth gaps (recorded, NOT patched with UI copy).** (1) `GET /api/auth/users` carries no roster persistence posture — a node whose roster has no persistence path is indistinguishable from a persisted one on the read model (writes learn it only as `persistence_not_configured`); the surface renders no persistence claim. (2) The legacy single-user mirror (`c.user`/`syncLegacyMirrorLocked`) has no read surface — which roster entry it mirrors, and whether a mirror exists, cannot be rendered. Both are additive read-model fields for a `.0`-class backend slice; neither blocks the honest rendering of every other fact, so the surfaces ship with those two facts absent rather than guessed. (3) Test-scope only, not a backend gap: an OIDC profile is not seeded in the real-binary journey because the issuer validator resolves the host through DNS (`validateExternalURL` → `isSafeRedirectURL` → `isPrivateHost`, fail-closed on resolution failure) and a hermetic harness cannot depend on it; the OIDC indicator is pinned by the unit matrix and the backend `TestPublicIdPProfile_ProjectionParity`.
>
> **6A1-E. Exit gate, chain and qualification of the merged head (`c5122760` + this record).** `origin/main` re-fetched at the exit gate had ADVANCED `de2a4584 → 2833db31` (PR #1370: MCP canary read-first classification, scope-in-force revalidation, the upstreamclient pre-send window, an OpenAPI approval field + regenerated types — no FE-6A.1 authoritative file); merged `--no-ff` as `c5122760`, the only conflict (`frontend/src/api/types.gen.ts`) resolved by regenerating it from the merged `openapi.json` with the canonical script; re-fetched again after qualification: unchanged, still an ancestor. Full chain: `3b6ba325` (entry merge) → `0258886f` (RED) → `5d92d01e` (product) → `0e97447c` (lookup re-key + harness corrections) → `eb7bb7ca` (dist) → `aae9fb03` (parity rows, current-state note, CLAUDE.md) → `caa72497` (per-worker fixture cleanup — full Playwright run 1 on the pre-merge head was 152/153: the one failure was policy-2a's "exactly two Stage-1 rules" premise broken by the fe6a1 fixture rule left behind; the spec now removes its own rule and AUTH profiles in `afterAll`) → `c5122760` (exit-gate merge) → this record. Custody: clean tree, remote equality re-proven at every push, no PR, no amend/squash/rebase. **Qualification on the merged head:** `gofmt -l` empty, `go build ./...` + `go vet` clean; **root race ok 1906.9 s** (`go test -race -count=1 -timeout=60m .`; the pre-merge head had passed identically at 1881.0 s); `./internal/mcp/...` race: all 40 packages ok (the surface the advance touched); `make api-lint api-route-coverage` ok (route pin unchanged — no Go, route, OpenAPI or classification change in this slice; no Go test changed, so the determinism lane is not triggered); frontend `scripts/verify.sh` **9/9 on the merged head** (toolchain, clean install, type-generation + drift, lint + format, strict typecheck, **819/819 unit tests** — the identical 819 on the pre-merge head, so the vitest suite ran twice with identical results — production build + committed-dist drift, bundle scan, license/vuln); real-binary: the focused FE-6A.1 journeys 7/7 (after the three harness corrections recorded in `0e97447c`), **two consecutive full Playwright runs on the merged head: 153 passed / 0 failed / 3 skipped each** (the three skips are the pre-existing env-gated evidence captures), the FE-6A.0 restart journey 34/34 against a binary rebuilt from the merged head, and the `/data` snapshot (51 files) byte-identical before and after every run. **Read-role matrix (proven in-browser):** admin — both nav entries, roster + lock set + registry rendered; operator and viewer — Identity Providers rendered from the viewer floor, Administrators refused by the server (403 as a bounded state, no roster fact, route intent to Overview), no Administrators nav entry; the admin-only ledger lookup issued exactly once for an admin and never below admin. **Leak sweep:** on every appliance (AUTH, YAMLUP, IDPQ) no bind-password canary, TOTP seed, bcrypt hash, `pass_hash`/`totp_secret`/`backup_codes`/`bindPassword`/`metadataXml` key, quarantine file name or raw dependency text in any API response body, the DOM, the URL or web storage; **no mutation** from either surface (every page request a GET; the sign-in/out exchange is the only non-GET a page context issues; roster and registry revisions unchanged by the visits); **auth boundary:** sign-out from Administrators leaves web storage empty (theme key only) and the roster out of the DOM, and the next viewer session cannot read it.
>
> **6A1-F. Deferrals (recorded).** FE-6A.2 in full (IdP create/update/delete with the loaded revision, 428/409 as typed facts, `referenced` rendering with rule links, the explicit legacy-LDAP cutover ceremony with its server-side confirm fence, `/api/idp/test` + `discover`, legacy import, the repair ceremony whose T2 word is the `quarantineEvidence` this slice deliberately does not display, Administrators create/update/delete/unlock/change-password with `selfAffected` sign-out, the UNPROVEN-2xx latch on every mutation); GAP-2 (TOTP enrollment); the two roster read-model gaps in 6A1-D; the IA "(admin)" annotation on `idproviders` (reconcile on the next IA touch); cleartext IdP/TOTP secrets at rest unchanged. **STOP for external freeze review of FE-6A.1; FE-6A.2 does not start until this record is approved or amended.**
>
> **FE-6A.1 CORRECTION RECORD — external freeze review of `6ab24a1e` REJECTED → one append-only correction round (this branch, 2026-09-13; `6ab24a1e` untouched).** Five blockers, each with deterministic correction RED rows committed on exactly `6ab24a1e` BEFORE any product change (`782fce03`: `fe6a1c-red.test.ts` C1–C3 + C5, 10 rows; `fe6a1c-red-page.test.tsx` CP1–CP5, 6 rows; 15 of the 16 rows verified failing at the assertion their blocker predicts, with `CP3 legacy failure + successful registry read` as the passing CONTROL — the registry already rendered independently of the legacy read, only the reverse direction was broken), the product + contract correction in ONE commit (`dc348313`), the regenerated embedded build (`e29c3a67`), and this record. Custody unchanged: `claude/culvert-frontend-batch2` frozen at `8e73a619`; `8be90030`, `3b6ba325 … 6ab24a1e` untouched; no PR; no amend/squash/rebase. **FE-6A.2 not started. STOP for external review at the end of this record.**
>
> **6A1C-A. Blocker → correction, one entry each (product commit `dc348313`).**
> - **B1 — bounded server classes were decoded and rendered as arbitrary strings.** Every bounded class the surface renders is now `readEnum` over the Go vocabulary that produces it, and the vocabularies are exported so the RED matrix pins them by value: `IDP_FLEET_REJECTION_REASONS` = the four `publishReject*` classes of `ConfigStore.Update` (`identity_degraded | snapshot_invalid | marshal_failed | wire_size_exceeded`; a raw dependency error on `cluster.lastRejection.reason` is a DECODE FAILURE of the whole list, so nothing of that response renders — CP1); `IDP_LEDGER_DEGRADED_REASONS` = `unreadable | corrupt` (`idp_operations.go`; CP1b), and a degraded ledger WITHOUT a reason is refused rather than rendered as "degraded, reason unknown"; `IDP_OPERATION_ACTIONS` = `idp.create`; `IDP_OPERATION_CODES` = the 10 refusal codes `writeIdPRefusal` can attach to a terminal record + the 9 settlement codes `<why>_<verdict>` (`why ∈ reconciled | lookup | settled_before_write`, verdict `committed` / `absent` / `unproven`), split into `COMMITTED_CODES` (the `_committed` family, optional on a committed record) and `TERMINAL_FAILURE_CODES` (everything else, REQUIRED on aborted / outcome_unknown). The lookup refusal is bounded the same way: `refusalCodeOf(err, allowed)` returns a verdict ONLY for a code inside `IDP_LOOKUP_REFUSAL_CODES` (`invalid_input | forbidden | not_found | operation_ledger_degraded` — what `apiIdPOperations` answers), so an unrecognised code renders `Lookup refused (HTTP N, unrecognised refusal code)` and the server word never reaches the DOM (CP5). **The vocabularies are now authoritative in the contract, not a UI-only reading**: `IdPOperation.code` is a closed 19-value enum with the per-state shape in its description; `/api/idp/legacy-ldap` answers a typed `LegacyLDAPSummary` (+ `LegacyLDAPCutover`, `trigger` enum) instead of a free object; `IdPProfileRead.oidc/saml/ldap` are typed `IdPOIDCRead`/`IdPSAMLRead`/`IdPLDAPRead` with the indicator bools documented as `omitempty` (absent ⇒ false). `openapi.json`, both HTML bundles, the API inventory and `types.gen.ts` are regenerated through the canonical scripts.
> - **B2 — missing evidence was converted into negative truth.** `decodeAdminRoster` REQUIRES `users` (`UserList.users` is required and non-nullable; `ListUIUsers` always returns a non-nil slice) and `decodeAdminUser` REQUIRES `totpEnabled` (`UIUserInfo` has no `omitempty`): a missing roster is a contract violation, never "no accounts", and a missing TOTP flag is never "not enrolled". `decodeLegacyLDAP` is a union — `present:false` carries only `retired`/`scope`/`cutoverDurability`/`cutover?`, and `present:true` REQUIRES `active`, `shadowed`, `url`, `baseDn`, `bindDn` and `bindCredentialConfigured` (the handler emits all of them on every present answer). `decodeIdPProfile` REQUIRES `priority` and `emailDomains` (neither is `omitempty`; `emailDomains` is nullable and `null` decodes to `[]`, `undefined` is refused) and exactly the profile's OWN type-specific object — the `oidc`/`saml`/`ldap` pointers are `omitempty` in Go and absent when nil, so a missing or `null` own object and a present foreign non-null object are both refused. Go `omitempty=false` is preserved ONLY where the authoritative schema defines absence as false: `clientSecretConfigured`, `inlineMetadataConfigured` and `bindCredentialConfigured` INSIDE the sub-configs (now documented on `IdPOIDCRead`/`IdPSAMLRead`/`IdPLDAPRead`).
> - **B3 — the operation record is a discriminated union.** `IdPOperation` = `pending {audited:false}` (forbids `auditState`, `finishedAt`, `code`, `committedRevision`, `result`) | `committed, audited:true {finishedAt, committedRevision, code? ∈ COMMITTED_CODES}` (forbids `auditState`) | `committed, audited:false {auditState:"pending", finishedAt, committedRevision, …}` | `aborted` / `outcome_unknown {audited:false, finishedAt, code ∈ TERMINAL_FAILURE_CODES}` (forbid `auditState`, `committedRevision`, `result`). A record contradicting its own state — a committed record without its revision, a pending record with a finish time or a code, an aborted record claiming an audit or a committed revision, a committed record carrying an `_absent` verdict, an audited record still owing its audit — is refused WHOLE (17 contradictory shapes in C3; the page renders the lookup as refused evidence, never a partial record). The two page-side readers (`materialIndicator`, `OperationRecord`) narrow on the discriminant instead of optional-chaining across the union.
> - **B4 — the legacy YAML LDAP truth renders independently of the registry read.** `IdentityProvidersPage` composes TWO independent sections from two independent snapshots: the registry section (skeleton / bounded error / document facts + provider cards + the ledger callout, the latter only when `operations.degradedReason` is defined) and the legacy section (its own skeleton "Loading the legacy YAML LDAP posture…", its own error "Legacy YAML LDAP posture unavailable", or the card). The ledger key handed to `LegacyCard` is a tri-state `LedgerKey` — `known {operationId}` (the enabling profile's create-provenance), `absent` (registry read, no such profile), `registry_unavailable` — so a registry failure surfaces the block, its authority, its retirement and the cutover record beside "Ledger key unavailable: the registry could not be read." instead of hiding the node-local truth (CP2). The snapshot bar's freshness is the later of the two reads; `hasData` is either.
> - **B5 — three explicit administrator postures.** `rosterFacts` derives `posture ∈ ROSTER_POSTURES = none | last_admin | multiple` (exported, pinned by C5); `lastAdmin` is set ONLY for `last_admin`. The Administrators page renders them as three distinct, mutually exclusive rows: `none` → a critical badge "No administrator accounts" (the backend's at-least-one-admin invariant is never assumed by a read model), `last_admin` → "Last admin: <user> — the appliance refuses demoting or deleting it", `multiple` → "More than one administrator" (CP4).
>
> **6A1C-B. Original RED/GREEN matrix.** Assertions unchanged except where the correction makes them type-narrowing: A2 and A4 (plus the legacy row of A5) read union members through the discriminant instead of `?.`; A1's and P2's fixtures replaced the placeholder rejection word `publish_rejected` with the authoritative `snapshot_invalid` (the placeholder was exactly the class of value B1 forbids — the original matrix could not have caught it because it accepted any string); A4's pending/terminal fixtures are built coherent (`omit` of the terminal fields) so the union accepts them; A8 asserts `posture`. Viewer/admin role rows, the secret-leak sweeps (any depth, any spelling), the bodiless-GET and no-mutation assertions, the nav and route-intent rows are byte-identical.
>
> **6A1C-C. Proofs.** RED (`782fce03`, on `6ab24a1e`): 15 of 16 rows failing as predicted, CP3 the control. GREEN on `dc348313`/`e29c3a67`: `eslint .` clean; `prettier --check` (repo globs) clean; `tsc --noEmit` clean; `vitest run` **835/835** (74 files; the 4 FE-6A.1 files 48/48); `frontend/scripts/verify.sh` **ALL 9 GATES PASSED** on the committed tree (types drift gate, dist drift gate `check-dist: OK (6 files)`); `make api-bundle api-lint api-route-coverage` ok (`TestOpenAPI_Gate3` ok); root `go test -race -count=1 -timeout=60m .` **ok, 2144.1 s, RC=0** (openapi.json is embedded, so the OpenAPI gates ran inside it); focused real-binary journeys `e2e-smoke.sh e2e/fe6a1.spec.ts` **7/7**; two consecutive full Playwright runs against the real binary **153/153 and 153/153** (3 pre-existing env-gated skips each, 3.5 min each; the appliance under test wrote an empty default `cluster.json` into the harness cwd — a runtime artifact removed after the run, not committed, not a product change); restart journey (`integration2.sh`, rebuilt `culvert-det1`) **34/34**; operator `/data` snapshot (51 files) re-verified after every run: **byte-identical, zero diff**.
>
> **6A1C-D. Exit gate.** `origin/main` re-fetched after qualification = `2833db31` — unchanged since the FE-6A.1 exit-gate merge `c5122760` and still an ancestor of the correction head, so NO merge and no requalification were needed. Chain: `6ab24a1e` (frozen candidate) → `782fce03` (RED) → `dc348313` (product + contract) → `e29c3a67` (dist) → this record. Local == remote at every push.
>
> **6A1C-E. Deferrals (recorded, unchanged from 6A1-F).** FE-6A.2 in full; GAP-2; the two roster read-model gaps in 6A1-D (a read model still cannot state roster persistence posture or the legacy single-user mirror's provenance — reported, not patched with UI copy); the IA "(admin)" annotation on `idproviders`; cleartext IdP/TOTP secrets at rest. **STOP for external freeze review of the FE-6A.1 correction candidate; FE-6A.2 does not start until this record is approved or amended.**
>
> **FE-6A.1 ROUND-2 CORRECTION RECORD — external freeze review of `b9336de0` REJECTED on the fail-closed read boundary → one focused append-only correction (this branch, 2026-09-13; `b9336de0` untouched).** Custody, ancestry and the round-1 qualification were accepted, as were the bounded vocabularies, the operation-state decoder, the independent registry/legacy snapshots and the three administrator postures. Two findings remained: `decodeLegacyLDAP` was not a RUNTIME union (it returned on `present:false` and silently discarded present-only facts, and on `present:true` required six of the eleven non-secret settings the handler always emits — `userFilter`, `requiredGroup`, `startTls`, `tlsSkipVerify`, `cacheTtlSeconds` were neither represented nor required, so the security-effective legacy configuration was absent from the read surface); and a MISSING `IdPList.profiles` / `LockoutsList.lockouts` key still decoded to an empty collection (an empty-state claim from malformed evidence). RED rows committed on exactly `b9336de0` BEFORE any product change (`9c6d12ed`: `fe6a1d-red.test.ts` D1–D4, 10 rows, + `fe6a1d-red-page.test.tsx` DP1/DP1b/DP2, 3 rows, over the shared plain-module fixture `fe6a1d-fixtures.ts`; 10 of 13 rows verified failing at the assertion their gap predicts, the 3 controls — the bare absent block, `[]`/`null` profiles, `[]`/`null` lockouts — passing; `tsc` reported 7 errors in the RED file alone, the five legacy fields not existing on the union being the RED itself), the product + contract correction in ONE commit (`c7e73892`), the regenerated embedded build (`b2209db2`), and this record. Custody unchanged: `claude/culvert-frontend-batch2` frozen at `8e73a619`; `8be90030`, `6ab24a1e`, `b9336de0` untouched; no PR; no amend/squash/rebase. **FE-6A.2 not started. STOP for external review at the end of this record.**
>
> **6A1D-A. Gap → correction (product commit `c7e73892`).**
> - **D1 — `present:false` is a real union member.** The decoder now walks `LEGACY_PRESENT_ONLY_KEYS` (the eleven facts `apiIdPLegacyLDAP` emits only on a present block — `active`, `shadowed`, `url`, `baseDn`, `bindDn`, `bindCredentialConfigured`, `userFilter`, `requiredGroup`, `startTls`, `tlsSkipVerify`, `cacheTtlSeconds`) and REFUSES an absent block carrying any of them (`forbid`, the same primitive the operation union uses), so contradictory evidence is rejected whole rather than accepted with the extra facts dropped. `cutover` stays legitimate in both states, as the handler emits it whenever a cutover record exists.
> - **D2 — `present:true` requires every always-emitted non-secret setting.** `LegacyLDAPPresentFacts` now carries all eleven, each `field`-required (`userFilter`/`requiredGroup` as strings — `""` is a configured value, never absence; `startTls`/`tlsSkipVerify` booleans; `cacheTtlSeconds` a number; wrong types refused). `LegacyCard` renders them verbatim beside the existing identity rows: **Base DN**, **User filter** (`(empty)` for `""`), **Required group** (`(none)` for `""`), **StartTLS** `Negotiated` / `Not negotiated`, **TLS certificate verification** `Enforced` / a CRITICAL badge `Skipped (tlsSkipVerify)` — the one setting that weakens the directory trust is the one that must never be quiet — and **Result cache TTL** `N s`. Nothing is derived or defaulted client-side; a block missing any setting is a bounded decode error.
> - **D3 / D4 — absence of a collection is a decode failure, `null` is the empty slice.** `decodeIdPList` throws when the `profiles` KEY is absent and `decodeLockouts` when `lockouts` is; both keep `null → []`. The reasoning is the contract's, not the emitters': `idpListReadModel` builds `profiles` with `make([]*IdPProfile, len(...))` and `LoginLimiter.Snapshot` starts from `[]LockedEntry{}`, so neither shipped emitter ever produces `null` — but OpenAPI declares both `required` + `nullable: true`, and a reader honours the contract it was given rather than today's implementation detail. A malformed lock-set response now renders the bounded error state, never "No active lockouts" (DP2).
>
> **6A1D-B. Contract artifacts.** `LegacyLDAPSummary` is now a state-dependent union: `oneOf [LegacyLDAPAbsent, LegacyLDAPPresent]` — `LegacyLDAPAbsent` (`present: enum [false]`, `required [present, retired, scope, cutoverDurability]`, `additionalProperties: false`, so a present-only key is a schema violation) and `LegacyLDAPPresent` (`present: enum [true]`, every non-secret setting plus `active`/`shadowed`/`bindCredentialConfigured` REQUIRED, `tlsSkipVerify` documented as security-effective), sharing a new `LegacyLDAPCutoverDurability` enum. `openapi.json`, both HTML bundles, `docs/api/API-INVENTORY.md` and `frontend/src/api/types.gen.ts` regenerated through `make api-bundle` + `scripts/generate-types.sh`; `make api-lint api-route-coverage` ok.
>
> **6A1D-C. Earlier matrices preserved.** Every accepted assertion from rounds 0–1 is unchanged; the only edits are FIXTURE completions — the three `present:true` legacy fixtures that predated D2 (`fe6a1c-red.test.ts` C2, `fe6a1-red-page.test.tsx` and `fe6a1c-red-page.test.tsx` `LEGACY_CUTOVER`) now carry the five settings the handler always emits (A5's fixture already did). `fe6a1.spec.ts` J4 gained assertions on the real IDPQ appliance, whose YAML block sets neither `start_tls` nor `tls_skip_verify`: the card must say `Enforced` and `Not negotiated`, never `Skipped (tlsSkipVerify)`.
>
> **6A1D-D. Proofs and qualification (`c7e73892` / `b2209db2`).** RED as above. GREEN: `eslint .`, `prettier --check` (repo globs), `tsc --noEmit` clean; `vitest run` **848/848** (76 files; the six FE-6A.1 files 61/61); `frontend/scripts/verify.sh` **ALL 9 GATES PASSED** on the committed tree (`check-dist: OK (6 files)`); `make api-bundle api-lint api-route-coverage` ok (`TestOpenAPI_Gate3` ok); root `go test -race -count=1 -timeout=60m .` **ok, 2189.7 s, RC=0** (openapi.json is embedded, so the OpenAPI gates ran inside it); focused real-binary journeys `e2e-smoke.sh e2e/fe6a1.spec.ts` **7/7** (now including the legacy TLS/StartTLS posture on IDPQ); two consecutive full Playwright runs **153/153 and 153/153** (3 pre-existing env-gated skips each, 3.6 min each; the harness's cwd `cluster.json` artifact removed after the run, not committed); restart journey (`integration2.sh`, rebuilt `culvert-det1`) **34/34**; operator `/data` snapshot (51 files) re-verified after every run: **byte-identical, zero diff**.
>
> **6A1D-E. Exit gate.** `origin/main` re-fetched after qualification = `2833db31` — unchanged since the FE-6A.1 exit-gate merge `c5122760` and still an ancestor of the round-2 head, so NO merge and no requalification were needed. Chain: `b9336de0` (frozen round-1 candidate) → `9c6d12ed` (RED) → `c7e73892` (product + contract) → `b2209db2` (dist) → this record. Local == remote at every push.
>
> **6A1D-F. Deferrals (recorded, unchanged from 6A1-F / 6A1C-E).** FE-6A.2 in full; GAP-2; the two roster read-model gaps in 6A1-D; the IA "(admin)" annotation on `idproviders`; cleartext IdP/TOTP secrets at rest; the shipped `profiles`/`lockouts` emitters never produce `null` while the contract permits it (a contract-tightening candidate for the next OpenAPI touch, not changed inside a fail-closed correction). **STOP for external freeze review of the FE-6A.1 round-2 correction candidate; FE-6A.2 does not start until this record is approved or amended.**
>
> **FE-6A.2 IMPLEMENTATION RECORD — Identity Providers and Administrators WRITE surfaces, recovery and ceremonies (this branch, 2026-09-13; entry baseline = frozen FE-6A.1 `98d4a6c80620e0d778a0310a081d4649b093672c`, `origin/main` re-fetched at entry = `2833db31`, an ancestor — no merge).** Chain (append-only, local == remote at every push): `98d4a6c8` → `7bfdaa52` (RED matrix, committed BEFORE any product change) → `2e1d9b10` (BACKEND CORRECTION + contract) → `5e647a17` (product) → `3b465742` (dist) → `d41e66a0` (journey locators) → `fb1560ec` (lint: named RED-helper results) → `3a5103c0` (docs: runbooks, parity, state, contract, CLAUDE.md) → `624f06e2` (exit-gate merge of `origin/main` `993b3902`, no conflicts) → `50785203` (topbar reflow fix + FE-6A.1 journeys adopt the contracted allowlists) → `6247b182` (dist) → this record.
>
> **6A2-A. RED before (on the exact post-entry baseline `98d4a6c8`, commit `7bfdaa52`).** Go `fe6a2_red_test.go` BR1–BR5 (a cutover through PUT requires the operationId a lost response is recovered with; every cutover-bearing write requires the server's confirm value — `428 cutover_confirm_required` / `409 confirm_mismatch` with `current.confirmValue`; `GET /api/idp/legacy-ldap` publishes `cutoverConfirmValue`; a cutover PUT is ledger-recorded `idp.update`, replays and refuses a different candidate; the legacy console participates — the 2F-A rule): **BR1–BR5 FAIL as predicted, control C1 (a non-cutover PUT is unchanged) PASSES.** Frontend: `fe6a2-red-api.test.ts` (A1–A8, 25 rows), `fe6a2-red-recovery.test.ts` (M1–M5, 10), `fe6a2-red-admins.test.ts` (B1–B4, 12), `fe6a2-red-page.test.tsx` (P2–P11, 20) — on the baseline all four fail at import resolution (the write clients, marker module and ceremony components do not exist), the controls `fe6a2-red-controls.test.tsx` C1/C2 (no mutation control below admin on either surface) PASS. Real binary: `frontend/e2e/fe6a2.spec.ts` W1–W5 on a NEW sixth harness appliance IDPW (corrupt registry + legacy `ldap:` block; repair → import → cutover → edit → delete) and A1–A5 on AUTH (create → role change → lockout clear → self password change from the shell → delete) with the secret-leak sweep.
>
> **6A2-B. BACKEND CORRECTION (explicitly backend work; commit `2e1d9b10`; RED BR1–BR5).** The directive's rule — *if the server does not bind a ceremony to the reviewed candidate strongly enough, fix the backend contract first; do not simulate binding in browser state* — applied to the legacy-LDAP authority cutover. Two gaps: a cutover through `PUT /api/idp/{id}` required no operationId (a lost response could be "recovered" only by risking a second cutover), and no write carried a server-required confirmation of WHICH authenticator is retired. Correction: (1) `GET /api/idp/legacy-ldap` (`present:true`) publishes `cutoverConfirmValue` = the legacy directory URL (required in `LegacyLDAPPresent`); (2) every cutover-bearing write (POST or PUT that enables an LDAP profile while the block is present and not retired) requires `?operationId=` (`428 operation_id_required`, unchanged for POST, NEW for PUT) and `?cutoverConfirm=<value>` (NEW `428 cutover_confirm_required` / `409 confirm_mismatch`, both with `current.confirmValue`), decided BEFORE any write (`idpCutoverConfirmGate`, `ui_auth.go`); (3) `PUT` with an operationId is ledger-recorded (`idp.update`) with the create's replay / mismatch / aborted / in-progress semantics — the replay is answered from the durable record BEFORE the revision fence so a lost response re-sent with the ORIGINAL fence replays instead of `409 stale`; `IdPRegistry.Update(p, expectedRev, operationID, beforePublish)` stamps the operationId as the profile's provenance in the same atomic write and excludes its own intent from settle-before-write; (4) the legacy console (`static/index.html` `saveIdP`) runs `confirmDanger` with `confirmWord = cutoverConfirmValue`, mints an operationId on PUT too, sends `cutoverConfirm`, explains a 428 (2F-A: legacy and v2 switch in one commit). OpenAPI: `cutoverConfirm` on POST + PUT, `operationId` on PUT, `IdPOperation.action enum [idp.create, idp.update]`, `LegacyLDAPPresent.cutoverConfirmValue` (required), the 428 description; `openapi.json`, both HTML bundles, `docs/api/API-INVENTORY.md`, `frontend/src/api/types.gen.ts` regenerated. Pre-existing cutover tests (FE-6A.0 R7 ×2, CR9 ×2, the LDAP persistence gate) now SEND the confirm value; every assertion unchanged. No route added → `uiRoutes` unchanged. Not changed and recorded (§6A2-H): `?preflight=connection` stays an untyped 422 gate (not consumed by v2); legacy import stays unfenced server-side (bodiless, T2 client ceremony).
>
> **6A2-C. Identity Providers write surface (`src/api/idp.ts`, `features/objects/idpWrites.tsx`, `idpRecovery.ts`, `IdentityProvidersPage.tsx`).** Write client: `createIdP` (document-revision fence + operationId [+ `cutoverConfirm`]), `updateIdP` (entry-revision fence [+ operationId + `cutoverConfirm` when the write carries a cutover — `carriesCutover(spec, legacy)`]), `deleteIdP` (entry revision), `testIdP` (transient credentials; 60 s client deadline over the server's 45 s watchdog; closed `IDP_TEST_STEPS`/`IDP_TEST_STEP_ERRORS`; `ok:false` = failed, unverifiable = unproven, never "passed"), `discoverOIDC` (https endpoints only), `importLegacyLDAP` (bound: `type:ldap`, `enabled:false`), `repairIdPRegistry` (bound: `evidence === confirm`). Every 2xx decoder is ACTION-BOUND (`writeOutcomeDecoder`: type, name, id, revision ≥ expected, fleet publication fact, echoed operationId = dispatched; a replay bound to the dispatched operationId) — anything else is UNPROVEN (`idpUnproven`: 401/403 are not; a recognised refusal is not). `IDP_REFUSAL_CONTRACT` = 26 codes → contracted status + REQUIRED typed facts (`revision`/`documentRevision` tokens, `references[]` decoded as typed rule refs and rendered through `consumerDestination`, `confirmValue` by grammar — quarantine base name or LDAP URL, `operationId` UUID, `state`, `code`, `detail` enum); a code outside the allowlist or at the wrong status is not a verdict. The write body carries secrets ONCE (`clientSecret`/`bindPassword`/`metadataXml`: undefined = keep, `""` = explicit clear) and never an indicator, id, revision or operationId; `candidateDigest` is FNV-1a-64 over the canonical NON-SECRET candidate with secret POSTURE (keep/clear/present) only. Read facts extended to every non-secret sub-config field the projection emits (Go `omitempty` ⇒ zero), so an edit re-sends the complete candidate instead of wiping unseen settings. Ceremonies: T2 review before every save (credential-bearing or not — one shape); the **cutover ceremony** (tier 3 typed on the server's `cutoverConfirmValue`, title names the retirement, provider identity + fence + operationId bound into the request); **delete** T3 typed on the provider id + loaded revision; **repair** typed on the quarantine evidence, which the page otherwise renders only as PRESENCE; **import** T2 stating "created disabled" and "copied server-side"; **Abandon** typed on the operationId. Unproven ⇒ `markUnproven`: dialog closed (secrets dropped), page latched (mutations + test blocked), ONE authoritative read-back (a transport death waits for Refresh), refusal callouts render codes only. Dirty editor guarded from navigation (`useDirtyGuard`).
>
> **6A2-D. Operation recovery state machine.** Marker `culvert.idp.operation-recovery.v1` (sessionStorage; ESLint's storage ban lifted line-level with the pinning test named): `{version:1, subject, operationId, action: create|update, profileId?, name, type, candidateDigest, fence, cutover, startedAt}` — NO secret, NO body, NO server response. Written BEFORE dispatch with read-back (a marker that cannot be written refuses the dispatch locally); one outstanding operation; ownership-bound (an UNRESOLVED subject — empty/blank — classifies nothing, a foreign subject discards, `registerAuthCleanup` purges at the auth boundary). Terminal outcomes clear it: a proven success, a replay, or a refusal that PROVES nothing was written (`TERMINAL_NOTHING_WRITTEN`: precondition/stale/mismatch/aborted/confirm/degraded classes). Otherwise the banner **"Unresolved provider operation"** offers: **Recover** → `GET /api/idp/operations/{id}` rendered as the server's state — `pending` / `committed` (+ "audit pending" when `audited:false`) / `aborted` (+ code) / `outcome_unknown` (+ code); committed ⇒ clear + refresh, and a "resolved operation" callout keeps the verdict visible; `404 not_found` ⇒ `never_recorded`, which is the ONLY state that offers **Re-send** (reopens the editor bound to the same operationId; the non-secret candidate is remembered in component memory and must hash to the marker's digest — a changed candidate is a new operation); `503 operation_ledger_degraded` ⇒ rendered as such, no re-send; **Abandon** (typed operationId) deletes the marker only. No automatic re-enrollment, no duplicate create, absence never classified without contract evidence.
>
> **6A2-E. Administrators write surface (`src/api/admins.ts`, `features/administration/adminWrites.tsx`, `ChangePasswordDialog.tsx`, `AdministratorsPage.tsx`, `layouts/AppShell.tsx`, `auth/machine.ts`, `api/auth.ts`).** `createAdminUser`/`updateAdminUser`/`deleteAdminUser` under the roster `revision` (query string; DELETE `?username=&revision=`), `clearLockout` under the lock-set `generation`, `changeOwnPassword` under the caller's `securityGeneration` (now carried on `GET /api/auth/status` → `AuthState.securityGeneration`); results action-bound (`bindUser` identity + role, `revision`, `persisted`, `sessionsRevoked`/`selfAffected`/`securityGeneration`, `deleted`/`ok` + `generation`); `ADMIN_REFUSAL_CONTRACT` PER ENDPOINT (`users.create`: + `user_exists`, `last_admin`; `users.update`/`users.delete`: + `not_found`, `last_admin`; `change_password`: `invalid_credentials` 403, `not_found`, `stale`/`precondition_required` on the generation, `persist_failed`, `persistence_not_configured`; `lockouts.clear`: `not_found`, `stale`/`precondition_required` on the generation) — a code the endpoint cannot emit is not a verdict; `adminUnproven` mirrors `idpUnproven`. Ceremonies: T2 review for create / role / password (password PRESENCE only), **T3 delete** typed on the exact username with the roster revision bound, **T2 lockout clear** generation-bound, **Change my password** = current credential + generation (shell button for EVERY role; the page-level button only for an admin with a loaded roster). `selfAffected:true` ⇒ `AuthMachine.logout()` — complete teardown to the login boundary, markers purged, roster hidden. A lost/unproven response claims no revocation; TOTP is preserved by the server on a password update (out-of-scope enrollment, GAP-2). Roster read-model gaps (persistence posture, legacy mirror provenance) KEPT deferred — writes carry `persisted` and the typed 503 refusal, no UI copy compensates.
>
> **6A2-F. Secret and redaction proof.** Write-only values (OIDC `clientSecret`, LDAP `bindPassword`, inline SAML metadata, test username/password, administrator current/new passwords) exist only in the open dialog's component state; released on close, completion, unproven, navigation and sign-out; never in a URL/query, the recovery marker, `localStorage`/`sessionStorage`, logs, audit, diagnostics or the mutation summaries (`specCarriesSecret` reports PRESENCE for the T2 review; `candidateDigest` hashes posture, never value); a failed or stale write never re-populates a secret field from a server response (the editor re-opens from the NON-SECRET candidate). Proofs: `fe6a2-red-api` A-rows (body carries the secret once, indicator never sent back, digest is value-independent), `fe6a2-red-recovery` M-rows (marker grammar; a marker containing a secret-bearing key is refused), `fe6a2-red-page` P-rows (dialog state cleared on unproven), `fe6a2.spec.ts` secret-leak sweep (every response body, the DOM, `sessionStorage`, and the recovery marker on the REAL binary; the YAMLUP/IDPW `bind_password` canary never reaches the browser), `fe6a2_red_test.go` + `integration3.sh` (process log, `audit.jsonl`, `idp_operations.json` carry neither the registry bind secret nor the YAML canary; create/update echoes carry `bindCredentialConfigured` only). Deferred as directed: cleartext IdP/TOTP persistence and archive encryption (FE-6F class, not expanded here).
>
> **6A2-G. Contract and generated artifacts.** `api/openapi/openapi.yaml` (+ `openapi.json`, both HTML bundles, `docs/api/API-INVENTORY.md`) and `frontend/src/api/types.gen.ts` as in 6A2-B; `api/route-classification.yaml` unchanged (no route added); `uiRoutes` unchanged; `frontend/dist` regenerated (`3b465742`, deterministic, `check-dist: OK`); the harness (`frontend/scripts/e2e-smoke.sh`, `e2e/fixtures.ts`) gained the IDPW appliance (port 19095, `CULVERT_E2E_IDPW_URL`); `fe6a1.spec.ts`'s API-driven YAMLUP cutover sends the confirm value; earlier FE-6A.1 matrices updated only for the grown contract (`IDP_OPERATION_ACTIONS` pins `[idp.create, idp.update]`, present fixtures carry `cutoverConfirmValue`, the P3/P5 "only Refresh" admin invariant is superseded by the contracted control allowlists `IDP_ADMIN_CONTROLS`/`ADMIN_PAGE_CONTROLS`; viewer/operator rows unchanged). Docs: parity rows FE-V27/FE-V37 (SHIPPED), `FRONTEND-CURRENT-STATE.md`, `FRONTEND-SECURITY-CONTRACT.md` D15 (EXTENDED — FE-6A.2), operator runbooks `docs/operator/idp-registry-recovery.md` (NEW), `docs/operator/administrator-account-recovery.md` (NEW), `docs/operator/ldap-identity-provider.md` (confirm fence), `CLAUDE.md` frontend line.
>
> **6A2-H. Qualification on the final head `6247b182` (the last non-record commit; this record is docs-only).** (1) `gofmt` clean, `go vet ./...` clean, `go build .` ok, `GOARCH=arm64` compile ok. (2) Diff-scoped `golangci-lint run --new-from-rev 98d4a6c8` (v2.5.0 built with the repo toolchain go1.26.6): **0 issues** (one `unnamedResult` finding on the RED helper was fixed in `fb1560ec`). (3) Focused RED/GREEN families ×3 under `-race` (`TestFE6A2_|TestFE6A0|TestLegacyLDAP_|TestUIAuthLDAP|TestIdP`, `-count=3`): **ok, 292.8 s, RC=0**. (4) Root `go test -race -count=1 -timeout=60m .`: **ok, 1890.5 s, RC=0** on `6247b182` (and **ok, 1915.8 s, RC=0** on the merged head `624f06e2`, whose delta to the final head is frontend-only: `AppShell.tsx`/`.module.css`, `fe6a1.spec.ts`, `dist`); non-root `go test -race ./internal/... ./cmd/...`: **107 packages ok, RC=0**. (5) `make api-bundle api-lint api-route-coverage` ok, `TestOpenAPI_*`/`TestAPIContract*`/`TestRouteClassification*` ok, tree clean after the bundle (no generated-artifact drift); `uiRoutes` untouched. (6) Frontend: `eslint .` clean, `format:check` clean (the four Prettier warnings under a bare `prettier --check .` are `categories.json`, `e2e/.state/admin.json`, `test-results/.last-run.json` and `tools/openapi-gen/generate.mjs` — outside the repo globs, none touched here), `tsc --noEmit` clean, `vitest run` **917/917** (81 files). (7) `frontend/scripts/verify.sh` **ALL GATES PASSED** on the committed tree; `test-drift-gate.sh` all cases correct (A–D fail, E passes); `verify-determinism.sh 5` **5 identical builds** (RC=0). (8) Binary determinism: two `CGO_ENABLED=0 go build -trimpath -ldflags=-buildid=` builds **byte-identical** (`3c8cc6be…`); arm64 compile ok. (9) Real-binary restart journeys on that binary: `integration2.sh` **34/34** (FE-6A.0 security-generation / fenced self-service change / cookie re-issue / durable invalidation / create fences / operationId replay + lookup across restart / lockout generation) and the NEW `integration3.sh` **38/38** — a node booted with a legacy YAML `ldap:` block: disabled LDAP create; enabling PUT refused `428 operation_id_required`, then `428 cutover_confirm_required` (+ `current.confirmValue`), then `409 confirm_mismatch` on a wrong value with NOTHING retired or written (revision unchanged, no ledger record); the correct value commits (200, echoed operationId, advanced revision, write-only credential preserved, legacy `retired`/`shadowed`, `cutover.trigger: admin_api`, profile provenance = the operationId, ledger `committed idp.update cutover:true audited:true`); replay with the ORIGINAL stale revision ⇒ `replayed:true`, nothing advanced; a different candidate under the same operationId ⇒ `409 operation_mismatch`; an ordinary post-cutover PUT needs no identity; **RESTART**: the ADMIN cutover record (identity, trigger, registry revision) and `cutoverConfirmValue` survive, the ledger entry survives, the replay still answers `replayed:true` and writes nothing, exactly ONE operation-keyed audit entry; fenced self-service change ⇒ `selfAffected:true`, the old cookie is 401 before and after the restart; no secret (registry bind password, YAML canary) in the process log, `audit.jsonl` or `idp_operations.json`. (10) Focused `e2e-smoke.sh e2e/fe6a2.spec.ts` on the IDPW + AUTH appliances: **W1–W5, A1–A5 pass**. (11) Two consecutive COMPLETE Playwright runs against the real binary on `6247b182`: **155/155 and 155/155** (3 pre-existing env-gated skips each, 3.1 / 3.0 min; the harness's cwd `cluster.json` artifact removed after each run, never committed). The first complete run on the MERGED head `624f06e2` had failed **5**: three reflow gates (fe2/fe4/policy-2a at 640×800) — a REAL regression, the FE-6A.2 shell "Change password" button widened the single-row topbar — fixed in `50785203` (short label + role chip yield at ≤760 px, accessible name unchanged at the default viewport) — and two `fe6a1.spec.ts` rows that pinned "every admin button is Refresh", the FE-6A.1 read-only invariant FE-6A.2 supersedes (now the contracted allowlists, as the vitest page matrix already did; viewer/operator rows unchanged). (12) Secret-leak sweep: the FE-6A.2 journey sweeps DOM, URL, `sessionStorage`, the recovery marker and every response body on the real binary against the YAML bind canary and the typed secrets; the 2F-D/2F-F canary passes and the 2A-M auth-boundary sweep ran in the same complete runs. (13) Operator `/data` snapshot (51 files): `sha256sum -c` **51 OK, 0 mismatches** after every run; `alert_retry_queue.json` was re-written with byte-identical content (mtime only) by an appliance under test — no residue, no mutation.
>
> **6A2-I. Exit gate.** `origin/main` re-fetched at the exit gate had ADVANCED `2833db31` → `993b3902` (PRs #1371 CDR `-cdr-fingerprint` CLI validation/flag name, #1374 GeoIP policy-resolution diagnostics: `geoip_resolve_health.go`, `diagnostics*`, `main.go`, `main_config_precedence_test.go` — 9 files, none overlapping the FE-6A.2 change set). Merged append-only with a no-ff merge commit `624f06e2` (no conflicts, no history rewrite) and the FULL qualification in 6A2-H was run on that merged head; a partial pre-merge run on `fb1560ec` (root race suite, non-root race suites) was stopped when the advance was detected, so the numbers above are the merged head's only. Local == remote at every push.
>
> **6A2-J. Deferrals and residuals (recorded).** (1) GAP-2 TOTP enrollment (unchanged; password update preserves TOTP). (2) Cleartext IdP/TOTP secrets at rest + archive encryption (FE-6F class). (3) The roster read model states no persistence posture and no legacy single-user mirror provenance (writes carry `persisted` / `persistence_not_configured`; no copy compensates). (4) `?preflight=connection` (LDAP activation preflight) stays an untyped 422 gate on the legacy console only; the v2 editor offers the typed directory test instead. (5) `POST /api/idp/legacy-ldap/import` stays unfenced server-side (bodiless; T2 client ceremony) — a fence would need a new contract row and is not required for truthfulness (the import creates a DISABLED profile, retires nothing). (6) Tier divergence from plan §H: the directive mandated T3 for provider delete and administrator delete; FE-7's ceremony sweep inherits them as already-T3. (7) PRE-EXISTING boot residual found by `integration3.sh` and NOT fixed inside this slice: on every boot of a node that has cut over and still carries the YAML `ldap:` block, the legacy-provider startup slice (`legacy_auth_providers_startup.go`, main.go:211) observes the enabled registry profile BEFORE `LoadAdminSettings` (main.go:240) applies the durable sentinel, so `markLegacyLDAPRetired` re-emits one `idp.legacy_ldap.retired` audit entry (actor `system`, trigger `observed`, a fresh record identity) per boot; the durable ADMIN record wins on load (`applyLegacyLDAPRetirement`) and is what the read model reports (pinned by the journey: identity/trigger/registryRevision byte-identical across the restart). Audit noise, not a truth defect on the write surface; a fix is a boot-ordering change outside FE-6A.2's scope. (8) The IA "(admin)" annotation on `idproviders`. (9) The shipped `profiles`/`lockouts` emitters never produce `null` while the contract permits it. **Do not start FE-6B. STOP for external freeze review of the FE-6A.2 candidate.**

> **FE-6A.2 CORRECTION ROUND — external freeze review REJECTED with four source-level contract breaks (this branch, 2026-09-13; frozen candidate `64da0df039af12c3133bff208e29cacb5f13b390` kept UNTOUCHED; `origin/main` = `993b3902` at entry and at exit, an ancestor — no merge).** Chain (append-only, local == remote at every push): `64da0df0` → `d5ff7725` (RED matrix, committed BEFORE any product change) → `91762767` (BACKEND CORRECTION + contract artifacts) → `6555d6b4` (frontend correction) → `b9b9cf51` (dist) → `e44e3f13` (lint on the RED scaffolding) → `3c92e8fe` (runbooks, contract, parity, state, CLAUDE.md) → this record. Everything the review accepted — git custody, the cutover confirmation fence, the React ceremonies, the administrator flows, recovery-marker ownership, secret redaction — is unchanged; no ceremony, retry, timeout, redaction or UNKNOWN handling was weakened.
>
> **6A2C-A. RED before (on the exact frozen candidate `64da0df0`, commit `d5ff7725`).** Go `fe6a2c_red_test.go` against the review's matrix: **R1** import vs concurrent registry mutation (stale/absent fence and absent operationId refused with zero mutation) — FAIL (200 written); **R2** lost import + repeat before/after a restart = one profile, `replayed`, one `idp.import` audit, action-bound result — FAIL (no facts, a second profile); **R4** same operationId + secret B for OIDC client secret / LDAP bind password / inline SAML metadata ⇒ `409 operation_mismatch`, zero mutation, no secret in the ledger — FAIL ×3 (replayed success); **R5** CONTROL exact candidate replays across a restart — PASS; **R6** enabled-LDAP create without a proven preflight ⇒ `422 preflight_failed {step, reason}`, no ledger record, no audit — FAIL (200 written); **R7** failing/unavailable directory on an enabling cutover PUT ⇒ zero registry/cutover/ledger/audit/fleet change, a healthy one CROSSES the preflight (bind observed) — FAIL (200, no bind); **R8** completed admin cutover + two simulated boots (legacy slice → settings load, no settings path during the slice, as in a real process) — FAIL (retirement audits 1 → 2); **R9** node-local candidate key excluded from archives, 0600 beside the ledger, never in it — FAIL. Frontend (14 rows, all failing on `64da0df0` — the import client carried no fence/operation and the outcome/refusal/digest exports did not exist): `fe6a2c-red-api` CA1–CA6 (fenced + identified import URL; action-bound outcome — an unrelated disabled profile, a wrong operationId, an enabled profile, a missing source or a credential is UNPROVEN; replay kind; `preflight_failed` = 422 with typed step + reason; `idp.import` in the action vocabulary; non-secret import candidate digest), `fe6a2c-red-recovery` CM1/CM2 (marker action `import`), `fe6a2c-red-page` PC1–PC4 (marker before the fenced POST and cleared on proof; the unrelated 2xx is UNPROVEN with the marker kept, one read-back, latch; Recover from the ledger and a 404 ⇒ same-operation re-send; `preflight_failed` rendered as step + reason only). Real binary: `fe6a2.spec.ts` W2 (fenced identified import URL + released marker), NEW W3a (typed preflight refusal: profile stays Disabled, legacy stays live, exactly one PUT) before W3 (cutover through a reachable directory); `fe6a1.spec.ts` J5's API cutover points at the same directory. Harness fixture: `internal/ldapstub` + `cmd/ldapstub` (a minimal LDAP v3 responder — bind + base-object search, configurable refusal — with its own tests), started by `frontend/scripts/e2e-smoke.sh` on `CULVERT_E2E_LDAP_STUB_PORT` (19389) because enabled-LDAP writes now cross the directory preflight unconditionally.
>
> **6A2C-B. BACKEND CORRECTION (explicitly backend work; commit `91762767`).** *Blocker 1 — import.* `POST /api/idp/legacy-ldap/import` requires `?documentRevision=` (`428 precondition_required` / `409 stale` + `current.documentRevision`, decided inside the registry transaction — `IdPRegistry.Create` with the document revision and the operationId) and `?operationId=` (`428 operation_id_required`); it rides the durable ledger as action `idp.import` with the create's intent-before-write / replay / `operation_mismatch` / pending-UNKNOWN / `GET /api/idp/operations/{id}` semantics; the intent's candidate commitment binds the authoritative legacy-source identity (URL, base DN, bind DN, credential PRESENCE, StartTLS, skip-verify, filter, group) — the credential is never in the ledger, audit, log or response; the answer is action-bound (`imported:true`, the disabled ldap profile identity + entry revision + `operationId` provenance, the RESULTING `documentRevision`, the credential-free `source` via `legacyLDAPImportSource`, the fleet publication facts). *Blocker 2 — exact secret binding.* Every ledger intent records `candidateCommitment` = hex HMAC-SHA256 over a length-framed (type, OIDC client secret, LDAP bind password, inline SAML metadata) under a NODE-LOCAL 32-byte key `<dir>/.idp_candidate_key` (0600, minted once beside `idp_operations.json`; an in-memory ledger uses a per-process key); replay requires the public spec digest AND a constant-time commitment match (`matchesCandidate`), so the same operationId with any different secret is `409 operation_mismatch` with zero mutation while the exact candidate replays across restart; an unreadable/short key marks the ledger DEGRADED (fail closed — every identified write refused), and `backup.go` excludes the key from every archive/restore (`isNodeLocalKeyArtifactPath`, the `.upstream_cred_key` rule). No plaintext, no unkeyed or reversible digest, anywhere. *Blocker 3 — non-bypassable preflight.* `ldapWriteActivationGate` (`ui_auth_ldap.go`): every create/update that introduces an ENABLED LDAP provider, or changes the connection spec (URL, StartTLS, skip-verify, bind DN, bind password, base DN) of an enabled one, crosses the authoritative directory test at the write boundary — after the replay + fence pre-checks, BEFORE the ledger intent — with no request parameter able to skip it (`?preflight=` is a compatibility no-op); a label-only edit does not re-dial; a failure is the bounded `422 preflight_failed` (`current.step` ∈ the five test steps, `current.reason` ∈ the seven bounded classes, + the sanitized report), and because it is decided before the intent a failed/stale/unavailable preflight leaves registry, ledger, cutover record, audit and fleet untouched (R6/R7, `integration4.sh`). *Blocker 4 — boot idempotence.* The legacy startup slice only OBSERVES the shadow (`observeLegacyLDAPShadowAtBoot`: fail-closed flag, no record, no audit); `LoadAdminSettings` reconciles it against the durable sentinel/record AFTER adopting them (`reconcileLegacyLDAPBootObservation`) — a durably completed cutover keeps its record identity and emits nothing; only a boot with NO durable record mints the boot-observed record and its one-time audit; missing/corrupt/unreadable settings return before reconciliation, so the retirement stays in force (single authority) and nothing is invented (R8, `integration4.sh` across two real restarts). Contract artifacts: `api/openapi/openapi.yaml` (+`LegacyLDAPImportSource`, `LegacyLDAPImportResult`, `IdPPreflightRefusal`; import params/responses; `IdPOperation.action` + `idp.import`), `openapi.json` (`make api-bundle`), `frontend/src/api/types.gen.ts` (`npm run generate`); the legacy console (`static/index.html`) sends the fence + operationId on import and handles 409/428/`replayed` (2F-A: legacy and v2 in one commit). No route added → `uiRoutes` unchanged. Pre-existing enabling-LDAP tests point at the in-process stub (the preflight can no longer be skipped); the import unit test carries the fence; the preflight unit test targets the gate's qualification rule.
>
> **6A2C-C. Frontend correction (commit `6555d6b4`).** `importLegacyLDAP(fence, signal)` is a bodiless POST carrying `?documentRevision&operationId`; its decoder sweeps the whole answer for secret-bearing keys at every depth, then binds the ACTION — `imported:true`, a DISABLED ldap identity + entry revision, the echoed operationId, the resulting `documentRevision` (token grammar), a credential-free `source.url`, the fleet facts — or `replayed:true` + the echoed operationId; anything else (an unrelated disabled profile included) is UNPROVEN; it does NOT require the full read-model projection (the page re-reads `GET /api/idp`, the only truth). `importCandidateDigest` hashes the NON-SECRET legacy-source identity (credential presence excluded — presence is not identity); the marker grammar gains action `import`; `runImport` persists the marker BEFORE dispatch, clears it on the proven answer, keeps it on an UNPROVEN one (latch, one read-back, Recover via the ledger), and a 404 lookup offers Re-send, which re-opens the import ceremony BOUND to the recorded operation (the ceremony names it) and refuses locally when the legacy block changed since it was reviewed (the appliance refuses it too: `operation_mismatch`). `IDP_REFUSAL_CONTRACT` gains `preflight_failed` (422, REQUIRED typed `step` + `reason`; the callout renders "step X · reason Y", never the server's text) and it is `TERMINAL_NOTHING_WRITTEN` (decided before the intent ⇒ the marker is released). **Found during the correction and fixed (PC5, verified failing on the `64da0df0` page before the fix): a Re-send of ANY unresolved operation never dispatched** — the fresh marker carried a new `startedAt`, and the store's immutable-evidence rule refused it as "another unresolved operation"; `adoptOrRecordMarker` now dispatches a re-send under the RECORDED marker (same evidence, same instant) and a first dispatch records the fresh one. Test pins updated for the grown contract only: `IDP_OPERATION_ACTIONS` pins `[idp.create, idp.update, idp.import]`; fe6a2-red-api A1/A7 use the fenced import call; the RED page file counts the read-back from the confirm instant (the mock answers synchronously), confirms the re-opened re-send ceremony, and tolerates the credential-free LDAP candidate having no T2 review step.
>
> **6A2C-D. Secret proof extended (Blocker 2's leak sweep).** Ledger (`idp_operations.json` + siblings), `audit.jsonl`, the process log, every API response and browser storage are swept against the typed secrets (OIDC secret A/B, LDAP bind password A/B, inline SAML metadata) and the YAML bind canary: R4/R9 (Go), `integration4.sh` (real binary, before and after two restarts), `fe6a2.spec.ts` (DOM, URL, `sessionStorage`, the recovery marker, every response body), and the decoder's whole-answer secret-key sweep on the import answer. The commitment key is 0600, beside the ledger, node-local and never archived (R9, `integration4.sh`). The marker stays non-secret (CM1/CM2 grammar; `importCandidateDigest` excludes credential presence).
>
> **6A2C-E. Qualification on the code head `e44e3f13` (`3c92e8fe` and this record are docs-only).** (1) `gofmt` clean, `go vet ./...` clean, `go build .` ok, `GOARCH=arm64` compile ok. (2) Diff-scoped `golangci-lint run --new-from-rev 98d4a6c8`: **0 issues** (the eight findings on the RED scaffolding — stub handler cognitive complexity, `noctx`, S1030, `unnamedResult`, an unused helper, import grouping — fixed in `e44e3f13`). (3) Focused RED/GREEN families ×3 under `-race` (`TestFE6A2C_|TestFE6A2_|TestFE6A1|TestFE6A0|TestLDAP|TestIdP|TestLegacyLDAP|TestAuthIdP|TestBackup|TestConfigSurfaces|TestRefusal`, `-count=3`, + `internal/ldapstub`): **ok, 393.5 s**. (4) Root `go test -race -count=1 -timeout=60m .`: **ok, 1903.5 s, RC=0**; non-root `go test -race ./internal/... ./cmd/...`: **108 packages ok, 0 failures**. A plain (non-race) root run during development failed once on `TestTopHosts_ConcurrentRecordDecayAndTop` (store.go untouched by this round; 5/5 in isolation; green in the race run) — the loaded-box decay race its own methodology note records. (5) `make api-bundle api-lint api-route-coverage` ok, `TestOpenAPI_*` ok, tree clean after the bundle; `uiRoutes` untouched. (6) Frontend: `eslint .` clean, `format:check` clean, `tsc --noEmit` clean, `vitest run` **933/933** (84 files; the fe6a2c files 16/16 incl. PC5). (7) `frontend/scripts/verify.sh` **ALL GATES PASSED**; `verify-determinism.sh 5` RC=0; `test-drift-gate.sh` all cases correct (A–D fail, E passes). (8) Binary determinism: two `CGO_ENABLED=0 go build -trimpath -ldflags=-buildid=` builds byte-identical (`f99f3055…`). (9) Real-binary restart journeys on that binary with the LDAP stub (`cmd/ldapstub`): `integration3.sh` **38/38** (its enabling PUTs now point at the stub — the preflight cannot be skipped) and the NEW `integration4.sh` **53/53**: import refused without fence / without operationId / on a stale fence (typed 428/428/409, `current.documentRevision`, nothing written, no ledger record); the fenced identified import answers action-bound (`imported`, disabled ldap, operationId, moved document revision, credential-free `source` incl. `bindCredentialConfigured:true`, fleet facts) and the profile's provenance is the import operation; a repeat is `replayed:true` with one profile; same operationId + secret B (LDAP and OIDC) ⇒ `409 operation_mismatch` with nothing written, the exact candidate replays; the candidate key is 0600; an enabled create against a dead directory ⇒ `422 preflight_failed {reachable, unreachable}` with the profile count, document revision, ledger FILE (byte-identical), audit line count and legacy retirement all unchanged and no ledger record; the enabling PUT against the stub commits the cutover (retired, `admin_api`, durable, exactly one retirement audit); **two real restarts** keep the record identity/trigger/registry revision/actor byte-identical and the retirement-audit count unchanged; import and exact-candidate replays survive both restarts, the mismatch is still refused, exactly one `idp.import` audit; no secret in ledger/audit/log at any point. (10) Focused `e2e-smoke.sh e2e/fe6a2.spec.ts e2e/fe6a1.spec.ts`: **9/9** (W1–W5 incl. the new W3a, A1–A5, J1–J9). (11) Two consecutive COMPLETE Playwright runs against the real binary: **155/155 and 155/155** (3 pre-existing env-gated skips each, 3.1 min each; the harness's cwd `cluster.json` artifact removed after each run, never committed). (12) Operator `/data` snapshot (51 files): **51 OK, 0 mismatches** after every run.
>
> **6A2C-F. Exit gate.** `origin/main` re-fetched after qualification = `993b3902`, unchanged since the FE-6A.2 exit-gate merge `624f06e2` and an ancestor of this head — no merge, no requalification. Local == remote at every push.
>
> **6A2C-G. Deferrals and residuals (recorded).** 6A2-J items (1) GAP-2, (2) cleartext secrets at rest (FE-6F), (3) the roster read-model gaps, (6) tier divergence, (8) the IA annotation and (9) the `null`-permitting emitters are unchanged. 6A2-J (4) `?preflight=connection` — CLOSED (the gate is non-bypassable; the parameter is a compatibility no-op). 6A2-J (5) unfenced import — CLOSED. 6A2-J (7) the boot residual — CLOSED. New, recorded: the commitment key is node-local by design, so a registry + ledger restored onto a fresh volume cannot REPLAY pre-restore operations (the same operationId answers `operation_mismatch` rather than replaying — a refusal, never a duplicate write; the restore runbook already excludes node-local keys); an import re-send after the legacy block changed is refused on both sides and needs an Abandon + fresh import. **Do not start FE-6B. STOP for external freeze review of the corrected FE-6A.2 candidate.**

> **6A3C — FE-6A.2 correction ROUND 3 (append-only; the corrected candidate `eb90ebc5` and every earlier frozen commit untouched).** The second external review of `eb90ebc5` REJECTED it on three source-level blockers and accepted everything else (custody/ancestry/qualification, the mandatory LDAP preflight + bounded refusal, the exact-secret HMAC once a valid durable key exists, the import ledger integration + PC5 re-send, completed-admin-cutover restart idempotence for a READABLE settings file, every prior ceremony/redaction/admin flow). Chain: `eb90ebc5 → 5c7be2d1 (RED on eb90ebc5) → 8829b804 (BACKEND CORRECTION) → 7ceb8653 (frontend) → 65c8bd2c (dist) → 9f26e887 (lint + key-fault gates) → e46faeec (docs) → 9899de32 (B4 fixture) → this record`.

> **6A3C-A. RED before (on the exact corrected candidate `eb90ebc5`, commit `5c7be2d1`).** Go `fe6a3c_red_test.go`: *Blocker 1* — **S1** reviewed source A, YAML changed to B before the POST ⇒ `409 import_source_stale` + `current.importSourceRevision`, zero registry/ledger/audit mutation; absent token ⇒ `428 import_source_required` — FAIL (no token exists); **S3** the exact token imports once and replays once across a restart with the token echoed, the same operationId + a different token ⇒ `operation_mismatch` — FAIL; **S4** a CREDENTIAL-ONLY YAML change invalidates the reviewed token and no token / read model / refusal / ledger discloses either credential — FAIL. *Blocker 2* — **K1** the key's publication is fsynced (file + directory) before the store reports healthy — FAIL (`os.WriteFile`); **K2** a file-fsync or directory-fsync fault during publication leaves the store DEGRADED (Begin refused), never healthy — FAIL ×2; **K3** concurrent minting (32 callers × 12 trials) publishes ONE generation that every caller reads — FAIL (last writer wins; many-trial because a single trial passed the defect 2/30); **K4** a commitment-bearing ledger whose key is missing is DEGRADED and never re-keyed — FAIL (re-minted); **K5** CONTROL: a missing key with no commitment-bearing ledger mints — PASS. *Blocker 3* — **B1** missing settings + YAML + enabled registry profile ⇒ ONE durable observed record (sentinel WITH its record) and ONE operation-keyed audit across two boots — FAIL (no record); **B2** unreadable settings ⇒ shadowed, no success audit; the first save after storage recovery reconciles once, never a sentinel without its record — FAIL (sentinel without record); **B3** corrupt settings ⇒ quarantined evidence preserved, no incomplete record, reconciled once on the first save — FAIL; **B4** durable record with `auditPending`, crash before the audit ⇒ exactly one operation-keyed audit on restart under the SAME identity — FAIL (0 audits); **B5** CONTROL: the completed admin cutover stays `TestFE6A2C_R8` — PASS. Frontend (13 rows, all failing on `eb90ebc5`: the decoder has no `importSourceRevision`, the fence has no such member, the digest ignores it, the two refusal codes are unknown): `fe6a3c-red-api` CB1–CB4 (the present block carries the token and refuses its absence or a non-commitment value; the POST query carries the reviewed token and a 2xx — imported or replayed — is proven ONLY when it echoes the exact token; the token is part of the marker's candidate digest; `import_source_required` 428 + `import_source_stale` 409 with a typed current token are contracted), `fe6a3c-red-page` PB1–PB3 (the POST carries the REVIEWED token; a 2xx with a different token is UNPROVEN — latched, marker kept, one read-back; the marker binds the token). Real binary: `fe6a2.spec.ts` W2 asserts the import POST carries the token `GET /api/idp/legacy-ldap` published and that the answer echoes it. The shared `LEGACY_PRESENT` fixture gained the token additively (the 933 accepted rows unchanged).

> **6A3C-B. BACKEND CORRECTION (explicitly backend work; commit `8829b804`, lint/gates `9f26e887`).** *Blocker 1 — import bound to the reviewed source.* `GET /api/idp/legacy-ldap` publishes `importSourceRevision` = `isr1:` + hex HMAC-SHA256 under the node-local candidate key over a length-framed (domain tag, the import candidate's public spec digest, the candidate's EXACT secret commitment) — every security-effective imported field, the bind-credential VALUE included, disclosing none; the literal `unavailable` when no usable ledger key exists. `legacyLDAPImportCandidate` is the ONE construction the read model's token and the import both commit to. `POST /api/idp/legacy-ldap/import` requires `?importSourceRevision=` (`428 import_source_required`; a malformed value is 400) and refuses a token that is not the CURRENT source's — the YAML changed, credential-only changes included, or the node restarted on an edited config — with `409 import_source_stale` + `current.importSourceRevision`, decided BEFORE the document fence, the ledger intent and any registry write; the intent records the token (`idpOperation.ImportSourceRevision`), a known operationId replays only when the re-dispatch names the token it was bound to (`idpReplayKnownImport`; the current YAML is deliberately NOT consulted for a committed import — its truth is the ledger), otherwise `409 operation_mismatch`; success and replay answers echo the token. *Blocker 2 — the candidate key is created durably, exclusively, once.* `internal/fileutil.PublishExclusive(path, data, perm)`: unique temp file in the same directory (perm applied), complete write with an explicit SHORT-write check, file fsync, `link(2)` publication (`EEXIST` ⇒ another generation won and the loser reads the winner's complete bytes — `created=false, err=nil`), directory fsync; every failure leaves NO partial target and no residue; a directory-fsync failure AFTER the link is still an error (the name's durability is unknown) with the complete key left for the next boot. The sync steps run through the package's existing `SetSyncHookForTest`/`SetSyncObserverForTest`; the write / short-write / link steps through the new `SetPublishIOHookForTest` seam. `newIdPOperationStore` reads the LEDGER before the key: a missing/short/corrupt/unreadable key beside a ledger carrying keyed commitments is fail-closed `operation_ledger_degraded` (reason `unreadable`, the detail naming the missing key) and is NEVER re-minted — minting happens only when no commitment-bearing record exists (`idpLoadCandidateKey(path, mayMint)`); a failed publication is degraded, never a key of unknown durability. No-backup (`isNodeLocalKeyArtifactPath`) and no-secret rules unchanged. *Blocker 3 — boot reconciliation is a state machine over EVERY settings-load outcome.* `LegacyLDAPCutover.AuditPending`: an OBSERVED transition is minted with its audit pending (`mintPendingLegacyLDAPRetirement`), the sentinel and the record are persisted TOGETHER first, and the save's success path completes the audit through the durable operation-keyed boundary (`audit.AppendOperation`, persist-first and idempotent on the record's operationId) then clears the flag durably; a crash between the durable record and the audit completes the SAME identity's audit exactly once on the next boot (a record loaded with `auditPending` is completed on load), a crash after the audit re-appends nothing. Missing settings = a KNOWN truth: `LoadAdminSettings` reconciles, saves record + sentinel, then audits. Unreadable / corrupt (quarantined) settings = an UNKNOWN truth: the observation stays PENDING (fail closed — the legacy authenticator stays shadowed, nothing minted, nothing audited), no save serialises the sentinel without its record (`LegacyLDAPRetired` is written only when no reconciliation is pending), quarantined evidence is preserved, and the FIRST successful save after storage recovery (`saveAdminSettingsWithOverrides`, under `adminSettingsMu`) reconciles the pending transition exactly once. A pre-existing durable sentinel without a record (pre-record files) is still honoured. `markLegacyLDAPRetired` (the boot-observed mint) is now pending-mint + synchronous save. Contract artifacts: `api/openapi/openapi.yaml` (`LegacyLDAPPresent.importSourceRevision` required, the import query parameter, `LegacyLDAPImportResult.importSourceRevision`, the two refusal codes), `openapi.json` (`make api-bundle`), `frontend/src/api/types.gen.ts` (`npm run generate`); the legacy console (`static/index.html`) sends the token it read, refuses `unavailable`, and re-reads the legacy card on 409/428 (2F-A: legacy and v2 in one commit). No route added → `uiRoutes` unchanged. Found and fixed inside the round: `adminSettingsPathSet()` re-locked `adminSettingsMu` from inside the save (deadlock, surfaced as a 600 s hang in the first GREEN run) — the recovery reconcile reads `adminSettingsPath` directly under the held lock and the helper is gone. Pre-existing import call sites (unit + `fe6a2c` R1/R2) carry the token; `withLegacyLDAPYAML` restores the boot latch on cleanup.

> **6A3C-C. Frontend correction (commit `7ceb8653`; dist `65c8bd2c`).** `LegacyLDAPPresentFacts.importSourceRevision` is REQUIRED by the decoder (grammar `^isr1:[0-9a-f]{64}$` or the literal `unavailable`; anything else refuses the whole legacy block — fail closed); `IdPImportFence.importSourceRevision` is carried in the POST query; the import decoder proves `imported` and `replayed` ONLY when the answer echoes the exact reviewed token (a different token is UNPROVEN: ceremony closed, page latched, marker kept, one read-back); the outcome carries the token; `importCandidateDigest` includes it (non-secret — the token is a keyed commitment, never the credential); `IDP_REFUSAL_CONTRACT` gains `import_source_required {428}` and `import_source_stale {409, typed current importSourceRevision}`, both `TERMINAL_NOTHING_WRITTEN` (decided before the intent ⇒ the marker is released, the page re-reads and shows the fresh source); the page refuses to open the import ceremony while the token is `unavailable` (the ledger is degraded — the appliance would refuse the import too). Pins grown for the contract only (fence objects, imported/replayed fixtures, URL expectations with the encoded token, FE-6A.1 inline legacy fixtures + the key inventory).

> **6A3C-D. Secret proof extended.** The token is a keyed commitment: S4 (Go) and `integration5.sh` (real binary) prove a credential-only change rotates it while neither credential appears in any token, read model, refusal, ledger, audit line, process log or response; the browser marker binds the token through the candidate digest (CB3/PB3 — non-secret). Repository sweep on the round-3 diff (`eb90ebc5..HEAD`): the test canaries (`LEGACY-BIND-P1/P2…`) appear ONLY in test files and fixtures, no private-key / token pattern in any added line, the candidate key name appears only in operator/design docs; `frontend/dist` and the OpenAPI artifacts carry neither; `gitleaks git --config .gitleaks.toml` (v8.30.1, the CI gate's rule set) over the 7 round-3 commits: **no leaks found**.

> **6A3C-E. Qualification on the code head `9899de32` (`e46faeec` is docs-only; `9899de32` is a test-fixture fix; this record is docs-only).** (1) `gofmt` clean, `go vet ./...` clean, `go build .` ok, `GOARCH=arm64` compile ok. (2) Diff-scoped `golangci-lint run --new-from-rev 98d4a6c8`: **0 issues** (cyclop on `PublishExclusive` → split into `writeTempSynced` + `syncParentDir`; `bytes.Equal`; gosec G101 on the canary constant names — all fixed in `9f26e887`). (3) Focused families ×3 under `-race` (`TestFE6A3C_|TestFE6A2C_|TestFE6A2_|TestFE6A1|TestFE6A0|TestLDAP|TestIdP|TestLegacyLDAP|TestAuthIdP|TestBackup|TestAdminSettings|TestUIAuthLDAP|TestAPIIdP|TestConfigSurfaces`, `-count=3`, + `internal/fileutil`, `internal/ldapstub`, `internal/audit`): **ok, 438.9 s**. The FIRST ×3 run failed B4 on its 2nd and 3rd iterations only: the audit boundary is exactly-once per `(action, operationId)` across the process-global ring, and B4 seeded a CONSTANT id, so a repeated run found it already recorded and — correctly — appended nothing; the fixture now mints a per-run id (`9899de32`; the product behaviour is the contract under test). (4) Root `go test -race -count=1 -timeout=60m .`: **ok, 2159.4 s, RC=0 (0 `--- FAIL`)**; non-root `go test -race ./internal/... ./cmd/...`: **108 packages ok, 0 failures**. (5) `make api-bundle api-lint api-route-coverage` ok, `TestOpenAPI_*` ok, tree clean after the bundle; `uiRoutes` untouched. (6) Frontend: `eslint .` clean, `format:check` clean, `tsc --noEmit` clean, `vitest run` **946/946** (86 files; the fe6a3c files 13/13). (7) `frontend/scripts/verify.sh` **ALL GATES PASSED**; `verify-determinism.sh 5` RC=0; `test-drift-gate.sh` all cases correct (A–D fail, E passes). (8) Binary determinism: two `CGO_ENABLED=0 go build -trimpath -ldflags=-buildid=` builds byte-identical (`b1975e16…`). (9) Real-binary restart journeys on that binary with the LDAP stub: `integration3.sh` **38/38**, `integration4.sh` **53/53** (its import calls now carry the token) and the NEW `integration5.sh` **51/51**: token required (428) / malformed (400); the ceremony's token goes STALE across a restart on a URL change AND on a credential-only change (`409 import_source_stale` echoing the current token, profile count / document revision / ledger file / audit line count unchanged, no ledger record); the exact token imports once and replays once across a restart with the token echoed; the candidate key removed beside the commitment-bearing ledger ⇒ ledger DEGRADED, the read model publishes `unavailable`, the import is 503 and nothing is minted; the key restored ⇒ the replay answers again; missing settings + YAML + enabled registry profile ⇒ one durable observed record (sentinel WITH record) and exactly one operation-keyed retirement audit across two real boots; corrupt settings ⇒ quarantined evidence preserved, the retirement pending (no sentinel, no audit), an UNRELATED `PUT /api/settings/log-level` save reconciles it exactly once with a fresh identity that is then stable across two further restarts with the audit count unchanged; no secret in ledger/audit/log at any point. (10) Focused `e2e-smoke.sh e2e/fe6a2.spec.ts e2e/fe6a1.spec.ts`: **9/9**. (11) Two consecutive COMPLETE Playwright runs against the real binary: **155/155 and 155/155 (3 pre-existing env-gated skips each, 3.7 / 3.6 min** (the harness's cwd `cluster.json` artifact removed after each run, never committed). (12) Operator `/data` snapshot (51 files): **51 OK, 0 mismatches after every run**.

> **6A3C-F. Exit gate.** `origin/main` re-fetched after qualification = `993b3902`, unchanged since the FE-6A.2 exit-gate merge `624f06e2` and an ancestor of this head — no merge, no requalification. Local == remote at every push.

> **6A3C-G. Deferrals and residuals (recorded).** 6A2C-G's items are unchanged. New, recorded: (a) an UNREADABLE settings file that happened to hold a COMPLETED cutover record is reconciled after storage recovery as a NEW observed identity (the old record was never readable, so its identity is unknowable) — the pre-existing settings-loss posture, which a restore of the file BEFORE the first save avoids (the runbook says so); (b) the write / short-write / link fault gates (`fe6a3c_key_faults_test.go` KF1–KF3) needed the publication seam that only exists WITH the primitive, so they were written in GREEN and each verified failing by disabling the corresponding check in `PublishExclusive` — recorded honestly rather than back-dated into the RED commit, whose K1/K2 prove the fsync faults through the pre-existing hooks; (c) the reviewed-source token is node-local by construction (keyed under the candidate key), so a legacy card read on one node cannot be imported on another — the import is node-local already. **Do not start FE-6B. STOP for external freeze review of the corrected FE-6A.2 candidate.**

> **6A4C — FE-6A.2 correction ROUND 4 (append-only; the corrected candidate `67e2a4a8` and every earlier frozen commit untouched).** The third external review of `67e2a4a8` REJECTED it on three source-level blockers and accepted the round-3 work (the reviewed-source token binding, the refused missing/stale tokens, the ledger-before-key ordering with fail-closed degradation, the missing/corrupt settings and persist-before-audit paths, the token-bound immediate import response, the qualification as executed). Chain: `67e2a4a8 → b4c0e9f9 (RED on 67e2a4a8) → a2eef2f3 (BACKEND CORRECTION) → fe2c53e8 (frontend) → 1f7aa334 (dist) → d0391f0d (docs) → 1139a2cf + 13082092 (lint: the intentional 0644 key write in C1) → this record`.

> **6A4C-A. RED before (on the exact corrected candidate `67e2a4a8`, commit `b4c0e9f9`).** Go `fe6a4c_red_test.go`: *Blocker 1* — **U1** a COMPLETED admin cutover → an injected unreadable boot (an unreadable object at the SAME path — the shape a root-run harness can observe) → readability restored → an UNRELATED save must adopt the same operationId with no new audit — FAIL (a new observed identity replaced the restored record); **U1b** the review's exact mode-based shape (`chmod 000`) — skipped as root, runs on an unprivileged harness; **U2** the file stays unreadable → the unrelated save must be refused with zero runtime mutation — FAIL (the observation was consumed and a record minted); **U2b** mode-based variant (original bytes unchanged) — skipped as root; **U3** CONTROL: corrupt/quarantined recovery → one durable identity + one keyed audit across two boots — PASS. *Blocker 2* — **L0** `GET /api/idp/operations/{id}` of a committed `idp.import` exposes its non-secret `importSourceRevision`, a non-import record carries none — FAIL (no token on the lookup). *Blocker 3* — **C1** a 0644 key, beside commitments or not ⇒ degraded, never re-moded or replaced — FAIL (accepted); **C2** a symlink named as the key ⇒ degraded, link intact — FAIL (the target was read as the key); **C3** a non-regular object ⇒ degraded — PASS (control); **C4** CONTROL: the contracted 0600 regular key loads — PASS. Frontend (12 rows; `tsc` fails on `67e2a4a8` — no `importSourceRevision` on the operation union or the marker): `fe6a4c-red-api` LA1 (4 rows: an `idp.import` record REQUIRES its token in the isr1 grammar, a non-import record FORBIDS it, malformed/misplaced is not a record, pending/aborted import records keep it — all FAIL) + LA2 (4 rows: the import marker carries the exact reviewed token as an allowlisted non-secret field and reads it back, a malformed token is refused, a create/update marker never carries one, a tampered store is unreadable — all FAIL); `fe6a4c-red-page` **L1** import marker + committed `idp.create` under the same id ⇒ UNPROVEN, marker retained, no re-send, no success claim — FAIL (marker cleared, "committed" announced); **L2** marker token A + committed import bound to token B ⇒ UNPROVEN — FAIL; **L3** CONTROL token A + import token A ⇒ committed and cleared — PASS; **L4** CONTROL pending / aborted / outcome_unknown unchanged (marker kept, no re-send, Abandon only on aborted) — PASS.

> **6A4C-B. BACKEND CORRECTION (explicitly backend work; commit `a2eef2f3`).** *Blocker 1 — storage recovery re-reads the file.* `LoadAdminSettings` records an EXPLICIT load posture (`adminSettingsLoadPostureNow`: `readable` / `missing` / `unreadable` / `corrupt_quarantined`). While the legacy-LDAP boot observation is still pending, EVERY save runs `reconcilePendingLegacyLDAPUnderSave` under `adminSettingsMu` BEFORE anything is written: it re-reads and parses the AUTHORITATIVE file — readable with a durable cutover ⇒ that EXACT record and sentinel are adopted verbatim (same `operationId`, trigger, actor), the observation consumed, NO new audit (logged as an adoption with the posture); still unreadable, or readable but unparseable ⇒ the save is REFUSED (`errAdminSettingsRecoveryUnreadable` / `errAdminSettingsRecoveryCorrupt`, `save REFUSED` in the process log) with zero file and zero runtime mutation — the evidence is never replaced and the observation stays pending for a later recovery; missing (quarantined at boot, or removed) or readable with no sentinel ⇒ nothing durable exists, so the observed transition is minted, persisted by that save and audited exactly once after it. The previous shape minted a NEW identity on the first save and atomically replaced the file without looking at it — and the round-3 deferral ("restore the file before the first save") was only true with a restart; it is true without one now. *Blocker 2 — an action-discriminated lookup.* `lookupReadModel` exposes `importSourceRevision` for an `idp.import` record and for no other action; OpenAPI `IdPOperation.importSourceRevision` (pattern `^isr1:[0-9a-f]{64}$`, the binding rule in its description), `openapi.json` (`make api-bundle`), `frontend/src/api/types.gen.ts` (`npm run generate`). *Blocker 3 — the key's confidentiality boundary.* `idpInspectCandidateKey` validates the key with NON-following metadata (`os.Lstat`) before a byte is read: a symlink, a non-regular object, or a mode with any group/world bit is `errIdPCandidateKeyExposed` ⇒ `operation_ledger_degraded` (reason `unreadable`, a bounded detail naming the boundary) — NEVER re-moded or replaced, beside commitments or not; the exclusive, synced mint path (`PublishExclusive`, 0600) is unchanged. No route added → `uiRoutes` unchanged.

> **6A4C-C. Frontend correction (commit `fe2c53e8`; dist `1f7aa334`).** `IdPOperation` is ACTION-discriminated (`IdPOperationActionFacts`): an `idp.import` record REQUIRES `importSourceRevision` in the isr1 commitment grammar (never `unavailable`), a create/update record FORBIDS it; a missing, malformed or misplaced token is not a record. The recovery marker is action-discriminated too: an import marker carries the EXACT reviewed token the POST was dispatched with (an allowlisted non-secret field, grammar-checked on write and read; a tampered store reads as unreadable; `sameMarker` compares it — immutable evidence), a create/update marker never does (the round-2 allowlist pin is unchanged for them). `recover()` binds the ledger record to the marker BEFORE any state is trusted (`operationBoundToMarker`: operationId, action, and for an import the token): an unbound record is the new `unbound` recovery view — "not bound to the dispatched candidate … outcome unproven; the marker is kept and nothing is re-sent" — with no Re-send, no Abandon and no commitment claim; a bound committed record clears the marker as before; pending / aborted / outcome_unknown are unchanged. Pins grown for the contract only: `fe6a2c` CM1/CM2 import markers and PC3's committed import record carry the token; LA2 narrows the read marker on its action.

> **6A4C-D. Secret proof extended.** The lookup's token is the keyed, non-disclosing commitment (L0 + `integration6.sh` assert no bind credential in the lookup body, ledger, audit or log); the marker's token is the same commitment (LA2 allowlist — no source fact, no credential). Repository sweep on the round-4 diff (`67e2a4a8..HEAD`): test canaries only in tests and fixtures; `gitleaks git --config .gitleaks.toml` over the round's commits: **no leaks found** (v8.30.1, the CI gate's rule set, 7 commits); `frontend/dist` and the OpenAPI artifacts carry no secret.

> **6A4C-E. Qualification on the code head `13082092` (`d0391f0d` and this record are docs-only; `1139a2cf`/`13082092` are a test-file lint directive).** (1) `gofmt` clean, `go vet ./...` clean, `go build .` ok, `GOARCH=arm64` compile ok. (2) Diff-scoped `golangci-lint run --new-from-rev 98d4a6c8`: **0 issues** (one gosec G306 on the RED row that deliberately writes a 0644 key — the fault under test — carried a `//nolint:gosec` directive with its reason in `13082092`). (3) Focused families ×3 under `-race` (`TestFE6A4C_|TestFE6A3C_|TestFE6A2C_|TestFE6A2_|TestFE6A1|TestFE6A0|TestLDAP|TestIdP|TestLegacyLDAP|TestAuthIdP|TestBackup|TestAdminSettings|TestUIAuthLDAP|TestAPIIdP|TestConfigSurfaces`, `-count=3`, + `internal/fileutil`, `internal/ldapstub`, `internal/audit`): **ok, 453.6 s**. (4) Root `go test -race -count=1 -timeout=60m .`: **ok, 2124.3 s, RC=0 (0 `--- FAIL`)**; non-root `go test -race ./internal/... ./cmd/...`: **108 packages ok, 0 failures**. (5) `make api-bundle api-lint api-route-coverage` ok, `TestOpenAPI_*` ok, tree clean after the bundle; `uiRoutes` untouched. (6) Frontend: `eslint .` clean, `format:check` clean, `tsc --noEmit` clean, `vitest run` **958/958** (88 files; the fe6a4c files 12/12). (7) `frontend/scripts/verify.sh` **ALL GATES PASSED**; `verify-determinism.sh 5` RC=0; `test-drift-gate.sh` all cases correct (A–D fail, E passes). (8) Binary determinism: two `CGO_ENABLED=0 go build -trimpath -ldflags=-buildid=` builds byte-identical (`3b9f7f88b5faa51c…`). (9) Real-binary restart journeys on that binary with the LDAP stub: `integration3.sh` **38/38**, `integration4.sh` **53/53**, `integration5.sh` **51/51** and the NEW `integration6.sh` **37/37**: a completed admin cutover; the settings path made unreadable for one boot (shadowed, pending, nothing invented, no audit); an unrelated `PUT /api/settings/log-level` while still unreadable is REFUSED — the unreadable object and the original bytes untouched, no record minted, no audit, `save REFUSED` logged; readability restored at the same path WITHOUT a restart → the next unrelated save ADOPTS the same operationId/trigger/actor (file and read model), no additional audit, the adoption logged, identity and audit count stable across two further restarts; the lookup of a committed `idp.create` carries no token while a committed `idp.import` exposes the reviewed token (also after a restart) and no credential; a 0644 key ⇒ ledger degraded naming the boundary, token `unavailable`, replay 503, the key neither re-moded nor replaced; `chmod 600` ⇒ healthy with the SAME key and token; a symlink key ⇒ degraded with the link and its target intact; a regular 0600 key restored ⇒ healthy. (10) Focused `e2e-smoke.sh e2e/fe6a2.spec.ts e2e/fe6a1.spec.ts`: **9/9**. (11) Two consecutive COMPLETE Playwright runs against the real binary: **155/155 and 155/155** (3 pre-existing env-gated skips each, 3.6 min each (the harness's cwd `cluster.json` artifact removed after each run, never committed). (12) Operator `/data` snapshot (51 files): **51 OK, 0 mismatches after every run**.

> **6A4C-F. Exit gate.** `origin/main` re-fetched after qualification = `993b3902`, unchanged since the FE-6A.2 exit-gate merge `624f06e2` and an ancestor of this head — no merge, no requalification. Local == remote at every push.

> **6A4C-G. Deferrals and residuals (recorded).** 6A3C-G (a) is CLOSED — a restored completed record is adopted by the first save without a restart, and an unreadable file is never replaced. 6A3C-G (b) and (c) unchanged. New, recorded: (a) the root-run harness cannot observe permission-based unreadability, so U1/U2 prove the shape with an unreadable OBJECT at the settings path and U1b/U2b carry the review's exact `chmod 000` shape for the unprivileged CI runner (skipped as root); (b) a readable-but-unparseable file at save time REFUSES the save rather than quarantining it — quarantine stays a boot-path decision (`quarantineCorruptStateFile`), so a mid-life corruption is never moved aside by an unrelated write and the operator repairs or restarts; (c) a key that fails the boundary check is reported and left in place — the operator's `chmod 600` (or replacing the link with the original file) plus a restart is the only remedy, by design; (d) admin handlers that persist BEST-EFFORT (`adminSettingsSave()` off the request goroutine — the pre-existing "a failing disk must not make an admin change fail" posture) still answer 2xx for their own runtime change while the durable save is refused and logged (`integration6.sh` records the log-level PUT answering 200 with the file object, the original bytes, the pending observation and the audit all untouched); handlers that call `SaveAdminSettings` directly receive the refusal; (e) the admin-API cutover's retirement audit line carries its operation identity in `detail` (`operationId=…`) rather than the structured `operationId` key the observed path uses since round 3 — pre-existing, outside this round's blockers, recorded (the journey reads either). **Do not start FE-6B. STOP for external freeze review of the corrected FE-6A.2 candidate.**

> **6A5C — FE-6A.2 correction ROUND 5 (append-only; the corrected candidate `a56ac527` and every earlier frozen commit untouched).** The fourth external review of `a56ac527` REJECTED it on three source-level blockers and accepted the round-4 work (the action-discriminated, token-bound import recovery; the fail-closed marker/decoder on action/token mismatch; the statically-present symlink/non-regular/exposed key degrading the ledger; an unreadable settings path no longer blindly replaced; the qualification as executed). Chain: `a56ac527 → 8ba04e02 (RED on a56ac527) → eb8bec66 (BACKEND CORRECTION) → 7cf84bcd (frontend) → e350d5a5 (dist) → 460a12e4 (docs) → this record`.

> **6A5C-A. RED before (on the exact corrected candidate `a56ac527`, commit `8ba04e02`).** Go `fe6a5c_red_test.go`: *Blocker 1* — **R1** a COMPLETED admin cutover + DISTINCTIVE unrelated settings across several ownership surfaces (session TTL 3 h, admin-UI allow CIDR, rate-limit exemption, log level) + an unknown-compatible field → an unreadable boot on a DEFAULTED runtime (the harness resets every seeded surface before the boot, as a fresh process would) → readability restored → an UNRELATED save: either refused with the file byte-identical (restart required) or accepted only with a complete rehydration — FAIL (the file was rewritten from defaults: `session_timeout_hours` 3 → 8, the unknown field gone); **R2** `legacy_ldap_retired:true` WITHOUT its record: retired stays in force, nothing minted, no audit, durability `record_missing`, a save carries it verbatim, a restart the same — FAIL (`durable`); **R3** the same sentinel-only file restored after an unreadable boot is never adopted as durable — FAIL (adopted as `durable`); **U1/U1b** (round-4 file) ASSERTION CORRECTION recorded in the RED commit: "the first save after recovery adopts and succeeds without a restart" → "the save is refused with zero mutation; the restart adopts the COMPLETE file" — U1 FAIL (the save was accepted), U1b skipped as root. *Blocker 2* — **K1/K2** a channel-controlled swap between the key's boundary validation and its read (seam `idpCandidateKeyPreReadHook`; the key path replaced by a symlink to a 0644 / a 0600 decoy): the result must be the already-validated bytes or fail-closed degradation, never the decoy — on `a56ac527` FAIL because no seam exists; against a TEMPORARILY seamed `a56ac527` (Lstat → hook → ReadFile; local verification only, never committed — the round-3 KF precedent) FAIL on the defect itself: "CHECK/USE RACE: the replacement symlink target's bytes were loaded as a healthy key"; **K3–K5** controls (no swap loads; a symlink present before the open is degraded and left intact; a wrong-length 0600 key is refused) — PASS. *Blocker 3* — **A1** the admin-API cutover's retirement audit carries the STRUCTURAL `operationId`, exactly once, record not left pending — FAIL (empty; identity only in free text); **A2** an unsyncable audit sink (`audit.SetPersistForTest` with a plain writer ⇒ `ErrSinkNotSyncable`) must leave the durable cutover audit-pending and the next boot completes it once — FAIL (an unkeyed best-effort entry was emitted, nothing pending); **A3** CONTROL a durable `admin_api` record with `auditPending` completes exactly once across two restarts — PASS; **A4** a crash AFTER the append but BEFORE the cleared marker persisted, against a REAL `RotatingFile` sink — FAIL (a second line was appended at the next boot); **A5** CONTROL a refused cutover (persist failure ⇒ `500 persist_failed`; preflight failure ⇒ `422`) emits no retirement audit and leaves no runtime state — PASS. Frontend: `fe6a5c-red-api` **DA1** ×3 (`record_missing` decodes on absent and present blocks; the enum lists exactly four words) — FAIL; **DA2** control (unknown word refused, three words decode) — PASS; `fe6a5c-red-page` **DP1** (`record_missing` renders "Record missing", never "Durable"/"Pending reconciliation", no fabricated identity, no non-GET) — FAIL.

> **6A5C-B. BACKEND CORRECTION (explicitly backend work; commit `eb8bec66`).** *Blocker 1 — refuse until restart; never partial adoption.* The safe result required correcting round 4's "save succeeds without restart" premise, recorded transparently (U1/U1b in the RED commit, U2's tail in the backend commit): `reconcilePendingLegacyLDAPUnderSave` REFUSES every save when a file EXISTS at the authoritative path — readable ⇒ `errAdminSettingsRecoveryRestartRequired` (the runtime booted on defaults; the restart's `LoadAdminSettings` adopts the COMPLETE file — every unrelated durable field and every unknown-compatible field, the same cutover identity, no new audit), still unreadable / unparseable ⇒ refused with zero mutation (as round 4); only a MISSING file mints the observed transition. The round-4 branch that copied `legacy_ldap_retired` + `legacy_ldap_cutover` and then atomically replaced the whole file with a snapshot of a defaulted runtime is gone. Full rehydration under the save was rejected: the apply functions carry component side effects and their own locks, and a save-time re-application of every surface is a second boot path to keep equivalent — a refusal with one bounded remedy is the smaller, provable contract. *Sentinel without record.* `applyLegacyLDAPRetirement` loads `legacy_ldap_retired:true` with no record fail-closed: retired stays in force, no record is invented, `legacyLDAPCutoverDurableFlag` stays false, the save never promotes it (guarded on a present record), later saves carry the file's evidence verbatim, the process log names the posture, and `legacyLDAPCutoverDurability` reports the new bounded word `record_missing` (derived, never latched: an unreadable boot still reports `pending_reconciliation`). The record is stored BEFORE the sentinel on every path (`mintPendingLegacyLDAPRetirement`, `markLegacyLDAPRetiredWith`, the load) so no reader observes a transient record-less sentinel. OpenAPI `LegacyLDAPCutoverDurability` enum + description; `openapi.json` (`make api-bundle`), `frontend/src/api/types.gen.ts` (`npm run generate`). *Blocker 2 — one descriptor for check and use.* `idpReadValidatedCandidateKey` opens with `O_RDONLY|O_NOFOLLOW|O_NONBLOCK` (the `list_backups.go` precedent; a symlink at the path fails the open with ELOOP ⇒ `isNoFollowRefusal` in the build-tagged nofollow files ⇒ `errIdPCandidateKeyExposed`), validates regular + no group/world bit on `f.Stat()` of the OPENED file, and reads exactly `idpCandidateKeyLen` bytes from that descriptor (`io.ReadFull` of len+1: one more byte or fewer is a length refusal). The path is consulted once, at the open; the Lstat-then-ReadFile shape (two lookups) is removed; the test seam `idpCandidateKeyPreReadHook` (nil in production) sits between the descriptor-bound validation and the read. *Blocker 3 — the admin cutover audit is keyed and recoverable.* `idpLegacyCutoverHook` mints its record with `AuditPending:true`; `markLegacyLDAPRetiredWith` installs record-then-sentinel and emits NOTHING (`audit.Add` removed); the persist-before-publish save makes sentinel + record durable and its success path completes the audit through `completeLegacyLDAPRetirementAudit` → `audit.AppendOperation` (structural `Entry.OperationID`, exactly once against the durable JSONL record via `FindAndSync`), then persists the cleared marker; a failed append leaves the record pending (next save or boot completes it once); a crash after the append but before the marker persisted appends nothing at the next boot; the reason text is derived from the durable record's trigger so a deferred completion emits the same line. A refused cutover (persist failure; preflight/fence refusals decided before the hook) emits nothing. No route added → `uiRoutes` unchanged.

> **6A5C-C. Frontend correction (commit `7cf84bcd`; dist `e350d5a5`).** `LEGACY_CUTOVER_DURABILITY` gains `record_missing`; the legacy card renders it as a warn badge ("Record missing — retired sentinel without its operation record …") and never as "Durable", with no fabricated cutover identity; the decoder still refuses any other word. DP1's assertion was narrowed to the blocker's claim: the Import control is gated on `present` alone (pre-existing FE-6A.2 behaviour; the server refuses an import on a retired node), so its absence is not asserted.

> **6A5C-D. Secret proof.** No new secret surface: the durability word, the refusal messages and the audit detail carry no credential; the key is read from a descriptor and never logged. `gitleaks git --config .gitleaks.toml` over `a56ac527..HEAD`: **no leaks found** (4 pre-record commits); `frontend/dist` and the OpenAPI artifacts carry no secret.

> **6A5C-E. Qualification on the code head `e350d5a5` (`460a12e4` and this record are docs-only).** (1) `gofmt` clean, `go vet .` clean, `go build .` ok, `GOOS=windows go build` ok (the nofollow platform files). (2) Diff-scoped `golangci-lint run --new-from-rev 98d4a6c8`: **0 issues** (R1's two branches were extracted into helpers for gocognit/nestif). (3) Focused families ×3 under `-race` (the round-4 selector + `TestFE6A5C_`, + `internal/fileutil`, `internal/ldapstub`, `internal/audit`): **ok, 385.4 s (a first run was terminated at 201 s by the heavy chain's own `pkill -x Culvert.test` sweep — no test had failed; rerun to completion after it)**. (4) Root `go test -race -count=1 -timeout=60m .`: **ok, 1760.3 s, RC=0 (0 `--- FAIL`)**; non-root `go test -race ./internal/... ./cmd/...`: **108 packages ok, 0 failures**. (5) `make api-bundle api-lint api-route-coverage` ok, `TestOpenAPI_*` ok, tree clean after the bundle; `uiRoutes` untouched. (6) Frontend: `frontend/scripts/verify.sh` **ALL GATES PASSED** (eslint, format, tsc, vitest **963/963** in 90 files — the fe6a5c files 5/5); `verify-determinism.sh 5` RC=0; `test-drift-gate.sh` all cases correct (A–D fail, E passes). (7) Binary determinism: two `CGO_ENABLED=0 go build -trimpath -ldflags=-buildid=` builds byte-identical (`d05ac93a976eadb8…`). (8) Real-binary restart journeys on that binary with the LDAP stub: `integration3.sh` **38/38**, `integration4.sh` **53/53**, `integration5.sh` **51/51** (its two-id audit expectations made order-independent — they had assumed a lexical order of two random ids) and `integration6.sh` **47/47**, RESTORED to the structured operation identity (`retire_audits` reads `operationId` only; detail-text parsing removed) and corrected to the round-5 contract: after a completed admin cutover (its audit keyed on the record's structural id) and an unreadable boot, readability restored at the same path WITHOUT a restart leaves the unrelated save REFUSED — file byte-identical, nothing adopted, no audit, `restart the node to adopt the file` logged — and the RESTART adopts the same operationId/trigger with the file untouched and no additional audit, stable across two further restarts; NEW B1b: a sentinel-only file boots `record_missing` (retired, shadowed, no `cutover`), an unrelated save carries it verbatim (sentinel kept, no record invented), still `record_missing` after the save and after a restart, no audit, the posture logged; B2/B3 unchanged (lookup action discrimination; the 0644/symlink/restored key boundary). (9) Focused `e2e-smoke.sh e2e/fe6a2.spec.ts e2e/fe6a1.spec.ts`: **9/9**. (10) Two consecutive COMPLETE Playwright runs against the real binary: **155/155 and 155/155 (3 pre-existing env-gated skips each, 3.1 min each** (the harness's cwd `cluster.json` artifact removed after each run, never committed). (11) Operator `/data` snapshot (51 files): **51 OK, 0 mismatches after every run**.

> **6A5C-F. Exit gate.** `origin/main` re-fetched after qualification = `993b3902`, unchanged since the FE-6A.2 exit-gate merge `624f06e2` and an ancestor of this head — no merge, no requalification. Local == remote at every push.

> **6A5C-G. Deferrals and residuals (recorded).** 6A4C-G (a)–(c) unchanged; 6A4C-G (d) narrowed: the best-effort handlers still answer 2xx while the durable save is refused and logged (the recorded FE-6E backend-truth debt, out of this round's scope by directive) — the recovery path now destroys none of their durable settings; 6A4C-G (e) is CLOSED (the admin cutover audit is operation-keyed). New, recorded: (a) round 4's "a restored file is adopted by the first save without a restart" is WITHDRAWN — adoption is the restart's; a save on a runtime that booted without the file is refused with one bounded remedy (the alternative, a save-time re-application of every settings surface, is a second boot path and was rejected); (b) `record_missing` is a terminal degraded posture on a node — no API mints the missing record; the remedy is a backup that carries it, or accepting the posture; (c) the key's check/use binding is proven through a test seam (`idpCandidateKeyPreReadHook`), not observable from the real binary — the K rows and the seamed-baseline verification are the evidence; (d) the integration5 fixture had asserted a lexical order of two random operation ids — corrected in the script (outside the repository). **Do not start FE-6B. STOP for external freeze review of the corrected FE-6A.2 candidate.**

> **6B0 — FE-6B.0 Certificates and CA lifecycle BACKEND-TRUTH GATE (backend only; no React page — FE-6B.1/6B.2 unstarted; append-only, FE-6A frozen at `8b356c4c` untouched).** Custody: `origin/main` re-fetched at entry = `fe464cdd`, NOT an ancestor of the frozen head → integrated by ONE evidence-preserving no-ff merge `f1db3633` (14 incoming files, all MCP First-Canary catalog usability — audited: no certificate/CA/TLS/OCSP/OpenAPI/route/backup-restore/legacy-UI file among them). Chain: `f1db3633 (merge) → 022f6281 (RED on the exact merged baseline) → 5f937ff0 (BACKEND CORRECTION + contract artifacts + legacy console + runbooks) → this record`. The exact current behaviour was recorded before any product change (scratch audit `fe6b0_audit.md`): on EVERY CA install path installation preceded the durable commit (`InitCA`/`LoadCustomCA` swapped the live CA and fired `CAChangedObserver` before `SaveCA`; the manual rotate answered `200 persisted:false`; auto-rotation installed a memory-only CA the next restart discarded); the rotation confirmation was a single GLOBAL, unbound, 60 s token consumed by ANY attempt; `POST /api/certs/upload` refused with plain-text 400s carrying the parser's text; `GET /api/ocsp` (viewer) published the mTLS client-cert PATH and the loader's RAW error; `GET /api/ca/status` published raw `unusableReason`/`rotationPersistError`/`loadFailureReason` (with the bundle path)/`loadRecoveryError`; `POST /api/ocsp` was a runtime-only toggle answered `200` although it did not survive a restart; no operationId, no ledger, no lost-response lookup, no fences anywhere on the surface; the legacy console consumed all of it.

> **6B0-A. RED before (on the exact merged baseline `f1db3633`, commit `022f6281`; `fe6b0_red_test.go`, 18 rows, every fault channel-controlled or filesystem-injected, no sleeps; every refusal row pins ZERO partial mutation — live CA fingerprint, bundle bytes, UI files — ZERO success audit and NO revision advancement).** All 18 FAIL on the baseline: **R01** stale/missing fences (no revision token on `GET /api/ca/status`; unfenced rotate/import/OCSP/UI-delete mutate or 404); **R02** a persistence failure (bundle path a directory) still PUBLISHED the new CA — "INSTALL PRECEDED THE DURABLE COMMIT"; **R03** no seam between the durable commit and the terminal record; **R04** no operationId replay, no ledger restart seam; **R05** the same operationId with a different candidate imported twice; **R06/R07** `POST /api/ca/rotate/challenge` 404 (the token unbound, consumed by unrelated attempts); **R08** key mismatch / malformed PEM / not-CA / broken chain all `400 invalid CA cert/key pair` (plain text); **R09** the data-dir path and raw errors on `GET /api/ocsp` and `GET /api/ca/status`; **R10** no UI-cert revision fence, no `DELETE /api/certs/ui`; **R11** the OCSP toggle `200` without durability, no fence, no scope; **R12** `mtlsClientCertFile` + `mtlsClientCertLastError` on a viewer response; **R13** an unkeyed best-effort audit while the sink refused; **R14** no fail-closed ledger posture; **R15/R16** no `GET /api/certificates` (the backup-manifest and `ConfigSnapshot` halves PASS as controls: `data/ca.bundle` archived, the UI key never, nothing CA/UI/OCSP on the CP→DP wire); **R17** the legacy console speaks `confirmation_token` and renders the raw fields; **R18** the valid journeys through the corrected contract. On `5f937ff0` all 18 PASS.

> **6B0-B. BACKEND CORRECTION (commit `5f937ff0`).** *Store/publication model.* `internal/ca/candidate.go`: a validated `Candidate` (`NewRotationCandidate` / `ParseCACandidate` / `ParseTLSCandidate`) → `PersistCandidate` (atomic 0600, the frozen PSCA envelope when a passphrase is set) → `Manager.Install`; `InitCA`, `LoadOrInitCA` (the first boot), `LoadCustomCA` and `RotateIfNeeded` are refactored onto it, so EVERY install path is persist-before-publish and a failed bundle write installs NOTHING — auto-rotation keeps the current CA, reports a bounded class through `RotationPersistFailureObserver` and retries at the next check (the engine tests that pinned "rotates in memory anyway" were inverted); `ca.PersistFailureClass` / `caFaultClass` / `caUnusableClass` are the bounded vocabularies; `ErrBundleDecrypt` / `ErrBundleMalformed` sentinels. *Identities and fences.* `caRevision` = `car1:<sha256 hex of the live CA DER>` (`car1:none`), `uiCertRevision` = `uic1:<sha256 hex of the persisted cert file>` (`uic1:none`), `ocspRevision` = `ocr1:<hex>` over the durable posture AND its generation (an A→B→A toggle never returns to an earlier token); absent ⇒ `428 precondition_required` (current under its own name), moved ⇒ `409 stale`; compared INSIDE `certOpsMu`, the one serialized boundary for every mutation (outer to `caMutationMu` and to `adminSettingsMu`). *Operation ledger.* `certificate_operations.go`: `<dataDir>/certificate_operations.json` mirrors `idp_operations.go` minus the candidate key (nothing here is secret): client UUID `?operationId=` REQUIRED on rotate / import / UI replace / UI delete / OCSP set (`428 operation_id_required`), intent durable BEFORE the first write, replay by id (`replayed:true`, also across a ledger restart), `409 operation_mismatch` for a different action or candidate, `409 operation_in_progress` / `operation_aborted` / `operation_outcome_unknown`, 256 slots with unresolved intents never evicted (`503 operation_ledger_full`), a corrupt/unreadable file FAIL-CLOSED `503 operation_ledger_degraded` with the evidence untouched; a terminal state is reported only once durable (`recordState: pending_reconciliation` otherwise), the success audit is part of the record — `audit.AppendOperation` keyed on action + operationId, marked durably after, `auditState: pending` until then — and `GET /api/ca/operations/{id}` (admin) SETTLES a pending intent from the object's OWN evidence (the live CA or the bundle on disk carrying the candidate fingerprint; the persisted UI cert carrying the candidate digest / no pair for a delete; the durable OCSP posture at the intent's generation), never a guess (`lookup_committed` / `lookup_absent` / `lookup_unproven` ⇒ `outcome_unknown`); `reconcileCertificateOperations` runs the same settlement at boot from `LoadAdminSettings`. *Challenge contract.* `POST /api/ca/rotate/challenge?operationId=&caRevision=` mints a 64-hex challenge bound to actor (`auditActor`), operationId, the CURRENT caRevision and a 120 s expiry (`caChallengeClock` seam), stated in the response with the CA fingerprint being replaced; process-local, single-use, consumed ONLY by a fully valid confirm — a malformed body is `400 invalid_input`, no challenge `428 challenge_required`, another actor / another operation / a moved revision / a wrong value / an expired one is `409 challenge_stale` with `current.changed` ⊂ {actor, operation, ca_revision, challenge, expired} and NOTHING consumed; audited `ca.rotate_requested` (an admin action, not a success). *Rotate.* `POST /api/ca/rotate`: replay → body → fence presence → lock → fence → challenge → `503 persistence_not_configured` without a bundle path (refused BEFORE anything is minted; the `persisted:false` success is gone) → candidate → intent → consume → `PersistCandidate` (failure ⇒ `500 persist_failed` + `current.class`, intent aborted, live CA unchanged, `rotationPersistDegraded`) → `Install` → `statCARotations` → terminal record → audit. *Import boundary.* `POST /api/certs/upload`: the COMPLETE candidate validated first — `400 candidate_invalid` with `current.reason` ∈ malformed_pem / chain_invalid / key_mismatch / not_ca / unsupported_key / encrypted_key_unsupported / expired / not_yet_valid, atomically, no key material or parser text echoed; `?dryRun=1` = the T2 facts (`fingerprint`, `subject`, `isCA`, `keyAlgorithm`, validity; UI: `dnsNames`, `chainLength`) + the fence to echo, no intent, no write; mitm fenced on `caRevision`, `409 candidate_duplicate` for the installed CA, persist-before-publish; ui fenced on `uiCertRevision`, `persistCustomUITLS` (cert then key with the compensating rollback — a rollback that also failed is the NON-terminal `500 outcome_unknown` `detail: rollback_failed`), `activation: restart_required`; file parts accepted beside plain fields. *Delete/replace safety.* `DELETE /api/certs/ui?operationId=&uiCertRevision=`: `404 not_found` when nothing is persisted, the private key removed FIRST (an interrupted delete leaves no usable half-pair), the T3 facts `uiCert.active` + `activation` (the running listener keeps what it loaded; the next restart falls back to self-signed); the inspection CA has NO delete route (always referenced by inspection; R10 pins it). *OCSP correction.* The desired posture is DURABLE (`OCSPSettingsSaved` / `OCSPCheckEnabled` / `OCSPSettingsGeneration` in `admin_settings.json`, AdminDurable-only `configSurfaces` rows, `applyAdminOCSP` at load wins over `proxy.ocsp_check`, `noteOCSPYAMLDesired` records the YAML source): `POST /api/ocsp?operationId=&ocspRevision=` persists the target under `adminSettingsMu` via `adminSaveOverrides.ocspSettings` and flips the checker only in `applyOnSuccess` (`ocspApplyRuntime` — one publication shape shared with boot), so a `200` (`durable:true`) always survives a restart; a persist failure is `500 persist_failed` with the runtime unchanged. `GET /api/ocsp` publishes `desired{enabled,source}` / `runtime{enabled}` / `durable` / `revision` / `scope: node-local` and a BOUNDED `mtlsClientCertReason` (cert_file_missing / key_file_missing / load_failed) — the recorded viewer-visible path/raw-error finding is closed AT THE SOURCE: `mtlsClientCertStatus` no longer holds the path or the loader's text, and the startup log names the reason class + base name. *Read model.* `GET /api/certificates` (viewer): `scope`, `ca{present, revision, fingerprint…, usable/unusableClass, persistDegraded/persistClass, loadFailed/loadFailureClass, persistenceConfigured, encryptedAtRest}`, `uiCert{present, revision, active, corrupt, …}`, `mtlsClientCert{configured, loaded, reason?, notAfter?}`, `ocsp{revision, desired, runtime, durable}`, `operations{degraded, retained, unresolved, capacity, auditSink}`, `backup{caBundleArchived:true, caBundleEncrypted, uiCertArchived:false, operationsArchived:false, configVersionRollback:false}`. `GET /api/ca/status` publishes `revision`, `scope`, `persistenceConfigured` and bounded `unusableClass` / `rotationPersistClass` / `loadFailureClass` / `loadRecoveryClass` (`noteSSLInspectionUnavailable` records a class beside the detail; the recovery loop stores the class). *Audit/recovery.* One durable operation-keyed audit per proven success after the durable record (`ca.rotate`, `ca.import`, `cert.ui.replace`, `cert.ui.delete`, `ocsp.set`); refused/aborted/ambiguous emit none; no audit, log, ledger record or refusal carries key material, a passphrase, a filesystem path, a raw parser/OS error or unbounded subject data (R09 sweeps response, ledger, audit and log). *Typed contract.* Every FE-6B route answers typed JSON with the closed `CertRefusal` vocabulary (405 typed; `503 ca_not_ready` replaces the plain 503 on `/api/ca-cert` + `/api/ca/download`); `requireRoleJSON` on all of them. *OpenAPI/routes.* `CAStatus` CLOSED; `OCSPStatus` gains revision/scope/desired/runtime/durable and the bounded reason (path/raw fields REMOVED); new `CertificateInventory`, `CARotateChallenge`, `CARotateConfirm`, `CARotateResult`, `CAImportResult`, `UICertRead`, `UICertCandidate`, `UICertReplaceResult`, `UICertDeleteResult`, `CertDryRunResult`, `CertUploadResult`, `CertOperation`, `OCSPDesired`, `OCSPRuntime`, `OCSPSetResult`, `CAFaultClass`, `CertRefusal` + `CertRefusal{BadRequest,Forbidden,NotFound,MethodNotAllowed,Conflict,PreconditionRequired,PersistFailed,Degraded}`; four genuinely new authoritative routes `POST /api/ca/rotate/challenge`, `GET /api/ca/operations/{operationId}`, `DELETE /api/certs/ui`, `GET /api/certificates` (`uiRoutes` 247 → 251; d0 + C1 pins moved; `api/route-classification.yaml` +4 rows; `make api-bundle api-lint api-route-coverage api-contract-test` green; `frontend/src/api/types.gen.ts` regenerated — no frontend runtime code consumes these types yet, `frontend/dist` unchanged). *Legacy console.* `forceRotateCA` reads `revision`, mints `crypto.randomUUID()`, obtains the bound challenge and confirms with the fence; `toggleOCSP` is fenced + identified and reports `durable`; `uploadCustomCert` fences on the inventory revisions and renders typed refusals from their bounded codes (`certRefusalText`); the CA/mTLS banners render bounded classes (`caClassText`); the persist banner no longer speaks of a memory-only CA. *Existing pins moved transparently* (recorded in the commit): the two-step token tests → the challenge contract; `TestForceRotate_Unpersisted…` → `500 persist_failed` with the live CA unchanged; `TestRotateIfNeeded_PersistFailureIsReported` / `…SuccessSignalIsGatedOnPersistence` → a failed write is NOT applied (bounded class observed); `TestCALoadFailure_SurfacedEvenWhenReady` → a first boot whose bundle write fails installs NO memory-only CA (the Ready()+failure window is built via the recovery shape); `loadFailureReason` → `loadFailureClass`; the mTLS status struct; the UI upload tests fenced + identified; the RSA rejection → the bounded reason.

> **6B0-C. Cert/secret boundaries.** Passphrases and private keys are write-only on every path (multipart fields, the CA bundle, the UI key file 0600); the ledger records only fingerprints/digests/fences/target values; `Candidate.Info` and every read model are public projections; R08/R09 pin no `PRIVATE KEY`, no `x509:` / `tls:` text and no data-dir path on any response, in the ledger, the audit trail or the process log; `integration7.sh` C8 sweeps the real binary's log, audit JSONL and ledger for key material, the passphrase and the data-dir path. `gitleaks git --config .gitleaks.toml` over `f1db3633..HEAD`: **no leaks found** (2 commits). No secret-inclusive backup support was introduced: `data/ca.bundle` stays the pre-existing Tier-1 artifact (sealed only under a passphrase), the UI pair and the ledger are never archived, and `GET /api/certificates.backup` states it.

> **6B0-D. Backup / restore / rollback / downgrade + node-local vs cluster (documented + tested).** `docs/operator/docker-compose-backup-restore.md` §13 (new) and `docs/operator/certificates-and-ca-lifecycle.md` §7: CA bundle archived (restore refuses an undecryptable one), UI pair NOT archived (re-upload after restore), ledger NOT archived (a pre-restore operation is `404` on the restored node), OCSP posture inside the sanitized settings file (restored + applied at boot), NONE of them on config-version rollback (R15 pins the `configSurfaces` rows: `ocsp_settings_saved` AdminDurable-only, no `ca_`/`ocsp` row on Rollback), nothing CA/UI/OCSP on the CP→DP wire (R16 pins `ConfigSnapshot`), a pre-FE-6B.0 binary ignores the new settings keys and never reads the ledger (the PSCA bundle format is unchanged). Runbooks `root-ca-expiry.md` (challenge ceremony; "a rotation is applied only once it is on disk"; bounded classes) and `ocsp-revocation-checking.md` (durable fenced set; bounded mTLS reason) updated; parity matrix FE-V28/FE-V29 rows record the shipped backend truth; CLAUDE.md project map + frontend entry extended.

> **6B0-E. Qualification (final code head `3be1fa84`; `5f937ff0` is the last product-code commit — `3be1fa84` is a TEST-ONLY hygiene fix, product bytes identical).** *RED→GREEN:* all 18 rows FAIL on `f1db3633` (31 evidence lines recorded in the scratch baseline: fences absent — `GET /api/ca/status` publishes no revision token; `POST /api/ca/rotate/challenge` 404 on every challenge row; import/UI-upload answered `200 persisted:true` unfenced and un-identified; every candidate fault `400 invalid CA cert/key pair` plain text; the viewer `GET /api/ocsp` carried a filesystem path; no ledger restart seam; `GET /api/certificates` 404; the legacy console consumed the retired fields `confirmation_token`/`mtlsClientCertFile`/`mtlsClientCertLastError`/`rotationPersistError`/`loadFailureReason`/`ca.unusableReason` and did not speak `/api/ca/rotate/challenge`/`caRevision`/`ocspRevision`/`mtlsClientCertReason`); all 18 PASS on `5f937ff0` and `3be1fa84`, twice under `-race` (42.6 s) and in the focused matrix ×3 under `-race` (root 12.3 s + `internal/ca` 13.7 s, 54 s wall, RC=0). *Static:* `gofmt -l` empty on every changed Go file; `go vet ./...` clean; diff-scoped `golangci-lint --new-from-rev 98d4a6c8 ./...` 0 issues (13 findings during the round — cyclop splits of `certOperationVerdict`/`apiCARotate`/`apiCertsReplaceUI`/`apiCertsUI`, rangeValCopy, nestif, unparam, dupl with rationale, unnamedResult — all resolved in-source, no suppression added except the one `//nolint:dupl` carrying its reason). *Race:* root package `go test -race -count=1 .` on `5f937ff0` = **RC=1 (1547 s) with exactly ONE failure, `TestTestFileReadsAreCWDIndependent`** — the R17 RED row read `static/index.html` by a CWD-relative path, which the repo's hygiene wall forbids because a concurrent `os.Chdir` in another test can flake it; corrected in `3be1fa84` (`staticIndexHTMLPath()` anchor, assertions unchanged, product code untouched) and the root race RE-RUN ALONE on `3be1fa84`: **RC=0 (0 `--- FAIL`, 0 panics) (1582 s)**; non-root `./internal/... ./cmd/...` under `-race`: **108 packages ok, 0 failures**. *Contract gates:* `make api-bundle api-lint api-route-coverage api-contract-test api-bundle-check` green (4 new routes classified by hand in `api/route-classification.yaml`, no PHANTOM/UNCLASSIFIED); `uiRoutes` 251 with d0 + C1 pins moved; C1.5 role/mutating parity green; `frontend/src/api/types.gen.ts` regenerated from the bundle, `frontend/dist` unchanged (no React code in this slice). *Builds:* deterministic Linux build twice on the final head → `62938f6e2e0ff9e4…` / `62938f6e2e0ff9e4…` (byte-identical, `CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags=-s -w`); arm64 cross-build RC=0; `cmd/culvert-maint` module build RC=0; `make api-bundle-check` RC=0. *Frontend:* `scripts/verify.sh` ALL GATES PASSED (eslint, format, tsc, vitest 963/963 in 90 files, licence + dist checks), RC=0; `scripts/verify-determinism.sh` RC=0 (dist byte-stable). *Real-binary journeys (deterministic binary, hermetic `CULVERT_DATA_DIR` per appliance, no root):* `integration7.sh` **60/60** — boot with a sealed CA; challenge-bound rotation → restart → operationId replay answers the committed record; a persistence fault (bundle path made a directory) ⇒ `500 persist_failed` class `not_a_file`, live CA fingerprint UNCHANGED, the operation reads `aborted`; import dry-run facts → `key_mismatch` refusal with zero mutation → commit → restart → same operationId with a different candidate ⇒ `409 operation_mismatch`; OCSP durable set survives a restart and the read model reports desired = runtime; UI-cert replace (`?dryRun=1` then commit, `activation: restart_required`) and typed delete; a corrupted ledger file ⇒ fail-closed `503 operation_ledger_degraded` on every FE-6B mutation with the evidence file preserved, restored file ⇒ recovery; process/leak sweep clean. Regression journeys `integration3/4/5/6_b0.sh` (the FE-6A.2 PAC/Upstream/IdP/Administrators surfaces on the same binary): **38/38, 53/53, 51/51, 47/47**. *Browser:* full Playwright smoke ×2 against the real binary (legacy console changed, so the legacy journeys are in scope): run 1 155 passed, 3 skipped (pre-existing env-gated), 2.8 min, RC=0; run 2 155 passed, 3 skipped, 2.8 min, RC=0. */data custody:* the pre-qualification `/data` snapshot (51 files) re-verified after the whole chain: 51 OK, 0 other after the Playwright chain AND 51 OK, 0 other after the root race — no qualification run wrote into the host's persisted state. *Secrets / identifiers:* `gitleaks` over `f1db3633..HEAD` (3 commits, 369 KB): no leaks; grep sweep of every changed file and every commit body for model identifiers: none (trailers only); the two `BEGIN … PRIVATE KEY` literals in `static/index.html` are pre-existing textarea PLACEHOLDERS present in the baseline, not key material. Working tree clean after the chain (0 dirty files); `frontend/cluster.json` removed after each Playwright run.

> **6B0-F. Exit gate.** `origin/main` re-fetched at exit = `fe464cdd`, unchanged since the FE-6B.0 entry merge `f1db3633` and an ancestor of this head — no merge, no requalification. Branch `claude/culvert-frontend-fe6-hyagdj` head `3be1fa84 (code head; this record is a docs-only commit appended on top of it)` = `origin/claude/culvert-frontend-fe6-hyagdj` (remote equality verified), working tree clean. FE-6A history (`98d4a6c8 → 64da0df0 → eb90ebc5 → 67e2a4a8 → a56ac527 → 8b356c4c`) is untouched and remains an ancestor; nothing was amended, squashed, rebased or rewritten; no pull request was opened.

> **6B0-G. Explicit deferrals (recorded, not fixed — each is a posture or scope decision outside "backend-truth gate only").** (1) **`DELETE /api/certs/ui` of the ACTIVE pair is ALLOWED, not refused**: the read model publishes `active` and the delete answer carries `activation: restart_required`, so the operator holds the T3 fact that the running listener keeps the old pair until restart; refusing would leave no API way to retire a compromised UI certificate without a restart-first ceremony — a product decision for FE-6B.1's ceremony design. (2) **`caRuntime` (ca.go) stays an unsynchronised package global** read by the inspect path; FE-6B.0 serialises every WRITER under `certOpsMu` → `caMutationMu` and made install persist-before-publish, but did not change the reader's memory model (pre-existing, outside this slice's contract). (3) **OCSP-8 stands**: the checker still does not reach the inspect path (`ocsp_coverage.go` claims pinned structurally); FE-6B.0 publishes the coverage truth and never claims otherwise on any surface — wiring it needs the soft-posture design CHAOS-65 recorded. (4) **The persistence-fault journey is observable only in the directory-at-path shape**: a permission fault needs a non-root harness user the CI container does not have; the `PersistFailureClass` table for `permission_denied`/`read_only`/`no_space` is unit-tested, not driven end-to-end. (5) **The rotation CHALLENGE store is process-local and volatile** (a restart between challenge and confirm ⇒ `409 challenge_stale current.changed:[challenge]` — no challenge is known for that operationId any more; a presented value that belongs to ANOTHER operation names `[operation]` instead — and the client re-issues); the OPERATION ledger is the durable half, and a challenge is deliberately not persisted because it is a secret whose only value is expiry. (6) **`ca.rotate_requested` (challenge issued) is an ordinary `auditEvent`, not operation-keyed**: it records intent to request, not a mutation; the operation-keyed success audit is emitted exactly once after the commit through `audit.AppendOperation`. (7) **`rootca_recovery.go`'s `SaveCA` branch** (a CA already loaded, the failure was the durability half) is unchanged: it can still hold `Ready()` true beside a recorded failure until the re-persist lands — FE-6B.0 made every NEW install persist-first, so the branch is reachable only from a pre-existing memory-only CA on upgrade, and the recovery loop plus `culvert_ca_load_failed` already cover it. (8) **No secret-inclusive backup** (private key / passphrase in the archive) was introduced — not approved; §13 of the backup runbook documents the node-local key artifacts the archive deliberately excludes and the restore-time posture for each. (9) **The React Certificates/CA page, FE-6B.1/6B.2, cluster/enrollment CA distribution and the legacy console's remaining non-cert panels are unstarted** by directive.


> **6B0C — FE-6B.0 CORRECTION ROUND (external freeze review of `3206ca47` REJECTED on four source-level lifecycle blockers; one append-only correction round; FE-6A still frozen at `8b356c4c`; no React page, FE-6B.1 unstarted).** Chain: `3206ca47 (rejected candidate, untouched) → a3051781 (RED correction matrix, test-only) → 4ea9e1cd (product correction + contract artifacts + runbook + legacy console copy) → 541b3fb6 (merged code head; this record is a docs-only commit on top of it) (this record)`. The rejection, restated in the repository's terms: `certOperationVerdict` decided a pending intent from the object's CURRENT content only (live/on-disk CA fingerprint, persisted UI-cert digest, UI-pair absence, OCSP generation+value), no writer settled an unresolved intent before changing its target and no per-object writer provenance existed — so a commit whose terminal record failed was re-classified aborted once a competitor wrote (false negative), a never-written intent was credited with a competitor's identical content or with absence (false positive), and a success audit could be lost forever; `StartCAAutoRotation` called `certMgr.RotateIfNeeded` outside `certOpsMu`/`caMutationMu` and its immediate round ran before `LoadAdminSettings`'s reconciliation; `certAbort` was best-effort and the handler still answered terminal `500 persist_failed`; a pending record retained no action-specific result, so a recovered commit replayed only generic fields.

> **6B0C-A. RED before (on exactly `3206ca47`, commit `a3051781`; `fe6b0c_red_test.go`, 18 functions / 10 rows, every fault channel- or file-controlled — the ledger path replaced by a directory, a bundle/settings/key path replaced by a non-empty directory, the `fileutil` durable-write SUCCESS observer arming a one-shot ledger break after an intent record, the durable-commit/terminal-record seam, crash-simulated pending intents written straight into the ledger file — no sleeps).** All of rows 1–9 FAIL on the baseline with the concrete defect as the message: **R01** X rotated (record failed) → Y imported B → X read `aborted` (`lookup_absent`); **R02** X pending import of A (never wrote) → Y imported the same A → X read `committed` (`lookup_committed`); **R03a–d** the UI replace/delete equivalents: replace-then-competitor `outcome_unknown`, never-written-same-pair `committed`, delete-then-competitor `outcome_unknown`, never-deleted-then-competitor-deletes `committed`; **R04** OCSP: commit-then-posture-change `outcome_unknown`, never-written-then-same-target `committed`; **R05** the auto-rotation round replaced the evidence of an unsettled X (live A → new) with the ledger unwritable, and a never-written intent stayed `pending` through a round (no `writer_*` settlement); **R06** the startup round rotated the CA while X was still unreconciled — "no boot gate exists"; **R06b** the source pin (no `defer finishCertificateLifecycleBoot()`, no `awaitCertLifecycleBootGate(` before the first round); **R07** all four refusal paths (rotate bundle-as-directory, UI replace cert-path-as-directory, UI delete key-path-as-directory, OCSP settings-path-as-directory) with the ledger broken after the intent record answered terminal `500 persist_failed`; **R08** (consequently) the refusal never became a durable record; **R09a–e** every recovered commit (rotate/import/UI replace/UI delete/OCSP) carried `result: <nil>`. **R10** controls PASS on the baseline (unrelated targets unblocked and untouched, completed operations never re-executed, valid auto-rotation with persistence + counter + dual-CA overlap). The three boot-gate seams were declared nil in the RED file on the baseline and moved into product code by the correction (the FE-6B.0 R03/R04 precedent).

> **6B0C-B. PRODUCT CORRECTION (commit `4ea9e1cd`).** *Blocker 1 — attribution.* The chosen shape is SETTLE-BEFORE-WRITE for every writer of every target, plus PER-TARGET WRITER PROVENANCE where the authoritative object can carry it atomically (OCSP). `settleCertTarget(s, target, why)` (certificate_operations.go) settles every pending intent on a target DURABLY — verdict from the object's evidence, the action-bound result rebuilt, the audit completed — and returns `errCertTargetUnsettled` when one stays pending (record not persistable, ledger degraded); every writer calls it under `certOpsMu` immediately before its write: the five admin handlers (`certSettleTargetOrRefuse` ⇒ `503 operation_unsettled`, `current.reason` a bounded ledger class, nothing written), the automatic rotation round (`runInspectionCARotationRound`, deferred with one log line, retried at the next check) and the CA recovery attempt (`tryInspectionCARecovery`, deferred, retried by the campaign). Why this closes both directions: content equality is valid evidence exactly until someone else writes, and now nobody writes before the evidence has been converted into a durable record — a competitor's identical content can never be credited to an earlier intent because that intent was settled (absent) before the competitor wrote, and a commit whose record failed is settled committed, result reconstructed from the still-intact object, before the competitor replaces it. The OCSP posture in `admin_settings.json` additionally records its writer (`OCSPSettingsWriteID`, `ocsp_settings_write_id`, co-written in the same atomic write; `config_surfaces` row `ocsp_settings_write_id`, AdminDurable-only); `ocspOperationVerdict` credits an intent only when the file names it — another writer's identical posture is the refusal, a posture without a writer is unproven. The CA bundle codec is FROZEN (PSCA) and the UI pair is two files, so those two targets carry no co-written provenance; settle-before-write is their protection and is pinned by R01–R03/R05. The settlement `why` names the settler (`lookup_*`, `reconciled_*`, `writer_*`). *Blocker 2 — the writer boundary.* The rotation round takes `certOpsMu` → `caMutationMu` (the documented order; nothing under either calls back), settles `root_ca` first, then `RotateIfNeeded` + secondary cleanup; the recovery attempt enters the same boundary. The boot is ORDERED EXPLICITLY: `certLifecycleBootGate` (armed at process start), `awaitCertLifecycleBootGate(ctx)` before the loop's immediate round, and `LoadAdminSettings` now runs `defer finishCertificateLifecycleBoot()` — reconcile the ledger, then release — on EVERY load path (missing, unreadable, corrupt-quarantined, readable; the previous inline reconcile ran only on the readable path, a defect the reorder exposed). Deadlock analysis: `certOpsMu` is outer to `caMutationMu` and `adminSettingsMu` everywhere; `settleCertTarget` takes only the ledger's own mutex through the store API; the gate is a closed channel plus ctx; the loop-starting tests release the gate as the settings slice would. *Blocker 3 — durable refusals.* `certAbort` reports whether the aborted record landed; on failure it memorises the refusal (`certRefusalMemo`, process-local) and every caller (rotate/import `persistCACandidate`, UI replace `uiCertPersistRefusal`, UI delete key-removal, OCSP save failure) answers `certRefusalNotDurable` — `500 outcome_unknown`, `current.detail: refusal_not_durable`, `current.state: pending`, `current.operationId` — with the product mutation absent. The next settlement (lookup, boot, or a later writer) records the memorised `persist_failed` (or `reconciled_absent` after a restart); a repeat of the same operationId replays `409 operation_aborted` and dispatches nothing. *Blocker 4 — action-bound recovery.* The intent records the non-secret recovery facts at Begin (`Previous` CA identity for rotate/import, `Candidate` public facts for a UI replace, `WasActive` for a UI delete) and the bounded `AuditDetail`; `certRecoveredResult` rebuilds the full result through the SAME builders the live handlers use (`caOperationResult`, `uiCertOperationResult`, `ocspOperationResult`), so lookup and replay carry `rotated`/`imported` + `ca` + `previous`, `replaced`/`deleted` + `activation` + `uiCert` + `candidate`, `ok` + `enabled` + `durable` + `revision` + `desired` + `runtime`; `Finish` keeps the recorded audit detail. Never a key, a passphrase or raw PEM. *Contract artifacts.* OpenAPI `CertRefusal` (operation_unsettled 503; the terminal-only-once-durable rule and the `refusal_not_durable` shape) and `CertOperation.code`/`result` descriptions; `openapi.json`/bundle regenerated (`make api-bundle api-lint api-route-coverage api-contract-test api-bundle-check` green, no route added — `uiRoutes` stays 251), `frontend/src/api/types.gen.ts` regenerated, `frontend/dist` unchanged; legacy console `certRefusalText` gains `operation_unsettled` and the `refusal_not_durable` detail; runbook `certificates-and-ca-lifecycle.md` §2 (recovered result, durable refusals) + new §8 (who may change a certificate object, boot order); CLAUDE.md entry extended. Existing tests adjusted: `rootca_recovery_test.go` + `cluster_ca_chaos_test.go` release the boot gate after `loadRootCA` (standing in for the admin-settings slice) — no accepted FE-6B.0 assertion was changed.

> **6B0C-C. Qualification (final code head `4ea9e1cd`; chain 9 ran on `4ea9e1cd`; the exit-gate merge `541b3fb6` (MCP-only incoming files) was requalified by chain 10 — see 6B0C-D; this record is a docs-only commit on top).** RED→GREEN: all 17 defect functions PASS on `4ea9e1cd` and R10 still passes; correction matrix ×5 under `-race`: RC=0 (7 s); correction + original FE-6B.0 matrices ×3 under `-race` (pre-commit): RC=0 (45 s); focused CA-rotation / startup-recovery / cluster-CA / UI-certificate / OCSP / ledger / audit / surfaces suites ×3 under `-race` (root + `internal/ca` + `internal/audit`): RC=0 (78 s). Static: `gofmt` clean, `go vet ./...` clean (RC=0), diff-scoped `golangci-lint --new-from-rev 98d4a6c8 ./...` 0 issues (the RED file's first pass had 6 — bytes.Equal, Index guards, two gocognit splits — resolved before the RED commit). Race: root `go test -race -count=1 .` RC=0 (1559 s, 0 `--- FAIL`); non-root `./internal/... ./cmd/...` RC=0 (108 packages ok, 0 failures). Contract gates: API bundle/lint/route-coverage/contract/bundle-check green; `make api-bundle-check` on the final head RC=0. Builds: deterministic build twice → byte-identical (`c11fdb750027885d…`, and identical to the journey binary built before the chain; `CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags=-s -w`); arm64 RC=0; `cmd/culvert-maint` RC=0. Frontend: `scripts/verify.sh` ALL GATES PASSED (vitest 963/963 in 90 files), RC=0; `verify-determinism.sh` RC=0 (dist byte-stable, unchanged by this round). Real-binary journeys on the deterministic binary (hermetic data dirs, no root): NEW `integration8.sh` **28/28** — J1 X committed → restart with X's record reverted to pending → boot reconciliation settles it `committed` (`reconciled_committed`) with the complete action-bound result on lookup AND replay, exactly one `ca.rotate` audit across the restart (idempotent operation-keyed append), then Y imports another CA: X stays committed, Y authoritative, one audit each; J2 a never-written import intent Z (candidate A) → restart → `aborted` (`reconciled_absent`) → Y2 imports the same A → Z never credited, import audits Y and Y2 only; J3 boot order: a near-expiry CA + a pending intent P → restart → P settled `reconciled_absent` (never `writer_*`) BEFORE the startup rotation round rotated the CA (dual-CA overlap active), then a corrupt ledger at boot DEFERS the startup round (`CA auto-rotation: round deferred`, CA unchanged, lookups `operation_ledger_degraded`) and the repaired ledger lets the next boot's round rotate; J4 OCSP provenance: the settings file names the writer, a reverted intent is re-settled committed with its action-bound result while the file names it and `aborted` once another writer id is recorded; J5 leak sweep clean. Regression journeys on the same binary: `integration7.sh` **60/60** (the FE-6B.0 lifecycle journeys unchanged), `integration3/4/5/6` **38/38 / 53/53 / 51/51 / 47/47**. Browser (legacy console copy changed): full Playwright ×2 — run 1 155 passed / 3 skipped (pre-existing env-gated), 2.9 min, RC=0; run 2 155 passed / 3 skipped, 2.9 min, RC=0. `/data` snapshot (51 files): 51 OK, 0 other after the whole chain (and again after the merged-head requalification: 51 OK, 0 other); leaked `culvert-det9` processes after the chain: 0; tree clean (0 dirty) after the chain and after the merged-head requalification. Secrets/identifiers: `gitleaks` over `f1db3633..HEAD` no leaks; no model identifier in any changed file or commit body (trailers only); no key material in the diff.

> **6B0C-D. Exit gate.** `origin/main` re-fetched at exit = `e21e6731`, NOT an ancestor of `4ea9e1cd` (it had advanced by PR #1422, the MCP First-Canary exact policy permit) → integrated by ONE evidence-preserving no-ff merge `541b3fb6`: 22 incoming files (`internal/mcp/{canary,policy,runtime}`, root `mcp_canary_*` + `mcp_rollout.go`, two MCP docs, one mutation script), audited — no certificate/CA/TLS/OCSP/OpenAPI/route-inventory/backup-restore/legacy-UI file, no file touched on both sides, no conflict. The merged head was REQUALIFIED (chain 10): `go build ./...` + `go vet ./...` clean; deterministic build twice byte-identical (`0920a8393403f1dc…`; differs from chain 9's binary only by the incoming MCP code); arm64 RC=0; `make api-bundle-check` RC=0; real-binary journeys on the merged binary `integration7.sh` **60/60**, `integration8.sh` **28/28** (a first run on the merged binary failed one harness expectation — the J2 audit check listed two random operation ids in creation order while the helper prints them lexically sorted; the script was corrected to compare order-independently, outside the repository, and re-run: 28/28 — the same fixture class as the FE-6A.2 integration5 correction); focused CA/UI/OCSP/ledger families + both FE-6B.0 matrices ×3 under `-race` RC=0 (118 s); root `go test -race -count=1 .` RC=0 (1565 s, 0 `--- FAIL`); non-root race RC=0 (108 packages ok, 0 failures); `/data` 51 OK, 0 other; tree clean. Frontend verify/dist determinism and the Playwright runs were NOT repeated for the merge: the incoming files contain no frontend, legacy-console or browser-consumed code (the chain-9 results on `4ea9e1cd` stand; `frontend/` is byte-identical between `4ea9e1cd` and `541b3fb6`). Branch head `541b3fb6 (merged code head; this record is a docs-only commit on top of it)` = `origin/claude/culvert-frontend-fe6-hyagdj`, working tree clean; `3206ca47` untouched and an ancestor; FE-6A history untouched; no amend, squash, rebase or rewrite; no pull request.

> **6B0C-E. Residuals (recorded, not fixed).** (1) The CA bundle and the UI pair carry NO co-written provenance (frozen PSCA codec; two files) — their attribution rests on settle-before-write, which holds for every IN-PROCESS writer; an OFFLINE writer (an operator restoring a backup whose bundle happens to be a pending intent's candidate) is outside the protocol and would be credited by boot reconciliation — the ledger is not archived, so a restore onto a fresh volume carries no pending intent, and the runbook §7/§8 state the boundary. (2) `certRefusalMemo` is process-local: a refusal whose record failed and a restart before recovery settles as `reconciled_absent` (still terminal, still a refusal) rather than `persist_failed`. (3) A degraded ledger now also defers automatic CA rotation (one log line per daily check) — fail-closed by the same rule as the handlers; the operator remedy is the runbook's. (4) The boot mint of a first-boot CA (`LoadOrInitCA` with no bundle) is outside the writer protocol by proof: a freshly minted key cannot equal any intent's candidate, so it can neither credit nor discredit one. (5) Blocker-3 refusal durability is proven with the durable-write success-observer seam and the ledger-as-directory fault (unit RED), not against the real binary (no seam to break the ledger between the intent and the abort at runtime); the real-binary journeys cover attribution, boot order, deferral and provenance. (6) `operation_unsettled` is answered from the handler's own settlement attempt; the operator-facing remedy is the lookup. **FE-6B.1 remains unstarted. STOP for external freeze review of the corrected candidate.**

> **6B0D — FE-6B.0 CORRECTION ROUND 3 (external freeze review of `f2e59ed9` REJECTED on three source-level durability/recovery blockers; one append-only correction round; FE-6A still frozen at `8b356c4c`; no React page, FE-6B.1 unstarted).** Chain: `f2e59ed9 (rejected candidate, untouched) → 09c12070 (RED round-3 matrix, test-only) → b1e4c4de (product correction + contract artifacts + runbook + legacy console copy + GREEN proofs) → bc2da436 (settlement idempotence fix found by the round-3 real-binary journey) → no merge (origin/main unchanged) (this record is a docs-only commit on top)`. The rejection, restated in the repository's terms: **B1** `fileutil.AtomicWrite` reported a post-rename directory-sync failure as `ErrReplacedNotSynced` but `ca.PersistCandidate` promised "any error means the bundle did not land", `persistCACandidate` aborted every error durably and answered terminal `persist_failed` while the bundle on disk already carried the candidate (a definitive non-commit verdict against the evidence), and `uiCertPersistRefusal` did the same for a UI pair whose key rename had landed; **B2** `persistCustomUITLS` wrote the certificate and the key as two separate live-path writes, so a process death between them left a NEW certificate beside the OLD key (the working pair destroyed) and `uiCertOperationVerdict` credited a replace on the certificate digest alone; an interrupted first installation left a certificate-only remnant at the live path, and an interrupted deletion (key removed, certificate left) was credited as a complete deletion because `customUITLSFilesPresent` read the remnant as absence; **B3** `bundleFingerprintHex` collapsed an unreadable or undecodable bundle into `""` so `caOperationVerdict` aborted a committed-but-unrecorded intent permanently when the bundle was merely unreadable at the next boot, `uiCertRevisionToken` collapsed stat/read failures into `uic1:none` (unavailable evidence proved a pending delete), and `caOperationResult` built a recovered commit's `ca` from the LIVE manager even when the bundle on disk had decided it.

> **6B0D-A. RED before (on exactly `f2e59ed9`, commit `09c12070`; `fe6b0d_red_test.go`, 12 functions / 11 rows + controls, every fault seam-, file- or passphrase-controlled — the `fileutil` synchronisation hook on the two `AtomicWrite` steps (declared in the RED file, wired by the correction), the UI key-write seam returning `ErrReplacedNotSynced` after a real write or raising a panic that stands in for a process death at that instant, a non-empty directory at a bundle/certificate path, a bundle re-sealed under one passphrase and read under another, pending intents written into the ledger file, restarts by re-loading the CA from disk / re-running the boot pair resolution and re-opening the ledger — no sleeps).** Every row FAILS on the baseline 3/3 with the concrete defect as the message: **D01** the bundle's post-rename seam is never reached ("correction absent"); **D02** the certificate write's seam likewise; **D03** a landed key write answered "the current UI certificate is unchanged" (terminal `persist_failed`) with the NEW pair on disk; **D04** the restart after a crash between the two writes found a MISMATCHED pair (new certificate, old key); **D05** an interrupted first installation left a certificate remnant at the live path; **D06** an incomplete cleanup was recorded as a complete deletion (no `cleanup` fact, remnant left); **D06b** a completed deletion did not state its cleanup; **D07a/D07b** an undecodable / unreadable bundle was converted into a terminal `aborted`; **D08** unavailable UI evidence credited a pending delete (`lookup_committed`, `uic1:none`); **D09** the recovered result named the live CA B instead of the evidence A that decided the commit. **D10** controls PASS on the baseline and after the correction: a pre-replacement key failure is still a terminal `persist_failed` + `aborted` with the previous pair intact and unaudited; a positively absent bundle with live ≠ candidate still aborts.

> **6B0D-B. PRODUCT CORRECTION (commit `b1e4c4de`, plus `bc2da436`).** *B1 — post-rename durability.* `fileutil.AtomicWrite` consults the package's synchronisation hook at BOTH steps (`atomic-file` = the temp fsync before the rename, path = the temp file; `atomic-dir` = the parent-directory fsync after it, path = the TARGET, a failure ⇒ `ErrReplacedNotSynced`) and reports both through the sync observer; `fileutil.SyncParentDir(path)` re-synchronises a parent directory so a caller can RESOLVE the doubt later (`internal/fileutil/atomicwrite_sync_test.go`). `ca.PersistCandidate`'s contract now states that an `ErrReplacedNotSynced` error means the bundle DID land. `persistCACandidate` answers a tri-state (`caPersistFailed` / `caPersistDurable` / `caPersistUnproven`); on unproven the rotate/import handlers INSTALL the candidate (the bundle on disk IS the candidate — a split live/disk state is never published), keep the intent PENDING (no terminal record of any kind) and answer the NON-terminal `500 outcome_unknown` with `current.detail: durability_unproven`, `current.state: pending` (`certDurabilityUnproven`); no inline retry — the doubt is resolved by the next settlement, which for every CA and UI verdict re-synchronises the object's directory BEFORE crediting (a failed resync ⇒ the recoverable `<why>_durability_unproven`, which blocks writers until it clears — G01). *B2 — the UI pair.* `ui_tls_custom.go` is a STAGED, MARKER-COMMITTED transition: stage `ui_tls_cert.pem.next` (real `AtomicWrite`), stage `ui_tls_key.pem.next` (the `uiTLSAtomicWrite` seam), write `ui_tls_transition.json` = the COMMIT POINT (kind, operationId, certificate digest — never a key digest), rename key, rename cert, remove the marker, sync the directory; delete = marker → remove key → remove cert → remove marker → sync. `recoverUITLSTransition` runs at boot (`resolveUITLSCertKey`, before the pair is examined, pre-logger `fmt.Printf` lines) and inside every UI settlement: a marker is a committed transition and is COMPLETED (idempotent — a step already done is skipped); staged files without a marker never committed and are ABANDONED with the live pair untouched; an unreadable marker is left in place (unavailable evidence). So the live pair is only ever the previous COMPLETE pair or the new COMPLETE pair. Error vocabulary: a failure before the commit point is an ordinary error (nothing at the live paths changed ⇒ terminal `persist_failed`); `errUITLSTransitionIncomplete` when a commit-phase rename/removal failed (marker kept; non-terminal `transition_incomplete`, intent pending, completed by the next settlement); `errUITLSDurabilityUnproven` when a post-rename sync failed on any step (the transition is still completed; non-terminal `durability_unproven`). The old compensating certificate rollback and `errUITLSRollbackFailed` are gone by construction (the live certificate is never written before the key is staged). `uiCertOperationVerdict` credits a replace only for a COMPLETE, VALID (`tls.LoadX509KeyPair`) pair whose certificate digest is the candidate — the key is proven by the pair parsing, never by a stored key digest (write-only key preserved); a delete credited from an incomplete cleanup (one remnant file) finishes the cleanup first and records `result.cleanup: completed_at_settlement`, a live delete answers `cleanup: complete` (`uiCertOperationResult(op, cleanup)`). *B3 — evidence classes.* `caBundleEvidenceNow` classifies the configured bundle `absent` (no path / not-exist) / `readable` (digest + a probe manager) / `unavailable` (stat or read failure, a directory at the path, `ErrBundleDecrypt` under the boot passphrase) / `invalid` (`ErrBundleMalformed`); `uiPairEvidenceNow` classifies the pair `absent` / `complete` (+ valid) / `incomplete` / `unavailable` (unavailability decided FIRST: a stat error other than not-exist, a directory at either path, an unreadable certificate). `uiCertRevisionToken` = `uic1:none` (positive absence) | `uic1:<digest>` | `uic1:incomplete` | `uic1:unavailable` (never identities; `uiCert.pairState` on the read model; a mutation echoing `uic1:unavailable` is `503 evidence_unavailable`, nothing written, no intent). Settlement (`settleCertOperation` over a `certVerdict`) records the RECOVERABLE `outcome_unknown` codes `<why>_evidence_unavailable`, `<why>_evidence_invalid`, `<why>_durability_unproven`, `<why>_cleanup_incomplete` (plus the unchanged `<why>_unproven`); `certOperation.recoverable()` makes every later settlement — lookup, boot, a later writer, and now a RECOVERED CA LOAD — re-decide them, and `blocksWriters()` (pending, evidence_unavailable, durability_unproven, cleanup_incomplete — NOT evidence_invalid, which only a writer can repair, and NOT plain unproven) holds every writer of the target (`503 operation_unsettled`) so the evidence is never destroyed before it decides; only a positively absent bundle (or a readable one carrying something else) aborts. A re-settlement with the SAME non-terminal verdict is not rewritten (`bc2da436`: the check compares the verdict suffix, so the first settlement's `reconciled_…` code stands — found by journey J3, where a lookup after a boot rewrote the record on every visit). `tryInspectionCARecovery`'s LOAD branch (`LoadCA` on the configured bundle) loads FIRST and settles `root_ca` from the recovered bundle after (`why = reconciled`), because settling first would defer the recovery forever behind the very intent the load makes decidable; its writing branches (`InitCA`, `SaveCA`) still settle first (G02). A commit decided from the bundle on disk builds `result.ca` from the probe that read that bundle and `committedRevision` from its digest (`caOperationResult(op, info)`), never from the live manager (D09). *Contract artifacts.* OpenAPI: `CertRefusal` (evidence_unavailable 503; the `durability_unproven` / `transition_incomplete` non-terminal shapes), `CertRefusalPersistFailed`, `CARotateResult.persisted`, `UICertRead` (`pairState` required + the four token forms), `UICertDeleteResult.cleanup` (required), `CertOperation` description + `code` + `result`; bundle regenerated (`make api-bundle api-lint api-route-coverage api-contract-test api-bundle-check` green — no route added, `uiRoutes` stays 251), `frontend/src/api/types.gen.ts` regenerated (typecheck clean), `frontend/dist` unchanged; legacy console `certRefusalText` gains `evidence_unavailable` and the two details; runbook `certificates-and-ca-lifecycle.md` §1 (tokens/pairState), §2 (post-rename durability, unavailable evidence, blocking), §4 (the staged transition, cleanup facts, remnants), §8 (blocking states, the recovery loop's load branch, evidence-named results); CLAUDE.md entry extended. *Existing tests.* `ui_tls_custom_partial_write_test.go` rewritten to the staged invariants (pre-commit failure leaves the previous pair intact and no remnant; a landed key write completes the pair and reports unproven; an incomplete commit is recovered from the marker; unmarked staging abandoned / marked staging completed); round-2 rows R07 (`ui_replace_persist_failure`, `ui_delete_persist_failure`) and R08 (`across_restart_reconciliation`) keep EVERY assertion — only their pre-commit fault moved to the new persistence boundary (the key staging seam `fe6b0cFailKeyStaging` / a directory at the marker path), because a directory at a live path is now honestly `uic1:unavailable` and refused before any intent (409 stale / 503 evidence_unavailable), which is the B3 behaviour, not a weakening. GREEN proofs `fe6b0d_green_test.go`: **G01** a settlement whose directory resync fails records `lookup_durability_unproven`, holds a writer (503), and commits once with its audit when the fault clears; **G02** the recovery loop's load branch settles `reconciled_evidence_unavailable` to `committed` with the candidate's revision and one audit, and clears the load failure; **G03** a malformed bundle is `lookup_evidence_invalid`, a repairing import is admitted, the intent keeps its code across the writer (not rewritten) and is decided `aborted` (`lookup_absent`) against the repaired bundle; **G04** the read model / token states `complete` → `uic1:incomplete` → `uic1:unavailable` → `uic1:none`, and a replace against unavailable evidence is refused with no intent.

> **6B0D-C. Qualification (final code head `bc2da436`; chain 11 ran on `bc2da436`; `origin/main` re-fetched at exit = `e21e6731`, unchanged since the round-2 exit-gate merge `541b3fb6` and an ancestor of this head — no merge, no requalification of a merge; this record is a docs-only commit on top).** RED→GREEN: all 11 round-3 rows PASS on `b1e4c4de`/`bc2da436` and D10 still passes; the round-1 (`fe6b0_red_test.go`, 18 rows) and round-2 (`fe6b0c_red_test.go`, 10 rows) matrices pass unchanged in assertion. Static: `gofmt` clean, `go vet ./...` clean, diff-scoped `golangci-lint --new-from-rev 98d4a6c8 ./...` 0 issues (the correction's first pass had 3 — a cyclop split of `uiPairEvidenceNow`, two test file modes — resolved before the product commit; the RED file's first pass had 1 gocognit, split D07 into D07a/D07b before the RED commit). Race: focused CA / UI-certificate / OCSP / ledger / fileutil / recovery families + all three FE-6B.0 matrices ×3 under `-race` (root + `internal/ca` + `internal/fileutil`): RC=0 (355 s; root 244 s, `internal/ca` 31 s, `internal/fileutil` 1 s); root `go test -race -count=1 .` RC=0 (2780 s, 0 `--- FAIL`); non-root `./internal/... ./cmd/...` RC=0 (108 packages ok, 0 failures). Contract gates: `make api-bundle api-lint api-route-coverage api-contract-test api-bundle-check` green on the product commit; `make api-bundle-check` + the API gates on the final head RC=0. Builds: deterministic build twice → byte-identical (`ad3763f6aed43f38…`; `CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags=-s -w`); arm64 RC=0; `go vet ./...` RC=0. Frontend: `scripts/verify.sh` ALL GATES PASSED (vitest 963/963), RC=0; `verify-determinism.sh` RC=0 (dist byte-stable, unchanged by this round — only `types.gen.ts` changed). Real-binary journeys on the deterministic binary (hermetic data dirs, no root): NEW `integration9.sh` **27/27** — J1 a replace interrupted AFTER its commit point (staged files + marker + pending intent) is COMPLETED at boot (`completed an interrupted custom UI certificate replace at boot`): the new pair is live and active, the intent `committed` (`reconciled_committed`) with the action-bound result and revision, exactly one audit each for the seed and X; staged certificate without a marker + a pending intent → boot ABANDONS it (`abandoned an uncommitted custom UI certificate replacement`), the previous pair untouched and active, the intent `aborted` (`reconciled_absent`), no audit, no remnant; J2 an interrupted delete (key removed, certificate left, pending delete intent) → boot does not load the remnant (not active, not corrupt), the lookup credits `committed` with `result.cleanup: completed_at_settlement` and `committedRevision: uic1:none`, the remnant removed, `pairState: absent`, one audit; a live delete answers `cleanup: complete`; J3 a rotation R committed → restart with R's record reverted to pending under a passphrase the bundle was not sealed under → `loadFailed`, R = `outcome_unknown` / `reconciled_evidence_unavailable`, a repairing import held `503 operation_unsettled` (`target_unsettled`), no second audit → restart under the right passphrase → R `committed` (`reconciled_committed`) naming its candidate's fingerprint and `car1:` revision, the live CA is R's candidate, one audit; J4 a malformed bundle at boot (`loadFailureClass: bundle_malformed`) + a pending import I → `reconciled_evidence_invalid`, a repairing import admitted (`committed`), I then `aborted` (`lookup_absent`) against the repaired bundle, the load failure cleared; J5 leak sweep clean (PEM material, passphrase, data-dir path — the sweep matches `BEGIN … PRIVATE KEY` because the malformed-bundle boot warning legitimately quotes the class text "missing CERTIFICATE or EC PRIVATE KEY block"), no transition remnants. Regression journeys on the same binary: `integration7.sh` **60/60**, `integration8.sh` **28/28**, `integration3/4/5/6` **38/38 / 53/53 / 51/51 / 47/47**. Browser (legacy console copy changed): full Playwright ×2 — run 1 155 passed / 3 skipped (pre-existing env-gated), 5.6 min, RC=0; run 2 155 passed / 3 skipped, 5.1 min, RC=0. `gitleaks detect --no-git` (whole tree) RC=0, no leaks. `/data` snapshot (51 files): 51 OK, 0 other after the whole chain; leaked `culvert-det11a` processes after the chain: 0; tree clean (0 dirty) after the frontend gates and after the whole chain. Post-rename sync faults are proven in-process (D01–D03, G01, the fileutil tests) and not against the real binary — no seam exists to fail a directory fsync at runtime; the journeys cover the interrupted transitions, the interrupted cleanup, unavailable and invalid evidence, and the restart proofs the review asked for. Secrets/identifiers: no model identifier in any changed file or commit body (trailers only); no key material in the diff.

> **6B0D-D. Exit gate.** `origin/main` re-fetched at exit = `e21e6731`, unchanged since the round-2 exit-gate merge `541b3fb6` (PR #1422) and an ancestor of `bc2da436` — no merge, no requalification beyond chain 11. Branch head `bc2da436 (code head; this record is a docs-only commit appended on top of it)` = `origin/claude/culvert-frontend-fe6-hyagdj` (remote equality verified after the push), working tree clean; `f2e59ed9` untouched and an ancestor; FE-6A history untouched; no amend, squash, rebase or rewrite; no pull request.

> **6B0D-E. Residuals (recorded, not fixed).** (1) The transition marker and the staged files live beside the pair under `<dataDir>` and are node-local like the pair itself: neither is archived by backup (the pair was never archived — 6B0-D), so a restore carries no half-finished transition. (2) A certificate-only or key-only remnant WITHOUT a delete intent (an old-binary crash, an out-of-band removal) is reported as `pairState: incomplete` / `uic1:incomplete` and left in place — the operator deletes or replaces it with that fence; the node never guesses which half is the wanted one. (3) A bundle that is readable but INVALID does not block writers by design (only a writer can repair it) — a committed-but-unrecorded intent whose bundle was later corrupted out of band is therefore decided `aborted` once a repairing writer's bundle is read; the runbook §2 states it. (4) `blocksWriters` also holds the AUTOMATIC rotation round and the recovery loop's writing branches while an intent's evidence is unavailable or its durability unproven (one log line per check); the recovery loop's LOAD branch is exempt by design. (5) `certRefusalMemo` remains process-local (6B0C-E.2). (6) The pre-logger boot lines of `recoverUITLSTransition` use `fmt.Printf` (the `resolveUITLSCertKey` convention) and carry the bounded persist-failure class only. **FE-6B.1 remains unstarted. STOP for external review of the corrected candidate.**

> **6B0E — FE-6B.0 CORRECTION ROUND 4 (external review of the round-3 record head `d00ffa6a` / code head `bc2da436` REJECTED on three source-level attribution / persistence-ordering / evidence blockers; one append-only correction round; FE-6A still frozen at `8b356c4c`; no React page, FE-6B.1 unstarted).** Chain: `d00ffa6a (rejected record head, untouched; code head bc2da436) → 01e76a28 (RED round-4 matrix, test-only) → d432a366 (product correction + contract artifacts + runbook + G03 correction) → ab6f0f14 (RED proof E11, test-only — found by the round-4 real-binary journey) → efc3ee17 (the auto-rotation round is a writer only when a rotation is due) → no merge (origin/main unchanged) (this record is a docs-only commit on top)`. The rejection, restated in the repository's terms: **B1** an intent whose bundle evidence is INVALID was recoverable but not blocking, so a repairing import Y could write candidate A while intent X (also targeting A) was unresolved, and X's next lookup — comparing CONTENT — credited X as committed and audited it although Y produced the evidence (G03 had tested only a different candidate B, and inferred X's non-commit from Y's bundle, which is the same defect in the other direction); **B2** `completeUITLSTransition` removed the transition marker BEFORE the completed pair (or deletion) was durably synchronised — one sync after the marker removal — so a crash in that window could lose the pair while the marker's removal survived, and recovery would then abandon what it should have finished; **B3** `uiPairEvidenceNow` only STAT-ed the private key and `customUITLSPairValid` collapsed every error to `false`, so a key that was present but UNREADABLE was classified `complete` / invalid and settled as the non-recoverable `lookup_unproven` — temporary key unavailability neither stayed recoverable nor protected the evidence from writers.

> **6B0E-A. RED before (on exactly `d00ffa6a`, commit `01e76a28`; `fe6b0e_red_test.go`, 12 functions / 10 rows + controls; the round-4 journey added E11 in `ab6f0f14` on `d432a366`).** Every fault is file-, seam- or ledger-controlled and every row fails on the product VERDICT or the PERSISTENCE ORDERING, never because a seam is absent: ordering is observed through the existing `fileutil` `dir` synchronisation hook, which samples the on-disk state (marker present? new pair live? pair absent?) at the instant a directory is about to be synchronised; an unreadable key is a unix socket standing at the key path with the key's bytes moved aside (a read failure on a present, non-directory object — deterministic under any uid, unlike a mode bit for root); restarts re-open the ledger and re-run the boot pair resolution; no sleeps. Every row FAILS on the baseline 3/3 with the concrete defect as the message: **E01** a same-candidate repair — "the unresolved intent was CREDITED with the repairing writer's content" (`committed`, audited); **E02** a different-candidate repair — "the unresolved intent was ABORTED from the repairing writer's content"; **E03** with the ledger unwritable the repair answered terminal `500 persist_failed` instead of the refusal `503 operation_unsettled` (a superseding decision that cannot be recorded must refuse the writer with nothing written); **E04/E05** one directory sync observed per transition, with the marker already gone in the only sample (`[{marker:false pairNew:true}]` / `[{marker:false absent:true}]`); **E06** "the marker was removed although the completed pair's synchronisation FAILED"; **E07** a post-rename sync failure answered `200` (terminal success) instead of the non-terminal `500 outcome_unknown`; **E08** the delete's marker removed although the removal's synchronisation failed; **E09** "a present but unreadable key was classified `complete` (valid=false) — a read failure collapsed into an invalid pair". **E10a/b/c** controls PASS on the baseline and after the correction: a readable malformed key and a readable mismatched key are `complete` / invalid (`lookup_unproven`, a writer admitted); recovery from every filesystem state permitted before each barrier (key renamed + certificate still staged + marker; both renamed + marker; delete with key removed + certificate present + marker; delete with both removed + marker) completes idempotently. **E11a** (on `d432a366`, commit `ab6f0f14`): a rotation round that does NOT rotate superseded the unresolved intent — "a non-writing rotation round changed the unresolved intent: … `Code:writer_evidence_superseded` … `SupersededBy:auto_rotation`"; **E11b** control PASSES: a DUE round supersedes (naming `auto_rotation`) before it writes and replaces the invalid bundle.

> **6B0E-B. PRODUCT CORRECTION (commit `d432a366`, plus `efc3ee17`).** *B1 — a repairing writer never decides historical authorship.* Invalid evidence stays recoverable and NON-blocking (only a writer can repair it), but the writer settlement now records the decision FIRST: `settleCertTarget(s, target, why, writerID)` settles every recoverable intent on the target and, for a writer, durably SUPERSEDES every intent that is still recoverable after that settlement — the terminal `outcome_unknown` / `writer_evidence_superseded` record (`certOperationStore.Supersede`: `SupersededBy` = the handler's operationId, `auto_rotation` or `ca_recovery`; `CommittedRevision` and `Result` cleared; `supersededBy` on the lookup read model) — BEFORE the writer writes. A superseded record is terminal by construction (`recoverable()` is false), so no later lookup, restart, repeated settlement or writer re-decides it from the bundle the writer produced: the same candidate imported by the repair is NOT the earlier intent's commit (E01) and a different one is NOT its refusal (E02); a superseding record that cannot be persisted refuses the writer `503 operation_unsettled` with nothing written, and a later repair is admitted and supersedes it (E03). The admin handlers pass their operationId through `certSettleTargetOrRefuse(w, s, target, opID)`; the auto-rotation round passes `certWriterAutoRotation`; the CA recovery attempt's WRITING branches pass `certWriterCARecovery` and its LOAD branch keeps `why = reconciled` (it replaces no evidence). **And a writer that writes nothing takes no writer posture** (`efc3ee17`, E11): `runInspectionCARotationRound` consults the new single predicate `ca.Manager.RotationDue()` (also the predicate `RotateIfNeeded` itself uses; a due CA stays due, so the decision cannot be invalidated under the round's locks) and a not-due round leaves the operation ledger untouched, running only the memory-only secondary-CA cleanup — the journey found that every boot with a load failure had otherwise superseded the operator's pending repair by `auto_rotation` before the repair could happen. A due round settles, supersedes and rotates exactly as before (E11b; R05/R06 unchanged). *B2 — the marker outlives its transition's durability.* `completeUITLSTransition` orders: renames (replace) or removals (delete) → BARRIER 1 (`fileutil.SyncParentDir` — the completed pair or the deletion is durable) → marker removal → BARRIER 2 (`SyncParentDir` — the removal is durable) and returns `(acted, durable, err)`: a failure at either barrier keeps the marker (or leaves its removal unproven) and is reported as `errUITLSDurabilityUnproven` (the handlers answer the non-terminal `500 outcome_unknown` / `durability_unproven`, intent pending), a rename/removal that cannot be done keeps the marker with `errUITLSTransitionIncomplete`; `recoverUITLSTransition` (boot + every settlement) is idempotent over every state a crash can leave before each barrier and over a marker that REAPPEARS after a crash (a step already done is skipped; the marker is consumed again; nothing is re-decided) — E04–E08, E10c, journey J3. `uiTLSRecovery.Acted` (a rename/removal actually changed the live paths) replaces the former `Durable`; `uiDeleteVerdict` records `cleanup: completed_at_settlement` only when the recovery ACTED on a delete, so a delete whose files were already gone answers `cleanup: complete` (E08, J3b). `removeIfExists` / `renameIfExists` return `(did, err)`. *B3 — an unreadable key is unavailable evidence.* `uiPairEvidenceNow` reads BOTH files and validates the pair from their bytes (`tls.X509KeyPair`); a key (or certificate) that cannot be read classifies the pair `unavailable` (`uic1:unavailable`, `pairState: unavailable`), so the intent settles as the recoverable `<why>_evidence_unavailable`, every writer of the target is held (`503 operation_unsettled` / `503 evidence_unavailable` for a mutation echoing the token), a restart decides nothing and loads nothing (not active, not corrupt), and the intent commits exactly once with one keyed audit when access is restored with the bytes unchanged (E09, J4); a readable malformed or mismatched key stays `complete` / invalid (E10a/b, J4 controls). *Contract artifacts.* OpenAPI `CertOperation`: description states the superseded rule, `code` gains `writer_evidence_superseded`, new `supersededBy` property; `UICertRead` states that an unreadable key is unavailable evidence; bundle regenerated (`make api-bundle api-lint api-route-coverage api-contract-test api-bundle-check` green — no route added, `uiRoutes` stays 251), `frontend/src/api/types.gen.ts` regenerated (typecheck clean), `frontend/dist` unchanged, legacy console unchanged; runbook `certificates-and-ca-lifecycle.md` §1 (unreadable key ⇒ `uic1:unavailable`), §2 (the superseded rule), §4 (two barriers), §8 (unreadable key, repair/superseded bullet, the not-due rotation round); CLAUDE.md ROUND 4 clause. *Changed assertions, stated explicitly.* (1) `fe6b0d_green_test.go` G03: the round-3 expectation "aborted `lookup_absent` against B's bundle" inferred a non-commit from the repairing writer's content — the B1 defect in its other direction — and now expects `outcome_unknown` / `writer_evidence_superseded` with `supersededBy == Y`, stable across lookups (the comment records why the round-3 inference was wrong). (2) `fe6b0e_red_test.go` E06/E07: the keyed-audit check was made order-independent (`fe6b0eHas`) — the audit ring's order is not part of the proof; row expectations unchanged. (3) `integration9.sh` J4: the round-3 journey expectation "I aborted `lookup_absent` against the repaired bundle" is the same inference and now expects `outcome_unknown` / `writer_evidence_superseded` with `supersededBy == W`. (4) Two call sites in `uiDeleteVerdict` adjusted to `removeIfExists`'s `(did, err)` result. No other proof changed: the accepted post-rename (D01–D03, G01), competitor (R05/R06, G01), boot-ordering (R06/R06b) and action-bound-result (D09, G02, J1–J3) proofs run unchanged in assertion.

> **6B0E-C. Qualification (final code head `efc3ee17`; chain 12 ran on `efc3ee17`; `origin/main` re-fetched at exit = `e21e6731`, unchanged since the round-2 exit-gate merge `541b3fb6` and an ancestor of this head — no merge, no requalification of a merge; this record is a docs-only commit on top).** RED→GREEN: all 10 round-4 rows + E11 PASS on `efc3ee17` and the E10 controls still pass; the round-1 (`fe6b0_red_test.go`, 18 rows), round-2 (`fe6b0c_red_test.go`, 10 rows) and round-3 (`fe6b0d_red_test.go`, 11 rows; `fe6b0d_green_test.go` G01–G04 with the G03 change above) matrices pass. Static: `gofmt` clean, `go vet ./...` clean, diff-scoped `golangci-lint --new-from-rev 98d4a6c8 ./...` 0 issues on every commit (the RED file's first pass had 3 — a gocognit split of E10 into E10a/b/c, a gocritic unnamed-result on `fe6b0eImport`, a noctx `net.Listen` → `ListenConfig.Listen` — resolved before the RED commit). Race: focused CA / UI-certificate / OCSP / ledger / fileutil / recovery families + all FOUR FE-6B.0 matrices ×3 under `-race` (root + `internal/ca` + `internal/fileutil`): RC=0 (305 s; root 210 s, `internal/ca` 23 s, `internal/fileutil` 1 s); root `go test -race -count=1 .` RC=0 (2340 s, 0 `--- FAIL`); non-root `./internal/... ./cmd/...` RC=0 (108 packages ok, 0 failures). Contract gates: `make api-bundle api-lint api-route-coverage api-contract-test api-bundle-check` green on the product commit; `make api-bundle-check` + the API gates on the final head RC=0. Builds: deterministic build twice → byte-identical (`9a684238…`; `CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags=-s -w`); arm64 RC=0; `go vet ./...` RC=0. Frontend: `scripts/verify.sh` ALL GATES PASSED (vitest 963/963), RC=0; `verify-determinism.sh` RC=0 (dist byte-stable, unchanged by this round — only `types.gen.ts` changed); tree clean after the frontend gates. Real-binary journeys on the deterministic binary (hermetic data dirs): NEW `integration10.sh` **46/46** — the binary runs as an UNPRIVILEGED user (`setpriv` → `nobody`, verified from `/proc/<pid>`), because a key made unreadable by MODE alone (bytes untouched) is not unreadable to root: J1 a malformed bundle at boot (`bundle_malformed`) + a pending import I of candidate A → `reconciled_evidence_invalid`; a repairing import W of the SAME candidate A is admitted (`committed`) and installs A; I is `outcome_unknown` / `writer_evidence_superseded` with `supersededBy == W`, no `committedRevision`, no `result`; a repeated lookup, a restart and W's own lookup change nothing; exactly one `ca.import` audit (W's); J2 a different-candidate repair W2 → I2 superseded by W2, never `aborted`, stable across restart, only the two writers audited; J3 a replace whose pair is LIVE but whose marker survived (a crash after barrier 1) is completed at boot (`completed an interrupted custom UI certificate replace at boot`): the pair unchanged and active, the marker consumed, the intent `committed` once with the action-bound result, one audit; the marker written AGAIN (a crash after barrier 2) is consumed again with no second audit and nothing re-decided; a delete with both files gone + marker → completed at boot, `pairState: absent`, `committed` with `cleanup: complete`, one audit; no remnants; J4 a completed replace R whose terminal record AND keyed audit never persisted (ledger reverted to pending, the audit line removed) → the key chmod 000 (sha256 unchanged) → `pairState: unavailable`, `uic1:unavailable`, not active, not corrupt; R `outcome_unknown` / `…_evidence_unavailable` at lookup; a writer held (`503 evidence_unavailable`); no audit; a restart with the key still unreadable decides nothing and loads no pair; access restored (same bytes) → R `committed` exactly once naming `uic1:<P2>`, the pair active, exactly one keyed audit, stable across a further restart; controls: a readable malformed key and a readable mismatched key are `complete` / corrupt and a writer repairs them; J5 leak sweep clean, no transition remnants. `integration9.sh` **27/27** with the J4 change above (J1–J3, J5 unchanged). Regression journeys on the same binary: `integration7.sh` **60/60**, `integration8.sh` **28/28**, `integration3/4/5/6` **38/38 / 53/53 / 51/51 / 47/47**. Browser (legacy console unchanged; run for parity with chain 11): full Playwright ×2 — run 1 155 passed / 3 skipped (pre-existing env-gated), 4.1 min, RC=0; run 2 155 passed / 3 skipped, 3.7 min, RC=0. `gitleaks detect --no-git` (whole tree) RC=0, no leaks. `/data` snapshot (51 files): 51 OK, 0 other after the whole chain; leaked `culvert-det12a` processes after the chain: 0; tree clean (0 dirty) after the frontend gates and after the whole chain. Post-rename and barrier faults are proven in-process (E04–E08, D01–D03, G01, the fileutil tests) — no seam exists to fail a directory fsync at runtime; the journeys cover the same-/different-candidate repairs across restart, every barrier state a crash can leave and a reappeared marker, the unreadable key with exactly-once commit and audit, and the controls. Secrets/identifiers: no model identifier in any changed file or commit body (trailers only); no key material in the diff.

> **6B0E-D. Exit gate.** `origin/main` re-fetched at exit = `e21e6731`, unchanged since the round-2 exit-gate merge `541b3fb6` (PR #1422) and an ancestor of `efc3ee17` — no merge, no requalification beyond chain 12. Branch head `efc3ee17 (code head; this record is a docs-only commit appended on top of it)` = `origin/claude/culvert-frontend-fe6-hyagdj` (remote equality verified after the push), working tree clean; `d00ffa6a` untouched and an ancestor; FE-6A history untouched; no amend, squash, rebase or rewrite; no pull request.

> **6B0E-E. Residuals (recorded, not fixed).** (1) A superseded intent is terminal-unknown BY DESIGN: the node never learns whether it had committed before its evidence became invalid, and it never guesses — the operator re-issues the operation with a new operationId; the runbook §2 and §8 state it. (2) A superseding decision is recorded even when the repairing writer then FAILS before writing (a candidate refused at validation is decided before the intent and never reaches the settlement; a persist failure after it does) — the intent stays superseded rather than being restored to recoverable, because restoring it would make the ledger's terminal record conditional on a later event. (3) The auto-rotation round's writer posture is keyed on `RotationDue()`; the CA recovery loop's writing branches (`InitCA` with no bundle on disk, `SaveCA` for a loaded-but-unpersisted CA) always write when reached and keep the writer posture unconditionally. (4) Barrier 2 failing leaves a marker whose removal is unproven; a reappeared marker is consumed by the next recovery without effect — the cost is one extra idempotent pass, never a wrong verdict. (5) `uiPairEvidenceNow` now READS the key on every read-model and settlement path (one extra file read per `GET /api/certificates` / lookup); the bytes never leave the process (the read model still carries only the certificate digest). (6) A key unreadable to the PROCESS but readable to the operator (mode, ownership, an ACL) is the case J4 proves; a directory or socket at the path is the in-process shape (E09) — both are `unavailable`, never `invalid`. (7) 6B0D-E.1/.2/.5/.6 stand. **FE-6B.1 remains unstarted. STOP for external review of the corrected candidate.**

> **6B1 — FE-6B.1 Certificates & CA READ surfaces (FE-V28 Certificates / FE-V29 CA Management; 2026-09-19; entry baseline = the frozen FE-6B.0 record head `c540b176` / code head `efc3ee17`; RED commit `c13c4326`; product commit `70cc4b32`; record commit = this one; `origin/main` at entry = `e21e6731`; at exit it had moved to `91c926e6` and was integrated by the no-ff merge `52ec68f1` — see 6B1-E). READ surfaces only: no upload, import, rotate, challenge, delete, OCSP toggle, repair, retry or re-send control exists and no disabled placeholder stands in for one (all FE-6B.2). Nothing certificate-related is persisted in the browser.**

> **6B1-A. Entry audit and recorded discrepancies.** Read before implementing: the approved decomposition (`docs/design/FRONTEND-MIGRATION-PLAN.md` FE-6B), the frozen FE-6B.0 OpenAPI schemas (`CertificateInventory`, `UICertRead`, `CAStatus`, `OCSPStatus`, `CertOperation`, `CertRefusal`, `NetworkSettings`), the authoritative handlers (`ui_certificates.go`, `certificate_operations.go`, `ui_config.go` network settings, `ui_tls_custom.go`) and `uiRoutes` (`GET /api/certificates`, `/api/ca/status`, `/api/ocsp`, `/api/ca/key-provider`, `/api/ca-cert`, `/api/ca/download`, `/api/settings/network` = **viewer**; `GET /api/ca/operations/{id}` = **admin**). *Discrepancy 1 — IA placement and role.* `docs/design/INFORMATION-ARCHITECTURE.md` places "Certificates & CA" under **Platform** as an **admin** item (the M2 merge of `certificates` + `ca-mgmt`); the shipped AppShell carried a planned `Certificates` placeholder under **Security** at the **viewer** floor, and `uiRoutes` makes every read endpoint viewer. Decision, per the FE-6A.1 convention that v2 minimum roles come from `uiRoutes` evidence and never from legacy navigation: Security section, label "Certificates & CA", route `/security/certificates` at the viewer floor, the M2 merge realised as two tabs (Certificates = FE-V28, CA Management = FE-V29, `?tab=ca` deep link, an unknown tab value falls back), the admin-only operation lookup gated inside the page (rendered and issued for admins only). The IA's Platform/admin placement is recorded here for the IA owner; nothing was inferred from the legacy console's nav gate. *Discrepancy 2 — a backend truth gap, REPORTED not masked.* `uiCert.active` (inventory) and `ui_custom_cert_active` (network settings) both derive from `uiCustomTLSActive`, which `resolveUITLSCertKey` (`ui_tls_custom.go:491`) sets when the persisted pair RESOLVES at boot — before and regardless of whether the admin listener actually serves TLS with it (`-ui-no-tls`, or a plain-HTTP fallback after a TLS bind failure), so the "active on the running listener" fact can be asserted for a listener serving plain HTTP. The surface does not paper over it with copy: the inventory's claim is cross-checked against the listener's own facts (`ui_tls_fallback`, `ui_custom_cert_uploaded/active/corrupt`) and any disagreement — including "active" beside a fallback listener — renders as a **Contradictory listener facts** callout with NO activation claim (the raw `ui_tls_fallback_reason` line is not decoded). Proposed bounded correction for review before FE-6B.2: derive `active` from the CHAOS-57 bind loop's OBSERVED evidence (the listener bound and is serving TLS with that pair) and publish one server-owned bounded listener posture (`tls_custom` | `tls_self_signed` | `plain_http`) on the inventory, so the browser reads one fact instead of reconciling two.

> **6B1-B. RED before (commit `c13c4326` on exactly `c540b176`, executed on that baseline before any product change).** `frontend/src/test/fe6b1-red.test.ts` (A1–A10: decoder completeness and contradictions, bounded enums, secret-key refusal at any depth including inside `result`, the operation state union and the seven postures, UI-pair postures, listener contradictions, OCSP agreement, GET-only reads to the exact paths with a lowercased UUID, client-side UUID refusal with zero fetch, the PEM download's media type and JSON refusal, route intent viewer) and `frontend/src/test/fe6b1-red-page.test.tsx` (P1–P8: viewer healthy truth with the exact control allowlist, zero non-GET, zero lookups, zero storage; degraded bounded classes and the four distinct pair-evidence renderings; persisted vs active vs durability and the fallback contradiction; OCSP desired vs runtime and the unchecked enforcing path; admin lookup — one GET per explicit Look up across pending / committed / audit pending / aborted / recoverable unknown / terminal superseded unknown, refusals 404 / 503 / raw 500 and a malformed id; raw text and secret-bearing answers end bounded; refresh keeps truth and the snapshots are independent; tabs and deep links) both fail on the baseline at import resolution (`../api/certificates`, `../features/security/CertificatesPage` absent — 2 files failed, no tests ran). `frontend/e2e/fe6b1.spec.ts` (J1–J7 in six journeys; fixtures `CERT_URL`/`CERTDEG_URL`; harness `scripts/e2e-smoke.sh` gained a SEVENTH and EIGHTH appliance — CERT: a passphrase-sealed persisted inspection CA with the UI pair seeded once through the supported admin upload API; CERTDEG: a malformed `ca.bundle` (load failed, no Root CA), a corrupt persisted pair and a pre-seeded operation ledger carrying a terminal superseded record, a pending record, an aborted record and a committed record) ran on the baseline binary with all eight instances ready: **6 failed / 1 passed** — every journey failed on the unserved route (`element(s) not found` on the heading / nav link), the one pass being the shared auth-setup project. Evidence `$SP/fe6b1_red_baseline_vitest.txt`, `$SP/fe6b1_red_baseline_e2e.log`. *GREEN-run findings, recorded transparently.* One PRODUCT defect the journeys found that the vitest matrix could not (the memory router mounts the page directly): the sign-in gate renders AT the requested URL and navigated to the resolved PATHNAME only, so `/app/security/certificates?tab=ca` signed in onto the Certificates tab — closed by `routeIntent.intentSearch` (the browser's own `?…` search string is carried through sign-in ONLY when the role may visit the exact route it addressed, never onto the Overview fallback; `src/test/fe6b1-green-intent.test.ts`). Three test-only corrections, none weakening an accepted assertion: the operator journey asserted the URL alone before reloading (the gate renders at that URL, so the reload could interrupt the sign-in POST) and now waits for the authenticated page, the ordering the deep-link journey already had; the nav-reachability step omitted the ≤1100 px viewport the shared `openNavToFinalState` proof requires (the toggle exists only there); two whole-tree lint findings in the RED vitest files (an unbound accessor replaced by `Reflect.set` with the element as receiver; a banned `as` assertion replaced by the parameter type). One product wording correction the degraded journey forced: the record container rendered "committed" in three elements (badge, explanation, "Committed revision" label) and the strict-mode locator refused it — the explanation and label no longer repeat the badge's word.

> **6B1-C. Product (commit `70cc4b32`).** `frontend/src/api/certificates.ts` — the typed client over the frozen wire contract: bounded vocabularies (`CA_UNUSABLE_CLASSES`, `CA_FAULT_CLASSES`, `UI_PAIR_STATES`, `MTLS_REASONS`, `OCSP_SOURCES`, `LEDGER_DEGRADED_REASONS`, `AUDIT_SINKS`, `OCSP_COVERAGE_PATHS`, `CERT_OPERATION_{STATES,ACTIONS,TARGETS}` with action↔target parity, settlement `why`/suffix grammar, `CERT_SUPERSEDED_CODE`, `CERT_LOOKUP_REFUSAL_CODES`); token grammars (`car1:`/`uic1:`/`ocr1:`, 64-hex fingerprints, UUID); decoders that reject missing required facts, non-enum words and contradictory states (`present`⇔identity fields, `usable`⇔`unusableClass`, `loadFailed`⇔class, `persistDegraded`⇔class, `pairState`⇔`revision`⇔`present`, `dualCAActive`⇔`secondaryCA`, `enabled`==`runtime.enabled`, `ready`⇔`revision`, coverage⇔`uncheckedEnforcingPaths`) and REFUSE any secret-bearing key at any depth (`CERT_SECRET_KEYS`), never decode the raw `ui_tls_fallback_reason` or the ledger's `degradedDetail`; pure postures `operationPosture` (pending / committed / committed_audit_pending / aborted / unknown_recoverable / unknown_unproven / unknown_superseded{supersededBy}), `uiPairPosture` (active_persisted / persisted_restart_required / active_not_persisted / absent / incomplete / unavailable / corrupt), `ocspAgreement`, `listenerContradiction`; GET-only reads plus the viewer PEM download of the PUBLIC root (`application/x-pem-file` only, deterministic filename). `frontend/src/features/security/CertificatesPage.tsx` — four INDEPENDENT snapshots (inventory, CA status, OCSP status, listener facts) behind one manual Refresh (no polling): "Updated" is the earliest successful snapshot and never advances on a failed refresh, a failed refresh keeps the previous snapshot behind the explicit stale badge, a failed first read renders a bounded error class + HTTP status (never server text), and one failed read never blanks another (the Inspection CA card composes the inventory identity and the signer runtime as two reads with two errors). Certificates tab: the inspection CA (identity, revision, usability, key provider, bundle path, encrypted/not encrypted at rest, load-failed / persist-degraded classes, signer runtime), the UI listener certificate as persisted vs active vs durability — the four evidence classes are four distinct renderings ("positively absent" / "exactly one of the two files" / "cannot be examined or read … not absent" / "did not parse as a matching pair"), "Activation requires a restart" only for a complete persisted pair that is not active, "no longer persisted" for an active pair with no persisted files, the listener cross-check callout — the mTLS client-certificate posture, the OCSP desired (source, durable) vs runtime posture, the operation ledger (retained / unresolved / capacity / audit sink / degraded reason) and the backup scope facts; ADMIN only: the operation lookup card (label "Operation ID", one GET per explicit "Look up", client-side UUID validation first, the note that the appliance's lookup may settle a pending operation and complete its audit, never issued on mount, never polled) rendering every state as the server states it — Pending / Committed + Audited / Committed + **Audit pending** ("not a failed certificate mutation") / Aborted + code / Outcome unknown — recoverable + code ("re-decided") / Outcome unknown — unproven + code / **Outcome unknown — terminal** naming the superseding writer and never the words succeeded, failed, cancelled, canceled, retry or "safe to" / No retained operation record (404) / the bounded refusal code (`operation_ledger_degraded`, `forbidden`, `invalid_input`) / a bounded HTTP error. CA Management tab: the CA status (identity, revision, usability, expiry, key provider, persistence, auto-rotation, overlap days, leaf validity, cache size/max/TTL, inspect-blocked / sign-refused / inspection-bypassed counters, rotation persist failures + "Last rotation could not be persisted" class, load-failed class, the recovery campaign — attempts, given up / not given up, last class — and the dual-CA overlap with the previous root's facts) and the full OCSP status (desired vs runtime vs durable, fail-closed decisions, revoked, cached verdicts, last fail-closed, the handshake-path coverage table with an Enforcing column and the **Evidence limitation** callout for an unchecked enforcing path — CHAOS-65 OCSP-8). Every card is badged Node-local. Wiring: `router.tsx`, `AppShell.tsx` (the planned placeholder replaced by "Certificates & CA" → `/security/certificates`), `routeIntent.ts` `KNOWN_ROUTES`; `LoginPage.tsx` carries the deep link's search string via `intentSearch`; `frontend/dist` rebuilt deterministically.

> **6B1-D. Qualification (head `70cc4b32`; chain 13).** Chain 13 on `70cc4b32` — deterministic builds: two independent `CGO_ENABLED=0 -trimpath -buildvcs=false -ldflags='-s -w'` builds byte-identical (`b0255a94…`); arm64 cross-compile, `go vet ./...`, `make api-bundle-check`, `make api-lint api-route-coverage api-contract-test` all clean (no contract change in this slice); `frontend/scripts/verify.sh` ALL GATES PASSED (toolchain identity, clean `npm ci --ignore-scripts`, OpenAPI type generation + drift, eslint + prettier, strict tsc, vitest 93 files / 1005 tests, production build + committed-dist drift, bundle security scan, license + audit policy); `verify-determinism.sh` identical rebuild; tree clean after the frontend gates; real-binary integrations 3–10 all green (3/4/5/6 FE-6B.0-C, 7 = 60 expectations, 8 = 28, 9 = 27, 10 = 46 under an unprivileged uid); focused `-race -count=3` over the certificate/CA/UI-TLS/admin-settings/fileutil matrix plus the embedded-frontend and lockstep gates (268 s, all ok); root package `go test -race` 2159 s ok; `./internal/... ./cmd/...` `-race` 108 packages ok, 0 failures; two consecutive full Playwright runs through `scripts/e2e-smoke.sh` (eight appliances) **161 passed / 0 failed / 3 skipped** each (the three skips are the pre-existing evidence-capture specs gated on the qualification capture directory); gitleaks clean; the harness data check restored (51 of 51 pre-qualification `/data` digests OK); tree clean; no leaked appliance process. FE-6B.1 journeys inside those runs: `fe6b1.spec.ts` 6 journeys + auth-setup, green in both runs and in the three focused GREEN runs (`$SP/fe6b1_green_e2e{,2,3}.log`).

> **6B1-E. Exit gate.** `origin/main` re-fetched after chain 13 had MOVED: `e21e6731` → `91c926e6` (PR #1431, three commits, ONE file: `policy_srcprefix_benchgate_test.go`, a root-package `benchgate`-tagged test made structural — no product, contract or frontend file). Integrated through the evidence-preserving no-ff merge `52ec68f1` (conflict-free; `git merge-tree` preview clean). Requalification of the affected scope on the merged head: the deterministic build of `52ec68f1` is BYTE-IDENTICAL to chain 13's `70cc4b32` binaries (`b0255a94…` — a `_test.go` change cannot alter the binary, and the hash proves it), `go vet .` clean, and the merged gate (`TestBenchGate_PolicySourceCIDRAllocFree`, `TestBenchGate_PolicySourceCIDRUsesPrefix`) run under its build tag `-tags benchgate -race -count=3`: all pass. Every other chain-13 result carries over unchanged because no input of those gates changed. Every predecessor (FE-6A frozen `8b356c4c`, FE-6B.0 frozen `c540b176`, RED `c13c4326`, product `70cc4b32`) is preserved; append-only history, no amend, squash, rebase or PR.

> **6B1-F. Residuals (recorded, not fixed).** (1) The `active` truth gap of 6B1-A discrepancy 2 is a BACKEND correction awaiting review; until it lands the surface renders the contradiction, never the claim. (2) The IA's Platform/admin placement vs the shipped Security/viewer placement is an IA-owner decision; the shell follows `uiRoutes`. (3) The admin operation lookup is a settlement GET by contract (it may settle a pending intent and complete its owed audit) — it is issued only on an explicit admin action and this is stated on the card; no automatic polling drives recovery. (4) `writer_evidence_superseded` is terminal UNKNOWN by design, rendered as such, including when the superseding writer later failed — carried forward from FE-6B.0. (5) Revocation is not checked on inspected HTTPS origin handshakes (CHAOS-65 OCSP-8); the surface renders the server's coverage rows and evidence limitation, it does not compensate. (6) The CA status' `expiresIn` is the server's Go duration string rendered verbatim as a bounded fact. (7) FE-6B.2 (mutations: upload / import / replace / delete / rotate with the bound challenge / OCSP set / repair / re-send) is unstarted.

> **6B1C — FE-6B.1 external freeze review REJECTED → one append-only correction round (2026-09-19; reviewed candidate `935891f4`; RED commit `7fd3a056` on exactly that candidate; product commit `e6ce79bb`; record commit = this one; `origin/main` at entry and at exit = `91c926e6`, an ancestor of the head — no merge was needed). Three blockers: B1 listener activation claimed without authoritative evidence; B2 durability claims beyond the frozen contract; B3 the operation lookup accepting unbound or contradictory evidence. The reviewer AUTHORISED the bounded backend correction proposed in 6B1-A (publish server-owned listener posture and served identity from actual activation evidence, separately from the persisted-pair identity). The reviewed candidate, frozen FE-6B.0 and every predecessor are preserved; append-only history, no PR, FE-6B.2 unstarted.**

> **6B1C-A. RED before (commit `7fd3a056`, executed on exactly `935891f4` before any product change).** Go `fe6b1c_red_test.go` rows C01–C08 (C09 folded into C02) — the admin listener is REALLY bound in the test (`serveAdminUIWithRetry` against an occupied-then-released port) and the served certificate is read back through a REAL TLS handshake (`tls.Dial`, `ca.FingerprintOf(PeerCertificates[0])`): C01 pair A served → B persisted without restart ⇒ the inventory and the network settings must publish served A, persisted B, `active: false`; C02 a restart with the pair persisted ⇒ served == persisted, `active: true` (and the served identity is the TLS peer's); C03 plain-HTTP listener with a persisted pair ⇒ `plain_http`, no served identity, `active: false`; C04 an explicitly configured `-tls-cert/-tls-key` pair ⇒ `tls_configured`, the served identity is that pair's, never the persisted GUI pair; C05 no bind observed ⇒ `unknown`, no claim; C06 a delete while A is served ⇒ absent + `active: false` + served A; C07 the self-signed posture names the auto certificate's identity (== the TLS peer's), `active: false`; C08 the two reads carry the same object. **8/8 failed on the candidate** (no `listener` object, `active` from the boot flag). Vitest `fe6b1c-red.test.ts` (A1–A6: the inventory requires `listener`, bounded state/posture words, TLS posture ⇔ served identity, `servesPersistedPair`/`active` derived and contradictions refused; `activationPosture` over the eight postures; the network read requires `ui_listener` and the two reads compare as objects; a request for X answering Y is refused; a committed `result` must agree with its record and the frozen contract; a refusal needs the contracted status AND the JSON media type AND the bounded shape) and `fe6b1c-red-page.test.tsx` (Q1–Q11: A served / B persisted names the served identity and never "Active on the running listener"; served == persisted after the restart claims it (control); plain HTTP stated; an explicitly configured certificate named; unknown evidence ⇒ no claim of any kind; a failed cross-check does not withdraw an evidence-backed claim (control); deleted while served; a persist failure renders the bounded class only, never "not on disk / memory-only / re-rotates"; an audited commit qualified by the audit sink and "durable" never said without the file sink; no blanket export/rollback/sync claim; X/Y, a `not_found` on a 500 or on `text/plain` render unverified, never "No retained operation record"): **36 failed / 44 passed** on the candidate (the passes are the two controls, the FE-6B.1 A-rows and P-rows that do not touch the corrected facts; evidence `$SP/fe6b1c_red_baseline_vitest.txt`). Playwright `fe6b1c.spec.ts` T1/T2 against the harness's NINTH appliance CERTTLS (boots WITHOUT `-ui-no-tls` with pair A persisted, so its admin listener REALLY serves A over TLS; `wait_ready_tls` over `https`; pairs `ui-a`/`ui-b` CN `ui-fe6b1c-{a,b}.e2e`; fixtures `CERTTLS_URL`, `CERTTLS_UI_PAIR_DIR`): **2 failed / 1 passed** with all nine instances ready — both journeys on "bad listener" (no evidence object on the read model); the pass is the shared auth-setup project (`$SP/fe6b1c_red_baseline_e2e.log`).

> **6B1C-B. Backend correction (B1; authorised).** `ui_listener_evidence.go` records the listener's activation evidence from the ONE place that knows it — `adminUIServeOnce` (`ui.go`), at the instant the bind succeeded and before Serve starts: `state` (`serving` between an observed bind and the serve call returning; `unknown` before the first bind and again once a serve ended, i.e. while the CHAOS-57 retry loop is rebinding), `posture` (`tls_custom` = the persisted GUI pair at `customUITLSCertPath()`, `tls_configured` = an explicit `-tls-cert/-tls-key` pair, `tls_self_signed`, `plain_http`, `unknown`) and the served leaf's PUBLIC identity (fingerprint in the inventory's upper-case colon SHA-256 form, subject, validity — never key material). `servesPersistedPair` — and therefore the legacy `uiCert.active` and `ui_custom_cert_active` — are DERIVED on every read (posture `tls_custom` AND the persisted pair complete and valid AND `ca.FingerprintOf(persistedUICertLeaf()) == served.Fingerprint`), never stored; the UI-delete ledger record's `WasActive` derives the same way. The object is published as `listener` on `GET /api/certificates` and `ui_listener` on `GET /api/settings/network` — the SAME object on both reads. `uiCustomTLSActive` remains the boot-time selection flag (`resolveUITLSCertKey`) and is no longer published anywhere; its comment says so. `resetAdminUIHealthForTest` clears the record. OpenAPI: new `AdminListener` schema (required `state`, `posture`, `servesPersistedPair`; optional `servedCertificate {fingerprint, subject, notBefore, notAfter}`), required on `CertificateInventory.listener` and `NetworkSettings.ui_listener`, and the `active` / `ui_custom_cert_active` descriptions restated as the derived fact; `make api-bundle` regenerated `openapi.json`, `generate-types.sh` regenerated `types.gen.ts`; `api-bundle-check`, `api-lint`, `api-route-coverage`, `api-contract-test` clean. Recorded, not fixed: `adminUIServeOnce` validates the operator pair with one read and `http.Server.ServeTLS` re-reads the files microseconds later (the CHAOS-57 HTTP/2 note explains why the double read stays), so a pair replaced in exactly that window is served but recorded as its predecessor until the next bind; the persisted-pair writers run through the staged marker transition, so an atomic replace lands whole on either side of it (6B1C-F).

> **6B1C-C. Frontend correction.** *B1.* `src/api/certificates.ts`: `AdminListener` / `ServedCertificate` types and `decodeAdminListener` (bounded `LISTENER_STATES` / `LISTENER_POSTURES`; `state: unknown` ⇔ `posture: unknown`; a served identity present iff the posture is a TLS one; `servesPersistedPair` only under `tls_custom`); `decodeCertificateInventory` REQUIRES `listener` and refuses a `servesPersistedPair` or `uiCert.active` that disagrees with the derived fact; `decodeListenerFacts` REQUIRES `ui_listener`, refuses a legacy `ui_custom_cert_active` that disagrees with it and a fallback flag beside a listener serving TLS; the pure `activationPosture(inventory)` decides one of eight postures — `unknown` (no bind observed), `plain_http`, `tls_configured{served}`, `self_signed{served, persistedActivatesOnRestart}`, `custom_matches{served}`, `custom_differs{served, persistedFingerprint}`, `custom_not_persisted{served}`, `custom_persisted_unusable{served, persistedState}`; `listenerReadsDisagree` compares the two reads as objects. `CertificatesPage.tsx` renders activation from that posture ALONE: unknown claims nothing ("Listener activation unknown … has not been observed"); plain HTTP states the persisted pair is not in use; the configured and self-signed postures name the served identity; only `custom_matches` says "Active on the running listener"; `custom_differs` names the served pair beside the persisted one and says a restart activates it; `custom_not_persisted` names the pair that is no longer on disk. The network read is a CROSS-CHECK: a disagreement between the two reads, or an answer that cannot be verified as consistent listener facts (a decode refusal), is a **Contradictory listener facts** callout that withholds every claim and describes both sides as stated (never picks one); a read that did not happen (transport failure) is a **Listener cross-check unavailable** callout that does not withdraw the inventory's evidence-backed claim. The persisted pair's own class keeps its four distinct renderings; "The listener serves the self-signed certificate" is no longer inferred from absence. *B2.* Both persist-degraded callouts (`CAInventoryFacts`, `CAStatusCard`) render the bounded class only — the "running root is not on disk", "memory-only" and "restart re-rotates" inferences are gone (false under the persist-before-publish contract, where an ordinary bundle-write failure retains the previous CA and a post-rename sync doubt installs the candidate as unproven; the operation's ledger record states what an attempt installed); the CA load-failed callout no longer infers that inspected HTTPS is bypassed; a committed operation's audit is qualified by the inventory's `auditSink` — "Audit persisted (file sink)" / "Audit recorded in the in-memory ring only (memory sink)" / "Audit recorded; sink evidence unavailable" when the inventory read failed — and "durable" is never said without the file sink; the page subtitle states the node-local scope per surface and defers the backup facts to the ledger card instead of the blanket "nothing here is exported, rolled back or synced" (the backup archive DOES carry the CA bundle). *B3.* `getCertOperation` decodes the answer and REFUSES a record whose `operationId` is not the requested UUID (case-insensitive; a `decode`-class error, rendered as "Lookup response not verified … could not be verified"); `checkCommittedResult` validates a committed record's action-specific `result` against the outer record and the frozen contract (the action's discriminant present and `true` with the other actions' discriminants absent; `result.operationId`/`action` equal to the record's; `ca.revision` equal to `committedRevision` with `ca.fingerprint` and the candidate fingerprint sharing its digest for `ca.rotate`/`ca.import`; `uiCert.revision` equal to `committedRevision` and a complete pair for `cert.ui.replace`; `deleted` with an absent pair and `uic1:none` for `cert.ui.delete`; `ok`, `durable`, `revision` equal to `committedRevision` and `enabled == runtime.enabled` for `ocsp.set`) — a contradiction is a decode refusal, never a rendered verdict; `certLookupRefusal` recognises a refusal ONLY with the contracted HTTP status per code (`LOOKUP_REFUSAL_STATUS`), the `application/json` media type (`ApiError` now carries `mediaType`) and the bounded `{error, code, current?}` shape — a `not_found` on a 500 or on `text/plain` renders as an unverified lookup response ("HTTP 500" / "HTTP 404"), never "No retained operation record". Terminal UNKNOWN and audit-pending semantics are unchanged. `frontend/dist` rebuilt deterministically.

> **6B1C-D. Recorded test corrections (each explained in place).** (1) `fe6b0c_red_test.go` R09d set the activation premise through the boot flag (`uiCustomTLSActive = true`); it now records listener evidence (`recordAdminListenerServing(adminListenerPostureCustom, persistedUICertLeaf())`) — the only way the fact can be true under the corrected contract. (2) `fe6b1-fixtures.ts`: `UI_ACTIVE_NOT_PERSISTED` (absent pair, `active: true`) RETIRED as a contradiction (an absent pair is never the served pair); the deleted-while-served case is `UI_ABSENT` beside `LISTENER_CUSTOM_A(false)`; `OP_COMMITTED.result` fingerprints aligned with its `committedRevision` digest (the original paired the CA fingerprint with an unrelated digest — a contradiction the B3 decoder now refuses, so the fixture was wrong, not the decoder). (3) `fe6b1-red-page.test.tsx` P3: case 2 re-expressed through the listener evidence (the former "Active on the running listener" assertion for an absent pair WITHDRAWN; the served identity and "no longer persisted" asserted instead); case 3 feeds a SELF-CONSISTENT network answer (a plain-HTTP `ui_listener` beside `ui_custom_cert_active: false`) that disagrees with the inventory — the former answer asserted `active: true` beside a plain-HTTP listener, which the fail-closed decoder now refuses whole (pinned in A3), rendered as a contradiction without echoing either side. (4) `fe6b1-red.test.ts` A7/A8: the active pair is decoded beside the listener observed serving it (`withUI` pairs the uiCert with the healthy inventory's self-signed listener, under which `active: true` is the refused contradiction); the fallback network answer is self-consistent. No accepted assertion was weakened: the role, explicit-lookup, no-polling, navigation and secret-boundary proofs are byte-identical.

> **6B1C-E. Qualification (head `e6ce79bb`; chain 14 + integration 11).** Chain 14 on `e6ce79bb` — deterministic builds: two independent `CGO_ENABLED=0 -trimpath -buildvcs=false -ldflags='-s -w'` builds byte-identical (`fe54238f…`); arm64 cross-compile, `go vet ./...`, `make api-bundle-check`, `make api-lint api-route-coverage api-contract-test` all clean (the `AdminListener` contract change is in the bundle, the inventory and the generated types); `frontend/scripts/verify.sh` ALL GATES PASSED (toolchain identity, clean `npm ci --ignore-scripts`, OpenAPI type generation + drift, eslint + prettier, strict tsc, vitest 95 files / 1044 tests, production build + committed-dist drift, bundle security scan, license + audit policy); `verify-determinism.sh` identical rebuild; tree clean after the frontend gates; real-binary integrations 3–10 all green (7 = 60 expectations, 8 = 28, 9 = 27, 10 = 46 under an unprivileged uid) PLUS the new **integration 11** (`$SP/integration11.sh`, 46 expectations): the served fingerprint the API publishes is compared against the certificate an INDEPENDENT TLS client receives (`openssl s_client` → SHA-256 over the DER) through the whole lifecycle — L1 boot serving persisted A over TLS (peer == published == `ui-a.crt`, `tls_custom`, `active: true`, the two reads carry one object); L2 replace with B and no restart (peer still A; served A, persisted B, `servesPersistedPair`/`active`/`ui_custom_cert_active` false); L3 delete while served (absent, `active: false`, peer still A); L4 restart with nothing persisted (`tls_self_signed`, served == peer, neither A nor B); L5 persist B + restart (peer == B, `tls_custom`, `active: true` — successful activation after a restart); L6 `-ui-no-tls` with B persisted at boot (the pair is STILL served — peer == B, `tls_custom`, active; see 6B1C-F.3) and L6b `-ui-no-tls` with nothing persisted (`plain_http`, no served certificate; a pair uploaded afterwards is persisted but not in use, `active: false`, `ui_custom_cert_uploaded: true`); L7 leak sweep (no key material or data-dir path in any API body, the listener object, the ledger, the audit or the log). Focused `-race -count=3` over the certificate/CA/UI-TLS/admin-settings/fileutil matrix plus `TestFE6B1C_` and the CHAOS-57 listener gates and the embedded-frontend/lockstep gates (367 s, all ok; the eight C-rows also run by name under `-race -v`, 8/8 PASS — `$SP/fe6b1c_rows_race.log`); root package `go test -race` 2143 s ok; `./internal/... ./cmd/...` `-race` 108 packages ok, 0 failures; two consecutive full Playwright runs through `scripts/e2e-smoke.sh` (NINE appliances) **163 passed / 0 failed / 3 skipped** each — the two new `fe6b1c.spec.ts` journeys (T1 CERTTLS: `securityDetails().subjectName` == the published served subject A before and after uploading B and after deleting the pair; T2 CERT: plain HTTP stated, no activation claim) green in both, the three skips the pre-existing evidence-capture specs; gitleaks clean; the harness data check restored (51 of 51 pre-qualification `/data` digests OK); tree clean; no leaked appliance process. Diff-scoped `golangci-lint --new-from-rev 935891f4` 0 issues. Exit gate: `origin/main` re-fetched after the chain — still `91c926e6`, an ancestor of the head, so no merge and no requalification of a merged scope was needed; remote branch head equals the local head.

> **6B1C-F. Residuals (recorded, not fixed).** (1) The bind-time double read in `adminUIServeOnce` (6B1C-B): a pair replaced between the validation read and `ServeTLS`'s own read is served but recorded as its predecessor until the next bind — microseconds wide, atomic-replace-safe, closed only by handing `ServeTLS` the loaded pair, which the CHAOS-57 HTTP/2 note deliberately does not do. (2) `state: serving` is bind evidence, not liveness: a listener that bound and later wedged without its serve call returning still reads `serving`; the CHAOS-57 admin-UI health plane (`/health admin_ui`, the fire-once alert) is the liveness signal. (3) A pair persisted at boot is served even under `-ui-no-tls` (the flag suppresses only the auto self-signed certificate; `resolveUITLSCertKey` runs regardless — pre-existing behaviour, outside this round's scope, now VISIBLE because the evidence reports `tls_custom` where the flag would have suggested plain HTTP; integration 11 L6 pins it, L6b pins the genuine plain-HTTP case with no pair). (4) The persisted pair's `unavailable` class beside a served custom pair is stated as "cannot be examined, so whether it is the served one is not known" — the appliance does not guess either. (5) The IA's Platform/admin placement vs the shipped Security/viewer placement remains the IA owner's decision (6B1-F.2). (6) The admin lookup remains a settlement GET issued only on an explicit action (6B1-F.3); `writer_evidence_superseded` remains terminal UNKNOWN (6B1-F.4); OCSP-8 and the verbatim `expiresIn` are unchanged (6B1-F.5/6). (7) FE-6B.2 is unstarted.

> **6B1D — FE-6B.1 second external freeze review REJECTED → one bounded append-only correction round (2026-09-19; reviewed candidate `8960ab53`; RED commit `7b5991b5` on exactly that candidate; product commit `2359f526`; test-lint commit `5383d682`; record commit = this one; `origin/main` at entry and at exit = `91c926e6`, an ancestor of the head — no merge was needed). Two source-level contract gaps: B1 the listener evidence was recorded from a pair the serve path then re-read from disk; B2 `checkCommittedResult` accepted contradictory result facts. The reviewed candidate, frozen FE-6B.0 and every predecessor are preserved; append-only history, no PR, FE-6B.2 unstarted.**

> **6B1D-A. RED before (commit `7b5991b5`, executed on exactly `8960ab53` before any product change).** *B1 — Go `fe6b1d_red_test.go`.* `adminUIServeOnce` loaded the pair, recorded its leaf, DISCARDED the pair and handed `ServeTLS` the file names, so `ServeTLS` read the files again; a pair replaced between the two reads was served as B while the appliance published A until the next bind — the window is microseconds wide, which bounds how often it happens and not at all what it costs. The rows make the race deterministic with a TEST SEAM added in the RED commit (`adminUIBeforeServeHook`, `ui.go`; nil in production; the double read itself untouched): it runs between the validation read and the serve call, pair B overwrites A there, and the row compares the PUBLISHED served fingerprint with the certificate a REAL TLS handshake receives — no sleeps, no timing. D01 (the persisted GUI pair, `tls_custom`) and D02 (an explicit `-tls-cert/-tls-key` pair, `tls_configured`) **failed on the candidate** — published A, TLS peer B (`$SP/fe6b1d_red_baseline_go.txt`). Controls that passed there and must keep passing: D03 ALPN `h2` negotiated and an HTTP/2 `GET` answered on the custom-pair listener (the HTTP/2 setup is the reason the double read was originally kept), D04 the evidence is cleared when the serve call returns, D05 a broken pair fails BEFORE the bind, records no evidence, classifies `tls_certificate` and leaves the port free. *B2 — vitest `fe6b1d-red.test.ts` E01–E16 + K01–K04 and `fe6b1d-red-page.test.tsx` R01–R05.* Each E-row starts from a record the authoritative builder emits (`certificate_operations.go` `caOperationResult` / `uiCertOperationResult`) and changes ONE fact: rotate `persisted:false` / missing; import `persisted:false`, `target:"ui"`, target missing; rotate `target:"ui"`; rotate `previous` not an object; replace `persisted:false`, `target:"mitm"`, `activation:"immediate"`, `candidate` missing, `candidate` naming another certificate; delete `cleanup:"partial"`, cleanup missing, `target:"mitm"`, `activation:"immediate"`. **16/16 E-rows and 4/4 R-rows failed on the candidate** (the record decoded and the page rendered "Committed / Audited"); the K-rows (the four builder records, `cleanup: completed_at_settlement`, `activation: restart_required` on a delete, a rotate carrying `target: mitm`) and R05 passed (`$SP/fe6b1d_red_baseline_vitest.txt`). Fixtures: `OP_ROTATE_COMMITTED` and `OP_UI_REPLACE_COMMITTED` added in the builders' shapes; recorded fixture correction — `OP_UI_DELETE_COMMITTED.result` gains `target: "ui"`, which the frozen `UICertDeleteResult` REQUIRES and the builder always emits (the original fixture omitted it). Existing suites 80/80 unchanged.

> **6B1D-B. Backend correction (B1; labelled as such).** `adminUIServeOnce` (`ui.go`) loads the pair ONCE, installs it into the server's TLS configuration and records the leaf of that SAME object; `ServeTLS` is called with EMPTY file names, so it takes the certificate from the configuration and reads nothing — a pair replaced on disk after the load is served only by the next bind, which records it. `ServeTLS` stays the serve call (never `srv.Serve(tls.NewListener(...))`) so its `setupHTTP2_ServeTLS` keeps ALPN `h2`; because that setup runs ONCE per server and mutates `srv.TLSConfig`, the per-attempt configuration is CLONED from `srv.TLSConfig` and left installed (never restored to nil), so a rebind after a fault carries `h2` forward exactly as the file-based path did (D03). `MinVersion` TLS 1.2 is spelled out — it is crypto/tls's server default, which the file-based `ServeTLS` call with a nil configuration applied. Preserved unchanged: the pre-bind validation and its `tls_certificate` classification, the CHAOS-57 descriptor-leak guarantee (validation fails before any socket exists), the `ln.Close` backstop, the evidence clearing on serve return, and the self-signed path (`startUI` installs that configuration; the served leaf was already read from it). The seam stays nil in production. `ui_listener_evidence.go`'s header records the residual as closed. No OpenAPI change — the published object is unchanged; only its truth is now bound to the served material.

> **6B1D-C. Frontend correction (B2).** `checkCommittedResult` (`src/api/certificates.ts`) now checks every fact the frozen result schemas make mandatory or bounded, per action's builder: `ca.rotate` / `ca.import` require `persisted: true` (`enum: [true]` — persist-before-publish; a false durability claim is a contradiction), `previous` as a bounded `CAPrevious` object, `ca` as a bounded `CAInfoWithRevision` with `ready`; import requires `target: mitm`, rotate accepts `target` only as `mitm` when present (the schema is `additionalProperties: true` there, a foreign value contradicts what a rotate writes); `cert.ui.replace` requires `persisted: true`, `target: ui`, `activation: restart_required` and a bounded `UICertCandidate` whose fingerprint is the replaced pair's; `cert.ui.delete` requires `target: ui`, `cleanup ∈ {complete, completed_at_settlement}` and accepts `activation` only as `restart_required` (documented optional). A contradiction refuses the record whole (a `decode`-class error), so the page renders "Lookup response not verified … could not be verified", never Committed / Audited. Documented optionality is preserved (`previous` fields, `candidate.dnsNames`, delete `activation`); no field was invented. Terminal UNKNOWN and audit-pending semantics are unchanged. `frontend/dist` rebuilt deterministically.

> **6B1D-D. Qualification (head `2359f526`; chain 15 + integration 11).** Chain 15 on `2359f526` — deterministic builds: two independent `CGO_ENABLED=0 -trimpath -buildvcs=false -ldflags='-s -w'` builds byte-identical (`569cf2c8…`), and the final head `5383d682` (a test-only lint commit, below) builds to the SAME digest; arm64 cross-compile, `go vet ./...`, `make api-bundle-check`, `make api-lint api-route-coverage api-contract-test` all clean (no contract change); `frontend/scripts/verify.sh` ALL GATES PASSED (toolchain identity, clean `npm ci --ignore-scripts`, OpenAPI type generation + drift, eslint + prettier, strict tsc, vitest 97 files / 1069 tests, production build + committed-dist drift, bundle security scan, license + audit policy); `verify-determinism.sh` identical rebuild; tree clean after the frontend gates; real-binary integrations 3–10 all green (7 = 60 expectations, 8 = 28, 9 = 27, 10 = 46 under an unprivileged uid) plus **integration 11** (46 expectations — the `openssl s_client` peer fingerprint equals the published served identity through boot, replace-without-restart, delete-while-served, self-signed restart, persist-and-restart activation, `-ui-no-tls` with and without a persisted pair, leak sweep). Focused `-race -count=3` over the certificate/CA/UI-TLS/admin-settings/fileutil matrix plus `TestFE6B1C_`, `TestFE6B1D_` and the CHAOS-57 listener gates: the run INSIDE the chain reported ONE failure in three iterations of `TestChaos50_TransientLoadFailureSelfHeals` (`recovery not recorded: {Attempts:0 Recovered:true}`), a root-CA recovery gate this round does not touch — recorded transparently: the mechanism is a pre-existing observability ordering in `rootca_recovery.go` (`recovered` is set at line 183 inside the successful attempt, `attempts++` at line 308 after the attempt returns, and the test's terminal wait releases on the first), it reproduced 0 times in 30 isolated `-race` iterations, and it surfaced while a deterministic build, the D-rows and the diff-scoped lint were deliberately run BESIDE the chain's focused run; the same focused matrix re-run on the final head `5383d682` with the machine quiet is ALL OK (`$SP/focused15b.full`, 315 s). Root package `go test -race` 2201 s ok; `./internal/... ./cmd/...` `-race` 108 packages ok, 0 failures; two consecutive full Playwright runs through `scripts/e2e-smoke.sh` (nine appliances) **163 passed / 0 failed / 3 skipped** each (the `fe6b1c.spec.ts` real-TLS journeys green in both; the three skips are the pre-existing evidence-capture specs); gitleaks clean; the harness data check restored (51 of 51 pre-qualification `/data` digests OK); tree clean; no leaked appliance process. Diff-scoped `golangci-lint --new-from-rev 8960ab53`: 0 issues after the test-only lint commit `5383d682` (three `noctx` sites and one `gocritic` `httpNoBody` in `fe6b1d_red_test.go`, replaced by `tls.Dialer.DialContext`, `ListenConfig.Listen`, `http.NewRequestWithContext` + `Client.Do`; no assertion changed; the D-rows re-run green under `-race` on that head). Exit gate: `origin/main` re-fetched after the chain — still `91c926e6`, an ancestor of the head, so no merge and no requalification of a merged scope was needed; remote branch head equals the local head; tree clean.

> **6B1D-E. Residuals (recorded, not fixed).** (0) `rootca_recovery.go` sets `recovered` before the campaign increments `attempts` (lines 183 / 308), so a reader that releases on `Recovered` can observe `Attempts: 0` — an observability ordering, not a behaviour change, seen once under deliberate concurrent load in chain 15 and never in isolation; owner follow-up, outside this round's scope. (1) `state: serving` remains bind evidence, not liveness (6B1C-F.2). (2) A pair persisted at boot is served even under `-ui-no-tls` (6B1C-F.3; integration 11 L6/L6b). (3) The IA placement, the settlement-GET nature of the admin lookup, `writer_evidence_superseded` as terminal UNKNOWN, OCSP-8 and the verbatim `expiresIn` are unchanged (6B1-F). (4) FE-6B.2 is unstarted.

> **6B2 — FE-6B.2 Certificates & CA MUTATION surfaces (FE-V28 / FE-V29 write side; 2026-09-19; entry baseline = the frozen FE-6B.1 head `212b1617`; `origin/main` at entry = `91c926e6`, an ancestor — no merge; RED commit `338f78ed` on exactly the baseline; product commit `10833f57`; correction commit `590015a4` (found by the real-binary journey, below); record commit = this one). Frontend only: the entry audit demonstrated NO backend contract gap, so no backend change was made and the frozen FE-6B.0/6B.1 contract, OpenAPI and `uiRoutes` are untouched. The reviewed FE-6B.1 candidate, frozen FE-6B.0/6A and every predecessor are preserved; append-only history, no PR, FE-6C unstarted.**

> **6B2-A. Entry contract map (`$SP/fe6b2_contract.md`).** Read before implementing: the approved decomposition (FE-6B in this plan and the R-E ceremony ruling — certificate upload T2 ships WITH FE-6B.2), the handlers `ui_certificates.go` / `certificate_operations.go` / `ui_tls_custom.go`, `uiRoutes` (every write `RoleAdmin` + `AuditExpected`), the frozen OpenAPI write schemas (`CARotateChallenge`, `CARotateConfirm`, `CARotateResult`, `CAImportResult`, `CertDryRunResult`, `UICertReplaceResult`, `UICertDeleteResult`, `OCSPSetResult`, `CertRefusal`, `CertOperation`). Each in-scope mutation maps to: **rotate** — `POST /api/ca/rotate/challenge` then `POST /api/ca/rotate` `{challenge}`, fence `caRevision`, operationId on both, challenge bound to actor + operationId + revision + 120 s, T3 typed `ROTATE` (the legacy word, D1) on the SERVER challenge (D2), result `rotated` / `persisted:true` / `ca` (new revision) / `previous` (at the fence); **import** — `POST /api/certs/upload?target=mitm` multipart, `?dryRun=1` = the T2 review (CACertificateInfo + `current.caRevision`), commit fenced on that revision, result `imported` / `target:mitm` / `ca.fingerprint` = the reviewed candidate; **UI replace** — `target=ui`, dry run (UICertCandidate + `current.uiCertRevision`), result `replaced` / `activation: restart_required` / `candidate` = reviewed / `uiCert.revision` = `uic1:<sha256 of the certificate bytes received>`; **UI delete** — `DELETE /api/certs/ui?operationId=&uiCertRevision=`, T3 typed word = the persisted fingerprint's first 8 bytes (identity-bound, bounded, shown verbatim), result `deleted` / `cleanup` / positively absent pair / `activation` when the served pair was the deleted one; **OCSP set** — `POST /api/ocsp?operationId=&ocspRevision=` `{enabled}`, T2 stating desired vs runtime vs coverage, result `ok` / `durable:true` / new revision / `desired.source: admin`. Refusals: typed JSON `{error, code, current?}` at a contracted status per code; the non-terminal `500 outcome_unknown` (`detail ∈ refusal_not_durable | durability_unproven | transition_incomplete`, `state: pending`) decides nothing. Recovery: `GET /api/ca/operations/{id}` (admin, a settlement GET); replay by id; a re-send of the SAME operation with the ORIGINAL fence is idempotent-safe by construction (replay / `409 stale` / `409 candidate_duplicate`). No gap: every 2xx carries an action discriminant, the operation identity and fence-derived facts the browser can bind; `jsonOK` sets the media type before the body; CSRF is the same-origin `Origin` check (browser multipart passes); the challenge may be re-issued for the same operationId while no ledger record exists.

> **6B2-B. RED before (commit `338f78ed`, executed on exactly `212b1617`).** *vitest* `fe6b2-red-api.test.ts` A01–A14 (70 rows: challenge binding and request shapes, action-bound 2xx per action with every single-fact contradiction UNPROVEN, dry run / commit = the same multipart candidate, replay, the refusal contract, `certUnproven`, the nothing-written set, `pemDigest`), `fe6b2-red-recovery.test.ts` M1–M8 (28 rows: the non-secret subject-bound marker, one outstanding operation, per-action grammar, ledger-record binding, Re-send only after 404), `fe6b2-red-page.test.tsx` P01–P18 (22 rows: roles, the five controls, rotate / stale fence / expired challenge, import review and commit, bounded candidate refusal, lost confirm and malformed 2xx ⇒ UNPROVEN latch, reload recovery with every ledger distinction, the T3 delete, OCSP, one dispatch per double confirm, the typed key only in the open ceremony, persisted ≠ served, the dirty guard): **3 files fail on the baseline** — the 70 API rows on undefined write exports, the marker and page files at import (`certRecovery` does not exist) (`$SP/fe6b2_red_baseline_vitest.txt`). *Real binary* `frontend/e2e/fe6b2.spec.ts` W1–W8 on a TENTH appliance **CERTW** (`scripts/e2e-smoke.sh`: sealed persisted Root CA, persisted UI pair A served over real TLS, OCSP default; pair B, an importable EC CA and a mismatched key generated beside it): **W1 (roles) passes on the baseline, W2–W8 fail on the absent controls** (`$SP/fe6b2_red_baseline_e2e.txt`, all ten appliances ready). Recorded fixture/assertion changes: the accepted admin control allowlists (`e2e/fe6b1.spec.ts`, `src/test/fe6b1-red-page.test.tsx`) gain exactly the five approved FE-6B.2 controls (the FE-6B.1 "no mutation control" statement is superseded by this scope; viewer/operator unchanged); the fe6b2 fixtures pair every `previous.fingerprint` with the colon form of the `car1:` fence it stood at (a `car1:` token IS the DER digest) and `PEM_DIGEST` is the real sha256 of the certificate canary; `e2e/fixtures.ts` gains `CERTW_URL` / `CERTW_DIR`.

> **6B2-C. Product (commit `10833f57`; frontend only).** `src/api/certificates.ts` (write client, appended beside the frozen read decoders): `requestCARotationChallenge` (bound to the requested operation, the echoed fence AND the CA at that fence), `confirmCARotation` (challenge in the BODY only), `dryRunCAImport` / `dryRunUIReplace` (bounded facts + the fence to echo; no id, fence or write), `importCA` / `replaceUICert` (the same multipart candidate under the dry run's fence), `deleteUICert`, `setOCSPPosture`, `pemDigest`; a 2xx is a verdict only when action-bound (discriminant, `persisted`/`durable` true, the action's target, `previous` at the fence, a NEW revision whose digest is its own fingerprint, the REVIEWED candidate — import by fingerprint, replace by fingerprint AND `uic1:<digest of the bytes sent>` — a positively absent pair, the requested OCSP posture with `source: admin`, `recordState` present); `asCertRefusal` (contracted status + `application/json` + bounded shape + required typed facts; the server's line never rendered), `CERT_TERMINAL_NOTHING_WRITTEN` (never the non-terminal `outcome_unknown`, `operation_in_progress`, `operation_outcome_unknown`, `operation_mismatch`), `certUnproven`. `features/security/certRecovery.ts`: `culvert.cert.operation-recovery.v1` — one outstanding operation per browser session, subject-bound, non-secret (operationId, action, the fence carried, the candidate's public identity, the CA identity a rotation replaces, startedAt), written before dispatch and verified by read-back, unavailable store ⇒ no dispatch, ownership-matched clear, auth-boundary purge, `operationBoundToCertMarker` (id + action + fence + candidate where the ledger publishes one), `certResendAllowed` only after an authoritative 404. `features/security/certWrites.tsx`: the ceremonies and one dispatch protocol — rotate (marker armed at the challenge request; typed `ROTATE`; an expired challenge offers a NEW challenge for the SAME operation; a moved fence renders the current revision and ends the ceremony), import / replace (paste → Review → T2 impact copy naming the persisted target and the restart-only activation → commit under the reviewed fence; a re-send must present the marker's candidate), delete (T3: persisted AND served identities stated; typed first 8 fingerprint bytes), OCSP (T2: desired vs runtime vs the coverage limit, node-local), typed Abandon; a terminal refusal clears the marker and renders its typed facts; a lost, unproven or non-terminal answer closes the ceremony (dropping every typed secret with the dialog tree), keeps the marker and disables every mutation; the unresolved card offers Recover (committed ⇒ cleared + result; pending / recoverable unknown kept; aborted ⇒ nothing written + Abandon; unproven / `writer_evidence_superseded` ⇒ TERMINAL UNKNOWN, never success, failure or retry; 404 ⇒ never recorded ⇒ Re-send of the same operation, candidate and original fence; an unbound record kept), a double confirm dispatches once, the dirty candidate editor guards navigation, nothing restarts on its own, persisted ≠ served on every replace/delete outcome. `CertificatesPage.tsx`: the five controls on the Certificates tab for admins only; every accepted FE-6B.1 read behaviour and the viewer/operator posture unchanged.

> **6B2-D. Correction found by the real-binary journey (commit `590015a4`).** The first product commit sent the pair as multipart STRING entries; the multipart encoding normalises a string entry's newlines to CRLF, so the bytes the appliance hashed into `uic1:<sha256>` differed from the bytes the browser had digested and the replace decoder refused the appliance's genuine 2xx as UNPROVEN — W4 red, the outcome latch behaving exactly as designed (no success claimed, marker retained; the import path was unaffected only because a CA's identity is its parsed fingerprint). `pairForm` now sends `cert` / `key` as byte-exact Blob parts (the handler's `multipartField` already reads file parts); A06 pins both as file parts. The same run exposed a spec bug — `opIdOf` picked the dry run (no operationId by contract) — fixed in the spec.

> **6B2-E. Qualification (chain 16 on the code head `1a703c9e`; `$SP/chain16.log`).** *RED→GREEN:* the three vitest files that fail on the baseline pass on the head (`fe6b2-red-api` 70/70, `fe6b2-red-recovery` 28/28, `fe6b2-red-page` 22/22); `frontend/e2e/fe6b2.spec.ts` W1–W8 pass on the real binary (`$SP/fe6b2_green_e2e2.txt`: 17/17 with the fe6b1 / fe6b1c regressions in the same run — on the first product head W3 was a spec bug and W4 the multipart finding of 6B2-D, both fixed in `590015a4`). *Deterministic builds:* two independent `CGO_ENABLED=0 -trimpath -buildvcs=false -ldflags='-s -w'` builds byte-identical (`284138f6…`); arm64 cross-compile, `go vet ./...`, `make api-bundle-check`, `make api-lint api-route-coverage api-contract-test` all clean (no contract change). *Frontend:* `scripts/verify.sh` ALL GATES PASSED (toolchain identity, clean `npm ci --ignore-scripts`, OpenAPI type generation + drift, eslint + prettier, strict tsc, vitest 100 files / 1189 tests, production build + committed-dist drift, bundle security scan, license + audit policy); `verify-determinism.sh` identical rebuild on every product commit; tree clean after the frontend gates. *Real-binary regressions on the deterministic binary:* integrations 3–6 (the FE-6A.2 PAC / Upstream / IdP / Administrators journeys) DONE, 7 = 60 expectations, 8 = 28, 9 = 27, 10 = 46, 11 = 46 (`openssl s_client` served identity through replace / delete / restart / `-ui-no-tls`) — all green. *Race:* the focused certificate / CA / UI-TLS / admin-settings / fileutil matrix plus the FE-6B0–6B1D and CHAOS-57 gates `-race -count=3`: ALL OK in 372 s (the `TestChaos50_TransientLoadFailureSelfHeals` observability ordering recorded in 6B1D-E.0 did not recur); root package `go test -race` ok, 2156 s, 0 failures; `./internal/... ./cmd/...` under `-race`: 108 packages ok, 0 failures. *Browser:* two consecutive complete Playwright runs through `scripts/e2e-smoke.sh` (TEN appliances) **171 passed / 0 failed / 3 skipped** each (163 + the eight W-journeys; the three skips are the pre-existing evidence-capture specs). *Hygiene:* gitleaks clean; the harness `/data` snapshot re-verified after the whole chain (51 of 51 digests OK — no qualification run wrote into the host's persisted state); tree clean; no leaked appliance process (every instance stopped by the harness's exit trap). *Failed attempts, recorded:* (1) the first product head's W4 journey failed on the CRLF-normalised multipart string entry (6B2-D) — fixed by byte-exact file parts and re-run green; (2) three page rows failed on the first product head because the marker's `previousFingerprint` was derived from two different sources at the challenge and the confirm step and because a second write of the same operation carried a new start instant — both fixed before the RED files were committed (the marker's CA identity is the fence's digest; the same operation keeps its recorded start instant); (3) chain 16 was started once, stopped after two minutes for the three self-review findings of `1a703c9e`, and restarted on that head — the reported chain is the complete second run.

> **6B2-F. Exit gate.** `origin/main` re-fetched at exit = `91c926e6`, unchanged since entry and an ancestor of the head — no merge, no requalification of a merged scope. Branch `claude/culvert-frontend-fe6-hyagdj` head = `1a703c9e` (code head; this record is a docs-only commit appended on top of it) = `origin/claude/culvert-frontend-fe6-hyagdj` after the push, working tree clean. Append-only chain `212b1617 (frozen FE-6B.1) → 338f78ed (RED) → 10833f57 (product) → 590015a4 (multipart correction) → 1a703c9e (self-review + runbook) → this record`; FE-6B.1 (`212b1617`, `8960ab53`, `935891f4`), FE-6B.0 (`c540b176`) and FE-6A (`8b356c4c`) remain ancestors untouched; nothing was amended, squashed, rebased or rewritten; no pull request was opened. Changed-file classification: **tests** — `frontend/src/test/fe6b2-fixtures.ts`, `fe6b2-red-api.test.ts`, `fe6b2-red-recovery.test.ts`, `fe6b2-red-page.test.tsx`, `frontend/e2e/fe6b2.spec.ts` (new), `frontend/e2e/fe6b1.spec.ts` + `frontend/src/test/fe6b1-red-page.test.tsx` (admin control allowlist widened, recorded), `frontend/e2e/fixtures.ts` (CERTW constants); **harness** — `frontend/scripts/e2e-smoke.sh` (tenth appliance CERTW); **product (frontend)** — `frontend/src/api/certificates.ts` (write client appended), `frontend/src/features/security/certRecovery.ts` (new), `frontend/src/features/security/certWrites.tsx` (new), `frontend/src/features/security/CertificatesPage.tsx` (controls wired), `frontend/dist` (deterministic rebuild); **backend** — none; **contract artifacts** — none (no OpenAPI / uiRoutes / generated-types change); **docs** — `docs/operator/certificates-and-ca-lifecycle.md` §9, this record, `FRONTEND-FEATURE-PARITY.md` FE-V28/FE-V29, `FRONTEND-CURRENT-STATE.md`, `FRONTEND-SECURITY-CONTRACT.md` D4 status, `CLAUDE.md`.

> **6B2-G. Residuals and limitations (recorded, not fixed).** (1) Recovery, replay and re-send are node-local: the ledger is not archived (§7 of the runbook), so a pre-restore operation is `404` on the restored node and the current object state is the only evidence — the surface states this on the never-recorded view. (2) The rotation challenge is process-local; a restart between challenge and confirm is `409 challenge_stale` and the console offers a new challenge. (3) The console never restarts the appliance and never distributes the CA to clients or nodes (outside FE-6B scope). (4) `writer_evidence_superseded` and an unproven `outcome_unknown` remain TERMINAL UNKNOWN; abandoning a marker discards the browser's marker only. (5) `state: serving` remains bind evidence, not liveness; persisted material is not necessarily active (carried forward). (6) The IA placement, the settlement-GET nature of the lookup, OCSP-8 and the verbatim `expiresIn` are unchanged (6B1-F). (7) FE-6C and every other slice remain unstarted.

> **6B2C — FE-6B.2 CORRECTION ROUND (external review REJECTED the candidate `fcdd626f` on three blockers; 2026-09-19; frontend only — the frozen FE-6B.0/6B.1 backend contract, OpenAPI and `uiRoutes` are untouched; the candidate `fcdd626f`, FE-6B.1 `212b1617`/`8960ab53`/`935891f4`, FE-6B.0 `c540b176` and FE-6A `8b356c4c` are preserved as ancestors; append-only history, no PR, FE-6C unstarted). RED commit `2dc925b3` on exactly `fcdd626f`; product commit `24b7c7ee`; record commit = this one.**

> **6B2C-A. Blockers as received, and what each proved false.** *B1 — a lookup 404 does not establish safe re-send.* The candidate offered Re-send after an authoritative 404 on the argument that the contract makes re-dispatching the same operation, candidate and original fence safe by construction (replay by id / `409 stale` / `409 candidate_duplicate`). The reviewer's counterexample holds and is now a permanent DEFECT PROOF on the real handlers, `fe6b2c_red_test.go` (`TestFE6B2C_B1a`, passes before and after because the backend is deliberately unchanged): pair A persisted; X deletes A (answer lost); 256 decided OCSP sets evict X (`certOperationsMax`, `evictDecidedLocked` — DECIDED records are evictable, unresolved ones never); an unrelated operation reinstalls the IDENTICAL pair A, so the content-derived fence `uic1:<sha256 A>` matches again; `GET /api/ca/operations/X` → 404; re-sending X under its original fence is accepted as a NEW intent and executes a SECOND delete (`deleted:true`, no replay) — the pair X never deleted is gone. `TestFE6B2C_B1b` is the CONTROL: with the record retained the same re-send replays and executes nothing, so the protection the candidate relied on is exactly ledger retention, which nothing guarantees. The candidate's view also claimed "a 404 alone is not proof of non-commit — the current object state above is": false, the current object state proves nothing about an absent operation (that is the counterexample). *B2 — the original unresolved marker was not preserved.* `dispatch` cleared the marker on terminal refusals even for a later attempt (a re-send), `cancelRotate` cleared it when a re-send ceremony was cancelled, and `requestChallenge` cleared it on every refusal or failed request including `operation_mismatch`. *B3 — the copy promised what the next start serves.* "the next restart serves this one" / "falls back to the automatic self-signed certificate" are false in general: an explicit `-tls-cert`/`-tls-key` pair selects another pair, and `-ui-no-tls` leaves the next boot on HTTP.

> **6B2C-B. RED before (commit `2dc925b3`, executed on exactly `fcdd626f`).** *Go:* `fe6b2c_red_test.go` B1a (the hazard) + B1b (control), both PASS on the candidate (a defect proof of the API contract, not a regression gate). *vitest* `fe6b2c-red-page.test.tsx` C01–C08 (14 rows): C01 Recover ⇒ 404 renders "retains no record … cannot be known", never "never recorded" / "did not start" / "may be re-sent" / "proof of non-commit" / "current object state", no Re-send, marker kept, every mutation blocked, Abandon offered; C02 the counterexample on the page — an unresolved DELETE fenced on the reinstalled pair's revision, lookup 404: no control of the unresolved card opens a ceremony or dispatches anything; C03 the seeded marker's identity and startedAt survive Recover (404 / pending) and Abandon → Cancel, and no Re-send path exists; C04 the challenge stage never touches the marker store (in flight, on `operation_mismatch`, on cancel); C05/C06 CONTROLS (the marker is armed at the confirm dispatch and retained on a lost answer; a first-attempt `409 stale` leaves no marker); C07/C08 delete and replace ceremonies + outcomes under `tls_configured` / `tls_custom` (served) / `unknown` / `plain_http` state the listener fact and "depends on the startup configuration" and never match `/self-signed|falls back|takes effect|next restart serves|serves this one|restart, which/`. *Re-expressed accepted assertions (rationale in each header):* M8 inverted — the module exports no re-send predicate; P04 asserts NO marker at the challenge step (the candidate wrote it there and cleared it on cancel / refusal); the P12 404 row expects UNKNOWN + no Re-send; e2e W8 is Recover ⇒ 404 ⇒ UNKNOWN ⇒ Abandon → Cancel keeps the marker ⇒ typed Abandon clears it ⇒ a NEW operation under a NEW id lands (the first id stays 404); W4/W5 assert the outcome and dialog copy carry no next-start claim. **Baseline evidence:** vitest 15 failed / 49 passed across the three files (the 12 correction rows + M8 + P04 + P12-404; C05/C06 pass — `$SP/fe6b2c_red_baseline_vitest.txt`); Playwright W4 / W5 / W8 fail on the real binary, W1–W3 / W6 / W7 pass (`$SP/fe6b2c_red_baseline_e2e.txt`); Go B1a/B1b pass (`$SP/fe6b2c_red_baseline_go.txt`). *Fixture correction recorded:* C04's `operation_mismatch` refusal carries its contracted `current.operationId` + `current.state` facts (fixed in the product commit; the row was RED on the baseline before that fix for the intended reason — a marker existed while the challenge was in flight).

> **6B2C-C. Product (commit `24b7c7ee`; frontend only).** `certRecovery.ts`: the view kind `never_recorded` becomes `absent` ("the authoritative lookup answered 404: the node retains no record — UNKNOWN; an evicted record and a never-started write are the same 404"); `certResendAllowed` removed; the header rule states why a re-send would need an explicitly labelled backend durable identity / continuity contract, which does not exist and is not added. `certWrites.tsx`: every re-send path removed (the rotate / delete / OCSP `resend` flags, the pair ceremony's `bound` candidate check, `resend()`, the Re-send button, the "Re-sends the unresolved operation" copy); the absent view is a `StatusBadge status="unknown"`: "UNKNOWN: the appliance retains no record of this operation. Whether it committed cannot be known from the ledger — a decided record can be evicted, and what the node holds now proves nothing about it. The marker is kept, nothing is re-sent (a new intent is a new operation), and every mutation stays blocked until the marker is abandoned, which cancels or reverses nothing on the appliance."; the card's standing text now reads "nothing is ever re-sent". B2: `requestChallenge` writes and clears NOTHING (no `armMarker`, no `clearCertRecovery`, no re-read — the marker is armed by `dispatch` at the confirm); `cancelRotate` only closes; the `dispatch` terminal-refusal clear is annotated as ownership-matched to the id THIS dispatch armed (every dispatch is a first dispatch); an existing unresolved marker blocks every control and is cleared only by a bound committed lookup (`recover`), the typed Abandon (`abandon`) or the auth boundary (`purgeCertRecovery`). B3: the replace outcome states "The persisted material changed; the pair is persisted, not active. The running listener is unaffected and keeps serving what it loaded. The appliance reports activation as `restart_required`: what the next start serves depends on the startup configuration (an explicitly configured certificate pair or a no-TLS start takes precedence over the persisted pair). Nothing restarts on its own."; the delete outcome states cleanup, that the pair is no longer persisted, whether the running listener was serving it (from the server's `activation` fact) and that it is unaffected, and "What the next start serves depends on the startup configuration; this deletion selects no replacement."; the pair ceremony's impact / rollback copy and the delete impact copy carry the same rule; `servedWords` states one fact per posture from bind evidence — `custom_matches` "serves THIS pair … keeps serving what it loaded", `custom_differs`/`custom_not_persisted`/`custom_persisted_unusable` a different pair kept serving, `self_signed` "the automatically generated certificate", `tls_configured` "an explicitly configured pair … selected by the startup configuration", `plain_http` "serves plain HTTP and keeps doing so", `unknown` "not observed (no bind evidence)" — each followed by the next-start sentence. `frontend/dist` rebuilt (identical rebuild verified by `verify-determinism.sh`); the bundle carries "retains no record" once and no FE-6B.2 Re-send. *Recorded observation (not in this scope):* the frozen FE-6A.2 IdP surface keeps its own typed "Re-send same operation" and `never_recorded` view (`IdentityProvidersPage.tsx`); that path rides the explicitly labelled continuity classifier of record 6A2/6A4C (`resendContinuityRefusal`, the keyed candidate commitment) and is untouched here — it is named so the reviewer can decide whether the same eviction reasoning applies to it.

> **6B2C-D. Qualification (chain 17 on the product head `24b7c7ee`; `$SP/chain17.log`).** *RED→GREEN:* `fe6b2c-red-page.test.tsx` 14/14, `fe6b2-red-recovery.test.ts` 28/28, `fe6b2-red-page.test.tsx` 22/22, `fe6b2-red-api.test.ts` 70/70 and the FE-6B.1/6B1C/6B1D page matrices pass on the head; the whole vitest suite 101 files / 1203 tests; `frontend/e2e/fe6b2.spec.ts` W1–W8 + `fe6b1.spec.ts` + `fe6b1c.spec.ts` on the real binary: 17/17 (`$SP/fe6b2c_green_e2e.txt`); `TestFE6B2C_*` under `-race` ok. *Deterministic builds:* two independent `CGO_ENABLED=0 -trimpath -buildvcs=false -ldflags='-s -w'` builds byte-identical (`a624d101…`); arm64 cross-compile, `go vet ./...`, `make api-bundle-check`, `make api-lint api-route-coverage api-contract-test` clean (no contract change). *Frontend:* `scripts/verify.sh` ALL GATES PASSED (toolchain identity, clean `npm ci --ignore-scripts`, OpenAPI type generation + drift, eslint + prettier, strict tsc, vitest 101 files / 1203 tests, production build + committed-dist drift, bundle security scan, license + audit policy); `verify-determinism.sh` identical rebuild; tree clean after the frontend gates. *Real-binary regressions on the deterministic binary:* integrations 3–6 DONE, 7 = 60 expectations, 8 = 28, 9 = 27, 10 = 46, 11 = 46 (`openssl s_client` served identity through replace / delete / restart / `-ui-no-tls`) — all green. *Race:* the focused certificate / CA / UI-TLS / admin-settings / fileutil matrix incl. `TestFE6B2C_` `-race -count=3` ALL OK in 358 s; root package `go test -race` ok in 2141 s, 0 failures; `./internal/... ./cmd/...` under `-race`: 108 packages ok, 0 failures. *Browser:* two consecutive complete Playwright runs through `scripts/e2e-smoke.sh` (TEN appliances): **171 passed / 0 failed / 3 skipped** each (163 + the eight W-journeys; the three skips are the pre-existing evidence-capture specs). *Hygiene:* gitleaks clean; the harness `/data` snapshot re-verified (51 of 51 digests OK — no qualification run wrote into the host's persisted state); tree clean; no leaked appliance process. *Failed attempts, recorded:* (1) C04 was first written with a bare `operation_mismatch` refusal body; the frozen refusal contract requires `current.operationId` + `current.state`, so the corrected product rendered the refusal as an unanswered challenge and the row failed on the head — the fixture was corrected (the baseline RED reason, a marker present during the challenge, is unchanged); (2) the first chain 17 launch ran under the tool's 10-minute bound and was stopped after the deterministic builds and relaunched detached — the reported chain is the complete second run.

> **6B2C-E. Exit gate.** `origin/main` re-fetched at exit = `36628eb6` (PR #1423, the MCP first-controlled-canary work): it ADVANCED by 53 commits during this round and is no longer an ancestor of the head; the merge-base is `91c926e6` (the FE-6B.2 entry point). Its 19 changed files (`internal/mcp/canary/*`, `mcp_canary_*`, `docs/design/mcp/`, `docs/operator/mcp-first-controlled-canary-review.md`) overlap NONE of the files this round or FE-6B.2 changed (verified by name-set intersection, `$SP/main_advance_files.txt`). No merge was performed: the directive bounds this round to the correction, and merging would put an unqualified scope into the candidate — bringing `main` in is the reviewer's call at freeze. Branch `claude/culvert-frontend-fe6-hyagdj` head = `24b7c7ee` (code head; this record is a docs-only commit appended on top of it) = `origin/claude/culvert-frontend-fe6-hyagdj` after the push, working tree clean. Append-only chain `fcdd626f (rejected candidate, preserved) → 2dc925b3 (RED) → 24b7c7ee (product) → this record`; nothing amended, squashed, rebased or rewritten; no pull request. Changed-file classification: **tests** — `fe6b2c_red_test.go` (new, Go defect proof), `frontend/src/test/fe6b2c-red-page.test.tsx` (new), `fe6b2-red-recovery.test.ts` (M8 inverted), `fe6b2-red-page.test.tsx` (P04, P12-404 re-expressed), `frontend/e2e/fe6b2.spec.ts` (W4/W5/W8 re-expressed); **product (frontend)** — `frontend/src/features/security/certRecovery.ts`, `frontend/src/features/security/certWrites.tsx`, `frontend/dist` (deterministic rebuild); **backend** — none; **contract artifacts** — none; **docs** — `docs/operator/certificates-and-ca-lifecycle.md` (§4 replace/delete semantics, §9), this record, `FRONTEND-FEATURE-PARITY.md` FE-V28, `FRONTEND-CURRENT-STATE.md`, `CLAUDE.md`.

> **6B2C-F. Residuals and limitations (recorded, not fixed).** (1) A 404 lookup is UNKNOWN by construction and stays so: without a backend durable identity / continuity contract (explicitly labelled, with its own RED) no frontend can distinguish a never-started write from an evicted decided record, and none is added here. (2) The IdP surface's Re-send (6A2) is out of this directive's scope and recorded in 6B2C-C for the reviewer. (3) Residuals 6B2-G (2)–(7) carry forward unchanged (process-local challenge, no restart / no distribution, TERMINAL UNKNOWN classes, `state: serving` is bind evidence not liveness, IA / settlement-GET / OCSP-8 / `expiresIn`, FE-6C unstarted).

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
