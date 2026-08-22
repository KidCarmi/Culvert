# Frontend Current State — Repository-Grounded Audit

- **Status**: Current (measured 2026-08-21 against the working tree at the head of `main`)
- **Companions**: `ADR-FE-001-frontend-platform.md` (decision), `FRONTEND-FEATURE-PARITY.md`
  (per-feature matrix), `FRONTEND-SECURITY-CONTRACT.md` (invariants),
  `FRONTEND-MIGRATION-PLAN.md` (program)
- **Supersedes as a factual audit**: `docs/design/CURRENT-UI-AUDIT.md` §1–§5 (measured when the
  file was ~11,964 lines / 25 views; it is now 21,565 lines / 38 views). That document's §6
  contracts are carried forward into `FRONTEND-SECURITY-CONTRACT.md` and the parity matrix.

Everything below was measured from the repository, with line anchors. Code is authoritative.

---

## 1. Physical inventory

| Asset | Size | Notes |
|---|---|---|
| `static/index.html` | 1,256,519 B / **21,565 lines** | The entire SPA: ~4,800 lines markup + SVG sprite, 840 lines CSS (5 `<style>` blocks), **15,925 lines JS** (3 inline `<script nonce>` blocks) |
| `static/chart.umd.js` | 204,948 B | Vendored Chart.js **v4.4.0** (2023), classic script, nonce-tagged; provenance recorded in `docs/design/M1-M2-SELF-REVIEW.md` |
| `static/logo.png` | 4,161,736 B | **2816×1536 RGBA PNG** used only as favicon + one sidebar `<img>` (`index.html:7`, `:752`). ~4 MB for a ~40 px logo; uncached (see §2) |

Code metrics (index.html): 833 `function` declarations; ~158 top-level mutable globals (+27
`mcpx*`); 327 `innerHTML` assignments; 557 `escHtml()` calls; 426 `textContent` writes; 402
`data-click` attributes dispatched through a **324-case `switch`** (`:5359–5750`); 1,999 inline
`style=` attributes; 123 `data-min-role` attributes; 420 `toast()` call sites; 0 inline `on*=`
handlers; 0 external origins.

There is **no Node toolchain anywhere in the repository**: no `package.json`, lockfile, tsconfig,
bundler config, or `.ts` file. The only `npm` invocation in CI installs the playwright-go driver
(`proxy-ui-e2e.yml:93–95`).

## 2. Serving contract (Go side)

- **Embed**: `//go:embed static` → `staticFiles embed.FS` (`ui.go:35`). `go build -o culvert .`
  picks assets up automatically; the Dockerfile runtime stage carries no `static/` — it lives in
  the binary. The embedded set is exactly the 3 files above.
- **Shell**: `loadUIShell` reads `index.html` **once at startup** into `cachedIndexHTML`
  (`ui_static.go:14–24`); `serveUIShell` substitutes `__CSP_NONCE__` per request via
  `strings.ReplaceAll` — a full **1.25 MB copy per page load** (`ui_static.go:49`) — and serves
  `Cache-Control: no-store` (`:48`). If the embed read fails, the shell serves an empty body
  (the FileServer-fallback comment at `:17–19` does not match behavior).
- **Assets**: everything except `/` and `/index.html` falls through to stdlib
  `http.FileServer(http.FS(sub))` (`ui_static.go:31–42`). One hardcoded cache special case:
  `/chart.umd.js` → `public, max-age=86400` (`:37–39`). **Everything else — including the 4 MB
  logo — is served with no cache headers at all** (embed FS has zero mod-times ⇒ no
  ETag/Last-Modified).
- **SPA fallback**: none. Only `/` and `/index.html` reach the shell; `/dashboard` would 404.
  Latent today because only the MCP section uses (hash-based) routing.
- **The serving layer assumes a fixed small file set** — no manifest, no hashed-asset
  convention, no per-type cache policy, no `/assets/` namespace.

## 3. Security posture (as-built)

- **CSP** (`ui_middleware.go:152–153`): `default-src 'self'; frame-ancestors 'none';
  script-src 'self' 'nonce-<n>'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;
  connect-src 'self'`. Scripts are **already nonce-based** (4 `<script>` tags, all nonce-tagged;
  0 inline handler attributes — event wiring is a delegated `data-click`/`data-change`/
  `data-input` layer built specifically for this, `index.html:5340`). Styles require
  `'unsafe-inline'` because of the 5 `<style>` blocks **and** pervasive JS
  `el.style.display = …` writes. Nonce = 16 random bytes hex; on entropy failure it fails
  closed to `""`.
- **Other headers**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `X-XSS-Protection`, `Referrer-Policy: strict-origin-when-cross-origin`. **No HSTS**, no
  `Permissions-Policy`, no CSP reporting.
- **Middleware chain** (`ui.go:100`): `withAdminPanicRecovery(uiIPGuardMiddleware(
  securityMiddleware(uiAuthMiddleware(uiMetadataEnforcement(mux)))))`.
- **CSRF = Origin/Host comparison only** on POST/PUT/DELETE (`ui_middleware.go:174–178`); no
  token, no double-submit. Requests with **no Origin header pass** (deliberate, for CLI).
  Defense rests on `SameSite=Strict`. **`PATCH` is not in the mutating set** — it would bypass
  CSRF, the 1 MiB body cap, and rate limiting (no PATCH routes exist today).
  Note: the SPA sends `X-CSRF-Token: (window.csrfToken || '')` on 9 MCP fetch sites, but
  `window.csrfToken` is never assigned — the header is always empty and enforces nothing.
- **Body limit** 1 MiB and **rate limit** (60/min/IP, fixed window) apply to mutating `/api/*`
  only; **GETs are unlimited** (which is why `/api/backups` grew its own single-flight cache,
  `backups_api.go:90–101`).
- **Session**: `ps_ui_session` cookie — HMAC-SHA256 signed payload `{Sub, Provider, Role, Exp,
  Jti}`, HttpOnly, `SameSite=Strict`, dynamic `Secure` from `isSecureRequest` (TLS or
  `X-Forwarded-Proto: https`), TTL clamped 15 min–7 d, per-token + per-user revocation persisted
  and cluster-gossiped. 401s are issued **without** `WWW-Authenticate` to suppress the native
  browser dialog. Basic Auth accepted as a CLI fallback.
- **RBAC**: admin(3) > operator(2) > viewer(1). Enforced twice: the C2 metadata middleware
  (enforce-by-default, `CULVERT_C2_ENFORCE` kill switch) and handler-level `requireRole`
  (defense-in-depth backstop). Role reaches the frontend via `GET /api/auth/status`
  → `{loggedIn, user, role}`.
- **First-admin setup**: while `!cfg.IsConfigured()` every request gets `RoleAdmin` injected
  (`ui_middleware.go:257–261`); `GET /api/setup/status` → `{needsSetup}`;
  `POST /api/setup/complete` validates complexity, rolls back on persist failure, auto-logs-in.
  Login pre-setup is refused (session pre-minting defense, `ui_auth.go:113–148`).
- **TOTP**: two-step **in-band on `/api/auth/login`** (`{totp_required:true}` → re-POST with
  code); replay-protected via stored counter; backup codes bcrypt-hashed. **The SPA has zero
  TOTP UI** and there is **no enrollment endpoint**; `/api/auth/totp*` sits in the public-path
  allowlist with no registered handler (dead entry, `ui_middleware.go:232–242`).

### Gaps discovered during this audit (backend, pre-existing — not caused by the frontend)

| ID | Finding | Anchor |
|---|---|---|
| GAP-1 | The C2 metadata index files Go-1.22 `{param}` wildcard paths under their literal `{id}` string, so the **10 wildcard routes never match**; e.g. `/api/support/bundles/<id>/approve` falls to the public `/` catch-all and skips the C2 metadata-enforcement layer. Stated precisely: a **C2 metadata-enforcement (defense-in-depth) bypass, not a proven authentication bypass** — handler-level `requireRole` still gates every affected handler. Tracked as work item SEC-C2. | `ui_metadata_enforcement.go:179–200` |
| GAP-2 | `/api/auth/totp*` public-allowlist entry has no handler; no TOTP enrollment API exists | `ui_middleware.go:232–242` |
| GAP-3 | No HSTS on the admin UI despite HTTPS-by-default; `Secure` cookie flag drops on self-sign failure or a proxy that omits `X-Forwarded-Proto`. **Partially narrowed on main (2026-08-22)**: the self-sign→plain-HTTP fallback is no longer *silent* — `ui_tls_fallback`/`ui_tls_fallback_reason` are exposed pre-auth on `/api/setup/status` + `/api/auth/status` and the legacy SPA renders warning banners on setup/login/in-app. The HSTS and header-trust halves remain open (SEC-HSTS / SEC-PROXY). | `ui.go`, `ui_session.go:16–18` |
| GAP-4 | `PATCH` outside `isMutating` (CSRF/body-cap/rate-limit bypass if ever routed) | `ui_middleware.go:174` |
| GAP-5 | `isSameOrigin` and `isSecureRequest` trust `X-Forwarded-Host`/`X-Forwarded-Proto` unconditionally (no trusted-proxy gate, unlike `realClientIP`) | `ui_middleware.go:216`, `ui_session.go:17` |
| GAP-6 | `mcp-rollout` nav item has no `viewMeta` entry → topbar renders the raw slug | `index.html:5958–6010` |
| GAP-7 | Keyboard shortcut map contains `'4': 'log'` — no such view exists | `index.html:5920` |
| GAP-8 | `describeLogPersistence` returns an `<svg>` string in one branch but callers use `textContent` → renders literal markup | `index.html:8130–8145` |
| GAP-9 | **SETUP-OPEN-MODE**: `POST /api/setup/complete {unauth:true}` flips the appliance to configured (`defaultAuthOutcome=Exempt` ⇒ `IsConfigured()` true) without creating any UI admin — from that moment `uiAuthMiddleware` demands a session/Basic credential that no in-band path can mint, so in-band management authentication is unavailable and recovery requires OOB appliance-shell access (`-user/-pass` / `auth.user` YAML / `--reset-password`). The legacy wizard never exposes the option; the v2 UI deliberately WITHHOLDS it (FE-3). Backend/product decision pending: either the setup API should refuse `unauth:true` without a credential, or the option should require/co-create an admin identity. | `ui_auth.go:505-511`, `store.go:596-600`, `ui_middleware.go:254-296` |

These are recorded here for visibility; fixing them is backend scope and is sequenced in the
migration plan where the new frontend depends on them (GAP-1 especially).

## 4. Application architecture (as-built)

- **One global script scope**, no modules, no components. All 38 views exist in the DOM at load;
  `switchView(name)` toggles `.active` and runs a flat ~25-branch `if` ladder of `loadX()` calls
  (`index.html:6054–6118`).
- **State**: ~158 top-level mutable globals — session (`uiRole`, `uiUsername`,
  `window.currentRole`), routing (`currentView`, `viewMeta`, `viewLeaveGuards`), connection
  (`sseConnected`, `_sseInstance`, `_tickInterval`…), dialogs (`_confirmResolver`,
  `_modalStack`, `mcpxDlg`), and per-panel caches (`polRules`, `blEntries`, `logEntries`,
  `cdrState`, `releaseCatalog`, …). MCP adds ticket/generation counters for race handling.
- **Rendering**: two coexisting styles. Main script: escaped-`innerHTML` template strings
  (327 assignments; `escHtml` escapes `& < > "` — not `'`). MCP script (lines 18898–21563):
  pure `createElement`/`textContent` via `mcpxEl()` (375 calls), **zero innerHTML**. Seven
  `innerHTML` sites interpolate without `escHtml`, all numeric/static values today.
- **API access**: two wrappers — `api()` (`:8086`: JSON body handling, 401 → login overlay +
  throw, error = thrown response text) and `apiFetch()` (raw Response) — plus 26 raw `fetch`
  sites. **189 distinct endpoints** consumed (188 `/api/*` + `/proxy.pac`).
- **Polling**: one main 3 s `tick()` (`:13282–13322`) fetching `/api/stats` + `/api/timeseries`
  + `/api/requests` unconditionally plus per-view extras; auto-pauses after 20 consecutive
  errors and resumes only on SSE `connected`. Two secondary loops: webhook delivery history
  (15 s, Settings-gated) and release dispatch status (recursive 2.5 s, phase-gated).
  `document.visibilityState` is never consulted — **polling continues in background tabs**.
- **SSE**: one `EventSource('/api/events')` (`:12239`), jittered exponential backoff
  (2 s·1.5ⁿ capped 30 s, ±25%), **hard cap 30 retries then permanent give-up until reload**;
  drives the LIVE/STALE pill and dashboard counters. Server side: 256-client cap, slow-client
  eviction, per-frame 10 s write deadline, **mid-stream re-auth every ~60 s**.
- **Routing**: hash-based and MCP-only; the other 37 views have no URL representation — not
  bookmarkable, no back-button.
- **Dialogs**: shared stack-managed `#confirm-dialog` (`confirmAction` ×54 / `confirmDanger`
  ×9 typed-word / `promptAction` ×7) + a separate hardened MCP danger dialog (typed phrase,
  double-submit guard, ticket supersede, "state is UNKNOWN" copy). **Six legacy modals bypass
  the stack** (raw `style.display`, no focus trap/Esc): `#user-modal`, `#idp-modal`,
  `#add-group-modal`, `#add-bw-modal`, `#enroll-modal`, `#ca-instructions-modal`. **Five native
  `prompt()`/`confirm()` sites survive**, all in the support-recipient / MCP-draft flows —
  including a support-bundle **passphrase entered via native `prompt()`** (`:16510`).
- **Role-dependent UI**: `data-min-role` display-hiding (123 elements; hidden, never disabled,
  handlers stay live in the dispatcher) + 39 imperative `uiRole` guards + render-time
  capability flags. Server RBAC is the real boundary.
- **Validation**: 94 `required`, numeric bounds, zero `pattern=` attributes; JS regexes for
  IP/CIDR/token/case-ID/hex-secret shapes; feedback almost entirely `toast('…','error')` — only
  login/setup have inline error slots; no `aria-invalid`.
- **Drafts / unsaved state**: server-backed policy draft (commit/revert + multi-admin actor
  warning); pure-client staged rule order (version-fenced, deliberately unguarded on leave);
  a single dirty guard (`viewLeaveGuards` has exactly **one** entry: `policy`) — every other
  editor silently loses state on navigation; ~10 chip/list editors that mutate an in-memory
  array and POST it whole; the MCP candidate policy textarea (explicitly never persisted).
- **Browser storage**: exactly one `localStorage` key — `culvert-theme` (`:5885–5899`). No
  sessionStorage/IndexedDB/JS-cookie access anywhere.
- **Accessibility**: 178 `role=` attributes, 32 `aria-live` regions, keyboard shortcuts 1–8,
  keydown activation for `[data-click][role="button"]`, focus-trap on stack modals only; no
  `inert` behind modals; contrast never formally audited (M1-M2-SELF-REVIEW M4); charts have no
  non-visual alternative (M5).
- **Charts**: 2 canvases, both dashboard-only (`rateChart` time series, `breakdownChart`
  doughnut), theme-aware via CSS custom properties; all other visualizations are hand-rolled
  divs.

## 5. Views, panels, and workflows

38 nav items ↔ 38 `data-view` panels in 8 sidebar sections (Overview, Monitor, MCP Gateway,
Policies, Objects, Platform, Administration). The authoritative per-view table — with feature
IDs, endpoints, roles, mutating/destructive classification, audit expectation, polling/SSE
dependencies, current test coverage, and migration risk — lives in
`FRONTEND-FEATURE-PARITY.md`, which is the parity gate for the migration. Summary counts:

- **Modals/wizards**: 6 stack-managed + 6 legacy non-stack + 2 full-screen overlays
  (login, setup) + 3 MCP drawers.
- **Destructive operations**: 9 Tier-3 typed-word confirmations (blocklist↔allowlist mode,
  default-auth outcome, session-key rotation, admin IP allowlist, PAC DIRECT bypass, cluster CA
  import, enable CP, enable HA, promote leader), ~54 Tier-1/2 confirms, plus the MCP danger
  dialog family (kill switch, emergency, rollback, transitions). Root-CA rotation is a
  **two-phase server-token ceremony** (probe → server warning + `confirmation_token` →
  confirm). Two destructive/high-impact flows currently ship **without** any confirm:
  `POST /api/releases/dispatch` (upgrade dispatch!) and custom-cert upload.
- **Security-sensitive workflows**: login, first-admin setup, session secret rotation,
  session timeout, admin IP allowlist, CA download/instructions/rotate/cache-clear, cert
  upload, cluster CA import, enrollment tokens, HA/CP enable + promote, config
  export/import(dry-run)/versions/rollback, release dispatch + resume + catalog refresh,
  maintenance-agent backups readout, support bundles (create/approve/validate/manifest/
  redaction-report/sealed+encrypted download/upload/recipients/telemetry), MCP four-eyes
  approvals + rollout ceremonies, blocklist mode flip, default-auth outcome.

## 6. Backend contracts the frontend consumes (keep — authoritative)

- **Routes**: 229 `uiRoutes` entries / **343** method rows (GET 146, POST 114, PUT 35,
  DELETE 32, MethodAny 16; viewer 147, admin 115, operator 66, public 15; mutating 182;
  audit-expected 162), count-locked by C1 + D0 tests. (An earlier draft said 344 — that
  figure counted a `{Method:` occurrence inside a comment at `ui_routes_meta.go:80`; the
  structured count is 343 and matches `api/route-classification.yaml` 1:1. The full generated
  accounting table lives in `FRONTEND-SECURITY-CONTRACT.md` §7.) Route additions
  are a four-place change (registration, `ui_routes_meta.go`, `d0KnownRoutes`,
  `api/route-classification.yaml`) + `make api-bundle`.
- **OpenAPI (ADR-0018)**: `api/openapi/openapi.yaml` (11,049 lines, 221 paths, ~570 schemas),
  deterministic committed `openapi.json`, offline docs pages, and
  `api/route-classification.yaml` binding **334 of 343** method rows as documented (9 exempt
  with owners + expiry ≤ 2027-01-31). Ten Go-native CI gates keep it in lockstep with
  `uiRoutes`. **Errors are `text/plain`**, not a JSON envelope — a typed client must model
  `(status, text)`.
- **Governance surface**: `GET /api/governance/control-plane` returns the live route inventory
  + C2 counters — the natural data source for a permissions/route-explorer screen.
- **Diagnostics**: `GET /api/diagnostics` → `OperatorContract` (stable snake_case `code`s,
  `status`, `operator_action`); `POST /api/diagnose/{storage,upstream,dns,tls,cluster,etcd,
  config,support,all}` — versioned typed JSON (`schema_version: 1`), fixed verb registry.
- **Config versioning**: list/diff/rollback with `dry_run`, the explicit
  "applied-but-not-persisted" partial-failure state, `runtime_only_surfaces`, and
  password-hash exclusion — all states the UI must render distinctly.
- **Config surface registry**: Export / Import / Rollback / AdminDurable / ClusterSynced /
  Sensitive are **independent per-field memberships** (`config_surfaces.go`); the UI must not
  present them as one uniform "configuration" concept (secrets are dropped from exports by
  construction; import-merge never wipes; rollback can wipe; `RequireCommit` is deliberately
  off the rollback surface).
- **SSE contract**: `event: connected` handshake, 1 Hz JSON dashboard payload, 503 +
  `Retry-After: 30` at the 256-client cap, eviction-close semantics, 60-message re-auth.
- **Release management**: viewer-readable catalog with explicit `available:false` +
  `verify_mode`/`trust_schemes` degraded states; admin-only async dispatch (202 + `op_id` poll +
  resume); the maintenance agent is reached only via dispatch and read-only `/api/backups`.

## 7. Test surface today

- **Backend contract suites (keep, untouched)**: D0 (route inventory locked at 229, auth
  allowlist, CSRF/body/rate), C1/C1.5 (metadata↔mux↔handler parity), C2/C2c (enforcement +
  audit observability), C4 (role divergence), C3 governance, `config_surfaces_test.go`,
  `apicontract_*` (10 OpenAPI gates), `data_surfaces_test.go`.
- **Markup-pinned Go tests (replacement candidates)**: ~23 disk-scan sites
  (`ui_redesign_foundation_test.go`, `ui_danger_quiet_test.go`,
  `pac_exceptions_uicontract_test.go`, `authpolicy_phase*_test.go`,
  `ui_idp_secret_redaction_test.go`, `policy_learning_m5*_test.go`,
  `decryptprofile_cert_contract_test.go`) + 6 HTTP shell-scan "GUI parity" tests
  (`release_gui_test.go`, `saas_feed_gui_test.go`, `support_upload_gui_test.go`,
  `decexcl_tunables_gui_test.go`, …). All are `strings.Contains`/regex scans of raw HTML. Some
  pin **intent worth re-expressing** (no inline handlers, air-gapped assets, no native dialogs,
  typed-confirm coverage, GUI↔runtime enum lockstep in
  `decryptprofile_cert_contract_test.go`); most pin incidental markup. Disposition per test in
  `FRONTEND-MIGRATION-PLAN.md` §Test Migration.
- **Browser E2E**: 32 playwright-go specs behind `//go:build uie2e`, mounted **in-process**
  over `httptest` (never against the real binary), 100% `#id` selectors, advisory-only
  (`proxy-ui-e2e.yml` is `continue-on-error: true`, nightly + path-filtered PRs; the path
  filter hardcodes `static/index.html`).
- **Test hygiene wall**: `static_read_wall_test.go` forces all HTML reads through
  `staticIndexHTMLPath()`; `qualification_manifest_test.go` asserts roadmap-cited test names
  still exist — renaming cited UI tests requires updating the citing roadmap doc.

## 8. Build/CI facts that bind the new frontend

- `pr-fast-gate.yml` hygiene builds the binary twice (static assert + arm64 cross-compile) —
  any frontend build must precede these or `dist` must be committed.
- `pr-deep-gate.yml` **determinism job builds release binaries twice and sha256-compares** —
  the embedded bundle makes Vite determinism a hard requirement either way.
- `ci.yml` release image is built by `docker/build-push-action` from `context: .` for
  amd64+arm64 with provenance + SBOM — a non-committed dist requires a pinned Node stage
  **inside the Dockerfile**.
- `go-licenses` covers Go only; npm licenses/vulns are unscanned today. `.dockerignore` and
  `.gitignore` have no `node_modules` entries. gitleaks runs on every PR and will need an
  allowlist review for lockfiles/bundles.
- `proxy-ui-e2e.yml`'s PR path filter must gain the new frontend paths.

## 9. Stale-document verdicts

| Document | Verdict |
|---|---|
| `docs/UI_REFACTOR_AUDIT.md` | Historical, correctly self-labeled (Go-side refactor; shipped). No action. |
| `docs/design/CURRENT-UI-AUDIT.md` | Facts stale (~1.8× growth since measured); §6 contracts inherited by this program. Marked superseded-as-audit. |
| `docs/design/REDESIGN-ROADMAP.md` | M1–M2 shipped, M3 partial, M4–M5 open. **Holds the primary prose "no framework" position — superseded by ADR-FE-001.** Marked. |
| `docs/design/INFORMATION-ARCHITECTURE.md` | Nav tree + migration table stale (self-annotated; also misses `policylearn`). Rationale and §5 settings split inherited. |
| `docs/design/DESIGN-SYSTEM.md` | Largely implemented; tokens + component contracts inherited as the seed of the new design system. |
| `docs/design/UX-PRINCIPLES.md` | **Current — the design constitution.** Inherited unchanged; gates redesign PRs. |
| `docs/design/PRODUCT-TERMINOLOGY.md` | Current minus the legacy `Update` row; needs MCP/decryption/learning/support terms. |
| `docs/design/SCREEN-SPECS.md` | Shipped for its 5 screens; keep the `[E]/[U]/[B]/[F]` legend convention. |
| `docs/design/M1-M2-SELF-REVIEW.md` | Live defect register (H1 modal nesting *partially* addressed — 6 legacy modals remain; M4 contrast, M5 chart a11y, M6 `style-src unsafe-inline`, M7 single confirm-resolver all still open). Inherited as backlog input. |
| `docs/design/M2-IMPLEMENTATION-REPORT.md` | Header stale ("awaiting review" — the work is in main); content accurate. |
| `docs/design/POLICY-DRAFT-DESIGN.md` | Current, implemented; §9 is a live UI spec the new frontend must honor. |
| `docs/design/POLICY-ARCHITECTURE-FUTURE.md` | §5's render-ceiling finding (whole-tbody innerHTML on the 3 s tick, ~200–300 rules before jank) is a design input for the new policy table. |
| `docs/design/OBJECT-REFERENCES-BY-ID.md` | Header stale ("pre-implementation" but S2 shipped); §9 UI implications inherited. |
| `roadmap/UI-DESIGN.md` | Stale (27 of 38 panels). Historical. |
| `roadmap/FEATURE-COVERAGE.md` | Near-current (misses `policylearn`); superseded as the parity source by `FRONTEND-FEATURE-PARITY.md`. |
