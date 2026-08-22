# Frontend Security Contract

- **Status**: Accepted with ADR-FE-001 (2026-08-21, external architecture review corrections
  incorporated). These are the security invariants the replacement frontend and its
  static-serving layer MUST preserve or strengthen. Anything that weakens a row needs its own
  ADR. Anchors refer to current code; a contract that targets a *change* is marked
  **[STRENGTHEN]**.
- The UI is **not** an authorization boundary. `uiRoutes` metadata + C2 middleware +
  handler-level `requireRole` remain authoritative (CLAUDE.md invariants #1–#7). Everything
  the frontend does with roles is presentation.

## 1. Session & authentication

| # | Invariant |
|---|---|
| S1 | The `ps_ui_session` cookie remains HttpOnly + `SameSite=Strict`, HMAC-signed server-side; **JavaScript never reads, writes, or is able to read session material**. The new app must not introduce `document.cookie` access. |
| S2 | All requests use the browser's default same-origin credential behavior. The client never sets `credentials: 'include'` semantics beyond same-origin and never adds `Authorization` headers from browser-stored secrets. |
| S3 | 401 handling is centralized and triggers the **authentication-boundary teardown** (§6.4): any 401 → present login after full teardown; never loop. Session expiry mid-SSE terminates the stream server-side (60-message re-auth) — the client treats stream termination + 401 on next request as expiry, not an error to retry blindly. **Sensitive application state does not survive the boundary** — only non-sensitive route intent (which screen to return to) and the theme preference may persist across re-authentication. |
| S4 | Login remains a 2-step in-band TOTP flow: `{totp_required:true}` (no cookie) → re-POST with code. The new login form implements this state machine; no TOTP secrets ever render client-side. (TOTP *enrollment* UI is out of scope until the backend gains an enrollment API — GAP-2; the screen is descoped, not faked.) |
| S5 | First-admin setup: the client mirrors password complexity for UX only; the server check is authoritative. The setup form handles the rollback-on-persist-failure 500 (retryable) and the pre-setup login refusal. The unauth/Exempt option keeps its explicit warning copy. |
| S7 | **Pre-auth TLS-fallback warning** (main, 2026-08-22): when `/api/setup/status` or `/api/auth/status` reports `ui_tls_fallback: true`, the setup and login screens (and the in-app shell) MUST render the plain-HTTP warning with `ui_tls_fallback_reason` BEFORE any credential is submitted. The new frontend carries this capability from FE-3 onward; it must never be lost in migration. |
| S6 | Logout always POSTs `/api/auth/logout` (server-side revocation), then runs the §6.4 teardown. Never "log out" by discarding state alone. |

## 2. CSRF

| # | Invariant |
|---|---|
| C1 | CSRF protection is server-side Origin/Host comparison on mutating methods. The frontend contract: **all mutations go through the typed API client**, which uses only `POST`/`PUT`/`DELETE` (never `PATCH` until SEC-PATCH lands and is contract-tested) and lets the browser send `Origin` naturally. |
| C2 | The vestigial empty `X-CSRF-Token` header (9 MCP call sites, token never set) is **dropped**, not cargo-culted into the new client. A token scheme, if ever wanted, is a backend ADR. |
| C3 | The new app never proxies or forwards admin API calls cross-origin and never needs `Access-Control-Allow-Credentials` (the server does not set it; keep it that way). |

## 3. CSP & the nonce decoupling

| # | Invariant |
|---|---|
| P1 | **The new application requires no nonce and no per-request HTML mutation**: zero inline scripts, zero inline styles, zero runtime style injection, no `__CSP_NONCE__` placeholder, no index-rewriting build plugin. The production bundle loads only external same-origin hashed assets. |
| P2 | **Route-specific CSP during parallel development.** Legacy UI (`/` until cutover): preserves the existing nonce policy and `style-src 'unsafe-inline'` temporarily, unchanged. New UI (`/app/` preview, then `/` at cutover): `default-src 'self'; script-src 'self'; script-src-attr 'none'; style-src 'self'; style-src-attr 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; connect-src 'self'`. No `unsafe-inline`, no `unsafe-eval`, no wildcard, no external origin — ever. |
| P3 | At final cutover the legacy nonce generation (`cspNonce`) and shell substitution (`serveUIShell` ReplaceAll) are **removed** with the legacy UI. `X-Frame-Options: DENY` and the other existing headers stay. |
| P4 | A production-browser CSP proof (zero violations) gates FE-1B, FE-2 (component gallery incl. the Chart.js decision), and FE-8 (full app). Tooling that would force inline output (preload polyfills, dev-only injection reaching the prod bundle, chart/style libraries writing element styles) is fixed or rejected — CSP is never loosened to accommodate a library. |
| P5 | No service worker, no PWA manifest, no cross-origin prefetch. Reopening requires an ADR (stale-UI-across-upgrade hazard). |
| P6 | **[STRENGTHEN]** HSTS is a separate backend decision (work item SEC-HSTS) covering self-signed bootstrap, IP access, custom certs, direct TLS, and trusted reverse proxies; no `preload`/`includeSubDomains` by default. It is not treated as a trivial frontend header. |

## 4. Inline-style ban (dynamic visual state)

Trusted constants, CSS custom properties, and dynamically created elements **do not bypass
CSP**: any write to an element's style is inline styling regardless of the value's provenance.

| # | Invariant |
|---|---|
| Y1 | Banned everywhere in the new app: React `style={...}`; `element.style.*` writes; `style.setProperty(...)`; `setAttribute("style", ...)`; runtime CSS injection (`insertRule` into constructed sheets attached at runtime, `<style>` element creation); and **any library that requires inline style mutation** (grounds for rejection at dependency review, including the Chart.js FE-2 gate). |
| Y2 | All dynamic visual state is expressed through: class toggling, `data-*` attributes, semantic HTML attributes (e.g. `hidden`, `disabled`, `open`, canvas `width`/`height`), and **predeclared CSS selectors** that match those states. Value-continuous state (progress %, chart geometry) is handled by predeclared classes/steps, SVG geometry attributes, or canvas drawing — not element style. |
| Y3 | Enforcement is layered: ESLint rules (`react/forbid-dom-props` for `style`, `no-restricted-properties`/`no-restricted-syntax` for the DOM forms), a production-bundle scan (no `style=` attributes, no `<style>` tags in emitted HTML/JS output), and the §3.P4 runtime CSP browser tests (`style-src 'self'` + `style-src-attr 'none'` makes every violation observable). |

## 5. RBAC presentation

| # | Invariant |
|---|---|
| R1 | Role from `GET /api/auth/status` drives navigation/route guards and control visibility; a 403 from any call is handled gracefully (toast + state refresh) because the server is authoritative and the client may be stale. |
| R2 | Hidden ≠ disabled ≠ removed is deliberate: destructive/admin controls are **not mounted** for insufficient roles (today they are display-hidden with live handlers). Viewer-facing read-only views render without mutation affordances. |
| R3 | The parity matrix's per-view minimum roles are the UI floor; per-endpoint roles in `uiRoutes` are the truth. Any new route follows the four-place backend registration convention + OpenAPI classification. |

## 6. Server-state layer (TanStack Query security profile) — mandatory defaults

| # | Invariant |
|---|---|
| Q1 | **Mutations**: `retry: false`, always. **No optimistic updates** for policy, identity, certificates, cluster, releases, support bundles, MCP, or any other security configuration — an optimistic workflow anywhere in those domains requires its own reviewed design. |
| Q2 | **Queries**: no retry on 400/401/403/404/409/422. Bounded retries (small count, jittered) only for classified network failures and selected 5xx. `refetchOnWindowFocus: false` by default. **No offline queue. No persistence plugin** — the cache is in-memory only. |
| Q3 | **Sensitive query data** (secret-adjacent responses, support-bundle material, credential-bearing config, TOTP flow state): `gcTime: 0` or explicit immediate removal on workflow completion; never retained after the workflow ends; never emitted to production logs or devtools (devtools excluded from production builds); where a one-shot local request is safer than the shared cache, use a plain client call outside the cache. |
| Q4 | **Authentication-boundary teardown** — on 401, logout, user change, or role change, in order: cancel all in-flight requests; clear the entire query cache; close the SSE connection; stop all timers and polling; revoke outstanding Blob URLs; clear secret-bearing forms and configuration candidates (policy drafts held client-side, MCP candidate text, staged reorders). Only non-sensitive route intent and the theme preference survive. This corrects the earlier draft's "preserve in-memory app state" statement — sensitive data and drafts must not cross an authentication boundary. |
| Q5 | Polling is owned by hooks tied to route + `document.visibilityState`; no timer survives navigation; mutating endpoints are never polled; client cadences no faster than today's (3 s dashboard, 15 s history, 2.5 s dispatch-in-flight) since GETs are server-side unlimited by design. |

## 7. Runtime response safety (typed boundary)

Generated TypeScript types (`types.gen.ts`) are **compile-time only**. The runtime boundary
for every API interaction is:

```
fetch → status validation → Content-Type validation → parse as unknown
      → endpoint adapter/decoder → typed domain object
```

| # | Invariant |
|---|---|
| T1 | Feature components never cast unchecked JSON (`as SomeType` on a parse result is banned; `any` is banned — both by lint + `tsc` strict config). All decoding lives in `src/api/` adapters. |
| T2 | Errors are modeled as `(status, text)` — the contract documents `text/plain` errors; the client renders the text as text, bounded in length, and never invents a JSON error schema. |
| T3 | Explicit runtime decoders/guards are **mandatory minimum** for: auth status + login/TOTP state; setup status/complete; policy draft + version-fencing responses; Root-CA rotation token responses; release operation state (`op_id` lifecycle, `available:false` variants); MCP ticket/transition state; config import (dry-run preview) + rollback (partial-failure, `runtime_only_surfaces`); support-bundle lifecycle. Malformed responses on these paths render an explicit error state, never a crash or a silently-wrong screen. |
| T4 | Decoders are total: unknown fields ignored, missing/invalid required fields → typed decode error surfaced through the standard error path. |

### Route/OpenAPI accounting (regenerated from the live repo, 2026-08-22 — post-FE-1B)

The FE-1B embedded-serving round added the three v2 static routes (`/app`, `/app/`,
`/assets/` — MethodAny, RolePublic, exempt `non-rest-surface`); the structured count is
**346**, in exact 1:1 parity with `api/route-classification.yaml` (zero rows on either side
without a counterpart — enforced by the route-coverage gate, green on this checkpoint):

| Quantity | Count | Notes |
|---|---|---|
| Registered method policies (`uiRoutes`, 232 routes) | **346** | GET 146, POST 114, PUT 35, DELETE 32, MethodAny 19 · viewer 147, admin 115, operator 66, public 18 · mutating 182, audit-expected 162 |
| Classification manifest rows | **346** | 1:1 with uiRoutes (gate-enforced projection) |
| Non-OpenAPI / non-REST rows (exempt, `security_class: non-rest-surface`) | **12** | `/` (legacy SPA shell), `/app` + `/app/` + `/assets/` (FE-1B v2 shell + hashed assets), `/api/events` (SSE), `/api/idp/` + `/api/cluster/bootstrap/` (dynamic sub-routers), `/auth/logout`, `/auth/oidc/callback`, `/auth/saml/callback`, `/auth/saml/metadata`, `/auth/select` (browser SSO flows) |
| OpenAPI-applicable rows | **334** | 346 − 12 |
| Documented rows | **334** | 100% of applicable rows |
| Exempt rows | **12** | all non-REST, owner + expiry recorded |
| Frontend-consumed exempt rows | **6** | `/` (legacy shell), `/app` + `/app/` + `/assets/` (the v2 app itself — HTML shell + hashed assets, browser navigations/loads, not XHR), `/api/events` (future SSE hook), `/api/idp/` (IdP item/groups sub-router — needs a hand-authored type + decoder). `/auth/*` are browser navigations the SPA links to, not XHR; `/api/cluster/bootstrap/` is not consumed by the SPA. |

Consequence: `types.gen.ts` covers every JSON XHR surface except the `/api/idp/` sub-router
(hand-authored types + decoder) and the SSE payload (hand-authored decoder in the SSE hook).

## 8. Destructive-operation ceremonies

| # | Invariant |
|---|---|
| D1 | The three-tier confirmation system is a design-system component (`ConfirmationDialog`): Tier 1/2 styled confirm with impact copy; Tier 3 typed-word gate. The 9 existing Tier-3 ceremonies migrate word-for-word. |
| D2 | The two-phase Root-CA rotation (probe `{confirm:false}` → server `warning` + `confirmation_token` → confirm with token) is preserved exactly; the client never invents the token. |
| D3 | The MCP danger-dialog semantics migrate intact: typed phrase, double-submit guard, Esc blocked while committing, ticket/supersede classification, explicit "action state is UNKNOWN" copy on network failure, `production_locked`/`self_approval` surfacing. |
| D4 | **[STRENGTHEN]** Two currently-unconfirmed high-impact actions gain ceremonies: `POST /api/releases/dispatch` (Tier 3) and custom-cert upload (Tier 2 with impact copy). |
| D5 | Native `window.confirm`/`prompt`/`alert` are banned (ESLint), replacing the 5 remaining sites; the support-bundle passphrase moves to an in-app masked dialog (§9.B4). |
| D6 | Tier-3 dialogs never confirm on Enter; the typed word gates the button. Result states (ok/warn/crit/unknown) render explicitly; a network error after submit is presented as unknown-state, never success or silent failure. The FE-7 mutation suite proves these properties per ceremony. |

## 9. Browser state & secrets

| # | Invariant |
|---|---|
| B1 | Browser storage policy: **exactly one persistent key** — the theme (`localStorage['culvert-theme']`). Nothing else persists: no tokens, no drafts of security config, no API responses, no form autosaves of secret fields. `sessionStorage`/IndexedDB stay unused. |
| B2 | Secret-bearing fields (IdP client secrets, LDAP bind passwords, webhook credentials, PEM keys, passphrases) are write-only: rendered empty with a redaction indicator, cleared only on explicit user action (preserving the explicit-clear checkbox semantics pinned today by `ui_idp_secret_redaction_test.go`, re-expressed as component tests). `autocomplete` hardened on such fields. A submitted secret is never echoed into the DOM. |
| B3 | Sensitive API responses are rendered, not retained (§6.Q3). |
| B4 | Passphrase entry uses an in-app masked dialog; the value lives only in component state for the duration of the request. |
| B5 | All server strings render as text (React text nodes / `textContent`). `dangerouslySetInnerHTML` is banned by ESLint with an empty exception list. This retires the escaped-`innerHTML` pattern and its `escHtml` single-quote caveat wholesale. |

## 10. Static serving & fallback (hardened contract — implemented in FE-1B)

| # | Invariant |
|---|---|
| V1 | Resolution order, exactly: (1) existing generated asset → serve it; (2) unknown path under the asset namespace → **404** (a missing `.js`/`.css`/image/font never falls back to HTML); (3) known reserved route (`/api/*`, `/auth/*`, `/healthz`, `/metrics`, `/proxy.pac`, `/pac/*`, future reserved namespaces — the test derives the set from the live route inventory) → normal server routing; (4) unknown **GET/HEAD** UI path → SPA shell; (5) unknown **mutating** method → 404/405, never the shell. |
| V2 | Shell `Cache-Control: no-store`; hashed assets `public, max-age=31536000, immutable`; fixed MIME allowlist; correct HEAD behavior; path traversal rejected (stdlib `http.FS`); no directory listing; **`manifest.json` and sourcemaps are never publicly served** (production sourcemaps are disabled at build); explicit base-path behavior for `/app/` (preview, flag-gated, default-off) and `/` (cutover). |
| V3 | Invalid/corrupt embedded frontend ⇒ **frontend subsystem unavailable**: explicit 503 with plain diagnostic on UI routes, readiness reports control-plane degradation, one critical structured log + metric; the proxy data plane continues on last-known-good configuration. A process-wide startup failure for a frontend asset problem is prohibited without its own ADR. |
| V4 | The public path set is owned by `uiAuthMiddleware` (`isPublicUIAuthPath`) and does not grow for frontend convenience. The SPA shell remains publicly served and contains no secrets (verified at FE-8 by shell-content review). The bootstrap window (pre-setup RoleAdmin injection) is respected as-is; the new setup flow creates no additional pre-auth surfaces. |

## 11. Uploads, downloads, streams, logging

| # | Invariant |
|---|---|
| U1 | File upload (certs, YARA rules, config import, CDR test) uses the existing endpoints with server-side validation; client `accept=` filters are UX only. Config import always runs the `dryRun=true` preview and shows the change summary before the destructive apply, preserving replace-vs-merge. |
| U2 | Downloads keep server-set `Content-Disposition` semantics; Blob URLs are revoked after use and at the authentication boundary; export redaction disclosure (secrets excluded by construction) is presented next to the action. |
| U3 | SSE: one EventSource, same-origin, jittered backoff preserved; the retry give-up becomes resumable (user-visible reconnect affordance); 503 + `Retry-After` honored; stream torn down on route unmount and at the authentication boundary. |
| U4 | Errors follow UX-PRINCIPLES: what failed / why / next action / current state. Distinct partial-failure states (rollback "applied-but-not-persisted", release `available:false` with reason, MCP unknown-state) each get distinct rendering — never a generic toast. Production builds never log secrets or full request bodies to the console. |

## 12. Backend security work items this contract references

Tracked as separate PRs in `FRONTEND-MIGRATION-PLAN.md` §3 (never bundled into FE-1A/FE-1B):

- **SEC-C2** — C2 metadata matching for `{param}` wildcard routes. Precisely: a
  **C2 metadata-enforcement bypass** (the defense-in-depth middleware layer is skipped for 10
  wildcard routes, which resolve to the public `/` catch-all), **not a proven authentication
  bypass** — handler-level `requireRole` still gates every affected handler. FE-8 cutover
  requires this landed.
- **SEC-PATCH** — `PATCH` joins the mutating-method classification (CSRF/body-limit/rate
  limit) with regression tests.
- **SEC-PROXY** — `X-Forwarded-Host`/`X-Forwarded-Proto` trusted only under the existing
  trusted-proxy doctrine; direct/trusted/spoofed test matrix.
- **SEC-HSTS** — separate decision + PR (see §3.P6).
- **GAP-2** — TOTP enrollment API (prerequisite for any account-security screen; otherwise
  descoped, not faked).
