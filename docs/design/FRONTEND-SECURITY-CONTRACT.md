# Frontend Security Contract

- **Status**: Proposed with ADR-FE-001 (2026-08-21). These are the security invariants the
  replacement frontend and its static-serving layer MUST preserve or strengthen. Anything that
  weakens a row needs its own ADR. Anchors refer to current code; where the contract targets a
  *change*, it is marked **[STRENGTHEN]**.
- The UI is **not** an authorization boundary. `uiRoutes` metadata + C2 middleware +
  handler-level `requireRole` remain authoritative (CLAUDE.md invariants #1–#7). Everything the
  frontend does with roles is presentation.

## 1. Session & authentication

| # | Invariant |
|---|---|
| S1 | The `ps_ui_session` cookie remains HttpOnly + `SameSite=Strict`, HMAC-signed server-side; **JavaScript never reads, writes, or is able to read session material**. The new app must not introduce `document.cookie` access. |
| S2 | All requests use the browser's default same-origin credential behavior (as `api()` does today). The client never sets `credentials: 'include'` semantics beyond same-origin and never adds `Authorization` headers from browser-stored secrets. |
| S3 | 401 handling stays centralized: any 401 → present login, preserve in-memory app state, never loop. Session expiry mid-SSE terminates the stream server-side (60-message re-auth) — the client treats stream termination + 401 on next request as expiry, not an error to retry blindly. |
| S4 | Login remains a 2-step in-band TOTP flow: `{totp_required:true}` (no cookie) → re-POST with code. The new login form must implement this state machine; no TOTP secrets ever render client-side. (TOTP *enrollment* UI is out of scope until the backend gains an enrollment API — GAP-2.) |
| S5 | First-admin setup: the client mirrors password complexity for UX only; the server check is authoritative. The setup form must handle the rollback-on-persist-failure 500 (retryable) and the pre-setup login refusal. The unauth/Exempt option keeps its explicit warning copy. |
| S6 | Logout always POSTs `/api/auth/logout` (server-side revocation), then clears client state. Never "log out" by discarding state alone. |

## 2. CSRF

| # | Invariant |
|---|---|
| C1 | CSRF protection is server-side Origin/Host comparison on mutating methods. The frontend contract: **all mutations go through the typed API client**, which uses only `POST`/`PUT`/`DELETE` (never `PATCH` — it is outside the server's `isMutating` set, GAP-4) and lets the browser send `Origin` naturally (same-origin fetches). |
| C2 | The vestigial empty `X-CSRF-Token` header (9 MCP call sites, token never set) is **dropped**, not cargo-culted into the new client. If a token scheme is ever wanted, that is a backend ADR. |
| C3 | The new app must never proxy or forward admin API calls cross-origin, and never needs `Access-Control-Allow-Credentials` (the server does not set it; keep it that way). |

## 3. CSP & asset serving

| # | Invariant |
|---|---|
| P1 | `script-src 'self' 'nonce-<per-request>'` is the floor. The Vite entry `<script>` tags in the served shell carry the nonce (the `__CSP_NONCE__` substitution contract in `serveUIShell` survives, applied to a now-small shell). No `unsafe-inline`, no `unsafe-eval`, no wildcard sources, no external origins — ever. Vite must be configured to emit **no inline module preload polyfill scripts without nonce** and no runtime `eval` (default esbuild output is fine; verify in the FE-1 gate). |
| P2 | **[STRENGTHEN]** `style-src` drops `'unsafe-inline'` at cutover: all styles ship as hashed `.css` assets; components toggle classes, not `el.style` (limited exceptions like chart canvas sizing use CSS custom properties or `style` on elements created from trusted constants — audited in review). This closes M1-M2-SELF-REVIEW finding M6. |
| P3 | `connect-src 'self'` stays (SSE and fetch are same-origin). `img-src 'self' data:` stays. `frame-ancestors 'none'` + `X-Frame-Options: DENY` stay. |
| P4 | Serving: hashed assets (`/assets/<name>-<hash>.<ext>`) get `Cache-Control: public, max-age=31536000, immutable`; the shell (`/` and the SPA fallback) stays `no-store`; correct MIME from a fixed extension table (embed FS has no mod-times). Unknown `/api/*`, `/auth/*`, `/healthz`, `/proxy.pac`, `/pac/*`, `/metrics` paths are **excluded from SPA fallback** (404/handler as today); all other unknown GET paths serve the shell so deep links work. Path handling stays on stdlib `http.FS` semantics (no custom traversal handling that could regress `..` rejection). |
| P5 | Missing/corrupt embedded assets fail loudly: the shell handler returns 500 with a plain diagnostic (never a blank 200 page, which is the current behavior when the embed read fails), and a startup check refuses to serve a build whose manifest references missing files. |
| P6 | No service worker, no PWA manifest, no prefetch of cross-origin anything. Reopening requires an ADR (stale-UI-across-upgrade hazard). |
| P7 | **[STRENGTHEN]** Add HSTS when TLS is active (GAP-3) — backend change, sequenced in FE-1. |

## 4. Browser state & secrets

| # | Invariant |
|---|---|
| B1 | Browser storage policy: **exactly one persistent key** — the theme preference (`localStorage['culvert-theme']`), carried over. Nothing else persists: no tokens, no drafts of security config, no API responses, no form autosaves of secret fields. The MCP candidate-policy "never enters localStorage" guarantee extends to *all* policy/config drafts. `sessionStorage`/IndexedDB stay unused. |
| B2 | Secret-bearing fields (IdP client secrets, LDAP bind passwords, webhook credentials, PEM keys, passphrases) are write-only in the UI: rendered empty with a redaction indicator, cleared only on explicit user action (preserve the explicit-clear checkbox semantics pinned by `ui_idp_secret_redaction_test.go` — re-expressed as component tests). `autocomplete="off"`/`new-password` on such fields. Never echo a submitted secret back into the DOM. |
| B3 | Sensitive API responses are rendered, not retained: no client cache layer may persist them (TanStack Query cache is in-memory only — no persister plugin). |
| B4 | Passphrase entry (support bundles) moves from native `window.prompt` to an in-app masked dialog; the value lives only in component state for the duration of the request. |
| B5 | Log/diagnostic rendering treats all server strings as text (`textContent` / React text nodes). No `dangerouslySetInnerHTML` anywhere in the app — enforced by ESLint rule; the sole sanctioned exception list starts empty. This retires the escaped-`innerHTML` pattern and its `escHtml` single-quote caveat wholesale. |

## 5. RBAC presentation

| # | Invariant |
|---|---|
| R1 | Role from `GET /api/auth/status` drives navigation/route guards and control visibility; a 403 from any call is still handled gracefully (toast + state refresh), because the server is authoritative and the client may be stale. |
| R2 | Hidden ≠ disabled ≠ removed is made deliberate: destructive/admin controls are **not mounted** for insufficient roles (today they are display-hidden with live handlers). Viewer-facing read-only views render without mutation affordances. |
| R3 | The parity matrix's per-view minimum roles are the UI floor; per-endpoint roles in `uiRoutes` are the truth. Any new route the frontend needs follows the four-place backend registration convention + OpenAPI classification. |

## 6. Destructive-operation ceremonies

| # | Invariant |
|---|---|
| D1 | The three-tier confirmation system is preserved as a design-system component (`ConfirmationDialog`): Tier 1/2 styled confirm with impact copy; Tier 3 typed-word gate. The 9 existing Tier-3 ceremonies (blocklist mode, default-auth outcome, session-key rotate, admin IP allowlist, PAC DIRECT bypass, cluster CA import, enable CP, enable HA, promote leader) migrate word-for-word. |
| D2 | The two-phase Root-CA rotation (probe `{confirm:false}` → server `warning` + `confirmation_token` → confirm with token) is preserved exactly; the client never invents the token. |
| D3 | The MCP danger-dialog semantics migrate intact: typed phrase, double-submit guard, Esc blocked while committing, ticket/supersede classification, explicit "action state is UNKNOWN" copy on network failure, `production_locked`/`self_approval` surfacing. |
| D4 | **[STRENGTHEN]** Two currently-unconfirmed high-impact actions gain ceremonies: `POST /api/releases/dispatch` (upgrade dispatch — Tier 3) and custom-cert upload (Tier 2 with impact copy). |
| D5 | Native `window.confirm`/`prompt` are banned (ESLint rule), replacing the 5 remaining sites. |
| D6 | Dialogs never auto-confirm on Enter for Tier 3; the typed word gates the button. Result states (ok/warn/crit/unknown) render explicitly; a network error after submit is presented as unknown-state, never as success or silent failure. |

## 7. Uploads, downloads, and streams

| # | Invariant |
|---|---|
| U1 | File upload (certs, YARA rules, config import, CDR test) uses the existing endpoints with their server-side validation; client `accept=` filters are UX only. Config import always runs the `dryRun=true` preview and shows the change summary before the destructive apply, preserving replace-vs-merge distinction. |
| U2 | Downloads (config export, CA cert, traffic export, support sealed/encrypted bundles, PAC) keep server-set `Content-Disposition` semantics; Blob URLs are revoked after use; export redaction disclosure (secrets excluded by construction) is presented next to the action. |
| U3 | SSE: one EventSource, same-origin, backoff with jitter preserved; the 30-retry give-up becomes resumable (user-visible reconnect affordance) instead of reload-only; 503 + `Retry-After` at the client cap is honored. Stream teardown on route unmount and on logout. |
| U4 | Polling: every interval is owned by a hook tied to route + `document.visibilityState`; no timer survives navigation (fixes always-on background polling); mutating endpoints are never polled. GETs are server-side unlimited (by design) — the client stays polite: no poll faster than today's cadences (3 s dashboard, 15 s history, 2.5 s dispatch-in-flight). |

## 8. Logging & error presentation

| # | Invariant |
|---|---|
| L1 | API errors are `(status, text/plain)` — render the text as text, bounded in length; never interpolate into markup; never log secrets or full request bodies to the console in production builds. |
| L2 | Errors follow UX-PRINCIPLES: what failed / why / next action / current state. Partial-failure states with distinct meanings (rollback "applied-but-not-persisted", release `available:false` with reason, MCP unknown-state) each get distinct rendering — never collapsed into a generic toast. |

## 9. Public vs authenticated surfaces

| # | Invariant |
|---|---|
| N1 | The public path set is owned by `uiAuthMiddleware` (`isPublicUIAuthPath`) and does not grow for frontend convenience. The SPA shell remains publicly served (it contains no secrets — verified at FE-8 by a shell-content review); all data comes from authenticated APIs. |
| N2 | SSO browser flows (`/auth/*`) and `/proxy.pac` are separate surfaces the SPA links to but never proxies. |
| N3 | The bootstrap window (pre-setup RoleAdmin injection) is respected as-is; the new app's setup flow must work inside it and must not create additional pre-auth surfaces. |

## 10. Backend gaps this contract depends on (sequenced in the migration plan)

- **GAP-1**: C2 wildcard-path indexing skips the 10 `{param}` routes (support-bundle surface is
  handler-gated only). Fix + tests belong to FE-1's backend slice — the new frontend leans on
  C2 semantics and should not launch on top of a known enforcement hole.
- **GAP-3**: HSTS; **GAP-4**: add `PATCH` to `isMutating` (defense-in-depth even though unused);
  **GAP-5**: gate `X-Forwarded-{Host,Proto}` trust on the trusted-proxy config, matching
  `realClientIP`.
- **GAP-2**: TOTP enrollment API (prerequisite for any account-security screen; otherwise that
  screen is descoped, not faked).
