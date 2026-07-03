# Admin-UI Browser E2E (Playwright) — Implementation Plan

Status: **slices 1–11 shipped**. Companion to
`docs/ci/proxy-quality-architecture.md`. This describes how to add real-browser
end-to-end coverage of the Culvert admin UI without breaking the single-binary,
zero-runtime-dependency, Go-first contract.

## Shipped

- **Slice 1 — UI RBAC nav gating** (`ui_rbac_e2e_test.go`, `ui_e2e_helpers_test.go`,
  build tag `uie2e`; advisory workflow `.github/workflows/proxy-ui-e2e.yml`).
  Extracted `newAdminUIHandler()` from `newAdminUIServer` (ui.go) so the REAL
  middleware chain mounts under `httptest.NewServer`. Verifies: admin sees
  `users`/`governance` panels + dashboard; viewer has admin/operator nav hidden
  but keeps the read-only dashboard; and a viewer's forced POST to
  `/api/auth/users` is 403'd server-side (the C2 backstop), with no user created.
- **Slice 2 — login / auth flows** (`ui_login_e2e_test.go`). Drives the REAL login
  overlay (not cookie-inject): wrong password → error shown, still gated; correct
  password → overlay clears, role gating applies, identity shown in the topbar;
  logout → gated again AND `/api/auth/status` reports logged-out (session cleared);
  and 5 failed attempts trip the brute-force lockout (429, "locked"). The
  process-global login limiter is snapshot/cleared for isolation.
- **Slice 3 — policy-editor cross-plane** (`ui_policy_e2e_test.go`). The strongest
  assertion in the suite: boots the admin UI AND a real proxy listener in one
  process (shared global `policyStore`). Baseline default-deny → a proxied request
  is 403; the admin creates an "allow *" rule through the policy panel; then the
  SAME request reaches the backend (200) — a control-plane (UI) change taking
  effect on the data plane (proxy), plus the rule rendering in the policy table.
  Note: the SPA's post-submit table refresh races the panel-open fetch at
  test speed (a real user's panel-open fetch has long completed before they
  submit), so the test re-opens the panel for a deterministic single fetch.
- **Slice 4 — live SSE dashboard** (`ui_events_e2e_test.go`). Proves the real-time
  telemetry path: the dashboard's EventSource → `/api/events` → SPA stat tile.
  Boots UI + a real proxy + the 1s SSE broadcaster; a block-all policy makes each
  proxied request bump `statBlocked`; the test snapshots the rendered "blocked"
  tile, sends N blocked requests, and asserts the tile climbs by ≥N via a live SSE
  frame (no reload). Three environment findings baked into the harness (see
  `ui_e2e_helpers_test.go`): (a) Chromium honors the ambient `HTTP(S)_PROXY`, so
  the browser is launched `--no-proxy-server` to reach the loopback server;
  (b) the SPA loads Chart.js from a CDN unreachable in the hermetic test — a
  no-op `Chart` stub is injected so the on-load init reaches `connectSSE()`
  instead of throwing; (c) the persistent SSE connection means `networkidle`
  never fires, so page loads wait for `load` and rely on the retrying assertions.
- **Slice 5 — audit-trail surfacing** (`ui_audit_e2e_test.go`). Compliance
  guarantee: an admin state change is recorded AND shown in the UI. The admin
  performs an audited mutation in their session (`POST /api/blocklist` with a
  unique host); the audit panel must then render an entry for it — asserted on
  the `blocklist.add` action and the unique host in the detail column (content
  discriminator, per the repo's audit-ring test guidance — never len() deltas,
  the ring is bounded at 500). Exercises auditEvent → in-memory ring →
  `/api/audit` → renderAuditLog.
- **Slice 6 — policy-tester (simulator)** (`ui_policytester_e2e_test.go`). Dry-runs
  the REAL policy engine via the tester panel (no traffic): a block rule the admin
  defined is reported as a block (matching rule identified) and an allow rule as an
  allow. Proves the simulator panel is wired to `/api/policy/test` → policyStore.
- **Slice 7 — governance / control-plane panel** (`ui_governance_e2e_test.go`). The
  admin-only C3 observability surface: asserts the panel renders the route
  inventory ("routes total"), the C2 metadata-enforcement mode, and the C2 counters
  (would_deny …) from `/api/governance/control-plane`, plus a backstop that a viewer
  is denied the endpoint. The browser view of the C2/RBAC machinery.
- **Slice 8 — blocklist cross-plane** (`ui_blocklist_e2e_test.go`). A host the admin
  adds to the blocklist in the UI is blocked on the LIVE proxy (shared global
  `bl`; the proxy's pre-policy `bl.IsBlocked` gate). Reachable → 200; after the UI
  add → 403 and the backend is never reached. Exercises the legacy blocklist path,
  which blocks before the policy engine.
- **Slice 9 — header-rewrite cross-plane** (`ui_rewrite_e2e_test.go`). A request-
  header "set" rule the admin adds in the UI is applied on the LIVE proxy (shared
  global `rewriter`; `rewriter.ApplyRequest` before forwarding). A header-capturing
  upstream sees no header at baseline, then the injected header after the UI add.
- **Slice 10 — file-extension blocking cross-plane** (`ui_fileblock_e2e_test.go`). An
  extension the admin blocks in the UI is enforced on the LIVE proxy (shared global
  file blocker; `fileBlocker.CheckPath` in the pre-policy gate): a request for a
  path with that extension reaches the backend at baseline, then is 403'd after the
  UI add and never forwarded.
- **Slice 11 — PAC served + previewed** (`ui_pac_e2e_test.go`). The dynamically
  generated `/proxy.pac` (served UNAUTHENTICATED for browser auto-config) is a valid
  PAC document (FindProxyForURL + PROXY, correct content-type), and the PAC panel
  renders the same generated config in its preview.

### Dependency footprint (test-only)

`go.mod` gains `playwright-community/playwright-go` + 3 small indirect deps
(`golang-set/v2`, `go-jose/v3`, `go-stack`). All are compiled **only** under
`-tags uie2e`, so they never enter the default `go test ./...` gate or the
shipped binary. `go mod tidy` retains them (it evaluates custom build tags).
If tighter supply-chain isolation is wanted later, the harness can move to a
nested module that drives the shipped binary over a socket instead of importing
`package main` — noted as a hardening follow-up, not required for the advisory
tier.

## 1. Why — the gap

Every test in the quality program so far drives the **traffic plane** over real
sockets (policy, MITM/SSL-inspect, CONNECT relay, SOCKS5, auth×authz). None of
it renders the **admin UI**, which is a single ~11.6k-line SPA
(`static/index.html`) exposing **25 `data-view` panels**:

```
audit authpolicy blocklist ca-mgmt catgroups cdr certificates cluster
dashboard diagnostics fileblock governance idproviders livefeed pac policy
policy-tester releases rewrite security settings updates upstream urlcat users
```

Browser E2E covers what socket tests cannot:

- **Login flows**: local bcrypt, session cookie (`ps_session`, dynamic `Secure`),
  logout/revocation, lockout on bad creds, and the OIDC/SAML redirect round-trips.
- **RBAC in the browser** — the front-end mirror of the C2 metadata-enforcement
  invariants: does a `viewer` see admin-only panels/controls gated, and do
  mutations surface a 403 instead of silently succeeding?
- **CSRF**, body-limit / rate-limit UX, form validation.
- **Live SSE dashboard** (`livefeed`, `/api/events`), config-version rollback UI,
  the `policy-tester` panel.

## 2. Stack decision — `playwright-go`, not Node

The repo is deliberately **`package main`, single binary, zero runtime deps**,
with **no `package.json` anywhere**. A Node `@playwright/test` toolchain would
cut against that hard.

[`github.com/playwright-community/playwright-go`](https://github.com/playwright-community/playwright-go)
drives the **same Chromium** over CDP but lives inside `go test`.

| Criterion | playwright-go (**recommended**) | Node @playwright/test |
|---|---|---|
| Language / toolchain | Go, one `go test` invocation | adds Node + npm dep tree |
| Fits repo ethos (zero-Node) | ✅ | ✗ |
| Built-in runner / trace-viewer / auto-retry | ✗ (wire it yourself) | ✅ richer |
| Community / feature velocity | smaller | larger |
| Dependency footprint | one **test-only** Go module | `node_modules` |

For Culvert the tradeoff clearly favors `playwright-go`. The lost niceties
(trace viewer, codegen, auto-retry) are acceptable for an advisory tier and can
be re-evaluated if UI E2E becomes load-bearing.

## 3. Architecture — hermetic, in-process (same pattern as the traffic E2E)

Boot the **real** admin-UI handler chain in-process via `httptest.NewServer`,
reusing the actual middleware stack, then point Playwright at the
`127.0.0.1:<port>` URL. No separate binary, no Docker, no public internet.

Today the mux + middleware are assembled **inline** inside `startUI` (ui.go),
which returns a fully-formed `*http.Server` (port + TLS). Small enabling
refactor:

- Extract the composition into a testable helper, e.g.
  `func buildUIHandler() http.Handler` returning
  `uiIPGuardMiddleware(securityMiddleware(uiAuthMiddleware(uiMetadataEnforcement(mux))))`.
  `startUI` calls it and wraps the `*http.Server`; tests mount the same handler
  under `httptest.NewServer(buildUIHandler())`.
- This keeps the middleware order identical between prod and test — the whole
  point (RBAC/CSRF behavior must be the real chain, not a stub).

Auth setup in-test reuses existing helpers already used by the Go suites:
`cfg.SetAuth`, `initSessionSecret`, `encodeSession`/`sessionCookieName` (so we
can seed an admin/operator/viewer session directly, or exercise the real
`/api/login` form).

## 4. Isolation & CI — advisory, never a merge gate

- **Build tag** `//go:build uie2e` so the browser tests are excluded from the
  required `qa-gate` — identical isolation model to `proxyload` / `proxystress`.
- **New workflow** `.github/workflows/proxy-ui-e2e.yml`: nightly (`schedule`) +
  `workflow_dispatch`, plus an optional **non-blocking** PR run. Mirrors
  `proxy-nightly-e2e.yml`. Never added to `qa-gate-approved` `needs` until the
  suite has proven stable over multiple nightly runs.
- Rationale: browser E2E is inherently flakier than socket-level Go tests;
  keeping it advisory protects the required gate's signal.

## 5. Environment gotchas (pre-solved in this runner)

- Chromium is **pre-installed** at `/opt/pw-browsers` and `PLAYWRIGHT_BROWSERS_PATH`
  is set. **Never run `playwright install`** — launch with
  `ExecutablePath: "/opt/pw-browsers/chromium"` (and set
  `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1` so the Go binding's install step is a
  no-op). CI installs Chromium via the OS/action, not via npm postinstall.
- Run **headless**.
- Select on stable `data-view="…"` attributes / element ids — **never on text**
  in an 11.6k-line SPA.
- **Determinism**: wait on selectors / `networkidle`; never `time.Sleep`.

## 6. First slice (small, real): UI RBAC gating

The browser complement to the C2 enforcement invariants. One workflow + one
test file + one `go.mod` add. Sketch (`ui_rbac_e2e_test.go`, tag `uie2e`):

```
//go:build uie2e

// 1. srv := httptest.NewServer(buildUIHandler()); seed local admin + a viewer.
// 2. pw, _ := playwright.Run(); browser via ExecutablePath=/opt/pw-browsers/chromium, headless.
// 3. admin session:
//      - log in through /api/login (real form) OR inject a signed ps_session cookie
//      - assert nav shows admin-only items (users, governance)
//      - open data-view="policy", add a rule, Save → 2xx, rule visible
// 4. viewer session (fresh context):
//      - admin-only nav items are gated/hidden
//      - a mutation (e.g. POST via the policy Save button) surfaces a 403 in the UI
//      - GET-only panels still render
// 5. Assert on DOM state + the surfaced status, not on sleeps.
```

Assertions map 1:1 onto the RBAC contract: admin (full) / operator (write) /
viewer (read-only), and "C2 must never allow what the handler denies."

## 7. Rollout (slice by slice — do NOT big-bang)

1. **RBAC gating** (this slice) — proves the harness + the invariant that matters most.
2. **Login/auth flows** — local login, session cookie + `Secure` flag, logout/revocation, lockout.
3. **Policy editor round-trip** — create/edit/delete in UI, assert it takes effect on the traffic plane (cross-plane test).
4. **Live SSE dashboard** — `/api/events` renders live events without leaking/hanging.
5. Broaden panel coverage opportunistically; keep each slice advisory until stable.

## 8. Open decisions

- **Stack**: playwright-go (recommended) vs Node @playwright/test.
- **Login path for slice 1**: exercise the real `/api/login` form (higher fidelity,
  slightly more brittle) vs. inject a pre-signed `ps_session` cookie (faster, more
  deterministic; auth-flow fidelity deferred to slice 2). Recommend **cookie-inject
  for slice 1**, real form in slice 2.
- **Trace capture**: playwright-go supports tracing; capture on failure only and
  upload as a CI artifact (like the pprof captures in the nightly load tier).
