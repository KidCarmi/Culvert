# Culvert Admin UI Refactor Audit

Status: living document — opened on 2026-04-28
Owner: refactor task force (Lead Architect)
Scope: `ui.go` and adjacent `ui_*.go` files, admin HTTP server, RBAC and session
        machinery. No proxy / SOCKS / policy-engine code.

---

## 1. Executive Summary

`ui.go` was historically a god file that owned route registration, three layers
of middleware, session/cookie machinery, RBAC helpers, a CSP nonce pipeline,
audit helpers, validation helpers, and a smattering of UI-specific globals.

A previous wave of work has already extracted the *handlers* themselves into
domain files (`ui_auth.go`, `ui_cluster.go`, `ui_config.go`, `ui_policy.go`,
`ui_security.go`, `cdr_ui.go`). What remains in `ui.go` (794 lines, 131 routes)
is the wiring layer — and it is still doing too many jobs.

The objective of this refactor is **mechanical** decomposition: split the
remaining `ui.go` along clean seams (middleware, session, RBAC, helpers),
preserve every byte of behavior, and lay the groundwork for a future route
metadata table. No handler logic is changed in the first wave.

**Risk posture**: low. The package layout is flat (`package main`), so moves are
file-level only — no import-graph changes, no API renames, no behavior changes.

---

## 2. Current `ui.go` Inventory

### 2.1 Globals / state

| Symbol | Purpose | Cross-file users |
|---|---|---|
| `staticFiles` (embed) | Embedded SPA assets | `ui.go` only |
| `uiCfgGeoIPDB`, `uiCfgLogFile`, `uiCfgLogMaxMB`, `uiCfgLogFormat` | Read-only display vars set in `main.go` | `main.go`, `ui_security.go`, `ui_config.go` |
| `pendingCARotation` | Two-step CA rotation token | `ui_security.go` |
| `cachedIndexHTML` | Pre-read SPA template for CSP nonce injection | `ui.go` only |
| `uiAllowedNetsMu`, `uiAllowedNets` | UI IP allowlist state | `ui.go`, tests |

### 2.2 Functions (24 in `ui.go`)

| Function | Domain | LoC | Has tests |
|---|---|---:|:---:|
| `tlsErrorFilter.Write` | logging filter | 8 | no (trivial) |
| `cspNonce` | security/CSP | 11 | indirect |
| `startUI` | route registration + server boot | 234 | indirect |
| `AddUIAllowedCIDR` | IP allowlist | 19 | yes (`ui_test.go:73`) |
| `SetUIAllowedCIDRs` | IP allowlist | 26 | yes (`ui_test.go:96`) |
| `ListUIAllowedCIDRs` | IP allowlist | 9 | indirect |
| `uiIPGuardMiddleware` | middleware | 23 | yes (`ui_test.go:114,133`) |
| `securityMiddleware` | middleware (CSP/CORS/CSRF/rate-limit) | 58 | yes (`ui_test.go:168,183`) |
| `isSameOrigin` | CSRF helper | 18 | yes (`ui_test.go:153`) |
| `uiRole` | RBAC | 6 | indirect |
| `sessionAdmin` | RBAC/audit | 13 | indirect |
| `requireRole` | RBAC gate | 7 | indirect |
| `uiAuthMiddleware` | middleware (session+basic auth) | 57 | indirect (most handler tests) |
| `isSecureRequest` | session/TLS detection | 3 | indirect |
| `setUISessionCookie` | session cookie | 22 | indirect |
| `readUISessionCookie` | session cookie | 10 | indirect |
| `clearUISessionCookie` | session cookie | 10 | indirect |
| `auditEvent` | audit | 3 | indirect |
| `auditEventDiff` | audit | 35 | indirect |
| `jsonOK` | JSON helper | 7 | indirect |
| `isValidBlocklistWildcard` | validation | 14 | indirect |
| `validatePolicyRule` | validation | 31 | indirect |
| `decodeJSON` | JSON helper | 5 | indirect |
| `parseTimestampParam` | parser | 26 | indirect |

### 2.3 Domain grouping of routes (131 total)

`startUI` registers routes that already align with the extracted handler files.
Counts below are derived from `ui.go:103-274`.

| Domain | Approx. count | Handler home |
|---:|---:|---|
| Setup / bootstrap | 2 | `ui_auth.go` |
| Dashboard / stats / logs / events / audit | ~12 | `ui_config.go`, `events.go` |
| Policy / blocklist / fileblock | ~13 | `ui_policy.go` |
| Settings / network / session / syslog | ~10 | `ui_config.go` |
| Security scan (ClamAV/YARA/feeds/exclusions) | ~12 | `ui_security.go` |
| CA / certs / OCSP / SSL bypass | ~7 | `ui_security.go` |
| Cluster / nodes / HA / bandwidth / bootstrap | ~16 | `ui_cluster.go` |
| Updates / rollback / registry | ~9 | `update.go`, `update_cluster.go` |
| Auth / users / IdP / TOTP | ~6 | `ui_auth.go` |
| Alerts (webhooks) | 3 | `alerts.go` (handlers) |
| Config versioning / import / export | 4 | `ui_config.go` |
| URL categories | 4 | `catdb.go` |
| CDR (Sluice) | 7 | `cdr_ui.go` |
| GeoIP / metrics / OTLP / connlimit / blockpage / upstream | ~9 | various |
| PAC / proxy.pac | 2 | `pac.go` |
| Auth callbacks (OIDC/SAML/select/logout) | 4 | `auth_oidc_flow.go`, `auth_saml.go` |
| Diagnostics / healthz | 2 | `diagnostics.go` |

---

## 3. Risk Ranking — endpoints worth extra attention

### 3.1 Critical — write/destroy on shared state, must remain admin-only

| Endpoint | Handler | Notes |
|---|---|---|
| `POST /api/update/apply` | `apiUpdateApply` | Replaces running binary; SSE stream |
| `POST /api/update/cluster` | `apiClusterUpdate` | Rolling update of fleet |
| `POST /api/ca/rotate` | `apiCARotate` | Two-step token (`pendingCARotation`) |
| `POST /api/cluster/revoke` | `apiClusterRevoke` | Removes a node from cluster |
| `POST /api/cluster/mode` | `apiClusterMode` | Switches CP/DP role |
| `POST /api/config/import` | `apiConfigImport` | Imports exported config |
| `POST /api/session-secret` | `apiSessionSecret` | Rotates session signing key |
| `PUT /api/settings/default-auth-outcome` | `apiDefaultAuthOutcome` | Sets default authentication outcome (require/open on no-match); legacy alias `/api/settings/unauth-mode` retained for back-compat |
| `POST /api/auth/users` | `apiAuthUsers` | RBAC user CRUD |

These endpoints already require auth via `uiAuthMiddleware`; most call
`requireRole(w, r, "admin")` internally. The refactor must not perturb the
middleware chain order: `uiIPGuardMiddleware → securityMiddleware → uiAuthMiddleware → mux`.

### 3.2 High — public, no auth gate (intentional)

| Endpoint | Reason it is public |
|---|---|
| `/` (SPA shell) | Static asset |
| `/api/setup/status`, `/api/setup/complete` | First-run bootstrap |
| `/api/auth/login`, `/api/auth/logout`, `/api/auth/status` | Login flow |
| `/api/auth/totp*` (allowlisted prefix) | TOTP enrollment |
| `/auth/oidc/callback`, `/auth/saml/callback`, `/auth/select`, `/auth/logout` | IdP redirect targets |
| `/proxy.pac` | Windows PAC clients cannot send credentials |
| `/healthz` | LB probe |

The public allowlist lives at `ui.go:541-549` in `uiAuthMiddleware`. Any new
`/api/setup/*` or `/auth/*` route is automatically public via prefix match —
this is a correctness hazard and is called out in the QA section below.

### 3.3 Medium — auth required, role check inside handler

Most other `/api/*` routes. Auth is enforced by `uiAuthMiddleware`; role
gating is the handler's responsibility (`requireRole(...)`). The audit code
should be exercised by every mutating handler.

### 3.4 Auth-disabled mode

When `cfg.AuthEnabled() == false` (first-run / explicit unauth mode),
`uiAuthMiddleware` injects `RoleAdmin` into the context (`ui.go:553`). This is
intentional but must be preserved exactly — the `setUISessionCookie` /
`readUISessionCookie` path, the `requireRole` check, and the IP guard all
remain in effect.

---

## 4. Cross-cutting concerns observed in `ui.go`

1. **CSRF** — same-origin check via `Origin` ↔ `Host`/`X-Forwarded-Host`
   (`securityMiddleware`, `isSameOrigin`).
2. **Body limit** — `1 MiB` cap on mutating requests (`securityMiddleware`).
3. **Rate limit** — sharded `apiLimiter.Allow(ip)` on mutating `/api/*`.
4. **CSP nonce** — generated per-request, threaded through `cspNonceKey{}`
   context value, consumed by the SPA shell handler.
5. **TLS error suppression** — `tlsErrorFilter` quiets self-signed handshake
   noise on `srv.ErrorLog`.
6. **Dynamic `Secure` cookie flag** — `isSecureRequest(r)` chooses `Secure: true`
   when TLS or `X-Forwarded-Proto: https` is present.

All six survive the refactor unchanged.

---

## 5. Proposed Target Layout

Keeping the flat `package main` layout (matches CLAUDE.md guidance), files
become:

```
ui.go                  startUI(), server bootstrap, embedded assets, SPA shell
ui_middleware.go       IP guard + security + auth middleware, CSP nonce, TLS log filter
ui_session.go          UI session cookie helpers (set/read/clear) + isSecureRequest
ui_rbac.go             uiRoleKey/uiRole/sessionAdmin/requireRole
ui_helpers.go          jsonOK, decodeJSON, parseTimestampParam, isValidBlocklistWildcard,
                       validatePolicyRule, auditEvent, auditEventDiff
ui_auth.go             (existing) auth/login/users/IdP handlers
ui_policy.go           (existing) policy + blocklist + fileblock handlers
ui_security.go         (existing) security/scan/CA/cert/SSL handlers
ui_cluster.go          (existing) cluster/nodes/bandwidth handlers
ui_config.go           (existing) settings/import/export/syslog/logger handlers
cdr_ui.go              (existing) CDR / Sluice handlers
```

Future (out of scope for the first PR):

```
ui_routes.go           registerXxxRoutes() helpers, route metadata table
```

---

## 6. Phased Plan

### Phase A — Mechanical extraction (safe, no behavior change)

* **A1 (this PR).** Extract from `ui.go`:
    * `ui_middleware.go` — `tlsErrorFilter`, `cspNonce` + `cspNonceKey`,
      `uiAllowedNets*`, `Add/Set/ListUIAllowedCIDR`, `uiIPGuardMiddleware`,
      `securityMiddleware`, `isSameOrigin`, `uiAuthMiddleware`.
    * `ui_session.go` — `uiSessionCookieName`, `isSecureRequest`,
      `set/read/clearUISessionCookie`.
    * `ui_rbac.go` — `uiRoleKey`, `uiRole`, `sessionAdmin`, `requireRole`.
* **A2 (follow-up).** Extract `ui_helpers.go` (`jsonOK`, `decodeJSON`,
  `parseTimestampParam`, `isValidBlocklistWildcard`, `validatePolicyRule`,
  `auditEvent`, `auditEventDiff`).
* **A3 (follow-up).** Extract `cachedIndexHTML` + SPA shell handler into a
  small `ui_static.go`. `pendingCARotation` moves to `ui_security.go` (its only
  user) once a separate test pass lands.

### Phase B — Route registration grouping

Replace the flat `mux.HandleFunc(...)` block in `startUI` with a small set of
domain register helpers (`registerAuthRoutes`, `registerPolicyRoutes`, …). One
file per domain or one helper per existing handler file. No new metadata yet —
**still purely mechanical**.

### Phase C — Route metadata foundation

Introduce a typed route table:

```go
type uiRoute struct {
    Path     string
    Method   string      // "" = any
    MinRole  UIRole      // RolePublic|RoleViewer|RoleOperator|RoleAdmin
    Mutating bool
    Audit    bool
}
```

`startUI` walks the table and registers handlers, with the auth middleware
consulting `MinRole` rather than the current ad-hoc handler checks. This is
the first behavior-affecting phase and must land with a full RBAC test sweep.

### Phase D — Regression tests

Add explicit tests for:

* every entry in §3.2 stays public (no cookie ⇒ 200/3xx, never 401);
* every other `/api/*` returns 401 without a session;
* admin-only handlers reject `viewer` and `operator` roles with 403;
* mutating endpoints honor the `Origin` mismatch CSRF check, the 1 MiB body
  limit, and the per-IP rate limit.

---

## 7. Testing Strategy for Phase A1

Phase A1 is a file-level move with no symbol renames. Existing tests cover the
moved code:

* `TestAddUIAllowedCIDR`, `TestSetUIAllowedCIDRs` — `ui_test.go:73,96`
* `TestUIIPGuardMiddleware_NoList`, `TestUIIPGuardMiddleware_Blocked` — `ui_test.go:114,133`
* `TestIsSameOrigin` — `ui_test.go:153`
* `TestSecurityMiddleware_Headers`, `TestSecurityMiddleware_OPTIONS` — `ui_test.go:168,183`
* `TestAuthLogout` — `ui_morecoverage_test.go:140`
* Many handler tests indirectly exercise `uiAuthMiddleware`, `uiRole`,
  `requireRole`, and the session cookie helpers.

Validation commands per phase:

```bash
gofmt -l .                                    # must be empty
go vet ./...                                  # must succeed
go build ./...                                # must succeed
go test ./...                                 # must pass
go test -race -count=1 -timeout=15m ./...     # CI mode
```

No new tests are required for Phase A1 — symbol identity is preserved. New
tests start landing in Phase D.

---

## 8. Follow-up PR plan (next 3–5)

| # | Title | Files touched | Risk | Validation |
|---:|---|---|:---:|---|
| 2 | Phase A2: extract `ui_helpers.go` | `ui.go`, new `ui_helpers.go` | low | `go test ./...` |
| 3 | Phase A3: extract SPA shell + move `pendingCARotation` | `ui.go`, new `ui_static.go`, `ui_security.go` | low | `go test ./...`, manual SPA load |
| 4 | Phase B: route registration grouped into `register*Routes` | `ui.go`, new `ui_routes.go` (or per-domain helpers) | medium | full test suite + race |
| 5 | Phase C: route metadata table + middleware-driven RBAC | `ui_routes.go`, `ui_middleware.go`, every handler | high | full test suite + race + new RBAC sweep |
| 6 | Phase D: RBAC/CSRF/rate-limit regression sweep | new `ui_rbac_test.go`, new `ui_csrf_test.go` | low | `go test -run TestRBAC -race` |

---

## 9. What this refactor explicitly does NOT do

* No endpoint is renamed.
* No endpoint changes auth requirement.
* No JSON contract changes.
* No new dependencies.
* No package split out of `package main`.
* No handler logic is rewritten.
* No CLI flag is added or removed.

Any change in those categories needs a separate PR with its own justification.
