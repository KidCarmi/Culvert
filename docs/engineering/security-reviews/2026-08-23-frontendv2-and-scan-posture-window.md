# Security Regression Review — FrontendV2 Embedded Serving (FE-1B), Monitor Cursor Pagination (ADR-FE-002), Scan-Posture Chaos Window (CHAOS-52/53)

- **Date:** 2026-08-23
- **Reviewer role:** Security Regression Engineer (standing charter, `docs/engineering/ENGINEERING-CONSTITUTION.md`)
- **Baseline:** `7df2677` (tip of the 2026-08-21 review)
- **Tip under review:** `1bd376c`
- **Window:** 41 commits / 217 files / ~46k insertions. Dominated by PR #1194
  (the new React admin frontend + FE-1B embedded serving + the ADR-FE-002
  Monitor keyset query), PR #1201/#1193 (CHAOS-53/52 scan-posture work),
  PR #1200 (latency-histogram sharding), PR #1196 (connection-limiter
  sharding), PR #1198 (OIDC JWKS stale-ceiling diagnostics), and the
  admin-UI TLS-fallback surfacing.

## Executive Summary

**One security regression found and fixed.** It is an information-disclosure
regression on the *unauthenticated* admin surface, introduced by a change whose
own purpose was to improve security posture (warning an operator that the admin
panel fell back to plain HTTP before they type a password). The warning is
right; shipping the raw cause with it, on a route reachable with no credential,
is not.

Everything else reviewed in this window is either byte-faithful to the baseline
or **strictly tighter**. The window's two headline security changes — CHAOS-53's
remote-scanner posture fix and CHAOS-52's ClamAV budget fix — each close a real
fail-open defect on the enforcement path. See "What got safer".

| ID | Finding | Severity | Class | Status |
|----|---------|----------|-------|--------|
| SEC-TLSFB-1 | `ui_tls_fallback_reason` — the raw `selfSignedTLS()` error — is returned by `/api/auth/status` and `/api/setup/status`, both on the **unauthenticated** public allowlist. The realistic self-sign failure is `x509.CreateCertificate` rejecting a SAN, and it quotes the offending value, so an operator-configured `-ui-san` / `CULVERT_PUBLIC_IP` entry or the host's own name is disclosed pre-auth. | **Low** | CWE-209 (Error Message Containing Sensitive Information) · CWE-200 · OWASP A01 (Broken Access Control) / A04 (Insecure Design) | Fixed |

---

## SEC-TLSFB-1 — Self-sign failure cause disclosed on the pre-auth surface

**Files:** `ui_auth.go` (`jsonOKAuthStatus`, `apiSetupStatus`), `ui.go`
(`uiTLSFallbackReason`), `static/index.html` (`renderTLSFallbackBanner`),
`api/openapi/openapi.yaml`
**Introduced by:** `a01d8a3` / `705093b` — "Surface admin-UI TLS self-sign
fallback to plain HTTP" / "Surface TLS fallback pre-auth and fix misleading
recovery advice".

### What changed

`startUI` records a self-sign failure in two new globals:

```go
tlsCfg, err := selfSignedTLS()
if err != nil {
    uiTLSFallbackActive = true
    uiTLSFallbackReason = err.Error()
    logger.Printf("TLS self-sign failed (%v), falling back to HTTP", err)
}
```

Both were then added to three surfaces — `GET /api/settings/network` (viewer),
`GET /api/auth/status`, and `GET /api/setup/status`:

```go
func jsonOKAuthStatus(w http.ResponseWriter, fields map[string]any) {
	fields["ui_tls_fallback"] = uiTLSFallbackActive
	fields["ui_tls_fallback_reason"] = uiTLSFallbackReason   // ← pre-auth
	jsonOK(w, fields)
}
```

The last two are on `uiAuthMiddleware`'s public allowlist:

```go
func isPublicUIAuthPath(path string) bool {
	return strings.HasPrefix(path, "/api/setup") ||
		…
		path == "/api/auth/status" ||
```

so every field they return is readable **with no credential at all** — by
design, because the login overlay must render before a session exists.

### Why it is a regression, not an accepted trade

The *flag* belongs there and is the whole point of the change: a browser about
to submit an admin password over cleartext should be told. It discloses nothing
— a client reading that response over plaintext already knows the panel is
plaintext.

The *reason* is a different object. `selfSignedTLS()` → `uitls.SelfSigned()`
returns errors from `ecdsa.GenerateKey`, `x509.CreateCertificate`,
`x509.MarshalECPrivateKey`, and `tls.X509KeyPair`. The realistic failure is the
second: `collectSANs` folds `-ui-san` entries, `CULVERT_PUBLIC_IP`, the
hostname, and every local interface address into the template, and
`CreateCertificate` refuses a malformed DNS SAN **by quoting it**
(`x509: cannot parse dnsName "…"`). The value quoted back is operator-supplied
internal naming.

This also contradicts a rule the codebase states explicitly, in two places, for
exactly this situation:

- `healthcheck.go` / `appendFrontendV2ReadinessCheck`: *"FIXED detail because
  the endpoint is unauthenticated (same rule as the ca/clamav rows)."*
- `checkIdentityBackend` (`diagnostics.go`): *"The cause text names the
  configured endpoint, so it goes to the log and the alert only — the
  viewer-role contract row carries the backend name and counts, never the
  cause."*

A pre-auth route is *less* privileged than the viewer role that rule already
withholds the cause from.

### Attack scenario

1. Self-signing fails at startup. The most reachable trigger is an operator
   typo in `-ui-san` / `proxy.ui_sans` (e.g. a value with a space, an
   underscore, or a stray control character) — an ordinary misconfiguration,
   not an attack precondition. The admin server falls back to plain HTTP.
2. An unauthenticated client that can reach the admin port issues
   `GET /api/auth/status` (no cookie, no Basic header).
3. The response body carries `ui_tls_fallback_reason`, e.g.
   `x509: cannot parse dnsName "mgmt-internal.corp.example"` — naming an
   internal management hostname the attacker had no other way to learn from
   this surface.

**Preconditions:** self-sign failure at startup (no `-tls-cert`/`-tls-key`,
`-ui-no-tls` not set) **and** network reach to the admin port.
**Exploitability:** trivial once the precondition holds — one unauthenticated
GET, no race, no timing.
**Likelihood:** Low. It needs a self-sign failure, which is not the common
state.
**Impact:** Low. Reconnaissance only — internal naming, no credential, no
session, no policy state. It is a *widening* of the pre-auth surface, and
pre-auth surfaces are exactly where this project has previously chosen fixed
detail.
**Affected assets:** admin-UI naming/SAN configuration; by extension, internal
DNS structure.
**Regression risk of the finding itself:** Medium — the field is on two public
routes and in the OpenAPI contract, so it would have been copied forward into
the new React frontend's generated types (it already was:
`frontend/src/api/types.gen.ts`).

### Fix (applied)

Keep the flag on both public routes; keep the full cause on the viewer-gated
`GET /api/settings/network` and in the process log.

```go
// The flag only, never uiTLSFallbackReason. /api/auth/status and
// /api/setup/status are on the uiAuthMiddleware public allowlist …
func jsonOKAuthStatus(w http.ResponseWriter, fields map[string]any) {
	fields["ui_tls_fallback"] = uiTLSFallbackActive
	jsonOK(w, fields)
}
```

`apiSetupStatus` the same. The two pre-auth banners in `static/index.html` drop
their reason `<span>` and point the operator at the server log and at
Settings → Network & TLS; `renderTLSFallbackBanner` no longer takes a reason
argument. `api/openapi/openapi.yaml` removes the property from `SetupStatus`
and `AuthStatus` (it stays on `NetworkSettings`), the bundle is regenerated via
`make api-bundle`, and `frontend/src/api/types.gen.ts` is regenerated with the
pinned generator so the FE-1A drift gate stays green.

No operator capability is lost: the cause was already on the authenticated
settings surface and in the log, and the pre-auth banner's actionable content
("your password is about to travel unencrypted; restart to retry, or use
`-tls-cert`/`-tls-key`") never depended on it.

**Safe implementation notes.** The redaction is at the *serialization* site
rather than at the global, so `uiTLSFallbackReason` stays a single source of
truth and the authenticated surface is unaffected. The globals are written once
in `startUI` before any listener goroutine is created, so the read path needs no
synchronization and none was added.

### Required tests (added — `ui_tls_fallback_preauth_test.go`)

| Kind | Test |
|------|------|
| Premise | `isPublicUIAuthPath` really returns true for both paths (asserted, not assumed) |
| Positive | the flag survives on both public routes and on `/api/settings/network` |
| Negative | `ui_tls_fallback_reason` absent from every branch of both public handlers, and the sentinel absent from the raw bytes (a rename cannot smuggle it back) |
| Authorization | `/api/settings/network` under `RoleViewer` still returns the full cause |
| Authentication | all three `apiAuthStatus` branches — unconfigured, anonymous, wrong Basic credentials |
| Boundary | fallback inactive ⇒ flag `false`, reason still absent |
| Malformed input | POST/PUT/DELETE/PATCH/TRACE with a malformed query string and a truncated JSON body — the 405 branches leak nothing |
| Concurrency | 32 goroutines × both endpoints, clean under `-race` |

All were verified **failing** against the pre-fix shape (the reason restored on
both handlers) and passing after.

---

## Regression Analysis — what was reviewed and why it is safe

### FrontendV2 embedded serving (`ui_frontend_v2.go`, 727 lines, NEW)

The largest new attack surface in the window. Reviewed against traversal,
unsafe serving, CSP weakening, and route-shadowing:

- **Traversal / arbitrary read:** `handleFrontendV2Asset` does an **exact-map
  lookup** against the validated asset set (`st.assets[key]`) — no `path.Clean`
  fallback, no `http.FileServer`, no directory listing. `manifest.json` and any
  `.map` are structurally unreachable because they are never admitted to that
  map. Manifest strings are validated as hostile before use
  (`frontendV2AssetPathShape`: absolute, backslash, `..`, `%`, `:`/`//`,
  non-canonical, out-of-`assets/`, `.map` all rejected) plus a conservative
  rune allowlist.
- **Serving contract:** MIME comes from an explicit six-entry allowlist, never
  a host MIME database; `securityMiddleware` sets `nosniff` before the handler
  runs, so the allowlist is load-bearing and enforced. Non-GET/HEAD is 404, not
  the shell.
- **CSP:** the route-scoped policy is **strictly tighter** than the global one
  it replaces (`style-src 'self'` instead of `'unsafe-inline'`, plus
  `object-src 'none'`, `base-uri 'none'`, `form-action 'self'`,
  `script-src-attr 'none'`, `style-src-attr 'none'`). Header ordering is
  correct: `securityMiddleware` writes before `next.ServeHTTP`, so the handler's
  `Set` wins for CSP only and `nosniff`/`X-Frame-Options`/`Referrer-Policy`
  survive.
- **Manifest parsing:** duplicate JSON keys are rejected before decode
  (`encoding/json` is last-value-wins, which would let an ambiguous artifact
  smuggle a second definition past validation); the duplicate-key walk is
  iterative with an explicit frame stack, so a deeply nested document cannot
  recurse the goroutine stack; the import-graph check is flat over
  `len(manifest)`, so cyclic graphs terminate by construction.
- **Default-off:** routes register unconditionally (keeping the C1/D0 route
  walls deterministic) but every handler 404s while `CULVERT_EXPERIMENTAL_UI`
  is unset — indistinguishable from an unregistered path. Env read once at
  handler construction, resolved through a CAS.
- **Fail-open check:** an invalid artifact degrades to 503 on the new routes
  only and a report-only `/ready` row; it never gates the readiness verdict and
  never touches the proxy data plane. Correct direction — a broken preview UI
  must not eject a serving gateway.
- **Auth posture:** `/app`, `/app/`, `/assets/` are `Public` in `uiRoutes`, and
  `uiAuthMiddleware` already treats every non-`/api/` path as public static.
  Same posture as the legacy `/` shell; the SPA's authority is the API layer,
  which is unchanged. **No new route bypasses `/api/` gating.**
- **Route shadowing:** `static/` contains no `assets/` tree and
  `static/index.html` emits zero `/assets/` references, so registering
  `/assets/` shadows nothing in the legacy UI.

### Monitor keyset pagination (`ui_logs_cursor.go`, `internal/logstore` `QueryPage*`)

- RBAC intact: reached only through `apiLogs`, which calls
  `requireRole(RoleViewer)` first.
- The cursor is opaque, **stateless**, and non-authoritative: length-capped
  before base64 decode (CWE-770), version-checked, fingerprint-bound to the
  query it was issued under, and its `ts` validated against the request's own
  time window — so a forged cursor can only reposition pagination inside a
  window the caller was already entitled to read. No datastore internals
  (Badger key bytes, file paths) are exposed.
- The two 400 responses carry fixed sentinel strings, never reflected input —
  no reflected XSS, no response splitting.
- DoS: page size clamped to 500, raw-scan budget clamped to `scanCap`, cost of
  page N independent of depth. Strictly better than the offset path it
  supplements, whose exact-`total` scan it deliberately drops.
- The legacy offset/limit/`total` behavior is byte-compatible for callers that
  send no `cursor` parameter.

### Scan posture (CHAOS-52 / CHAOS-53)

Both are **fail-open → fail-closed corrections** on the enforcement path and
were re-derived from the code, not accepted from the commit message:

- `Scanner.ScanBody` now runs under a `context` rather than a bare timer, so an
  abandoned scan releases its ClamAV slot instead of squatting it for the
  client's own timeout. The budget is enforced from **both** sides (parent
  select and worker `ctx.Err()` check), so an overrun cannot be laundered into a
  clean verdict by winning the select's coin flip.
- `publishVerdict` is tighten-only: an abandoned scan may publish a late BLOCK
  but never a late CLEAN — closing a race in which whether an object was blocked
  or served depended on the deadline beating the scanner.
- `cacheTimeoutCooldown` is `SetTTLUnless` with a keep predicate, so an
  infrastructure verdict can never overwrite a confirmed threat entry, and it
  expires in 30 s instead of inheriting the 1 h content TTL.
- `clamav.ScanContext` charges the queue wait to the *caller's* budget. The old
  private 5 s wait returned an ordinary error that the orchestrator classified
  as an engine fault and handled **fail-open** — five concurrent large downloads
  on a healthy daemon admitted content unscanned. Verified: with a
  deadline-carrying context, `acquireSlot`'s `ErrQueueFull` can only be returned
  with `ctx.Err() != nil`, so it lands on the fail-closed timeout path.
- `RemoteScanner.ScanBody` now (a) uses the same `scanBodyTimeout()` as the
  local path instead of a private 30 s deadline six times shorter than its own
  client timeout, (b) requires an **affirmative** verdict — `{}`, `null`, and a
  JSON maintenance page no longer read as "clean", (c) computes the result hash
  **locally** so a compromised sidecar cannot name arbitrary objects in the
  operator's allowlist/cache-evict UI, (d) consults the admin hash allowlist
  before the round trip, and (e) bounds `/scan`, `/status`, and `/health`
  response reads.
- `loadScanExclusions` now runs in **both** modes. On a sidecar node the store
  never learned a path, so `Save()` was a silent no-op: every admin edit
  returned 200, was audited, took a config-version snapshot, and persisted
  nothing. That is a real (pre-existing) integrity defect closed in this window.
- The genuine-fault branch stays **fail-open** — unchanged, and still the
  recorded owner decision (WK-2b / WK-1b), now reached only by an actual fault.
- Alert detail is a bounded reason class rather than `err.Error()`; transport
  errors embed the ephemeral local port, so the old detail defeated the 30 s
  dedup by construction and could evict real threat alerts from the 500-entry
  retry queue. `HasSubscriber` gating added via the new
  `internal/alerts` probe seam, which **fails toward delivery** when no probe
  is installed — a missing wire-up can never silence a real alert.

### Concurrency / sharding changes

- `internal/connlimit`: per-IP semantics preserved exactly. Every operation for
  an IP routes through one `shard(ip)`, so the cap stays per-IP (not per-shard);
  the TOCTOU guard around the increment, the `cur == ctr` entry-identity check
  on the reject path, and the `≤0` delete are transposed per shard unchanged.
  `maxPerIP` moved to `atomic.Int64` and is published **before** the enabled
  flag. The only behavioural difference is `ActiveIPs()` — a diagnostic gauge —
  becoming a sum of per-shard snapshots.
- `metrics.go` histogram: exposition-only. Non-finite guard added (one NaN used
  to poison `_sum` for the process lifetime); `_count` now derives from the
  same fold as the buckets, so it can no longer disagree with `+Inf`. `Observe`
  cannot panic on a negative or non-finite input; `newHistogram`'s panic is
  construction-time with fixed bucket sets, not attacker-reachable.
- `internal/uitls`: `raceProbesByPrecedence` returns the same
  precedence-ordered first success as the old sequential loop; only wall-clock
  changes. Endpoint responses are still bounded (64 bytes) and `net.ParseIP`-
  validated. **Noted, not a finding:** all probes now dial, so a host that
  previously stopped at the first success now contacts every fallback
  reflector at startup. No new trust is granted (the SAN-from-reflector
  decision is pre-existing) — it is an outbound-footprint change worth
  recording.

### Auth / identity

- `auth_oidc_flow.go`: the stale-ceiling re-check reads `fetchedAt` again under
  the lock and serves the key **only** when `staleServable` holds on the fresh
  value. `fetchedAt` is monotonic non-decreasing, so the re-read can only remove
  false breaches — it never admits a genuinely stale key set. No deadlock: the
  lock is released before `logStaleRefusal`, which takes it itself.
- `checkOIDCJWKSTrust` embeds admin-configured IdP display names in a
  diagnostics message. Verified not an XSS vector: the SPA renders operator-
  contract rows through `escHtml` for code, status, message, and
  `operator_action` alike.
- `proxy.go`'s `trailerRescrubBody` change is the implementation of the prior
  window's SEC-TRL-1 hardening: the wrapped body is now a **named field** with
  an explicit `Close`, so no copy fast path (`io.WriterTo`) can ever be promoted
  and drain the body past the trailer rescrub.
- Nine other auth-adjacent files in the window (`auth_idp.go`, `auth_ldap.go`,
  `auth_ldap_provider.go`, `authpolicy.go`, `legacy_auth_providers_startup.go`,
  `config_surfaces.go`, `controlplane_snapshot.go`, `store.go`,
  `ui_auth_ldap.go`) are **comment-only ADR-0025 → ADR-0027 renames**, confirmed
  by diffing with comment lines excluded — one metadata `Note` string is the
  only non-comment change.

### New frontend source (`frontend/src`, not shipped)

`frontend/dist` is the only tree embedded in the binary. Reviewed anyway
because it will ship later:

- No credential or token storage — `localStorage` is used for the theme
  preference only.
- No `innerHTML`, no `dangerouslySetInnerHTML`, no `eval`.
- `apiRequest` refuses any target outside `/api/`, before `fetch` is called, and
  rejects encoded traversal / backslashes / control bytes rather than
  normalizing them; `redirect: "error"`, `credentials: "same-origin"`, bounded
  streaming error-body read, exact `application/json` media-type check.
- Origin-based CSRF (`securityMiddleware`) is unchanged and compatible with the
  new client — no CSRF relaxation was needed or made.
- The embedded bundle was scanned for secret patterns: all matches are React
  form-field type strings.

### Other

- `docker-compose.yml`: the `cli` service's `command: []` did **not** prevent an
  accidental `--profile cli up -d` from starting a second proxy against the
  shared `proxy-data` volume (`main.go`'s one-shot dispatch only exits early
  when a one-shot flag is set). `command: ["-h"]` makes the accidental
  invocation print usage and exit. A correct hardening.
- `internal/hashcache` `SetTTL`/`SetTTLUnless`: test-and-write are one atomic
  step under the cache lock, closing the Get-then-Set window a caller would
  otherwise have.

---

## Residual Risk

- **RS-1 (accepted, unchanged).** A genuine remote-scanner *fault* remains
  fail-open (WK-2b). Correctly scoped now — slowness and capacity no longer
  reach that branch — but a sidecar returning 5xx still admits content
  unscanned. This is a recorded owner decision, not a finding.
- **RS-2 (pre-existing, out of window).** A local ClamAV `ErrQueueFull`
  returned *without* an expired context still falls through to a clean verdict.
  Unreachable in production — `*clamav.Client` always takes the
  context path, where `acquireSlot` can only return `ErrQueueFull` once the
  budget is gone — but it is reachable through the `ClamScanner` interface, so
  a future non-context scanner implementation would silently reinstate a
  fail-open capacity path. Worth a fail-closed default at the classification
  site in a later slice; not changed here (this review does not alter security
  behavior beyond the finding it fixes).
- **RS-3.** `detectPublicIPFallback` still folds an IP returned by an external
  reflection service into the admin-UI certificate SANs. Pre-existing trust
  decision, unchanged by this window; now every configured reflector is
  contacted per startup rather than only the first.
- **RS-4.** FrontendV2 validation runs once at startup against an artifact
  embedded at build time; its integrity therefore rests on the build pipeline
  and the FE-1A drift gates, not on a runtime signature. Acceptable while the
  surface is default-off and preview-only; it should be revisited before
  `CULVERT_EXPERIMENTAL_UI` becomes a supported production surface.

## Files changed by this review

| File | Change |
|------|--------|
| `ui_auth.go` | `jsonOKAuthStatus` + `apiSetupStatus` return the flag only |
| `ui.go` | records the exposure split on the fallback globals |
| `static/index.html` | pre-auth banners drop the reason; point at the log / Settings |
| `api/openapi/openapi.yaml` | property removed from `SetupStatus` + `AuthStatus` |
| `api/openapi/openapi.json` | regenerated (`make api-bundle`; the docs pages and route inventory were byte-unchanged) |
| `frontend/src/api/types.gen.ts` | regenerated with the pinned generator |
| `ui_tls_fallback_preauth_test.go` | new regression wall (8 assertion classes) |
