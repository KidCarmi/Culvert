# Culvert

Enterprise-grade open-source HTTP/HTTPS/SOCKS5 forward proxy written in Go.
Single binary, zero runtime dependencies.

## Project Structure

```
*.go          — All source in package main (flat layout, no internal/)
main.go       — Entrypoint, flag parsing, signal handling, graceful shutdown
proxy.go      — HTTP/CONNECT/WebSocket handlers, tunnel relay, upstream transport, sanitizeLog
socks5.go     — SOCKS5 protocol handler (RFC 1928/1929)
policy.go     — Policy engine: rule evaluation, FQDN/category/GeoIP/schedule matching
store.go      — Persistent state: blocklist, request log, audit log, config store
ca.go         — Root CA management, leaf cert signing, encrypted CA bundle (AES-GCM + PBKDF2), LRU cert cache
ui.go         — startUI bootstrap only (no direct mux.HandleFunc; routes registered via register*Routes helpers)
ui_routes_meta.go — uiRoutes: single source of truth for route metadata (method-aware via Methods []uiRouteMethod)
ui_metadata_enforcement.go — C2 metadata-driven middleware (MinRole enforcement + AuditExpected observability)
ui_auth.go / ui_config.go / ui_policy.go / ui_security.go / ui_cluster.go / ui_static.go / cdr_ui.go / pac.go / update.go / diagnostics.go — per-domain register*Routes helpers + handlers
ui_helpers.go — auditEvent / auditEventDiff / decodeJSON / shared validators
ui_middleware.go / ui_session.go / ui_rbac.go — middleware chain, session cookies, RBAC helpers
session.go    — HMAC-SHA256 signed session cookies, revocation list, dynamic Secure flag
auth.go       — Local bcrypt auth
auth_ldap.go  — LDAP bind + search auth with group resolution
auth_oidc.go  — OIDC token introspection (RFC 7662)
auth_oidc_flow.go — Full OIDC Authorization Code + PKCE flow
auth_saml.go  — SAML 2.0 SP via crewjam/saml
auth_idp.go   — Multi-IdP registry, validateExternalURL
identity.go   — Identity model (Sub, Groups, Source)
clam.go       — ClamAV INSTREAM scanner
yara_scan.go  — Pure-Go YARA rule engine
scanner.go    — Unified DPI + ClamAV + YARA scan coordinator
security.go   — Security helpers (SSRF guard via isPrivateHost, header scrub)
security_scan.go — Scan orchestration: ClamAV + YARA + threat feed + hash cache
fileblock.go  — File extension/MIME blocking profiles
fileprofile.go — Named file-type blocking profiles (Executables, Archives, etc.)
geoip.go      — MaxMind GeoLite2 country lookup with background cache
controlplane.go — gRPC-based Control Plane / Data Plane distributed architecture
enrollment.go — Token-based node enrollment, ClusterStore, cluster CA, heartbeat monitor
upstream.go   — Upstream proxy chaining with failover, circuit breaker, round-robin health checks
ocsp.go       — OCSP/CRL revocation checking for upstream TLS certificates
metrics.go    — Prometheus metrics (culvert_* namespace, per-rule hit counters, latency histogram)
connlimit.go  — Per-IP connection limiting and X-Request-ID generation
alerts.go     — Webhook alerting for security events (HMAC-SHA256 signed)
threatfeed.go — Threat intelligence feed integration (URLhaus, OpenPhish), domain allowlist for hosting platforms
feedsync.go   — UT1 URL category database syncer
blocklist_feed.go — Blocklist URL feed syncer
rewrite.go    — HTTP header rewrite rules (per-host, wildcard)
plugin.go     — Middleware plugin API
logger.go     — Rotating file logger with JSON mode
syslog.go     — Syslog SIEM forwarding (UDP/TCP, RFC 3164)
config.go     — YAML + CLI flag configuration (goccy/go-yaml)
pac.go        — PAC file generator
hashcache.go  — SHA-256 scan result cache with TTL
lockout.go    — Brute-force lockout (IP + user)
totp.go       — TOTP 2FA (RFC 6238, inline stdlib HMAC-SHA1, no external dep)
tls.go        — TLS helpers (self-signed cert for admin UI)
blockpage.go  — Block page HTML template
events.go     — SSE event stream for live UI dashboard
catdb.go      — URL category database
configversion.go — Config versioning, snapshots, diff, rollback (50-version max)
nodegroup.go  — Node group definitions with label selectors, priority-based matching
bandwidth.go  — Per-group bandwidth/QoS policies with token bucket rate limiting
bootstrap.go  — Bootstrap script/compose generators for node enrollment
update.go     — Self-update system (binary + Docker)
update_cluster.go — Rolling cluster update orchestrator (canary, drain, HA sync)
scan_remote.go — Remote scan sidecar for production sandboxing
```

## Build & Test

```bash
go build -o culvert .                       # build binary
go test ./...                               # run all tests
go test -race -count=1 -timeout=15m ./...   # race detector (CI mode)
go test -coverprofile=coverage.out ./...    # coverage report
```

## Run

```bash
# Minimal
./culvert -addr :8080 -ui-addr :9090

# With SSL inspection
CULVERT_CA_PASSPHRASE=mysecret ./culvert -addr :8080 -ui-addr :9090 -ca-bundle /data/ca.bundle

# Docker
docker compose up -d
```

## Key Environment Variables

- `CULVERT_CA_PASSPHRASE` — CA private key encryption passphrase (required for SSL inspect)
- `CULVERT_C2_ENFORCE` — C2 metadata-driven RBAC mode. Default = enforce (fail-closed). Set to `false`/`0`/`no`/`off` to revert to shadow (log-only) mode without rebuild. Read once at startup.

## Code Conventions

- **Package**: Everything is `package main` (flat layout)
- **Go version**: 1.25 (go.mod pinned to 1.25.10 for govulncheck — fixes GO-2026-4982 in html/template)
- **Logging**: Use `logger.Printf()`, never `log.Printf()` or `fmt.Printf()`
- **User input in logs**: Wrap with `sanitizeLog(s)` and use `%q` format verb (CWE-117 prevention; sanitizeLog uses strings.ReplaceAll which CodeQL recognises)
- **CodeQL compliance**: For values that flow through objects (e.g. `rl.Limit()`, `added.Priority`), inline `strings.ReplaceAll` or `fmt.Sprintf` + `strings.ReplaceAll` at the call site so CodeQL sees the sanitiser
- **SSRF guards**: Inline `url.Parse` + scheme check + `isPrivateHost()` before outbound HTTP requests so CodeQL can verify the guard; do not rely solely on wrapper functions like `validateExternalURL()`
- **HTTP contexts**: Use `http.NewRequestWithContext()`, never bare `http.NewRequest()`; use `HandshakeContext()` not `Handshake()`; use `DialContext()` not `DialTimeout()`
- **Errors**: Return `fmt.Errorf("context: %w", err)` for wrapping
- **Concurrency**: Use `sync.RWMutex` for read-heavy stores, `atomic` for counters
- **Security**: SSRF checks via `isPrivateHost()` before any outbound dial
- **Tests**: Test files use `_test.go` suffix, same package (whitebox)
- **Lint suppressions**: Use `//nolint:errcheck` with reason comment; `// #nosec G402` for gosec
- **GUI parity**: Every new CLI flag or config option MUST have a corresponding admin API endpoint AND a UI panel/section so the user can manage it from the GUI. CLI-only features are not acceptable — the admin must have full control from the web interface.
- **API pattern**: Admin API handlers follow `apiXxx(w, r)` naming, registered through `register*Routes` helpers and represented in `uiRoutes` metadata (`ui_routes_meta.go`). Use `requireRole(w, r, "admin")` for write operations, `requireRole(w, r, "viewer")` for reads — handler-level RBAC stays as defense-in-depth even with C2 active.
- **UI pattern**: SPA panels in `static/index.html` use `data-view="name"` attributes. New panels need a nav-item in the sidebar, a view div, and JS load/render functions.
- **Config versioning**: Config-mutating API handlers must call `saveConfigVersion(actor, action)` after `auditEvent()` to create automatic snapshots.
- **Range iteration**: Use index-based range (`for i := range slice`) for large structs (PolicyRule 240 bytes, EnrolledNode 176 bytes) to avoid `rangeValCopy` gocritic warnings.
- **gosec G117**: Avoid struct field names or JSON tags matching secret patterns (e.g. `secret`, `password`, `token`). Rename to non-matching names (e.g. `SessionHMAC` instead of `SessionSecret`).
- **gosec G124**: When cookies use dynamic `Secure` flag (e.g. `isSecureRequest(r)`), suppress with `// #nosec G124 -- dynamic Secure flag`.
- **Cyclomatic complexity**: Keep functions under cyclop threshold of 15. Extract helpers for complex switch/if chains.
- **`upstreamTransport` is read-only after publication**: the shared upstream `*http.Transport` is owned by `upstream_transport.go` (P5.3 / S6). Read via `getUpstreamTransport()`. Mutate via `swapUpstreamTransport(update)` only — the update closure builds a NEW `*http.Transport` (use `cloneTransport` + `cloneTLSConfig`) and MUST NOT mutate its input. Direct field assignment on a loaded transport (`getUpstreamTransport().Proxy = …`, including the local-variable bind form `t := getUpstreamTransport(); t.Proxy = …`) is forbidden — it races against the proxy hot path's reads.

## CI Pipelines

- `.github/workflows/ci.yml` — Build, test, Dependency Obituary, SLSA provenance, release
- `.github/workflows/codeql.yml` — CodeQL SAST (security-and-quality query suite)
- `.github/workflows/code-review.yml` — PR lint (golangci-lint via reviewdog), coverage delta, auto go-mod-tidy
- `.github/workflows/security-release-gate.yml` — 10-check security gate (gosec, govulncheck, trivy, gitleaks, staticcheck, hadolint, race tests, coverage, licenses, SBOM)

## Architecture Notes

- **Default deny**: Policy engine defaults to deny when no rule matches (Zero Trust)
- **SSL inspect**: MITM via on-the-fly leaf certs signed by internal CA (ECDSA P-256)
- **Cert cache**: LRU eviction at 10k entries, 1h TTL
- **Hop-by-hop**: Dynamic stripping per RFC 7230 (parses Connection header for additional hop-by-hop names)
- **Relay pattern**: All tunnel relays (CONNECT, WebSocket, SOCKS5) wait for BOTH goroutines; CloseWrite unblocks peers
- **GeoIP policy**: Fails closed on cache miss (unknown country = rule does not match)
- **Admin RBAC**: Three roles — admin (full), operator (write), viewer (read-only)
- **Session**: HMAC-SHA256 signed cookies with configurable TTL (default 8h); dynamic Secure flag based on TLS state
- **Slowloris**: 60s read deadline on SSL-inspected client connections
- **Audit actor**: Enriched with authenticated admin identity from session cookie
- **Threat feed allowlist**: Popular hosting domains (GitHub, Google Drive, etc.) are exempt from domain-level blocking; URL-level blocking still applies. Managed via admin API + UI, persisted in threat feed DB.
- **UnauthMode persistence**: Open/Policy-Only mode survives restarts via JSON envelope format in ui_users.json
- **Performance tuning**: Transport pool uses 512 max idle conns, 64 per host, 128KB relay buffers (sync.Pool), sharded rate limiter (64 shards), lock-free latency histogram
- **Relay buffers**: All tunnel relays (bypass, inspect, WebSocket) use `relayBufPool` (128 KB pooled buffers) via `io.CopyBuffer`
- **Config versioning**: Numbered JSON snapshots in `/data/config_versions/v{N}.json`, 50-version max, auto-created on config mutations via `saveConfigVersion(actor, action)` in 17 API handlers
- **Node groups**: Label selectors (`map[string]string`) for matching enrolled nodes; auto GeoIP labels (`geo:country`, `geo:country_name`) assigned on enrollment/heartbeat
- **Bandwidth/QoS**: Token bucket rate limiting per label group, configurable rates (KB/s, MB/s, GB/s), stored in `/data/bandwidth_policies.json`
- **ConfigSnapshot sync**: CP pushes `ConfigSnapshot` to DP nodes containing policy rules, blocklist, PAC exclusions, threat feed data, session HMAC, bandwidth policies, and node groups
- **Cluster gaps**: All 8 items from CLUSTER-GAPS.md implemented: PAC sync, rolling upgrades, config versioning, geo-aware grouping, bandwidth/QoS, secrets sync, threat feed sync, config diff
- **Compose operator contract (D1.5)**: The profile-gated `cli` service in `docker-compose.yml` is the canonical operator path for backup, restore, and cleanup — `docker compose --profile cli run --rm cli <flags>`. Same image as `proxy` (no version-skew). `/backup` (volume `culvert-backups`) is mounted **only** in `cli`; the `proxy` container must not be able to read its own backups. `cli` must not mount `/var/run/docker.sock`. Restore commit is offline-only (`docker compose down` → `run --rm cli --confirm` → `up -d`); backup, restore dry-run, list-leftovers, and cleanup-leftovers (dry-run **and** `--confirm`) are runtime-OK. The legacy `updater` sidecar is documented as superseded by D1.6 but not removed in D1.5. See `roadmap/D1.5-docker-compose-operator-contract.md` for the design and `docs/operator/docker-compose-backup-restore.md` for the operator-facing how-to.
- **Startup slices (PR3 pilot — shipped)**: All 11 SAFE-zone slices from `roadmap/ARCH_DISCOVERY.md` are extracted under the `<domain>_startup_config.go` (resolver + DTO) + `<domain>_startup.go` (loader) + `<domain>_startup_test.go` (per-slice tests) layout — `fileblock`, `inspection_rules`, `geoip`, `pac`, `mtls_ocsp`, `ui_extras`, `legacy_auth_providers`, `rewrite_default_action`, `ui_access_policy`, `metrics_token`, `session`. Each `init*` in `main.go` is a thin shim. `startup_slice_contract_test.go` pins the resolver convention (purity + determinism) for all of them. **Do not re-extract** `initFileBlocking` or any other shipped pilot — they are covered by the per-slice `*_startup_test.go` files. Future startup extraction must start from the ARCH_DISCOVERY.md MEDIUM-risk list (`initBlocklist`, `initObservability`, `initConnAndRateLimit`, …) and stay small/sliced.
- **Roadmap**: See `roadmap/PHASES.md` for development phases (1–6), `roadmap/ROADMAP.md` for production deployment action items, `roadmap/FEATURE-COVERAGE.md` for GUI coverage audit, `roadmap/UI-DESIGN.md` for panel design reference, `roadmap/CLUSTER-GAPS.md` for cluster gap analysis, `roadmap/D1.6-maintenance-agent-design.md` for the Maintenance Agent / host-operations design (supersedes the deprecated `roadmap/docker-system-update.md`), `roadmap/roadmap-day2.md` for day-2 code review findings (108 items across 8 domains), `roadmap/RUNTIME-OWNERSHIP.md` for the Runtime Ownership & Startup Decoupling Program (Phases 0–6, stable SPOF IDs S1–S10)

## Admin UI / Control Plane

The admin API is wired in three layers — `startUI()` only composes them, never registers routes itself.

**Route registration**
- `startUI()` MUST NOT contain `mux.HandleFunc` calls. All routes are registered through per-domain `register*Routes(mux, ...)` helpers (e.g. `registerPolicyRoutes`, `registerSecurityRoutes`).
- `uiRoutes` in `ui_routes_meta.go` is the **single source of truth** for route metadata. Adding a route means: (1) register it via a `register*Routes` helper, (2) add a corresponding `uiRouteMetadata` entry to `uiRoutes`.
- Metadata is **method-aware** via `Methods []uiRouteMethod`. Each entry declares `Method`, `MinRole`, `Mutating`, `AuditExpected`, plus an optional note. `MethodAny` (`"*"`) is the catch-all when a handler intentionally treats every method the same.

**Middleware chain (outer → inner)**

```
uiIPGuardMiddleware → securityMiddleware → uiAuthMiddleware → uiMetadataEnforcement → mux
```

- `uiAuthMiddleware` owns the public-route allowlist and injects `uiRoleKey{}` into the request context.
- `uiMetadataEnforcement` (C2) reads that role and gates the request against per-method `MinRole` from `uiRoutes`. **Active by default** — fail-closed.
- `securityMiddleware` still owns CSRF, body-limit, and rate-limit decisions based on the HTTP method. The `Mutating` flag in metadata is **informational only**; it does not alter middleware behavior.

**Kill switch**
- `CULVERT_C2_ENFORCE=false` (or `0`/`no`/`off`) reverts C2 to shadow mode (log-only, never blocks). Read once at startup; admin-API runtime mutation is intentionally not supported.

**AuditExpected (C2c)**
- Pure observability. After a 2xx/3xx response, if metadata says `AuditExpected=true` and no `auditEvent`/`auditEventDiff` ran, the middleware emits one `C2: audit missing ...` log line and increments `c2AuditMissingTotal`. Failed requests, hijacked responses, and public routes are skipped. C2c **never** blocks a request.

**Role-divergence detector (C4 — REPORT-ONLY)**
- Pure observability. When the C2 middleware admits a request whose per-method `MinRole` is *lower* than what the handler-level `requireRole` ultimately demands (e.g. `apiIdPRouter` declares `MethodAny=viewer` but `apiIdPItem`'s PUT branch calls `requireRole(RoleAdmin)`), C4 increments `c2RoleDivergenceTotal` and emits one `C2: role divergence ...` log line. The middleware injects the C2-evaluated `MinRole` into the request context; `requireRole`'s failure branch reads that value and compares against the role it just rejected.
- C4 **never** blocks, allows, or alters the response. The handler's existing `requireRole` writes the 403 itself; C4 only observes the decision after the fact. Defense-in-depth (invariant #6) is preserved; the handler is still the real backstop.
- Audit ring is intentionally untouched — divergence events are governance observability, not admin-action audit. They flow out via the structured logger and the C3 governance endpoint only.

**Governance surface (C3)**
- `GET /api/governance/control-plane` (admin-only) exposes route inventory, C2 mode, the six C2 counters, derived health (four axes), and the parity-test pyramid (D0/C1/C1.5/C2/C2c/C4). Read-only and side-effect-free; no Prometheus exposure, no AST replay, no schema mutation. The kill switch stays env-only and read-once.
- C3 health severity policy (`deriveGovernanceHealth`):
  - `missing_meta > 0` → `metadata_parity = drift`, status = `drift`. C1 reverse-parity should make this impossible at runtime, so any non-zero value is genuine governance/config drift.
  - `no_policy > 0` → `metadata_parity = warn`, status ≥ `warn`. The counter can be triggered by a client sending a method the route does not accept (e.g. PATCH against a GET-only route, scanner probes); reserving drift for `missing_meta` keeps the indicator from flipping to drift on benign client traffic.
  - `audit_missing > 0` → `audit_completion = warn`, status ≥ `warn`.
  - `enforce_denied > 0` while `mode = shadow` → `enforce_consistency = drift`, status = `drift` (the kill-switch contract is read-once at startup).
  - `role_divergence > 0` → `role_divergence = warn`, status ≥ `warn`. Triggered legitimately by viewers probing admin-only sub-actions on dynamic dispatchers; reserved for warn rather than drift to avoid noise on benign client traffic.
- The six C2 counters surfaced by C3 (one-line definitions):
  - `would_deny` — session role was below the per-method `MinRole`. Increments in BOTH shadow and enforce modes; tracks the policy decision regardless of action.
  - `enforce_denied` — request actually got a 403 from the metadata-driven gate. Stays at zero in shadow mode; in enforce mode it moves in lock-step with `would_deny`.
  - `missing_meta` — request path resolved through the mux but had no matching `uiRoutes` entry (the static `/` catch-all absorbs unknown paths, so this is rare in practice). Soft-fail; never blocks a request.
  - `no_policy` — path matched a `uiRoutes` entry but the HTTP method had no exact policy and no `MethodAny` fallback. Soft-fail; never blocks a request. Triggered both by genuine drift and by clients sending unsupported methods (see severity policy above).
  - `audit_missing` — successful request (2xx/3xx) on an `AuditExpected=true` route did not emit an `auditEvent`/`auditEventDiff` call (C2c observability).
  - `role_divergence` — handler-level `requireRole` rejected a request whose C2-evaluated `MinRole` was strictly lower (i.e. metadata was more permissive than the handler's actual contract). Increments at most once per request, on the failure branch of `requireRole`. Observability only; never blocks.

### Admin UI / Control Plane Invariants

These are non-negotiable for any change touching the admin API:

1. **No route without metadata.** Every `mux.HandleFunc` path must have a matching `uiRoutes` entry. C1 forward/reverse parity tests enforce this.
2. **Metadata must never be more permissive than handler behavior.** If the handler enforces admin, metadata cannot say viewer. C1.5 AST parity tests enforce this for directly detectable handler behavior; dynamic/delegated handlers must be documented and reviewed.
3. **Resolution order: specific method > MethodAny > soft-fail.** Don't use `MethodAny` to paper over a method-specific contract.
4. **Missing metadata / no method policy must NEVER block requests.** Both are soft-fail in shadow and enforce mode — they log + count, the handler-level `requireRole` remains the real backstop.
5. **Public routes are owned by `uiAuthMiddleware` only.** C2 stays out (`RolePublic` is documentation, not enforcement). Don't add public-route gates to C2.
6. **Do not remove handler-level `requireRole`.** C2 is an additional gate, not a replacement. Defense-in-depth is the contract.
7. **C2 must never allow what the handler denies.** If they ever disagree, the handler wins by design — C2's role is to add denials, never to widen access.

### Testing Guarantees

Each layer has its own test suite — keep them green when modifying the admin API.

- **D0** (`d0_*_test.go`) — route/auth/security baseline invariants: route inventory pinned at the canonical count, auth allowlist, CSRF, body-limit, and rate-limit checks.
- **C1** (`ui_routes_meta_test.go`) — bidirectional route/metadata parity layer: forward (every `uiRoutes` entry has a matching `mux.HandleFunc`) and reverse (every `mux.HandleFunc` has a matching `uiRoutes` entry), source-scan based.
- **C1.5** (`ui_routes_meta_audit_test.go`) — AST-walk parity between metadata `MinRole`/`Mutating` and the per-method behavior of each handler (`requireRole` calls, method switches).
- **C2** (`ui_metadata_enforcement_test.go`) — middleware enforcement: shadow mode is silent, enforce mode returns 403, kill switch toggles correctly, missing-meta and no-policy stay soft-fail.
- **C2c** (`ui_metadata_enforcement_test.go` — `TestC2c_*`) — audit-completion observability: warns on success without audit, silent on failure / hijacked / public / `AuditExpected=false`, never blocks the request.
- **C4** (`ui_metadata_divergence_test.go` — `TestC4_*`) — report-only role-divergence detector: increments `c2RoleDivergenceTotal` and emits a structured log line when the handler's `requireRole(R)` rejects a request whose C2-evaluated `MinRole` was strictly lower. Tests cover the canonical viewer-on-admin-route case via `apiIdPRouter`, the parity case (no event), the C2-stricter case (no event), and the response-decision invariance proof (C4 cannot change the 403 the handler already wrote).

### Test-authoring pitfalls

- **Audit ring saturation.** The in-memory audit ring is bounded at `maxAuditLogs = 500`. Tests MUST NOT assert on `len(auditGet())` deltas (e.g. `len(after) == len(before)+1`) because under `-count=2 -shuffle=on` the cumulative suite saturates the ring and `len()` stops growing — adding a new entry evicts the oldest. The determinism gate (`QA · Determinism`) re-runs the suite shuffled to flush these out. Instead, assert on entry **content**: scan `auditGet()` for an entry matching a unique discriminator (`Actor` IP from a TEST-NET-2 reserved range, plus `Action`/`Object`, plus a baseline `TS` captured before the call). See `security_feedsync_audit_test.go` for the canonical pattern.
