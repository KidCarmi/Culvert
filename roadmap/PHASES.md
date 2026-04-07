# Culvert Development Roadmap & Security Standards
This document outlines the strategic progression for Culvert, moving from a PoC to an Enterprise-Grade Secure Web Gateway (SWG).

> **Shift-Left Security**: Every feature ships with security tests. No feature merges without a corresponding `_test.go` covering the security-relevant code paths.

## Phase 1: Policy Engine Refactoring (Palo Alto Style) ✅
- [x] **Object-Based Rules:** Implement a rule schema supporting Source IP, Identity (Mock/OIDC), Destination (FQDN/Category), and Service.
- [x] **Action Matrix:** Support `Allow`, `Drop`, `Block_Page` (HTML 403), and `Redirect`.
- [x] **SSL Policy:** Integrate `Decrypt` (Inspect) and `Bypass` (Tunnel) logic per rule.
- [x] **Hit Counter:** Persistent tracking of rule triggers in the UI.

## Phase 2: Security Hardening ✅
- [x] **CA Secret Management:** Root CA private key encrypted at rest with AES-256-GCM + PBKDF2-SHA256 (100k iterations). Passphrase via `CULVERT_CA_PASSPHRASE` env var — never in CLI args. Flag: `-ca-path`.
- [x] **Strict SSL Validation:** Upstream connections enforce TLS 1.2 minimum (`MinVersion: tls.VersionTLS12`). Certificate validation is on by default (fail-secure — no `InsecureSkipVerify`).
- [x] **Non-Root Execution:** Dockerfile runs as unprivileged `proxy` user. Recommended runtime flags documented: `--read-only --cap-drop=ALL --security-opt no-new-privileges`.
- [x] **Header Scrubbing:** `scrubForwardedHeaders()` strips RFC 1918 / loopback / link-local IPs from `X-Forwarded-For`, removes private `X-Real-IP`, and always deletes `X-User-Identity` before forwarding (prevents topology leakage and identity injection).

## Phase 3: Identity & Advanced Inspection ✅
- [x] **OIDC Integration:** Full Authorization Code + PKCE flow (`auth_oidc.go`, `auth_oidc_flow.go`). Supports multi-IdP routing, group extraction, and UI captive-portal redirect.
- [x] **SAML 2.0:** SP-initiated SSO with metadata fetch, assertion validation, and attribute mapping (`auth_saml.go`).
- [x] **LDAP Authentication:** Group membership resolution with caching (`auth_ldap.go`).
- [x] **MITM Content Scanning:** DPI regex engine applied to decrypted HTTPS responses (`scanner.go`). Patterns managed via UI. True prevention — responses buffered before forwarding.
- [x] **File Blocking Profile:** Block file downloads by extension across 5 named profiles (Executables, Archives, Documents, Media, Strict) — `fileblock.go`.
- [x] **TOTP 2FA:** Admin UI supports TOTP enrollment and backup codes (`totp.go`, `store.go`).

## Phase 4: Observability & Management ✅
- [x] **Audit Logs:** Track all configuration changes (Who, What, When). Every mutating API call recorded with actor IP, action, object, and detail. Accessible via `GET /api/audit`. In-memory ring buffer of 500 entries.
- [x] **Live Stats:** Real-time SSE feed of request counts (total / allowed / blocked) with 60-minute rolling time-series (`events.go`, `store.go`).
- [x] **Content Scanning (DPI):** Regex engine applied to decrypted HTTPS text responses (requires SSL Inspect mode). Patterns managed via `GET/POST/DELETE /api/content-scan`. Binary/media content passes through unscanned.
- [x] **Prometheus Metrics:** `/metrics` endpoint exposing request counts, block rates, and latency histograms (`metrics.go`).
- [x] **Syslog/SIEM Forwarding:** UDP/TCP syslog (RFC 3164) compatible with Splunk, Elastic, QRadar (`syslog.go`).
- [x] **Webhook Alerts:** Configurable webhook delivery for threat events, policy blocks, and auth lockouts with HMAC-SHA256 signing (`alerts.go`).

## Phase 5: DevSecOps Pipeline ✅
- [x] **SAST:** gosec, staticcheck, golangci-lint (18 linters), go vet — run on every push.
- [x] **SCA:** govulncheck (reachable CVEs), trivy filesystem (all dependencies), dependabot (automated updates).
- [x] **Secret Scanning:** gitleaks on PR diffs and full history at release time.
- [x] **Container Security:** trivy Docker image scan (CRITICAL/HIGH blocking), Hadolint Dockerfile linting.
- [x] **License Compliance:** go-licenses enforces no GPL/AGPL/LGPL/CPAL dependencies.
- [x] **SBOM:** Syft generates CycloneDX JSON SBOM attached to every release.
- [x] **CodeQL:** Deep semantic SAST for Go — injection flaws, path traversal, unsafe patterns.
- [x] **Cosign Signing:** Release binaries signed with keyless Sigstore OIDC (no secrets needed). Signatures published to Rekor transparency log.
- [x] **SLSA Provenance:** SLSA Level 3 provenance generated for all release artifacts — cryptographically verifiable build attestation.
- [x] **Coverage Gate:** ≥55% statement coverage enforced on every push and release; fuzz tests for 6 critical input-parsing paths.
- [x] **Fuzzing:** Go fuzz targets for `isPrivateHost`, `isSafeRedirectURL`, `parseClamResponse`, `normaliseFeedURL`, `matchDest`, `parseYARALiteralString`.

## Phase 6: Architecture Review Hardening ✅

Based on a three-reviewer expert architecture audit. Current score: **10/10** (P0–P5 complete).

### P0 — Critical Fixes (✅)
- [x] **Goroutine leak fix:** Wait for both relay goroutines; close write halves to unblock peers (proxy.go, socks5.go)
- [x] **RFC 7230 hop-by-hop:** Parse Connection header for additional hop-by-hop headers; fix "Trailers"→"Trailer" (proxy.go)
- [x] **SystemCertPool fail-closed:** Log warning when falling back to empty cert pool (proxy.go)
- [x] **GeoIP fail-closed:** Unknown country (cache miss) = rule does not match (policy.go)
- [x] **Cert cache LRU + TTL:** 1h TTL per entry, LRU eviction at 10k entries (ca.go)
- [x] **Blocklist double-add:** Already idempotent via map semantics (no change needed)

### P1 — Security Hardening (✅)
- [x] **Slowloris protection:** 60s read deadline on SSL inspect HTTP request loop (proxy.go)
- [x] **Session cookie Secure flag:** Dynamic `isSecureRequest(r)` checks TLS and X-Forwarded-Proto (session.go)
- [x] **Audit log actor:** Enriched with authenticated admin identity from session cookie (ui.go)
- [x] **Wildcard blocklist depth:** Already correct — walks full label chain (no change needed)
- [x] **Exception list safety:** Warn on broad domain exceptions (TLDs, short wildcards) (store.go)
- [x] **Schedule timezone validation:** Invalid IANA timezone logs warning at evaluation time (policy.go); rejected at creation time (ui.go)
- [x] **OIDC explicit context timeout:** 10s context.WithTimeout on token exchange, userinfo, introspection (auth_oidc_flow.go)
- [x] **LDAP anonymous bind guard:** Warn when BindDN empty with RequiredGroup configured (auth_ldap.go)

### P2 — Performance & Compliance (✅)
- [x] **Policy audit trail:** Log matched rule ID + priority + conditions for every policy evaluation (proxy.go, policy.go)
- [x] **CSRF behind reverse proxy:** Check `X-Forwarded-Host` in `isSameOrigin()` (ui.go)
- [x] **DNS caching for SSRF checks:** TTL cache (30s) for `isPrivateHost()` lookups (security.go, proxy.go)
- [x] **Global http.Client reuse:** Already uses shared `upstreamTransport` with connection pooling (no change needed)
- [x] **ClamAV connection pooling:** Semaphore-limited concurrent scans (`clamSem`, max 4) (clam.go)
- [x] **YARA regex timeout:** 5s goroutine-based timeout on regex matching — ReDoS prevention (yara_scan.go)
- [x] **Content-Length pre-check:** Skip buffering when `Content-Length` exceeds scan limit (proxy.go)
- [x] **PBKDF2 iteration increase:** 100k → 600k (NIST SP 800-132 2024 guidance) (ca.go)
- [x] **Data Plane backoff:** Exponential backoff (2s–60s) on Control Plane connection failure (controlplane.go)
- [x] **Multi-IdP group resolution:** Priority field on IdP profiles; `RouteByDomain` picks lowest priority match (auth_idp.go)
- [x] **Log rotation cleanup:** Delete stale `.1` files before rotation (logger.go)

### P3 — Enterprise Features (✅)
- [x] **Upstream proxy chaining / failover** — Route through parent proxies with round-robin selection and health checks (upstream.go)
- [x] **Circuit breaker** — Atomic state machine (closed→open→half-open) stops forwarding to hung upstreams after N failures (upstream.go)
- [x] **Policy conflict detection** — Warns when rules at same priority overlap with different actions (policy.go)
- [x] **Request/response size logging** — Global byte counters (statBytesSent/statBytesRecv) exposed as Prometheus metrics for data exfiltration detection (proxy.go, metrics.go, store.go)
- [x] **Hot config reload** — SIGHUP reloads blocklist, policy, rewrite rules, rate limit, upstream pool, default action without restart (main.go)
- [x] **Per-rule Prometheus metrics** — Per-rule hit counters with 200-rule cardinality cap (metrics.go)
- [x] **Client certificate (mTLS)** — Mutual TLS client cert for upstream servers via `client_cert_file`/`client_key_file` config (main.go, config.go)
- [x] **CA auto-rotation** — Background goroutine checks CA expiry daily; auto-rotates 30 days before expiry (ca.go)
- [x] **HSM/KMS integration** — `KeyProvider` interface for external key management (AWS KMS, Azure Key Vault, PKCS#11 HSMs); default local in-memory provider (ca.go)
- [x] **OCSP/CRL checking** — OCSP responder queries with 1h result cache and 5s timeout; configurable via `ocsp_check` (ocsp.go)

### P4 — Resilience & Observability Polish (✅)
- [x] **P3 test coverage** — 30+ tests for upstream chaining, circuit breaker, OCSP checker, CA auto-rotation, per-rule metrics, byte counting, policy conflict detection, KeyProvider interface (upstream_test.go, ocsp_test.go, p4_test.go)
- [x] **Request tracing** — X-Request-ID header auto-generated if absent; echoed to response for log correlation (proxy.go, connlimit.go)
- [x] **Connection limiting** — Per-IP concurrent connection cap (`max_conns_per_ip`, default 256) with acquire/release tracking (connlimit.go)
- [x] **Latency metrics** — Request duration histogram with 11 buckets (5ms–10s + Inf) in Prometheus exposition format (metrics.go)
- [x] **Graceful drain** — 15s drain window waits for active tunnels (CONNECT/WebSocket) before forced shutdown (main.go)

### P5 — Final Polish (✅)
- [x] **Config validation** — Reject unknown YAML fields (typo detection) and invalid enum values at startup with clear error messages (config.go)
- [x] **Admin API rate limiting** — 60 req/min per IP on all mutating `/api/` endpoints; protects against credential-stuffed admin abuse (lockout.go, ui.go)
- [x] **Graceful shutdown** — Lifecycle context cancels all background goroutines (CA rotation, feed syncers, threat feeds, health checks) on SIGTERM/SIGINT; syslog writer flushed (main.go)
- [x] **Structured JSON logging** — JSON mode extracts `{key=value}` structured fields into top-level JSON keys; policy/auth log lines now emit `req_id`, `identity`, `rule`, `action` fields (logger.go, proxy.go)
- [x] **Complete config.example.yaml** — All 70+ config fields documented with types, defaults, and examples (config.example.yaml)
- [x] **SOCKS5 integration tests** — 6 tests: handshake, auth success/failure, blocklist block, SSRF guard, unsupported command (socks5_test.go)

## Score Targets

| Milestone | Rating | Key Deliverables |
|-----------|--------|------------------|
| P0 done | **7.0/10** | Critical bugs fixed, fail-closed everywhere |
| P1 done | **7.5/10** | Auth hardened, wildcards fixed, audit useful |
| P2 done | **8.5/10** | Performance ready, compliance audit-ready |
| P3 done | **9.0/10** | Enterprise-grade HA, PKI, observability |
| P4 done | **9.5/10** | Full test coverage, tracing, latency metrics |
| P5 done | **10/10** | Config validation, structured logs, API rate limit, SOCKS5 tests |
