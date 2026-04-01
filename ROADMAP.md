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

## Phase 6: Architecture Review Hardening ✅ (P0) / 🔧 (P1-P3)

Based on a three-reviewer expert architecture audit. Current score: **6.5/10**.

### P0 — Critical Fixes  ()
- [ ] **Goroutine leak fix:**
- [ ] **RFC 7230 hop-by-hop:**
- [ ] **SystemCertPool fail-closed:** 
- [ ] **GeoIP fail-closed:** 
- [ ] **Cert cache LRU + TTL:**
- [ ] **Blocklist double-add:**

### P1 — Security Hardening (Next Sprint)
- [ ] **Slowloris protection:** Add read deadline to SSL inspect HTTP request loop (`proxy.go:809`)
- [ ] **Session cookie Secure flag:** Use dynamic `isSecureRequest(r)` instead of hardcoded `true` (`session.go:219`)
- [ ] **Audit log actor:** Use authenticated admin username, not just source IP (`ui.go:692`)
- [ ] **Wildcard blocklist depth:** Walk full label chain so `*.example.com` blocks `a.b.example.com` (`store.go:393`)
- [ ] **Exception list safety:** Add exact-only mode, warn on broad domain exceptions (`store.go:409`)
- [ ] **Schedule timezone validation:** Reject invalid IANA timezone strings, log warning (`policy.go:517`)
- [ ] **OIDC explicit context timeout:** Use `context.WithTimeout` on token/userinfo/introspection calls (`auth_oidc_flow.go`)
- [ ] **LDAP anonymous bind guard:** Warn/reject empty BindDN when RequiredGroup is configured (`auth_ldap.go:136`)

### P2 — Performance & Compliance (This Quarter)
- [ ] **Policy audit trail:** Log matched rule ID + conditions for every policy evaluation
- [ ] **CSRF behind reverse proxy:** Check `X-Forwarded-Host` in `isSameOrigin()`
- [ ] **DNS caching for SSRF checks:** TTL cache for `isPrivateHost()` lookups
- [ ] **Global http.Client reuse:** Single client instead of per-request allocation
- [ ] **ClamAV connection pooling:** Semaphore-limited pool instead of per-scan dial
- [ ] **YARA regex timeout:** Context-based timeout on pattern matching (ReDoS prevention)
- [ ] **Content-Length pre-check:** Validate before buffering response body for scan
- [ ] **PBKDF2 iteration increase:** 100k → 600k (NIST 2024 guidance)
- [ ] **Data Plane backoff:** Exponential backoff on Control Plane connection failure
- [ ] **Multi-IdP group resolution:** Document provider priority, add provider selection
- [ ] **Log rotation cleanup:** Delete old `.1` files on rotation

### P3 — Enterprise Features (Next Quarter)
- [ ] **Upstream proxy chaining / failover** — Route through parent proxies with health checks
- [ ] **Circuit breaker** — Stop forwarding to hung upstreams after N failures
- [ ] **Policy conflict detection** — Warn when rules contradict at same priority
- [ ] **Request/response size logging** — Log bytes transferred per request (data exfiltration detection)
- [ ] **Hot config reload** — SIGHUP reloads YAML without restart
- [ ] **Per-rule Prometheus metrics** — With cardinality cap
- [ ] **Client certificate (mTLS)** — Mutual TLS for upstream servers
- [ ] **CA auto-rotation** — Scheduled CA cert renewal with overlap period
- [ ] **HSM/KMS integration** — Store CA key in hardware/cloud KMS
- [ ] **OCSP/CRL checking** — Verify upstream cert revocation status

## Score Targets

| Milestone | Rating | Key Deliverables |
|-----------|--------|------------------|
| P0 done | **7.0/10** | Critical bugs fixed, fail-closed everywhere |
| P1 done | **7.5/10** | Auth hardened, wildcards fixed, audit useful |
| P2 done | **8.5/10** | Performance ready, compliance audit-ready |
| P3 done | **9.0/10** | Enterprise-grade HA, PKI, observability |
