# Culvert

Enterprise-grade open-source HTTP/HTTPS/SOCKS5 forward proxy written in Go.
Single binary, zero runtime dependencies.

## Project Structure

```
*.go          — All source in package main (flat layout, no internal/)
main.go       — Entrypoint, flag parsing, signal handling, graceful shutdown
proxy.go      — HTTP/CONNECT/WebSocket handlers, tunnel relay, upstream transport
socks5.go     — SOCKS5 protocol handler (RFC 1928/1929)
policy.go     — Policy engine: rule evaluation, FQDN/category/GeoIP/schedule matching
store.go      — Persistent state: blocklist, request log, audit log, config store
ca.go         — Root CA management, leaf cert signing, encrypted CA bundle (AES-GCM + PBKDF2)
ui.go         — Admin API + SPA (14 panels), RBAC (admin/operator/viewer)
session.go    — HMAC-SHA256 signed session cookies, revocation list
auth.go       — Local bcrypt auth
auth_ldap.go  — LDAP bind + search auth with group resolution
auth_oidc.go  — OIDC token introspection (RFC 7662)
auth_oidc_flow.go — Full OIDC Authorization Code + PKCE flow
auth_saml.go  — SAML 2.0 SP via crewjam/saml
auth_idp.go   — Multi-IdP registry
identity.go   — Identity model (Sub, Groups, Source)
clam.go       — ClamAV INSTREAM scanner
yara_scan.go  — Pure-Go YARA rule engine
scanner.go    — Unified DPI + ClamAV + YARA scan coordinator
security.go   — Security helpers (SSRF guard, header scrub, sanitizeLog)
fileblock.go  — File extension/MIME blocking profiles
geoip.go      — MaxMind GeoLite2 country lookup with background cache
controlplane.go — gRPC-based Control Plane / Data Plane distributed architecture
metrics.go    — Prometheus metrics (culvert_* namespace)
alerts.go     — Webhook alerting for security events
threatfeed.go — Threat intelligence feed integration
blocklist_feed.go — Blocklist URL feed syncer
rewrite.go    — HTTP header rewrite rules
plugin.go     — Middleware plugin API
logger.go     — Rotating file logger with JSON mode
syslog.go     — Syslog SIEM forwarding (UDP/TCP)
config.go     — YAML + CLI flag configuration
pac.go        — PAC file generator
hashcache.go  — SHA-256 scan result cache with TTL
lockout.go    — Brute-force lockout (IP + user)
totp.go       — TOTP 2FA support
tls.go        — TLS helpers
blockpage.go  — Block page HTML template
events.go     — SSE event stream for live UI
catdb.go      — URL category database
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

## Code Conventions

- **Package**: Everything is `package main` (flat layout)
- **Go version**: 1.25
- **Logging**: Use `logger.Printf()`, never `log.Printf()` or `fmt.Printf()`
- **User input in logs**: Always wrap with `sanitizeLog(s)` (CWE-117 prevention)
- **HTTP contexts**: Use `http.NewRequestWithContext()`, never bare `http.NewRequest()`
- **Errors**: Return `fmt.Errorf("context: %w", err)` for wrapping
- **Concurrency**: Use `sync.RWMutex` for read-heavy stores, `atomic` for counters
- **Security**: SSRF checks via `isPrivateHost()` before any outbound dial
- **Tests**: Test files use `_test.go` suffix, same package (whitebox)
- **Lint suppressions**: Use `//nolint:errcheck` with reason comment; `// #nosec G402` for gosec

## CI Pipelines

- `.github/workflows/ci.yml` — Build, test, SLSA provenance, release
- `.github/workflows/codeql.yml` — CodeQL SAST
- `.github/workflows/code-review.yml` — PR lint, coverage delta, auto go-mod-tidy
- `.github/workflows/security-release-gate.yml` — 10-check security gate (gosec, govulncheck, trivy, gitleaks, staticcheck, hadolint, race tests, coverage, licenses, SBOM)

## Architecture Notes

- **Default deny**: Policy engine defaults to deny when no rule matches (Zero Trust)
- **SSL inspect**: MITM via on-the-fly leaf certs signed by internal CA (ECDSA P-256)
- **Cert cache**: LRU eviction at 10k entries, 1h TTL
- **Hop-by-hop**: Dynamic stripping per RFC 7230 (parses Connection header)
- **Relay pattern**: All tunnel relays (CONNECT, WebSocket, SOCKS5) wait for BOTH goroutines
- **GeoIP policy**: Fails closed on cache miss (unknown country = rule does not match)
- **Admin RBAC**: Three roles — admin (full), operator (write), viewer (read-only)
- **Session**: HMAC-SHA256 signed cookies with configurable TTL (default 8h)
