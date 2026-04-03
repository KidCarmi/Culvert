<p align="center">
  <img src="static/logo.png" alt="Culvert" width="200" />
</p>

<h1 align="center">Culvert</h1>

<p align="center">
  <strong>Enterprise-grade open-source forward proxy</strong><br/>
  HTTP &middot; HTTPS &middot; SOCKS5 &middot; WebSocket<br/>
  Single binary &middot; Zero dependencies &middot; Written in Go
</p>

<p align="center">
  <a href="https://github.com/KidCarmi/Culvert/actions/workflows/ci.yml"><img src="https://github.com/KidCarmi/Culvert/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/KidCarmi/Culvert/actions/workflows/codeql.yml"><img src="https://github.com/KidCarmi/Culvert/actions/workflows/codeql.yml/badge.svg" alt="CodeQL" /></a>
  <a href="https://github.com/KidCarmi/Culvert/actions/workflows/security-release-gate.yml"><img src="https://github.com/KidCarmi/Culvert/actions/workflows/security-release-gate.yml/badge.svg" alt="Security Gate" /></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a>
  <a href="https://goreportcard.com/report/github.com/KidCarmi/Culvert"><img src="https://goreportcard.com/badge/github.com/KidCarmi/Culvert" alt="Go Report Card" /></a>
</p>

---

## Why Culvert?

Most forward proxies force you to choose: commercial appliance with vendor lock-in, or a minimal open-source tool you have to build around. Culvert is neither. It ships as a **single Go binary** with everything built in — SSL inspection, identity-aware policy, antivirus scanning, threat feeds, a full admin UI, and enterprise auth (OIDC, SAML, LDAP) — all without plugins, agents, or runtime dependencies.

Deploy it with `docker-compose up -d` and you get a production-ready proxy with zero-trust default-deny, real-time dashboards, Prometheus metrics, and a 10-check CI security pipeline. Scale it out with the built-in gRPC Control Plane for multi-node deployments. Extend it with the plugin API when you need custom logic.

---

## Features

### Proxy & Protocols

- **HTTP / HTTPS** forward proxy with full CONNECT tunnel support
- **SSL/TLS inspection** — on-the-fly MITM certs (ECDSA P-256), per-host bypass, LRU cert cache (10k entries, 1h TTL)
- **SOCKS5** proxy (RFC 1928/1929) with username/password auth
- **WebSocket** tunneling through CONNECT
- **PAC file** auto-generation for browser auto-configuration
- **Upstream proxy chaining** with round-robin, health checks, and automatic failover
- **Circuit breaker** — stops forwarding to hung upstream proxies after consecutive failures

### Policy Engine (Zero Trust)

- **Default deny** — unmatched traffic is blocked
- **Priority-based rules** — first match wins across 8 condition types:
  - Source IP / CIDR
  - Authenticated identity
  - IdP group membership
  - Auth source (OIDC, SAML, LDAP, local)
  - Destination FQDN (exact + wildcard)
  - URL category (Social, Streaming, Gambling, News, Malicious, Adult, ...)
  - Destination country (GeoIP, fail-closed on cache miss)
  - Time schedule (day of week + time window + timezone)
- **Actions**: Allow, Drop, Block Page, Redirect
- **Per-rule SSL action**: Inspect (full MITM) or Bypass (transparent tunnel)
- **Policy conflict detection** — warns on overlapping rules at same priority
- **Per-rule Prometheus metrics** with cardinality cap

### Authentication & Identity

- **Local auth** with bcrypt hashes and first-run setup wizard
- **OIDC** Authorization Code + PKCE (Okta, Azure AD, Google, Auth0, Keycloak)
- **SAML 2.0** SP-initiated SSO (Okta, Azure AD, ADFS)
- **LDAP** bind + search with group resolution (Active Directory, OpenLDAP, FreeIPA)
- **Multi-IdP** — simultaneous providers with email-domain routing
- **TOTP 2FA** with backup codes for admin accounts
- **RBAC** — admin / operator / viewer roles

### Content Security

- **ClamAV** antivirus (INSTREAM protocol, connection pooling, auto-detection)
- **YARA rules** — pure-Go engine (no libyara), runtime reload, ReDoS-safe (5s timeout)
- **Threat feeds** — URLhaus + OpenPhish with hourly sync
- **DPI** — regex content scanning on decrypted HTTPS responses
- **File-type blocking** — 5 named profiles (Executables, Archives, Documents, Media, Strict)
- **Domain blocklist** with wildcard matching and allow-list mode
- **URL category database** (UT1) with background sync
- **SHA-256 scan cache** with configurable size + TTL

### Admin Web UI

14-panel single-page application with real-time updates:

| Panel | Description |
|-------|-------------|
| Dashboard | Live stats, timeseries chart, top domains, country traffic map |
| Live Feed | Real-time request log with filtering and CSV/JSON export |
| Blocklist | Domain entries with wildcards; allow-list / deny-list toggle |
| Policy | Visual PBAC rule editor with all 8 condition types |
| Policy Tester | Dry-run evaluation against any host/user/IP |
| Security | IP filter, rate limiting, SSL bypass, scanner status |
| File Block | File-type blocking profile selector |
| Rewrite | Per-host header rewrite rules (request + response) |
| IdP Providers | Step-by-step wizard for OIDC, SAML, LDAP |
| Certificates | Root CA viewer, rotation, custom TLS upload |
| PAC | PAC file generator with custom exclusions |
| Audit Log | Tamper-evident JSONL trail of all admin actions |
| Users | User management with RBAC role assignment |
| Settings | Session timeout, UI access control, SIEM, config export/import |

### Observability & SIEM

- **Prometheus metrics** — requests, blocks, auth failures, AV scans, YARA matches, bytes transferred, latency histogram, per-rule counters
- **Real-time SSE** dashboard feed
- **Structured logging** — text or JSON with `req_id`, `identity`, `rule`, `action` fields
- **Rotating log files** with configurable size threshold
- **Syslog forwarding** (UDP/TCP, RFC 3164) for Splunk, Elastic, QRadar
- **JSONL audit trail** with actor identity enrichment
- **Webhook alerts** — HMAC-SHA256 signed notifications for threats, blocks, lockouts
- **Request tracing** — auto-generated X-Request-ID for end-to-end correlation

### Resilience & Operations

- **Hot config reload** — `SIGHUP` reloads blocklist, policy, rewrite, rate limit, upstream pool
- **Graceful shutdown** — lifecycle context + 15s drain window for active tunnels
- **CA auto-rotation** — daily expiry check, auto-rotates 30 days before expiry
- **OCSP/CRL checking** on upstream TLS certificates (fail-closed)
- **Per-IP connection limiting** (default 256 concurrent)
- **Brute-force lockout** — 5 failures triggers 15-min IP + user lock
- **Admin API rate limiting** — 60 req/min per IP on mutating endpoints
- **Atomic file writes** for CA bundle and config persistence
- **PBKDF2 600k iterations** (NIST SP 800-132 2024) for CA key encryption

### Distributed Architecture

- **Control Plane / Data Plane** — gRPC config sync with mTLS
- **Exponential backoff** on connection failures (2s–60s)
- **Client mTLS** for upstream proxy authentication

### Extensibility

- **Plugin API** — `Middleware` interface for custom request/response inspection
- **HSM/KMS integration** — `KeyProvider` interface (AWS KMS, Azure Key Vault, PKCS#11)

---

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/KidCarmi/Culvert
cd Culvert
docker-compose up -d
```

No configuration required — the setup wizard creates your admin account on first visit.

| Endpoint | URL | Notes |
|----------|-----|-------|
| HTTP/HTTPS Proxy | `http://localhost:8080` | Configure browser/PAC to point here |
| SOCKS5 Proxy | `socks5://localhost:1080` | Disabled by default, enable via config |
| PAC File | `http://localhost:8080/proxy.pac` | Auto-config for browsers |
| Admin Web UI | `https://localhost:9090` | Accept the self-signed cert on first visit |
| Health Check | `http://localhost:8080/health` | `{"status":"ok",…}` |
| Prometheus Metrics | `http://localhost:8080/metrics` | Optional bearer token protection |

```bash
# Verify it works
curl http://localhost:8080/health
curl -x http://localhost:8080 https://example.com
```

#### With custom config

```bash
cp config.example.yaml config.yaml   # edit as needed
# Uncomment the config.yaml volume mount in docker-compose.yml, then:
docker-compose up -d
```

#### With monitoring stack (Prometheus + Grafana)

```bash
docker-compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d
# Grafana → http://localhost:3000  (admin / culvert)
```

### Binary

```bash
# Download the latest release, then:
./culvert                                  # proxy :8080, admin UI :9090
./culvert -port 3128 -socks5-port 1080
./culvert -config config.yaml
```

---

## Proxy Usage

### HTTP / HTTPS

```bash
curl -x http://localhost:8080 https://example.com

# With credentials
curl -x http://alice:secret@localhost:8080 https://example.com

# Via environment variable
export http_proxy=http://localhost:8080
export https_proxy=http://localhost:8080

# PAC file (auto-configure browsers)
# Point your browser to: http://localhost:8080/proxy.pac
```

### SOCKS5

```bash
curl --proxy socks5://localhost:1080 https://example.com

# SSH tunneling through SOCKS5
ssh -o ProxyCommand="nc -X 5 -x localhost:1080 %h %p" user@remote
```

### SSL Inspection

When SSL inspection is enabled, import the Root CA into your browser/OS trust store:

```bash
# Download CA from Admin UI → Certificates, or:
curl -k https://localhost:9090/api/ca-cert > culvert-ca.crt

# Linux
sudo cp culvert-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# macOS
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain culvert-ca.crt

# Windows (PowerShell as Admin)
Import-Certificate -FilePath culvert-ca.crt -CertStoreLocation Cert:\LocalMachine\Root
```

---

## Configuration

Culvert works out of the box with sensible defaults. All settings can be managed through the Admin Web UI, a YAML config file, CLI flags, or a combination. See [`config.example.yaml`](config.example.yaml) for full documentation of all 70+ fields.

### config.yaml (optional)

```yaml
proxy:
  port: 8080
  ui_port: 9090
  socks5_port: 1080      # 0 = disabled

default_action: block     # allow | block | drop

auth:
  ldap:
    url: ldaps://ldap.corp.com:636
    bind_dn: "cn=svc-culvert,ou=Services,dc=corp,dc=com"
    base_dn: "ou=Users,dc=corp,dc=com"
    required_group: "proxy-users"

security:
  ip_filter_mode: allow   # allow | block | "" (off)
  ip_list:
    - 192.168.1.0/24
  rate_limit: 60          # requests/min per IP
  max_conns_per_ip: 256

upstream:
  proxies:
    - url: http://parent-proxy:3128
      health_interval: 30s
  circuit_breaker:
    threshold: 5
    timeout: 30s

rewrite:
  - host: "*.internal.example.com"
    req_set:
      X-Forwarded-By: Culvert
    resp_remove:
      - Server
      - X-Powered-By
```

### CLI Flags

```
Core:
  -port int              Proxy listening port (default 8080)
  -ui-port int           Admin Web UI port (default 9090)
  -socks5-port int       SOCKS5 proxy port (0 = disabled)
  -config string         Path to config.yaml

TLS:
  -ca-path string        Root CA bundle persistence path (/data/ca.bundle)
  -tls-cert string       Custom TLS certificate for Web UI
  -tls-key string        Custom TLS key for Web UI
  -ui-no-tls             Serve Web UI over plain HTTP (not recommended)

Auth & Access:
  -ui-users-file string  Persistent admin user database (/data/ui_users.json)
  -ui-allow-ip string    Comma-separated CIDRs allowed to access the Web UI
  -session-timeout int   Admin session lifetime in hours (default 8)

Rules & Filtering:
  -blocklist string      Domain/IP blocklist file path
  -policy string         Policy rules JSON file path
  -geoip-db string       MaxMind GeoLite2-Country.mmdb path

Security Scanning:
  -clamav-addr string    ClamAV address — tcp:host:port or unix:/path/to/clamd.sock
  -yara-rules-dir string Directory containing .yar / .yara rule files
  -threat-feed-db string Threat feed local database path

Logging:
  -logfile string        Request log file (rotated at -log-max-mb)
  -log-max-mb int        Log rotation threshold in MB (default 50)
  -audit-log string      Persistent JSONL audit log path
  -syslog string         Remote syslog — udp://host:514 or tcp://host:601

Metrics:
  -metrics-token string  Bearer token protecting /metrics (empty = open)
  -rate-limit int        Max requests/min per source IP (0 = off)

Distributed:
  -cp-grpc-addr string   Control Plane gRPC listen address (e.g. :50051)
  -cp-grpc-cert string   Control Plane gRPC TLS certificate
  -cp-grpc-key string    Control Plane gRPC TLS key
  -cp-grpc-ca string     Control Plane gRPC CA for mTLS client validation
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `CULVERT_CA_PASSPHRASE` | CA private key encryption passphrase (required for SSL inspection) |

---

## Prometheus Metrics

Available at `GET http://localhost:8080/metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `culvert_requests_total` | counter | All proxy requests |
| `culvert_requests_allowed` | counter | Forwarded requests |
| `culvert_requests_blocked` | counter | Blocked requests (all reasons) |
| `culvert_requests_auth_fail` | counter | Authentication failures |
| `culvert_bytes_sent_total` | counter | Total bytes sent to clients |
| `culvert_bytes_recv_total` | counter | Total bytes received from upstream |
| `culvert_request_duration_seconds` | histogram | Request latency (11 buckets, 5ms–10s) |
| `culvert_rule_hits_total{rule="..."}` | counter | Per-rule hit counter |
| `culvert_av_scans_total` | counter | ClamAV scans performed |
| `culvert_av_detections_total` | counter | Malware detections |
| `culvert_yara_matches_total` | counter | YARA rule matches |
| `culvert_threat_feed_blocks_total` | counter | Threat feed blocks |
| `culvert_blocklist_size` | gauge | Blocklist entry count |
| `culvert_policy_rules` | gauge | Active PBAC rule count |
| `culvert_uptime_seconds` | gauge | Proxy uptime |

---

## Plugin API

Implement the `Middleware` interface to add custom request inspection:

```go
package main

import "net/http"

type MyPlugin struct{}

func (p *MyPlugin) Name() string { return "my-plugin" }

func (p *MyPlugin) OnRequest(clientIP, method, host string) Decision {
    if host == "ads.example.com" {
        return DecisionBlock
    }
    return DecisionAllow
}

func (p *MyPlugin) OnResponse(resp *http.Response) {
    resp.Header.Del("Server")
}

func init() { RegisterPlugin(&MyPlugin{}) }
```

Plugins run before every other check and can short-circuit the chain.

---

## Security

Culvert follows a defence-in-depth approach:

| Area | Implementation |
|------|---------------|
| **Zero Trust** | Default-deny policy engine; unmatched traffic is blocked |
| **SSRF prevention** | `isPrivateHost()` resolves DNS and rejects private/loopback IPs before every outbound dial |
| **Log injection (CWE-117)** | `sanitizeLog()` strips `\n`, `\r`, `\t`; `%q` format verb; X-Request-ID sanitized at source |
| **Open redirect** | `isSafeRedirectURL()` validates scheme + non-private host |
| **Brute-force** | IP + user lockout after 5 failures (15 min cooldown) |
| **Admin API rate limiting** | 60 req/min per IP on mutating endpoints |
| **Slowloris** | 60s read deadline on SSL-inspected connections |
| **Session security** | HMAC-SHA256 signed cookies; dynamic `Secure` flag; fixation prevention |
| **CA key protection** | AES-256-GCM + PBKDF2-SHA256 (600k iterations) at rest |
| **OCSP/CRL** | Upstream certificate revocation checking (fail-closed) |
| **Hop-by-hop** | RFC 7230 compliant — parses `Connection` header for dynamic names |
| **GeoIP** | Fail-closed on cache miss (unknown country = no match) |
| **Header scrubbing** | Strips private IPs from `X-Forwarded-For`, removes `X-User-Identity` |

### CI Security Pipeline

Every push runs a **10-check security gate**:

1. **gosec** — Go security linter
2. **govulncheck** — reachable CVE detection
3. **trivy** — filesystem + Docker image vulnerability scan
4. **gitleaks** — secret scanning on PR diffs
5. **staticcheck** — advanced static analysis
6. **hadolint** — Dockerfile best practices
7. **Race tests** — `-race` flag on full test suite
8. **Coverage gate** — minimum 55% statement coverage
9. **License compliance** — no GPL/AGPL/LGPL/CPAL dependencies
10. **SBOM generation** — CycloneDX JSON via Syft

Plus: **CodeQL** semantic SAST, **Cosign** keyless signing, and **SLSA Level 3** provenance on all releases.

---

## Architecture

```
main.go            — Entrypoint, CLI flags, graceful shutdown, hot reload (SIGHUP)
proxy.go           — HTTP/HTTPS/WebSocket handler, SSL inspection, structured logging
socks5.go          — SOCKS5 server (RFC 1928/1929)
policy.go          — PBAC engine: rule evaluation, conflict detection, GeoIP fail-closed
session.go         — HMAC-SHA256 signed cookies, revocation, dynamic Secure flag
ui.go              — Admin Web UI (47 REST endpoints, RBAC, audit enrichment)
store.go           — Config, blocklist, request log, time-series, audit log
security.go        — IP filter, rate limiter, SSRF guard, DNS cache
security_scan.go   — ClamAV + YARA + threat feed scan coordinator
clam.go            — ClamAV INSTREAM client with connection pooling
yara_scan.go       — Pure-Go YARA engine with ReDoS timeout
threatfeed.go      — URLhaus + OpenPhish sync
feedsync.go        — UT1 URL category syncer
geoip.go           — MaxMind GeoLite2 with background cache
upstream.go        — Proxy chaining, failover, circuit breaker, health checks
ocsp.go            — OCSP/CRL revocation checking
ca.go              — Root CA, MITM certs, AES-GCM encryption, LRU cache, auto-rotation
auth.go            — Auth provider interface
auth_ldap.go       — LDAP bind + search + group resolution
auth_oidc_flow.go  — OIDC Authorization Code + PKCE
auth_saml.go       — SAML 2.0 SP-initiated SSO
auth_idp.go        — Multi-IdP registry with domain routing
identity.go        — Identity model (Sub, Groups, Source, Provider)
totp.go            — TOTP 2FA with backup codes
lockout.go         — Brute-force + API rate limiting
connlimit.go       — Per-IP connection limiter, X-Request-ID
metrics.go         — Prometheus metrics (per-rule, latency, bytes)
logger.go          — Structured text/JSON logging with rotation
syslog.go          — RFC 3164 syslog forwarding
alerts.go          — HMAC-SHA256 signed webhook alerts
events.go          — SSE live dashboard stream
config.go          — YAML config loading + validation
rewrite.go         — Per-host header rewrite engine
fileblock.go       — File extension/MIME blocking
pac.go             — PAC file generation
blockpage.go       — Block page HTML template
hashcache.go       — SHA-256 scan cache with TTL
controlplane.go    — gRPC Control Plane / Data Plane
plugin.go          — Middleware plugin chain
catdb.go           — URL category database
static/            — Embedded SPA (vanilla JS, Chart.js)
deploy/            — Prometheus + Grafana stack
yara/              — Starter YARA detection rules
```

---

## Development

Requires **Go 1.25+**.

```bash
go build -o culvert .                       # build
go test -v -race ./...                      # full suite with race detector
go test -coverprofile=cover.out ./...       # coverage report
go test -fuzz FuzzIsPrivateHost -fuzztime=30s  # fuzz SSRF guard
```

### Fuzz Targets

| Target | Coverage |
|--------|----------|
| `FuzzIsPrivateHost` | SSRF guard (DNS + private IP) |
| `FuzzIsSafeRedirectURL` | Open redirect prevention |
| `FuzzParseClamResponse` | ClamAV response parser |
| `FuzzNormaliseFeedURL` | Threat feed URL normalisation |
| `FuzzMatchDest` | Policy destination matching |
| `FuzzParseYARALiteralString` | YARA rule string parser |

### Docker Build

```bash
docker build -t culvert:dev .
docker run -p 8080:8080 -p 9090:9090 culvert:dev
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Run tests (`go test -race ./...`)
4. Commit your changes
5. Open a Pull Request

All PRs are validated by the full CI pipeline including CodeQL, the security gate, and golangci-lint with 18 linters.

---

## License

[MIT](LICENSE)
