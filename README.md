# ProxyShield

**Enterprise-grade open-source HTTP/HTTPS/SOCKS5 forward proxy** — built in Go, single binary, zero runtime dependencies.

[![CI](https://github.com/KidCarmi/Claude-Test/actions/workflows/ci.yml/badge.svg)](https://github.com/KidCarmi/Claude-Test/actions/workflows/ci.yml)
[![Security Gate](https://github.com/KidCarmi/Claude-Test/actions/workflows/security-release-gate.yml/badge.svg)](https://github.com/KidCarmi/Claude-Test/actions/workflows/security-release-gate.yml)

---

## Features

| Category | Details |
|----------|---------|
| **Protocols** | HTTP, HTTPS (CONNECT + SSL inspection), WebSocket, SOCKS5 |
| **Policy engine** | PBAC rules: source IP/CIDR, identity, group, IdP, FQDN, URL category, GeoIP country, schedule |
| **Authentication** | Local (bcrypt), LDAP, OIDC Authorization Code + PKCE, SAML 2.0; multi-IdP support |
| **SSL inspection** | MITM with rotating CA; per-host bypass list; TLS fingerprinting |
| **Content filtering** | Domain blocklist (wildcards), file-type profiles, ClamAV antivirus, YARA rules, threat feeds |
| **GeoIP** | Per-country allow/block rules via MaxMind GeoLite2; live country traffic map on dashboard |
| **Header rewriting** | Per-host request/response header set/add/remove (exact + `*.wildcard` patterns) |
| **Admin Web UI** | 14-panel SPA: dashboard, live feed, blocklist, policy, security, certificates, audit log, … |
| **Observability** | Prometheus metrics, real-time SSE dashboard, rotating request log, JSONL audit trail |
| **SIEM** | Syslog forwarding (UDP/TCP, RFC 3164) compatible with Splunk, Elastic, QRadar |
| **Resilience** | Graceful shutdown, log rotation, persistent volumes, atomic file writes |
| **Distributed** | Control Plane / Data Plane gRPC mode with mTLS for multi-node deployments |
| **Extensibility** | Plugin middleware API (`Middleware` interface) |

---

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/KidCarmi/Claude-Test
cd Claude-Test
docker-compose up -d
```

No configuration required — on first visit the setup wizard creates your admin account.

| Endpoint | URL | Notes |
|----------|-----|-------|
| HTTP/HTTPS Proxy | `http://localhost:8080` | Configure browser/PAC to point here |
| PAC file | `http://localhost:8080/proxy.pac` | Auto-config for browsers |
| Admin Web UI | `https://localhost:9090` | Accept the self-signed cert on first visit |
| Health check | `http://localhost:8080/health` | `{"status":"ok",…}` |

```bash
# Verify it works
curl http://localhost:8080/health
curl -x http://localhost:8080 https://example.com
```

#### With custom config (optional)

```bash
cp config.example.yaml config.yaml   # edit as needed
# Uncomment the config.yaml volume line in docker-compose.yml, then:
docker-compose up -d
```

#### With monitoring stack (Prometheus + Grafana)

```bash
docker-compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d
# Grafana → http://localhost:3000  (admin / proxyshield)
```

### Binary

```bash
# Download the latest release, then:
./proxyshield                                  # proxy :8080, admin UI :9090
./proxyshield -port 3128 -socks5-port 1080
./proxyshield -config config.yaml
```

---

## Admin Web UI

Open `https://localhost:9090` (accept the self-signed cert). On first launch a setup wizard creates the admin account.

| Panel | What you can do |
|-------|----------------|
| **Dashboard** | Live request stats, timeseries chart, top domains, country traffic map |
| **Live Feed** | Real-time request log — filter by host / IP / status / level; export CSV/JSON |
| **Blocklist** | Add/remove/wildcard domain entries; toggle allow-list ↔ deny-list mode |
| **Policy** | PBAC rule editor — source IP, identity, group, FQDN, URL category, GeoIP, schedule, SSL action |
| **Security** | IP allowlist/blocklist, rate limiting, SSL bypass patterns, ClamAV/YARA/threat-feed status |
| **File Block** | Block file downloads by type (Executables, Archives, Documents, Media, Strict) |
| **Rewrite** | Per-host header rewrite rules (req + resp: set / add / remove) |
| **IdP Providers** | Configure OIDC, SAML 2.0, LDAP identity providers with step-by-step wizard |
| **PAC** | Generate and download Proxy Auto-Configuration file with custom exclusions |
| **Certificates** | View/rotate Root CA, upload custom TLS certificates |
| **Policy Tester** | Dry-run PBAC evaluation against any host/user/IP without live traffic |
| **Audit Log** | Tamper-evident JSONL audit trail of all admin actions |
| **Users** | Admin user management with RBAC (admin / operator / viewer roles) |
| **Settings** | Session timeout, UI access IP allowlist, syslog/SIEM, config export/import |

---

## Authentication & Authorization

### Local credentials (default)

Created via the first-run setup wizard; stored as bcrypt hashes in `/data/ui_users.json`.

### RBAC roles

| Role | Capabilities |
|------|-------------|
| **admin** | Full access — create/delete users, change settings, modify all rules |
| **operator** | Modify rules (blocklist, policy, rewrite) — cannot change users or core settings |
| **viewer** | Read-only dashboard access |

### Identity Providers

Add OIDC, SAML 2.0, or LDAP providers in **Settings → IdP Providers**. Multiple providers are supported simultaneously. Users are routed to the correct IdP based on email domain matching.

| Protocol | Supported IdPs |
|----------|---------------|
| OIDC Authorization Code + PKCE | Okta, Azure AD, Google, Auth0, Keycloak, … |
| SAML 2.0 (SP-initiated SSO) | Okta SAML, Azure AD SAML, ADFS, … |
| LDAP | Active Directory, OpenLDAP, FreeIPA |

---

## Policy Engine (PBAC)

Rules are evaluated in priority order; the first match wins. Unmatched traffic defaults to **Deny** (zero-trust).

### Match conditions

| Field | Examples |
|-------|---------|
| Source IP / CIDR | `10.0.0.0/8`, `192.168.1.5` |
| Authenticated identity | `alice`, `bob@corp.com` |
| IdP group membership | `admins`, `contractors` |
| Auth source | `okta`, `ldap`, `local`, `unauth` |
| Destination FQDN | `*.youtube.com`, `github.com` |
| URL category | Social, Streaming, Gambling, News, Malicious, Adult |
| Destination country | `US`, `CN`, `RU` (ISO 3166-1) |
| Schedule | Days of week + time window + timezone |

### Actions

| Action | Description |
|--------|-------------|
| `Allow` | Forward the request |
| `Drop` | Silently close the connection |
| `Block_Page` | Return branded block page |
| `Redirect` | 302 redirect to configured URL |

### SSL actions (per rule)

| Action | Description |
|--------|-------------|
| `Inspect` | Full MITM — decrypt, scan, re-encrypt |
| `Bypass` | Transparent tunnel — no decryption |

---

## Content Security

### ClamAV antivirus

Enabled automatically when the ClamAV container is running (included in `docker-compose.yml`). Virus definition database updates automatically via `freshclam`. The proxy starts immediately; scanning activates once the daemon is ready (~2–5 min on first boot).

### YARA rules

Place `.yar` / `.yara` rule files in `/app/yara/` (or mount a custom directory). Rules are loaded at startup and can be reloaded at runtime via the Security panel without a restart.

### Threat feeds

Automatic hourly sync from URLhaus and OpenPhish. Matched domains are blocked as `Malicious`. The local database survives restarts at `/data/threatfeeds.json`.

### File-type blocking

| Profile | Extensions blocked |
|---------|--------------------|
| Executables | .exe .dll .bat .cmd .ps1 .scr .msi .pif .com .vbs |
| Archives | .zip .rar .7z .tar .gz .bz2 .xz .cab .iso |
| Documents | .docm .xlsm .pptm .xlam .dotm (macro-enabled only) |
| Media | .mp3 .mp4 .avi .mkv .mov .flv .wmv .webm |
| Strict | All of the above combined |

---

## Configuration Reference

### docker-compose (recommended)

All persistent data lives in the `proxy-data` volume — no extra configuration needed for most deployments.

```yaml
# Uncomment in docker-compose.yml to use a config file:
# - ./config.yaml:/app/config.yaml:ro
```

### config.yaml (optional)

```yaml
proxy:
  port: 8080
  ui_port: 9090
  socks5_port: 1080      # 0 = disabled

security:
  ip_filter_mode: allow  # allow | block | "" (off)
  ip_list:
    - 192.168.1.0/24
  rate_limit: 60         # requests/min per IP

# Header rewrite rules (also configurable in the UI)
rewrite:
  - host: "*.internal.example.com"
    req_set:
      X-Forwarded-By: ProxyShield
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

Security scanning:
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

Distributed (Control Plane / Data Plane):
  -cp-grpc-addr string   Control Plane gRPC listen address (e.g. :50051)
  -cp-grpc-cert string   Control Plane gRPC TLS certificate
  -cp-grpc-key string    Control Plane gRPC TLS key
  -cp-grpc-ca string     Control Plane gRPC CA for mTLS client validation
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
http://localhost:8080/proxy.pac
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
# Download CA from the Admin UI → Certificates, or:
curl -k https://localhost:9090/api/ca-cert > proxyshield-ca.crt

# Linux
sudo cp proxyshield-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain proxyshield-ca.crt
```

---

## Prometheus Metrics

Available at `GET http://localhost:8080/metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `proxyshield_requests_total` | counter | All proxy requests |
| `proxyshield_requests_allowed` | counter | Forwarded requests |
| `proxyshield_requests_blocked` | counter | Blocked requests (all reasons) |
| `proxyshield_requests_auth_fail` | counter | Authentication failures |
| `proxyshield_av_scans_total` | counter | ClamAV scans performed |
| `proxyshield_av_detections_total` | counter | Malware detections |
| `proxyshield_yara_matches_total` | counter | YARA rule matches |
| `proxyshield_threat_feed_blocks_total` | counter | Threat feed blocks |
| `proxyshield_blocklist_size` | gauge | Blocklist entry count |
| `proxyshield_policy_rules` | gauge | Active PBAC rule count |
| `proxyshield_uptime_seconds` | gauge | Proxy uptime |
| `proxyshield_rate_limit_rpm` | gauge | Configured rate limit |
| `proxyshield_rate_limit_enabled` | gauge | 1 = rate limiting active |

```bash
# Full monitoring stack (Prometheus + Grafana pre-configured)
docker-compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d
# Grafana → http://localhost:3000  (admin / proxyshield)
```

---

## Plugin API

Implement the `Middleware` interface to add custom request inspection logic:

```go
// plugin_myplugin.go
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
    resp.Header.Del("Server") // strip server fingerprint
}

func init() { RegisterPlugin(&MyPlugin{}) }
```

Plugins run before every other check (blocklist, policy, etc.) and can short-circuit the chain.

---

## Development

### Build & run

```bash
go build -o proxyshield .
./proxyshield
```

### Tests

```bash
go test -v -race ./...               # full suite with race detector
go test -run TestBlocklist ./...     # blocklist tests
go test -run TestPolicy ./...        # PBAC engine tests
go test -run TestSession ./...       # session / auth tests
go test -run TestPAC ./...           # PAC generation tests
go test -coverprofile=cover.out ./...
go tool cover -html=cover.out        # open coverage report
```

### Docker build

```bash
docker build -t proxyshield:dev .
docker run -p 8080:8080 -p 9090:9090 proxyshield:dev
```

---

## Architecture

```
main.go            — CLI flags, startup, graceful shutdown (SIGTERM/SIGINT)
proxy.go           — HTTP/HTTPS/WebSocket request handler, SSL inspection pipeline
socks5.go          — SOCKS5 server (CONNECT only; respects blocklist + rate limit)
policy.go          — PBAC engine: rule store, evaluation, SSL bypass matcher
session.go         — HMAC-SHA256 signed session cookies, revocation list, TTL
ui.go              — Admin Web UI server (47 REST API endpoints, RBAC middleware)
store.go           — Config, blocklist, request log, time-series stats, audit log
security.go        — IP filter (allow/block mode + CIDR), per-IP rate limiter
security_scan.go   — Scan orchestration: ClamAV + YARA + threat feed + hash cache
clam.go            — ClamAV TCP/Unix socket client (INSTREAM protocol)
yara_scan.go       — Pure-Go YARA rule engine (no libyara dependency)
threatfeed.go      — URLhaus + OpenPhish threat feed sync and lookup
geoip.go           — MaxMind GeoLite2 country lookup with background cache refresh
pac.go             — PAC file generation and persistence
rewrite.go         — Per-host request/response header rewrite engine
fileblock.go       — File-type blocking by extension profile
blockpage.go       — Branded block page HTML generator
lockout.go         — Login rate-limiter / account lockout (5 failures → 15 min lock)
auth.go            — Auth provider interface and dispatcher
auth_idp.go        — Generic IdP profile store (OIDC + SAML multi-provider)
auth_oidc.go       — OIDC token introspection (RFC 7662)
auth_oidc_flow.go  — OIDC Authorization Code + PKCE full flow
auth_saml.go       — SAML 2.0 SP-initiated SSO
auth_ldap.go       — LDAP two-step bind with result caching
ca.go              — Root CA generation, persistence (AES-256-GCM encrypted), MITM cert issuance
tls.go             — Self-signed TLS certificate for admin UI
metrics.go         — Prometheus /metrics endpoint
logger.go          — Structured log (text/JSON), rotation, write-through to syslog
syslog.go          — RFC 3164 syslog forwarding (UDP/TCP)
events.go          — SSE live dashboard (real-time request stream)
hashcache.go       — SHA-256 scan result cache (configurable size + TTL)
plugin.go          — Plugin middleware chain
controlplane.go    — Control Plane / Data Plane gRPC config sync with mTLS
config.go          — YAML config file loading and validation
static/            — Embedded single-page admin UI (vanilla JS, Chart.js)
deploy/            — Prometheus + Grafana monitoring stack
yara/              — Starter YARA detection rules
```

---

## Self-Hosted CI Runner

ProxyShield CI uses a self-hosted GitHub Actions runner for the Docker build step.

```bash
export RUNNER_TOKEN=<Settings → Actions → Runners → New self-hosted runner>
bash scripts/install-runner.sh
```

The script installs Docker, adds the current user to the `docker` group, and registers the runner as a systemd service.

---

## License

MIT
