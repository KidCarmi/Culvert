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
  <a href="https://github.com/KidCarmi/Dependency-Obituary"><img src="https://img.shields.io/badge/deps-Dependency%20Obituary-blueviolet" alt="Dependency Obituary" /></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a>
  <img src="https://img.shields.io/badge/PQC-ML--KEM--768-brightgreen?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJ3aGl0ZSI+PHBhdGggZD0iTTEyIDFMMyA1djZjMCA1LjU1IDMuODQgMTAuNzQgOSAxMiA1LjE2LTEuMjYgOS02LjQ1IDktMTJWNWwtOS00eiIvPjwvc3ZnPg==" alt="Post-Quantum Ready" />
  <a href="https://goreportcard.com/report/github.com/KidCarmi/Culvert"><img src="https://goreportcard.com/badge/github.com/KidCarmi/Culvert" alt="Go Report Card" /></a>
</p>

---

## Why Culvert?

Most forward proxies force you to choose: commercial appliance with vendor lock-in, or a minimal open-source tool you have to build around. Culvert is neither. It ships as a **single Go binary** with everything built in - SSL inspection, identity-aware policy, antivirus scanning, threat feeds, a full admin UI, and enterprise auth (OIDC, SAML, LDAP) - all without plugins, agents, or runtime dependencies.

Deploy it with `docker-compose up -d` and you get a production-ready proxy with zero-trust default-deny, real-time dashboards, Prometheus metrics, and a 10-check CI security pipeline. Scale it out with the built-in gRPC Control Plane for multi-node deployments. Extend it with the plugin API when you need custom logic.

---

## Features

### Proxy & Protocols

- **HTTP / HTTPS** forward proxy with full CONNECT tunnel support
- **SSL/TLS inspection** - on-the-fly MITM certs (ECDSA P-256), per-host bypass, LRU cert cache (10k entries, 1h TTL)
- **SOCKS5** proxy (RFC 1928/1929) with username/password auth
- **WebSocket** tunneling through CONNECT
- **PAC file** auto-generation for browser auto-configuration
- **Upstream proxy chaining** with round-robin, health checks, and automatic failover
- **Circuit breaker** - stops forwarding to hung upstream proxies after consecutive failures

### Policy Engine (Zero Trust)

- **Default deny** - unmatched traffic is blocked
- **Priority-based rules** - first match wins across 8 condition types:
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
- **Policy conflict detection** - warns on overlapping rules at same priority
- **Per-rule Prometheus metrics** with cardinality cap

### Authentication & Identity

- **Local auth** with bcrypt hashes and first-run setup wizard
- **OIDC** Authorization Code + PKCE (Okta, Azure AD, Google, Auth0, Keycloak)
- **SAML 2.0** SP-initiated SSO (Okta, Azure AD, ADFS)
- **LDAP** bind + search with group resolution (Active Directory, OpenLDAP, FreeIPA)
- **Multi-IdP** - simultaneous providers with email-domain routing
- **TOTP 2FA** (RFC 6238, inline stdlib implementation) with backup codes for admin accounts
- **RBAC** - admin / operator / viewer roles

### Content Security

- **ClamAV** antivirus (INSTREAM protocol, concurrency-limited scanning, auto-detection)
- **YARA rules** - pure-Go engine (no libyara), runtime reload, ReDoS-safe (5s timeout)
- **Threat feeds** - URLhaus + OpenPhish with hourly sync, dynamic domain allowlist for hosting platforms (GitHub, Google Drive, etc.)
- **DPI** - regex content scanning on decrypted HTTPS responses
- **File-type blocking** - 5 named profiles (Executables, Archives, Documents, Media, Strict)
- **Domain blocklist** with wildcard matching and allow-list mode
- **URL category database** (UT1) with background sync
- **SHA-256 scan cache** with configurable size + TTL
- **Remote scan sidecar** - process-isolated ClamAV/YARA scanning via remote microservice
- **Blocklist feed syncer** - auto-sync domain blocklists from remote URLs

### Admin Web UI

19-panel single-page application with real-time updates:

| Panel | Description |
|-------|-------------|
| Dashboard | Live stats, timeseries chart, top domains, country traffic map |
| Live Feed | Real-time request log with per-status badges, filtering, CSV/JSON export |
| Blocklist | Domain entries with wildcards; allow-list / deny-list toggle |
| Policy | Visual PBAC rule editor with all 8 condition types |
| Policy Tester | Dry-run evaluation against any host/user/IP |
| Security | IP filter, rate limiting, connection limits, block page editor, scanner status |
| File Block | File-type blocking profile selector |
| Rewrite | Per-host header rewrite rules (request + response) |
| Upstream Proxies | Parent proxy chaining with health checks and circuit breaker |
| IdP Providers | Step-by-step wizard for OIDC, SAML, LDAP |
| SSL / TLS | Root CA viewer, custom TLS upload, SSL bypass patterns |
| CA Management | CA lifecycle, PEM download, cache stats, OCSP toggle, force rotation |
| Cluster Nodes | Multi-node role display, DP node metrics, enrollment command generator |
| Node Groups | Label-based node grouping with geo-aware auto-labeling |
| Bandwidth / QoS | Per-group bandwidth policies with token bucket rate limiting |
| Config Versions | Auto-snapshot history, side-by-side diff, one-click rollback |
| PAC | PAC file generator with custom exclusions |
| Audit Log | Tamper-evident JSONL trail of all admin actions |
| Users | User management with RBAC role assignment |
| Settings | Session timeout, UI access control, syslog, config export/import |

### Observability & SIEM

- **Prometheus metrics** - requests, blocks, auth failures, AV scans, YARA matches, bytes transferred, latency histogram, per-rule counters
- **Real-time SSE** dashboard feed
- **Structured logging** - text or JSON with `req_id`, `identity`, `rule`, `action` fields
- **Rotating log files** with configurable size threshold
- **Syslog forwarding** (UDP/TCP, RFC 3164 + RFC 5424) for Splunk, Elastic, QRadar
- **JSONL audit trail** with actor identity enrichment
- **Webhook alerts** - HMAC-SHA256 signed notifications for threats, blocks, lockouts
- **Request tracing** - auto-generated X-Request-ID for end-to-end correlation

### Self-Update System

- **Docker update sidecar** - lightweight Go service with Docker socket access, triggered from the GUI
- **One-click update** - pull, recreate, health check, automatic rollback on failure (SSE progress stream)
- **Rollback** - previous container preserved for 1 hour (configurable); one-click restore
- **Self-update** - updater can update itself via reaper container pattern
- **Air-gapped mode** - load images from tarball when no registry access
- **Concurrent operation guard** - prevents double-click races on update/rollback

### Resilience & Operations

- **Hot config reload** - `SIGHUP` reloads blocklist, policy, rewrite, rate limit, upstream pool
- **Graceful shutdown** - lifecycle context + 15s drain window for active tunnels
- **CA auto-rotation** - daily expiry check, auto-rotates 30 days before expiry
- **OCSP/CRL checking** on upstream TLS certificates (fail-closed)
- **Per-IP connection limiting** (configurable, default 1024) with runtime admin API
- **Brute-force lockout** - 5 failures triggers 15-min IP + user lock
- **Admin API rate limiting** - 60 req/min per IP on mutating endpoints
- **Atomic file writes** for CA bundle and config persistence
- **PBKDF2 600k iterations** (NIST SP 800-132 2024) for CA key encryption
- **Post-Quantum Cryptography** - ML-KEM-768 hybrid key exchange (Go 1.25), protects against "Harvest Now, Decrypt Later" attacks
- **Password complexity** - enforces 8+ characters, mixed case, digit requirement
- **Log levels** - runtime DEBUG/INFO/WARN/ERROR with admin API control

### Distributed Architecture

- **Control Plane / Data Plane** - gRPC config sync with mTLS, per-node metrics aggregation
- **Cluster dashboard** - connected node list, health, request counts, enrollment wizard
- **Node groups** - label-based selectors with auto GeoIP labeling on enrollment
- **Bandwidth / QoS** - per-group token bucket rate limiting with admin UI
- **Config versioning** - automatic snapshots on every mutation, side-by-side diff, one-click rollback (50 versions)
- **Rolling upgrades** - orchestrated cluster updates with drain, canary, HA sync
- **PAC / threat feed / secrets sync** - full config snapshot pushed to data plane nodes
- **Bootstrap generator** - one-line curl|bash enrollment scripts and docker-compose templates for DP nodes
- **Exponential backoff** on connection failures (2s–60s)
- **Client mTLS** for upstream proxy authentication
- See **[Deployment Guide](docs/deployment-guide.md)** for single-node, multi-node, and upstream chaining setup

### Extensibility

- **Plugin API** - `Middleware` interface for custom request/response inspection
- **HSM/KMS integration** - `KeyProvider` interface (AWS KMS, Azure Key Vault, PKCS#11)

---

## Sizing Guide

Culvert is lightweight by design - a single Go binary with no runtime dependencies. Resource requirements scale with traffic volume, SSL inspection depth, and whether antivirus scanning is enabled.

All benchmarks below are based on **x86_64 (AMD64)** processors. ARM64 (AWS Graviton, Apple Silicon) typically achieves 10-20% better throughput per vCPU due to Go's efficient ARM code generation. If deploying on ARM, you can conservatively use the same numbers or reduce vCPU count by one tier.

### Deployment Profiles

| Profile | Users | Requests/sec | Max throughput | Concurrent conns | SSL Inspection | ClamAV | YARA |
|---|---|---|---|---|---|---|---|
| **Home Lab** | 1-5 | < 50 | ~100 Mbps | < 100 | Optional | Off | Off |
| **Small Office** | 10-50 | 50-500 | ~500 Mbps | 100-1000 | Recommended | Optional | Optional |
| **Enterprise (single node)** | 100-500 | 500-2000 | ~1 Gbps | 1000-5000 | Yes | Yes | Yes |
| **Enterprise (cluster)** | 500-5000+ | 2000-10000+ | ~10 Gbps (multi-DP) | 5000+ | Yes | Yes | Yes |

> **When to cluster:** A single node with SSL inspection + ClamAV handles ~500 concurrent users comfortably. Beyond 500 users or 1 Gbps sustained throughput, deploy a Control Plane + Data Plane cluster and add DP nodes horizontally.

### Resource Requirements

| Resource | Home Lab | Small Office | Enterprise |
|---|---|---|---|
| **CPU** | 1 vCPU | 2 vCPU | 4+ vCPU |
| **RAM (proxy only)** | 128 MB | 256 MB | 512 MB - 1 GB |
| **RAM (with ClamAV)** | 512 MB | 1 GB | 2 GB |
| **RAM per connection** | ~10 KB idle / ~138 KB active | same | same |
| **Storage (base)** | 50 MB (binary + config) | 50 MB | 50 MB |
| **Storage (ClamAV DB)** | - | 300 MB | 300 MB |
| **Storage (GeoIP DB)** | 5 MB | 5 MB | 5 MB |
| **Storage (UT1 category feed)** | 150 MB | 150 MB | 150 MB |
| **Storage (logs)** | 100 MB - 1 GB | 1 - 5 GB | 5 - 50 GB |
| **Storage (admin settings)** | < 10 KB | < 10 KB | < 10 KB |
| **Disk type** | Any (HDD OK) | SSD recommended | SSD required |

### Connection Memory Breakdown

Each proxied connection consumes memory proportional to its state:

| State | RAM per connection | Notes |
|---|---|---|
| Idle (keepalive) | ~10 KB | Go net/http conn + buffers |
| Active HTTP forward | ~70 KB | Request/response buffers (32 KB each) |
| SSL-inspected tunnel | ~138 KB | 2x 32 KB relay buffers (pooled) + TLS state |
| Body scanning (ClamAV/YARA) | +64 KB - 4 MB | Buffered body up to scan limit, then freed |
| WebSocket relay | ~138 KB | Same as tunnel (bidirectional relay) |

At 5000 concurrent SSL-inspected connections: ~670 MB for connection buffers alone. Plan RAM accordingly for high-concurrency environments.

### Notes

- **ClamAV** is the largest resource consumer. It downloads ~300 MB of virus signatures on first boot and keeps them in memory (~500 MB RSS). If you don't need antivirus scanning, disable it to save ~500 MB RAM. ClamAV signature reloads (freshclam updates, typically every 4 hours) cause a brief CPU spike (~2-5 seconds) but do **not** block proxy traffic - the reload happens in the ClamAV sidecar process, not in Culvert itself. No over-provisioning needed.
- **SSL inspection** adds ~1 KB RAM per cached leaf certificate (LRU cache, 10K max = ~10 MB). CPU impact is ~0.5ms per **new** TLS handshake using **ECDSA P-256 signing** (Culvert's default). RSA 2048 would be ~5x slower per signing operation, but Culvert exclusively uses ECDSA P-256 for its internal CA - no RSA path exists. Cached certificates (cache hit) have zero signing overhead.
- **Log rotation** is automatic. Request logs rotate at 100 MB (configurable via `-request-log-max-mb`), audit logs at 50 MB, system logs at 50 MB. **Storage I/O:** log writes are append-only and sequential - HDD is adequate for Home Lab. For Small Office+ with SSL inspection (high request volume), SSD is recommended to avoid I/O wait impacting proxy latency.
- **Threat feeds** (URLhaus + OpenPhish) add ~5-20 MB RAM depending on feed size.
- **UT1 category feed** (University of Toulouse) downloads a ~50 MB tarball on first sync, stored in BadgerDB at ~150 MB on disk + ~50-100 MB RAM for the index. Provides millions of categorized domains (Adult, Gambling, Malicious, etc.) auto-synced hourly. The SaaS category feed (AI, Marketing, etc.) adds negligible storage (< 100 KB JSON).
- **Prometheus metrics** are stateless - scraped externally, no local storage.
- **Post-quantum (ML-KEM-768)** adds ~1 KB to initial TLS handshakes. No ongoing RAM/CPU impact.
- **Docker image size:** ~30 MB (distroless base + static Go binary).

### Minimum Requirements

For a functional deployment with all features enabled:

```
2 vCPU | 1.5 GB RAM | 2.5 GB disk (SSD recommended)
```

For proxy-only (no AV, no SSL inspection):

```
1 vCPU | 128 MB RAM | 100 MB disk (any)
```

### Cluster Deployments (Control Plane / Data Plane)

| Component | CPU | RAM | Storage | Notes |
|---|---|---|---|---|
| **Control Plane** | 2 vCPU | 512 MB | 500 MB | No proxy traffic - config sync, enrollment, dashboard only |
| **Control Plane (HA pair)** | 2 vCPU each | 512 MB each | 500 MB each | Leader + standby with automatic failover |
| **Data Plane node** | 2 vCPU | 1 GB | 1 GB | Handles proxy traffic, receives config from CP |
| **Data Plane + ClamAV** | 2 vCPU | 2 GB | 1.5 GB | Add ~1 GB RAM + 300 MB disk for AV |

**Scale reference:**

| Setup | Nodes | Total resources | Throughput | Handles |
|---|---|---|---|---|
| **Small cluster** | 1 CP + 2 DP | 6 vCPU, 2.5 GB RAM | ~2 Gbps | ~1000 concurrent users |
| **Medium cluster** | 1 CP (HA) + 5 DP | 12 vCPU, 6 GB RAM | ~5 Gbps | ~5000 concurrent users |
| **Large cluster** | 1 CP (HA) + 10 DP | 22 vCPU, 11 GB RAM | ~10 Gbps | ~10000+ concurrent users |

- **CP is lightweight** - it only serves gRPC config sync, node enrollment, and the admin dashboard. No proxy traffic flows through it.
- **DP nodes are stateless** - they receive their entire config from the CP on connect. Lose a DP, spin up a new one, it auto-enrolls and gets the full config in seconds.
- **Bandwidth/QoS** policies are enforced per-DP, so rate limits scale linearly with node count.
- **Network:** CP to DP communication uses gRPC over mTLS. Typical bandwidth: < 1 KB/s per node (config sync + heartbeat every 30s).
- **Horizontal scaling:** each DP node adds ~1 Gbps throughput capacity (with SSL inspection). Scale is linear - no shared state between DP nodes.

---

## Quick Start

### One-Line Install (recommended)

Works on Ubuntu, Debian, RHEL, CentOS, Rocky, Alma, Fedora, Amazon Linux, and Arch.
Runs anywhere Linux runs: AWS EC2, Azure VM, GCP Compute, DigitalOcean, Hetzner, bare metal.
Installs Docker, clones the repo, pulls the pre-built images and starts everything:

```bash
curl -fsSL https://raw.githubusercontent.com/KidCarmi/Culvert/main/scripts/install.sh | bash
```

The script handles all Docker installation quirks (snap removal, compose v2, distro packages) so you don't have to.

### Docker (manual)

```bash
git clone https://github.com/KidCarmi/Culvert
cd Culvert
docker compose up -d
```

No configuration required - the setup wizard creates your admin account on first visit.

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

### After it's running

Three things to do once the containers are up:

1. **Setup wizard** — open `https://<host>:9090` in a browser, accept the self-signed cert, and create the first admin account. This step is required before any other API call.
2. **Verify readiness** — confirm Culvert is fit to take traffic:
   ```bash
   curl http://<host>:8080/ready
   ```
   Returns `200` with `{"status":"ready", "checks":{...}}` when ready, `503` with `"status":"not_ready"` when a gating check fails. See [`docs/OPERATIONS.md`](docs/OPERATIONS.md) for the full checks-map reference.
3. **Open Diagnostics** — Admin UI → **Infrastructure → Diagnostics**. The page surfaces the operator contract: storage path, policy load, root CA, session HMAC, CDR, cluster TLS posture, updater URL, config-version health, and any active risky-but-allowed warnings (`cluster-insecure`, unauth mode). Resolve any `fail` rows before exposing the proxy to clients.

#### With custom config

```bash
cp config.example.yaml config.yaml   # edit as needed
# Uncomment the config.yaml volume mount in docker-compose.yml, then:
docker compose up -d
```

#### With monitoring stack (Prometheus + Grafana)

```bash
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d
# Grafana → http://localhost:3000  (admin / culvert)
```

The **Culvert Overview** dashboard (12 panels: traffic, latency, security blocks, top policy rules) is auto-provisioned from `deploy/grafana/dashboards/culvert-overview.json` - no manual import needed.

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
  -clamav-addr string    ClamAV address - tcp:host:port or unix:/path/to/clamd.sock
  -yara-rules-dir string Directory containing .yar / .yara rule files
  -threat-feed-db string Threat feed local database path

Logging:
  -logfile string        Request log file (rotated at -log-max-mb)
  -log-max-mb int        Log rotation threshold in MB (default 50)
  -audit-log string      Persistent JSONL audit log path
  -syslog string         Remote syslog - udp://host:514 or tcp://host:601

Metrics:
  -metrics-token string  Bearer token protecting /metrics (empty = open)
  -rate-limit int        Max requests/min per source IP (0 = off)

Distributed (Control Plane):
  -cp-grpc-addr string   Control Plane gRPC listen address (e.g. :50051)
  -cp-grpc-cert string   Control Plane gRPC TLS certificate
  -cp-grpc-key string    Control Plane gRPC TLS key
  -cp-grpc-ca string     Control Plane gRPC CA for mTLS client validation

Distributed (Data Plane):
  -dp-cp-addr string     ControlPlane gRPC address to connect to (e.g. cp.corp:50051)
  -dp-node-id string     Unique node identifier (default: hostname)
  -dp-cert string        Data Plane gRPC client TLS certificate
  -dp-key string         Data Plane gRPC client TLS key
  -dp-ca string          Data Plane gRPC CA certificate
```

> See **[docs/deployment-guide.md](docs/deployment-guide.md)** for complete single-node, multi-node, and upstream chaining examples.

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
| **Hop-by-hop** | RFC 7230 compliant - parses `Connection` header for dynamic names |
| **GeoIP** | Fail-closed on cache miss (unknown country = no match) |
| **Header scrubbing** | Strips private IPs from `X-Forwarded-For`, removes `X-User-Identity` |
| **Post-Quantum (PQC)** | ML-KEM-768 hybrid key exchange via Go 1.25 - quantum-resistant on all TLS connections |

### Post-Quantum Cryptography (PQC)

Culvert is **quantum-resistant by default**. Go 1.25's `crypto/tls` automatically negotiates ML-KEM-768 (formerly Kyber) hybrid key exchange on all TLS connections when the peer supports it. This protects against "Harvest Now, Decrypt Later" attacks where an adversary records encrypted traffic today and decrypts it with a future quantum computer.

| Connection | PQC Key Exchange | Notes |
|---|---|---|
| Browser to Admin UI | Auto-negotiated | Chrome 124+, Firefox 128+, Edge 124+ |
| Proxy to upstream servers | Auto-negotiated | When upstream supports ML-KEM |
| Control Plane to Data Plane (gRPC mTLS) | Always active | Both sides run Go 1.25 |
| SSL-inspected client connections | Auto-negotiated | When client browser supports ML-KEM |

**What's quantum-resistant today:** All key exchanges (TLS handshakes) use hybrid X25519 + ML-KEM-768, meaning traffic confidentiality is protected even against quantum computers.

**What's still classical:** Certificate signing uses ECDSA P-256. PQC signature algorithms (ML-DSA / Dilithium) are not yet in Go's standard library. Culvert will adopt PQC signing when Go adds native support (expected Go 1.26+). This is a lower risk - signatures prove identity at connection time and cannot be "harvested" for future decryption.

No configuration required - PQC is enabled automatically. No performance impact - the ML-KEM handshake adds ~1ms to the initial TLS connection.

### CI Security Pipeline

Every push runs a **10-check security gate**:

1. **gosec** - Go security linter
2. **govulncheck** - reachable CVE detection
3. **trivy** - filesystem + Docker image vulnerability scan
4. **gitleaks** - secret scanning on PR diffs
5. **staticcheck** - advanced static analysis
6. **hadolint** - Dockerfile best practices
7. **Race tests** - `-race` flag on full test suite
8. **Coverage gate** - minimum 55% statement coverage
9. **License compliance** - no GPL/AGPL/LGPL/CPAL dependencies
10. **SBOM generation** - CycloneDX JSON via Syft

Plus: **CodeQL** semantic SAST, **Dependency Obituary** dependency health scoring, **Cosign** keyless signing, and **SLSA Level 3** provenance on all releases.

---

## Architecture

```
main.go            - Entrypoint, CLI flags, graceful shutdown, hot reload (SIGHUP)
proxy.go           - HTTP/HTTPS/WebSocket handler, SSL inspection, structured logging
socks5.go          - SOCKS5 server (RFC 1928/1929)
policy.go          - PBAC engine: rule evaluation, conflict detection, GeoIP fail-closed
session.go         - HMAC-SHA256 signed cookies, revocation, dynamic Secure flag
ui.go              - Admin Web UI (47 REST endpoints, RBAC, audit enrichment)
store.go           - Config, blocklist, request log, time-series, audit log
security.go        - IP filter, rate limiter, SSRF guard, DNS cache
security_scan.go   - ClamAV + YARA + threat feed scan coordinator
clam.go            - ClamAV INSTREAM client with connection pooling
yara_scan.go       - Pure-Go YARA engine with ReDoS timeout
threatfeed.go      - URLhaus + OpenPhish sync, domain allowlist
feedsync.go        - UT1 URL category syncer
geoip.go           - MaxMind GeoLite2 with background cache
upstream.go        - Proxy chaining, failover, circuit breaker, health checks
ocsp.go            - OCSP/CRL revocation checking
ca.go              - Root CA, MITM certs, AES-GCM encryption, LRU cache, auto-rotation
auth.go            - Auth provider interface
auth_ldap.go       - LDAP bind + search + group resolution
auth_oidc_flow.go  - OIDC Authorization Code + PKCE
auth_saml.go       - SAML 2.0 SP-initiated SSO
auth_idp.go        - Multi-IdP registry with domain routing
identity.go        - Identity model (Sub, Groups, Source, Provider)
totp.go            - TOTP 2FA (RFC 6238, stdlib HMAC-SHA1)
lockout.go         - Brute-force + API rate limiting
connlimit.go       - Per-IP connection limiter, X-Request-ID
metrics.go         - Prometheus metrics (per-rule, latency, bytes)
logger.go          - Structured text/JSON logging with rotation
syslog.go          - RFC 3164/5424 syslog forwarding
alerts.go          - HMAC-SHA256 signed webhook alerts
events.go          - SSE live dashboard stream
config.go          - YAML config loading + validation (goccy/go-yaml)
rewrite.go         - Per-host header rewrite engine
fileblock.go       - File extension/MIME blocking
pac.go             - PAC file generation
blockpage.go       - Block page HTML template
hashcache.go       - SHA-256 scan cache with TTL
controlplane.go    - gRPC Control Plane / Data Plane
plugin.go          - Middleware plugin chain
catdb.go           - URL category database
update.go          - Self-update system (binary + Docker)
update_cluster.go  - Rolling cluster update orchestrator (canary, drain, HA sync)
scan_remote.go     - Remote scan sidecar client for process-isolated scanning
blocklist_feed.go  - Domain blocklist URL feed syncer
bootstrap.go       - Bootstrap script/compose generators for node enrollment
static/            - Embedded SPA (vanilla JS, Chart.js)
updater/           - Docker update sidecar (Go service with rollback)
scripts/           - Install script (multi-distro), CI runner setup
deploy/            - Prometheus + Grafana stack
yara/              - Starter YARA detection rules
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
