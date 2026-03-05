# ProxyShield

**Enterprise-grade open source HTTP/HTTPS/SOCKS5 proxy** - built in Go, zero dependencies beyond the standard library.

[![CI](https://github.com/KidCarmi/Claude-Test/actions/workflows/ci.yml/badge.svg)](https://github.com/KidCarmi/Claude-Test/actions/workflows/ci.yml)

---

## Features

| Category | Details |
|----------|---------|
| **Protocols** | HTTP, HTTPS (CONNECT tunnel), WebSocket, SOCKS5 |
| **Security** | Basic auth (bcrypt), domain blocklist (wildcards), IP allowlist/blocklist (CIDR), rate limiting |
| **Auth providers** | Local credentials, LDAP (two-step bind), OIDC token introspection (RFC 7662) |
| **Header rewriting** | Per-host request/response header set/add/remove rules (exact + `*.wildcard` patterns) |
| **Observability** | Prometheus metrics (`/metrics`), real-time Web UI, structured request log (text or JSON) |
| **Export** | Download logs as CSV or JSON |
| **Production** | Docker image, docker-compose, graceful shutdown, log rotation |
| **Extensibility** | Plugin middleware API (`Middleware` interface) |
| **Distributed** | Control Plane / Data Plane gRPC mode for multi-node deployments |

---

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/KidCarmi/Claude-Test
cd Claude-Test
docker-compose up -d
```

That's it. No configuration required.

| Endpoint | URL |
|----------|-----|
| HTTP/HTTPS Proxy | `http://localhost:8080` |
| Web UI | `https://localhost:9090` (accept the self-signed cert) |
| Health check | `http://localhost:8080/health` |

To verify it works:
```bash
curl http://localhost:8080/health
# → {"status":"ok","uptime":"...","version":"1.0.0"}

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
docker-compose --profile monitoring up -d
# Grafana → http://localhost:3000  (admin / proxyshield)
```

### Binary

```bash
# Download the latest release for your platform, then:
./proxyshield                          # runs on :8080 (proxy) + :9090 (UI)
./proxyshield -port 3128 -socks5-port 1080
./proxyshield -config config.yaml
```

---

## Configuration

Copy `config.example.yaml` to `config.yaml`:

```yaml
proxy:
  port: 8080
  ui_port: 9090
  socks5_port: 1080      # 0 = disabled
  log_format: json       # "text" (default) or "json"

auth:
  user: alice
  pass: supersecret

security:
  ip_filter_mode: allow  # allow | block | "" (off)
  ip_list:
    - 192.168.1.0/24
  rate_limit: 60         # requests/min per IP

# Optional: LDAP authentication (takes precedence over local auth)
ldap:
  url: ldap://ldap.example.com:389
  bind_dn: "cn=svc,dc=example,dc=com"
  bind_pass: secret
  base_dn: "ou=users,dc=example,dc=com"
  filter: "(uid=%s)"

# Optional: OIDC token introspection (RFC 7662)
oidc:
  introspection_url: https://auth.example.com/oauth2/introspect
  client_id: proxyshield
  client_secret: secret

# Optional: header rewrite rules
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
-port int              Proxy port (default 8080)
-ui-port int           Web UI port (default 9090)
-socks5-port int       SOCKS5 port (0 = disabled)
-config string         Path to config.yaml
-user string           Basic auth username
-pass string           Basic auth password
-blocklist string      Path to blocklist file
-logfile string        Log file path (rotated at -log-max-mb)
-log-max-mb int        Log rotation threshold in MB (default 50)
-rate-limit int        Max requests/min per IP (0 = off)
-ip-filter-mode string IP filter mode: allow|block (empty = off)
-tls-cert string       Custom TLS certificate for Web UI
-tls-key string        Custom TLS key for Web UI
-metrics-token string  Bearer token to protect /metrics (empty = open)
-socks5-port int       SOCKS5 proxy port (0 = disabled)
```

---

## Blocklist Format

```
# Lines starting with # are comments
evil.com
*.ads.com        # blocks sub.ads.com, deep.sub.ads.com, and ads.com
tracker.net
```

---

## Proxy Usage

### HTTP / HTTPS

```bash
# curl
curl -x http://localhost:8080 https://example.com
curl -x http://alice:secret@localhost:8080 https://example.com

# Environment variable
export http_proxy=http://localhost:8080
export https_proxy=http://localhost:8080
curl https://example.com

# Browser: set HTTP proxy to localhost:8080
```

### SOCKS5

```bash
curl --proxy socks5://localhost:1080 https://example.com
curl --proxy socks5://alice:secret@localhost:1080 https://example.com

# SSH tunneling
ssh -o ProxyCommand="nc -X 5 -x localhost:1080 %h %p" user@remote
```

---

## Prometheus Metrics

Available at `GET http://localhost:8080/metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `proxyshield_requests_total` | counter | All requests |
| `proxyshield_requests_allowed` | counter | Forwarded requests |
| `proxyshield_requests_blocked` | counter | Blocked (domain + IP) |
| `proxyshield_requests_auth_fail` | counter | Auth failures |
| `proxyshield_blocklist_size` | gauge | Blocked domain count |
| `proxyshield_uptime_seconds` | gauge | Proxy uptime |
| `proxyshield_rate_limit_rpm` | gauge | Configured RPM limit |
| `proxyshield_rate_limit_enabled` | gauge | 1 = rate limiting active |

```bash
# Start full monitoring stack (Prometheus + Grafana)
docker-compose --profile monitoring up -d
# Grafana → http://localhost:3000  (admin / proxyshield)
```

---

## Plugin API

Implement the `Middleware` interface to add custom logic:

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
    // Optionally modify response headers, log, etc.
}

func init() {
    RegisterPlugin(&MyPlugin{})
}
```

`RegisterPlugin` must be called before the proxy starts (use `init()`).

---

## Web UI

Open `https://localhost:9090` in your browser (accept the self-signed certificate).

| Section | Features |
|---------|---------|
| Dashboard | Request stats, timeseries chart, traffic breakdown doughnut, top-hosts panel |
| Live Feed | Real-time log with host/IP/status/level/method filters, CSV/JSON export |
| Blocklist | Add/remove/wildcard hosts, import/export `.txt` |
| Security | IP filter mode + list, rate limit |
| Rewrite | Per-host request/response header rewrite rules (set/add/remove) |
| Settings | Basic auth credentials |

---

## Self-Hosted CI Runner

ProxyShield CI runs on a self-hosted GitHub Actions runner so the Docker build step can use a real Docker daemon.

### One-command install

```bash
# Set your registration token (Settings → Actions → Runners → New self-hosted runner)
export RUNNER_TOKEN=<your_token>
bash scripts/install-runner.sh
```

The script will:
1. Install Docker (if missing)
2. **Add the current user to the `docker` group** — this is the most common failure point
3. Download & configure the GitHub Actions runner binary
4. Install it as a systemd service that starts automatically on boot

### Manual setup (if you prefer)

```bash
# 1. Install Docker
curl -fsSL https://get.docker.com | sudo sh

# 2. Add your user to the docker group (prevents "permission denied" on the Docker socket)
sudo usermod -aG docker "$USER"
newgrp docker          # apply immediately without re-login

# 3. Download runner (replace VERSION and TOKEN)
mkdir ~/actions-runner && cd ~/actions-runner
curl -fsSL -o runner.tar.gz \
  https://github.com/actions/runner/releases/download/v2.322.0/actions-runner-linux-x64-2.322.0.tar.gz
tar xzf runner.tar.gz && rm runner.tar.gz

# 4. Configure
./config.sh --url https://github.com/KidCarmi/Claude-Test \
            --token <TOKEN> --labels self-hosted,linux,x64 --unattended

# 5. Run as a service
sudo ./svc.sh install && sudo ./svc.sh start
```

> **Note:** After `usermod -aG docker`, you must log out and back in (or run `newgrp docker`)
> for the group change to take effect. Then restart the runner service:
> `sudo ~/actions-runner/svc.sh restart`

---

## Development

```bash
go test -v -race ./...
go build -o proxyshield .
```

### Running tests

```bash
go test ./...                        # all tests
go test -run TestBlocklist ./...     # blocklist tests only
go test -run TestIPFilter ./...      # IP filter tests
go test -run TestRateLimit ./...     # rate limiter tests
go test -run TestPlugin ./...        # plugin chain tests
go test -run TestHandleRequest ./... # proxy handler integration tests
```

---

## Architecture

```
main.go           — CLI flags, startup, graceful shutdown
proxy.go          — HTTP/HTTPS/WebSocket request handler
socks5.go         — SOCKS5 server
plugin.go         — Plugin middleware API
security.go       — IPFilter + RateLimiter
store.go          — Blocklist, Config, request log, time-series stats, top-hosts
ui.go             — Web UI server + REST API endpoints
metrics.go        — Prometheus /metrics endpoint
logger.go         — Structured logging + log rotation (text/JSON)
config.go         — YAML config file loading
tls.go            — Self-signed TLS certificate generation
rewrite.go        — Header rewrite engine (host-pattern, req/resp rules)
auth_ldap.go      — LDAP authentication provider
auth_oidc.go      — OIDC token introspection provider
controlplane.go   — Control Plane / Data Plane gRPC
static/           — Embedded Web UI (single HTML file, Chart.js)
scripts/          — Helper scripts (self-hosted runner setup)
```

---

## License

MIT
