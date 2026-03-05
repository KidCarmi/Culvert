# ProxyShield

**Enterprise-grade open source HTTP/HTTPS/SOCKS5 proxy** — built in Go, zero dependencies beyond the standard library.

[![CI](https://github.com/KidCarmi/Claude-Test/actions/workflows/ci.yml/badge.svg)](https://github.com/KidCarmi/Claude-Test/actions/workflows/ci.yml)

---

## Features

| Category | Details |
|----------|---------|
| **Protocols** | HTTP, HTTPS (CONNECT tunnel), WebSocket, SOCKS5 |
| **Security** | Basic auth, domain blocklist (wildcards), IP allowlist/blocklist (CIDR), rate limiting |
| **Observability** | Prometheus metrics (`/metrics`), real-time Web UI, request log |
| **Export** | Download logs as CSV or JSON |
| **Production** | Docker image, docker-compose, graceful shutdown, log rotation |
| **Extensibility** | Plugin middleware API (`Middleware` interface) |

---

## Quick Start

### Binary

```bash
# Download the latest release for your platform, then:
./proxyshield                          # runs on :8080 (proxy) + :9090 (UI)
./proxyshield -port 3128 -socks5-port 1080
./proxyshield -config config.yaml
```

### Docker

```bash
cp config.example.yaml config.yaml   # edit as needed
docker-compose up -d
# Web UI → https://localhost:9090
# Prometheus → docker-compose --profile monitoring up -d
```

---

## Configuration

Copy `config.example.yaml` to `config.yaml`:

```yaml
proxy:
  port: 8080
  ui_port: 9090
  socks5_port: 1080      # 0 = disabled

auth:
  user: alice
  pass: supersecret

security:
  ip_filter_mode: allow  # allow | block | "" (off)
  ip_list:
    - 192.168.1.0/24
  rate_limit: 60         # requests/min per IP
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
| Dashboard | Request stats, rate chart, recent requests |
| Live Feed | Real-time log with host/IP/status filters, CSV/JSON export |
| Blocklist | Add/remove/wildcard hosts, import/export `.txt` |
| Security | IP filter mode + list, rate limit, export logs |
| Settings | Basic auth credentials |

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
main.go          — CLI flags, startup, graceful shutdown
proxy.go         — HTTP/HTTPS/WebSocket request handler
socks5.go        — SOCKS5 server
plugin.go        — Plugin middleware API
security.go      — IPFilter + RateLimiter
store.go         — Blocklist, Config, request log, time-series stats
ui.go            — Web UI server + REST API endpoints
metrics.go       — Prometheus /metrics endpoint
logger.go        — Structured logging + log rotation
config.go        — YAML config file loading
tls.go           — Self-signed TLS certificate generation
static/          — Embedded Web UI (single HTML file, Chart.js)
```

---

## License

MIT
