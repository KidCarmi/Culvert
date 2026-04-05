# Feature Coverage Audit

## Current GUI Panels (15 panels in sidebar)

| # | Panel | data-view | API Endpoints | Status |
|---|-------|-----------|---------------|--------|
| 1 | Dashboard | `dashboard` | `/api/stats`, `/api/timeseries`, `/api/top-hosts`, `/api/country-traffic` | FULL |
| 2 | Live Feed | `livefeed` | `/api/logs`, `/api/events` (SSE) | FULL |
| 3 | Blocklist | `blocklist` | `/api/blocklist`, `/api/blocklist/mode`, `/api/blocklist/feed`, `/api/blocklist/feed/sync`, `/api/blocklist/exceptions` | FULL |
| 4 | Security | `security` | `/api/security` (IP filter, rate limit) | PARTIAL — missing conn limit, syslog, metrics config |
| 5 | Policy | `policy` | `/api/policy`, `/api/policy/reorder`, `/api/default-action` | FULL |
| 6 | URL Categories | `urlcat` | `/api/urlcat`, `/api/urlcat/host`, `/api/urlcat/lookup` | FULL |
| 7 | File Blocking | `fileblock` | `/api/fileblock`, `/api/fileblock/profiles` | FULL |
| 8 | Header Rewrite | `rewrite` | `/api/rewrite` | FULL |
| 9 | Identity Providers | `idproviders` | `/api/idp`, `/api/idp/discover`, `/api/idp/{id}`, `/api/idp/{id}/groups` | FULL |
| 10 | PAC File | `pac` | `/api/pac-config`, `/proxy.pac` | FULL |
| 11 | Certificates | `certificates` | `/api/ca-cert`, `/api/certs/upload`, `/api/ssl-bypass`, `/api/content-scan` | PARTIAL — missing OCSP, HSM/KMS |
| 12 | Settings | `settings` | `/api/settings`, `/api/settings/unauth-mode`, `/api/session-timeout`, `/api/ui-allow-ips`, `/api/syslog`, `/api/config/export`, `/api/config/import` | PARTIAL |
| 13 | Policy Tester | `policy-tester` | `/api/policy/test` | FULL |
| 14 | Audit Log | `audit` | `/api/audit` | FULL |
| 15 | Users | `users` | `/api/auth/users` | FULL |

## Security Scanning (sub-panels inside Security view)

| Feature | API | GUI Panel | Status |
|---------|-----|-----------|--------|
| ClamAV status | `/api/security-scan/status` | Security Scanning section | VIEW ONLY — no config |
| YARA status + reload | `/api/security-scan/yara/reload` | Security Scanning section | VIEW ONLY — no config |
| Threat feed sync | `/api/security-scan/feeds/sync` | Security Scanning section | FULL |
| Domain allowlist | `/api/security-scan/feeds/domain-allowlist` | Security Scanning section | FULL |
| Alert webhooks | `/api/alerts/webhooks`, `/api/alerts/webhooks/test` | Security Scanning section | FULL |

---

## Features NOT in GUI (CLI/Config-file only)

### CRITICAL — No GUI, No API

| Feature | Backend File | CLI Flag / Config | Gap |
|---------|-------------|-------------------|-----|
| **Control Plane setup** | `controlplane.go` | `-cp-grpc-addr`, `-cp-grpc-cert/key/ca` | No way to deploy/manage multi-node from GUI |
| **Data Plane enrollment** | `controlplane.go` | `-dp-cp-addr`, `-dp-node-id`, `-dp-cert/key/ca` | No node enrollment UI |
| **Node health dashboard** | `controlplane.go` | gRPC PushMetrics | Metrics received but no visualization |
| **HSM / KMS key provider** | `ca.go:453-499` | Code interface only, no config | KeyProvider interface exists but no way to configure |
| **Upstream proxy chaining** | `upstream.go` | `upstream` in config.yaml | No GUI — failover, circuit breaker, health checks |
| **OCSP/CRL revocation** | `ocsp.go` | `proxy.ocsp_check` in config | Checkbox buried in config, no dedicated panel |
| **GeoIP database mgmt** | `geoip.go` | `-geoip-db` flag | No GUI to upload/refresh MaxMind DB |

### MODERATE — Has API but Limited/No GUI

| Feature | API | Gap |
|---------|-----|-----|
| **Syslog config** | `/api/syslog` | Has API, has Settings UI section, but buried and minimal |
| **Connection limit** | None | Hardcoded constant `defaultMaxConnsPerIP = 1024`, no API or GUI |
| **ClamAV address** | None | CLI-only `-clamav-addr`, no runtime change |
| **YARA rules dir** | `/api/security-scan/yara/reload` | Can reload but can't change directory path |
| **Metrics token** | None | CLI-only `-metrics-token`, no runtime change |
| **Log format** | None | CLI-only, text/JSON toggle at startup |
| **Log rotation size** | None | CLI-only `-log-max-mb` |
| **Block page template** | None (`blockpage.go`) | Hardcoded HTML, no customization |
| **CA auto-rotation alerts** | Infrastructure exists (`alerts.go`) | `cert_expiry` event defined but never fired |
| **Scan timeouts/limits** | None | `maxBytes` configurable via config only |

### LOW — Startup-only, Reasonable as CLI

| Feature | Flag | Notes |
|---------|------|-------|
| Proxy port | `-port` | Startup-only, correct |
| UI port | `-ui-port` | Startup-only, correct |
| TLS cert/key for UI | `-tls-cert`, `-tls-key` | Startup-only, correct |
| SOCKS5 port | `-socks5-port` | Startup-only, correct |
| CA bundle path | `-ca-path` | Startup-only, correct |
| Category feed DB path | `-cat-feed-db` | Startup-only, correct |

---

## Summary: What Needs GUI Panels

### New Panels Needed

1. **Cluster / Multi-Node** (new sidebar section)
   - Node list with health, sync status, uptime
   - Control Plane / Data Plane enrollment wizard
   - Per-node metrics aggregation view
   - Centralized audit log viewer

2. **Upstream Proxies** (new panel)
   - Parent proxy list with failover order
   - Circuit breaker settings (threshold, timeout, reset)
   - Health check configuration
   - Round-robin weight configuration

3. **Advanced Security** (expand existing Security panel)
   - Connection limit per-IP (configurable)
   - Scan buffer size limit
   - DPI/YARA timeout settings
   - Block page template editor

4. **Certificate Management** (expand existing Certificates panel)
   - OCSP/CRL toggle and status
   - HSM/KMS provider configuration
   - CA export (download PEM)
   - CA rotation status and timeline
   - CA auto-rotation webhook alert toggle

5. **Observability** (new panel or expand Settings)
   - Syslog address + format (RFC 3164/5424)
   - Log format toggle (text/JSON)
   - Metrics token management
   - GeoIP database upload/status
   - OpenTelemetry configuration (future)
