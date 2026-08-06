# Feature Coverage Audit

## Current GUI Panels (27 panels in sidebar, verified against `static/index.html` 2026-07-17)

> This table previously listed 18 panels and several renamed/removed labels (e.g. "Live Feed",
> "Policy", "File Blocking", "Users", a standalone "HA Failover" panel with `/api/ha/*` routes
> that no longer exist). It has been refreshed to match the live sidebar. CLAUDE.md's project
> structure table and `ui_routes_meta.go`'s `uiRoutes` remain the canonical sources of truth —
> treat this table as a snapshot, not a substitute for either.

| # | Panel | data-view | API Endpoints | Status |
|---|-------|-----------|---------------|--------|
| 1 | Dashboard | `dashboard` | `/api/stats`, `/api/timeseries`, `/api/top-hosts`, `/api/country-traffic` | FULL |
| 2 | Traffic | `livefeed` | `/api/logs`, `/api/events` (SSE) | FULL |
| 3 | Audit Log | `audit` | `/api/audit` | FULL |
| 4 | Decryption Exclusions | `decexclusions` | `/api/decryption-exclusions`, `/api/decryption-exclusions/tunables` | FULL |
| 5 | Policy Tester | `policy-tester` | `/api/policy/test` | FULL |
| 6 | Access Rules | `policy` | `/api/policy`, `/api/policy/reorder`, `/api/default-action` | FULL |
| 7 | Authentication Rules | `authpolicy` | `/api/authpolicy`, `/api/authpolicy/reorder` | FULL |
| 8 | Blocklist | `blocklist` | `/api/blocklist`, `/api/blocklist/mode`, `/api/blocklist/feed`, `/api/blocklist/feed/sync`, `/api/blocklist/exceptions` | FULL |
| 9 | Content & Scanning | `security` | `/api/security`, `/api/connlimit`, `/api/security-scan/*`, `/api/alerts/webhooks` | FULL |
| 10 | File Control | `fileblock` | `/api/fileblock`, `/api/fileblock/profiles` | FULL |
| 11 | CDR | `cdr` | `/api/cdr/config`, `/api/cdr/instances`, `/api/cdr/policies`, `/api/cdr/health`, `/api/cdr/test` | FULL |
| 12 | URL Categories | `urlcat` | `/api/urlcat`, `/api/urlcat/host`, `/api/urlcat/lookup` | FULL |
| 13 | Category Groups | `catgroups` | `/api/category-groups` | FULL |
| 14 | Decryption Profiles | `decprofiles` | `/api/decryption-profiles` | FULL |
| 15 | Header Rewrite | `rewrite` | `/api/rewrite` | FULL |
| 16 | Identity Providers | `idproviders` | `/api/idp`, `/api/idp/discover`, `/api/idp/{id}`, `/api/idp/{id}/groups` | FULL |
| 17 | Certificates | `certificates` | `/api/ca-cert`, `/api/certs/upload`, `/api/ssl-bypass`, `/api/content-scan`, `/api/content-scan/bypass`, `/api/ocsp` | FULL |
| 18 | CA Management | `ca-mgmt` | `/api/ca/status`, `/api/ca/key-provider`, `/api/ca/download`, `/api/ca/cache-clear`, `/api/ca/rotate` | FULL |
| 19 | Cluster (incl. HA Fencing Lease section) | `cluster` | `/api/cluster/status`, `/api/cluster/mode`, `/api/cluster/nodes`, `/api/cluster/tokens`, `/api/cluster/audit`, `/api/cluster/ha`, `/api/cluster/ha/promote` | FULL |
| 20 | Upstream Proxies | `upstream` | `/api/upstream`, `/api/upstream/settings` | FULL |
| 21 | PAC File | `pac` | `/api/pac-config`, `/proxy.pac` | FULL |
| 22 | Releases | `releases` | `/api/releases`, `/api/releases/current`, `/api/releases/dispatch*`, `/api/releases/catalog-refresh` | FULL |
| 23 | Diagnostics | `diagnostics` | `/api/diagnostics` | FULL |
| 24 | Support | `support` | `/api/support/status`, `/api/support/bundles` | FULL |
| 25 | Settings | `settings` | `/api/settings`, `/api/settings/default-auth-outcome` (legacy alias `/api/settings/unauth-mode`), `/api/session-timeout`, `/api/ui-allow-ips`, `/api/syslog`, `/api/config/export`, `/api/config/import`, `/api/metrics-config`, `/api/logger`, `/api/geoip`, `/api/blockpage`, `/api/otel` | FULL |
| 26 | Administrators | `users` | `/api/auth/users` | FULL |
| 27 | Governance | `governance` | `/api/governance/control-plane` | FULL |

## Security Scanning (sub-panels inside Security view)

| Feature | API | GUI Panel | Status |
|---------|-----|-----------|--------|
| ClamAV status | `/api/security-scan/status` | Security Scanning section | FULL |
| YARA status + reload | `/api/security-scan/yara/reload` | Security Scanning section | FULL |
| Threat feed sync | `/api/security-scan/feeds/sync` | Security Scanning section | FULL |
| Domain allowlist | `/api/security-scan/feeds/domain-allowlist` | Security Scanning section | FULL |
| Alert webhooks | `/api/alerts/webhooks`, `/api/alerts/webhooks/test` | Security Scanning section | FULL |
| Scan microservice mode | `/api/security-scan/svc` | Scan service banner | FULL |
| DPI patterns | `/api/security-scan/dpi` | Security Scanning section | FULL |

---

## Certificates Panel (sub-sections)

| Feature | API | Status |
|---------|-----|--------|
| Root CA management | `/api/ca-cert` | FULL — generate, download PEM, view expiry |
| SSL bypass list | `/api/ssl-bypass` | FULL |
| Content scanning toggle | `/api/content-scan` | FULL |
| OCSP/CRL revocation | `/api/ocsp` | FULL — toggle, cache stats |
| HSM/KMS key provider | `/api/ca/key-provider` | FULL — shows active provider, CA readiness, dual-CA status |
| Dual-CA overlap | `/api/ca-cert` | FULL — secondary CA auto-expires after NotAfter |

## Settings Panel (sub-sections)

| Feature | API | Status |
|---------|-----|--------|
| Default authentication outcome | `/api/settings/default-auth-outcome` (legacy alias `/api/settings/unauth-mode`) | FULL |
| Session timeout | `/api/session-timeout` | FULL |
| UI allow IPs | `/api/ui-allow-ips` | FULL |
| Syslog / SIEM | `/api/syslog` | FULL — address, format (RFC 3164/5424) |
| Config export/import | `/api/config/export`, `/api/config/import` | FULL |
| Prometheus metrics | `/api/metrics-config` | FULL — bearer token management |
| Logger configuration | `/api/logger` | FULL — format, rotation, file path |
| GeoIP database | `/api/geoip` | FULL — status, path |
| Block page template | `/api/blockpage` | FULL — HTML editor with preview and reset |
| OpenTelemetry (OTLP) | `/api/otel` | FULL — collector URL, push interval |
| Connection limit | `/api/connlimit` | FULL — per-IP limit configurable |

---

## Cluster Panel (sub-sections)

| Feature | API | Status |
|---------|-----|--------|
| CP/DP mode toggle | `/api/cluster/mode` | FULL |
| Enrollment tokens | `/api/cluster/enroll` | FULL |
| Node list + health | `/api/cluster/nodes`, `/api/cluster/status` | FULL — per-node health cards with counts, uptime, last-seen |
| Centralized audit log | `/api/cluster/audit` | FULL — unified table with node ID, actor, action |

---

## Features Remaining as CLI/Config-only (by design)

### Startup-only — Correct as CLI

| Feature | Flag | Notes |
|---------|------|-------|
| Proxy listen address | `-addr` | Startup-only, correct |
| UI listen address | `-ui-addr` | Startup-only, correct |
| TLS cert/key for UI | `-tls-cert`, `-tls-key` | Startup-only, correct |
| SOCKS5 listen address | `-socks5-addr` | Startup-only, correct |
| CA bundle path | `-ca-bundle` | Startup-only, correct |
| Category feed DB path | `-cat-feed-db` | Startup-only, correct |
| ClamAV address | `-clamav-addr` | Startup-only, correct |
| YARA rules directory | `-yara-rules` | Reload via API, path is startup-only |
| Scan svc listen address | `-scan-svc-listen` | Startup-only sidecar mode, correct |
| Scan svc remote URL | `-scan-svc-url` | Startup-only, correct |
| gRPC CP/DP addresses | `-cp-grpc-addr`, `-dp-cp-addr` | Startup-only, correct |

---

## Summary

All roadmap GUI coverage gaps have been addressed. Every feature that can be
configured at runtime has a corresponding admin API endpoint and UI panel/section.
Startup-only settings (listen addresses, file paths, gRPC endpoints) remain as
CLI flags / config fields, which is the correct design.
