# UI Panel Design — Implementation Status

All panels and API endpoints described below have been implemented as part of the
roadmap. This document is preserved as a design reference.

## Navigation Structure (Current Sidebar)

> Refreshed 2026-07-17 to match the live sidebar in `static/index.html` (27 nav items across
> 6 sections). The prior version of this block dated back to an earlier milestone and used
> since-renamed labels ("Live Feed", "Policy Rules", "File Blocking", "Users") and a standalone
> "HA Failover" entry that no longer exists — HA is now a section inside the single Cluster panel.

```
OVERVIEW
  Dashboard

MONITOR
  Traffic
  Audit Log
  Decryption Exclusions
  Policy Tester

POLICIES
  Access Rules
  Authentication Rules
  Blocklist
  Content & Scanning
  File Control
  CDR

OBJECTS
  URL Categories
  Category Groups
  Decryption Profiles
  Header Rewrite
  Identity Providers

PLATFORM
  Certificates
  CA Management           — OCSP, HSM/KMS, dual-CA, CA export
  Cluster                 — includes the HA Fencing Lease section
  Upstream Proxies
  PAC File
  Releases
  Diagnostics
  Support
  Settings                — syslog, logger, metrics, GeoIP, OTLP, block page

ADMINISTRATION
  Administrators
  Governance
```

---

## 1. Cluster Nodes Panel — ✅ IMPLEMENTED

- `data-view="cluster"` in `static/index.html`
- API: `/api/cluster/status`, `/api/cluster/nodes`, `/api/cluster/mode`, `/api/cluster/enroll`, `/api/cluster/audit`
- Features: CP/DP mode toggle, enrollment tokens, node list with health cards, centralized audit log

---

## 2. Upstream Proxies Panel — ✅ IMPLEMENTED

- `data-view="upstream"` in `static/index.html`
- API: `/api/upstream`, `/api/upstream/settings`
- Features: Parent proxy list, failover/round-robin mode, circuit breaker settings, health check status

---

## 3. CA Management (Certificates panel) — ✅ IMPLEMENTED

- Expanded Certificates panel in `static/index.html`
- API: `/api/ca-cert`, `/api/ocsp`, `/api/ca/key-provider`
- Features: Root CA info + download PEM, OCSP/CRL toggle + cache stats, HSM/KMS provider status, dual-CA overlap

---

## 4. Observability (Settings panel) — ✅ IMPLEMENTED

- Sub-sections inside Settings panel in `static/index.html`
- API: `/api/syslog`, `/api/metrics-config`, `/api/logger`, `/api/geoip`, `/api/otel`, `/api/blockpage`
- Features: Syslog address/format (RFC 3164/5424), Prometheus bearer token, logger config, GeoIP status, OTLP collector config, block page template editor

---

## 5. Expanded Security Panel — ✅ IMPLEMENTED

- Additional sections inside Security panel in `static/index.html`
- API: `/api/connlimit`, `/api/blockpage`, `/api/security-scan/svc`
- Features: Per-IP connection limit, block page HTML editor with preview/reset, scan microservice mode banner

---

## Implementation Phases — All Complete

- [x] Phase 1 — CA Management, connection limit, block page, OCSP toggle, cert_expiry alert
- [x] Phase 2 — Upstream Proxies panel with CRUD, circuit breaker, health checks
- [x] Phase 3 — Cluster panel with node list, enrollment, config sync, centralized audit
- [x] Phase 4 — Observability: GeoIP, logger, metrics token, OpenTelemetry (OTLP)
- [x] Phase 5 — HSM/KMS panel showing active provider + CA readiness
