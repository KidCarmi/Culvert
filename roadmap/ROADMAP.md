# Culvert Roadmap

## Production Readiness — Action Items

Sourced from production deployment evaluation feedback (April 2026).

### P0 — High Availability & Distributed State

- [x] **Configurable session signing key** — Shared HMAC secret via `CULVERT_SESSION_SECRET` env var, `session_secret` config field, or admin GUI. All LB nodes now validate each other's sessions.
- [ ] **Distributed session revocation** — Sync revocation list via gRPC Control Plane channel (today revocation is per-process in-memory)
- [ ] **Distributed rate limiting** — Optional Redis-backed sliding-window counters for accurate per-IP rate limiting across nodes (today counters are per-process, N nodes = Nx effective limit)
- [x] **Wire `cert_expiry` webhook alert** — `RotateIfNeeded()` fires `cert_expiry` alert with rotation details via `fireAlert()`.

### P1 — Observability

- [ ] **OpenTelemetry (OTLP) export** — Export metrics + traces via OTLP gRPC/HTTP. Today only Prometheus text format is supported.
- [x] **W3C Traceparent propagation** — Forward `traceparent`/`tracestate` headers through proxied requests for distributed tracing across multi-node setups
- [x] **RFC 5424 syslog** — Currently only RFC 3164 (BSD syslog). Modern SIEMs prefer RFC 5424 structured data.

### P1 — Process Isolation & Stability

- [x] **DPI scanner timeout** — Add per-pattern timeout to DPI regex matching (YARA has 5s timeout, DPI has none)
- [x] **YARA timeout goroutine leak fix** — Timed-out regex goroutines currently leak indefinitely. Add context cancellation or goroutine tracking.
- [ ] **Optional scan microservice mode** — Allow YARA + DPI to run as a sidecar HTTP service instead of in-process, for deployments that need process isolation
- [x] **Panic recovery around scanning** — Add `defer recover()` in scan call sites (`proxy.go` scan paths) to prevent one bad file from killing a request goroutine

### P2 — CA & Certificate Management

- [ ] **Dual-CA overlap mode** — Serve leaf certs from both old and new CA simultaneously during rotation window, for true zero-downtime CA rotation
- [x] **CA export API endpoint** — Admin API to download the current root CA cert (PEM) for MDM/GPO distribution
- [ ] **HSM/KMS UI panel** — The `KeyProvider` interface exists in code (`ca.go:453-499`) but has no GUI configuration. Add admin panel for AWS KMS / Azure Key Vault / GCP Cloud KMS / PKCS#11 setup.

### P2 — Multi-Node Operations

- [x] **Control Plane UI panel** — GUI for enabling CP mode, deploying Data Plane nodes, enrollment tokens, node list with health/sync status.
- [ ] **Node health dashboard** — Aggregate per-node metrics (already pushed via gRPC `PushMetrics`) into a visual dashboard
- [ ] **Centralized audit log** — Forward audit events from Data Plane nodes to Control Plane for unified visibility

### P3 — Protocol Handling

- [x] **TLS protocol detection in SSL inspection** — Peek first byte of CONNECT tunnel to detect non-TLS protocols (SSH, RDP, databases). Fall back to raw relay instead of crashing. Approach designed but deferred.

### P3 — GUI Coverage Gaps

- [x] **Upstream proxy chaining UI** — Admin panel for parent proxies, failover, circuit breaker, health checks
- [x] **Header rewrite rules UI** — Admin panel for per-host header rewrite rules
- [x] **OCSP/CRL settings UI** — Toggle OCSP checking, view cache stats
- [x] **Syslog configuration UI** — Configure syslog forwarding address from Settings panel
- [x] **Metrics endpoint configuration UI** — Bearer token management via Settings panel
- [x] **Logger configuration UI** — View log format, rotation, file path in Settings panel
- [x] **Connection limit configuration UI** — Per-IP limit configurable from Security panel
- [x] **GeoIP database management UI** — Status and path display in Settings panel
- [x] **PAC file customization UI** — PAC template editor with proxy address configuration
- [x] **Block page customization UI** — HTML template editor with preview and reset
