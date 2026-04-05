# Culvert Roadmap

## Production Readiness — Action Items

Sourced from production deployment evaluation feedback (April 2026).

### P0 — High Availability & Distributed State

- [ ] **Configurable session signing key** — Allow shared HMAC secret via env var / mounted secret instead of random-at-startup, so all nodes behind a LB validate each other's session cookies
- [ ] **Distributed session revocation** — Sync revocation list via gRPC Control Plane channel (today revocation is per-process in-memory)
- [ ] **Distributed rate limiting** — Optional Redis-backed sliding-window counters for accurate per-IP rate limiting across nodes (today counters are per-process, N nodes = Nx effective limit)
- [ ] **Wire `cert_expiry` webhook alert** — Alert infrastructure exists (`alerts.go`) and `cert_expiry` event type is defined, but `RotateIfNeeded()` never calls `fireAlert()`. Quick win.

### P1 — Observability

- [ ] **OpenTelemetry (OTLP) export** — Export metrics + traces via OTLP gRPC/HTTP. Today only Prometheus text format is supported.
- [ ] **W3C Traceparent propagation** — Forward `traceparent`/`tracestate` headers through proxied requests for distributed tracing across multi-node setups
- [ ] **RFC 5424 syslog** — Currently only RFC 3164 (BSD syslog). Modern SIEMs prefer RFC 5424 structured data.

### P1 — Process Isolation & Stability

- [ ] **DPI scanner timeout** — Add per-pattern timeout to DPI regex matching (YARA has 5s timeout, DPI has none)
- [ ] **YARA timeout goroutine leak fix** — Timed-out regex goroutines currently leak indefinitely. Add context cancellation or goroutine tracking.
- [ ] **Optional scan microservice mode** — Allow YARA + DPI to run as a sidecar HTTP service instead of in-process, for deployments that need process isolation
- [ ] **Panic recovery around scanning** — Add `defer recover()` in scan call sites (`proxy.go` scan paths) to prevent one bad file from killing a request goroutine

### P2 — CA & Certificate Management

- [ ] **Dual-CA overlap mode** — Serve leaf certs from both old and new CA simultaneously during rotation window, for true zero-downtime CA rotation
- [ ] **CA export API endpoint** — Admin API to download the current root CA cert (PEM) for MDM/GPO distribution
- [ ] **HSM/KMS UI panel** — The `KeyProvider` interface exists in code (`ca.go:453-499`) but has no GUI configuration. Add admin panel for AWS KMS / Azure Key Vault / GCP Cloud KMS / PKCS#11 setup.

### P2 — Multi-Node Operations

- [ ] **Control Plane UI panel** — No GUI for deploying/managing Data Plane nodes. Today requires CLI flags (`-cp-addr`, `-dp-connect`). Need admin panel showing node list, health, sync status, metrics.
- [ ] **Node health dashboard** — Aggregate per-node metrics (already pushed via gRPC `PushMetrics`) into a visual dashboard
- [ ] **Centralized audit log** — Forward audit events from Data Plane nodes to Control Plane for unified visibility

### P3 — Protocol Handling

- [ ] **TLS protocol detection in SSL inspection** — Peek first byte of CONNECT tunnel to detect non-TLS protocols (SSH, RDP, databases). Fall back to raw relay instead of crashing. Approach designed but deferred.

### P3 — GUI Coverage Gaps

- [ ] **Upstream proxy chaining UI** — Backend exists (`upstream.go`) but no admin panel for configuring parent proxies, failover, circuit breaker settings
- [ ] **Header rewrite rules UI** — Backend exists (`rewrite.go`) but no admin panel
- [ ] **OCSP/CRL settings UI** — Backend exists (`ocsp.go`) but no admin panel
- [ ] **Syslog configuration UI** — Backend exists (`syslog.go`) but configured via CLI flags only
- [ ] **Metrics endpoint configuration UI** — Bearer token, endpoint path — CLI flags only
- [ ] **Logger configuration UI** — Log format (text/JSON), rotation size, log path — CLI flags only
- [ ] **Connection limit configuration UI** — Per-IP limit is hardcoded constant, should be configurable via admin panel
- [ ] **GeoIP database management UI** — MaxMind license key, database path, refresh interval — CLI flags only
- [ ] **PAC file customization UI** — PAC template, proxy address — CLI flags only
- [ ] **Block page customization UI** — HTML template for block pages — no admin panel
