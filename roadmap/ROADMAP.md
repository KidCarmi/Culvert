# Culvert Roadmap

## Production Readiness — Action Items

Sourced from production deployment evaluation feedback (April 2026).

### P0 — High Availability & Distributed State

- [x] **Configurable session signing key** — Shared HMAC secret via `CULVERT_SESSION_SECRET` env var, `session_secret` config field, or admin GUI. All LB nodes now validate each other's sessions.
- [x] **Distributed session revocation** — Sync revocation list via gRPC Control Plane channel every 3s. Each node exports local revocations; CP merges and broadcasts. Logout on any node is enforced cluster-wide.
- [x] **Distributed rate limiting** — Gossip-based approximate counters via existing gRPC Control Plane channel. Each DP syncs hot-IP deltas (>50% of limit) every 5s; CP aggregates and broadcasts cluster-wide totals. No Redis dependency.
- [x] **Wire `cert_expiry` webhook alert** — `RotateIfNeeded()` fires `cert_expiry` alert with rotation details via `fireAlert()`.

### P1 — Observability

- [x] **OpenTelemetry (OTLP) export** — Push all culvert_* metrics to any OTLP/HTTP collector as JSON every 15s. Counters, gauges, histogram, per-rule hits. Zero SDK dependency — uses plain net/http. CLI flag, config field, and admin GUI panel.
- [x] **W3C Traceparent propagation** — Forward `traceparent`/`tracestate` headers through proxied requests for distributed tracing across multi-node setups
- [x] **RFC 5424 syslog** — Currently only RFC 3164 (BSD syslog). Modern SIEMs prefer RFC 5424 structured data.

### P1 — Process Isolation & Stability

- [x] **DPI scanner timeout** — Add per-pattern timeout to DPI regex matching (YARA has 5s timeout, DPI has none)
- [x] **YARA timeout goroutine leak fix** — Timed-out regex goroutines currently leak indefinitely. Add context cancellation or goroutine tracking.
- [x] **Optional scan microservice mode** — Allow YARA + DPI to run as a sidecar HTTP service instead of in-process, for deployments that need process isolation
- [x] **Panic recovery around scanning** — Add `defer recover()` in scan call sites (`proxy.go` scan paths) to prevent one bad file from killing a request goroutine

### P2 — CA & Certificate Management

- [x] **Dual-CA overlap mode** — On rotation, old CA is preserved as secondary. Leaf certs include both CAs in the chain. Secondary auto-expires after its NotAfter. Status shown in CA Management UI.
- [x] **CA export API endpoint** — Admin API to download the current root CA cert (PEM) for MDM/GPO distribution
- [x] **HSM/KMS UI panel** — Admin panel shows active KeyProvider (local/external), CA readiness, and dual-CA overlap status. API: GET /api/ca/key-provider. External KMS registration via SetKeyProvider() in custom builds.

### P2 — Multi-Node Operations

- [x] **Control Plane UI panel** — GUI for enabling CP mode, deploying Data Plane nodes, enrollment tokens, node list with health/sync status.
- [x] **Node health dashboard** — Per-node health cards in Cluster view showing total/blocked/auth-fail counts, uptime, status, and last-seen time from existing PushMetrics data.
- [x] **Centralized audit log** — DP nodes push audit events to CP via PushAuditEvents RPC every 10s. CP stores in ring buffer (5000 max). Admin UI shows unified table with node ID, actor, action, object.

### P3 — Protocol Handling

- [x] **TLS protocol detection in SSL inspection** — Peek first byte of CONNECT tunnel to detect non-TLS protocols (SSH, RDP, databases). Fall back to raw relay instead of crashing. Approach designed but deferred.

### P3 — GUI Coverage Gaps

- [x] **Upstream proxy chaining UI** — Admin panel for parent proxies, failover, circuit breaker, health checks
- [x] **Header rewrite rules UI** — Admin panel for per-host header rewrite rules
- [x] **OCSP settings UI** — Toggle OCSP checking, view cache stats (CRL checking is not implemented — see README Limitations)
- [x] **Syslog configuration UI** — Configure syslog forwarding address from Settings panel
- [x] **Metrics endpoint configuration UI** — Bearer token management via Settings panel
- [x] **Logger configuration UI** — View log format, rotation, file path in Settings panel
- [x] **Connection limit configuration UI** — Per-IP limit configurable from Security panel
- [x] **GeoIP database management UI** — Status and path display in Settings panel
- [x] **PAC file customization UI** — PAC template editor with proxy address configuration
- [x] **Block page customization UI** — HTML template editor with preview and reset
