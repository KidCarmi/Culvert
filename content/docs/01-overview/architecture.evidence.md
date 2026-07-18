# Claim-Evidence Ledger — "Architecture"

Article: [`architecture.md`](architecture.md). Verified against repo revision
`ca60d83`. Capability-level evidence (TLS, policy, identity, CP/DP) is shared
with [`what-is-culvert.evidence.md`](what-is-culvert.evidence.md); this ledger
covers the architecture-specific claims — chiefly the **verified pipeline
order**.

## Request pipeline order (from `proxy.go:handleRequest`, l.792+)

| Stage | Claim | Evidence |
|---|---|---|
| 1 | Request tracing (X-Request-ID) + record-only panic backstop | `proxy.go` `setupRequestTracing`, `proxyCrashGuard` (comment: "never writes an HTTP status") |
| 2 | Per-IP connection limit, `503` on exceed | `proxy.go` `connLimiter.Acquire` → `http.Error(..., 503)` |
| 3 | IP filter, `403 IP_BLOCKED` | `proxy.go` `ipf.Allowed` → `recordRequest(..., "IP_BLOCKED", ...)` |
| 4 | Rate limit, `429 RATE_LIMITED` | `proxy.go` `rl.AllowAuto(clientIP)` → `recordRequest(..., "RATE_LIMITED", ...)` |
| 5 | Stage-1 auth (writes its own 407/redirect/403) | `proxy.go` `resolveRequestAuth(w, r, clientIP, reqID)` (comment: "writes any terminal 407/redirect/403 itself") |
| 6 | Host canonicalization gate, IDNA, **fail-closed** | `proxy.go:850-859` (comment "RISK-013, fail-closed"; logs `INVALID_HOST`, source `idna`) |
| 7 | Pre-dispatch blocks: blocklist → threat feed → plugin → file-type | `proxy.go:401` `preDispatchBlocked`; blocklist `:406`, threat `:417`, plugin `:435` `pluginDecision`, file-ext `:449` |
| 8 | Stage-2 policy, first-match by priority, default-deny | `policy.go:1083` `Evaluate`; `proxy.go:19` `defaultPolicyActionAllow // 0 = deny (default)` |
| 10 | TLS action Inspect/Bypass on CONNECT | `proxy_tunnel.go` `handleTunnelInspect`/bypass; `policy.go:33-34` |
| 12 | Header scrub before forward (drops `X-User-Identity`) | `proxy.go:46` `scrubForwardedHeaders` |
| 13 | Upstream + SSRF re-check at connect | `upstream.go`; `internal/ssrf` `isPrivateHost` re-check |
| 14 | Telemetry for every outcome | `store.go` `recordRequest*`, `metrics.go`, `events.go` |

## Doc-drift note (finding G-05)

`docs/architecture.md` ASCII diagram places the plugin middleware chain **before**
authentication and omits the rate-limit and host-canonicalization stages. The
code runs `pluginDecision` **after** Stage-1 auth, inside `preDispatchBlocked`
(`proxy.go:435`). The website article uses the code-verified order. Recorded in
`RUN-STATE.md` as a product-doc drift to reconcile (not edited here — it is
product documentation, outside content scope).

## TLS inspection internals

| Claim | Evidence |
|---|---|
| Leaf certs ECDSA P-256, cache 10k/1h TTL LRU, memory-only signing key | `internal/ca/ca.go:78-79` (`certCacheMaxSize = 10_000`, `certCacheTTL = 1h`), `:763` (leaf P-256) |
| CA key AES-256-GCM + PBKDF2-SHA256 @ 600k | `internal/ca/ca.go:138,352,358` |
| Verified-only upstream session resumption | `docs/architecture.md` §2 |
| Per-host bypass | `internal/sslbypass` |
| PQ key exchange inherited from Go 1.25 | `pqc_test.go:59` `TestPQC_MLKEM768_KeyExchange` |

## Control Plane / Data Plane

| Claim | Evidence |
|---|---|
| DP stateless, full snapshot on connect | `controlplane_snapshot.go`; `docs/architecture.md` §3 |
| Snapshot redacts secrets to non-enrolled callers | `controlplane_server.go:91-100` |
| mTLS; Enroll open via `VerifyClientCertIfGiven` | `controlplane_tls.go:91`, `verifyNode` |
| etcd fencing lease, key `/culvert/ha/leader`, epoch = `CreateRevision` | `internal/halease/etcd.go:20,101,150` |
| Node groups + auto GeoIP labels; per-group token-bucket QoS | `nodegroup.go`, `enrollment.go:351-364`, `bandwidth.go:45-66` |

## Failure modes

Each row in the article's Failure-modes table maps to a `recordRequest*` outcome
string emitted at the corresponding stage in `proxy.go` (`IP_BLOCKED`,
`RATE_LIMITED`, `INVALID_HOST`, `BLOCKED`, `THREAT_BLOCKED`) or to the
documented default-deny / GeoIP-fail-closed / OCSP-fail-closed behaviors
(`policy.go:1384-1389`, README/architecture §4).
