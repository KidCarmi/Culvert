# Claim-Evidence Ledger — "What is Culvert?"

Article: [`what-is-culvert.md`](what-is-culvert.md)
Verified against repo revision `ca60d83` (branch
`claude/culvert-content-foundation-5geqkh`).

Evidence types: `src` = runtime source (`file:line`); `test` = automated test;
`api` = route/handler; `cfg` = config/flag; `adr` = architecture decision/spec;
`lab` = reproduced command in this environment.

## Framing claims

| Claim | Type | Evidence |
|---|---|---|
| Shipped binary is statically linked, `CGO_ENABLED=0` | src | `Dockerfile:20`, `Dockerfile:37` (comment: "static binary that runs on any distro") |
| A plain `go build` is dynamically linked (dev build differs from release) | lab | `file` on `go build` output → "dynamically linked"; release uses `CGO_ENABLED=0` |
| Default proxy port 8080 | src | `main.go:502` `firstNonZero(*s.proxyPort, s.fc.Proxy.Port, 8080)` |
| Default UI port 9090 | src | `main.go:503` `firstNonZero(..., 9090)` |
| SOCKS5 disabled by default (`0`) | cfg/src | `config.go:23` `// 0 = disabled`; `main.go:236` flag default `0`; gated `main.go:857 if socks5Port > 0` |
| `/health`, `/ready`, `/metrics`, `/proxy.pac` served on proxy port | src | `main.go:892-900` (proxy handler switch) |

## Proxy and transport

| Claim | Type | Evidence |
|---|---|---|
| HTTP/HTTPS forward proxy + full CONNECT tunneling | src/test | `proxy.go`, `proxy_tunnel.go` (`handleTunnelInspect`, CONNECT-bypass relay ~l.201/243), `proxy_tunnel_h2.go`; `proxy_traffic_e2e_test.go` |
| SOCKS5 RFC 1928/1929, CONNECT only, UDP ASSOCIATE rejected | src/test | `socks5.go:44` (comment), `socks5.go:303` `if cmd != 0x01`; RFC 1929 `socks5.go:184-250`; `socks5_test.go` |
| WebSocket relay | src/test | `proxy_tunnel.go:42` `isWebSocketUpgrade`, `:81` `handleWebSocket`; `proxy_websocket_status_test.go` |
| PAC file served | src/test | `pac.go:98` `servePACFile`, route `/proxy.pac`; `ui_pac_e2e_test.go` |
| Upstream chaining + health checks + circuit breaker | src/test | `internal/upstream/upstream.go` (`CircuitBreaker` l.48, `RunHealthCheckLoop` l.352); `internal/upstream/upstream_test.go` |

## TLS inspection

| Claim | Type | Evidence |
|---|---|---|
| MITM with on-the-fly ECDSA P-256 leaf certs, internal CA | src/test | `internal/ca/ca.go:146` (CA P-256), `:763` (leaf P-256); `mitm_inspect_e2e_test.go` |
| Per-rule / per-host Inspect vs Bypass | src/test | `policy.go:33-34` `SSLAction Inspect\|Bypass`; `internal/sslbypass/sslbypass.go`; `sslbypass_test.go` |
| Leaf cache 10,000 entries / 1h TTL, LRU | src | `internal/ca/ca.go:78` `certCacheMaxSize = 10_000`, `:79` `certCacheTTL = 1h`, eviction `:703` |
| CA key AES-256-GCM + PBKDF2-SHA256 @ 600,000 iters | src/test | `internal/ca/ca.go:138` `pbkdf2Iter = 600_000 // NIST SP 800-132`, `:352`, `:358` GCM; `ca_test.go` |
| Decryption Profiles | src/adr | `internal/decryptprofile`; `docs/operator/decryption-profiles.md` |
| Adaptive decryption exclusion (opt-in per profile) | src | `internal/autoexclude`; CLAUDE.md architecture note |

## Policy

| Claim | Type | Evidence |
|---|---|---|
| Priority-ordered, first-match | src/test | `policy.go:1083` `Evaluate` (priority-sorted, first hit `:1140`), `:90` comment; `policy_flow_e2e_test.go` |
| Default-deny; fresh install w/ 0 rules = passthrough | src | `proxy.go:19` `defaultPolicyActionAllow // 0 = deny (default)`, `setDefaultPolicyAction`; README Limitations |
| 8 condition types | src | `policy.go:94-109` (`SourceIP`, `SourceIdentity`, `SourceGroup`, `AuthSource`, `DestFQDN`, `DestCategory`, `DestCountry`, `Schedule`) |
| GeoIP fail-closed on cache miss | src | `policy.go:1384-1389` ("Fail-closed: ... rule does NOT match") |
| Actions Allow/Drop/Block Page/Redirect + TLS action | src | `policy.go:23-26`, `:33-34`, `RedirectURL :124` |
| Conflict detection (same priority, different action) | src | `policy.go:877` `DetectConflicts()`, `rulesOverlap :905` |
| Policy Tester dry-run | api/test | `POST /api/policy/test` (`apiPolicyTest`), trace `ui_policy.go:1880`; `authpolicy_slice8_test.go:295` |

## Identity and access

| Claim | Type | Evidence |
|---|---|---|
| Local auth (bcrypt) | src/test | `store.go:436` `bcrypt.GenerateFromPassword` (DefaultCost), verify `:497` |
| OIDC Auth-Code + PKCE (S256) and introspection (RFC 7662) | src | `auth_oidc_flow.go:386-387` (PKCE S256), introspection fallback `:367-371` |
| SAML 2.0 SP | src/test | `auth_saml.go:45` `NewSAMLProvider` (crewjam/saml); `TestSAMLProvider_DisplayName` |
| LDAP/AD bind + search + group check (single `RequiredGroup` DN) | src | `auth_ldap.go:162` reads `memberOf`, `isMember :194-196`, `RequiredGroup :42` |
| Multi-IdP registry, email-domain routing | src/test | `auth_idp.go:487-501` `RouteByDomain`, `EmailDomains :31`; `TestIdPRegistry_RouteByDomain_NoMatch` |
| TOTP 2FA (RFC 6238), stdlib-only | src | `internal/totp/totp.go:1-15` (stdlib only), `VerifyTOTPReturnCounter :43` |
| Admin RBAC admin/operator/viewer | src/test | `store.go:318-323`; `requireRole` `ui_policy.go:39,45`; `TestSlice8_ViewerAndOperatorWritesBlocked` |
| Session HMAC-SHA256, per-session `jti`, TTL 8h, disk revocation | src | `internal/session/session.go:427` (HMAC-SHA256), `Jti :362`, `ttl = 8h :311`, `revocationsPath :242-253` |
| Brute-force lockout (IP+user 5/15min; account-wide tier) | src | `internal/lockout/lockout.go:42` `MaxAttempts = 5`, `:49` 15min; account tier `:25,44` |
| Password complexity 8+/mixed-case/digit | src | `store.go:644-663` `validatePasswordComplexity` |

## Content security

| Claim | Type | Evidence |
|---|---|---|
| ClamAV INSTREAM (sidecar) | src/test | `internal/clamav/clamav.go:168` `zINSTREAM`; `TestClient_ScanMultiChunkFindsVirus` |
| Pure-Go YARA engine | src | `internal/yara/yara.go:1-18` ("without requiring cgo or libyara") |
| Threat feeds URLhaus + OpenPhish + domain allowlist | src | `internal/threatfeed/threatfeed.go:103-104`, `defaultDomainAllowlist :359-363` |
| Regex DPI on decrypted responses | src | `internal/scanner/scanner.go:1-2` (comment), compiled regexps `:87-91` |
| File-type blocking (extension profiles + magic/MIME) | src | `internal/fileblock/fileprofile.go:17,37,45`; `internal/filemagic/filemagic.go` |
| UT1 + curated categories | src | `internal/feedsync/feedsync.go` (UT1 syncer); `internal/urlcat/urlcat.go:30-35` (curated) |
| CDR via **external Sluice engine** (gRPC/mTLS) — companion, not in-binary | src | `cdr.go:3-10` ("Sluice CDR ... streaming gRPC client"); policy `cdrpolicy.go` |

## Observability / Distributed / Supply chain

| Claim | Type | Evidence |
|---|---|---|
| Prometheus `culvert_*`, per-rule hits, latency histogram, bearer-protected | src/test | `metrics.go:332-338` (`culvert_policy_rule_hits_total`), `:369-380` (latency histogram), `handleMetrics :429-439` (constant-time bearer); proxy port `main.go:897`; `authpolicy_slice5_test.go:197` |
| Live SSE dashboard (fan-out, slow-client eviction, cap 256) | src/test | `internal/sse/sse.go` (Hub); `events.go:59,125`; `events_broadcaster_test.go` |
| Rotating JSON(L) file logger | src | `internal/reqlog/reqlog.go:65` (`*fileutil.RotatingFile`, JSONL), `internal/fileutil/rotating.go` |
| Syslog RFC 3164/5424, async drop-on-full (queue 2048, single drain) | src/test | `internal/syslog/syslog.go:7-22` (comment), `queueCap = 2048 :67`, drops `:53,141`; `syslog_async_test.go` |
| HMAC-SHA256 webhook alerts + retry queue | src/test | `internal/alerts/secret.go:3-4` (HMAC-SHA256 key), `enqueueRetry`/`retryMax`; `retry_test.go:32-62` |
| Audit ring bounded 500, **append-only JSONL (no hash-chain/signature — NOT tamper-evident)** | src | `internal/audit/audit.go:49` `MaxRing = 500`, evict `:124-126`. Tamper-evidence claim in README/architecture is **not** backed by code. |
| `/health` + `/ready` with checks map, 200/503 | src/test | `main.go:893-896`; `computeReadiness healthcheck.go:128-129`, `Checks map :94`; `readyz_dp_health_test.go` |
| gRPC CP/DP + mTLS (enrolled calls cert-verified; Enroll open via `VerifyClientCertIfGiven`) | src | `controlplane_server.go:21-25`, `verifyNode :32`, `controlplane_tls.go:91` |
| ConfigSnapshot push (SessionHMAC redacted before push) | src | `controlplane_snapshot.go`; redaction `controlplane_server.go:91-100` |
| Node groups + auto GeoIP labels | src | `internal/nodegroup/nodegroup.go:25,153-170`; `autoGeoLabel enrollment.go:351-364` |
| Per-group token-bucket QoS | src | `internal/bandwidth/bandwidth.go:45-66` (`tokenBucket`/`consume`) |
| Config versioning, 50-version max, auto on mutation | src/test | `internal/configver/configver.go:33` `DefaultMax = 50`; `TestSave_PrunesBeyondMax` |
| etcd fencing lease (optional HA) | src/adr | `internal/halease/etcd.go:20` (`leaderKey`), epoch `CreateRevision :101,150`; flag `main.go:245`; ADR-0005. **Note:** `halease.go:7` doc comment ("S1 ships the primitive ONLY") appears stale vs. root `ha_lease.go`/`ha_failover.go` + CLAUDE.md "PROGRAM COMPLETE"; integration state to confirm for the HA article (M-023). |
| Signed release catalog (Ed25519 + Sigstore keyless), enforce-default, freshness/rollback | src | `release_catalog_verify.go:56` (`VerifyMode` default enforce), `:107-108,154`; `release_catalog_freshness.go` |
| Digest-pinned dispatch (`repo@sha256:…`) at sudo boundary | src/test | `release_dispatch.go:177` (`splitRepoRef`); `install_script_maint_sudoers_render_test.go` |
| SLSA L3 + Cosign (CI-only build pipeline, not runtime) | ci | `.github/workflows/ci.yml:343-344` (`provenance: true`), `:363-382` (cosign keyless) |
| PQ hybrid X25519+ML-KEM-768 (inherited from Go toolchain, not Culvert code) | test | `pqc_test.go:59` `TestPQC_MLKEM768_KeyExchange` |

## Corrections applied during verification

- **"Tamper-evident audit trail"** (README/architecture wording) → downgraded to
  **"bounded, append-only audit ring"**. No hash-chain or signature exists in
  `internal/audit`; the ring only evicts oldest at `MaxRing = 500`.
- **CDR** → clarified as a client to an **external Sluice CDR engine** over
  gRPC/mTLS (`cdr.go`), not an in-binary disarm implementation.
- **LDAP group resolution** → scoped to a single `RequiredGroup` DN, not full
  group-list extraction (relevant to the identity deep-dive, not this overview).

## Known-limitation claims

| Claim | Type | Evidence |
|---|---|---|
| OCSP only, no CRL; OCSP fail-open on no responder, fail-closed on unreachable | src | README Limitations; `docs/architecture.md` §4 |
| SOCKS5 UDP ASSOCIATE rejected | src | `socks5.go:303` |
| PQC: key exchange from Go 1.25, signing classical ECDSA P-256 | src | `docs/architecture.md` §2; README |
| Decryption Profile `permissive`/`fail-open` marked "coming soon" | src | `docs/operator/decryption-profiles.md` |
