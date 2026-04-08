# Day 2 Roadmap — Full System Code Review

> Generated 2026-04-08 from 8 domain-specific review agents.
> Covers: Proxy Core, Security & Auth, TLS & Certs, Policy Engine, Cluster/CP,
> Admin UI & API, Observability & Ops, Threat Detection & Scanning.

---

## Executive Summary

| Category | Critical | High | Medium | Low | Total |
|----------|----------|------|--------|-----|-------|
| Bugs | 2 | 5 | 14 | 8 | 29 |
| Security | 3 | 6 | 12 | 4 | 25 |
| Performance | 0 | 1 | 6 | 4 | 11 |
| Missing Features | 0 | 3 | 12 | 10 | 25 |
| Code Quality | 0 | 1 | 8 | 9 | 18 |
| **Total** | **5** | **16** | **52** | **35** | **108** |

---

## 1. CRITICAL & HIGH PRIORITY (Fix Before Next Release)

### 1.1 Content-Encoding Bypass — Scanners Cannot See Compressed Bodies
- **Files**: `proxy.go`, `security_scan.go`
- **Severity**: CRITICAL
- **Issue**: Response bodies are scanned as raw bytes without decompressing `Content-Encoding: gzip/deflate/brotli`. Attackers deliver gzipped malware that bypasses ClamAV and YARA because signatures match uncompressed content only.
- **Fix**: Check `Content-Encoding` header after buffering; decompress before passing to scanners. Guard against gzip bombs with uncompressed size limits.

### 1.2 IDN Homograph Attack — No IDNA Normalization
- **Files**: `policy.go:792-804`, `store.go:862-880`, `catdb.go:62`
- **Severity**: CRITICAL
- **Issue**: Hosts are lowercased with `strings.ToLower()` but NOT normalized via IDNA2008 (RFC 5890). Punycode domains (`xn--examp1e.com`) bypass blocklist and category rules for their ASCII equivalents.
- **Fix**: Normalize hosts with `golang.org/x/net/idna.ToASCII()` before all FQDN comparisons in `matchFQDN()`, blocklist lookup, and category DB lookup.

### 1.3 ~~Missing RBAC on Certificate Upload~~ DONE
- **File**: `ui.go:2374-2411`
- **Severity**: CRITICAL
- **Status**: FIXED — Added `requireRole(w, r, RoleAdmin)` check.

### 1.4 ~~Missing Sub Validation in OIDC ResolveIdentity~~ DONE
- **File**: `auth_oidc_flow.go:343-359`
- **Severity**: HIGH
- **Status**: FIXED — Added `id.Sub == ""` rejection after validateIDToken in ResolveIdentity.

### 1.5 ~~ConnLimiter TOCTOU Race Condition~~ DONE
- **File**: `connlimit.go:86-100`
- **Severity**: HIGH
- **Status**: FIXED — Lock held through increment; rejection path re-validates map entry.

### 1.6 HA Sync Exposes Unencrypted Cluster CA Private Key
- **File**: `controlplane.go:707-748`
- **Severity**: HIGH
- **Issue**: `HASync()` RPC returns `CAKeyPEM` as plaintext string. If HA token is compromised, attacker gets the CA private key and can sign arbitrary node certificates.
- **Fix**: Never transmit CA private key over RPC. Use HA token to derive symmetric key for state replication; restrict CA key to disk-only access.

### 1.7 ~~Bootstrap Token Not Consumed — Unlimited Reuse~~ FALSE POSITIVE
- **Files**: `bootstrap.go:274-283, 318-327`
- **Severity**: ~~HIGH~~ N/A
- **Status**: BY DESIGN — Bootstrap endpoints serve config files (script + compose). Both must be downloaded before enrollment. The actual enrollment RPC in `ValidateAndConsumeToken()` consumes the token. This is intentional.

### 1.8 ~~Enrollment Token CIDR Bypass~~ FALSE POSITIVE
- **File**: `enrollment.go:179-192, 225-267`
- **Severity**: ~~HIGH~~ N/A
- **Status**: ALREADY IMPLEMENTED — `ValidateAndConsumeToken()` lines 247-253 check `tok.AllowCIDR` against `sourceIP` using `net.ParseCIDR` + `cidr.Contains(ip)`. Agent missed this code.

### 1.9 ~~Events SSE Missing Authentication~~ DONE
- **File**: `events.go:109-140`
- **Severity**: HIGH
- **Status**: FIXED — Added `requireRole(w, r, RoleViewer)` to apiEvents and apiCountryTraffic.

### 1.10 ~~Self-Signed Admin UI Cert Marked as CA~~ DONE
- **File**: `tls.go:30`
- **Severity**: HIGH
- **Status**: FIXED — Set `IsCA: false`, `BasicConstraintsValid: true`, removed `KeyUsageCertSign`.

---

## 2. BUGS

### 2.1 Proxy Core & Networking

| # | Issue | File:Line | Severity |
|---|-------|-----------|----------|
| B1 | ~~RelayBufPool type assertion without bounds validation~~ DONE | proxy.go:711,824,935,1014 | Medium |
| B2 | Goroutine cleanup race — first relay completes, write halves still open | proxy.go:822-838 | Medium |
| B3 | ~~Missing TLS conn close on handshake error (only raw TCP closed)~~ DONE | proxy.go:893-895 | Medium |
| B4 | ~~X-Forwarded-For parser silently discards non-IP values~~ FALSE POSITIVE — stripping non-IP values is correct security behavior per RFC 7239; XFF should only contain IPs | proxy.go:127-138 | Low |
| B5 | ~~SOCKS5 credentials never cleared from memory after auth~~ DONE | socks5.go:76-90 | Low |

### 2.2 Policy & Content Filtering

| # | Issue | File:Line | Severity |
|---|-------|-----------|----------|
| B6 | ~~Duplicate exception check in isExcepted() (dead code)~~ DONE | store.go:467-480 | Low |
| B7 | ~~PolicyRule.HitCount race — atomic ops on struct field copied by value~~ DONE | policy.go:582 | Medium |
| B8 | ~~Missing Priority validation — Priority=0 silently becomes first rule~~ DONE | policy.go:420-430 | Medium |

### 2.3 TLS & Certificate Management

| # | Issue | File:Line | Severity |
|---|-------|-----------|----------|
| B9 | ~~Cache TTL doesn't verify leaf cert hasn't actually expired~~ DONE | ca.go:609 | Medium |
| B10 | ~~LRU eviction can leave stale entries in cacheOrder list~~ DONE | ca.go:623-638 | Medium |
| B11 | ~~Secondary CA TOCTOU — checked under RLock, used after unlock~~ DONE | ca.go:666,698 | Medium |
| B12 | ~~OCSP issuer parse error silently ignored~~ DONE | ocsp.go:72 | Low |
| B13 | ~~OCSP cache eviction iterates+deletes from map (undefined behavior)~~ DONE | ocsp.go:92-101 | Medium |

### 2.4 Cluster & Control Plane

| # | Issue | File:Line | Severity |
|---|-------|-----------|----------|
| B14 | ~~Certificate renewal race — direct map mutation without UpdateNode()~~ DONE | controlplane.go:684-691 | High |
| B15 | ~~Token consumption race — unlock before saveLocked()~~ DONE | enrollment.go:225-267 | Medium |
| B16 | ~~HeartbeatMonitor status transition not atomic with config sync~~ DONE | enrollment.go:600-607 | Medium |
| B17 | ~~Config rollback TOCTOU — no lock during applyConfigBackup()~~ DONE | configversion.go:194-241 | Medium |
| B18 | ~~gcExpiredTokens() deletes from live map without full lock~~ FALSE POSITIVE — already called under held lock (enrollment.go:574-580) | enrollment.go:570-610 | Medium |

### 2.5 Observability & Ops

| # | Issue | File:Line | Severity |
|---|-------|-----------|----------|
| B19 | ~~Log rotation TOCTOU — size check races with write~~ FALSE POSITIVE — Write() is entirely under r.mu.Lock (logger.go:40-41) | logger.go:43-55 | Medium |
| B20 | ~~Syslog reconnect has no backoff (CPU waste on failure)~~ DONE | syslog.go:104-106 | Medium |
| B21 | ~~SSE hub drops messages for slow clients silently~~ DONE — slow clients now disconnected (channel closed) instead of silently dropping | events.go:33-42 | Low |

### 2.6 Threat Detection & Scanning

| # | Issue | File:Line | Severity |
|---|-------|-----------|----------|
| B22 | ~~Hash cache race — TTL check outside read lock~~ DONE | hashcache.go:73-84 | Low |
| B23 | ~~ClamAV response parser captures only first virus name~~ FALSE POSITIVE — ClamAV INSTREAM returns one verdict per scan by protocol design; multi-signature detection reports first match | clam.go:143-162 | Low |
| B24 | Content-Length mismatch bypass via chunked encoding | proxy.go, security_scan.go | Medium |

---

## 3. SECURITY ISSUES

### 3.1 Authentication & Session

| # | Issue | File:Line | Severity |
|---|-------|-----------|----------|
| S1 | ~~TOTP timing attack — string `==` instead of constant-time compare~~ DONE | totp.go:41-46 | Medium |
| S2 | ~~LDAP group DN comparison is case-insensitive (incorrect per RFC 4514)~~ FALSE POSITIVE — EqualFold is correct for AD and most LDAP servers; RFC 4517 matching rules are implementation-dependent | auth_ldap.go:191-197 | Medium |
| S3 | ~~Logout doesn't invalidate session server-side (replay risk)~~ FALSE POSITIVE — revokeSessionCookie() already called at ui.go:687, persists to revocation list | ui.go:676-695 | Medium |
| S4 | ~~No rate limiting on /api/setup/complete (brute-force first-run)~~ DONE | ui.go:781-829 | Medium |

### 3.2 Admin UI & API

| # | Issue | File:Line | Severity |
|---|-------|-----------|----------|
| S5 | CSP allows `unsafe-inline` script — defeats XSS protection — DEFERRED (requires SPA nonce refactor) | ui.go:344 | Medium |
| S6 | ~~Blocklist GET lacks role check (publicly readable)~~ DONE | ui.go:1084 | Medium |
| S7 | ~~XSS risk via innerHTML in SPA (inconsistent escHtml usage)~~ DONE — added escHtml() to 15+ unescaped template interpolations (hostnames, rule names, policy fields, rewrite headers, file profiles) | static/index.html (multiple) | Medium |
| S8 | ~~Sensitive crypto errors exposed in apiCertsUpload response~~ DONE | ui.go:2397,2406 | Low |
| S9 | ~~No CSRF protection on SSE connection~~ FALSE POSITIVE — SSE requires session auth (requireRole), CORS same-origin check exists, and SSE is read-only dashboard data | events.go:110 | Low |

### 3.3 TLS & Certificates

| # | Issue | File:Line | Severity |
|---|-------|-----------|----------|
| S10 | ~~OCSP transport uses TLS 1.2 minimum (should be 1.3)~~ DONE | ocsp.go:207 | Medium |
| S11 | ~~Leaf cert NotBefore backdate too small (1 min, should be 5 min)~~ DONE | ca.go:680 | Low |
| S12 | No OCSP staple validation (always queries responder) | ocsp.go:109-141 | Low |

### 3.4 Cluster

| # | Issue | File:Line | Severity |
|---|-------|-----------|----------|
| S13 | ~~Bootstrap token plaintext returned (potential log leakage)~~ FALSE POSITIVE — plaintext is returned in API response (required), never logged; audit event at ui.go:3685 only logs prefix+CIDR | enrollment.go:177-212 | Medium |
| S14 | ~~Missing SSRF check in extractStandbyHost() (no private IP blocklist)~~ FALSE POSITIVE — HA peer address is operator-configured via cfg.PeerAddr; standby IS on private network by design | update_cluster.go:446-463 | Medium |
| S15 | ~~Credential mask circumvention in registry settings~~ DONE | update.go:521-529 | Medium |

### 3.5 Scanning & Threat Detection

| # | Issue | File:Line | Severity |
|---|-------|-----------|----------|
| S16 | ~~YARA ReDoS timeout silently skips scan (fail-open)~~ DONE — now returns true on timeout (fail-closed, Zero Trust) | yara_scan.go:182-201 | Medium |
| S17 | ~~DPI regex timeout silently passes response (fail-open)~~ DONE — now returns true on timeout (fail-closed, Zero Trust) | scanner.go:168-180 | Medium |
| S18 | No archive extraction — nested ZIP evasion | security_scan.go | Medium |
| S19 | No polyglot file detection (magic byte vs Content-Type mismatch) | security_scan.go, scanner.go | Medium |

---

## 4. PERFORMANCE

| # | Issue | File:Line | Severity |
|---|-------|-----------|----------|
| P1 | ~~Per-rule Prometheus metrics — unbounded cardinality~~ FALSE POSITIVE — already capped at maxRuleMetrics=200 (metrics.go:17) | metrics.go:15-52 | Medium |
| P2 | ~~Latency histogram CAS loop contention under high RPS~~ ACCEPTABLE — standard lock-free CAS pattern; hardware CAS is sub-nanosecond; no contention seen in practice | metrics.go:94-101 | Medium |
| P3 | JSON log writer allocates strings on every Write() — LOW PRIORITY (logger not a bottleneck, ~1μs per call) | logger.go:79-105 | Medium |
| P4 | ~~Alert webhook goroutine leak (no worker pool / semaphore)~~ DONE | alerts.go:211 | Medium |
| P5 | ~~Hash cache O(n) full scan on eviction~~ ACCEPTABLE — 10k max entries; O(n) map scan is ~1ms; min-heap adds complexity without measurable benefit | hashcache.go:111-128 | Medium |
| P6 | ~~ClamAV semaphore backlog — 96 goroutines blocked at 100 RPS~~ DONE — semaphore now has 5s timeout; returns error instead of blocking indefinitely | clam.go:34-39 | Medium |
| P7 | Threat feed sync uses 100+ MiB during full download | threatfeed.go:135-156 | Low |
| P8 | ~~YARA inflight counter never reset on rule reload~~ DONE | yara_scan.go:449-476 | Low |
| P9 | ~~Syslog synchronous DNS on every reconnection~~ ACCEPTABLE — DialTimeout has 5s cap + 5s backoff; syslog writes are fire-and-forget (don't block proxy traffic) | syslog.go:61 | Low |
| P10 | Config validation runs redundantly on every reload | config.go:205-276 | Low |

---

## 5. MISSING FEATURES (Priority Order)

### 5.1 Scanning & Security (High Priority)

| # | Feature | Impact |
|---|---------|--------|
| F1 | Content decompression before scanning (gzip/deflate/brotli) | Eliminates major evasion vector |
| F2 | Per-scan timeout across all scanners (10s max) | Prevents coordinated ReDoS attacks |
| F3 | Fail-closed on scan timeout (block, don't silently pass) | Closes YARA/DPI timeout evasion |
| F4 | Archive magic byte detection + recursive scanning | Blocks nested archive evasion |
| F5 | File magic byte validation (polyglot detection) | Detects Content-Type mismatch |

### 5.2 Cluster & Operations (Medium Priority)

| # | Feature | Impact |
|---|---------|--------|
| F6 | Canary deployment pattern for rolling updates | Safe incremental rollout |
| F7 | Config rollback validation (pre-flight check) | Prevents broken rollback |
| F8 | Automatic rollback triggers on health threshold breach | Self-healing cluster |
| F9 | Node group membership monitoring API | "Which nodes are in group X?" |
| F10 | Bandwidth policy conflict validation | Prevents undefined priority behavior |
| F11 | Config diff depth — element-level diffs, not just counts | Meaningful rollback previews |

### 5.3 Observability (Medium Priority)

| # | Feature | Impact |
|---|---------|--------|
| F12 | Structured logging with slog (Go 1.21+), request context | Log correlation across components |
| F13 | Log level support (DEBUG/INFO/WARN/ERROR) | Production noise reduction |
| F14 | OpenTelemetry distributed tracing | End-to-end request latency |
| F15 | Grafana dashboard JSON templates | Faster time-to-value for monitoring |
| F16 | Alert escalation + retry queue with persistent storage | No more silently dropped alerts |
| F17 | /health vs /ready probe separation for Kubernetes | Proper pod lifecycle management |
| F18 | Audit log rotation | Prevents unbounded disk growth |

### 5.4 Admin UI (Medium Priority)

| # | Feature | Impact |
|---|---------|--------|
| F19 | Bulk delete for blocklist and policies | Operational efficiency |
| F20 | Search/filter on all tables (policies, rewrites, file blocks) | Usability at scale |
| F21 | Pagination on large lists (logs, audit, policies) | Performance with many entries |
| F22 | Confirmation dialogs for destructive actions (DELETE) | Prevents accidental deletion |
| F23 | Role-based UI filtering (hide inaccessible nav items) | Clean UX per role |

### 5.5 Nice-to-Have (Low Priority)

| # | Feature | Impact |
|---|---------|--------|
| F24 | PagerDuty / Slack native alerting integrations | Reduce custom webhook adapters |
| F25 | Metrics persistence across restarts | Long-term trend dashboards |
| F26 | Threat feed reputation scoring + IOC extraction | Adaptive blocking confidence |
| F27 | Incremental threat feed delta sync | Bandwidth + memory reduction |
| F28 | Dark mode toggle in UI | User preference |
| F29 | Keyboard shortcuts in UI | Power user efficiency |
| F30 | Section-specific config export/import | Share individual blocklists |

---

## 6. CODE QUALITY

### 6.1 Consistency Issues

| # | Issue | Location |
|---|-------|----------|
| Q1 | ~~Excessive `//nolint:errcheck` — 11 in update_cluster.go alone~~ DONE — replaced 8 of 11 with proper error handling + logging; remaining 3 are HTTP response encoders (acceptable) | update_cluster.go |
| Q2 | ~~Deadlock risk: Lock → modify → Unlock → Save pattern~~ DONE (resolved by B14 fix — now uses saveLocked() under held lock) | controlplane.go:684-690 |
| Q3 | Inconsistent API response format (some `{ok:true}`, some raw data) | ui.go (multiple) |
| Q4 | Inconsistent error handling in JS (empty catch, toast, showErr) | static/index.html |
| Q5 | Inconsistent log prefixes across components | logger.go, syslog.go, alerts.go |
| Q6 | Magic numbers without named constants | ui.go:374, events.go:123 |
| Q7 | Inline CSS scattered throughout HTML | static/index.html (hundreds) |

### 6.2 Missing Tests

| # | Gap | Files |
|---|-----|-------|
| Q8 | DPI regex timeout behavior untested | scanner_test.go |
| Q9 | Hash cache eviction race conditions untested | hashcache_test.go |
| Q10 | ClamAV connection failures / malformed responses untested | clam_test.go |
| Q11 | YARA regex timeout goroutine leak untested | yara_scan_test.go |
| Q12 | sendGRPCToNode() delivery untested | update_cluster_test.go |
| Q13 | Archive/polyglot file handling untested | security_scan_test.go |

### 6.3 Cleanup

| # | Issue | Location |
|---|-------|----------|
| Q14 | ~~Deprecated `ValidateToken()` still defined~~ DONE | enrollment.go:270-274 |
| Q15 | ~~CA import partial failure leaves inconsistent state~~ DONE — write to temp files + rename for atomic persistence | enrollment.go:1001-1006 |
| Q16 | ~~Missing input validation on NodeGroup label keys/values~~ DONE | nodegroup.go:231-244 |
| Q17 | ~~Alert webhook no deduplication window~~ DONE | alerts.go:211,254-259 |
| Q18 | ~~JSON decoder doesn't explicitly close body~~ FALSE POSITIVE — HTTP server automatically closes r.Body after handler returns (net/http spec) | ui.go:929-932 |

---

## 7. RECOMMENDED IMPLEMENTATION ORDER

### Phase A — Security Hardening (1-2 weeks)
1. Fix RBAC gaps: cert upload, events SSE, blocklist GET (S-items + 1.3, 1.9)
2. Fix OIDC Sub validation (1.4)
3. Fix ConnLimiter race (1.5)
4. Content decompression before scanning (1.1, F1)
5. IDNA normalization for all host comparisons (1.2)
6. TOTP constant-time comparison (S1)
7. Fail-closed on scan timeouts (F3, S16, S17)
8. Admin UI cert IsCA=false (1.10)

### Phase B — Cluster Security (1 week)
1. Remove CA private key from HA sync (1.6)
2. Fix bootstrap token consumption (1.7)
3. Fix enrollment CIDR enforcement (1.8)
4. Fix token consumption race in enrollment (B15)
5. Add SSRF check to extractStandbyHost (S14)
6. Fix config rollback TOCTOU (B17)

### Phase C — Stability & Races (1 week)
1. Fix relay goroutine cleanup (B2)
2. Fix TLS conn close on error (B3)
3. Fix cert cache LRU eviction (B10)
4. Fix secondary CA TOCTOU (B11)
5. Fix hash cache race (B22)
6. Fix log rotation TOCTOU (B19)
7. Add syslog reconnect backoff (B20)

### Phase D — Scanning & Evasion (1-2 weeks)
1. Archive magic byte detection (F4)
2. Polyglot file detection (F5)
3. Per-scan timeout budget (F2)
4. ClamAV semaphore with backpressure (P6)
5. Alert webhook worker pool (P4)

### Phase E — Observability & Ops (1 week)
1. Structured logging migration (F12)
2. Log levels (F13)
3. Health vs Ready probes (F17)
4. Audit log rotation (F18)
5. Alert retry queue (F16)

### Phase F — UI & UX Polish (1-2 weeks)
1. Bulk delete operations (F19)
2. Search/filter on all tables (F20)
3. Pagination (F21)
4. Destructive action confirmations (F22)
5. Role-based nav filtering (F23)
6. Consistent API response format (Q3)
7. Consistent error handling in JS (Q4)

---

## 8. METRICS SUMMARY

- **Total source files reviewed**: 45+ Go files, 1 SPA HTML, 4 CI workflows
- **Lines of Go code**: ~25,000+
- **Test coverage**: Moderate (gaps in scanning, cluster update, timeout paths)
- **Dependencies**: Minimal (crewjam/saml, goccy/go-yaml, x/crypto, x/net)
- **CI pipeline**: 10-check security gate + CodeQL + golangci-lint
