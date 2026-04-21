# CULVERT — Full Spectrum Production Audit (FSPA)

**Auditor role:** Lead Architect & Head of AppSec
**Audit date:** 2026-04-21
**Scope:** `KidCarmi/Culvert` @ branch `claude/culvert-production-audit-0t817` (HEAD `ddf80c7`)
**Corpus:** ~64,000 LOC Go, single-binary forward proxy with admin UI, control plane, scanning, updater sidecar.
**Method:** README-as-contract adversarial review. Evidence is cited by `file:line`. Every finding validated against the Validation + Simulation engines defined in the brief.

---

## 1. Executive Summary

| | |
|---|---|
| **Overall risk** | **CRITICAL** |
| **Production verdict** | **NO-GO** |
| **Contract status** | README-declared Zero-Trust / mTLS / default-deny contract is **breached** in multiple places |

### Top 5 blockers (must fix before any production deployment)

1. **Cluster Control-Plane lets unauthenticated callers read the session-signing HMAC and full config** — a single unauthenticated `GetConfig` RPC returns `session_hmac` in plaintext, letting the attacker forge arbitrary admin sessions cluster-wide. (See C1.)
2. **Enrollment RPC is unconditionally cleartext** — `callEnrollRPC` uses `insecure.NewCredentials()` with no TLS; enrollment token, CSR and CA are all recoverable by any on-path attacker. (See C2.)
3. **Node-identity check is silently skipped when the peer presents no client cert** — combined with `ClientAuth = VerifyClientCertIfGiven` this means any caller can pass `verifyNode` for any claimed `node_id`, reaching `PushMetrics`, `SyncRateLimits`, `SyncRevocations`, `PushAuditEvents`, `RenewCert`, and `TriggerUpdate` (which has no identity check at all). (See C3.)
4. **"Zero Trust / default deny" contract is violated at bootstrap** — a fresh install with no policy rules is set to `default_action = allow` (open proxy) and the admin UI grants `RoleAdmin` to any caller until `/api/setup/complete` is invoked; install.sh + compose bind all interfaces. (See C4.)
5. **Policy engine trusts client-supplied `X-User-Identity` in unauth / passthrough mode** — the header is only scrubbed on *egress*, not on *ingress*; when `authRequired == false` the attacker's value flows into `policyStore.Evaluate(...)` for identity-based rule matching. (See C5.)

Other high-impact issues (HA token timing-safe compare, CA-passphrase persisted 0644 next to cipher-text, updater state writable under 0644, revocation lazy eviction unbounded memory, `/data/updater_token.txt` shipped mode 0644 by design, open-redirect via OIDC relay URL, RBAC fallback silently upgrading empty-role sessions to Admin) are documented in §HIGH / §MEDIUM.

A rough but honest overall judgement: the code is ambitious and the README is impressive, but the cluster trust boundary is wide open. Single-node deployment behind a real auth layer is *arguably* viable after C4/C5/M-Role are fixed. Multi-node / HA deployment as shipped today would be negligent.

---

## 2. Architecture Snapshot

### Core components (verified)
| Component | File(s) | Purpose |
|---|---|---|
| HTTP/CONNECT/WS proxy | `proxy.go` | ingress + MITM inspect |
| SOCKS5 | `socks5.go` | alt ingress |
| Admin UI + API | `ui.go` (5 308 LOC), `admin_settings.go`, `events.go` | RBAC, policy CRUD, dashboards |
| AuthN | `auth.go`, `auth_ldap.go`, `auth_oidc*.go`, `auth_saml.go`, `auth_idp.go`, `identity.go`, `session.go` | local bcrypt, OIDC PKCE, SAML, LDAP |
| Policy / PBAC | `policy.go`, `categorygroup.go`, `rewrite.go`, `fileblock.go`, `fileprofile.go` | rule evaluation |
| MITM / CA | `ca.go`, `tls.go` | on-the-fly leaf signing, AES-GCM + PBKDF2 bundle |
| Cluster CP/DP | `controlplane.go`, `enrollment.go`, `ha.go`, `update_cluster.go`, `main.go:1487` | gRPC, mTLS (claimed), state push |
| Self-update | `update.go`, `updater/main.go` (1 937 LOC) | Docker socket sidecar |
| Scanning | `clam.go`, `yara_scan.go`, `scanner.go`, `security_scan.go`, `cdr*.go`, `scan_remote.go` | AV + YARA + CDR/Sluice |
| Observability | `metrics.go`, `otlp*.go`, `logger.go`, `syslog.go`, `events.go` | Prom, OTLP, SIEM, SSE |
| Session plumbing | `session.go` + HMAC secret distributed in `ConfigSnapshot.SessionHMAC` | cluster-wide session validity |

### Integration model (observed)
```
Browser / client
       │
       ├── :8080  handleRequest (proxy.go)  ──► policy ──► upstream
       │                                     ▲
       │                                     │   (SessionHMAC)
       ├── :9090  uiAuthMiddleware → securityMiddleware (CORS/CSP/CSRF origin)
       │          ├── /api/auth/login  (bcrypt + TOTP + lockout)
       │          ├── /auth/oidc|saml/callback → setSessionCookie (ps_session)
       │          └── /api/**  → handlers (requireRole)
       │
       ├── :7123  updater sidecar (Docker socket, Bearer token shared via /data/updater_token.txt)
       │
       └── :<grpc>  ControlPlane gRPC (VerifyClientCertIfGiven)
                   GetConfig (no auth) / Enroll / PushMetrics / HASync / TriggerUpdate
```

### Trust boundaries (as *implemented*)
1. **Client ↔ proxy ingress**: auth gate can be disabled via `unauth_mode`. When disabled, **X-User-Identity injection is possible**.
2. **UI ↔ admin API**: session cookie (HMAC-SHA256, HttpOnly, SameSite=Strict, Origin-based CSRF). Falls back to `RoleAdmin` if `AuthEnabled()==false`.
3. **Proxy ↔ CP gRPC**: **mTLS is optional** (`VerifyClientCertIfGiven`); several RPCs skip identity checks silently when no cert is presented.
4. **CP ↔ updater sidecar**: Bearer token from shared volume (mode 0644). Tokens exchanged locally inside docker network.
5. **CP ↔ DP enrollment**: performed over **unencrypted gRPC**, secured only by TOFU fingerprint (which itself must be delivered securely out-of-band).
6. **Proxy ↔ upstream**: standard TLS with optional per-rule `tlsSkipVerify`.

### Attack surface (ranked)
| Surface | Exposure | Severity |
|---|---|---|
| CP gRPC listener (`:50051`-style, any port configured) | Wide open given `VerifyClientCertIfGiven` + missing identity checks | **CRITICAL** |
| Admin UI during bootstrap window | `RoleAdmin` without credentials | **CRITICAL** |
| Proxy data path in `unauth_mode` | X-User-Identity injection | **CRITICAL** |
| Enrollment handshake | Cleartext | **CRITICAL** |
| Updater sidecar | Docker socket, token in 0644 file | **HIGH** |
| MITM leaf-cert cache | LRU, 10 000 entries, 1 h TTL — memory-safe but cert reuse across rotations must be checked | MEDIUM |
| SSE / audit stream | Gated behind `RoleViewer` | LOW |

---

## 3. CRITICAL Findings

### C1 — Cluster session HMAC leaks to *any* unauthenticated gRPC caller

**Severity:** CRITICAL
**Location:** `controlplane.go:491` (`GetConfig`), `controlplane.go:107` + `controlplane.go:1521-1524` (snapshot build), `session.go:44-55` (sync path), `controlplane.go:1425-1434` (DP apply).
**Evidence:**
```go
// controlplane.go:491
func (s *controlPlaneServer) GetConfig(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
    // GetConfig is called during initial poll before enrollment completes.
    // No node identity check required — config is not secret ...
    snap := globalConfigStore.Get()
    ...
    b, err := json.Marshal(snap)
    ...
}

// controlplane.go:1521-1524 — built into the snapshot every time
if len(sessionSecret) > 0 {
    snap.SessionHMAC = hex.EncodeToString(sessionSecret)
}

// controlplane.go:107
SessionHMAC string `json:"session_hmac,omitempty"`
```
The comment *"config is not secret"* is wrong. The returned JSON contains:
- `session_hmac` — **the admin session signing key** used by `session.go:297` (`encodeSession`) and `session.go:309` (`decodeSession`).
- Threat-feed allowlists, policy rules, rate-limit settings, bandwidth policies, etc.

**Attacker path:**
1. Attacker reaches the CP gRPC listener (typically on internal cluster network, but exposed the moment CP is reachable — and it must be for DPs to connect).
2. Attacker opens a gRPC channel with no client cert (`VerifyClientCertIfGiven` + `GetConfig` has no identity check at all).
3. Receives `session_hmac`, decodes hex, sets it as the local HMAC key.
4. Mints a cookie payload `{sub:"admin", role:"admin", exp:<now+24h>}`, signs it with the stolen secret, sends it as `ps_ui_session`.
5. `decodeSession` accepts. `uiAuthMiddleware` grants `RoleAdmin`. Full cluster takeover.

**Impact:** Total compromise of every admin UI in the cluster; policy rewrite, TLS inspection redirect, updater trigger. The README's "Zero Trust" claim collapses here.

**Remediation (priority order):**
1. **Delete `SessionHMAC` from `ConfigSnapshot`** and distribute it only via a dedicated mTLS-gated RPC that requires `verifyNode`.
2. Gate `GetConfig` behind `verifyNode`; nodes must enroll before they can fetch config. Bootstrapping can use the existing `Enroll` RPC.
3. Rotate the session secret immediately on any upgrade that includes this fix; invalidate all existing sessions.

---

### C2 — Enrollment RPC is unconditionally plaintext

**Severity:** CRITICAL
**Location:** `main.go:1487` (`callEnrollRPC`).
**Evidence:**
```go
// main.go:1487
func callEnrollRPC(cpAddr, token, nodeID string, csrPEM []byte) (*EnrollResponse, error) {
    conn, err := grpc.NewClient(cpAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
    ...
    reqBytes, _ := json.Marshal(EnrollRequest{Token: token, CSR: string(csrPEM), NodeID: nodeID})
```
There is **no TLS code path** in `callEnrollRPC` — the CA fingerprint is only checked *after* the cleartext RPC returns (`verifyCAFingerprint` at `main.go:1509`), i.e., as a sanity check on the CA cert received in plaintext.

**Attacker path:**
- Passive: on-path attacker reads the one-time `token` in flight, then races the legitimate node to enroll (the token is single-use but attacker wins the race by sitting on the wire).
- Active: MITM can swap the CA cert. Fingerprint check would catch this *only if* the admin fetched `ca-fp=sha256:...` over a separate, authenticated channel — nothing in the code enforces that. An attacker who forges a convincing `culvert://enroll/...` URL with their own fingerprint bypasses the check entirely.

**Impact:** Any "mTLS cluster" claim is false for first contact. Every enrollment is a bootstrapping event that's susceptible to interception. Combined with C1/C3, an attacker who owns the enrollment channel owns the cluster.

**Remediation:**
1. Require TLS for `callEnrollRPC`. Use `credentials.NewTLS(&tls.Config{ InsecureSkipVerify: true, VerifyPeerCertificate: fingerprintVerifier })` — verify the fingerprint **during the handshake**, before any bytes are sent.
2. Block `--cluster-insecure` from affecting enrollment. The flag's own help text says *"NEVER use in production"* (`main.go:104`), yet enrollment is hard-coded insecure regardless.
3. Gate enrollment with a second factor (admin-printed HMAC over `{nodeID, pubkey}`) so a leaked token alone is insufficient.

---

### C3 — `verifyNode` silently passes when no client cert is presented, and `TriggerUpdate` skips it entirely

**Severity:** CRITICAL
**Location:** `controlplane.go:450-489` (`verifyNode`, `verifyNodeCert`), `controlplane.go:1626` (`ClientAuth = tls.VerifyClientCertIfGiven`), `update_cluster.go:235` (`TriggerUpdate`).
**Evidence:**
```go
// controlplane.go:469
func verifyNodeCert(ctx context.Context, claimedNodeID string) error {
    p, ok := peer.FromContext(ctx)
    if !ok || p.AuthInfo == nil {
        return nil // insecure dev mode — skip cert pinning
    }
    tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
    if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
        return nil  // <— same silent-pass when TLS is on but client omitted cert
    }
    ...
}

// controlplane.go:461-465
node, exists := globalClusterStore.GetNode(claimedNodeID)
if exists && globalClusterStore.IsRevoked(node.CertSerial) {
    return status.Errorf(codes.PermissionDenied, "node %q is revoked", claimedNodeID)
}
return nil   // <— non-existent node ID: also returns nil
```
Three independent silent-pass paths. Combined with:
```go
// controlplane.go:1626
tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven   // <— accepts clients with NO cert
```
This means any gRPC caller can reach authenticated endpoints as any claimed `node_id`.

And `TriggerUpdate` (`update_cluster.go:235`) does not call `verifyNode` at all — a DP executing this handler will fire `/api/update/apply` on the updater the instant an attacker invokes `TriggerUpdate` over gRPC.

**Attacker path:**
1. Open gRPC channel to CP (or to a DP that serves CP-style handlers).
2. Claim `node_id: "any-enrolled-node"`.
3. Call `PushMetrics`, `SyncRateLimits`, `SyncRevocations`, `PushAuditEvents`, `RenewCert` — all succeed, allowing cache poisoning, forged audit entries, and (via `RenewCert`) obtaining a freshly-signed cluster cert for the impersonated identity provided the CSR's `CommonName` matches.
4. Call `TriggerUpdate{TargetTag:"whatever"}` to force Docker image pull on a DP node.

**Operator failure:** An operator who forgets `--cluster-insecure=false` or ships without a CA file lands in the "skip pinning" branch with no warning beyond the startup log line.

**Impact:** Complete breach of the CP↔DP trust boundary. Audit logs can be poisoned, rate-limit counters subverted, rogue node certs obtained, rolling update orchestrator hijacked.

**Remediation:**
1. Change `ClientAuth = tls.RequireAndVerifyClientCert` — `VerifyClientCertIfGiven` was only needed for the *unenrolled* `Enroll` RPC. Host `Enroll` on a **separate** port or expose it via an unauthenticated service endpoint on the same port, not via the same mTLS socket.
2. In `verifyNodeCert`, replace every "return nil when no cert" branch with `return status.Errorf(codes.Unauthenticated, "client cert required")`.
3. Call `verifyNode` in `TriggerUpdate` (and audit-trace any other handlers added since this audit).
4. Allow `--cluster-insecure` only under an explicit `CULVERT_INSECURE=dev` env flag, and refuse to start if the flag is set in a container image built with a non-`dev` VERSION.

---

### C4 — "Zero Trust / default deny" is violated on every fresh install

**Severity:** CRITICAL
**Location:** `main.go:711-720`, `proxy.go:419-430`, `ui.go:552-557`, `docker-compose.yml` (command line has no `--default-action deny`), `install.sh:95-105` (no IP allowlist default).
**Evidence:**
```go
// main.go:711-720
defaultAction := firstStr(fc.DefaultAction)
if defaultAction == "" {
    if len(policyStore.List()) == 0 {
        defaultAction = "allow"       // <—— fresh install, 0 rules
        logger.Printf("Policy: no rules configured; defaulting to Allow (passthrough)...")
    } else {
        defaultAction = "deny"
    }
}
```
```go
// proxy.go:419-430 — when no rule matches
if defaultPolicyAction() == "allow" {
    recordRequest(..., "OK", "default-allow", "Allow", ...)   // passthrough
}
```
```go
// ui.go:552-557 — admin UI before first-time setup
if !cfg.AuthEnabled() {
    ctx := context.WithValue(r.Context(), uiRoleKey{}, RoleAdmin)
    next.ServeHTTP(w, r.WithContext(ctx))
    return
}
```
And `docker-compose.yml:80-81` exposes `9090:9090` to every interface — the setup-wizard page is reachable by anyone who can route to that port.

**Attacker path:**
- Operator runs `docker compose up -d`. For the minutes-to-days window before someone navigates to `https://host:9090/` to "set up", the admin UI grants `RoleAdmin` to any caller. An attacker who scans the network during this window can POST to `/api/auth/users`, `/api/policy/*`, or `/api/setup/complete {"unauth": true}` to permanently lock the system into open-proxy mode.
- Even after setup, the *proxy* defaults to `allow` until a policy rule is written.

**Impact:** README claims *"Default deny: Policy engine defaults to deny when no rule matches (Zero Trust)"* (CLAUDE.md). Code contradicts that claim. This is the **flagship security guarantee** of the project.

**Remediation:**
1. Default `defaultAction` to `deny` unconditionally. Provide a first-boot bundled starter rule allowing an admin-configured bootstrap CIDR, or keep the proxy *bound but returning 403* until policy is set.
2. During the no-auth bootstrap window, bind the UI to loopback only, print a one-time `setup_token` to stdout, and require it in `/api/setup/complete`. The current rate-limiter (`ui.go:941`) is not a substitute for access control.
3. Separate the "setup is incomplete" state from "auth is disabled" — `ui.go:552` currently conflates the two.

---

### C5 — `X-User-Identity` header injection when auth is not required

**Severity:** CRITICAL (HIGH for customers who always run auth-enabled; CRITICAL because `unauth_mode` is a supported, one-click setup option)
**Location:** `proxy.go:139-166` (`scrubForwardedHeaders` — only called at egress), `proxy.go:294-296` (ingress set), `proxy.go:361` (policy consumer), `proxy.go:605` (only scrub point).
**Evidence:**
```go
// proxy.go:294
if authenticatedIdentity != "" {
    r.Header.Set("X-User-Identity", authenticatedIdentity)
}
// ... no Header.Del("X-User-Identity") when authenticatedIdentity is empty ...

// proxy.go:361
identity := r.Header.Get("X-User-Identity")
match := policyStore.Evaluate(clientIP, identity, authenticatedSource, host, authenticatedGroups)
```
`scrubForwardedHeaders` (the only place that deletes the header) runs at `proxy.go:605`, which is **after** `policyStore.Evaluate`. In the `authRequired == false` branch (`unauth_mode` on, or no IdP + no local user configured), nothing writes or deletes the header, so the client-supplied value flows through.

**Attacker path:**
1. Operator runs Culvert with `unauth_mode: true` (a supported mode advertised in README as "Open/Policy-Only").
2. Attacker sends `GET http://internal-host/ HTTP/1.1` with `X-User-Identity: ceo@corp`.
3. Any rule matching on identity (`identity:ceo@corp` → allow `dangerous.site`) evaluates as if the CEO made the call.

**Impact:** Silent policy bypass. Identity-based rules — the main reason most sites deploy a forward proxy at all — are trivially forgeable. Violates README's claim that identity-based PBAC rules are meaningful in `unauth_mode`.

**Remediation:**
1. Move `scrubForwardedHeaders(r)` (or at minimum `r.Header.Del("X-User-Identity")`) to the **top of `handleRequest`**, before any policy evaluation.
2. After that, set the internal header only when the proxy itself authenticated the identity.
3. Audit for any other *internal-only* headers that may be consumed before egress scrubbing (e.g., `X-Request-ID` is attacker-set but only used for tracing, lower risk).

---

## 4. HIGH Findings

### H1 — Empty-role UI session silently upgraded to `RoleAdmin`

**Severity:** HIGH
**Location:** `ui.go:572-575`.
**Evidence:**
```go
// ui.go:572
role := UIRole(sess.Role)
if !role.HasRole(RoleViewer) {
    role = RoleAdmin // backwards compat: sessions without role = admin
}
```
`HasRole` looks up `rolePriority[r]`; for any string not in the map (`""`, `"guest"`, `"attacker"`), priority is `0` < `RoleViewer`'s `1`, so the condition is true and the code falls back to `RoleAdmin`.

**Attacker path:** Any HMAC-signed session whose payload omits (or mis-cases) `role` becomes admin. This is exactly the shape of cookies produced by `setSessionCookie` (session.go:357 — never sets `Role`), so anyone who convinces the UI to read a `ps_session`-style cookie under the name `ps_ui_session` (e.g., by obtaining the HMAC via C1 and minting one) lands as admin regardless of what role they declared.

**Impact:** Defence-in-depth against C1 is neutralised — even if an attacker only steals the secret and forges the *minimum viable* cookie payload, they're admin. Also trivially caught by a reviewer: "backwards compat" cannot justify role elevation.

**Remediation:** Strip the fallback. Require `role` ∈ {admin, operator, viewer}; reject anything else with 401 and force re-login.

---

### H2 — Audit trail reads the wrong cookie — admin identity lost

**Severity:** HIGH
**Location:** `ui.go:1008` (`auditEventDiff`), `ui.go:509` (`sessionAdmin`).
**Evidence:**
```go
// ui.go:1008  (admin-side audit enrichment)
if sess, err := readSessionCookie(r); err == nil && sess != nil {
    name := sess.Sub
    ...
    actor = name + "@" + actor
}

// ui.go:509  (used by saveConfigVersion)
func sessionAdmin(r *http.Request) string {
    sess, err := readSessionCookie(r)
    ...
}
```
`readSessionCookie` reads **`ps_session`** — the *proxy user* cookie. The admin UI issues **`ps_ui_session`** via `setUISessionCookie` (ui.go:604). These are different cookies set by different flows with different content. So every config change made from the admin UI is audited as just the IP address, with *no administrator identity* at all.

Every config-mutating handler that uses `sessionAdmin` (pac.go:215, configversion.go:253, ha.go:421, cdr_ui.go:127/205/334/515/537/634) is affected.

**Attacker path:** An attacker with a stolen admin UI session exfiltrates or rewrites policy; the audit log shows "10.0.0.25" with zero admin context, making forensics useless.

**Impact:** Breaks the "full audit trail" property the README claims; violates SOC2 / ISO 27001 §A.12.4.1 accountability.

**Remediation:** Replace `readSessionCookie(r)` inside audit paths with a helper that tries `readUISessionCookie(r)` **first**, falls back to `readSessionCookie(r)` for API clients. Add a regression test that walks through `apiAuthLogin → apiPolicyAdd → latest audit entry` and asserts the admin username is recorded.

---

### H3 — `callEnrollRPC` tier-skips server auth; TOFU pin is post-hoc

**Severity:** HIGH (already covered in part by C2; the **separate** issue here is that **even if** TLS is enabled, the server cert is not pinned during the handshake)
**Location:** `main.go:1487-1524`.
**Evidence:** `grpc.WithTransportCredentials(insecure.NewCredentials())` — no TLS path exists. The fingerprint verifier (`verifyCAFingerprint`) runs only on the returned `CAPEM`; the CP's *own gRPC TLS cert* is never pinned because there is no TLS. Even if upgraded to TLS, the current shape of the code would only verify CA PEM content, not the handshake.

**Remediation:** Build the TLS config with a `VerifyPeerCertificate` closure that performs the pin inside the handshake, before the request is sent.

---

### H4 — ClamAV error path is fail-open

**Severity:** HIGH
**Location:** `security_scan.go:497-506`.
**Evidence:**
```go
if clam != nil {
    name, found, err := clam.Scan(data)
    if err != nil {
        logErrorf("SecurityScan: ClamAV error: %s", ...)   // <-- logs, then falls through
    } else if found {
        ... return Blocked ...
    }
}
// ... YARA runs, then cache "clean" ...
```
No `return` on the error branch — the file is treated as *not yet determined malicious*, YARA runs, and on YARA miss the result is cached as **clean**. The sibling timeout branch (line 484) is explicitly fail-closed ("ScanBody timeout ... blocking (fail-closed)"), so the asymmetry is not intentional hardening — it's a bug.

**Attacker path:** Take ClamAV offline (resource exhaustion, OOM during freshclam refresh, container crash during healthcheck debounce). Downloads bypass AV until ClamAV recovers. Combined with the 1-hour `hashcache` TTL, a single malicious file hash can poison the "clean" cache for 60 min.

**Impact:** Silent AV bypass. "ClamAV + YARA" is advertised as a dual-engine defence; the dual is reduced to single-engine under normal ClamAV failure modes.

**Remediation:** Return a `Blocked: true, Source: "clamav_error"` result (or gate behind a `clamav_fail_mode` admin setting: `open | closed | warn`). Do **not** cache the result on error — the next request may see a healthy ClamAV.

---

### H5 — Upstream HTTP transport and CONNECT dialers bypass the SSRF-safe dialer (DNS rebinding TOCTOU)

**Severity:** HIGH
**Location:** `proxy.go:913-923` (`upstreamTransport` has no `DialContext`), `proxy.go:940` (bypass dial), `proxy.go:1011` (inspect dial), `proxy.go:795` (WS dial).
**Evidence:** `upstreamTransport` uses the default dialer. `handleTunnelBypass`, `handleTunnelInspect`, and `handleWebSocket` call `(&net.Dialer{Timeout: 10 * time.Second}).DialContext(...)`. All four paths perform `isPrivateHost(host)` *before* dialling, but re-resolve DNS at dial time.
`ssrfDNSCache` has a 30-second TTL; an attacker-controlled DNS record can TTL-flip between the guard's resolution and the dialer's resolution. `ssrfSafeDialContext` exists (security.go:49) and is used for *outbound* helpers (OIDC, alerts, threat feeds) — but **not** for proxied user traffic.

**Attacker path:** Attacker points `evil.example.com` at `1.1.1.1` with TTL=1s. Proxy resolves, passes SSRF guard. By dial time the record resolves to `169.254.169.254` (cloud metadata) or `127.0.0.1` (admin UI). The proxy opens a tunnel / plain HTTP request to the internal target on the attacker's behalf.

**Impact:** SSRF to cloud metadata, internal services, and the admin UI (which itself is reachable on localhost). Given the admin UI is gated by RBAC, exploit depth depends on other findings (C1, C4) — in combination this is a full breach chain.

**Remediation:** Set `upstreamTransport.DialContext = ssrfSafeDialContext`; replace every `(&net.Dialer{Timeout}).DialContext(r.Context(), ...)` with `ssrfSafeDialContext`. Remove the negative-result caching or shrink TTL to <2 s.

---

### H6 — Per-rule `tlsSkipVerify` produces a silent MITM-through-MITM

**Severity:** HIGH (intent-vs-reality gap)
**Location:** `proxy.go:1027-1033`.
**Evidence:**
```go
if tlsSkipVerify {
    logWarnf("SSLInspect: skipping upstream cert verify for %q (tlsSkipVerify rule)", ...)
    upstreamTLSCfg = &tls.Config{
        ServerName:         hostOnly,
        MinVersion:         tls.VersionTLS12,
        InsecureSkipVerify: true,   // <-- full MITM window open
    }
}
```
When an admin toggles `tlsSkipVerify` for a rule (e.g., to reach an internal self-signed host), the proxy silently connects to *any* cert for *any* host matching that rule. Because this is the path where the proxy *itself* MITMs the client (SSL inspect), the client still sees a valid cert from the proxy CA — so the client has **no signal** that the upstream leg is now unauthenticated. The proxy becomes a confused deputy laundering a downgrade attack.

**Impact:** A TLS downgrade on the upstream leg is invisible to the protected user. README markets MITM inspection as a security control; this flag turns it into a security liability.

**Remediation:** Require the admin to pin a host-specific CA or SPKI hash instead of offering a blanket skip-verify toggle. If keeping the toggle, refuse to apply it to hosts resolvable to public IPs; emit a block-page warning to end-users on every affected request.

---

### H7 — Admin UI bound to all interfaces; no network allowlist in the shipped compose file

**Severity:** HIGH
**Location:** `docker-compose.yml:80-81`, `install.sh:20-26`.
**Evidence:**
```yaml
ports:
  - "8080:8080"
  - "9090:9090"   # Admin Web UI
```
And install.sh has no `--ui-allow-ip` / binding constraint. Combined with **C4** (pre-setup RBAC grants `RoleAdmin`), a default `docker compose up` on an exposed host hands over the keys.

**Attacker path:** IPv4 scan for port 9090, reach `/api/setup/complete` with `{"user":"pwn","pass":"Pwn1234"}`, authenticate with that user, own the proxy.

**Remediation:** Bind `9090:9090` → `127.0.0.1:9090:9090` in `docker-compose.yml` and document how to front it with Nginx / Traefik mTLS. Same for `updater` (already bound to `127.0.0.1` — good). Add a hard `ip_allowlist` default to the example config file.

---

### H8 — `/data/updater_token.txt` created world-readable, on a shared volume

**Severity:** HIGH
**Location:** `update.go:127-128`.
**Evidence:**
```go
// #nosec G306 -- 0644 required: updater sidecar runs with cap_drop:ALL (no DAC_OVERRIDE), so root cannot read 0600 files owned by the proxy user
if err := os.WriteFile(path, []byte(token+"\n"), 0o644); err != nil {
```
The justification — that 0644 is *"required"* because the updater runs with `cap_drop:ALL` — is only valid inside a container-with-uid-mapping setup. When the same file is reused on bare-metal (install.sh writes `/var/lib/culvert/...`), any local user can read it. Bearer tokens for the updater API granting **Docker socket operations** are equivalent to host root.

**Attacker path:** Low-priv local account on the host reads `/var/lib/culvert/updater_token.txt`, POSTs to `http://127.0.0.1:7123/api/update/apply` with an attacker-chosen tag (limited by registry pin, but still a supply-chain vector / DoS vector via `handleSelfUpdate`).

**Remediation:**
1. Write the file at `0o640`, owned by `proxy:docker` group in containerized deployments; in install.sh, create a dedicated `culvert` user and `0600` the file.
2. Cut the shared volume: have the proxy POST the token to the updater over localhost once, never touching disk.

---

### H9 — Rolling-update `TriggerUpdate` RPC is unauthenticated

**Severity:** HIGH (called out in C3; re-flagging the specific impact of the missing `verifyNode` in TriggerUpdate)
**Location:** `update_cluster.go:235-267`.
**Evidence:** Unlike `PushMetrics` et al., `TriggerUpdate` does not call `verifyNode`. Once a gRPC client reaches the listener, it can spawn `POST /api/update/apply` on the local updater — pulling any tag in the registry and recreating the container.
**Remediation:** Add `if err := verifyNode(ctx, req.Initiator); err != nil { return err }` immediately after request unmarshalling; reject `Initiator == ""`.

---

## 5. MEDIUM Findings

### M1 — CSRF defence relies on Origin-present heuristic

**Severity:** MEDIUM
**Location:** `ui.go:444-448`, `ui.go:477-478`.
**Evidence:**
```go
// ui.go:477
if origin == "" {
    return true // no Origin = direct tool access — not a browser cross-site request
}
// ui.go:444
if origin != "" && !isSameOrigin(r, origin) && isMutating {
    http.Error(w, "Forbidden", http.StatusForbidden)
    return
}
```
Modern browsers always send `Origin` on cross-site fetch/XHR/form POSTs, but edge cases (intranet IE-compat paths, Safari CORB quirks for non-CORS form POSTs in older versions, PDF/SVG form-submit attacks) can omit it. The in-code comment acknowledges this is the policy, but it ships without a fallback CSRF token.
**Remediation:** Issue a double-submit CSRF token (signed with `sessionSecret`) and require it on every mutating `/api/*` request. The current infrastructure has everything needed to implement this.

---

### M2 — OIDC relay URL permits arbitrary absolute public HTTPS redirects

**Severity:** MEDIUM
**Location:** `ui.go:3851-3857`, `proxy.go:755-767`.
**Evidence:** `isSafeRedirectURL` only rejects private/loopback hosts and non-http(s) schemes. `authOIDCCallback` accepts any absolute https URL pointing to a public IP as `relayURL`. After a successful OIDC login, the callback 302-redirects the browser to the attacker's origin, which already holds the freshly-issued session cookie (HttpOnly — not readable, but the redirected page still auto-fires authenticated XHRs from JS injected on the attacker domain after a second login hop; phishing-friendly).
**Remediation:** Restrict `isSafeRedirectURL` to same-origin relative paths for OIDC/SAML callbacks; keep the public-host allowance only for *policy-engine* redirect rules where the admin explicitly entered the URL.

---

### M3 — HA `VerifyToken` not timing-safe

**Severity:** MEDIUM
**Location:** `ha.go:77-81`.
**Evidence:** `return h.token != "" && h.token == token` — plain Go string equality compares byte-by-byte with early exit.
**Attacker path:** Over a noisy network the leak is small; inside a cluster on a fast LAN with statistical sampling it's observable. Unlikely to be a solo exploit but compounds C1/C2.
**Remediation:** Use `subtle.ConstantTimeCompare([]byte(h.token), []byte(token)) == 1`.

---

### M4 — HA CA-key PBKDF2 iteration count is 100 000; project standard is 600 000

**Severity:** MEDIUM
**Location:** `controlplane.go:744`, contrast with `ca.go:83` (`pbkdf2Iter = 600_000`).
**Evidence:** HA bundle encryption uses 100 000 rounds; CA bundle encryption uses 600 000. Both protect equivalent (or more) sensitive material — the HA bundle literally carries the CA key.
**Remediation:** Raise to at least 600 000 (or switch to Argon2id via `golang.org/x/crypto/argon2`). Add a magic/version byte to the encrypted blob so old ciphertexts remain decryptable during a rolling fix.

---

### M5 — Revocation list grows unbounded in memory

**Severity:** MEDIUM
**Location:** `session.go:62-71`, `session.go:73-91` (lazy eviction).
**Evidence:** Tokens are only evicted when `IsRevoked()` is called with the same base64 payload. If an attacker rapidly revokes many tokens (or a buggy client spams logout), no one calls `IsRevoked(b64)` for those exact strings → memory grows monotonically until the TTL.
**Remediation:** Sweep on a timer (`time.AfterFunc` or the existing `Cleanup()` pattern in `security.go`). Add a length cap and a Prometheus gauge.

---

### M6 — `unauthMode` can be enabled anonymously via `/api/setup/complete` before any admin exists

**Severity:** MEDIUM
**Location:** `ui.go:959-965`.
**Evidence:** `apiSetupComplete` checks `cfg.AuthEnabled()` first — but `unauth` = true **sets** `cfg.unauthMode = true`, which flips `AuthEnabled()` to true, *permanently closing setup* without ever requiring a password. Combined with H7 (all-interfaces bind), the first scanner to hit the UI can lock out the legit admin by POSTing `{"unauth": true}`.
**Remediation:** Require a one-time token (printed at first boot to container logs and the host terminal) for both `apiSetupComplete` payload variants.

---

### M7 — `GetConfig` response includes `ThreatDomainAllowlist`, feeds, and PAC data to unauthenticated callers

**Severity:** MEDIUM (data exposure; adjacent to C1 but distinct content)
**Location:** `controlplane.go:491`, `controlplane.go:1510-1518`.
**Evidence:** Same RPC, same no-auth path. Leaks a full inventory of internal domain categorisation, PAC exclusions (internal hostnames that bypass the proxy), and the threat-feed allowlist. For red-teamers this is a reconnaissance jackpot.
**Remediation:** Apply `verifyNode`; build a stripped-down `BootstrapSnapshot` for the pre-enrollment window containing only the CA fingerprint and enrollment metadata.

---

### M8 — Upstream TLS `MinVersion = TLS 1.2` while the CP gRPC side uses TLS 1.3

**Severity:** MEDIUM (policy inconsistency + older-suite exposure)
**Location:** `proxy.go:1031`, `proxy.go:1043`.
**Evidence:** SSL-inspect upstream handshake permits TLS 1.2; the cluster control plane requires TLS 1.3 (`controlplane.go:1613`, `controlplane.go:1648`). Upstream sites still need 1.2 support for legacy backends, but the flag has no policy control — admins can't enforce "1.3 only for inspect".
**Remediation:** Expose an admin setting `inspect_min_tls_version`; default to 1.2, log-warn on every use of <1.3.

---

### M9 — Setup rate-limiter keyed by raw `r.RemoteAddr` — trivial to bypass behind NAT

**Severity:** MEDIUM
**Location:** `ui.go:936-943`.
**Evidence:** The lockout key is `"setup:" + clientIP`, where `clientIP` comes straight from `r.RemoteAddr`. Behind a shared NAT (entire office), every user is the same key — lockouts persistently deny everyone on the LAN. Worse, there's no global attempt counter, so a distributed scanner (each from a unique IP) never triggers any lockout at all.
**Remediation:** Track a **global** attempt counter in addition to per-IP; after N global attempts without success, disable the endpoint entirely and require a printed token.

---

### M10 — Password-reset CLI leaks password via `ps`

**Severity:** MEDIUM
**Location:** `main.go:111-147`.
**Evidence:** `--reset-password user:secret` passes the new password on the command line. `/proc/<pid>/cmdline` is world-readable in most Linux default configs.
**Remediation:** Accept only `--reset-password-stdin`, read once from stdin, clear the slice.

---

### M11 — Default AES-GCM nonce reuse risk in HA encryption on small token space

**Severity:** MEDIUM
**Location:** `controlplane.go:753-754`.
**Evidence:** Random 12-byte nonce per invocation; safe *so long as* `rand.Read` is healthy. The code ignores `rand.Read` error handling in several places around it (e.g., fallback to zero-bytes on error — `enrollment.go` patterns). Low-probability but high-impact if it ever fires.
**Remediation:** Propagate the `rand.Read` error (already done here, good); apply the same pattern to every other `rand.Read` in the tree.

---

### M12 — OIDC `validateIDToken` accepts only RSA but the JWKS parser is RSA-only too — no ES256

**Severity:** MEDIUM (spec/capability gap; README claims ES256 support)
**Location:** `auth_oidc_flow.go:514-516`, JWKS loader reads only `n`/`e`.
**Evidence:** Comment in the file header says *"RS256/ES256 only"*; implementation rejects anything not `*jwtv5.SigningMethodRSA`. Deployments using Azure AD B2C (ES256) or Google Cloud IAP (ES256) will fail.
**Remediation:** Add `*jwtv5.SigningMethodECDSA` to the accepted list and extend `jwkKeyRaw` to parse `crv`/`x`/`y`.

---

### M13 — `installer.sh` runs the daemon as `User=root` under systemd

**Severity:** MEDIUM
**Location:** `install.sh:134`.
**Evidence:** `User=root`. The README says the Docker image runs as `proxy:proxy`; the bare-metal path contradicts that.
**Remediation:** Create a `culvert` user, run under it with `AmbientCapabilities=CAP_NET_BIND_SERVICE`, make `$DATA_DIR` owned by that user.

---

### M14 — `install.sh` uses the `curl|bash` install pattern

**Severity:** MEDIUM
**Location:** `install.sh:3`.
**Evidence:** Supported usage documented as `curl -sSL <url>/install.sh | bash`. Fine until the hosting CDN is compromised (or the TLS cert is pinned to a reseller). Supply-chain risk: no signature verification, no reproducible checksum.
**Remediation:** Publish signed release assets; the script should verify a minisign/cosign signature of the binary before running.

---

### M15 — `updater/main.go` rollback file written 0644

**Severity:** MEDIUM
**Location:** `updater/main.go:141`, `updater/main.go:222`.
**Evidence:** `os.WriteFile(tmp, data, 0644)` — rollback metadata on a writable volume. Not secret *per se* but contains image digests / container names that aid reconnaissance.
**Remediation:** 0640; owned by a dedicated `culvert-updater` group.

---

## 6. LOW Findings

### L1 — Overlong single-file source units with explicit `nolint:gocognit,funlen,cyclop`

`ui.go` is 5 308 LOC, `controlplane.go` 1 674, `updater/main.go` 1 937. `handleTunnelInspect` (`proxy.go:998`) carries five-directive `nolint` suppressions admitting gocognit 112. Not a security bug but materially increases the probability of future regressions in the MITM path. *Remediation:* split `ui.go` by resource (policy, auth, CA, CDR) — the existing `admin_settings.go` and `events.go` show the pattern.

### L2 — Overly permissive CSP for static assets

`ui.go:422-423` allows `script-src 'self' 'nonce-...' https://cdn.jsdelivr.net` and `style-src 'self' 'unsafe-inline'`. Any future compromise of `cdn.jsdelivr.net` or its namespace trust becomes a foothold. *Remediation:* pin a subresource-integrity hash for each third-party asset and tighten `style-src` to `'self' 'nonce-<n>'`.

### L3 — `logger.Printf` accepting raw `%v` on error objects

`update.go:327` logs `sanitizeLog(err.Error())`, but several other files pass `err` directly through `%v` where an attacker can inject newlines (e.g., LDAP error messages). CWE-117. Spot-check: `auth_ldap.go`, `auth_saml.go`. *Remediation:* lint for `logger.Printf(.*%v.*, err)` and wrap every offender with `sanitizeLog(err.Error())`.

### L4 — `scan_remote.go` lacks retry backoff boundaries

The remote scanner retries up to a fixed 3 times with fixed back-off; combined with 30 s per attempt this lets an attacker hold a goroutine for 90 s. *Remediation:* cap total time to `scanBodyTimeout`.

### L5 — Prometheus metrics are unauthenticated on `/metrics`

Metrics are behind `RoleViewer` via `requireRole(w, r, RoleViewer)` (events.go:115) — good — but a public health / ready endpoint is adjacent. Ensure `/metrics` is not exposed on the proxy listener (only on UI). *Remediation:* audit the mux registrations once per release.

### L6 — Password complexity rule permits `Aa1aaaaa`

`store.go:1197-1215` requires ≥8 chars with upper+lower+digit. No deny-list of top-N leaked passwords. *Remediation:* integrate a truncated SHA-1 HIBP blocklist (or zxcvbn) at setup/user-create time.

### L7 — `dockerfile.updater` and sidecar image have no scanned SBOM in the repo

The SECURITY_RELEASE_PROCEDURE.md references a 10-check gate; only the proxy image flows through it. The updater sidecar is a separate image pulled by tag (`ghcr.io/kidcarmi/culvert-updater:latest`). *Remediation:* extend SBOM generation and Trivy scans to the updater image.

### L8 — TLS config `CipherSuites` not explicitly set

TLS 1.3 has a fixed list — fine. But TLS 1.2 handshakes (inspect upstream, LDAP) fall back to Go defaults, which still include some CBC-mode suites. *Remediation:* set `CipherSuites` to the AEAD-only modern list.

### L9 — Several `defer resp.Body.Close()` after error checks

Common Go pitfall — if `resp == nil`, deferring `resp.Body.Close()` panics. Not an attack but flakes tests. `update.go:330` pattern is correct; search the repo for places that defer before checking err.

### L10 — Lockout lease uses `setupKey = "setup:"+ip` without normalisation

IPv6-mapped IPv4 (`::ffff:1.2.3.4`) and bare `1.2.3.4` produce different keys. Minor bypass. *Remediation:* canonicalise with `net.ParseIP(...).String()` before composing the key.

---

## 7. Quick Wins (<1 day each)

| # | Task | Files | Impact |
|---|---|---|---|
| Q1 | Remove `SessionHMAC` from `ConfigSnapshot`; distribute via dedicated `SyncSessionSecret` RPC gated by `verifyNode` | `controlplane.go:107,1521-1524,1425-1434` | Closes C1 |
| Q2 | Strip the empty-role → `RoleAdmin` fallback | `ui.go:572-575` | Closes H1 |
| Q3 | Move `scrubForwardedHeaders` / `r.Header.Del("X-User-Identity")` to top of `handleRequest` | `proxy.go:168` | Closes C5 |
| Q4 | Use `readUISessionCookie` inside `auditEventDiff` and `sessionAdmin` | `ui.go:509,1008` | Closes H2 |
| Q5 | Replace `insecure.NewCredentials()` in `callEnrollRPC` with TLS + in-handshake fingerprint pin | `main.go:1487` | Mitigates C2/H3 |
| Q6 | Call `verifyNode` inside `TriggerUpdate`; bail if empty `Initiator` | `update_cluster.go:235` | Closes H9 |
| Q7 | Default `defaultAction = "deny"` regardless of rule count | `main.go:711-720` | Closes half of C4 |
| Q8 | Switch `upstreamTransport.DialContext = ssrfSafeDialContext` + replace 3 raw dialers | `proxy.go:913,940,1011,795` | Closes H5 |
| Q9 | `ClientAuth = tls.RequireAndVerifyClientCert` on CP listener; move `Enroll` to a separate listener | `controlplane.go:1626,867` | Closes C3 |
| Q10 | Use `hmac.Equal` / `subtle.ConstantTimeCompare` for HA token verify | `ha.go:77-81` | Closes M3 |

---

## 8. Strategic Remediation Plan

### Phase A — "Stop the bleeding" (1 week, blocks prod)
1. Land Q1–Q10 as a single security-release.
2. Cut a CVE for C1 (session-HMAC disclosure) with forced rotation guidance; document that every deployed cluster must rotate `session_secret` AND re-enrol every DP after upgrade.
3. Gate the release with a new `cluster-hardening.yml` CI job that fails if:
   - `ClientAuth != tls.RequireAndVerifyClientCert` on CP listener,
   - any RPC handler lacks `verifyNode`,
   - `ConfigSnapshot` contains any field whose name matches `/secret|hmac|password|key/i`.

### Phase B — "Rebuild trust boundary" (2–4 weeks)
4. Split the gRPC surface: `BootstrapService` (public, unauth, returns only CA fingerprint + enrollment metadata) and `ControlService` (mTLS, authenticated). Move `GetConfig`, `PushMetrics`, `SyncRateLimits`, `SyncRevocations`, `PushAuditEvents`, `RenewCert`, `HASync`, `TriggerUpdate` to the latter.
5. Replace the Bearer-token-file updater auth with a localhost-only Unix domain socket. No shared volume.
6. Replace the `tlsSkipVerify` per-rule toggle with a per-rule **SPKI pin** field; update the UI to show a warning glyph on any rule using it.
7. Promote the bootstrap token pattern: print `setup_token=<32 hex>` on first boot; require it in the body of `/api/setup/complete` and `/api/auth/login` for the first session.

### Phase C — "Correctness hardening" (4–8 weeks)
8. Restructure the session layer: one cookie name, one payload with a mandatory `aud` claim (`"proxy"` vs `"ui"`). Reject audience mismatch in `decodeSession`. This eliminates C1/H1-style replay between surfaces entirely.
9. Add double-submit CSRF tokens on every mutating endpoint (M1).
10. Add a chaos-style test harness that kills ClamAV, freezes DNS, trips the HA standby, and asserts the proxy fails **closed** every time (H4, H5, M5).
11. Extend `SECURITY_RELEASE_PROCEDURE.md` with a mandatory adversarial review before any change to: `session.go`, `ca.go`, `controlplane.go`, `enrollment.go`, `update*.go`.

### Phase D — "Process" (ongoing)
12. Stand up a security-focused code review rota — the single-author pattern visible in `git log --pretty=%an | sort -u | wc -l` (near-1) is the root cause of most findings above.
13. Publish signed release artifacts (cosign + SLSA level 3 provenance — the CI already emits it per CLAUDE.md; just complete the publishing step).
14. Add explicit fault-injection tests into CI for every "fail-closed" claim in the README.

---

## 9. Verdict

Culvert is a *capable* forward proxy with an unusually broad feature set. However, the FSPA discovered:

- **5 CRITICAL** findings, any one of which independently supports a `NO-GO` verdict,
- **9 HIGH** findings that multiply the blast radius of the CRITICALs,
- **15 MEDIUM** and **10 LOW** findings that indicate the codebase has outgrown the current quality-gate model.

The distance between the README ("Zero Trust", "mTLS", "default deny", "full audit trail") and the executable is too large to bridge with documentation. The fixes are all tractable; the code author(s) understand the domain. But until Phase A + Phase B ship, **do not run this in production**, particularly not in any cluster / HA configuration.

*End of audit.*




