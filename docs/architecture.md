# Culvert Architecture

Culvert is a single-process Secure Web Gateway. Client traffic flows through a
staged request pipeline; a control plane distributes configuration to stateless
data-plane nodes. This document describes both.

> A rendered, interactive version of these diagrams is published as a Culvert
> Artifact and linked from the project README.

---

## 1. Request pipeline

Every proxied request is evaluated through an ordered pipeline. Any stage can
short-circuit the request; only traffic that survives every gate reaches the
upstream.

```
                        ┌─────────────────────────────┐
      client  ─────────▶│  Connection & rate limits    │  per-IP conn cap, X-Request-ID
                        │  connlimit.go                │  60 req/min mutating (admin)
                        └──────────────┬───────────────┘
                                       ▼
                        ┌─────────────────────────────┐
                        │  IP filter                   │  allow / block CIDR lists
                        │  security.go                 │
                        └──────────────┬───────────────┘
                                       ▼
                        ┌─────────────────────────────┐
                        │  Plugin middleware chain     │  runs first; may short-circuit
                        │  plugin.go                   │
                        └──────────────┬───────────────┘
                                       ▼
                        ┌─────────────────────────────┐
        Stage 1 ───────▶│  Authentication / identity   │  local · OIDC(PKCE) · SAML · LDAP
                        │  auth_*.go, identity.go      │  multi-IdP email-domain routing
                        └──────────────┬───────────────┘
                                       ▼
                        ┌─────────────────────────────┐
        Stage 2 ───────▶│  Policy evaluation           │  8 conditions, first-match by
                        │  policy.go                   │  priority, DEFAULT-DENY
                        └──────────────┬───────────────┘
                                       ▼
                        ┌─────────────────────────────┐
                        │  Action                      │  Allow · Drop · Block Page · Redirect
                        └──────────────┬───────────────┘
                                       ▼ (Allow + CONNECT)
                        ┌─────────────────────────────┐
                        │  TLS action                  │  Inspect (MITM, ECDSA P-256 leaf)
                        │  ca.go, proxy_tunnel.go      │  or Bypass (transparent tunnel)
                        └──────────────┬───────────────┘
                                       ▼ (Inspect only)
                        ┌─────────────────────────────┐
                        │  Content scanning            │  DPI regex · ClamAV · YARA ·
                        │  scanner.go, clam.go, yara   │  file-type · threat-feed
                        └──────────────┬───────────────┘
                                       ▼
                        ┌─────────────────────────────┐
                        │  Header scrubbing            │  strip private XFF, drop
                        │  proxy.go                    │  X-User-Identity
                        └──────────────┬───────────────┘
                                       ▼
                        ┌─────────────────────────────┐
                        │  Upstream selection + dial   │  direct or upstream pool
                        │  upstream.go  +  SSRF guard  │  round-robin + circuit breaker;
                        │  security.go / internal/ssrf │  isPrivateHost re-check at connect
                        └──────────────┬───────────────┘
                                       ▼
                                    upstream
                                       │
        Telemetry (all outcomes) ◀─────┘  request log · metrics · SSE feed · audit
```

**Default-deny nuance:** deny is enforced once any rule exists or
`default_action: deny` is set. A fresh install with zero rules starts in
passthrough so operators cannot lock themselves out.

---

## 2. TLS inspection

When a rule's TLS action is `Inspect`, Culvert terminates the client TLS
session with an on-the-fly leaf certificate signed by its internal CA:

- **Leaf certs:** ECDSA P-256, minted per SNI, cached in a bounded cache
  (10,000 entries, 1h TTL).
- **CA key at rest:** AES-256-GCM with PBKDF2-SHA256 (600,000 iterations);
  passphrase from `CULVERT_CA_PASSPHRASE`.
- **Bypass:** rules can carry `Bypass` to tunnel sensitive destinations
  (banking, health) without decryption. Per-host bypass patterns are managed in
  the UI.
- **Post-quantum:** the TLS key exchange auto-negotiates hybrid
  X25519 + ML-KEM-768 via the Go 1.25 standard library.

---

## 3. Control Plane / Data Plane

```
                    ┌──────────────────────────────────┐
                    │          CONTROL PLANE            │
                    │  • config snapshot authority      │
                    │  • node enrollment                │
                    │  • admin UI + dashboard           │
                    │  • no proxy traffic               │
                    └───────┬───────────────┬───────────┘
                            │  gRPC / mTLS  │   (config snapshot + heartbeat every 30s)
              ┌─────────────┘               └─────────────┐
              ▼                                            ▼
   ┌────────────────────┐                      ┌────────────────────┐
   │   DATA PLANE #1     │                      │   DATA PLANE #N     │
   │  stateless          │        ...           │  stateless          │
   │  full config on     │                      │  full config on     │
   │  connect            │                      │  connect            │
   │  proxy traffic ✔    │                      │  proxy traffic ✔    │
   └────────────────────┘                      └────────────────────┘
```

- **DP nodes are stateless.** On connect they receive the entire config
  snapshot - policy rules, blocklist, PAC exclusions, threat-feed data, session
  HMAC key, bandwidth policies, node groups. Replace a node and it re-enrolls in
  seconds.
- **Config snapshot** is a single walled surface (capture/apply/redaction/
  wire-wipe parity is enforced by tests) so sensitive fields (session key, IdP
  secrets) are never leaked to a non-enrolled caller.
- **HA fencing (optional):** an etcd fencing lease provides fail-closed leader
  election with epoch-based fencing (`-ha-etcd-*`). Without it, the legacy
  leader/standby model applies.
- **Node groups & QoS:** label selectors (with auto GeoIP labels) drive
  per-group token-bucket bandwidth policies, enforced per-DP so limits scale
  linearly with node count.

---

## 4. Defense-in-depth layers

| Layer | Control |
|---|---|
| Ingress | Per-IP connection cap, admin-API rate limit (60/min mutating), IP allow/block |
| Identity | Local bcrypt, OIDC (PKCE), SAML 2.0, LDAP/AD, multi-IdP routing, TOTP 2FA, RBAC |
| Egress safety | SSRF guard with connect-time re-resolution (anti DNS-rebinding), open-redirect guard |
| Content | ClamAV, YARA, DPI regex, file-type profiles, domain blocklist, threat feeds, CDR |
| Session | HMAC-SHA256 cookies, 128-bit jti, disk-persisted revocation synced across cluster |
| Data at rest | AES-256-GCM + PBKDF2 (600k) for CA key and secrets |
| Transport | Upstream OCSP (fail-closed on unreachable responder), hop-by-hop stripping (RFC 7230) |
| Admin plane | Metadata-driven RBAC enforcement + per-handler `requireRole`; governance surface |
| Supply chain | Signed release catalog (Ed25519 + Sigstore keyless), digest-pinned dispatch, SLSA L3 |

See [`../CLAUDE.md`](../CLAUDE.md) for the authoritative package inventory and
the admin-API invariants, and [Limitations](../README.md#limitations--known-gaps)
for known gaps (notably: OCSP only, no CRL).
