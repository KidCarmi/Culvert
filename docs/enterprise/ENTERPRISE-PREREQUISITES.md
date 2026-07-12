# Culvert Enterprise Prerequisites

Everything the customer must prepare *before* installation. Each row is marked:

- **Verified** — observed in code/tests/compose.
- **Inferred** — reasonable engineering conclusion, not directly asserted by code.
- **Configurable** — customer-settable (flag/YAML/GUI/API).
- **Hard-coded** — fixed in the binary/image.
- **Undocumented** — real behaviour with no operator doc.
- **Unsupported** — capability does not exist.
- **Unknown** — could not be determined from the repository.

> Sizing figures are the project's own engineering estimates, **not** published benchmarks (README "Limitations"). Validate against your workload.

---

## 1. Compute

| Resource | Requirement | Status |
|---|---|---|
| CPU (full feature, ~500 users) | 2 vCPU | Verified (README/deployment-guide sizing) · Inferred accuracy |
| CPU (proxy only) | 1 vCPU | Verified (docs) |
| Memory (full feature incl. ClamAV) | 1.5 GB (ClamAV keeps ~600 MB signatures resident) | Verified (`scripts/install.sh:210-217` warns <1500 MB) |
| Memory (proxy only) | 128 MB | Verified (docs) |
| Control Plane node | 2 vCPU / 512 MB / 500 MB | Verified (docs) |
| Data Plane node | 2 vCPU / 1 GB / 1 GB (+~1 GB for ClamAV) | Verified (docs) |

## 2. Storage

| Item | Requirement | Status |
|---|---|---|
| Disk (full feature) | 2.5 GB SSD | Verified (docs) |
| Docker engine + images headroom | ~3 GB free in `/var` | Verified (`install.sh:220-228`) |
| ClamAV signature DB | ~250 MB, persisted in `clamav-db` volume | Verified (`docker-compose.yml:6-9`) |
| Persistent data volume | `/data` (Docker named volume `proxy-data`) — flat files, no DB | Verified (`docker-compose.yml:78,229`) |
| Growth drivers | request log (`-request-log-max-mb`, default 100), proxy log (`-log-max-mb`, default 50), audit JSONL (50 MB rotation), saved log store, config versions (50) | Verified (`config.go`, `internal/audit`) |
| Storage growth assumptions | Logs rotate at fixed sizes; audit/config bounded. Threat-feed/GeoIP DBs small. No unbounded growth by design (`topHosts` capped, audit ring 500) | Inferred |

> **Provision durable, writable storage.** The startup writability probe is one-shot; a mount that appears after boot won't flip Diagnostics `storage_path` back to `ok` without a restart (`docs/OPERATIONS.md §4`).

## 3. Network interfaces & addressing

| Item | Requirement | Status |
|---|---|---|
| Interfaces | 1 is sufficient (all listeners bind `0.0.0.0`) | Verified — no bind-interface flag (GAP-NET-04) |
| Management-plane isolation | Achieved via host firewall / VLAN + `-ui-allow-ip`, **not** in-product interface binding | Verified · Configurable (allowlist only) |
| IP addresses | 1 host IP (single node). Cluster: 1 per CP + 1 per DP + LB VIP + optional etcd witness IP | Inferred |
| Subnet / gateway / netmask | **Host-owned** — no Culvert setter | Unsupported in-app (GAP-APP-02) |
| Default gateway | Host-owned | Unsupported in-app |
| `CULVERT_PUBLIC_IP` | Optional env — TLS cert SAN hint only, not an L3 setting | Verified · Configurable (env) |

## 4. DNS

| Item | Requirement | Status |
|---|---|---|
| Name resolution | Host/Docker DNS; Culvert has no resolver config | Verified · Host-owned |
| Internal DNS records | A/PTR for the appliance hostname, LB VIP, CP/DP nodes; IdP endpoint names resolvable | Inferred |
| Catalog/feed hostnames | `catalog.culvertlabs.com` (unless disabled), `urlhaus.abuse.ch`/`openphish.com` (if threat feeds on) must resolve | Verified |

## 5. Time (NTP) & timezone

| Item | Requirement | Status |
|---|---|---|
| NTP | **Host-owned** — Culvert makes no NTP calls | Verified · Unsupported in-app |
| Accurate clock | Required for SAML/OIDC assertion windows, TLS validity, schedule rules | Inferred (important) |
| Timezone | `TZ` env (default UTC); policy schedules carry their own IANA tz per rule | Verified · Configurable (env) |

## 6. PKI & certificates

| Item | Requirement | Status |
|---|---|---|
| Admin UI TLS | Self-signed auto-generated, or supply `-tls-cert`/`-tls-key`; `-ui-no-tls` to disable | Verified · Configurable |
| Inspection root CA | Auto-generated ECDSA P-256 (10 yr), or import your own | Verified |
| **Accepted import formats** | **PEM only** (cert + unencrypted EC private key). No PKCS#12/DER | Verified · Hard-coded (GAP-PKI-04) |
| **Imported CA key algorithm** | **ECDSA only** — RSA rejected | Verified · Hard-coded (GAP-PKI-02) |
| Imported CA persistence | **Not persisted via GUI upload** (lost on restart); durable only via on-disk `-ca-path` bundle | Verified · (GAP-PKI-01) |
| CA key at rest | PBKDF2-SHA256 600k + AES-256-GCM, passphrase `CULVERT_CA_PASSPHRASE` | Verified |
| Cluster mTLS certs (CP/DP) | Customer-generated (openssl) or GUI enrollment (auto-issued from cluster CA) | Verified |
| Upstream-proxy client mTLS | `proxy.client_cert_file`/`client_key_file` or GUI upload | Verified · Configurable |

## 7. Outbound connectivity (egress to plan/approve)

| Destination | Default | Override / disable | Status |
|---|---|---|---|
| `catalog.culvertlabs.com/release-catalog` | On (enforce, boot + ~6h) | `CULVERT_RELEASE_CATALOG_URL=off` | Verified · Configurable (env-only) |
| `urlhaus.abuse.ch`, `openphish.com` | On iff threat feeds/scanner enabled | **None** | Verified · Hard-coded (GAP-NET-02) |
| `raw.githubusercontent.com` (UT1/SaaS categories) | Off by default | `-cat-feed-url` (UT1) | Verified · Configurable/Hard-coded |
| OTLP collector | Off | `-otlp-endpoint` / GUI | Verified · Configurable |
| Syslog/SIEM | Off | `-syslog` / GUI | Verified · Configurable |
| OCSP responders | Off (`ocsp_check` default false); URLs from origin certs | Config | Verified · Configurable |
| Alert webhooks / IdP / upstream proxies | Off (operator-set) | GUI/API | Verified · Configurable |
| Docker/GHCR (install + updates) | Required for install & registry-pull updates | Private registry / offline staging | Verified |
| Sigstore/Rekor/Fulcio | **No runtime egress** (offline verify) | — | Verified |

## 8. Inbound connectivity

| Source → Dest | Port | Required | Status |
|---|---|---|---|
| Proxy clients → appliance | 8080/tcp | Yes | Verified |
| Admins → appliance | 9090/tcp | Yes | Verified |
| SOCKS5 clients → appliance | 1080/tcp | Only if enabled (default off) | Verified |
| Data Plane → Control Plane | 50051/tcp (gRPC/mTLS) | Cluster only | Verified |
| LB health probes → appliance | 8080 (`/health`,`/ready`), 9090 (`/healthz`) | Recommended | Verified |
| HA standby → leader CP | 50051 | HA only | Verified |
| CP ↔ etcd witness | 2379 | HA lease only | Verified |

## 9. Ports & protocols summary

| Port | Proto | Purpose | Auth | Configurable |
|---|---|---|---|---|
| 8080 | HTTP/1.1 + CONNECT | Forward proxy; `/health` `/ready` `/metrics` `/proxy.pac` | Proxy: policy; `/metrics`: optional token; health: none | `-port` |
| 9090 | HTTPS | Admin UI/API; `/healthz`; SSE | Session cookie + RBAC; `/healthz` none | `-ui-port` |
| 1080 | SOCKS5 | Proxy (CONNECT only) | Policy | `-socks5-port` (0=off) |
| 50051 | gRPC | CP↔DP | mTLS | `-cp-grpc-addr` |

## 10. Authentication dependencies

| Dependency | Requirement | Status |
|---|---|---|
| Admin auth | Local bcrypt accounts (+ optional TOTP). **No external IdP for admin** | Verified (GAP-IAM-02) |
| Proxy-user LDAP/AD | `ldaps://` reachable; bind DN + base DN + optional required group | Verified · Configurable |
| Proxy-user OIDC | Discovery/introspection endpoints reachable; client creds; `proxy.base_url` set | Verified · Configurable |
| Proxy-user SAML | Valid IdP metadata; `proxy.base_url` = SP Entity ID; ACS = base_url + `/auth/saml/callback` | Verified · Configurable |
| Session HMAC (cluster) | `CULVERT_SESSION_SECRET` (64 hex) on every node | Verified |

## 11. Update dependencies

| Dependency | Requirement | Status |
|---|---|---|
| Maintenance agent | `culvert-maint` host systemd service (root/privileged) + sudoers allowlist | Verified |
| Registry access | Pull access to the pinned proxy repo (public GHCR or internal mirror) | Verified |
| Trust roots | Baked ed25519 + Sigstore keyless; extend via env (public keys only) | Verified · Configurable (env-only, GAP-UPD-03) |
| Air-gapped updates | No turnkey path (GAP-UPD-01) | Unsupported (turnkey) |

## 12. Backup / logging / monitoring integration

| Item | Requirement | Status |
|---|---|---|
| Backup storage | Off-host destination for encrypted archives (operator-owned; `culvert-backups` volume is local) | Verified · Operator-owned (GAP-BAK-02) |
| Backup passphrase | `CULVERT_BACKUP_PASSPHRASE` for `--encrypt` | Verified |
| Logging | stdout + optional rotating file (`-logfile`); JSON mode | Verified · Configurable (flags-only, GAP-MON-03) |
| Audit persistence | `-audit-log /data/audit.jsonl` (shipped compose sets it) | Verified (GAP-IAM-04) |
| SIEM | Syslog UDP/TCP (RFC 3164/5424); GUI/API configurable | Verified · Configurable |
| Metrics | Prometheus `/metrics` (optional bearer token) | Verified · Configurable |
| Tracing | OTLP/HTTP (optional) | Verified · Configurable |

## 13. Client / browser & PAC requirements

| Item | Requirement | Status |
|---|---|---|
| Proxy config | Explicit proxy `http://<host>:8080` or PAC | Verified |
| PAC URL | `http://<host>:8080/proxy.pac` (also `:9090/proxy.pac`), unauthenticated by design | Verified |
| CA trust (if inspecting) | Culvert Root CA in every client OS/browser trust store (GPO/MDM/`update-ca-trust`) | Verified |
| SOCKS5 | CONNECT only; UDP ASSOCIATE rejected | Verified |

## 14. Organisational prerequisites

| Item | Requirement | Status |
|---|---|---|
| Required customer roles | Docker/Linux host admin (install + backup/restore + break-glass), network admin (firewall/DNS/NTP/LB), PKI admin (CA/trust distribution), IdP admin (LDAP/OIDC/SAML) | Inferred |
| Change-window | Restore commit and agent-driven upgrades want a maintenance window (restore is offline; upgrade recreates the container) | Verified |
| Test/prod separation | Recommended; promotion via config export/import (`/api/config/export|import`) | Verified · Configurable |
| Host access for day-2 | Required for backup/restore (GAP-BAK-01), admin recovery (GAP-IAM-01), agent install, trust-root changes, manual rollback | Verified |

> **Net prerequisite the customer must accept up front:** even in a "GUI-only" operating model, Culvert today requires **retained host/container-shell access** for backup/restore, administrator break-glass, maintenance-agent provisioning, update trust-root changes, and deliberate rollback. Plan this into the operating model or the deployment will stall at day-2.
