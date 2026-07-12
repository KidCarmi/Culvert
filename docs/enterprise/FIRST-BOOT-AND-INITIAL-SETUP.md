# First Boot & Initial Setup

What actually happens the first time Culvert starts, and exactly which initial-setup items an administrator can configure through a supported customer interface (GUI/API) versus the host OS, an environment variable, a file edit, or not at all.

---

## 1. First-boot sequence (Docker Compose model)

1. `docker compose up -d` starts the ClamAV sidecar and the `proxy` container. The proxy waits for ClamAV's health check (transient unavailability is tolerated).
2. The proxy reads its flags/YAML/env, runs the 24 startup slices, and probes `/data` writability **once**.
3. With no `-ca-path` CA present and `CULVERT_CA_PASSPHRASE` set, it generates the ECDSA P-256 root CA and writes the encrypted `ca.bundle`. Back this up immediately.
4. It binds 8080 (proxy) and 9090 (admin UI, self-signed HTTPS). `/health` returns 200; `/ready` returns 503 until `session_secret` and `config_snapshot_validator` pass (they pass once the session HMAC is initialised).
5. With **no admin account and no policy rules**, the proxy starts in **passthrough** (allow) so you cannot lock yourself out. `GET /api/setup/status` returns `{"needsSetup": true}`.

**Evidence:** `main.go` startup, `healthcheck.go`, `ui_auth.go:371-472`, `docker-compose.yml`.

---

## 2. Creating the first administrator

Open `https://<host>:9090`, accept the self-signed certificate, and complete the **setup wizard**. It POSTs to `POST /api/setup/complete`, which is public and one-time: it validates password complexity, bcrypt-hashes the credential, writes `/data/ui_users.json` (mode 0600), and logs you in. There is **no default password** and no hardcoded credential.

> **⚠ Security — trust-on-first-use (GAP-APP-04).** The wizard authenticates *nobody* before creating the admin — whoever reaches :9090 first claims it. There is no console-printed setup token or serial binding. **Firewall port 9090 to a trusted admin workstation until setup is complete.**

**First actions after setup (do all four):**
1. Create a **second admin account** (Auth → Users). With only one admin, a lost password is recoverable only via host CLI (GAP-IAM-01).
2. Enable **TOTP** for admin accounts.
3. Verify audit persistence — the shipped compose passes `-audit-log /data/audit.jsonl`; without it, admin history is a 500-entry in-memory ring lost on restart (GAP-IAM-04).
4. Open **Infrastructure → Diagnostics** and resolve `fail` rows.

---

## 3. Initial-setup configurability matrix

Legend: **GUI/API** = supported customer interface · **Host/OS** = configure the underlying host · **Env** = environment variable / `.env` · **File** = edit a file on disk · **Unsupported** = no mechanism.

| Setup item | Mechanism | Evidence | Status |
|---|---|---|---|
| Admin credentials | **GUI/API** — setup wizard, then `/api/auth/users` | `ui_auth.go:381-472,187-258` | Verified |
| Recovery / additional admins | **GUI/API** — `/api/auth/users`; TOTP; **but no dedicated break-glass** | `ui_auth.go`; `internal/totp` | Partially implemented (GAP-IAM-01) |
| Admin roles (admin/operator/viewer) | **GUI/API** — `/api/auth/users` (admin-only) | `ui_rbac.go`, `ui_routes_meta.go` | Verified |
| Certificate trust (inspection CA mgmt) | **GUI/API** — `/api/ca/status`, `/api/ca-cert`, `/api/ca/rotate`, `/api/certs/upload` | `ui_security.go`, `ui_policy.go:1353` | Verified (import caveats: GAP-PKI-01/02/03) |
| CA passphrase | **Env** — `CULVERT_CA_PASSPHRASE` | `docker-compose.yml:96` | Verified · Env |
| UI TLS cert / SANs / base URL / trusted proxies | **GUI/API** — `POST /api/settings/network`; or `-tls-cert`/`-tls-key` flags | `ui_config.go:1206-1275` | Verified |
| Proxy settings (port/socks/upstream) | Ports = flags/YAML; upstream = **GUI/API** (`/api/upstream`) | `config.go`, `docs/deployment-guide.md` | Verified · Configurable |
| Update source (catalog URL/trust) | **Env** only — `CULVERT_RELEASE_CATALOG_*` | `release_wiring.go:42-78` | Verified · Env (GAP-UPD-03) |
| Telemetry preference (OTLP) | **GUI/API** — `/api/otlp` (enable/disable/endpoint) | `ui_config.go:1480-1536` | Verified |
| Syslog/SIEM | **GUI/API** — `/api/syslog` (+ test) | `ui_config.go:1015-1070` | Verified |
| Metrics token | **GUI/API** (runtime) or `-metrics-token` | `metrics.go`, `static/index.html:7469` | Verified (open by default, GAP-MON-03) |
| Backup destination / schedule | **Host/CLI** only — `docker compose --profile cli` + operator cron | `docker-compose.yml:214`, `roadmap/D1.3a` | Unsupported via GUI (GAP-BAK-01/02) |
| Authentication provider (proxy users) | **GUI/API** — IdP profiles (OIDC/SAML/LDAP) | `auth_idp.go`, `ui_*` | Verified |
| Support access | **Host** — retained container-exec for break-glass/backup; no in-product support-access toggle | — | Unsupported in-app |
| **Management IP / subnet / gateway** | **Host/OS** | negative search | Unsupported in-app (GAP-APP-02) |
| **DNS servers** | **Host/OS** | negative search | Unsupported in-app |
| **Hostname** | **Host/OS** (only read for cert SANs) | `internal/uitls` | Unsupported in-app |
| **NTP / time sync** | **Host/OS** (Culvert makes no NTP calls) | negative search | Unsupported in-app |
| **Timezone** | **Env** — `TZ` (no GUI) | `docker-compose.yml:88` | Configurable · Env |

---

## 4. Blockers exposed at first boot

- **GAP-APP-02** — L3/DNS/hostname/NTP/timezone are not customer-configurable in-product. A no-SSH customer cannot bring the box onto the network through Culvert; do it via host provisioning during the build phase.
- **GAP-APP-04** — setup wizard is trust-on-first-use; firewall :9090 until claimed.
- **GAP-IAM-01/04** — no in-band admin recovery and audit-off-by-default risk; mitigate with a second admin + confirmed `-audit-log`.
- **GAP-UPD-03** — update source/trust is env-only; set it before exposing the box if running restricted.

---

## 5. Data initialisation & persistence

`/data` is a set of flat JSON/text files created lazily on first write — **no database, no migration engine**. Key files: `ca.bundle`, `ui_users.json`, `policy.json`, `idp_profiles.json`, `audit.jsonl`, `requests.jsonl`, `config_versions/v{N}.json`, `cluster.json`, `threatfeeds.json`. Encryption at rest uses `CULVERT_CA_PASSPHRASE` / `CULVERT_LOG_PASSPHRASE`. **The canonical `scripts/install.sh` sets these for you** on a fresh install (auto-generating a strong passphrase by default, including in non-interactive runs — install.sh:1036-1094), so the standard install encrypts the CA key out of the box; save the passphrase it prints. **The plaintext risk is on the non-installer paths:** a **manual** `docker compose up` without `CULVERT_CA_PASSPHRASE`, the installer's **[3] Skip** option, or adding inspection to an existing deployment — there, `SaveCA` writes the root CA key as **plaintext PEM** and inspection stays active with an unencrypted key (`internal/ca/ca.go:194-235`), a key-custody risk (not "inspection off"). Always confirm the passphrase is set and `ssl_inspection: ready` on `/health`.
