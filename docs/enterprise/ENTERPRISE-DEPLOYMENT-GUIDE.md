# Culvert Enterprise Deployment Guide (Zero → Production)

**Audience:** Professional-services / implementation engineers and enterprise platform teams deploying Culvert on-prem for the first time.
**Purpose:** A single executable path from bare infrastructure to a validated, change-controlled production Secure Web Gateway, honest about where the product blocks.

> **How to read this guide.** Every step is written to be executed against Culvert *as it exists in this repository today*. Where a step cannot be completed with the shipping product through a supported customer interface, it is marked:
>
> **⛔ DEPLOYMENT BLOCKER — GAP-XXX-NN**
>
> …and cross-references the [Enterprise Implementation Gap Register](../engineering/ENTERPRISE-IMPLEMENTATION-GAP-REGISTER.md), which holds the evidence, severity, workaround, and recommended fix. Do not treat a blocker as fatal — most have a workaround — but do treat it as a decision the customer must make consciously.
>
> **Status vocabulary:** Verified (observed in code/tests) · Implemented · Partially implemented · Undocumented · Unsupported · Blocked.

---

## 0. Executive summary — is Culvert deployable from zero without the creator?

**Verdict: Yes, with material caveats, on the Docker-Compose-on-a-customer-Linux-host model — not on an ISO/OVA appliance model.**

Culvert is a single Go binary delivered as a signed container image plus a one-command installer. A competent Linux/Docker operator can bring up a working, policy-enforcing, TLS-inspecting proxy with an admin UI, SSO for proxy users, metrics, and a signed update path — using only the product, its installer, and its GUI/API. The first genuine hard stop for the *stated* enterprise model appears at **appliance installation** (there is no ISO/OVA — GAP-APP-01) and, for the *no-SSH* constraint, at **backup/restore** (host-CLI only — GAP-BAK-01) and **administrator recovery** (host shell only — GAP-IAM-01).

The five capabilities most likely to fail an enterprise gate: no appliance image, no in-band admin break-glass, GUI/API backup+restore absent, no monitor-only policy pilot mode, and no turnkey air-gapped update. All are documented as gaps with workarounds and recommended fixes.

---

## 1. Supported deployment assumptions

| Assumption | Reality in the shipping product | Status |
|---|---|---|
| Delivery form | Signed container image `ghcr.io/kidcarmi/culvert` + `scripts/install.sh` (Docker Engine + Compose). **No ISO/OVA.** | Verified — GAP-APP-01 |
| Host | Customer-provided Linux VM/host (Ubuntu/Debian/RHEL family/Fedora/Amazon Linux/Arch) | Verified |
| Runtime deps | None beyond Docker; optional ClamAV sidecar | Verified |
| Persistence | Flat files under `/data` (Docker named volume). No database, no migrations | Verified |
| Management | Admin UI (HTTPS :9090) + admin API. Some day-2 settings are env-only | Verified |
| Clustering | Optional gRPC Control Plane / Data Plane with mTLS; optional etcd HA fencing lease | Verified |
| Updates | Signed release catalog + host maintenance agent (`culvert-maint`) | Verified |

---

## 2. Architecture decisions (make these first)

1. **Single node vs cluster.** ≤~500 users or ≤~1 Gbps → single node. Beyond that → Control Plane + stateless Data Plane nodes behind a TCP load balancer. (README sizing; `docs/deployment-guide.md`.) Sizing numbers are engineering estimates, not benchmarks — validate against your workload.
2. **TLS inspection: on or off.** Off → Culvert is a plain forward proxy; endpoints need no CA. On → you must generate or import an inspection CA and distribute trust (§10).
3. **Identity model.** Admin operators authenticate with **local accounts only** (bcrypt + optional TOTP). Proxy end-users can authenticate via LDAP/OIDC/SAML. Admin SSO does not exist (GAP-IAM-02).
4. **Update trust.** Verification is enforce-by-default when a trust root is present. Decide whether you accept the vendor catalog origin (`catalog.culvertlabs.com`) or run restricted (§13).
5. **HA.** For safe automatic control-plane failover you need a third-machine etcd witness with TLS (ADR-0005). A 2-node pair alone is manual-promotion only.

---

## 3. Prerequisites

See the companion **[ENTERPRISE-PREREQUISITES.md](ENTERPRISE-PREREQUISITES.md)** for the full, itemised list (CPU/memory/storage/network/ports/PKI/outbound/inbound). Minimum viable full-feature single node: **2 vCPU / 1.5 GB RAM / 2.5 GB SSD**; proxy-only: **1 vCPU / 128 MB / 100 MB**.

---

## 4. Networking & firewall

**Inbound (must reach the appliance):**

| Port | Purpose | Who connects | Configurable |
|---|---|---|---|
| 8080/tcp | Forward proxy (HTTP/HTTPS CONNECT) + `/health` `/ready` `/metrics` `/proxy.pac` | Proxy clients, LB probes | `-port` |
| 9090/tcp | Admin UI/API (HTTPS) + `/healthz` + `/api/events` (SSE) | Admins, LB probes | `-ui-port` |
| 1080/tcp | SOCKS5 (default **disabled**, `socks5_port: 0`) | SOCKS5 clients | `-socks5-port` |
| 50051/tcp | Control-Plane gRPC (cluster only, mTLS) | Data Plane nodes | `-cp-grpc-addr` |

All listeners bind `0.0.0.0`; there is no bind-interface flag (GAP-NET-04). Restrict the admin UI with `-ui-allow-ip <cidrs>` **and** a host firewall / management VLAN.

**Outbound (egress the customer must plan / approve):**

| Destination | Default | Override / disable | Notes |
|---|---|---|---|
| `catalog.culvertlabs.com` | **On** (enforce mode, boot + ~6h) | `CULVERT_RELEASE_CATALOG_URL=off` | Signed catalog fetch — GAP-NET-01 |
| `urlhaus.abuse.ch`, `openphish.com` | On **iff** threat feeds/scanner enabled | **No override** (hard-coded) | GAP-NET-02 |
| OTLP / syslog / OCSP / blocklist feed / IdP / upstream | Off by default | Operator-configured | — |
| Sigstore/Rekor/Fulcio | **No runtime egress** (offline verify) | — | Air-gap safe |

> **⛔ DEPLOYMENT BLOCKER — GAP-NET-01 / GAP-NET-02 (restricted egress).** A stock install makes an outbound call to `catalog.culvertlabs.com`; enabling threat feeds forces egress to two hard-coded public feeds with no internal-mirror option. **Before go-live** on a restricted network: set `CULVERT_RELEASE_CATALOG_URL=off` (or allowlist the host) and decide whether to run without threat feeds. Both are env-only; there is no GUI toggle. Workaround-acceptable for the catalog; a genuine capability gap for threat-feed mirroring.

---

## 5. Time, DNS, hostname (host-owned)

Culvert makes no NTP calls and has no hostname/DNS setter — these are host-OS responsibilities. Time sync matters: SAML/OIDC assertion windows and TLS validity depend on an accurate clock.

> **⛔ DEPLOYMENT BLOCKER — GAP-APP-02 (no-SSH first-boot L3/time).** If your operating model prohibits host SSH/console, you cannot set IP/DNS/hostname/NTP/timezone through Culvert. Configure them via host provisioning (cloud-init, DHCP, `chrony`, `timedatectl`) during the build phase. This is normal for a Docker-on-VM model; it is a gap against an appliance-console expectation.

---

## 6. Installation

**Connected host (canonical path):**

```bash
curl -fsSL https://raw.githubusercontent.com/KidCarmi/Culvert/main/scripts/install.sh | bash
```

This installs Docker + Compose, provisions `/srv/culvert` from the image's `/app/deploy` bundle, seeds the local `culvert/proxy:pinned` tag from a signed release, starts the stack, and (best-effort) installs the `culvert-maint` Maintenance Agent. Opt out of the agent with `CULVERT_SKIP_MAINT_AGENT=1`.

**Manual Docker:**

```bash
git clone https://github.com/KidCarmi/Culvert && cd Culvert
docker build -t culvert/proxy:pinned .   # seed the local-only pinned tag
export CULVERT_CA_PASSPHRASE="<strong-passphrase>"   # required for TLS inspection
docker compose up -d
```

> **⛔ DEPLOYMENT BLOCKER — GAP-APP-01 (no appliance image).** There is no ISO/OVA. If procurement requires a signed vendor appliance, you must instead run the Compose stack on a hardened customer VM (a valid but different model) or build a golden VM internally (no signed provenance). Decision required.

> **⛔ DEPLOYMENT BLOCKER — GAP-APP-03 (air-gapped install).** `install.sh` hard-fails without reaching `download.docker.com` and pulls images from `ghcr.io`. For an air-gapped segment you must pre-stage images (`docker save`/`load` or a private registry) and provide the compose files manually (`CULVERT_PROXY_SEED_REF`, `CULVERT_PROXY_REPO`). No signed offline install bundle ships today.

---

## 7. First boot & initial administrator

Open `https://<host>:9090`, accept the self-signed cert, and complete the **setup wizard** — it creates the first admin (bcrypt, persisted to `/data/ui_users.json`). There is no default password.

> **⛔ DEPLOYMENT BLOCKER — GAP-APP-04 (trust-on-first-use).** Whoever reaches :9090 first can claim the admin account — there is no console-printed setup token. **Firewall :9090 to a trusted admin host until setup is complete.**

See **[FIRST-BOOT-AND-INITIAL-SETUP.md](FIRST-BOOT-AND-INITIAL-SETUP.md)** for the full first-boot checklist and what is/isn't configurable.

**Immediately after setup:**
1. Create a **second admin account** (Auth → Users). This is your only practical break-glass — see below.
2. Enable **TOTP** for admins.
3. Confirm `-audit-log` is active (the shipped compose sets it) so admin actions persist (GAP-IAM-04).

> **⛔ DEPLOYMENT BLOCKER — GAP-IAM-01 (administrator recovery).** The only recovery from a lost sole-admin password is the host CLI `--reset-password username:newpassword` (run via `docker exec`/`compose run`). There is no in-band (GUI/API) reset and no IdP fallback for admin login. **Mitigate by always provisioning ≥2 admins and retaining container-exec access as documented break-glass.** Under a strict no-SSH mandate this is a P0 for recovery SLAs. See [OPERATIONS-RUNBOOK.md](OPERATIONS-RUNBOOK.md) §Admin recovery.

---

## 8. Initial health validation

```bash
curl http://<host>:8080/health      # liveness, always 200
curl -i http://<host>:8080/ready    # 200 ready / 503 not_ready (gating checks)
```

`/ready` gates on `session_secret`, `config_snapshot_validator`, and (if configured) `clamav`. A fresh install shows `policy_loaded: fail` — that is expected (default-deny with no rules is a valid posture) and does **not** gate readiness.

Then, in the UI: **Infrastructure → Diagnostics** (`GET /api/diagnostics`, viewer role). Resolve every `fail`; consciously accept each `warn`.

---

## 9. Identity setup

See **[IDENTITY-AND-ACCESS-DEPLOYMENT.md](IDENTITY-AND-ACCESS-DEPLOYMENT.md)**. Summary: configure LDAP/OIDC/SAML for **proxy users** (admin UI → IdP profiles; all providers fail *closed* on misconfiguration). Admin RBAC (admin/operator/viewer) is local-only and assigned manually. Set `proxy.base_url` before enabling production OIDC/SAML (it is the SAML SP Entity ID / ACS base).

---

## 10. TLS inspection rollout

See **[TLS-INSPECTION-DEPLOYMENT.md](TLS-INSPECTION-DEPLOYMENT.md)**. Summary:
1. Set `CULVERT_CA_PASSPHRASE` and `-ca-path /data/ca.bundle`; the first start generates an ECDSA P-256 root CA (encrypted at rest, PBKDF2-600k + AES-256-GCM).
2. Download the CA: **Certificates → Download Root CA (.pem)** or `GET /api/ca-cert`. Distribute to endpoint trust stores (GPO/MDM/`update-ca-trust`).
3. Configure inspection bypass for pinned/banking/mTLS hosts: **SSL Inspection Bypass** or per-rule `Bypass`.

> **⛔ DEPLOYMENT BLOCKER — GAP-PKI-01/02/03 (bring-your-own CA).** If you import your internal-PKI CA (`POST /api/certs/upload`, `target=mitm`): it must be **ECDSA** (RSA rejected), it is **not persisted** (lost on restart), and **auto-rotation will overwrite it** with an auto-generated CA at the 30-day mark. For a durable imported CA today, pre-stage an EC PEM bundle at `-ca-path` on disk (needs host access) and monitor expiry externally. Evaluate carefully before committing to internal-PKI-signed inspection.

---

## 11. Policy setup & pilot

See **[POLICY-ROLLOUT-GUIDE.md](POLICY-ROLLOUT-GUIDE.md)**. Summary: priority-ordered, first-match rules, default-deny (Zero Trust). Use **Policy Tester** (`/api/policy/test`) to dry-run requests against the live ruleset. Config versioning gives 50 auto-snapshots with dry-run diff and one-click rollback.

> **⛔ DEPLOYMENT BLOCKER — GAP-POL-01 (no monitor-only pilot).** There is no observe-only enforcement mode: a blocking rule always blocks. To pilot safely you must either (a) scope rules to a pilot population by source IP/IdP group and start with `Allow`+log, then flip to enforce, or (b) run a passthrough default while you observe. Plan the pilot around this.

---

## 12. Explicit-proxy & PAC rollout

Point browsers at `http://<host>:8080` (or push the PAC at `http://<host>:8080/proxy.pac` — also served on `:9090/proxy.pac`, unauthenticated by design for Windows clients). Configure PAC exclusions in the admin UI.

---

## 13. Update source configuration

See **[OPERATIONS-RUNBOOK.md](OPERATIONS-RUNBOOK.md)** §Updates. The Control Plane dispatches upgrades to the `culvert-maint` agent, which pulls a pinned digest and restarts via Compose. Trust is enforce-by-default (ed25519 + Sigstore keyless). Release Management is GUI/API-driven (`/api/releases/*`), **including auto-rollback on a failed upgrade**.

> **⛔ DEPLOYMENT BLOCKER — GAP-UPD-01/02/03 (restricted/change-controlled updates).**
> - **Air-gapped image update** has no turnkey path (no offline bundle; the internal-registry `RepoRewrite` is unwired). Workaround: self-signed private catalog + mirrored images — heavy and undocumented.
> - **Deliberate (non-failure) rollback** to a prior image or `/data` is not exposed via CP/GUI (the agent primitive exists at `/v1/rollbacks`); it needs a host-level agent call.
> - **Trust-root management** is env-only (restart required).

---

## 14. Backup & restore

> **⛔ DEPLOYMENT BLOCKER — GAP-BAK-01/02 (no-SSH backup).** Full `/data` backup/restore exists **only** as a host CLI (`docker compose --profile cli run --rm cli --backup …` / `--restore … --confirm`). There is **no GUI/API self-service backup or restore**, and **no scheduled backup**. A no-SSH customer cannot back up or recover from the console today. Mitigate: run an external cron invoking the `cli` container with `--encrypt` and copy archives off-host; retain host access for restore. A restore **dry-run** is runtime-safe and non-destructive; restore **commit** is offline-only and overwrites `/data` (with a preserved `.bak` rollback).

See [OPERATIONS-RUNBOOK.md](OPERATIONS-RUNBOOK.md) §Backup/Restore for exact commands.

---

## 15. Validation, pilot, production cutover

1. **Validation:** `/ready` = 200 on every node; Diagnostics clean; Policy Tester confirms expected decisions; a test client is allowed/blocked as designed; CA trust verified on a pilot endpoint; metrics scraping live.
2. **Pilot:** scope policy to a pilot IdP group / IP range (GAP-POL-01/02 workaround); watch the live feed and metrics; take a config snapshot before each change.
3. **Cutover:** widen policy scope; distribute PAC/CA fleet-wide; confirm LB health checks route only to `200` nodes; take a full encrypted `/data` backup.
4. **Rollback:** config-version rollback for policy/settings; image auto-rollback on failed upgrade; `/data` restore (offline) for state.

See **[PRODUCTION-READINESS-CHECKLIST.md](PRODUCTION-READINESS-CHECKLIST.md)** for the go-live gate.

---

## 16. Operational handoff

Hand operators: [OPERATIONS-RUNBOOK.md](OPERATIONS-RUNBOOK.md), the Diagnostics page, the metrics/Grafana dashboard, the audit trail, and the documented break-glass (`--reset-password`, multi-admin). Confirm they can execute: health check, config rollback, backup, restore dry-run, admin recovery, and upgrade+rollback.

---

## 17. Known limitations (deployment-relevant)

- No ISO/OVA appliance image (GAP-APP-01).
- No in-band admin recovery / no admin SSO (GAP-IAM-01/02).
- Bring-your-own inspection CA is fragile: ECDSA-only, non-persistent, auto-rotation clobbers it (GAP-PKI-01/02/03).
- No monitor-only policy mode (GAP-POL-01); no node-scoped staged rollout (GAP-POL-02).
- No GUI/API or scheduled backup (GAP-BAK-01/02).
- No support bundle (GAP-MON-01).
- No turnkey air-gapped update; no customer-triggered rollback via GUI (GAP-UPD-01/02).
- OCSP-only revocation (no CRL); SOCKS5 CONNECT-only (README limitations).

Every item above is a tracked gap with a workaround and a recommended fix in the [Gap Register](../engineering/ENTERPRISE-IMPLEMENTATION-GAP-REGISTER.md).
