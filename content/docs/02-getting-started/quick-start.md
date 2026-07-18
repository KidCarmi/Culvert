# Quick start & first boot

This guide takes you from nothing to a running Culvert proxy with an admin
account and a verified-ready node. Every command and every endpoint response
below is taken from the shipped artifacts or reproduced against a built binary —
see [Source evidence](#source-evidence).

For what Culvert is and the capabilities you are about to enable, see
[What is Culvert](../01-overview/what-is-culvert.md); for how requests flow, see
[Architecture](../01-overview/architecture.md).

---

## Purpose

Stand up a working Culvert instance, create the first administrator, confirm the
node reports **ready**, and understand the default traffic posture before you
put it in front of users.

## Prerequisites

- A Linux host (the one-line installer is tested on Ubuntu, Debian, RHEL,
  CentOS, Rocky, Alma, Fedora, Amazon Linux, and Arch).
- Docker Engine + Compose v2 (the one-line installer provisions these for you).
- Outbound network access from the host, or an internal mirror.
- **Optional:** a passphrase for CA encryption at rest (`CULVERT_CA_PASSPHRASE`),
  required only if you enable TLS inspection.
- **Optional:** a ClamAV sidecar, required only if you enable antivirus scanning.

## Supported install paths

| Path | When to use | Command |
|---|---|---|
| One-line installer | Fastest; provisions Docker + host service | `curl -fsSL https://raw.githubusercontent.com/KidCarmi/Culvert/main/scripts/install.sh \| bash` |
| Docker (manual) | You manage Docker yourself | `docker build -t culvert/proxy:pinned . && docker compose up -d` |
| Binary | No containers | `go build -o culvert . && ./culvert -port 8080 -ui-port 9090` |

> **Why the `docker build` step?** The compose file intentionally resolves the
> local-only image tag `culvert/proxy:pinned` — the proxy image is pinned at the
> sudo boundary and never pulled by name. Seed that tag with `docker build`, or:
> `docker pull ghcr.io/kidcarmi/culvert:latest && docker tag ghcr.io/kidcarmi/culvert:latest culvert/proxy:pinned`.
> A bare `docker compose up -d` without seeding fails with
> `pull access denied for culvert/proxy`.

## Configuration procedure

### 1. Start the stack

```bash
docker compose up -d
```

No configuration file is required. In the shipped compose file, persistence
paths (`/data/ca.bundle`, `/data/policy.json`, `/data/audit.jsonl`, …) and the
listening ports are supplied by the proxy container's command line, not by
binary-flag defaults (`docker-compose.yml`).

### 2. Endpoints

| Endpoint | URL | Notes |
|---|---|---|
| HTTP/HTTPS proxy | `http://localhost:8080` | Point browsers / PAC here |
| Admin UI (HTTPS) | `https://localhost:9090` | Accept the self-signed cert on first visit |
| SOCKS5 proxy | `socks5://localhost:1080` | Disabled by default (`socks5_port: 0`) |
| PAC file | `http://localhost:8080/proxy.pac` | Browser auto-config |
| Liveness | `http://localhost:8080/health` | `{"status":"ok", …}` |
| Readiness | `http://localhost:8080/ready` | `200 ready` / `503 not_ready` |
| Prometheus metrics | `http://localhost:8080/metrics` | Optional bearer-token protection |

`/health`, `/ready`, `/metrics`, and `/proxy.pac` are served on the **proxy**
port (`8080`), not the admin-UI port (`main.go:892-900`).

### 3. First boot: create the first administrator

Open `https://<host>:9090`, accept the self-signed certificate, and complete the
setup wizard. The browser first calls the public `GET /api/setup/status`, which
returns `{"needsSetup": true}` until an admin exists (`ui_auth.go:371-378`).
Submitting the wizard calls `POST /api/setup/complete`, which sets the initial
admin credential; once set, that endpoint refuses to run again
(`ui_auth.go:411`).

The initial admin password must satisfy the complexity policy: **8+ characters,
mixed case, and a digit** (`store.go:644-663`).

Until the first admin exists, the admin UI and API are gated — creating the
admin is required before any other API call.

---

## Validation steps

### Liveness

```bash
curl http://localhost:8080/health
```

Reproduced response (out-of-the-box binary, no config):

```json
{"status":"ok","uptime":"0m 4s","version":"dev","clamav":"disabled","ca_expires_days":3649,"ssl_inspection":"ready","threat_feed_entries":0}
```

### Readiness

```bash
curl -i http://localhost:8080/ready
```

Reproduced response — **HTTP 200**:

```json
{"status":"ready","uptime":"0m 4s","version":"dev","checks":{"ca":{"status":"ok"},"config_snapshot_validator":{"status":"ok"},"policy_loaded":{"status":"fail","detail":"no rules"},"session_secret":{"status":"ok"}}}
```

A fresh node is **ready out of the box**: the two gating checks that must pass —
`session_secret` and `config_snapshot_validator` — are `ok` on first boot. The
`policy_loaded: fail "no rules"` row is **informational and does not gate
readiness** (an empty policy is a valid Zero-Trust posture), so a fresh install
does not flap load balancers (`healthcheck.go:180-187`).

### Readiness check reference

| Check | Gates readiness? | Meaning |
|---|---|---|
| `session_secret` | **Yes** | Admin session HMAC key initialized; without it signed cookies cannot be issued |
| `config_snapshot_validator` | **Yes** | The cluster config-apply validator accepts the empty baseline |
| `clamav` | Yes, if configured | ClamAV sidecar reachable (skipped when disabled) |
| `ca` | No (report-only) | TLS-inspection CA load status; proxy still works as a plain forward proxy without it |
| `policy_loaded` | No (report-only) | `fail: "no rules"` on a fresh install is expected |
| `geoip`, `yara` | No | Present only when configured |

> **Strict probe.** `GET /ready?strict=1` treats every failing row — including
> the report-only ones — as gating (`healthcheck.go:224-233`). Use the default
> `/ready` for load-balancer health; reserve strict mode for pre-cutover checks.

### Proxy a request

```bash
curl -x http://localhost:8080 https://example.com -o /dev/null -w '%{http_code}\n'
```

---

## Operational behavior: the default posture

A fresh install with **zero policy rules and no explicit `default_action`**
starts in **passthrough (allow)** so you cannot lock yourself out. The startup
log states this explicitly (reproduced):

```
Policy: no rules configured; defaulting to Allow (passthrough).
        Add rules and set default_action: deny for Zero Trust.
Policy: default action: allow
```

### Enforce Zero Trust

Before taking production traffic, make the default deny — either add policy
rules (any rule flips the default to deny) or set `default_action: deny`
explicitly:

```yaml
# config.yaml
default_action: deny
```

Then review **Infrastructure → Diagnostics** in the admin UI, which surfaces the
operator contract (storage, policy load, root CA, session key, cluster TLS
posture, release-management and config-version health). Resolve any `fail` rows
before taking traffic.

---

## Failure modes & troubleshooting

| Symptom | Cause | Resolution |
|---|---|---|
| `pull access denied for culvert/proxy` | The compose file resolves the local-only tag `culvert/proxy:pinned`, which was never seeded | Run `docker build -t culvert/proxy:pinned .`, or pull `ghcr.io/kidcarmi/culvert:latest` and retag |
| `/ready` returns `503 not_ready` | A **gating** check failed — usually `session_secret` uninitialized or `clamav` unreachable | Read the `checks` map; restart to re-initialize the session key; verify the ClamAV sidecar |
| Admin UI shows the setup wizard again | First-time setup not completed, or `IsConfigured()` is false | Complete `POST /api/setup/complete`; it runs once |
| TLS inspection not active | No `-ca-path` + `CULVERT_CA_PASSPHRASE`, or no rule sets `Inspect` | See [TLS inspection administration](../04-tls-inspection/tls-inspection.md) |
| Traffic passes when you expected it blocked | Fresh-install passthrough is still in effect | Add rules or set `default_action: deny` |

---

## Known limitations

- The `version` field reads `dev` on a locally built binary; the shipped image
  stamps a real version at build time (`Dockerfile:20`).
- The one-line installer also installs a host-side maintenance agent by default;
  opt out with `CULVERT_SKIP_MAINT_AGENT=1`. A home-directory stack under a
  `0700` home leaves the agent unreachable (the Release Management panel shows
  "Agent unreachable") — the `/srv/culvert` default avoids this.
- SOCKS5 is disabled by default and supports CONNECT only (UDP ASSOCIATE is
  rejected).

## Related documentation

- [What is Culvert](../01-overview/what-is-culvert.md) · [Architecture](../01-overview/architecture.md).
- [Policy engine & Zero-Trust authoring](../03-policy/policy-engine.md).
- [TLS inspection administration](../04-tls-inspection/tls-inspection.md).
- In-repo: [`../../../README.md`](../../../README.md) (Quick Start),
  [`../../../docs/enterprise/FIRST-BOOT-AND-INITIAL-SETUP.md`](../../../docs/enterprise/FIRST-BOOT-AND-INITIAL-SETUP.md).

## Source evidence

- Reproduced readiness run: [`../../evidence/quick-start-lab-run.md`](../../evidence/quick-start-lab-run.md).
- Claim-evidence ledger: [`quick-start.evidence.md`](quick-start.evidence.md).
