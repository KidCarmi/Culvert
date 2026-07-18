# Configuration reference

Culvert can be driven by the admin UI, a YAML file, CLI flags, environment
variables, or any combination. This reference explains the **precedence model**,
how configuration is **validated**, and the shape of each config section. For the
exhaustive, always-current field list, the authoritative source is
[`config.example.yaml`](../../../config.example.yaml) — this page documents how
configuration behaves, not a copy of every field.

Prerequisite reading: [Quick start](../02-getting-started/quick-start.md).

---

## Precedence

For a given setting, the effective value is resolved highest-priority-first:

1. **CLI flag** (if set)
2. **Config file** value (if set)
3. **Built-in default**

This is implemented as `firstNonZero(flag, configValue, default)` — e.g. the
proxy port is `firstNonZero(*proxyPort, fc.Proxy.Port, 8080)`
(`main.go:502-503`). A zero/empty flag means "not set," so it falls through to
the config file, then the default.

Environment variables are a separate channel for **secrets and posture** (e.g.
`CULVERT_CA_PASSPHRASE`, `CULVERT_C2_ENFORCE`, the `CULVERT_RELEASE_*` family) —
see the [README environment variables](../../../README.md).

> **Shipped-image note.** In the Docker image, persistence paths and ports are
> supplied on the proxy container's command line (`docker-compose.yml`), not by
> binary-flag defaults — so the image's effective values come from that command,
> not from `8080`/`9090` defaults alone.

## GUI parity

Every CLI flag / config option that governs runtime behavior has a corresponding
admin API endpoint and UI panel, so an administrator can manage it from the web
interface. The documented exceptions are the `CULVERT_RELEASE_*` family (env-only
today; read-only status in the UI — see
[Release management](../11-supply-chain/release-management.md)) and startup-scoped
values like HA etcd endpoints.

## Validation

The config file is validated at load (`FileConfig.validate`, `config.go:356`):

- **Enums** (`validateEnums`, `config.go:369`): `default_action` must be `allow`
  or `deny` (or empty = auto-detect); `ip_filter_mode` and other string enums are
  range-checked.
- **Limits** (`validateLimits`): numeric bounds (e.g. `socks5_port` in
  `1–65535`, `session_timeout_hours` in `1–168`).
- **Cluster** (`validateCluster`) and **CDR** (`validateCDR`): section-specific
  consistency checks.

Invalid configuration is reported at startup rather than silently ignored.

## Configuration sections

The top-level YAML sections (`config.example.yaml`):

| Section | Governs | Related guide |
|---|---|---|
| `proxy` | `port`, `ui_port`, `socks5_port` | [Quick start](../02-getting-started/quick-start.md) |
| `auth` / `ldap` / `oidc` | Identity sources | [Identity & access](../05-identity/identity-and-access.md) |
| `security` | `ip_filter_mode`, `ip_list`, `rate_limit`, `max_conns_per_ip` | [Architecture](../01-overview/architecture.md) |
| `security_scan` | Content scanning engines | [Content security](../07-content-security/content-security.md) |
| `upstream` | Parent-proxy pool, `health_interval`, `circuit_breaker` | [Architecture](../01-overview/architecture.md) |
| `rewrite` | Per-host header rewrite rules | — |
| `file_block` | File-type block profile | [Content security](../07-content-security/content-security.md) |
| `default_action` | `allow` (passthrough) / `deny` (Zero Trust) / empty (auto) | [Policy engine](../03-policy/policy-engine.md) |
| `log_format`, `audit_log_file`, `syslog_addr`, `log_store_path`, `log_retention_*` | Logging & SIEM | [Observability](../06-observability/observability.md) |
| `cluster` | Control Plane / Data Plane, HA | [Distributed](../08-distributed/control-plane-data-plane.md), [HA](../08-distributed/high-availability.md) |
| `ui_allow_ips`, `session_timeout_hours` | Admin-UI access & sessions | [Identity & access](../05-identity/identity-and-access.md) |

## Minimal example

```yaml
proxy:
  port: 8080
  ui_port: 9090
  socks5_port: 0            # 0 = disabled

default_action: deny        # allow (passthrough) | deny (zero-trust) | "" (auto)

security:
  ip_filter_mode: allow     # allow | block | "" (off)
  ip_list:
    - 192.168.1.0/24
  rate_limit: 60            # requests/min per IP
  max_conns_per_ip: 256

upstream:
  proxies:
    - url: http://parent-proxy:3128
  health_interval: 30s      # a field on `upstream`, not on a proxy entry
  circuit_breaker:
    threshold: 5
    timeout: 30s
```

> **Structure gotchas (from `config.example.yaml`):** `ldap` is a **top-level**
> block (a sibling of `auth`), not nested under it; `upstream.health_interval`
> and `upstream.circuit_breaker` are siblings of `proxies`, not fields on a proxy
> entry.

## Key CLI flags

```
Core        -port  -ui-port  -socks5-port  -config <file>
TLS         -ca-path <bundle>  -tls-cert  -tls-key  -ui-no-tls
Auth        -ui-users-file <db>  -ui-allow-ip <cidrs>  -session-timeout
Filtering   -blocklist  -policy  -geoip-db  -clamav-addr  -yara-rules-dir  -threat-feed-db
Logging     -logfile  -log-max-mb  -request-log-max-mb  -audit-log  -syslog
Metrics     -metrics-token  -rate-limit  -otlp-endpoint <url>
Control Pl. -cp-grpc-addr  -cp-grpc-cert  -cp-grpc-key  -cp-grpc-ca
Data Plane  -dp-cp-addr  -dp-node-id  -dp-cert  -dp-key  -dp-ca
HA lease    -ha-etcd-endpoints  -ha-etcd-cert  -ha-etcd-key  -ha-etcd-ca  -ha-lease-ttl
```

## Validation steps

```bash
# Start with an explicit config and confirm it loads without validation errors
./culvert -config /path/to/config.yaml
# A malformed enum or out-of-range limit is reported at startup.
```

## Failure modes

| Condition | Behavior |
|---|---|
| `default_action` not `allow`/`deny`/empty | Startup validation error |
| `socks5_port` out of `1–65535` (non-zero) | Startup validation error |
| `session_timeout_hours` outside `1–168` | Startup validation error |
| Flag set to zero/empty | Falls through to config, then default |
| Nested `ldap` under `auth` | Ignored — `ldap` must be top-level |

## Known limitations

- The `CULVERT_RELEASE_*` family and HA etcd endpoints are env/startup-scoped,
  not managed from the UI (documented deferrals).
- This page is intentionally not a per-field dump; treat
  [`config.example.yaml`](../../../config.example.yaml) as the authoritative,
  version-matched field list.

## Related documentation

- [Quick start](../02-getting-started/quick-start.md) ·
  [Policy engine](../03-policy/policy-engine.md) ·
  [Identity & access](../05-identity/identity-and-access.md).
- In-repo: [`../../../config.example.yaml`](../../../config.example.yaml),
  [`../../../README.md`](../../../README.md).

## Source evidence

Claim-evidence ledger: [`configuration.evidence.md`](configuration.evidence.md).
