# Lab evidence — quick-start readiness run

Reproduced in the content-factory environment against a binary built from repo
revision `ca60d83` (`go build -o culvert .`). Ports shifted to avoid clashes;
no config file, no CA passphrase, no ClamAV — i.e. the out-of-the-box posture.

## Command

```bash
./culvert -port 18080 -ui-port 19090 -ui-no-tls &
sleep 4
curl -s http://localhost:18080/health
curl -s http://localhost:18080/ready
```

## Captured `/health` (proxy port)

```json
{"status":"ok","uptime":"0m 4s","version":"dev","clamav":"disabled","ca_expires_days":3649,"ssl_inspection":"ready","threat_feed_entries":0}
```

## Captured `/ready` (proxy port, HTTP 200)

```json
{"status":"ready","uptime":"0m 4s","version":"dev","checks":{"ca":{"status":"ok"},"config_snapshot_validator":{"status":"ok"},"policy_loaded":{"status":"fail","detail":"no rules"},"session_secret":{"status":"ok"}}}
```

## Key startup log lines

```
SSLCA: Root CA ready in-memory (set -ca-path + CULVERT_CA_PASSPHRASE for persistence)
Policy: no rules configured; defaulting to Allow (passthrough). Add rules and set default_action: deny for Zero Trust.
Policy: default action: allow
Metrics: /metrics open (set -metrics-token to restrict)
UIHTTP: http://localhost:19090
Proxy: http://localhost:18080
```

## What this proves

- `/ready` returns **HTTP 200 `ready`** out of the box: `session_secret` and
  `config_snapshot_validator` (both gating) are `ok` on first boot.
- `policy_loaded` reports `fail: "no rules"` but does **not** gate readiness —
  an empty policy is a valid posture, so a fresh node does not flap load
  balancers (`healthcheck.go:180-187`).
- A fresh install with no rules and no `default_action` runs in **passthrough**,
  exactly as the startup log states — Zero Trust must be enforced explicitly.
- `version:"dev"` here because this local build carries no version ldflag; the
  shipped image stamps a real version (`Dockerfile:20` `-X main.version=...`).
