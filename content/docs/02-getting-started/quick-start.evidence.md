# Claim-Evidence Ledger — "Quick start & first boot"

Article: [`quick-start.md`](quick-start.md). Verified against repo revision
`ca60d83`.

Evidence types: `src` = source (`file:line`); `cfg` = config/compose/flag;
`api` = route/handler; `lab` = reproduced command (see
[`../../evidence/quick-start-lab-run.md`](../../evidence/quick-start-lab-run.md)).

| Claim | Type | Evidence |
|---|---|---|
| Compose resolves local-only tag `culvert/proxy:pinned`; bare `up` → `pull access denied` | cfg | `docker-compose.yml` (proxy `image: culvert/proxy:pinned`); README quick-start note |
| Persistence paths + ports come from the proxy container command line | cfg | `docker-compose.yml:129-140` (`-port 8080`, `-ca-path /data/ca.bundle`, …) |
| Endpoints `/health` `/ready` `/metrics` `/proxy.pac` served on the proxy port | src | `main.go:892-900` (proxy handler switch) |
| SOCKS5 disabled by default (`socks5_port: 0`) | cfg/src | `config.go:23`; `main.go:236` |
| Setup wizard gate: `GET /api/setup/status` → `needsSetup` (public) | api | `ui_auth.go:371-378` |
| `POST /api/setup/complete` sets the first admin; refuses once configured | api | `ui_auth.go:381-411` |
| Password complexity: 8+ chars, mixed case, digit | src | `store.go:644-663` `validatePasswordComplexity` |
| `/health` returns `status:ok` with clamav/ca/ssl fields | lab | Captured JSON (lab run) |
| `/ready` returns HTTP 200 `ready` out of the box | lab | Captured JSON, status 200 (lab run) |
| Gating checks: `session_secret`, `config_snapshot_validator` (+ `clamav` if configured) | src | `healthcheck.go:192-207` (`allOK = false` branches) |
| `policy_loaded: fail "no rules"` is report-only, does NOT gate | src | `healthcheck.go:180-187` (comment: "does NOT gate readiness") |
| `ca` is report-only (proxy works as plain forward proxy without it) | src | `healthcheck.go:139-153` |
| `/ready?strict=1` treats report-only failures as gating | src | `healthcheck.go:224-233` (`strictVerdictFails`) |
| Fresh install, 0 rules, no `default_action` → passthrough (allow) | lab/src | Startup log (lab run); `proxy.go:19` `defaultPolicyActionAllow` |
| `default_action: deny` enforces Zero Trust | cfg/src | `config.go:84-87`; `setDefaultPolicyAction` |
| Diagnostics panel surfaces the operator contract | src | README First-run checklist; `diagnostics.go` |
| One-line installer opt-out `CULVERT_SKIP_MAINT_AGENT=1`; `0700` home → agent unreachable | src | README Quick Start; `scripts/install.sh` |
| `version` is `dev` on local build; shipped image stamps it | lab/cfg | Lab run (`version:"dev"`); `Dockerfile:20` (`-X main.version`) |

## Reproduction note

The `/health` and `/ready` payloads were produced by running the built binary
with no config on shifted ports and are recorded verbatim in
[`../../evidence/quick-start-lab-run.md`](../../evidence/quick-start-lab-run.md).
They are the out-of-the-box posture; a production deployment with `-ca-path`,
`-clamav-addr`, `-policy`, etc. will show additional checks.
