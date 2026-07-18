# Claim-Evidence Ledger — "Observability"

Article: [`observability.md`](observability.md). Verified against repo revision
`ca60d83`.

| Claim | Type | Evidence |
|---|---|---|
| `/metrics` on the proxy port, `culvert_*` namespace, bearer-protected | src | `main.go:897`; `handleMetrics metrics.go:429-439` (constant-time bearer) |
| Metric families listed exist | src | `metrics.go` — `culvert_requests_allowed`, `culvert_bytes_{sent,recv}_total`, `culvert_request_duration_seconds` (`:369-380`), `culvert_policy_rule_hits_total` (`:332`), `culvert_{clamav,dpi,file}_blocked_total`, `culvert_decrypt_{sessions,failures}_total`, `culvert_cert_sign_duration_seconds` |
| Live SSE dashboard at `/api/events`, fan-out hub, cap 256 | src | `ui_config.go:1870`; `internal/sse/sse.go`; `events.go:59,125` |
| Request log JSONL via rotating writer | src | `internal/reqlog/reqlog.go:65` (`*fileutil.RotatingFile`) |
| Log routes: view/retention/purge | src | `ui_config.go:1865-1867` |
| Syslog RFC 3164/5424, UDP/TCP, async drop-on-full, single drain, queue 2048 | src | `internal/syslog/syslog.go:7-22`, `queueCap = 2048 :67`, drops `:53,141` |
| Syslog config + test routes | src | `ui_config.go:1901-1902` |
| OTLP/HTTP export, SSRF-guarded | src | `ui_config.go:1905` (`/api/otlp`); `otlp.go` |
| Alerts HMAC-SHA256 signed + retry queue | src | `internal/alerts/secret.go:3-4`; routes `ui_security.go:1345-1346` |
| Audit ring bounded 500, append-only JSONL, **no hash-chain/signature** | src | `internal/audit/audit.go:49` (`MaxRing = 500`), evict `:124-126`; no `hash`/`sign`/`chain` symbols in `internal/audit` |
| Per-rule metric cardinality capped at 200 | src | `metrics.go:332` ("capped at 200 rules") |
| Grafana Overview dashboard auto-provisioned | cfg | `deploy/grafana/dashboards/culvert-overview.json`; README monitoring section |

## Correction carried from C-001

The audit trail is documented here as **append-only, not tamper-evident**,
consistent with the C-001 correction and product-gap G-01. The README/
architecture "tamper-evident" wording is not backed by `internal/audit`.
