# Observability

Culvert emits a decision trail for every request across five surfaces:
Prometheus metrics, a live dashboard, structured logs, syslog/SIEM forwarding,
and an audit trail — plus signed webhook alerts and optional OTLP export. This
guide covers what each surface exposes, how to configure it, and its honest
limits.

Prerequisite reading: [Quick start](../02-getting-started/quick-start.md)
(health/readiness) and [Architecture](../01-overview/architecture.md) (telemetry
is the final pipeline stage).

---

## Purpose

- Measure traffic, policy decisions, and content-scan outcomes quantitatively.
- Stream live activity to an operator dashboard.
- Ship structured events to a SIEM and page on-call via signed webhooks.
- Keep an audit record of administrative actions.

## Prometheus metrics

Metrics are exposed at `GET /metrics` on the **proxy** port (`main.go:897`),
under the `culvert_*` namespace. Access can be restricted with a bearer token
(`-metrics-token`); the handler uses a constant-time comparison
(`handleMetrics`, `metrics.go:429-439`).

Representative metric families (verified in `metrics.go`):

| Metric | Meaning |
|---|---|
| `culvert_requests_allowed` / `culvert_requests_auth_fail` | Request outcomes |
| `culvert_bytes_sent_total` / `culvert_bytes_recv_total` | Bytes proxied (incl. raw tunnels) |
| `culvert_request_duration_seconds` | Latency histogram (`metrics.go:369-380`) |
| `culvert_policy_rule_hits_total` | Per-rule hit counter (capped at 200 rules, `metrics.go:332`) |
| `culvert_clamav_blocked_total` / `culvert_dpi_blocked_total` / `culvert_file_blocked_total` | Content-scan blocks |
| `culvert_decrypt_sessions_total` / `culvert_decrypt_failures_total` | TLS inspection volume/failures |
| `culvert_cert_sign_duration_seconds` | Leaf-cert signing latency |
| `culvert_blocklist_size` / `culvert_rate_limit_rpm` | Configuration gauges |

A 12-panel **Culvert Overview** Grafana dashboard is auto-provisioned from
`deploy/grafana/dashboards/culvert-overview.json` when you bring up the optional
monitoring stack (see the README).

## Live dashboard (SSE)

The admin UI subscribes to a server-sent-events feed at `/api/events`
(`ui_config.go:1870`), backed by a fan-out hub with slow-client eviction
(`internal/sse/sse.go`, cap 256; `events.go:59,125`). This drives the real-time
activity view without polling.

## Structured logs

- **Request log:** JSONL via a rotating file writer
  (`internal/reqlog/reqlog.go:65` → `*fileutil.RotatingFile`). Raw tunnels emit a
  `TUNNEL_CLOSED` entry with per-connection bytes and duration.
- **Management:** `/api/logs` (view), `/api/logs/retention`, `/api/logs/purge`
  (`ui_config.go:1865-1867`).

## Syslog / SIEM forwarding

Culvert forwards events to a syslog collector over UDP or TCP, in RFC 3164 or RFC
5424 format (`internal/syslog/syslog.go:7-22`). Delivery is **asynchronous**: a
caller formats and enqueues onto a bounded channel (`queueCap = 2048`,
`:67`); a single drain goroutine owns the socket and reconnect/backoff. When the
queue is full, messages are **dropped** (counted), never blocking the proxy hot
path (`:53,141`).

Configure at `/api/syslog`; send a test message with `/api/syslog/test`
(`ui_config.go:1901-1902`).

> **Design implication:** a slow or unreachable SIEM costs you dropped log
> messages, not proxy latency. Monitor the drops counter if completeness matters.

## OTLP export

Culvert can export metrics/spans over OTLP/HTTP to a collector; configure at
`/api/otlp` (`ui_config.go:1905`; transport in `otlp.go`, endpoints SSRF-guarded).

## Signed webhook alerts

Alerts fire to webhooks that are **HMAC-SHA256 signed** so the receiver can
verify authenticity (`internal/alerts/secret.go:3-4`), with a retry queue on
delivery failure. Manage at `/api/alerts/webhooks`; test-fire at
`/api/alerts/webhooks/test` (`ui_security.go:1345-1346`).

## Audit trail

Administrative actions are recorded to an in-memory ring bounded at 500 entries,
with optional append-only JSONL persistence (`internal/audit/audit.go:49`,
`MaxRing = 500`). The ring evicts the oldest entry at capacity.

> **Integrity scope — read this.** The audit trail is **append-only, not
> cryptographically tamper-evident**: there is no hash-chain or signature over
> entries in `internal/audit`. If you require tamper-evidence, forward audit
> events to an external, write-once SIEM via syslog and treat that as the
> system of record. (Tracked as a product gap in the content factory's run
> state.)

---

## Configuration / API summary

| Surface | Route(s) | Notes |
|---|---|---|
| Metrics | `GET /metrics` (proxy port), `/api/metrics-config` | Bearer via `-metrics-token` |
| Live dashboard | `/api/events` (SSE) | Fan-out hub |
| Logs | `/api/logs`, `/api/logs/retention`, `/api/logs/purge` | JSONL, rotating |
| Syslog | `/api/syslog`, `/api/syslog/test` | RFC 3164/5424, async |
| OTLP | `/api/otlp` | OTLP/HTTP export |
| Alerts | `/api/alerts/webhooks`, `/api/alerts/webhooks/test` | HMAC-signed |
| Health / readiness | `/health`, `/ready` (proxy port) | See [Quick start](../02-getting-started/quick-start.md#validation-steps) |

## Validation steps

```bash
# Metrics (add -H "Authorization: Bearer $TOKEN" if a metrics token is set)
curl -s http://localhost:8080/metrics | grep -E '^culvert_' | head

# Readiness (JSON checks map)
curl -s http://localhost:8080/ready
```

## Failure modes

| Condition | Behavior |
|---|---|
| SIEM unreachable / slow | Syslog messages dropped (counted); proxy latency unaffected |
| Metrics token set, request without/with wrong token | `/metrics` denied (constant-time compare) |
| Webhook endpoint down | Alert retried from the retry queue |
| Audit ring at 500 entries | Oldest entry evicted (bounded memory) |

## Security implications

- Protect `/metrics` with `-metrics-token` if the proxy port is reachable beyond
  your monitoring network — metrics reveal traffic and configuration shape.
- Sign-verify webhook payloads on the receiver using the shared HMAC key.
- Because the audit ring is not tamper-evident, forward it to an immutable store
  for compliance-grade retention.

## Known limitations

- **Audit trail is not cryptographically tamper-evident** (no hash-chain/
  signature) — see the callout above.
- The in-memory audit ring holds only the newest 500 entries; enable JSONL
  persistence and external forwarding for durable history.
- Per-rule metric cardinality is capped at 200 rules (`metrics.go:332`).

## Related documentation

- [Quick start](../02-getting-started/quick-start.md) ·
  [Architecture](../01-overview/architecture.md) · [What is Culvert](../01-overview/what-is-culvert.md).
- In-repo: [`../../../docs/enterprise/OPERATIONS-RUNBOOK.md`](../../../docs/enterprise/OPERATIONS-RUNBOOK.md),
  [`../../../docs/operator/support-bundles-and-diagnostics.md`](../../../docs/operator/support-bundles-and-diagnostics.md).

## Source evidence

Claim-evidence ledger: [`observability.evidence.md`](observability.evidence.md).
