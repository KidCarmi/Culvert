# OpenTelemetry (OTLP) export — configuration, limits and recovery

**Applies to:** every deployment that pushes Culvert metrics or request traces to an
OpenTelemetry collector. Export is off by default. The pull-based `/metrics` endpoint is
separate and is not covered here.

Owners: `internal/otlp` (transport, buffering, payloads), `otlp.go` (which metrics are
sent), `ui_config.go` `apiOTLPConfig` (admin API), `diagnostics_otlp_export.go`.

---

## 1. What is sent

One endpoint setting enables two independent push loops. Both use OTLP/HTTP with a JSON
body, every 15 seconds, with a 10-second request timeout. The interval is not configurable.

| Signal | Request | Content |
|---|---|---|
| Metrics | `POST {endpoint}/v1/metrics` | A cumulative snapshot of the metrics listed below |
| Traces | `POST {endpoint}/v1/traces` | The spans recorded since the last delivered push |

Enter the collector's base URL. Culvert appends `/v1/metrics` and `/v1/traces` itself, so
an endpoint that already ends in one of those paths posts to a wrong URL.

**Metrics.** This is a fixed subset, not the full `/metrics` set, and the names differ
from the Prometheus names:

- Counters: `culvert.requests.total`, `.blocked`, `.auth_fail`, `.file_blocked`,
  `.dpi_blocked`, `.clamav_blocked`, `.yara_blocked`, `.threat_feed_blocked`;
  `culvert.bytes.sent`, `culvert.bytes.recv`.
- Gauges: `culvert.uptime`, `culvert.blocklist.size`, `culvert.rate_limit.rpm`,
  `culvert.threat_feed.entries`, `culvert.scan_cache.size`.
- Histogram: `culvert.request.duration` (seconds).
- `culvert.policy.rule_hits`, one data point per rule with a `rule` attribute.

Health series such as feed freshness, syslog delivery and listener state are exported only
on `/metrics`.

**Traces.** One span named `proxy_request` is recorded for each request the proxy
dispatched to a tunnel, WebSocket or HTTP handler (`proxy.go` `recordRequestTelemetry`).

- Attributes: `http.method`, `http.host`, `net.peer.ip` (the client address),
  `culvert.status`, and when present `culvert.rule` and `culvert.ssl_action`
  (`inspect` or `bypass`).
- A request refused before dispatch produces no span. That covers IP filter, rate limit
  and connection limit refusals, authentication challenges and policy blocks. Use the
  request log for those. `culvert.status` is therefore always `OK`.
- The trace and span IDs come from the request's `Traceparent` header, which Culvert
  generates when the client sends none; see
  [`request-tracing-input-bounds.md`](request-tracing-input-bounds.md).
- `http.host` is the plaintext destination. The
  [traffic-log destination privacy](traffic-log-destination-privacy.md) setting does not
  apply to spans.
- There is no sampling setting.

**Resource identity.** Every node sends `service.name=culvert` and
`service.version=1.0.0`, and no node or instance attribute. In a cluster the collector
receives identical resources from every node, so distinguish nodes in the collector if you
need per-node series.

## 2. Endpoint requirements

- **Scheme.** `http` or `https`.
- **The collector must be at a public address.** Both loops dial through the SSRF guard
  (`ssrf.SafeDialContext`), which refuses loopback, RFC 1918, carrier-grade NAT,
  link-local and IPv6 unique-local addresses. A collector reached by a Docker or
  Kubernetes service name such as `otel-collector`, or by any private IP, never receives
  a push. There is no override.
- **TLS.** An `https` endpoint is verified against the system trust store. There is no
  setting for a private CA and none to skip verification.
- **No proxy.** Pushes go direct from the node. They do not use configured upstream
  proxies or the `HTTP_PROXY` environment variables.
- **Authentication.** One request header (name and value) can be stored through the GUI
  or the API. The flag and `config.yaml` cannot set a header.

## 3. Configuring

| Surface | How | Validation |
|---|---|---|
| GUI | **Settings → OpenTelemetry (OTLP)**, **Enable** / **Disable** | Same as the API |
| Admin API | `GET` / `POST /api/otlp` (admin role for both) | Scheme, then private-address check |
| Flag | `-otlp-endpoint <url>` | None at startup |
| `config.yaml` | `otlp_endpoint: "<url>"` | None at startup |

`POST /api/otlp` takes `endpoint`, `authHeaderName` and `authHeaderValue`.

- An empty `endpoint` disables both loops.
- A private or unresolvable host is answered `400 endpoint must not resolve to a private
  network`. The flag and YAML paths have no such check: a private endpoint is accepted at
  startup and then fails on every push (§5).
- If either header field is empty, the header already in use is kept. Neither the panel
  nor the API clears a stored header while the process runs.
- `GET` returns `enabled`, `endpoint`, `hasAuth`, `authHeaderName`, `metricsHealth` and
  `tracesHealth`. It never returns the header value.
- A change applies at once, without a restart, and writes a `settings.otlp` audit entry.
  It does not create a configuration version, so it cannot be rolled back from
  configuration history.

**Persistence and precedence.** The endpoint and header are stored in the node's admin
settings file. The header value is stored there in clear text; the file mode is `0600`.
At startup the flag overrides `config.yaml`, and a stored non-empty endpoint then replaces
both. A stored *disabled* state does not: if the flag or `otlp_endpoint` is set, a
**Disable** from the GUI lasts only until the next restart. Remove the flag or YAML value
to keep export off.

**Cluster.** The Control Plane's endpoint is part of the configuration snapshot
(`config_surfaces.go` `otlp_endpoint`). A node applying a snapshot takes that endpoint,
and an empty endpoint stops export on that node. The auth header is not in the snapshot
(`otlp_headers` is admin-durable only). A Data Plane node that takes an endpoint from the
snapshot pushes without a header, so a collector that requires one rejects that node.

## 4. Failure behavior

Export never affects proxy traffic or policy enforcement.

| Event | Metrics | Traces |
|---|---|---|
| Connection error, timeout, `408`, `429`, `5xx` | Snapshot skipped. Nothing is lost: counters are cumulative and the next push carries the totals. | Batch kept and retried on the next interval, ahead of newer spans |
| Any other `4xx` (for example `401`, `403`, `404`) | Same as above | Batch discarded and counted |
| More than 4096 spans held | — | Oldest spans dropped and counted |
| **Disable**, or endpoint changed | Loop stops or restarts | Buffered spans dropped and counted. Spans collected for one endpoint are never sent to another. |
| Shutdown | One final push | One final push; what remains is dropped and logged with its count |

The span buffer holds 4096 spans in memory and is emptied by each delivered push. A node
that dispatches more than about 270 requests per second for a full interval overflows it
even when the collector is healthy. Nothing is written to disk, so spans held at a crash
are lost.

The shutdown push for both signals shares a 2-second budget and runs after the durable log
closers; see [`graceful-shutdown.md`](graceful-shutdown.md).

## 5. Monitoring and troubleshooting

Health is kept in memory per node and resets at restart. It is not exported as a
`/metrics` series and raises no alert event.

- **Settings → OpenTelemetry (OTLP)** and `GET /api/otlp`: per signal, `failureCount`,
  `lastError`, `lastErrorAt`, `lastSuccessAt`, and for traces `droppedSpans` (spans never
  delivered, for any reason in §4).
- **Diagnostics** row `otlp_export` (WARN): present while the most recent push of an
  enabled signal failed. It names the signal only and clears after the next delivered push
  or a restart. A trace loop with no spans to send makes no attempt, so it records
  neither a failure nor a delivery.
- Process log, prefixed `OTLP`: `OTLP push error:` (metrics), `OTLP traces push error:`,
  `OTLP traces: discarded N span(s) — <reason>`, `OTLP traces: dropped N buffered span(s)
  on disable` / `on an endpoint change`, and at shutdown `OTLP traces: N span(s) could not
  be delivered before shutdown`.

| `lastError` contains | Cause | Action |
|---|---|---|
| `refusing tcp4 dial to private address` (or `tcp6`) | The endpoint resolves to an address the SSRF guard refuses (§2) | Use a collector at a public address |
| `OTLP collector returned 401` / `403` | Missing or wrong auth header; on a Data Plane node, the header was not synced (§3) | Store the header name and value on the affected node itself (§3) |
| `OTLP collector returned 404` | Endpoint is not the collector's OTLP/HTTP base URL | Remove any `/v1/...` suffix; check the port (OTLP/HTTP, not gRPC) |
| `x509:` / `tls:` | Certificate not trusted by the system store | Use a publicly trusted certificate on the collector |
| `invalid OTLP endpoint URL` | Flag or YAML value without an `http://` or `https://` scheme | Correct the value and restart, or save a valid endpoint in the GUI |
| `droppedSpans` rising with no failures | Buffer overflow at high request rates (§4) | Expected at that rate; traces are not a complete record |

To stop export immediately, select **Disable** (or `POST /api/otlp` with an empty
`endpoint`). Buffered spans are dropped; metrics counters are unaffected.
