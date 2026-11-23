# Documentation governance review 2026-11-22

Scope: checked-out `main` at `155df09`. Point-in-time record; not a source of truth for
behavior.

## Finding (High): OTLP export has no operator guide, and the CLI help contradicts the implementation

- **Problem.** OpenTelemetry export has a GUI panel, an admin API, a flag, a YAML key, a
  cluster-synced surface, a Diagnostics row and (since CHAOS-126, merged 2026-11-22) a
  defined span-loss and shutdown-flush contract. Its only operator text was one README
  paragraph. Two sources disagreed about a hard requirement: `config.example.yaml` states
  that a collector at a private address is refused, while the `-otlp-endpoint` help text
  and three code comments gave `http://otel-collector:4318` as the example and the README
  said nothing. The help text also described the flag as metrics-only.
- **Implementation evidence.** `internal/otlp/otlp.go` and `spans.go` (both clients dial
  through `ssrf.SafeDialContext`; 15 s interval; 4096-span ring; retain on transport error,
  `408`, `429`, `5xx`; discard and count on other `4xx`; drop on disable or endpoint
  change), `otlp.go` (the exported metric set), `proxy.go` `recordRequestTelemetry` (one
  span per dispatched request, status always `OK`), `ui_config.go` `apiOTLPConfig` and
  `resolveOTLPHeaders`, `observability_startup.go`, `admin_settings.go`
  (`applyAdminServices`, `snapshotAdminEndpoints`), `controlplane_snapshot.go` (endpoint
  synced, `Configure(endpoint, nil)`), `config_surfaces.go`, `main_shutdown.go`
  (`otlp-flush`, 2 s), `diagnostics_otlp_export.go`, `static/index.html`.
- **Why it matters.** The usual deployment, a collector beside the proxy on a private
  network, cannot work and fails only at push time when set by flag or YAML. Other facts an
  administrator cannot infer from the panel: only a fixed subset of metrics is exported
  under different names; blocked and refused requests produce no span; spans carry the
  client address and the plaintext destination regardless of the destination-privacy
  setting; every node reports an identical resource; the auth header is not synced to
  nodes that take the endpoint from the Control Plane; a GUI disable does not survive a
  restart while the flag or YAML value is set.
- **Who is affected.** Administrators integrating Culvert with an observability stack;
  on-call staff reading the `otlp_export` Diagnostics row; privacy reviewers.
- **Canonical source.** The code above. The new page owns OTLP export; the README keeps a
  summary and links to it.
- **Change.** New `docs/operator/otlp-export.md`; index entry in
  `docs/operator/README.md`; one sentence and a link in `README.md`; corrected example and
  description in the `-otlp-endpoint` help text (`main.go`) and in comments in `otlp.go`,
  `config.go` and `internal/otlp/otlp.go`. No behavior change. Effort: medium. Risk: low.

## Checks performed

- Every name, status code, limit, log line and field in the new page was read from the
  files above at this revision.
- The private-address refusal was reproduced with a throwaway test (not committed): a
  metrics push to `127.0.0.1`, `10.1.2.3` and `192.168.1.10` each failed with `ssrf control:
  destination blocked: refusing tcp4 dial to private address`, and the listener received
  no request.
- `python3 docs/agent-context/check.py`, `go build ./...`, `go vet` and the focused tests
  listed in the pull request.

## Not assessed / documentation debt

- **Ambiguity, for the owner:** whether refusing private collector addresses is intended.
  `config.example.yaml` documents it and the code enforces it with no override, so the
  guide states it as the contract. The GUI placeholder and the vendors it names are all
  public SaaS endpoints.
- **Medium, product text:** the panel says "Push all Culvert metrics"; a fixed subset is
  pushed. `service.version` is the literal `1.0.0`, not the build version. Left to a code
  change.
- **Medium, product behavior:** no way was found to clear a stored OTLP auth header from
  the panel or the API while the process runs (`Stop` keeps the headers and
  `resolveOTLPHeaders` falls back to them). Read from code, not exercised.
- **Low:** `docs/operator/graceful-shutdown.md` does not list the `otlp-flush` hook in its
  Flush phase.
- Not verified, so not documented: whether a Data Plane node serves the admin API in every
  deployment, and how a node's own stored header interacts with later snapshots.
- Carried: `CULVERT_MCP_LIVE_CREDENTIAL_KEK`; no environment-variable reference; no catalog
  of Diagnostics codes or alert events; GAP-PKI-05 wording; the `auth_cr_no_credential_provider`
  message; `POST /api/authpolicy/killswitch` route metadata. Enterprise guides not
  re-audited.
