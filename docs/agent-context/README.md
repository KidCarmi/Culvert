# Task routes and evidence

Use the route matching the changed behavior, including callers at repository root.
Read current code/tests first, the relevant ADR/operator contract next, and the
specific historical failure cases before changing their behavior. Historical
blocks contain still-important invariants and rejected alternatives: their label
is a warning to reconcile them, not permission to ignore them. No route claims
that every paragraph in its history bucket is current or fully re-audited.

For unknown ownership, use the [preserved project map](history/project-map.md)
as a search aid, then verify paths in the checkout. Avoid stale package counts.
Current [conventions](conventions.md) reconcile the [original conventions](history/conventions.md).
For checks use [verification](workflows/verification.md); for an explicit review
use [review-change](workflows/review-change.md). Source paths below are relative
to this checkout, not to an unmerged branch.

## Core admission and connections

- IPFilter, RateLimiter, `admission.go`, `security.go`, `cluster_ratelimit*`,
  snapshot/startup/restore callers: [current admission contract](domains/admission.md),
  [scoped guide](../../internal/admission/AGENTS.md),
  [package contract](../../internal/admission/doc.go),
  [ADR-0039](../adr/0039-admission-engine-package.md).
- Connection-count acquire/release is a distinct owner:
  [internal/connlimit](../../internal/connlimit) and
  [sharding rationale](history/admission-and-connection-limits.md#claude-main-l240-l240).
- [Admission history](history/admission-and-connection-limits.md) includes
  freshness, raw-string exemptions, differential controls and bulk publication.
  It also contains the [DP→CP audit queue](history/admission-and-connection-limits.md#claude-main-l182-l182)
  and [cross-domain performance overview](history/admission-and-connection-limits.md#claude-main-l238-l238).
  Do not confuse these with MCP execution admission or listener fairness below.

## Admin API and configuration mutations

- Root `ui*.go`, `cdr_ui.go`, `pac.go`, `diagnostics.go`, `store.go`,
  `configversion.go` and legacy UI: [admin contract](domains/admin-control-plane.md).
- Current [route metadata](../../ui_routes_meta.go),
  [delegated-role tests](../../ui_routes_meta_delegation_test.go),
  [surface registry](../../config_surfaces.go) and
  [OpenAPI contract](../../api/openapi/openapi.yaml) determine the affected contract.
- [Admin history](history/admin-control-plane.md) preserves all eight invariants,
  governance severity/counter semantics and global-test pitfalls. Apply
  [current versioning exceptions](conventions.md#ui-configuration-and-api-changes),
  not the old blanket snapshot instruction. Existing
  [versioning triage](../../roadmap/CONFIG-VERSIONING-TRIAGE.md) is rationale;
  its old inventory is not an authoritative current capture list.

## Authentication and identity

- `auth*`, `session*`, `ui_auth*`, `ui_session*`, `ui_rbac*`, credential/roster/TOTP
  mutations in `store.go`: inspect [store.go](../../store.go),
  [session owner](../../internal/session), [auth-state owner](../../internal/authstate),
  [credential-cost owner](../../internal/authcost) and the corresponding tests.
- LDAP: [ADR-0027](../adr/0027-ldap-first-class-idp.md),
  [auth_ldap_provider.go](../../auth_ldap_provider.go) and
  [directory implementation](../../auth_ldap.go). Internal directory transport
  deliberately differs from generic public outbound-HTTP URL validation.
- [Authentication history](history/authentication-and-identity.md): username bounds,
  durable roster writes, default authentication, IdP/JWKS availability, callback
  fairness, audit identity and session behavior. For credential changes read the
  [TOTP preservation block](history/authentication-and-identity.md#claude-main-l226-l226)
  and [password no-version test](../../auth_password_change_no_versioning_test.go).

## Proxy, policy and scanning

- Forwarding, CONNECT/SOCKS5, destination bounds, tracing, TLS/CA/OCSP and tunnels:
  [proxy.go](../../proxy.go), [proxy_http.go](../../proxy_http.go),
  [proxy_tunnel.go](../../proxy_tunnel.go), [socks5.go](../../socks5.go),
  [destination bounds](../../proxy_host_bounds.go), [internal/ca](../../internal/ca),
  [internal/ocsp](../../internal/ocsp). Use the matching tests and
  [proxy/TLS history](history/proxy-tls-and-certificates.md), including raw attacker
  log bytes, hop-by-hop stripping, no-redirect forwarding and fail-open/closed boundaries.
  See also [transport/relay cost context](history/admission-and-connection-limits.md#claude-main-l238-l238).
- Policy, GeoIP/DNS, category/blocklist/threat feeds: [policy.go](../../policy.go),
  [host/category composition](../../policy_hostcat.go), [geoip.go](../../geoip.go),
  [internal/urlcat](../../internal/urlcat), [internal/blocklist](../../internal/blocklist),
  [internal/threatfeed](../../internal/threatfeed), [internal/feedsched](../../internal/feedsched).
  [Policy/feed history](history/policy-category-feeds.md) carries lookup, freshness,
  DNS and warming constraints. Check [default-policy errata](errata.md#default-policy-posture).
- Scanning, remote/local body budget, error posture and regex/DPI: inspect
  [internal/secscan](../../internal/secscan), [internal/scanner](../../internal/scanner),
  [scanner.go](../../scanner.go), [scan capacity runbook](../operator/scan-capacity-and-timeouts.md)
  and [scanning history](history/scanning.md).

## Lifecycle, storage and observability

- `main*`, `*_startup*`, listener health, optional SOCKS5/admin bind, hijacked-tunnel
  drain: [shutdown owner](../../internal/shutdown),
  [ADR-0037](../adr/0037-shutdown-registry-package-isolation.md),
  [main_shutdown.go](../../main_shutdown.go),
  [graceful shutdown](../operator/graceful-shutdown.md),
  [startup/listener history](history/startup-shutdown-listeners.md).
  Main owns budgets and real hooks; optional-listener failure must not become a
  new primary data-plane termination path.
- Persistence, storage recovery, audit/request/process logs: inspect
  [internal/storeguard](../../internal/storeguard), [internal/audit](../../internal/audit),
  [internal/reqlog](../../internal/reqlog), [internal/logsink](../../internal/logsink),
  [internal/logstore](../../internal/logstore) and [storage history](history/storage-and-durability.md).
  For DP→CP audit loss also read
  [the shared freshness/audit block](history/admission-and-connection-limits.md#claude-main-l182-l182):
  `trimPendingLocked`/`PendingDrops`, oldest-unsent loss and local-versus-central trail.
- `logger*`, `metrics*`, `alerts*`, tracing, syslog, per-minute/top-host counters:
  [internal/obs](../../internal/obs), [internal/alerts](../../internal/alerts),
  [internal/syslog](../../internal/syslog), [metrics.go](../../metrics.go),
  [store.go](../../store.go), [observability history](history/observability-and-alerts.md)
  and [cross-domain performance context](history/admission-and-connection-limits.md#claude-main-l238-l238).
- Support collection/exports/redaction/consent:
  [ADR-0028](../adr/0028-supportability-framework-collector-model.md),
  [ADR-0029](../adr/0029-support-source-side-redaction.md),
  [ADR-0030](../adr/0030-support-privileged-host-collection.md),
  [ADR-0031](../adr/0031-support-export-consent-and-trust.md),
  [support runbook](../operator/support-bundles-and-diagnostics.md),
  [support history](history/support-and-redaction.md). Verify the source-side
  redaction and collection authority before broadening an export.

## Appliance (on-prem OVA)

- OVA build, first-boot provisioning and OS maintenance: [appliance/](../../appliance),
  with design and evidence under [docs/appliance](../appliance) (readiness report,
  matrices, runbooks) and Docker-driven qualification in
  [test/e2e/appliance](../../test/e2e/appliance).
- Restore commit on a mount-point `/data` (journaled in-place swap, explicit
  `--recover-restore`, data-dir lock): [restore_inplace.go](../../restore_inplace.go).
- Supported-predecessor floor and transition refusals:
  [release_transition_policy.go](../../release_transition_policy.go); durable
  dispatch record and resume (never re-applies):
  [release_dispatch_persist.go](../../release_dispatch_persist.go).
- First-admin claim protection (`CULVERT_SETUP_TOKEN`, header
  `X-Culvert-Setup-Token`): [setup_token.go](../../setup_token.go).
  Boot policy posture (`CULVERT_DEFAULT_ACTION`): see
  [default-policy errata](errata.md#default-policy-posture). AV-fault posture
  (`CULVERT_AV_UNAVAILABLE`): [errata](errata.md#body-scan-fault-posture).
- `/ready` and `/health` distinguish services running, setup complete and ready
  to enforce (report-only `setup_complete` and `policy_posture` rows; gating
  under `?strict=1`): [healthcheck.go](../../healthcheck.go).

## Configuration, cluster and delivery

- Config snapshots/versioning, rewrite, upstream transports/credentials,
  node groups and bandwidth: [config_surfaces.go](../../config_surfaces.go),
  [configversion.go](../../configversion.go), [internal/upstream](../../internal/upstream),
  [upstream_transport.go](../../upstream_transport.go),
  [configuration/upstream history](history/configuration-and-upstream.md).
- CP/DP wire/snapshot/enrollment/HA: [controlplane_snapshot.go](../../controlplane_snapshot.go),
  [cluster CA](../../cluster_ca_validity.go), [internal/halease](../../internal/halease),
  [cluster/HA history](history/cluster-and-ha.md). Config application also crosses
  the admission, auth, persistence and MCP contracts; follow those affected routes.
- Release catalog signatures/trust/freshness, image pinning, installer/bootstrap,
  maintenance: [release_wiring.go](../../release_wiring.go),
  [maintenance module](../../cmd/culvert-maint),
  [release publication contract](../operator/release-publication-gating.md),
  [maintenance design](../../roadmap/D1.6-maintenance-agent-design.md),
  [release/maintenance history](history/release-and-maintenance.md).
  Transport origin is not trust; preserve signed identity, offline restore,
  sudo/image-boundary and untrusted-host-input constraints.
- CI `.github/workflows`/`.github/scripts`, toolchain, coverage and publication:
  [CI redesign](../../roadmap/CI-REDESIGN.md),
  [Fast gate](../../.github/workflows/pr-fast-gate.yml),
  [Deep gate](../../.github/workflows/pr-deep-gate.yml),
  [coverage-floor implementation](../../.github/scripts/coverage-floor.sh),
  [CI history](history/ci-and-release.md). Read current workflow predicates;
  documentation and old PR statuses do not prove today's gates passed.
  The [original build/test examples](history/build-and-test.md) are retained as
  provenance; choose current commands from the verification workflow.
- Startup/run environment lookup: [config.go](../../config.go),
  [data_dir.go](../../data_dir.go), [go.mod](../../go.mod),
  [preserved run/environment reference](history/run-and-environment.md).
  Verify defaults and read-once behavior in the relevant resolver.

## Frontend

`frontend/`, `ui_frontend_v2.go`, `static/index.html`, OpenAPI generated clients:
[frontend migration](../design/FRONTEND-MIGRATION-PLAN.md),
[security contract](../design/FRONTEND-SECURITY-CONTRACT.md),
[platform ADR](../adr/ADR-FE-001-frontend-platform.md),
[package scripts](../../frontend/package.json),
[verification workflow](../../.github/workflows/frontend-verify.yml),
[embedded serving](../../ui_frontend_v2.go),
[original project map](history/project-map.md#claude-main-l006-l091).
Respect generated-output checks, legacy-versus-experimental route separation,
CSP and API/GUI parity. Follow admin/auth routes for the corresponding backend.

## MCP and policy learning

- MCP gateway/management/distribution/rollout: [ADR-0024](../adr/0024-mcp-agent-security-gateway-trust-boundary.md),
  [design contracts](../design/mcp), [internal/mcp](../../internal/mcp),
  [MCP history](history/mcp-gateway.md). Do not collapse isolated capabilities
  or activate disabled surfaces as a side effect of guidance work.
- MCP execution admission: [execution owner](../../internal/mcp/execution),
  [auxiliary admission tests](../../internal/mcp/execution/auxiliary_admission_test.go),
  [ADR-0035](../adr/0035-mcp-canary-execution-architecture.md). Discovery/lifecycle
  can be auxiliary without bypassing lifecycle admission or slot release;
  unclassified methods remain metered. This is not core IP rate limiting.
- MCP listener fairness: [ADR-0033](../adr/0033-mcp-admission-fairness.md);
  distinguish accepted design from still-open implementation/operator work.
- Policy learning: [ADR-0025](../adr/0025-policy-learning-advisory-boundary.md),
  [internal/policylearn](../../internal/policylearn),
  [learning history](history/policy-learning.md). Preserve advisory/activation
  boundaries and confirm current enablement rather than assuming history shipped.

## Governance

Architecture advice: [Engineering Constitution](../engineering/ENGINEERING-CONSTITUTION.md),
[dashboard](../engineering/ENGINEERING-DASHBOARD.md),
[risk register](../engineering/TECHNICAL-RISK-REGISTER.md),
[debt register](../engineering/TECHNICAL-DEBT-REGISTER.md),
[ADR practice](../adr/0001-record-architecture-decisions.md).
[Governance/roadmap history](history/governance-and-roadmaps.md) is navigation
and chronology, not a requirement to load every planning document.

## Historical source inventory

[Preservation map](preservation-map.json) assigns every original byte to exactly
one block owner. Multiple routes can and should reference the same block.
[Errata](errata.md) records verified conflicts without rewriting the source.
[Migration and validation](migration.md) records what has actually been checked.
[Vendor research and design](research.md) explains the rationale and limits.

- [admin control plane](history/admin-control-plane.md)
- [admission and connection limits](history/admission-and-connection-limits.md)
- [architecture index](history/architecture-index.md)
- [authentication and identity](history/authentication-and-identity.md)
- [build and test](history/build-and-test.md)
- [ci and release](history/ci-and-release.md)
- [cluster and ha](history/cluster-and-ha.md)
- [configuration and upstream](history/configuration-and-upstream.md)
- [conventions](history/conventions.md)
- [governance and roadmaps](history/governance-and-roadmaps.md)
- [mcp gateway](history/mcp-gateway.md)
- [observability and alerts](history/observability-and-alerts.md)
- [policy category feeds](history/policy-category-feeds.md)
- [policy learning](history/policy-learning.md)
- [project map](history/project-map.md)
- [proxy tls and certificates](history/proxy-tls-and-certificates.md)
- [release and maintenance](history/release-and-maintenance.md)
- [run and environment](history/run-and-environment.md)
- [scanning](history/scanning.md)
- [startup shutdown listeners](history/startup-shutdown-listeners.md)
- [storage and durability](history/storage-and-durability.md)
- [support and redaction](history/support-and-redaction.md)
