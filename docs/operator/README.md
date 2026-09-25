# Operator documentation index

This directory holds Culvert's operator-facing runbooks and reference guides — one
file per subsystem, each written as the operator contract for that subsystem
(what it does, how to configure it, how it fails, how to recover it). It has no
narrative order, so this index exists purely for discovery: find the subsystem,
follow the link.

For the product-level overview, quick start, and feature list, start at the
repository [`README.md`](../../README.md) instead — it links directly to the
runbook for anything it calls out as needing operator attention. For the
underlying design/engineering record behind a given behavior (ADRs, chaos-
engineering sweeps, technical registers), see `CLAUDE.md`'s Architecture Notes
and `docs/engineering/`.

## Install, upgrade, and release management

- [`catalog-bootstrap-install-runbook.md`](catalog-bootstrap-install-runbook.md) — catalog-driven fresh install: operator inputs, fallback matrix, release-cutover checklist, identity-rotation runbook.
- [`release-management-agent.md`](release-management-agent.md) — wiring Release Management to the maintenance agent, the sole day-2 update path (no Docker socket).
- [`release-publication-gating.md`](release-publication-gating.md) — how a release becomes publishable and what blocks it.
- [`enterprise-release-catalog-plan.md`](enterprise-release-catalog-plan.md) — the release-catalog trust design (signing, freshness, rollback); historical plan doc, superseded sections are marked inline.
- [`catalog-hosting-r2-activation.md`](catalog-hosting-r2-activation.md) — activating Cloudflare R2 as the release-catalog origin.
- [`catalog-resign-runbook.md`](catalog-resign-runbook.md) — the weekly catalog re-sign pipeline (M1-4) and how to recover it.
- [`sigstore-trusted-root-lifecycle.md`](sigstore-trusted-root-lifecycle.md) — keyless (Sigstore-identity) catalog signature verification and trusted-root rotation.
- [`feeds-hosting-r2-activation.md`](feeds-hosting-r2-activation.md) — activating the public SaaS URL-category feed origin (`feeds.culvertlabs.com`).
- [`docker-compose-backup-restore.md`](docker-compose-backup-restore.md) — backup, restore, and cleanup via the profile-gated `cli` compose service.
- [`support-bundles-and-diagnostics.md`](support-bundles-and-diagnostics.md) — collecting redacted support bundles and running on-appliance diagnostics.

## Cluster and high availability

- [`ha-lease-failover.md`](ha-lease-failover.md) — automatic HA failover backed by an etcd fencing lease (ADR-0005).
- [`ha-lease-recovery.md`](ha-lease-recovery.md) — recovering a fencing lease that could not be reacquired (denied promotion, denied resume, self-fence).
- [`cluster-ca-expiry.md`](cluster-ca-expiry.md) — cluster (enrollment) CA expiry and the resulting control-plane trust outage.
- [`cluster-config-capacity.md`](cluster-config-capacity.md) — CP→DP config-sync capacity limits and operations.
- [`cluster-rate-limit-freshness.md`](cluster-rate-limit-freshness.md) — how cluster-wide rate limiting degrades during a Control Plane outage.

## Authentication and identity

- [`identity-backend-availability.md`](identity-backend-availability.md) — LDAP / OIDC / JWKS backend availability, caching, and fail-closed behavior.
- [`ldap-identity-provider.md`](ldap-identity-provider.md) — configuring LDAP / Active Directory as an identity provider.
- [`ldap-directory-stalls.md`](ldap-directory-stalls.md) — what happens when a directory accepts a connection and then stops answering.
- [`credential-verification-cost.md`](credential-verification-cost.md) — the bounded credential-verification governor and the `auth_verify_saturated` alert.
- [`admin-login-input-bounds.md`](admin-login-input-bounds.md) — why the admin login endpoint bounds the submitted username, and what it protects.

## TLS inspection, certificates, and decryption

- [`root-ca-expiry.md`](root-ca-expiry.md) — root (inspection) CA expiry and the resulting SSL-inspection outage.
- [`decryption-profiles.md`](decryption-profiles.md) — configuring decryption (SSL inspection) profiles.
- [`decryption-auto-exclusions.md`](decryption-auto-exclusions.md) — the adaptive, fail-open decryption-exclusion cache and its tunables.
- [`http2-inspection.md`](http2-inspection.md) — native HTTP/2 SSL inspection.
- [`ocsp-revocation-checking.md`](ocsp-revocation-checking.md) — what OCSP revocation checking covers, how it fails, and how to read its counters.
- [`key-at-rest.md`](key-at-rest.md) — key-at-rest encryption for stored secrets and CA material.

## Networking and traffic steering

- [`upstream-proxies.md`](upstream-proxies.md) — parent-proxy chaining (upstream proxies): identity, credentials, and eligibility.
- [`pac-traffic-steering.md`](pac-traffic-steering.md) — PAC-based traffic steering.
- [`socks5-listener-health.md`](socks5-listener-health.md) — SOCKS5 listener accept-loop health, backoff, and degradation reporting.
- [`admin-ui-listener-recovery.md`](admin-ui-listener-recovery.md) — why an admin-UI listener failure never takes down the data plane, and how it recovers.
- [`dns-resolution-health.md`](dns-resolution-health.md) — destination-host DNS resolution health, bounding, and recovery.
- [`geoip-resolution-health.md`](geoip-resolution-health.md) — GeoIP policy resolution health and the warmer that backs it.
- [`traffic-log-destination-privacy.md`](traffic-log-destination-privacy.md) — controlling how much destination detail lands in traffic logs.

## Security scanning and threat intelligence

- [`scan-capacity-and-timeouts.md`](scan-capacity-and-timeouts.md) — content-scan (ClamAV/YARA/remote sidecar) capacity, timeouts, and posture.
- [`threat-feed-freshness.md`](threat-feed-freshness.md) — threat-feed sync cadence, staleness detection, and recovery.
- [`threat-feed-domain-allowlist.md`](threat-feed-domain-allowlist.md) — managing the threat-feed domain allowlist.
- [`policy-learning-mode.md`](policy-learning-mode.md) — Policy Learning Mode: observation, aggregation, and recommendation generation.

## Storage and recovery

- [`category-store-recovery.md`](category-store-recovery.md) — community category store corruption detection and recovery.
- [`request-history-recovery.md`](request-history-recovery.md) — request-history store corruption, encryption, and recovery.
- [`graceful-shutdown.md`](graceful-shutdown.md) — the shutdown envelope, its phases, and what a stall costs.
- [`tunnel-drain-on-shutdown.md`](tunnel-drain-on-shutdown.md) — draining long-lived tunnels (WebSocket, SOCKS5, CONNECT) on shutdown.
- [`secure-upload.md`](secure-upload.md) — secure upload of support bundles to TAC.

## MCP Agent Security Gateway (ADR-0024, disabled by default)

Operator runbooks:

- [`mcp-rollout-durable-state.md`](mcp-rollout-durable-state.md) — rollout durable state and the Shadow transition mechanics.
- [`mcp-shadow-activation.md`](mcp-shadow-activation.md) — controlled MCP Shadow activation.
- [`mcp-qualification-inventory.md`](mcp-qualification-inventory.md) — the Gateway Qualification tool/server inventory (QUAL-2).
- [`mcp-qualification-policy.md`](mcp-qualification-policy.md) — Gateway Observe qualification policy (QUAL-4).
- [`mcp-qualification-telemetry.md`](mcp-qualification-telemetry.md) — Gateway Qualification telemetry (QUAL-3).
- [`mcp-observe-acceptance-harness.md`](mcp-observe-acceptance-harness.md) — the Observe acceptance test harness (QUAL-6).
- [`mcp-observe-acceptance-runbook.md`](mcp-observe-acceptance-runbook.md) — running the Observe acceptance harness.
- [`mcp-observe-acceptance-decisions.md`](mcp-observe-acceptance-decisions.md) — the Observe acceptance decision worksheet.
- [`examples/README.md`](examples/README.md) — copyable Observe acceptance inputs, including the [`mcp-observe-acceptance-authoritative.json`](examples/mcp-observe-acceptance-authoritative.json) specification template.
- [`mcp-tool-trust-approvals.md`](mcp-tool-trust-approvals.md) — MCP tool-trust approvals (ADR-0034).

Point-in-time rollout evidence and review reports (historical record of a specific
rollout stage, not living reference docs — kept for audit trail):

- [`mcp-first-controlled-canary-review.md`](mcp-first-controlled-canary-review.md)
- [`mcp-shadow-first-controlled-run-report.md`](mcp-shadow-first-controlled-run-report.md)
- [`mcp-shadow-soak-report.md`](mcp-shadow-soak-report.md)
- [`mcp-shadow-exit-review-report.md`](mcp-shadow-exit-review-report.md)
- [`mcp-shadow-exit-gap-closure-report.md`](mcp-shadow-exit-gap-closure-report.md)

See `docs/design/mcp/` for the ADR-0024 trust-boundary/threat-model design and
`docs/adr/0024-mcp-agent-security-gateway-trust-boundary.md` for the ADR itself.
