# ADR-0024: MCP Agent Security Gateway — trust boundaries, separation from the SWG, and PR-1 entry decisions

- **Status:** Proposed (design decisions approved by the PR-0 facilitator on 2026-07-24; **awaiting formal ratification by the Architecture Review Board and Security Architecture** — see "Ratification" below). Do not treat as organizationally Accepted until that step is recorded.
- **Date:** 2026-07-24
- **Deciders:** Staff/Principal Engineer + Product Security Architect (proposer). **Ratifiers (pending):** Architecture Review Board (ARB) + Security Architecture, with domain approvers IAM/PAM (D-2), SRE/Security (D-5), Privacy/Legal + Network Security (D-8, D-9), Security Architecture (D-13).
- **Supersedes:** [`docs/design/mcp/ADR-PROPOSAL-mcp-trust-boundary.md`](../design/mcp/ADR-PROPOSAL-mcp-trust-boundary.md) (the in-package Option-B proposal, now a non-authoritative pointer to this ADR).
- **Related:** ADR-0001 (record architecture decisions), ADR-0002 (flat `package main` → `internal/`), [`docs/adr/0018-openapi-contract.md`](0018-openapi-contract.md) (OpenAPI contract — renamed on `main` from the former `ADR-0007-openapi-contract.md`); the C1/C1.5/C2 admin-route metadata program; the PR-0 design package under [`docs/design/mcp/`](../design/mcp/README.md).
- **Numbering:** `0024` is the **next free number across the repository-wide ADR/RFC allocation**, not merely "next in `docs/adr/`". As of `origin/main` `7791c706`, `docs/adr/` runs `0001–0018` (with legacy duplicate numbers at `0008`–`0011`); the OpenAPI-contract ADR was **renamed from the former `ADR-0007-openapi-contract.md` to [`docs/adr/0018-openapi-contract.md`](0018-openapi-contract.md)**, leaving `0007` solely the secret-containment ADR (`docs/adr/0007-secret-containment-boundary.md`). `docs/support/rfc/` holds `0012` and `0018`–`0022` (highest RFC `0022`). **`0023` is claimed by the unrelated Durable Configuration Publication ADR in open PR #854** (`docs/adr/0023-durable-config-publication.md`), wholly separate from MCP. This MCP ADR therefore takes **`0024`**, which is **unique across all `origin/main` refs and open PRs** (verified — no `0024` exists on `main`).

## Context

Culvert is an enterprise SWG (HTTP/HTTPS/CONNECT/TLS-inspect/WebSocket/SOCKS5 forward proxy). The MCP
Agent Security Gateway program adds a **new** capability class: an identity/policy/credential/inspection
enforcement point between AI agents and MCP servers (Capability B — MCP Security Gateway), plus a separate
read-only Management MCP surface (Capability A). The repository was inspected at HEAD
`c0ae2bca274ab8104c65abb629027b9acdb73f08` (default branch `main`); findings are recorded in
[`VERIFIED-REPOSITORY-CONTEXT.md`](../design/mcp/VERIFIED-REPOSITORY-CONTEXT.md). No MCP or JSON-RPC
listener exists in the inspected paths.

Key repository facts that force architectural decisions (all `[FACT]`, cited):
- The SWG `PolicyRule` (`policy.go:91-188`) is a network-destination selector with a four-verb action
  model (`policy.go:19-27`); it carries no tool/method/argument concepts.
- SWG policy evaluation performs DNS/disk I/O during a decision (`policy.go:1387`, `geoip.go:125-204`).
- The SWG OIDC flow binds audience to the OIDC `client_id` (`auth_oidc_flow.go:523`), has no RFC 8707
  resource indicator, and no bearer access-token replay defense (VRC §6).
- The in-memory audit ring is bounded (`internal/audit/audit.go:49`, `MaxRing=500`) and best-effort; every
  event sink (SSE, syslog, OTLP) sheds load by design.
- The CP→DP `ConfigSnapshot` (`controlplane_snapshot.go:22-112`) has epoch/version fields but no
  content-hash or signature; integrity rests on mTLS + epoch.

`ADR-0001` requires an ADR for any change to the proxy data path, the auth/authorization model, the
configuration/persistence model, the cluster/HA contract, or any cross-cutting invariant. The MCP program
introduces **new trust boundaries** — a new listener, a new bearer-auth surface, an outbound-fetch path, a
new decision-event pipeline, and new CP→DP snapshot fields — so an ADR is mandatory. This ADR is the
first such record and is a **hard PR-1 entry gate**.

## Decision

### Part 1 — Trust-boundary and separation constraints (binding for PR-1..PR-11)

1. **Separate runtime, separate listeners.** The MCP Security Gateway (Capability B) and the Management
   MCP (Capability A) run as **separate engines on their own listeners/ports**, distinct from the SWG
   proxy and SOCKS5 listeners and from each other. They share only Control-Plane services (admin UI
   shell/auth, RBAC framework, config publication/immutable snapshots, audit conventions/export infra,
   OpenAPI/CI/release).
2. **No reuse of the SWG `PolicyRule` or evaluator.** The MCP policy engine is a **separate schema** with a
   nine-action model and reason codes; it is a **pure, I/O-free** evaluator (MCP-POLICY-002). MCP fields
   are **never** added to the SWG `PolicyRule`.
3. **No reuse of the SWG OIDC flow as the generic MCP auth model.** See D-2 below. The SWG OIDC flow is
   reused only as implementation precedent for selected signature/expiry/issuer-validation primitives.
4. **No token passthrough; credential-broker isolation.** The client token terminates at the gateway; a
   distinct, scoped, short-lived upstream credential is selected **only after** a policy ALLOW-class
   decision. Agents never receive upstream credentials.
5. **No reuse of the audit ring as the decision-event pipeline.** See D-5 below.
6. **Signed, fenced CP→DP snapshots.** MCP configuration publishes as an immutable snapshot with epoch +
   config/policy/catalog/credential revisions + `minimum_dp_version` + **content-hash + signature**,
   validated whole and applied atomically, reusing the `halease`/`dpObserveEpoch` fencing and DP
   fail-static behavior. (Signing scheme selection is D-10, deferred to PR-10.)
7. **New inbound Origin/Host anti-rebinding control**, which does not exist today, split across two slices:
   the **pure Origin/Host validation primitive `MCP-INSP-008` ships in PR-1** (no listener), and the
   **listener that binds configured interfaces and enforces it end-to-end is `MCP-INSP-009` at PR-5**. This
   is independent of whether any DMZ model is ever offered (see D-9).
8. **Package placement under `internal/mcp/*`**, consistent with ADR-0002; the exact split/naming is
   evaluated (not adopted) in `RECOMMENDED-ARCHITECTURE.md`. Every new config field follows the
   config-surface anti-drift registry and GUI-parity mandate.

### Part 2 — Closed PR-1 entry decisions (D-2, D-5, D-8, D-9, D-13)

These five decisions were the blocking GO/NO-GO items required before PR-1. They are approved as follows.

#### D-2 — Authentication & authorization: Culvert as an OAuth protected resource server (Option A)

1. The client access token **terminates at Culvert and is never forwarded upstream** (MCP-AUTH-005).
2. The token's **effective OAuth audience MUST** identify the canonical Culvert MCP protected resource
   that receives the token:
   - Management MCP: the canonical resource URI for `/mcp/management`.
   - Gateway MCP: the canonical Culvert resource URI for `/mcp/gateway/{server-id}`, or an equivalent
     Culvert-controlled logical resource identifier approved by architecture review.

   That binding is established **through the authorization flow, not by a bespoke token claim**: Culvert's
   registered clients send `resource=<canonical Culvert resource URI>` on authorization/token requests
   (RFC 8707 §2) and Culvert publishes the same URI in its protected-resource metadata; Culvert then
   verifies the **resulting** restriction from standard metadata — `aud` for JWT access tokens (RFC 9068),
   or the introspection response's `aud`/resource metadata for opaque tokens (RFC 7662). Because RFC 8707
   `resource` is a *request* parameter, Culvert **MUST NOT** require a non-standard resource-indicator
   claim inside the token (that would break spec-compliant JWT and opaque tokens alike); an
   **unrestricted, `aud`-less token MUST NOT** authorize write/high-risk operations.
3. The client token **MUST NOT** use the upstream business MCP server as its recipient/audience. The
   approved upstream MCP server, tool and enterprise resource are **policy inputs and credential-broker
   scope attributes**. Culvert selects a separate upstream credential **only after** an ALLOW-class
   policy decision (MCP-POLICY-004 / MCP-CRED-001).
4. Management MCP and Gateway MCP **MUST** use separate OAuth client registrations, canonical resource
   identifiers and disjoint scope namespaces (MCP-AUTH-008).
5. **Option C is approved only as an issuer topology under Option A.** Enterprise IAM/PAM systems may
   issue Culvert-targeted tokens or workload identities, but Culvert remains the validating protected
   resource.
6. **Option B is not the primary model.** Any future token-exchange capability may only produce a
   short-lived Culvert-targeted token and requires a separate design review.
7. **Replay protection is NOT defined as one-time-use rejection of an access-token `jti`.** Reuse of a
   still-valid access token is not by itself evidence of replay.
8. The security posture (MCP-AUTH-006, corrected) instead requires: TLS on every request; short token
   lifetime; audience and resource restriction; issuer/signature/expiry/tenant/scope validation;
   introspection or revocation support where applicable; client/session correlation, rate limits and
   anomaly signals; and **sender-constrained tokens (mTLS or DPoP) for high-risk or externally reachable
   deployment profiles when supported**.
9. **When DPoP is used, replay detection applies to the per-request DPoP proof** (proof `jti`, HTTP
   method, URI, issue time, access-token hash `ath`, and server nonce where required). It **MUST NOT**
   treat the underlying access token as a one-time token.
10. The existing SWG OIDC implementation is precedent for selected signature, expiry and issuer-validation
    primitives only; it is **not** the MCP authentication model.

#### D-5 — Durable decision-event architecture: local encrypted durable spool + pluggable export (Option C)

Every relevant Data Plane has a **mandatory local encrypted, bounded, durable spool** with bounded queues,
backpressure and replay identifiers. An external message bus or SIEM is an **additive adapter/exporter** —
**never a substitute** for the local spool and not a mandatory runtime dependency (the spool is required even
when an exporter is configured). Durability-unavailable semantics are fixed by action class (MCP-EVENT-002);
for the critical write classes, fail-closed **and** degraded-mode-with-alert are **both** required:

| Action class | Behavior when a decision event cannot be durably persisted |
|---|---|
| Read-only / low-risk ALLOW or MONITOR | May proceed **only** when an explicit degraded-mode policy permits it; raise a health alarm; increment an integrity-protected loss/degradation counter; keep retrying persistence/export within bounded budgets; **never fail silently**. |
| Write action | **Fail closed AND** enter degraded mode + alert + integrity-protected loss counter. |
| Destructive / production action | **Fail closed AND** degraded mode + alert + loss counter. |
| Configuration publication | **Fail closed AND** degraded mode + alert — do not publish a configuration change without a durable change event. |
| Credential issue / rotation / revoke / selection for a high-risk operation | **Fail closed AND** degraded mode + alert + loss counter. |
| State-affecting Management MCP operation | **Fail closed AND** degraded mode + alert (and such operations remain out of V1 regardless — see D-13). |
| Authentication failure or authorization denial | The request is **already denied** — this is **not** relabeled as an additional "fail closed" action. If the denial event cannot be persisted, enter a **critical degraded state**, alert, increment integrity-protected loss counters, and **block new write/high-risk allowed operations until critical-event durability is restored**, unless an explicitly approved emergency policy states otherwise. |

The in-memory audit ring (`MaxRing=500`), SSE hub, syslog queue and best-effort OTLP exporters are **not**
the durable decision-event pipeline. The PR-8 design **MUST** specify: event-ordering scope, deduplication,
replay cursor, encryption at rest, corruption recovery, tenant isolation, retention, disk-pressure
behavior, and restart/failover recovery.

#### D-8 — On-prem outbound connector: Model A only in V1; Model B is a post-V1 slice

**Model A (local enterprise client)** over customer-controlled LAN, VPN, VDI or private-platform
connectivity is the **only supported V1 connectivity model**. The outbound-only connector (Model B) is an
**explicitly designed post-V1 roadmap extension**, subject to:

1. The connector is **not** assigned to PR-11. PR-11 remains Shadow/Canary per the accepted slice plan.
2. The connector receives its **own future implementation slice and design gate after V1**, unless a
   human-approved roadmap change explicitly renumbers the slices.
3. No ChatGPT, Claude or other-vendor integration is claimed supported until a named integration has been
   verified against **authoritative, date-stamped vendor requirements** and tested.
4. The future connector must be customer-initiated, tenant-bound, mTLS-identified, revocable,
   certificate-rotating, bounded and observable (MCP-CONNECT-001/002/004).
5. The connector **must not store or receive production upstream credentials** (MCP-CRED-004).
6. DLP, redaction and destination policy execute before approved content leaves the customer environment
   (MCP-PRIVACY-001).
7. Failure, reconnection, proxy, HA, upgrade and incident-response behavior remain design requirements,
   not implemented capabilities.

#### D-9 — Hardened DMZ endpoint: not supported in V1, disabled by default

A publicly routable or externally reachable hardened DMZ MCP endpoint (Model C) is **not supported in V1
and is disabled by default**.

1. The local-client deployment model is **sufficient for V1**. The future outbound connector does not need
   to exist before the first local-client production model.
2. Future DMZ support requires a **separate architecture and production-readiness approval**, signed
   customer risk acceptance, OAuth, reverse proxy, WAF, rate limits, DDoS controls, internal mTLS,
   monitoring and dedicated incident runbooks (MCP-CONNECT-003).
3. **Host validation and configured-host allowlisting are mandatory for every HTTP MCP listener** (not
   DMZ-only).
4. Origin validation follows the supported MCP protocol baseline: validate the `Origin` header on incoming
   Streamable HTTP connections; reject a present-but-invalid Origin with the protocol-required HTTP
   response; **do not invent a blanket requirement that every non-browser client must always send an
   Origin header** unless the selected protocol version explicitly requires it.
5. Local deployment **must bind only to explicitly configured interfaces**; it must not default to
   unrestricted public ingress.
6. Inbound Origin/Host protection (MCP-INSP-008) remains a **PR-1 Protocol Kernel requirement** even though
   public DMZ exposure is deferred.

#### D-13 — Management MCP scope: read-only + draft/validate/simulate; mutation excluded from V1

V1 Management MCP is limited to read-only operations plus draft, validate and simulate **without
activation** (MCP-MGMT-001).

- **V1 permitted:** explain a policy decision; inspect bounded effective configuration; compare desired vs
  actual state; query bounded health information; query bounded, redacted security-event summaries;
  validate policy syntax/semantics; simulate policy impact; generate a draft that cannot activate itself.
- **V1 prohibited:** configuration activation; policy publication; credential issue/rotation/revoke or
  secret retrieval; raw trace export; arbitrary log export; arbitrary command execution; service restart;
  cluster mutation; node removal; certificate replacement; emergency-bypass creation; any other
  state-changing management operation (MCP-MGMT-003).

Isolation requirements:

1. Management MCP and Gateway MCP have **separate endpoint/listener ownership**.
2. They have **separate OAuth clients, resource identifiers, scopes, policy namespaces, rule bundles,
   quotas, audit categories, threat models and runbooks**.
3. They **may share reviewed implementation libraries and selected Control-Plane infrastructure**.
4. They **may use the same underlying durable event transport only when events are separated by
   authorization domain, tenant, category, partitioning, retention and query policy**.
5. Two entirely separate **physical** event systems are **not** required when logical and security
   isolation is enforceable and tested.
6. They may share a policy-engine **implementation library**, but **must not** share active policy state,
   rule bundles, namespaces or authorization decisions.
7. Management outputs must be tenant-scoped, RBAC-controlled, paginated, redacted, size-bounded and
   time-bounded (MCP-MGMT-002/004).
8. Management **mutation remains post-V1** and requires a separate plan → validate → approve → apply
   architecture decision.

## Consequences

**Positive:**
- The SWG data path, `PolicyRule`, OIDC flow, and audit ring are untouched — no regression risk to the
  existing product (MCP-OPS-001).
- Clear separation enables independent threat models, rate limits, failure semantics and runbooks per
  capability, and multiple SKUs on one platform.
- Reuses mature primitives (SSRF peer-IP recheck, `halease` fencing, `configver` rollback,
  `internal/secret` KEK/provider, `internal/redaction`, `culvert_*` metrics, OpenAPI contract) without
  contaminating them.
- The corrected D-2 replay posture avoids a false sense of security from access-token `jti` one-time-use
  and instead pins replay defense to sender-constraint (DPoP-proof / mTLS) for high-risk/external profiles.
- D-5's fail-closed matrix makes critical-event durability a design invariant, not an operational hope.

**Negative / costs:**
- Net-new subsystems (protocol kernel, registry/catalog, identity, broker, policy, inspection, event
  pipeline) and net-new CI gates (malicious-server, OAuth-negative, DNS-rebinding, inbound Origin/Host,
  SSE-exhaustion, mixed-version/stale-epoch/corrupt-snapshot, MCP-off overhead).
- New signing scheme for snapshots (D-10) and net-new sender-constraint/replay defense (D-2).
- Additional operational surface (two more listeners, a durable event spool).
- The outbound connector (D-8) and any DMZ model (D-9) are deferred, so cloud-AI clients without a local
  path are unserved in V1 — an accepted commercial trade-off.

**Risk if not adopted:** reusing SWG constructs would add MCP fields to `PolicyRule`, repurpose an
audience=client_id OIDC flow, and treat a 500-entry debug ring as audit evidence — each an explicit
blueprint red line and a GO/NO-GO NO-GO condition.

## Alternatives considered

1. **Extend the SWG `PolicyRule` and evaluator with MCP fields.** Rejected: incompatible schema and I/O
   during evaluation; violates the blueprint non-goal and the "no I/O during eval" requirement.
2. **Reuse the SWG OIDC proxy flow as the MCP auth model (D-2).** Rejected: audience = client_id, no
   RFC 8707, no replay/sender-constraint; a machine bearer model needs resource-scoped, sender-constrained
   tokens.
3. **D-2 Option B (Culvert-issued/exchanged token) as primary.** Rejected: makes Culvert a token issuer
   with key-rotation, revocation and offline-DP-validation burden; retained only as an edge token-exchange
   feeding Option A.
4. **D-2 replay defense via access-token `jti` one-time-use.** Rejected: a still-valid token replaying is
   not itself evidence of replay; sender-constraint (DPoP proof / mTLS) is the correct control.
5. **D-5 Option A (local spool, no export) or Option B (mandatory external bus).** Rejected: A under-serves
   SIEM integration; B forces a hard external runtime dependency on every customer and violates DP
   fail-static autonomy. Option C (spool + pluggable export) chosen.
6. **D-8 assign the connector to PR-11 / D-8 support Model C in V1.** Rejected: PR-11 stays Shadow/Canary;
   the connector is a post-V1 slice; DMZ is deferred (D-9).
7. **D-9 support a DMZ endpoint in V1.** Rejected: only model with public ingress; Model A (+ future B)
   covers the realistic V1 deployment space without it.
8. **D-13 controlled mutation in V1.** Rejected: mutation requires the full plan→validate→approve→apply
   control set first; V1 is read-only + draft/validate/simulate.
9. **One generic policy schema shared by SWG, Management MCP and Gateway MCP.** Rejected: a maintainability
   and security failure; the three have different trust boundaries and action models.
10. **Single shared listener multiplexing SWG and MCP.** Rejected: couples resource limits and failure
    semantics; the SWG dispatch (`proxy.go:794-913`) has no place to speak JSON-RPC/MCP.

## PR-1 entry gate

PR-1 (Protocol Kernel) may begin only when **all** of the following hold:

1. This ADR is **Accepted** under `docs/adr/` (ARB + Security Architecture ratification recorded — see
   "Ratification"). Until then it is `Proposed` and the gate is **not** satisfied.
2. `PR0-REVIEW-CHECKLIST.md` is signed by all roles.
3. The Scope, Architecture, Dual-surface (D-13), Identity (D-2), Events (D-5) and Connectivity (D-8, D-9)
   domain gates are GO with no hard NO-GO line tripped ([`GO-NO-GO-CHECKLIST.md`](../design/mcp/GO-NO-GO-CHECKLIST.md)).
4. Every blocking decision due at PR-1/PR-3 has a named owner.
5. **D-1 (supported MCP protocol-version baseline and compatibility policy) is externally verified and
   human-approved.** Because PR-1 *is* the Protocol Kernel — parser, lifecycle, transport and
   compatibility behavior depend directly on D-1 — D-1 **must not** be left for closure during
   implementation.
6. The **current repository build and test baseline is run and recorded** before any PR-1 code change
   begins (the PR-0 session did not run it — VRC §11).

This ADR closes **D-2, D-5, D-8, D-9, D-13**. **D-1** remains open and is elevated to a hard PR-1 entry
gate (item 5). **D-3, D-4, D-6, D-10, D-12** remain slice-scoped; **D-7, D-11** remain post-V1 / GA. **D-14**
(concrete protocol-kernel limit values + batch policy) is added slice-scoped to PR-1 — the `MCP-PROTO-*`
requirements are defined; only their numeric values are open.

**PR-1 Protocol-Kernel scope (post-remediation).** The PR-1 attack surface — MCP parser, JSON-RPC framing,
version adapters and protocol state — is modeled by threats **MCP-T-057..074**, bounded by requirements
**MCP-PROTO-001..014**, and gated by blocking PR-1 fuzz + structural/differential/protocol-state suites plus
a **D-1-gated** compatibility gate (see `THREAT-MODEL.md`, `SECURITY-REQUIREMENTS.md`, `CI-GATES.md`, and
`PR1-READINESS-REMEDIATION.md`). Item 8's `internal/mcp/*` decision ratifies the **namespace and boundary**;
the exact leaf-package names remain `[REC]`, subject to implementation review (not fixed by this ADR).

## Ratification

This ADR is created as `Status: Proposed`. To move to `Accepted`, record here: the ratification date, the
named ARB and Security Architecture approvers, and confirmation that the domain approvers (IAM/PAM for D-2,
SRE/Security for D-5, Privacy/Legal + Network Security for D-8/D-9, Security Architecture for D-13) have
signed. Per ADR-0001 practice, reference this ADR from the Technical Risk/Debt registers and the
Engineering Dashboard on acceptance. Do not claim organizational approval that has not occurred.
