# ADR Proposal: MCP subsystem trust boundaries and separation from the SWG

> **This is an ADR _proposal_, not a numbered ADR.** Per [`OPEN-DECISIONS.md`](OPEN-DECISIONS.md) D-0
> (Option B), PR-0 is confined to `docs/design/mcp/`, so this proposal lives here in the standard
> six-section ADR format with `Status: Proposed`. **A human promotes it to a numbered, Accepted ADR under
> `docs/adr/NNNN-*` as a hard PR-1 entry gate** — that promotion is intentionally *not* performed by PR-0,
> because writing under `docs/adr/` is outside the PR-0 change boundary. When promoted, keep the section
> structure and flip Status to Accepted with a date and deciders.

- **Status:** Proposed (PR-0 proposal; to be promoted to a numbered ADR before PR-1)
- **Date:** 2026-07-24
- **Deciders:** Staff/Principal Engineer (proposer); Architecture Review Board + Security Architecture (to ratify)
- **Related:** ADR-0001 (record architecture decisions), ADR-0002 (flat `package main` → `internal/`), ADR-0007 (OpenAPI contract); the C1/C1.5/C2 admin-route metadata program; [`RECOMMENDED-ARCHITECTURE.md`](RECOMMENDED-ARCHITECTURE.md), [`THREAT-MODEL.md`](THREAT-MODEL.md)

## Context

Culvert is an enterprise SWG (HTTP/HTTPS/CONNECT/TLS-inspect/WebSocket/SOCKS5 forward proxy). The MCP
Agent Security Gateway program adds a **new** capability class: an identity/policy/credential/inspection
enforcement point between AI agents and MCP servers, plus a separate read-only Management MCP surface. The
repository was inspected at HEAD `c0ae2bca274ab8104c65abb629027b9acdb73f08` (default branch `main`,
verified); findings are recorded in [`VERIFIED-REPOSITORY-CONTEXT.md`](VERIFIED-REPOSITORY-CONTEXT.md).

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
new decision-event pipeline, and new CP→DP snapshot fields — so an ADR is mandatory.

## Decision

Adopt the following trust-boundary and separation decisions for the MCP subsystem. These are binding
design constraints for PR-1..PR-11.

1. **Separate runtime, separate listeners.** The MCP Security Gateway (Capability B) and the Management MCP
   (Capability A) run as **separate engines on their own listeners/ports**, distinct from the SWG proxy and
   SOCKS5 listeners and from each other. They share only Control-Plane services (admin UI shell/auth, RBAC
   framework, config publication/immutable snapshots, audit conventions/export infra, OpenAPI/CI/release).
2. **No reuse of the SWG `PolicyRule` or evaluator.** The MCP policy engine is a **separate schema** with a
   nine-action model and reason codes ([`MCP-POLICY-MODEL.md`](MCP-POLICY-MODEL.md)); it is a **pure,
   I/O-free** evaluator (MCP-POLICY-002). MCP fields are **never** added to the SWG `PolicyRule`.
3. **No reuse of the SWG OIDC flow as the generic MCP auth model.** MCP auth validates the bearer token's
   **audience = the MCP resource** and an RFC 8707 **resource indicator**, with net-new replay protection
   and separate OAuth clients/scopes for Management vs Gateway ([`AUTH-AND-CREDENTIAL-MODEL.md`](AUTH-AND-CREDENTIAL-MODEL.md)).
4. **No token passthrough; credential-broker isolation.** The client token terminates at the gateway; a
   distinct, scoped, short-lived upstream credential is selected **only after** a policy ALLOW-class
   decision. Agents never receive upstream credentials.
5. **No reuse of the audit ring as the decision-event pipeline.** MCP decision events use a **durable,
   backpressured, replay-addressable** pipeline with an explicit critical-event loss policy
   ([`EVENT-MODEL.md`](EVENT-MODEL.md)); the 500-entry audit ring is not production evidence.
6. **Signed, fenced CP→DP snapshots.** MCP configuration publishes as an immutable snapshot with epoch +
   config/policy/catalog/credential revisions + `minimum_dp_version` + **content-hash + signature**,
   validated whole and applied atomically, reusing the `halease`/`dpObserveEpoch` fencing and DP
   fail-static behavior ([`CP-DP-HA-MODEL.md`](CP-DP-HA-MODEL.md)).
7. **New inbound Origin/Host anti-rebinding control** for the MCP/SSE listener (MCP-INSP-008), which does
   not exist today.
8. **Package placement under `internal/mcp/*`**, consistent with ADR-0002, with the exact split evaluated
   (not adopted) in [`RECOMMENDED-ARCHITECTURE.md`](RECOMMENDED-ARCHITECTURE.md). Every new config field
   follows the config-surface anti-drift registry and GUI-parity mandate.

## Consequences

**Positive:**
- The SWG data path, `PolicyRule`, OIDC flow, and audit ring are untouched — no regression risk to the
  existing product (MCP-OPS-001).
- Clear separation enables independent threat models, rate limits, failure semantics and runbooks per
  capability, and multiple SKUs on one platform.
- Reuses mature primitives (SSRF peer-IP recheck, `halease` fencing, `configver` rollback, `internal/secret`
  KEK/provider, `internal/redaction`, `culvert_*` metrics, OpenAPI contract) without contaminating them.

**Negative / costs:**
- Net-new subsystems (protocol kernel, registry/catalog, identity, broker, policy, inspection, event
  pipeline) and net-new CI gates (malicious-server, OAuth-negative, DNS-rebinding, inbound Origin/Host,
  SSE-exhaustion, mixed-version/stale-epoch/corrupt-snapshot, MCP-off overhead).
- New signing scheme for snapshots (D-10) and net-new replay defense (D-2).
- Additional operational surface (two more listeners, a durable event spool).

**Risk if not adopted:** reusing SWG constructs would add MCP fields to `PolicyRule`, repurpose an
audience=client_id OIDC flow, and treat a 500-entry debug ring as audit evidence — each an explicit
blueprint red line and a GO/NO-GO NO-GO condition.

## Alternatives considered

1. **Extend the SWG `PolicyRule` and evaluator with MCP fields.** Rejected: incompatible schema and I/O
   during evaluation; violates the blueprint non-goal and the "no I/O during eval" requirement.
2. **Reuse the SWG OIDC proxy flow as the MCP auth model.** Rejected: audience = client_id, no RFC 8707,
   no replay defense; a machine bearer model needs resource-scoped, replay-protected tokens.
3. **Reuse the in-memory audit ring for decision events.** Rejected: bounded/best-effort; cannot guarantee
   critical-event durability.
4. **One generic policy schema shared by SWG, Management MCP and Gateway MCP.** Rejected: a maintainability
   and security failure (BLUEPRINT §03); the three have different trust boundaries and action models.
5. **Single shared listener multiplexing SWG and MCP.** Rejected: couples resource limits and failure
   semantics; the SWG dispatch (`proxy.go:794-913`) has no place to speak JSON-RPC/MCP.

## Promotion checklist (human, before PR-1)

- [ ] Assign a number `docs/adr/NNNN-mcp-trust-boundary.md` (next in sequence).
- [ ] Copy this content; set `Status: Accepted`, add ratification date + deciders.
- [ ] Reference it from the Technical Risk/Debt registers and the Engineering Dashboard (ADR-0001 practice).
- [ ] Record the promotion as satisfying the PR-1 entry gate in [`GO-NO-GO-CHECKLIST.md`](GO-NO-GO-CHECKLIST.md).
