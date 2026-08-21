# ADR-0024: MCP Agent Security Gateway — trust boundaries, separation from the SWG, and PR-1 entry decisions

- **Status:** Accepted (2026-07-31). The accepted architecture baseline is the merged repository state — this ADR, the `docs/design/mcp/` package, the predicates, and the CI gates that enforce them. See "Acceptance" below.
- **Date:** 2026-07-24 (decided); 2026-07-31 (accepted).
- **How decided:** developed through independent, isolated AI architecture and security reviews plus adversarial red-team review, with every decision reduced to a recorded requirement, threat, config surface, or predicate. There is no external Architecture Review Board, Security Architecture team, IAM/PAM team, SRE team, or Privacy team in this project; it is developed by the repository owner using independent AI research, adversarial review, structural predicates, and CI. The domain labels retained below (identity, events, connectivity, dual-surface) name the *review lens*, not an organizational sign-off.
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

   **Binding structural constraint (added by the board-blocker remediation for
   [#927](https://github.com/KidCarmi/Culvert/issues/927); strategy decision `D-15`; owning requirement
   `MCP-CFG-001`).** The sentence above asserts coverage the tooling does not currently provide:
   `config_surfaces_test.go` hard-codes a three-type inventory (`configBackup`, `AdminSettings`,
   `ConfigSnapshot`) and reflects **one level deep**, so an unenumerated or nested MCP config struct is
   invisible to forward and reverse parity, while `redactUnenrolledSnapshot` zeroes only rows flagged
   `Sensitive`. This ADR therefore binds the implementation to **both** of the following:

   - **(a) Enumeration is mandatory and total.** *Every* MCP configuration structure — including every
     nested struct, at any depth — **MUST** be enumerated in the anti-drift inventory and **MUST** have
     complete registry semantics (`Sensitive`, Export/Import, Rollback, AdminDurable, `AppliesOnDP`,
     `WireWipeCapable`, validation, snapshot capture/apply). **An implementation that introduces a
     nested MCP config struct which the parity inventory does not enumerate violates this ADR**, and is
     not made conformant by the struct's fields individually appearing in the config matrix.
   - **(b) The parity machinery must actually reach what (a) enumerates.** Nested/dotted field paths,
     nested slice/map cap parity, and nested wire-wipe ⇔ `omitempty` parity **MUST** be covered before
     the first MCP config field ships. Satisfying (b) by the **flat mandate** — one top-level struct
     field and one registry row per logical MCP setting, no nested MCP config struct — is an acceptable
     and explicitly permitted way to discharge it; satisfying it by **extending the parity machinery to
     recurse** (the `D-15` Option A recommendation) is the preferred route. What is **not** permitted is
     a nested struct with a one-level-deep checker: that combination is the defect this constraint
     exists to forbid.

   Conformance is evidenced by the anti-omission gates in
   [`CI-GATES.md`](../design/mcp/CI-GATES.md), which **MUST** fail for *both* omission cases — a new
   field in an already-enumerated type, **and** an entirely new or nested MCP config type. A gate that
   catches only the first case does not discharge this constraint.

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
   claim inside the token (that would break spec-compliant JWT and opaque tokens alike). An **absent
   audience is rejected for EVERY operation class** — not merely write/high-risk — because a token with no
   verifiable audience cannot be shown to target Culvert at all (fail closed; the unconditional form of
   MCP-AUTH-002).
3. The client token **MUST NOT** use the upstream business MCP server as its recipient/audience. The
   approved upstream MCP server, **the protocol method and its operation class**, tool and enterprise
   resource are **policy inputs and credential-broker scope attributes** — the authorization tuple is keyed
   on the **method/operation**, not tool identity alone (**tool name is one operand type, not the universal
   key**; #928, MCP-PROTO-016). Culvert selects a separate upstream credential **only after** an ALLOW-class
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

**Ordering precondition:** for every class below whose behavior is **fail closed**, the decision event **MUST be
durably committed BEFORE THAT CLASS'S OWN irreversible action** — per the table below: the upstream call; the
snapshot **sign/push/apply**, including a **rollback swap**; broker **materialization** (mint/rotate/revoke); the
Management **state change and the signed snapshot it publishes**; the operation runs only after that commit is confirmed. Phrasing this as "before
credential use and the upstream call" would leave configuration publication and the Management class
unconstrained, since neither performs an upstream call — the precondition must name each class's own side effect. Evaluated after execution, "fail closed" is unimplementable — the side effect has already happened.
The outcome event is emitted separately afterwards and is not the gate (MCP-EVENT-002, MCP-T-044).

**The irreversible action is class-specific, and each class is gated at its own** — gating only "the upstream
call" leaves configuration publication and credential mutation ungated, because neither makes one:

| Class | Its irreversible action | Commit must precede | Absence assertion in the test |
|---|---|---|---|
| Write / destructive | the upstream call | the call | no upstream call occurred **AND no broker-side materialization occurred** (DFD-5 gates both at `WAL`) |
| Configuration publication | signing / pushing / applying the snapshot | `SIGN` (DFD-10) | no revision created, nothing signed or pushed, every DP on the prior epoch |
| Credential issue / rotate / revoke / high-risk selection | broker-side **materialization** (mint / rotate / revoke) | materialization — **planning may precede it** | broker credential state unchanged **AND no upstream call occurred** (DFD-5 gates both at `WAL`) |
| State-affecting Management operation | the state change **and the publication it produces** | the change **and** the snapshot being signed / pushed / applied (DFD-3 `WALM`) | no Management state change **AND no revision created, nothing signed or pushed, every DP on the prior epoch** |

**The assertion set is per FLOW, not per class NAME.** A class's case **MUST** assert the absence of **every**
irreversible action reachable downstream of that flow's commit gate, not only the action the class is named
after: an approved Management mutation both changes Management state **and** publishes a signed snapshot
(DFD-3), and the Gateway gate precedes **both** credential materialization and the upstream call (DFD-5).
Asserting only the eponymous action passes an implementation that leaves that one record untouched while
performing the other.

**A confirmed commit, not an enqueue.** Queue admission is not durability: a full disk, an `fsync` error or an
encryption-key failure is a commit FAILURE and must fail closed exactly as saturation does.

| Action class | Behavior when the decision event cannot be durably persisted |
|---|---|
| Read-only / low-risk `ALLOW` or `MONITOR` | May proceed **only** when an explicit degraded-mode policy permits it; raise a health alarm; increment an **integrity-protected loss/degradation counter**; keep retrying persistence/export within bounded budgets; **never fail silently**. |
| Write action | **Fail closed** (deny the operation) **AND** enter `critical-durability-degraded` **scoped to the affected durability domain only** + alert + integrity-protected loss counter. |
| Destructive / production action | **Fail closed AND** enter `critical-durability-degraded` **scoped to the affected durability domain only** + alert + loss counter. |
| Configuration publication | **Fail closed AND** enter `critical-durability-degraded` **scoped to the affected durability domain only** + alert — do not publish a configuration change without a durable change event. |
| Credential issue / rotation / revoke / selection for a high-risk operation | **Fail closed AND** enter `critical-durability-degraded` **scoped to the affected durability domain only** + alert + loss counter. |
| State-affecting Management MCP operation | **Fail closed AND** enter `critical-durability-degraded` **scoped to the affected durability domain only** + alert (and out of V1 regardless — see ADR-0024 §D-13). |
| Authentication failure **or** authorization denial | The request is **already denied** — this is **not** relabeled as an additional "fail closed" action. These events are **attacker-mintable**, so they **MUST NOT** enter `critical-durability-degraded` and **MUST NOT** block any authenticated operation. They travel the **separate denial lane**: pre-queue admission control → attacker-rate-independent coalescing → the denial partition `P-DEN`, which **MUST NOT** consume the reserved critical partition `P-CRIT`. If the coalesced aggregate cannot be committed, enter **`denial-lane-degraded`** for that capability on that node only, alert, increment a **distinct** integrity-protected denial-loss counter, and **continue rejecting** the request. **No fleet-wide, cross-tenant or cross-capability lockout, and no emergency-policy bypass.** |

**Degradation is CONTAINED, and a denial event can never widen it (amendment — MCP-T-075).** The original
form of the denial row made an **unauthenticated** attacker the trigger of a **fleet-wide write lockout**:
mint auth failures faster than the spool commits them, and every allowed write across the estate stops. The
control was reachable by the one actor it was meant to produce evidence about, so it converted an
evidence-integrity mechanism into a denial-of-service amplifier. Two separate mechanisms now replace it, and
they must not be recombined:

1. **Authenticated critical-operation commit failure** — the triggering operation still **fails closed before
   its own irreversible action** (unchanged, non-negotiable), and the runtime enters
   `critical-durability-degraded` **only in the narrow durability domain that could have lost the evidence**.
   The **maximum automatic domain** is `(one node / DP runtime) × (one MCP capability) × (the affected durable
   critical partition)`. Management and Gateway degradation states are **independent**; one tenant, listener or
   capability **MUST NOT** automatically block another; and **fleet-wide escalation is not a protocol or
   runtime side effect** — any broader action is a separately authorized incident-response decision by a human.
2. **Authentication failures and authorization denials** — the attacker-mintable class — use the **denial
   lane** described in the row above and in [`EVENT-MODEL.md`](../design/mcp/EVENT-MODEL.md) §4b, with its own
   quota, its own partition and its own degraded state. It can exhaust **only itself**.

**Three logically separate partitions** are required, even when one physical encrypted spool or transport is
shared: `P-CRIT` (authenticated critical decision events, with **reserved capacity denial traffic cannot
consume**), `P-ORD` (ordinary authenticated events) and `P-DEN` (coalesced unauthenticated / authorization-denial
aggregates). Reclamation is deterministic and priority-ordered — `P-DEN` before `P-ORD` before `P-CRIT`, and
**unexported critical records are never reclaimed while any lower-priority record remains**. The bounded sizes,
reserve, watermarks, retention, rotation and recovery-probe interval are configuration rows in
[`CONFIG-SURFACE-MATRIX.md`](../design/mcp/CONFIG-SURFACE-MATRIX.md); the normative state machine
(`normal` → `denial-lane-degraded` / `critical-durability-degraded` → `recovering`), its bounded exit criteria
and its **restart persistence** are [`EVENT-MODEL.md`](../design/mcp/EVENT-MODEL.md) §4b.

**There is NO emergency-policy escape hatch, and V1 instantiates no bypass configuration.** The former
"unless an explicitly approved emergency policy states otherwise" clause is **deleted**, not relocated: it
offered an operator under active attack a switch whose only effect was to disable the evidence guarantee at
exactly the moment evidence mattered most, and it was never needed once the attacker-mintable class stopped
being able to trigger a lockout at all. **Recovery means restoring durable event commitment** and satisfying
the §4b exit criteria — never disabling the control. No hidden or unnamed break-glass path exists.

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
6. Inbound Origin/Host defence remains required even though public DMZ exposure is deferred, and it is
   **split across two layers** (Part 1 item 7):
   - the **validation primitive** (`MCP-INSP-008`) is a **PR-1 Protocol Kernel requirement** — a pure,
     listener-independent decision function, unit-tested without a socket; and
   - the actual **listener-side enforcement/protection** (`MCP-INSP-009`) is **PR-5**: binding only
     configured interfaces (the only accept-time obligation), enforcing the host allowlist **per request / per HTTP/2
     stream after header parsing** — never once per connection, since `Host`/`:authority`/`Origin` do not exist at
     accept time and keep-alive/H2 multiplexing carry many requests per connection — and **end-to-end** rebinding proof
     against a running listener.

   **PR-1 binds no listener, so this item is NOT satisfied by PR-1 alone** — the inbound rebinding threats
   (MCP-T-031/055, and MCP-T-052 for any future DMZ) close only when `MCP-INSP-009` ships. Reserve the words
   "protection" and "enforcement" for `MCP-INSP-009`.

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
- D-5's per-action durability matrix (**fail closed AND** degrade+alert for the critical classes; **critical degraded
  state, scoped to ONE durability domain**, with the attacker-mintable auth-failure/authz-denial class isolated in its own
  non-blocking denial lane) makes critical-event durability a design invariant, not an operational hope — and one that an
  unauthenticated attacker cannot turn into an outage.

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

1. This ADR is **Accepted** under `docs/adr/` (recorded above and in "Acceptance"). **Satisfied.**
2. The PR-0 role-evidence review is complete — the eight review lenses in
   [`PR0-REVIEW-CHECKLIST.md`](../design/mcp/PR0-REVIEW-CHECKLIST.md) each point to concrete documents,
   RPRs, tests, or independent-verification evidence (no human role signatures are required — see #923
   Gate 2). **Satisfied.**
3. The Scope, Architecture, Dual-surface (D-13), Identity (D-2), Events (D-5) and Connectivity (D-8, D-9)
   domain gates are GO with no hard NO-GO line tripped ([`GO-NO-GO-CHECKLIST.md`](../design/mcp/GO-NO-GO-CHECKLIST.md)).
4. Every blocking decision due at PR-1/PR-3 has a named owner.
5. **D-1 (supported MCP protocol-version baseline and compatibility policy) is CLOSED** with the V1
   baseline recorded in [`OPEN-DECISIONS.md`](../design/mcp/OPEN-DECISIONS.md) §D-1,
   [`PROTOCOL-COMPATIBILITY.md`](../design/mcp/PROTOCOL-COMPATIBILITY.md),
   [`TRANSPORT-FALLBACK-EVIDENCE.md`](../design/mcp/TRANSPORT-FALLBACK-EVIDENCE.md) and
   [`PR1-ENTRY-CLOSURE.md`](../design/mcp/PR1-ENTRY-CLOSURE.md): primary `2025-11-25`, compatibility floor
   `2025-06-18`, every other revision (incl. `2024-11-05`, `2025-03-26`, `2026-07-28`) rejected; Remote
   Streamable HTTP only (no stdio, no legacy HTTP+SSE); batch rejected; the six-method admitted surface of
   [`MCP-OPERATION-REGISTRY.md`](../design/mcp/MCP-OPERATION-REGISTRY.md). **Satisfied.**
6. **D-15 (MCP config-surface registry integration) is CLOSED** — implementation contract accepted;
   `MCP-CFG-001` and the config-surface matrix are authoritative (OPEN-DECISIONS §D-15). **Satisfied.**
7. The **current repository build and test baseline is re-anchored to current `main`** and recorded in
   #923 Gate 4 and [`PR1-ENTRY-CLOSURE.md`](../design/mcp/PR1-ENTRY-CLOSURE.md). **Satisfied.**

This ADR closes **D-2, D-5, D-8, D-9, D-13**; **D-1** and **D-15** are now CLOSED (the two hard PR-1 entry
gates — see [`OPEN-DECISIONS.md`](../design/mcp/OPEN-DECISIONS.md)). **D-3, D-4, D-6, D-10, D-12** remain
slice-scoped; **D-7, D-11** remain post-V1 / GA. **D-14** (concrete protocol-kernel limit values + batch
policy) is added slice-scoped to PR-1 — the `MCP-PROTO-*` requirements are defined and batch is rejected in
V1; only the numeric limit values are open.

**PR-1 Protocol-Kernel scope (post-remediation).** The PR-1 attack surface — MCP parser, JSON-RPC framing,
version adapters and protocol state — is modeled by threats **MCP-T-057..074** (plus RPR-1 **MCP-T-076/077**),
bounded by requirements **MCP-PROTO-001..016**, and gated by blocking PR-1 fuzz +
structural/differential/protocol-state suites plus a **D-1-gated** compatibility gate. **The kernel is
peer-role parameterized (one decoder for BOTH the client-facing and upstream-server-facing legs; #925,
MCP-PROTO-015) with requestor-scoped `(session, direction, id)` correlation, and admits methods only from
the Culvert-reviewed [`MCP-OPERATION-REGISTRY.md`](../design/mcp/MCP-OPERATION-REGISTRY.md), not the raw
negotiated-version method set (#928, MCP-PROTO-016).** (See `THREAT-MODEL.md`, `SECURITY-REQUIREMENTS.md`,
`CI-GATES.md`, and `PR1-READINESS-REMEDIATION.md`.) Item 8's `internal/mcp/*` decision ratifies the **namespace and boundary**;
the exact leaf-package names remain `[REC]`, subject to implementation review (not fixed by this ADR).

## Acceptance

This ADR is **Accepted** as of 2026-07-31. Acceptance rests on the merged repository state, not on an
organizational sign-off:

- The design decisions were developed through **independent, isolated AI architecture and security
  reviews** and **adversarial red-team review**. This project has no external ARB, Security Architecture,
  IAM/PAM, SRE, or Privacy organization; those labels name review lenses, not approvers.
- All **five board blockers** ([#925](https://github.com/KidCarmi/Culvert/issues/925),
  [#926](https://github.com/KidCarmi/Culvert/issues/926),
  [#927](https://github.com/KidCarmi/Culvert/issues/927),
  [#928](https://github.com/KidCarmi/Culvert/issues/928),
  [#929](https://github.com/KidCarmi/Culvert/issues/929)) were **remediated and independently verified**,
  and are closed as completed.
- **RPR-1 through RPR-4** (the four-PR remediation plan covering those blockers) are **complete**.
- **D-1** (protocol baseline) and **D-15** (config-surface registry integration) — the two hard PR-1 entry
  decisions — are **CLOSED** (see [`OPEN-DECISIONS.md`](../design/mcp/OPEN-DECISIONS.md)).
- Implementation must satisfy the recorded requirements (`MCP-*`), the structural **predicates**
  ([`predicates/`](../design/mcp/predicates/README.md), enforced by the required Fast PR Gate), and the CI
  gates ([`CI-GATES.md`](../design/mcp/CI-GATES.md)).

No separate signature block is required, and none is implied. Per ADR-0001 practice, this ADR is referenced
from the closure record [`PR1-ENTRY-CLOSURE.md`](../design/mcp/PR1-ENTRY-CLOSURE.md) and the PR-1 entry
tracker [#923](https://github.com/KidCarmi/Culvert/issues/923).
