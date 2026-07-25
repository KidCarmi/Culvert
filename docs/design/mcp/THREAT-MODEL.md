# MCP Security Gateway — Threat Model

Scope: the Culvert MCP Security Gateway (Capability B) and the Culvert Management MCP Server
(Capability A), as separate trust boundaries sharing selected Control-Plane services. This document is
the **canonical threat-ID registry** (`MCP-T-###`) for the PR-0 package;
[`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md), [`ABUSE-CASES.md`](ABUSE-CASES.md),
[`ATTACK-TREES.md`](ATTACK-TREES.md) and [`TEST-TRACEABILITY-MATRIX.md`](TEST-TRACEABILITY-MATRIX.md)
reference these IDs.

**Status:** PR-0 design artifact. This is a **design-time** threat model; no control below is claimed as
implemented. Repository facts are cited from [`VERIFIED-REPOSITORY-CONTEXT.md`](VERIFIED-REPOSITORY-CONTEXT.md).

---

## 1. Assets

| ID | Asset | Why it matters |
|---|---|---|
| A-1 | Upstream production credentials (broker-held) | Direct access to enterprise systems; must never reach the agent. |
| A-2 | Client/agent bearer tokens | Authenticate the caller to Culvert; theft enables impersonation. |
| A-3 | Policy bundle + reason-code semantics | Determines what is allowed; tampering changes enforcement. |
| A-4 | Tool catalog + fingerprints | Distinguishes approved tools from drift/poisoning. |
| A-5 | Server registry (endpoints, TLS identity, ownership) | Defines approved destinations. |
| A-6 | Decision events (durable audit) | Investigation, compliance, non-repudiation. |
| A-7 | CP→DP configuration snapshot | Fleet-wide source of enforcement truth. |
| A-8 | Approval state | Human-in-the-loop authorization for high-risk actions. |
| A-9 | Enterprise data in tool arguments/responses | PII, secrets, production data crossing the gateway. |
| A-10 | Tenant isolation boundary | Prevents cross-customer/cross-tenant access. |
| A-11 | Management MCP capabilities | Control over Culvert's own configuration. |
| A-12 | Outbound connector / DMZ endpoint identity | The on-prem ↔ cloud trust link. |

## 2. Actors

| Actor | Trust | Notes |
|---|---|---|
| Legitimate human principal | Semi-trusted | Delegates actions; may be socially engineered. |
| Managed agent / workload | Semi-trusted | Autonomous; may be compromised or buggy. |
| AI client / application | Semi-trusted | Hosts the agent; token holder. |
| External attacker | Untrusted | Steals tokens, hosts malicious MCP servers, probes endpoints. |
| Malicious/compromised MCP server | Untrusted | May poison tools, rug-pull, exfiltrate, or emit injection. |
| Malicious insider / over-eager admin | Partially trusted | May expand policy without review. |
| Cloud AI service | External processor | Processes approved content under customer contract. |

## 3. Assumptions

- Culvert runs inside the customer environment; the request path does not depend on a Control-Plane
  round-trip per call (**[FACT]** DP fail-static: `controlplane_snapshot.go · applyDPLastGoodConfigSnapshot · 981-997`).
- TLS/mTLS terminates at Culvert; upstream identity is verifiable.
- The SWG data path and the MCP subsystem are **separate listeners/engines** (**[REC]**; no shared
  listener — [`RECOMMENDED-ARCHITECTURE.md`](RECOMMENDED-ARCHITECTURE.md)).
- Pattern-based inspection is best-effort, not a guarantee (residual risk R-2).
- The customer owns the server allowlist, connectivity model and data-flow classification.

## 4. Trust boundaries

| TB | Boundary | Primary concerns |
|---|---|---|
| TB-1 | Agent/client ↔ Culvert MCP listener | Token validation, Origin/Host, protocol bounds, rate limits. |
| TB-2 | Culvert ↔ upstream MCP server | mTLS/TLS identity, SSRF/DNS, credential isolation, allowlist. |
| TB-3 | Control Plane ↔ Data Planes | Signed snapshot, epoch/fencing, whole-snapshot validation. |
| TB-4 | Runtime ↔ event/export | Redaction, durability, bounded queues, loss policy. |
| TB-5 | Admin ↔ policy publication | RBAC, four-eyes, simulation, audit. |
| TB-6 | Cloud AI ↔ customer network | Connector identity, tenant binding, data residency. |
| TB-7 | Management MCP ↔ Culvert control surface | Separate scopes, read-only default, plan/validate/approve/apply. |

## 5. Entry points

E-1 MCP gateway listener `/mcp/gateway/{server-id}` · E-2 Management listener `/mcp/management` ·
E-3 SSE/streaming channel · E-4 Admin API + GUI · E-5 CP→DP snapshot channel · E-6 outbound
connector/DMZ ingress · E-7 credential-provider integration · E-8 event export.

## 6. Data flows

See [`DATA-FLOW-DIAGRAMS.md`](DATA-FLOW-DIAGRAMS.md) (15 numbered DFDs; DFD-15 — the PR-1 protocol-kernel
decode path — added by the remediation). STRIDE-per-flow in §9 references those DFD numbers (DFD-1 … DFD-15).

## 7. Risk-rating methodology

Severity = f(Impact, Likelihood), each rated Low/Medium/High.

- **Impact:** Critical = production write, credential exposure, cross-tenant, or critical-event loss;
  High = data exfiltration or availability loss; Medium = single-tenant degradation; Low = cosmetic.
- **Likelihood:** High = reachable by a remote unauthenticated/low-privilege actor with known technique;
  Medium = requires some position/precondition; Low = requires insider or chained preconditions.
- **Rating band:** `Critical` (Impact Critical & Likelihood ≥ Medium), `High`, `Medium`, `Low`.
- **Closure:** a threat is *closed* when it maps to ≥1 requirement, ≥1 control, ≥1 test with an evidence
  expectation, and an accountable owner; residual risk is explicitly accepted by the owner.

## 8. STRIDE per component

| Component | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| Protocol Kernel / Listener | MCP-T-069 | MCP-T-058,068 | — | MCP-T-060 | MCP-T-042,043,044,063,073,074 | MCP-T-066,067 |
| Identity Resolver | MCP-T-006,007,008 | MCP-T-003,004 | MCP-T-009 | — | — | MCP-T-030 |
| Server Registry | MCP-T-020 | MCP-T-016 | — | — | — | MCP-T-016 |
| Tool Catalog | MCP-T-011,012 | MCP-T-013,014,015 | — | — | — | MCP-T-017 |
| Policy Engine | — | MCP-T-019 | MCP-T-046 | — | — | MCP-T-018,031 |
| Credential Broker | MCP-T-024 | — | — | MCP-T-005,023,025 | MCP-T-024 | MCP-T-022 |
| Inspection Pipeline | MCP-T-038 | — | — | MCP-T-026,027,036,041 | MCP-T-040 | MCP-T-018 |
| Decision Event Pipeline | MCP-T-045 | MCP-T-045 | MCP-T-045 | MCP-T-028 | MCP-T-044 | — |
| CP→DP snapshot | MCP-T-049 | MCP-T-047,050 | — | — | — | MCP-T-047 |
| Management MCP | MCP-T-034 | MCP-T-034 | — | MCP-T-035 | — | MCP-T-034 |
| Connector / DMZ | MCP-T-051 | MCP-T-052 | — | MCP-T-053 | MCP-T-042 | MCP-T-051 |

*(S=Spoofing, T=Tampering, R=Repudiation, I=Info-disclosure, D=DoS, E=Elevation.)*

> **Protocol-Kernel row corrected by the PR-1 remediation (`PR1-READINESS-REMEDIATION.md`, finding M-4).**
> The row previously listed threats owned by other components (`MCP-T-005` credential/identity, `MCP-T-013`
> tool-catalog, `MCP-T-036` egress, `MCP-T-041` redirect). Those are now attached where their control is
> enforced (`MCP-T-005` → Credential Broker; `MCP-T-013` already on Tool Catalog; `MCP-T-036`/`MCP-T-041` →
> Inspection Pipeline). The kernel row now carries only threats native to parsing/framing/version/protocol-
> state, whose controls are the new `MCP-PROTO-*` requirements: T (differential) = `MCP-T-058/068`,
> I (mis-correlation) = `MCP-T-060`, D (parse-time exhaustion + listener DoS) = `MCP-T-063/073/074` (+ the
> listener-half SSE/queue DoS `MCP-T-042/043/044`, gated PR-5), S (session/state confusion) = `MCP-T-069`,
> E (version downgrade/unknown-version) = `MCP-T-066/067`.

## 9. STRIDE per flow (DFD cross-reference)

| DFD | Flow | Dominant STRIDE threats |
|---|---|---|
| DFD-1 | Mgmt read-only request | MCP-T-034, MCP-T-035, MCP-T-010, **MCP-T-031, MCP-T-055** (inbound rebinding / cross-origin, validated per request by MCP-INSP-009) |
| DFD-2 | Mgmt draft/validate | MCP-T-034, MCP-T-046, **MCP-T-031, MCP-T-055** (inbound rebinding / cross-origin, validated per request by MCP-INSP-009) |
| DFD-3 | Future mgmt mutation approval | MCP-T-034, MCP-T-032, MCP-T-033 |
| DFD-4 | Gateway tool discovery | MCP-T-011..017, MCP-T-020 |
| DFD-5 | Gateway tool call | MCP-T-003..008, MCP-T-019, MCP-T-046 |
| DFD-6 | Credential selection | MCP-T-022..025 |
| DFD-7 | Input inspection | MCP-T-026, MCP-T-036, MCP-T-037, MCP-T-041 |
| DFD-8 | Output inspection | MCP-T-027, MCP-T-038, MCP-T-039 |
| DFD-9 | Decision event publication | MCP-T-028, MCP-T-044, MCP-T-045 |
| DFD-10 | CP→DP snapshot publication | MCP-T-047..050 |
| DFD-11 | Rollback | MCP-T-047, MCP-T-048 |
| DFD-12 | Local enterprise client connectivity | MCP-T-036, MCP-T-037, MCP-T-030 |
| DFD-13 | Outbound-only connector | MCP-T-051, MCP-T-052, MCP-T-053 |
| DFD-14 | Hardened DMZ endpoint | MCP-T-036, MCP-T-042, MCP-T-051 |
| DFD-15 | Protocol-kernel decode path (PR-1) | MCP-T-057..074 (parser/framing/version/state) |

## 10. Security objectives

O-1 No production credential reaches an agent · O-2 No token passthrough; audience/resource validated ·
O-3 Unknown/changed tools never auto-allow · O-4 Deterministic, explainable, default-deny decisions ·
O-5 Critical decision events are never silently lost · O-6 No cross-tenant/cross-user confusion ·
O-7 Bounded resources under hostile load · O-8 CP/DP integrity (no split-brain, no stale/corrupt apply) ·
O-9 Management MCP cannot escalate to unreviewed mutation · O-10 Data residency is explicit and enforced
before egress.

## 11. Risk register (canonical threat IDs)

Controls reference requirement IDs from [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md); tests
reference [`TEST-TRACEABILITY-MATRIX.md`](TEST-TRACEABILITY-MATRIX.md). Owner = accountable role.

### Identity, token & tenancy

| ID | Threat | Sev | Primary controls (req IDs) | Owner |
|---|---|---|---|---|
| MCP-T-001 | Token theft | High | MCP-AUTH-001,004,006 | IAM/Sec |
| MCP-T-002 | Token replay | High | MCP-AUTH-006 (net-new; **NOT VERIFIED as present** per §6 VRC) | IAM/Sec |
| MCP-T-003 | Wrong audience | High | MCP-AUTH-002 | IAM/Sec |
| MCP-T-004 | Wrong resource (RFC 8707) | High | MCP-AUTH-003 | IAM/Sec |
| MCP-T-005 | Token passthrough | Critical | MCP-AUTH-005, MCP-CRED-001 | IAM/Sec |
| MCP-T-006 | Agent impersonation | High | MCP-ID-002,005 | IAM/Sec |
| MCP-T-007 | Workload impersonation | High | MCP-ID-003,005 | IAM/Sec |
| MCP-T-008 | Cross-user session confusion | High | **MCP-ID-008** (one resolved identity per session, no mid-flight rebind — the enforcing control), MCP-AUTH-007, MCP-ID-006 (assurance/step-up, contributory only) | IAM/Sec |
| MCP-T-009 | Cross-tenant confusion | Critical | MCP-ID-007, MCP-PRIVACY-002 | IAM/Sec |
| MCP-T-010 | Tenant-binding failure | Critical | **MCP-ID-007** (every session incl. LAN/VPN-local — the **V1/Model-A** control, PR-3) + MCP-CONNECT-004 (connector/DMZ sessions only — PR-C / Future DMZ gate) | IAM/Sec |

### Tool discovery & drift

| ID | Threat | Sev | Controls | Owner |
|---|---|---|---|---|
| MCP-T-011 | Tool poisoning | High | MCP-TOOL-001,004 | Sec/Eng |
| MCP-T-012 | Tool shadowing | Medium | MCP-TOOL-002 | Sec/Eng |
| MCP-T-013 | Tool schema drift | High | MCP-TOOL-003,004 | Sec/Eng |
| MCP-T-014 | Tool description drift | Medium | MCP-TOOL-003,005 | Sec/Eng |
| MCP-T-015 | Rug pull | High | MCP-TOOL-004,006 | Sec/Eng |
| MCP-T-016 | Server identity change | High | MCP-SERVER-002,003 | Sec/Eng |
| MCP-T-017 | Unknown tool auto-allow | Critical | MCP-TOOL-006, MCP-POLICY-001 | Sec/Eng |

### Policy & authorization

| ID | Threat | Sev | Controls | Owner |
|---|---|---|---|---|
| MCP-T-018 | Policy bypass | High | MCP-POLICY-001,002,005 | Sec/Eng |
| MCP-T-019 | Privilege expansion | High | MCP-TOOL-004, MCP-POLICY-003 | Sec/Eng |
| MCP-T-046 | Confused deputy | High | MCP-POLICY-004, MCP-CRED-002 | Sec/Eng |

### Credentials

| ID | Threat | Sev | Controls | Owner |
|---|---|---|---|---|
| MCP-T-022 | Over-privileged credentials | High | MCP-CRED-002,003 | IAM/PAM |
| MCP-T-023 | Credential leakage | Critical | MCP-CRED-004, MCP-EVENT-003 | IAM/PAM |
| MCP-T-024 | Credential-cache compromise | High | MCP-CRED-005,006 | IAM/PAM |
| MCP-T-025 | Scope mismatch not rejected | High | MCP-CRED-002 | IAM/PAM |

### Network egress

| ID | Threat | Sev | Controls | Owner |
|---|---|---|---|---|
| MCP-T-036 | SSRF | High | MCP-INSP-004, MCP-SERVER-001 | Sec/Eng |
| MCP-T-037 | DNS rebinding | High | MCP-INSP-005 | Sec/Eng |
| MCP-T-041 | Redirect abuse | Medium | MCP-INSP-006 | Sec/Eng |
| MCP-T-030 | Private-network access | High | MCP-INSP-004,005 | Sec/Eng |

### Data & secrets

| ID | Threat | Sev | Controls | Owner |
|---|---|---|---|---|
| MCP-T-026 | Data exfiltration (input) | High | MCP-INSP-001,003 | Sec/Privacy |
| MCP-T-027 | Data exfiltration (output) | High | MCP-INSP-002,003 | Sec/Privacy |
| MCP-T-028 | Secret leakage into events/logs | Critical | MCP-EVENT-003, MCP-CRED-004 | Sec/Privacy |

### Server trust

| ID | Threat | Sev | Controls | Owner |
|---|---|---|---|---|
| MCP-T-020 | Malicious MCP server | High | MCP-SERVER-001,002 | Sec/Eng |
| MCP-T-021 | Compromised approved server | High | MCP-SERVER-003, MCP-TOOL-004, MCP-INSP-002 | Sec/Eng |
| MCP-T-029 | Destructive calls | High | MCP-POLICY-006, MCP-INSP-001 | Sec/Eng |

### Approval

| ID | Threat | Sev | Controls | Owner |
|---|---|---|---|---|
| MCP-T-032 | Approval phishing | Medium | MCP-POLICY-007 | Product Sec |
| MCP-T-033 | Approval ambiguity | Medium | MCP-POLICY-007 | Product Sec |

### Injection

| ID | Threat | Sev | Controls | Owner |
|---|---|---|---|---|
| MCP-T-038 | Prompt/tool injection | Medium | MCP-INSP-007 | Sec/Eng |
| MCP-T-039 | Untrusted elicitation | Medium | MCP-INSP-007, MCP-POLICY-007 | Sec/Eng |

### Availability

| ID | Threat | Sev | Controls | Owner |
|---|---|---|---|---|
| MCP-T-040 | Oversized payloads | High | **MCP-PROTO-006/008** (parse-time structural + per-session bounds — the control that rejects an oversized frame, **PR-1**, before any listener exists), MCP-OPS-002 (listener/runtime bounds under load, PR-5), MCP-INSP-001 (semantic input validation, PR-7) | SRE/Sec |
| MCP-T-042 | SSE exhaustion | High | MCP-OPS-002 | SRE/Sec |
| MCP-T-043 | Slow-client attacks | Medium | MCP-OPS-002 | SRE/Sec |
| MCP-T-044 | Queue saturation / event-loss | Critical | MCP-EVENT-001,002,004 | SRE/Sec |

### Integrity & audit

| ID | Threat | Sev | Controls | Owner |
|---|---|---|---|---|
| MCP-T-045 | Audit tampering / repudiation | High | MCP-EVENT-005,006 | Sec |

### CP/DP & HA

| ID | Threat | Sev | Controls | Owner |
|---|---|---|---|---|
| MCP-T-047 | Stale snapshot applied | High | MCP-CPDP-002, MCP-HA-001 | Eng/SRE |
| MCP-T-048 | Split-brain | High | MCP-HA-001,002 | Eng/SRE |
| MCP-T-049 | Stale Control-Plane publication | High | MCP-HA-001 | Eng/SRE |
| MCP-T-050 | Mixed-version CP/DP behavior | High | MCP-CPDP-003 | Eng/SRE |

### Bypass

| ID | Threat | Sev | Controls | Owner |
|---|---|---|---|---|
| MCP-T-054 | Local stdio bypass | High (residual) | MCP-OPS-004 (documented limitation) | Product/Sec |
| MCP-T-055 | localhost bypass | High (residual) | MCP-OPS-004; MCP-INSP-008 (Origin/Host primitive, PR-1) + MCP-INSP-009 (listener enforcement, PR-5) | Product/Sec |
| MCP-T-056 | Direct egress bypass | High (residual) | MCP-OPS-004 (documented V1 limitation, R-1) — the only **in-product** control; a customer-owned network egress policy is a **compensating control outside Culvert**, not an MCP requirement ID | Net/Sec |

### Management MCP

| ID | Threat | Sev | Controls | Owner |
|---|---|---|---|---|
| MCP-T-034 | Management MCP privilege escalation | Critical | MCP-MGMT-001,002,003 | Sec/Eng |
| MCP-T-035 | Management MCP data overexposure | High | MCP-MGMT-004, MCP-PRIVACY-001 | Sec/Privacy |

### Connectivity & privacy

| ID | Threat | Sev | Controls | Owner |
|---|---|---|---|---|
| MCP-T-051 | Outbound connector compromise | High | MCP-CONNECT-001,002 | Net/Sec |
| MCP-T-052 | DMZ endpoint abuse | High | MCP-CONNECT-003, MCP-INSP-009 (listener-side Origin/Host enforcement) | Net/Sec |
| MCP-T-053 | Cloud AI data-residency risk | High | MCP-PRIVACY-001,003 | Privacy/Legal |

### Inbound listener (new requirement surfaced in Phase 1)

| ID | Threat | Sev | Controls | Owner |
|---|---|---|---|---|
| MCP-T-031 | Inbound DNS-rebinding against the MCP/SSE listener | High | MCP-INSP-008 (Origin/Host validation **primitive** + harness, PR-1 — **no listener**) + MCP-INSP-009 (listener binding + host-allowlist + **E2E** rebinding enforcement, PR-5). **Missing today** — `isSafeRedirectURL` is captive-portal-only, `proxy_portal.go:152`. | Sec/Eng |

### Protocol kernel — parsing, framing, version, protocol state (PR-1)

Added by the PR-1 remediation (`PR1-READINESS-REMEDIATION.md`, finding H-1) to model the attack surface
PR-1 actually ships: the MCP parser, JSON-RPC framing, version adapters and protocol-state machine. PR-1
adds **no public listener**, but these threats are intrinsic to the kernel that will later front the PR-5
listener and are gated at **PR-1**. Distinct rows are kept where controls/tests differ (no collapse into a
single "invalid input"). Controls are the new `MCP-PROTO-*` requirements
([`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md)); tests + gate in
[`TEST-TRACEABILITY-MATRIX.md`](TEST-TRACEABILITY-MATRIX.md).

| ID | Threat | Sev | Primary controls (req IDs) | Owner |
|---|---|---|---|---|
| MCP-T-057 | Malformed JSON-RPC envelope / invalid UTF-8 not safely rejected | Medium | MCP-PROTO-001,013,014 | Sec/Eng |
| MCP-T-058 | Parser differential (duplicate/ambiguous keys, conflicting fields) → downstream sees a different message than was validated | High | MCP-PROTO-001 | Sec/Eng |
| MCP-T-059 | JSON-RPC message-type misclassification / unknown-or-unsupported method or extension dispatched | Medium | MCP-PROTO-002 | Sec/Eng |
| MCP-T-060 | Request-ID confusion / response mis-correlation (integer/string/null edge cases, duplicate/absent id) | High | MCP-PROTO-003 | Sec/Eng |
| MCP-T-061 | Batch-message ambiguity / amplification, or reject-bypass when batch is unsupported | Medium | MCP-PROTO-004 | Sec/Eng |
| MCP-T-062 | Framing ambiguity / truncated / partial message mishandled | Medium | MCP-PROTO-005,013 | Sec/Eng |
| MCP-T-063 | Oversized message / excessive JSON depth / field-count / string-size (parse-time exhaustion) | High | MCP-PROTO-006,008 | SRE/Sec |
| MCP-T-064 | Numeric overflow / pathological number encodings | Medium | MCP-PROTO-007 | Sec/Eng |
| MCP-T-065 | Unicode-normalization confusion in method/identifier names | Medium | MCP-PROTO-014 (exact method-token comparison + reject non-ASCII method names pending D-1; NFC is **not** a confusable defense; opaque-ID confusable handling deferred to a field-level policy) + MCP-PROTO-001 | Sec/Eng |
| MCP-T-066 | Version-negotiation confusion / unknown-version accepted best-effort | High | MCP-PROTO-010 | Sec/Eng |
| MCP-T-067 | Downgrade to an unsupported/weaker protocol semantics | High | MCP-PROTO-010 | Sec/Eng |
| MCP-T-068 | Version-adapter differential (same input → divergent normalized message across adapters) | High | MCP-PROTO-011 | Sec/Eng |
| MCP-T-069 | Protocol-state / session confusion (mid-session identity rebind, out-of-order lifecycle) | High | MCP-PROTO-012 (protocol lifecycle + immutable opaque session context, PR-1) + MCP-ID-008 (resolved-identity binding / no rebind, PR-3) | Sec/Eng |
| MCP-T-070 | Cancellation race (cancel-and-retry as a decision bypass; unclean cancel) | Medium | MCP-PROTO-012 | Sec/Eng |
| MCP-T-071 | Duplicate completion / in-session response replay | Medium | MCP-PROTO-003,012 | Sec/Eng |
| MCP-T-072 | Reconnect / replay of protocol messages (resumption abuse) | Medium | MCP-PROTO-012 | Sec/Eng |
| MCP-T-073 | Slow-input / partial-frame buffering resource exhaustion (parse-time) | Medium | MCP-PROTO-005,008 | SRE/Sec |
| MCP-T-074 | Panic / crash / uncontrolled allocation from hostile input | High | MCP-PROTO-009,013 | Sec/Eng |

The eight **High** protocol-kernel threats (`MCP-T-058,060,063,066,067,068,069,074`) carry a full
Threat → Requirement → Control → Test → Evidence → Owner → Gate row in
[`TEST-TRACEABILITY-MATRIX.md`](TEST-TRACEABILITY-MATRIX.md) §1; the Medium ones are covered by the
protocol-kernel fuzz + structural-limit test classes there.

## 12. Residual risk ownership

| ID | Residual risk | Owner | Acceptance condition |
|---|---|---|---|
| R-1 | stdio/localhost/direct-egress bypass (MCP-T-054..056) | Product/Sec | Documented V1 limitation; endpoint bridge is roadmap ([`OPEN-DECISIONS.md`](OPEN-DECISIONS.md) **D-7** — the local-MCP/stdio-localhost roadmap decision; D-8 is the distinct connector model). |
| R-2 | Pattern inspection cannot catch every secret/injection (MCP-T-026,027,038) | Sec/Privacy | Defense-in-depth + approvals; accepted with monitoring. |
| R-3 | Approved server later compromised (MCP-T-021) | Sec/Eng | Drift + destination + output controls; accepted. |
| R-4 | Human approval social engineering (MCP-T-032,033) | Product Sec | Explicit, auditable approval UX; accepted. |
| R-5 | Cloud AI vendor data handling (MCP-T-053) | Privacy/Legal | Customer contract + allowlist + DLP-before-egress; accepted per deployment. |

## 13. Closure criteria

A threat is closed for PR-1 entry when: (1) it appears in this register with a severity; (2) it maps to
≥1 requirement in [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md); (3) it maps to ≥1 control and
≥1 test with an evidence expectation in [`TEST-TRACEABILITY-MATRIX.md`](TEST-TRACEABILITY-MATRIX.md);
(4) it has an accountable owner; and (5) any residual is explicitly accepted in §12. **A critical threat
without an owner is a NO-GO** ([`GO-NO-GO-CHECKLIST.md`](GO-NO-GO-CHECKLIST.md)).

> **Note on MCP-T-002 (token replay):** per [`VERIFIED-REPOSITORY-CONTEXT.md`](VERIFIED-REPOSITORY-CONTEXT.md)
> §6, the reusable SWG bearer path provides **no** access-token replay defense. MCP anti-replay is
> **net-new and NOT VERIFIED as present**; `MCP-AUTH-006` is a build requirement, not a reuse.
> **Reframed by [`ADR-0024 §D-2`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md) (items 7–9):**
> the control is **not** access-token `jti` one-time-use (a still-valid token replaying is not itself
> evidence of replay). It is a layered posture — short TTL, audience/resource, issuer/sig/exp/tenant/scope
> validation, introspection/revocation, correlation + rate limits + anomaly, and **sender-constrained
> (mTLS/DPoP) tokens for high-risk/external profiles**, with DPoP replay detection applied to the
> per-request DPoP proof.

> **Decision closure (2026-07-24).** The threats governing the five closed decisions have accountable
> owners and are recorded in [`docs/adr/0024`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md):
> D-2 → MCP-T-001..010 (esp. MCP-T-005 Critical passthrough); D-5 → MCP-T-044 Critical / MCP-T-028 /
> MCP-T-045; D-8 → MCP-T-051 / MCP-T-053 (residual R-5) / MCP-T-010; D-9 → MCP-T-052 / MCP-T-031 (inbound
> Origin/Host, Missing-today, split across two layers: **`MCP-INSP-008` — the PR-1 pure Origin/Host
> validation primitive (no listener); `MCP-INSP-009` — the PR-5 listener binding + end-to-end
> enforcement**); D-13 → MCP-T-034 Critical / MCP-T-035. No closure
> removes a threat's owner or residual acceptance in §12.
