# MCP Security Gateway — Product Scope

Purpose: this document defines what Culvert's MCP capabilities are, who they are for, why an enterprise
would pay for them, and — just as importantly — what they explicitly are **not** in V1. It is the
scope-of-record for the PR-0 package: [`THREAT-MODEL.md`](THREAT-MODEL.md) and
[`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md) assume this scope when they define threat IDs and
requirement IDs; [`RECOMMENDED-ARCHITECTURE.md`](RECOMMENDED-ARCHITECTURE.md) assumes this scope when it
proposes trust boundaries; [`IMPLEMENTATION-SLICES.md`](IMPLEMENTATION-SLICES.md) assumes this scope when
it sequences PR-1 through Production Qualification.

**Status: PR-0 design artifact (Proposed).** Nothing described here is implemented. Every capability,
workflow, and metric below is a design intent unless explicitly marked **[FACT]** and traced to
[`VERIFIED-REPOSITORY-CONTEXT.md`](VERIFIED-REPOSITORY-CONTEXT.md). Repository-grounded claims use the
claim legend: **[FACT]** (verified by repository read), **[INFER]** (architectural inference),
**[REC]** (recommendation), **[EXT]** (externally unverified, e.g. MCP protocol versions).

---

## 1. Product Category

Culvert's MCP work is an **Agent Security Gateway** — sub-definition: an MCP identity, policy, and
inspection enforcement point sitting between AI clients/agents and the MCP servers that expose real
enterprise systems.

It **complements** — and explicitly does not replace — adjacent enterprise security categories:

| Category | What it owns | Why Culvert does not replace it |
|---|---|---|
| SWG (Secure Web Gateway) | General HTTP/HTTPS/SOCKS5 egress control | Culvert's existing SWG engine (this repository) is a separate product surface; MCP governance is protocol-aware (tools, schemas, arguments) in a way generic web filtering is not. Per the non-goals below, MCP fields are never added to the SWG `PolicyRule` **[FACT]** (`policy.go:91-188`, 4 actions only, `policy.go:19-27`, no MCP action verbs — grep 0). |
| IAM (Identity and Access Management) | Human/workload identity lifecycle, SSO, directory | Culvert consumes IAM-issued identity; it does not issue or federate enterprise identity itself. |
| PAM (Privileged Access Management) | Vaulting and rotation of privileged human/service credentials | Culvert brokers *scoped, short-lived* upstream credential use for agent tool calls; it is not a general-purpose secrets vault or session-recording PAM product. |
| DLP (Data Loss Prevention) | Enterprise-wide content classification and egress control | Culvert applies bounded, MCP-specific inspection (schema, size, secret/DLP pattern, destination) to tool arguments/responses; it is not a general DLP platform. |
| SIEM (Security Information and Event Management) | Long-term log aggregation, correlation, and investigation tooling | Culvert emits durable decision events for MCP calls; it is a source that feeds a SIEM, not a SIEM replacement. |

**Defensible moat** (design intent, not yet built): an identity/tool/credential/resource graph, a history
of tool fingerprints that distinguishes safe narrowing from privilege expansion, a policy simulator that
estimates blast radius before publication, decision events suitable for investigation and compliance, and
credential isolation that separates the agent's token from upstream privilege.

---

## 2. Buyer vs. User

MCP governance has a wider buying committee than a typical infrastructure add-on. The persona table below
is the scope-level contract for who a V1 pitch, demo, and onboarding flow must satisfy — reproduced from
the blueprint's persona/JTBD analysis (BLUEPRINT §05).

| Persona | Primary Goal | Core Fear | Proof of Value |
|---|---|---|---|
| CISO / Product Security | Enable AI adoption without a new blind spot. | An agent holds production privilege, or data exfiltrates through an agent. | Complete inventory, blocked test incidents, policy coverage, and audit evidence. |
| IAM / PAM | Apply least privilege and delegation to agents. | Shared credentials and missing attribution. | Credential profiles, delegated identity, and rapid revoke. |
| AI Platform Team | Connect agents to tools quickly and consistently. | Security friction and one-off integrations per team. | Fast onboarding, standards compatibility, and shadow mode. |
| Application Owner | Expose controlled access to a system they own. | A tool bypasses business controls or causes damage. | Tool-level policy, resource scope, approvals, and usage visibility. |
| SOC / IR | Investigate and contain agent activity. | Insufficient logs, or exposed credentials in those logs. | Decision trace, identity chain, and no raw secrets in events. |
| SRE / Network | Operate a stable gateway without harming the existing SWG. | Latency, resource exhaustion, or split-brain during rollout. | Bounded resource use, SLOs, immutable config snapshots, and rollback. |

**Buyer vs. user pattern:** CISO/Product Security and IAM/PAM are the typical economic buyers (security
budget, compliance mandate); the AI Platform Team and Application Owners are the day-to-day users who
onboard servers and tune policy; SOC/IR and SRE/Network are the operational stakeholders who must sign off
before a canary/enforce rollout (see [`ROLLOUT-AND-ROLLBACK.md`](ROLLOUT-AND-ROLLBACK.md) and
[`GO-NO-GO-CHECKLIST.md`](GO-NO-GO-CHECKLIST.md)). A pitch that satisfies only the CISO without a credible
onboarding story for the AI Platform Team, or vice versa, is incomplete.

---

## 3. Business Problem, Value Proposition, and Plain-Language Promise

### Positioning

> Culvert governs every approved remote MCP tool call using enterprise identity, least privilege,
> credential isolation, inline inspection, and explainable policy.

### Plain-language promise

Culvert lets enterprises connect AI agents to real systems without giving those agents direct access,
unmanaged tools, or open production credentials.

### The problem customers pay to solve

| Pain | Why existing approaches fall short | Culvert's response (design intent) |
|---|---|---|
| Shadow MCP | Agents and clients connect to servers without central inventory. | Discovery, ownership, allowlist, and an enforceable traffic path. |
| Over-privileged agents | A token or service account grants broader access than a single action requires. | Short-lived credential profiles scoped by server, tool, resource, and environment. |
| Tool drift / rug pull | A tool name stays constant while schema, description, identity, or behavior changes underneath it. | Fingerprint, diff, risk re-score, and quarantine. |
| No attribution | The organization cannot prove who initiated an action and on whose behalf. | Identity chain: human/workload → agent → client → server → tool → resource. |
| Unsafe autonomy | Write or destructive operations execute without meaningful approval. | Risk-aware confirmation, security approval, allow-once/session, and deny. |
| Weak investigations | Technical logs do not explain why an action was allowed. | Decision events with reason code, revisions, evidence, and remediation. |

This value proposition is scoped to what a gateway sitting in front of **remote** MCP traffic can actually
guarantee — see §6 for the local-MCP limitation that bounds this promise.

---

## 4. Proof-of-Value Flow (Killer Workflow, Scope Level)

The workflow below is the "killer demo" at a **scope** level — a security team should be able to walk this
path for one server in a single sitting. It is not an implementation plan; sequencing and acceptance
criteria for the underlying engineering work live in [`IMPLEMENTATION-SLICES.md`](IMPLEMENTATION-SLICES.md).

```
Connect → Discover → Classify → Simulate → Shadow → Enforce → Explain → Roll Back
```

| Step | Action | Output |
|---|---|---|
| 1. Connect | Enter endpoint, owner, environment, and auth method. | Server record in Pending state. |
| 2. Discover | Handshake, capability check, and tool listing. | Inventory, fingerprints, and a compatibility report. |
| 3. Classify | Culvert computes risk; an administrator reviews or overrides. | Tool risk tiers and a policy recommendation. |
| 4. Simulate | Run the proposed policy against historical events and test vectors. | Blast radius, conflicts, and expected decisions. |
| 5. Shadow | Real traffic; policy reports but does not block, except hard failures. | False-positive report and rule tuning. |
| 6. Enforce | Enable for a small canary scope. | Allowed/blocked decisions and SLO evidence. |
| 7. Explain | Dashboard and decision trace. | Reason code, matched rule, revisions, and remediation. |
| 8. Roll Back | Return to the previous immutable config snapshot. | Measured recovery without partial state. |

Initial policy recommendation by risk class (design intent — the actual policy engine is PR-6, see
[`MCP-POLICY-MODEL.md`](MCP-POLICY-MODEL.md)):

| Risk class | Default | Examples |
|---|---|---|
| Read-only / bounded | ALLOW in shadow, then enforce for approved groups. | search, list, get status |
| Write / reversible | REQUIRE_CONFIRMATION or approval by scope. | create ticket, write file |
| Destructive | REQUIRE_APPROVAL or DENY. | delete, revoke, deploy production |
| Open-world / broad destination | MONITOR, restrict destinations, apply low rate. | fetch arbitrary URL, generic SQL |
| Unknown / changed | QUARANTINE. | new tool, changed schema, new TLS identity |

> **Red line:** an unknown tool, a changed identity, or a privilege expansion never moves to automatic
> allow. It enters quarantine until reviewed. This is a hard product principle, not a tunable default —
> see MCP-T-017 (unknown-tool auto-allow, Critical) in [`THREAT-MODEL.md`](THREAT-MODEL.md).

---

## 5. V1 Scope

### Coverage map

| Capability | V1 | After V1 |
|---|---|---|
| Transport | Remote Streamable HTTP, version adapters, and SSE lifecycle. | Additional transports based on demand and standards maturity. |
| Discovery | Server registration, tool inventory, fingerprints, and diffs. | Behavioral learning and reputation feeds. |
| Policy | Identity + server + tool + arguments + resource + risk. | Adaptive recommendations based on observed usage. |
| Credentials | Brokered upstream credentials, rotation hooks, mTLS/workload identity. | Dynamic JIT credentials and broader vault integrations. |
| Inspection | Schema, size, secret/DLP patterns, URL and destination controls. | Specialized AI-threat inspection integrations. |
| Approvals | Confirm, allow once/session, and security approval. | Multi-party and ticket/workflow integrations. |
| Local MCP | Out of scope. | Desktop/Endpoint Bridge for stdio and localhost (see §6). |
| Analytics | Dashboards, decision events, and exports. | Behavioral anomaly models and risk trends. |

Transport, protocol-version adapters, and MCP-over-HTTP framing details are **[EXT]** — MCP protocol
version specifics are externally defined and not verified against this repository; see
[`PROTOCOL-COMPATIBILITY.md`](PROTOCOL-COMPATIBILITY.md).

### Sellable MVP

A V1 release must demonstrate, at minimum:

- Remote Streamable HTTP transport
- Server and tool inventory
- Schema and description drift detection
- Identity-aware policy
- Credential separation (no raw upstream credential ever reaches the agent)
- Input/output secret inspection
- Decision trace and reason codes
- Shadow mode
- Approval gating for destructive tools
- Rollback to a prior config snapshot

---

## 6. Local MCP Limitations (Explicit V1 Exclusion)

**Local MCP transports — stdio, localhost sockets, and any MCP traffic that reaches an enterprise system
via direct egress rather than through the gateway — are out of scope for V1.** A remote gateway cannot
observe, authenticate, or inspect a tool call that never crosses its listener. This is a coverage
limitation, not an oversight, and the product must not imply blanket protection it cannot provide (see the
"Honest coverage" principle and V1 non-goals in §7).

This limitation corresponds to three residual threats tracked in [`THREAT-MODEL.md`](THREAT-MODEL.md) and
must be represented honestly in every customer-facing scoping conversation:

| Threat ID | Bypass vector | V1 posture |
|---|---|---|
| MCP-T-054 | stdio transport (agent and MCP server on the same host, no network hop for Culvert to intercept). | Not covered. Documented residual risk. |
| MCP-T-055 | localhost-bound MCP server (loopback traffic bypasses any network-positioned gateway). | Not covered. Documented residual risk. |
| MCP-T-056 | Direct egress (an agent or client configured to call an enterprise MCP server directly, bypassing the gateway endpoint entirely). | Not covered. Requires policy/config discipline on the client side; Culvert cannot force routing it never sees. |

A **Desktop/Endpoint Bridge** that could extend coverage to stdio/localhost MCP traffic is a roadmap idea,
not a V1 commitment. Its priority, design, and whether it ships at all is an open decision — see
[`OPEN-DECISIONS.md`](OPEN-DECISIONS.md) **D-7** (local MCP / endpoint-bridge roadmap). *(Corrected
2026-07-24: the endpoint bridge is tracked under D-7, not D-8; D-8 is the outbound-connector model.)*
Until that decision is made and a bridge is delivered, sales and product messaging must state local-MCP
coverage as absent, not "coming soon."

---

## 7. Explicit Non-Goals

These are hard boundaries for V1. Reproduced from BLUEPRINT §06 ("Product Principles and Boundaries" /
"V1 Non-Goals") and restated here as the scope-of-record:

- **Do not add MCP fields to the existing SWG `PolicyRule`.** The SWG policy engine is a verified,
  unrelated destination-selector model (**[FACT]** `policy.go:91-188`, ~34 destination-selector fields; 4
  actions only — Allow/Drop/Block_Page/Redirect, `policy.go:19-27`; grep for MCP action verbs returns 0
  matches) that also performs network and disk I/O during a policy decision (**[FACT]** `policy.go`
  `Evaluate:1083-1143`, DNS resolution at `:1387` → `geoip.go` `resolveHost:125-204`) — incompatible with
  an MCP policy engine's "no I/O during evaluation" requirement. MCP needs its own schema and its own
  action verbs (see the nine policy actions in [`MCP-POLICY-MODEL.md`](MCP-POLICY-MODEL.md)).
- **Do not reuse the existing SWG OIDC proxy flow as a generic MCP authentication model.** The current
  OIDC integration binds audience to `client_id` only (**[FACT]** `auth_oidc_flow.go:523`), has no RFC 8707
  resource-indicator support (**[FACT]** grep 0 matches), and has no bearer access-token replay defense or
  DPoP/sender-constraint (**[FACT]** grep 0 matches for both). MCP identity and token validation is a
  separate design surface — see [`AUTH-AND-CREDENTIAL-MODEL.md`](AUTH-AND-CREDENTIAL-MODEL.md).
- **Do not store raw arguments or raw tool outputs by default.** Decision events capture reason codes,
  matched rules, and redacted/classified evidence — not a verbatim replay log. See
  [`EVENT-MODEL.md`](EVENT-MODEL.md).
- **Do not build a new LLM or model that promises to detect every prompt/tool injection.** Inspection is
  bounded (schema, size, secret/DLP pattern, destination control), not a general injection classifier —
  see MCP-T-038/039 in [`THREAT-MODEL.md`](THREAT-MODEL.md).
- **Do not turn Culvert into a complete SIEM, PAM, or secrets manager.** Culvert emits durable decision
  events and brokers scoped credential *use*; it does not replace long-term SIEM correlation, full PAM
  session recording/vaulting, or general-purpose secrets management (see §1 category boundaries).
- **Do not support every MCP transport, extension, and protocol version on day one.** V1 is Remote
  Streamable HTTP; other transports are explicitly deferred (see §5 coverage map).
- **Do not expose a production listener before PR-0 and a production-readiness review.** No runtime code
  ships as part of this design package; see [`IMPLEMENTATION-SLICES.md`](IMPLEMENTATION-SLICES.md) and the
  [`GO-NO-GO-CHECKLIST.md`](GO-NO-GO-CHECKLIST.md).
- **Do not treat local/stdio MCP as covered.** See §6.

---

## 8. Management MCP Scope vs. Security Gateway Scope

Culvert's MCP work spans **two capabilities that share a platform shell but must never share a listener,
policy schema, or threat model.** This separation is a hard product and architecture doctrine, not a
phased convenience — see the "Shared vs. Separate" table below and
[`RECOMMENDED-ARCHITECTURE.md`](RECOMMENDED-ARCHITECTURE.md) for the trust-boundary detail.

> **Decision status — D-13 CLOSED (2026-07-24, [`ADR-0023 §D-13`](../../adr/0023-mcp-agent-security-gateway-trust-boundary.md)).**
> **V1 Management MCP = read-only + draft / validate / simulate, with NO activation. Mutation and
> publication are excluded from V1.** Isolation is at the level of listener, OAuth client/resource/scopes,
> policy namespace, rule bundles, quotas, audit category, threat model and runbook; the two capabilities
> **may** share reviewed implementation libraries, selected Control-Plane infrastructure, a shared
> policy-engine **library** (never shared active state/rule-bundles/namespaces/decisions), and even the
> underlying durable event **transport** — but only when events are separated by authorization domain,
> tenant, category, partitioning, retention and query policy. Two physically separate event systems are
> not required when logical + security isolation is enforced and tested.

### Capability A — Culvert Management MCP Server (read-only by default)

An AI client uses MCP to query, explain, and — eventually, under tightly controlled conditions — perform
management operations on Culvert itself.

> `AI Client → /mcp/management → Culvert management capabilities`

| Initial tool class | Examples | Default posture |
|---|---|---|
| Read-only explanation | Explain a policy decision; show effective configuration; compare desired vs. actual state. | Allowed only to authorized roles; bounded output and tenant scope. |
| Health and analytics | Cluster health, node readiness, bounded security-event queries. | Read-only, redacted, and rate limited. |
| Draft and validation | Draft a policy; validate syntax; simulate impact. | No activation. Full audit required. |
| Mutation | Apply or publish configuration. | Out of scope until a mature plan → validate → approve → apply control set exists. |
| Prohibited | Raw secret access, arbitrary command execution, unrestricted trace/log export. | Never exposed as MCP tools. |

### Capability B — MCP Security Gateway

Culvert sits between AI clients/agents and business MCP servers. It authenticates the client, identifies
the acting agent, discovers and fingerprints tools, evaluates policy, inspects arguments and responses,
selects a scoped upstream credential, calls the approved server, and records the decision.

> `AI Agent → /mcp/gateway/{server-id} → Approved MCP Server → Enterprise System`

### Shared vs. Separate (the "one platform, separate engines" doctrine)

| Shared platform services | Must remain separate |
|---|---|
| Admin UI shell and authentication | Listeners and endpoint exposure |
| RBAC framework and tenant model | Policy schemas and decision actions |
| Configuration publication and immutable snapshots | Trust boundaries and threat models |
| Audit conventions and export infrastructure | Runtime pools, quotas, and failure semantics |
| OpenAPI, CI, and release infrastructure | Management authorization vs. business-tool authorization |

> Commercially: one Culvert platform can expose multiple SKUs. Architecturally: one generic "policy for
> everything" would be a maintainability and security failure.

This scope document, like every other PR-0 artifact, keeps Capability A and Capability B's listeners,
scopes, policy schemas, threat models, and runbooks separate throughout. Where a table above (e.g. the
coverage map in §5) reads as a single list, it describes the Security Gateway (Capability B) unless
explicitly marked Management (Capability A) — Capability A's V1 surface is limited to the read-only/health/
draft rows in the table above, with mutation explicitly out of scope.

---

## 9. Packaging Questions (Open)

Whether Capability A (Management MCP) and Capability B (Security Gateway) ship as a single SKU, separate
SKUs, or a bundled-with-existing-SWG-license offering is **not decided in this document**. Packaging
touches pricing, licensing enforcement, and go-to-market sequencing that are outside a PR-0 design
package's authority. This is tracked as an open decision — see [`OPEN-DECISIONS.md`](OPEN-DECISIONS.md) for
the specific packaging question(s) and their current status.

---

## 10. Success Metrics (Design Targets, Not Measured Results)

**Every number below is a DESIGN TARGET.** None has been measured against a running system — there is no
MCP runtime in this repository yet (**[FACT]** no existing MCP/JSON-RPC listener in inspected paths). These
targets exist to define what "done" should look like once PR-1 through Production Qualification are built
and exercised, and to give [`GO-NO-GO-CHECKLIST.md`](GO-NO-GO-CHECKLIST.md) something concrete to check
against. Reproduced from BLUEPRINT §22.

> North Star (design intent): the percentage of enterprise MCP calls that pass through Culvert with
> complete attribution, an explainable policy decision, and an isolated credential.

| Metric | Design target | Why it matters |
|---|---|---|
| Time to first governed server | < 15 minutes | Proves onboarding, not consulting. |
| Initial inventory time | < 5 minutes | Fast time to value. |
| Discovery to shadow policy | < 30 minutes | Makes security an enabler, not a blocker. |
| Full attribution coverage | > 99.9% | Foundation for governance and investigation. |
| Unknown tools auto-allowed | 0 | Core trust principle (see the red line in §4). |
| Credentials delivered to agent | 0 | Primary differentiation from a naive proxy. |
| Decisions without reason code | 0 | Product explainability. |
| False positive after shadow | < 1% | Enforcement without business disruption. |
| Policy rollback | < 5 minutes | Trust in change management. |
| High-risk calls with approval/effective deny | 100% | Control of critical operations. |
| Paid pilot conversion | Defined before GA | Evidence of commercial demand. |
| Connector deployment success | > 95% in supported patterns | Proves on-prem integration is a product, not bespoke services. |

Executive reporting intent (also design targets): agents/servers onboarded with owners and unmanaged gaps;
high-risk tools and over-privileged credentials; blocked exfiltration, unauthorized write, and drift
incidents; policy coverage and exception age; latency, availability, event loss, and rollback readiness;
connectivity model and connector health.

> Note on test evidence: low risk for the read-only Phase 1 investigation that produced this scope
> document, but the current repository test baseline remains unverified in this session.

---

## Related Documents

- [`THREAT-MODEL.md`](THREAT-MODEL.md) — canonical threat-ID registry (MCP-T-###) referenced throughout this scope.
- [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md) — canonical requirement-ID registry (MCP-AUTH-###, etc.).
- [`OPEN-DECISIONS.md`](OPEN-DECISIONS.md) — packaging questions (§9) and the Endpoint Bridge decision (D-8, §6).
- [`IMPLEMENTATION-SLICES.md`](IMPLEMENTATION-SLICES.md) — how this scope is delivered across PR-1 … PR-11 and Production Qualification.
- [`RECOMMENDED-ARCHITECTURE.md`](RECOMMENDED-ARCHITECTURE.md) — trust boundaries implementing the Capability A / Capability B separation in §8.
- [`VERIFIED-REPOSITORY-CONTEXT.md`](VERIFIED-REPOSITORY-CONTEXT.md) — source of every **[FACT]** claim in this document.
