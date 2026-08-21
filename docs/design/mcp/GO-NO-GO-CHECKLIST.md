# MCP Go / No-Go Checklist

> **PR-11 status (guarded execution / Shadow / Canary) — IMPLEMENTED, disabled by default.** The mode
> ladder, immutable revisioned scope, central hard-failure classifier, bounded Model-A upstream client,
> guarded execution (commit-before-side-effect, DLP-before-egress, credential containment, no client-token
> passthrough), and signed CP→DP rollout distribution now ship in `internal/mcp/{rollout,upstreamclient,execution}`
> and the `package main` composition. **Observe is non-executing; Shadow/Canary execute only inside an exact
> approved scope for Model A (local-client); Production remains qualification-locked** (no config/env/CLI/API
> bypass; no in-binary issuer). `outbound-connector`/`dmz-endpoint`, endpoint bridge, transparent discovery,
> and Management mutation remain excluded. Duration targets (14d/7d/24h) are measurable machinery, not
> completed evidence; Production Qualification is the separate gate. There is no PR-12 in this
> package's slice sequence — see [`IMPLEMENTATION-SLICES.md`](IMPLEMENTATION-SLICES.md) (not to be
> confused with the unrelated fix CLAUDE.md separately labels "PR-12").


Blocking conditions that gate progression. **Status: PR-0 design artifact (Proposed).** This checklist
governs two decisions: **(1) is PR-0 approved so PR-1 may begin?** and **(2) is the subsystem ready for
Production Qualification?** Each domain lists GO conditions and NO-GO conditions. IDs reference
[`THREAT-MODEL.md`](THREAT-MODEL.md), [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md),
[`OPEN-DECISIONS.md`](OPEN-DECISIONS.md).

---

## Hard NO-GO lines (absolute — any one blocks)

1. **A critical threat without an owner → NO-GO.** (Every `MCP-T-*` Critical in the risk register has an owner: [`THREAT-MODEL.md`](THREAT-MODEL.md) §11.)
2. **A production credential reaching an agent → NO-GO.** (MCP-CRED-001; abuse case MCP-AC-005.)
3. **Token passthrough → NO-GO.** (MCP-AUTH-005; abuse case MCP-AC-004.)
4. **An unknown tool receiving automatic allow → NO-GO.** (MCP-TOOL-006; abuse case MCP-AC-007.)
5. **An unrehearsed rollback → NO-GO.** (MCP-HA-002; [`ROLLOUT-AND-ROLLBACK.md`](ROLLOUT-AND-ROLLBACK.md).)
6. **Undefined critical-event loss behavior → NO-GO.** (MCP-EVENT-002; abuse case MCP-AC-016.)

These six are non-negotiable and apply at every stage.

---

## Domain gates

| Domain | GO when | NO-GO when |
|---|---|---|
| **Scope** | Remote coverage + non-goals approved; local/bypass documented as limitation (MCP-OPS-004). | Promises imply local/bypass coverage that is not built. |
| **Architecture** | Dedicated MCP subsystems + trust boundaries approved; ADR accepted (D-0). | MCP fields added to SWG `PolicyRule`, or the audit ring reused as the decision pipeline. |
| **Dual MCP surfaces** | Management + Gateway have separate scopes, policies, threat models (D-13). | Management tools and business gateway calls share a generic policy. |
| **Connectivity** | The **V1-supported** on-prem model — Model A `local-client` — verified with a documented data flow (D-8). | Cloud connectivity assumed, a private endpoint exposed without review (D-9), or V1 sign-off made contingent on the deferred connector/DMZ models. |
| **Identity** | Principal/delegation model + no-passthrough + audience/resource validation (MCP-AUTH-002/003/005). | Identity ambiguous, token forwarded, or audience not validated. |
| **Threat model** | All Critical/High threats map to controls, tests, owners (closure criteria met). | Any open critical threat or residual risk without an owner. |
| **Policy** | Default-deny, drift quarantine, simulator, reason codes (MCP-POLICY-001/003, MCP-TOOL-006). | Unknown tool auto-allows, or decisions are opaque. |
| **Credentials** | Brokered, scoped, revocable, no secret leakage (MCP-CRED-001..004). | Agent receives a production secret, or logs contain credentials. |
| **Protocol kernel** | PR-1 parser/framing/version/protocol-state attack surface modeled (MCP-T-057..074) and bounded by MCP-PROTO-001..014; blocking PR-1 fuzz + structural/differential/protocol-state gates defined; compatibility gate defined and **D-1-gated**. | Protocol-kernel threats unmodeled, "protocol bounds" undefined, or fuzz/compat claimed green with no blocking gate / before D-1 closes. |
| **Inspection** | Semantic input/output schema + DLP + SSRF + Origin/Host (MCP-INSP-001..009: the Origin/Host **primitive** is `MCP-INSP-008` at PR-1, the **listener binding + E2E rebinding** is `MCP-INSP-009` at PR-5); structural parse-time bounds owned by the kernel (MCP-PROTO-006). | SSRF/rebinding unguarded, or listener (PR-5) binds default-public / skips the allowlist. |
| **Events** | Critical decision events durable + exportable; loss policy defined (MCP-EVENT-001/002). | Loss policy undefined, or critical events can silently disappear. |
| **Reliability** | Bounds, HA, rollback + load/soak/chaos evidence (MCP-OPS-002, MCP-HA-002). | Unbounded streams/queues, or rollback not rehearsed. |
| **On-prem connectivity** | **V1 scope = Model A (`local-client`) only:** the local-client deployment validated with data-flow + failure semantics, and tenant binding proven for it via **MCP-ID-007** (tenant identity bound and enforced on **every call**, cross-tenant denied — PR-3, tenant-escape tests). *`MCP-CONNECT-004` is **not** the V1 control here: it is scoped to connector/DMZ sessions and gated at PR-C / the Future DMZ gate.* Connector (Model B) and DMZ (Model C) are **explicitly out of V1 scope** and **MUST NOT** gate V1 GA — they are cleared at their own later gates (PR-C for MCP-CONNECT-001/002 + the connector aspect of 004; the Future DMZ Architecture & Production-Readiness Gate for MCP-CONNECT-003 + the DMZ aspect of 004 + MCP-INSP-009). V1 GO also requires that the shipped config surface **reject** `outbound-connector` and `dmz-endpoint`. | V1 GA blocked on connector/DMZ evidence (a circular gate — those slices cannot start until after GA); or Model A tenant binding unproven; or a non-Model-A connectivity mode selectable in V1. |
| **Privacy** | DLP-before-egress + data-flow + retention + privacy review (MCP-PRIVACY-001/003). | Content crosses cloud-AI boundary without DLP or review. |
| **SSDLC** | CI gates, SBOM, signing, provenance, vuln SLA mapped (MCP-SUPPLY-*). | Release can ship without evidence or artifact verification. |
| **Supply chain** | Pinned deps/actions, signed SBOM+provenance verified before deploy. | Unpinned actions, or unsigned/unverified artifacts. |
| **Operations** | On-call, dashboards, runbooks, support model (MCP-OPS-003). | No owner for incidents/upgrades/escalation. |
| **Support** | Known limitations, troubleshooting, upgrade/downgrade, customer comms. | Support ownership undefined. |
| **Commercial readiness** | Customer pain + pilot success validated (D-11). | Build continues without customer evidence or a clear buyer. |

---

## PR-0 → PR-1 gate (this package)

> **Decision-closure status (2026-07-31 — PR-1 entry closed).** All five blocking domain decisions are
> **CLOSED** and recorded in [`docs/adr/0024`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md):
> **Dual-surface (D-13), Connectivity (D-8 + D-9), Identity (D-2), Events (D-5)** are **GO**. **ADR-0024 is
> `Status: Accepted`**, so the ADR gate item below is **satisfied**. The two hard PR-1 entry decisions **D-1**
> (protocol baseline) and **D-15** (config anti-drift contract) are **CLOSED**. There is **no** ARB / Security
> Architecture / committee ratification step in this project — closure rests on independent AI research,
> adversarial review, structural predicates, and CI. See [`PR1-ENTRY-CLOSURE.md`](PR1-ENTRY-CLOSURE.md) and
> tracker [#923](https://github.com/KidCarmi/Culvert/issues/923). **PR-1 implementation is GO.**

GO to begin PR-1 requires ALL of:
- [x] PR-0 documentation review complete per [`PR0-REVIEW-CHECKLIST.md`](PR0-REVIEW-CHECKLIST.md) — evidence-based (documents, RPRs, tests, independent verification), not human role signatures (#923 Gate 2).
- [x] No hard NO-GO line tripped by the design.
- [x] Scope, Architecture, Dual-surface, Identity, Threat-model, Policy, Events domains GO. *(D-2/D-5/D-8/D-9/D-13 closed in ADR-0024.)*
- [x] Blocking open decisions with "Due: PR-1/PR-3" have owners assigned (D-0 resolved).
- [x] **A numbered ADR is Accepted under `docs/adr/`** (Option B, D-0) — **ADR-0024 is `Status: Accepted`.**
- [x] **D-1 (protocol-version baseline) CLOSED** — V1 baseline frozen (primary `2025-11-25`, floor `2025-06-18`, all others rejected; Streamable HTTP only; batch rejected; six-method surface; sessionless missing-header → `400`).
- [x] **D-15 (config anti-drift contract) CLOSED** — implementation contract accepted; `MCP-CFG-001` authoritative.
- [x] **Repository build/test baseline re-anchored to current `main` and recorded** (#923 Gate 4; [`PR1-ENTRY-CLOSURE.md`](PR1-ENTRY-CLOSURE.md)).
- [x] **PR-1 protocol-kernel attack surface modeled** (MCP-T-057..074 + RPR-1 MCP-T-076/077) and mapped to **MCP-PROTO-001..016** with PR-1 **blocking** fuzz + structural/differential/protocol-state gates and the compatibility gate (remediation findings H-1..H-4; the gates are wired in PR-1).
- [x] Two capabilities (Management vs Gateway) confirmed separate across all documents.

## Production Qualification gate

GO to production requires ALL domain gates GREEN, the complete
[`TEST-TRACEABILITY-MATRIX.md`](TEST-TRACEABILITY-MATRIX.md) green, signed SBOM/provenance verified, and
the Joint Go/No-Go Board sign-off (BLUEPRINT §24 RACI). Any hard NO-GO line remains absolute.

---

## Current PR-0 self-assessment

| Gate | Status at PR-0 |
|---|---|
| Documentation completeness | Met (this package). |
| Two-capability separation | Met (enforced across docs). |
| Hard NO-GO lines designed-for | Met (each mapped to a requirement + abuse case + test). |
| Repository claims evidenced | Met ([`VERIFIED-REPOSITORY-CONTEXT.md`](VERIFIED-REPOSITORY-CONTEXT.md)). |
| ADR under `docs/adr/` | **`docs/adr/0024` is `Status: Accepted` (2026-07-31).** Accepted on the merged repository state — no organizational ratification step exists in this project. |
| Five blocking decisions (D-2/D-5/D-8/D-9/D-13) | **CLOSED** in ADR-0024. |
| D-1 protocol baseline | **CLOSED (2026-07-31)** — V1 baseline frozen (see [`OPEN-DECISIONS.md`](OPEN-DECISIONS.md) §D-1). |
| D-15 config anti-drift contract | **CLOSED — implementation contract accepted.** |
| Test baseline | **Re-anchored to current `main` and recorded** (#923 Gate 4; [`PR1-ENTRY-CLOSURE.md`](PR1-ENTRY-CLOSURE.md)). |

**Recommendation (2026-07-31):** the four PR-1 entry gates are complete and **PR-1 implementation is GO**
(protocol-kernel scope only — see [`PR1-ENTRY-CLOSURE.md`](PR1-ENTRY-CLOSURE.md) for the allowed/prohibited
scope). GO does not authorize a listener, OAuth, policy, credentials, upstream execution, UI, or production
traffic.
