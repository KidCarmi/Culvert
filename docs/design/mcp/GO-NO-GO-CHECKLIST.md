# MCP Go / No-Go Checklist

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
| **Connectivity** | A supported on-prem model verified with a documented data flow (D-8). | Cloud connectivity assumed, or a private endpoint exposed without review (D-9). |
| **Identity** | Principal/delegation model + no-passthrough + audience/resource validation (MCP-AUTH-002/003/005). | Identity ambiguous, token forwarded, or audience not validated. |
| **Threat model** | All Critical/High threats map to controls, tests, owners (closure criteria met). | Any open critical threat or residual risk without an owner. |
| **Policy** | Default-deny, drift quarantine, simulator, reason codes (MCP-POLICY-001/003, MCP-TOOL-006). | Unknown tool auto-allows, or decisions are opaque. |
| **Credentials** | Brokered, scoped, revocable, no secret leakage (MCP-CRED-001..004). | Agent receives a production secret, or logs contain credentials. |
| **Inspection** | Input/output bounds + DLP + SSRF + inbound Origin/Host (MCP-INSP-001..008). | SSRF/rebinding unguarded, or inbound Origin/Host missing on the listener. |
| **Events** | Critical decision events durable + exportable; loss policy defined (MCP-EVENT-001/002). | Loss policy undefined, or critical events can silently disappear. |
| **Reliability** | Bounds, HA, rollback + load/soak/chaos evidence (MCP-OPS-002, MCP-HA-002). | Unbounded streams/queues, or rollback not rehearsed. |
| **On-prem connectivity** | Local/connector/DMZ deployment validated with data-flow + failure semantics (MCP-CONNECT-*). | Connector assumed; tenant binding unproven. |
| **Privacy** | DLP-before-egress + data-flow + retention + privacy review (MCP-PRIVACY-001/003). | Content crosses cloud-AI boundary without DLP or review. |
| **SSDLC** | CI gates, SBOM, signing, provenance, vuln SLA mapped (MCP-SUPPLY-*). | Release can ship without evidence or artifact verification. |
| **Supply chain** | Pinned deps/actions, signed SBOM+provenance verified before deploy. | Unpinned actions, or unsigned/unverified artifacts. |
| **Operations** | On-call, dashboards, runbooks, support model (MCP-OPS-003). | No owner for incidents/upgrades/escalation. |
| **Support** | Known limitations, troubleshooting, upgrade/downgrade, customer comms. | Support ownership undefined. |
| **Commercial readiness** | Customer pain + pilot success validated (D-11). | Build continues without customer evidence or a clear buyer. |

---

## PR-0 → PR-1 gate (this package)

GO to begin PR-1 requires ALL of:
- [ ] PR-0 documentation reviewed per [`PR0-REVIEW-CHECKLIST.md`](PR0-REVIEW-CHECKLIST.md) (all roles).
- [ ] No hard NO-GO line tripped by the design.
- [ ] Scope, Architecture, Dual-surface, Identity, Threat-model, Policy, Events domains GO.
- [ ] Blocking open decisions with "Due: PR-1/PR-3" have owners assigned (D-0 minimum resolved).
- [ ] **A numbered ADR is Accepted under `docs/adr/`** (Option B, D-0) — human-performed, not PR-0.
- [ ] Two capabilities (Management vs Gateway) confirmed separate across all documents.

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
| ADR accepted under `docs/adr/` | **Pending human action** (D-0, Option B) — PR-1 gate. |
| Test baseline verified | **Not verified this session** — no build/test executed. |

**PR-0 recommendation:** ready for human review; PR-1 remains gated on the ADR promotion and reviewer sign-off.
