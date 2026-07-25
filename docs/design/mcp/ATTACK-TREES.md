# MCP Attack Trees

Ten attack trees (AT-10, protocol-kernel subversion, added by the PR-1 remediation —
`PR1-READINESS-REMEDIATION.md`, finding H-1). Every **leaf** maps to one or more threat IDs from
[`THREAT-MODEL.md`](THREAT-MODEL.md); mitigations are the requirement IDs from
[`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md). **Status: PR-0 design artifact (Proposed).**
Trees are ASCII for reviewable diffs; each is followed by a leaf→threat→requirement table.

---

## AT-1 — Unauthorized production change

```
Goal: Agent modifies production without authorized intent
├─ L1 Steal or misuse identity token
├─ L2 Bypass Culvert via direct or local MCP
├─ L3 Call approved server with overbroad credential
├─ L4 Exploit tool drift under an approved name
├─ L5 Abuse arguments to target an unapproved resource
├─ L6 Trick a human through ambiguous approval UX
├─ L7 Exploit stale or inconsistent policy snapshot
└─ L8 Abuse Management MCP to publish a change
```

| Leaf | Threats | Mitigations |
|---|---|---|
| L1 | MCP-T-001,002,003,004 | MCP-AUTH-001..006 |
| L2 | MCP-T-054,055,056 | MCP-OPS-004 (documented limit); Origin/Host split — **MCP-INSP-008** primitive at PR-1, **MCP-INSP-009** listener-side enforcement + E2E at **PR-5** (MCP-T-055 needs a live listener, so the PR-1 primitive alone does not close it) |
| L3 | MCP-T-005,022,046 | MCP-CRED-001,002, MCP-POLICY-004 |
| L4 | MCP-T-013,015,019 | MCP-TOOL-003,004 |
| L5 | MCP-T-046 | MCP-POLICY-003, MCP-INSP-001 |
| L6 | MCP-T-032,033 | MCP-POLICY-007 |
| L7 | MCP-T-047,050 | MCP-CPDP-002, MCP-HA-001 |
| L8 | MCP-T-034 | MCP-MGMT-001,002,003 |

## AT-2 — Production credential theft

```
Goal: Obtain a usable upstream/production credential
├─ Extract credential from agent (agent should never hold it)
├─ Read credential from logs / metrics / traces / events
├─ Compromise the credential cache
└─ Trigger scope-mismatched credential issuance
```

| Leaf | Threats | Mitigations |
|---|---|---|
| Extract from agent | MCP-T-005 | MCP-CRED-001 |
| Read from logs/events | MCP-T-023,028 | MCP-CRED-004, MCP-EVENT-003 |
| Cache compromise | MCP-T-024 | MCP-CRED-005 |
| Scope-mismatched issuance | MCP-T-022,025 | MCP-CRED-002,006 |

## AT-3 — Data exfiltration

```
Goal: Move enterprise secrets/PII to an external party
├─ Embed secret in tool arguments to an external destination
├─ Extract secret from tool output and relay onward
├─ Reach an arbitrary/open-world destination (SSRF)
└─ Cross the cloud-AI boundary without DLP
```

| Leaf | Threats | Mitigations |
|---|---|---|
| Secret in arguments | MCP-T-026 | MCP-INSP-001,003 |
| Secret in output | MCP-T-027 | MCP-INSP-002,003 |
| Open-world destination | MCP-T-036,030 | MCP-INSP-004,005 |
| Cross cloud-AI boundary | MCP-T-053 | MCP-PRIVACY-001 |

## AT-4 — Tool rug pull

```
Goal: Change an approved tool's behavior while keeping its name
├─ Change input/output schema after approval
├─ Change description/semantics after approval
├─ Change server TLS/endpoint identity
└─ Introduce a new tool and get it auto-allowed
```

| Leaf | Threats | Mitigations |
|---|---|---|
| Schema change | MCP-T-013 | MCP-TOOL-003,004 |
| Description/semantic change | MCP-T-014 | MCP-TOOL-005 |
| Server identity change | MCP-T-016 | MCP-SERVER-003 |
| New tool auto-allow | MCP-T-017 | MCP-TOOL-006 |

## AT-5 — Policy bypass

```
Goal: Get an action allowed that policy should deny
├─ Cause evaluation to be non-deterministic (I/O side effects)
├─ Confuse audience/resource so a foreign token is accepted
├─ Exploit confused deputy (credential before decision)
└─ Reach an unregistered server
```

| Leaf | Threats | Mitigations |
|---|---|---|
| Non-deterministic eval | MCP-T-018 | MCP-POLICY-002 |
| Audience/resource confusion | MCP-T-003,004 | MCP-AUTH-002,003 |
| Confused deputy | MCP-T-046 | MCP-POLICY-004 |
| Unregistered server | MCP-T-020 | MCP-SERVER-001 |

## AT-6 — Management MCP privilege escalation

```
Goal: Use Management MCP to exceed intended read-only scope
├─ Invoke a mutation tool that should not be exposed
├─ Escape tenant scope
├─ Reach a prohibited capability (raw secrets / command exec / log export)
└─ Replay a management action
```

| Leaf | Threats | Mitigations |
|---|---|---|
| Mutation tool | MCP-T-034 | MCP-MGMT-001 |
| Tenant escape | MCP-T-034,009 | MCP-MGMT-002, MCP-ID-007 |
| Prohibited capability | MCP-T-034,035 | MCP-MGMT-003 |
| Replay management action | MCP-T-002 | MCP-AUTH-006, MCP-AUTH-008 |

## AT-7 — Event evidence destruction

```
Goal: Prevent a decision/security event from being recorded
├─ Saturate the event queue to force drops
├─ Wedge the export sink
├─ Tamper with stored events
└─ Exploit undefined loss policy for critical classes
```

| Leaf | Threats | Mitigations |
|---|---|---|
| Queue saturation | MCP-T-044 | MCP-EVENT-001,002 |
| Wedge export | MCP-T-044 | MCP-EVENT-001,002 |
| Tamper stored events | MCP-T-045 | MCP-EVENT-005 |
| Undefined loss policy | MCP-T-044 | MCP-EVENT-002 — for critical classes **fail closed AND** enter degraded mode + alert + integrity-protected loss counter (**not** "fail closed *or* degrade"); see [`EVENT-MODEL.md`](EVENT-MODEL.md) §4a and ADR-0024 §D-5 |

## AT-8 — Control Plane compromise / split-brain

```
Goal: Get Data Planes to enforce wrong or partial configuration
├─ Publish a stale snapshot (fenced-out CP)
├─ Deliver a partial/corrupt snapshot
├─ Exploit mixed-version CP/DP semantics
└─ Force split-brain across Data Planes
```

| Leaf | Threats | Mitigations |
|---|---|---|
| Stale snapshot | MCP-T-047,049 | MCP-HA-001 |
| Partial/corrupt snapshot | MCP-T-047 | MCP-CPDP-002 |
| Mixed-version | MCP-T-050 | MCP-CPDP-003 |
| Split-brain | MCP-T-048 | MCP-HA-001,002 |

## AT-9 — Outbound connector / DMZ compromise

```
Goal: Hijack the on-prem ↔ cloud trust link
├─ Impersonate the connector identity
├─ Replay a tunnel session
├─ Abuse the DMZ endpoint (rebinding / rate / origin)
└─ Break tenant binding
```

| Leaf | Threats | Mitigations |
|---|---|---|
| Impersonate connector | MCP-T-051 | MCP-CONNECT-001,002 |
| Tunnel replay | MCP-T-051 | MCP-CONNECT-002 |
| DMZ abuse | MCP-T-052,031 | MCP-CONNECT-003 + **MCP-INSP-009** (listener-side host allowlist + bind-configured-interfaces + E2E rebinding proof, **Future DMZ gate**). `MCP-INSP-008` is the PR-1 **validation primitive only** and does **not** close this leaf — a live listener is required. |
| Break tenant binding | MCP-T-010,053 | MCP-CONNECT-004 (connector/DMZ sessions — **PR-C / Future DMZ gate**). *V1 Model A tenant binding is `MCP-ID-007` at PR-3, not this leaf.* |

## AT-10 — Protocol-kernel subversion (PR-1)

```
Goal: Subvert the MCP protocol kernel before identity/policy ever run
├─ Parser differential (duplicate/ambiguous keys) so downstream sees a different message
├─ Confuse request/response classification or request-ID correlation
├─ Exhaust the parser (oversized / depth / field / string / slow-input) or crash it
├─ Negotiate an unknown/weaker protocol version, or exploit adapter differential
└─ Confuse protocol/session state (mid-session rebind, cancellation race, reconnect replay)
```

| Leaf | Threats | Mitigations |
|---|---|---|
| Parser differential | MCP-T-058,057,065 | MCP-PROTO-001,013 |
| Classification / ID confusion | MCP-T-059,060,061,071 | MCP-PROTO-002,003,004 |
| Parse-time exhaustion / crash | MCP-T-063,064,073,074,062 | MCP-PROTO-005,006,007,008,009,013 |
| Version confusion / adapter differential | MCP-T-066,067,068 | MCP-PROTO-010,011 |
| Protocol-state confusion (lifecycle/cancellation/reconnect — identity-free) | MCP-T-070,072, protocol-state half of MCP-T-069 | MCP-PROTO-012 (**PR-1**) |
| **Mid-session identity rebind** (resolved-identity binding) | identity half of **MCP-T-069** | **MCP-ID-008** (**PR-3**) — *not* closable by MCP-PROTO-012, whose session context is deliberately opaque and identity-free |

All leaves are gated at **PR-1 except the mid-session identity-rebind leaf, which is gated at PR-3** via
`MCP-ID-008` — PR-1's protocol context carries no resolved identity, so that branch **MUST NOT** be reported
closed at PR-1. Version-confusion fixtures depend on **D-1** closure
([`OPEN-DECISIONS.md`](OPEN-DECISIONS.md)). This tree covers the surface DFD-15 diagrams.

---

## Coverage note

Every leaf above references at least one defined threat ID and at least one requirement ID. The
threat→requirement→test chain for all leaves is consolidated in
[`TEST-TRACEABILITY-MATRIX.md`](TEST-TRACEABILITY-MATRIX.md). Bypass leaves (AT-1 L2) are **residual**
per [`THREAT-MODEL.md`](THREAT-MODEL.md) §12 (R-1) — the V1 mitigation is a documented limitation
(MCP-OPS-004) plus the inbound Origin/Host control — the **MCP-INSP-008** primitive (PR-1) and its
listener-side enforcement **MCP-INSP-009** (PR-5) — not full coverage.
