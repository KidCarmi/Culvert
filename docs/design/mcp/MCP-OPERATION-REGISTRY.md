# MCP Operation Registry — the Culvert-reviewed admitted-method surface

**Status:** Proposed (PR-0 design artifact; part of the RPR-1 remediation for board blockers
[#925](https://github.com/KidCarmi/Culvert/issues/925) and
[#928](https://github.com/KidCarmi/Culvert/issues/928)). No control below is implemented; this is
design-time authority only. Do not treat as organizationally Accepted — [ADR-0024](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md)
remains **Proposed** and **PR-1 remains NO-GO**.

This document is the **single authoritative registry** of every MCP JSON-RPC method Culvert admits, on
which leg, in which direction, and to which handling owner. It is the authority every version adapter must
**narrow to**: a method valid in a negotiated protocol version but **absent from this registry is rejected**
(`MCP-PROTO-016`). It does **not** choose D-1's supported-version baseline — D-1 remains OPEN.

`resources/read`, `prompts/*`, `completion/*`, `sampling/*`, `elicitation/*`, `roots/*` and `tasks/*`
appear here **only** as explicit **rejected** rows. The admitted surface is deliberately the smallest safe
V1 set: `initialize`, `notifications/initialized`, `ping`, `notifications/cancelled`, `tools/list`,
`tools/call` — and nothing else. Responses carry no method and are handled through requestor-scoped
correlation, never as registry methods.

---

## 1. Peer-role two-leg kernel model

The **same** protocol-kernel implementation processes hostile bytes from **both** untrusted legs:

- the **client-facing** leg (the agent/client → Culvert, TB-1 / TB-7); and
- the **upstream-server-facing** leg (Culvert ↔ the upstream MCP server, TB-2).

There is **no second, unspecified decoder for upstream bytes.** The kernel API shape carries an explicit
**peer role / leg**, and the parser, framing, envelope classification, version adapter, size/depth/resource
bounds and cleanup invariants (`MCP-PROTO-001..014`) apply **identically to both legs** — see `MCP-PROTO-015`
and DFD-16. A peer-role-specific method registry (the rows below) MAY produce different **admission**
outcomes per leg, but the **security parser itself MUST NOT diverge** between legs.

## 2. Request identity and correlation (requestor-scoped)

Outstanding-request correlation state MUST be keyed by at least the composite
`(session, requestor-role/direction, request-id)`. Where the design uses distinct session IDs per transport
leg, that is stated and the **requestor dimension is preserved regardless**. The same JSON-RPC `id` MAY be
outstanding **concurrently in both directions** without cross-correlation — each resolves only to its own
requestor. One direction MUST NEVER **resolve, complete, cancel, delete, overwrite or release** the other
direction's state. Any bridge mapping between a client-leg request and an upstream-leg request MUST be
**explicit** and MUST NOT assume equal wire IDs. (Amends `MCP-PROTO-003`.)

## 3. Cancellation semantics

- A cancellation MUST reference only a request **issued in the same direction**, and only the **owning
  requestor** may cancel it.
- A same-session **opposite-direction** `id` match has **no effect** — it neither cancels nor releases the
  other direction's state.
- The `initialize` request MUST NOT be cancelled.
- Wrong-owner and wrong-direction cancellation are rejected or ignored per the message-class contract
  (`MCP-PROTO-013`), **without any state deletion**.
- A cancellation arriving **after** a response has completed is a tolerated **late race** and MUST NOT be
  classified as a duplicate-completion fault (reconciles the spec-tolerated post-response cancellation with
  `MCP-PROTO-012`'s duplicate-completion rejection).
- A rejected notification produces **no wire response**; a malformed or rejected cancellation MUST NOT
  release legitimate outstanding state (the `MCP-PROTO-013` remote-state-deletion guard, now reachable on the
  legitimate cancellation path across both directions).
- `tasks/cancel` remains **rejected** because the tasks capability is not advertised in V1.

Bounded cleanup and timeout behavior (`MCP-PROTO-008/012/013`) are preserved unchanged.

## 4. The operation registry

Column 14 (**Handling owner**) uses a controlled vocabulary that this document's gate parses mechanically:

- `kernel-terminal` — the method is **admitted** and handled + answered by the kernel; it is never dispatched
  downstream.
- `decision-point: <name>` — the method is **admitted** and dispatched to exactly one **named** downstream
  decision point.
- `rejected` — the method is **rejected** in V1 and has **no dispatch owner**.

**Forward/reverse parity (`MCP-PROTO-016`):** for every **admitted** row, exactly one of {names a decision
point, is `kernel-terminal`} holds — never both, never neither. Every **rejected** row has owner `rejected`.
No dispatch path exists for a method absent from this table. Management and Gateway carry **separate rows,
separate authorization namespaces and separate handling owners even for the same wire method**.

| Capability | Leg / peer role | Requestor & direction | Method | V1 status | Operation class | Resource/destination extraction | Authorization namespace | Catalog / drift | Credential scope | Default-deny semantics | Audit / durability | Legal policy actions | Handling owner | Capability advertisement | Impl gate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Gateway | client-facing peer | client → Culvert (c→s) | initialize | admitted | control | none (handshake; supplies version/capabilities) | protocol-version + capability set | not catalogued | none | n/a (handshake, pre-identity) | proto-lifecycle event / ordinary | none (kernel ack/err only) | kernel-terminal | n/a (lifecycle, not a capability) | PR-1 |
| Gateway | client-facing peer | client → Culvert (notif) | notifications/initialized | admitted | control | none | protocol-lifecycle | not catalogued | none | n/a (notification) | proto-lifecycle event / ordinary | none (no wire response) | kernel-terminal | n/a (lifecycle) | PR-1 |
| Gateway | client-facing peer | client → Culvert (req; either dir) | ping | admitted | control | none | protocol-lifecycle | not catalogued | none | n/a (liveness) | proto-lifecycle event / ordinary | pong (kernel) | kernel-terminal | n/a (lifecycle) | PR-1 |
| Gateway | client-facing peer | client → Culvert (notif) | notifications/cancelled | admitted | control | request-id in params, resolved ONLY vs this requestor's same-direction outstanding set | protocol-correlation | not catalogued | none | n/a (notification) | proto-lifecycle event / ordinary | none (no wire response) | kernel-terminal | n/a (lifecycle) | PR-1 |
| Gateway | client-facing peer | client → Culvert (req) | tools/list | admitted | discovery | none at request; result feeds the reviewed tool catalog | tool-name (Gateway) | catalogued + fingerprinted (drift source) | none at list time | default-deny after catalog/discovery filter | discovery decision event / ordinary | ALLOW / DENY / FILTER | decision-point: tool catalog & discovery (DFD-4) | tools capability advertised | PR-1 (admission) / PR-2 (catalog) |
| Gateway | client-facing peer | client → Culvert (req) | tools/call | admitted | read / write / destructive (per tool risk) | params → operand + destination (MCP-INSP-004) | tool-name (Gateway) | catalogued + fingerprinted | full credential-broker scope (MCP-CRED-002) | default-deny on a representable (tool, args, resource, destination) | tool-call decision event / durable | all nine policy actions | decision-point: policy engine (DFD-5) | tools capability advertised | PR-6 |
| Management | client-facing peer | client → Culvert (c→s) | initialize | admitted | control | none (handshake) | Mgmt protocol-version + capability | not catalogued | none | n/a (handshake) | mgmt proto-lifecycle event / ordinary | none (kernel ack/err) | kernel-terminal | n/a (lifecycle) | PR-1 |
| Management | client-facing peer | client → Culvert (notif) | notifications/initialized | admitted | control | none | mgmt protocol-lifecycle | not catalogued | none | n/a (notification) | mgmt proto-lifecycle event / ordinary | none (no wire response) | kernel-terminal | n/a (lifecycle) | PR-1 |
| Management | client-facing peer | client → Culvert (req; either dir) | ping | admitted | control | none | mgmt protocol-lifecycle | not catalogued | none | n/a (liveness) | mgmt proto-lifecycle event / ordinary | pong (kernel) | kernel-terminal | n/a (lifecycle) | PR-1 |
| Management | client-facing peer | client → Culvert (notif) | notifications/cancelled | admitted | control | request-id in params, resolved ONLY vs this requestor's same-direction outstanding set | mgmt protocol-correlation | not catalogued | none | n/a (notification) | mgmt proto-lifecycle event / ordinary | none (no wire response) | kernel-terminal | n/a (lifecycle) | PR-1 |
| Management | client-facing peer | client → Culvert (req) | tools/list | admitted | discovery | none; result is the reviewed Management operation catalog | mgmt-operation (separate from Gateway tool-name) | mgmt operations are reviewed, not third-party-fingerprinted | none at list time | default-deny after Management authorization | mgmt discovery decision event / ordinary | ALLOW / DENY / FILTER | decision-point: Management authorization (D-13, read-only) | mgmt tools capability advertised | PR-1 (admission) / PR-6 |
| Management | client-facing peer | client → Culvert (req) | tools/call | admitted | read + draft/validate/simulate ONLY (D-13; no activation/cred-mutation/prod-state) | params → mgmt operand | mgmt-operation (separate namespace) | reviewed mgmt operations | mgmt scope; no production credential mutation | default-deny; mutation/activation actions are unavailable in V1 | mgmt decision event / durable | ALLOW / DENY / REQUIRE_APPROVAL (read/draft/validate/simulate) — no activation | decision-point: Management authorization (D-13) | mgmt tools capability advertised | PR-6 |
| Gateway | client-facing peer | client → Culvert (req) | resources/read | rejected | read (would be exfil primitive) | n/a — rejected before extraction; a URI operand has no tool identity to police | n/a (not admitted) | not catalogued | n/a (no credential path) | n/a (never reaches policy — rejected at admission) | admission-reject event / ordinary | none (rejected at ADMIT; no wire response where message-class forbids one) | rejected | not advertised | PR-1 |
| Gateway | client-facing peer | client → Culvert (req) | resources/* (list, templates, subscribe) | rejected | read/discovery | n/a — rejected; resources are not an admitted Culvert operand class in V1 | n/a (not admitted) | not catalogued | n/a (no credential path) | n/a (never reaches policy — rejected at admission) | admission-reject event / ordinary | none (rejected at ADMIT; no wire response where message-class forbids one) | rejected | not advertised | PR-1 |
| Gateway | client-facing peer | client → Culvert (req) | prompts/* (list, get) | rejected | read/discovery | n/a — rejected; prompts are not admitted in V1 | n/a (not admitted) | not catalogued | n/a (no credential path) | n/a (never reaches policy — rejected at admission) | admission-reject event / ordinary | none (rejected at ADMIT; no wire response where message-class forbids one) | rejected | not advertised | PR-1 |
| Gateway | client-facing peer | client → Culvert (req) | completion/complete | rejected | read | n/a — rejected; completion is not admitted in V1 | n/a (not admitted) | not catalogued | n/a (no credential path) | n/a (never reaches policy — rejected at admission) | admission-reject event / ordinary | none (rejected at ADMIT; no wire response where message-class forbids one) | rejected | not advertised | PR-1 |
| Gateway | client-facing peer | client → Culvert (req) | tasks/cancel | rejected | control | n/a — tasks capability not advertised (a second mandatory cancellation mechanism is not admitted in V1) | n/a (not admitted) | not catalogued | n/a (no credential path) | n/a (never reaches policy — rejected at admission) | admission-reject event / ordinary | none (rejected at ADMIT; no wire response where message-class forbids one) | rejected | not advertised | PR-1 |
| Gateway | client-facing peer | client → Culvert (req) | tasks/* (create, list, get, result) | rejected | control/read | n/a — tasks capability not advertised in V1 | n/a (not admitted) | not catalogued | n/a (no credential path) | n/a (never reaches policy — rejected at admission) | admission-reject event / ordinary | none (rejected at ADMIT; no wire response where message-class forbids one) | rejected | not advertised | PR-1 |
| Gateway | client-facing peer | client → Culvert (notif/req) | logging/* & notifications/*_list_changed | rejected | control | n/a — optional method families not added to the reviewed registry by this PR | n/a (not admitted) | not catalogued | n/a (no credential path) | n/a (never reaches policy — rejected at admission) | admission-reject event / ordinary | none (rejected at ADMIT; no wire response where message-class forbids one) | rejected | not advertised | PR-1 |
| Management | client-facing peer | client → Culvert (req) | resources/read | rejected | read | n/a — Management admits only its six lifecycle/tools methods; every other method is rejected | n/a (not admitted) | not catalogued | n/a (no credential path) | n/a (never reaches policy — rejected at admission) | admission-reject event / ordinary | none (rejected at ADMIT; no wire response where message-class forbids one) | rejected | not advertised | PR-1 |
| Gateway | upstream-server-facing peer | Culvert → server (c→s, outbound) | initialize | admitted | control | none (Culvert-originated handshake to upstream) | upstream protocol-version | not catalogued | none | n/a (Culvert-originated) | proto-lifecycle event / ordinary | none | kernel-terminal | n/a (lifecycle) | PR-1 |
| Gateway | upstream-server-facing peer | Culvert → server (c→s, outbound) | notifications/initialized | admitted | control | none (Culvert-originated; completes the upstream handshake so tools/list & tools/call may begin) | upstream protocol-lifecycle | not catalogued | none | n/a (Culvert-originated notification) | proto-lifecycle event / ordinary | none (no wire response) | kernel-terminal | n/a (lifecycle) | PR-1 |
| Gateway | upstream-server-facing peer | either direction | ping | admitted | control | none | upstream protocol-lifecycle | not catalogued | none | n/a (liveness) | proto-lifecycle event / ordinary | pong (kernel) | kernel-terminal | n/a (lifecycle) | PR-1 |
| Gateway | upstream-server-facing peer | Culvert → server (c→s, outbound) | notifications/cancelled | admitted | control | request-id resolved ONLY vs Culvert-originated upstream requests in the SAME (Culvert→server) direction — the legitimate outbound path that PROPAGATES a client cancellation to the upstream | upstream protocol-correlation (Culvert = requestor) | not catalogued | none | n/a (Culvert-originated notification) | proto-lifecycle event / ordinary | none (no wire response) | kernel-terminal | n/a (lifecycle) | PR-1 |
| Gateway | upstream-server-facing peer | server → Culvert (reverse notif) | notifications/cancelled | admitted | control | request-id resolved ONLY vs SERVER-originated outstanding requests (same server→Culvert direction); server-originated requests are NOT admitted in V1, so this references none and NEVER cancels/releases a Culvert-originated request | upstream protocol-correlation (server = requestor) | not catalogued | none | n/a (notification) | proto-lifecycle event / ordinary | none (no wire response; never releases Culvert-originated state — MCP-PROTO-015) | kernel-terminal | n/a (lifecycle) | PR-1 |
| Gateway | upstream-server-facing peer | Culvert → server (c→s, outbound) | tools/list | admitted | discovery | result → catalog + fingerprint/drift process | tool-name (Gateway) | catalogued + fingerprinted (drift source) | none | default-deny after catalog/discovery | discovery decision event / ordinary | ALLOW / DENY / FILTER | decision-point: tool catalog & drift (DFD-4) | (Culvert-originated; no advertisement) | PR-1 / PR-2 |
| Gateway | upstream-server-facing peer | Culvert → server (c→s, outbound) | tools/call | admitted | read / write / destructive | materialization of the client-leg decision (MCP-POLICY-004 ordering) | tool-name (Gateway) | catalogued + fingerprinted | selected upstream credential (post-ALLOW, MCP-CRED-001) | default-deny already applied on the client leg; upstream call is the materialization only | tool-call decision event / durable | materialize / block (per the client-leg decision) | decision-point: policy engine (DFD-5) | (Culvert-originated; no advertisement) | PR-6 |
| Gateway | upstream-server-facing peer | server → Culvert (reverse req) | sampling/createMessage | rejected | control (reverse-channel inference/exfil oracle) | n/a — server-originated request rejected; Culvert advertises no sampling client capability | n/a (not admitted) | not catalogued | n/a (no credential path) | n/a (never reaches policy — rejected at admission) | admission-reject event / ordinary | none (rejected at ADMIT; no wire response where message-class forbids one) | rejected | not advertised | PR-1 |
| Gateway | upstream-server-facing peer | server → Culvert (reverse req) | elicitation/create | rejected | control | n/a — server-originated request rejected; no elicitation capability advertised | n/a (not admitted) | not catalogued | n/a (no credential path) | n/a (never reaches policy — rejected at admission) | admission-reject event / ordinary | none (rejected at ADMIT; no wire response where message-class forbids one) | rejected | not advertised | PR-1 |
| Gateway | upstream-server-facing peer | server → Culvert (reverse req) | roots/list | rejected | read | n/a — server-originated request rejected; no roots capability advertised | n/a (not admitted) | not catalogued | n/a (no credential path) | n/a (never reaches policy — rejected at admission) | admission-reject event / ordinary | none (rejected at ADMIT; no wire response where message-class forbids one) | rejected | not advertised | PR-1 |
| Gateway | upstream-server-facing peer | server → Culvert (reverse req) | tasks/cancel | rejected | control | n/a — server-originated tasks/cancel rejected; tasks capability not advertised on either leg | n/a (not admitted) | not catalogued | n/a (no credential path) | n/a (never reaches policy — rejected at admission) | admission-reject event / ordinary | none (rejected at ADMIT; no wire response where message-class forbids one) | rejected | not advertised | PR-1 |

## 5. Explicitly unsupported in V1 (rejected)

Culvert MUST NOT advertise capabilities for, proxy, or dispatch any method not admitted above. In
particular, and as pinned by the rejected rows: `resources/*` (incl. `resources/read`), `prompts/*`,
`completion/*`, server-originated `sampling/createMessage`, `elicitation/create`, `roots/list`, and
`tasks/*` (incl. `tasks/cancel`) are **rejected**, never admitted-and-unpoliced. A server-originated
reverse-channel request on the upstream leg is rejected at admission; there is **no reverse-channel proxying
in V1**. Capability advertisement (column 15) **exactly matches** the admitted registry — Culvert advertises
no client capability for any rejected class.

## 6. Configuration surface

The admitted set is selected by two Culvert-reviewed, signed/controlled method-registry **profile
references**, not an operator-provided method list:

- `mcp_gateway_method_registry_ref` (Gateway) — synced CP→DP;
- `mcp_mgmt_method_registry_ref` (Management) — CP-local.

Both are `policy-ref` / **RC-3** rows in [CONFIG-SURFACE-MATRIX.md](CONFIG-SURFACE-MATRIX.md) with full
config/API/GUI/OpenAPI/registry semantics under `MCP-CFG-001` / D-15. **For V1 only the reviewed
tools-only profile may be selected.** No YAML, CLI, API or GUI input MAY add a method absent from the
reviewed registry; there is **no `allow_unknown_methods` option** and no blanket exemption — a method absent
from the reviewed registry is rejected regardless of configuration.

## Cross-references

- [SECURITY-REQUIREMENTS.md](SECURITY-REQUIREMENTS.md) — `MCP-PROTO-002/003/011/012/013`, `MCP-PROTO-015`
  (peer-role/requestor-scoped state), `MCP-PROTO-016` (admitted-method registry parity),
  `MCP-POLICY-001/004`, `MCP-CRED-002`, `MCP-TOOL-*`.
- [PROTOCOL-COMPATIBILITY.md](PROTOCOL-COMPATIBILITY.md) §3/§5/§7 — id-correlation, cancellation, and the
  unsupported-capability / non-support rows that reference this registry.
- [DATA-FLOW-DIAGRAMS.md](DATA-FLOW-DIAGRAMS.md) — DFD-15 (peer-role ingress) and DFD-16 (two-leg kernel,
  method admission, decision-point / kernel-terminal / rejection branches, no reverse-channel proxying).
- [MCP-POLICY-MODEL.md](MCP-POLICY-MODEL.md) §1/§7 — the decision tuple's protocol-method / operation-class /
  operation-namespace / normalized-operand dimensions.
- [THREAT-MODEL.md](THREAT-MODEL.md) §11 — `MCP-T-076` (reverse-channel/requestor-direction state confusion),
  `MCP-T-077` (admitted-but-unpoliced method dispatch); TB-2 protocol obligations.
