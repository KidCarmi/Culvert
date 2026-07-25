# On-Premises Connectivity and Data Residency Model

Culvert's MCP capabilities (Management MCP and MCP Security Gateway) run inside the customer's own
environment. Neither capability assumes that a cloud AI client — Claude, ChatGPT, or any other vendor —
can simply "reach" a private network. This document defines the three supported connectivity models, the
security posture of each, the recommended adoption order, and the data-residency truth customers must be
told before any deployment. It exists so that no PR-1+ implementation, sales conversation, or customer
architecture review has to improvise a connectivity story.

**Status: PR-0 design artifact (Proposed).**

> **Decision status — D-8 and D-9 CLOSED (2026-07-24, [`ADR-0024 §D-8`/`§D-9`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md)).**
> **Model A (local enterprise client) is the ONLY supported V1 connectivity model.** The outbound
> connector (**Model B**) is a **post-V1 roadmap extension with its own future implementation slice** — it
> is **NOT** assigned to PR-11 (PR-11 stays Shadow/Canary) and its vendor compatibility stays **[EXT]**
> unverified until a named, date-stamped integration is validated. A hardened **DMZ endpoint (Model C)** is
> **not supported in V1 and is disabled by default.** Host validation + configured-host allowlisting are
> mandatory on **every** HTTP MCP listener; local deployments bind only to explicitly configured
> interfaces. The inbound Origin/Host **validation primitive** (`MCP-INSP-008`) ships in **PR-1**, and the
> **listener-side enforcement** — binding configured interfaces + the host allowlist, proven end-to-end —
> is **`MCP-INSP-009` at PR-5**; PR-1 binds no listener, so the listener-side rebinding threats
> (MCP-T-031/055) are **not** closed until PR-5.
>
> **Config-surface consequence:** "not supported in V1" is enforced, not merely defaulted — V1 validation
> **MUST REJECT** `mcp_gateway_connector_mode` values `outbound-connector` and `dmz-endpoint` across API,
> YAML/env/flag parsing, config import and snapshot apply, so an operator cannot select or persist a mode
> that has no implementation and no security gate ([`CONFIG-SURFACE-MATRIX.md`](CONFIG-SURFACE-MATRIX.md)
> `mcp_gateway_connector_mode`). Correspondingly, Model B/C evidence **MUST NOT** gate V1 GA — see
> [`GO-NO-GO-CHECKLIST.md`](GO-NO-GO-CHECKLIST.md) (On-prem connectivity) and
> [`IMPLEMENTATION-SLICES.md`](IMPLEMENTATION-SLICES.md) (Production Qualification).

**Naming note (`SOURCE REVIEW REQUIRED`):** the source DOCX blueprint index named this document
`ONPREM-CONNECTIVITY-MODEL.md`; PR-0 uses the task-specified filename `ON-PREM-CONNECTIVITY.md`. This is
recorded once here and in [`BLUEPRINT.md`](BLUEPRINT.md) §23 (PR-0 Document Package); no other document
should re-litigate it.

---

## 1. Why this exists

`AI Client → Culvert MCP endpoint → enterprise system` only works if the AI client can physically establish
a connection to Culvert. That connection path is a security decision, not an implementation detail: it
determines whether Culvert exposes any inbound listener to the public internet, whether the customer or the
vendor initiates the session, and what a compromised endpoint on either side can reach. **[INFER]** Three
models cover the realistic deployment space for both Capability A (Management MCP) and Capability B (MCP
Security Gateway); they are architecturally independent of which capability is deployed, though the two
capabilities never share a listener, endpoint, or trust boundary (see [`BLUEPRINT.md`](BLUEPRINT.md) §03 and
[`THREAT-MODEL.md`](THREAT-MODEL.md)). **[REC]**

---

## 2. Model A — Local Enterprise Client

**Topology:** `Internal AI client (Claude Desktop/Code, IDE, internal agent, private AI platform, VDI) →
LAN/VPN → Culvert MCP endpoint`. The Culvert endpoint is reachable only from inside the corporate network
or over an already-established VPN tunnel. **No public ingress exists.** **[REC]**

**Who this fits:** Claude Desktop or Claude Code running on a managed workstation, IDE-integrated agents,
internal automation agents, and private/self-hosted AI platforms that already sit inside the perimeter.
**[REC]**

**Security position:** this is the **simplest first production model** — it introduces no new inbound
attack surface, relies on network controls the customer already operates (LAN segmentation, VPN
authentication), and defers OAuth/WAF/DMZ hardening entirely. **[REC]**

**Requirements engaged:**
- **MCP-ID-007** — every session, including a LAN/VPN-local one, **MUST** be tenant-bound ("tenant identity
  MUST be bound and enforced on **every call**; cross-tenant access MUST be denied", **PR-3**, tenant-escape
  tests); "internal network" is not itself a tenant boundary. **This — not `MCP-CONNECT-004` — is the V1
  Model A tenant-binding requirement**: `MCP-CONNECT-004` is scoped to **connector/DMZ** sessions and gated
  at PR-C / the Future DMZ gate, so citing it here would put Model A on a post-V1 test chain (see
  [`IMPLEMENTATION-SLICES.md`](IMPLEMENTATION-SLICES.md) Production Qualification and
  [`GO-NO-GO-CHECKLIST.md`](GO-NO-GO-CHECKLIST.md)). See
  [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md).
- **MCP-INSP-008 / MCP-INSP-009** — Origin/Host validation prevents DNS-rebinding that would let a malicious
  local web page pivot into the local listener, even when the listener is LAN-only. The **validation
  primitive** is `MCP-INSP-008` (PR-1, no listener); the **listener that binds configured interfaces and
  enforces it end-to-end** is `MCP-INSP-009` (PR-5). **[FACT]** No such inbound Origin/Host anti-rebinding guard exists in the repository today —
  `isSafeRedirectURL` (`proxy_portal.go:152`) is captive-portal-only and does not cover an inbound MCP/SSE
  listener (`internal/ssrf/ssrf.go` guards outbound dials, not inbound Origin/Host). See
  [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md) MCP-INSP-008 / MCP-INSP-009 and
  [`THREAT-MODEL.md`](THREAT-MODEL.md) MCP-T-031/MCP-T-055.

**Data-flow reference:** [`DATA-FLOW-DIAGRAMS.md`](DATA-FLOW-DIAGRAMS.md) DFD-12.

---

## 3. Model B — Outbound-Only Connector

**Topology:** `Culvert (customer environment) → outbound encrypted connection → approved cloud AI
service's connector/tunnel endpoint`. The connection is **customer-initiated**; there is **no unsolicited
inbound port** opened on the customer's perimeter for this path. **[REC]**

**Who this fits:** approved cloud AI vendors whose product supports an enterprise connector or reverse
tunnel mechanism (vendor-specific — see §6). **[REC]**

> **V1 posture (D-8, closed).** Model B is a **post-V1 roadmap extension**. It receives its **own future
> implementation slice and design gate** after V1 (it is **not** folded into PR-11, which remains
> Shadow/Canary) unless a human-approved roadmap change explicitly renumbers the slices. No ChatGPT/Claude/
> other-vendor connector is claimed supported until a named integration is verified against authoritative,
> date-stamped vendor requirements and tested. The future connector must not store or receive production
> upstream credentials. See [`ADR-0024 §D-8`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md).

**Key properties:**

| Property | Requirement |
|---|---|
| Initiation | Customer-initiated outbound only; no unsolicited inbound port. **MCP-CONNECT-001**. |
| Tenant binding | Every connector session **MUST** be tenant-bound. **MCP-CONNECT-004**. |
| Connector identity | mTLS connector identity — the far end authenticates the connector, not just the transport. **MCP-CONNECT-001**. |
| Certificate rotation | Connector certificates **MUST** rotate on a defined schedule without requiring an outage. **MCP-CONNECT-002**. |
| Reconnect behavior | Reconnect attempts **MUST** be bounded (backoff, retry ceiling) — an unbounded reconnect loop is itself an availability risk. **MCP-CONNECT-002**. |
| Degraded mode | A defined degraded mode **MUST** exist for when the connector is down (e.g. fail-closed: no tool calls proxied) rather than an undefined hang or silent fallback. **MCP-CONNECT-002**. |
| Vendor compatibility | Vendor-specific connector/tunnel support **MUST** be verified during integration — do not assume feature parity across vendors. **[EXT]** |
| Data classification | Only policy-approved request/response content is eligible to cross this path (see §5). **MCP-PRIVACY-001**. |

**Threat model engaged:** **MCP-T-051** (outbound connector compromise) is the primary threat this model
must defend against — a compromised connector could be repurposed to originate traffic the customer did not
intend, or to leak the mTLS connector identity. See [`THREAT-MODEL.md`](THREAT-MODEL.md) MCP-T-051 (mapped
to MCP-CONNECT-001/002) and the risk register entry (High severity).

**Data-flow reference:** [`DATA-FLOW-DIAGRAMS.md`](DATA-FLOW-DIAGRAMS.md) DFD-13.

**Vendor-specific compatibility verification `[EXT]`:** whether a given cloud AI vendor's outbound
connector/tunnel product exists, and what identity/rotation/reconnect semantics it offers, is external to
this repository and must be verified per-vendor before this model is marketed as supported for that vendor.
Do not promise universal compatibility (see §5).

---

## 4. Model C — Hardened DMZ Endpoint

**Topology:** `Cloud AI client → public internet → routable remote MCP endpoint (DMZ) → internal mTLS →
Culvert`. This is the only model that exposes a routable, internet-reachable MCP endpoint. **[REC]**

> **V1 posture (D-9, closed).** Model C is **not supported in V1 and is disabled by default.** Model A is
> **sufficient for V1**; the future connector (Model B) does not need to exist first. If ever offered, DMZ
> requires a separate architecture + production-readiness approval and a **signed customer risk
> acceptance**. **Independent of DMZ**, two controls are mandatory on **every** HTTP MCP listener now:
> (1) **host validation + configured-host allowlisting**, and (2) **binding only to explicitly configured
> interfaces** — a local deployment must never default to unrestricted public ingress. **Origin
> validation follows the supported MCP protocol baseline**: validate the `Origin` header on incoming
> Streamable HTTP connections and reject a present-but-invalid Origin with the protocol-required HTTP
> response; do **not** invent a blanket rule that every non-browser client must always send an `Origin`
> header unless the selected protocol version explicitly requires it. Inbound Origin/Host anti-rebinding is
> **split across two layers**: the **validation primitive** (`MCP-INSP-008`) is a **PR-1** requirement (pure,
> listener-independent, no socket), while the **listener-side enforcement** — binding configured interfaces (the only
> accept-time obligation), evaluating the allowlist **per request / per H2 stream after header parsing** (never once
> per connection — `Host`/`Origin` do not exist at accept time and keep-alive/H2 carry many requests per
> connection), **E2E** rebinding proof **including connection reuse** — is **`MCP-INSP-009`** (**PR-5** for the Model A local
> listener; the **Future DMZ gate** for a Model C public listener). **PR-1 binds no listener, so the
> live-listener control for this model is NOT satisfied by PR-1 work.** See
> [`ADR-0024 §D-9`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md) item 6.

**Who this fits:** cloud AI clients that have no supported outbound-connector mechanism and therefore
require a directly reachable remote MCP URL. **[REC]**

**Required controls, all simultaneously:**

| Control | Purpose | Requirement |
|---|---|---|
| OAuth | Authenticate the calling client before any MCP traffic is proxied inward. | **MCP-CONNECT-003**. |
| WAF | Filter malicious HTTP traffic before it reaches the reverse proxy / Culvert. | **MCP-CONNECT-003**. |
| Reverse proxy | Terminate public TLS, present a controlled surface, isolate the DMZ from internal segments. | **MCP-CONNECT-003**. |
| Origin/Host validation | Reject requests whose Origin/Host does not match the expected value — the DNS-rebinding defense for an internet-reachable listener. | **MCP-INSP-009** (listener-side enforcement + E2E proof, Future DMZ gate); `MCP-INSP-008` supplies the PR-1 validation primitive only. |
| Rate limits | Bound abusive or runaway request volume against a now-public endpoint. | **MCP-CONNECT-003**. |
| Internal mTLS | The DMZ-to-Culvert hop is itself mutually authenticated — the DMZ is not implicitly trusted internal network. | **MCP-CONNECT-003**. |
| Explicit risk acceptance | A documented, signed-off risk acceptance is required before this model goes into production — it is the only model with public ingress. | **MCP-CONNECT-003**. |
| Monitoring | Continuous monitoring of the DMZ endpoint (traffic, auth failures, WAF blocks) is required, not optional, given the exposed surface. **[REC]** |
| Abuse response | A defined runbook for responding to detected abuse (e.g. rate-limit trips, WAF blocks, auth-failure spikes) must exist before go-live. **[REC]** |

**Threat model engaged:** **MCP-T-052** (DMZ endpoint abuse) is the threat this model exists to contain,
mapped to MCP-CONNECT-003 and **MCP-INSP-009** (listener-side enforcement; `MCP-INSP-008` is the PR-1
primitive only). See [`THREAT-MODEL.md`](THREAT-MODEL.md) MCP-T-052 (risk
register, High severity) and MCP-T-031 (inbound DNS-rebinding against the MCP/SSE listener, currently
**Missing today** per the SSRF note in §6).

**Data-flow reference:** [`DATA-FLOW-DIAGRAMS.md`](DATA-FLOW-DIAGRAMS.md) DFD-14.

---

## 5. Recommended Deployment Priority

This ordering is carried forward from [`BLUEPRINT.md`](BLUEPRINT.md) §04 and is the canonical adoption
sequence for any customer rollout — do not skip Model A to sell Model C first. **[REC]**

| Priority | Model | Best For | Security Position |
|---|---|---|---|
| 1 | Local enterprise client | Claude Desktop/Code, IDEs, internal agents, VDI and private AI platforms. | No public ingress; direct LAN/VPN access; simplest first production model. |
| 2 | Outbound-only connector | Approved cloud AI services where an enterprise connector/tunnel is supported. | Customer initiates the encrypted connection; no unsolicited inbound port. |
| 3 | Hardened DMZ endpoint | Cloud clients that require a routable remote MCP URL. | OAuth, WAF, origin/host validation, rate limits, internal mTLS and explicit risk acceptance. |

> **V1 support (D-8/D-9, closed):** **only Priority 1 (Model A) is supported in V1.** Priority 2 (Model B
> connector) is a **post-V1 roadmap slice**; Priority 3 (Model C DMZ) is **not supported in V1 and is
> default-off**. The ordering above is the adoption *sequence*, not a statement that all three ship in V1.

---

## 6. Data Residency Truth

State this to every customer and in every deployment conversation, without softening it:

> **Culvert controls which content may leave the environment, but it does not turn a cloud AI model into
> an on-premises model.**

What that means concretely:

- **Stays on-prem, always, regardless of connectivity model:** production credentials, policy, the tool
  catalog, approval state, and internal server connections. None of these cross any of the three
  connectivity models above.
- **What may cross:** only policy-approved request and response content — content that has already passed
  the policy engine's decision (see [`BLUEPRINT.md`](BLUEPRINT.md) §11) — is eligible to leave the
  environment over the selected connectivity path (Model A, B, or C).
- **What runs before that content leaves:** DLP, redaction, and destination controls execute before any
  approved content crosses the boundary. This is a hard requirement, not a best-effort filter. **MCP-PRIVACY-001**.
- **What every deployment needs, no exceptions:** a documented data-flow diagram (see
  [`DATA-FLOW-DIAGRAMS.md`](DATA-FLOW-DIAGRAMS.md)), a retention model, a privacy review, and a
  customer-owned allowlist of approved destinations. **MCP-PRIVACY-003**.
- **What the product must not promise:** universal compatibility with ChatGPT, Claude, or any specific
  cloud vendor's connectivity mechanism, until that vendor's connector requirements have actually been
  validated (§3, `[EXT]`). Marketing or sales language that implies unconditional cross-vendor support gets
  ahead of what has been verified.

This is why a cloud AI service processing Culvert-approved content still does so under **that vendor's**
contract and configuration — Culvert's data-residency control is a gate on what leaves, not a guarantee of
where it is subsequently processed. Threat **MCP-T-053** (cloud AI data-residency risk) captures this
residual risk explicitly; it is accepted per deployment via customer contract, allowlist, and
DLP-before-egress, not eliminated. See [`THREAT-MODEL.md`](THREAT-MODEL.md) MCP-T-053 (risk register entry
R-5, owner Privacy/Legal).

---

## 7. SSRF and Inbound-Listener Constraints

**[FACT]** The repository's existing SSRF guard (`internal/ssrf/ssrf.go`) rejects private-IP origins:
`PrivateIP` (`ssrf.go:36-72`) covers RFC1918 + CGN + link-local + metadata + NAT64 + ULA ranges,
`PrivateHost` (`ssrf.go:86-103`) fails closed, and the dialer's `Control` callback re-checks the peer IP at
connect time (`ssrf.go:126-139`) specifically to close the DNS-rebinding TOCTOU window between a resolved
hostname and the socket that is actually dialed. This is a recorded **constraint**, not a capability to
build on directly: it protects **outbound** dials Culvert itself makes (e.g. to an internal mirror or a
connector's origin), and is the correct reference pattern for any new outbound leg introduced by Models B
or C. It does **not** cover the **inbound** side — validating the Origin/Host header presented by a client
connecting *to* Culvert's own MCP/SSE listener is a distinct, currently-unimplemented control
(**MCP-INSP-008** primitive at PR-1 + **MCP-INSP-009** listener enforcement at PR-5; see §2 and §4). Both directions matter for these connectivity models: an internal
mirror or connector origin must not resolve to a private/metadata address unexpectedly (outbound, existing
guard), and the MCP/SSE listener itself must not accept a rebound Origin/Host (inbound, not yet built).

**Threats engaged:** **MCP-T-053** (data-residency, §6), **MCP-T-036** (SSRF), **MCP-T-037** (DNS
rebinding), and **MCP-T-031** (inbound DNS-rebinding against the MCP/SSE listener — the inbound-specific
threat that the MCP-INSP-008 primitive + **MCP-INSP-009** listener enforcement exist to close — a live
listener is required, so PR-1 alone does not close it). See [`THREAT-MODEL.md`](THREAT-MODEL.md) §9 (DFD-to-threat
matrix, DFD-12/13/14 rows) and §11 (risk register).

---

## 8. Cross-References

- Connectivity requirements: [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md) MCP-CONNECT-001..004,
  MCP-INSP-008 (PR-1 primitive) + **MCP-INSP-009** (PR-5 listener enforcement), **MCP-ID-007** (V1 Model A
  tenant binding, PR-3), MCP-PRIVACY-001/003.
- Threats: [`THREAT-MODEL.md`](THREAT-MODEL.md) MCP-T-051 (outbound connector compromise), MCP-T-052 (DMZ
  abuse), MCP-T-053 (cloud AI data-residency), MCP-T-036 (SSRF), MCP-T-037 (DNS rebinding), MCP-T-031
  (inbound DNS-rebinding vs the MCP/SSE listener).
- Data-flow diagrams: [`DATA-FLOW-DIAGRAMS.md`](DATA-FLOW-DIAGRAMS.md) DFD-12 (local enterprise client),
  DFD-13 (outbound-only connector), DFD-14 (hardened DMZ endpoint).
- Deployment priority and product framing: [`BLUEPRINT.md`](BLUEPRINT.md) §04.
- Implementation sequencing note (updated by D-8/D-9, [`ADR-0024`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md)):
  the **local-listener** wiring for Model A folds into **PR-5** (Observe runtime), and CP/DP snapshot
  semantics into **PR-10** (CP/DP & HA). The **outbound connector (Model B) is NOT part of PR-11** and is
  **not** V1 — it is a **post-V1 slice** with its own design gate. DMZ (Model C) is deferred and
  default-off. The Inbound Origin/Host **validation primitive** (`MCP-INSP-008`) ships in **PR-1**; its
  **listener-side enforcement** (`MCP-INSP-009`) ships with the listener in **PR-5** (Model A) / the Future
  DMZ gate (Model C). Any distinct connectivity
  slice remains tracked in [`OPEN-DECISIONS.md`](OPEN-DECISIONS.md) (D-8/D-12).

---

## 9. Risk Note

Consistent with the rest of the PR-0 package: this document describes a design baseline, not a validated
implementation. No connectivity model above has been exercised end-to-end in this repository — there is no
existing MCP/JSON-RPC listener in the inspected paths **[FACT]**, and Model C's inbound Origin/Host defence
is explicitly **not yet built** — neither the `MCP-INSP-008` primitive nor its `MCP-INSP-009` listener-side
enforcement. Risk from untested connectivity paths is Low for
the read-only Phase 1 investigation, but the current repository test baseline remains unverified in this
session.
