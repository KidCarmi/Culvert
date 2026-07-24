# MCP Data-Flow Diagrams

Fifteen numbered data-flow diagrams (DFD-1 … DFD-15) for the MCP subsystem. Each marks its **trust
boundaries** (TB-1 … TB-7 from [`THREAT-MODEL.md`](THREAT-MODEL.md)) and the dominant threats. **Status:
PR-0 design artifact (Proposed).** These are design flows; no runtime exists. Diagrams are Mermaid so they
render on GitHub and diff cleanly. Management MCP (Capability A) and the Security Gateway (Capability B)
are kept as **separate** flows. **DFD-15 (the PR-1 protocol-kernel decode path) was added by the PR-1
remediation** (`PR1-READINESS-REMEDIATION.md`, finding M-3).

Trust-boundary legend: **TB-1** agent/client↔Culvert · **TB-2** Culvert↔MCP server · **TB-3** CP↔DP ·
**TB-4** runtime↔events · **TB-5** admin↔publication · **TB-6** cloud AI↔customer network · **TB-7**
Management MCP↔control surface.

---

## DFD-1 — Management MCP read-only request (Capability A)

Crosses TB-7. Threats: MCP-T-034, MCP-T-035, MCP-T-010.

```mermaid
flowchart LR
  AC[AI Client] -- bearer: mgmt scope --> L1{{/mcp/management listener}}
  subgraph Culvert Management MCP
    L1 --> AZ[Mgmt authz: RBAC + tenant + read-only default]
    AZ --> RO[Bounded read-only tool]
    RO --> RED[Redact + bound output]
  end
  RED --> AC
  AZ -. deny/quarantine .-> EV[(Decision events)]
  classDef tb fill:#fee,stroke:#c00;
  class L1 tb
```
TB-7 at the listener/authz edge. No mutation tool exists (MCP-MGMT-001). Output redacted (MCP-MGMT-004).

## DFD-2 — Management MCP draft & validation (Capability A)

Crosses TB-7, TB-5. Threats: MCP-T-034, MCP-T-046.

```mermaid
flowchart LR
  AC[AI Client] --> L1{{/mcp/management}}
  L1 --> DR[Draft policy tool]
  DR --> VAL[Validate syntax + simulate blast radius]
  VAL --> AUD[Full audit: no activation]
  AUD --> AC
  VAL -. never publishes .-> X[(No snapshot change)]
```
Draft/validate/simulate only; **no** activation (MCP-MGMT-001). Simulation is read-only.

## DFD-3 — Future Management MCP mutation approval (Capability A, out of scope V1)

Crosses TB-7, TB-5, TB-3. Threats: MCP-T-034, MCP-T-032, MCP-T-033.

```mermaid
flowchart LR
  AC[AI Client] --> PLAN[Plan] --> VALID[Validate] --> APPR[Human approve four-eyes]
  APPR --> PUB[Publish signed snapshot]
  PUB --> DP[(Data Planes)]
  APPR -. denied .-> EV[(Decision events)]
```
**Out of scope until plan→validate→approve→apply exists** (MCP-MGMT-001). Shown for completeness.

## DFD-4 — Security Gateway tool discovery (Capability B)

Crosses TB-1, TB-2. Threats: MCP-T-011..017, MCP-T-020.

```mermaid
flowchart LR
  A[AI Agent] --> G{{/mcp/gateway/server-id}}
  subgraph Gateway
    G --> REG[Server registry: allowlist + TLS identity]
    REG --> DISC[Discover + list tools]
    DISC --> FP[Canonical fingerprint + drift classify]
    FP --> Q{Unknown / expansion?}
    Q -- yes --> QUAR[QUARANTINE: no execution]
    Q -- no --> CAT[(Tool catalog)]
  end
  REG -- mTLS/TLS verify --> S[MCP Server]
  classDef tb fill:#fee,stroke:#c00;
  class G,REG tb
```
Unregistered server denied (MCP-SERVER-001); unknown tool quarantined (MCP-TOOL-006).

## DFD-5 — Security Gateway tool call (Capability B, primary path)

Crosses TB-1, TB-2. Threats: MCP-T-003..008, MCP-T-019, MCP-T-046.

```mermaid
flowchart LR
  A[AI Agent] -- bearer: aud=Culvert --> G{{/mcp/gateway/server-id}}
  subgraph Gateway
    G --> ID[Identity resolver: token+aud+resource+replay]
    ID --> II[Input inspection]
    II --> POL[Policy engine: pure, default-deny]
    POL --> DEC{Decision}
    DEC -- ALLOW-class --> CB[Credential broker]
    DEC -- DENY/QUARANTINE/APPROVAL --> EV[(Decision events)]
    CB --> CALL[Call upstream with scoped cred]
    CALL --> OI[Output inspection]
    OI --> EV
  end
  CALL -- mTLS --> S[Approved MCP Server]
  OI --> A
  classDef tb fill:#fee,stroke:#c00;
  class G,CALL tb
```
No token passthrough (MCP-AUTH-005); credential selected **after** ALLOW (MCP-POLICY-004).

## DFD-6 — Credential selection (Capability B)

Crosses TB-2. Threats: MCP-T-022..025, MCP-T-005.

```mermaid
flowchart LR
  DEC[Policy ALLOW-class] --> SEL[Select credential profile by env/server/tool/resource]
  SEL --> SCOPE{Scope <= action?}
  SCOPE -- no --> DENY[DENY + security event]
  SCOPE -- yes --> FETCH[Fetch short-lived cred bounded+encrypted cache]
  FETCH --> USE[Attach to upstream call only]
  USE -. never returned to agent .-> A[Agent]:::x
  classDef x stroke-dasharray: 5 5,stroke:#c00;
```
Agent never receives the credential (MCP-CRED-001); over-broad rejected (MCP-CRED-002); fail-closed on
broker failure for high-risk (MCP-CRED-006).

## DFD-7 — Input inspection (Capability B)

Crosses TB-1. Threats: MCP-T-026, MCP-T-036, MCP-T-037, MCP-T-041, MCP-T-040.

```mermaid
flowchart LR
  ARG[Tool arguments] --> SCH[Semantic schema conformance MCP-INSP-001<br/>structural size/depth/field bounds already enforced at the protocol kernel — DFD-15, MCP-PROTO-006]
  SCH --> SEC[Secret/DLP detection]
  SEC --> DST[Destination check: scheme/host/IP private policy]
  DST --> DNS[DNS pin: resolve->connect rebinding guard]
  DNS --> RES[Extract resource fields]
  RES --> POL[to Policy]
  SEC -. secret found .-> BLOCK[DENY MCP.INSPECTION.SECRET_FOUND]
  DST -. private .-> BLOCK
```
Reuses the SSRF peer-IP recheck primitive (`internal/ssrf` `Control` :126-139) — MCP-INSP-004/005.

## DFD-8 — Output inspection (Capability B)

Crosses TB-2, TB-4. Threats: MCP-T-027, MCP-T-038, MCP-T-039.

```mermaid
flowchart LR
  RESP[Upstream response] --> OB[Size/type/schema bounds + truncation]
  OB --> RED[Secret/PII redact or block]
  RED --> LBL[Label injection/elicitation content]
  LBL --> HASH[Retain hashes/labels; drop raw by default]
  HASH --> A[Agent]
  HASH --> EV[(Decision events)]
```
Raw output not stored by default (MCP-EVENT-003); injection labeled (MCP-INSP-007).

## DFD-9 — Decision event publication (Capability B/A)

Crosses TB-4. Threats: MCP-T-028, MCP-T-044, MCP-T-045.

```mermaid
flowchart LR
  DEC[Decision + inspection + execution] --> RDX[Redact: no tokens/secrets/raw]
  RDX --> Q[[Bounded queue + backpressure]]
  Q -->|ok| SPOOL[Disk spool / durable export]
  Q -->|saturated + critical class| FC[Fail closed or degraded mode + alert]
  SPOOL --> INT[Integrity + replay-id + tenant tag]
  INT --> EXP[Authorized, tenant-separated export]
```
Critical events never silently lost (MCP-EVENT-002); **not** the audit ring (`MaxRing=500`).

## DFD-10 — Control Plane → Data Plane snapshot publication

Crosses TB-3, TB-5. Threats: MCP-T-047..050.

```mermaid
flowchart LR
  ADM[Admin publish] --> CP[Control Plane]
  CP --> SIGN[Stamp epoch+revisions+min_dp_version+content_hash+signature]
  SIGN --> PUSH[(mTLS push)]
  PUSH --> DP[Data Plane]
  subgraph DP apply
    DP --> V[Validate sig/schema/caps/revisions/version]
    V --> FENCE[Epoch fence: reject stale]
    FENCE --> BUILD[Build off active path + dry samples]
    BUILD --> SWAP[Atomic swap]
    SWAP --> KEEP[Retain previous]
    KEEP --> ACK[Acknowledge hash + health]
  end
  V -. invalid/partial .-> REJECT[Reject whole; keep last good]
```
Reuses `halease`/`dpObserveEpoch` fencing; adds content_hash+signature (missing today) — MCP-CPDP-001/002.

## DFD-11 — Rollback

Crosses TB-3. Threats: MCP-T-047, MCP-T-048.

```mermaid
flowchart LR
  TRIG[Regression detected] --> PAUSE[Pause rollout]
  PAUSE --> CMP[Compare snapshots]
  CMP --> RB[Atomic swap to previous snapshot]
  RB --> ACK[Acknowledge + export affected decisions]
```
Atomic; no partial state (MCP-HA-002); `configver` (DefaultMax=50) prior art.

## DFD-12 — Local enterprise client connectivity (Model A)

Crosses TB-1, TB-6(local). Threats: MCP-T-036, MCP-T-037, MCP-T-030, MCP-T-031/055.

```mermaid
flowchart LR
  IDE[Internal AI client / IDE / agent] -- LAN/VPN, no public ingress --> ORG[Origin/Host validate]
  ORG --> G{{/mcp/gateway}}
  G --> GW[Gateway pipeline DFD-5]
```
No public ingress; inbound Origin/Host validation required (MCP-INSP-008) — this guard is **missing today**.

## DFD-13 — Outbound-only connector (Model B)

Crosses TB-6. Threats: MCP-T-051, MCP-T-052, MCP-T-010.

```mermaid
flowchart LR
  CLOUD[Cloud AI service] -. no inbound port .- CONN
  ENV[Customer environment] --> CONN[Outbound connector: customer-initiated, mTLS identity]
  CONN -- encrypted tunnel, tenant-bound --> CLOUD
  CONN --> G{{/mcp/gateway}}
```
Customer initiates; no unsolicited inbound port; tenant-bound (MCP-CONNECT-001/004).

## DFD-14 — Hardened DMZ endpoint (Model C)

Crosses TB-6, TB-1. Threats: MCP-T-036, MCP-T-042, MCP-T-052, MCP-T-031.

```mermaid
flowchart LR
  CLOUD[Cloud client] --> WAF[WAF + reverse proxy]
  WAF --> OAUTH[OAuth + Origin/Host validate + rate limit]
  OAUTH --> MTLS[Internal mTLS]
  MTLS --> G{{/mcp/gateway}}
  OAUTH -. abuse .-> MON[Monitoring + abuse response]
```
Explicit risk acceptance required (MCP-CONNECT-003); Origin/Host + rate limits mandatory (MCP-INSP-008,
MCP-OPS-002).

## DFD-15 — Protocol-kernel decode path (Capability B, PR-1)

Crosses TB-1. Threats: MCP-T-057..074 (parser/framing/version/protocol-state). **PR-1 ships this decode
path and its test harness — but NO public/production listener** (the listener is PR-5). Requirements:
`MCP-PROTO-001..013`. No policy, credential, or upstream execution happens here.

```mermaid
flowchart LR
  BYTES["Hostile client bytes<br/>(untrusted)"] --> FRAME[Bounded transport / framing<br/>MCP-PROTO-005/006/008]
  FRAME --> DEC[Strict JSON-RPC decode<br/>single parser, no differential<br/>MCP-PROTO-001/007]
  DEC --> CLASS[Classify req/resp/notif + method<br/>reject unknown/unsupported<br/>MCP-PROTO-002; ID correlation MCP-PROTO-003]
  CLASS --> STRUCT[Structural validation:<br/>size/depth/fields/string/number limits<br/>MCP-PROTO-006/007]
  STRUCT --> VER[Protocol-version adapter<br/>allowlist + equivalence, no downgrade<br/>MCP-PROTO-010/011]
  VER --> NORM["Normalized internal message"]
  NORM --> STATE[Protocol-state machine<br/>one identity/session, cancellation/reconnect<br/>MCP-PROTO-012]
  STATE --> HANDOFF{{"Test harness (PR-1)<br/>/ later runtime boundary (PR-5)"}}
  FRAME -. limit exceeded / truncated .-> ERR[Bounded JSON-RPC error<br/>no state leak + deterministic cleanup<br/>MCP-PROTO-013]
  DEC -. malformed / differential .-> ERR
  CLASS -. unknown method / bad id .-> ERR
  STRUCT -. over-limit .-> ERR
  VER -. unsupported version / downgrade .-> ERR
  STATE -. race / duplicate / rebind .-> ERR
  classDef tb fill:#fee,stroke:#c00;
  class FRAME,DEC tb
```
Untrusted bytes are bounded and strictly decoded before any downstream stage; every reject path yields a
bounded, non-leaky error with deterministic cleanup (MCP-PROTO-013). No hostile input may panic the kernel
(MCP-PROTO-009). **No policy/credential/upstream call exists on this path** — PR-1 is the kernel only.

---

## Trust-boundary coverage summary

| DFD | Capability | Trust boundaries | Dominant threats |
|---|---|---|---|
| 1 | A (mgmt) | TB-7 | 034, 035, 010 |
| 2 | A (mgmt) | TB-7, TB-5 | 034, 046 |
| 3 | A (mgmt, future) | TB-7, TB-5, TB-3 | 034, 032, 033 |
| 4 | B (gateway) | TB-1, TB-2 | 011–017, 020 |
| 5 | B (gateway) | TB-1, TB-2 | 003–008, 019, 046 |
| 6 | B (gateway) | TB-2 | 022–025, 005 |
| 7 | B (gateway) | TB-1 | 026, 036, 037, 041, 040 |
| 8 | B (gateway) | TB-2, TB-4 | 027, 038, 039 |
| 9 | A/B | TB-4 | 028, 044, 045 |
| 10 | platform | TB-3, TB-5 | 047–050 |
| 11 | platform | TB-3 | 047, 048 |
| 12 | connectivity | TB-1, TB-6 | 036, 037, 030, 031/055 |
| 13 | connectivity | TB-6 | 051, 052, 010 |
| 14 | connectivity | TB-6, TB-1 | 036, 042, 052, 031 |
| 15 | B (gateway, PR-1 kernel) | TB-1 | 057–074 (parser/framing/version/state) |
