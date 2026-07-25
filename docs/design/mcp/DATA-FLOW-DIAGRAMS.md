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

Crosses TB-7. Threats: MCP-T-034, MCP-T-035, MCP-T-010, **MCP-T-031, MCP-T-055** (inbound rebinding / cross-origin — this flow validates `Host`/`:authority`/`Origin` per request at `HV1`, so it is a consumer of `MCP-INSP-009`).

```mermaid
flowchart LR
  AC[AI Client] -- bearer: mgmt scope --> K15["Protocol kernel — see DFD-15<br/>strict decode + structural bounds<br/>+ version + lifecycle (Management bound set)"]
  K15 --> HV1["MCP-INSP-009 listener validation<br/>Host/:authority/Origin vs the MANAGEMENT allowlist<br/>per request AND per H2 stream, after header parsing"]
  HV1 -->|allowed| L1{{/mcp/management listener}}
  HV1 -.disallowed.-> HVX1[Reject — DNS-rebinding / cross-origin defence]
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

Crosses TB-7, TB-5. Threats: MCP-T-034, MCP-T-046, **MCP-T-031, MCP-T-055** (inbound rebinding / cross-origin — validated per request at `HV2`, `MCP-INSP-009`).

```mermaid
flowchart LR
  AC[AI Client] --> K15["Protocol kernel — see DFD-15<br/>strict decode + bounds + version + lifecycle"]
  K15 --> HV2["MCP-INSP-009 listener validation<br/>Host/:authority/Origin vs the MANAGEMENT allowlist<br/>per request AND per H2 stream"]
  HV2 -->|allowed| L1{{/mcp/management}}
  HV2 -.disallowed.-> HVX2[Reject]
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
    DEC -- ALLOW-class --> CBP["Credential broker: PLAN only<br/>choose identity + scope, NO mutation"]
    DEC -- DENY/QUARANTINE/APPROVAL --> EV[(Decision events)]
    CBP --> WAL{{"DURABLE decision-event COMMIT<br/>critical classes — MCP-EVENT-002<br/>commit FAILED ⇒ fail closed, nothing runs<br/>see DFD-9"}}
    WAL -- "commit CONFIRMED" --> CB["Credential broker: MATERIALIZE<br/>mint / rotate / revoke"]
    WAL -- "commit FAILED" --> FCG["Fail closed + degraded + alert<br/>no credential minted, no upstream call"]
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
  DEC[Policy ALLOW-class] --> SEL[Select credential profile by env/server/tool/resource<br/>PLAN — no broker mutation]
  SEL --> SCOPE{Scope <= action?}
  SCOPE -- no --> DENY[DENY + security event]
  SCOPE -- yes --> WALC{{"DURABLE decision-event COMMIT<br/>credential class — MCP-EVENT-002<br/>MUST precede any broker mutation"}}
  WALC -- "commit FAILED" --> FCC["Fail closed + degraded + alert<br/>broker state UNCHANGED: nothing minted/rotated/revoked"]
  WALC -- "commit CONFIRMED" --> FETCH[Fetch short-lived cred bounded+encrypted cache<br/>MATERIALIZE]
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
  DEC["Decision + request-side inspection<br/>NO execution yet"] --> RDX[Redact: no tokens/secrets/raw]
  RDX --> Q[[Bounded queue + backpressure]]
  Q -->|"admitted (NOT yet a commit)"| SPOOL[Mandatory local encrypted durable spool per DP]
  SPOOL -->|"commit CONFIRMED"| GATE{Critical action class?}
  SPOOL -->|"commit FAILED: ENOSPC / fsync error / encryption-key failure"| LOSS
  GATE -->|"write / destructive"| XUP["Upstream call<br/>MCP-EVENT-002 write/destructive class"]
  GATE -->|"configuration publication"| XPUB["Snapshot SIGN → push → apply<br/>enters DFD-10 at SIGN, never earlier"]
  GATE -->|"credential issue / rotate / revoke"| XCRED["Broker MATERIALIZATION<br/>mint / rotate / revoke"]
  GATE -->|"state-affecting Management op"| XMGMT["Management state change<br/>out of V1 — ADR-0024 D-13"]
  GATE -->|"read-only / low-risk: NOT execution-gated"| XLOW["Execute read-only / low-risk call<br/>proceeds WITHOUT a commit gate<br/>see LOSS for the non-persistable case"]
  XLOW --> OUT
  GATE -->|"auth-failure / authz-denial event, commit CONFIRMED:<br/>request already denied, nothing to gate"| INT
  XUP --> OUT["Outcome event — emitted AFTER the irreversible action<br/>NOT the fail-closed gate"]
  XPUB --> OUT
  XCRED --> OUT
  XMGMT --> OUT
  OUT --> RDXO["Redact outcome: no tokens/secrets/raw"]
  RDXO --> QO[[Bounded queue + backpressure]]
  QO -->|"admitted"| SPOOLO["Durable spool — OUTCOME lane"]
  SPOOLO -->|"commit CONFIRMED"| INT
  QO -->|"saturated"| ODEG
  SPOOLO -->|"commit FAILED"| ODEG["Degraded + alert + loss counter ONLY<br/>the operation ALREADY happened, so fail-closed is vacuous<br/>NEVER a re-execution path"]
  Q -->|"saturated"| LOSS{{"DURABILITY LOST — dispatch by event class<br/>IDENTICAL for queue saturation and spool commit failure"}}
  LOSS -->|"critical: write / destructive / config-publication /<br/>credential / state-affecting Management"| FC["Fail closed AND degraded mode + alert + loss counter<br/>the operation NEVER RUNS — commit precedes execution"]
  LOSS -->|"auth-failure / authz-denial (already denied)"| CDEG["CRITICAL degraded state\n+ alert + loss counter\nrequest already denied"]
  LOSS -->|"read-only / low-risk"| LP{"configured loss policy?<br/>mcp_{gateway,mgmt}_event_loss_policy"}
  LP -->|"degrade-and-alert"| LDEG["Degraded + alert + integrity-protected loss counter<br/>DECISION lane: the operation has NOT happened yet"]
  LDEG --> XLOW
  LP -->|"fail-closed"| FC
  CDEG --> LOCK["DURABILITY LOCKOUT:\nblock NEW allowed write/high-risk ops\nuntil durability is restored"]
  INT[Integrity + replay-id + tenant tag]
  INT -. additive, async .-> EXP[Additive authorized, tenant-separated export — never a substitute]
```
**A low-risk durability loss follows the configured policy, and `degrade-and-alert` means the call still runs.** `mcp_gateway_event_loss_policy` / `mcp_mgmt_event_loss_policy` select it: under `degrade-and-alert` the degradation is recorded (alarm + integrity-protected loss counter) **and the low-risk operation proceeds** to `XLOW`; only `fail-closed` denies it. Terminating this arm at a degradation node would make `degrade-and-alert` behave as `fail-closed`, contradicting the config contract and `EVENT-MODEL` §4a. Note also that the decision-lane degradation node (`LDEG`) is **not** the outcome-lane one (`ODEG`): in the decision lane the operation has **not** happened yet, which is exactly why it can still proceed.

**The gate decides whether execution is *gated*, not whether it happens.** A committed **read-only / low-risk** decision proceeds to execution (`XLOW`) **without** being gated on the commit, and its outcome enters the outcome lane like any other — routing it straight to integrity/export would either drop every successful low-risk call or silently discard its outcome event, since DFD-5 sends **all** ALLOW-class traffic through this path. Only the **already-denied** classes terminate at `INT` without execution, because there is nothing left to run.

**`SPOOL` has NO unconditional onward edge.** Every path out of the spool is labelled: `commit CONFIRMED` reaches `GATE`, `commit FAILED` reaches `LOSS`. An unconditional `SPOOL --> INT` would let a failed commit continue to integrity/export and reach neither fail-closed nor the lockout — which would make the single dispatch below decorative. A **successfully committed** denial event is routed to `INT` **through `GATE`**, after classification, not around it.

**Durability loss has ONE dispatch, and it covers every class.** Queue saturation and spool **commit failure** converge on `LOSS`, which routes by event class: the five critical classes (write, destructive, configuration publication, credential, **state-affecting Management**) to fail-closed + degraded; an already-denied **auth-failure / authz-denial** event to the **critical degraded state + durability lockout** (fail-closed is vacuous there — the request was already denied); and read-only/low-risk to the **configured loss policy** (`LP`) — `degrade-and-alert` records the degradation and the operation **still proceeds** to `XLOW`, `fail-closed` denies it. That arm is a **policy branch, not a posture**: terminating it at a degradation node would make `degrade-and-alert` and `fail-closed` behave identically and delete a configurable contract. Sending commit failure straight to fail-closed would bypass the lockout for denial events, and omitting the Management class would leave a saturated Management state change with no route at all.

**The gate dispatches by class, because each class has a different irreversible action** (`MCP-EVENT-002`): write/destructive → the upstream call; configuration publication → snapshot **sign/push/apply**, entering DFD-10 at `SIGN` and never earlier; credential → **broker materialization** (mint/rotate/revoke); state-affecting Management → the state change. A single edge to "upstream call" would leave publication and credential mutation ungated, since neither makes one.

**Two lanes, and they must never join.** The **decision** lane (`DEC → RDX → Q → SPOOL → GATE`) gates execution; the **outcome** lane (`XUP`/`XPUB`/`XCRED`/`XMGMT` → `OUT → RDXO → QO → SPOOLO → INT`) records what happened and **never returns to `GATE`** or to any execution node. Feeding outcome events back into the decision lane would re-enter the gate still carrying the critical action class, whose only matching edge is `EXEC` — i.e. it would re-execute the side effect, indefinitely. Outcome-lane loss is therefore **degraded + alert + loss counter only**: the operation has already happened, so fail-closed is vacuous for it, exactly as for an already-denied request. **Ordering is load-bearing:** for the critical classes the decision event is **durably committed BEFORE that class's OWN irreversible action**, so a saturated queue can still fail the operation closed. A durability check reached only *after* execution cannot fail closed at all — the side effect has already happened (`MCP-T-044`). The **outcome** event is emitted after execution and is explicitly **not** the fail-closed gate. Critical events never silently lost (MCP-EVENT-002); **not** the audit ring (`MaxRing=500`). The **three** loss branches are **distinct**: the five critical classes (write, destructive, configuration publication, credential, **state-affecting Management**) ⇒ **fail closed AND** degrade+alert; a non-persistable **authentication-failure / authorization-denial** ⇒ **critical degraded state + durability lockout** (the request is already denied, so there is no operation to fail closed); **read-only / low-risk ⇒ the configured loss policy**, which is a selection between two behaviours and not a posture of its own — EVENT-MODEL §4a, ADR-0024 §D-5.

## DFD-10 — Control Plane → Data Plane snapshot publication

Crosses TB-3, TB-5. Threats: MCP-T-047..050.

```mermaid
flowchart LR
  ADM[Admin publish] --> CP[Control Plane]
  CP --> WALC{{"Durable decision-event COMMIT<br/>config-publication class — MCP-EVENT-002<br/>BEFORE sign/push/apply"}}
  WALC -->|"commit FAILED"| FCC["Fail closed AND degraded + alert<br/>NO revision created, NOTHING signed or pushed<br/>every DP stays on the prior epoch"]
  WALC -->|"commit CONFIRMED"| SIGN[Stamp epoch+revisions+min_dp_version+content_hash+signature]
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
Reuses `halease`/`dpObserveEpoch` fencing; adds content_hash+signature (missing today) — MCP-CPDP-001/002. **The configuration-publication class is gated here, not on the Gateway call path:** its irreversible action is signing/pushing/applying the snapshot, so the `MCP-EVENT-002` durable commit precedes `SIGN`. Gating only "the upstream call" would have left this flow ungated entirely, since publication makes no upstream call.

## DFD-11 — Rollback

Crosses TB-3. Threats: MCP-T-047, MCP-T-048.

```mermaid
flowchart LR
  TRIG[Regression detected] --> PAUSE[Pause rollout]
  PAUSE --> CMP[Compare snapshots]
  CMP --> WALR{{"DURABLE decision-event COMMIT<br/>rollback IS a configuration change<br/>MCP-EVENT-002 config-publication class"}}
  WALR -- "commit FAILED" --> FCR["Fail closed AND degraded + alert<br/>NO swap performed — the CURRENT snapshot stays active<br/>rollback is refused, not silently applied"]
  WALR -- "commit CONFIRMED" --> RB[Atomic swap to previous snapshot]
  RB --> ACK[Acknowledge + export affected decisions]
```
**Rollback is a configuration change, so it is gated like one.** An operator- or health-triggered rollback applies a snapshot, which is the `MCP-EVENT-002` configuration-publication class's irreversible action — so the durable commit **MUST precede the atomic swap**, and on commit failure the rollback is **refused with the current snapshot left active**, never applied-then-reported. Gating only DFD-10's forward publication would leave rollback as an ungated way to change configuration while the spool is failing.

Atomic; no partial state (MCP-HA-002); `configver` (DefaultMax=50) prior art.

## DFD-12 — Local enterprise client connectivity (Model A)

Crosses TB-1, TB-6(local). Threats: MCP-T-036, MCP-T-037, MCP-T-030, MCP-T-031/055.

```mermaid
flowchart LR
  IDE[Internal AI client / IDE / agent] -- LAN/VPN, no public ingress --> ORG[Origin/Host validate]
  ORG --> G{{/mcp/gateway}}
  G --> GW[Gateway pipeline DFD-5]
```
No public ingress; inbound Origin/Host validation required — enforced on this **live listener** by
**MCP-INSP-009** (PR-5), using the **MCP-INSP-008** validation primitive (PR-1). This guard is **missing
today**, and the PR-1 primitive alone does not make the listener safe.

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
Explicit risk acceptance required (MCP-CONNECT-003); Origin/Host + rate limits mandatory — the
**listener-side** Origin/Host enforcement on this public path is **MCP-INSP-009** (Future DMZ gate;
`MCP-INSP-008` is the PR-1 validation primitive only), plus MCP-OPS-002.

## DFD-15 — Protocol-kernel decode path (Capability **A and B**, PR-1)

Crosses **TB-1, TB-7** — Gateway traffic crosses TB-1 and **Management traffic crosses TB-7**, since this kernel is on both listeners' paths. Threats: MCP-T-057..074 (parser/framing/version/protocol-state). **This is the SAME kernel for BOTH capabilities** — the config surface instantiates `MCP-PROTO-*` bounds per capability, so hostile **Management** traffic traverses strict decoding, classification, structural bounds, version negotiation and the lifecycle state machine **before** reaching Management authorization or tool handling, exactly as Gateway traffic does, evaluated against the **Management** bound set. DFD-1 and DFD-2 therefore begin **downstream of this diagram** (both now show the kernel explicitly); they are not an alternative path around it. **PR-1 ships this decode
path and its test harness — but NO public/production listener** (the listener is PR-5). Requirements:
`MCP-PROTO-001..014`. No policy, credential, or upstream execution happens here. **PR-1 is
identity-agnostic:** the `MCP-PROTO-012` state machine holds an **immutable, opaque session context that
carries no resolved identity** — identity binding and the no-rebind guarantee are **`MCP-ID-008` at PR-3**,
so the **identity half of MCP-T-069 is NOT closed by this diagram**.

```mermaid
flowchart LR
  BYTES["Hostile client bytes (untrusted)<br/>EITHER listener: Gateway or Management"] --> FRAME["Bounded transport / framing<br/>MCP-PROTO-005/006/008<br/>evaluated against THIS listener's own bound set"]
  FRAME --> DEC[Strict JSON-RPC decode<br/>single parser, no differential<br/>MCP-PROTO-001/007]
  DEC --> CLASS[Classify req/resp/notif + method<br/>reject unknown/unsupported<br/>MCP-PROTO-002; ID correlation MCP-PROTO-003]
  CLASS --> STRUCT[Structural validation:<br/>size/depth/fields/string/number limits<br/>MCP-PROTO-006/007]
  STRUCT --> VER[Protocol-version adapter<br/>allowlist + equivalence, no downgrade<br/>MCP-PROTO-010/011]
  VER --> NORM["Normalized internal message"]
  NORM --> STATE[Protocol-state machine<br/>immutable OPAQUE session context - no resolved identity<br/>lifecycle / cancellation / reconnect<br/>MCP-PROTO-012]
  STATE --> HANDOFF{{"Test harness (PR-1)<br/>/ later runtime boundary (PR-5)"}}
  FRAME -. limit exceeded / truncated .-> REJ
  DEC -. malformed / differential .-> REJ
  CLASS -. unknown method / bad id .-> REJ
  STRUCT -. over-limit .-> REJ
  VER -. unsupported version / downgrade .-> REJ
  STATE -. race / duplicate / out-of-order lifecycle .-> REJ
  REJ{{"Reject: branch by message class<br/>MCP-PROTO-013"}}
  REJ -->|request| ERR["Bounded JSON-RPC error<br/>no state leak<br/>MCP-PROTO-013"]
  REJ -->|notification| NORESP["NO wire response<br/>record rejection + loss/metric only<br/>one-way: replying would be reply amplification"]
  REJ -->|"response (uncorrelated / malformed / over-limit)"| DROP["DISCARD + record — NO wire response<br/>a reply to a response is a feedback loop<br/>free the OFFENDING MESSAGE's resources only<br/>outstanding-request entry released ONLY on trusted<br/>same-session correlation, else bounded timeout"]
  REJ -->|unclassifiable| NULLERR["At most one id:null error<br/>rate-bounded so it cannot become the amplifier"]
  ERR --> CLEAN["Deterministic cleanup<br/>UNCONDITIONAL - every class"]
  NORESP --> CLEAN
  DROP --> CLEAN
  NULLERR --> CLEAN
  classDef tb fill:#fee,stroke:#c00;
  class FRAME,DEC tb
```
Untrusted bytes are bounded and strictly decoded before any downstream stage. Rejection **branches by message class** (MCP-PROTO-013): a rejected **request** yields a bounded, non-leaky JSON-RPC error; a rejected **notification** yields **no wire response at all** (one-way — replying would recreate the notification-flood reply amplifier), only a recorded rejection and metric; a rejected **response** — uncorrelated, malformed or over-limit — is **discarded and recorded with no wire response** (answering a response is a feedback loop); the **offending message's** resources are freed, but an **outstanding-request entry is released only on trustworthy same-session correlation** — never on an ID lifted from the rejected message, since that would be a remote state-deletion primitive — and otherwise expires on its bounded timeout; an **unclassifiable** message yields at most one `id: null` error over a **rate-bounded** path. Deterministic cleanup is **unconditional across every class**. No hostile input may panic the kernel
(MCP-PROTO-009). **No policy/credential/upstream call exists on this path** — PR-1 is the kernel only.

---

## Trust-boundary coverage summary

| DFD | Capability | Trust boundaries | Dominant threats |
|---|---|---|---|
| 1 | A (mgmt) | TB-7 | 034, 035, 010, **031, 055** |
| 2 | A (mgmt) | TB-7, TB-5 | 034, 046, **031, 055** |
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
| 15 | **A and B** (both listeners, PR-1 kernel) | **TB-1, TB-7** | 057–074 (parser/framing/version/state) |
