# MCP Open Decisions

Decisions that cannot be made safely by the coding agent and require named human owners. Each: ID,
question, options, recommended option, evidence, owner, approver, due stage, closure condition, blocking
status. **Status: PR-0 design artifact (Proposed).** Recommendations are `[REC]` — they do not decide.

Blocking status: **GO/NO-GO** = must be resolved before the stage in "Due"; **PR-1 gate** = blocks PR-1
start; **Slice** = blocks the named slice; **Non-blocking** = can trail.

> **Update 2026-07-24 — five decisions closed.** **D-2, D-5, D-8, D-9, D-13 are CLOSED** and recorded in
> the numbered ADR [`docs/adr/0024-mcp-agent-security-gateway-trust-boundary.md`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md)
> (per-decision closure blocks below). **D-0** is promoted to ADR-0024. **D-1** was **elevated to a hard
> PR-1 entry gate**. **D-14 is NEW** (protocol-kernel concrete limit values and batch support, added by the
> same remediation). Enumerated from the diff against the merge base rather than from recollection: the
> decision blocks this remediation touched are exactly **D-0, D-1, D-2, D-5, D-8, D-9, D-13** plus the new
> **D-14**; every other decision block is byte-unchanged (`predicates/predicate-25.py`).
>
> **Update 2026-07-31 — PR-1 entry closure. ADR-0024 is `Status: Accepted`; the two hard PR-1 entry gates
> D-1 and D-15 are CLOSED.** D-1 freezes the V1 protocol baseline (primary `2025-11-25`, floor `2025-06-18`,
> all others rejected; Streamable HTTP only; batch rejected; the six-method surface; sessionless
> missing-header → `400`). D-15 accepts the config anti-drift contract (`CLOSED — implementation contract
> accepted`). There is **no** external ARB / Security Architecture / committee / role-signature step in this
> project — closure rests on independent AI research, adversarial review, structural predicates, and CI. See
> [`PR1-ENTRY-CLOSURE.md`](PR1-ENTRY-CLOSURE.md) and tracker [#923](https://github.com/KidCarmi/Culvert/issues/923).
>
> **Later addition, separately attributed — NOT part of the remediation described above.** **D-15** (MCP
> config-surface registry integration strategy) was added by the board-blocker remediation for
> [#927](https://github.com/KidCarmi/Culvert/issues/927), a subsequent PR. It is named here because
> `predicate-25` measures the **cumulative** diff against the immutable recorded base `1203e04b`, so a
> decision block touched by any later PR must be named in this note or the provenance check fails.
> Attribution is stated explicitly rather than folded into the sentence above, because silently widening
> an earlier remediation's claim is the false-provenance defect that predicate exists to catch.

---

### D-0 — ADR scope (Option A vs Option B)
- **Question:** where does the mandatory MCP trust-boundary ADR live during PR-0?
- **Options:** (A) PR-0 writes a numbered ADR under `docs/adr/`; (B) PR-0 writes an ADR **proposal** inside
  `docs/design/mcp/`, and a human promotes it to a numbered Accepted `docs/adr/NNNN` as a PR-1 entry gate.
- **Recommended [REC]:** **Option B.** Option A violates the PR-0 restriction "only `docs/design/mcp/`".
- **Evidence:** task absolute restrictions; `docs/adr/0001` ADR mandate.
- **Owner:** Eng/Arch. **Due:** PR-1 gate. **Closure:** numbered ADR accepted.
- **Blocking:** PR-1 gate. *(Proposal authored: [`ADR-PROPOSAL-mcp-trust-boundary.md`](ADR-PROPOSAL-mcp-trust-boundary.md).)*
- **STATUS — CLOSED (ADR ACCEPTED, 2026-07-31):** the proposal was promoted to the numbered ADR
  [`docs/adr/0024-mcp-agent-security-gateway-trust-boundary.md`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md),
  now **`Status: Accepted`** (see ADR-0024 "Acceptance"). Acceptance rests on the merged repository state —
  independent AI research, adversarial review, predicates, and CI — not an organizational ratification step.
  The in-package proposal file is a non-authoritative pointer.

### D-1 — Protocol baseline
- **Question:** which stable MCP protocol version(s) to freeze, and the adapter/transport/batch/method policy?
- **Options:** single pinned version; N-latest with adapters; permissive.
- **Recommended [REC]:** freeze a small supported set + version adapters in the protocol kernel; default-deny unknown versions.
- **Evidence:** protocol posture enumerated with primary/SDK sources in
  [`PROTOCOL-COMPATIBILITY.md`](PROTOCOL-COMPATIBILITY.md) and
  [`TRANSPORT-FALLBACK-EVIDENCE.md`](TRANSPORT-FALLBACK-EVIDENCE.md); admitted method surface in
  [`MCP-OPERATION-REGISTRY.md`](MCP-OPERATION-REGISTRY.md).
- **Owner:** Eng. **Approver:** Arch. **Due:** PR-1. **Closure:** version/transport/negotiation/batch/method baseline recorded and predicate-enforced.
- **Blocking:** was a HARD PR-1 entry gate (elevated 2026-07-24, ADR-0024 PR-1 entry gate item 5).
- **CLOSED — 2026-07-31. V1 protocol baseline frozen.** This is the authoritative D-1 record; the runtime
  behavior is implemented in PR-1+ per slice ownership, and MUST match this baseline.

  **Supported versions.**
  - **Primary:** `2025-11-25`.
  - **Compatibility floor:** `2025-06-18`.
  - **All other revisions are rejected**, explicitly including `2024-11-05`, `2025-03-26`, and `2026-07-28`,
    plus any unknown future revision. `2026-07-28` may remain **comparison / evidence material only** — it
    is **not** part of V1.

  **Transport.** Remote **Streamable HTTP only**. **No** stdio; **no** localhost bridge; **no** legacy
  HTTP+SSE endpoint pair; **no** endpoint-event route; **no** automatic fallback; **no** pre-negotiation SSE
  stream allocation. A GET without a valid negotiated context returns **`405`** and retains **zero** streams.

  **Version negotiation.** `initialize` **may counter-offer** a supported version using the documented
  successful initialize response (`200` carrying the JSON-RPC body — preferred over a `4xx` hard reject, so
  the client is never recruited into the legacy probe). A client that cannot accept the selected version
  **terminates**. An invalid or unsupported `MCP-Protocol-Version` header returns **`400`**. A missing
  required session identifier returns the evidence-backed status recorded in the
  [`TRANSPORT-FALLBACK-EVIDENCE.md`](TRANSPORT-FALLBACK-EVIDENCE.md) matrix. An unknown or terminated
  session returns the evidence-backed **`404`**. **DELETE** unsupported returns **`405`**.

  **Sessionless missing version header (the final D-1 sub-decision).** A sessionless / first request with
  **no** `MCP-Protocol-Version` header is **rejected with HTTP `400`**. Culvert **does not** silently assume
  `2025-03-26`. This is a deliberate security and compatibility decision: silently assuming `2025-03-26`
  would re-admit version semantics excluded from V1, including batch and version-surface differences. The
  upstream spec uses **SHOULD** language here (the *"SHOULD assume `2025-03-26`"* clause is conditioned on
  the server having no other way to identify the version); with a negotiated session/trusted context Culvert
  *has* another way and honoring it is conformant — only the sessionless / first-request case is a genuine
  deviation, and it is recorded transparently as such, **not** as an unconditional spec requirement (the
  narrowed Gate 3 conflict C-7; C-6 **withdrawn** as a false positive, A-7 **removed**).

  **Batch.** JSON-RPC **batch arrays are unsupported in V1**. The **entire batch is rejected** — never
  split, partially processed, or best-effort dispatched (`MCP-PROTO-004`; D-14 batch sub-decision resolved:
  reject).

  **Method surface.** The admitted set is exactly the six reviewed methods of
  [`MCP-OPERATION-REGISTRY.md`](MCP-OPERATION-REGISTRY.md): `initialize`, `notifications/initialized`,
  `ping`, `notifications/cancelled`, `tools/list`, `tools/call`. Everything else is rejected through the
  authoritative method registry (`MCP-PROTO-016`; #928).

  **Origin and Host (frozen reviewed posture).** Host allowlisting is **mandatory**; a present invalid
  `Origin` is **rejected**; Culvert does **not** require every non-browser client to send `Origin` unless the
  selected protocol revision requires it. **PR-1 owns the pure validation primitive** (`MCP-INSP-008`);
  **PR-5 owns listener enforcement** (`MCP-INSP-009`).

  Owned by `MCP-PROTO-017` / `MCP-T-078` for the transport-rejection posture; recorded in
  [`PR1-ENTRY-CLOSURE.md`](PR1-ENTRY-CLOSURE.md) and enforced by `predicate-29` and `predicate-30`.

### D-2 — Authentication deployment model
- **Question:** MCP as OAuth resource server, gateway-issued token, or enterprise-broker integration; RFC 8707 adoption?
- **Options:** resource server (validate external tokens); gateway-issued; broker integration; hybrid.
- **Recommended [REC]:** resource-server with mandatory audience + RFC 8707 resource validation; separate Mgmt/Gateway clients; add net-new replay defense.
- **Evidence:** [FACT] SWG OIDC binds audience to client_id (`auth_oidc_flow.go:523`), no RFC 8707, no replay defense (VRC §6).
- **Owner:** IAM/Sec Arch. **Approver:** Sec Arch. **Due:** PR-3. **Closure:** threat model + interop tests approved.
- **Blocking:** GO/NO-GO (identity) + Slice (PR-3).
- **CLOSED — 2026-07-24; recorded in the now-Accepted [`ADR-0024`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md) §D-2.**
  - **Decision:** **Option A** — Culvert is the OAuth protected resource server. Client token terminates at
    Culvert (no passthrough); clients request the canonical resource via RFC 8707 `resource` and Culvert
    validates the resulting audience restriction (`aud` / introspection, never a bespoke in-token claim),
    so the audience identifies the canonical Culvert MCP resource
    (`/mcp/management`, `/mcp/gateway/{server-id}` or an approved Culvert-controlled logical resource);
    upstream server/tool/resource are policy + broker-scope inputs; separate Mgmt/Gateway OAuth clients +
    disjoint scopes. Option C = issuer topology under A; Option B = edge token-exchange only, separate
    review. **Replay defense is NOT access-token `jti` one-time-use** — it is TLS + short TTL +
    audience/resource + issuer/sig/exp/tenant/scope validation + introspection/revocation + correlation +
    rate limits/anomaly + **sender-constrained (mTLS/DPoP) tokens for high-risk/external profiles**; DPoP
    replay detection applies to the per-request DPoP proof, not the access token.
  - **Review lens:** IAM / Security (recorded in the now-Accepted ADR-0024; no organizational ratification step exists in this project).
  - **Evidence:** VRC §6 (no access-token replay defense; audience=client_id); AUTH-AND-CREDENTIAL-MODEL §4–§7; MCP-AUTH-001..008.
  - **Residual risk:** MCP-T-002 replay defense is net-new (must be built + tested, PR-3); DPoP/mTLS availability is deployment-profile-dependent.

### D-3 — Credential providers for MVP
- **Question:** which of Vault/KMS/Secrets Manager/workload-identity are in V1?
- **Options:** one provider + interface; two; workload-identity-first.
- **Recommended [REC]:** ship the provider interface + one production integration + workload-identity where supported.
- **Evidence:** [FACT] `internal/secret` provider model is reusable-after-refactor prior art.
- **Owner:** IAM/PAM. **Approver:** Sec Arch. **Due:** PR-4. **Closure:** interface + first integration selected.
- **Blocking:** Slice (PR-4).

### D-4 — Approval channel
- **Question:** in-product approval only, or ticket/chat integration?
- **Options:** in-product only; +ticket; +chat; multi-party.
- **Recommended [REC]:** in-product complete-disclosure dialog for V1 (MCP-POLICY-007); integrations later.
- **Evidence:** BLUEPRINT §14 approval UX.
- **Owner:** Product/Sec. **Approver:** Product Sec. **Due:** PR-9. **Closure:** UX + audit requirements finalized.
- **Blocking:** Slice (PR-9).

### D-5 — Event durability architecture
- **Question:** local disk spool, message bus, or both; and the critical-event loss policy?
- **Options:** local spool; bus; spool+bus; fail-closed vs degraded-mode.
- **Recommended [REC]:** local durable spool + pluggable export; fail-closed for critical classes on saturation.
- **Evidence:** [FACT] audit ring `MaxRing=500`; no durable pipeline exists ([`EVENT-MODEL.md`](EVENT-MODEL.md)).
- **Owner:** SRE/Sec. **Approver:** Sec Arch. **Due:** PR-8. **Closure:** loss policy + load evidence approved.
- **Blocking:** GO/NO-GO (events) + Slice (PR-8).
- **CLOSED — 2026-07-24; recorded in the now-Accepted [`ADR-0024`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md) §D-5.**
  - **Decision:** **Option C** — local encrypted durable spool on every relevant DP, bounded queues +
    backpressure + replay IDs + pluggable async exporters; message bus/SIEM is an adapter, never a
    mandatory runtime dependency. Durability-unavailable is fixed by action class (EVENT-MODEL §4a table):
    read-only/low-risk → proceed only under explicit degraded-mode policy + alarm + integrity-protected
    loss counter + bounded retry, never silent; write/destructive/config-publication/credential/
    state-affecting-Mgmt → **fail closed**; auth-failure/authz-denial → request already denied (not
    relabeled) and, because such events are ATTACKER-MINTABLE, handled in a **separate denial lane**
    (admission control + coalescing + own quota + no access to the critical reserve) whose worst outcome is
    `denial-lane-degraded` — it blocks **no** authenticated operation. Critical-class degradation is scoped to
    one durability domain, restart-persistent and bounded on exit. **No emergency-policy bypass exists**
    (amended for [#926](https://github.com/KidCarmi/Culvert/issues/926) / `MCP-T-075`). Design MUST specify ordering scope, dedup, replay cursor, encryption-at-rest, corruption
    recovery, tenant isolation, retention, disk-pressure, restart/failover recovery.
  - **Approver role:** SRE / Security Architecture (recorded in the now-Accepted ADR-0024; no organizational ratification step exists in this project).
  - **Evidence:** VRC §5/§8 (no durable pipeline; audit ring `MaxRing=500`); EVENT-MODEL §4–§6 **and §4b** (containment, denial lane, partition contract, degraded-state machine); **MCP-EVENT-001..007** and **MCP-OPS-005**.
  - **Residual risk:** tracked as **`R-6`** in [`THREAT-MODEL.md`](THREAT-MODEL.md) §12 — *a genuine durability
    failure may block critical operations on the affected node/capability until recovery* (`MCP-T-075`,
    `MCP-T-044`). **Status: proposed owner `SRE / Reliability`; acceptance PENDING approval; NOT accepted by a
    named human.** This decision block does **not** accept it, and the earlier wording here — which called the
    trade-off "accepted, alertable" — was **stale**: it asserted an acceptance no named human had given, and
    contradicted `R-6`'s own pending state. Acceptance is recorded in `THREAT-MODEL.md` §12 by the accepting
    owner, never inferred from this block. Exporter-adapter integrations verified per deployment.

### D-6 — Inspection depth
- **Question:** built-in patterns vs external DLP/AI-security service?
- **Options:** built-in only; external integration; hybrid.
- **Recommended [REC]:** built-in patterns (reuse `internal/redaction`) + optional external integration; document best-effort residual (R-2).
- **Evidence:** [FACT] `internal/redaction` fail-closed taxonomy.
- **Owner:** Sec/Privacy. **Approver:** Sec Arch. **Due:** PR-7. **Closure:** latency/privacy/failure-mode approved.
- **Blocking:** Slice (PR-7).

### D-7 — Local MCP (stdio/localhost) roadmap
- **Question:** endpoint-bridge timing and platform scope?
- **Options:** post-V1 bridge; never; partial (localhost only).
- **Recommended [REC]:** out of V1; document as known limitation (MCP-OPS-004); bridge is post-V1.
- **Evidence:** residual R-1 (MCP-T-054/055/056).
- **Owner:** Product/Eng. **Approver:** Exec/Arch. **Due:** post-V1. **Closure:** roadmap + commercial commitment agreed.
- **Blocking:** Non-blocking for V1 (documented limitation).

### D-8 — Connector model (cloud-AI connectivity)
- **Question:** which of Model A/B/C are supported and vendor-validated?
- **Options:** A only; A+B; A+B+C.
- **Recommended [REC]:** Model A (local client) for first production; B/C as validated per vendor.
- **Evidence:** [EXT] vendor connector requirements unverified ([`ON-PREM-CONNECTIVITY.md`](ON-PREM-CONNECTIVITY.md)).
- **Owner:** Net/Sec/Privacy. **Approver:** Arch/Privacy. **Due:** PR-11. **Closure:** vendor + data-flow + failure semantics validated.
- **Blocking:** GO/NO-GO (connectivity) + Slice (PR-11). **[EXT] EXTERNAL VERIFICATION REQUIRED.**
- **CLOSED — 2026-07-24; recorded in the now-Accepted [`ADR-0024`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md) §D-8.**
  - **Decision:** **Model A (local enterprise client) is the ONLY supported V1 connectivity model.** The
    outbound connector (Model B) is a **post-V1 roadmap extension** and is **NOT** assigned to PR-11 (PR-11
    stays Shadow/Canary); it gets its **own future implementation slice + design gate** unless a
    human-approved roadmap change renumbers slices. No ChatGPT/Claude/other-vendor support is claimed until
    a named integration is verified against **authoritative, date-stamped** vendor requirements and tested.
    The future connector must be customer-initiated, tenant-bound, mTLS-identified, revocable,
    cert-rotating, bounded, observable, and **must not store/receive production upstream credentials**;
    DLP/redaction/destination run before egress.
  - **Approver role:** Network/Security + Privacy (recorded in the now-Accepted ADR-0024; no organizational ratification step exists in this project).
  - **Evidence:** ON-PREM-CONNECTIVITY §2–§6; MCP-CONNECT-001/002/004; MCP-PRIVACY-001; residual R-5.
  - **Residual risk:** cloud-AI clients without a local path are unserved in V1 (accepted); vendor connector semantics remain **[EXT]** unverified until per-vendor validation.

### D-9 — DMZ support
- **Question:** offer a routable remote MCP endpoint at all, and accept its risk?
- **Options:** no DMZ; DMZ with explicit risk acceptance.
- **Recommended [REC]:** defer DMZ (Model C) until A/B proven; require explicit written risk acceptance if offered.
- **Evidence:** threat MCP-T-052; MCP-CONNECT-003, MCP-INSP-009 (listener-side; MCP-INSP-008 is the PR-1 primitive).
- **Owner:** Sec Arch/Exec. **Approver:** Arch + Exec. **Due:** PR-11. **Closure:** risk acceptance signed or DMZ deferred.
- **Blocking:** GO/NO-GO (connectivity).
- **CLOSED — 2026-07-24; recorded in the now-Accepted [`ADR-0024`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md) §D-9.**
  - **Decision:** a publicly routable / externally reachable hardened DMZ MCP endpoint (Model C) is **NOT
    supported in V1 and is disabled by default.** Model A is **sufficient for V1** (the future connector
    need not exist first). Future DMZ needs a separate architecture + production-readiness approval, signed
    customer risk acceptance, OAuth/reverse-proxy/WAF/rate-limits/DDoS/internal-mTLS/monitoring/runbooks.
    **Host validation + configured-host allowlisting are mandatory on every HTTP MCP listener.** Origin
    validation follows the MCP protocol baseline (validate Origin on incoming Streamable HTTP; reject
    present-but-invalid with the protocol-required response; do **not** invent a blanket "always send
    Origin" rule unless the protocol version requires it). Local deployment binds only to explicitly
    configured interfaces. Inbound Origin/Host defence is **split across two layers**: the validation
    **primitive** (`MCP-INSP-008`) is a **PR-1** requirement, and the **listener-side enforcement**
    (`MCP-INSP-009`) lands with the listener — **PR-5** for Model A, the **Future DMZ gate** for Model C.
    **PR-1 binds no listener, so this decision's listener controls are NOT satisfied by PR-1 alone**
    (ADR-0024 §D-9 item 6).
  - **Approver role:** Security Architecture + Executive (recorded in the now-Accepted ADR-0024; no organizational ratification step exists in this project).
  - **Evidence:** ON-PREM-CONNECTIVITY §4/§7; MCP-CONNECT-003, **MCP-INSP-009** (listener-side host
    allowlist + E2E rebinding; `MCP-INSP-008` supplies the PR-1 primitive); MCP-T-052/031.
  - **Residual risk:** connector-less cloud clients unserved in V1 (accepted); DMZ, if ever offered, carries the only public-ingress surface (explicit signed risk acceptance required).

### D-10 — Snapshot signing scheme
- **Question:** reuse the release-catalog ed25519/keyless prior art, or a new scheme, for the MCP snapshot content-hash + signature?
- **Options:** ed25519 (reuse); Sigstore-keyless (reuse); new scheme.
- **Recommended [REC]:** reuse the release-catalog ed25519 envelope pattern for the snapshot content-hash + signature.
- **Evidence:** [FACT] no snapshot signing today (mTLS+epoch only); ed25519 exists only in the release-catalog subsystem.
- **Owner:** Eng/Sec Arch. **Approver:** Arch. **Due:** PR-10. **Closure:** scheme selected + tested.
- **Blocking:** Slice (PR-10).

### D-11 — Packaging / licensing / pricing / support lifecycle
- **Question:** SKU vs bundled; pricing; entitlement; support lifecycle?
- **Options:** bundled into Culvert; separate SKU(s); tiered.
- **Recommended [REC]:** decide commercially; one platform can expose multiple SKUs (BLUEPRINT §03).
- **Evidence:** BLUEPRINT §22 (pilot conversion "defined before GA").
- **Owner:** Product/Exec. **Approver:** Exec Sponsor. **Due:** pre-GA. **Closure:** pricing + entitlement + support model approved.
- **Blocking:** GO/NO-GO (commercial) at GA; non-blocking for PR-1.

### D-12 — Distinct connectivity / PR-12 slice reinstatement
- **Question:** should connectivity adapters be a distinct slice (a "PR-12") rather than folded into PR-5/PR-10/PR-11?
- **Options:** fold (current plan); reinstate a distinct connectivity slice; reinstate a PR-12 shadow/canary split.
- **Recommended [REC]:** keep the fold (no PR-12); revisit only if connector scope grows.
- **Evidence:** editorial correction (PR-0..PR-11 + Production Qualification; [`IMPLEMENTATION-SLICES.md`](IMPLEMENTATION-SLICES.md)).
- **Owner:** Staff Eng. **Due:** PR-5. **Closure:** slice plan recorded; if reinstated, PR-12 must be explicitly defined + justified here.
- **Blocking:** Non-blocking (planning).

### D-13 — Management MCP scope (read-only vs draft vs controlled mutation)
- **Question:** how far does Management MCP go in V1?
- **Options:** read-only only; +draft/validate; +controlled mutation (plan→validate→approve→apply).
- **Recommended [REC]:** read-only + draft/validate in V1; mutation only after the full approval workflow exists (MCP-MGMT-001).
- **Evidence:** BLUEPRINT §03; MCP-MGMT-001.
- **Owner:** Sec/Eng. **Approver:** Sec Arch. **Due:** PR-9. **Closure:** separate threat model + RBAC + plan/validate/approve/apply approved.
- **Blocking:** GO/NO-GO (dual MCP surfaces) + Slice (PR-9).
- **CLOSED — 2026-07-24; recorded in the now-Accepted [`ADR-0024`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md) §D-13.**
  - **Decision:** V1 Management MCP = **read-only + draft/validate/simulate, NO activation.** Permitted:
    explain decision, inspect bounded effective config, desired-vs-actual, bounded health, bounded/redacted
    security-event summaries, validate policy syntax/semantics, simulate impact, generate a non-activating
    draft. Prohibited (V1): config activation, policy publication, credential/secret ops, raw-trace export,
    arbitrary log export, arbitrary command exec, service restart, cluster mutation, node removal, cert
    replacement, emergency-bypass creation, any other state-changing op. **Mutation is excluded from V1.**
    Isolation: separate listener/OAuth-client/resource/scopes/policy-namespace/rule-bundles/quotas/audit/
    threat-model/runbook; **may** share reviewed libraries + selected CP infra; **may** share the durable
    event transport **only** with authorization-domain/tenant/category/partition/retention/query
    separation (two physical event systems NOT required when logical+security isolation is enforced +
    tested); **may** share a policy-engine library but **not** active state/rule-bundles/namespaces/
    decisions; outputs tenant-scoped, RBAC, paginated, redacted, size- and time-bounded.
  - **Approver role:** Security Architecture (recorded in the now-Accepted ADR-0024; no organizational ratification step exists in this project).
  - **Evidence:** PRODUCT-SCOPE §8; RECOMMENDED-ARCHITECTURE §1; MCP-POLICY-MODEL §8; MCP-MGMT-001..004.
  - **Residual risk:** shared durable transport / shared policy-engine library must be proven logically isolated by test (MCP-T-034/035); mutation deferred to a separate post-V1 plan→validate→approve→apply ADR.

### D-14 — Protocol-kernel concrete limit values and batch support
- **Added by:** the PR-1 remediation (`PR1-READINESS-REMEDIATION.md`, finding H-2) — the `MCP-PROTO-*`
  requirements define **required configurable limits** but the PR-0 package does **not** invent production
  numeric defaults without evidence.
- **Question:** the concrete safe-default and hard-cap **values** for the `MCP-PROTO-006/007/008` limits
  (max envelope size, JSON nesting depth, object-field/array-element counts, string length, method-name
  length, max active/in-flight request IDs, max partial-frame buffer, max parser memory per session, max
  parsing time/work budget); and **whether JSON-RPC batch is supported** (`MCP-PROTO-004`: bounded vs
  explicit-reject).
- **Options:** derive defaults from the MCP spec + measured load; adopt conservative caps first and tune;
  batch supported-with-bounds vs batch explicitly rejected in V1.
- **Recommended [REC]:** define every limit as configurable with a **conservative safe-default and a hard
  cap**; **numeric values remain an open implementation decision** to be fixed with evidence (spec + load
  measurement) during PR-1, not guessed in PR-0. Batch: **reject in V1 unless a concrete need is shown**
  (smaller attack surface), decided with D-1.
- **Evidence:** `[EXT]` MCP spec framing/limits + `[D-1]` protocol baseline; no repository prior art for MCP framing.
- **Owner:** Eng. **Approver:** Sec Arch. **Due:** PR-1. **Closure:** limit values + batch policy fixed,
  tested (limit + resource-budget assertions), and recorded; **the requirement IDs (`MCP-PROTO-*`) are not
  blocked — only their numeric values are.**
- **Blocking:** Slice (PR-1) for the values; the `MCP-PROTO-*` requirements themselves are already defined.

### D-15 — MCP config-surface registry integration strategy
- **Added by:** the board-blocker remediation for [#927](https://github.com/KidCarmi/Culvert/issues/927)
  (Enterprise Security Architecture Board, blocker B-3). Resolves the deferral previously left dangling
  in [`CONFIG-SURFACE-MATRIX.md`](CONFIG-SURFACE-MATRIX.md) §"The anti-drift pattern this surface must
  follow", which pointed at this document without allocating a decision here.
- **Question:** how do MCP configuration surfaces obtain the *enforced* anti-drift parity guarantees
  (forward, reverse, redaction, capture/apply, cap, wire-wipe, GUI) that `config_surfaces.go` +
  `config_surfaces_test.go` provide for the existing three types?
- **Why it is not merely a style choice `[FACT]`:** `csrStructTypes()` hard-codes exactly three types
  (`configBackup`, `AdminSettings`, `ConfigSnapshot`) and the reflection walk is one level deep. A new
  or nested MCP config struct is therefore **invisible** to parity — registering fails loudly, *not*
  registering passes silently. `redactUnenrolledSnapshot` zeroes only rows flagged `Sensitive`, so an
  invisible nested MCP struct discloses the server registry and credential-provider references to an
  **unenrolled** peer (the DEBT-006 `SessionHMAC`/`IdPProfiles` class).
- **Options:**
  - **Option A — extend the existing registry.** Add MCP surfaces to `configSurfaces` and extend the
    parity machinery to handle nested/dotted field paths, nested cap parity, and nested wire-wipe.
  - **Option B — parallel MCP registry.** A separate registry + parity suite providing equivalent or
    stronger forward, reverse, redaction, capture/apply, cap, wire-wipe and GUI guarantees.
- **Recommended `[REC]`: Option A — extend the existing registry.** Repository evidence:
  1. `config_surfaces_test.go` already implements every guarantee needed (forward/reverse parity,
     `SnapshotCapParity`, `SnapshotApplyParity`, redaction parity, wire-wipe ⇔ `omitempty`,
     `SnapshotCaptureOwner`). Option B re-implements all of it, and a second implementation is a second
     thing that can drift — the exact failure class the registry exists to prevent.
  2. The single leak path is `redactUnenrolledSnapshot`, which reads **one** registry. Two registries
     means two redaction call sites and a standing question of which one a new field belongs to.
  3. `CLAUDE.md` records the registry as "the anti-drift wall for Finding 10.3 / DEBT-004/006/009" —
     one wall, not a family of walls.
  4. Option B's only real advantage — freedom to model MCP-specific surfaces — is obtainable under
     Option A by extending the taxonomy (a new `fieldKind`), which is additive.
  - **Cost of Option A, stated honestly:** it requires touching shared parity machinery that currently
    guards the whole product, so the extension itself must land with its own regression evidence. That
    is the trade this decision accepts.
- **Binding structural constraint (either option):** every MCP configuration structure — including any
  nested struct — **MUST** be enumerated in the anti-drift inventory. A hard-coded inventory that
  silently ignores an unenumerated nested type does **not** satisfy this decision; see `MCP-CFG-001`.
- **Evidence:** `[FACT]` `config_surfaces.go`, `config_surfaces_test.go` (`csrStructTypes`, one-level
  reflection, `SnapshotCapParity` skipping `Ptr`/`Struct`); `[FACT]` `CLAUDE.md` config-surface
  registry contract; `[REC]` the recommendation above.
- **Owner:** Eng — platform/config. **Approver:** Architecture (registry contract) **and** Product
  Security (redaction/disclosure class). **Due:** PR-1.
- **Blocking:** **HARD PR-1 entry gate**, alongside D-1 — the wall must exist *before* the first MCP
  config field, because retrofitting after PR-4/PR-8 add credential and event rows is materially harder.
- **Closure conditions:** (1) option selected and recorded; (2) the constraint recorded in ADR-0024
  §Decision Part 1 item 8; (3) `MCP-CFG-001` present with verification + evidence; (4) the anti-omission
  gates in [`CI-GATES.md`](CI-GATES.md) specified as blocking, including **both** omission cases (new field
  in a known type **and** an entirely new/nested type).
- **Status: CLOSED — implementation contract accepted (2026-07-31).** The MCP configuration anti-drift
  contract is accepted as the implementation baseline: **`MCP-CFG-001` and the config-surface matrix
  ([`CONFIG-SURFACE-MATRIX.md`](CONFIG-SURFACE-MATRIX.md)) are authoritative**; every future MCP config
  field MUST have complete **config / API / GUI / OpenAPI / registry / test parity**; Option A (extend the
  existing registry) is the recorded strategy; the binding structural constraint is in ADR-0024 §Decision
  Part 1 item 8. The **runtime binding is implemented in PR-1+ according to slice ownership** — this closure
  accepts the contract, not a runtime implementation (none exists yet). Recorded in
  [`PR1-ENTRY-CLOSURE.md`](PR1-ENTRY-CLOSURE.md).

---

## Blocking summary

| Decision | Blocking | Due | Status (2026-07-24) |
|---|---|---|---|
| D-0 ADR scope | PR-1 gate | PR-1 | **CLOSED — ADR-0024 `Status: Accepted` (2026-07-31)** |
| D-2 auth model | GO/NO-GO + PR-3 | PR-3 | **CLOSED (Option A; ADR-0024 §D-2)** |
| D-5 event durability | GO/NO-GO + PR-8 | PR-8 | **CLOSED (Option C; ADR-0024 §D-5)** |
| D-8 connector model | GO/NO-GO + PR-11 | PR-11 | **CLOSED (Model A only V1; connector post-V1 own slice; ADR-0024 §D-8)** |
| D-9 DMZ support | GO/NO-GO | PR-11 | **CLOSED (not supported V1, default-off; ADR-0024 §D-9)** |
| D-13 Mgmt MCP scope | GO/NO-GO + PR-9 | PR-9 | **CLOSED (read-only+draft/validate/simulate; mutation excluded; ADR-0024 §D-13)** |
| **D-1 protocol baseline** | **HARD PR-1 entry gate** (elevated; was Slice) | **PR-1** | **CLOSED (2026-07-31) — V1 baseline: primary `2025-11-25`, floor `2025-06-18`, all others rejected; Streamable HTTP only; batch rejected; six-method surface; sessionless missing-header → `400`** |
| **D-14 protocol-kernel limit values + batch** | Slice (PR-1) — values only | PR-1 | **Batch policy resolved (reject in V1); numeric limit defaults/hard-caps remain the open PR-1 implementation decision (`MCP-PROTO-*` requirements defined)** |
| **D-15 config-surface registry integration** | **HARD PR-1 entry gate** | **PR-1** | **CLOSED — implementation contract accepted (2026-07-31). Option A (extend the existing registry); `MCP-CFG-001` + config-surface matrix authoritative; runtime binding in PR-1+ per slice ownership** |
| D-3, D-4, D-6, D-10, D-12 | Slice | per slice | Open (slice-scoped) |
| D-7, D-11 | Non-blocking / GA | post-V1 / GA | Open (post-V1 / GA) |
