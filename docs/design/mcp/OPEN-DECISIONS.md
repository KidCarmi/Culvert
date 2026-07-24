# MCP Open Decisions

Decisions that cannot be made safely by the coding agent and require named human owners. Each: ID,
question, options, recommended option, evidence, owner, approver, due stage, closure condition, blocking
status. **Status: PR-0 design artifact (Proposed).** Recommendations are `[REC]` — they do not decide.

Blocking status: **GO/NO-GO** = must be resolved before the stage in "Due"; **PR-1 gate** = blocks PR-1
start; **Slice** = blocks the named slice; **Non-blocking** = can trail.

---

### D-0 — ADR scope (Option A vs Option B)
- **Question:** where does the mandatory MCP trust-boundary ADR live during PR-0?
- **Options:** (A) PR-0 writes a numbered ADR under `docs/adr/`; (B) PR-0 writes an ADR **proposal** inside
  `docs/design/mcp/`, and a human promotes it to a numbered Accepted `docs/adr/NNNN` as a PR-1 entry gate.
- **Recommended [REC]:** **Option B.** Option A violates the PR-0 restriction "only `docs/design/mcp/`".
- **Evidence:** task absolute restrictions; `docs/adr/0001` ADR mandate.
- **Owner:** Eng/Arch. **Approver:** ARB. **Due:** PR-1 gate. **Closure:** numbered ADR accepted.
- **Blocking:** PR-1 gate. *(Proposal authored: [`ADR-PROPOSAL-mcp-trust-boundary.md`](ADR-PROPOSAL-mcp-trust-boundary.md).)*

### D-1 — Protocol baseline
- **Question:** which stable MCP protocol version(s) to freeze, and the adapter policy?
- **Options:** single pinned version; N-latest with adapters; permissive.
- **Recommended [REC]:** freeze a small supported set + version adapters in the protocol kernel; default-deny unknown versions.
- **Evidence:** [EXT] — protocol versions are externally unverified ([`PROTOCOL-COMPATIBILITY.md`](PROTOCOL-COMPATIBILITY.md)).
- **Owner:** Eng. **Approver:** Arch. **Due:** PR-1. **Closure:** compatibility matrix approved + tested.
- **Blocking:** Slice (PR-1). **[EXT] EXTERNAL VERIFICATION REQUIRED.**

### D-2 — Authentication deployment model
- **Question:** MCP as OAuth resource server, gateway-issued token, or enterprise-broker integration; RFC 8707 adoption?
- **Options:** resource server (validate external tokens); gateway-issued; broker integration; hybrid.
- **Recommended [REC]:** resource-server with mandatory audience + RFC 8707 resource validation; separate Mgmt/Gateway clients; add net-new replay defense.
- **Evidence:** [FACT] SWG OIDC binds audience to client_id (`auth_oidc_flow.go:523`), no RFC 8707, no replay defense (VRC §6).
- **Owner:** IAM/Sec Arch. **Approver:** Sec Arch. **Due:** PR-3. **Closure:** threat model + interop tests approved.
- **Blocking:** GO/NO-GO (identity) + Slice (PR-3).

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

### D-9 — DMZ support
- **Question:** offer a routable remote MCP endpoint at all, and accept its risk?
- **Options:** no DMZ; DMZ with explicit risk acceptance.
- **Recommended [REC]:** defer DMZ (Model C) until A/B proven; require explicit written risk acceptance if offered.
- **Evidence:** threat MCP-T-052; MCP-CONNECT-003, MCP-INSP-008.
- **Owner:** Sec Arch/Exec. **Approver:** Arch + Exec. **Due:** PR-11. **Closure:** risk acceptance signed or DMZ deferred.
- **Blocking:** GO/NO-GO (connectivity).

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
- **Owner:** Staff Eng. **Approver:** ARB. **Due:** PR-5. **Closure:** slice plan ratified; if reinstated, PR-12 must be explicitly defined + justified here.
- **Blocking:** Non-blocking (planning).

### D-13 — Management MCP scope (read-only vs draft vs controlled mutation)
- **Question:** how far does Management MCP go in V1?
- **Options:** read-only only; +draft/validate; +controlled mutation (plan→validate→approve→apply).
- **Recommended [REC]:** read-only + draft/validate in V1; mutation only after the full approval workflow exists (MCP-MGMT-001).
- **Evidence:** BLUEPRINT §03; MCP-MGMT-001.
- **Owner:** Sec/Eng. **Approver:** Sec Arch. **Due:** PR-9. **Closure:** separate threat model + RBAC + plan/validate/approve/apply approved.
- **Blocking:** GO/NO-GO (dual MCP surfaces) + Slice (PR-9).

---

## Blocking summary

| Decision | Blocking | Due |
|---|---|---|
| D-0 ADR scope | PR-1 gate | PR-1 |
| D-2 auth model | GO/NO-GO + PR-3 | PR-3 |
| D-5 event durability | GO/NO-GO + PR-8 | PR-8 |
| D-8 connector model | GO/NO-GO + PR-11 | PR-11 |
| D-9 DMZ support | GO/NO-GO | PR-11 |
| D-13 Mgmt MCP scope | GO/NO-GO + PR-9 | PR-9 |
| D-1, D-3, D-4, D-6, D-10, D-12 | Slice | per slice |
| D-7, D-11 | Non-blocking / GA | post-V1 / GA |
