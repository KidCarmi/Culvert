# PR-0 Reviewer Checklist

Per-role checklists for reviewing this PR-0 documentation package. **Status: PR-0 design artifact
(Proposed).** Each reviewer confirms their domain before the PR-0 → PR-1 gate in
[`GO-NO-GO-CHECKLIST.md`](GO-NO-GO-CHECKLIST.md) can clear. Check items are about the **design/documents**,
not about running code (none exists).

How to use: each role signs off its section. Any unchecked blocking item holds the gate. Link findings to
the specific document and ID.

> **Decision status (2026-07-31 — PR-1 entry closed).** All five blocking decisions are closed and recorded
> in [`docs/adr/0024`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md): **D-2** (identity), **D-5**
> (events), **D-8 + D-9** (connectivity), **D-13** (dual-surface). **ADR-0024 is `Status: Accepted`.** The two
> remaining hard PR-1 entry decisions **D-1** (protocol baseline) and **D-15** (config anti-drift contract)
> are **CLOSED**, and the **build/test baseline is re-anchored to current `main` + recorded**. The lenses
> below are review dimensions, satisfied on an **evidence basis** — actual documents, RPRs, tests, and
> independent-verification comments — **not** human role signatures; there is no ARB / committee / sign-off
> step in this project (#923 Gate 2). See [`PR1-ENTRY-CLOSURE.md`](PR1-ENTRY-CLOSURE.md).

---

## Product
- [ ] [`PRODUCT-SCOPE.md`](PRODUCT-SCOPE.md) category, buyer/user, V1 scope and non-goals are accurate and sellable.
- [ ] Success metrics are labeled **design targets**, never measured results.
- [ ] Management MCP vs Security Gateway scopes are distinct and both make product sense.
- [ ] Local-MCP limitation (stdio/localhost) is honestly stated, not implied as covered.
- [ ] Packaging/licensing questions are captured in [`OPEN-DECISIONS.md`](OPEN-DECISIONS.md) (D-11), not pre-decided.

## Architecture
- [ ] [`RECOMMENDED-ARCHITECTURE.md`](RECOMMENDED-ARCHITECTURE.md) keeps SWG, Gateway and Management runtimes separate; shared CP services only.
- [ ] Proposed `internal/mcp/*` boundaries are **evaluated, not adopted**; consistent with ADR-0002.
- [ ] Prohibited coupling is explicit (no SWG `PolicyRule` fields; no OIDC-flow reuse; no audit-ring reuse; no shared listeners; no policy-eval I/O).
- [ ] Trust boundaries TB-1..TB-7 are coherent across [`DATA-FLOW-DIAGRAMS.md`](DATA-FLOW-DIAGRAMS.md) and [`THREAT-MODEL.md`](THREAT-MODEL.md).
- [x] ADR proposal promoted to [`docs/adr/0024`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md) (D-0, Option B); the in-package file is now a pointer. *(ADR is **`Status: Accepted`** — the PR-1 ADR gate is satisfied on the merged repository state; no ARB / committee ratification step exists in this project.)*

## Product Security
- [ ] [`THREAT-MODEL.md`](THREAT-MODEL.md) covers all listed threat classes; every Critical/High has controls, tests, owner, closure.
- [ ] **No critical threat lacks an owner** (hard NO-GO line 1).
- [ ] [`ATTACK-TREES.md`](ATTACK-TREES.md) leaves all map to defined threat IDs.
- [ ] [`ABUSE-CASES.md`](ABUSE-CASES.md) cover token passthrough, unknown-tool auto-allow, credential-to-agent, critical-event loss (hard NO-GO lines 2,3,4,6).
- [ ] [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md) IDs are unique; every requirement maps to a threat/verification/evidence/gate.
- [ ] Replay protection is stated as **net-new / NOT VERIFIED**, not implied as present, **and framed per [`ADR-0024 §D-2`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md) as sender-constraint / DPoP-proof replay — NOT access-token `jti` one-time-use**.
- [ ] Inbound Origin/Host anti-rebinding is a stated new requirement, **split across two layers**: the pure validation primitive `MCP-INSP-008` (**PR-1**, no listener) **and** the listener-side enforcement + E2E rebinding proof `MCP-INSP-009` (**PR-5** Model A / Future DMZ gate Model C). Tick this only if **both** are stated — PR-1 alone does not close MCP-T-031/055.
- [ ] **PR-1 protocol-kernel attack surface is modeled (findings H-1..H-4):** parser/framing/version/protocol-state threats **MCP-T-057..074** exist with owners; the former undefined "protocol bounds" acceptance item is now the **MCP-PROTO-001..014** requirement family; **fuzz** and **compatibility** have defined **blocking PR-1** gate homes ([`CI-GATES.md`](CI-GATES.md)) with compatibility **D-1-gated**; and `MCP-OPS-002` is PR-5 (runtime), not PR-1.

## IAM / PAM
- [ ] [`AUTH-AND-CREDENTIAL-MODEL.md`](AUTH-AND-CREDENTIAL-MODEL.md) defines all principals + delegation; human `Identity` reuse is post-refactor only.
- [ ] No token passthrough; audience + RFC 8707 resource validation required; separate Mgmt/Gateway clients (**D-2 CLOSED — [`ADR-0024 §D-2`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md); Culvert = resource server, Option C = issuer topology, Option B = edge only**).
- [ ] Credential broker: scoped, short-lived, revocable, fail-closed; **agent never holds a secret** (hard NO-GO line 2).
- [ ] Credential providers for MVP captured as a decision (D-3).
- [ ] No secrets in events/logs (MCP-CRED-004, MCP-EVENT-003).

## SRE
- [ ] [`OPERATIONS-AND-SUPPORT.md`](OPERATIONS-AND-SUPPORT.md) SLOs are labeled design targets; runbooks exist for every incident class.
- [ ] [`CP-DP-HA-MODEL.md`](CP-DP-HA-MODEL.md) fencing/last-known-good/rollback are sound; DP never depends on CP per call.
- [ ] [`ROLLOUT-AND-ROLLBACK.md`](ROLLOUT-AND-ROLLBACK.md) mode ladder + **rehearsed rollback** (hard NO-GO line 5); hard failures blocked even in Shadow.
- [ ] Bounds/rate-limits defined at **both** layers: **parse-time** structural + per-session bounds `MCP-PROTO-006/008` (**PR-1**, kernel, no listener) **and** listener/runtime stream/connection/queue/rate bounds `MCP-OPS-002` (**PR-5**). Tick only if both are stated — deferring oversized-payload defence entirely to PR-5 would leave the PR-1 kernel accepting hostile frames.
- [ ] MCP-off overhead regression is planned (MCP-OPS-001).

## Privacy
- [ ] [`ON-PREM-CONNECTIVITY.md`](ON-PREM-CONNECTIVITY.md) states the data-residency truth (cloud AI ≠ on-prem).
- [ ] DLP-before-egress + per-deployment data-flow/retention/privacy-review required (MCP-PRIVACY-001/003).
- [ ] Tenant isolation across events/exports/catalog (MCP-PRIVACY-002).
- [ ] [`EVENT-MODEL.md`](EVENT-MODEL.md) never-stored list protects tokens/secrets/raw args/outputs.

## Support
- [ ] Known limitations documented (stdio/localhost/direct-egress; best-effort inspection).
- [ ] Upgrade/downgrade/rollback + compatibility-incident procedures exist.
- [ ] Support ownership + incident severity + customer escalation defined.
- [ ] Support lifecycle captured; commercial support model referenced to D-11.

## Release Engineering
- [ ] [`SUPPLY-CHAIN-SECURITY.md`](SUPPLY-CHAIN-SECURITY.md) distinguishes Existing vs Proposed controls accurately.
- [ ] [`CI-GATES.md`](CI-GATES.md) classifies every gate (Existing/Insufficient/Proposed/Blocking/Advisory); no gate claimed present that isn't.
- [ ] Signed SBOM + provenance verify-before-deploy required (MCP-SUPPLY-003).
- [ ] **CodeQL is described accurately (finding M-1):** `codeql.yml` **already analyzes `internal/mcp/**`** via its `internal/**` PR path filter (no path-filter edit needed), but it is **non-blocking** (not a branch-protection-required check); the only MCP CodeQL "change" is the optional policy choice to make it blocking via branch protection. The MCP-specific **fuzz / structural / compatibility** gates (PR-1) and other proposed gates are genuine PR-1+ CI additions.
- [ ] [`SSDLC-CONTROL-MAPPING.md`](SSDLC-CONTROL-MAPPING.md) maps controls to SSDF/SDL/SAMM/BSIMM/ASVS/API-Sec/SLSA.

---

## Cross-role confirmations (all reviewers)
- [ ] No document presents a roadmap feature as implemented.
- [ ] Every repository claim carries file · symbol · line evidence or is marked `NOT VERIFIED` / `[EXT]`.
- [ ] Management MCP and Security Gateway are never merged.
- [ ] Only files under `docs/design/mcp/` **plus the promoted `docs/adr/0024-mcp-agent-security-gateway-trust-boundary.md`** changed; the source DOCX and diagram assets are unchanged; **no product code, CI workflow, config or runtime change** — the standalone document-structure checks under `docs/design/mcp/predicates/` are Python but are not wired to any workflow and check *these documents*, not the product; no listener.
- [ ] Implementation sequence is PR-0 … PR-11 + separate Production Qualification (no PR-12 unless justified in [`OPEN-DECISIONS.md`](OPEN-DECISIONS.md) D-12).

## Sign-off

| Role | Reviewer | Date | Blocking items open? |
|---|---|---|---|
| Product | | | |
| Architecture | | | |
| Product Security | | | |
| IAM/PAM | | | |
| SRE | | | |
| Privacy | | | |
| Support | | | |
| Release Engineering | | | |
