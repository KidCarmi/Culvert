# PR-0 Reviewer Checklist

Per-role checklists for reviewing this PR-0 documentation package. **Status: PR-0 design artifact
(Proposed).** Each reviewer confirms their domain before the PR-0 → PR-1 gate in
[`GO-NO-GO-CHECKLIST.md`](GO-NO-GO-CHECKLIST.md) can clear. Check items are about the **design/documents**,
not about running code (none exists).

How to use: each role signs off its section. Any unchecked blocking item holds the gate. Link findings to
the specific document and ID.

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
- [ ] **ADR proposal** [`ADR-PROPOSAL-mcp-trust-boundary.md`](ADR-PROPOSAL-mcp-trust-boundary.md) is complete; ready to promote to `docs/adr/NNNN` (D-0, Option B). *(Blocking for PR-1.)*

## Product Security
- [ ] [`THREAT-MODEL.md`](THREAT-MODEL.md) covers all listed threat classes; every Critical/High has controls, tests, owner, closure.
- [ ] **No critical threat lacks an owner** (hard NO-GO line 1).
- [ ] [`ATTACK-TREES.md`](ATTACK-TREES.md) leaves all map to defined threat IDs.
- [ ] [`ABUSE-CASES.md`](ABUSE-CASES.md) cover token passthrough, unknown-tool auto-allow, credential-to-agent, critical-event loss (hard NO-GO lines 2,3,4,6).
- [ ] [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md) IDs are unique; every requirement maps to a threat/verification/evidence/gate.
- [ ] Replay protection is stated as **net-new / NOT VERIFIED**, not implied as present.
- [ ] Inbound Origin/Host anti-rebinding is a stated new requirement (MCP-INSP-008).

## IAM / PAM
- [ ] [`AUTH-AND-CREDENTIAL-MODEL.md`](AUTH-AND-CREDENTIAL-MODEL.md) defines all principals + delegation; human `Identity` reuse is post-refactor only.
- [ ] No token passthrough; audience + RFC 8707 resource validation required; separate Mgmt/Gateway clients (D-2).
- [ ] Credential broker: scoped, short-lived, revocable, fail-closed; **agent never holds a secret** (hard NO-GO line 2).
- [ ] Credential providers for MVP captured as a decision (D-3).
- [ ] No secrets in events/logs (MCP-CRED-004, MCP-EVENT-003).

## SRE
- [ ] [`OPERATIONS-AND-SUPPORT.md`](OPERATIONS-AND-SUPPORT.md) SLOs are labeled design targets; runbooks exist for every incident class.
- [ ] [`CP-DP-HA-MODEL.md`](CP-DP-HA-MODEL.md) fencing/last-known-good/rollback are sound; DP never depends on CP per call.
- [ ] [`ROLLOUT-AND-ROLLBACK.md`](ROLLOUT-AND-ROLLBACK.md) mode ladder + **rehearsed rollback** (hard NO-GO line 5); hard failures blocked even in Shadow.
- [ ] Bounds/rate-limits defined for streams/payloads/queues/events (MCP-OPS-002).
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
- [ ] CodeQL path extension + MCP-specific gates are noted as PR-1+ CI changes (not done in PR-0).
- [ ] [`SSDLC-CONTROL-MAPPING.md`](SSDLC-CONTROL-MAPPING.md) maps controls to SSDF/SDL/SAMM/BSIMM/ASVS/API-Sec/SLSA.

---

## Cross-role confirmations (all reviewers)
- [ ] No document presents a roadmap feature as implemented.
- [ ] Every repository claim carries file · symbol · line evidence or is marked `NOT VERIFIED` / `[EXT]`.
- [ ] Management MCP and Security Gateway are never merged.
- [ ] Only files under `docs/design/mcp/` changed; the source DOCX is unchanged; no code/CI/config/runtime change; no listener; no commit/push.
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
