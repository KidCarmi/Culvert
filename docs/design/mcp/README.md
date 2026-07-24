# Culvert MCP Agent Security Gateway — PR-0 Design Package

This directory is the **PR-0 documentation baseline** for the Culvert MCP Agent Security Gateway. It is
a **documentation-only** deliverable. **No runtime code, no MCP listener, and no changes to existing
proxy/SWG behavior are part of PR-0.**

---

## Purpose

PR-0 converts the product blueprint into a repository-grounded, reviewable, implementation-ready design
package so that Product, Engineering, Product Security, Architecture, IAM/PAM, SRE, Privacy, Support and
Release Engineering reviewers can decide **whether PR-1 may begin**. PR-0 does not implement anything.

## Authority and document hierarchy

Precedence when documents disagree:

1. **The current repository** (code, `CLAUDE.md`, ADRs, CI) — the source of truth for **what already
   exists**. All repository claims in this package are evidenced in
   [`VERIFIED-REPOSITORY-CONTEXT.md`](VERIFIED-REPOSITORY-CONTEXT.md) with `path · symbol · line-range`.
2. **[`BLUEPRINT.md`](BLUEPRINT.md)** (normalized from the preserved source DOCX) — the source of truth
   for **intended product and security direction**.
3. The individual PR-0 documents below — derived, normative design artifacts that must not contradict
   (1) or (2). Where they must diverge, they say so explicitly.

The original DOCX in [`source/`](source/) is preserved byte-for-byte (SHA-256 recorded in
`VERIFIED-REPOSITORY-CONTEXT.md`) and is never edited.

## Product targets vs. verified implementation

Throughout this package, four claim types are kept distinct:

- **[FACT]** — verified by direct repository read (carries file · symbol · lines).
- **[INFER]** — architectural inference from facts.
- **[REC]** — a recommendation for a human decision.
- **[EXT]** — an externally unverified requirement (needs a non-repository source before implementation).

SLOs, latency budgets, availability and conversion numbers are **design targets**, never measured
results. Any capability is described as existing **only** if it is verified in the current repository.

## Package contents

| Document | Role |
|---|---|
| [`BLUEPRINT.md`](BLUEPRINT.md) | Normalized product/security blueprint (from the DOCX). |
| [`VERIFIED-REPOSITORY-CONTEXT.md`](VERIFIED-REPOSITORY-CONTEXT.md) | Evidenced repository state, reusable/incompatible/missing primitives, commands run. |
| [`PRODUCT-SCOPE.md`](PRODUCT-SCOPE.md) | Category, buyers, V1 scope, non-goals, Management vs Gateway scope, success metrics. |
| [`PROTOCOL-COMPATIBILITY.md`](PROTOCOL-COMPATIBILITY.md) | Transports, versions, JSON-RPC/SSE lifecycle, adapters, compatibility tests. |
| [`RECOMMENDED-ARCHITECTURE.md`](RECOMMENDED-ARCHITECTURE.md) | Runtime separation, package boundaries, interfaces, prohibited coupling. |
| [`DATA-FLOW-DIAGRAMS.md`](DATA-FLOW-DIAGRAMS.md) | 14 numbered DFDs with trust boundaries. |
| [`THREAT-MODEL.md`](THREAT-MODEL.md) | Assets, STRIDE per component/flow, risk register, residual owners. |
| [`ATTACK-TREES.md`](ATTACK-TREES.md) | Nine attack trees; leaves map to threat IDs. |
| [`ABUSE-CASES.md`](ABUSE-CASES.md) | Attacker-centric cases with expected control/event/test. |
| [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md) | Stable-ID normative requirements with verification/evidence/gate. |
| [`AUTH-AND-CREDENTIAL-MODEL.md`](AUTH-AND-CREDENTIAL-MODEL.md) | Principals, delegation, no-passthrough, credential broker. |
| [`MCP-POLICY-MODEL.md`](MCP-POLICY-MODEL.md) | Policy tuple, nine actions, reason codes, lifecycle. |
| [`TOOL-DISCOVERY-AND-DRIFT.md`](TOOL-DISCOVERY-AND-DRIFT.md) | Tool identity, drift classes, quarantine. |
| [`EVENT-MODEL.md`](EVENT-MODEL.md) | Durable decision events, never-stored data, loss policy. |
| [`CP-DP-HA-MODEL.md`](CP-DP-HA-MODEL.md) | Snapshot fields, fencing, validation, rollback. |
| [`ON-PREM-CONNECTIVITY.md`](ON-PREM-CONNECTIVITY.md) | Local client, outbound connector, DMZ endpoint, data residency. |
| [`CONFIG-SURFACE-MATRIX.md`](CONFIG-SURFACE-MATRIX.md) | Every proposed field across all config surfaces. |
| [`SSDLC-CONTROL-MAPPING.md`](SSDLC-CONTROL-MAPPING.md) | Controls mapped to SSDF/SDL/SAMM/BSIMM/ASVS/API-Sec/SLSA. |
| [`SUPPLY-CHAIN-SECURITY.md`](SUPPLY-CHAIN-SECURITY.md) | Dependency, build, signing, provenance, response controls. |
| [`TEST-TRACEABILITY-MATRIX.md`](TEST-TRACEABILITY-MATRIX.md) | Threat → requirement → control → test → evidence → owner → gate. |
| [`CI-GATES.md`](CI-GATES.md) | Fast/deep/release/prod-readiness gates, classified Existing/Insufficient/Proposed. |
| [`ROLLOUT-AND-ROLLBACK.md`](ROLLOUT-AND-ROLLBACK.md) | Disabled→Observe→Shadow→Canary→Production, rollback, emergency disable. |
| [`OPERATIONS-AND-SUPPORT.md`](OPERATIONS-AND-SUPPORT.md) | SLO targets, runbooks, incident/support model. |
| [`IMPLEMENTATION-SLICES.md`](IMPLEMENTATION-SLICES.md) | PR-0 … PR-11 + Production Qualification, per-slice contract. |
| [`GO-NO-GO-CHECKLIST.md`](GO-NO-GO-CHECKLIST.md) | Blocking conditions and hard NO-GO lines. |
| [`OPEN-DECISIONS.md`](OPEN-DECISIONS.md) | Human decisions with options, recommendation, owner, closure. |
| [`PR0-REVIEW-CHECKLIST.md`](PR0-REVIEW-CHECKLIST.md) | Per-role reviewer checklists. |
| [`ADR-PROPOSAL-mcp-trust-boundary.md`](ADR-PROPOSAL-mcp-trust-boundary.md) | **Superseded** — non-authoritative pointer to [`docs/adr/0023`](../../adr/0023-mcp-agent-security-gateway-trust-boundary.md). |
| [`source/`](source/) | Preserved original DOCX (unchanged). |
| [`assets/`](assets/) | Diagrams extracted from the DOCX. |

## Approval flow

```
PR-0 authored (this package)
      → Reviewer checklists (PR0-REVIEW-CHECKLIST.md) completed per role
      → GO-NO-GO-CHECKLIST.md blocking conditions cleared
      → ADR promoted to docs/adr/0023 (Proposed; DONE 2026-07-24)
      → ARB + Security Architecture ratify ADR-0023 → Accepted  [PENDING]
      → D-1 protocol baseline externally verified + approved     [PENDING]
      → repository build/test baseline run + recorded            [PENDING]
      → PR-1 may begin
```

## The implementation gate

**PR-1 cannot begin until PR-0 is approved.** In addition, changes to any trust boundary require an ADR
(per [`docs/adr/0001-record-architecture-decisions.md`](../../adr/0001-record-architecture-decisions.md)).
Because the MCP subsystem introduces new trust boundaries (a new listener, a new auth surface, an
outbound-fetch path, a new persistence/snapshot surface), an ADR is mandatory.

### ADR scope — Option B (adopted for PR-0); PROMOTED 2026-07-24

- **During PR-0:** an ADR **proposal** (`Status: Proposed`) lived inside this directory as
  `ADR-PROPOSAL-mcp-trust-boundary.md`. This kept PR-0 confined to `docs/design/mcp/`.
- **Promotion (done 2026-07-24):** the proposal was promoted to the numbered ADR
  [`docs/adr/0023-mcp-agent-security-gateway-trust-boundary.md`](../../adr/0023-mcp-agent-security-gateway-trust-boundary.md),
  which also records the five closed PR-1 entry decisions (D-2, D-5, D-8, D-9, D-13). The in-package
  proposal file is now a **non-authoritative pointer** to ADR-0023.
- **ADR status is `Proposed`, not yet `Accepted`.** The hard, human-controlled PR-1 entry gate closes only
  when the **Architecture Review Board and Security Architecture record ratification** in ADR-0023's
  "Ratification" section. In addition, **D-1 (protocol baseline) is elevated to a hard PR-1 entry gate**
  and the **repository build/test baseline must be run and recorded** before PR-1 code begins.

## Trust-boundary changes require an ADR

Any later change that alters an MCP trust boundary — listener exposure, token/audience validation, the
credential-broker boundary, the CP→DP snapshot trust model, or the outbound-fetch policy — requires a new
or updated ADR under `docs/adr/`, following the repository's six-section ADR format. This package's
[`ADR-PROPOSAL-mcp-trust-boundary.md`](ADR-PROPOSAL-mcp-trust-boundary.md) is the first such record.

## Scope guardrails honored by this package

- Only files under `docs/design/mcp/` are created or modified.
- The source DOCX is preserved unchanged.
- No Go, CI, dependency, configuration or runtime change.
- No MCP listener is created.
- No commit, push or pull request is performed as part of authoring.
