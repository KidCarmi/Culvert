# MCP Supply-Chain Security — Dependency, Build, Signing, Provenance and Vulnerability Response

**Status: PR-0 design artifact (Proposed).**

This document maps the Blueprint's [`BLUEPRINT.md`](BLUEPRINT.md) §18 "Supply-Chain Gates" table to the
**current, verified** state of the Culvert CI/release pipeline, and to the four canonical
`MCP-SUPPLY-001..004` requirements defined in [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md).
Every row below is classified **Existing [FACT]**, **Existing-but-insufficient**, or **Proposed** —
no control is described as existing unless it is present in the VERIFIED EVIDENCE set. Test-gate detail
(which workflow runs which check, and why) lives in [`CI-GATES.md`](CI-GATES.md); framework mapping
(NIST SSDF / SDL / SAMM / BSIMM / ASVS / SLSA) lives in
[`SSDLC-CONTROL-MAPPING.md`](SSDLC-CONTROL-MAPPING.md). This document is the supply-chain-specific
cross-section of both.

## Scope and shared-vs-separate posture

The MCP subsystem (both **Capability A — Management MCP** and **Capability B — MCP Security Gateway**,
kept separate everywhere else in this package) ships inside the **same single Culvert binary** as the
existing SWG — there is no separate MCP build, no separate container image, and no separate release
pipeline. Per the doctrine in [`README.md`](README.md)/[`PRODUCT-SCOPE.md`](PRODUCT-SCOPE.md), CI/release
infrastructure is one of the explicitly **shared** Control Plane services. Consequently:

- The supply-chain controls below (dependency pinning, SBOM, signing, provenance, reproducibility)
  **[INFER]** apply automatically to any MCP code once merged, because they operate on the repository and
  the produced binary/image as a whole, not per-subsystem. No new supply-chain *infrastructure* is
  required to cover MCP code specifically.
- What MCP work **can** change is the **inputs** to that pipeline: new Go dependencies (e.g. a JSON-RPC/
  MCP protocol library, an OAuth/JOSE library), new CI workflow steps, and new secrets/credentials for a
  listener. Those inputs are where this document's gaps are concentrated.

## Legend

| Status | Meaning |
|---|---|
| **Existing [FACT]** | Verified in the current repository/CI per the VERIFIED EVIDENCE in the PR-0 package. |
| **Existing-but-insufficient** | A related control exists but does not fully satisfy the stated requirement. |
| **Proposed** | Net-new; not present today (`MCP-SUPPLY-00x`, Status: Proposed, per `SECURITY-REQUIREMENTS.md`). |

---

## 1 · Minimal Dependency Footprint & Pinned Versions (`MCP-SUPPLY-001`)

| Requirement | Status | Evidence / CI location | Requirement ID | Owner | Gate |
|---|---|---|---|---|---|
| Single-binary, zero-runtime-dependency posture (minimal footprint by design). | **Existing [FACT]** | `CLAUDE.md` project description: "Single binary, zero runtime dependencies." Repo is `package main`, flat layout. | MCP-SUPPLY-001 | Sec/Release | PR-1 |
| Dependency versions pinned. | **Existing [FACT]** | Pinned `go.mod` (Go 1.25.12 pinned for govulncheck fixes per `CLAUDE.md`); "tidy check" in `pr-fast-gate.yml`. | MCP-SUPPLY-001 | Sec/Release | PR-1 |
| Mechanical **no-new-dependency** CI gate (blocks a PR that silently adds a runtime dependency). | **Existing-but-insufficient** | Only an **advisory** "Dependency Obituary" exists; it is not a mechanical/blocking gate. **[FACT]**: "NO mechanical no-new-deps gate (advisory Dependency Obituary only)." | MCP-SUPPLY-001 | Sec/Release | Proposed strengthening — no gate currently enforces "new runtime deps SHOULD be avoided" from the `MCP-SUPPLY-001` normative statement. |

**Reading**: the *posture* (minimal footprint, pinned versions) is real and verified. The *enforcement*
gap is that nothing mechanically stops a future MCP PR from adding a new runtime dependency (e.g. an MCP/
JSON-RPC SDK) beyond an advisory note. `MCP-SUPPLY-001`'s "new runtime deps **SHOULD** be avoided" clause
is therefore only as strong as manual PR review today.

## 2 · Dependency-Review Policy & License Policy (`MCP-SUPPLY-001`)

| Requirement | Status | Evidence / CI location | Requirement ID | Owner | Gate |
|---|---|---|---|---|---|
| License-compliance check on dependency changes. | **Existing [FACT]** | `go-licenses` runs in `pr-deep-gate.yml`, diff-gated on dependency changes. | MCP-SUPPLY-001 | Sec/Release | PR-1 |
| Automated dependency-review (new/changed transitive deps surfaced with advisory/license diff on every PR, e.g. GitHub's `dependency-review-action`). | **Proposed** | **[FACT]**: "NO dependency-review-action" in the current pipeline. `go-licenses` covers license text, not a structured advisory/severity diff of the dependency graph itself. | MCP-SUPPLY-001 | Sec/Release | Proposed — recommend adding `dependency-review-action` (or equivalent) diff-gated like `go-licenses`, ahead of any MCP PR that touches `go.mod`. |

## 3 · Vulnerability-Remediation SLA (`MCP-SUPPLY-004`)

| Requirement | Status | Evidence / CI location | Requirement ID | Owner | Gate |
|---|---|---|---|---|---|
| Automated vulnerability scanning of the dependency graph and standard library, **blocking**. | **Existing [FACT]** | `govulncheck` runs in `pr-fast-gate.yml` (required merge gate: "Fast PR Gate — APPROVED"). | MCP-SUPPLY-001 (footprint/vuln posture) | Sec/Release | PR-1 |
| Static application security testing, **blocking**. | **Existing [FACT]** | `gosec` runs in `pr-fast-gate.yml`. | MCP-SUPPLY-001 | Sec/Release | PR-1 |
| Written, severity-based **remediation SLA** (time-to-fix by CVSS/severity band). | **Proposed** | Not in VERIFIED EVIDENCE — `govulncheck`/`gosec` gate *merges*, but no document ties a scan finding to a remediation deadline. | MCP-SUPPLY-004 | Sec/Release | Prod-Qual |
| **Emergency revoke** procedure (e.g. pull a signed release/catalog entry, force re-enrollment/re-issuance). | **Proposed** | No evidence of a documented revoke runbook in scope. Adjacent prior art exists for release-catalog trust (rollback/floor mechanics in `release_catalog_freshness.go` per `CLAUDE.md`) but that is a **freshness/rollback** floor, not an incident-driven emergency-revoke runbook. | MCP-SUPPLY-004 | Sec/Release | Prod-Qual |
| **Customer-notification** procedure for a supply-chain or vulnerability incident. | **Proposed** | Not in VERIFIED EVIDENCE. | MCP-SUPPLY-004 | Sec/Release | Prod-Qual |

**Reading**: the *detection* half of `MCP-SUPPLY-004` (finding vulnerabilities) is a real, blocking gate
today via `govulncheck`/`gosec`. The *response* half (a written SLA, an emergency-revoke runbook, and a
customer-notification procedure) does not exist yet and is entirely `Proposed`, gated at
**Production Qualification** per `SECURITY-REQUIREMENTS.md`.

## 4 · CI Actions Pinned to Immutable SHAs; Least-Privilege Tokens; Protected Environments (`MCP-SUPPLY-002`)

| Requirement | Status | Evidence / CI location | Requirement ID | Owner | Gate |
|---|---|---|---|---|---|
| GitHub Actions pinned to immutable commit SHAs (not floating tags). | **Existing [FACT]** | "Actions SHA-pinned." (VERIFIED EVIDENCE, CI section). | MCP-SUPPLY-002 | Release | PR-1 |
| Least-privilege `permissions:` blocks per workflow/job. | **NOT VERIFIED in this session** | No per-workflow `permissions:` audit is in the VERIFIED EVIDENCE list; this document does not claim it exists or is absent. | MCP-SUPPLY-002 | Release | Proposed verification pass before PR-1 touches any workflow file. |
| Protected environments (required reviewers / deployment gates) for release/publish jobs. | **NOT VERIFIED in this session** | No protected-environment configuration is in the VERIFIED EVIDENCE list. | MCP-SUPPLY-002 | Release | Proposed verification pass before PR-1. |
| Avoid long-lived CI secrets where workload identity (OIDC) is available. | **NOT VERIFIED in this session** | Blueprint §18 lists this as a required gate (`BLUEPRINT.md` §18, "Secrets" row); no repository evidence either confirms or refutes current CI secret posture in this package. | MCP-SUPPLY-002 (closest existing ID; no dedicated `MCP-SUPPLY` ID for this sub-clause) | Release | Proposed — fold into the `MCP-SUPPLY-002` verification step; log any resulting decision in [`OPEN-DECISIONS.md`](OPEN-DECISIONS.md) rather than this file. |

**Reading**: SHA-pinning is the one sub-clause of `MCP-SUPPLY-002` that is directly verified. The
least-privilege-token and protected-environment sub-clauses are **not asserted either way** — this
package's VERIFIED EVIDENCE does not include a `permissions:`/environments audit, so they are marked
`NOT VERIFIED` rather than `Existing` or `Gap`, per the CLAIM LEGEND.

## 5 · Secret Scanning

| Requirement | Status | Evidence / CI location | Requirement ID | Owner | Gate |
|---|---|---|---|---|---|
| Repository-wide secret scanning on every PR, including docs-only changes. | **Existing [FACT]** | `gitleaks` runs in `pr-fast-gate.yml`, "even docs-only PRs" (VERIFIED EVIDENCE, CI section). | — (blocking test gate, Blueprint §18, not a numbered `MCP-SUPPLY` requirement) | Sec/Release | PR-1 (existing, repo-wide; no MCP-specific extension needed) |

This control is not one of the four `MCP-SUPPLY-00x` IDs (those cover dependencies, CI-action integrity,
SBOM/signing/provenance, and vulnerability response) — it is listed here for completeness against
Blueprint §18's Supply-Chain Gates table, and cross-references the general secret-handling requirements
in `MCP-CRED` (credential broker, [`AUTH-AND-CREDENTIAL-MODEL.md`](AUTH-AND-CREDENTIAL-MODEL.md)) and the
secret-leakage-into-events threat (`MCP-T-028`, Critical, [`THREAT-MODEL.md`](THREAT-MODEL.md)). This
existing repo-wide `gitleaks` gate is a **prior-art precedent**, not itself an MCP secret-handling
control — it would still need to catch any credential accidentally embedded in new MCP code/config, which
it already covers as-is (no new gate required).

## 6 · SBOM, Signing, Provenance & Reproducibility (`MCP-SUPPLY-003`)

| Requirement | Status | Evidence / CI location | Requirement ID | Owner | Gate |
|---|---|---|---|---|---|
| Machine-readable SBOM per release artifact. | **Existing [FACT]** | `syft` generates a CycloneDX SBOM on the tag path (`ci.yml`). | MCP-SUPPLY-003 | Release | Prod-Qual |
| Binary signing. | **Existing [FACT]** | Cosign keyless signing on the tag path (`ci.yml`). | MCP-SUPPLY-003 | Release | Prod-Qual |
| Container-image signing. | **Existing [FACT]** | Cosign keyless signing of the published multi-arch image (`ci.yml`). | MCP-SUPPLY-003 | Release | Prod-Qual |
| SBOM signing. | **Existing [FACT]** | Signed alongside the release artifact per the "cosign keyless + SLSA L3 verifiable + syft SBOM on tag path" evidence. | MCP-SUPPLY-003 | Release | Prod-Qual |
| Provenance signing. | **Existing [FACT]** | SLSA provenance is generated and signed on the tag path (`ci.yml`, "release + SLSA provenance"). | MCP-SUPPLY-003 | Release | Prod-Qual |
| Source SHA, builder identity, build inputs/parameters recorded (provenance content). | **Existing [FACT]** | SLSA L3 provenance on the tag path (VERIFIED EVIDENCE, CI section: "cosign keyless + SLSA L3 verifiable ... on tag path (ci.yml)"). | MCP-SUPPLY-003 | Release | Prod-Qual |
| Reproducible / independently verifiable builds. | **Existing [FACT]** | Determinism gate (any `*_test.go` change) in `pr-deep-gate.yml`, plus SLSA verification on the tag path. | MCP-SUPPLY-003 | Release | Prod-Qual |
| Consumers **verify before deploy** (not just produce signed artifacts). | **Existing [FACT]** (for the general release path) | The maintenance-agent install/apply/rollback path is signature-verified before use (`verify_pinned_image_signature` cosign-verifies the pinned proxy image against a pinned Sigstore identity before trusting the bundled agent — `CLAUDE.md` "Proxy image pin binding" section). | MCP-SUPPLY-003 | Release/Ops | Prod-Qual |

**Reading**: this is the strongest area of the four — SBOM, binary/container/SBOM/provenance signing,
SLSA L3 recording, determinism/reproducibility, and verify-before-trust are all `Existing [FACT]` for the
general Culvert release pipeline. Because MCP ships inside the same binary/image (see "Scope" above), the
MCP subsystem inherits this posture **without new supply-chain infrastructure**, provided no MCP-specific
artifact (e.g. a standalone catalog/manifest for registered MCP servers, if ever introduced) is invented
outside this pipeline. Any such new artifact type would need its own SBOM/signing/provenance wiring and
should be flagged in [`OPEN-DECISIONS.md`](OPEN-DECISIONS.md) if proposed later.

## 7 · Emergency Revoke & Customer-Notification Procedure (`MCP-SUPPLY-004`)

See §3 above — both sub-clauses ("emergency revoke" and "customer communication plan" from Blueprint §18)
are consolidated under `MCP-SUPPLY-004` and are **Proposed**, gated at Production Qualification. They are
not duplicated in a second table here to avoid a split source of truth for the same requirement ID.

---

## Summary: `MCP-SUPPLY-001..004` at a glance

| Requirement ID | Normative statement (abridged, per `SECURITY-REQUIREMENTS.md`) | Overall status | Gate |
|---|---|---|---|
| MCP-SUPPLY-001 | Pinned + minimal dependencies; avoid new runtime deps. | **Existing-but-insufficient** — posture verified; no mechanical no-new-deps gate, no dependency-review-action. | PR-1 |
| MCP-SUPPLY-002 | CI actions pinned to immutable SHAs, least-privilege tokens. | **Existing-but-insufficient** — SHA-pinning verified; least-privilege tokens/protected environments/OIDC-vs-long-lived-secrets not verified either way in this session. | PR-1 |
| MCP-SUPPLY-003 | Every artifact ships a signed SBOM + signed provenance; verified before deploy. | **Existing [FACT]** for the general release pipeline (syft, cosign keyless, SLSA L3, determinism, verify-before-trust). No MCP-specific artifact exists to test this against yet. | Prod-Qual |
| MCP-SUPPLY-004 | Vulnerability-remediation SLA, emergency revoke, customer-notification procedure. | **Proposed** — detection (govulncheck/gosec) exists and blocks; the written SLA, revoke runbook, and notification procedure do not exist. | Prod-Qual |

## Cross-references

- [`CI-GATES.md`](CI-GATES.md) — full fast/deep/release/prod-readiness gate classification (Existing /
  Insufficient / Proposed) for **all** MCP blocking test gates, not only the supply-chain subset covered
  here.
- [`SSDLC-CONTROL-MAPPING.md`](SSDLC-CONTROL-MAPPING.md) — maps these same controls to NIST SSDF, Microsoft
  SDL, OWASP SAMM, BSIMM, OWASP ASVS/API Security and SLSA (Blueprint §18 "Control Framework Mapping").
- [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md) — canonical, stable-ID source of truth for
  `MCP-SUPPLY-001..004` (this document only elaborates evidence/status; it does not renumber or restate
  the normative text).
- [`THREAT-MODEL.md`](THREAT-MODEL.md) — `MCP-T-020` (malicious server) and `MCP-T-021` (compromised
  approved server) are about a *third-party MCP server* being malicious/compromised, and are deliberately
  **not** conflated with this document's scope, which is Culvert's **own** build/release supply chain.
- [`AUTH-AND-CREDENTIAL-MODEL.md`](AUTH-AND-CREDENTIAL-MODEL.md) — credential-broker secret handling,
  cross-referenced from §5 above.
- [`BLUEPRINT.md`](BLUEPRINT.md) §18 — source Supply-Chain Gates and Blocking Test Gates tables this
  document elaborates.

## Verification status of this document

No build, test, or scan was executed while authoring this document — it is a documentation-only PR-0
artifact per the HARD SCOPE RULES, and every `Existing [FACT]` row above is sourced from the PR-0
package's pre-recorded VERIFIED EVIDENCE, not from a fresh command run. Risk framing: Low for the
read-only Phase 1 investigation, but the current repository test baseline remains unverified in this
session.
