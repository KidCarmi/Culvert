# Culvert MCP — SSDLC Control Framework Mapping

This document maps the Culvert MCP program (Capability A — Culvert Management MCP Server, and
Capability B — MCP Security Gateway) against seven external secure-SDLC frameworks — **NIST SSDF,
Microsoft SDL, OWASP SAMM, BSIMM, OWASP ASVS, OWASP API Security Top 10, and SLSA** — so a reviewer can
trace every framework practice/area to a concrete Culvert control, the stable requirement ID(s) that bind
it, the evidence expected to prove it, an owner, and the release stage at which it lands. It operationalizes
the framework summary in [`BLUEPRINT.md`](BLUEPRINT.md) §18 ("SSDLC, Supply Chain and Governance") with
per-control traceability instead of a one-line-per-framework summary.

**Status: PR-0 design artifact (Proposed).** Nothing in this document describes a shipped MCP control —
MCP does not exist in the repository today (VERIFIED: no MCP/JSON-RPC listener in inspected paths). Rows
either (a) bind to a **stable requirement ID** already defined in [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md)
as a normative `MUST`/`MUST NOT`/`SHOULD`/`MAY` obligation for the MCP program, or (b) describe **framework
guidance** the program intends to satisfy but that is not yet bound to a stable ID, or (c) point at an
**already-verified repository control** ([FACT]) that MCP will reuse or must independently implement
because the existing control does not cover MCP's threat surface.

## How to read this document

Every table uses the same six columns:

| Column | Meaning |
|---|---|
| Framework practice/area | The named practice, phase, or category from the external framework. |
| Culvert MCP control (requirement IDs) | The concrete Culvert control and, where one exists, the `MCP-*` requirement ID(s) from [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md) that bind it. |
| Claim type | One of the four labels below — never both a repository fact and an unimplemented claim in the same cell. |
| Evidence expected | What a reviewer/auditor will look at to confirm the control is real (test artifact, CI job, log, doc, signature). |
| Owner | Control/implementation owner, reusing the Owner convention from `SECURITY-REQUIREMENTS.md`. |
| Release stage | The PR slice (PR-0 … PR-11) or the standalone **Prod-Qual** (Production Qualification) gate at which the control becomes enforced, per the implementation sequence in [`BLUEPRINT.md`](BLUEPRINT.md) §23. |

**Claim-type labels** (per-cell, may combine where a row is genuinely both):

- **[Normative project requirement]** — an internal Culvert MUST/SHOULD bound to a stable `MCP-*` ID in `SECURITY-REQUIREMENTS.md`. This is *our* obligation, not the framework's wording.
- **[Framework guidance]** — external best practice the program aligns with, not (yet) bound to a stable Culvert requirement ID. Treated as directional, not gating.
- **[FACT]** — an already-verified, already-shipped repository control (path·symbol·lines), cited only from the VERIFIED EVIDENCE ledger this package is built from. Reused as evidence *for* an MCP control, or cited to show a gap MCP must independently close because the existing control does not cover MCP's surface.
- **[MISSING / Proposed]** — a control this mapping asserts is currently absent and must be built; never claimed as done.

Threat IDs referenced inline are canonical IDs owned by [`THREAT-MODEL.md`](THREAT-MODEL.md) (`MCP-T-###`) —
this document does not renumber them. Test-level traceability (threat → control → test → evidence) lives in
[`TEST-TRACEABILITY-MATRIX.md`](TEST-TRACEABILITY-MATRIX.md); CI wiring and gate mechanics live in
[`CI-GATES.md`](CI-GATES.md); dependency/build/signing chain detail lives in
[`SUPPLY-CHAIN-SECURITY.md`](SUPPLY-CHAIN-SECURITY.md). This document is the cross-framework index over all
three — it does not restate their full detail.

**Capability tag.** Where a control applies to only one capability, the "Culvert MCP control" cell is
prefixed `(Mgmt)` for Capability A (Management MCP) or `(GW)` for Capability B (Security Gateway). Unmarked
rows apply to both under the shared-Control-Plane-services doctrine (shared: admin UI shell/auth, RBAC
framework, config publication, audit conventions, OpenAPI/CI/release; separate: listeners, scopes, policy
schemas, decision namespaces, threat models, runbooks — see `BLUEPRINT.md` §03).

---

## 1. NIST SSDF (SP 800-218)

| SSDF practice group / practice | Culvert MCP control (requirement IDs) | Claim type | Evidence expected | Owner | Release stage |
|---|---|---|---|---|---|
| **PO.1** Define security requirements for software | Stable, versioned requirement registry `MCP-AUTH-001..MCP-OPS-004` in `SECURITY-REQUIREMENTS.md`, each with rationale, threat IDs, owner, verification, evidence, gate | [Normative project requirement] | `SECURITY-REQUIREMENTS.md` itself + traceability rows in `TEST-TRACEABILITY-MATRIX.md` | Sec / Eng | PR-0 (registry shipped); enforcement lands per-row PR-2…PR-11 |
| **PO.3** Implement supporting toolchains | Required merge gates `pr-fast-gate.yml` (Fast PR Gate) + `pr-deep-gate.yml` (Deep PR Gate); `ci.yml` main/tag pipeline | [FACT] (existing SWG toolchain) — MCP-scoped extension is [MISSING / Proposed] | CI run logs for both gate checks on the first MCP PR | Release | PR-1 (MCP code first enters the toolchain) |
| **PO.5** Implement secure environments for software development | Actions pinned to immutable commit SHAs (repo-wide) | [FACT] ("Actions SHA-pinned") | Workflow diff review (no floating tags) | Release | PR-1 (MCP workflows inherit this) |
| **PS.1** Protect all forms of code from unauthorized access and tampering | `gitleaks` secret scan runs on every PR including docs-only | [FACT] (pr-fast-gate.yml) | gitleaks job log | Sec / Release | PR-0 (already covers this doc) |
| **PS.2 / PS.3** Provide and archive a mechanism for verifying release integrity | cosign keyless signing + SLSA L3 verifiable provenance + syft SBOM, generated on the tag path (`ci.yml`) — `MCP-SUPPLY-003` | [FACT] (mechanism exists for the SWG binary today) + [Normative project requirement] (MCP artifacts must be covered the same way once MCP ships) | Signature/provenance verification transcript for an MCP-inclusive release build | Release | Prod-Qual |
| **PW.1** Design software to meet security requirements | `THREAT-MODEL.md` STRIDE-per-component + attack tree; `MCP-POLICY-001` default-deny, `MCP-POLICY-002` no-I/O-during-eval | [Normative project requirement] — note the existing SWG policy engine does network+disk I/O during evaluation (`policy.go` `Evaluate`, DNS resolution path) and is [FACT] **explicitly not reused** for MCP policy evaluation | Design review sign-off on `THREAT-MODEL.md` + a pure-function determinism test for the MCP policy engine | Sec / Eng | PR-6 |
| **PW.4** Reuse existing, well-secured software | SSRF guard (`internal/ssrf`), secret/DLP seams (`internal/secret`, `internal/redaction`, `internal/sealbox`, `internal/backupcrypt`) reused for `MCP-INSP-004`, `MCP-CRED-004/005` | [FACT] (seams exist and are production-hardened) + [Normative project requirement] (binding them into MCP) | Code review confirming MCP calls the shared seam rather than re-implementing SSRF/redaction | Sec / Eng | PR-4 (credential broker), PR-7 (inspection) |
| **PW.5** Configure software to have secure settings by default | `(Mgmt)` Management MCP defaults read-only, no mutation tool until plan→validate→approve→apply exists — `MCP-MGMT-001`; `(GW)` Gateway defaults deny-on-no-match — `MCP-POLICY-001` | [Normative project requirement] — precedent-only [FACT]: SWG default-deny (`policy.go:1142`, `proxy.go:543-556`) is architectural precedent, not the MCP implementation | Mutation-negative test suite (Mgmt) + default-deny unit tests (Gateway) | Sec / Eng | PR-6 (Gateway), PR-9 (Mgmt) |
| **PW.7** Review human-readable code | Diff-scoped `golangci-lint`, `gosec`, `staticcheck` on every PR touching MCP packages | [FACT] (existing repo-wide gate) | Lint/SAST job logs on the MCP PR | Sec / Eng | PR-1 |
| **PW.8** Test executable code | `-race` run owning the 55% global + per-file coverage floors (pr-fast-gate); `fuzz-nightly.yml` coverage-guided fuzzing (not a merge gate) | [FACT] (mechanism exists) — malicious-MCP-server test corpus is [MISSING / Proposed] | Coverage report + first malicious-server fixture set | Sec / Eng | PR-2 (malicious-server tests target `MCP-SERVER-001..003`) |
| **PW.9** Configure software to have a minimized attack surface | `MCP-OPS-002` bounded connections/SSE/payload/queue/concurrency with per-entity rate limits; `MCP-CONNECT-001` no unsolicited inbound port | [Normative project requirement] | Load/soak/slowloris/queue-saturation test evidence | SRE / Eng | PR-5 (bounds), PR-11 (connector) |
| **RV.1** Identify and confirm vulnerabilities | `govulncheck` + `gosec` on every PR | [FACT] (repo-wide gate) | Scan job logs | Sec / Release | PR-1 |
| **RV.2 / RV.3** Assess, prioritize, remediate, and analyze root cause | `MCP-SUPPLY-004` — vulnerability-remediation SLA, emergency revoke, customer-notification procedure | [Normative project requirement]; root-cause/postmortem process itself is [Framework guidance] — no repo-verified incident process exists today (NOT VERIFIED) | Documented SLA + at least one revoke drill | Sec / Release | Prod-Qual |

## 2. Microsoft SDL

| SDL phase | Culvert MCP control (requirement IDs) | Claim type | Evidence expected | Owner | Release stage |
|---|---|---|---|---|---|
| Training | Secure-development training for engineers touching the MCP trust boundary | [Framework guidance] — NOT VERIFIED as an existing repository/program artifact | Training log / completion record | Sec / Eng mgmt | Prod-Qual |
| Requirements | `SECURITY-REQUIREMENTS.md` — `MCP-AUTH-001..MCP-OPS-004`, each with MUST/MUST NOT wording, rationale, and gate | [Normative project requirement] | The requirements registry itself | Sec / Eng | PR-0 |
| Design | `THREAT-MODEL.md` (STRIDE, attack tree, residual risk) + `ADR-PROPOSAL-mcp-trust-boundary.md` (trust-boundary decision, Status: Proposed) | [Normative project requirement] | Design review sign-off; ADR promotion to a numbered Accepted `docs/adr/NNNN` is the hard PR-1 entry gate | Sec / Eng / Architecture | PR-0 (artifact), PR-1 (ADR must be Accepted before PR-1 lands) |
| Implementation (secure defaults / banned patterns) | No client-token passthrough upstream — `MCP-AUTH-005`; default-deny — `MCP-POLICY-001`; no secrets in logs/events — `MCP-CRED-004`, `MCP-EVENT-003` | [Normative project requirement]. Precedent-only [FACT]: SWG header scrub (`proxy.go` `scrubForwardedHeaders`, `proxy_tunnel.go` `removeHopHeaders` deleting `Proxy-Authorization`) shows the *pattern* exists elsewhere in the codebase; it is not an MCP implementation | Upstream-capture test proving no client token reaches the enterprise system; secret-scan of decision-event payloads | Sec / Eng | PR-3 (auth), PR-4 (credential), PR-6 (policy), PR-8 (events) |
| Verification | `gosec`, `govulncheck`, `gitleaks`, `staticcheck` (repo-wide, all PRs); `codeql.yml` (PR path-scoped) | [FACT] for the mechanism — **[MISSING / Proposed]**: CodeQL is PR path-scoped to the proxy/security/release surface today and MCP paths are **not yet wired into that path filter**; malicious-MCP-server tests, OAuth-negative matrix, DNS-rebinding lab, SSE-exhaustion tests are also [MISSING / Proposed] | CodeQL workflow diff adding MCP path globs; first green run of each missing test class | Sec / Eng | PR-1 (CodeQL path extension), PR-2/3/7/5 (respective test classes — see §7 Gap Register) |
| Release | Production Qualification gate — a release security checklist + production-readiness review distinct from PR-0..PR-11 | [Normative project requirement] (sequencing decision) + [Framework guidance] (checklist content) | Signed-off Production Qualification checklist | Product / Sec / Eng | Prod-Qual |
| Response | `MCP-SUPPLY-004` — severity-based SLA, emergency revoke, customer communication | [Normative project requirement] | Runbook + drill evidence | Sec / Release | Prod-Qual |

## 3. OWASP SAMM

| SAMM business function | Representative practices | Culvert MCP control (requirement IDs) | Claim type | Evidence expected | Owner | Release stage |
|---|---|---|---|---|---|---|
| Governance | Strategy & Metrics, Policy & Compliance, Education & Guidance | Stable requirement/threat ID registries (`SECURITY-REQUIREMENTS.md`, `THREAT-MODEL.md`); ADR practice for trust-boundary changes (`docs/adr/NNNN-title.md`, 6 mandatory sections) | [Normative project requirement] for the ID registries; [FACT] for the ADR practice (repo-wide convention, applies to MCP as a "cluster-HA"/cross-cutting-invariant-class change); training/education is [Framework guidance], NOT VERIFIED | ADR promotion record; registry completeness check | Sec / Eng / Architecture | PR-0 |
| Design | Threat Assessment, Security Requirements, Security Architecture | `THREAT-MODEL.md` attack tree ("Unauthorized Production Change"); `BLUEPRINT.md` §09 trust boundaries; two-capability separation doctrine | [Normative project requirement] | Design review; trust-boundary diagram review | Sec / Eng / Architecture | PR-0 |
| Implementation | Secure Build, Secure Deployment, Defect Management | SHA-pinned Actions, least-privilege tokens, protected environments (repo-wide) | [FACT] for the existing toolchain; MCP-specific defect triage against `MCP-SUPPLY-004` is [Normative project requirement] | Build config review; defect-tracking record for MCP findings | Release / Sec | PR-1 |
| Verification | Architecture Assessment, Requirements-Driven Testing, Security Testing | Admin UI parity-test pyramid (D0/C1/C1.5/C2/C2c/C4 — route/metadata/RBAC parity) is the **precedent pattern** the MCP admin surface (`(Mgmt)` API + GUI) is expected to reuse | [FACT] (pyramid exists and is enforced today for the admin API) — an MCP-equivalent pyramid is [MISSING / Proposed] | New parity-test suite scoped to MCP admin/API routes, mirroring the existing D0–C4 layers | Sec / Eng | PR-9 |
| Operations | Incident Management, Environment Management, Operational Management | `MCP-OPS-001..004` — MCP-off overhead ≈ zero, bounded resources, dashboards/alerts/runbooks | [Normative project requirement] | Runbook set cross-linked from `OPERATIONS-AND-SUPPORT.md`; MCP-off benchmark result | SRE / Eng | PR-5 (bounds/overhead), Prod-Qual (runbooks) |

## 4. BSIMM

| BSIMM domain | Representative practices | Culvert MCP control (requirement IDs) | Claim type | Evidence expected | Owner | Release stage |
|---|---|---|---|---|---|---|
| Governance | Strategy & Metrics, Compliance & Policy, Training | Same registry/ADR artifacts as SAMM Governance above | [Normative project requirement] + [FACT] (ADR practice) | See SAMM Governance row | Sec / Eng | PR-0 |
| Intelligence | Attack Models, Security Features & Design, Standards & Requirements | `THREAT-MODEL.md` canonical threat IDs (`MCP-T-001..056`); nine-action policy model (`MCP-POLICY-MODEL.md` Appendix); reason-code taxonomy (`MCP.AUTH`, `MCP.SERVER`, `MCP.TOOL`, `MCP.POLICY`, `MCP.CREDENTIAL`, `MCP.INSPECTION`, `MCP.RATE`, `MCP.SYSTEM`, `MCP.MANAGEMENT`) | [Normative project requirement] | Threat-model and policy-model review | Sec / Eng | PR-0 (models), PR-6 (policy engine implements the nine actions) |
| SSDL Touchpoints | Architecture Analysis, Code Review, Security Testing | Diff-scoped lint/SAST (repo-wide); admin-UI parity-test pyramid (precedent) | [FACT] for both existing mechanisms — MCP-scoped security testing (malicious-server, OAuth-negative, DNS-rebinding, SSE-exhaustion) is [MISSING / Proposed] | Test suite additions per Gap Register (§7) | Sec / Eng | PR-2/3/7/5 |
| Deployment | Penetration Testing, Software Environment, Configuration Management & Vulnerability Management | `trivy` container scan + `hadolint` (pr-deep-gate, diff-gated); cosign keyless + SLSA L3 provenance + syft SBOM (tag path); config-surface registry (`config_surfaces.go`) pattern for CP↔DP field parity | [FACT] for all four mechanisms as they exist for the SWG today; extension to MCP's CP→DP snapshot fields (`MCP-CPDP-001..003`) is [Normative project requirement] — the current `ConfigSnapshot` lacks `catalog_revision`/`credential_revision`/`minimum_dp_version`/`content_hash`/signature | Config-surface parity test extended to MCP fields; MCP penetration-test report | SRE / Eng | PR-10 |

## 5. OWASP ASVS (Application Security Verification Standard)

| ASVS chapter | Culvert MCP control (requirement IDs) | Claim type | Evidence expected | Owner | Release stage |
|---|---|---|---|---|---|
| V1 Architecture, Design and Threat Modeling | `THREAT-MODEL.md` + `ADR-PROPOSAL-mcp-trust-boundary.md` | [Normative project requirement] | Design/ADR review | Sec / Architecture | PR-0 |
| V2 Authentication | `MCP-AUTH-001` (no query-string tokens), `MCP-AUTH-002` (audience validation), `MCP-AUTH-003` (RFC 8707 resource indicator), `MCP-AUTH-004` (short-TTL/expiry), `MCP-AUTH-006` (replay protection), `MCP-AUTH-008` (separate OAuth clients per capability) | [Normative project requirement] — [FACT] gap basis: today's OIDC binds audience to `client_id` only (`auth_oidc_flow.go:523`), has no RFC 8707 resource indicator (grep 0), and the bearer-access-token path (RFC 7662 introspection, `auth_oidc.go:166-265`) has **no replay defense** and no DPoP/`cnf` sender-constraint (grep 0) | Negative auth matrix: missing/invalid/query-string/wrong-audience/wrong-resource/replayed-token rejections | Sec / Eng | PR-3 |
| V3 Session Management | `MCP-AUTH-007` cross-user session confusion prevention | [Normative project requirement]; precedent-only [FACT]: existing admin-UI session is an HttpOnly signed cookie (`internal/session/session.go:345-363`), a **different surface** than an MCP bearer token — not directly reusable | Cross-session isolation tests under concurrent load | Sec / Eng | PR-3 |
| V4 Access Control | `(Mgmt)` `MCP-MGMT-002` tenant-scoped, tool-level RBAC; `(GW)` `MCP-ID-005/007` deny-on-ambiguous-identity, tenant binding | [Normative project requirement]; precedent [FACT]: three-role RBAC (`RoleAdmin`/`Operator`/`Viewer`, `store.go:317-336`) and `requireRole` (`ui_rbac.go:46-53`) is the pattern Management MCP tool-level RBAC is expected to extend — it does not itself constitute per-tool/per-tenant enforcement | Tool-level RBAC negative tests; tenant-escape tests | IAM / Eng | PR-3 (identity), PR-9 (Mgmt RBAC) |
| V5 Validation, Sanitization and Encoding | `(GW)` `MCP-INSP-001` input schema/size/depth/field-count bounds, `MCP-INSP-002` output size/type/schema bounds with truncation policy | [Normative project requirement] | Fuzz + limit tests; output-truncation tests | Sec / Eng | PR-7 |
| V8 Data Protection | `MCP-CRED-004` no secrets in logs/metrics/traces/events, `MCP-CRED-005` bounded+encrypted credential cache, `MCP-EVENT-003` no raw tokens/secrets/complete raw args/outputs by default | [Normative project requirement]; [FACT] prior-art seams to reuse: `internal/secret` (KEK containment), `internal/redaction` (fail-closed DataClass), `internal/sealbox` (NaCl sealed box), `internal/backupcrypt` (AES-256-GCM envelope) | gitleaks pass on event payloads; redaction unit tests against a synthetic-secret corpus | IAM/PAM / Sec | PR-4 (credential), PR-8 (events) |
| V9 Communications | `(GW)` `MCP-SERVER-002` server TLS/workload identity verified and pinned to the registry entry; `MCP-CONNECT-001` mTLS connector identity | [Normative project requirement] | TLS-identity mismatch tests; connector mTLS verification tests | Sec / Eng | PR-2 (server registry), PR-11 (connector) |
| V10 Malicious Code / Server-Side Request Forgery | `(GW)` `MCP-INSP-004` outbound destination checks, `MCP-INSP-005` DNS-pinning (rebinding TOCTOU), `MCP-INSP-006` redirect hop-limit and re-check | [Normative project requirement]; [FACT] prior art: `internal/ssrf` `PrivateIP` (RFC1918+CGN+link-local+metadata+NAT64+ULA), `PrivateHost` fail-closed, dialer `Control` peer-IP recheck — but redirect guards today are **re-implemented per client with no shared helper** (`internal/supportupload/upload.go`, `internal/blocklistfeed`, `release_catalog_http.go`), a gap `MCP-INSP-006` explicitly calls out for consolidation | Private-IP matrix; DNS-rebinding lab; redirect-chain tests | Sec / Eng | PR-7 |
| V13 API and Web Service | OpenAPI-governed admin API surface for `(Mgmt)` and the Gateway's own API/GUI surface | [FACT] for the existing mechanism (`api/openapi/openapi.yaml`, ADR-0018, `api-contract.yml` + `pr-api-governance.yml` MERGE-BLOCKING breaking-change/client-gen checks, `route-classification.yaml`) — MCP route additions to this contract are [Normative project requirement] | OpenAPI diff + contract-governance CI pass on the first MCP admin-route PR | Eng / Release | PR-9 |
| V14 Configuration | `(GW)` `MCP-CPDP-001..003` signed/versioned CP→DP snapshot with `minimum_dp_version` gating | [Normative project requirement]; [FACT] prior art: `config_surfaces.go` field-membership registry parity-enforced by `config_surfaces_test.go`, and the repo-wide GUI-parity mandate (every CLI flag/config option needs an admin API + UI panel) — today's `ConfigSnapshot` (`controlplane_snapshot.go:22-112`) has `Version`/`Epoch`/`PolicyVersion` but **no** `catalog_revision`/`credential_revision`/`minimum_dp_version`/`content_hash`/signature | Snapshot-schema tests; corrupt/partial-snapshot whole-reject tests | Eng / SRE | PR-10 |

## 6. OWASP API Security Top 10 (2023)

| API Security risk | Culvert MCP control (requirement IDs) | Claim type | Evidence expected | Owner | Release stage |
|---|---|---|---|---|---|
| API1: Broken Object Level Authorization | `MCP-ID-007` tenant binding/enforcement per call, `MCP-CRED-002` scope-mismatch rejection | [Normative project requirement] | Cross-tenant/scope-mismatch negative tests | IAM/PAM / Eng | PR-3 (tenant), PR-4 (credential scope) |
| API2: Broken Authentication | `MCP-AUTH-001..006` (see ASVS V2 row above) | [Normative project requirement] | Negative auth matrix | Sec / Eng | PR-3 |
| API3: Broken Object Property Level Authorization | `MCP-INSP-002` output size/type/schema bounds + truncation; `MCP-EVENT-003` redaction-by-default | [Normative project requirement] | Output-limit and redaction tests | Sec / Eng | PR-7 (inspection), PR-8 (events) |
| API4: Unrestricted Resource Consumption | `MCP-OPS-002` bounded connections/SSE streams/payloads/queues/concurrency/event buffers with per-entity rate limits; `MCP-INSP-001` input bounds | [Normative project requirement]; [FACT] precedent only: repo-wide sharded rate limiter and pooled relay buffers exist for the SWG data path, not for MCP | Load/soak/slowloris/queue-saturation tests; SSE-exhaustion tests | SRE / Eng | PR-5 (bounds), PR-7 (input) |
| API5: Broken Function Level Authorization | `(Mgmt)` `MCP-MGMT-002` tool-level RBAC | [Normative project requirement]; [FACT] precedent: `requireRole`/three-role RBAC pattern (see ASVS V4) | Tool-level RBAC negative tests | Sec / Eng | PR-9 |
| API6: Unrestricted Access to Sensitive Business Flows | `(GW)` `MCP-POLICY-006` destructive tools require `REQUIRE_APPROVAL` or `DENY` by default; `(Mgmt)` `MCP-MGMT-001` read-only default, no mutation until plan→validate→approve→apply exists | [Normative project requirement] | Destructive-tool approval/deny tests; mutation-negative tests | Sec / Eng | PR-6 (Gateway), PR-9 (Mgmt) |
| API7: Server-Side Request Forgery | `MCP-INSP-004/005/006` (see ASVS V10 row above) | [Normative project requirement]; [FACT] gap: no shared redirect-guard helper across the repo today | Private-IP matrix; DNS-rebinding lab; redirect-chain tests; **[MISSING / Proposed]** dedicated DNS-rebinding lab as a CI artifact | Sec / Eng | PR-7 |
| API8: Security Misconfiguration | `MCP-SERVER-001` allowlist-only reachability, `MCP-SERVER-003` auto-disable on server-identity change, `MCP-CPDP-002` whole-reject on corrupt/partial snapshot | [Normative project requirement] | Allowlist-bypass tests; identity-change auto-disable tests; corrupt-snapshot whole-reject tests | Sec / Eng | PR-2 (server registry), PR-10 (CP/DP) |
| API9: Improper Inventory Management | `MCP-TOOL-001` mandatory tool fingerprinting (server ID + name + canonicalized input/output/description hashes + credential profile + destination class), `MCP-TOOL-002` shadowing detection, `MCP-TOOL-003` drift classification | [Normative project requirement] | Canonicalization determinism tests; shadowing-collision tests; drift-classification fixture tests | Sec / Eng | PR-2 |
| API10: Unsafe Consumption of APIs | `MCP-SERVER-002` TLS/workload identity pinned to registry entry; `MCP-TOOL-004` quarantine (never auto-allow) on privilege expansion / rug-pull | [Normative project requirement] | TLS-identity mismatch tests; expansion/rug-pull quarantine tests | Sec / Eng | PR-2 (server), PR-6 (quarantine enforcement) |

## 7. SLSA (Supply-chain Levels for Software Artifacts)

| SLSA requirement track | Culvert MCP control (requirement IDs) | Claim type | Evidence expected | Owner | Release stage |
|---|---|---|---|---|---|
| Source (version control, retained history, two-person review) | Required merge gates on every PR (`✅ Fast PR Gate — APPROVED`, `✅ Deep PR Gate — APPROVED`) | [FACT] (existing repo-wide branch-protection posture) — formal SLSA source-track self-attestation for MCP paths specifically is [Framework guidance], NOT VERIFIED as a distinct claim | Branch-protection config review | Release | PR-1 |
| Build (scripted build, build service, ephemeral/isolated environment) | `ci.yml` build + multi-arch docker publish, run on GitHub-hosted Actions runners | [FACT] | CI job logs for an MCP-inclusive build | Release | PR-1 |
| Provenance (available, authenticated, service-generated, non-falsifiable) | cosign keyless signing + **SLSA L3 verifiable provenance** + syft SBOM, generated on the tag path (`ci.yml`) — `MCP-SUPPLY-003` | [FACT] for the mechanism as it exists today for the proxy binary; extending it to cover MCP-inclusive artifacts is [Normative project requirement] | Provenance verification transcript naming the MCP-inclusive artifact digest | Release | Prod-Qual |
| Common requirements (security, access control of the build platform) | Actions pinned to immutable commit SHAs; least-privilege tokens — `MCP-SUPPLY-002` | [FACT] for SHA-pinning; least-privilege token scoping is [Normative project requirement] pending explicit review of MCP-specific workflow permissions | Workflow `permissions:` block review | Release | PR-1 |
| Dependency / SCA hygiene | Pinned, minimal dependencies; new runtime deps avoided (single-binary, zero-runtime-dep posture) — `MCP-SUPPLY-001` | [Normative project requirement]; [FACT] gap: **no** `dependency-review-action`, **no** mechanical no-new-deps gate exists repo-wide today (only an advisory "Dependency Obituary" check) | `go.mod` diff review + `go-licenses` pass on the first MCP dependency addition, if any | Sec / Release | PR-1 |
| Consumer verification before deploy | "Consumers MUST verify SBOM+provenance before deploy" — `MCP-SUPPLY-003`; vulnerability-remediation SLA + emergency revoke — `MCP-SUPPLY-004` | [Normative project requirement] | Documented deploy-time verification step in the operator runbook; at least one emergency-revoke drill | Sec / Release | Prod-Qual |

---

## 8. Gap Register (MCP-specific — MISSING / Proposed)

These are named explicitly in the VERIFIED EVIDENCE ledger as absent from the current CI surface. None are
claimed as done anywhere in this document; each is carried forward here as the authoritative cross-framework
gap list, with the requirement IDs and release stage that will close it.

| Gap | Frameworks it affects | Closes requirement(s) | Target stage |
|---|---|---|---|
| Malicious-MCP-server test corpus | SSDF PW.8, BSIMM SSDL Touchpoints, API Security API8/API10 | `MCP-SERVER-001..003` | PR-2 |
| OAuth audience/resource/replay negative matrix | SSDF PW.8, SDL Verification, ASVS V2, API Security API2 | `MCP-AUTH-001..006` | PR-3 |
| DNS-rebinding lab (outbound) + inbound Origin/Host anti-rebinding tests | ASVS V10, API Security API7, SDL Verification | `MCP-INSP-005`, `MCP-INSP-008` | PR-7 (outbound), PR-1 (inbound listener) |
| SSE-exhaustion / resource-exhaustion tests | SSDF PW.9, API Security API4 | `MCP-OPS-002` | PR-5 |
| Mixed-version / stale-epoch / corrupt-snapshot MCP gates | BSIMM Deployment, ASVS V14, API Security API8 | `MCP-CPDP-001..003`, `MCP-HA-001..002` | PR-10 |
| MCP-off overhead regression benchmark | SSDF PW.9, SAMM Operations | `MCP-OPS-001` | PR-5 |
| CodeQL path-scope extension to MCP packages | SDL Verification, BSIMM SSDL Touchpoints | — (CI configuration, not a stable requirement ID) | PR-1 |

**Risk phrasing for the current state of this register**: Low for the read-only Phase 1 investigation, but
the current repository test baseline remains unverified in this session.

---

## Cross-references

- [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md) — canonical `MCP-*` requirement-ID registry this document maps against.
- [`THREAT-MODEL.md`](THREAT-MODEL.md) — canonical `MCP-T-###` threat-ID registry and STRIDE/attack-tree detail.
- [`TEST-TRACEABILITY-MATRIX.md`](TEST-TRACEABILITY-MATRIX.md) — threat → control → test → evidence detail underlying the "Evidence expected" columns above.
- [`CI-GATES.md`](CI-GATES.md) — mechanics of the CI gates cited as [FACT] throughout this document.
- [`SUPPLY-CHAIN-SECURITY.md`](SUPPLY-CHAIN-SECURITY.md) — dependency, build, signing, and SBOM/provenance chain detail underlying the SLSA and NIST SSDF PS/RV rows.
- [`BLUEPRINT.md`](BLUEPRINT.md) §18 — the one-line-per-framework summary this document expands into per-control rows; §23 — the PR-0…PR-11 + Prod-Qual implementation sequence used for the "Release stage" column.
- [`ADR-PROPOSAL-mcp-trust-boundary.md`](ADR-PROPOSAL-mcp-trust-boundary.md) — the Proposed ADR gating PR-1 (Option B: promoted to a numbered Accepted ADR by a human before PR-1 proceeds).
