# MCP CI Gates

Status: PR-0 design artifact (Proposed)

> **Decision provenance (2026-07-24, [`docs/adr/0023`](../../adr/0023-mcp-agent-security-gateway-trust-boundary.md)).**
> The Proposed gates are now decision-backed: the **OAuth/replay negative matrix (PR-3)** enforces the
> reframed D-2 posture (sender-constraint / DPoP-proof replay, not access-token one-time-use); the
> **event-durability-under-saturation gate (PR-8)** enforces the D-5 per-action fail-closed matrix; the
> **inbound Origin/Host + SSRF/rebinding gate (PR-1/PR-7)** enforces D-9 (host-allowlist + Origin-per-
> protocol on every listener). Connector CI (D-8) is a **post-V1** slice gate; Management-vs-Gateway
> separation (D-13) is carried by the Existing `api-contract`/`pr-api-governance` gates plus the PR-9
> mutation-negative tests. No CI file is modified in PR-0.

This document inventories every CI/CD gate relevant to the two MCP capabilities — the **Culvert
Management MCP Server** (Capability A) and the **MCP Security Gateway** (Capability B) — and classifies
each one as `Existing`, `Existing-but-insufficient`, `Proposed`, `Blocking`, or `Advisory`. Its purpose is
to let reviewers see, in one place, which controls the existing pipeline already enforces for any MCP
code that lands, which existing gates apply but don't yet cover MCP-specific attack surface, and which
gates do not exist yet and must be proposed as **hard, blocking entry conditions** for the PRs that
introduce that surface (per [`IMPLEMENTATION-SLICES.md`](IMPLEMENTATION-SLICES.md)).

No CI file is created or modified by this document or by PR-0. See the note at the bottom of this file
and [`README.md`](README.md) for the scope boundary.

## Required-merge-gate fact

**[FACT]** Per branch protection, only two checks are required-to-merge on any PR in this repository:
`✅ Fast PR Gate — APPROVED` (`pr-fast-gate.yml`) and `✅ Deep PR Gate — APPROVED` (`pr-deep-gate.yml`,
required-if-triggered by the diff classifier). Every other workflow listed below — `qa-gate.yml`,
`security-release-gate.yml`, `codeql.yml`, `code-review.yml`, nightly/weekly workflows, and the tag-path
release workflow (`ci.yml`) — is either a pass-through shell on PRs, advisory, or scoped to the main/tag
path, and is **not** a branch-protection-required PR check today. Any MCP-specific gate proposed below
that is meant to block an MCP PR must be wired into `pr-fast-gate.yml` or `pr-deep-gate.yml` (or added as
a new required check in branch protection) to actually block a merge — being merely present in
`ci.yml`/`qa-gate.yml`/`security-release-gate.yml` does not block a PR.

## Fast pull-request gates — Existing, Blocking

**[FACT]** `pr-fast-gate.yml` runs on every PR and is one of the two required merge checks. It already
applies to any Go code added under `internal/mcp/**` or any new root-package MCP file, with no MCP-aware
carve-out:

| Gate | What it enforces | Applies to MCP code today? |
|---|---|---|
| fmt / vet / build (+arm64 compile, static assert, tidy check) | Compiles, formats, vets cleanly | Yes — mechanical, no MCP awareness needed |
| Diff-scoped golangci-lint | Lint on changed lines | Yes — mechanical |
| `-race` full run (single run owning both coverage contracts) | Data races; 55% global + per-file coverage floors | Yes — a new `internal/mcp/*` package must clear the per-file floor like every other package |
| benchgate | Regression-gates pinned benchmarks | Yes for any benchmark MCP code adds to the pinned set; does **not** by itself create an MCP-off overhead benchmark (see MCP-OPS-001 below) |
| govulncheck + gosec | Known-vuln / static-security scan of Go deps and code | Yes — mechanical, language-level; has no MCP-protocol-specific rules |
| gitleaks | Secret-pattern scan, even docs-only PRs | Yes — would catch a literal secret checked into MCP code or docs, but is a pattern scanner, not the MCP-specific "no raw secrets in decision events" runtime property (MCP-CRED-004/MCP-EVENT-003) |
| path-gated maint-agent checks | Maintenance-agent-specific checks | N/A to MCP unless MCP code touches that surface |
| advisory traffic smoke | Basic smoke test | Generic, not MCP-aware |

**Classification: Existing, Blocking.** These gates are real today and will fire on any MCP PR without
further action — but they are **generic Go-quality/dependency-hygiene gates**, not MCP-protocol or
MCP-threat-model gates. They enforce "this code compiles, is reasonably safe Go, and meets coverage" —
not "this code resists a malicious MCP server" or "this code enforces audience binding correctly." See
Existing-but-insufficient note below.

## Deep gates — Existing, Blocking-if-triggered

**[FACT]** `pr-deep-gate.yml` is diff-classified (only runs the sub-jobs relevant to what changed) but is
the second required merge check whenever triggered:

| Gate | What it enforces | Trigger condition |
|---|---|---|
| build-image-once → trivy scan | Container image vulnerability scan | Docker/image-relevant diff |
| compose validation | `docker-compose.yml` well-formedness | Compose file diff |
| hadolint | Dockerfile lint | Dockerfile diff |
| staticcheck | Deeper Go static analysis than golangci-lint | Go diff |
| determinism | Repeated-build byte-identical check | Any `*_test.go` change |
| go-licenses | Dependency license compliance | Dependency (go.mod/go.sum) diff |
| packaging (shellcheck/visudo/systemd) | Install/packaging surface | Packaging file diff |

**Classification: Existing, Blocking-if-triggered.** These fire on the *kind* of change, not on
MCP-specific content — a Dockerfile change in an MCP PR gets `hadolint`+`trivy` exactly as any other
Dockerfile change would, with no MCP-aware policy layered on top.

## Release gates — Existing, tag path only

**[FACT]** `ci.yml` (main/tag path) performs, on the **tag** path: cosign keyless signing, SLSA L3
verifiable provenance, syft SBOM generation, and the catalog gate (auto-tag waits for both PR gate
approvals on the SHA before tagging; see `CLAUDE.md` Release catalog sections for the full P2b/P2b-2b
keyless-signing chain). **Classification: Existing, tag-path only — not a PR-merge gate.** These protect
the supply chain of the *shipped binary/image*, not the correctness of an MCP PR's diff. They are
unmodified by, and orthogonal to, any MCP work; MCP code inherits them automatically once it ships in a
tagged release, with no MCP-specific SBOM/provenance content (e.g., no MCP-tool-catalog provenance).

## Advisory / scheduled — Existing but NOT merge gates

**[FACT]**

| Gate | Scope today | Classification |
|---|---|---|
| `codeql.yml` | Main pushes, weekly, and **PRs touching the proxy/security/release surface** — path-scoped | **Existing-but-insufficient.** `internal/mcp/**` paths are **NOT VERIFIED** as wired into CodeQL's PR path filter today. Wiring them in is a CI-config change and belongs to PR-1+, not PR-0 (see note at bottom). |
| `fuzz-nightly.yml` | Mon/Wed/Fri coverage-guided fuzzing | Advisory / nightly only — never blocks a PR |
| Dependency Obituary | Advisory dependency-health signal | Advisory — not a merge gate, not a hard no-new-deps check |
| `proxy-nightly-e2e.yml`, `proxy-weekly-stress.yml`, `proxy-ui-e2e.yml` (playwright), `auth-idp-interop.yml` | Nightly/weekly load, stress, UI e2e, auth-interop | Advisory / scheduled only — never blocks a PR |
| `install-lifecycle-e2e.yml` + `maint-agent-*-e2e.yml` | Nightly + installer-surface PRs | Advisory/path-gated — not a general MCP gate |
| `qa-gate.yml` / `security-release-gate.yml` | Full functional QA / 10-check security scan on main pushes, tags (security), weekly cron (security) | Pass-through shell on PRs (does not block PR merge); real content runs post-merge |
| `code-review.yml` | Reviewdog inline lint, PR-size, conventional commits | Advisory PR DX — never blocks |
| `api-contract.yml` + `pr-api-governance.yml` | Breaking-change + client-gen check on `api/openapi/openapi.yaml` changes | **Existing, Blocking for API changes** — any MCP Management API surface (Capability A) that extends `api/openapi/openapi.yaml` is already gated by these two checks per ADR-0007 |

## Production-readiness gates — Proposed

The following do not exist as CI gates anywhere in the repository today and are **Proposed** as the
evidence pack a human reviews at the Production Qualification milestone (after PR-11 Shadow & canary, per
[`IMPLEMENTATION-SLICES.md`](IMPLEMENTATION-SLICES.md)), not as automated PR checks:

- Full `SECURITY-REQUIREMENTS.md` verification-column evidence collected and reviewed.
- Full `TEST-TRACEABILITY-MATRIX.md` threat→requirement→control→test→evidence chain closed with no gaps.
- `GO-NO-GO-CHECKLIST.md` blocking conditions cleared.
- Shadow/canary metrics reviewed per `ROLLOUT-AND-ROLLBACK.md`.
- SSDLC control mapping (`SSDLC-CONTROL-MAPPING.md`) and supply-chain posture
  (`SUPPLY-CHAIN-SECURITY.md`) reviewed as a pack, not as a single automated check.

**Classification: Proposed, not Blocking-in-CI** — this is a human sign-off gate assembled from evidence
that other (existing or proposed) automated gates produce; it is not itself a new CI job.

## MCP-specific gates that are MISSING today — Proposed, Blocking for their PRs

**[FACT]** None of the following exist in any workflow file today (per the brief's VERIFIED EVIDENCE CI
section: "MISSING for MCP: malicious-MCP-server tests, OAuth-negative matrix, DNS-rebinding lab, inbound
Origin/Host tests, SSE-exhaustion, mixed-version/stale-epoch/corrupt-snapshot MCP gates, MCP-off overhead
regression"). Each row below is **Proposed** and should be **Blocking** for the PR that introduces the
surface it covers — i.e. these are hard entry gates for PR-1 through PR-10, not optional follow-ups.

| Proposed gate | Enforces requirement(s) | Threat ID(s) | Target PR |
|---|---|---|---|
| Malicious-MCP-server test suite (fixture servers with poisoned tools, rug-pull updates, schema/description drift, unknown-tool responses) | MCP-TOOL-001..006 | MCP-T-011..017 | PR-2 |
| OAuth/audience/replay negative matrix (MCP-AUTH-*): wrong audience, wrong resource, token passthrough, expired/forged token, **replayed DPoP proof** + sender-constraint enforcement + rate-limit/anomaly on token abuse (**not** access-token one-time-use — [`ADR-0023 §D-2`](../../adr/0023-mcp-agent-security-gateway-trust-boundary.md)) | MCP-AUTH-001..008 | MCP-T-002,003,004,005 | PR-3 |
| SSRF private-IP matrix + DNS-rebinding lab + inbound Origin/Host tests | MCP-INSP-004, MCP-INSP-005, MCP-INSP-008 | MCP-T-036,037,030,031,055,052 | PR-7 (INSP-004/005), PR-1 (INSP-008 — inbound listener ships in PR-1) |
| SSE-exhaustion / slowloris / queue-saturation load tests | MCP-OPS-002, MCP-EVENT-002 | MCP-T-040,042,043,044 | PR-5 (bounds), PR-8 (event durability under saturation) |
| Mixed-version / stale-epoch / corrupt-snapshot CP↔DP tests | MCP-CPDP-001..003, MCP-HA-001..002 | MCP-T-047,048,049,050 | PR-10 |
| MCP-off overhead regression benchmark | MCP-OPS-001 | — | PR-5 |
| Tool canonicalization + drift-classification + privilege-expansion fixture tests | MCP-TOOL-001..006 | MCP-T-011..015,019 | PR-2 (canonicalization/drift), PR-6 (quarantine enforcement) |
| Secret-in-events scan (decision-event payload redaction assertions) | MCP-CRED-004, MCP-EVENT-003 | MCP-T-023,028 | PR-4 (credential broker), PR-8 (event model) |
| Event durability under saturation (no silent loss of auth/deny/high-risk events) | MCP-EVENT-002 | MCP-T-044 | PR-8 |

Also missing and Proposed, cross-cutting (not tied to one PR):

- **No `dependency-review-action`** — no automated new-dependency review gate on PRs.
- **No mechanical no-new-deps gate** — only the advisory Dependency Obituary signal exists; nothing
  blocks an unreviewed new dependency from merging.
- **No markdown/link-check CI** — a broken relative link between the MCP design docs (or later, MCP
  operator docs) is not caught by any existing workflow.

These three are general repository gaps surfaced by this MCP work, not MCP-specific controls; they are
listed here because the MCP design package (13+ cross-linked documents, and later PRs likely adding new
dependencies for MCP/JSON-RPC/OAuth libraries) is exactly the kind of change that would benefit from them.

## Master table

| Gate | Lane | Classification | Blocking? | Requirement IDs enforced | Present today? |
|---|---|---|---|---|---|
| fmt/vet/build/tidy | fast | Existing | Yes | — (mechanical) | Yes |
| Diff-scoped golangci-lint | fast | Existing | Yes | — (mechanical) | Yes |
| `-race` + coverage floors (55% global + per-file) | fast | Existing | Yes | — (mechanical) | Yes |
| benchgate | fast | Existing | Yes | — (mechanical); not MCP-OPS-001 | Yes |
| govulncheck | fast | Existing | Yes | — (mechanical) | Yes |
| gosec | fast | Existing | Yes | — (mechanical) | Yes |
| gitleaks | fast | Existing-but-insufficient | Yes (pattern-scan only) | Partial MCP-CRED-004 (static secrets only) | Yes |
| staticcheck | deep | Existing | Yes, if triggered | — (mechanical) | Yes |
| trivy | deep | Existing | Yes, if triggered | Container CVEs | Yes |
| hadolint | deep | Existing | Yes, if triggered | Dockerfile hygiene | Yes |
| go-licenses | deep | Existing | Yes, if triggered | License compliance | Yes |
| determinism + reproducible build | deep | Existing | Yes, if `*_test.go` changed | Build reproducibility | Yes |
| cosign keyless / SLSA L3 / syft SBOM | release | Existing | Tag path only, not PR-blocking | Supply-chain | Yes |
| catalog gate | release | Existing | Tag path only | Release-catalog trust | Yes |
| `codeql.yml` | advisory/scheduled | Existing-but-insufficient | No (PR path-scoped, MCP paths not wired) | — | Partial |
| `fuzz-nightly.yml` | advisory/scheduled | Advisory | No | — | Yes |
| Dependency Obituary | advisory/scheduled | Advisory | No | — | Yes |
| DAST / load / stress nightlies | advisory/scheduled | Advisory | No | — | Yes |
| `api-contract.yml` / `pr-api-governance.yml` | fast/deep (API diff) | Existing | Yes, for API changes | OpenAPI/ADR-0007 contract | Yes |
| Production Qualification evidence pack | prod-readiness | Proposed | Human sign-off gate, not automated PR check | All MCP-* IDs (aggregate) | No |
| Malicious-MCP-server test suite | proposed (target PR-2) | Proposed | Yes, for PR-2 | MCP-TOOL-001..006 | No |
| OAuth/audience/replay negative matrix | proposed (target PR-3) | Proposed | Yes, for PR-3 | MCP-AUTH-001..008 | No |
| SSRF private-IP matrix + DNS-rebinding lab + inbound Origin/Host tests | proposed (target PR-1/PR-7) | Proposed | Yes, for PR-1 (inbound) / PR-7 (SSRF/rebinding) | MCP-INSP-004,005,008 | No |
| SSE-exhaustion/slowloris/queue-saturation tests | proposed (target PR-5/PR-8) | Proposed | Yes, for PR-5/PR-8 | MCP-OPS-002, MCP-EVENT-002 | No |
| Mixed-version/stale-epoch/corrupt-snapshot tests | proposed (target PR-10) | Proposed | Yes, for PR-10 | MCP-CPDP-001..003, MCP-HA-001..002 | No |
| MCP-off overhead regression benchmark | proposed (target PR-5) | Proposed | Yes, for PR-5 | MCP-OPS-001 | No |
| Tool canonicalization/drift/privilege-expansion tests | proposed (target PR-2/PR-6) | Proposed | Yes, for PR-2/PR-6 | MCP-TOOL-001..006 | No |
| Secret-in-events scan | proposed (target PR-4/PR-8) | Proposed | Yes, for PR-4/PR-8 | MCP-CRED-004, MCP-EVENT-003 | No |
| Event durability under saturation | proposed (target PR-8) | Proposed | Yes, for PR-8 | MCP-EVENT-002 | No |
| `dependency-review-action` | proposed, cross-cutting | Proposed | REC — not yet scoped to a specific PR | — | No |
| Mechanical no-new-deps gate | proposed, cross-cutting | Proposed | REC — not yet scoped to a specific PR | — | No |
| Markdown/link-check CI | proposed, cross-cutting | Proposed | REC — not yet scoped to a specific PR | — | No |

## Scope note

**[FACT]** Wiring `codeql.yml`'s PR path filter to include `internal/mcp/**`, and adding every "Proposed"
gate in this document as an actual workflow job, are **CI/config changes**. Per the PR-0 scope boundary
(see [`README.md`](README.md) and the shared PR-0 authoring brief), **PR-0 is documentation-only and
modifies no CI file** — these changes belong to PR-1 and later, scoped per the "Target PR" column above.
This document records what is required so that each of those PRs can carry its own gate as a **hard entry
condition**, not a follow-up.

## Cross-references

- [`TEST-TRACEABILITY-MATRIX.md`](TEST-TRACEABILITY-MATRIX.md) — full threat → requirement → control →
  test → evidence → owner → gate chain that this document's proposed gates feed into.
- [`SUPPLY-CHAIN-SECURITY.md`](SUPPLY-CHAIN-SECURITY.md) — dependency, build, signing, provenance, and
  incident-response controls (the supply-chain half of what release-gate classification above covers).
- [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md) — the normative requirement IDs (MCP-AUTH-*,
  MCP-TOOL-*, MCP-INSP-*, MCP-OPS-*, etc.) that the proposed gates in this document enforce.
- [`IMPLEMENTATION-SLICES.md`](IMPLEMENTATION-SLICES.md) — the PR-1 … PR-11 + Production Qualification
  sequence that the "Target PR" column above is keyed to.
- [`GO-NO-GO-CHECKLIST.md`](GO-NO-GO-CHECKLIST.md) — blocking conditions, including CI-gate completeness,
  reviewed at the Production Qualification milestone.
