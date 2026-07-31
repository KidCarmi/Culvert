# MCP CI Gates

Status: PR-0 design artifact (Proposed)

> **Decision provenance (2026-07-24, [`docs/adr/0024`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md)).**
> The Proposed gates are now decision-backed: the **OAuth/replay negative matrix (PR-3)** enforces the
> reframed D-2 posture (sender-constraint / DPoP-proof replay, not access-token one-time-use); the
> **event-durability-under-saturation gate (PR-8)** enforces **both branches** of the D-5 per-action durability matrix (**fail closed AND** degrade+alert for the critical write/destructive/config-publication/credential classes, with the degraded state **scoped to one durability domain**, and the attacker-mintable authentication-failure/authorization-denial class routed to a **separate denial lane that blocks nothing authenticated** — MCP-T-075); the
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
| gitleaks **[dual-capability sweep: EXEMPT — repo-wide secret scan, capability-agnostic by design; its `MCP-EVENT-003` association is incidental, so it MUST NOT be amended to name both capabilities]** | Secret-pattern scan, even docs-only PRs | Yes — would catch a literal secret checked into MCP code or docs, but is a pattern scanner, not the MCP-specific "no raw secrets in decision events" runtime property (MCP-CRED-004/MCP-EVENT-003) |
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
| `codeql.yml` | Main pushes, weekly, and path-scoped PRs. **[FACT, verified at `origin/main` `2eef667`, `.github/workflows/codeql.yml`]** the `pull_request` path filter **already includes `internal/**`**, which matches `internal/mcp/**` — so MCP Go code under `internal/mcp/**` is analyzed by CodeQL on PRs **automatically once it exists, with no path-filter change needed**. (Root-package MCP files, if any land at repo root, would still need their filenames added to the filter.) | **Existing but non-blocking.** CodeQL analyzes `internal/mcp/**`, but `codeql.yml` is **not** a branch-protection-required check (see "Required-merge-gate fact" above), so it **runs but does not block a merge**. What remains for MCP is a **policy choice**, not a path-filter edit: if CodeQL must *block* MCP PRs, add it as a required check in branch protection (a repo-settings change, PR-1+). |
| `fuzz-nightly.yml` | Mon/Wed/Fri coverage-guided fuzzing | Advisory / nightly only — never blocks a PR |
| Dependency Obituary | Advisory dependency-health signal | Advisory — not a merge gate, not a hard no-new-deps check |
| `proxy-nightly-e2e.yml`, `proxy-weekly-stress.yml`, `proxy-ui-e2e.yml` (playwright), `auth-idp-interop.yml` | Nightly/weekly load, stress, UI e2e, auth-interop | Advisory / scheduled only — never blocks a PR |
| `install-lifecycle-e2e.yml` + `maint-agent-*-e2e.yml` | Nightly + installer-surface PRs | Advisory/path-gated — not a general MCP gate |
| `qa-gate.yml` / `security-release-gate.yml` | Full functional QA / 10-check security scan on main pushes, tags (security), weekly cron (security) | Pass-through shell on PRs (does not block PR merge); real content runs post-merge |
| `code-review.yml` | Reviewdog inline lint, PR-size, conventional commits | Advisory PR DX — never blocks |
| `api-contract.yml` + `pr-api-governance.yml` | Breaking-change + client-gen check on `api/openapi/openapi.yaml` changes | **Existing, Blocking for API changes** — any MCP Management API surface (Capability A) that extends `api/openapi/openapi.yaml` is already gated by these two checks per ADR-0018 |

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
| **Protocol-kernel fuzz gate (PR-time, blocking)** — a **bounded** `go test -fuzz` run over the JSON-RPC parser, framing, version adapters and cancellation state, with **panic/crash detection**, `-race`, **resource-budget assertions**, the run repeated under **each capability's bound set** (Management and Gateway) so a bound proven safe for one listener is never assumed for the other, a checked-in **seed + malformed-JSON-RPC corpus** (which **MUST** include invalid-UTF-8 and non-ASCII/normalization-sensitive method-token inputs per `MCP-PROTO-014`), **corpus-regression storage**, and **reproduction of discovered crashes**. Distinct from `fuzz-nightly.yml`, which stays advisory (see scheduled note below). | MCP-PROTO-001,002,006,007,008,009,013,**014** | MCP-T-057..065,073,074 | **PR-1** |
| **Protocol-kernel structural + protocol-state test suite (blocking)** — parser-differential/duplicate-key, message classification, **response-only `id` correlation** (a valid notification carrying no top-level `id` MUST be accepted, not rejected as uncorrelatable; a notification carrying an `id` MUST be rejected; a cancellation naming another session's request `id` in params MUST NOT take effect), **no-reply-to-rejected-notification** (a rejected notification MUST produce no wire response — asserting the amplification vector is closed), **no-reply-to-rejected-response** (an uncorrelated / malformed / over-limit inbound **response** MUST be discarded and recorded with no wire response — asserting no response-to-response feedback loop — **and MUST NOT delete an outstanding request's state**: a malformed response naming a legitimate in-flight `id` MUST leave that entry intact to expire on its bounded timeout, while the offending message's own resources are freed; an entry may be released only on trustworthy same-session correlation), request-ID correlation edge cases, structural size/depth/field/string limits, **deterministic batch-policy cases (`MCP-PROTO-004`/`MCP-T-061`): maximum batch size, per-element bounds, bounded amplification, and — when batch is unsupported — explicit rejection with the defined error, never silent splitting or partial processing**, **deterministic pathological-number cases (`MCP-PROTO-007`/`MCP-T-064`): overflow, precision loss, and pathological encodings asserting bounded work and no precision-driven parser differential** — these are DETERMINISTIC assertions and **MUST NOT** be delegated to the fuzz gate, which is crash-oriented and cannot establish semantics, framing/truncation, protocol-state machine, cancellation race, reconnect re-validation, duplicate completion, **plus the `MCP-PROTO-014` token-handling fixtures: invalid-UTF-8 rejection, exact (byte-for-byte, no normalization folding) method-token comparison, non-ASCII-method-name rejection (pending D-1), and a test proving the kernel does NOT globally Unicode-normalize opaque identifiers**, **and the cross-capability limit-isolation cases: for every paired kernel bound and the batch policy, change the Management value and assert the Gateway value is unchanged at runtime, and vice versa — an implementation backed by a single shared limits object MUST fail, since the whole purpose of the per-capability split is that raising a bound on one listener cannot widen the other's trust boundary**. | MCP-PROTO-001,002,003,004,005,006,007,008,012,013,**014** | MCP-T-057..063,065,069,070,071,072 | **PR-1** |
| **Protocol-compatibility conformance gate (blocking; content gated on D-1)** — per supported protocol version: negotiation, unsupported-version rejection, downgrade behavior, invalid lifecycle sequences, malicious/non-compliant peers, version-adapter equivalence, required error responses. **Fixtures cannot be authored — and this gate must not be marked green — until [D-1](OPEN-DECISIONS.md) (the supported-version baseline) is externally verified and human-approved.** | MCP-PROTO-010,011 | MCP-T-066,067,068 | **PR-1** (fixtures/greenness gated on D-1 closure) |
| Malicious-MCP-server test suite (fixture servers with poisoned tools, rug-pull updates, schema/description drift, unknown-tool responses) | MCP-TOOL-001..006 | MCP-T-011..017 | PR-2 |
| OAuth/audience/replay negative matrix (MCP-AUTH-*): wrong audience, wrong resource, token passthrough, expired/forged token, **replayed DPoP proof** + sender-constraint enforcement + rate-limit/anomaly on token abuse (**not** access-token one-time-use — [`ADR-0024 §D-2`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md)) | MCP-AUTH-001..008 | MCP-T-002,003,004,005 | PR-3 |
| SSRF private-IP matrix + DNS-rebinding lab + Origin/Host validation + listener rebinding, **plus cross-capability allowlist isolation** (add an approved host to the Management allowlist and assert the Gateway listener still rejects it, and vice versa — one shared allowlist object MUST fail), **plus per-request revalidation over a reused connection** (HTTP keep-alive **and** multiplexed HTTP/2: an allowed first request followed by a disallowed `Host`/`:authority`/`Origin` on the **same connection** MUST be rejected — a listener that validates only at accept time or once per connection MUST fail) | MCP-INSP-004, MCP-INSP-005, MCP-INSP-008, MCP-INSP-009 | MCP-T-036,037,030,031,055,052 | PR-7 (INSP-004/005); **PR-1 (INSP-008 — the Origin/Host validation *primitive* + harness, NO listener)**; **PR-5 (INSP-009 — listener bind + host-allowlist + E2E rebinding)** |
| SSE-exhaustion / slowloris / queue-saturation load tests — run against **each listener separately** (both capabilities carry their own availability bounds), so saturating one listener is never taken as evidence for the other | MCP-OPS-002, MCP-EVENT-002 | MCP-T-040,042,043,044 | PR-5 (bounds), PR-8 (event durability under saturation) |
| Mixed-version / stale-epoch / corrupt-snapshot CP↔DP tests, **plus a re-run of the PR-8 event-durability suite against the REAL signed publication path** — a saturated or commit-failed configuration-publication decision event MUST leave **no new revision, nothing signed or pushed, and every DP on the prior epoch** (`MCP-EVENT-002`), **and a separate ROLLBACK failure-injection case MUST assert no swap occurred and the CURRENT snapshot remains active** — rollback's side effect is a swap, so the forward-path assertions pass vacuously for an act-first rollback; PR-8 can only stub this because the publication path does not exist until PR-10 | MCP-CPDP-001..003, MCP-HA-001..002, **MCP-EVENT-002** | MCP-T-047,048,049,050, **044** | PR-10 |
| **Config-surface anti-drift gate (blocking) — BOTH omission cases.** (1) **New field in an already-enumerated MCP type** added without registry metadata **MUST fail the build**. (2) **An entirely new or nested MCP config type outside the parity inventory MUST fail the build** — this is the case today's hard-coded three-type, one-level-deep inventory misses, and a gate that catches only (1) does **not** discharge `MCP-CFG-001` or ADR-0024 §Decision Part 1 item 8. Plus: every `Sensitive` MCP value provably zeroed on the `!callerIsEnrolledNode` path; capture/apply parity for every DP-affecting field **including the four `RC-5` snapshot-integrity fields** (`AppliesOnDP: true`, else apply-parity skips exactly the fields whose purpose is pre-apply verification). **`RC-5` is four rows, not six**: the two operator-controlled publication settings (`snapshot_sync_enabled`, `snapshot_min_dp_version`) live in `RC-7` because they are admin-durable and exportable, and they remain covered by the **every-DP-affecting-field** clause above — which is deliberately not scoped to `RC-5`, so no DP-affecting row escapes parity by changing class. **Plus PARSE VALIDITY AND ANTI-VACUITY — this clause is ordered FIRST because every clause below is quantified over the matrix rows:** the config-surface matrix **MUST** parse as a syntactically valid GFM table (header cell count **==** delimiter cell count **==** every data-row cell count), and **every delimiter cell MUST independently carry at least three hyphens** with optional alignment colons — `-` and `--` are not delimiter cells, and accepting them would let a table GitHub refuses to render pass the gate; the parse **MUST** yield a **non-empty** row set and the **expected** live-row count; **zero parsed rows is an UNCONDITIONAL FAILURE, never a pass** — a 17-cell header against a 16-cell delimiter makes GFM refuse the table, so a conformant parser sees no rows and `count(RC-X) == 0` and every invariant below hold trivially while asserting nothing (this shipped in #947). **Summary integrity:** every declared registry-class summary label **MUST** occur **exactly once** (zero occurrences and duplicates both fail — two rows sharing a label can disagree while a first-match reader sees only one), and no field may be named twice **inside** one summary (a member list collapsed to a set absorbs the duplicate silently). There **MUST** be forward **and** reverse parity between **every** summary and the live rows, with the reverse direction bound one of **two** ways, declared per row: a summary that enumerates a class exhaustively (`RC-1`, `RC-2`, `RC-3`, `RC-4`, `RC-5`) is checked against **the class** — every live row of that class is named; a summary that is a deliberately **bounded subset** of a large class is checked against an **explicit pinned name list**, because class-level reverse parity is inapplicable there. `Snapshot publication settings` names two of the 38 `RC-7` rows and is bound the second way; the earlier mixed `{RC-5, RC-7}` row was checked exhaustively for `RC-5` **only**, leaving both `RC-7` publication settings deletable with the gate green — which is why the category is now **two** rows. Both censuses — **value kind and registry class** — **MUST** be COMPLETE, UNIQUE and reproduced from parsed rows: every vocabulary token carries a count **including zero-valued ones** (`pinned-identity 0`, `RC-X 0`), each token claimed **exactly once**, no token outside the declared vocabulary, plus the row total and the sensitive-kind total. An omitted claim must not be able to hide a stale one, and a duplicated claim must not be able to hide a wrong one behind a correct first match. Summary membership **MUST** use full field names; abbreviations defeat mechanical parity. Executable today as `predicates/predicate-26.py`, which carries **22** seeded controls — one-, two-hyphen and malformed-alignment delimiter cells, the 16-vs-17 delimiter, the zero-row parse, a dropped bounded-summary member, a duplicate member, a duplicate summary row, four registry-class census cases (omitted `RC-3`, wrong `RC-7`, duplicated `RC-2`, `RC-X` published as `1`), three value-kind census cases, an `RC-1` summary disagreement, an `RC-0` row listed in the `RC-2` summary, a missing summary member, `provider-ref → RC-6`, a duplicate field, an unknown value kind and a live `RC-X` row — plus negative controls proving it does not police unrelated prose tables and accepts valid alignment syntax. **Plus the value-kind → class sensitivity invariant, evaluated over REGISTRY ENTRIES (not merely matrix rows):** the value kind **MUST** be carried on the `configSurfaces` entry and an entry **MUST NOT** be creatable without one; every registry entry **and** every matrix row **MUST** declare a `Value kind` from the closed vocabulary (an unknown token fails); **MCP registry entries and matrix rows MUST hold bidirectional field-ID parity** — every MCP registry entry has exactly one matrix row, and every matrix row except `RC-0` (which by definition has no field) resolves to exactly one registry entry;  `value-kind ∈ {server-endpoint, pinned-identity, provider-ref}` **MUST** resolve to `registry-class ∈ {RC-1, RC-2}`; `RC-0 ⇔ value-kind = none`; `value-kind = snapshot-meta ⇔ RC-5`; and redaction parity **MUST** cover every row so classified. The gate **MUST** carry **two** seeded negative cases, both of which **MUST fail**: (i) a row declared `provider-ref` and classified `RC-6`; and (ii) **a sensitive field registered in `configSurfaces` with NO matrix row** — the parity case, which without (7) passes both omission checks and leaves the value-kind rule nothing to quantify over, letting a `Sensitive: false` field reach an unenrolled peer with the gate green. A gate that passes either is not enforcing `MCP-CFG-001`(6)-(7); **nested** slice/map cap parity bounded by `snapshotCapCeiling`; wire-wipe ⇔ `omitempty` parity for MCP slice/map fields; every API-backed MCP row has a GUI surface; and `count(RC-X) == 0` (inline secret material is rejected at validation, never stored-and-redacted). **Plus class↔row consistency**, which catches a class of defect prose review misses: a row in a synced class (`RC-1`/`RC-5`/`RC-7`) **MUST NOT** carry `Snapshot (CP→DP) = No`; a row in `RC-6` (never synced) **MUST NOT** carry `Snapshot = Yes`; a row in `RC-0` (checklist-only, no field may exist) **MUST** carry `Snapshot = N/A` with no concrete API/GUI surface, and `RC-0` rows are excluded from the registry-row count. Without this assertion a class declaring "synced" can be worn by a row the design explicitly forbids publishing — four such mismatches were found in the first classification pass of this matrix, one of them only by the check itself. | **MCP-CFG-001** (strategy `D-15`) | MCP-T-023,047 | **PR-1** |
| MCP-off overhead regression benchmark | MCP-OPS-001 | — | PR-5 |
| Tool canonicalization + drift-classification + privilege-expansion fixture tests | MCP-TOOL-001..006 | MCP-T-011..015,019 | PR-2 (canonicalization/drift), PR-6 (quarantine enforcement) |
| Secret-in-events scan (decision-event payload redaction assertions) — **MUST scan both capabilities' event streams**; Management events carry configuration payloads, so a Gateway-only scan leaves the higher-privilege stream unchecked | MCP-CRED-004, MCP-EVENT-003 | MCP-T-023,028 | PR-4 (credential broker), PR-8 (event model) |
| Event durability under saturation (no silent loss of auth/deny/high-risk events) — **MUST cover BOTH capabilities: (a)** the Gateway critical-class case **and** the **Management** critical-class case (a non-persistable configuration-publication / state-affecting Management event **fails closed AND** enters degraded mode with alert), **and (b)** the **nine blocking `MCP-T-075` containment tests** enumerated below, which REPLACE the superseded denial-event durability-lockout test — that test asserted the vulnerability succeeded, so a green result on it was evidence of the defect, not of the control — **plus commit-before-execute ordering asserted PER CLASS, each proving the ABSENCE OF EVERY IRREVERSIBLE ACTION DOWNSTREAM OF THAT FLOW'S COMMIT GATE — not only the eponymous one, since a single flow can carry two classes' side effects — and "no upstream call" is meaningless for classes that make none: write/destructive ⇒ **no upstream call occurred AND no broker-side materialization occurred**; configuration publication ⇒ **no new configuration revision exists, nothing was signed or pushed, and every DP remains on the prior epoch** — **SLICE TIMING: the real signed CP→DP publication path lands in PR-10, which depends on PR-8, so at PR-8 this case can only exercise a stub. It is therefore ALSO a PR-10 gate obligation: the PR-8 durability suite **MUST be re-run against the real publication wiring when PR-10 introduces it**, and PR-10 MUST NOT be marked green until it has been. Otherwise the actual publication path could ship without this assertion ever executing**; credential issue/rotation/revocation ⇒ **broker-side credential state unchanged** (nothing minted, rotated or revoked) **AND no upstream call occurred**; state-affecting Management operation ⇒ **no state change AND no new revision, nothing signed or pushed, every DP on the prior epoch** — DFD-3's irreversible action is `Publish signed snapshot`, so a state-change-only assertion passes a handler that publishes after the commit fails. **SLICE TIMING — `state-affecting Management` has NO V1 mechanism** (ADR-0024 §D-13 defers every Management mutation to a post-V1 decision), so PR-8 can only **stub** this class; the **real-path** assertion is assigned to the ****Future Management-Mutation Gate** (IMPLEMENTATION-SLICES, D-13), which MUST NOT be marked green without it** (amendment 18's dual ownership, as for the PR-10 publication re-run). A test observing only the returned error or the degraded state passes against an implementation that acts first and reports failure afterwards. **Plus a spool-commit-failure case distinct from queue saturation** (full disk / `fsync` error / encryption-key failure) proving the gate is a CONFIRMED durable commit rather than successful enqueueing** | MCP-EVENT-002 | MCP-T-044 | PR-8 |

> **Fuzz gate — blocking (PR-time) vs. advisory (scheduled).** PR-1's acceptance requires **fuzz green**,
> so a **bounded, blocking** protocol-kernel fuzz job must be wired into `pr-fast-gate.yml`/`pr-deep-gate.yml`
> (the first row above). `fuzz-nightly.yml` is **not** that gate and **must not be described as
> merge-blocking**; it remains **advisory/scheduled** and should be **extended** with a deeper, longer
> protocol-kernel corpus as an additional non-blocking deep signal. **No CI workflow file is changed by this
> documentation task** — the implementation owner (Eng/Sec) wires these jobs during PR-1.
>
> **Compatibility gate — blocking but D-1-gated.** PR-1's **compat green** likewise requires a blocking
> conformance job; its *content* (which protocol versions) is blocked on **D-1** external verification.
> Compatibility **must not be reported green before D-1 is closed and the fixtures exist**.

Also missing and Proposed, cross-cutting (not tied to one PR):

- **No `dependency-review-action`** — no automated new-dependency review gate on PRs.
- **No mechanical no-new-deps gate** — only the advisory Dependency Obituary signal exists; nothing
  blocks an unreviewed new dependency from merging.
- **No markdown/link-check CI** — a broken relative link between the MCP design docs (or later, MCP
  operator docs) is not caught by any existing workflow.

These three are general repository gaps surfaced by this MCP work, not MCP-specific controls; they are
listed here because the MCP design package (13+ cross-linked documents, and later PRs likely adding new
dependencies for MCP/JSON-RPC/OAuth libraries) is exactly the kind of change that would benefit from them.

### The nine blocking `MCP-T-075` containment tests (PR-8)

**These REPLACE the superseded denial-event durability-lockout acceptance test.** That test asserted that
a lost denial event **succeeded** in blocking subsequent allowed write/high-risk operations — i.e. it
proved the vulnerability worked. A gate whose green result is evidence of the defect is worse than no
gate, because it converts the flaw into a maintained invariant. All nine below are **blocking for PR-8**.

| # | Test | What it proves | Requirement |
|---|---|---|---|
| 1 | **Headline attacker test** — generate unauthenticated authentication failures at the **maximum admitted rate**; hold until the denial lane is demonstrably **saturated and shedding/coalescing**; run authenticated **allowed critical** work in a **different tenant / listener / capability** throughout | An unauthenticated attacker **cannot** stop authenticated critical work. The authenticated operations **MUST succeed for the whole duration** — a single failure is a FAILING result | MCP-EVENT-007, MCP-T-075 |
| 2 | **Coalescing** — `N` equivalent unauthenticated denials from one bucket/window | **O(1)** durable aggregate records (not O(`N`)), with a **correct count** and correct **first/last-seen** timestamps | MCP-EVENT-007 |
| 3 | **Reserved partition** — saturate the denial lane, then commit an authenticated critical event | The critical event **still commits**, using `P-CRIT` reserved capacity that denial traffic could not consume | MCP-EVENT-001 |
| 4 | **Local-scope containment** — (a) Management denial degradation does not block Gateway; (b) one node does not automatically degrade another; (c) one tenant/principal scope does not block a different one where identity is available | The degradation domain is **at most** `node × capability × partition`; a system-wide block is a FAILING result | MCP-OPS-005, MCP-EVENT-002 |
| 5 | **Preserved fail-closed guarantee** — two separate cases: (a) an authenticated critical operation whose own event cannot commit **under queue saturation**; (b) the same under a **post-admission commit failure** (`fsync` / `ENOSPC` / encryption failure / storage I/O error) | The operation **fails closed BEFORE its own irreversible action** in **both** cases, with the per-class absence assertions of the §4a table unchanged. **This is the guarantee #926 must not erode** | MCP-EVENT-002 |
| 6 | **Recovery termination** — restore durability, let the recovery marker commit | The state exits **within one documented probe interval** after all four exit criteria hold. A state that outlives its cause is a FAILING result | MCP-OPS-005 |
| 7 | **Restart persistence** — restart the process while `critical-durability-degraded` | The state **remains active** with its scope intact, and **restart alone does NOT permit a previously blocked critical operation** | MCP-OPS-005 |
| 8 | **Storage reclamation** — drive the spool past its high watermark with mixed records | Denial and ordinary records are reclaimed **before** unexported critical records; the critical reserve is **never** consumed by denial traffic | MCP-EVENT-001 |
| 9 | **Counter integrity** — induce denial-lane loss and authenticated critical commit failure separately | The two increment **separate** counters at **separate severities**; neither is attributable to the other | MCP-EVENT-007, MCP-EVENT-002 |

**There is no break-glass test, because V1 has no bypass.** A test asserting that an emergency policy can
skip denial-event durability would be asserting the existence of a path this design deliberately does not
have — and a test claiming both that a bypass exists and that it cannot be configured is the contradiction
[#926](https://github.com/KidCarmi/Culvert/issues/926) §8 item 5 requires removed.

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
| `codeql.yml` | advisory/scheduled | Existing, non-blocking | No — analyzes `internal/**` (⊇ `internal/mcp/**`) on PRs but is **not** a branch-protection-required check | — | Yes (analysis); **not** a merge gate |
| `fuzz-nightly.yml` | advisory/scheduled | Advisory | No | — | Yes |
| Dependency Obituary | advisory/scheduled | Advisory | No | — | Yes |
| DAST / load / stress nightlies | advisory/scheduled | Advisory | No | — | Yes |
| `api-contract.yml` / `pr-api-governance.yml` | fast/deep (API diff) | Existing | Yes, for API changes | OpenAPI/ADR-0018 contract | Yes |
| Production Qualification evidence pack | prod-readiness | Proposed | Human sign-off gate, not automated PR check | All MCP-* IDs (aggregate) | No |
| Protocol-kernel fuzz gate (PR-time, bounded) — **MUST run against each capability's configured bounds (per-capability parameterization), not one shared bounds object**, since `MCP-PROTO-006`/`008`/`013`/`014` are per-capability config rows; a fuzz gate exercising only one capability's bounds leaves the other's unfuzzed while reporting green | proposed (target PR-1) | Proposed | Yes, for PR-1 | MCP-PROTO-001,002,006,007,008,009,013,014 | No |
| Protocol-kernel structural + protocol-state suite (**incl. cross-capability limit isolation**, **and a STAGE-ORDER case: a method valid only in the version about to be negotiated MUST NOT be rejected pre-negotiation, and a version-specific method MUST be admitted against the NEGOTIATED version's allowlist — `MCP-PROTO-002` split around `MCP-PROTO-010/011`; PLUS a BOOTSTRAP case — on an un-negotiated session the `initialize` handshake MUST be admitted version-independently, and a NON-initialize method MUST be rejected WITHOUT its version/capability fields being interpreted and WITHOUT any negotiation-state mutation**) | proposed (target PR-1) | Proposed | Yes, for PR-1 | MCP-PROTO-001..008,012,013,014 | No |
| Protocol-compatibility conformance gate (D-1-gated) | proposed (target PR-1) | Proposed | Yes, for PR-1 (green only after D-1) | MCP-PROTO-010,011 | No |
| Deeper scheduled protocol-kernel fuzzing | proposed (extends `fuzz-nightly.yml`) | Advisory | No (scheduled/deep signal) | MCP-PROTO-009 | Partial (harness exists) |
| Malicious-MCP-server test suite | proposed (target PR-2) | Proposed | Yes, for PR-2 | MCP-TOOL-001..006 | No |
| OAuth/audience/replay negative matrix | proposed (target PR-3) | Proposed | Yes, for PR-3 | MCP-AUTH-001..008 | No |
| SSRF private-IP matrix + DNS-rebinding lab + inbound Origin/Host tests (**incl. cross-capability allowlist isolation**) | proposed (target PR-1/**PR-5**/PR-7) | Proposed | Yes, for PR-1 (INSP-008 **primitive only**, no listener) / **PR-5 (INSP-009 — listener bind + host allowlist + E2E rebinding; the PR-1 unit test does NOT close the listener-side threat)** / PR-7 (SSRF) | MCP-INSP-004,005,008,**009** | No |
| SSE-exhaustion/slowloris/queue-saturation tests (**per listener**) | proposed (target PR-5/PR-8) | Proposed | Yes, for PR-5/PR-8 | MCP-OPS-002, MCP-EVENT-002 | No |
| Mixed-version/stale-epoch/corrupt-snapshot tests **+ PR-8 durability-suite re-run on the real publication path** | proposed (target PR-10) | Proposed | Yes, for PR-10 | MCP-CPDP-001..003, MCP-HA-001..002, **MCP-EVENT-002** | No |
| MCP-off overhead regression benchmark | proposed (target PR-5) | Proposed | Yes, for PR-5 | MCP-OPS-001 | No |
| Tool canonicalization/drift/privilege-expansion tests | proposed (target PR-2/PR-6) | Proposed | Yes, for PR-2/PR-6 | MCP-TOOL-001..006 | No |
| Secret-in-events scan (**both capabilities' streams**) | proposed (target PR-4/PR-8) | Proposed | Yes, for PR-4/PR-8 | MCP-CRED-004, MCP-EVENT-003 | No |
| Event durability under saturation (**both capabilities; MCP-T-075 containment suite included**) | proposed (target PR-8 **+ Future Management-Mutation Gate (D-13) for the real `state-affecting Management` path — PR-8 stubs it**) | Proposed | **Yes, for PR-8 AND for the Future Management-Mutation Gate (D-13)** — the post-V1 real-path re-run is **blocking for that gate**, which MUST NOT be marked green on PR-8's stub coverage | MCP-EVENT-001/002/007, MCP-OPS-005 | No |
| `dependency-review-action` | proposed, cross-cutting | Proposed | REC — not yet scoped to a specific PR | — | No |
| Mechanical no-new-deps gate | proposed, cross-cutting | Proposed | REC — not yet scoped to a specific PR | — | No |
| Markdown/link-check CI | proposed, cross-cutting | Proposed | REC — not yet scoped to a specific PR | — | No |

## Scope note

**[FACT]** CodeQL's PR path filter **already covers `internal/mcp/**`** via its `internal/**` glob
(verified at `origin/main` `2eef667`), so **no path-filter edit is required** for CodeQL to *analyze* MCP
code; making CodeQL a *blocking* MCP gate is a **branch-protection settings change** (adding it as a
required check), not a workflow edit. Adding every "Proposed" gate in this document as an actual workflow
job (the fuzz, compatibility, and other MCP-specific gates below) **is** a CI/workflow change. Per the
PR-0 scope boundary (see [`README.md`](README.md) and the shared PR-0 authoring brief), **PR-0 — and the
readiness remediation — is documentation-only and modifies no CI file**; those changes belong to PR-1 and
later, scoped per the "Target PR" column above. This document records what is required so that each of
those PRs can carry its own gate as a **hard entry condition**, not a follow-up.

**[FACT] One exception now exists, and it is deliberately narrow.** A standalone CI-hardening change wired
the **document-structure predicates** into the required Fast PR Gate as
`Gate · MCP design predicates` — an explicit allowlist of **eight**
(`predicate-19`, `-21`, `-22`, `-23`, `-24`, `-26`, `-27`, `-28`), run by
[`.github/scripts/mcp-doc-predicates.sh`](../../../.github/scripts/mcp-doc-predicates.sh) when a PR touches
`docs/design/mcp/**`, ADR-0024, that script, or `pr-fast-gate.yml`. A failure blocks the
`✅ Fast PR Gate — APPROVED` aggregate; a skip (irrelevant PR) counts as passing. `predicate-25` is
**excluded on purpose** — it is provenance-specific and diffs against a fixed historical base commit, so as
a general gate it would fail unrelated valid PRs; it stays manual. The membership is an allowlist rather
than a `predicate-*.py` glob so a future predicate cannot become blocking without review.

`predicate-27` is the newest allowlist member: it mechanically derives the live **requirement** registry
(`SECURITY-REQUIREMENTS.md`) and the live **threat** registry (`THREAT-MODEL.md` §11) and fails when any
published census that summarises them — the `SECURITY-REQUIREMENTS.md` `## Summary` total, namespace count
and complete per-family census; the `TEST-TRACEABILITY-MATRIX.md` final-totals `**N threats**` /
`**N requirements**` and its per-family spot-claims; and the §3 `all N requirements, 0 unreachable`
coverage total — is missing, duplicated, incomplete, stale or internally inconsistent. It closes the
recount-vs-increment drift that recurred during RPR-2, where a document published an old total (a stale
"91 requirements") while every existing check stayed green because nothing recounted the registry.

`predicate-28` is the RPR-1 (#925/#928) member: it parses the Culvert-reviewed
[`MCP-OPERATION-REGISTRY.md`](MCP-OPERATION-REGISTRY.md) and fails when the admitted-method surface drifts —
non-vacuous GFM parse; unique composite `(capability, leg, direction, method)` keys; every **admitted** row
names exactly one downstream decision point **XOR** is kernel-terminal (never both, never neither); every
**rejected** row has no dispatch owner; separate Management and Gateway rows; explicit rejection of
`resources/*` (incl. `resources/read`), `prompts/*`, `completion/*`, `sampling`/`elicitation`/`roots` and
`tasks/*` (incl. `tasks/cancel`); reverse capabilities not advertised; the requestor-scoped
`(session, direction, id)` correlation, same-direction-only cancellation, `initialize`-not-cancellable and
late-cancel-tolerated normative statements; no `allow_unknown_methods`; and cross-references from
`DATA-FLOW-DIAGRAMS.md` and `PROTOCOL-COMPATIBILITY.md`. Seventeen seeds (session-only key,
opposite-direction cancel deleting state, `initialize` made cancellable, late-cancel-as-duplicate, upstream
bytes to another decoder, sampling/`resources/read`/`tasks/cancel` admitted, no-owner/two-owner/duplicate
rows, dispatch-for-absent-method, arbitrary method list, advertisement wider than the registry, zero-row
table, first-match laundering) each fire their intended violation; three negative controls stay silent. The
eighteen RPR-1 blocking fixtures are enumerated in [`TEST-TRACEABILITY-MATRIX.md`](TEST-TRACEABILITY-MATRIX.md)
§1b — the registry/parity and protocol-state fixtures blocking at **PR-1**, the two business-policy
enforcement fixtures at **PR-6**, without weakening the PR-1 registry gate.

This exception exists because blocker #927 took three PRs and four verification rounds in which **every**
intermediate head passed the full pipeline while still carrying a real defect — once because the
config-surface matrix did not parse as a table at all, making every assertion over it vacuous. No CI job
parsed these documents, so green carried no signal. **It changes nothing else:** every "Proposed" gate in
the table above remains proposed and belongs to PR-1 or later, the eight predicates check **design
documents** and not the runtime `configSurfaces` registry, and `MCP-CFG-001`(7)'s registry-side binding
stays **specified but unenforced** until PR-1.

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
