# PR-1 Readiness Remediation

Remediation log answering every substantive finding in [`PR1-READINESS-REVIEW.md`](PR1-READINESS-REVIEW.md)
(the independent review, preserved **verbatim** and unedited), with the review file brought over from
`origin/claude/mcp-pr1-doc-review-q8iibt`. The work was authored on branch
`claude/mcp-pr1-decision-package-3p0l2u`.

**ADR renumbered `0023 → 0024` (collision with open PR #854).** The decision-package commit created the MCP
ADR as `docs/adr/0023-…`. Before commit, open **PR #854** ("ADR-0023 Durable Configuration Publication",
base `main`, head `claude/adr-0012-to-main`, adds only `docs/adr/0023-durable-config-publication.md`) was
found to already claim `0023`. A full scan of all remote branches and open PRs confirmed only two `002x`
ADRs — both at `0023` — and **no allocation of `0024`**, so this MCP ADR was renumbered to the next free
repository-wide number, **`0024`**: `docs/adr/0024-mcp-agent-security-gateway-trust-boundary.md`. The
unrelated Durable Configuration Publication ADR and its references were **not** touched.

**Branch reconciliation.** The decision-package branch was 8 commits behind `origin/main`. It was
**rebased onto `origin/main` `2eef667`** (before HEAD `4d523cb` → after HEAD `06fcbab`; the 8 main-only
commits touch neither `docs/design/mcp/` nor `docs/adr/`, so the rebase and the working-tree restore applied
**with zero conflicts**). The remediation was preserved via an external backup + `git stash` across the
rebase.

**Scope discipline.** Documentation only. No Go source, CI workflow, dependency, runtime config, binary
asset, or the preserved source DOCX was changed. Changes are confined to
`docs/adr/0024-mcp-agent-security-gateway-trust-boundary.md` and `docs/design/mcp/**`. Preserved invariants:
ADR-0024 stays `Status: Proposed`; D-1 stays a hard pre-PR-1 gate; PR-1 stays protocol-kernel-only with **no
public/production listener**; PR-5 stays the first observe/listener runtime; PR-11 stays Shadow/Canary; no
token passthrough; Management vs Gateway stay separate; no SWG `PolicyRule`/OIDC reuse; no test or gate is
claimed to already exist.

**Evidence baseline.** Repository line-number corrections were re-verified at `origin/main` `2eef667`
(current default-branch HEAD); the design package's overall inspection baseline remains `c0ae2bc` (VRC §1).

---

## New identifiers allocated (after inspecting existing allocation)

- **Threats — `MCP-T-057 … MCP-T-074`** (18). Prior allocation was the contiguous `MCP-T-001..056`; the new
  block starts at `057`. Eight are **High** (`058, 060, 063, 066, 067, 068, 069, 074`) and carry a full
  Threat→Requirement→Control→Test→Evidence→Owner→Gate row; ten are **Medium**.
- **Requirements — new family `MCP-PROTO-001 … MCP-PROTO-013`** (13, round 1), all gated **PR-1**.
- **Abuse cases — `MCP-AC-021 … MCP-AC-027`** (7). Prior allocation was `MCP-AC-001..020`.
- **Attack tree — `AT-10`** (protocol-kernel subversion). Prior: AT-1..AT-9.
- **Data-flow diagram — `DFD-15`** (protocol-kernel decode path). Prior: DFD-1..DFD-14.
- **Open decision — `D-14`** (protocol-kernel concrete limit values + batch policy; values-only, PR-1).

> **IDs are NOT a closed set — this remediation adds IDs (correcting any prior impression otherwise).**
> Round 1 added the `MCP-PROTO-001..013` family. The **follow-up round** (below) added **three more
> requirement IDs** — `MCP-PROTO-014`, `MCP-INSP-009`, `MCP-ID-008` — so the total moved **75 → 88 (round 1)
> → 91 (follow-up)** across **16 namespaces** (`MCP-PROTO` 14, `INSP` 9, `ID` 8). Any statement in earlier
> reporting that the requirement set was final / that no IDs were added is superseded by this record.

---

## Finding-by-finding

### H-1 — Model the PR-1 protocol attack surface — **RESOLVED**
The parser/framing/version/protocol-state surface is now represented across the package.
- **THREAT-MODEL.md:** new §11 subsection "Protocol kernel (PR-1)" defining `MCP-T-057..074` (distinct rows,
  not collapsed), each with severity, `MCP-PROTO-*` control, and owner; §8 STRIDE Protocol-Kernel row
  corrected (see M-4); §9 gains a DFD-15 row; §6 count 14→15.
- **ATTACK-TREES.md:** `AT-10` with five leaves → threat/requirement mapping; count Nine→Ten.
- **ABUSE-CASES.md:** `MCP-AC-021..027` (parser differential, ID mis-correlation, depth/size bomb, version
  downgrade, adapter differential, mid-session rebind, hostile-input crash); count 20→27.
- **SECURITY-REQUIREMENTS.md:** `MCP-PROTO-001..013` (see H-2).
- **TEST-TRACEABILITY-MATRIX.md:** §1 full rows for the 8 High threats; §2 new protocol-kernel test rows.
- **DATA-FLOW-DIAGRAMS.md:** `DFD-15` decode path with limit/error/cleanup edges (see M-3).
- **IMPLEMENTATION-SLICES.md / CI-GATES.md / GO-NO-GO-CHECKLIST.md:** PR-1 requirements, blocking gates, and
  a Protocol-kernel domain gate (see H-2/H-3/H-4).
- Coverage of each mandated item (malformed envelopes, ambiguous/duplicate keys/differentials, request/
  response/notification classification, unknown methods, request-ID confusion, int/string/null id edge
  cases, batch, framing, truncation, oversized, depth/field/string limits, numeric overflow, Unicode
  normalization, version negotiation/downgrade/adapter differential, session/state confusion, cancellation
  races, duplicate completion, reconnect replay, slow-input exhaustion, panic/crash) maps to a distinct
  threat and requirement — see the H-1↔bullet table below.

### H-2 — Replace the phantom "protocol bounds" acceptance item — **RESOLVED**
- New family **`MCP-PROTO-001..013`** in SECURITY-REQUIREMENTS.md defines measurable behavior for: max
  request/envelope size, JSON nesting depth, object-field/array-element counts, string/method-name length
  (`PROTO-006`); max active/in-flight request IDs (`PROTO-003,008`); max partial-frame buffering
  (`PROTO-005`); max parser memory per session + parsing time/work budget (`PROTO-008`); unsupported batch
  behavior (`PROTO-004`); unsupported extension behavior (`PROTO-002,010`); cancellation/cleanup guarantees
  (`PROTO-012,013`); limit-exceeded error behavior (`PROTO-013`).
- IMPLEMENTATION-SLICES.md PR-1 "Security requirements" no longer says "protocol bounds"; it references
  `MCP-PROTO-001..013` + `MCP-INSP-008`.
- **Numeric values are NOT invented.** Each limit is a required **configurable** bound with a **safe-default**
  + **hard-cap** obligation; the concrete values (and batch support yes/no) are open decision **D-14**
  (owner Eng, approver Sec Arch, due PR-1, closure = values fixed+tested). The requirement IDs themselves are
  defined and unblocked.

### H-3 — Give fuzz and compatibility gates a real blocking home — **RESOLVED (documented; CI unchanged)**
- **CI-GATES.md** "MISSING today — Proposed, Blocking" table gains three rows, all target **PR-1**:
  (1) **protocol-kernel fuzz gate** (bounded PR-time `go test -fuzz` over parser/framing/adapter/cancellation
  with seed + malformed corpus, panic/crash detection, `-race`, resource-budget assertions, corpus-regression
  storage, crash reproduction); (2) **protocol-kernel structural + protocol-state suite**; (3) **protocol-
  compatibility conformance gate**, explicitly **greenness gated on D-1 closure**. A note distinguishes the
  **blocking PR-time** fuzz gate from **advisory `fuzz-nightly.yml`** (which is extended as a deeper scheduled
  signal, never described as merge-blocking). Master table + `codeql`/fuzz rows updated.
- **Compatibility** must not be marked green before D-1 is externally verified and fixtures exist — stated in
  CI-GATES.md, IMPLEMENTATION-SLICES.md (PR-1 acceptance), TEST-TRACEABILITY-MATRIX.md, PROTOCOL-COMPATIBILITY.md.
- **No CI workflow file changed.** The gates are documented requirements with implementation owner Eng/Sec,
  wired during PR-1.

### H-4 — Resolve the MCP-OPS-002 gate contradiction — **RESOLVED (split by responsibility)**
- **`MCP-OPS-002`** narrowed to the **listener/runtime** bounding (live connections, SSE streams, concurrency,
  queues, event buffers, per-entity rate limits) — the deployed-listener property that depends on the PR-5
  Observe Runtime; gate stays **PR-5**. Its threat list drops `MCP-T-040` (now split, below).
- **Parse-time** per-message/per-session bounds moved to **`MCP-PROTO-006/008`** at **PR-1**.
- IMPLEMENTATION-SLICES.md PR-1 no longer claims `MCP-OPS-002`; it is explicitly PR-5. PR-1 does **not** claim
  listener availability, production request-serving SLOs, or operational readiness of a listener that does not
  exist; PR-1 requires parser/resource-limit counters, fuzz/race evidence, and deterministic cleanup instead.
- `MCP-T-040` (oversized) traceability row now split: `MCP-PROTO-006` (parse, PR-1) + `MCP-OPS-002` (runtime,
  PR-5). No duplicate or orphan IDs (verified in §Validation).

### M-1 — CodeQL wording — **RESOLVED (corrected to verified fact)**
`codeql.yml`'s `pull_request` path filter **already includes `internal/**`** (verified `origin/main`
`2eef667`, `.github/workflows/codeql.yml`), which matches `internal/mcp/**` — so MCP Go code is analyzed on
PRs **with no path-filter change**. But `codeql.yml` is **not** a branch-protection-required check, so it
**runs but does not block a merge**. What remains for MCP is a **policy choice** (add it as a required check
in branch protection) — not a path-filter edit. Corrected in CI-GATES.md (advisory row, master row, scope
note), IMPLEMENTATION-SLICES.md (PR-1 release gate), and PR0-REVIEW-CHECKLIST.md.

### M-2 — MCP-INSP-001 gate divergence — **RESOLVED (split)**
`MCP-INSP-001` is now **semantic** tool-argument schema validation (PR-7); **structural** parse-time
size/depth/field-count bounds are owned by `MCP-PROTO-006` (PR-1). References realigned in
PROTOCOL-COMPATIBILITY.md §3/§10, TEST-TRACEABILITY-MATRIX.md, DATA-FLOW-DIAGRAMS.md DFD-7, and
SECURITY-REQUIREMENTS.md. No requirement is gated at two different slices for the same responsibility.

### M-3 — Decode-path DFD — **RESOLVED**
`DFD-15` added (Hostile bytes → bounded framing → strict JSON-RPC decode → classification/ID-correlation →
structural validation → version adapter → normalized internal message → test harness / later runtime
boundary), with trust boundary (TB-1), untrusted-data marking, limit checks, error paths, cancellation/
cleanup, and an explicit "no policy/credential/upstream execution in PR-1" note.

### M-4 — STRIDE attribution — **RESOLVED**
THREAT-MODEL.md §8 Protocol-Kernel row rebuilt from threats owned by other components to protocol-native
threats attached where their `MCP-PROTO-*` control is enforced: S=`T-069`, T=`T-058/068`, I=`T-060`,
D=`T-063/073/074` (+ listener-half `T-042/043/044`, PR-5), E=`T-066/067`. Displaced threats relocated:
`T-005`→Credential Broker (I), `T-036`/`T-041`→Inspection Pipeline (I), `T-013` already on Tool Catalog. A
correction note documents the move.

### L-1 — Line-range slips — **RESOLVED**
VERIFIED-REPOSITORY-CONTEXT.md rows re-verified at `origin/main` `2eef667` and marked **⟳**:
`newHistogram :348-408 → :360`; `PrivateIP :36-72 → :72-79`; `PrivateHost :86-103 → :86-113`; `uiRoutes`
range → `var uiRoutes :87`; `validateIDToken :497-561 → :499-566` (now consistent with the §3 row's
`:499-566`). A §3 note records the ⟳ meaning + inspected SHA; the document's overall baseline stays `c0ae2bc`.

### L-2 — Missing symbol·line evidence — **RESOLVED**
Secret row → `internal/secret/secret.go · Provider · 64` (+`kekSource :54`), `internal/secret/provider.go ·
fileProvider · 27-45`, and the ADR reference disambiguated (`docs/adr/0007-secret-containment-boundary.md`,
noting the repo's two `0007` ADRs). Redaction row → `class.go · DataClass · 12`, `redactor.go · Redactor ·
77`, `scrubber.go · Scrubber · 27`.

### L-3 — ADR numbering language — **RESOLVED (verified) + collision-driven renumber**
ADR-0024 carries a **Numbering** note: `0024` is the **next free number across the repository-wide ADR/RFC
allocation**. *(Post-sync update: `main` has since renamed the OpenAPI-contract ADR from the former
`ADR-0007-openapi-contract.md` to `docs/adr/0018-openapi-contract.md`, so `docs/adr/` now runs `0001–0018`
and the `0007` slot is solely the secret-containment ADR.)* `docs/support/rfc/` holds `0012` and
`0018`–`0022` (highest RFC `0022`); **`0023` is taken by open PR #854's unrelated Durable Configuration
Publication ADR**, so this MCP ADR is **`0024`** (verified unique against `origin/main` `7791c706` + PR #854).
No doc calls it "next sequential in
`docs/adr/`". (The superseded `ADR-PROPOSAL` is already a pure pointer with no "next in sequence" language.)

### Renumber & review-artifact treatment (collision follow-up)
- **Rename:** `docs/adr/0023-mcp-agent-security-gateway-trust-boundary.md` → `docs/adr/0024-mcp-agent-security-gateway-trust-boundary.md`.
- **References updated** to `ADR-0024` / `adr/0024-…` across every `docs/design/mcp/` file that referenced
  the MCP ADR, plus the ADR body itself. No stale MCP `ADR-0023` / `0023-mcp-…` reference remains.
- **The unrelated `0023-durable-config-publication.md` ADR and its references were not touched** (there are
  none in the MCP package).
- **`PR1-READINESS-REVIEW.md` was NOT modified** — it contains **no** `0023`/ADR-path cross-reference (it
  predates the ADR and only recommended promoting a proposal to a numbered ADR), so it remains **byte-
  identical** to the independent review. No erratum was injected because nothing in it became stale; the
  original reviewer is **not** made to appear to have used the new number.

### L-4 — Package-name / pending-ADR wording — **RESOLVED**
IMPLEMENTATION-SLICES.md, RECOMMENDED-ARCHITECTURE.md and ADR-0024 now state that ADR-0024 §Decision item 8
ratifies the **`internal/mcp/*` namespace and boundary**, while the **exact leaf-package names remain `[REC]`,
subject to implementation review, even after ADR-0024 is Accepted.**

### L-5 — MCP-T-056 prose control — **RESOLVED**
THREAT-MODEL.md §11: `MCP-T-056` control cell clarifies `MCP-OPS-004` is the only in-product control (documented
V1 limitation, R-1) and that "network egress policy" is a customer-owned **compensating control outside
Culvert**, not an MCP requirement ID.

### L-6 — `SOURCE REVIEW REQUIRED` marker — **NOTED (reviewer action)**
The PR-11/PR-12 fold in IMPLEMENTATION-SLICES.md retains its `SOURCE REVIEW REQUIRED` marker; it is consistent
with D-12 and closes at PR-0 sign-off. This is a human reviewer action, not a documentation defect to rewrite.

---

## H-1 mandated coverage → threat / requirement

| Mandated item | Threat | Requirement |
|---|---|---|
| Malformed JSON-RPC envelopes | MCP-T-057 | MCP-PROTO-001,013 |
| Ambiguous / conflicting JSON-RPC fields | MCP-T-058 | MCP-PROTO-001 |
| Duplicate object keys / parser differentials | MCP-T-058 | MCP-PROTO-001 |
| Invalid request/response/notification classification | MCP-T-059 | MCP-PROTO-002 |
| Unknown / unsupported methods | MCP-T-059 | MCP-PROTO-002 |
| Request-ID confusion / response mis-correlation | MCP-T-060 | MCP-PROTO-003 |
| Integer/string/null ID edge cases | MCP-T-060 | MCP-PROTO-003 |
| Batch behavior (or explicit rejection) | MCP-T-061 | MCP-PROTO-004 |
| Framing ambiguity | MCP-T-062 | MCP-PROTO-005 |
| Truncated / partial messages | MCP-T-062 | MCP-PROTO-005,013 |
| Oversized messages | MCP-T-063 | MCP-PROTO-006 |
| Excessive JSON depth / field count / string size | MCP-T-063 | MCP-PROTO-006 |
| Numeric overflow / pathological numbers | MCP-T-064 | MCP-PROTO-007 |
| Unicode normalization / invalid UTF-8 | MCP-T-065 (+057) | MCP-PROTO-001 |
| Version-negotiation confusion | MCP-T-066 | MCP-PROTO-010 |
| Downgrade to unsupported/weaker semantics | MCP-T-067 | MCP-PROTO-010 |
| Version-adapter differential behavior | MCP-T-068 | MCP-PROTO-011 |
| Session / protocol-state confusion | MCP-T-069 | MCP-PROTO-012 |
| Cancellation races | MCP-T-070 | MCP-PROTO-012 |
| Duplicate completion | MCP-T-071 | MCP-PROTO-003,012 |
| Reconnect / replay of protocol messages | MCP-T-072 | MCP-PROTO-012 |
| Slow input / resource exhaustion | MCP-T-073 | MCP-PROTO-005,008 |
| Panic / crash / uncontrolled allocation | MCP-T-074 | MCP-PROTO-009,013 |

---

## Follow-up remediation (round 2 — independently-verified findings 1–7)

Applied on top of the round-1 commit `5c59e04`. Documentation-only; ADR-0024 stays `Proposed`; PR-1 stays
protocol-kernel-only; PR-5 stays the first listener runtime.

1. **Durability (F-1/F-2) restored.** `MCP-EVENT-001` now mandates a **local encrypted, bounded, durable
   spool on every relevant Data Plane**, with external export **additive, never a substitute**.
   `MCP-EVENT-002` and the EVENT-MODEL §4a table make the critical **write/destructive/config/credential**
   classes **fail closed AND enter degraded mode + alert + integrity-protected loss counter** (both, not
   either). Aligned across SECURITY-REQUIREMENTS, EVENT-MODEL (§4, §4a, CRITICAL constraint, §6 flow),
   DFD-9, and ADR-0024 §D-5.
2. **Connector gates reassigned.** `MCP-CONNECT-001/002/004` → **PR-C** (post-V1 connector slice);
   `MCP-CONNECT-003` → **Future DMZ Architecture & Production-Readiness Gate**; **PR-11 stays
   Shadow/Canary only**. Updated SECURITY-REQUIREMENTS, TEST-TRACEABILITY-MATRIX, IMPLEMENTATION-SLICES
   (PR-C refined + explicit Future DMZ gate slice).
3. **`MCP-INSP-008` split.** PR-1 = the **pure, listener-independent Origin/Host validation primitive +
   test harness (no listener)**; **new `MCP-INSP-009`** (PR-5) = listener binding, configured interfaces,
   host allowlist at accept, and **E2E rebinding enforcement**. The false "an inbound listener ships in
   PR-1" claim is removed (SECURITY-REQUIREMENTS, THREAT-MODEL, TEST-TRACEABILITY, IMPLEMENTATION-SLICES
   PR-1/PR-5, GO-NO-GO).
4. **`MCP-PROTO-012` split.** PR-1 = protocol lifecycle, cancellation, reconnect, **immutable opaque
   session context (no identity)**; **new `MCP-ID-008`** (PR-3) = resolved-identity binding + no
   mid-session rebind. **PR-1 retains identity as a non-goal** (stated in the PR-1 slice and PROTO-012).
5. **UTF-8/protocol-token control added (accurate semantics).** **New `MCP-PROTO-014`** (PR-1): reject
   invalid UTF-8; compare method tokens **exactly** against the version allowlist; reject non-ASCII method
   names until D-1 permits them; opaque user/server/tool identifiers follow **field-specific**
   canonicalization and are **not** globally normalized by the kernel. **NFC is not claimed as a
   homoglyph/confusable defense** — confusable handling for any later Unicode-identifier profile needs an
   explicit field-level policy + dedicated tests. Covers `MCP-T-057`/`MCP-T-065` without overstating the
   control.
6. **Traceability completeness.** Explicit §1a rows added for `MCP-AUTH-008`, `MCP-EVENT-004`,
   `MCP-EVENT-006`, `MCP-CONNECT-004`; the "Unit | all" row is annotated as **not** requirement-specific
   proof; the outdated "no IDs added/removed" impression is corrected (three IDs added — see the callout
   above).
7. **THREAT-MODEL residual R-1** corrected from **D-8 → D-7** (the local-MCP/stdio-localhost roadmap
   decision; D-8 is the distinct connector model).

**Follow-up IDs added:** `MCP-PROTO-014`, `MCP-INSP-009`, `MCP-ID-008` (requirements 88 → **91**). No ID
removed; no duplicates/orphans (re-validated). No new threat/DFD/abuse-case IDs were required.

## Files changed

**ADR (renamed + edited):** `docs/adr/0023-mcp-agent-security-gateway-trust-boundary.md` **→**
`docs/adr/0024-mcp-agent-security-gateway-trust-boundary.md` (collision renumber; numbering note L-3; PR-1
protocol-kernel scope note; D-14 reference; package-name clarification L-4). The working tree deletes the
`0023-mcp` path and adds the `0024-mcp` path; a human `git add -A` finalizes the rename (no stage/commit was
performed here).

**`docs/design/mcp/` — substantive remediation:** `THREAT-MODEL.md`, `SECURITY-REQUIREMENTS.md`,
`TEST-TRACEABILITY-MATRIX.md`, `ATTACK-TREES.md`, `ABUSE-CASES.md`, `DATA-FLOW-DIAGRAMS.md`, `CI-GATES.md`,
`IMPLEMENTATION-SLICES.md`, `GO-NO-GO-CHECKLIST.md`, `PROTOCOL-COMPATIBILITY.md`, `OPEN-DECISIONS.md`,
`RECOMMENDED-ARCHITECTURE.md`, `VERIFIED-REPOSITORY-CONTEXT.md`, `PR0-REVIEW-CHECKLIST.md`, `README.md`;
**new** `PR1-READINESS-REMEDIATION.md`; **brought in verbatim** `PR1-READINESS-REVIEW.md`.

**`docs/design/mcp/` — mechanical ADR renumber only (0023→0024, no other change):** `PRODUCT-SCOPE.md`,
`CONFIG-SURFACE-MATRIX.md`, `EVENT-MODEL.md`, `ON-PREM-CONNECTIVITY.md`, `ROLLOUT-AND-ROLLBACK.md`,
`SSDLC-CONTROL-MAPPING.md`, `AUTH-AND-CREDENTIAL-MODEL.md`, `ADR-PROPOSAL-mcp-trust-boundary.md`.

Untouched (no reference to the MCP ADR): `BLUEPRINT.md`, `MCP-POLICY-MODEL.md`, `TOOL-DISCOVERY-AND-DRIFT.md`,
`CP-DP-HA-MODEL.md`, `SUPPLY-CHAIN-SECURITY.md`, `OPERATIONS-AND-SUPPORT.md`, `source/`, `assets/`. The
unrelated `docs/adr/0023-durable-config-publication.md` (open PR #854) is **not** on this branch and was
**not** touched.

---

## Remaining human decisions / PR-1 blockers (unchanged by this remediation)

1. **ADR-0024 ratification** by ARB + Security Architecture (ADR stays `Proposed`) — the hard PR-1 entry gate.
2. **PR-0 reviewer sign-offs** (`PR0-REVIEW-CHECKLIST.md`) across all roles.
3. **D-1 (protocol-version baseline)** externally verified + human-approved *before* PR-1 — and therefore the
   **compatibility gate cannot be green** until D-1 closes.
4. **D-14 (protocol-kernel limit values + batch policy)** numeric values fixed with evidence during PR-1.
5. **Repository build/test baseline** run and recorded before PR-1 code.

This remediation makes PR-1's acceptance criteria **verifiable** (every PR-1 acceptance item now references a
real requirement ID with a defined blocking gate home); it does **not** clear the human gates above.

## Validation

See the "Validation" section results recorded in the delivering message / commit description. Markdown link,
threat-ID, requirement-ID, duplicate-ID, and undefined-reference checks pass; no file outside
`docs/adr/0024-*` and `docs/design/mcp/**` changed; no `.go/.mod/.sum/.yml/.yaml`/config/binary file changed;
the source DOCX and diagram assets are byte-unchanged.

---

## Main-sync reconciliation (round 4 — merge with current `origin/main`)

Merged current `origin/main` (`7791c706`) into the review branch with `--no-ff` (no rebase, no force-push;
published history preserved). Reconciliation outcomes:

- **OpenAPI ADR renumber (main governance):** `main` renamed the OpenAPI-contract ADR from the former
  `ADR-0007-openapi-contract.md` to `docs/adr/0018-openapi-contract.md` (the `0007` slot is now solely the
  secret-containment ADR). Every MCP reference where **ADR-0007 meant the OpenAPI contract** was updated to
  **ADR-0018 / `docs/adr/0018-openapi-contract.md`** (CI-GATES, SSDLC, VERIFIED-REPOSITORY-CONTEXT, and
  ADR-0024 `Related` + `Numbering`). References where **ADR-0007 means the secret-containment ADR**
  (`docs/adr/0007-secret-containment-boundary.md`) were **left unchanged** (CONFIG-SURFACE-MATRIX,
  AUTH-AND-CREDENTIAL-MODEL, VERIFIED-REPOSITORY-CONTEXT secret row).
- **Conflicts resolved (2):** `VERIFIED-REPOSITORY-CONTEXT.md` (kept the PR-1 ⟳ citation fixes AND main's
  ADR-0018 rename) and `ADR-PROPOSAL-mcp-trust-boundary.md` (kept the superseded-by-ADR-0024 pointer — the
  proposal is promoted on this branch). `CI-GATES.md`, `SSDLC-CONTROL-MAPPING.md` and
  `AUTH-AND-CREDENTIAL-MODEL.md` auto-merged, keeping both main's ADR-0018 fix and the MCP remediation.
- **Traceability closed to 91/91:** explicit §1a rows added for the 12 previously token-unreachable
  requirements — genuine-threat rows for `MCP-ID-001/004/005`, `MCP-CRED-003`, `MCP-CPDP-001`,
  `MCP-POLICY-005/007`, `MCP-TOOL-005`, `MCP-OPS-003`; a **clearly labeled cross-cutting posture block**
  (no invented threat) for `MCP-SUPPLY-001/002/004`. Independently recomputed: **91 defined / 91 reachable /
  0 missing / 0 duplicates** (generic "Unit"/"Integration" harness rows excluded from proof).
- **ID provenance disambiguated:** first PR-1 remediation allocated `MCP-T-057..074` + `MCP-PROTO-001..013`;
  the follow-up allocated `MCP-PROTO-014` + `MCP-INSP-009` + `MCP-ID-008`. `MCP-PROTO-014` is counted once.
- **Preserved review:** `PR1-READINESS-REVIEW.md` is kept **byte-identical**; its one `ADR-0007-openapi-
  contract.md` mention is a point-in-time observation that was accurate when authored (pre-rename) and is
  not an operational cross-reference, so it is intentionally not edited.
- **ADR-0024 remains `Status: Proposed`; unique across all `origin/main` refs and open PRs.**

---

## Round 5 — automated-review remediation on the main-synced head (`8d8cfc26`)

Four findings raised by the automated reviewer against the synced head (3×P1, 1×P2). All are
documentation-consistency defects in this package; each is fixed at the canonical source **and** in every
divergent copy, so an implementer cannot follow a stale statement.

### R5-1 (P1) — RFC 8707 validated through the authorization flow, not by an in-token claim

**Finding.** RFC 8707 `resource` is an **authorization/token-request parameter**. A protected resource
receives the resulting *audience-restricted access token*, not a token that necessarily carries a resource
indicator. Requiring every MCP token to "carry an RFC 8707 resource indicator" would fail spec-compliant
JWTs that carry only `aud`, fail opaque tokens validated by RFC 7662 introspection, or force a private claim.

**Fix.** The control is restated as a two-sided contract: **(a)** Culvert's registered clients send
`resource=<canonical Culvert-controlled MCP resource URI>` on authorization/token requests (RFC 8707 §2) and
Culvert publishes that same URI in its protected-resource metadata; **(b)** Culvert verifies the **resulting**
audience restriction from **standard** metadata — `aud` for JWT access tokens (RFC 9068), or the introspection
response's `aud`/resource metadata for opaque tokens (RFC 7662) — rejecting any token whose audience names the
upstream business MCP server or another non-Culvert service. Culvert **MUST NOT** require a non-standard
in-token resource claim; an unrestricted (`aud`-less) token **MUST NOT** authorize write/high-risk operations.
The intent of ADR-0024 §D-2 (Culvert is the token recipient; upstream is a policy/broker input) is unchanged —
only the enforcement mechanism is made standards-accurate.

Updated: `SECURITY-REQUIREMENTS.md` (MCP-AUTH-003, incl. verification over **both** token forms plus an
`aud`-less-token negative and an outbound-`resource` assertion), `ADR-0024` §D-2 item 2,
`AUTH-AND-CREDENTIAL-MODEL.md` (D-2 status quote, §4 Resource row, §4 token-state bullets, §6 Hard
Requirements rule 4, §7 sequence diagram), `PROTOCOL-COMPATIBILITY.md` (which also still carried a residual
"specific target MCP server" phrasing — now cleared),
`OPEN-DECISIONS.md` D-2 closure, `TEST-TRACEABILITY-MATRIX.md` MCP-T-004 row, `SSDLC-CONTROL-MAPPING.md` V2.

### R5-2 (P1) — stale upstream-resource recommendation in the repository-context doc

**Finding.** `VERIFIED-REPOSITORY-CONTEXT.md` §5 still normatively recommended validating
`audience/resource = the MCP server` — exactly the upstream-resource behavior ADR-0024 §D-2 forbids and the
new negative test rejects.

**Fix.** The `[REC]` now names the **canonical Culvert-controlled MCP resource URI** (which may encode the
target server ID), states the upstream server is a policy + broker-scope input and never the token's
recipient, and cites ADR-0024 §D-2 / MCP-AUTH-003. The §6 ID-token "Gap" cell is corrected the same way.

### R5-3 (P1) — circular V1 connectivity release gate removed

**Finding.** V1 Production Qualification required the complete test taxonomy and every domain gate green,
and the Go/No-Go **On-prem connectivity** domain required local **+ connector + DMZ** deployments validated.
Since PR-C (connector) and the Future DMZ gate cannot start until **after** V1 GA, V1 GA transitively
depended on post-GA work — an unsatisfiable gate.

**Fix.** V1 qualification is scoped to **Model A (`local-client`)**:
- `GO-NO-GO-CHECKLIST.md` — **On-prem connectivity** is Model-A-only, names connector/DMZ as explicitly out
  of V1 scope with their owning gates, and makes "V1 GA blocked on connector/DMZ evidence" an explicit
  **NO-GO** (the circularity itself is now a listed failure condition). The **Connectivity** domain row is
  scoped the same way.
- `IMPLEMENTATION-SLICES.md` — Production Qualification is bounded to V1/Model-A scope, is **explicitly not
  dependent** on PR-C or the Future DMZ gate, covers only the Model-A/tenant-binding aspect of
  MCP-CONNECT-004, and requires the taxonomy green **for PR-0..PR-11 rows** — PR-C / Future-DMZ rows are
  **deferred, not waived**: they stay tracked as **Missing** and block *their own* gate.
- `ROLLOUT-AND-ROLLBACK.md` §6 — the Connectivity evidence row (which Production Qualification aggregates
  from) is scoped to Model A, so the circularity is closed at the source too.

### R5-4 (P2) — deferred connectivity modes rejected in V1, not merely defaulted

**Finding.** The `mcp_gateway_connector_mode` validation enum still **accepted** `outbound-connector` and
`dmz-endpoint` while the same row said Model A is the only V1 mode and scheduled validation tests post-V1 —
so an operator could select and snapshot a mode with no implementation and no security gate.

**Fix.** `CONFIG-SURFACE-MATRIX.md` — the V1 accepted value is **`local-client` only**; the other two are
**reserved names V1 validation MUST REJECT** ("not supported in this release") across API, YAML/env/flag
parsing, config import **and snapshot apply** (a V1 DP must reject such a snapshot, never silently
downgrade). V1 **negative tests are assigned to PR-9** (config surface); the positive Model-B/Model-C
acceptance tests remain with PR-C / the Future DMZ gate. Constraint class raised to **Override** (no
operator path out of `local-client`). `ON-PREM-CONNECTIVITY.md` records the same enforcement consequence, so
"not supported in V1" is enforced rather than merely defaulted.

**Unchanged by round 5:** ADR-0024 remains `Status: Proposed`; `PR1-READINESS-REVIEW.md` remains
byte-identical; no requirement or threat IDs were added or removed (still 74 threats / 91 requirements /
91 of 91 reachable / 0 duplicates / 0 undefined); no code, CI, dependency, runtime, config-implementation or
binary change; PR-1 is not begun.

---

## Round 6 — follow-on findings introduced by round 5 (`2cabc33a`)

Two P1 findings raised against the round-5 head. Both are defects **in the round-5 edits themselves**, so
they are recorded separately rather than folded into round 5.

### R6-1 (P1) — an absent audience must be rejected for every operation, not just write/high-risk

**Finding.** Round 5's MCP-AUTH-003 said an unrestricted (`aud`-less) token "MUST NOT authorize write/
high-risk operations". That carve-out (inherited from the pre-round-5 "unbound tokens denied for write/
high-risk" phrasing) is weaker than the same requirement's own "verify on every request" clause and weaker
than **MCP-AUTH-002**'s unconditional audience requirement: PR-3 could satisfy the matrix while **accepting**
a read/low-risk request bearing a JWT with no `aud`, or an opaque token whose introspection response omits
`aud` — a token that cannot be shown to target Culvert at all.

**Fix.** An **absent audience is now a rejection for every operation class** (fail closed), stated as
MCP-AUTH-003 clause (c) and propagated to `ADR-0024` §D-2 item 2, `AUTH-AND-CREDENTIAL-MODEL.md` §4
token-state bullets, `PROTOCOL-COMPATIBILITY.md` (which still carried the carve-out) and the
`TEST-TRACEABILITY-MATRIX.md` MCP-T-004 row. Verification now explicitly requires the `aud`-less negative on
a **read/low-risk** request as well as a write/high-risk one, over **both** token forms (JWT without `aud`;
introspection response omitting `aud`). Note the distinction retained: a **mismatched** audience and an
**absent** audience are both rejections — the requirement no longer treats "absent" as a lesser case.

### R6-2 (P1) — V1 Model A tenant binding cited a requirement with no V1 test chain

**Finding.** Round 5 scoped V1 qualification to "the Model-A/tenant-binding aspect of **MCP-CONNECT-004**",
but that requirement is defined for **connector/DMZ sessions** and gated at **PR-C / the Future DMZ gate**,
and neither traceability row for it carries a Model A case. Combined with round 5's own rule that the
taxonomy must be green only for **PR-0..PR-11** rows, V1 Production Qualification asserted a tenant-binding
condition for which it had **no V1 test or evidence chain** — a gate that could not be cleared as written.

**Fix.** V1 Model A tenant binding is retargeted to **`MCP-ID-007`** — "tenant identity **MUST** be bound and
enforced on **every call**; cross-tenant access **MUST** be denied", owned by **PR-3** with tenant-escape
tests — which is inside the PR-0..PR-11 range and therefore has a real V1 evidence chain.
`IMPLEMENTATION-SLICES.md` (Production Qualification) and `GO-NO-GO-CHECKLIST.md` (On-prem connectivity) now
state explicitly that **no `MCP-CONNECT-*` requirement is V1 evidence** and that `MCP-CONNECT-004` is not the
V1 control, so the connector/DMZ family stays wholly behind its own gates. `MCP-CONNECT-004`'s definition and
slice ownership are unchanged — round 6 stops V1 from *claiming* it, rather than broadening it.

**Unchanged by round 6:** ADR-0024 remains `Status: Proposed`; `PR1-READINESS-REVIEW.md` remains
byte-identical; no requirement or threat IDs added/removed (74 threats / 91 requirements / 91 of 91
reachable / 0 duplicates / 0 undefined); documentation only; PR-1 not begun.

---

## Round 7 — stale mappings left behind by the requirement splits (`d5a84cd4`)

Five findings (2×P1, 2×P2 from the protocol reviewer; 1 from the repository review bot). Every one is the
**same class of defect**: earlier rounds *split* a requirement into a PR-1 primitive and a later
enforcement/identity control, but downstream artifacts still mapped the threat to the **PR-1-only** half —
so a threat could be reported closed one or more slices too early. The splits themselves are unchanged;
round 7 propagates them.

### R7-1 (P1) — `MCP-INSP-009` / PR-5 propagated to every live-listener and DMZ mapping

**Finding.** `MCP-INSP-008` is a **pure validation primitive** (PR-1, binds no listener) while
`MCP-INSP-009` owns listener binding + host allowlist + E2E rebinding proof (PR-5 / Future DMZ gate). Several
artifacts still mapped listener and DMZ enforcement to `MCP-INSP-008` alone, so the rebinding threats
(MCP-T-031/052/055) could be reported covered once only the unit-tested function existed.

**Fix — propagated everywhere, not only the cited lines.** `ATTACK-TREES.md` (the DMZ-abuse leaf **and** the
AT-1 L2 bypass leaf + its residual-risk narrative), `ABUSE-CASES.md` (the local-listener rebinding case and
the connector/DMZ case — both now state that a PR-1 unit test does **not** close them), `ON-PREM-
CONNECTIVITY.md` (the D-8/D-9 posture block, the Model C control table, §7 inbound/outbound discussion, the
MCP-T-031 mapping, and §8 cross-references), `DATA-FLOW-DIAGRAMS.md` (DFD-12 local-listener note and the
DFD-14 DMZ note), `OPEN-DECISIONS.md` (D-9 evidence, both blocks), and `CI-GATES.md` (the master-table row,
which omitted `MCP-INSP-009` and PR-5 entirely).

### R7-2 (P1) — `ON-PREM-CONNECTIVITY.md` §2 retargeted to `MCP-ID-007`

**Finding.** Round 6 retargeted V1 Model A tenant binding to `MCP-ID-007` in the checklist and the
Production Qualification slice, but §2 of the connectivity document still said every LAN/VPN-local session
engages `MCP-CONNECT-004` — contradicting both the connector/DMZ-only definition of that ID and round 6's
own "no `MCP-CONNECT-*` requirement is V1 evidence" statement. An implementer following the connectivity
document would have put Model A back on a post-V1 test chain.

**Fix.** §2 now engages **`MCP-ID-007`** (PR-3, tenant-escape tests) and states explicitly why
`MCP-CONNECT-004` is *not* the V1 control here, cross-referencing the slice and checklist.

### R7-3 (P2) — attack-tree session leaf split for `MCP-ID-008`

**Finding.** `ATTACK-TREES.md` AT-10 mapped the whole protocol/session-state leaf to `MCP-PROTO-012` and
declared **all** leaves gated at PR-1 — but round 2 moved resolved-identity binding to `MCP-ID-008` at PR-3,
so the mid-session-rebind branch was treated as closed two slices early.

**Fix.** The leaf is **split**: protocol-state confusion (lifecycle/cancellation/reconnect, identity-free) →
`MCP-PROTO-012` at PR-1; **mid-session identity rebind** → **`MCP-ID-008` at PR-3**, annotated as *not*
closable by `MCP-PROTO-012`. The "all leaves are gated at PR-1" sentence is corrected to carve out the
identity leaf. `MCP-T-069` is now shown as split across the two halves consistently with the threat model.

### R7-4 (P2) — `MCP-PROTO-014` wired into the blocking PR-1 gates

**Finding.** The three blocking PR-1 gate rows in `CI-GATES.md` never referenced `MCP-PROTO-014`, and none
named its fixtures — so PR-1 could satisfy every enumerated gate while the UTF-8/protocol-token verification
stayed unwired, despite the traceability matrix assigning it to the PR-1 gate.

**Fix.** `MCP-PROTO-014` is added to the **structural + protocol-state suite** row with its fixtures named
explicitly (invalid-UTF-8 rejection; exact byte-for-byte method-token comparison with no normalization
folding; non-ASCII-method-name rejection pending D-1; a test proving the kernel does **not** globally
normalize opaque identifiers), and to the **fuzz gate** row (the corpus must include invalid-UTF-8 and
non-ASCII/normalization-sensitive method tokens). Both master-table rows updated to match.

### R7-5 — DFD-15 no longer implies identity binding at PR-1

**Finding (review bot).** DFD-15 labelled the `MCP-PROTO-012` state machine "one identity/session", which
contradicts PR-1's identity-agnostic design and the `MCP-ID-008` split.

**Fix.** The node now reads "immutable **opaque** session context — no resolved identity; lifecycle /
cancellation / reconnect", the error edge drops "rebind", and the DFD-15 preamble states that the identity
half of MCP-T-069 is **not** closed by this diagram (it is `MCP-ID-008` at PR-3).

**Unchanged by round 7:** no requirement or threat was added, removed or redefined — only their *mappings*
were corrected. ADR-0024 remains `Status: Proposed`; `PR1-READINESS-REVIEW.md` remains byte-identical;
74 threats / 91 requirements / 91 of 91 reachable / 0 duplicates / 0 undefined; documentation only; PR-1 not
begun.

---

## Round 8 — the identity split's remaining consumers (`c9ef5ec4`)

Two P2 findings, both the **same propagation class as round 7**: the `MCP-PROTO-012` → `MCP-ID-008` split
was applied at the requirement, attack-tree and DFD layers, but two consumers still described the *old*
model.

### R8-1 (P2) — PR-1 session semantics no longer depend on PR-3 identity work

**Finding.** `PROTOCOL-COMPATIBILITY.md` §5 — the contract an implementer builds PR-1 from — still said a
session "is created **only after identity resolution** attaches a principal", called identity binding a
**protocol-layer** behavior, and required the **kernel** to re-verify the bearer token on reconnect. Those
semantics contradict the identity-agnostic kernel and would have made PR-1 depend on PR-3 authentication.

**Fix.** §5 is re-cut **by layer**:
- **Session establishment (PR-1, identity-agnostic)** — the protocol session is created once version
  negotiation + the Origin/Host check succeed, producing an **immutable opaque context carrying no resolved
  identity** (`MCP-PROTO-012`); the kernel never resolves/attaches/inspects a principal, so **PR-1 has no
  dependency on PR-3**.
- **Identity attachment (PR-3)** — a new row; principal attachment and the ambiguous-identity write/high-risk
  denial (`MCP-ID-005`) are a layer **above** the kernel.
- **Session identity binding (PR-3)** — one resolved identity per session, no mid-flight rebind, owned by
  **`MCP-ID-008`**, annotated that the kernel *cannot* express this because its context is opaque.
- **Reconnect** — split: at PR-1 the kernel re-runs the `MCP-INSP-008` Origin/Host check and never replays
  trust, **with no token or identity check** (it holds neither); from PR-3 the identity/auth layer re-verifies
  token expiry and re-establishes the `MCP-ID-008` binding.

### R8-2 (P2) — `MCP-T-008` cross-user session confusion now names its enforcing control

**Finding.** `MCP-ID-008` declares control over **both** MCP-T-069 and **MCP-T-008**, but the canonical
MCP-T-008 rows (`THREAT-MODEL.md` §11 risk register and the `TEST-TRACEABILITY-MATRIX.md` §1 chain) still
listed only `MCP-AUTH-007` + `MCP-ID-006` — and `MCP-ID-006` is *optional* assurance/step-up behavior, which
does not enforce the one-identity/no-rebind invariant. The cross-user threat could therefore be reported
traced without requiring the identity-binding tests.

**Fix.** Both rows now lead with **`MCP-ID-008`** as the **enforcing** control and label `MCP-ID-006`
**contributory only**; the traceability row adds an explicit **identity-rebind negative test** (mid-session
identity change denied) with matching evidence. The forward mapping (`MCP-ID-008` → MCP-T-069,008) and the
reverse mapping now agree in both directions.

**Unchanged by round 8:** no requirement or threat added, removed or redefined — mappings and layer
attribution only. ADR-0024 remains `Status: Proposed`; `PR1-READINESS-REVIEW.md` remains byte-identical;
74 threats / 91 requirements / 91 of 91 reachable / 0 duplicates / 0 undefined; documentation only; PR-1 not
begun.

---

## Round 9 — the last two split consumers (`dc769863`)

Two P2 findings, again the same propagation class — and both in **consumer** documents rather than the
definitions.

### R9-1 (P2) — ADR-0024 §D-9 item 6 no longer lets PR-1 satisfy inbound protection

**Finding.** The ADR is the *binding* document, and its §D-9 item 6 still read "Inbound Origin/Host
**protection** (`MCP-INSP-008`) remains a **PR-1** Protocol Kernel requirement" — while Part 1 item 7 and
`SECURITY-REQUIREMENTS.md` define that ID as a **pure, listener-independent primitive** and assign actual
enforcement to `MCP-INSP-009` at PR-5. An implementer following the ADR could report the D-9 control
satisfied after PR-1, with no listener enforcing anything.

**Fix.** Item 6 now states the defence is **split across two layers** — the `MCP-INSP-008` validation
primitive at PR-1 (unit-tested without a socket) and the `MCP-INSP-009` listener-side
enforcement/protection at PR-5 (bind configured interfaces, allowlist at accept, **E2E** rebinding proof) —
and adds explicitly that **PR-1 binds no listener, so the item is NOT satisfied by PR-1 alone**: MCP-T-031/055
(and MCP-T-052 for any future DMZ) close only when `MCP-INSP-009` ships. It also directs that the words
"protection" and "enforcement" be reserved for `MCP-INSP-009`, so the wording cannot regress.

### R9-2 (P2) — SSDLC threat range extended through `MCP-T-074`

**Finding.** `SSDLC-CONTROL-MAPPING.md` (BSIMM **Intelligence** row) still described the canonical threat
register as `MCP-T-001..056`, so an SSDLC/PR-0 evidence review following that mapping would exclude **all 18**
new PR-1 protocol-kernel threats — the very threats the PR-1 entry gate rests on.

**Fix.** The range is now `MCP-T-001..074`, with an inline note that it **includes `MCP-T-057..074`**, that
those are part of the PR-1 entry gate, and that they must not be excluded from SSDLC/PR-0 evidence review.
A repository-wide sweep for other stale `..056` ranges and stale threat/abuse-case counts found none; the only
remaining `MCP-T-001..056` mention is this ledger's own historical note about the *prior* allocation, which is
accurate as written.

**Unchanged by round 9:** no requirement or threat added, removed or redefined. ADR-0024 remains
`Status: Proposed`; `PR1-READINESS-REVIEW.md` remains byte-identical; 74 threats / 91 requirements / 91 of 91
reachable / 0 duplicates / 0 undefined; documentation only; PR-1 not begun.

### Convergence note (rounds 5–9)

Every finding in rounds 5–9 shares one root cause: a requirement was **split or re-scoped** at its definition
site (`MCP-INSP-008`→`009`, `MCP-PROTO-012`→`MCP-ID-008`, `MCP-CONNECT-004`→`MCP-ID-007`,
`MCP-T-001..056`→`..074`) without updating every downstream consumer, letting a threat read as closed one or
more slices early. Severity and volume have fallen monotonically (4 P1 → 2 P1 → 2 P1 + 2 P2 → 2 P2 → 2 P2),
which is consistent with convergence. **A future editor making any similar split MUST sweep every consumer —
threat register, traceability chain, attack trees, abuse cases, DFDs, CI gate rows, the connectivity/protocol
contracts, and ADR-0024 itself — not only the requirement table.**

---

## Round 10 — the two consumers the round-7 sweep mis-judged (`1c6b37f0`)

Two P2 findings. Both are instances the **round-7 sweep deliberately skipped** as "accurate statements about
the primitive" or "not a listener mapping" — that judgement was wrong in context, which is itself worth
recording: the sweep instruction from round 9 is only useful if applied to *contextual* meaning, not just to
literal wording.

### R10-1 (P2) — V1 tenant-binding config rows retargeted to `MCP-ID-007`

**Finding.** Rounds 6–7 moved `MCP-CONNECT-004` wholly to PR-C / the Future DMZ gate and recorded that **no
`MCP-CONNECT-*` requirement is V1 evidence** — but the V1 `mcp_gateway_tenant_binding_mode` row in
`CONFIG-SURFACE-MATRIX.md` was still governed by `MCP-CONNECT-004` while its test stayed at PR-3/PR-11. The
configuration contract therefore had **no V1 requirement/evidence chain** for a setting that ships in V1.

**Fix.** Both tenancy rows now cite **`MCP-ID-007`** as the V1 control with **PR-3 tenant-escape evidence**,
and each states that `MCP-CONNECT-004` is *not* the V1 requirement for the row — it governs it only once the
connector/DMZ models ship. The `tenant_binding_mode` verification column is split: **V1 evidence = PR-3
(MCP-ID-007)**, with PR-11 adding Model-A rollout coverage. (`mcp_gateway_per_tenant_overrides` had the same
defect and is fixed in the same pass, though it was not cited.)

### R10-2 (P2) — Model C posture paragraph no longer implies PR-1 enforcement

**Finding.** The Model C (§4) V1-posture blockquote still read "Inbound Origin/Host anti-rebinding
(`MCP-INSP-008`) remains a **PR-1** requirement". In a *public-listener* context that reads as the
enforcement control, so a connectivity review could treat the live-listener control as satisfied by PR-1's
primitive-only work — exactly what ADR-0024 §D-9 item 6 now forbids.

**Fix.** The paragraph describes the **two-layer split** and makes the gate explicit: the `MCP-INSP-008`
primitive at PR-1 (pure, no socket) vs `MCP-INSP-009` listener-side enforcement at **PR-5** (Model A local
listener) / the **Future DMZ gate** (Model C public listener), plus the sentence **"PR-1 binds no listener, so
the live-listener control for this model is NOT satisfied by PR-1 work."**

**Swept in the same pass (not cited, same defect):** the §8 implementation-sequencing note and the §9 risk
note both attributed inbound Origin/Host defence to `MCP-INSP-008` alone; both now name the primitive **and**
its `MCP-INSP-009` enforcement layer. The §2 cross-reference likewise now points at both IDs.

**Unchanged by round 10:** no requirement or threat added, removed or redefined. ADR-0024 remains
`Status: Proposed`; `PR1-READINESS-REVIEW.md` remains byte-identical; 74 threats / 91 requirements / 91 of 91
reachable / 0 duplicates / 0 undefined; documentation only; PR-1 not begun.

**Amendment to the round-9 convergence note.** Two rounds of findings came from instances a sweep *saw and
dismissed*. The standing instruction is therefore strengthened: when a requirement is split or re-scoped, every
mention must be re-read **in its surrounding context** — a sentence that is literally true of the PR-1
primitive can still license a wrong closure claim when it sits in a listener, DMZ or config-contract section.
Prefer naming **both** layers everywhere over judging a mention harmless.

---

## Round 10b — proactive contextual sweep (self-initiated, no finding filed)

Immediately after round 10, the amended rule ("re-read every mention of a split requirement **in context**;
prefer naming both layers over judging a mention harmless") was applied **as an audit** rather than waiting
for the next review round. Eight further bare/context-risky mentions were found and fixed. None was reported
by a reviewer — this is the rule working prospectively.

| Location | Why it was risky | Fix |
|---|---|---|
| `IMPLEMENTATION-SLICES.md` D-8 header note | "Inbound Origin/Host validation (`MCP-INSP-008`) remains in PR-1" — sits directly above the slice table an implementer reads first | Names both layers + "PR-1 binds no listener" |
| `OPEN-DECISIONS.md` D-9 **closure block** | Same bare phrasing inside the *decision of record* for the DMZ | Two-layer split + "this decision's listener controls are NOT satisfied by PR-1 alone" (ADR-0024 §D-9 item 6) |
| `PR0-REVIEW-CHECKLIST.md` | A reviewer ticking "Origin/Host anti-rebinding is a stated new requirement (`MCP-INSP-008`)" would sign off the listener control on primitive-only text | Requires **both** IDs stated; "tick only if both — PR-1 alone does not close MCP-T-031/055" |
| `PROTOCOL-COMPATIBILITY.md` §4 PR-1/PR-5 split note | `MCP-INSP-008` listed bare as a PR-1 requirement | Marks it the *primitive*; notes `MCP-INSP-009` listener enforcement is PR-5 |
| `PROTOCOL-COMPATIBILITY.md` §8 cross-version invariants | `MCP-INSP-008` listed as an invariant that "applies identically" — an enforcement claim | Names the primitive **and** its `MCP-INSP-009` enforcement once a listener exists |
| `SECURITY-REQUIREMENTS.md` decision-provenance header | Mapped "host-allowlist + Origin-per-protocol **on every listener**" (D-9) to `MCP-INSP-008` alone | Adds `MCP-INSP-009` with its PR-5 / Future-DMZ gate |
| `THREAT-MODEL.md` §11 `MCP-T-010` | Controls read `MCP-ID-007, MCP-CONNECT-004` with no V1/post-V1 distinction | `MCP-ID-007` marked the **V1/Model-A** control (PR-3); `MCP-CONNECT-004` marked connector/DMZ-only (PR-C / Future DMZ gate) |

Mentions deliberately **left** as-is are those where `MCP-INSP-008` is the subject of a requirement statement
about the primitive itself (its own row in `SECURITY-REQUIREMENTS.md`, the `MCP-PROTO-012` reconnect re-check,
the PR-1 primitive test rows) — in those, the primitive *is* the correct referent and no listener claim is
implied.

**Unchanged:** no requirement or threat added, removed or redefined; ADR-0024 `Status: Proposed`;
`PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 91 of 91 reachable / 0 duplicates /
0 undefined; documentation only; PR-1 not begun.

---

## Round 11 — two split axes the 10b audit did not cover (`cfc51356`)

Two P2 findings. Both are the **same propagation class**, but on **split axes the round-10b audit did not
enumerate**. 10b swept `MCP-INSP-008`→`009`, `MCP-PROTO-012`→`MCP-ID-008`, `MCP-CONNECT-004`→`MCP-ID-007`
and the `MCP-T-001..0NN` ranges — it did **not** sweep the `MCP-OPS-002`→`MCP-PROTO-006/008` split, nor the
**CodeQL factual correction** (finding M-1), which is a re-scope of a *fact* rather than of a requirement.
**That scope gap is the lesson of this round**: an audit is only as good as its enumeration of what was
re-scoped.

### R11-1 (P2) — parse-time payload bounds kept in the PR-1 mapping

**Finding.** Earlier remediation narrowed `MCP-OPS-002` to **listener/runtime** bounds (PR-5) and moved
**structural parse-time** limits to `MCP-PROTO-006/008` (PR-1). Several consumers still assigned payload
bounding **entirely** to `MCP-OPS-002` at PR-5/PR-7, so an SSDLC or threat review could defer the **High**
oversized-payload control to PR-5 while the PR-1 kernel is already accepting hostile frames.

**Fix — every consumer of the OPS-002 axis:** `SSDLC-CONTROL-MAPPING.md` **PW.9** and **API4** rows now lead
with `MCP-PROTO-006/008` parse-time bounds at **PR-1** (with PR-1 structural-limit + fuzz + resource-budget
evidence) and scope `MCP-OPS-002` to the running listener; a **new** test row covers the PR-1
structural/resource-budget tests distinctly from the PR-5 SSE-exhaustion row. `THREAT-MODEL.md` **MCP-T-040**
now names `MCP-PROTO-006/008` as *the* control that rejects an oversized frame (PR-1), with `MCP-OPS-002`
(PR-5) and `MCP-INSP-001` (PR-7, semantic) as the other layers. Also fixed: `ABUSE-CASES.md` (the
oversized/exhaustion case), `PR0-REVIEW-CHECKLIST.md` (the bounds sign-off item now requires **both** layers
and warns that deferring to PR-5 leaves the kernel exposed), `ROLLOUT-AND-ROLLBACK.md` (hard-failure row) and
`PROTOCOL-COMPATIBILITY.md` §4, which still listed "payloads" under `MCP-OPS-002`.

### R11-2 (P2) — the CodeQL path-extension claims removed

**Finding.** Finding M-1 established — and this package's checklist/CI-GATES already stated — that
`codeql.yml`'s `pull_request` path filter **already includes `internal/**`**, so `internal/mcp/**` is analyzed
with **no path-filter change**; what is missing is only **blocking** status (it is not branch-protection
required). But `SSDLC-CONTROL-MAPPING.md` (Verification row + gap register) and `TOOL-DISCOVERY-AND-DRIFT.md`
still said MCP paths were **not wired** and **scheduled a PR-1 CodeQL workflow edit**. That would send an
implementer to make an unnecessary workflow change, and left the package self-contradictory.

**Re-verified before editing** (not taken on the reviewer's word): `.github/workflows/codeql.yml` —
`pull_request.paths` includes `internal/**`. **Fix:** the Verification row now states the verified fact, that
the gap is **blocking status only**, and that the evidence is *not* a CodeQL path-glob diff; the gap-register
row is retitled from "path-scope extension" to "**blocking status** (branch-protection policy choice — NOT a
path-scope extension)"; `TOOL-DISCOVERY-AND-DRIFT.md` carries the same correction with an explicit **"do not
schedule a CodeQL path-glob change as MCP work."**

**Unchanged by round 11:** no requirement or threat added, removed or redefined. ADR-0024 remains
`Status: Proposed`; `PR1-READINESS-REVIEW.md` remains byte-identical; 74 threats / 91 requirements / 91 of 91
reachable / 0 duplicates / 0 undefined; documentation only; PR-1 not begun.

**Second amendment to the convergence note.** The standing sweep instruction must enumerate **every** re-scope
performed, including re-scopes of **facts** (like the CodeQL correction) and **layer moves between two existing
requirements** (`MCP-OPS-002` → `MCP-PROTO-006/008`) — not only splits that created a *new* ID. Before
declaring a sweep complete, list the re-scopes it covered; anything not on that list is unswept by definition.

---

## Round 11b — the enumerated re-scope audit (self-initiated, no finding filed)

Round 11's lesson was that an audit is only as good as its **enumeration** of what was re-scoped. So this pass
first wrote the list, then checked each entry's consumers. **The enumeration is the deliverable** — future
editors should extend this table rather than re-derive it.

| # | Re-scope performed by this package | Swept in |
|---|---|---|
| 1 | `MCP-INSP-008` → **+`MCP-INSP-009`** (primitive PR-1 / listener PR-5) | 7, 10, 10b, 11b |
| 2 | `MCP-PROTO-012` → **+`MCP-ID-008`** (lifecycle PR-1 / identity PR-3) | 7, 8, 10b |
| 3 | `MCP-CONNECT-004` → **`MCP-ID-007`** for V1 Model A tenant binding (PR-3) | 7, 10, 10b |
| 4 | Threat register `MCP-T-001..056` → **`..074`** | 9 |
| 5 | `MCP-OPS-002` → **`MCP-PROTO-006/008`** for parse-time bounds (PR-1) | 11 |
| 6 | CodeQL **fact** correction (already wired; blocking-status-only gap) | 11 |
| 7 | `MCP-INSP-001` → **`MCP-PROTO-006`** for *structural* bounds (INSP-001 becomes semantic-only) | **11b** |
| 8 | PR-11 → **PR-C / Future DMZ gate** (connector + DMZ slice moves) | **11b** — verified consistent |
| 9 | `MCP-AUTH-006` **reframed** (layered posture + DPoP-proof replay; **not** access-token `jti`) | **11b** |
| 10 | `MCP-EVENT-002` critical classes → **fail closed AND** degraded+alert (not "or") | **11b** |

Axes 7, 9 and 10 each still had a stale consumer; axis 8 checked clean.

- **Axis 9 was the most serious.** `MCP-AC-002` still read *"replay the same token on a second call … Closure:
  replayed token rejected/flagged"* — i.e. it demanded exactly the **one-time-use access-token `jti`** behavior
  that ADR-0024 §D-2 items 7–9 **forbid**. An implementer closing that abuse case would have built the
  rejected design. It is rewritten as **stolen-token abuse / DPoP-proof replay**: replay detection binds to the
  **per-request DPoP proof**, bare token reuse yields anomaly/rate-limit handling rather than an automatic DENY,
  and the test is explicitly **not** an access-token one-time-use test.
- **Axis 10:** `ATTACK-TREES.md` AT-7 "Undefined loss policy" mitigation read `MCP-EVENT-002 (fail
  closed/degraded)` — the slash reads as **or**, the exact weakening corrected in `BLUEPRINT.md` earlier. Now
  "**fail closed AND** degraded mode + alert + integrity-protected loss counter", citing EVENT-MODEL §4a / §D-5.
- **Axis 7:** the ASVS **V5** row still assigned "input schema/size/depth/field-count bounds" to `MCP-INSP-001`
  at PR-7 only; it now splits structural (`MCP-PROTO-006/008`, PR-1) from semantic (`MCP-INSP-001`, PR-7). The
  two `mcp_gateway_inspect_max_{schema_depth,field_count}` config rows are **kept** on `MCP-INSP-001` — they are
  genuinely inspection-stage settings — but each now says explicitly that it is **not** the kernel's structural
  parse-time bound, which is enforced earlier by `MCP-PROTO-006`.

**Unchanged:** no requirement or threat added, removed or redefined. ADR-0024 `Status: Proposed`;
`PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 91 of 91 reachable / 0 duplicates /
0 undefined; documentation only; PR-1 not begun.

---

## Round 12 — config-surface consumers of two enumerated axes, plus a new axis 11 (`a94c083c`)

Three findings (1×P1, 2×P2). Two land on axes **already in the round-11b enumeration table** — but on
consumers that table's sweep did not reach: the **config-surface matrix** (axis 10) and the **SSDLC ASVS V2
evidence column** (axis 9). So the enumeration was right and still incomplete in *coverage*: enumerating the
re-scopes is necessary but not sufficient — each axis must also enumerate **which document families** it
touches. The third finding is a genuinely **new axis 11**.

### R12-1 (P1) — critical-class fail-closed is an invariant, not a selectable mode

**Finding.** `MCP-EVENT-002` requires, for the critical classes, **fail closed AND** degraded-mode-with-alert.
But `mcp_gateway_event_loss_policy` still exposed `fail-closed | degrade-and-alert` as **mutually exclusive**
enum values. An operator selecting `degrade-and-alert` could therefore let a saturating **high-risk** operation
**proceed without a durable event** — a configuration path that directly violates the requirement. This is the
most serious kind of defect in this package: a config surface that can switch off an invariant.

**Fix.** The setting is scoped to govern **only the read-only / low-risk ALLOW-or-MONITOR class**.
`degrade-and-alert` **MUST NOT** be selectable for, or applied to, the critical classes (write,
destructive/production, configuration-publication, credential issue/rotate/revoke/high-risk-selection,
state-affecting Management operations, auth-failure/authz-denial): for those, fail-closed **AND**
degraded-mode-with-alert are **unconditional invariants** with **no configuration path** to bypass. Constraint
class **Override**; the PR-8 test list now **requires a negative test** proving `degrade-and-alert` cannot be
applied to a critical class (config rejected and/or runtime still fails closed).

### R12-2 (P2, **new axis 11**) — the `MCP-PROTO` family had no config-surface rows

**Finding.** `MCP-PROTO-006` (and 003/004/005/008) make every PR-1 envelope/depth/count/string limit a
**required configurable bound**, and the matrix's own contract (GUI-parity: every config option needs an API +
GUI + row) means a field without a row **cannot be implemented**. The matrix defined **no** `MCP-PROTO` fields —
its only payload-size setting, `mcp_gateway_inspect_max_payload_bytes`, mapped solely to semantic
`MCP-INSP-001` at PR-7. A PR-1 implementer could not satisfy the requirement and the config contract at once.

**Fix.** Added **seven** kernel-bound rows under a new **"Protocol kernel bounds (PR-1)"** category, capability
**Both** (the kernel is shared by Management and Gateway): `mcp_protocol_max_envelope_bytes`,
`_max_json_depth`, `_max_field_count`/`_max_array_elements`, `_max_string_bytes`/`_max_method_name_bytes`,
`_max_partial_frame_bytes`, `_max_inflight_ids`/`_max_parser_memory_bytes`/`_max_parse_work_budget`, and
`mcp_protocol_batch_policy`. Each carries YAML/env/flag/API (`GET/PUT /api/mcp/protocol/limits`)/GUI panel,
**safe-default + hard-cap** validation with the concrete values left to **D-14** (not invented), snapshot
sync, **Override** backward-compat (a hard cap configuration cannot exceed), and **PR-1** tests
(`mcp_protocol_limits_test.go`, `_framing_test.go`, `_budget_test.go`, `_batch_test.go`). Silent batch
split/partial processing is **structurally excluded** from the batch enum.
`mcp_gateway_inspect_max_payload_bytes` now states it is the **inspection-stage** cap, **not** the wire-envelope
cap, and **MUST be ≤** `mcp_protocol_max_envelope_bytes`.

### R12-3 (P2) — DPoP-proof replay named in the SSDLC + fixture evidence

**Finding.** The ASVS **V2** evidence column still demanded generic "**replayed-token** rejections", so an
implementer following the SSDLC mapping could build the **forbidden one-time-use access-token** behavior — the
same defect round 11b fixed in `MCP-AC-002`, in a different document family.

**Fix.** The V2 evidence now names **replayed per-request DPoP proof rejected + sender-constraint enforced on
high-risk profiles + stolen-token-abuse anomaly/rate-limit signals**, and states explicitly that reuse of a
still-valid access token is **not** itself replay (ADR-0024 §D-2 items 7–9). It also folds in the audience
verification over **both** token forms and the `aud`-less-denied-everywhere rule. The
`PROTOCOL-COMPATIBILITY.md` OAuth-negative fixture row carried the same generic phrasing and is corrected
identically.

**Third amendment to the convergence note.** A re-scope sweep must enumerate not only the **axes** but, per
axis, the **document families** to check: (1) the requirement registry, (2) the threat register, (3) the
traceability matrix, (4) attack trees, (5) abuse cases, (6) DFDs, (7) CI-gate rows, (8) the **config-surface
matrix**, (9) the **SSDLC/ASVS framework mappings**, (10) the protocol/connectivity contracts, (11) the
review checklists, and (12) ADR-0024. Rounds 11b and 12 each missed a *family*, not an axis. Additionally:
**whenever a requirement makes something configurable, the config-surface matrix needs a row in the same
change** — the GUI-parity contract makes a missing row an implementation blocker, not a documentation nit.

**Unchanged by round 12:** no requirement or threat added, removed or redefined (the new config rows bind to
existing `MCP-PROTO-003/004/005/006/008`). ADR-0024 `Status: Proposed`; `PR1-READINESS-REVIEW.md`
byte-identical; 74 threats / 91 requirements / 91 of 91 reachable / 0 duplicates / 0 undefined; documentation
only; PR-1 not begun.

---

## Round 13 — defects in round 12's own new rows (`34f9b73c`)

Two findings, **both in the config-surface rows round 12 added**. Round 12 fixed a missing surface; round 13
fixes that surface being wrong. Worth stating plainly: adding a *new* surface re-opens every contract that
surface must satisfy, so a fix that adds rows needs the same review as a fix that edits them.

### R13-1 (P1) — the denial-event **durability lockout** was flattened into "fail closed"

**Finding.** The corrected `mcp_gateway_event_loss_policy` row grouped **auth-failure / authz-denial** events
with the classes that must "fail closed" — but for a denial the triggering request is **already denied**, so
fail-closed is not the remedy. `MCP-EVENT-002` and ADR-0024 §D-5 require a different behavior: enter the
**critical degraded state** and **block subsequent *allowed* write/high-risk operations until durability is
restored**. Round 12's proposed test only proved the config value could not be applied — so an implementation
following the matrix could **omit the lockout and keep executing privileged work after losing denial evidence**.
This is the same distinction the round-2 remediation introduced in the requirement, lost when the config row
was written.

**Fix.** The row now states **two distinct, separately non-configurable invariants**: (a) critical write /
destructive / config-publication / credential / state-affecting-Management ⇒ **fail closed AND** degraded +
alert + loss counter; (b) auth-failure / authz-denial ⇒ **critical degraded state + alert + loss counter +
BLOCK NEW *allowed* write/high-risk operations until durability is restored** (a **durability lockout**),
absent an explicitly approved emergency policy. It adds "**no configuration path that skips the denial-event
lockout**". The PR-8 test list now requires **two** tests: the config-rejection negative **and** a
**denial-event durability-lockout test** — drop a denial event under saturation, assert the critical degraded
state **and** that a subsequent *allowed* write/high-risk operation is blocked until durability returns.

### R13-2 (P2) — the kernel-bound rows violated the matrix's own capability-separation contract

**Finding.** Round 12 added the seven kernel rows with capability **`Both`** and a single `mcp.protocol.*`
namespace/API. But the matrix's separation contract states the two capabilities keep **separate registry rows
— "a Management MCP field and a Gateway MCP field are never the same row, even when conceptually parallel"** —
and **all 61 pre-existing rows are single-capability** (`Mgmt` or `Gateway`; zero `Both`). The shared row also
had a real security consequence: **raising a bound for Gateway would widen the separate Management trust
boundary.**

**Fix.** The 7 shared rows are replaced by **22 per-capability rows** (11 fields × Mgmt + Gateway) —
`mcp_mgmt_protocol_*` / `mcp_gateway_protocol_*`, namespaces `mcp.management.protocol.*` /
`mcp.gateway.protocol.*`, env `CULVERT_MCP_MGMT_PROTO_*` / `CULVERT_MCP_GW_PROTO_*`, separate APIs
(`/api/mcp/management/protocol/limits`, `/api/mcp/gateway/protocol/limits`) and separate GUI panels. Each row
states the governing principle explicitly: **the protocol-kernel *code* is shared, but its *configuration is
instantiated separately per capability*, so raising a bound on one listener MUST NOT widen the other's trust
boundary.** The Gateway inspection cap constraint is re-pointed at the **Gateway** envelope value specifically.
Capability tally after the change: **0 `Both`**, matching the contract.

**Unchanged by round 13:** no requirement or threat added, removed or redefined (all 22 rows bind to existing
`MCP-PROTO-003/004/005/006/008/013/014`). ADR-0024 `Status: Proposed`; `PR1-READINESS-REVIEW.md`
byte-identical; 74 threats / 91 requirements / 91 of 91 reachable / 0 duplicates / 0 undefined; documentation
only; PR-1 not begun.

**Fourth amendment to the convergence note.** **A remediation that ADDS a surface must re-check that surface
against every contract the surface itself is subject to** — for the config matrix that means the
capability-separation contract, the GUI-parity/API/OpenAPI columns, snapshot semantics, the Override/backward-
compat column, and per-class invariants that must not become selectable. Rounds 12→13 show the failure mode:
the fix for a missing row introduced a row that broke a different documented invariant.

---

## Round 14 — the denial-lockout in the event FLOW, and a new axis 12 (`6b552ccf`)

Two findings (1×P1, 1×P2).

### R14-1 (P1) — the event flow diagram never modelled the denial-event lockout

**Finding.** §4a's table and (after round 13) the config row both carry the denial-event **durability
lockout** — but the §6 **flow diagram** routed the whole critical branch to `DEG` (degraded mode) only, and
the prose under it **incorrectly listed authentication/deny inside the fail-closed branch**, which §4a
explicitly says is *not* how an already-denied request is handled. A PR-8 implementation following the flow
could **enter degraded mode and then continue privileged work after losing denial evidence** — the same hole
round 13 closed in the config row, still open one document over. This is the **third** consumer of this one
axis (requirement → config row → flow diagram), which is why it keeps recurring: the axis has more consumers
than any sweep list had entries.

**Fix.** The flow now branches the critical class in two:
- a new decision node **"Is the event an auth-failure / authz-DENIAL? (request already denied)"**;
- **no** ⇒ `FAIL` (fail closed the triggering operation) **AND** `DEG` — both, as before;
- **yes** ⇒ new **`CDEG`** (critical degraded state + alert + loss counter) → new **`LOCK`**
  (**"DURABILITY LOCKOUT: block NEW allowed write/high-risk ops until durability is restored"**).

The prose is rewritten as two explicitly numbered, explicitly non-interchangeable outcomes, stating that for a
denial "fail closed" is **vacuous** and that **entering degraded mode alone is not sufficient** — without the
lockout, privileged work could continue after denial evidence was lost.

### R14-2 (P2, **new axis 12**) — Management tenancy/RBAC derived from a session the listener does not have

**Finding.** Round 1–2 made `mcp_mgmt_auth_mode` **`oauth-token`-only** and removed the session-cookie
fallback — but two consumers still derived Management authority from a browser session:
`mcp_mgmt_tenant_scope_mode` used enum **`session-bound`** with "tenant is derived from the authenticated
admin session", and the `mcp_mgmt_credential_profiles` rationale said the capability "acts as the
authenticated admin's own **RBAC session**". A Management MCP request has **no such session**, so PR-3 had
**no defined authoritative tenant source** for its tenant-escape checks. This is a **new axis** — the
`mcp_mgmt_auth_mode` re-scope — that no previous enumeration listed.

**Fix.** The enum is renamed **`session-bound` → `token-bound`**: tenant and RBAC context derive from the
**validated OAuth principal / access-token metadata** (issuer + subject/workload identity + tenant claim +
granted scopes, resolved by the PR-3 identity layer), **never client-asserted**; the row states that the
`oauth-token`-only listener has **no browser session** so the admin-UI RBAC cookie is **not** an authoritative
source for it, and that a token with **no resolvable tenant MUST be denied rather than defaulted**. Constraint
class raised to **Override** (V1 cannot be configured to accept a client-asserted tenant), verification
extended to four cases (token-derived tenant; client-asserted tenant ignored; no-tenant token denied;
cross-tenant escape negative), and the requirement link now includes **MCP-ID-007** + **MCP-AUTH-008**. The
credential-profile rationale now says the capability acts **on behalf of the OAuth principal in its own bearer
token**, with its RBAC decision from the token's granted scopes and resolved role.

**Unchanged by round 14:** no requirement or threat added, removed or redefined. ADR-0024 `Status: Proposed`;
`PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 91 of 91 reachable / 0 duplicates /
0 undefined; documentation only; PR-1 not begun.

**Axis 12 added to the enumeration table:** `mcp_mgmt_auth_mode` → **`oauth-token`-only** (no session-cookie
fallback) — consumers: the tenancy enum, the credential-profile rationale, and any statement deriving
Management authority, tenancy or RBAC from a browser/admin session. **Swept in round 14.**

**Fifth amendment to the convergence note.** Two axes (`MCP-EVENT-002` denial lockout; `MCP-INSP-008`→`009`)
each produced findings across **three or more** consumer documents in **different rounds**. Consumer count is
therefore not bounded by intuition: for any axis touching a **behavioural invariant** (what the system must do,
not just which ID owns it), enumerate consumers by **grepping the invariant's vocabulary** — here "fail
closed", "degraded", "loss policy", "session" — not only the requirement ID. An invariant restated in prose or
drawn in a diagram will not match an ID grep.
