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
`docs/adr/0024-mcp-agent-security-gateway-trust-boundary.md` and `docs/design/mcp/**` — including
`docs/design/mcp/predicates/`, which holds the **document-structure checks this log cites** (see below).
Those are standalone scripts run by hand from the repository root; they are **not** wired to any workflow,
and they check *these documents*, not the product.

**Predicate artifacts, and which of the results below can be re-run.** From round 12 onward this log cites
executable structural checks by number. The ones that survive as artifacts live in
[`predicates/`](predicates/) with a per-file table and a **reproducibility register** in
[`predicates/README.md`](predicates/README.md). **Predicates 19, 21, 22, 23 and 24 are checked in and
re-runnable; predicates 7, 8, 13, 18 and the "outcome-lane check" are NOT** — they were written and run in a
working session and never saved, so the results recorded for them below are claims rather than reproducible
evidence, and the register says so rather than leaving a later reader to discover it by searching. They are
deliberately **not** reconstructed from memory to fill the gap (round 35's re-derivation of predicate 19
produced a residual the original had evidently excluded silently — a reconstruction is a different check
wearing the same number). Preserved invariants:
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
cap, and **MUST be ≤** the Gateway envelope bound.

> **Superseded in part by [R13-2](#r13-2-p2--the-kernel-bound-rows-violated-the-matrixs-own-capability-separation-contract).**
> The generic field names above (`mcp_protocol_max_envelope_bytes`, `mcp_protocol_batch_policy`, …) and their capability
> **`Both`** were exactly what round 13 found to violate the matrix's capability-separation contract. They no longer exist:
> each is now a per-capability pair (`mcp_mgmt_protocol_*` / `mcp_gateway_protocol_*`). This entry is kept as the historical
> record of round 12; **the current contract is R13-2's**, and the inspection-cap inequality binds
> `mcp_gateway_inspect_max_payload_bytes` **≤** `mcp_gateway_protocol_max_envelope_bytes` (Gateway-to-Gateway).

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

---

## Round 14b — vocabulary-based sweep of the denial-lockout axis (self-initiated, no finding filed)

Round 14's fifth amendment says: for a **behavioural** invariant, enumerate consumers by grepping the
**invariant's vocabulary**, not the requirement ID. Applied immediately as an audit
(`fail[ -]?clos|degraded mode|loss polic|silent(ly)? (drop|los)`), it found **two more** consumers of the
denial-lockout axis that four previous ID-based sweeps had all missed. Neither was reported by a reviewer.

| Consumer | Why it mattered | Fix |
|---|---|---|
| **`ABUSE-CASES.md` MCP-AC-016 — "Critical decision-event loss"** | The abuse case's own attacker goal is *"induces pipeline saturation to **erase a deny event**"* — yet its expected control/event/result described only fail-closed + degraded mode, and its **closure condition was "zero critical loss demonstrated"**, which the lockout does not appear in at all. The single abuse case most specific to this attack could have been signed off **without ever testing the lockout**. | Expected control now states both §4a outcomes with (b) as the branch *this attacker targets*; expected event adds that subsequent allowed write/high-risk ops are blocked; expected result states **degraded mode alone is not sufficient for a lost denial event — otherwise the attacker erases the deny evidence and privileged work continues**; the test adds an explicit **denial-event lockout case**; and closure now requires the lockout proven, noting the case is **not** closed by degraded-mode alerting alone. |
| **`BLUEPRINT.md` §16 loss-policy note** | The top-level blueprint statement collapsed both kinds into one "critical classes MUST fail closed AND degrade" sentence, so the highest-level document a reader starts from omitted the denial branch entirely. | Rewritten as two numbered, explicitly non-collapsible outcomes, with the denial branch carrying the **durability lockout** and "degraded mode **alone is not sufficient**". |

**Why this validates the amendment:** this axis has now produced findings in **five** consumers across rounds
2, 13, 14 and 14b — the requirement (§4a table), the config row, the flow diagram, the prose beneath it, the
abuse case, and the blueprint note. An ID grep matched only the first two, because the rest restate the
invariant **in prose, in a diagram, and as an attacker-goal narrative** without citing `MCP-EVENT-002`. The
vocabulary sweep is what surfaced them.

**Unchanged:** no requirement or threat added, removed or redefined. ADR-0024 `Status: Proposed`;
`PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 91 of 91 reachable / 0 duplicates /
0 undefined / 27 contiguous abuse cases; documentation only; PR-1 not begun.

---

## Round 15 — the per-capability split's orphans, and the denial lockout's 6th–9th consumers (`5f82ded7`)

Three findings from Codex (2×P1, 1×P2), plus **nine** further consumers found by the round-14b
vocabulary sweep re-run against the two axes the findings named. No reviewer reported the nine.

### R15-1 (P1) — the Management listener had no Origin/Host allowlist

**Finding.** `MCP-INSP-009` binds the host-allowlist to the inbound listener and `MCP-INSP-008` makes an
**empty allowlist fail closed**. The matrix defined `mcp_gateway_origin_host_allowlist` only. Because the
matrix's own §"separate registry rows" contract forbids a Management field and a Gateway field being the same
row, the Management listener had **no allowlist it was permitted to use** — so an implementer following the
matrix would either reject every Management request (empty ⇒ fail closed) or skip the mandatory rebinding
defense. `CI-GATES.md` states the D-9 gate applies "on every listener", which is the corroborating contract.

**Fix.** Added `mcp_mgmt_origin_host_allowlist` (full 15-column row: YAML/env/flag/API/GUI/OpenAPI,
fail-closed validation, PR-1 primitive test + PR-5 listener E2E, `Override` backward-compat). The row states
why it is a separate row from the Gateway's rather than a shared one.

### R15-2 (P1) — the architecture's failure-ownership table flattened the denial lockout (6th consumer)

**Finding.** `RECOMMENDED-ARCHITECTURE.md`'s `MCP-EVENT-002` row truncated the requirement **before** its
denial clause and assigned `internal/mcp/events` only "fail-closed **and** degraded-mode-with-alert". The
triggering request of a denial is *already denied*, so fail-closed-plus-alert is not an equivalent posture —
an implementation reading only this table would keep performing privileged work after denial evidence was
lost. **This is the component-ownership table**, i.e. the artifact an implementer maps to packages.

**Fix.** Both columns now carry the denial branch, and the Failure Posture names it "a distinct posture, not a
synonym", assigning the lockout enforcement to `internal/mcp/runtime` consistently with the general principle
already stated below that table.

### R15-3 (P2, **new axis 13**) — the per-capability config split left orphaned references

**Finding.** Round 13 split the shared `mcp_protocol_*` rows into `mcp_mgmt_*`/`mcp_gateway_*` pairs. Two
references to the **deleted generic names** survived: the PR-7 inspection cap's inequality pointed at
`mcp_protocol_max_envelope_bytes` (unimplementable — no such field), and the **Management** envelope row
carried a duplicated *Gateway* constraint, coupling the two trust boundaries in the one place the split
existed to separate.

**Fix.** The inequality is re-pointed at `mcp_gateway_protocol_max_envelope_bytes` (Gateway-to-Gateway); the
duplicated Gateway constraint is removed from the Management row, which already lives correctly on the
Gateway row.

### Self-initiated sweep of both axes (nine further consumers, none reviewer-reported)

Axis 13 was swept mechanically — extract every `mcp_*` identifier defined as a matrix row, extract every
`mcp_*` identifier *referenced* anywhere in the package, and diff. Axis 10 (denial lockout) was re-swept by
vocabulary per the fifth amendment.

| Consumer | Class | Why it mattered |
|---|---|---|
| `CONFIG-SURFACE-MATRIX.md` — Management event pipeline | axis 13, capability symmetry | The **entire** event-pipeline surface was Gateway-only. `MCP-EVENT-002`'s denial lockout is system-wide and "configuration publication" is a *Management* action class, so Management had no row for a surface it is required to have. Added five rows (spool/export/loss-policy/redaction/replay-id), each noting that the durable **transport** may be shared per EVENT-MODEL §4 but the **configuration** is per-capability. |
| `PR1-READINESS-REMEDIATION.md` R12-2 | axis 13 | This ledger's own round-12 entry still described the generic names and capability **`Both`** as current. Kept as historical record with an explicit supersession note pointing at R13-2. |
| `DATA-FLOW-DIAGRAMS.md` DFD-9 | axis 10 (**9th consumer**) | **A second event-durability diagram.** Round 14 fixed "the event flow diagram" — there were two. DFD-9 modelled only the fail-closed edge. Added the `CDEG` → `LOCK` branch using the same node names as EVENT-MODEL's diagram. |
| `IMPLEMENTATION-SLICES.md` PR-8 | axis 10 | The slice that *builds* the event pipeline listed no denial-lockout test and an acceptance of "zero loss … (or fail-closed + alert)". A green PR-8 could have shipped without the lockout ever being exercised. |
| `ATTACK-TREES.md` AT-7 | axis 10 (7th) | "Undefined loss policy" mitigation enumerated only the critical-class posture. |
| `CI-GATES.md` §preamble | axis 10 (8th) | The PR-8 gate was described as enforcing "the D-5 per-action **fail-closed** matrix" — the flattening, in the gate contract. |
| `BLUEPRINT.md` PR-8 slice row | axis 10 | Exit criteria were "zero loss for critical classes" only. |
| `SECURITY-REQUIREMENTS.md` §preamble | axis 10 | The requirements document's own summary of D-5 said "per-action fail-closed matrix". |
| `ADR-0024` §Consequences | axis 10 | Same flattening in the decision record's consequences. |
| `EVENT-MODEL.md` §4 "Degraded mode" | axis 10 | The definition row named only the ordinary degraded state; §4a's **critical** state and lockout are now named there too, with "MUST NOT be collapsed". |
| `ABUSE-CASES.md` MCP-AC-015 | axis 10 | Queue exhaustion is the *cause* of event loss; its expected result now points at MCP-AC-016's lockout. |

**Sixth amendment to the convergence note — two lessons.**

1. **A split or rename produces two defect classes, not one.** The obvious one is *dangling references to the
   deleted name*. The silent one is *newly-asymmetric coverage*: while a surface was shared, it covered both
   sides for free; the moment it is split, every side that did not get a row loses the surface entirely, with
   no broken link to reveal it. R15-1 and the Management event pipeline are both this second class, and
   neither is findable by grepping for the old name. **After any split, sweep in both directions:** every
   reference resolves to a defined name (mechanical), *and* every capability still has every surface its
   requirements bind it to (semantic).
2. **When an invariant is drawn, find every diagram that models that flow — not the one the reviewer named.**
   Round 14's finding was "the event flow diagram"; the fix landed on EVENT-MODEL's. DFD-9 modelled the same
   flow and kept the flattened form for a further round. A reviewer naming one artifact is not an enumeration.

**Unchanged by round 15:** no requirement or threat added, removed or redefined. ADR-0024 `Status: Proposed`;
`PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 91 of 91 reachable / 0 duplicates /
0 undefined / 27 contiguous abuse cases / 0 `Both` capability rows; documentation only; PR-1 not begun.

---

## Round 16 — the split was declared but never tested (`5dee6e8c`)

Two findings from Codex (1×P1, 1×P2). **Both land on rows added or extended in round 15** — the
"defect in my own newly-added text" class (rounds 12→13 precedent), now confirmed twice.

### R16-1 (P1) — the per-capability split had no isolation test

**Finding.** Round 13 split the kernel bounds into `mcp_mgmt_protocol_*` / `mcp_gateway_protocol_*`
pairs precisely so that *raising a bound on one listener cannot widen the other's trust boundary*. All 22
paired rows pointed at the same **generic** test (`mcp_protocol_limits_test.go` et al.), and the PR-1 gate
required no cross-capability assertion. **An implementation backed by a single shared limits object would
pass every named test** — the split would exist on paper only, and a Management change could silently widen
the Gateway boundary. The rows declared an invariant that nothing verified.

**Fix.** All 22 paired rows now additionally name `mcp_protocol_limits_isolation_test.go` (**PR-1**): set one
capability's value, assert the paired capability's is unchanged at runtime, and vice versa — a shared limits
object **MUST fail**. The requirement is pushed into the two places that actually gate it: the **blocking
PR-1 protocol-kernel gate** in `CI-GATES.md` (plus its taxonomy row) and the `MCP-T-063` row of
`TEST-TRACEABILITY-MATRIX.md`, whose evidence column now reads "a Management change never widens the Gateway
bound (and vice versa)".

### R16-2 (P2) — the new Management loss-policy row had no critical-class negative test

**Finding.** The Gateway row carries an explicit two-part **MUST include** contract (a negative test proving
`degrade-and-alert` cannot be applied to a critical class, *and* the denial-event lockout test). The
Management row added in round 15 named only its loss-policy test plus "the shared denial-event lockout test",
so PR-8 could go green without ever proving the Management critical branch — and a later state-affecting
Management operation could proceed after losing its event.

**Fix.** The Management row now carries the parallel two-part contract, scoped to the Management critical
classes (configuration publication / state-affecting Management operation), and its lockout case explicitly
asserts against a **Gateway** operation, since the lockout is system-wide rather than per-capability.

**Seventh amendment to the convergence note — a declared invariant is not a verified one.** Rounds 13 and 15
both added rows whose *validation* prose stated the separation contract correctly while their *Tests* column
named a capability-agnostic test. Prose asserting "X MUST NOT affect Y" is inert unless some named test
changes X and observes Y. **For any row whose validation text claims isolation, independence or "MUST NOT
widen", the Tests cell must name a test that manipulates one side and asserts the other — and that test must
appear in the blocking gate, not only in the row.** The mechanical form of this check: for every
capability-paired row, does its Tests cell name anything capability-specific or isolation-specific? For all 22
protocol rows the answer was no, and a single grep over the Tests column surfaced the entire class at once.

**Unchanged by round 16:** no requirement or threat added, removed or redefined. ADR-0024 `Status: Proposed`;
`PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 91 of 91 reachable / 0 duplicates /
0 undefined / 27 contiguous abuse cases / 0 `Both` capability rows; documentation only; PR-1 not begun.

---

## Round 17 — the seventh amendment, applied where round 16 failed to apply it (`699c472e`)

Two findings from Codex (1×P1, 1×P2). **Both are the seventh amendment turned back on round 16 itself**:
round 16 wrote "a declared invariant is not a verified one — and the test must appear in the blocking gate,
not only in the row", then fixed only the 22 protocol rows and left the same defect in two other places.

### R17-1 (P1) — the two host allowlists had no isolation coverage

**Finding.** The `mcp_mgmt_origin_host_allowlist` row added in round 15 states that widening one allowlist
**MUST NOT** widen the other, and named only per-capability tests. If both capabilities were accidentally
backed by one shared allowlist, each named test still passes while approving a Gateway host also authorizes
it on the **Management** listener. The blocking Origin/Host gate did not change one capability and observe
the other either. This is round 16's P1 in a different pair — and I created the pair myself in round 15.

**Fix.** Both allowlist rows now name `mcp_origin_allowlist_isolation_test.go` (PR-1 primitive scope, PR-5
listener scope): add an approved host to one capability's allowlist, assert the paired capability's listener
**still rejects it**, and vice versa; one shared allowlist object **MUST fail**. Pushed into the blocking
Origin/Host gate, its taxonomy row, and the `MCP-T-031` listener-E2E traceability row.

### R17-2 (P2) — the Management event branch lived only in the matrix row

**Finding.** Round 16 added the Management critical-class and lockout cases to the *configuration-matrix
row* while the blocking PR-8 gate, its taxonomy row and the traceability row stayed capability-agnostic. The
gate could therefore be declared green on the Gateway cases alone, so a Management configuration-publication
path that proceeds after losing its event was **not required to fail the merge** — exactly the failure the
seventh amendment names, committed in the same change that wrote the amendment.

**Fix.** The blocking PR-8 gate now requires **both** capabilities' critical-class cases **and** the
denial-event lockout originated on **each** leg, with the Management-originated case asserting that a
subsequent *allowed* **Gateway** write/high-risk operation is blocked (the lockout is system-wide, so a
Management-only assertion would let a per-capability implementation pass). Mirrored into the taxonomy row and
the `MCP-T-044` traceability row.

### Self-initiated sweep — four more capability-agnostic gates

Rather than inspect, I enumerated mechanically: every requirement that has config rows on **both**
capabilities, then every gate row binding one of those requirements, then whether the gate's text is
capability-aware. Fifteen requirements are dual-capability; six gate rows were agnostic. Codex reported two.

| Gate | Why per-capability coverage is required |
|---|---|
| **Protocol-kernel fuzz gate** (PR-1) | Round 16 made the *structural* gate capability-aware but left the **fuzz** gate agnostic. Kernel code is shared, bounds are not — fuzzing under one capability's bound set proves nothing about the other. Now repeated under each. |
| **SSE-exhaustion / slowloris / queue-saturation** (PR-5/PR-8) | Both listeners carry their own availability bounds, so saturating one is not evidence for the other. Now run against each listener separately. |
| **Secret-in-events scan** (PR-4/PR-8) | Both capabilities now have event redaction profiles, and **Management events carry configuration payloads** — a Gateway-only scan left the higher-privilege stream unchecked. Now scans both streams. |
| *(taxonomy rows for the above)* | Same text, mirrored. |

Deliberate non-finding: the `gitleaks` row in the existing-CI table references `MCP-EVENT-003` incidentally;
it is a repository-wide secret scan, not a per-capability MCP contract, and stays agnostic by design.

**Eighth amendment — apply a new amendment to its own whole class before shipping it.** Rounds 16 and 17 are
the same defect twice: round 16 derived the correct general rule and then applied it only to the instance the
reviewer pointed at. An amendment is a *predicate*, and shipping it means running it over every row, gate and
traceability entry it can match — mechanically, in the same change that introduces it. The two sweeps that
close this round are now the standing checks: (a) every row whose validation prose claims
isolation/independence/"MUST NOT widen" names a test that manipulates one side and asserts the other; (b) for
every requirement with config rows on both capabilities, every gate binding it names both capabilities. Both
are one script over a table column, and both should have run in round 16.

**Unchanged by round 17:** no requirement or threat added, removed or redefined. ADR-0024 `Status: Proposed`;
`PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 91 of 91 reachable / 0 duplicates /
0 undefined / 27 contiguous abuse cases / 0 `Both` capability rows; documentation only; PR-1 not begun.

---

## Round 18 — three latent protocol-correctness defects in the requirements themselves (`a5059664`)

Three P1 findings from Codex. **This round is categorically different from rounds 5–17.** Those were
*propagation* failures (a re-scope not reaching every consumer) and *verification* failures (an invariant no
test enforced). These three are **substantive protocol and security defects in the requirement statements
themselves** — present since the package was first written, and survived seventeen review rounds because
every prior round was checking whether the documents agreed with each other, not whether what they agreed on
was correct against JSON-RPC and HTTP semantics.

### R18-1 (P1) — `MCP-PROTO-003` required correlating notifications, which have no `id`

**Finding.** The requirement said reject/ignore any response **or notification** whose ID cannot be correlated
to an outstanding request. A JSON-RPC notification is a request object **without** an `id` member — that is
its definition. So the requirement directed PR-1 to **reject every valid notification**: cancellation,
progress, list-changed. The package contradicted itself two rows away, where `PROTOCOL-COMPATIBILITY.md`
already described a notification as "one-way with no correlatable response".

**Fix.** Correlation is now explicitly **response-only**. Notifications are validated independently: a
notification bearing a top-level `id` is a classification error and is rejected (`MCP-PROTO-002`); its method
token is validated (`MCP-PROTO-002`/`014`); size/rate bounds still apply (`MCP-PROTO-006`/`008`). Added the
case the original wording obscured — a cancellation names a request `id` in its **params**, and that
param-level reference must resolve only within the **same session**, so it cannot cancel another tenant's
request. Propagated to `PROTOCOL-COMPATIBILITY.md`'s `id`-correlation row and `MCP-AC-022`.

### R18-2 (P1) — `MCP-PROTO-013` mandated a reply to rejected notifications (reply amplification)

**Finding.** "Every exceeded limit / rejected message **MUST** yield a defined, bounded JSON-RPC error" was
unconditional. Applied to a notification it (a) breaks one-way conformance and (b) converts a cheap
notification flood into **reply amplification** — the attacker sends small notifications, the server answers
every one. A requirement whose literal implementation creates a DoS amplifier.

**Fix.** Handling is now by message class: a rejected **request** gets the bounded error; a rejected
**notification** gets **no wire response**, only a recorded rejection (event + metric) and cleanup. Only a
message that cannot be parsed or classified at all may emit one `id: null` error, and **that path is itself
rate-bounded** so it cannot become the amplifier by another route. The cleanup guarantee stays
**unconditional** across all classes. Propagated to the `Errors` row of `PROTOCOL-COMPATIBILITY.md`.

### R18-3 (P1) — `MCP-INSP-009` enforced the host allowlist at accept time, where the headers do not exist

**Finding.** The requirement said enforce the allowlist "at accept time" and invoke the primitive "on every
connection". `Host`/`:authority` and `Origin` are **per-request headers that do not exist at socket accept**,
and with HTTP keep-alive — especially multiplexed **HTTP/2** — one accepted connection carries many requests
each with its own values. A listener could satisfy the requirement literally by validating the first request
and let **every subsequent request on that connection bypass the rebinding control**. This is a real bypass in
the control that MCP-T-031/055/052 depend on.

**Fix.** The two obligations are separated: interface **binding** is the only accept-time obligation;
Origin/Host validation **MUST** run after header parsing on **every request and every HTTP/2 stream**, never
once per connection. The E2E proof must **exercise connection reuse and H2 multiplexing** — an allowed first
request followed by a disallowed `Host`/`Origin` on the *same connection* must be rejected. Per amendments 7
and 8 this is in the **blocking** Origin/Host gate ("a listener that validates only at accept time or once per
connection MUST fail"), the `MCP-T-031` traceability row, `ON-PREM-CONNECTIVITY.md` §7 and ADR-0024 §D-9 —
all three of which repeated the accept-time framing.

### Sweep (amendment 8 applied before shipping)

Each finding was turned into a predicate and run over the package before fixing:

| Predicate | Consumers found | Reported by Codex |
|---|---|---|
| Enforcement described as connection/accept-level for data that is per-request | 3 (`SECURITY-REQUIREMENTS` MCP-INSP-009, `ON-PREM-CONNECTIVITY` §7, `ADR-0024` §D-9) | 1 |
| Mandates a wire response without excluding notifications | 2 (`SECURITY-REQUIREMENTS` MCP-PROTO-013, `PROTOCOL-COMPATIBILITY` Errors row) | 1 |
| Treats a notification as correlatable by `id` | 3 (`SECURITY-REQUIREMENTS` MCP-PROTO-003, `PROTOCOL-COMPATIBILITY` `id` row, `ABUSE-CASES` MCP-AC-022) | 1 |

**Ninth amendment — internal agreement is not correctness.** Every sweep discipline accumulated in rounds
5–17 tests whether the documents are *consistent with each other*. All three of these defects were perfectly
consistent across the package: the wrong rule was stated once and echoed faithfully. Consistency checking
cannot find them, and neither can a test-coverage check, because a test written from the defective requirement
would assert the defective behaviour. The only thing that finds them is reading a requirement **against the
external protocol it claims to implement** — JSON-RPC 2.0 message classes here, HTTP/1.1 keep-alive and HTTP/2
multiplexing there. For every requirement citing an `[EXT]` external fact, the check is: *would a conformant
implementation of the named spec satisfy this sentence, and does the sentence's literal reading create a
behaviour the spec forbids?* Two of these three had the answer written down elsewhere in this same package.

**Unchanged by round 18:** no requirement or threat ID added, removed or renumbered (three requirement
*statements* corrected). ADR-0024 `Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74 threats /
91 requirements / 91 of 91 reachable / 0 duplicates / 0 undefined / 27 contiguous abuse cases / 0 `Both`
capability rows; documentation only; PR-1 not begun.

---

## Round 19 — round 18's own corrections, unpropagated (`e119a535`)

Three P1 findings from Codex. **Two are round 18's fixes not carried to every consumer** — the propagation
class, applied to my own corrections one round after amendment 8 said to run each fix as a predicate over its
whole class. The third is an older unswept consumer of the `MCP-INSP-001` re-scope.

### R19-1 (P1) — the architecture ran `policy → credentials → inspection`

**Finding.** `MCP-INSP-001` (re-scoped to *semantic* validation "before policy/upstream use") and DFD-7 —
whose request chain literally terminates in `RES --> POL` — both require request-side inspection to feed
policy. `RECOMMENDED-ARCHITECTURE.md` still sequenced `identity → registry/catalog → policy → credentials →
inspection` in **both** its runtime-orchestration row and its dependency chain. An implementation following
the architecture would **evaluate policy against unvalidated arguments and obtain an upstream credential
before a malformed argument or disallowed destination was rejected** — defeating `MCP-INSP-001`/`004`/`005`
and the `MCP-CRED-006` least-privilege posture. The architecture's own `credentials` row already said
"only after an ALLOW-class policy decision", so the document contradicted itself.

**Root cause.** The architecture modelled `inspection` as **one** stage. It is two, in two positions, and the
order is load-bearing.

**Fix.** Both order statements now read `identity → registry/catalog → inspection (request side) → policy →
credentials → upstream call → inspection (response side) → events`. The `internal/mcp/inspection` component
row states which checks belong to each pass (request: `MCP-INSP-001`/`004`/`005` + resource extraction;
response: `002`/`003`/`007`) and *why* the order cannot be reversed, with the DFD-7 cross-reference.

### R19-2 (P1) — `MCP-INSP-009`'s acceptance cells still said "at accept"

**Finding.** Round 18 corrected the normative **Statement** cell to require per-request/per-stream validation,
and left the **Verification** cell reading `host-allowlist-at-accept` and the **Evidence** cell reading
"allowlist enforced at accept" — plus the same stale framing in `IMPLEMENTATION-SLICES.md` (twice) and the
traceability matrix. PR-5 is implemented and reviewed against those acceptance cells, so an implementation
could validate once per connection, satisfy every acceptance description, and leave later keep-alive requests
and HTTP/2 streams unprotected. The correction was cosmetic where it mattered least and absent where it
mattered most.

**Fix.** Verification, Evidence, both `IMPLEMENTATION-SLICES.md` references and the `MCP-T-031` control cell
now all require post-header-parse evaluation per request / per H2 stream and an E2E proof over a **reused**
connection.

**Why the round-18 sweep missed it.** The predicate was `at accept time|per connection|every connection`. The
surviving instances read `host-allowlist-at-accept` (hyphenated, no "time") and `allowlist at accept`. **The
pattern matched one spelling of the concept, so it reported clean while the class was open.**

### R19-3 (P1) — DFD-15 still routed every rejection to a single error node

**Finding.** Round 18 fixed `MCP-PROTO-013` to branch rejection by message class, and DFD-15 still routed
limit/method/state rejections to one `ERR` node with the caption "every reject path yields a bounded,
non-leaky error". Implementing DFD-15 literally **recreates the notification-flood reply amplifier round 18
closed** — the same defect class as round 15's DFD-9, in the same file.

**Fix.** The reject path branches through a `REJ` node: request ⇒ bounded JSON-RPC error; notification ⇒ **no
wire response**, recorded rejection + metric only; unclassifiable ⇒ at most one **rate-bounded** `id: null`
error. All three converge on an **unconditional** cleanup node. Caption rewritten to match.

**Tenth amendment — two rules, both about how a fix is applied.**

1. **A requirement is a ROW, not a sentence.** Correcting the normative statement while leaving the
   Verification and Evidence cells asserting the old rule is worse than leaving the row alone, because
   implementers and reviewers work from the acceptance cells. Any statement correction **MUST** be applied to
   every cell of that row, and to the same requirement's rows in `IMPLEMENTATION-SLICES.md`,
   `TEST-TRACEABILITY-MATRIX.md` and `CI-GATES.md`. Round 18 changed one cell of four.
2. **Derive the sweep pattern from the concept, then validate it against a known positive in every
   spelling.** Round 18's regex was written from the phrasing in front of me and silently missed the
   hyphenated and "time"-less variants. **A predicate that reports clean has proven nothing until it has been
   shown to match an instance already known to be defective.** Before trusting a clean sweep, seed it with the
   instance the reviewer named and confirm it fires.

**Unchanged by round 19:** no requirement or threat ID added, removed or renumbered. ADR-0024
`Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 91 of 91
reachable / 0 duplicates / 0 undefined / 27 contiguous abuse cases / 0 `Both` capability rows; documentation
only; PR-1 not begun.

---

## Round 20 — a misattributed citation in round 19's text (`100f93cd`)

One P2 from Codex, in text round 19 had just written.

### R20-1 (P2) — the new ordering invariant cited the wrong requirement

**Finding.** Round 19's pipeline-order rationale cited **`MCP-CRED-006`** as the "least-privilege posture"
requiring a credential to follow validation. `MCP-CRED-006` says nothing of the kind — it governs **broker
failure** behavior ("fail closed for write/high-risk; fail-open MAY be allowed only with a valid cached
credential…"). The requirement that actually states the invariant is **`MCP-POLICY-004`**: "Upstream credential
selection **MUST** occur only after a policy ALLOW-class decision" — and it is the ID carrying the ordering
test (`MCP-T-046` confused deputy, `TEST-TRACEABILITY-MATRIX.md:55`, "Ordering (unit) · No cred pre-decision").
Credential-**scope** least privilege is `MCP-CRED-002`.

**Impact.** The architecture is used to derive implementation acceptance. A rationale citing `MCP-CRED-006`
attaches the ordering claim to an **unrelated broker-failure test**, so an implementer tracing the invariant to
its evidence lands on a test that cannot fail when the ordering is wrong. The invariant reads as gated and is
not.

**Fix.** Both round-19 citations now name `MCP-POLICY-004` (ordering, with the `MCP-T-046` test named inline)
and `MCP-CRED-002` (scope), and the logical-order paragraph states explicitly that `MCP-CRED-006` is *not* the
control here. `MCP-CRED-006`'s two legitimate uses in the file (the requirement-summary row and the
`fail-closed default` DFD node) are unchanged.

**Eleventh amendment — a citation is a claim, and reachability does not check it.** Every invariant I have
added is justified by a cited requirement ID, and **my reachability invariant counts an ID as reachable
because it is mentioned, never because the citation is apt.** A misattributed citation is therefore invisible
to all three of my existing check families: consistency sweeps (the documents agree), the reachability count
(the ID exists), and coverage checks (a test exists — just not of this invariant). Before citing a requirement
as the authority for an invariant: **read that row and confirm it states the invariant, then confirm
`TEST-TRACEABILITY-MATRIX.md` binds a test of *that* invariant to *that* ID.** If the matrix names a test of
something else, the citation is wrong even when the ID is real.

**Unchanged by round 20:** no requirement or threat ID added, removed or renumbered. ADR-0024
`Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 91 of 91
reachable / 0 undefined / 27 contiguous abuse cases; documentation only; PR-1 not begun.

---

## Round 21 — self-found: the recorded sweeps were expectations, not predicates (`fe330f21` → next)

No new reviewer findings. This round came from re-running disciplines 7 and 8 during a scheduled check-in, and
it found **two residuals the ledger had recorded as clean** — plus the reason they were recorded that way.

### R21-1 (P1, self-found) — the event-spool non-aliasing rule was one-directional and untested

**Finding.** `mcp_mgmt_event_spool_path` forbids aliasing "`/data/config_versions`, the debug audit ring, or
**the Gateway spool**" — a cross-capability isolation claim. Its Gateway counterpart
`mcp_gateway_event_spool_path` forbade only "`/data/config_versions` or other existing durable stores" and
**did not forbid aliasing the Management spool**. Neither row's Tests cell named an assertion; both named a
bare test file.

So the prohibition held in one direction only, and **the unprotected direction is the higher-consequence
one**: a Gateway spool aliased onto the Management spool lands Gateway-domain events in the store the
Management critical-class lockout and `mcp_mgmt_event_loss_policy` reason over. An operator doing this would
violate no stated rule and no test.

**Fix.** The Gateway row's Validation now forbids aliasing the Management spool, stated as **symmetric in both
directions** with the consequence inline. Both Tests cells now require a cross-capability non-aliasing case:
point one capability's spool at the other's configured path and assert the configuration is **rejected**, and
with distinct paths assert an event of one domain never appears in the other's spool. Shared-transport
deployments must still assert separation by authorization domain and tenant.

This is discipline 7 (an isolation claim must name a test that manipulates one side and asserts the other) and
discipline 4 (a split produces silently-asymmetric coverage) landing on the same row.

### R21-2 (P2, self-found) — a blocking gate bound four dual-capability requirements without naming either

**Finding.** The **Protocol-kernel fuzz gate** row (blocking for PR-1) binds `MCP-PROTO-001,002,006,007,008,
009,013,014`; four of those — `006`, `008`, `013`, `014` — have config rows on **both** capabilities. The row
named no capability. Its sibling row in the same table, the structural + protocol-state suite, *was* amended in
round 17 to say "incl. cross-capability". **Round 17 applied its own rule to one row of the class and missed
the adjacent one** — the exact failure round 17 was created to stop.

**Fix.** The fuzz-gate row now states it MUST run against each capability's configured bounds
(per-capability parameterization), not one shared bounds object, with the reason inline: a fuzz gate
exercising one capability's bounds leaves the other's unfuzzed while reporting green.

### R21-3 — the known exemption is now written down

The dual-capability sweep has exactly one legitimate exemption: the repo-wide **gitleaks** row, whose
`MCP-EVENT-003` association is incidental. That exemption lived only in this ledger's prose and in my working
memory, so every re-run re-flagged it and invited a wrong "fix". It is now recorded **in the gate row itself**
as `[dual-capability sweep: EXEMPT — … MUST NOT be amended to name both capabilities]`.

**Twelfth amendment — record the predicate, never the expected output.** The ledger and my check-in notes said
*"sweep 7 returns NONE; sweep 8 returns only the gitleaks row."* That is an **expectation**, not a check. To
re-run it I had to reconstruct the script from prose, and my reconstruction matched different phrasings than
the original — it missed `incl. cross-capability`, `per listener` and `and vice versa` (producing false
positives) while the original had evidently missed `MUST NOT alias` and the bare-test-file case (producing
false negatives). **A recorded expected result actively suppresses the finding**, because the next run is
compared against "expect NONE" rather than against the requirement. Every discipline in this ledger must
therefore be recorded as its **exact predicate — pattern, table scope, and explicit exemption list —** and
each exemption must be annotated at the exempt row itself, not held in prose. Promoting these predicates from
recorded regexes to an executed CI check is PR-0/PR-1 work (out of scope for a documentation PR), and until
that lands the predicates below are the authority:

- **Discipline 7** — over `CONFIG-SURFACE-MATRIX.md` rows: any row matching
  `isolat|independen|MUST NOT widen|MUST NOT alias` MUST also match
  `cross-capability|one shared|assert the other|and vice versa|never appears`. Exemptions: none.
- **Discipline 8** — over `CI-GATES.md` rows: any row binding a requirement that has config rows on **both**
  capabilities MUST match `both capabilit|cross-capabilit|per listener|per-capability|each capabilit|and vice
  versa`. Exemptions: the `gitleaks` row only, annotated in place.

**Known limitation of both predicates, recorded because a control's weakness must be as visible as the control.**
These are **text** predicates, not semantic ones: a row satisfies them by *containing* the required vocabulary,
not by actually requiring the coverage. Two consequences follow, and both are live:

1. The `gitleaks` exemption annotation added in R21-3 contains the words "both capabilities", so that row now
   **passes discipline 8 by matching the pattern** rather than by being skipped as exempt. The outcome is
   correct and the row is self-documenting, but it passes for the wrong reason.
2. Therefore **any** row can be made to pass either predicate by mentioning the vocabulary in prose without
   naming a test that establishes the coverage. Nothing in the current tree does this, but nothing prevents it.

These predicates are consequently a **regression guard, not a proof** — they catch a row that says nothing
about cross-capability coverage, which is exactly how R21-1 and R21-2 were found, and they cannot judge whether
a named test really manipulates one side and asserts the other. Closing that gap requires the executed CI check
(PR-0/PR-1), which must assert on the **named test identifiers** rather than on prose. Until then, a `NONE`
result from either predicate means "no row is silent", not "every claim is verified".

**Unchanged by round 21:** no requirement or threat ID added, removed or renumbered. ADR-0024
`Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 91 of 91
reachable / 0 duplicates / 0 undefined / 27 contiguous abuse cases / 0 `Both` capability rows; documentation
only; PR-1 not begun.

---

## Round 22 — the fail-closed guarantee was positioned after the side effect (`a55079b5` → next)

Three Codex findings on `a55079b5`. One is the **third** instance of the same mistake; one is a real
unimplementable guarantee in the durability design.

### R22-1 (P1) — `MCP-EVENT-002`'s fail-closed rule could not be implemented as written

**Finding.** DFD-9 reached the fail-closed branch only via `Decision + inspection + execution → Redact →
Queue`, and `RECOMMENDED-ARCHITECTURE.md` placed event emission after the upstream call. So when the queue
saturates, **the write/destructive/configuration operation has already happened** — there is nothing left to
deny, and `MCP-EVENT-002`'s "the operation MUST fail closed" is unimplementable at that point.

**Root cause, and it was stated as an invariant.** `RECOMMENDED-ARCHITECTURE.md` §3 asserted "**`events` never
blocks the decision path** … must not be able to stall or alter a policy decision already made." That
invariant exists to protect `MCP-POLICY-002` **policy purity**, and it is correct for that purpose — but it
**over-reached from the decision into the side effect**. Never blocking a *decision* and never gating
*execution* are different properties, and conflating them is what made the durability guarantee decorative.

**Fix (write-ahead ordering, propagated across the whole dimension).** For the critical **write /
destructive / configuration-publication / credential** classes the decision event **MUST be durably committed
BEFORE credential use and before the upstream call**; the operation runs only after the commit is confirmed;
if it cannot be committed the operation **MUST NOT run**. The **outcome** event is emitted separately after
execution and is explicitly **not** the fail-closed gate. Applied to:

- `MCP-EVENT-002` — Statement, **Verification and Evidence** (amendment 10a: the row, not the sentence). The
  saturation test must now assert **the upstream call never occurred**, because a test that only observes the
  returned error passes against the broken design.
- `RECOMMENDED-ARCHITECTURE.md` — the "never blocks" invariant is split into decision-purity (unchanged) vs
  execution-gating (new); both order statements gain the commit step; the component diagram gains the commit
  gate node.
- `DATA-FLOW-DIAGRAMS.md` DFD-9 — regraphed so the commit precedes a distinct execution node, with the
  outcome event re-entering redaction afterwards.
- `EVENT-MODEL.md` §4a and **`ADR-0024` §D-5** — the ordering precondition is stated above each action-class
  table, so the decision record no longer licenses the post-execution reading.
- `CI-GATES.md` — the blocking saturation gate must assert the side effect did not happen.

### R22-2 (P1) — third time: prose fixed, diagram left behind

The `RECOMMENDED-ARCHITECTURE.md` component diagram still showed `CAT → POL → CRED → INSP → RT → EVT` after
round 19 corrected both prose order statements **in the same file**. Implementers following the diagram would
evaluate unvalidated arguments and acquire credentials before destination/schema rejection — re-opening the
exact `MCP-T-046` path round 19 closed.

This is the third occurrence: round 15 (DFD-9), round 19 (DFD-15), round 22 (the component diagram). Rounds 15
and 19 both recorded "find every diagram" as prose. Prose did not work.

### R22-3 (P2) — the blocking suite claimed batch and numeric coverage it did not assert

The structural + protocol-state suite binds `MCP-PROTO-004` (batch bounds / explicit rejection when
unsupported) and `MCP-PROTO-007` (numeric overflow, precision, pathological encodings) but named neither
behaviour — batch appeared only as a cross-capability isolation case. The fuzz gate is crash-oriented and
cannot establish deterministic semantics, so PR-1 could pass every blocking gate while permitting batch
amplification (`MCP-T-061`) or a numeric parser differential (`MCP-T-064`). Both gates and the traceability
row now name the deterministic cases explicitly and forbid delegating them to fuzzing.

**Thirteenth amendment — a fail-closed guarantee is a position, not a sentence.** For any requirement of the
form *"if X cannot be done, the operation must fail closed"*, two things must be checked and neither is about
wording: (a) **every flow reaches X before the irreversible action**, and (b) **the named test asserts the
side effect did not occur**, not merely that an error was returned. A test of form (b) written without (a)
passes against a design that executes first and reports failure afterwards — which is precisely the state this
package was in for `MCP-EVENT-002`.

**Fourteenth amendment — diagrams are a checked consumer, with a predicate.** "Also update the diagrams" has
now failed three times as prose, so it becomes executable. Predicate 13, over every ```mermaid block in the
package including ADR-0024: **no edge may run from a credentials-class node to an inspection-class node**
(`CRED* --> INSP*`), because that is the pipeline inversion in graph form. Verified to fire on a seeded
positive, and currently `NONE`. Its limitation is the same as predicates 7 and 8 — it is structural, catches
this specific inversion, and does not validate a diagram's semantics in general; every ordering change still
requires reading each mermaid block whose flow it touches.

**Unchanged by round 22:** no requirement or threat ID added, removed or renumbered. ADR-0024
`Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 91 of 91
reachable / 0 duplicates / 0 undefined / 27 contiguous abuse cases / 0 `Both` capability rows; documentation
only; PR-1 not begun.

---

## Round 23 — round 22's fix was written in Gateway vocabulary and gated one class of four (`2cdf7d1d` → next)

Five Codex findings. Four are the **same** defect: round 22 established "the decision event must be committed
before the side effect" and then expressed it as *"before credential use and before the upstream call"* — which
is the **write/destructive** class's irreversible action, and **not** the irreversible action of the other three
classes `MCP-EVENT-002` itself enumerates. The fifth is an enumeration I built by hand instead of from the spec.

### R23-1 (P1) — configuration publication was never on the gated path

DFD-10 runs `Admin publish → sign → push → validate → atomic swap` with **no durable commit anywhere**.
Configuration publication makes **no upstream call**, so round 22's wording did not reach it at all: with the
spool unavailable, a configuration could be signed, pushed and applied, and only then fail. The class the
package treats as most sensitive was the one the fix missed.

**Fix.** DFD-10 gains the commit gate **before `SIGN`**, with a fail-closed branch asserting no revision is
created, nothing is signed or pushed, and every DP stays on the prior epoch.

### R23-2 (P1) — credential materialization happened before the gate

The component diagram ran `POL → CRED → WAL`, and the `credentials` component "selects/mints". So for the
credential class — issue / rotation / revocation / high-risk selection — the **broker-side mutation occurred
before the commit**. A mint or a revocation cannot be undone by a later failure, so that class could not fail
closed either.

**Fix.** `credentials` is split into two phases because only the second is irreversible: **PLAN** (choose
identity + scope, no mutation) may precede the commit; **MATERIALIZE** (mint / rotate / revoke) **MUST NOT**.
Diagram now `POL → CREDPLAN → WAL → CREDMAT → RT`, with the component row and both order statements updated.

### R23-3 (P2) — the gate accepted an enqueue as a commit

DFD-9 had **no failure edge from `SPOOL`**: only queue saturation reached fail-closed. But the guarantee is
conditioned on a *confirmed durable commit*, and a full disk, an `fsync` error or an encryption-key failure all
succeed at admission and fail at commit. My own label said "commit CONFIRMED" while the graph only branched on
saturation.

**Fix.** `SPOOL` now has an explicit commit-failure edge to fail-closed; `MCP-EVENT-002` states that queue
admission is **not** a commit; the gate requires a distinct spool-commit-failure test case.

### R23-4 (P2) — JSON-RPC has four dispositions and I had enumerated three

DFD-15's reject branch covered **request / notification / unclassifiable** and omitted **response**. An
uncorrelated, malformed or over-limit inbound response would fall through — permitting a response-to-response
feedback loop and leaving the outstanding-request correlation entry allocated (leaked correlation state).
Rounds 18–22 built this enumeration by hand, three times, and never went back to the spec's own list.

**Fix.** `MCP-PROTO-013`, DFD-15 and the blocking suite gain the response class: **discard + record, no wire
response, correlation entry released**.

### R23-5 (P1) — the absence assertion only fitted one class

The saturation gate proved "the upstream call never occurred" — which, as Codex notes, **cannot fail** for
classes that make no upstream call. Configuration publication and credential mutation could publish or mutate,
report failure afterwards, and satisfy the named assertion.

**Fix.** Per-class absence assertions in `MCP-EVENT-002` Verification/Evidence and the blocking gate: no
upstream call / no revision-or-push and every DP on the prior epoch / broker credential state unchanged / no
Management state change — plus the spool-commit-failure case.

**Fifteenth amendment — enumerate from the authority, never from the instance in front of me.** Both root
causes this round are the same error at different scales. `MCP-EVENT-002` **lists its four critical classes in
its own statement**, and I fixed the one the reviewer's example used, letting its vocabulary ("the upstream
call") silently narrow the guarantee. JSON-RPC **defines its message dispositions**, and I enumerated them from
whichever cases were under discussion, three rounds running. So: when a requirement or a cited spec contains an
**explicit enumeration**, that enumeration is the checklist — apply the fix to every member, and state the
per-member specifics rather than a phrase that happens to fit one. Corollary for tests: an absence assertion
must name **that member's own** side effect; a shared phrasing is a coverage gap wearing the costume of a
guarantee.

**Sixteenth amendment — define "succeeded" at the layer that can fail.** A guarantee conditioned on an
operation completing must say what completion means where the storage actually lives. "Durably persisted" read
as "accepted by the queue" until this round, and every fail-closed test would have exercised only saturation.

**Unchanged by round 23:** no requirement or threat ID added, removed or renumbered. ADR-0024
`Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 91 of 91
reachable / 0 duplicates / 0 undefined / 27 contiguous abuse cases / 0 `Both` capability rows; predicates 7, 8
and 13 all `NONE` (each proven to fire on a seeded positive); documentation only; PR-1 not begun.

---

## Round 24 — every finding was a defect in round 23's own fixes (`64342985` → next)

Four Codex findings, **all four introduced by round 23**. One of them made the design worse than before the
fix, and one re-committed the exact error the round it belongs to had just recorded as an amendment.

### R24-1 (P1) — round 23's outcome-event edge created an unbounded re-execution loop

To separate the decision event from the outcome event I added `OUT -.re-enters redaction + queue.-> RDX`. But
the outcome event **retains the critical action class**, so re-entering the decision lane reaches `GATE`, whose
only matching edge for a critical class is `EXEC`. An implementation following DFD-9 literally would **repeat
the upstream side effect indefinitely** — while the caption two lines below asserted the outcome event is not
the execution gate.

**This is worse than the defect round 23 fixed.** Round 22's flaw was a guarantee that failed to stop one side
effect; this one manufactures unbounded side effects.

**Fix.** Two lanes that never join: the **decision** lane (`DEC → RDX → Q → SPOOL → GATE`) gates execution; the
**outcome** lane (`EXEC → RDXO → QO → SPOOLO → INT`) records and terminates at integrity/export. Outcome-lane
loss is **degraded + alert + loss counter only** — the operation already happened, so fail-closed is vacuous
for it, the same reasoning already applied to an already-denied request. A regression predicate now asserts **no
edge runs from `{OUT, RDXO, QO, SPOOLO, ODEG}` into `{RDX, Q, SPOOL, GATE, EXEC}`**, seeded and confirmed to
fire.

### R24-2 (P2) — round 23's cleanup rule was a remote state-deletion primitive

Round 23 required a rejected response to "release the outstanding-request correlation entry so no correlation
state leaks." Codex is right that this is unsafe and partly meaningless: an **uncorrelated** response has no
entry to release, and a **malformed or over-limit** response may carry an ID that was never trustworthy decoded.
Implemented literally, **a peer could delete a legitimate in-flight request's state by naming its ID in a
deliberately malformed response.** I introduced a remote state-deletion vector while closing a resource leak.

**Fix.** The cleanup is now explicitly asymmetric: free the **offending message's** own resources always;
release an **outstanding-request** entry **only after successful, trustworthy, same-session correlation**,
otherwise retain it for its bounded timeout. The blocking gate asserts a malformed response naming a live `id`
**leaves that entry intact**.

### R24-3 (P1) — the spool-commit-failure branch was added to one diagram of two

Round 23 gave DFD-9 a commit-failure edge and left `EVENT-MODEL.md`'s canonical event-flow diagram with
`FAIL`/`DEG` reachable **only** via `SAT -- yes`, and `SPOOL` carrying success edges only. So the file that owns
the event model still routed `ENOSPC` / `fsync` / key failure straight to integrity+export.

**Fix.** `SPOOL` now branches `commit CONFIRMED → INT` and `commit FAILED → CRIT`, so commit failure reaches the
identical class-based posture as saturation for **both** critical-action and denial-event handling.

**This is the fourth occurrence of prose-or-one-diagram fixed while a sibling diagram kept the old flow**
(rounds 15, 19, 22, 24). Predicate 13 does not catch it: that predicate tests one specific edge inversion, and
this is a *missing* edge in a different file. As recorded with predicate 13's limitation, the structural check
was never a substitute for reading every diagram whose flow a change touches — and I did not.

### R24-4 (P1) — the per-class assertions went into the threat-name cell

The traceability row's **Test** and **Evidence** cells still required only generic queue saturation and the
denial lockout; my round-23 additions had been appended to the **threat-name** cell, where nothing consumes
them. PR-8 could pass the canonical matrix without testing commit failure or proving any class's side effect
absent.

Round 19 recorded amendment 10a — *a requirement is a row, not a sentence; a correction must reach the
Verification and Evidence cells* — and round 23 **cited that amendment in its own commit message** while
appending to the wrong cell of a different matrix. Recording a rule and applying it are evidently independent.

**Fix.** Test and Evidence cells now carry the spool-commit-failure case and the four per-class absence
assertions; the threat-name cell is restored to a plain identifier.

**Seventeenth amendment — a fix is not done until its own regression check exists.** Every one of these four
was reachable by a mechanical check I could have written in the same commit: an unreachable-loop check on the
graph I edited, a "does this cell actually get consumed" check on the matrix row I edited, and a
sibling-diagram check on the flow I changed. Rounds 22 and 23 added prose and then relied on the next reviewer.
So: **when a change alters a flow, a cell's semantics, or an enumeration, the same commit must add the
predicate that would fail if the change were reverted or applied incompletely** — and must run it. The
outcome-lane predicate above is that check for R24-1; R24-4's is the traceability-cell consumption check.

**Standing note on the pattern.** Ten of the last twelve rounds found defects in the immediately preceding
round's new text, and rounds 22–24 form a chain in which each fix introduced the next finding. That is not a
converging series; it is evidence that this package's correctness currently depends on the external reviewer
rather than on the disciplines recorded here.

**Unchanged by round 24:** no requirement or threat ID added, removed or renumbered. ADR-0024
`Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 0 duplicates / 27
contiguous abuse cases / 0 `Both` capability rows; predicates 7, 13 and the new outcome-lane check all clean
(each proven to fire on a seeded positive); no non-ASCII strays; documentation only; PR-1 not begun.

---

## Round 25 — the per-class gate reached the prose and not the graph; and one assertion is unprovable in its own slice (`cc928c9f` → next)

Two Codex findings. Both are round 23/24 work left incomplete rather than wrong.

### R25-1 (P2) — DFD-9 still funnelled all four classes into "upstream call"

Round 23 established that each critical class is gated at **its own** irreversible action, and propagated that
to `MCP-EVENT-002`, the gates, `EVENT-MODEL` §4a and `ADR-0024` §D-5. DFD-9's gate kept **one** critical edge:

```
GATE -->|"write / destructive / config-publication / credential"| EXEC["Credential use + upstream call"]
```

So the normative flow diagram still said every class ends in an upstream call — the exact narrowing round 23
was correcting, surviving in the artifact an implementer reads first.

**Fix.** The gate now dispatches by class: write/destructive → `XUP` (upstream call); configuration
publication → `XPUB` (snapshot **sign/push/apply**, entering DFD-10 at `SIGN` and never earlier); credential →
`XCRED` (broker **materialization**); state-affecting Management → `XMGMT`. All four converge on the outcome
lane. The round-24 outcome-lane predicate was re-run against the rewritten block and extended to the four new
execution nodes.

**This is the fifth occurrence of a fix reaching prose and not the graph** (rounds 15, 19, 22, 24, 25). Round 22
made it a predicate and round 24 recorded that the predicate is too narrow to catch this class; round 25 is the
demonstration. The honest statement is that **no predicate I have written checks whether a diagram's structure
matches a requirement's enumeration** — only that one specific bad edge is absent.

### R25-2 (P1) — the publication assertion is unprovable in the slice it was assigned to

Round 23's per-class table gave PR-8 the obligation to prove that a failed durable commit leaves **no
configuration revision, nothing signed or pushed, every DP on the prior epoch**. But
`IMPLEMENTATION-SLICES.md` places the signed CP→DP publication path in **PR-10**, which *depends on* PR-8. At
PR-8 there is no publication path to assert against — only a stub — and PR-10's gate covered only
mixed-version / stale-epoch / corrupt-snapshot / rollback behaviour. **The real publication path could
therefore ship without that assertion ever executing.**

**Fix.** The assertion is now dual-owned and the timing is stated: PR-8 keeps what it can exercise, and the
PR-10 gate **must re-run the PR-8 event-durability suite against the real signed publication wiring**, with
PR-10 blocked until it has. Recorded in the blocking-gate row, the gate-status table, and the traceability
row's Gate column (`PR-8 + mandatory PR-10 re-run`).

**Eighteenth amendment — an assertion must be assigned to a slice in which the asserted mechanism exists.** A
gate obligation placed before the machinery it constrains is not a weak test, it is **no test**: it passes
against a stub and never runs against the real path. For every assertion, check the slice that introduces the
mechanism; if it is later than the gate, either move the assertion or make the later slice's gate re-run it
explicitly. Predicate 18 encodes the mechanical half: a `CI-GATES.md` row whose own slice precedes a mechanism
it names (`signed CP`, `publication path`, `CP→DP`, `snapshot swap`) must carry a re-run / slice-timing note.
Seeded, confirmed to fire, currently `NONE`.

**Standing note.** Rounds 22–25 are one continuous chain: each round's fix produced the next round's findings.
Ten of the last thirteen rounds found defects in the immediately preceding round's new text. Two of those
defects were worse than what they replaced (an execution loop, a remote state-deletion primitive). The
eighteen amendments have not yet produced a round in which my own checks found what the reviewer found.

**Unchanged by round 25:** no requirement or threat ID added, removed or renumbered. ADR-0024
`Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 0 duplicates / 27
contiguous abuse cases / 0 `Both` capability rows; predicates 7, 13, 18 and the outcome-lane check clean (each
proven to fire on a seeded positive); no non-ASCII strays; documentation only; PR-1 not begun.

---

## Round 26 — the durable commit had never reached the PRIMARY flows (`aeaf36b4` → next)

Four Codex findings. All four are rounds 24–25 left incomplete, and the first is the most consequential
omission in the whole durability thread.

### R26-1 (P1) — DFD-5 and DFD-6, the flows an implementer actually follows, never reached the commit

Rounds 22–25 built the commit-before-side-effect guarantee in DFD-9, DFD-10, DFD-15, `MCP-EVENT-002`,
`EVENT-MODEL` §4a, `ADR-0024` §D-5 and the gates. **DFD-5 — the primary Gateway request flow — still ran
`DEC -- ALLOW-class --> CB[Credential broker] --> CALL[Call upstream]`, and DFD-6 ran
`SCOPE -- yes --> FETCH[Fetch short-lived cred]`.** Both are complete write/high-risk execution paths with no
durable commit anywhere on them.

So for four rounds the guarantee existed on the diagram that *describes event publication* and was absent from
the two diagrams that *describe how a call is served*. An implementer following DFD-5 would mint a credential
and call upstream before any event was persisted, and would never see a contradiction, because DFD-9 is a
different page.

**Fix.** DFD-5 now runs `DEC → CBP (PLAN, no mutation) → WAL{durable commit} → CB (MATERIALIZE) → CALL`, with a
fail-closed branch asserting no credential minted and no upstream call. DFD-6 gates before `FETCH` with the
same posture and states that broker state is unchanged on failure.

### R26-2 (P1) — round 24's commit-failure edge bypassed the denial lockout

Round 24 added `SPOOL -->|commit FAILED| FC` — **unconditionally**. For an already-denied
authentication-failure / authorization-denial event, fail-closed is vacuous; the required protection is the
**system-wide durability lockout**. So the edge I added to fix one gap opened another, and it contradicted the
`EVENT-MODEL` text I wrote **in the same commit**, which says commit failure takes the same class dispatch as
saturation.

### R26-3 (P2) — the saturation path had no route for the class round 25 added

Round 25 added `state-affecting Management op` as its own gate branch and left the saturation edge listing only
write/destructive/config/credential. A saturated Management state change had **no route at all**.

**Fix for both.** Saturation and commit failure now converge on one `LOSS` dispatch that routes by event class:
the five critical classes → fail-closed + degraded; already-denied auth/authz-denial → critical degraded state
+ **durability lockout**; read-only/low-risk → degraded only. One dispatch, so the two entry paths cannot drift
apart again, and coverage is verified by enumerating the classes against the diagram.

### R26-4 (P1) — the PR-10 re-run reached the gate tables and not the slice contract

Round 25's fix landed in `CI-GATES.md` and the traceability matrix, while `IMPLEMENTATION-SLICES.md` still
limited PR-10's **Security requirements, Tests, Acceptance and Release gate** to
mixed-version/corrupt-snapshot/rollback. An implementer following the per-slice contract could mark PR-10 green
without ever running the assertion — restoring exactly the stub-only gap round 25 closed. `MCP-EVENT-002`, the
re-run, the acceptance criterion and the release gate are now all in the PR-10 slice.

**Nineteenth amendment — and the first predicate that found something before the reviewer did.**
Predicate 19: **every DFD containing a node that performs an irreversible action** (`Call upstream`,
`MATERIALIZE`, `Fetch short-lived`, `SIGN[`, `mint / rotate / revoke`) **must also contain a durable-commit
node.** Applied to all fifteen DFDs it immediately reported DFD-8 — which on inspection is a **false
positive**: DFD-8 begins at `Upstream response`, entirely post-execution, and my first pattern matched the word
"upstream" rather than an act. I narrowed the pattern to action-performing node text instead of adding an
exemption, then re-verified: `NONE` residual, DFD-8 correctly excluded, fires on both an upstream-call seed and
a credential-materialize seed, and does **not** fire on `Upstream response`.

That sequence is worth recording precisely because it is the first time in twenty-six rounds that one of my own
checks did work the reviewer had not already done — and it only worked after being corrected once. It does not
change the standing conclusion below.

**Standing note.** Rounds 22–26 are one chain: each round's fix produced the next round's findings. Twelve of
the last fifteen rounds found defects in the immediately preceding round's new text. The durability guarantee
in particular took **five rounds** to reach the primary request flow, and during all five it read as complete.

**Unchanged by round 26:** no requirement or threat ID added, removed or renumbered. ADR-0024
`Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 0 duplicates / 27
contiguous abuse cases / 0 `Both` capability rows; predicates 7, 13, 18, 19 and the outcome-lane check clean
(each proven to fire on a seeded positive); no non-ASCII strays; documentation only; PR-1 not begun.

---

## Round 27 — round 26's "single dispatch" had a bypass, and my own predicate's vocabulary was an unswept enumeration (`49a37bc6` → next)

Three Codex findings, all in round 26's work.

### R27-1 (P1) — `SPOOL` kept an unconditional edge, so the single dispatch was decorative

Round 26 added `SPOOL -->|commit FAILED| LOSS` and left the pre-existing **unconditional** `SPOOL --> INT`
edge in place. A failed commit could therefore continue to integrity/export and reach neither fail-closed nor
the durability lockout — while the caption I wrote in the same commit claimed one mandatory dispatch. **Adding
a branch does not make it mandatory; removing the bypass does.**

**Fix.** `SPOOL` now has **no unlabelled out-edge**: `commit CONFIRMED → GATE`, `commit FAILED → LOSS`. A
successfully committed **denial** event reaches `INT` **through `GATE`** via an explicit arm, after
classification rather than around it. Verified mechanically — `SPOOL` out-edges are both labelled, and `INT` is
reachable only from `GATE` and `SPOOLO`.

### R27-2 (P1) — DFD-11 rollback applied a snapshot with no durability gate

Round 26 gated DFD-10's forward publication and left DFD-11's `Atomic swap to previous snapshot` ungated. A
rollback **is** a configuration change — the `MCP-EVENT-002` configuration-publication class's irreversible
action — so an operator- or health-triggered rollback could apply configuration while the spool was failing.

**Fix.** DFD-11 gates before the swap; on commit failure the rollback is **refused with the current snapshot
left active**, never applied-then-reported.

**Why predicate 19 missed it, which is the part worth recording.** I built its action vocabulary — `Call
upstream`, `MATERIALIZE`, `Fetch short-lived`, `SIGN[`, `mint / rotate / revoke` — **from the diagrams I had
just edited.** `Atomic swap` was never in the list, so the check could not see the ungated rollback. That is
**amendment 15 applied to my own predicate**: I enumerated from the instances in front of me instead of from
the authority. The vocabulary is now derived from `MCP-EVENT-002`'s own class table (upstream call /
sign-push-apply **including a rollback swap** / broker materialization / Management state change), and
re-verified: residual `NONE`, fires on a rollback-swap seed as well as upstream-call and materialize seeds, and
still does not fire on the post-execution `Upstream response`.

### R27-3 (P1) — the PR-8 slice contract, one slice over from round 26's fix

Round 26 carried the assertions into PR-10's slice and left **PR-8's** Tests and Acceptance naming only generic
saturation and "fail closed plus degraded". An act-first implementation reporting `ENOSPC` *after* the side
effect satisfies those completion fields while `MCP-EVENT-002` and `CI-GATES.md` reject it. PR-8's Tests,
Acceptance and Release gate now carry the distinct spool-commit-failure case and all four per-class
side-effect-absence assertions, with the explicit statement that observing fail-closed + degraded is **not**
sufficient.

**Twentieth amendment — a predicate's own vocabulary is an enumeration, and it decays.** Every check I have
written matches a *list of tokens*, and each list was drawn from the artifacts in front of me when I wrote it.
So a predicate silently narrows as the package grows: predicate 19 was blind to rollback from the moment it was
written. Therefore **a predicate's token list must be derived from the authority it enforces** — for
predicate 19, `MCP-EVENT-002`'s class table — **and re-derived whenever that authority changes.** A green
predicate whose vocabulary predates the text it checks is not evidence.

**Standing note.** Rounds 22–27: six consecutive rounds where each fix produced the next round's findings.
Thirteen of the last sixteen rounds found defects in the immediately preceding round's new text. Round 26's
central claim — "one mandatory loss dispatch" — was false when written, because a bypass edge two lines below
it survived.

**Unchanged by round 27:** no requirement or threat ID added, removed or renumbered. ADR-0024
`Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 0 duplicates / 27
contiguous abuse cases / 0 `Both` capability rows; predicates 7, 13, 18, 19 (v2) and the outcome-lane check
clean, each proven to fire on seeded positives; no non-ASCII strays; documentation only; PR-1 not begun.

---

## Round 28 — round 27's low-risk arm dropped every successful call; and the kernel was modelled for one capability (`13f04b66` → next)

Four Codex findings. Three are round 24/27 work; one is an older structural gap in the DFD set.

### R28-1 (P1) — the read-only/low-risk arm terminated at integrity, so successful calls vanished

Round 27 added `GATE -->|read-only / low-risk: not execution-gated| INT`. I had read "not execution-gated" as
"does not proceed to execution", which is wrong: it means execution is **not conditioned on the commit**. Since
DFD-5 routes **all** ALLOW-class traffic through this path, following the diagrams literally either **drops every
successful low-risk call or discards its outcome event**.

**Fix.** `GATE → XLOW["Execute read-only / low-risk call — proceeds WITHOUT a commit gate"] → OUT`, so low-risk
traffic executes and its outcome enters the outcome lane like any other. Only the **already-denied** classes
terminate at `INT` without execution, because there is nothing left to run — that distinction is now stated.

### R28-2 (P1) — the rollback assertions passed vacuously

Round 27 gated DFD-11 and pointed PR-10's re-run at the forward publication path. But **rollback's side effect
is a swap, not a revision** — so "no new revision / nothing signed or pushed / prior epoch retained" is
**vacuously true for an act-first rollback**. The gate I had just written could not fail on the path I had just
gated.

**Fix.** PR-10's Tests and the blocking gate now require a **separate rollback failure-injection case**: invoke
rollback with the decision event non-persistable and assert **no swap occurred and the current snapshot remains
active**. This is amendment 15's test-side corollary again — an absence assertion must name **that path's own**
side effect.

### R28-3 (P2) — the unconditional cleanup clause could delete the state round 24 protected

`MCP-PROTO-013` ends "**MUST** deterministically release all resources associated with the offending
message/session". Round 24 had added, earlier in the same row, the rule that an outstanding-request entry must
be **retained** unless trustworthily correlated. An implementer reading the final clause as session cleanup
would delete exactly the entry the earlier sentence protects — **the row contradicted itself**, and the
contradiction was introduced by my own fix landing next to inherited text I did not re-read.

**Fix.** Cleanup is now "unconditional but **scoped**": always release what was allocated to the **offending
message**; **never** release unrelated session correlation state on the strength of a rejected message.
"Unconditional" is defined explicitly as *the offending message is always cleaned up*, not *everything reachable
from its session is*.

### R28-4 (P2) — the protocol kernel was drawn for one capability out of two

DFD-15 was scoped "Capability B", while the config surface instantiates `MCP-PROTO-*` bounds for **both**.
DFD-1 and DFD-2 began at the Management listener and went straight to authorization/tool handling, so the DFD
set contained **no structural path showing hostile Management traffic through strict decoding, version
negotiation, lifecycle checks and bounds**.

**Fix.** DFD-15 is now Capability **A and B**, with its entry node and caption stating that the same kernel
evaluates each listener against **its own** bound set; DFD-1 and DFD-2 now show the kernel explicitly upstream
of the Management listener, so they read as downstream of DFD-15 rather than as a path around it.

**Amendment 15, refined — enumerate irreversible ACTIONS, not classes.** R28-2 is the third instance of the
same error (round 23: one assertion for four classes; rounds 26–27: the slice contract still accepting
"fail-closed plus degraded"; round 28: a newly gated path reusing the forward path's assertions). The pattern in
my failures is that I treat *"an assertion exists for this requirement"* as sufficient. It is not: the
requirement is satisfied **per irreversible action**, and **rollback is a distinct irreversible action from
publication even though both belong to the configuration-publication class**. So the enumeration to walk is the
set of *actions*, not the set of *classes* — a class with two irreversible actions needs two absence assertions.

**Amendment 15, second refinement — a new exception placed upstream of an existing absolute loses.** R28-3's
mechanism: I inserted a narrow retain-unless-correlated rule into a row whose **closing** sentence still said
"release **all** resources associated with the offending message/**session**". On a literal reading the trailing
absolute wins, so the exception was decorative. Amendment 10a told me a requirement is a *row* and I had applied
that only to **which cells I edit**; it applies equally to **the text I did not touch**. When adding a
qualifier, find every "unconditional / always / all / MUST" clause already in that row and write the exception
**into** it, rather than merely before it.

**Twenty-first amendment — a per-capability requirement needs a per-capability *structure*, not only
per-capability rows.** Rounds 16–17 established that paired config rows and paired tests are required; this
round shows the same split must exist in the **flow model**. A capability whose traffic has no drawn path
through a control has no structural evidence that the control applies to it, whatever the config matrix says.

**Standing note.** Rounds 22–28: eight consecutive rounds in which each round's fix produced the next round's
findings. Fourteen of the last seventeen rounds found defects in the immediately preceding round's new text.
Round 27's low-risk arm is the clearest case yet of a fix that read correctly and broke the flow it was
describing.

**Unchanged by round 28:** no requirement or threat ID added, removed or renumbered. ADR-0024
`Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 0 duplicates / 27
contiguous abuse cases / 0 `Both` capability rows; predicates 7, 13, 18, 19 and the outcome-lane check clean;
`SPOOL` still has zero unconditional out-edges; no non-ASCII strays; documentation only; PR-1 not begun.

---

## Round 29 — round 28's three fixes each left one consequence (`a9ebada3` → next)

Three Codex findings, all consequences of round 28.

### R29-1 (P2) — my `LOSS` dispatch made `degrade-and-alert` behave as `fail-closed`

Round 26's `LOSS` node routed `read-only / low-risk` to the degradation node and stopped. But the config
surface offers `mcp_{gateway,mgmt}_event_loss_policy`, and `degrade-and-alert` means the degradation is
**recorded while the low-risk operation proceeds**. Terminating the arm at degradation silently converted the
documented policy into `fail-closed` — the diagram overrode a configurable contract.

**Fix.** The arm now branches on the configured policy: `degrade-and-alert` → record degradation (`LDEG`) **and
continue to `XLOW`**; `fail-closed` → `FC`. Also corrected a conflation I had introduced: `LDEG` (decision lane,
operation **has not** happened) is distinct from `ODEG` (outcome lane, operation **already** happened) — routing
the decision-lane case to `ODEG` was wrong on its own terms, since `ODEG`'s whole premise is that re-execution
is impossible.

### R29-2 (P1) — the Management flows reached authorization without listener-side Host/Origin validation

Round 28 added the protocol kernel upstream of the Management listener and went straight on to
authz/tool-handling. But `MCP-INSP-008` is **deliberately listener-independent** and cannot perform
per-request `Host`/`:authority`/`Origin` checks after header parsing — that is `MCP-INSP-009`, which I did not
place on the path. An implementation following DFD-1/DFD-2 could accept a disallowed request on a reused HTTP/2
connection: exactly the bypass round 18 corrected for the Gateway, reintroduced on the Management side by my own
new path.

**Fix.** Both Management flows now show `MCP-INSP-009` validation between the kernel and the listener —
per request **and** per H2 stream, against the **Management** allowlist — with an explicit reject edge.

### R29-3 (P2) — the trust-boundary coverage row still said Gateway-only

Round 28 retitled DFD-15 to Capability **A and B** and left the coverage-summary row reading
`B (gateway, PR-1 kernel) | TB-1`. A trust-boundary audit run from that table would still report **no
protocol-kernel protection for the Management boundary** — the summary contradicted the diagram it summarises,
in the same file, two hundred lines apart. Now `A and B | TB-1, TB-7`.

**Twenty-second amendment — a diagram's summary row is a consumer of the diagram.** The chain recorded in round
27 (requirement → gate → traceability → slice contract → release gate) has an intra-document link I had not
counted: **coverage/summary tables inside the same file**. They are what an auditor reads instead of the
diagram, so they must be updated with it. This is the fifth distinct link where the same stop-early error has
occurred (rounds 19, 24, 26, 27, 29).

**Standing note.** Rounds 22–29: nine consecutive rounds where each round's fix produced the next round's
findings. R29-1 and R29-2 are both cases where **a fix silently overrode a control documented elsewhere** — a
config contract and a listener requirement respectively — rather than merely being incomplete. That is a
different and worse failure mode than the propagation gaps of rounds 5–15.

**Unchanged by round 29:** no requirement or threat ID added, removed or renumbered. ADR-0024
`Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 0 duplicates / 27
contiguous abuse cases / 0 `Both` capability rows; predicates 7, 13, 18, 19 and the outcome-lane check clean;
`SPOOL` has zero unconditional out-edges; no non-ASCII strays; documentation only; PR-1 not begun.

## Round 30 — every one of round 29's three fixes reached the graph and not the sentence that restates it (`64885629` → next)

Three P2 findings, all on round 29's own changes, all the **same** shape: the fix landed in the structure and
not in a nearby artifact that restates the same fact. Amendment 22 named exactly this class one round earlier.

**R30-1 — DFD-9's dispatch prose still said "read-only/low-risk to degraded only."** Round 29 replaced that
arm with a policy branch (`LP`: `degrade-and-alert` proceeds to `XLOW`, `fail-closed` denies) and left the
paragraph four lines below summarising the pre-branch behaviour. An implementer reading the prose would omit
the configured `fail-closed` path the branch existed to restore. The paragraph now describes both outcomes and
states that this arm is a **policy selection, not a posture**.

**Two residuals in that same paragraph, which the reviewer did not flag and the sweep found:**

- it still read *"durably committed BEFORE credential use and the upstream call"* — the exact round-22
  phrasing that **amendment 15 was recorded to eliminate**, because it does not constrain configuration
  publication or credential materialization. Now "BEFORE that class's OWN irreversible action".
- it still called the loss handling *"two loss branches"* enumerating four critical classes — stale since
  round 26 added `state-affecting Management` and round 29 added the policy arm. Now **three** branches, five
  critical classes.

**R30-2 — `MCP-INSP-009` on the Management path had no threat traceability.** Round 29 put the rebinding guard
on DFD-1/DFD-2 but left both flows' threat declarations, both coverage rows, and both `THREAT-MODEL.md` STRIDE
rows without `MCP-T-031`/`MCP-T-055`. A threat-to-flow audit would report **no Management flow covering the
exact risk the new node mitigates**. All six sites now carry them. DFD-3 is deliberately **not** included: it
has no listener node (it begins at `Plan`) and so does not consume `MCP-INSP-009` — an exclusion by
construction, recorded so it does not read as an oversight.

**R30-3 — DFD-15's own boundary declaration still said `Crosses TB-1`.** Round 29 fixed the coverage row to
`TB-1, TB-7` and left the diagram's own header Gateway-only. The header and the summary of the same diagram
disagreed *about the fix made in the previous round*.

**The sibling-diagram instance the sweep found, unflagged: `EVENT-MODEL`'s canonical event-flow diagram had
the same missing policy branch** — `CRIT -- "no (low-risk ALLOW/MONITOR)" --> DEG`, with no route to `FAIL` at
all. So in the file that **owns** the event model, `fail-closed` was an unreachable value of a documented enum.
Fixed with the same `LP` branch plus prose. This is the **sixth** time a flow change reached one diagram and
not its siblings (15, 19, 22, 24, 26, 30).

**Twenty-third amendment — a structural fix is not complete until every sentence that describes that
structure is re-read.** Amendment 22 established that summary *tables* are consumers. R30-1 shows that
**prose paragraphs immediately adjacent to the diagram** are the same hazard and are harder to see, because
proximity reads as currency. The operative unit is not the file and not the diagram — it is **every
restatement of the changed fact**, and the ones nearest the change are the ones least likely to be checked.

**Predicate 21 (new) — DFD header ⇔ coverage-row parity.** For every DFD the trust-boundary set and threat set
declared in its own `Crosses … Threats: …` header must equal the coverage-summary row that restates it.
Vocabulary is **derived from the two tables themselves**, not a hand-written token list, so it cannot decay
(amendment 20). Seeded with three known-positives (drop `TB-7` from DFD-15's header; drop `031/055` from
DFD-1's coverage row; drop `TB-5` from DFD-2's coverage row) — **each seed is required to produce a NEW
violation naming the seeded DFD.** That requirement mattered twice:

1. My first harness reported `FIRES` for the DFD-15 seed while actually naming **DFD-6** — it was passing on a
   pre-existing residual, not on the seeded change. A predicate that "fires" for the wrong reason is worth
   less than no predicate, because it certifies the wrong thing.
2. With the harness corrected the DFD-15 seed then genuinely **MISSED**: my boundary extraction scanned the
   whole header line, so the explanatory prose "*Management traffic crosses TB-7*" kept satisfying the check
   after the declaration itself was gutted. The parse now stops at the declaration clause. **A later prose
   mention of a boundary is not a declaration of it** — and my own round-30 wording was what hid the gap.

Strict-arm residual: **NONE**.

**Pre-existing divergence surfaced, NOT silently fixed.** Predicate 21's advisory arm compares each DFD header
against `THREAT-MODEL.md`'s §9 STRIDE row and reports five mismatches in flows this round did not touch —
DFD-6 (`005`), DFD-7 (`040`), DFD-12 (`031`, `055`), DFD-13 (`010` vs `053`), DFD-14 (`031`, `052` vs `051`).
That arm is **advisory and not gated**, because whether §9's STRIDE emphasis must equal a DFD's dominant-threat
declaration is a design question, not a drift bug — and editing five untouched rows to make my own new check
go green would be precisely the kind of unreviewed change that looks like rigour. **Flagged for human
adjudication at PR-0 sign-off; deliberately left failing-visible rather than resolved by me.**

**Standing note.** Rounds 22–30: ten consecutive rounds in which each round's fix produced the next round's
findings. Every one of round 30's three findings is an instance of the class recorded as amendment 22 in round
29 — I wrote the rule and then reproduced the error three times in the same commit. The sweep did find two
unflagged residuals and one sibling-diagram defect this round, which is the second time my own checking has
added anything; it also produced a predicate that certified the wrong thing until corrected twice. That is the
accurate summary, and it is not a convergence claim.

**Unchanged by round 30:** no requirement or threat ID added, removed or renumbered (`MCP-T-031`/`055` were
already defined; only their flow traceability changed). ADR-0024 `Status: Proposed`;
`PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 0 duplicates / 27 contiguous abuse
cases / 0 `Both` capability rows; predicates 7, 13, 18, 19, 21 and the outcome-lane check clean; `SPOOL` has
zero unconditional out-edges; `LOSS` has exactly three arms and `LP` exactly two; no non-ASCII strays;
documentation only; PR-1 not begun.

## Round 31 — round 30 claimed a swept dimension and had swept one file of three (`4bbf1e16` → next)

Five P2 findings. **Two are the identical sentence round 30 fixed in one file while its own reply asserted the
dimension had been swept**, and the check that would have found them is a one-second grep.

**R31-1 / R31-2 — the amendment-15 phrasing survived in `EVENT-MODEL` §4a and `ADR-0024` §D-5.** Round 30 found
the narrow wording ("durably committed BEFORE credential use and the upstream call") in DFD-9's caption, fixed
it there, reported it as a sweep residual — and never grepped the package for the same sentence. It was in
**three** live documents. Configuration publication and the Management class perform no upstream call, so in
both of those files the load-bearing precondition constrained nothing for two of the five critical classes,
directly contradicting the per-class table printed immediately below it in each.

**The third instance — `RECOMMENDED-ARCHITECTURE.md:149` — the reviewer did NOT flag.** Found only because this
round finally ran the grep. All three now name each class's own irreversible action, and each states explicitly
why the narrow phrasing is insufficient so it cannot be "simplified" back.

**R31-3 — `MCP-EVENT-002`'s own Verification and Evidence cells omitted the Management class.** The requirement
declares five critical classes and its per-class absence assertions enumerated three, so PR-8 could satisfy the
**canonical requirement row** without proving a Management state change absent. Both cells now carry it. This is
amendment 15's test-side corollary at its source: the row that *defines* the enumeration was itself short.

**R31-4 — DFD-5 unconditionally failed low-risk calls closed.** `WAL -- commit FAILED --> FCG` applied to every
class, and DFD-5 carries **all** ALLOW-class traffic — so the primary Gateway flow made `degrade-and-alert`
behave as `fail-closed` for every read-only call, the exact defect round 29 fixed in DFD-9 and round 30 fixed in
`EVENT-MODEL`. **Third file, same defect, third consecutive round.** Now class-aware via `LPG`; the caption
records that DFD-6/10/11 need no such arm **by construction** (credential materialization and snapshot
publication are always critical), so the absence there is not a fourth instance waiting.

**R31-5 — round 30's own new edge dropped half its outcome.** `LP -- fail-closed --> FAIL` reached only `FAIL`,
which denies the operation; the prose below says low-risk loss **always** degrades and alerts, with the policy
deciding only whether it *also* blocks. So the edge I added one round earlier lost the degraded/alert/counter
half. Fixed with an explicit AND pair, matching how `KIND` already expresses AND.

**Twenty-fourth amendment — a phrase is a dimension, and the sweep for it is `grep`, not memory.** Rounds
22–30 treated "sweep the dimension" as re-reading the artifacts I could bring to mind. For a defect that is a
**specific form of words**, the dimension is enumerable mechanically and exhaustively in one command. Round 30
found the narrow phrasing, wrote three paragraphs about why it mattered, and fixed one third of it — because it
searched its memory of the package instead of the package. **When the defect has a textual signature, grep the
whole tree before claiming the dimension is closed.**

**Predicate 22 (new) — no live normative document may state the ordering precondition in the narrow form.**
Vocabulary derived from `MCP-EVENT-002`'s class table (amendment 20); the ledger is **excluded by design**
because it records historical wording verbatim (2 occurrences retained). Seeded by injecting the narrow sentence
into each of the three files that carried it — each seed required to produce a NEW violation naming that file.
All three fire; residual on live documents **NONE**.

**Standing note.** Rounds 22–31: eleven consecutive rounds where each round's fix produced the next round's
findings. Round 30 recorded amendment 23 about restatements being consumers, and R31-1/2/4 are three more
restatements it did not reach. The one thing this round did better is mechanical: the grep found a site the
reviewer missed. That is the argument for **executed checks over recorded discipline**, which is now the
eleventh consecutive round's worth of evidence for the same conclusion — and it is not a convergence claim.

**Unchanged by round 31:** no requirement or threat ID added, removed or renumbered. ADR-0024
`Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 0 duplicates / 27
contiguous abuse cases; predicates 7, 13, 18, 19, 21, 22 and the outcome-lane check clean; `SPOOL` has zero
unconditional out-edges; no non-ASCII strays; documentation only; PR-1 not begun.

## Round 32 — round 31's own fix opened a post-commit-failure credential mutation (`07dcbfeb` → next)

Three P2 findings. **Two are defects in round 31's DFD-5 fix, and the first is a security regression I
introduced while restoring correct behaviour** — the same shape as rounds 23 and 27.

**R32-1 — `LPG -- degrade-and-alert --> CB` routed a failed low-risk commit into broker MATERIALIZE.** `CB`
mints/rotates/revokes, which is itself the `MCP-EVENT-002` **credential critical class** and requires a
*confirmed* commit (DFD-6 fails it closed unconditionally). So round 31's fix — which existed to stop
`degrade-and-alert` behaving as `fail-closed` — created a path where **broker state mutates after the commit
failed**, the precise failure the requirement exists to prevent. The degraded continuation is now explicitly
**non-mutating**: `LOWX` proceeds only on a credential already valid from the `PLAN` phase, and a low-risk call
that *needs* materialization **fails closed**, because minting is what the policy would be authorising and the
low-risk loss policy cannot authorise it. Verified mechanically: **`CB`'s only in-edge is `WAL`.**

**R32-2 — the `WAL` node label still read "commit FAILED ⇒ fail closed, nothing runs"** while the arms below it
allowed low-risk continuation. **Fourth instance of one specific failure mode: my labels and prose are ahead of
(or behind) the graph in the same commit** — round 24 (label said "commit CONFIRMED", graph branched on
saturation), round 27 (caption claimed mandatory, bypass two lines below), round 31 (prose said "always
degrades", edge degraded in one of two cases), round 32 (label says unconditional, graph is class-aware). Now
class-aware.

**R32-3 — the Management absence assertion added in round 31 is gated where its mechanism does not exist.**
`ADR-0024` §D-13 defers **every** Management mutation past V1, so PR-8 can only test a fake path, and — unlike
configuration publication, which has the mandatory PR-10 re-run — **no later Management slice existed to
inherit the real-path assertion.** That is amendment 18's class exactly: an obligation placed where the
machinery isn't. Now dual-owned at all four consumer links (requirement row, blocking gate, slice contract,
traceability row): **PR-8 stub only; the real-path assertion belongs to the future Management-mutation gate,
which MUST NOT be marked green without it.**

**Predicate 18's vocabulary was blind to this, and that is amendment 20 for the third time.** Its token list
(`signed CP`, `publication path`, `CP→DP`, `snapshot swap`) was drawn from the PR-10 finding that produced it,
so a row naming a **Management** mechanism could never match. The vocabulary now derives from the deferral
authorities (including `ADR-0024` §D-13), seeded with a row that names the deferred mechanism and carries no
note — fires; residual **NONE**.

**Standing note.** Rounds 22–32: twelve consecutive rounds in which each round's fix produced the next round's
findings. Round 31 closed with the claim that its grep sweep was the round's one mechanical win; R32-1 shows
the same commit opened a credential-mutation path after a failed commit. **A round can be simultaneously the
best-verified so far and the one that introduces the worst defect** — those are not in tension, and the ledger
should stop implying they are.

**Unchanged by round 32:** no requirement or threat ID added, removed or renumbered. ADR-0024
`Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 0 duplicates;
predicates 13, 18 (re-derived), 19, 21, 22 and the outcome-lane check clean; `CB` reachable only via `WAL`;
no non-ASCII strays; documentation only; PR-1 not begun.

## Round 33 — round 32 named a gate that did not exist, and put the note in the wrong column (`71af0423`/`316ad14a` → next)

One P2 finding, and it lands on **amendment 10a at the same matrix that produced amendment 10a's own
restatement in round 24.** Round 32 fixed the Management slice-timing gap by writing "PR-8 stub only; the
real-path assertion is owned by the future Management-mutation gate" into the **Test** cell of
`TEST-TRACEABILITY-MATRIX`'s `MCP-T-044` row — and left the formal **Gate** column reading
`PR-8 + mandatory PR-10 re-run (publication path)`. A consumer reading the Gate column, which is the cell that
actually says when the row is closed, could mark `MCP-T-044` done having run the assertion only as a stub.

**Round 24's finding on this exact matrix was that I edited the threat-NAME cell instead of Test/Evidence.
Round 33's is that I edited the Test cell instead of Gate.** Amendment 10a's own corollary — *confirm the cell
you edited is one a gate CONSUMES* — has now failed twice in the same table, in the same way, nine rounds
apart, with the rule written down in between.

**The larger defect the sweep found, which the reviewer did not state:** "owned by the future
Management-mutation gate" **named a gate that existed nowhere in the package.** `ADR-0024` §D-13 defers
Management mutation, but no gate section owned the deferred assertion — unlike PR-C and the Future DMZ gate,
which are real named post-V1 gates with their own requirement/test/owner fields. So round 32's dual ownership
had **one owner and one dangling reference**, which is the attribution class (a citation naming something that
does not state — here, does not exist).

Fixed by making the owner real, then pointing all four references at it:

- **New `## Future Management-Mutation Gate (post-V1, not a PR slice)`** in `IMPLEMENTATION-SLICES.md`,
  modelled on the Future DMZ gate: objective, non-goals, `MCP-MGMT-001` + `MCP-EVENT-002` for the
  `state-affecting Management` class, the **real-path re-run** as its test, owner/reviewer, and "MUST NOT be
  marked green without that re-run" — plus, like PR-C and the DMZ gate, explicitly **not** a Production
  Qualification dependency, so V1 GA cannot come to depend on post-GA work.
- **Traceability Gate column** and the **CI-GATES gate-status row** now both name it.
- The prose references in `SECURITY-REQUIREMENTS`, `CI-GATES` and `IMPLEMENTATION-SLICES` were rewritten from
  the lowercase "future Management-mutation gate" to the **defined** gate name, so each reference resolves.

**Also this round: 6 behind `main`.** Merged in (no rebase, no force-push, per the standing constraint) —
`316ad14a`, 0 behind, still documentation-only for this branch's own contribution, all invariants re-verified
**after** the merge rather than before it.

**Standing note.** Rounds 22–33: thirteen consecutive rounds, each producing the next round's findings. The
one structural observation worth adding is that round 32's error was **not** a propagation miss — I did carry
the fix to four documents. It was that the thing I carried pointed at nothing, and that the one cell which
formally gates the row was not among the four. **Breadth of propagation is not the same as reaching the
consuming cell**, and my sweeps optimise for the former.

**Unchanged by round 33:** no requirement or threat ID added, removed or renumbered (a new *gate* is not a new
requirement). ADR-0024 `Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91
requirements / 0 duplicates; no malformed traceability rows; predicates 21-strict and 22 clean; no non-ASCII
strays; documentation only; PR-1 not begun.

## Round 34 — the gate I created in round 33 could go green on one failure mode, and its own subject flow was ungated (`eca4d838` → next)

Two P2 findings, **both on the `Future Management-Mutation Gate` section round 33 added one round earlier.**

**R34-1 — the gate's test said "non-persistable via EITHER queue saturation OR spool commit failure".**
`MCP-EVENT-002` requires **both**, as separate cases: saturation *and* a distinct post-admission commit
failure. "Either" lets the gate go green having exercised one path — and a real mutation handler that blocks
on saturation but changes state after an `fsync` failure (or the reverse) passes. **The sweep found the
identical weakening in PR-10's re-run** (`queue saturated **or** spool commit failed`) **and in the rollback
failure-injection case** — both written in rounds 26/27, both unflagged for eight rounds. All three now
require BOTH modes as separate cases and say why either alone is insufficient.

**R34-2 — DFD-3 routed `APPR --> PUB[Publish signed snapshot]` directly.** The gate I created designates DFD-3
as the future Management-mutation flow, and DFD-3 documented publishing straight after four-eyes approval with
**no durable commit and no failure branch** — i.e. the flow the gate exists to govern still violated the one
assertion the gate owns. Now `APPR → WALM{commit} → PUB`, with a commit-FAILED arm that publishes nothing and
changes no Management state, and a caption saying plainly that **human approval is necessary but not
sufficient**. `PUB`'s only in-edge is `WALM`.

**Predicate 19 was blind to DFD-3, and this is amendment 20's FOURTH failure.** Its action vocabulary carried
`SIGN[` but nothing matching `PUB[Publish signed snapshot]`, so the one diagram in the package with an
ungated publication could never be flagged — it reported `NONE` across all fifteen DFDs while DFD-3 sat there.
The vocabulary now derives from `MCP-EVENT-002`'s own words — *"before the snapshot is **signed, pushed or
applied**"* — rather than from node names I had happened to write. Seeded by reverting DFD-3's gate: **fires on
block 3**; residual `NONE`; DFD-8 (post-execution `Upstream response`) still correctly excluded.

**The pattern across amendment 20's four failures is now unambiguous.** Round 27: `Atomic swap` missing.
Round 32: Management mechanisms missing from predicate 18. Round 34: publish-type nodes missing from
predicate 19 — *the same predicate I re-derived in round 27*. Re-deriving a predicate once, from the authority,
at the moment it fails, does not keep it derived. **Each predicate needs its vocabulary re-derived from the
authority on every round in which that authority's text changes**, and I have never once done that
prospectively — only in response to a finding that the check missed.

**A note on scope discipline, since it cuts the other way this time.** Round 30 deliberately *excluded* DFD-3
from the `MCP-INSP-009` sweep, correctly: it has no listener node. That exclusion was sound for that control
and I recorded it as by-construction. But I never asked the separate question of whether DFD-3 needed the
**durability** gate. **A justified exclusion from one dimension is not an exclusion from the others**, and
writing down "excluded by construction" made the diagram feel handled.

**Standing note.** Rounds 22–34: thirteen consecutive rounds, each producing the next round's findings. Round
33 created a gate; round 34 found that gate could pass on half its contract and that its own subject flow was
ungated. The gate was still worth creating — the alternative was the dangling reference it replaced — but
**creating an artifact and getting it right are separate events**, and the ledger should not let the first
imply the second.

**Unchanged by round 34:** no requirement or threat ID added, removed or renumbered. ADR-0024
`Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 0 duplicates / 27
contiguous abuse cases; `CB` in-edges `[WAL]`, `PUB` in-edges `[WALM]`; DFD-3 has no undefined edge targets;
predicates 13, 19 (re-derived), 21-strict, 22 clean; no non-ASCII strays; documentation only; PR-1 not begun.

## Round 35 — the gate names two owners and blocks on one; the gate's own subject flow has two irreversible actions and the test asserts one (`8da359ad` → next)

Two P2 findings. Both land, for the **third consecutive round**, on the `Future Management-Mutation Gate`
section — created in round 33, amended in round 34, wrong again in round 35.

**R35-1 — the gate-status row's `Blocking?` cell named PR-8 while its `Target PR` cell named PR-8 AND the
future gate.** A consumer reading the status column could therefore treat the post-V1 real-path re-run as
advisory and close the proposed gate on PR-8's stub coverage — which is precisely the outcome the D-13 section
exists to prevent. The blocking designation now names both, and says the gate MUST NOT be marked green on stub
coverage.

**The sweep was mechanical, not from memory.** Predicate 23 enumerates owner tokens from every gate-status
row's Target cell and subtracts the Blocking cell's, with the owner vocabulary derived from the cells
themselves (`PR-<n>`, `PR-C`, any `Future … Gate`, any `D-nn`). **16 rows examined, three seeded
known-positives fire, residual NONE** — so the row Codex found was the only one, and I can say that without
having re-read the table.

**R35-2 — the gate's test asserted `NO Management state change occurred`, and DFD-3's irreversible action is
`Publish signed snapshot`.** A handler can leave its Management record untouched and still sign or push after
`WALM` fails; it would pass both required failure modes. Round 34 gated the flow correctly and then wrote an
assertion covering only half of what the gate now protects.

**The general defect, which is bigger than the finding.** The whole package had been enumerating absence
assertions **by class NAME** — each class asserting the absence of the action it is named after. But the
assertion is scoped to a **FLOW**, and a flow can carry two classes' irreversible actions:

- DFD-3's approved Management mutation **changes Management state AND publishes a signed snapshot**.
- DFD-5's `WAL` gate precedes **both broker materialization AND the upstream call** — and its fail-closed node
  has said so all along (`no credential minted, no upstream call`), so the diagram was already stricter than
  the tests derived from it.

So three clauses were short, not one: `write/destructive` needed *no materialization*, `credential` needed
*no upstream call*, and `state-affecting Management` needed the publication-class absences. All are fixed in
`SECURITY-REQUIREMENTS` (`MCP-EVENT-002` Verification + Evidence), `EVENT-MODEL` §4a, `ADR-0024` §D-5,
`CI-GATES` (blocking row), `IMPLEMENTATION-SLICES` (PR-8 + the future gate), and
`TEST-TRACEABILITY-MATRIX` (MCP-T-044 Test + Evidence), with the rule stated once in the authority: **the
assertion set is per FLOW, not per class NAME.**

**Predicate 24 found the consumer I had not reached.** It parses the required action-key set for each class
out of EVENT-MODEL §4a's table and checks every per-class enumeration in four documents against it. After I
had fixed five documents by hand it still reported three live violations — all in
`TEST-TRACEABILITY-MATRIX.md`, which I had not opened. Three seeded reversions fire; residual now NONE. This
is the first round in which a predicate caught a propagation gap **before** the reviewer, rather than after.

**Predicate 24 arm 2 — the authority exists in TWO copies, and I made them diverge inside this round.**
EVENT-MODEL §4a and ADR-0024 §D-5 each carry the same per-class table. I fixed EVENT-MODEL's first; for the
next several minutes the ADR silently contradicted it, with no check that would have said so. Arm 2 now
compares the two copies cell-for-cell (seed-proven: reverting the ADR's Management row reports all three
differing columns). **Twenty-fifth amendment — a duplicated authority needs a predicate that compares the
copies, not one that validates each.** Checking each copy against itself passes two copies that disagree.

**Twenty-sixth amendment — an absence assertion is scoped to a FLOW, not to the class's NAME.** Enumerate the
irreversible actions reachable downstream of that flow's commit gate and assert every one of them; the
eponymous action is the one you will think of, and the other is the one the implementation will perform.

**On predicate 19, and a correction to round 34's claim.** Round 34 reported predicate 19 as "fires on block
3, residual NONE" but never saved it, so this round I re-derived it — and the reconstruction reported a
residual on DFD-2 (`VAL -. never publishes .-> X[(No snapshot change)]`) that round 34's version evidently
excluded silently. A **negated** edge documents an action's absence, not its occurrence; that exclusion is now
written down and the predicate is saved to a file rather than to a transcript. **Round 34's numbers were
right; the artifact that produced them did not exist**, which makes them unverifiable, and I recorded them as
if they were reproducible.

**Standing note.** Rounds 22–35: fourteen consecutive rounds, each producing the next round's findings. Rounds
33, 34 and 35 have all landed on the same section, each time on the part the previous round had just written.
Round 34's ledger said "creating an artifact and getting it right are separate events"; round 35 is that
sentence applied to round 34's own correction.

**Unchanged by round 35:** no requirement, threat or abuse-case ID added, removed or renumbered; no diagram
edge added or removed. ADR-0024 `Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74 threats /
91 requirements / 0 duplicates / 27 contiguous abuse cases; predicates 19, 21-strict, 22, 23, 24 (both arms)
clean; no non-ASCII strays; documentation only; PR-1 not begun.

## Round 36 — the round-35 correction was itself unverifiable: I claimed a saved artifact and saved it outside the repository (`2f251b80` → next)

One P2 finding, and it lands on **the paragraph in which round 35 corrected round 34 for recording an
unreproducible verification result.**

**R36-1 — "the predicate is a file, not a transcript" was true and useless.** The file was in a working
scratchpad, not in the tree, so a reviewer searching tracked files finds only prose. Round 34 recorded a
result with no artifact; round 35 named that as the defect, produced an artifact, and left it somewhere no
reader of this repository can reach. **A verification artifact that is not in the repository is, to every
consumer of the repository, exactly the transcript I said I had stopped writing.** The correction reproduced
the defect one level down, which makes this the fourth *fix-introduced defect* in the log and the third
consecutive round landing on the previous round's own words.

**Fixed:** [`predicates/`](predicates/) now holds `predicate-19.py`, `predicate-21.py`, `predicate-22.py`,
`predicate-23.py` and `predicate-24.py`, plus a README giving the run command, the two-part contract every
predicate satisfies (**seeded known-positives must fire** *and* residual must be empty), and the authority
each one derives its vocabulary from. All five exit `0` when run from the repository root. They are
standalone scripts, not wired to CI — PR-0 modifies no workflow file, and promoting them into executed gates
stays recorded work for PR-0/PR-1.

**The sweep is the part that costs me something.** The dimension is not "check in predicate 19"; it is
**every result this log claims**. Predicates **7, 8, 13, 18 and the outcome-lane check** were never saved,
and they are cited in eleven round-closing verification lines. They are now listed in a **reproducibility
register** in the README and in this log's header as **NOT re-runnable** — the recorded results stand as
claims, explicitly labelled, rather than being quietly backed by an artifact that does not exist.

**I did not reconstruct them, and that is deliberate.** Round 35 re-derived predicate 19 and the
reconstruction reported a residual the original had evidently excluded in silence; a reconstruction is a
*different* check wearing the same number, and filling the register with reconstructions would have made the
table look complete while making it less true. The honest table has five rows filled and five rows marked
unavailable.

**Twenty-seventh amendment — an artifact is only evidence where the reader can run it.** "Saved" is not a
property of my session; it is a property of the tree the reviewer clones. Any claim of the form *"predicate
N: seeds fire, residual NONE"* must be accompanied by a tracked path, or be labelled as unreproducible in
the same breath.

**Standing note.** Rounds 22–36: fifteen consecutive rounds. Rounds 33, 34, 35 and 36 form a chain in which
each round's finding is on the artifact the previous round created to fix the round before it — a gate, then
its failure modes, then its assertion set, then the evidence for the assertion set. The ledger's habit of
recording a lesson in the same round it violates it is now itself the most reliable pattern in the log.

**Unchanged by round 36:** no requirement, threat or abuse-case ID added, removed or renumbered; no diagram
edge added or removed; no normative statement changed. ADR-0024 `Status: Proposed`;
`PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements / 0 duplicates / 27 contiguous abuse
cases; predicates 19, 21, 22, 23, 24 all exit `0` **from the checked-in copies**; no non-ASCII strays;
changes confined to `docs/`; PR-1 not begun.

## Round 37 — checking the predicates in made them reviewable, and the first review found one certifying parity it had not verified (`2d5a1b98` → next)

One P2 finding, **on `predicates/predicate-21.py` itself** — round 36's own deliverable, reviewed within
minutes of becoming visible. That is the point of checking them in, and it took one round to prove it.

**R37-1 — `nums()` kept only a range's endpoints.** These documents write threat ranges two ways —
`MCP-T-011..017` in the DFD headers, `011–017` (en-dash) in the coverage rows — and the parser matched
`\d{3}` against the raw text. So `057..074` and `057, 074` compared **equal**: a coverage row that dropped
threats 058–073 would have been certified as header/coverage parity. The predicate was not merely weak on
that input; **it reported `NONE` while the property it claims to check was unverified for every ranged row**
— which is five of the fifteen DFDs, including DFD-15's entire eighteen-threat protocol-kernel range.

`nums()` now expands both syntaxes (and a hyphen form, since nothing stops a future edit using it) before
comparing. Seed-proven **in both directions**: collapsing DFD-15's range on the *coverage* side fires, and
collapsing DFD-4's `011..017` on the *header* side fires. The strict residual stays `NONE`, so no live
violation was hiding behind the endpoints — the defect was in what the check could prove, not in the
documents.

**The sweep is an audit of every predicate that compares parsed sets.** `predicate-23.py` reads owner tokens
from two table cells and subtracts them; `PR-1..PR-11` is a form these documents use elsewhere, so it now
expands `PR-a..PR-b` (seed-proven) even though no gate-status cell uses it today — the point is that a future
edit must not be able to narrow the comparison silently. `predicate-19`, `-22` and `-24` compare node
presence, phrasing and action-keys rather than identifier sets, so no expansion applies; that was **checked
and recorded in `predicates/README.md`**, not assumed. `TB-n` is never written as a range, and the README
says what to do if that changes.

**Twenty-eighth amendment — a set comparison must expand every compressed notation in its inputs before
comparing.** Matching a range literally does not fail loudly; it silently shrinks the property to its
endpoints and still prints `NONE`. Any predicate that parses identifiers out of prose has to normalise
before it compares, and its seeds must include a *collapse* of each compressed form on **each** side of the
comparison.

**What this round says about the previous thirty-six.** A predicate reporting `NONE` has been my strongest
evidence in every round-closing line, and this is the first external check of whether one of them means what
I said it meant. It did not. The other four have now been audited for the same class, but they have been
audited **by me**, which is exactly the assurance this finding just devalued. The register in
`predicates/README.md` already marks predicates 7, 8, 13, 18 and the outcome-lane check as unavailable; the
honest reading of round 37 is that the five that *are* available were, until now, unreviewed.

**Standing note.** Rounds 22–37: sixteen consecutive rounds. Rounds 33 → 37 are one chain — a gate, its
failure modes, its assertion set, the evidence for the assertion set, and now the correctness of the evidence
itself. Each round's artifact became the next round's finding.

**Unchanged by round 37:** no requirement, threat or abuse-case ID added, removed or renumbered; no diagram
edge added or removed; no normative statement changed — the only document edits are `predicates/` and this
log. ADR-0024 `Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements /
0 duplicates / 27 contiguous abuse cases; predicates 19, 21, 22, 23, 24 all exit `0` from the checked-in
copies; no non-ASCII strays; changes confined to `docs/`; PR-1 not begun.

## Round 38 — two predicates did not check what they claimed, and the requirement registry's provenance note was false (`9331813e` → next)

Three P2 findings. Two are in the predicates checked in one round earlier; one is in the canonical
requirement registry and had been live since the package was written.

**R38-1 — `predicate-22` matched one SENTENCE, not the prohibited MEANING.** It searched for the literal
string `committed BEFORE credential use`. So `durably committed before the upstream call`, and
`durably persisted before credential use and the upstream call` — the same incomplete ordering rule,
differently worded — produced **no violation**, and `CLASS_ACTS`, the vocabulary derived from the
authority, was **asserted at start-up and never used in the decision**. The predicate's `NONE` did not
establish the property the README claimed for it. It now compares the actions a sentence NAMES against the
four `MCP-EVENT-002` requires: the class-generic delegation passes, an enumeration of all four passes, a
sentence scoped to one class passes when it names exactly that class's own actions (parsed from EVENT-MODEL
§4a), and anything else is a violation. Four seeds — each a *different* incomplete phrasing — fire; a
negative control on the class-generic form stays silent; residual `NONE`.

**R38-2 — `predicate-24` could be defeated by a Markdown reflow.** It skipped any line not containing the
literal `upstream call`. The configuration-publication and Management clauses mention no upstream call, so
reformatting the enumeration into one bullet or line per class — a purely cosmetic edit — would have
dropped them from coverage entirely while the predicate still printed `NONE`. The prerequisite is gone, the
scan is text-wide, and there is now a seed that **reflows the layout and weakens a clause in the same
edit**. Removing the filter produced no false positives: residual stayed `NONE`.

**Both are the same defect as round 37's, one level up.** Round 37 was a predicate certifying parity it had
not verified; these are predicates certifying properties they never tested. The common shape: **a check
whose `NONE` is cheaper to produce than the property it stands for.**

**R38-3 — the requirement registry said its IDs and statements were "unchanged except MCP-AUTH-006".** That
is false in both directions: this remediation **adds sixteen IDs** (`MCP-PROTO-001..014`, `MCP-ID-008`,
`MCP-INSP-009`) and **rewrites seven statements** (`MCP-AUTH-003`, `MCP-AUTH-006`, `MCP-EVENT-001`,
`MCP-EVENT-002`, `MCP-INSP-001`, `MCP-INSP-008`, `MCP-OPS-002`). A provenance note is the one thing a
reviewer reads **instead of** the diff, so a false one is worse than none — and this was in the canonical
registry, the document where the change list most needs to be exact. The note now carries the enumerated
sets, states that none were removed, and says plainly what the old sentence hid.

**The sweep found two more provenance claims, and one of them was also false.** Grepping the package for
"unchanged" claims rather than fixing the reported line:

- `OPEN-DECISIONS.md` — "All other decisions are unchanged." The touched blocks are exactly the seven the
  note names, **but it omitted that D-14 is entirely new**. Now stated.
- `VERIFIED-REPOSITORY-CONTEXT.md` — "Non-⟳ rows are unchanged." **False for two rows**: `ID-token
  validation` (its *Class for MCP* cell was rewritten for ADR-0024 §D-2) and `OpenAPI contract + CI gate`
  (ADR-0018 re-cited by path). Both are text corrections rather than line-range fixes, so they carry no ⟳;
  the note now names them.
- `PR0-REVIEW-CHECKLIST.md` — its "no code/CI/config/runtime change" line predates round 36's
  `predicates/`. Qualified to **no product code**, with the predicates named as non-workflow document checks.

**Predicate 25 makes this class enumerable instead of remembered.** It parses each provenance note's own
claimed sets and compares them against `git merge-base HEAD origin/main`: added/rewritten requirement IDs,
touched decision blocks, and every repository-context row that changed without a ⟳ or a mention. Four seeds
fire (drop an added ID; drop a rewritten ID; drop D-14; drop a named row); residual `NONE`. **The diff is
the authority, which is the only thing that can check a claim about a diff.**

**Twenty-ninth amendment — a predicate must detect the prohibited MEANING, and must not lose coverage to a
reformat.** Matching one phrasing, or gating on a token that a cosmetic edit can move, produces a `NONE`
that costs nothing to obtain. Every predicate's seeds must include **a differently-worded instance** of the
defect and **a layout change**, not just the exact construction that prompted it.

**Thirtieth amendment — a provenance claim is checkable only against the diff.** "Unchanged except X" is an
assertion about a commit range; recollection cannot verify it and neither can reading the document. If a
document claims what a change did, a predicate must derive that from `git`.

**Standing note.** Rounds 22–38: seventeen consecutive rounds. Rounds 33 → 38 are one chain — a gate, its
failure modes, its assertion set, the evidence for that set, the correctness of the evidence, and now the
evidence's own coverage. Round 37 said the four unreviewed predicates had been "audited by me, which is
exactly the assurance this finding just devalued." Two of those four were wrong, and review found both.

**Unchanged by round 38:** no requirement, threat or abuse-case ID added, removed or renumbered — the
registry's *statements* are untouched; only the provenance note changed. No diagram edge added or removed.
ADR-0024 `Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements /
0 duplicates / 27 contiguous abuse cases; predicates 19, 21, 22, 23, 24, 25 all exit `0`; no non-ASCII
strays; changes confined to `docs/`; PR-1 not begun.

## Round 39 — a fixed window let neighbouring prose absolve an incomplete rule, and the new provenance predicate checked one direction and one side (`7d81b55f` → next)

Four findings, **all four inside the predicates**, and the first **P1** of the remediation. Checking the
predicates in has now produced findings in three consecutive rounds; every one of them is a defect in what a
check could prove, not in what the documents say.

**R39-1 (P1) — `predicate-22` judged an ordering sentence on a 600-character WINDOW, not on the sentence.**
So `durably committed before the upstream call.` was accepted whenever the *following, unrelated* prose
happened to mention publication, materialization and a state change inside the window: `named_acts(span)`
saw all four and reported clean while the rule itself left three classes ungated. The span is now terminated
at the **sentence end**; `WINDOW` survives only as a backstop for a sentence with no terminator. The new seed
is exactly the reviewer's construction — an incomplete rule followed by a sentence naming the other three
actions — and it **fires**; under the old window it reported nothing. Round 38 fixed this predicate to detect
a meaning; round 39 found the detector's *scope* was wrong, which is the same lesson at a smaller radius.

**R39-2 — `predicate-25`'s decision arm compared one direction only** (`actual - claimed`), so a note naming
an **unchanged** decision — claiming credit for touching D-3 — passed. Both directions now compared, and
block **removal** counts as a change (`set(n) ^ set(o)`, not `set(n) - set(o)`). Seeded: naming D-3 fires.

**R39-3 — `predicate-25`'s repository-context arm iterated `set(o) & set(n)`**, the intersection, so an
**added** row, a **deleted** row, or a **renamed** label was invisible to a note asserting every other row is
byte-unchanged. Now the union, with one-sided rows required to be named. Two seeds — add an unmarked row,
delete a non-⟳ row — both fire. **The added-row seed immediately exposed a real bug in my own fix**
(`n.get(k, o[k])` evaluates the default eagerly → `KeyError`), which is the argument for writing the seed
before believing the fix.

**R39-4 — the provenance base tracked `origin/main`, so it would break at the moment it mattered.** Once
this branch merges, `git merge-base HEAD origin/main` resolves to the current tree: the diff empties, the
live provenance claims "fail", and two seeds report `MISSED`. A predicate advertised as re-runnable has to
stay re-runnable **after the merge it describes**. The base is now the **recorded immutable commit**
`1203e04b`, with `CULVERT_PROVENANCE_BASE` for a transplanted history, and a start-up check asserts the base
is an ancestor of `HEAD` and is not `HEAD`.

**The sweep — the same unbounded-window defect was in `predicate-25` three more times.** R39-1 is a fixed
character window standing in for a syntactic boundary; `predicate-25` read each provenance note as
`[:2500]` / `[:900]` / `[:1600]` characters. Those windows sit directly above the `MCP-PROTO` requirement
table, so a growing document would have dragged unrelated IDs into the *claimed* set — silently making the
claim look bigger and the check look green. All three now extract the **blockquote** the note lives in, using
the document's own `>` delimiters. `predicate-24` was checked and is already clause-bounded (it splits on
`;` and sentence end); `predicate-19/21/23` parse structure, not prose.

**Thirty-first amendment — a window is not a boundary.** When a check needs "the sentence", "the note" or
"the clause", it must find the syntactic end of that thing. A character count is a guess that fails in both
directions: too small truncates the evidence (round 38's per-line scan), too large imports evidence that
belongs to something else (this round). Both failures print `NONE`.

**What three consecutive rounds of predicate findings say.** Rounds 37, 38 and 39 have produced **six**
defects in the checked-in predicates — parity certified on endpoints, a meaning matched as one phrase, a
coverage filter a reformat could defeat, a one-direction set comparison, an intersection where a union was
required, and a base that dissolves on merge. Every one produced `NONE` while proving less than claimed. I
audited all of them myself before each was reviewed, and found none of the six. That is the strongest
evidence in this ledger for the position it already records: **these predicates are worth having and are not
worth trusting unreviewed**, and the recorded recommendation to promote them into executed CI gates during
PR-0/PR-1 should be read as promoting *reviewed* checks, not these.

**Unchanged by round 39:** no requirement, threat or abuse-case ID added, removed or renumbered; no normative
statement, diagram edge or provenance claim changed — the only document edits are `predicates/` and this log.
ADR-0024 `Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74 threats / 91 requirements /
0 duplicates / 27 contiguous abuse cases; predicates 19, 21, 22, 23, 24, 25 all exit `0`; no non-ASCII
strays; changes confined to `docs/`; PR-1 not begun.

## Round 40 — the boundary fix had the same hole one predicate over, a substring stood in for coverage, and a repository claim named the wrong symbol (`229d7a16` → next)

Four findings: a second **P1** on the very boundary class round 39 had just closed, a coverage check that
containment made vacuous for nineteen rows, and the first Copilot finding of the remediation — a factual
attribution error in a repository-context row that has been wrong since the package was written.

**R40-1 (P1) — `predicate-24`'s clause boundary did not recognise a terminator after Markdown.** The
splitter required a lowercase letter before the period (`(?<=[a-z])\.\s`), so
`… ⇒ **no new configuration revision exists**.` — period preceded by `*` — was not a boundary. The clause
ran on into the following prose, which could then supply `signed`/`pushed`/`epoch` and make an incomplete
publication assertion report complete. **This is round 39's P1 in the adjacent predicate**: I fixed the
boundary in `predicate-22` and did not ask whether the other boundary matcher had the same hole. It did.

Both predicates now share one definition — **a terminator may be preceded by any non-space character**
(`(?<=\S)\.\s+(?![a-z])`), which covers a closing `**`, backtick, bracket, quote or digit, while the
lowercase lookahead still excludes `e.g.` and decimal points. Each carries a seed whose clause ends at
`**.` with the missing keys in the *next* sentence; both fire, and `predicate-22`'s sixth seed is the same
construction on the ordering sentence.

**R40-2 — `predicate-25` treated substring containment as coverage.** A row is "covered" if the
citation-correction note names it — and the note contains `PR-1`, so `'1' in note.lower()` was true for the
numbered command-inventory rows `1`..`19`. **Nineteen rows could change with no ⟳ and no mention and produce
no violation.** Coverage is now the set of **backticked tokens** the note explicitly names, matched whole.
Seeded by mutating row `1` with no row-specific note: fires.

**R40-3 (Copilot) — `VERIFIED-REPOSITORY-CONTEXT`'s SSRF row attributed "fail-closed on DNS error" to
`Control`.** Verified against `internal/ssrf/ssrf.go`: `Control` runs **after** DNS resolution, receives the
resolved `IP:port`, and fails closed on a *parse anomaly* — it never sees a hostname, so it cannot observe a
DNS error at all. The DNS-failure fail-closed belongs to the pre-flight `PrivateHost`, which rejects a
`LookupHost` error and deliberately does not cache it. The row now states **two properties in two symbols**
rather than collapsing them into one. The evidence citations were right; the *proves* cell attributed one
symbol's property to another — the same attribution class as rounds 20 and 33, and this one had been live
since the package was written, through every round of self-review.

**The sweep, and what it cost me to do it properly.** R40-1's dimension is *every place a boundary is
computed*; that is `predicate-22` (fixed round 39, lookbehind still too narrow — widened) and `predicate-24`
(the finding). R40-2's dimension is *every place membership is decided by containment rather than by an
explicit set*: the requirement and decision arms already compare parsed ID sets, and `predicate-23` matches
whole owner tokens — checked, not assumed. R40-3's dimension is *every "Proves" cell whose evidence names
more than one symbol*; that check is by reading, and I am recording it as **not** enumerable — there is no
mechanical form of "this sentence attributes this property to that symbol", so it stays a human-review
obligation and I am not claiming otherwise.

**Thirty-second amendment — fixing a class in one site is not fixing the class.** Round 39 closed a
boundary defect in `predicate-22` and I did not grep for the other boundary matcher, which was three files
away and had the identical hole. When a fix corrects a *shape*, the sweep is over every implementation of
that shape, including the ones inside the tooling.

**Thirty-third amendment — containment is not coverage.** `x in text` answers a question about characters,
not about naming. Where a check asks "is this thing explicitly accounted for", it must compare against a
parsed set of names, and its seeds must include the shortest and most collision-prone label in the corpus.

**What forty rounds of this say, stated without softening.** Rounds 37–40 have produced **eight** defects in
the checked-in predicates. Every one printed `NONE` while proving less than advertised; I audited all eight
before review and found none of them. Two of the four findings this round are defects I introduced *while
fixing the previous round's findings*. The recorded position stands and is now better evidenced: these
checks are worth keeping and are not worth trusting unreviewed, and the recommendation to promote them into
CI during PR-0/PR-1 means promoting **reviewed** checks.

**Unchanged by round 40:** no requirement, threat or abuse-case ID added, removed or renumbered; no normative
statement, diagram edge or provenance claim changed. One repository-context ⟳ row's *Proves* cell corrected
(`predicate-25` re-verified: still covered). ADR-0024 `Status: Proposed`; `PR1-READINESS-REVIEW.md`
byte-identical; 74 threats / 91 requirements / 0 duplicates / 27 contiguous abuse cases; predicates 19, 21,
22, 23, 24, 25 all exit `0`; no non-ASCII strays; changes confined to `docs/`; PR-1 not begun.

## Round 41 — the boundary fix over-excluded, and one class had no scope token at all (`c8efbb7e` → next)

Two findings, both on `predicate-22` (one shared with `predicate-24`), one of them a **P1** on the boundary
I had now edited in three consecutive rounds.

**R41-1 (P1) — `(?![a-z])` treated EVERY lowercase-starting sentence as non-terminal, not just an
abbreviation.** So `… before the upstream call. publication signs and pushes the snapshot …` was one span:
the next sentence, starting with a lowercase technical term, was absorbed and supplied the three missing
actions. The lookahead was written to skip `e.g.` and decimals and silently skipped far more than that —
**a correction that over-shot in the direction of leniency**, which is the worst direction for a check whose
output is `NONE`. The exclusion is now the actual abbreviation set (`e.g`, `i.e`, `cf`, `vs`, `etc`,
`approx`, `Fig`, `No`, `p`, `pp`) plus decimals, and both predicates share it. Seeded with the reviewer's
construction in both: fires in `predicate-22` and in `predicate-24`.

**Three rounds, three edits, three defects on the same regex.** Round 39 replaced a fixed window with a
sentence end; round 40 found the lookbehind rejected a terminator after `**`; round 41 finds the lookahead
absorbed any lowercase continuation. Each edit fixed the reported case and got the general rule wrong in a
new way, and each time the result printed `NONE`.

**R41-2 — the `Write / destructive` class had NO scope token, so a legitimately scoped write sentence was
reported as incomplete.** `scope_tokens()` takes words of six characters or more minus a stopword set;
`write` is five, and I had put `destructive` in the stopword list myself in round 38. The set came back
**empty**, so `For a write operation, the decision event MUST be durably committed BEFORE the upstream
call.` could never match its own class and was judged as an unscoped general rule missing three actions.
`destructive` is out of the stopword list, the floor falls back to four characters when a class would
otherwise be tokenless, **the predicate now prints its per-class tokens and fails if any class has none**,
and there are two new negative controls (a scoped *write* sentence and a scoped *publication* sentence) that
must stay silent.

**What the tokens print now** — `Write=['destructive']`, `Configuration=['configuration','publication']`,
`Credential=['credential','revoke','rotate']`, `State-affecting=['management']`. That line exists because a
silently empty set is invisible: the check kept running and kept reporting, it simply could not recognise one
of the four classes.

**Thirty-fourth amendment — a correction must be tested from BOTH sides.** Every one of the three boundary
defects was a rule that was right about the reported case and wrong about the complement: too narrow, then
too narrow again, then too wide. A fix to a discriminator needs a seed for the case it must catch **and** a
negative control for the case it must not — round 41 is the first of the three edits to ship both.

**Thirty-fifth amendment — a derived set must never be silently empty.** Where a predicate derives tokens,
keys or vocabulary per category, it must print them and fail when a category derives nothing. An empty set
does not raise; it just quietly stops matching, and the check goes on producing `NONE` for a class it can no
longer see.

**Standing note.** Rounds 22–41: twenty consecutive rounds. Rounds 37–41 have now produced **ten** defects
in the checked-in predicates. Three of those ten are defects I introduced while fixing an earlier round's
finding in the same file. I have found none of the ten before review.

**Unchanged by round 41:** no requirement, threat or abuse-case ID added, removed or renumbered; no normative
statement, diagram edge, provenance claim or repository-context row changed — the only document edits are
`predicates/` and this log. ADR-0024 `Status: Proposed`; `PR1-READINESS-REVIEW.md` byte-identical; 74
threats / 91 requirements / 0 duplicates / 27 contiguous abuse cases; predicates 19, 21, 22, 23, 24, 25 all
exit `0`; no non-ASCII strays; changes confined to `docs/`; PR-1 not begun.
