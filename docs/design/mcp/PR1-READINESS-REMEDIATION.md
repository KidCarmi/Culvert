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
