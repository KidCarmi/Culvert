# PR-1 Readiness Review — MCP Agent Security Gateway Design Package

**Reviewer role:** Architecture / Product-Security design review (PR-0 → PR-1 gate).
**Review date:** 2026-07-24.
**Object under review:** the PR-0 documentation baseline under `docs/design/mcp/` (as merged to `main`;
this review ran on branch `claude/mcp-pr1-doc-review-q8iibt`, repo HEAD `2eef667`). The package pins its
own inspection baseline to HEAD `c0ae2bc` (verified: a real commit, "Merge PR #907").
**Question answered:** *Is the design package sufficient, accurate and self-consistent to authorize PR-1
("Protocol Kernel") to begin?*

This review is **documentation-only** and changes no design decision. It records findings for the PR-0
authors, the Architecture Review Board (ARB), and Product Security to act on. Every repository claim below
was verified by direct read; every doc claim carries a `file:line` citation.

---

## 1. Verdict

**The package is thorough, repository-grounded, and self-consistent enough to enter PR-0 human review — but
PR-1 is NOT yet authorized to begin, and should not begin on the current documents even once the acknowledged
gate mechanics clear.**

Two classes of blocker:

- **Acknowledged gate conditions (by design, not defects).** The single hard PR-1 entry gate — a numbered,
  **Accepted** ADR under `docs/adr/` (Decision D-0, Option B) — is unmet; only the in-directory *proposal*
  exists. PR-0 role sign-offs (`PR0-REVIEW-CHECKLIST.md`) are uncollected and the `GO-NO-GO-CHECKLIST.md`
  PR-0→PR-1 checkboxes are unchecked. These are exactly what this review is a step toward clearing.
- **Documentation defects that undermine PR-1's own acceptance criteria (should be fixed first).** PR-1's
  novel attack surface — the MCP protocol parser, JSON-RPC framing, malformed-input handling, and version
  adapters — is **not modeled by any threat ID, is backed only by a phantom requirement ("protocol bounds"),
  and its two named acceptance blockers ("fuzz green", "compat green") have no blocking CI home.** These are
  documentation-only fixes, but they sit on PR-1's critical path: as written, three of PR-1's four
  release-gate conditions are not fully implementable, and the parser PR-1 ships has no security requirement
  it can be verified against.

**Recommendation:** *Conditional GO for PR-0 human review; NO-GO for PR-1 start* until (a) the acknowledged
gate items clear and (b) the four **High** findings in §4 are remediated in a documentation revision. All (b)
fixes stay within the PR-0 change boundary (`docs/design/mcp/` only) and require no code.

---

## 2. What is strong (verified, credit where due)

These were independently checked against the repository and hold up:

- **The repository-grounding is sound.** A rigorous sample of the load-bearing `[FACT]` claims in
  `VERIFIED-REPOSITORY-CONTEXT.md` resolves to real code at (or within a line or two of) the cited symbol.
  Spot-verified directly: the SWG 4-action model (`policy.go:19-27`), audience-bound-to-`client_id`
  (`auth_oidc_flow.go:523` → `jwtv5.WithAudience(p.cfg.ClientID)`), the bounded audit ring
  (`internal/audit/audit.go:49` → `const MaxRing = 500`), captive-portal-only redirect guard
  (`proxy_portal.go:152` → `isSafeRedirectURL`), and the **genuine absence of any MCP/JSON-RPC listener**
  (the lone repo-wide `mcp` grep hit is a false positive inside `NumCPU`). Every PR-1 reuse primitive
  (`internal/ssrf` `Control` fail-closed TOCTOU recheck, header-scrub/no-passthrough posture, `halease`
  epoch fencing + DP fail-static, config-versioning + anti-drift registry, the `register*Routes`/`uiRoutes`/
  `requireRole` admin convention, `internal/secret` KEK, `internal/redaction`) exists as described.
- **The trust-boundary and separation decisions are correct and well-argued.** The "no reuse of SWG
  `PolicyRule`/OIDC-flow/audit-ring; separate listeners; pure I/O-free policy engine; no token passthrough;
  signed fenced snapshots" doctrine is consistent across `ADR-PROPOSAL-mcp-trust-boundary.md`,
  `RECOMMENDED-ARCHITECTURE.md`, and `THREAT-MODEL.md`, and each red line maps to a requirement + abuse case
  + a hard NO-GO line.
- **The ADR proposal is format-ready to promote.** The repo ADR format (`# ADR-NNNN`, a
  `Status/Date/Deciders` header, then `Context / Decision / Consequences / Alternatives considered` — per
  `docs/adr/0001` and newer ADRs like 0004/0006) is matched exactly by
  `ADR-PROPOSAL-mcp-trust-boundary.md`, which additionally carries a copy-paste promotion checklist.
- **The ID registries are internally consistent.** Every `MCP-T-*` threat referenced across the package
  resolves to a definition in `THREAT-MODEL.md` §11 (the contiguous `MCP-T-001…056`, none orphaned), and
  every `MCP-*-*` requirement reference falls within the 75 defined in `SECURITY-REQUIREMENTS.md`. The
  weakness (§4) is *coverage*, not dangling cross-references.
- **The required-merge-gate names are exact.** `✅ Fast PR Gate — APPROVED` (`pr-fast-gate.yml:351,369`) and
  `✅ Deep PR Gate — APPROVED` (`pr-deep-gate.yml:470,490`) are cited correctly, and the `-race`+coverage-floor
  job that PR-1's "race green" gate rests on is real and required.

---

## 3. Blocking gate conditions (unmet — acknowledged by the package)

| # | Condition | Status | Evidence |
|---|---|---|---|
| B-1 | Numbered **Accepted** ADR under `docs/adr/` (D-0, Option B) — the hard PR-1 entry gate. | **Unmet** — proposal only. | `ADR-PROPOSAL-mcp-trust-boundary.md:10` (`Status: Proposed`); `GO-NO-GO-CHECKLIST.md:56,75`; `OPEN-DECISIONS.md:12-19`. |
| B-2 | PR-0 reviewed per `PR0-REVIEW-CHECKLIST.md` by all roles; GO-NO-GO PR-0→PR-1 checkboxes cleared. | **Unmet** — sign-off table empty, checkboxes unchecked. | `GO-NO-GO-CHECKLIST.md:52-57`. |

B-1 and B-2 are *expected* to be open at this stage — they are the point of the review. They are listed so
the go/no-go board sees the full gate. **B-1 is a human action and must not be performed by an agent** (it
writes under `docs/adr/`, outside the PR-0 boundary).

---

## 4. High findings — documentation defects on PR-1's critical path (fix before PR-1)

These are documentation-only, but each directly weakens a PR-1 acceptance criterion. Recommend remediating
all four in a PR-0 revision *before* PR-1 code begins.

### H-1 — PR-1's own attack surface (protocol parser / framing / version adapters) is unmodeled by any threat ID
PR-1's core deliverable is the MCP parser/framing and JSON-RPC decode (`IMPLEMENTATION-SLICES.md:36,40-42`;
`RECOMMENDED-ARCHITECTURE.md:137` names `internal/mcp/protocol` the boundary owner). Yet `THREAT-MODEL.md`
contains **zero** occurrences of parser / framing / malformed / JSON-RPC / batch / nesting-depth / version-
downgrade (verified by grep). The contiguous `MCP-T-001…056` set has **no** threat for the parser attack
surface PR-1 creates, so `THREAT-MODEL.md` §13 closure criteria cannot even be evaluated for the component
PR-1 actually ships. **Fix:** add `MCP-T-*` threats for (a) malformed/abusive protocol input and parse-time
resource exhaustion (nesting depth, batch amplification, frame limits) and (b) protocol-version
downgrade / adapter confusion, and thread them into the STRIDE-per-component table.

### H-2 — "protocol bounds" is a phantom requirement
PR-1's declared security requirements are "**MCP-INSP-008, MCP-OPS-002, protocol bounds**"
(`IMPLEMENTATION-SLICES.md:41`). "protocol bounds" is **not a defined requirement ID** — it appears only as
prose (`THREAT-MODEL.md:58`, `RECOMMENDED-ARCHITECTURE.md:137`) with no normative statement, verification
method, evidence, or gate. PR-1 therefore has an acceptance requirement that cannot be verified. **Fix:**
promote it to a real `MCP-INSP-*` / `MCP-OPS-*` requirement, gated at PR-1, with a verification method.

### H-3 — "fuzz green" and "compat green" are PR-1 acceptance blockers with no blocking CI home
`IMPLEMENTATION-SLICES.md:43,45` make PR-1 acceptance/release contingent on "fuzz/race/compat block" and
"fuzz+race+compat green." But:
- **Fuzz is advisory-only.** `fuzz-nightly.yml` is Mon/Wed/Fri cron with no `pull_request` trigger;
  `CI-GATES.md:87,162` and `TEST-TRACEABILITY-MATRIX.md:80` both classify it "never blocks a PR / not a
  merge gate," and the `CI-GATES.md` "Proposed / Blocking" table (`:119-129`) has **no** row for a PR-time
  protocol-kernel fuzz gate. `malformed JSON-RPC` (`IMPLEMENTATION-SLICES.md:42`) appears in no threat,
  requirement, traceability row, or CI-gate row at all.
- **Compat is Missing + externally blocked.** `TEST-TRACEABILITY-MATRIX.md:77` marks protocol conformance
  **Missing** and `[EXT]`; its content depends on D-1 (protocol baseline), which is
  `[EXT] EXTERNAL VERIFICATION REQUIRED` and unresolved (`OPEN-DECISIONS.md:21-27`). There is no CI-gate
  row for a protocol-compatibility/conformance gate.

**Fix:** add `CI-GATES.md` blocking-gate rows (target PR-1) for a bounded `go test -fuzz` malformed-JSON-RPC
smoke and a protocol-conformance gate; state where each plugs into the Fast/Deep gate; and note that
"compat green" *content* is gated on D-1 closing (a human/external step).

### H-4 — `MCP-OPS-002` gate contradiction, and it is largely unfulfillable under PR-1's scope
`IMPLEMENTATION-SLICES.md:41` lists `MCP-OPS-002` as a **PR-1** requirement, but the canonical registry gates
it at **PR-5** (`SECURITY-REQUIREMENTS.md:158`), the traceability matrix routes its tests to **PR-5**
(`TEST-TRACEABILITY-MATRIX.md:56-57,94`), and PR-5 also claims it (`IMPLEMENTATION-SLICES.md:90`). Moreover
`MCP-OPS-002` requires bounding "connections, SSE streams, queues, concurrency … with per-entity rate
limits" — which needs the listener/pools that PR-1 explicitly excludes ("**no public listener**",
`IMPLEMENTATION-SLICES.md:36`). So PR-1 claims a requirement whose canonical gate is PR-5 **and** which it
cannot fulfill. **Fix:** either drop `MCP-OPS-002` from PR-1 and cover PR-1's parse-time bounds with the new
requirement from H-2, or split `MCP-OPS-002` into a PR-1 "protocol-framing bounds" clause and a PR-5
"runtime/rate-limit bounds" clause.

---

## 5. Medium findings

### M-1 — The CodeQL "wired for `internal/mcp/**`" claim is factually wrong (three docs share it)
`IMPLEMENTATION-SLICES.md:45` makes "CodeQL wired for `internal/mcp/**`" a PR-1 gate, and `CI-GATES.md:86,161,182`
+ `PR0-REVIEW-CHECKLIST.md:66` treat it as a pending PR-1 CI-config change. Reality: `codeql.yml`'s
`pull_request` path filter **already** includes `internal/**` (verified at `.github/workflows/codeql.yml`,
`internal/**` glob), which matches `internal/mcp/**` — CodeQL will analyze PR-1 code with **no CI change**.
**Nuance to preserve:** `codeql.yml` is *not* a branch-protection-required check, so it will *run* but not
*block* merge. **Fix:** correct the three docs; if PR-1 wants CodeQL *blocking*, scope the branch-protection
change explicitly (the docs currently imply a non-existent path-filter edit instead).

### M-2 — `MCP-INSP-001` / `MCP-T-040` gate divergence across docs
The same "input size/depth/field-count bounded" requirement, `MCP-INSP-001`, is gated **PR-7** in the
canonical registry (`SECURITY-REQUIREMENTS.md:88`) and in the traceability matrix's exfiltration row
(`TEST-TRACEABILITY-MATRIX.md:45`), yet the same matrix invokes it at **PR-1** in the fuzzing row
(`:80`) and at **PR-5** in the oversized-payload row (`:56`); `PROTOCOL-COMPATIBILITY.md:256` also maps the
PR-1 malformed-JSON-RPC fixtures to `MCP-INSP-001` at gate **PR-1**. So the ID PR-1 leans on for parse bounds
is canonically PR-7. The oversized-payload threat `MCP-T-040` is likewise split across PR-5/PR-7 with the
parser that first receives the frame at PR-1. **Fix:** resolves naturally once H-2 gives PR-1 its own
parse-bound requirement ID; until then the divergence should be annotated.

### M-3 — No data-flow diagram for the PR-1 decode path
`DATA-FLOW-DIAGRAMS.md` has 14 DFDs; the inbound path appears only as DFD-12 (Origin/Host → pipeline) and
DFD-7 (input inspection, attributed to PR-7 `MCP-INSP-004/005`). There is **no** DFD for JSON-RPC decode,
frame boundaries, or SSE stream lifecycle — the exact component PR-1 builds. **Fix:** add a DFD for the
protocol-kernel decode/framing/SSE path.

### M-4 — `THREAT-MODEL.md` §8 Protocol-Kernel STRIDE row mis-attributes threats
The §8 Protocol Kernel row (`THREAT-MODEL.md:93`) lists S=`MCP-T-005` (token passthrough), T=`MCP-T-013`
(tool schema drift), E=`MCP-T-036` (SSRF) — threats owned by the identity/catalog/egress components
elsewhere in the same table. Only the DoS cell (`MCP-T-042/043/044`) is protocol-kernel-native, and the row
has **no Spoofing/Tampering threat native to parsing/framing** (the H-1 gap, surfaced as an inconsistency).
**Fix:** re-map the row to the new parser threats from H-1.

---

## 6. Low / cosmetic findings

- **L-1 — Five line-range slips in `VERIFIED-REPOSITORY-CONTEXT.md`** (symbol real, range off): `newHistogram`
  cited `:348-408`, actually `metrics.go:360`; SSRF `PrivateIP` cited `:36-72`, actually `:71-79`;
  `PrivateHost` cited `:86-103`, actually `:86-113`; `uiRoutes` cited `:48-87` (48 is `uiRouteMethod`, `var
  uiRoutes` is `:87`); and §3-vs-§6 disagree on `validateIDToken` (`:499-566` vs `:497-561`; actual start
  `:499`).
- **L-2 — Two `§3` evidence rows omit the symbol·line the table header promises:** the secret-containment row
  (`internal/secret/{provider,secret}.go`) and the redaction row (`internal/redaction/{class,redactor,
  scrubber}.go`) give file paths only. Both are "reusable-after-refactor" primitives PR-1/PR-4/PR-7 lean on,
  so tightening them to symbol·line is worthwhile.
- **L-3 — "Assign the next ADR number" is not mechanically safe.** `docs/adr/` already has **duplicate
  numbers** (two each of `0008`–`0011`) plus an oddly-prefixed `ADR-0007-openapi-contract.md`, so the
  proposal's "next in sequence" (`ADR-PROPOSAL…:106`) is ambiguous. The human promoter must disambiguate.
- **L-4 — Package-name "pending ADR" overstates what promotion resolves.** `IMPLEMENTATION-SLICES.md:37`
  scopes PR-1 to `internal/mcp/protocol` "(name [REC], pending ADR)," but ADR decision #8
  (`ADR-PROPOSAL…:66-68`) ratifies only the `internal/mcp/*` *namespace*, leaving the exact split "evaluated
  (not adopted)." The `protocol` package name stays `[REC]` even after the ADR is Accepted.
- **L-5 — `MCP-T-056` control cell uses prose, not an ID.** `THREAT-MODEL.md:253` lists controls as
  "MCP-OPS-004, network egress policy"; the second is prose, so the threat effectively maps to one requirement.
- **L-6 — The PR-11/PR-12 fold still carries a `SOURCE REVIEW REQUIRED` marker** (`IMPLEMENTATION-SLICES.md:13`);
  a reviewer should close that tag during PR-0 sign-off (consistent with D-12, no contradiction).

---

## 7. Note on D-1 (protocol baseline) — external dependency, easy to overlook

`OPEN-DECISIONS.md:21-27` marks D-1 blocking = "Slice (PR-1)", Due PR-1, `[EXT] EXTERNAL VERIFICATION
REQUIRED`. Per the letter of the PR-0→PR-1 gate (`GO-NO-GO-CHECKLIST.md:55`), PR-1-due decisions need only an
*owner assigned* (D-1 has one) to *start* PR-1 — so D-1 does not block PR-1's start. But it gates PR-1's
"compat green" release condition and requires pulling the authoritative MCP specification (every concrete
protocol-version/transport/lifecycle detail in `PROTOCOL-COMPATIBILITY.md` is deliberately `[EXT]`). Surface
this to the go/no-go board so it is not discovered mid-slice.

---

## 8. Recommended actions

**Human (clear the gate):**
1. Complete `PR0-REVIEW-CHECKLIST.md` role sign-offs; clear the `GO-NO-GO-CHECKLIST.md` PR-0→PR-1 checkboxes (B-2).
2. Promote `ADR-PROPOSAL-mcp-trust-boundary.md` to a numbered, **Accepted** `docs/adr/NNNN-*` (B-1), resolving
   the numbering ambiguity in L-3.
3. Assign an owner + external verifier to close D-1 (protocol baseline) against the MCP spec.

**Documentation revision (before PR-1 code — all within `docs/design/mcp/`):**
4. H-1: add threat IDs for parser/framing/malformed-input, parse-time exhaustion, and version-downgrade.
5. H-2: promote "protocol bounds" to a real PR-1-gated requirement ID with a verification method.
6. H-3: add `CI-GATES.md` blocking-gate rows (target PR-1) for a fuzz/malformed-JSON-RPC smoke and a
   protocol-conformance gate.
7. H-4: resolve the `MCP-OPS-002` PR-1-vs-PR-5 contradiction (split or reassign).
8. M-1..M-4: correct the CodeQL claim, annotate the `MCP-INSP-001` gate divergence, add the decode-path DFD,
   fix the §8 STRIDE row.
9. L-1..L-6: fix the line-range slips, add symbol·line evidence to the two §3 rows, and close the
   `SOURCE REVIEW REQUIRED` tag.

**Nothing above requires a code change**, and none of it re-opens a settled design decision — the trust-
boundary doctrine, two-capability separation, and repository grounding are sound.

---

## 9. Go / No-Go

| Decision | Recommendation |
|---|---|
| Enter PR-0 human review | **GO** — the package is thorough, grounded, and self-consistent at the ID-registry level. |
| Begin PR-1 today | **NO-GO** — B-1 (ADR) and B-2 (sign-offs) are unmet by design. |
| Begin PR-1 after B-1/B-2 clear, on the current documents | **NO-GO** — remediate the four **High** findings first; as written, three of PR-1's four release-gate conditions ("protocol bounds", "fuzz green", "compat green") are not implementable and the parser PR-1 ships has no verifiable security requirement. |
| Begin PR-1 after B-1/B-2 clear **and** §4 remediated | **GO** (with D-1 tracked as an in-slice external dependency). |

*This review is an input to the PR-0 go/no-go, not a decision. It performs no ADR promotion and mutates no
design artifact.*
