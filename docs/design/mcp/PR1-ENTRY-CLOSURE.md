# MCP PR-1 Entry Closure

**The concise, authoritative source of truth for the MCP PR-1 entry decision.** After this document merges,
it — together with [`OPEN-DECISIONS.md`](OPEN-DECISIONS.md), [`ADR-0024`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md),
[`MCP-OPERATION-REGISTRY.md`](MCP-OPERATION-REGISTRY.md) and [`TRANSPORT-FALLBACK-EVIDENCE.md`](TRANSPORT-FALLBACK-EVIDENCE.md) —
records why **MCP PR-1 implementation is GO**. It closes tracker
[#923](https://github.com/KidCarmi/Culvert/issues/923).

This project is developed by one repository owner using **independent AI research, adversarial review,
structural predicates, and CI**. There is **no** external Architecture Review Board, Security Architecture
team, IAM/PAM team, SRE team, Privacy team, or other organization, and **no** human role-signature,
committee ratification, or ARB-attendance step is required or implied anywhere in this closure.

---

## 1. Baseline

- **Baseline commit (current `origin/main` at closure):** `6810fce9bc52c3f567ef6c20630f1c510cc267b6`.
- **No MCP implementation exists.** There is no `internal/mcp` package, no MCP-named Go file, and no
  JSON-RPC reference in any `*.go` file. The entire MCP program is documentation under `docs/design/mcp/`
  plus [`ADR-0024`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md) and the structural
  predicates. This closure changes **no Go source**.
- The baseline is re-anchored to current `main` with the current required CI evidence (Fast PR Gate + Deep
  PR Gate, security/QA/API gates). Because every MCP change since the original technical baseline is
  documentation, predicates, and CI wiring — not runtime code — the original repository build/test baseline
  (and its pre-existing/environmental failures) remains valid and is not re-run for ceremony; see #923
  Gate 4.

---

## 2. Closed board blockers (#925–#929)

All five board blockers are **closed as completed**, each with an independently verified closure-evidence
list.

| Blocker | RPR | Title | State | Evidence |
|---|---|---|---|---|
| [#925](https://github.com/KidCarmi/Culvert/issues/925) | RPR-1 | Bidirectional requests + requestor-scoped protocol state | closed / completed | 9/9 closure evidence verified |
| [#926](https://github.com/KidCarmi/Culvert/issues/926) | RPR-2 | Unauthenticated fleet-wide durability-lockout DoS | closed / completed | 11/11 closure evidence verified |
| [#927](https://github.com/KidCarmi/Culvert/issues/927) | RPR-3 | All MCP surfaces inside the anti-drift registry wall | closed / completed | 9/9 closure evidence verified |
| [#928](https://github.com/KidCarmi/Culvert/issues/928) | RPR-1 | Authorize every supported capability, not only tools/call | closed / completed | 9/9 closure evidence verified |
| [#929](https://github.com/KidCarmi/Culvert/issues/929) | RPR-4 | Prevent downgrade and legacy SSE fallback | closed / completed | 9/9 closure evidence verified |

**RPR-1, RPR-2, RPR-3 and RPR-4 (the four-PR remediation plan) are complete.** RPR-1 covers the paired
protocol-kernel blockers #925 + #928; RPR-2 covers #926; RPR-3 covers #927; RPR-4 covers #929.

---

## 3. D-1 — protocol baseline: **CLOSED** (final V1 decision)

The authoritative record is [`OPEN-DECISIONS.md`](OPEN-DECISIONS.md) §D-1; the transport portion is
[`TRANSPORT-FALLBACK-EVIDENCE.md`](TRANSPORT-FALLBACK-EVIDENCE.md); the admitted method surface is
[`MCP-OPERATION-REGISTRY.md`](MCP-OPERATION-REGISTRY.md). This is the V1 baseline the PR-1 kernel MUST match.

### 3.1 Supported versions

| Role | Version |
|---|---|
| Primary | `2025-11-25` |
| Compatibility floor | `2025-06-18` |

All other revisions are **rejected**, explicitly including **`2024-11-05`**, **`2025-03-26`**,
**`2026-07-28`**, and any unknown future revision. `2026-07-28` may remain **comparison material only** — it
is **not** part of V1.

### 3.2 Transport

Remote **Streamable HTTP only**. **No** stdio; **no** localhost bridge; **no** legacy HTTP+SSE endpoint
pair; **no** endpoint-event route; **no** automatic fallback; **no** pre-negotiation SSE stream allocation.
A GET without a valid negotiated context returns **`405`** and retains **zero** streams.

### 3.3 Version negotiation

- `initialize` may **counter-offer** a supported version using the documented successful initialize response
  (`200` carrying the JSON-RPC body), preferred over a `4xx` hard reject.
- A client that cannot accept the selected version **terminates**.
- An invalid or unsupported `MCP-Protocol-Version` header returns **`400`**.
- A missing required session identifier returns the evidence-backed status recorded in the transport
  evidence matrix.
- An unknown or terminated session returns the evidence-backed **`404`**.
- **DELETE** unsupported returns **`405`**.

### 3.4 Sessionless missing version header

A sessionless / first request without `MCP-Protocol-Version` is **rejected with HTTP `400`**. Culvert does
**not** silently assume `2025-03-26`. This is a deliberate security and compatibility decision: silently
assuming `2025-03-26` would re-admit version semantics excluded from V1, including batch and version-surface
differences. Recorded transparently where the upstream spec uses **SHOULD** language — it is **not** a
falsely-claimed unconditional spec requirement.

### 3.5 Batch

JSON-RPC **batch arrays are unsupported in V1**. The **entire batch is rejected** — never split, partially
processed, or best-effort dispatched.

### 3.6 Method surface

The admitted set is exactly six methods (everything else is rejected through the authoritative method
registry, `MCP-PROTO-016`):

- `initialize`
- `notifications/initialized`
- `ping`
- `notifications/cancelled`
- `tools/list`
- `tools/call`

### 3.7 Origin and Host (frozen reviewed posture)

Host allowlisting is **mandatory**; a present invalid `Origin` is **rejected**; Culvert does **not** require
every non-browser client to send `Origin` unless the selected protocol revision requires it. **PR-1 owns
the pure validation primitive** (`MCP-INSP-008`); **PR-5 owns listener enforcement** (`MCP-INSP-009`).

---

## 4. D-15 — config anti-drift contract: **CLOSED — implementation contract accepted**

The MCP configuration anti-drift contract is accepted as the implementation baseline. `MCP-CFG-001` and the
config-surface matrix ([`CONFIG-SURFACE-MATRIX.md`](CONFIG-SURFACE-MATRIX.md)) are authoritative; every
future MCP config field MUST have complete **config / API / GUI / OpenAPI / registry / test** parity. The
runtime binding is implemented in **PR-1+ according to slice ownership** (Option A — extend the existing
registry; binding structural constraint in ADR-0024 §Decision Part 1 item 8). This is **not** called
human-approved.

---

## 5. ADR-0024: **Status: Accepted**

[`ADR-0024`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md) is **`Status: Accepted`**
(2026-07-31). Acceptance rests on the merged repository state — this ADR, the `docs/design/mcp/` package, the
predicates, and the CI gates — not on any organizational sign-off. Decisions were developed through isolated
AI architecture/security reviews and adversarial review; all five board blockers were remediated and
independently verified; RPR-1 through RPR-4 are complete; D-1 and D-15 are closed. No separate signature
block is required.

---

## 6. Predicate runner census

The runner [`.github/scripts/mcp-doc-predicates.sh`](../../../.github/scripts/mcp-doc-predicates.sh)
executes an **explicit allowlist** (not a glob) as a **required Fast PR Gate**. After this closure it runs
**exactly ten blocking predicates**:

`19, 21, 22, 23, 24, 26, 27, 28, 29, 30`

**`predicate-25` remains manual** (deliberately excluded — it is remediation/provenance-specific and diffs
against a fixed historical base commit). **`predicate-30`** is the entry-closure predicate added by this PR:
it enforces every closure invariant recorded here and fails closed if any is reverted.

---

## 7. Known-open adjudication

Every previously "known-open" governance item is adjudicated here; none is left as a hidden or unowned tail.

| Item | Adjudication |
|---|---|
| DFD-header vs THREAT-MODEL STRIDE divergences (DFD-6, DFD-7, DFD-12, DFD-13, DFD-14) | **Resolved.** DFD-13 and DFD-14 carried a genuine `051/052/053` connector↔DMZ transposition and are **corrected** to the authoritative D-8/D-9 closure mapping; DFD-6/7/12 (and DFD-14's `031`) are **documented as intentional** header⊇§9 dominant-subset supersets. See [`DATA-FLOW-DIAGRAMS.md`](DATA-FLOW-DIAGRAMS.md) "STRIDE-divergence reconciliation". No unexplained divergence remains. |
| `predicate-24` parenthetical-attribution limitation | **Recorded as a known parser limitation — advisory and non-blocking.** Tightening the clause splitter to absorb parentheticals raises false positives on live documents where the parenthetical is the clause's own assertion; distinguishing the two cases falls in the not-mechanisable attribution dimension. It does **not** weaken the current arms and is **not** an unowned gate. See [`predicates/README.md`](predicates/README.md). |
| Unsaved historical predicates 7, 8, 13, 18, and the outcome-lane check | **Non-reproducible historical evidence, not current blockers.** Their recorded results stand as labelled claims in the reproducibility register and are **not reconstructed from memory** (a reconstruction is a different check wearing the same number). See [`predicates/README.md`](predicates/README.md). |
| Human-only prose-attribution review (attribution inside a "Proves" cell) | **Advisory, not a PR-1 entry blocker.** Carried as a standing advisory review note, not a gate. |
| Whether the checked-in predicates are wired to CI | **Resolved / no longer open.** The predicates are wired as a **required Fast PR Gate** (`.github/workflows/pr-fast-gate.yml` → `mcp-predicates`) with **ten** explicit blocking predicates. The prior "not wired to CI" statement is retired. |

---

## 8. Four PR-1 entry gates — all COMPLETE

| Gate | Requirement | State |
|---|---|---|
| Gate 1 | ADR-0024 Accepted; blocker remediations complete; direct decision dependencies (D-1, D-15) closed | **COMPLETE** |
| Gate 2 | PR-0 evidence coverage (Product/Architecture/Product-Security/IAM-OAuth/SRE/Privacy/Support/Release-Engineering) — actual documents, RPRs, tests, independent verification; **no human role signatures** | **COMPLETE** |
| Gate 3 | Final D-1 protocol baseline recorded (§3 above) | **COMPLETE** |
| Gate 4 | Repository baseline re-anchored to current `main` with required CI evidence; no MCP implementation exists; original baseline failures classified pre-existing/environmental | **COMPLETE** |

**#923 final state: `PR-1 implementation: GO`.** #923 closes as completed on merge.

---

## 9. PR-1 allowed scope (protocol-kernel only)

PR-1 may contain **only**:

- Protocol parsing and strict JSON / JSON-RPC framing.
- Protocol-version negotiation and adapters.
- Session lifecycle, cancellation, correlation, and reconnect semantics.
- Structural payload/resource bounds.
- UTF-8 and protocol-token handling.
- Compatibility, fuzz, malicious-input, race, and structural test harnesses.
- The pure, listener-independent `MCP-INSP-008` Origin/Host **decision primitive**.
- Only the MCP configuration contract strictly required by the approved PR-1 config surface (registry-walled
  per `MCP-CFG-001`).

## 10. PR-1 prohibited scope

PR-1 **must not** contain:

- A bound listener or any production / public ingress.
- Identity / authentication / OAuth implementation.
- Policy enforcement.
- Credential brokering.
- Registry / catalog runtime implementation.
- Upstream execution.
- Management MCP implementation.
- UI / API implementation beyond the strictly-required PR-1 configuration contract.

---

## 11. Final statement

**MCP PR-1 implementation is GO.**

**GO applies only to the PR-1 protocol-kernel scope.** It does **not** authorize a listener, OAuth, policy,
credentials, upstream execution, UI, or production traffic. Those land in their own later slices under their
own gates.
