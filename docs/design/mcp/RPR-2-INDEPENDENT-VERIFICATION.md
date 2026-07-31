# RPR-2 — Independent Verification Record (issue #926 §8 closure)

This document records **one independent verification pass** against issue
[#926](https://github.com/KidCarmi/Culvert/issues/926) §8 closure evidence —
the eleventh and final §8 checklist item ("*One independent verification pass
recorded against this list only*"). It is scoped to that list only, per §9.

**This is a governance verification record. No product implementation was
introduced. ADR-0024 remains Proposed; PR-1 remains NO-GO.**

## Inspection metadata

| Item | Value |
|---|---|
| Verification date | 2026-07-31 |
| Branch | `claude/rpr-2-verification-wmo0r7` |
| Verified against | `main` HEAD `2d45a39db08cccc90fd40507201eff8e5ce0e419` |
| Verifier authored #968 / #971 | **No** — verification is independent of the remediation |
| Method | git ancestry checks · direct document reads (file · line) · full MCP design-predicate CI suite |

## Remediation ancestry — VERIFIED

Both remediation PR heads are incorporated into the verified `main`
(`git merge-base --is-ancestor … HEAD` ⇒ true for each):

| PR | Head SHA | Ancestor of verified `main`? |
|---|---|---|
| #968 — durability-degradation containment | `3bb70dd39d58c964e516f56999105cbea9ad7f9b` | **YES** |
| #971 — post-merge MCP-AC-016 / D-5 corrections | `3dc5bac705ae4858fdc30e38d5b35643468fba76` | **YES** |

## Machine-checkable gate — PASS

The full MCP design-document predicate suite
(`.github/scripts/mcp-doc-predicates.sh`; the six predicates that gate the
Fast PR Gate) was run against the verified tree and **all six passed**,
including:

- `predicate-24` arm 4 — MCP-AC-016 states no positive denial-event lockout
  requirement, and D-5's residual status is read from R-6 (THREAT-MODEL §12),
  its authority, rather than a hard-coded literal (the #971 fix).
- `predicate-24` — the EVENT-MODEL §4a class table and ADR-0024 §D-5 copy are
  byte-identical (build fails on any cell divergence, header included).
- `predicate-26` — the config-surface matrix parses to a non-empty table and
  every registry-class invariant holds (all 22 seeded positives fire, all 3
  negative controls stay silent).

## Preserved guarantee — PASS

For every authenticated critical operation class (write, destructive/
production, configuration-publication, credential issue/rotate/revoke,
state-affecting Management), failure to durably commit the operation's own
required decision event still causes the operation to **fail closed before its
own irreversible action** — stated explicitly for **both** failure modes as
separate cases:

- queue / admission saturation; and
- post-admission commit failure (`fsync`, `ENOSPC`, encryption-key, storage
  I/O).

Evidence: `EVENT-MODEL.md:254-261` (§4b, "Preserved guarantee, stated first
because nothing below may erode it"); regression coverage mandated at
`CI-GATES.md:180` (gate #5, two separate cases (a)+(b)). PLAN/MATERIALIZE
separation and commit-before-irreversible-action ordering remain intact and
were not weakened (§4b narrows the blast radius of the degraded state, not the
fail-closed guarantee).

## #926 §8 closure checklist

| # | Closure item | Result | Primary evidence |
|---|---|---|---|
| 1 | Degradation domain defined normatively, no wider than `node × capability × partition`, cross-capability coupling justified/removed | PASS | `ABUSE-CASES.md:180`; EVENT-MODEL §4a/§4b |
| 2 | Coalescing + reserved critical partition + pre-queue admission control | PASS | `ABUSE-CASES.md:180` (`P-DEN` MUST NOT consume `P-CRIT`) |
| 3 | Pre-identity (unauthenticated) scoping without invented tenant attribution | PASS | `ABUSE-CASES.md:180-181` (listener/source scope) |
| 4 | Bounded exit + restart-persistence rule + operator runbook | PASS | OPERATIONS-AND-SUPPORT lockout runbook |
| 5 | Emergency-policy contradiction removed in all four documents; no replacement bypass | PASS | `ADR-0024:186,216-217` (clause "deleted, not relocated"); `EVENT-MODEL.md:235`; contradiction sweep clean |
| 6 | Threat ID + §11 control row + §12 residual acceptance (R-6) with proposed owner, acceptance PENDING | PASS | `THREAT-MODEL.md:333` (R-6 PENDING); MCP-T-075 |
| 7 | Spool size/retention/rotation/quota/window/probe surfaces + deterministic reclamation | PASS | CONFIG-SURFACE-MATRIX (parses; predicate-26) |
| 8 | `CI-GATES.md:141` gate proves the denial-lockout **attack fails** (not that the lockout holds) | PASS | `CI-GATES.md:142`; `ABUSE-CASES.md:183` ("lockout ATTACK PROVEN TO FAIL") |
| 9 | EVENT-MODEL §4a and ADR-0024 §D-5 cell-for-cell identical | PASS | `predicate-24` (byte-identical, build-enforced) |
| 10 | Preserved-guarantee regression covers saturation **and** post-admission failure separately | PASS | `EVENT-MODEL.md:254-261`; `CI-GATES.md:180` |
| 11 | One independent verification pass recorded | PASS | this document |

**11 / 11 independently verified.**

The #971 post-merge correction is confirmed: MCP-AC-016 now consistently
requires the isolated denial lane and makes a demonstrated denial-triggered
lockout a **failing** result, not a passing one (`ABUSE-CASES.md:183`).

## Notes on phrasing (transparency, non-blocking)

- The GO/NO-GO authority (`GO-NO-GO-CHECKLIST.md`) expresses the PR-1 NO-GO
  posture as **unmet GO conditions / an open entry gate** (lines 57-66, 84,
  89) plus the six Hard NO-GO lines (11-18), rather than a literal "PR-1 is
  NO-GO" headline. The substance is unchanged: PR-1 is not GO.
- The eleven §8 items are enumerated in **issue #926 §8 itself**; no single
  repository document consolidates them. Each affected design doc folds its
  relevant #926 change into its own subject matter. This record is that
  consolidated cross-reference.

## Outstanding governance state (unchanged by this verification)

This verification accepts nothing on the design's behalf. As of the verified
`main`:

- ADR-0024 remains **Proposed** (`0024-…md:3`) — awaiting ARB + Security
  Architecture ratification.
- D-15 remains **OPEN** and not human-approved (`OPEN-DECISIONS.md:317`).
- D-1 remains **open** (`OPEN-DECISIONS.md:315`).
- R-6 remains **PENDING** — proposed owner SRE/Reliability, not accepted by a
  named human (`THREAT-MODEL.md:333`); this verification does not accept it.
- **PR-1 remains NO-GO.**

**#926 §8 closure evidence: 11/11 independently verified. RPR-2 is complete.**
