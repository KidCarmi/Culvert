# Remediation predicates

Executable structural checks written during the PR-1 readiness remediation
(`../PR1-READINESS-REMEDIATION.md`). Each one exists because a defect of that
shape reached a reviewer, and each is intended to make the same shape
**enumerable** rather than re-checked from memory.

They are **not wired to CI.** PR-0 and this remediation are documentation-only
and modify no workflow file (see [`../CI-GATES.md`](../CI-GATES.md) §Scope note).
Promoting these into executed gates is recorded work for PR-0/PR-1, not something
this PR does.

## Running them

From the **repository root** (they resolve `docs/...` paths relative to the CWD):

```bash
python3 docs/design/mcp/predicates/predicate-19.py   # exit 0 = seeds fire AND residual is empty
```

No third-party dependencies; Python 3.8+ standard library only.

Every predicate has the same two-part contract, and **both parts must pass**:

1. **Seeded known-positives.** The predicate injects a defect of exactly the shape
   it claims to detect and asserts it produces a **NEW** violation **naming the
   seeded target**. A predicate that cannot be shown to fire is not evidence.
2. **Residual on the live documents.** What the check reports as it stands.

Vocabularies are **derived from the authority document at run time** — never a
hand-written token list — because a hand-written list goes stale the moment the
authority changes. That failure has happened four times in this remediation
(ledger amendment 20).

## What is here

| Predicate | Asserts | Authority its vocabulary derives from |
|---|---|---|
| `predicate-19.py` | every DFD containing an irreversible-action node also contains a durable-commit node | `MCP-EVENT-002`'s own action wording ("signed, pushed or applied", "before any broker-side materialization", …) |
| `predicate-21.py` | each DFD's header declaration agrees with the coverage-summary row that restates it, on both the trust-boundary set and the threat set | the DFD headers and the coverage table themselves |
| `predicate-22.py` | no live normative document states the commit-ordering precondition in terms naming only the Gateway's side effect | `MCP-EVENT-002`'s class table |
| `predicate-23.py` | every owner named in a gate-status row's `Target PR` cell also appears in that row's `Blocking?` cell | the cells themselves (`PR-<n>`, `PR-C`, `Future … Gate`, `D-nn`) |
| `predicate-24.py` | (arm 1) every per-class absence enumeration carries the action-keys that class requires; (arm 2) the two copies of the per-class table agree cell-for-cell | `EVENT-MODEL.md` §4a's per-class table |

`predicate-21.py` has a second, **advisory** arm reporting DFD-header vs
`THREAT-MODEL.md` STRIDE-row divergences. It is deliberately **not** gated: the
five it reports (DFD-6/7/12/13/14) are pre-existing and left failing-visible for
PR-0 adjudication rather than normalised by me.

## Reproducibility register — read this before citing a ledger result

The ledger cites predicate results from round 12 onward. **Only the predicates
listed above can be re-run from this repository.** The rest were written and run
in a working session and never saved:

| Cited in the ledger | Reproducible here? |
|---|---|
| Predicates 19, 21, 22, 23, 24 | **Yes** — files above |
| Predicates 7, 8, 13, 18, and the "outcome-lane check" | **No** — not saved; their recorded results cannot be re-run |

This register exists because round 35 corrected round 34 for recording a
predicate result whose artifact did not exist, and then recorded its own results
against files that were saved outside the repository — which is the same defect
one level down. A result nobody else can reproduce is a claim, not evidence, and
it is listed here as a claim.

The unsaved predicates are **not** reconstructed from memory to fill the table.
Round 35 showed why: re-deriving `predicate-19` produced a residual the original
had evidently excluded silently, so a reconstruction is a *different* check
wearing the same number.
