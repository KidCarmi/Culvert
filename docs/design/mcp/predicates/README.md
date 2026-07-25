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
| `predicate-22.py` | no live normative document states the commit-ordering precondition in a form naming FEWER than all four class-specific irreversible actions (the class-generic delegation, and a sentence scoped to one class, both pass) | `MCP-EVENT-002`'s class table + `EVENT-MODEL.md` §4a for the per-class scopes |
| `predicate-23.py` | every owner named in a gate-status row's `Target PR` cell also appears in that row's `Blocking?` cell | the cells themselves (`PR-<n>`, `PR-C`, `Future … Gate`, `D-nn`) |
| `predicate-24.py` | (arm 1) every per-class absence enumeration carries the action-keys that class requires; (arm 2) the two copies of the per-class table agree cell-for-cell | `EVENT-MODEL.md` §4a's per-class table |
| `predicate-25.py` | every **provenance** claim ("what this remediation changed") matches the actual diff — added/rewritten requirement IDs (both directions), touched decision blocks (both directions), and every repository-context row added, removed or changed without cover | the diff against the **recorded pre-remediation commit** `1203e04b` (`CULVERT_PROVENANCE_BASE` overrides) |

`predicate-21.py` has a second, **advisory** arm reporting DFD-header vs
`THREAT-MODEL.md` STRIDE-row divergences. It is deliberately **not** gated: the
five it reports (DFD-6/7/12/13/14) are pre-existing and left failing-visible for
PR-0 adjudication rather than normalised by me.

## Detect the meaning, not one sentence — and stay layout-independent

Two failure modes cost `predicate-22` and `predicate-24` their stated properties, both found by review
after they were checked in:

- **Matching one phrase instead of the prohibited meaning.** `predicate-22` originally matched the literal
  string `committed BEFORE credential use`. `durably committed before the upstream call` — the same
  incomplete rule, differently worded — passed silently, and the derived class vocabulary was asserted but
  never used in the decision. It now compares the actions a sentence NAMES against the four the authority
  requires, accepts the class-generic delegation, and accepts a sentence SCOPED to one class when it names
  exactly that class's own actions.
- **A line-level prerequisite that a cosmetic reflow can defeat.** `predicate-24` only examined lines
  containing the literal `upstream call`, so reflowing the enumeration to one line per class would have
  skipped the configuration-publication and Management clauses — neither mentions an upstream call — and
  still printed `NONE`. Both predicates now scan the whole text — `predicate-22` bounded at the sentence
  end, `predicate-24` at the clause end — and `predicate-24` carries a seed that **reflows the layout and
  weakens a clause in the same edit**.

A predicate must not be able to lose coverage to a Markdown reformat, and its seeds have to include the
reformat.

**A window is not a boundary** (round 39). When a check needs "the sentence", "the note" or "the clause", it
must find that thing's syntactic end. A character count fails in both directions and prints `NONE` either
way: too small truncates the evidence, too large imports evidence belonging to something else —
`predicate-22` accepted `durably committed before the upstream call.` because unrelated *following* prose
mentioned the other three actions inside a 600-character window. `predicate-22` now stops at the sentence
end; `predicate-25` extracts each provenance note's `>` blockquote instead of a character slice.

**Fixing a boundary in one predicate is not fixing the class** (round 40). Round 39 corrected
`predicate-22`'s span; `predicate-24`'s clause splitter had the identical hole — it required a lowercase
letter before the period, so `**exists**.` was not a boundary and the clause absorbed the next sentence.
Both now share one definition: a terminator may be preceded by **any non-space character**
(`(?<=\S)\.\s+(?![a-z])`), which still excludes `e.g.` and decimals.

**A correction must be tested from both sides** (round 41). The sentence boundary was edited in three
consecutive rounds and was wrong three times — a fixed window, then a lookbehind that rejected `**.`, then a
lookahead that absorbed *any* lowercase continuation (`… the upstream call. publication signs …`). Each edit
was right about the reported case and wrong about its complement. The exclusion is now the actual
abbreviation set plus decimals, and `predicate-22` carries negative controls (a class-generic sentence, a
scoped *write* sentence, a scoped *publication* sentence) that must stay silent alongside the seeds that
must fire.

**A derived set must never be silently empty** (round 41). `scope_tokens('Write / destructive')` returned
`{}` — "write" fell below the length floor and "destructive" was in the stopword list — so that class could
never be recognised as scoped and its legitimate sentences were reported as incomplete. `predicate-22` now
prints its per-class tokens and fails if any class derives none.

**Containment is not coverage** (round 40). `predicate-25` asked whether a row label appeared *anywhere* in
the citation-correction note; the note contains `PR-1`, so the numbered rows `1`..`19` were all "covered"
by the digit. Coverage is now the set of backticked tokens the note names, matched whole — and the seed
mutates the shortest label in the corpus.

**A set comparison runs in both directions, over the union.** `predicate-25` originally reported only
changes the note omitted, never decisions the note claimed but never touched, and iterated the intersection
of table rows — so an added, deleted or renamed row was invisible to a note asserting every other row was
byte-unchanged.

**A base must outlive the merge it describes.** `predicate-25` pins the recorded pre-remediation commit
(`CULVERT_PROVENANCE_BASE` overrides). `git merge-base HEAD origin/main` would resolve to the current tree
once this branch merges, emptying the diff and failing every claim the predicate exists to confirm.

## Compressed notation must be expanded before sets are compared

A predicate that parses identifiers out of prose and compares them as **sets**
has to expand every compressed form first. These documents write threat ranges
two ways — `MCP-T-011..017` in the DFD headers and `011–017` (en-dash) in the
coverage rows — and a parser that keeps only the endpoints will report parity
between `057..074` and `057, 074`, certifying a row that dropped 058–073.

- `predicate-21.py` expands **both** syntaxes (`nums()`), seed-proven in both
  directions: collapsing a range on the coverage side **and** on the header side
  each fire.
- `predicate-23.py` expands `PR-a..PR-b`. No gate-status cell uses that form
  today; the expansion is there so a future edit that does cannot silently
  narrow the comparison. Seed-proven.
- `predicate-19.py`, `predicate-22.py` and `predicate-24.py` compare node
  presence, phrasing and action-keys — not identifier sets — so no expansion
  applies. That was checked, not assumed.

Trust-boundary tokens (`TB-n`) are never written as ranges in these documents,
so `tbs()` does not expand them; if that ever changes the same treatment is
needed.

## Reproducibility register — read this before citing a ledger result

The ledger cites predicate results from round 12 onward. **Only the predicates
listed above can be re-run from this repository.** The rest were written and run
in a working session and never saved:

| Cited in the ledger | Reproducible here? |
|---|---|
| Predicates 19, 21, 22, 23, 24, 25 | **Yes** — files above |
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
