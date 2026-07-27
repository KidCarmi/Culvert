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
| `predicate-22.py` | no live normative document states the commit-ordering precondition in a form naming FEWER than all four class-specific irreversible actions. The class-generic delegation and a sentence scoped to specific classes both pass — but only when the marker sits in the **object of `BEFORE`** (delimited by `;`, `,` or `—`), not in a trailing aside | `MCP-EVENT-002`'s class table + `EVENT-MODEL.md` §4a for the per-class scopes |
| `predicate-23.py` | every owner named in a gate-status row's `Target PR` cell also appears in that row's `Blocking?` cell | the cells themselves (`PR-<n>`, `PR-C`, `Future … Gate`, `D-nn`) |
| `predicate-24.py` | (arm 1) every per-class absence enumeration carries the action-keys that class requires; (arm 2) the two copies of the per-class table agree cell-for-cell | `EVENT-MODEL.md` §4a's per-class table |
| `predicate-25.py` | every **provenance** claim ("what this remediation changed") matches the actual diff — added/rewritten requirement IDs (both directions), touched decision blocks (both directions), and every repository-context row added, removed or changed without cover | the diff against the **recorded pre-remediation commit** `1203e04b` (`CULVERT_PROVENANCE_BASE` overrides) |
| `predicate-26.py` | the config-surface matrix **parses as a table at all**, is **non-empty**, and every `MCP-CFG-001` row invariant holds over the **parsed** rows — header/delimiter/data widths equal, **every delimiter cell ≥ 3 hyphens**, expected row count, no duplicate field IDs, known registry classes and value kinds, sensitive value kinds only in `RC-1`/`RC-2`, `RC-X` empty, the `RC-0 ⇔ none` and `snapshot-meta ⇔ RC-5` biconditionals; **every declared summary label present exactly once**, no duplicate members inside a summary, and forward **and** bounded-reverse summary↔live parity for **every** summary; and **two complete, unique published censuses** (value kind *and* registry class) — every vocabulary token claimed exactly once, including zero-valued ones, no unknown tokens, plus the row and sensitive-kind totals — all reproduced from parsed rows | `CONFIG-SURFACE-MATRIX.md` §"The matrix" + its own class/vocabulary/summary/census blocks |

### `predicate-26.py` — the anti-vacuity check

**Exact property.** Every `MCP-CFG-001` assertion is quantified over the rows of one table. *A check quantified over a set it failed to build is not a check — it is a green tick.* PR #947 shipped exactly that: a 17-cell header against a 16-cell delimiter row. Per GFM, *"The header row must match the delimiter row in the number of cells. If not, a table will not be recognized"* — so a conformant parser yields **zero** rows, `count(RC-X) == 0` holds trivially, the value-kind invariant has nothing to quantify over, and every downstream assertion passes while asserting nothing. This predicate's **first duty is to refuse to be vacuous**: an unparseable or empty table is an unconditional failure, never a silent pass.

**How to run** (from the repository root):

```
python3 docs/design/mcp/predicates/predicate-26.py
```

Exit `0` = every property holds, every seed fired, every negative control stayed silent. Exit `1` = at least one violation, printed. Stdlib only; no network, no third-party imports, no repository mutation.

**Two ways a summary row is bound, and why it matters.** A summary that enumerates *every* live row of a class (`RC-1`, `RC-2`, `RC-3`, `RC-4`, `RC-5`) is checked by **class-level reverse parity** — drop a member and the missing live row is named. A summary that is a deliberately **bounded subset** of a large class cannot be checked that way: `Snapshot publication settings` names two of the 38 `RC-7` rows, so demanding class-level reverse parity there would demand all 38. Its membership is instead **pinned to an explicit name list** in the predicate, which is the stronger constraint — it fixes the set exactly, so neither a dropped nor an added name passes. The earlier mixed `{RC-5, RC-7}` row was checked exhaustively for `RC-5` only, which left both `RC-7` publication settings deletable with the predicate green; that is why the row was split in two.

**Seeded positive controls — each of the 22 mutations MUST be detected** (the run prints `DETECTED`/`MISSED` per seed, and a `MISSED` fails the predicate, so a decorative check cannot pass):

*Parse validity (4)*
1. a delimiter cell containing **one** hyphen;
2. a delimiter cell containing **two** hyphens;
3. a delimiter cell with **malformed alignment syntax** (`:-:-:`);
4. a 17-column header with a 16-column delimiter — *the #947 defect itself*.

*Anti-vacuity (1)*
5. a table that parses to **zero** rows.

*Summary integrity (5)*
6. an `RC-7` publication setting **dropped from its bounded summary** — the case class-level parity cannot reach;
7. the same field named **twice inside one summary row** — invisible once the member list is collapsed to a set;
8. **two summary rows carrying the same label** — invisible to a first-match reader;
9. an **RC-1** summary disagreeing with the live rows — parity is enforced for *every* summary, not only `RC-2`;
10. a live `RC-0` row named in the `RC-2` summary — *the D-2 defect itself*.

*Census completeness and uniqueness (7)*
11. the **registry-class** census omitting `RC-3`;
12. the **registry-class** census stating the wrong `RC-7` count;
13. the **registry-class** census claiming `RC-2` **twice**;
14. the **registry-class** census stating `RC-X` as `1` — the forbidden class published as non-empty;
15. a published value-kind census count **deleted** — an omitted claim must not hide a stale one;
16. a **zero-valued** census claim falsified (`pinned-identity 0 → 99`) — kinds with no live rows are still checked;
17. the published **row total** falsified.

*Row invariants (5)*
18. a live `RC-2` row missing from its summary — the class-exhaustive reverse direction;
19. `provider-ref → RC-6` — a sensitive value kind in a non-sensitive class;
20. a duplicate field ID;
21. an unknown value-kind token;
22. a live row classified `RC-X`.

Seeds 1–3, 6–8 and 11–14 were added after the third verification round; seeds 9, 15–17 after the second. Each round found the same shape of hole — a check that quantified over what the document happened to mention rather than over the declared vocabulary, or that took a first match instead of counting occurrences. Two further failure conditions are enforced but not separately seeded: a census claiming a token **outside** the declared vocabulary (no parsed count could ever confirm or refute it), and a bounded summary gaining a name outside its pinned list.

**Negative controls — each MUST stay silent**, proving the predicate is bound to this one table and does not police unrelated prose: an unrelated prose table gaining a row; a fenced code example containing `mcp_`-shaped pipe rows; an ordinary prose edit outside any table. Valid GFM alignment syntax (`:---:`) is also accepted without complaint — the three-hyphen minimum constrains cell *length*, not alignment.

**Limits — read before over-claiming.** It parses **one named table**, located by its exact heading (`## The matrix`) and its exact first header cell (`Field ID`), plus the summary and census blocks of that same document, against a documented schema. It is **not** a general Markdown validator and proves nothing about any other table, document or file — including the other tables in the same document. It checks the *design matrix*; it cannot check the runtime `configSurfaces` registry, which does not exist yet, so `MCP-CFG-001`(7)'s registry-side binding and registry↔matrix parity remain **specified but unenforced** until PR-1. Summary membership must use **full field names**: the snapshot summary originally abbreviated them (`_credential_revision`), which silently defeated mechanical parity and is why the expanded form is now required. `EXPECTED_ROWS`, the summary bindings and the two vocabularies are deliberate constants: a legitimate row addition, a new summary row or a new class token is expected to fail this predicate until the constant is updated under review.

**Like every predicate here, it is not wired into CI.** It passes only when run by hand.

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

**An early exit must satisfy a higher bar than the check it bypasses** (round 44). Every "skip the verdict"
branch here has been wrong at least once — a bare marker matched anywhere (43), a marker not bound to the
object of `BEFORE` (44), a multi-class sentence exempted by one class (44), a scope context read from a raw
lookback (42). An exemption decides what *not* to look at; bind it to the exact construct it claims to
recognise.

**Narrowing a check to the counter-example is not narrowing it to the class** (round 45). Round 44 bound
`predicate-22`'s generic escape to the object of `BEFORE` and delimited that object with `;` and `—` — the
two forms it had been shown — leaving the escape reachable through a **comma** aside. The same round read
the scope from the whole sentence, so a class token in a trailing aside (`… BEFORE the upstream call; write
metrics are emitted separately.`) became the assertion's scope. Rounds 39, 40, 41, 44 and 45 all fixed a
boundary or an exemption using exactly the delimiter the reporter demonstrated; four were wrong about a
sibling form within one round. Enumerate a construct's delimiters from the grammar, not from the failing
example. Note the asymmetry that fix required: the escape and the scope use the **tight object**, while
action detection stays on the full sentence span, because a legitimate enumeration crosses commas
(`signed, pushed or applied`).

**Enumerate a construct's delimiters exhaustively — and where enumeration cannot reach, guard the
semantics instead** (round 46). Round 45 replaced "copy the reporter's punctuation" with "derive the
delimiters from the grammar", and then enumerated three of them: `[;,—]` omitted the **parenthesis**, so the
same escape reopened one round later. Worse, one instance of the construct carries **no delimiter at all** —
a coordinated aside (`… BEFORE the upstream call **and** write metrics are emitted separately`) — and
splitting on `" and "` would break a legitimate compound object (`the upstream call and any retry of that
call`). That case is closed by a different mechanism: an **explicit universal quantifier** (*all / each /
every class*) forbids any single-class token from narrowing the assertion, whatever punctuation carries it.
When a delimiter list cannot reach a form, a longer character class is the wrong instrument.

**The same tightening can be correct in one predicate and a regression in another** (round 46). Sweeping
this dimension found `predicate-24`'s clause splitter absorbing a parenthetical as owned evidence — but
adding `(` to its `CLAUSE_END` raises **three false positives on live documents**, because there the
parenthetical *is* the clause's own assertion rather than a place an escape hides. That gap is recorded as
**open and demonstrated**, not closed: telling "the clause's own parenthetical" from "a parenthetical that
attributes the assertion elsewhere" falls in the **attribution** dimension listed below as not mechanisable.
Check each consumer of a shared span separately before propagating a fix across them.

**A seed must discriminate the change it certifies** (round 45). The two round-45 seeds were run against the
committed **pre-fix** predicate as well as the fixed one, and required to MISS there. A seed that fires
before and after proves the harness runs, not that the fix works.

**A table of test cases must assert its own distinctness** (round 44). `predicate-22`'s seeds were a dict
keyed by target filename; two round-44 seeds reused files earlier seeds had used and were silently
discarded by the dict literal, appearing to pass while never running. Seeds are now a list with unique
labels and unique targets, asserted at run time.

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
