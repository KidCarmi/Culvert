# Remediation predicates

Executable structural checks written during the PR-1 readiness remediation
(`../PR1-READINESS-REMEDIATION.md`). Each one exists because a defect of that
shape reached a reviewer, and each is intended to make the same shape
**enumerable** rather than re-checked from memory.

## CI status — exact, per predicate

**Seven of the eight now run in the required Fast PR Gate.** This changed after board
blocker #927, which took three PRs and four verification rounds — and *every*
intermediate head passed the full pipeline while still carrying a real defect,
including one where the config-surface matrix did not parse as a table at all and
every assertion over it passed vacuously. CI carried no signal because nothing in
it parsed these documents.

| Predicate | CI status |
|---|---|
| `predicate-19.py` | **Runs in Fast PR Gate** — `Gate · MCP design predicates` |
| `predicate-21.py` | **Runs in Fast PR Gate** (gated arm only; the advisory arm stays report-only) |
| `predicate-22.py` | **Runs in Fast PR Gate** |
| `predicate-23.py` | **Runs in Fast PR Gate** |
| `predicate-24.py` | **Runs in Fast PR Gate** |
| `predicate-25.py` | **Manual only — deliberately excluded from CI** (see below) |
| `predicate-26.py` | **Runs in Fast PR Gate** |
| `predicate-27.py` | **Runs in Fast PR Gate** |

The job runs when a PR touches `docs/design/mcp/**`, ADR-0024, the runner script,
or `pr-fast-gate.yml`; it is skipped otherwise, and a skip counts as passing. A
**failure blocks** the `✅ Fast PR Gate — APPROVED` aggregate, so a relevant MCP
docs PR cannot go green while a selected predicate fails. Runner:
[`.github/scripts/mcp-doc-predicates.sh`](../../../../.github/scripts/mcp-doc-predicates.sh),
which carries the membership as an **explicit allowlist** — not a
`predicate-*.py` glob, so a future predicate does not become blocking without
review.

**Arm 4 — the two blocks the #926 merge left behind (added post-merge).** Narrowly scoped **by
construction**: it reads exactly two named blocks and checks four stated properties. It is **not** a prose
linter and must not become one.

1. **`MCP-AC-016` states no POSITIVE denial-event lockout requirement.** A phrase such as `DURABILITY
   LOCKOUT`, `operations are blocked`, `critical degraded state` or `the lockout proven` fails, *unless* the
   sentence is explicitly labelled historical (`superseded`, `former`, `no longer`, `PROVEN TO FAIL`) or the
   phrase carries an **attached** grammatical negation within 45 characters.
2. **`MCP-AC-016`'s five fields agree** — Expected control, Expected event, Expected policy result, Test and
   Closure must all take the denial-lane stance, and the Closure must assert the lockout **attack FAILED**
   rather than that a lockout was established.
3. **`D-5`'s residual is consistent with `R-6`'s CURRENT status, read from `THREAT-MODEL.md` §12** — never
   hard-coded. While `R-6` is `pending`, `D-5` must reproduce that and must not claim acceptance; once
   `R-6` is accepted, `D-5` must stop asserting the pending state. An unparseable `R-6` row is a
   violation, not a pass.
4. **`D-5`'s evidence names `MCP-EVENT-001..007` and `MCP-OPS-005`**, not the stale `..006` range.

**Why this arm exists.** The #926 remediation updated *some* fields of these two blocks and not others. The
result was one abuse case that simultaneously **required** the denial-event lockout (Expected control,
Expected event, Closure) and **forbade** it (Expected policy result, Test), and a decision block still
calling the residual *"accepted, alertable"* while `THREAT-MODEL` `R-6` recorded it as **PENDING, not
accepted by a named human**. Both survived a full predicate run, a green required gate, and a self-check by
the session that wrote the change — because nothing quantified over those blocks. Four of the arm's five
seeds restore the **actual surviving text**, so the arm is pinned to a defect that really occurred rather
than to a hypothetical one.

**A negation must be attached, and it must belong to ITS OWN occurrence.** This exemption logic leaked
three times, each caught by a seed rather than by reading:

1. Sentence-wide negation matching let a genuine lockout demand pass because an unrelated `cannot` sat
   ~110 characters upstream in the same sentence → the window was narrowed to 45 characters.
2. `re.search` returns only the **leftmost** match, so a negated occurrence followed by a positive one
   ended the scan for that pattern → the loop is over `finditer`, so every occurrence is inspected.
3. A plain 45-character lookback around the *second* occurrence still swallowed the *first* occurrence's
   `no` → each window is bounded by the end of the previous match, so one occurrence's negation can never
   exempt the next.

The seeds pin all three. This is the same "a check that can be laundered is not a check" lesson
`predicate-22` and `predicate-26` each learned in their own way — and it took three rounds here because
each fix opened the next hole, which is exactly why the seeds exist rather than a careful reading.

**Why `predicate-25.py` is excluded.** It is remediation/provenance-specific: it
diffs against a **fixed historical base commit** (`1203e04b`, overridable via
`CULVERT_PROVENANCE_BASE`) to check that one remediation's provenance claims match
its actual diff. Run as a general gate it would fail an unrelated, perfectly valid
PR merely for changing a requirement or decision *after* that historical point —
a false block on correct work. It stays manual, and should be run by hand when
auditing a remediation's provenance claims.

**What passing still does not prove.** These predicates check **design documents**.
The runtime `configSurfaces` registry does not exist yet, so `MCP-CFG-001`(7)'s
registry-side binding and registry↔matrix parity remain **specified but
unenforced** until PR-1 — `predicate-26` passing green says nothing about them.
Nothing here promotes PR-1 or discharges any remaining board blocker.

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
| `predicate-24.py` | (arm 1) every per-class absence enumeration carries the action-keys that class requires; (arm 2) the two copies of the per-class **irreversible-action** table agree cell-for-cell; (arm 3) the two copies of the per-**action-class** durability table agree cell-for-cell, **header included** (#926); (arm 4) **`MCP-AC-016` and `OPEN-DECISIONS` `D-5` carry no stale denial-lockout or residual-acceptance semantics** (#926 post-merge) | `EVENT-MODEL.md` §4a's per-class table; `ABUSE-CASES.md` `MCP-AC-016`; `OPEN-DECISIONS.md` `D-5` |
| `predicate-25.py` | every **provenance** claim ("what this remediation changed") matches the actual diff — added/rewritten requirement IDs (both directions), touched decision blocks (both directions), and every repository-context row added, removed or changed without cover | the diff against the **recorded pre-remediation commit** `1203e04b` (`CULVERT_PROVENANCE_BASE` overrides) |
| `predicate-26.py` | the config-surface matrix **parses as a table at all**, is **non-empty**, and every `MCP-CFG-001` row invariant holds over the **parsed** rows — header/delimiter/data widths equal, **every delimiter cell ≥ 3 hyphens**, expected row count, no duplicate field IDs, known registry classes and value kinds, sensitive value kinds only in `RC-1`/`RC-2`, `RC-X` empty, the `RC-0 ⇔ none` and `snapshot-meta ⇔ RC-5` biconditionals; **every declared summary label present exactly once**, no duplicate members inside a summary, and forward **and** bounded-reverse summary↔live parity for **every** summary; and **two complete, unique published censuses** (value kind *and* registry class) — every vocabulary token claimed exactly once, including zero-valued ones, no unknown tokens, plus the row and sensitive-kind totals — all reproduced from parsed rows | `CONFIG-SURFACE-MATRIX.md` §"The matrix" + its own class/vocabulary/summary/census blocks |
| `predicate-27.py` | both the **requirement** registry and the **threat** registry **parse non-vacuously**, and every published census that summarises them matches the value **derived from the live registry** — the requirement total, namespace (family) count and **complete, unique per-family** census in `SECURITY-REQUIREMENTS.md` `## Summary`; the `TEST-TRACEABILITY-MATRIX.md` final-totals `**N threats**` / `**N requirements**`, its per-family spot-claims, and the §3 `all N requirements, 0 unreachable` total; plus per-ID uniqueness in both registries. Occurrence-counted, not first-match; a statement explicitly describing an **earlier** state is not governed | the requirement rows of `SECURITY-REQUIREMENTS.md` (per-family `\| ID \| … \|` tables) and the canonical `MCP-T-###` rows of `THREAT-MODEL.md` §11 |

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

**It now runs in the required Fast PR Gate** for PRs touching the MCP design surface (see §CI status above) — a failure blocks the aggregate. That closes the "green CI while the document does not parse" gap that produced it, but it does **not** extend its reach: it still checks the design matrix, never the runtime registry.

### `predicate-27.py` — requirement/threat census parity

**Exact property.** Every published census that summarises the MCP requirement or threat registries must be **mechanically derived from the live registry** and must fail CI when it is missing, duplicated, incomplete, stale or internally inconsistent. This closes the **recount-vs-increment** drift that recurred during RPR-2: a document publishes an old total (a stale `91 requirements` that predated a later-added ID) while every existing check stays green, because nothing in CI recounts the live registry and compares it to the published figure. A published prose number is never the authority here — it is the thing under test.

**The two authorities, and only these two.**

- **Requirement registry** — `SECURITY-REQUIREMENTS.md`: the requirement rows of the per-family GFM tables (header `| ID | Statement | … |` or `| ID | Normative statement | … |`). Live facts derived: total ID count, per-family counts, per-ID uniqueness, and the complete family set. The family of an ID is taken from the **row**, never a heading — `## MCP-CPDP / MCP-HA` names two families in one heading, so heading parsing would miscount.
- **Threat registry** — `THREAT-MODEL.md` §11 "Risk register (canonical threat IDs)": the canonical `MCP-T-###` values in the **first column** of the §11 sub-tables. Live facts: total ID count, per-ID uniqueness. Incidental `MCP-T-###` references elsewhere in the file (STRIDE tables, control columns, residual-risk prose) are **not** the registry and are not counted — negative control 2 pins that.

**Governed censuses — every enforced claim.** Each is compared against the value **derived from the live registry**, occurrence-counted (not first-match):

1. `SECURITY-REQUIREMENTS.md` `## Summary` — `**Total requirements: N**` equals the live total; `across N namespaces` equals the number of live families; the per-family parenthetical `(MCP-PROTO N, …)` is a **complete, unique** family census (forward parity: no unknown family; reverse parity: no live family omitted; uniqueness: no family claimed twice; each count equals live); and the per-family counts **sum** to the live total (internal consistency).
2. `TEST-TRACEABILITY-MATRIX.md` final-totals bullet — `**N threats**` equals the live threat total; `**N requirements**` (anchored to the adjacent `**N threats**;` so a historical `"**91 requirements**" was stale` sentence is **not** matched) equals the live requirement total; and each per-family spot-claim `MCP-FAM **N**` (a deliberately *partial* list — "the other families unchanged") equals live for the families it names.
3. `TEST-TRACEABILITY-MATRIX.md` §3 coverage — `all N requirements, 0 unreachable` equals the live requirement total.
4. Both registries parse **non-vacuously** (a registry that parses to zero rows is an unconditional failure) with a valid GFM table shape (every delimiter cell ≥ 3 hyphens; header width == delimiter width == every data-row width), and every live ID in each registry is **unique**.

The cell splitter is **inline-code aware**: a pipe inside backticks (e.g. a cell reading `` `RC-1|RC-2` ``) is not a column separator, exactly as GitHub renders it — a splitter that ignored code spans would over-count that row and silently drop a live requirement.

**Drift fixed in the same change.** The §3 coverage assertion still read `all 91 requirements, 0 unreachable` — the stale figure the #927 recount corrected in the final-totals bullet but missed here. It is corrected to `94` (the live total, matching the document's own authoritative final-totals census). No requirement, threat or decision text is otherwise touched.

**How to run** (from the repository root):

```
python3 docs/design/mcp/predicates/predicate-27.py
```

Exit `0` = every property holds, every seed fired its intended violation, every negative control stayed silent. Exit `1` = at least one violation, printed. Stdlib only; no network, no third-party imports, no repository mutation.

**Seeded positive controls — each of the 17 mutations MUST fire its INTENDED violation** (the harness checks that the seed's new violation contains a target substring, so a seed that trips only a *different* check — e.g. anti-vacuity — is reported `MISSED`, not laundered into a pass):

1. wrong total requirement count;
2. wrong count for one live requirement family (`PROTO`);
3. one live family omitted from the family census (`TOOL`) — reverse parity;
4. duplicate family census claim (`ID`) — uniqueness;
5. unknown family census claim (`FOO`) — forward parity;
6. duplicate total requirement claim — uniqueness;
7. **add** one valid live requirement row without updating any census;
8. **remove** one valid live requirement row without updating any census;
9. wrong total threat count;
10. duplicate total threat claim;
11. **add** one valid live threat row without updating any census;
12. **remove** one valid live threat row without updating any census;
13. the requirement registry table parses to **zero** rows — anti-vacuity;
14. a malformed requirement-registry delimiter/header width;
15. **first-match laundering** — a correct total followed by a wrong duplicate; a first-match reader passes on the correct one, occurrence counting catches the second;
16. a requirement row whose first cell is a **malformed ID** (`MCP-OPS-0O5`) — a row inside a matched registry table must be *reported*, not silently dropped, or a recount-and-reduce hides an untracked requirement *(added in response to Codex review)*;
17. a stale **duplicate total in a later paragraph** of `## Summary` — census claims are counted over the whole bounded section, not just its first paragraph *(added in response to Codex review)*.

**Enforced but not covered by a dedicated seed** (each is either exercised transitively by the add/remove-row seeds, or shares the exact code path of a seeded case): **per-ID uniqueness** in both registries (a duplicate requirement or threat ID); the **namespace-count** claim and the **family-census internal-sum** consistency (both move under seeds 7/8); the **threat registry's** own anti-vacuity and delimiter/width validation (same parser as the requirement registry, whose zero-row and malformed cases are seeded — 13, 14); and the `TEST-TRACEABILITY-MATRIX.md` **§3 coverage total** and **per-family spot-claims** (both move under seeds 7/8/11/12 — e.g. removing `MCP-OPS-005` makes the `MCP-OPS **5**` spot-claim and the §3 total disagree with the live registry).

**Negative controls — each MUST stay silent**, proving the predicate governs the two registries and their explicit censuses, not prose: a **historical** statement citing an earlier total (`"88 requirements" … historical`); an **incidental** `MCP-T-###` reference in a non-first column of a §11 row; and an unrelated number in ordinary requirement prose.

**Limits — read before over-claiming.** It governs two named registries and a small, explicit set of census statements about them. It is **not** a general Markdown linter and asserts nothing about any other number, table or file. It does not re-validate *reachability* (that a requirement is actually tested) — it validates that the published *counts* match the live registries; the coverage assertions themselves remain a Phase-5 concern. A statement that explicitly describes an **earlier** state is deliberately out of governance, so a corrected history note never trips it.

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
