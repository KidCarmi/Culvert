# Instruction migration and validation record

## Scope and baseline

This instruction-only change is based on main
`3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af`, tree
`b4158d816f7a9bf5fc51a467578c8dc4ff5e4201`. A separate fresh checkout and
branch avoid changing active development work. Main was chosen because the open
appliance branch contains unmerged behavior; it is not an interchangeable source.
No application source, runtime test, dependency/toolchain pin, CI workflow,
permission setting, merge requirement or deployment is changed.

Original root `CLAUDE.md`: 464,534 bytes; 346 newline-terminated lines;
Git blob `84e5b5c06e3972862f6ce2c75dce128a5635cddb`;
SHA-256 `d52076cca7e76045e31000e4abe89d3b0262ed28d1e82a2c20a7f95d0f06853c`.
There were no other tracked AGENTS/CLAUDE/native skill files at this baseline.

## Architecture and preservation

- Root `AGENTS.md` is the shared current guide; root `CLAUDE.md` explicitly imports
  it AND [conventions.md](conventions.md) (correction round: the rules CI and CodeQL
  enforce — `logger.Printf`, `sanitizeLog`, `isPrivateHost`, `NewRequestWithContext`,
  `requireRole`, `saveConfigVersion`, GUI parity — were reachable only through a
  link an agent had no reason to follow before writing code; the root guide now
  names them as mandatory and the Claude adapter loads them eagerly). The
  adapters' imports are an EXACT allowlist in `check.py` (`EAGER_IMPORTS`), and
  the imported documents are terminal (`NO_IMPORTS`): a second import, a
  different target, or an import inside an imported document is refused.
- Root semantic routes cover root-level adapters as well as package directories.
  Current conventions and admin/admission contracts keep consequential constraints
  discoverable; full incident narratives remain on-demand evidence.
- The 108 ordered source blocks have one canonical owner across 22 history files
  (domain buckets plus original reference sections). Markers retain the exact raw
  bytes, including duplicates and obsolete prose. Current summaries/errata sit outside
  those blocks. No second full monolith is needed for reconstruction.
- Each history file has stable anchors and a topic list. Source-root relative
  references inside preserved bytes retain their original spelling: use the pinned
  original link beside each block to follow them, or the working current routes.
  The validator deliberately excludes those frozen embedded links from relocation
  checks; all newly authored navigation is checked.
- [preservation-map.json](preservation-map.json) records original source ranges,
  hashes, byte lengths, destinations, anchors and scoped current-route obligations.
  Each declared task section must link directly to its exact block or to its
  history document whose Topics list links to that block; an inventory link in
  another section cannot silently substitute for the task route. Multiple domains
  can reference one block. No paragraph is discarded as “obsolete.”
- Two narrow workflows have native entry points in both `.agents/skills` and
  `.claude/skills`; thin wrappers explicitly load the same canonical procedure.
  Ordinary-document links remain available when a client does not advertise skills.
- Only admission gets additional scoped instructions in this first migration:
  its ownership and review cases were inspected in depth. Other domains get
  explicit source/history routes rather than invented new authoritative manuals.

[Research and design](research.md) records actual public vendor practices,
loading mechanisms, tradeoffs and evaluation recommendations. The 8 KiB root
budget is a project working budget, not a vendor rule or evidence of a quality gain.

## Reproduce structural checks

From repository root, with Python 3 and Git:

```sh
python3 docs/agent-context/check.py
python3 docs/agent-context/check.py --self-test --diff-base 3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af
python3 docs/agent-context/check.py --reconstruct /tmp/culvert-original-guide.md
git hash-object /tmp/culvert-original-guide.md
git diff --check
```

These check source/destination hashes and full reconstruction, unique ownership,
links and anchors, native wrappers, transitive adapter imports, budgets, semantic
route fixtures and the change allowlist. Negative controls deliberately corrupt
copies and must be rejected. Static route fixtures test reachability/content,
not an agent's actual decision or implicit skill selection.

`--diff-base <commit>` is the per-PR scope rule the CI job applies: every
changed guidance-SHAPED path (an `AGENTS.md`/`CLAUDE.md`/`AGENTS.override.md`
anywhere, anything under `docs/agent-context/`, a native `SKILL.md`, a
`.claude/rules/` file) must be one the checker registers, so a new nested guide
or skill is refused until `check.py` lists it. A PR that also changes code
passes this rule; `--instruction-only` additionally refuses any non-guidance
path and is the posture the ORIGINAL migration commits were validated under.
An unresolvable base is an explicit failure, never an empty diff. The default
integrity check remains usable after unrelated runtime commits; the historical
source hashes stay pinned independently of the diff base. The import check
conservatively rejects path-shaped @ references anywhere in shared/native
guidance except each adapter's exact approved list, including inline
occurrences; it intentionally does not attempt to emulate every client parser.

## Continuous enforcement

The Fast PR Gate (`.github/workflows/pr-fast-gate.yml`, the required merge
check) carries a `docs-guidance` job. Its classifier sets `guidance=true` for
any registered guidance path, any guidance-shaped path the checker must refuse,
the checker and its metadata, and the workflow itself; those paths stay
documentation to the code classifier, so a guidance-only pull request runs this
job and not the race suite. The job resolves the comparison base per event — a
pull request uses the merge commit's first parent (the base tip the diff was
computed against), a dispatch uses the merge base with the base branch, and any
other event or a missing base is an explicit failure — then runs
`check.py --self-test --diff-base <base>`. The aggregate requires the job to be
exactly `success` whenever the classifier saw guidance, mirroring the race-path
rule for code. `fast_gate_race_shards_test.go` drives the real classifier with a
guidance-only diff, a stray nested guide, and the workflow change, and pins the
job's event rules and the aggregate requirement. The checker's own registry
(`GUIDES`, `SKILLS`, `EAGER_IMPORTS`) is the list CI enforces: adding a nested
`AGENTS.md`, a Claude adapter or a skill means registering it there in the same
change, which is how the import wall and load budgets cover it.

## Actual execution record

Environment: isolated cloud checkout; Git 2.52.0; Python 3.12.14; Codex CLI 0.159.2.
No Claude CLI was found. No local authenticated model run was attempted.

- Structural checker PASS: 108 source blocks, 464,534 reconstructed bytes and
  original Git blob identity; 441 newly authored navigation links/anchors; 117 declared task-section-to-block
  edges; 10
  static route fixtures; native wrapper parity/frontmatter; change allowlist.
  All 10 corruption/route/import/drift/budget negative controls were rejected.
  Two future-baseline controls passed: unrelated source changes preserve source
  integrity, and a committed future runtime change is excluded by a new PR base.
  `git diff --cached --check` PASS (including all newly staged files). These are deterministic checks, not model evaluations.
- Measured source bytes at the initial head: shared root 6,460; root-plus-admission
  9,052; including both Claude adapters 9,298. After the correction round that
  made conventions eager and mandatory: shared root 7,190 (budget 8,192); Codex
  root-plus-admission 9,782; Claude root eager chain (`CLAUDE.md` + `AGENTS.md`
  + `conventions.md`) 14,850 (budget 16,384); every registered guide plus the
  eager conventions 17,483 (budget 32,768). These are static file sizes, not
  observed loaded context or token measurements. No full history is
  transitively imported; the checker refuses one.
- Real Codex loader attempted with `codex debug prompt-input` at root. It failed
  before reading instructions because the fs sandbox helper could not build its
  bubblewrap command: app-server socket directory ownership/mode requirement.
  A private writable CODEX_HOME/XDG_RUNTIME_DIR and read-only/no-approval mode did
  not resolve it. No system/security settings or credentials were changed.
- Codex focused-directory loading, model-guided root routing, explicit/implicit
  skill invocation, Claude root/nested loading, controlled hosted-review loading
  trials and resumed/compacted task trials: NOT RUN. Static predictions are not substitutes.
- Application Go tests: NOT RUN. The computer's `/usr/bin/go` is not a working
  Go compiler (`go version` returns “Unknown option”). No Go/runtime files change.
- No application performance benchmark, token measurement, model-quality comparison,
  review-recall experiment or compaction trial was run. Smaller instruction bytes
  alone do not establish fewer total tokens, better outcomes or subscription savings.

The [research validation matrix](research.md#validation-plan-and-honest-completion-claims)
and [retrieval cases](routing-cases.json) provide a reproducible next step in the
actual installed clients. For a behavioral comparison pin baseline/candidate SHA,
client/version/model/settings/cwd, use fresh sessions, capture actual loaded sources
and task decisions, and include safe counterexamples. Test explicit, implicit and
negative skill triggers separately. Do not mark the PR behaviorally proven until
these rows have evidence.

## Correction round: enforcement and discoverability

Validated locally against the reworked checker and the CI job's own step
scripts (replayed with the shipped `run` blocks on a disposable merge commit of
this branch into `main`, the shape `actions/checkout` gives a pull request):

- `check.py --self-test --diff-base 3fcc07e7…` PASS: 108 blocks, 464,534 bytes,
  blob `84e5b5c0…`, 449 navigation links, 117 route edges, 10 route cases,
  17 negative controls rejected, 2 future-baseline controls passed; 44 changed
  paths of which 42 are registered guidance.
- `--instruction-only` REFUSES this round (`Out-of-scope change:
  .github/workflows/pr-fast-gate.yml`), as it must: the round adds a workflow
  job and a Go test, so it is no longer instruction-only. The original two
  commits remain validated under that posture.
- Base resolution: `pull_request` with the event base → the merge commit's
  first parent, equal to `origin/main`; `pull_request` without a base SHA → exit
  1; event `push` → exit 1; `workflow_dispatch` → merge-base with `origin/main`;
  an empty resolved base at the checker step → exit 1.
- Negative controls through the CI invocation, each restored afterwards and the
  worktree verified clean: a retargeted README route → `Broken declared
  route-to-block edge: claude-main-L175-L175`; an edited `.claude` skill copy →
  `Native skill drift: culvert-verify`; a third `@import` in `CLAUDE.md` →
  `Unexpected eager imports`; an `@import` inside `conventions.md` →
  `Transitive eager import`; an untracked `internal/connlimit/AGENTS.md` →
  `Unregistered guidance file`.
- `go test -run 'TestFastGate|CIPerf|Toolchain|AdmissionMigration|Workflow|
  Pinned|Actions|Gate|QARace|CodeQL|Release…|Feeds|Cosign|DocsADR' .` PASS,
  `gofmt`/`go vet` clean. The full root suite, the Fast/Deep gates for this head,
  and any Claude or Codex loading trial were NOT run here.

## Initial hosted review and follow-up

The PR was created as draft. The owner marked it ready on 10 October 2026;
this implementation did not toggle it. Hosted Codex and CodeRabbit then reviewed
initial commit `ef9fcbb9b39f1a9836e0d4a7734ed27dcd1c07b0`.
[Codex identified](https://github.com/KidCarmi/Culvert/pull/1592#discussion_r4236812506)
that existing-file/link checks could miss a misdirected task route. The follow-up
adds all 117 declared section-to-block obligations plus retargeted-link and
wrong-TOC-anchor negative controls. A generic inventory link cannot mask either.
[CodeRabbit requested](https://github.com/KidCarmi/Culvert/pull/1592#discussion_r4236808227)
clarification of timestamp reference frames; current prose now distinguishes
sampled, recorded and lock/append times without changing runtime behavior.

Both required CI aggregates passed on that initial commit. A new follow-up SHA
requires its own CI verdict. This actual hosted review is useful evidence, but
it is not a controlled baseline/candidate instruction-loading or quality trial.

## Branch reconciliation

PR [#1528](https://github.com/KidCarmi/Culvert/pull/1528) was observed at
`72c827b7f59f4e43ff2a813241be9029f58f23a9`: its guide was 472,104 bytes,
blob `c9e6cb372f8d97f2dc73a94efa565de191dcab91`. Its additional appliance
contracts and Go 1.26.9 pin are deliberately excluded from this main-based change.

If main advances before merge, compare the incoming guide with the preserved
source first. Do not resolve a CLAUDE conflict by keeping only the short adapter.
Inventory and preserve every incoming addition with a new pinned source/hash,
reconcile changed active claims and links, regenerate the complete source-to-owner
ledger/expected hashes for that baseline, and rerun structural plus applicable
loading checks. Keep the old migration provenance accessible in Git history.
Do not reset or force-push another developer's branch.

## Follow-ups recorded, not done here

- Stale section-specific `CLAUDE.md` citations now point at a short adapter:
  53 Go files (64 occurrences, 13 naming a specific section such as
  "Test-authoring pitfalls", "HTTP contexts" or "Admin-UI invariant #6"), 83 files
  under `docs/` (234), 45 under `roadmap/` (95) and 2 under `.github/` (4).
  Retarget them to `docs/agent-context/history/<bucket>.md#<anchor>` or the
  domain document in a dedicated change; bulk-rewriting historical citations is
  deliberately not part of this migration.
- The Deep PR Gate classifier maps `internal/*` to `security=true`, so editing
  `internal/<pkg>/AGENTS.md` runs staticcheck and the shuffled Go suite. A
  follow-up should treat nested guidance files specifically; not every Markdown
  file under `internal/` is safe to exclude without checking how it is consumed.
- Deep determinism failures seen on this PR at `5551a4a` (no Go source changed):
  attempt 1, `TestBenchGate_IPFilterBulkLoadIsLinear` measured 8.74x against its
  8x bound — a timing-ratio gate stabilised twice on main in the preceding
  fortnight (`c276313`, `6a83a2b`) whose own comment records CI ratios of 8.28x
  and 10.81x for the unchanged linear implementation; attempt 2,
  `TestChaos64_StaleServesDoNotStackRefreshes` read 1 resolver call where 2 were
  expected — its assertion reads the counter immediately after the stale burst,
  while the refresh leader runs in a detached goroutine (`refreshAsync` →
  `lookupPublicHostIP`) that need not have been scheduled yet, and the drain
  that would wait for it is deferred until after the assertion, so a count of 1
  means "refresh not started", not "refreshes stacked"; waiting for the second
  call before asserting that no third arrives is the candidate fix. Baseline
  evidence that the class predates this PR: the QA Gate on the PR base
  `3fcc07e` itself failed in root race shard 3 (run 36842294126), and an
  unrelated PR (#1587, `bffb182`) failed Deep determinism on
  `TestShadowExitC7_LatencyBudget` at 10.09x against a 5x ceiling (run
  37997901929). None of those tests is modified here; the evidence is recorded
  so a rerun is not mistaken for a resolution.

## Maintenance

A new invariant belongs with its current owner and executable contract; add its
route when otherwise undiscoverable. A chronology or benchmark belongs in history,
with revision and conditions. A repeated procedure belongs in a workflow. Review
instruction changes like code, check both tool-native discovery paths, and evaluate
whether additional scaffolding earns its overhead. Existing task permissions remain
separate from instructions, skills and reviewer suggestions.
