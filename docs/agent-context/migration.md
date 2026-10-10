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

- Root `AGENTS.md` is the shared current guide; root `CLAUDE.md` explicitly imports it.
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
  hashes, byte lengths, destinations, anchors and current routes. Multiple domains
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

`--diff-base` is an explicit per-task scope check. Use this migration baseline
for this PR, and the actual task/PR base for later instruction-only changes.
The default integrity check remains usable after unrelated runtime commits;
the historical source hashes stay pinned independently of the diff base.
The import check conservatively rejects path-shaped @ references anywhere in
shared/native guidance except each adapter's one approved import, including
inline occurrences; it intentionally does not attempt to emulate every client parser.

## Actual execution record

Environment: isolated cloud checkout; Git 2.52.0; Python 3.12.14; Codex CLI 0.159.2.
No Claude CLI was found. No authenticated model run was attempted.

- Structural checker PASS: 108 source blocks, 464,534 reconstructed bytes and
  original Git blob identity; 434 newly authored navigation links/anchors; 10
  static route fixtures; native wrapper parity/frontmatter; change allowlist.
  All 8 corruption/route/import/drift/budget negative controls were rejected.
  Two future-baseline controls passed: unrelated source changes preserve source
  integrity, and a committed future runtime change is excluded by a new PR base.
  `git diff --cached --check` PASS (including all newly staged files). These are deterministic checks, not model evaluations.
- Measured source bytes: shared root 6,460; root-plus-admission 9,052; including
  both Claude adapters 9,298. These are static file sizes, not observed loaded
  context or token measurements. No full history is transitively imported.
- Real Codex loader attempted with `codex debug prompt-input` at root. It failed
  before reading instructions because the fs sandbox helper could not build its
  bubblewrap command: app-server socket directory ownership/mode requirement.
  A private writable CODEX_HOME/XDG_RUNTIME_DIR and read-only/no-approval mode did
  not resolve it. No system/security settings or credentials were changed.
- Codex focused-directory loading, model-guided root routing, explicit/implicit
  skill invocation, Claude root/nested loading, hosted Codex Review behavior and
  resumed/compacted task trials: NOT RUN. Static predictions are not substitutes.
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

## Maintenance

A new invariant belongs with its current owner and executable contract; add its
route when otherwise undiscoverable. A chronology or benchmark belongs in history,
with revision and conditions. A repeated procedure belongs in a workflow. Review
instruction changes like code, check both tool-native discovery paths, and evaluate
whether additional scaffolding earns its overhead. Existing task permissions remain
separate from instructions, skills and reviewer suggestions.
