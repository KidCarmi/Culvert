# Culvert agent instruction architecture research

Research date: 10 October 2026. Repository baseline: `KidCarmi/Culvert`, main commit `3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af`.

## Recommendation

Decompose the instruction system around how work is discovered and verified. Keep one compact shared entry point, explicit routes to relevant knowledge, small native entry points for repeatable workflows, and scoped review guidance. Preserve the complete existing guide as traceable historical material, while distinguishing it from current, source-verified contracts.

This is a quality and engineering-leverage proposal. The existing agent and review workflow is the starting point; usage scarcity is not the problem being optimized. There is no evidence here that another subscription would outperform improving that workflow. There is also no measured Culvert quality or token-saving result yet.

The proposed first PR changes instructions and their supporting documentation/validation only. It does not refactor application code, change CI merge requirements, enable an MCP capability, or revise runtime security posture. Admission is the well-inspected validation case, not the limit of the decomposition.

## Evidence classes

- **Observed repository fact:** established from pinned files, complete Git trees, source, or tests inspected during this audit.
- **Published vendor practice:** a vendor's public implementation or firsthand report. This does not expose or prove all of its private production practices.
- **Documented mechanism:** behavior described by current product documentation. Installed versions and settings still need verification.
- **Proposal:** our application of that evidence to Culvert. It must be evaluated rather than presented as a vendor prescription.

No runtime tests or agent-behavior comparisons were executed during this research. File inventory, source-byte reconstruction, hashes, and local executable availability were checked.

## Repository findings

### Exact baseline

The complete main tree contains 3,497 entries and is not truncated. The only tracked agent instruction file is root `CLAUDE.md`; no tracked `AGENTS.md`, `.agents`, `.claude`, or `.codex` configuration was present. This establishes repository state, not the owner's global instructions, untracked files, installed plugins, or Codex Review account settings.

The original guide is 464,534 UTF-8 bytes, with 346 newline-terminated lines. A string split on newline produces 347 elements because the final element is empty. Its Git blob is `84e5b5c06e3972862f6ce2c75dce128a5635cddb`; SHA-256 is `d52076cca7e76045e31000e4abe89d3b0262ed28d1e82a2c20a7f95d0f06853c`.

The file has very long paragraphs: its largest single line is 21,839 bytes including the newline. Therefore, a line-count target can be met while retaining an excessive context footprint. The Architecture Notes section alone occupies 400,600 bytes, about 86.2% of the guide. Other sections include the project map, 28,078 bytes; conventions, 6,002 bytes; CI, 7,236 bytes; and admin-control-plane material, 11,835 bytes.

The main tree has 1,281 root-level Go files, including 897 tests, and 70 first-level directories under `internal` containing tracked files. The guide's prose still says 68 internal packages, which should not be mechanically replaced with 70: directories and Go packages are different counts. Prefer durable ownership descriptions over manually maintained counts.

Sources: [pinned guide](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/CLAUDE.md), [complete main tree](https://api.github.com/repos/KidCarmi/Culvert/git/trees/b4158d816f7a9bf5fc51a467578c8dc4ff5e4201?recursive=1).

### The current file already contains several different kinds of knowledge

Its content combines active conventions, ownership rules, source navigation, operational commands, incident narratives, rejected alternatives, measurements, PR history, known remaining work, and detailed API contracts. Much of that history is valuable. Deleting it or summarizing it indiscriminately would discard the reasons behind unusually important invariants.

The problem is not simply that the file is long. It gives historical findings, current requirements, broad defaults, and specific exceptions the same apparent authority. A reader cannot quickly distinguish a current constraint from an old measurement or a superseded location.

The existing [Engineering Constitution](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/docs/engineering/ENGINEERING-CONSTITUTION.md) already establishes evidence-first advice, simplicity, and the precedence Source Code → Tests → CI Workflows → Configuration → Deployment → Documentation. It also defines an advisory role whose mission is not writing code. Preserve that charter and route architectural-advice tasks to it; do not import its role persona indiscriminately into every implementation task.

### Verified guidance drift

1. **Default policy posture:** the guide's blanket default-deny sentence is incomplete. At this main revision, `loadRewriteAndDefaultAction` defaults to allow when the configured action is empty and there are zero rules, and deny when rules exist. Explicit configuration is honored. Tests pin all four cases. Correct the current summary; retain the original historical source. This is a documentation finding, not a proposal to change policy. [Loader](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/rewrite_default_action_startup.go), [tests](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/rewrite_default_action_startup_test.go).
2. **Admission locations:** large older notes still name `security.go` for code now owned by `internal/admission`. ADR-0039, the package contract, and the new root aliases establish the current boundary. Historical benchmarks remain historical evidence, not fresh measurements. [ADR-0039](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/docs/adr/0039-admission-engine-package.md).
3. **Timestamp-clamp explanation:** the guide and code/test comments compare with “true arrival,” while the implementation clamps an earlier sample up to the prior newest stamp. Expiry is later or equal relative to the original sample, but normally earlier or equal relative to later lock/append time. These reference frames must not be conflated or labeled universally reversed. The synthetic ordering test does not capture actual arrival times or prove a per-entry arrival-based bound. Preserve the algorithm and test; record the reference-frame clarification separately. [Engine](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/internal/admission/engine.go), [window test](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/internal/admission/security_ratelimit_window_test.go).
4. **Overgeneral conventions:** a generic RWMutex recommendation cannot override the specific immutable-view and sharded-lock decisions documented elsewhere. Retain the decision boundaries and exceptions instead of turning one technique into a universal rule.
5. **Duplicate history:** the category-store recovery topic appears twice, with different text. Preserve both source blocks initially and flag their relationship; do not silently deduplicate them as though they were byte-identical.

### Active branch separation

PR #1528 is open on `feat/onprem-appliance-readiness`; its observed head is `72c827b7f59f4e43ff2a813241be9029f58f23a9`. Its guide is 472,104 bytes and 353 lines, blob `c9e6cb372f8d97f2dc73a94efa565de191dcab91`. Its complete tree has 4,681 entries and likewise contains no other tracked agent instruction file.

The branch adds appliance, in-place restore, release-transition, dispatch-resume, readiness, scanner-posture, setup-token, and login-binding knowledge. It also changed the documented build toolchain from Go 1.26.8 to 1.26.9; this PR later adopted the same 1.26.9 pin so govulncheck passes on the standard-library advisories fixed there. The branch's other facts are not interchangeable with main. A main-based instruction PR must preserve main's source and must not describe the branch-only paths as shipped. If #1528 merges first, regenerate the migration inventory from the new base, preserve its new blocks, and recheck every curated claim. Do not resolve a CLAUDE merge conflict by keeping the short new file and losing the branch additions. [PR #1528](https://github.com/KidCarmi/Culvert/pull/1528), [branch guide](https://github.com/KidCarmi/Culvert/blob/72c827b7f59f4e43ff2a813241be9029f58f23a9/CLAUDE.md).

## What the vendors publicly demonstrate

### OpenAI internal agent-first product experiment

OpenAI reports trying a monolithic instruction file and replacing it with an approximately 100-line navigation entry point into structured repository documentation. The team also used mechanically enforced architectural boundaries and documentation maintenance. This is a concrete internal case, with self-reported throughput, not a controlled demonstration that 100 lines is optimal. Its permissive merge philosophy is expressly tied to that particular high-throughput environment and should not be imported into Culvert's security-gateway process. [Harness engineering](https://openai.com/index/harness-engineering/).

### OpenAI Agents SDK maintenance

The published workflow combines repository policy, narrowly triggered skills, optional scripts/references, and GitHub Actions for already-stable procedures. It includes report-first documentation/coverage work and conditional verification, rather than running the entire stack for every editorial change. The blog reports 457 merged PRs versus 316 in the preceding three months across its two SDK repositories; this is observational throughput, with no causal isolation of the instruction changes. [SDK maintenance account](https://developers.openai.com/blog/skills-agents-sdk).

The actual current Python SDK guide is more extensive than that blog's simplified example: the fetched blob has 38,241 characters and 215 newline-split elements. It separates strategy, review, verification, and handoff triggers, and explicitly treats changes to decision-making guidance as requiring realistic scenarios and an independent pass. This is useful evidence against turning a vendor example into a universal length rule. Its repository-specific approval and release policies are not Culvert policies. [Actual contributor guide](https://github.com/openai/openai-agents-python/blob/main/AGENTS.md), [verification skill](https://github.com/openai/openai-agents-python/blob/main/.agents/skills/code-change-verification/SKILL.md), [strategy skill](https://github.com/openai/openai-agents-python/blob/main/.agents/skills/implementation-strategy/SKILL.md).

### OpenAI review rules and recent model guidance

OpenAI's custom-review evaluation included known violations and safe counterexamples. It reports 98% recovery of required custom findings versus 58.3% in its control, and emphasizes restraint and retention of ordinary bug detection. This supports testing a small set of consequential, scoped rules with explicit safe paths. It is not a forecast of Culvert recall or escaped-defect reduction. [Custom review rules](https://developers.openai.com/blog/custom-code-review-rules-for-codex).

The September 2026 prompting guidance warns that overbroad skill triggers, mandatory reading stacks, and rigid recipes can hinder newer models. It recommends contextual pointers and clear outcome/decision boundaries, while noting that other models may need different scaffolding. The implication is to retain domain constraints and verifiable completion criteria, then measure workflow overhead rather than mandating ceremony for every edit. [Recent prompting guidance](https://developers.openai.com/blog/rethinking-skills-and-prompts-for-gpt-6-astra).

### Anthropic team reports

Anthropic's firsthand team interviews describe targeted instructions learned from repeated failures, condensed runbooks, discovery of relevant files, checkpoints, and test-driven work. They distinguish interactive work on core logic from more autonomous disposable prototypes. These are qualitative accounts, not controlled evidence for a particular directory tree or number of agents. They support capturing durable lessons where future work can find them, rather than appending every session narrative to startup context. [Team interview report](https://www-cdn.anthropic.com/58284b19e702b49db9302d5b6f135ad8871e7658.pdf), [public summary](https://claude.com/resources/articles/how-anthropic-teams-use-claude-code).

Anthropic's context-engineering guidance favors high-signal context and just-in-time retrieval using useful identifiers. It also acknowledges the cost: retrieval can add latency and miss relevant information. A minimal but vague index therefore fails the goal. Culvert's routes must identify applicability, owning code, current contracts, and the historical failure cases worth reading. [Context engineering](https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents).

### Anthropic public workflow implementations

The inspected public code-review command uses four parallel reviewers followed by independent issue validation. Its high-certainty/diff restrictions and avoidance of linter noise are implementation choices, not proof that its separate hosted review service uses the same process. For Culvert, independent validation is valuable; restricting reviewers from tracing callers, state transitions, and concurrency would be harmful. The command also differs from descriptions of an older numerical confidence threshold. [Pinned public review command](https://github.com/anthropics/claude-code/blob/db8834ba1d72e9a26fba30ac85f3bc4316bb0689/plugins/code-review/commands/code-review.md).

The public feature-development workflow assigns distinct exploration perspectives and has the lead read important files identified by explorers. That is stronger than blindly trusting compressed summaries. Its full phase structure is appropriate to complex work, not a typo fix. [Feature development command](https://github.com/anthropics/claude-code/blob/main/plugins/feature-dev/commands/feature-dev.md).

### Orchestration has measurable tradeoffs

Anthropic reports a 90.2% improvement over its single-agent baseline on an internal research evaluation, alongside approximately 15 times chat token consumption for multi-agent systems. The report warns that tightly dependent coding is less parallelizable than breadth-first research. These results justify selective independent investigation, not a permanent four-agent team for every Culvert change. [Multi-agent research system](https://www.anthropic.com/engineering/multi-agent-research-system).

Its C-compiler experiment describes agents colliding around a shared blocker until the verification problem was decomposed. Concise test output and accessible detailed logs were part of making the work tractable. [Compiler experiment](https://www.anthropic.com/engineering/building-c-compiler).

The later long-running-app harness account revisits earlier scaffolding, removes components to test their value, and compares a $200 full-harness example with a $9 solo example that tackled a narrower scope. That is not an apples-to-apples cost-effectiveness result. The useful principle is periodic ablation: keep orchestration only when it improves the actual task. [Harness design](https://www.anthropic.com/engineering/harness-design-long-running-apps).

## Loading semantics that affect the design

### Claude Code

Current documentation says ancestor/current-directory CLAUDE files load at launch; descendant files and path-scoped rules load on relevant access. Imports and unscoped rules load eagerly. The under-200-line target is advice, not a hard CLAUDE truncation limit. Instructions are context, not enforcement. Native AGENTS support starts at v2.1.277 with additional older-version caveats; default fallback can ignore AGENTS when qualifying CLAUDE files exist. An explicit `@AGENTS.md` import is supported and deduplicated. We therefore propose a tiny compatibility adapter until the owner's actual versions/settings are established. Import only the shared core, not the extracted history. [Memory documentation](https://code.claude.com/docs/en/memory).

Claude documents `.claude/skills/<name>/SKILL.md`, not `.agents/skills`, for repository skill discovery. Metadata is initially visible and the procedure is loaded when selected; preloading into a subagent is eager. Current compaction retention is bounded, so neither skill bodies nor early conversation details should be treated as permanent storage. Keep Claude-specific invocation controls out of a supposedly portable shared format. [Skill reference](https://code.claude.com/docs/en/skills).

Subagent context is not universal: ordinary non-fork agents do not inherit the full conversation, and built-in Explore/Plan behavior differs from custom agents. Delegate the relevant scope and source references explicitly and verify the actual client behavior. [Subagent reference](https://code.claude.com/docs/en/sub-agents).

### Codex implementation sessions and GitHub review

Codex's documented startup chain runs from project root to current working directory, taking at most one qualifying instruction file per directory. The default aggregate limit is 32 KiB. This does not establish that a root-started session automatically loads every descendant guide when it later edits a file there. Root routing must therefore tell it to inspect applicable nested instructions. GitHub review is separately documented to apply root and more-specific guidance covering changed files; keep review rules near those files. [Instruction discovery](https://learn.chatgpt.com/docs/agent-configuration/agents-md), [GitHub review](https://learn.chatgpt.com/docs/third-party/github).

Codex discovers repository skills in `.agents/skills` along the working-directory-to-root path. Initial metadata has its own budget and may be shortened or omitted if the skill collection is too large. Skills are therefore appropriate for a few repeatable workflows, not one for every paragraph of history. [Skill discovery](https://learn.chatgpt.com/docs/build-skills).

Current documentation recommends read-heavy parallel tasks and cautions about conflicting writes. Main coordination should retain scope/decisions while workers return evidence-backed summaries. [Subagent workflow documentation](https://learn.chatgpt.com/docs/agent-configuration/subagents).

### Implications

- Eagerly splitting the old file into imports would improve editing organization but retain the context problem.
- A nested-files-only design would miss much of Culvert: the root contains most application adapters and many cross-domain paths.
- Sharing a file format does not share skill discovery, permission semantics, or subagent context.
- Do not raise context limits as the primary fix. Larger windows do not resolve conflicting authority or obsolete instructions.
- Keep execution controls and authorization outside prose-only guidance. OpenAI publicly describes bounded execution, managed policies, and telemetry as separate controls. [Operational controls](https://openai.com/index/running-codex-safely/).

## Proposed repository design

The names below are proposed paths, not existing facts. The implementation may adjust naming while preserving the loading and traceability properties.

### Shared entry point

`AGENTS.md` becomes the shared current guide. It should contain the project purpose, source precedence, package-ownership boundary, a few truly universal security/compatibility constraints, task-relevant navigation, verification routing, and concise code-review rules. Use a reviewed working budget around 8 KiB, not a rigid vendor-mandated number. Keep the total automatically discovered chain comfortably below the default Codex budget.

`CLAUDE.md` becomes a small adapter using `@AGENTS.md`. Any additional text must be Claude-specific and small. No eager imports of domain histories or whole workflow manuals.

Do not force every task to read a complete architecture index. Directly route common concerns from the root, and offer the detailed index when the ownership is unclear or the change crosses domains.

### Current routing and historical evidence

Use `docs/agent-context/README.md` as a task/domain index. Each row states matching concerns and paths, current source authorities, the relevant workflow, and specific historical references. Distinguish the core IP/rate limiter from MCP listener fairness and MCP execution admission.

Use `docs/agent-context/history/` for the full extracted source material. Label it as preserved guidance from the pinned baseline, with possible stale claims and links to current authorities/errata. These files are not automatically loaded and are not new architectural authority. Do not give a historical file the reserved basename `CLAUDE.md` or `AGENTS.md`, or place it in an automatically discovered rules directory. The 15 proposed semantic buckets in the preservation ledger are navigation buckets, not 15 newly validated architectures. Large buckets should have a contents list and stable topic anchors; split them further only where retrieval benefits justify it.

Use `docs/agent-context/errata.md` for verified conflicts such as default-policy posture, stale admission locations, and timestamp-clamp prose. Each correction names the exact source claim, revision, implementation/test evidence, and current interpretation. Preserve the original block rather than rewriting historical evidence invisibly.

A small `docs/agent-context/domains/admission.md` can contain the current source-verified admission contract. Other domain guides should be short routing cards pointing to existing ADRs, contracts, and tests until their claims have been similarly checked. Do not dress a historical dump up as a current architecture guide.

### Scoped instructions

Add small scoped `AGENTS.md` files where real directory ownership makes them useful, starting with `internal/admission`. Frontend, MCP, maintenance-agent, and workflow directories may receive short routing/review adapters based on their existing contracts. Add matching small CLAUDE import adapters only where needed for supported Claude versions.

A root task touching `admission.go`, `cluster_ratelimit*`, or snapshot/startup adapters must still be routed to the admission contract. Likewise, a root admin handler must reach the admin-control-plane rules. A directory boundary does not replace a semantic dependency map.

### Repeatable workflows and native skill entry points

Start with two substantive procedures:

1. `docs/agent-context/workflows/verification.md`: choose relevant existing checks from changed behavior and ownership, identify exact toolchain/module/build-tag requirements, run focused checks during iteration, and distinguish focused results from the actual aggregate CI verdict.
2. `docs/agent-context/workflows/review-change.md`: establish the changed contract, examine callers and lifecycle/concurrency/error paths, validate candidate findings independently, report concrete supported scenarios, and avoid repeating formatting/lint results.

Provide thin native skill entry points under both `.agents/skills` and `.claude/skills` that explicitly read the same canonical procedure. Keep metadata narrow and tool-specific controls native. This introduces an extra read, so test that it happens. Generated copies with a drift check are an alternative only if thin wrappers prove unreliable; a generator is unnecessary machinery before that evidence exists.

A skill must not silently enlarge task authority, post a review, push, or publish. Workflow completion and permission to share externally remain separate. If skills are not advertised by a client, root guidance must provide the ordinary-document fallback.

### Review guidance

Keep root review rules concise, consequential, and conditional. Examples of suitable concerns are changes to supported persistence/wire contracts, security-posture boundaries, or instance-owned state. Explain safe exceptions. Do not turn every past incident into a review finding template.

For admission, likely high-value rules are instance isolation and retained state across configuration changes, fresh-versus-stale remote-count semantics, and immutable-view publication without widening exemptions. Validation should include safe counterexamples so the reviewer does not flag correct local-only degradation or intentional root aliases.

A fresh independent review is appropriate for instruction-routing changes because they influence subsequent engineering decisions. Do not mandate several parallel reviewers on every small task. When using workers, assign independent questions and require source paths, observed behavior, uncertainty, and a concrete result; the lead should inspect critical evidence.

## Preservation contract

The supplied research ledger covers every original main byte in 108 ordered blocks: section ranges plus 98 individual architecture-note lines. Each block carries source line range, byte length, SHA-256, title, and proposed destination. A reconstruction of the ordered raw blocks matched the original source byte-for-byte. This validates the research inventory only; candidate destination extraction must be checked separately after implementation.

The implementation must:

1. Reconfirm base SHA and source Git blob before extraction.
2. Preserve every original block exactly once in a canonical historical destination, even if several domain routes reference it.
3. Record any active summary, correction, duplicate relationship, or supersession separately from original text.
4. Reconstruct the baseline from extracted blocks and verify full SHA-256 and Git blob identity.
5. Verify all current routes and anchors resolve and historical files cannot become eager imports accidentally.
6. Leave existing ADRs, risk/debt registers, test evidence, and runtime files unchanged unless a separately reviewed instruction-only correction is needed.
7. Keep the branch-specific #1528 delta out of a main-based rewrite, with an explicit merge/rebase preservation note.

The ledger's destination names are provisional. Move them under the historical namespace rather than treating every inherited paragraph as current guidance. Repository Git history already preserves the original monolith; a second full archived copy is optional and should not be required if lossless extracted blocks plus reconstruction provide stronger, less duplicated evidence.

## Admission validation case

The current package owns IPFilter, RateLimiter, shared prefix matching, immutable views, sliding-window buckets, per-instance distributed counts/stamps, and freshness observation history. Main owns transport/DTOs, CP aggregation, configuration/persistence, protocol adapters, cleanup scheduling, and rendering. Root aliases are permanent composition adapters. Constructors start no goroutines. [Package contract](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/internal/admission/doc.go), [boundary test](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/internal/admission/boundary_test.go).

Required retrieval cases include:

- Configuration/cluster toggles retain counts and diagnostic state; active limiting uses constructors.
- `ApplyRemoteCounts` owns its map; callers must not mutate it. Map publication and atomic receipt stamp are ordered but not a transactional snapshot.
- Missing, future-dated, or age-at-least-window broadcasts contribute zero. Staleness degrades to local enforcement, not indefinite denial or disabled local limiting.
- A successful nil/empty broadcast is fresh and clears old remote counts. Freshness is armed only when both cluster and limiter are enabled.
- `ClusterFreshness` derives status; `ObserveClusterFreshness` advances episode history. Read-only metrics/API do not count episodes.
- `ExportHotDeltas` means absolute qualifying in-window counts and does not reset accounting; its historical name is not a new delta protocol.
- Mutators republish immutable views; bulk paths use `AddAll`/`AddExemptions`; preserve raw-string exemption behavior and differential controls.
- Ring timestamps equal to the cutoff expire; out-of-order samples clamp upward.

Sources: [freshness implementation](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/internal/admission/freshness.go), [ownership tests](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/internal/admission/security_admission_ownership_test.go), [production integration](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/controlplane_admission_ownership_test.go), [migration checks](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/admission_contract_test.go).

Source-verified commands for later execution include:

```sh
go test -race -shuffle=on -count=2 ./internal/admission
go test -tags benchgate -run 'TestBenchGate_' -count=1 -timeout=10m -v . ./internal/admission
```

The tagged gate must name both root and admission. Ten other `TestBenchGate_` entries are in default-tag test files; the name alone does not indicate build-tag exclusion. Within the admission package, only the two rate-window gates require `benchgate`; `TestChaos61_` does not require a chaos tag. Package-only success does not establish root integration or complete CI success. Main's `go.mod` distinguishes language minimum 1.26.6 from toolchain 1.26.8.

The coverage script separately requires global 55% and function-average per-file floors of 70% for root `security.go`, admission `engine.go`, and `freshness.go`. Missing files must fail the check. Do not replace this with a newly invented package coverage threshold. [Coverage implementation](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/.github/scripts/coverage-floor.sh).

MCP auxiliary execution admission is a different contract: lifecycle checks and slot release still apply, while discovery/lifecycle operations do not consume physical-side-effect reservations. Unclassified methods remain metered. Route that work to `internal/mcp/execution`, not to the core rate-limiter guide. [Auxiliary admission tests](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/internal/mcp/execution/auxiliary_admission_test.go).

## Validation plan and honest completion claims

### Static checks required in the PR

- Full original-byte reconstruction, source and destination block hashes, no unmapped or multiply owned source blocks.
- Valid relative links/anchors and referenced files; no cloud workspace paths in repository guidance.
- Automatically loaded byte budget checked transitively, including the Claude adapter; no history import cycle or unscoped history rules.
- Narrow, unique skill descriptions and native discovery paths; wrappers reference the same canonical procedures.
- Diff allowlist proves no runtime implementation change, no altered dependency/toolchain pin, and no weakened CI gate.
- Current summaries checked against code/tests; errata and historical evidence distinguished.
- Independent review of instruction conflicts, missing routes, accidental authority expansion, and branch reconciliation.

These checks can establish structural integrity without either agent CLI. They cannot prove actual discovery, behavioral adherence, or quality improvement.

### Actual-client loading matrix

Record product/client, version, model, settings, working directory, baseline SHA, candidate SHA, and relevant global/project overrides for each trial. Do not claim all clients work because one session read the right file.

1. Codex started at repository root: shared root loaded; admission task explicitly reads nested/domain guidance; a trivial edit avoids unrelated histories.
2. Codex started inside `internal/admission`: root-to-cwd chain contains the scoped file and stays within the actual configured budget.
3. Claude started at root: adapter loads the shared core once, histories remain unloaded until relevant access, skills appear in the supported directory.
4. Claude accessing a nested subsystem: scoped guidance actually enters context with that client's mechanism.
5. Explicit and implicit skill invocation: wrapper loads canonical procedure; adjacent unrelated prompts do not trigger it.
6. GitHub Codex Review: root and scoped rules guide a representative diff, including one valid exception. This is a separate product test; a CLI review is not a substitute.
7. Resumed/compacted task: the agent retrieves unresolved state and relevant invariants from durable artifacts without depending on the entire old conversation.

On this research computer, `codex --version` returned 0.159.2; no `claude` executable was found. No authenticated Codex model run, Claude run, hosted-review trial, or compaction experiment was performed. Unknown authentication/model availability must not be reported as a product failure. If a client cannot be exercised, record that row as not run and leave the PR's behavioral claims bounded.

### Behavioral comparison

Use identical prompts and pinned code for baseline/candidate instruction sets, fresh sessions, the same model/reasoning settings, and isolated disposable state. Include repeated runs for high-variance tasks. Start with a small set covering a trivial edit, package-local task, root adapter, cross-cutting change, historical regression, false-positive review control, and resumed task. Derive expected answers from the actual contracts, not from the new instructions alone.

Useful admission prompts ask whether remote broadcasts may remain effective indefinitely, whether toggling cluster mode may reset counts, whether a nil broadcast is stale, whether an exemption can be canonicalized, which test command exercises both tagged packages, and whether an MCP discovery method belongs to the core limiter. Include safe cases that should produce no review finding.

Measure correct invariant retrieval/application, valid findings versus noise, missed constraints, human corrections, read volume, command/tool count, elapsed time, input/output/cache tokens where exposed, and compaction events. Separate automatic startup context from on-demand reads. A final answer merely listing an instruction path is weak evidence; use supported trace/loading evidence and observable task decisions. Keep captured logs free of secrets.

OpenAI's skill-evaluation guidance explicitly tests outcomes, process, efficiency, explicit/implicit invocation, and negative controls with captured runs. Its older sample directory names should not override current discovery documentation. [Skill evaluation workflow](https://developers.openai.com/blog/eval-skills). Anthropic's evaluation guidance likewise emphasizes clear tasks, verifiable outcomes, and isolated trials. [Agent evaluation guidance](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents).

### Context and cost interpretation

An 8 KiB core would be approximately 98.2% smaller in source bytes than the present 464,534-byte guide, before adapter/scoped files and on-demand reading. This is a proposed structural budget, not an observed 98.2% token reduction or quality gain. A tokenizer was not available in this research environment, and character/byte division would be only an estimate; no exact token count is asserted.

Token usage is not equivalent to new dollar expenditure on the owner's subscriptions. Additional parallel agents can increase token use while reducing elapsed time; retrieval can reduce irrelevant context while adding reads. Report these separately. Do not extrapolate vendor productivity statistics, internal review recall, or research-agent cost ratios into a Culvert ROI claim.

Acceptance should prioritize no lost critical knowledge, correct routing and decisions, and no increase in invalid review findings. Smaller startup context and reduced human steering are secondary measured benefits. If the only verified result is preservation and discoverability structure, say so; do not label the architecture behaviorally proven.

## Maintenance after migration

New durable invariants belong beside their owner and executable contract. Repeated procedures belong in the shared workflow; incident chronology and rejected alternatives belong in history. Update the root only when the route or genuinely universal rule changes. Review instruction changes like code, and retire redundant scaffolding when tests show it no longer helps.

The expected return is a more reliable way for the existing agents and reviewer to find Culvert's hard-won knowledge. Achieving that requires both preservation and retrieval validation; shortening a file alone is not completion.
