# Policy pure-core feasibility: baseline and evidence

2026-10-01. Decision: **PREREQUISITE FIRST**, as specified in
[ADR-0040](../adr/0040-policy-evaluation-ownership-prerequisite.md).
This PR changes documentation only. No prototype, production, test, module or CI
configuration changes are included.

## Baseline and overlap

Freshly fetched main is `3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af`;
#1525's merge is that commit. #1524 was merged into #1525 before it landed on main.
The assessment uses isolated branch `codex/policy-core-feasibility`, not the old
admission worktree. The main tree is `b4158d816f7a9bf5fc51a467578c8dc4ff5e4201`,
identical to final #1525 head `6a83a2bfbbf52e78354b0cfbe2f8ee1406b8bd3d`.
Read CLAUDE.md, the package-isolation roadmap, ADR-0002's closure/rejection,
ADR-0025/0026, current policy/auth/CDR, feed/geo adapters and learning fences.
No AGENTS.md applies in this worktree or its ancestors.

REST inventories of all 30 open PRs were checked, including ADR numbering in
`docs/adr` and `docs/support/rfc`; none claims 0040 or modifies this roadmap.
Important overlaps:

| PR / inspected head | What is proposed, separate from current main | Coordination |
|---|---|---|
| #1470 / `db819dbfe95c2938dc17939a3979be15f7a5582c` | Five-file diff; `policy.go` adds `verified` and `sameRuleSlice`, marks publication in `sortLocked`, replaces repeated nil-counter scan with identity memo; two new test files | Still open. No merge/cherry-pick/copied implementation. Resolve its disposition before ownership edits; preserve its accepted algorithm. Its reported performance is not measured main evidence |
| #1505 / `92153337a3bd10665143058707701d1b5ea921bf` | urlcat membership-lock sharding and `policy_category_bench_test.go` | Compatible conceptual boundary, overlapping performance baseline/fixture. Re-fetch and remeasure if it lands; do not copy its optimization |
| #1485 / `2f7bb2cfad7f40992d38bfc246ae194fd633a5fe` | IdP availability and access-policy startup integration | Retain validation/startup ownership in main; recheck integration tests after it lands |
| Other open PRs | Dependency updates, MCP/CDR/telemetry work and several CLAUDE.md edits | No direct canonical access-scan change identified; this PR avoids CLAUDE.md and their implementation files |

This is code/PR-state coordination, not a claim that another author approved the
sequence. No message was posted to another PR. Recheck heads and open files before
implementation; an open PR's body is evidence of intent, not shipped behavior.

## Boundary evidence

Source anchors on the recorded baseline:

| Concern | Evidence |
|---|---|
| Actual canonical callers | `policy.go:1435,1510`; `ui_policy.go:2768`; `authpolicy.go:232`; `proxy.go:1570`. Production search finds two direct core callers. SOCKS5's `handleSOCKS5` does not call the access scan |
| Rule publication / ownership | `policy.go:1215,1258,1322,1352`; all nested copies, cache rebuilds, stable atomic counter cells and detached match values remain load-bearing |
| Live lookup schedule | `policy_hostcat.go:76,109,136,162`; `categorygroup.go:46`; `policy.go:1958`; `geoip.go:591` |
| Shared helper consumers | `authpolicy.go:531,614,810`; `cdrpolicy.go:480` reuses predicates but has its own scan and clock behavior |
| Load/activation safety | `policy.go:353,670`; `authpolicy.go:1152`, `validateAuthRule`, `validateSSOProviderRefsLive`; draft/mutation and learning-accept files own durable activation |
| Generations | `policy_learning_admin.go:234,240,301`; `policy_learning_observe.go:85,111,145,169,193`; content identity is distinct from monotonic change witnessing |

Findings to keep explicit: “no logging/store locks” in the core's comment describes
its immediate loop, not transitive effects. Geo/category/cache adapters can mutate,
lock or do DB work. UT1 and geo are not fully generation-pinned. Comments in older
auth-policy sections still say “not wired”; actual functions and callers take
precedence. #1470's statement that every protocol uses Evaluate does not establish
a SOCKS5 call. These observations do not authorize a new enforcement policy or a
stronger snapshot guarantee.

## Exact test ownership plan

[Inventory](policy-core-test-inventory.tsv): **327 entries in 47 root test files**,
317 default-tag entries, nine `benchgate`, one `uie2e`. Entry means top-level
test, fuzz target or benchmark; subtests remain attached to their parent.
The selection includes all entries in the main matcher/publication/counter/tester
files, direct matcher/core users in mixed files, and named related governance,
learning-fence, transaction and CDR integration suites. It is a bounded migration
inventory, not a claim to enumerate every transitive root consumer or replace
`go test ./...`. Other root tests remain root and remain discovered unchanged.

Every entry stays in main in the ownership prerequisite. **31 matching/scratch/
trace entries are conditional relocation candidates** for the later package;
the TSV identifies each name, existing file, tag and reason. Do not equate these
31 with the 38-test measured development command, which deliberately includes
store publication and tester integrations. No tests disappear in this PR.

- `policy_test.go` and `policy_misc_test.go` are mixed: schedule/IP/category
  predicates could move, but file profiles, store operations, HTTP/admin/login/CA
  tests stay main. FQDN wrappers already delegate to `internal/hostutil`; do not
  re-extract that implementation.
- `policy_srcprefix_test.go` mixes pure differentials with publication cache
  invalidation, draft-content comparison and concurrent replacement; those
  production assertions stay main. `policy_precompute_test.go` mostly pins real
  store publication, not just compilation. Do not move it wholesale.
- Only `TestCovIsoPolicy_EvalAccessRulesTracesSourceMismatch` from
  `coverage_isolation_policy_test.go` is a core candidate. The remaining mixed
  file is untouched. `FuzzMatchDest` may move with the predicate; retain its corpus
  and fuzz entry, not just default seed execution.
- Real `PolicyStore.Evaluate` benchmarks remain main: NoMatch, MatchLast,
  CIDRRules, ScheduledRules, CategoryGroupRules, CategoryRules,
  CategoryGroupRulesSynthetic/Parallel and PerfQual_Evaluate. They include
  publication/accounting/copy costs and must not be silently replaced by a
  cheaper core-only workload. `BenchmarkScrubForwardedHeaders` is unrelated and
  stays main. Add isolated Scan benchmarks only when there is a real package.
- All nine inventoried tagged gates stay on the actual production wrappers.
  Keep their bounds (including current allowance of four allocations in the
  three Evaluate allocation gates); the shared AuthResolve and AuthScheduleTZ gates also remain root. Do not “preserve zero allocations” by
  forgetting successful-match result copies. Root source-CIDR sentinel controls
  must still prove which representation the production path uses.
- Keep tester running/draft selection, Stage-1 auth gates, CDR integration,
  unforgeable identity/default-deny, `PolicyMatch` defensive copies, retained/reset
  counters, startup persistence, real snapshot/rollback/CP→DP and HTTP dispatch
  tests in main. Learning acceptance/durability and ABA/window tests remain at
  their current main/`internal/policylearn` owners.

#1470-only inventory (not present or counted on baseline):
`policy_snapshot_memo_test.go` has seven default tests
(`TestBenchGate_SnapshotControl_StillReturnsTheWholeRulebase`,
`TestEvaluationSnapshot_DifferentialAgainstLegacy`,
`TestEvaluationSnapshot_EveryMutationIsVisibleImmediately`,
`TestEvaluationSnapshot_DirectInstallIsStillNormalized`,
`TestEvaluationSnapshot_MemoDoesNotSurviveItsSlice`, `TestSameRuleSlice`,
`TestEvaluationSnapshot_ConcurrentReadersAndMutators`) and four default benchmarks
(`BenchmarkPolicySnapshot_Legacy`, `BenchmarkPolicySnapshot_Current`,
`BenchmarkPolicySnapshot_CurrentParallel`, `BenchmarkPolicyEvaluate_FirstMatch`).
`policy_snapshot_benchgate_test.go` adds the tagged
`TestBenchGate_EvaluationSnapshotIsFlatInRuleCount`. All remain main if merged.
The control's BenchGate prefix does **not** imply it is build-tagged.

## Coverage, source contracts and CI migration requirements

Nothing changes now. `.github/scripts/coverage-floor.sh` enforces **policy.go 60%**,
global **55%**, and the existing other security floors, including admission's 70%
engine/freshness floors. There is no separate policy_hostcat.go floor today.
Future extraction must retain 60% on residual `policy.go` and apply at least 60%
to the relocated implementation files, plus explicit coverage for a new root
lookup adapter. Measure exact implementation blocks, not a thin shim or a package
average diluted by unrelated code. Keep the global universe unchanged except for
relocated paths and prove missing/uncovered implementation is rejected.

Required source/selector work for a future extraction:

| Contract | Required treatment |
|---|---|
| `qa_gate_coverage_test.go`: FloorTableUnchanged and floor-script negative controls; `admission_contract_test.go`: CoverageRejectsOmittedEngine | Update the exact floor/profile inventory without removing existing floors; add omission and uncovered-core controls |
| `policylearn_wall_test.go`: ImportSurface, NoPolicyMutationTokens, RootTranslatorOwnership, NoWallClock, RequestPathOneWayTransport | Preserve advisory-only direction; include relocated core files in the no-learning path scan, not just residual policy.go |
| `TestScheduleTests_NoWallClockFullDayWindowEndsAt2359` | Root-only glob must cover moved schedule tests and their new field names; injected bad full-day window must still fail |
| `TestBenchGate_PolicySourceCIDRUsesPrefix` | Preserve negative controls across the production path; keep package-private cache mutation beside its owner if the core later needs an additional white-box control |
| Fast/QA/weekly benchgate commands | Currently `. ./internal/admission`. Retain both; explicitly add accesspolicy if tagged engine gates appear. Prove omitted package cannot pass |
| Deep, CodeQL, edge-case-lab path classifiers | `internal/*` already enables Deep security; verify CodeQL and edge-case paths explicitly for the new directory rather than assuming a policy.go-only glob covers it |
| Shared `qa-race-shards.yml` / `cmd/rootshard` | `go list ./...` non-root discovery and independent coverage universe include a new package automatically; verify inventory multiset, build tags and merged coverage blocks against the baseline |

The UI route metadata/source contracts stay root because handlers stay there.
The same-named `internal/mcp/runtime/policy.go` AST contracts concern MCP, not this
root file. A source search must resolve actual paths before editing selectors.

## Measurements on current main

[Machine-readable samples and exact selector](policy-core-baseline.json).
Go **1.26.8 linux/amd64**, AMD EPYC 9V74, five visible logical CPUs,
`GOMAXPROCS=4`, `GOFLAGS='-mod=readonly -p=4'`. Warm module cache throughout;
compiler cache warm except the explicitly new empty `GOCACHE` for the cold build.
No competing measurement job was launched. Shared-host noise is uncontrolled.
Test results are never cached (`-count=1`, race `-count=3`).

`focused-38` is the exact anchored selector recorded in JSON and the TSV's last
column. It covers host-category scratch, precompute, source-prefix differentials,
schedules, publication/counters and tester running/draft selection. Reproduce:

```sh
POLICY_SELECTOR=$(python3 -c 'import json; print(json.load(open("docs/engineering/policy-core-baseline.json"))["focused_selector"])')
go test -c -o /tmp/policy-root.test .
go test -count=1 -run "$POLICY_SELECTOR" .
/tmp/policy-root.test -test.count=1 -test.run "$POLICY_SELECTOR"
go test -race -count=3 -shuffle=on -timeout=10m -run "$POLICY_SELECTOR" .
# For a genuinely cold compiler build, set GOCACHE to a newly created empty dir.
```

| Observation | Samples / wall seconds | Interpretation |
|---|---|---|
| First root build in fresh worktree | 30.923 | Mixed existing compiler cache, **not cold** |
| Focused go test, warm compiler cache | 2.514 / 2.319 / 2.049; median **2.319** | Includes Go driver, build checks, vet/link as needed and execution |
| Root test build, warm compiler cache | 0.540 / 0.524 / 0.466; median **0.524** | `go test -c`, no test execution |
| Focused prebuilt root execution | 0.299 / 0.283 / 0.249; median **0.283** | Same 38 tests; not full root execution |
| Cold compiler-cache root build | **58.273** (one run) | Dependencies plus entire root test binary, warm downloaded modules |
| Race/shuffled focused command | **50.793** wall; package execution 6.436 | Three passing repetitions; includes fresh worktree race build |
| Seven Stage-2/category tagged gates | package execution **27.051**, all pass | Existing commands/assertions unchanged |
| Shared AuthResolve/AuthScheduleTZ tagged gates | Both pass | Same shared-helper allocation bounds |

Prebuilt benchmark command:
`root.test -test.run='^$' -test.bench='^BenchmarkPolicyEvaluate_(NoMatch|MatchLast|CIDRRules|ScheduledRules)$' -test.benchtime=100ms -test.count=3 -test.benchmem`.
Representative medians; complete samples in JSON:

| Workload | ns/op | B/op / allocs/op |
|---|---:|---:|
| NoMatch, 10 / 1,000 / 10,000 rules | 155.6 / 13,283 / 155,592 | 0 / 0 |
| MatchLast, 11 / 1,001 rules | 411.5 / 13,050 | 641 / 2 |
| CIDR full scan, 1,000 rules | 18,412 | 0 / 0 |
| Scheduled full scan, 1,000 rules | 48,744 | 0 / 0 |

These include current main's O(N) publication check. #1470's numbers describe a
different head/hardware; do not attribute its prospective savings to isolation.
No extracted-package timing exists; the prerequisite creates no package. The
measured root overhead supports investigating local iteration benefits, but the
31 potential moves retain substantial integration work in root. Full-root
execution, edit/rebuild latency, isolated-core latency and CI savings from this
candidate remain **unmeasured**. No speedup is claimed by subtracting prebuilt
execution from go-test wall time.

## Existing CI evidence and this documentation PR

Reuse the same-tree #1525 runs, attempt 1, both successful:
[Fast 36839090899](https://github.com/KidCarmi/Culvert/actions/runs/36839090899)
and [Deep 36839090820](https://github.com/KidCarmi/Culvert/actions/runs/36839090820).
Unchanged `cmd/cireport.Analyze` was applied offline to attempt/job REST metadata:

| Metric | Observation |
|---|---:|
| Fast to approval | 854 s |
| Deep to approval | 828 s |
| Both approvals from their common run start | 854 s |
| Fast / Deep runner time | 67.4 / 19.1 runner-minutes |
| Combined Fast + Deep runner time | 86.5 runner-minutes |

Runner time sums overlapping jobs; it is not elapsed time or billing. These totals
exclude other workflows, author/review time and overall PR time-to-merge. Raw logs
and artifacts are unavailable through the environment proxy, so cache/image
cohorts and per-test CI critical-path contribution are unobserved. This is one
baseline, not a controlled improvement comparison or a stable trend.

For this design-only PR, run ADR numbering, local relative-link and inventory
checks plus `git diff --check`; verify only documentation paths changed. The
existing Fast/Deep documentation classifiers should skip heavy code jobs and
still produce their required approval aggregates. Those skips are legitimate
scope classification, not new coverage/race evidence. Record final-head checks
in the PR description; do not change workflow configuration to force a green
verdict or infer policy performance from a short documentation run.
