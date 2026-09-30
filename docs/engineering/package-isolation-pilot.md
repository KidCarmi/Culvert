# Shutdown package-isolation pilot evidence

Baseline: `1f7f42c6937847c26f29387dcaae6685e356a9b0`, Go 1.26.8,
Linux amd64, 4-vCPU cgroup, 32 GiB RAM; GOMAXPROCS=4, Go build parallelism 4.
Design and exact migration: [roadmap](../../roadmap/PACKAGE-ISOLATION.md),
[ADR-0037](../adr/0037-shutdown-registry-package-isolation.md).

## Validation

- Package race + shuffle: `go test -race -count=10 -shuffle=20260930 ./internal/shutdown` passed (13.020 s).
- Production shutdown integration: selected registry/wiring, CHAOS-56, audit-close
  and cluster-flush tests passed; final `-race -count=2 -shuffle=20260930` root execution was 44.599 s.
- Rootshard source/binary inventory agreement: 6,742 root entries; 17 moved to
  the new package, 2 added to root, no lost entries. New package: 24 entries.
  Whole-module source inventory: 9,964 → 9,973 runnable entries, no missing
  name/multiplicity; all 309 benchmarks retained (152 in root).
- Extracted engine statement coverage is 97.8% (90/92 statements) from its
  completed local race run; this does not validate the incomplete root profile.
- The existing per-file coverage table names no moved shutdown source. No floor
  or workflow edits are needed; global coverage still includes the new package.

## Baseline limitations being compared

The first full baseline root run used the machine's default umask 0077, warm
compiler cache, no race/coverage, no result cache, and completed in 357.1 s:
6,682 top-level entries passed, 16 failed, 59 skipped. This is a diagnostic
run, **not a clean performance baseline**. Four failure families were identified:

- File-mode fixtures expect standard umask 0022 (backup/restore and KEK-mode
  checks). Subsequent validation uses that mask, scoped to the test process.
- `getent ahostsv4 example.com` fails in this cloud machine; IdP URL validation
  correctly refuses unresolved external fixtures. No security guard is bypassed.
- The real-Docker installer fixture calls `sudo docker`; Docker/Compose work,
  but `sudo` is absent. The installer conservatively answers NOTFRESH.
- An upstream portability audit assertion fails during the full root run;
  the test passed in isolation (0.266 s), so full-run failure is not a shutdown regression. Matched results follow below.

The broad candidate `go test -race -count=1 -timeout=20m -json
-coverprofile=... ./...` passed 113 packages but root timed out at 1,201.645 s in
the existing MCP-heavy suite. It reproduced the DNS and installer failures. It
also caught the new ADR initially colliding with support RFC 0036; the decision
was renumbered to **0037**, and `TestADRNumberingNoCollisions` passed after the
correction. That broad profile is **incomplete**, not proof of global coverage.
The existing sharded CI verdict is the authority for full race completeness.

Local vet, formatting, static amd64 and arm64 builds pass. The unchanged
`golangci-lint v2.5.0 --timeout=5m --new-from-rev origin/main` first reported zero
issues but timed out under concurrent validation; its cached retry passed.
`go mod tidy -diff` was blocked locally by the existing Google API module's
forbidden proxy download (canonical-source retry also forbidden); GitHub's
hygiene job passed the same check. No module files or security guards changed.

## Existing CI evidence (not an equivalent candidate pair)

The PR that produced baseline main is #1490, head
`349ecf6410994731edb1a98010662a060cd77b92`:

- [Fast 36264359485](https://github.com/KidCarmi/Culvert/actions/runs/36264359485):
  attempt 1 success, 765 s from first job start to last completion, 3,537 summed
  job runner-seconds. Root compile 118 s; slowest root shard 486 s; non-root lane
  681 s. The non-root lane, not this pilot's ~1 s of movable tests, bounds Fast.
- [Deep 36264359560](https://github.com/KidCarmi/Culvert/actions/runs/36264359560):
  attempt 2 success; successful determinism job 781 s, first failed attempt 661 s;
  1,734 runner-seconds across all Deep attempts. Its 7,880 s job-span
  includes rerun delay; it must not be called execution cost or compared with
  a single-attempt candidate as a speedup.

Across the eight observed workflows at that baseline PR head, runner time was
5,592 s (5,271 s in Fast + Deep). From workflow creation until both required
gates completed was 7,883 s, including the Deep rerun delay. Fast's creation-to-
completion time was 805 s; its 765 s job span excludes initial queue delay.
These are observed durations, not billable-minute estimates. CI cache hit/miss
state is unverified: job metadata is accessible, but the log-storage redirect
is forbidden by this environment's network policy.

CI-REDESIGN §18.5/§19.1 gives broader historical evidence that Deep determinism
often bounds both-gates completion. Its Go/toolchain, source revision, queue and
attempt cohorts differ; preserve that qualification when choosing follow-ups.

## Matched local measurements

Both checkouts used the toolchain/limits above, umask 0022 and TEST_SEED=20260421.
Runs were serialized after broad validation and lint exited. Compiler/module
caches were warm; **test-result caching was disabled** with `-count=1` (or direct
binary execution). These are not cold-compilation results. No cold-cache or
edit/recompile improvement is claimed.

| Measurement | Baseline | Candidate | Interpretation |
|---|---:|---:|---|
| Focused command, identical 17 entries, median of 3 | 4.043 s (3.690–4.816) | 1.251 s (1.223–1.271) | 69% less wall time for this warm-build local command |
| Warm root test build, 2 repeats | 0.774 / 0.830 s | 0.811 / 0.958 s | No demonstrated build improvement; exclude the first output-building run from each pair |
| Prebuilt execution, same 17 entries, median of 3 | 1.110 s | 1.013 s | Approximately the same ~1 s engine work; root process setup differs |
| All 24 extracted-package entries, prebuilt, one run | n/a | 1.171 s | Includes the seven new contracts |
| Complete prebuilt root execution, one matched run | 337.886 s | 343.201 s | Failed diagnostic runs; no speedup demonstrated |

Reproduce the focused command by using the unchanged nine `TestShutdownRegistry_*`
and eight moved `TestChaos56_*` names in the migration table's three new files
as one anchored `-run` expression: `go test -count=1 -run "$pattern" .` in the
baseline and the same expression over `./internal/shutdown` in the candidate.
Build separately with `go test -c -o /tmp/root.test .`; execute from the matching
checkout using `go tool test2json -t -p github.com/KidCarmi/Culvert /tmp/root.test
-test.v=test2json -test.timeout=20m -test.count=1`. The package binary must run
from `internal/shutdown` because its boundary test inspects package sources.

The root pair ran every inventoried entry: baseline 6,687 pass / 11 fail / 59
skip; candidate 6,671 pass / 12 fail / 59 skip. All 11 shared failures are the
IdP external-DNS and installer sudo families above. The additional candidate
failure is `TestUpstreamV2DC_CR1_ChangedAuthorityImportCannotClearRequiresReplacement`
(the same audit-success assertion that failed in the initial baseline run).
It passed in isolation in both trees (0.266 s baseline / 0.100 s candidate).
These are **not clean whole-suite performance
samples**, and a single ~5 s difference is not a causal extraction effect.
No shutdown test failed. Local raw logs and inventories remain in
`/workspace/isolation-evidence` for this session.

## Live implementation CI and limits

Validated implementation commit: `5d7df00408bf0890b8e773f627af05041b336b06`.
[PR #1522](https://github.com/KidCarmi/Culvert/pull/1522) stays open, unmerged.
The final evidence update changes documentation only; its Go source/tests are
identical to this validated implementation. Report any new tip's CI status
separately rather than treating a prior run as a check on a different SHA.

- [Fast 36734863959](https://github.com/KidCarmi/Culvert/actions/runs/36734863959):
  **success**, including four root race shards, every non-root package, the
  independent inventory/coverage completeness verdict, all coverage floors,
  allocation benchgates, lint, security, hygiene and privileged regression.
- [Deep 36734864425](https://github.com/KidCarmi/Culvert/actions/runs/36734864425):
  **success**, including the complete `-count=2 -shuffle` suite, staticcheck,
  image build and compose validation. Determinism job: 728 s.
- No CI selector, source-contract guarantee, coverage threshold, release
  protection, module dependency or entry point was weakened or changed.

| CI observation | Baseline PR head | Validated candidate head |
|---|---:|---:|
| Fast job span / creation-to-completion | 765 / 805 s | 791 / 953 s |
| Fast runner-seconds | 3,537 | 3,876 |
| Non-root lane | 681 s | 692 s |
| Slowest root shard | 486 s | 550 s |
| Deep successful determinism job | 781 s | 728 s |
| Deep all-attempt job span / creation-to-completion | 7,880 / 7,883 s | 753 / 792 s |
| Deep runner-seconds, all attempts | 1,734 | 998 |
| Both required gates complete, from workflow creation | 7,883 s | 953 s |
| All observed workflows' runner-seconds at that head | 5,592 (8 workflows) | 5,267 (8 workflows) |

“Both gates complete” is a CI-readiness measure, not human review/merge time.
Each runner total sums non-skipped jobs, including failed attempts, from all
pages of the jobs API (`filter=all`); overlapping jobs are intentionally summed.
It is scoped to the named head, not all development pushes. The first pilot
head was cancelled for the ADR correction; that work and documentation reruns
are excluded from this head comparison. Cache state is unverified in CI.

These CI cohorts are **not a controlled performance pair**: baseline Deep was
rerun after a long delay; candidate adds production-change image/compose and
CodeQL work; queue/runner conditions differ. Candidate Fast is slightly slower,
and its slowest root shard completes ~10 s after the non-root lane. The lower
both-gates elapsed value and total runner value do **not** establish CI savings.
The demonstrated improvement is the focused local command and independent state
ownership. Cold compilation, long-term flake rate and total-CI improvement remain
unmeasured. Re-measure a matched cohort after the admission ownership/extraction
follow-ups; do not optimize by skipping tests or weakening crypto fixtures.

Remaining risks: context-ignoring shutdown hooks can still outlive abandonment
(the preserved contract); the upstream audit test has existing full-suite order/
timing sensitivity; cloud DNS/sudo limitations prevent a clean local root run.
Main and all 30 other open PR heads were re-fetched/rechecked before handoff:
main remains the baseline SHA, no other heads changed, and the documented #1494/
#1504/#1470 overlap assessment still holds.
