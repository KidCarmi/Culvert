# Admission state ownership evidence

Baseline: `60f127389d7a1004a6af7dd4dd352b908b8ad313`, fresh origin/main including
merged #1522. Design: [ADR-0038](../adr/0038-instance-owned-admission-state.md).
This is package-isolation step 2, a state-ownership prerequisite. No package,
workflow, coverage floor, persistence schema or entry point moves in this PR.

## Test ownership

| Existing tests | Before | After |
|---|---|---|
| `distributed_rl_test.go` cluster/standalone admission | Global count replacement / enable reset | Their constructed limiter owns both; same names and assertions |
| CHAOS-61 admission, stamp/freshness, episodes, concurrent publish | Application limiter swap plus count/flag/latch resets | Local owners, no reset fixture; timestamp helper now test-only |
| Three CHAOS-61 metrics cases | Global resets | Bind a new owner to `rl` and restore the old owner intact |
| IPFilter mutator publication and negative controls | Global hook + sync.Map/Once registry | Receiver-owned hook and recorder; attribution/new-view assertions unchanged |
| Startup, config/rollback, HTTP/SOCKS5, exemption/window suites | Root composition / engine tests | Remain root; no test relocation or selector change |

New tests cover concurrent count/enable/history isolation, supported construction,
retained counts/local history across enable/config changes, nil broadcast and
exemption behavior, independent publication observations, and the real CP handler
→ gossip → snapshot-configured limiter → HTTP/SOCKS5 → metrics/API path. The
transport alone is stubbed; enrolled certificate identity verification still runs.
Gossip cancellation is joined and disables only its owner. Existing fresh, stale,
future/clock-rollback and publication-evasion controls retain their assertions.

## Validation and measurements

Commands
use Go 1.26.8, Linux amd64, the same 4-vCPU cloud machine, GOMAXPROCS=4,
`-p=4`, umask 0022. Result caching is disabled (`-count=1`); compiler cache state
is reported separately. This PR claims independent operation and testing, not CI
acceleration. The subsequent package extraction must measure compilation and CI
separately; no tests join the non-root lane until that extraction.

- Focused engine, CHAOS-61, new ownership/wiring, snapshot/rollback and startup
  suite: `-race -count=5 -shuffle=20260930`, passed (4.564 s package execution).
  The same existing test names and all their assertions remain discoverable.
- Local `go mod tidy -diff` remains blocked by the existing Google API module
  download redirect (network policy returns Forbidden); dependencies are unchanged.
  Required CI hygiene must validate tidiness on the final implementation.

- Whole-module source inventory: 9,973 → 9,977 runnable entries; root 6,742 →
  6,746. No name or multiplicity lost. All 309 existing benchmarks remain;
  one distributed-admission benchmark is added. Every non-root inventory is
  unchanged. Coverage discovery/floors and the source-contract negative controls
  are unchanged (`security.go` 70%, `controlplane_client.go` 55%, global 55%).
- Formatting/diff checks, `go vet ./...`, static amd64/arm64 builds and the
  complete tagged allocation benchgate passed (163.057 s benchgate execution).

- Final production-wiring fixture: another five race/shuffle repeats passed
  after its helper split (1.850 s). `golangci-lint v2.5.0 --new-from-rev
  origin/main` passed with zero issues. Locally only VCS stamping was disabled
  for lint (`-buildvcs=false`): the sandbox's masked parent `.git` confused Go
  discovery. CI flags remain unchanged.
- `cmd/rootshard inventory -check-list` cross-checks all 6,746 root runnable
  entries and 153 benchmarks against the compiled candidate binary. Non-root
  discovery remains exactly unchanged; this PR moves state, not tests/packages.

## Matched local result

Three serialized, alternating baseline/candidate pairs after warmup; warm compiler
cache, no result cache. The identical **73 existing tests** are selected by taking
baseline names matching `Test(RateLimit|AllowClusterAware|AllowAuto|ClusterCount|
IPFilter|RLExempt|Chaos61|LoadConnAndRateLimit|RateLimitCleanup)` and using the same
anchored name list in both `go test -count=1 -run` commands. New ownership cases
are validated separately, not mixed into the comparison.

| Wall time, median (range), seconds | Baseline | Candidate |
|---|---:|---:|
| Focused `go test` command | 2.120 (2.113–2.153) | 2.092 (2.076–2.298) |
| Warm root `go test -c` build | 0.507 (0.488–0.529) | 0.498 (0.481–0.503) |
| Prebuilt root binary, same 73 tests | 0.313 (0.295–0.321) | 0.319 (0.305–0.325) |

No material focused-command improvement is demonstrated. Cold compilation,
whole-root execution and CI acceleration are unmeasured in this ownership PR.
There is no extracted-package execution yet. Required Fast/Deep results on the
exact PR head are reported in the PR validation record; their durations are not
inferred from these local samples.

Benchmarks use `-run '^$' -benchtime=300ms -count=1`, three alternating pairs,
GOMAXPROCS=4. The new `BenchmarkDistributedAdmission` is run against original
baseline production code using only a temporary setup adaptation:
`r.SetClusterEnabled` → `clusterRateLimitEnabled.Store`, and
`r.remoteCounts.applyAtForTest` → `clusterCounts.applyAtForTest`. The timed
workload/verdicts are identical; no alternate admission implementation. Buckets
are primed at cap before timing. Existing parallel filter and limiter benchmarks
are unchanged.

| ns/op, median | Baseline | Candidate |
|---|---:|---:|
| AllowAuto standalone | 87.78 | 91.73 |
| AllowAuto fresh remote | 101.7 | 112.4 |
| AllowAuto stale remote | 102.1 | 102.3 |
| AllowAuto future remote | 92.82 | 95.27 |
| AllowAuto limiter disabled | 3.289 | 3.533 |
| AllowAuto exempt | 15.99 | 14.32 |
| IP filter disabled, parallel | 0.685 | 0.759 |
| IP filter block miss, parallel | 20.10 | 19.94 |
| Local limiter at cap 600, parallel | 44.07 | 66.59 |
| Local limiter at cap 6000, parallel | 40.94 | 41.57 |

**Every sample is 0 B/op and 0 allocs/op.** Latency is variable; do not equate
allocation equivalence with a throughput guarantee. The slower cap-600 sample
prompted six additional alternating prebuilt-binary pairs at 500 ms, CPU=1,4:

| Cap 600 follow-up ns/op, median (range) | Baseline | Candidate |
|---|---:|---:|
| One core | 94.19 (91.84–103.3) | 95.75 (90.21–99.49) |
| Four cores | 51.19 (42.69–73.37) | 45.71 (40.99–55.34) |

The direction reverses at four cores; there is no consistent parallel slowdown
in this follow-up. `Allow` itself is unchanged (also checked by normalized
instruction comparison). No latency improvement or exact equivalence claim is
made from these short samples. Longer controlled profiling is appropriate if a
strict latency budget is introduced. Raw logs, inventories and measurement
scripts are in `/workspace/admission-evidence` for this session.

## Handoff boundaries

Main was re-fetched and all 30 open PR heads rechecked: unchanged at the recorded
baseline. ADR-0038 identifies overlapping files and the sections deliberately
left alone. Published maps remain caller-transferred and immutable; one gossip
loop owns each production limiter's enablement. Existing zero-value active-use
and misleading export-comment limitations are recorded separately in the ADR.
Next PR is exactly the `internal/admission` extraction in roadmap step 3, including
engine tests/benchgates and the coverage selector migration, with real application
wiring, transport, persistence, logging and lifecycle remaining in main.
