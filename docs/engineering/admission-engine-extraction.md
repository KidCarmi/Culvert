# Admission engine extraction evidence

Baseline: `31a7562fc9ae807523664b028401e5b5fc35065e` (merged #1522/#1523).
Design: [ADR-0039](../adr/0039-admission-engine-package.md), extending ADR-0038.
Candidate: the implementation PR head; its exact SHA, final CI runs and gate
measurements are recorded in the PR body, so updating remote evidence does not
invalidate the tested commit.

## Boundary and production paths

`internal/admission` contains the single IPFilter/RateLimiter implementation,
shared prefix matcher, remote count store and derived freshness/transition state.
It imports only net, net/netip, sort, sync, sync/atomic and time. Constructors,
existing filter/limiter methods, PrefixFromIPNet, HotCount/HotThresholdPercent and
the freshness status/observation are the API. Mutable fields and publication
hooks stay private. No engine-owned persistence, init function or goroutine.

Main's `admission.go` is aliases, constructors and application handles. Policy's
prefix conversion delegates to the same engine helper. HTTP/SOCKS5, startup,
config/snapshot apply and rollback keep those handles. Snapshot validation now
constructs its scratch filter through NewIPFilter. Gossip captures the same
limiter; it converts exported counts into unchanged root wire DTOs, applies the
response to that limiter and renders the engine's observation. Metrics/API use
ClusterFreshness without advancing diagnostic history. Cleanup/stop ownership
stays in the application. Nil delta slices still encode as JSON null.

ExportHotDeltas retains absolute qualifying in-window counts on every export;
the baseline's misleading reset/delta comment is corrected, with a repeated
export regression assertion. A normalized comparison of all 48 relocated function bodies (ignoring comments
and the deliberate API renames) found no algorithm differences. No count reset,
threshold, window, exemption,
future-stamp, stale fallback, synchronization or configuration policy changed.
Logging text is unchanged. The production gossip loop serializes observation and
logging; the engine serializes its observation latch/counter, not application IO.

## Tests and CI

The [entry inventory](admission-test-migration.tsv) records old/new package,
source, name and build tag for all 97 relocated entries: 74 default tests,
21 benchmarks and two benchgate-tagged tests. Nine whole files move; mixed
distributed/misc/edge/CHAOS-61 files are split by behavior. Names, tags,
differential oracles, publication stack attribution and negative controls remain.
The cold-start age-rendering assertion splits into a named root metric test.
The CP→DP test checks the exact decoded remote count at the transport boundary,
then checks the real admission/HTTP/SOCKS5/metrics/API/cancellation effects.

Shared race source inventory: root 6,746 → 6,677; all packages 9,977 → 9,985;
admission has 77 default entries. All 310 runnable benchmarks remain. The eight
new entries cover package boundaries (two), repeated export accounting, root
logging, the split metric assertion, selector omission, Deep classification and coverage omission.
The source inventory across all build tags also loses no name or multiplicity.

Fast, QA and weekly tagged commands explicitly run `. ./internal/admission` with
`-count=1`. Contract tests parse the actual workflow jobs and reject removal of
either target, the tag or the test selector. The shared race lane and independent
universe use `go list ./...` minus the exact root path; admission is discovered
without a new allowlist. Fast's classifier has an admission regression case;
Deep's `internal/*` security and `*_test.go` patterns, and CodeQL's
`internal/**`, cover the engine. Their root selectors now also include
`admission.go` and `cluster_ratelimit*.go`, preserving the previous security.go
trigger for the relocated adapters; a test executes the Deep classifier. No release controls change.

The coverage table retains residual `security.go` at 70% and adds exact-path
70% floors for `internal/admission/engine.go` and `freshness.go`. The original
function-average calculation, global 55%, and every other floor are unchanged.
The engine floor includes the entire relocated implementation, not aliases or
unrelated code. Real generated profiles exercise the shipped floor script: a
fully covered control passes; omitted or zero-covered engine, freshness or root
security fails with that file's annotation despite healthy unrelated coverage.

## Validation and limitations

Local validation and measurements are below. Required Fast/Deep CI on the PR
head supplies the full race+coverage inventory/universe verdict, global/per-file
floors, shuffled full double run, allocation gates, hygiene, scans and build
validation. See the PR's final results rather than interpreting an early run as
final-head evidence.

Zero-value support remains deliberately bounded: use constructors before active
local limiting or single-address filter writes. Applied maps transfer ownership;
map/stamp and configuration fields are not a transaction, as at the baseline.
No CI acceleration claim follows from a faster independent package command.
The next step is the policy pure-core feasibility/ownership assessment, coordinated
with #1470, using fresh root timings; no policy extraction is included here.

## Local measurements

Same 4-CPU cloud machine, AMD EPYC 9V74, Go 1.26.8 linux/amd64,
GOMAXPROCS=4, GOFLAGS=`-mod=readonly -p=4`, umask 022. Baseline and candidate
alternate; execution uses `-count=1` (prebuilt binaries `-test.count=1`).
Warm rows are medians of three runs after compilation warmup. Cold rows are
one build each in distinct empty GOCACHE directories; module downloads remain
warm. These are local observations, not confidence intervals or CI cache claims.

| Workload | Baseline | Candidate |
|---|---:|---:|
| Same 74 engine tests, warm `go test` command | 2.363 s | 0.567 s |
| Root warm test binary build | 0.491 s | 0.490 s |
| Same 74 engine tests, prebuilt execution | 0.459 s | 0.376 s |
| Same 30 retained root integrations, prebuilt execution | 0.106 s | 0.096 s |
| Root cold test binary build | 57.990 s | 57.195 s |
| Admission warm test binary build | in root above | 0.058 s |
| Admission cold test binary build | in root above | 7.782 s |

The focused command uses the exact 74 relocated default test names from the
inventory (root `.` before, `./internal/admission` after), excluding newly added
tests. Root execution above is the same retained integration subset, not a full
root execution measurement. CI's root-shard execution steps and full shuffled
run are reported separately in the PR. Warm build rows include cache lookup and
binary materialization, not an uncached compile.

Representative hot paths: three alternating samples, prebuilt binaries,
`-test.benchtime=300ms -test.benchmem`, result caching disabled. All ten sampled
cases retain **0 B/op, 0 allocs/op**. Median distributed admission (ns/op):
standalone 86.26 → 88.75, fresh 101.7 → 104.5, stale 95.51 → 96.87,
future 94.55 → 96.36, disabled 3.319 → 3.015, exempt 15.10 → 13.35.
IP filter disabled/block-miss parallel: 0.773 → 0.754 / 22.43 → 20.46.
Parallel at-cap limiter medians were 49.25 → 70.65 (limit 600) and
45.54 → 53.65 (6000), with wide within-arm ranges (600: baseline 39.8–71.8,
candidate 46.65–80.77). The six-pair follow-up below checks that variation; neither sample establishes
a hot-path speedup. No algorithm is changed to
chase the sample. Both packages' existing scaling/allocation gates passed:
53 root and 12 admission gates executed under the migrated tagged command.

Local validation: package race + five shuffled repeats; root integration race +
three shuffled repeats; selector and real-profile coverage negative controls;
existing differential/publication/ownership suites; complete tagged gates.
The exact final-head required CI results and the follow-up latency observations
belong in the PR's validation record. Local full-root execution and a controlled
CI before/after experiment are not claimed.

Follow-up: six alternating paired prebuilt runs, 500 ms per benchmark, CPU=1,4,
both at-cap sizes; no concurrent compilation or test jobs. Medians (ns/op):

| Limit / CPUs | Baseline | Candidate |
|---|---:|---:|
| 600 / 1 | 93.730 | 93.975 |
| 600 / 4 | 42.875 | 45.365 |
| 6000 / 1 | 96.200 | 92.160 |
| 6000 / 4 | 43.525 | 42.310 |

All remain allocation-free. The initial large parallel delta did not persist:
600/4 spans 40.60–74.36 baseline and 41.48–48.52 candidate; 6000/4 spans
41.37–53.36 and 41.48–81.07. Report this scheduler-sensitive variation rather
than attributing a stable latency improvement or regression to relocation.
