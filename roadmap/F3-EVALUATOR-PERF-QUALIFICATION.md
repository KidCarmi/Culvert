# F3 Performance Qualification — evalAccessRules extraction (ADR-0026)

> Status: **COMPLETE — PASS (2026-08-13).** Verdict: the ADR-0026 evaluator-core
> extraction meets the end-to-end acceptance budget (≤2% throughput/CPU per
> request, allocation-neutral, no material p95 regression). The residual
> microbenchmark-only regression (+4.5% geomean on `Evaluate` in isolation) is
> accepted per the qualification criterion: its end-to-end cost is demonstrably
> negligible. ADR-0026 remains ACCEPTED; one canonical evaluator; no semantic
> shortcut or mode-specific path was introduced.

## Question

Foundation finding #9: extracting the Stage-2 scan from `PolicyStore.Evaluate`
into the shared non-inlinable `evalAccessRules` core measured ~10% slower on the
1000-rule policy microbenchmark. Is that a real per-request cost, or an isolated
microbenchmark artifact?

## Method

- **Builds:** parent `a4f9ee1` (pre-F3) vs HEAD `99b0339` (F1–F4), compiled as
  separate test binaries from a git worktree; identical benchmark sources
  (`policy_perfqual_test.go`, `proxy_e2e_perfqual_test.go`) compiled into both.
- **Interleaving:** binaries alternated round-by-round (A,B,A,B…) so machine
  drift affects both equally; `benchstat` for significance. Noise floor
  established by interleaving one binary against itself (~±2%, n.s.).
- **Micro:** `Evaluate` at 10/50/100/500 rules × first/middle/last/no-match
  positions, n=10 rounds.
- **E2E:** real `handleRequest` dispatch — plain-HTTP forward (keep-alive,
  10/100/500-rule mixed FQDN+CIDR rulebase, catch-all allow last = full scan
  per request) and CONNECT tunnel establishment — n=16 rounds × 1000
  requests/round. Metrics: wall ns/op, **CPU/request** (rusage user+sys across
  all in-process actors), p50/p95, B/op, allocs/op. Per-request policy log line
  silenced (its synchronous stderr write is a test-harness artifact; production
  uses the async logsink).
- **Profiles:** CPU profiles of the significant micro case (rules=100/no-match)
  on both builds + `pprof -diff_base` differential.

## Results

**Micro (`Evaluate` in isolation)** — geomean **+4.5%**; first-match cases
statistically flat; long scans +3.5–8.2% (worst: rules=500/middle +8.2%).
Absolute worst delta ≈ +0.9µs at 500 rules. Allocations and B/op **identical**
(p=1.000). Differential profile: the delta is diffuse call-frame overhead
(work moved from the inlined `Evaluate` loop into the non-inlinable core frame);
dominant real work (FQDN-matcher string operations) identical in both builds.
Three argument-passing forms were measured (explicit params +16%,
pointer-to-struct +9.5% at 1000 rules, forwarded params +13.5%); the
pointer-to-struct form shipped. `ruleIsEnabled`/`ruleTypeOf` inline into the
core exactly as they did into `Evaluate`; the matchers were never inlinable in
either build.

**End-to-end (n=16 interleaved, benchstat)** — every comparison
not-significant (p ≥ 0.38):

| metric | geomean delta | worst single case |
|---|---|---|
| throughput (sec/op) | **+0.43%** (n.s.) | all n.s.; per-case median req/s deltas scatter −2.6%…+2.8% with no consistent sign (rules=500 faster on HEAD) |
| **CPU/request** (rusage) | **−0.20%** (n.s.) | all n.s. |
| p50 | +1.15% (n.s.) | all n.s. |
| p95 | +0.52% (n.s.) | all n.s. — an earlier low-power (+13%, p=0.019) p95 hit at rules=100 did **not** reproduce at 2.5× power; noise |
| B/op | −0.09% | ~ |
| allocs/op | **0.00%, all samples equal** | — |

Representative absolute numbers (4-core CI-class VM, loopback, in-process
client+proxy+backend): ~3.3–3.9k req/s per serial connection; ~255–306µs
wall/op; ~390–625µs CPU/op.

**Physics cross-check:** the worst realistic micro delta (~+250ns at 100 rules)
against a ~400µs CPU request budget predicts ≤0.1% E2E — consistent with the
measured ~0%.

## Verdict

- E2E throughput/CPU regression: **within the ≤2% budget** (statistically
  indistinguishable from zero).
- Allocation-neutral: **yes** (identical at micro and E2E).
- p95: **no material regression**.
- Microbenchmark-only residual (+4.5% geomean, worst +8.2%): **accepted** under
  the qualification criterion — E2E cost demonstrably negligible.

## Artifacts

- `policy_perfqual_test.go` — Evaluate micro qualification benchmark
  (size × match-position matrix). Benchmark-only; not part of `go test ./...`.
- `proxy_e2e_perfqual_test.go` — E2E proxy HTTP-forward + CONNECT benchmarks
  with `cpu-ns/op` (rusage) and `p50-ns`/`p95-ns` custom metrics. Benchmark-only.
- Both are permanent regression harnesses: re-run the interleaved comparison
  against any future evaluator change
  (`go test -run '^$' -bench 'BenchmarkPerfQual' -benchmem -count=N .`).

## Constraints honored

No second evaluator, no semantic shortcut, no mode-specific policy path. The
only optimization iterations were argument-passing forms of the single core,
each behavior-identical and equivalence-fuzz-verified; the best-measured form
shipped in F3.
