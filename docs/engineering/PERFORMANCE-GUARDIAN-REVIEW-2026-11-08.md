# Performance Guardian Review — 2026-11-08

**Scope.** `902f3c9` (`origin/main`). The proxied-request hot paths: plain-HTTP
forward, CONNECT tunnel establishment and relay, Stage-2 policy evaluation,
per-request tracing, decision logging and request-log persistence. Measured, not
read: every number below came from a profile or a benchmark run on this
revision, on this machine (Go 1.27.3, linux/amd64, 4 vCPU Xeon @ 2.10 GHz,
`tsc` clocksource).

**Question asked.** Not "can this be made faster?" but "where is the product
paying for something it does not use, and is that cost on a path that scales
with load?" A cost that is real but bounded by one request is worth less
attention than a cost multiplied by the concurrent connection count.

**Method.** End-to-end CPU and allocation profiles through the real
`handleRequest` dispatch (`BenchmarkPerfQual_ProxyHTTPForward`,
`BenchmarkPerfQual_ProxyCONNECT`, 100-rule mixed rulebase), then targeted
microbenchmarks to attribute what the profiles pointed at. The repository's own
123 `TestBenchGate_` performance contracts were run as the regression baseline.

**One finding, fixed here. One quantified non-finding, deliberately not acted
on. No regression against the existing gates.**

---

## Executive Summary

Culvert's request hot paths are, with one exception, already tuned to the point
where the remaining costs are each gated by a `TestBenchGate_` contract. The
exception is not a CPU cost at all — it is **resident memory that scales with
the concurrent connection count**, which for a forward proxy is the one
scalability quantity that is sold.

Every tunnel relay direction checked a 128 KB buffer out of `relayBufPool` and
held it for the **lifetime of the tunnel**, and on every production relay shape
`io.CopyBuffer` never read it: both ends of a CONNECT-bypass relay are
`*net.TCPConn`, which implements `io.WriterTo` *and* `io.ReaderFrom`, so the
copy delegated to the kernel splice path; each WebSocket relay's source is a
`*bufio.Reader`, which implements `io.WriterTo`. Measured: **131,177 bytes of
live heap per open relay direction, ~256 KiB per tunnel, none of it ever
read** — ~250 MiB at 1,000 concurrent tunnels, ~2.4 GiB at 10,000. `allocs/op`
could not see it (a warm `sync.Pool` reports ~0 either way), which is why 498
existing benchmarks did not.

The fix takes the buffer only for a pair whose copy will read it, using
`io.copyBuffer`'s own dispatch condition. Residency falls to ~70 B/relay
(−99.95%); relay throughput is unchanged (2,460 vs 2,483 MB/s, one spread); and
the decision is cheaper than the pool round trip it replaced (2.97 ns vs
11.45 ns serial, 0.81 ns vs 2.81 ns at 4-way parallel).

---

## Finding 1 — the tunnel relay pinned 128 KB per direction that nothing read

**Severity.** Memory scalability, proportional to concurrent connections.
Not a correctness or security defect: the buffer was harmless, merely resident.

**Root cause.** `idleCopyCounted` (`proxy_tunnel.go`) acquired its pooled buffer
unconditionally, before the copy loop, and returned it on function exit:

```go
bp := getRelayBuf()          // 128 KB, held for the life of the tunnel
defer relayBufPool.Put(bp)
...
n, err := io.CopyBuffer(dst, src, *bp)
```

`io.copyBuffer` (Go 1.27.3, `$GOROOT/src/io/io.go`) dispatches before it ever
looks at the buffer:

```go
if wt, ok := src.(WriterTo); ok { return wt.WriteTo(dst) }
if rf, ok := dst.(ReaderFrom); ok { return rf.ReadFrom(src) }
// ... only here is buf read
```

Both production call sites take a delegated path:

| Call site | `dst` | `src` | `src` is `WriterTo` | `dst` is `ReaderFrom` | buffer read |
|---|---|---|---|---|---|
| `handleTunnelBypass` (`proxy_tunnel.go:538`) | `*net.TCPConn` | `*net.TCPConn` | yes | yes | **no** |
| `handleWebSocket` (`proxy_tunnel.go:165`) | `*net.TCPConn` | `*bufio.Reader` | yes | yes | **no** |

The function's own doc comment already recorded that the splice fast path was
deliberately preserved — the buffer was simply never removed from the path that
no longer uses it.

**Evidence.** `BenchmarkRelayResidency_*`, 48 idle splice-path relay directions,
live heap measured after two forced collections (which also empties
`relayBufPool`, so a pre-warmed pool cannot flatter the legacy arm):

| | held-B/relay | 48 relays | allocated establishing 48 relays |
|---|---|---|---|
| legacy (always pooled) | 131,177 | 6.005 MB | 6.48 MB |
| current (predicate) | 70 | 0.003 MB | 189 KB |
| | **−131,107 (−99.95%)** | | **−97%** |

**Expected gain.** ~256 KiB of resident heap per concurrent tunnel removed
(two directions). At 1k tunnels ~250 MiB; at 10k ~2.4 GiB. Secondary: one
`sync.Pool` Get/Put pair removed from every tunnel establishment, and on a pool
miss a 128 KB large-object allocation that the sweeper then had to walk.

**Trade-offs.** None measured. The predicate is `io.copyBuffer`'s own condition
for reaching its read loop, so no dispatch decision and no emitted byte changes:
a pair that delegates today still delegates, and a pair that copies through a
buffer today still receives a pooled 128 KB one. The two interface assertions
cost 2.97 ns against the 11.45 ns pool round trip they replace.

**Risk.** The one way this could be wrong is if the predicate and
`io.copyBuffer` ever disagree — a future Go release changing the dispatch, or
`WriteTo`/`ReadFrom` appearing on another type. That is covered by a
differential oracle rather than by restating the assertions:
`TestRelayCopyReadsBuffer_MirrorsIOCopyDispatch` hands `io.CopyBuffer` a
sentinel-filled buffer on each production pair shape and fails if the predicate
disagrees with whether the bytes actually moved through it. The predicate is
also conservative in the costly direction: an unforeseen pair gets a buffer.

**Files.**

- `proxy_tunnel.go` — `relayCopyReadsBuffer` + the conditional acquisition in
  `idleCopyCounted` (~40 lines, mostly the rationale comment).
- `proxy_tunnel_relaybuf_test.go` — differential oracle, slow-path negative
  control, bidirectional payload/accounting integrity through
  `bidiRelayCounted` on real `*net.TCPConn` pairs.
- `proxy_tunnel_relaybuf_bench_test.go` — residency (current + frozen legacy),
  allocation, throughput control (current + frozen legacy), and the two
  concurrency arms.
- `proxy_tunnel_relaybuf_benchgate_test.go` — `TestBenchGate_RelayBufferResidency`
  (absolute ceiling, 4 KB/relay against a 131,072-byte buffer) and
  `TestBenchGate_RelayBufferBeatsLegacy` (one-process before/after, with a
  vacuity guard that fails if the legacy arm stops seeing its buffer). Root is
  already in the Fast PR Gate's `benchgate` job, so no workflow change is
  needed. Both gates were negative-controlled: pointing them at the frozen
  always-buffered body fails them with the real diagnostic.

**Throughput control.** The kernel splice is what makes a bypass tunnel fast, so
"saving" the buffer by losing that path would be a far worse trade than the
memory it recovers. `BenchmarkRelayThroughput_Splice` vs `_SpliceLegacy`
(256 KB chunks, `-count=5 -benchtime=4000x`, medians): **2,460 MB/s current
against 2,483 MB/s legacy**, both arms spanning 2,337–2,851 MB/s. One spread, no
gap — and a lost splice would not be a few per cent, it would be a per-byte
userspace round trip.

---

## Non-finding 1 — the per-request decision snapshot: the cost *is* the contract

Recorded because `policy_match_snapshot_bench_test.go` explicitly leaves the
structural question open ("Still open, and NOT addressed here…"), and because
the attribution below is the number that question needs. **No change is
proposed.**

`PolicyStore.Evaluate` returns a `PolicyMatch` carrying a fully detached copy of
the matched rule (`copyPolicyRuleForMatch`), so a consumer cannot mutate the
published rulebase. `PolicyMatch` is 632 bytes with 34 pointer-bearing fields
and lands exactly at the top of the 640-byte malloc size class. Decomposed on a
100-rule store with the match at scan position 1:

| | ns/op |
|---|---|
| `Evaluate`, full | 507 |
| `&PolicyMatch{}` + `copyPolicyRuleForMatch` | 359 |
| `&PolicyMatch{}` alone (640 B, pointer-dense, no copy) | 244 |
| a 64-byte match struct pointing at the published rule | 39 |
| `Evaluate`, 10 rules, no match (full scan, no snapshot) | 105 |

So in isolation the snapshot is **~71% of a matching `Evaluate`** — the scan
itself is the cheap part — and `runtime.gcDrain` is 26.6% of that benchmark's
CPU, driven by the 34 pointer slots the collector must mark per request.

**Why no change.** Three reasons, in order:

1. **End to end it is small.** In the real `handleRequest` profile
   (`BenchmarkPerfQual_ProxyHTTPForward`, 40,000 requests) `Evaluate` is 1.18%
   of total CPU and `copyPolicyRuleForMatch` 0.36%. The 244 ns allocation figure
   is inflated by a microbenchmark whose live heap is a few MB, so GC runs
   continuously; it is an upper bound, not a production cost.
2. **HTTPS does not pay it per request.** Policy is evaluated once per
   connection for CONNECT (`inspect_host_pin.go` pins the decision); inner
   requests under TLS inspection do not re-evaluate. The per-request multiplier
   applies to plain HTTP only.
3. **The only way to remove it is to stop detaching**, i.e. to hand callers a
   pointer into the published rulebase. Nothing in `decryptprofile_resolve.go`,
   `decryption_observability.go`, `proxy_tunnel*.go`, `store.go` or
   `policy_learning_observe.go` mutates `match.Rule` today, but the detachment
   is a deliberate safety property of a security gateway's enforcement path, and
   `match.Rule.HitCount` would become the stale published value. That is an
   ownership decision for the policy owner, not a Guardian micro-optimization —
   and it would buy ~0.4% of end-to-end request CPU.

The repository's own rejected experiment (folding the three `*bool` cells
inline, rejected on measurements) remains correct for the same size-class
reason: `PolicyMatch` at 632 bytes has zero slack, so the next byte costs a full
64-byte class step on every matched request.

---

## Gate baseline

| Check | Result |
|---|---|
| `go test -run 'TestBenchGate_' -count=1 .` (untagged) | pass |
| `go test -tags benchgate -run 'TestBenchGate_' -count=1 -v .` | 69 gates pass, 0 fail |
| `go build ./...`, `go vet .`, `go vet -tags benchgate .` | clean |

No existing performance contract regressed on this revision.

---

## Benchmark plan — what this review could not measure

Recorded so the next pass starts where this one stopped, not so it is treated
as covered.

1. **TLS inspection under real handshakes.** `BenchmarkPerfQual_ProxyCONNECT`
   measures tunnel *establishment* on the bypass path. The inspect path's
   per-connection leaf-certificate mint, ALPN negotiation and inner-request
   pipeline were not profiled here. Target: `internal/ca` leaf cache hit/miss
   ratio under a realistic host mix, and allocation per inner request through
   `proxy_tunnel_h2.go`.
2. **Residency at real scale.** The gate measures 48 relay directions. The
   claim it supports is linear extrapolation to 10k tunnels. A load scenario
   holding 10k concurrent idle tunnels against RSS — not `HeapAlloc` — would
   convert the extrapolation into a measurement, and would also expose the
   per-tunnel costs this review did not look for (goroutine stacks, conn
   structures, `registerDrainableTunnel` bookkeeping).
3. **SOCKS5.** Not profiled at all in this pass.
4. **The loopback ceiling.** Both end-to-end benchmarks run client, proxy and
   origin in one process over loopback, so 21.7% of samples are `Syscall6` and
   13.4% `futex`. Culvert's own share of a request is therefore *understated* as
   a fraction, and real-NIC profiles would re-rank the cost centres. A
   two-machine `pprof` capture under sustained load is the honest instrument for
   any future CPU claim.
5. **GC behaviour at a production heap.** Every allocation figure here was taken
   at a microbenchmark heap of a few MB. `GOGC`/`GOMEMLIMIT` behaviour at a
   realistic live heap would change the weight of the snapshot non-finding
   above, in either direction.

---

## Residual risk

- The relay fix's correctness rests on the predicate agreeing with
  `io.copyBuffer`. That agreement is asserted by execution, on every production
  pair shape, in the default suite — not by inspection. A Go toolchain bump that
  changes the dispatch fails `TestRelayCopyReadsBuffer_MirrorsIOCopyDispatch`
  rather than silently reintroducing a per-call 32 KB allocation.
- `TestBenchGate_RelayBufferResidency` reads `runtime.MemStats`, which carries a
  measurement floor (~220–620 B/relay observed across six runs). The ceiling is
  4 KB/relay against a 131,072-byte buffer, and the before/after gate requires a
  saving of one buffer less that floor; taking the buffer back drops the saving
  to ~0, two orders of magnitude below the bar. Both were negative-controlled.
- The 2.4 GiB figure is an extrapolation from a measured per-relay constant, and
  is labelled as such wherever it appears. It is not a measured RSS delta.
- No claim here is a hosted-CI result. Local gates are not the Fast or Deep PR
  Gate verdict.
