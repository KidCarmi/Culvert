# Performance Guardian Review — 2026-11-09

**Scope.** `d11ed3a` (`origin/main`), 53 commits after the previous pass's
`902f3c9`. This review picked up where that one's benchmark plan stopped: its
item 1 was *"TLS inspection under real handshakes — the inspect path's
per-connection cost was not profiled"* and item 3 was *"SOCKS5 — not profiled at
all"*. Measured, not read: every number below came from a profile or a benchmark
run on this revision, on this machine (Go 1.27.3, linux/amd64, 4 vCPU Xeon
@ 2.10 GHz).

**Question asked.** Not "can this be made faster?" but "where is the gateway
paying for something it does not use, and does that cost scale with the
concurrent connection count?" A per-request cost is bounded by one request. A
per-connection cost is multiplied by every connection the appliance is sold to
hold.

**Method.** CPU, allocation, mutex-delay and block profiles through the real
`handleRequest` dispatch (`BenchmarkPerfQual_ProxyHTTPForward`,
`BenchmarkPerfQual_ProxyCONNECT`, 100-rule mixed rulebase), then a read of the
inspected-tunnel and SOCKS5 paths the end-to-end benchmarks do not reach, then
targeted benchmarks and stdlib probes to attribute what the reading suggested.
The repository's own `TestBenchGate_` contracts were the regression baseline.

**Outcome: the candidate optimization was MEASURED, then WITHDRAWN on
correctness.** What ships instead is the contract that was missing. Plus one
correctness defect found while measuring, reported for its own change, and one
quantified non-finding.

---

## Executive Summary

The request hot paths this product sells on — plain-HTTP forward, CONNECT
establishment, policy evaluation, the tunnel relay — are tuned to the point where
every remaining cost in them is either gated by a `TestBenchGate_` contract or
has a recorded decision behind it. The mutex-delay profile over 15,000 proxied
requests at 4-way parallelism totals **4.60 ms, none of it in a Culvert lock**;
there is no contention finding at this scale.

The one cost that looked both large and free was per-connection memory on the
**inspected** tunnel. `runH1InspectLoop` gives each leg of every decrypted
HTTP/1.1 tunnel a 32 KiB `bufio.Reader` and holds both for the tunnel's lifetime:
**65,747 B of resident heap per concurrent inspected tunnel (~627 MiB at
10,000)**, written as two bare `32*1024` literals with no recorded reason. Both
`net/http`'s own server and `http.Transport` use 4 KiB for the identical two
roles. Dropping to 4 KiB measures **8,403 B/tunnel (−57,344 B, −87.2%)** with no
throughput or parse-latency cost in either direction.

**That change was prepared, gated, and then withdrawn, because the size is
load-bearing and not for throughput.** `net/http` reads a chunked body's
trailers through the same `bufio.Reader` and bounds the trailer block by the
reader's buffer size (`transfer.go`, `readTrailer` → `seeUpcomingDoubleCRLF`;
the stdlib's own comment: *"This limits the trailer to the underlying buffer
size, typically 4kB."*). Measured against the real stdlib, an ~8 KiB trailer
block is **accepted at 32 KiB and refused at 4 KiB**. Shrinking the constant
would therefore have made *enabling inspection* reject chunked responses that
pass with it off — the plain-HTTP forward path reads through `http.Transport`
with `ReadBufferSize: 64 KiB`, so its window is already wider than the inspect
path's.

So the deliverable is not the optimization. It is: the magic number becomes a
**named constant carrying both sides of the trade**, the trailer-window
dependence becomes a **default-suite test that fails with the reason attached**,
the per-tunnel memory becomes a **measured benchgate ceiling** so an increase is
deliberate, and the decision — whether a narrower trailer window is worth ~57 KiB
per inspected tunnel — is handed to the contract owner instead of taken on
performance grounds.

Separately, and not part of this change: the inspected-WebSocket upgrade path
hands its raw relay the `*tls.Conn`s rather than the two buffered readers, so
frame bytes already sitting in those readers when the 101 arrives are silently
dropped. Correctness defect, independently confirmed, reported in Finding 2.

---

## Finding 1 — the inspect-leg read buffer: 65.7 KB per tunnel, and it is load-bearing

**Severity.** Not a defect. An undocumented constant that couples a memory cost
to a traffic-acceptance decision, with neither side recorded, on the enforcement
path.

**What it costs.** `runH1InspectLoop` (`proxy_tunnel.go`) opened with:

```go
clientBR := bufio.NewReaderSize(clientTLS, 32*1024)
upstreamBR := bufio.NewReaderSize(upstreamTLS, 32*1024)
```

`bufio.NewReaderSize` allocates eagerly and both readers live until the tunnel
closes, so this is resident from establishment. Measured over 48 live tunnels
(`BenchmarkInspectReadBufResidency_*`, live heap across forced collections, each
reader proven live by a byte through it):

| | held B/tunnel | 48 tunnels | at 10k tunnels |
|---|---|---|---|
| shipped (2 × 32 KiB) | 65,747–65,748 | 3,155,856 B | ~627 MiB |
| hypothetical (2 × 4 KiB) | 8,403 | 403,344 B | ~80 MiB |
| | **−57,344 (−87.2%)** | | **−547 MiB** |

Deterministic to within ~3 bytes across runs: the dominant term is a
deterministic eager allocation. `allocs/op` cannot see a cost of this shape at
all — one allocation per tunnel that never goes away — which is why the
repository's 500+ existing benchmarks say nothing about it.

**What it is NOT bought with.** Throughput, in either direction. These readers
sit on a `*tls.Conn`, and `tls.Conn.Read` returns at most one TLS record, so a
larger buffer absorbs no more per fill; a consumer reading at least the buffer
size bypasses the buffer entirely (`bufio.Reader.Read`'s "Large read, empty
buffer" branch, verified in the stdlib source). Measured on a real handshaked TLS
pair over TCP loopback, `-benchtime=2s -count=3`, 32 KiB against 4 KiB:

| | 32 KiB (shipped) | 4 KiB |
|---|---|---|
| `http.ReadRequest`, ns/op | 3677, 3913, 3944 | 3692, 3790, 3834 |
| …allocations | 1944 B, 21 allocs | 1944 B, 21 allocs |
| read-through @1 KiB reads, MB/s | 1772, 1901, 2056 | 1878, 1933, 2082 |

The 1 KiB consumer read size is chosen **against** a shrink's interest: reads
that small are served from the buffer, so the buffer's size sets the refill
frequency. One spread, no ordering. Scratch probes at 8 KiB and 16 KiB, at 512 B
reads, and on chunked-response delivery landed in the same spread.

**What it IS bought with — the reason the obvious optimization is wrong.**
`net/http` reads a chunked message's trailers through the same `bufio.Reader`,
and guards against an unbounded trailer with a buffer-sized `Peek` loop
(`net/http/transfer.go`):

```go
	// Instead, a hack: we iteratively Peek up
	// to the bufio.Reader's max size, looking for a double CRLF.
	// This limits the trailer to the underlying buffer size, typically 4kB.
	if !seeUpcomingDoubleCRLF(b.r) {
		return errors.New("http: suspiciously long trailer after chunked body")
	}
```

So the constant sets the trailer block an inspected tunnel accepts. Measured
against the real stdlib at the pinned toolchain:

| trailer block | 4 KiB | 8 KiB | 16 KiB | 32 KiB |
|---|---|---|---|---|
| ~3,800 B | accepted | accepted | accepted | accepted |
| ~4,090 B | **refused** | accepted | accepted | accepted |
| ~8,000 B | **refused** | accepted | accepted | accepted |
| ~20,000 B | **refused** | **refused** | **refused** | accepted |
| ~40,000 B | refused | refused | refused | refused |

Production consequence of a shrink, traced through this file: with scanning on,
`readScanPrefix` returns a read error → `scanInspectBody` → `scanReadError` →
`exDeliverError` → the tunnel is torn down; a **legitimate** response is dropped.
With scanning off or the host excluded, the body is already streaming to the
client when the trailer read fails, so the client gets an unterminated chunked
response. The same mechanism applies on the client leg to a chunked inner request
with a large trailer block (`rq.Write(upstreamTLS)` → `exRoundTripError`).

And it would make inspection *more* restrictive than no inspection: the
plain-HTTP forward path reads through `http.Transport` with
`ReadBufferSize: 64 KiB` (`upstream_transport.go`), i.e. a ~64 KiB window. The
inspect path at 32 KiB is already the narrower of the two. There is an in-repo
contract that trailers survive this pipeline at all
(`inspect_exchange_test.go`, grpc-status).

**How this was caught, recorded because the sequence is the lesson.** The 4 KiB
change was written, measured, gated, negative-controlled and passing — including
a differential oracle over an inner-request/response corpus asserting that the
parse was identical at both sizes. The corpus contained a chunked response with
trailers, but a **9-byte** trailer block, so it was inside every candidate buffer
and the oracle was green. An independent reviewer, given the code and bounded
questions rather than the conclusion, traced the stdlib body readers and found
the dependence; it was then reproduced directly against `net/http` before being
accepted. A test whose corpus is built from the shapes the author already has in
mind confirms the author.

**What ships instead.**

1. The two literals become `inspectLoopReadBufSize`, documented with the trailer
   window it bounds, the stdlib mechanism and measured table, the per-tunnel
   memory it costs, the throughput question closed in both directions, and an
   explicit statement that changing it is a traffic-acceptance decision owned by
   the proxy/inspection contract — not a tuning knob. Raising it to the forward
   path's 64 KiB costs ~63 KiB more per concurrent inspected tunnel; lowering it
   needs a decision that the narrower window is acceptable.
2. `TestInspectLoopReadBuf_TrailerWindowIsLoadBearing` (default suite) pins the
   dependence by execution: an ~8 KiB trailer block must be accepted at the
   shipped size, and the same block must still be refused at 4 KiB so the test
   cannot keep passing if the dependence disappears. Negative-controlled — with
   the constant shrunk to 4 KiB it fails naming the consequence.
3. `TestInspectLoopReadBuf_HeaderShapesDoNotDependOnTheSize` keeps the parity
   corpus but **scoped** to where independence genuinely holds (header blocks
   and over-long header lines, which `textproto` reassembles across refills),
   with the chunked-trailer case moved out. Separating the two is the point: one
   undifferentiated "parses identically" test is what made the size look free.
4. `TestBenchGate_InspectReadBufResidency` pins the per-tunnel residency as a
   **ceiling** (80 KiB against 65.7 KB measured) with a lower-bound vacuity
   guard, so an increase — a larger size, or a third buffered reader — fails with
   the 10k multiplier attached instead of landing as a one-character diff. There
   is deliberately no "smaller is better" gate. Negative-controlled in both
   directions: a 64 KiB pair breaches the ceiling, and a 4 KiB pair trips the
   lower-bound guard.
5. `newInspectLoopReaders` exists so all of the above is pinned on the
   production pair rather than on a copy of it.

**Trade-offs.** No behaviour and no performance change: the constant keeps its
shipped value. The cost is ~6 lines of production code, a named constructor, and
the tests.

**Risk.** The trailer-window assertion depends on stdlib behaviour that could
change. That is why it is asserted by execution in the default suite with a
two-sided control: a toolchain bump that removes the dependence fails the control
arm with an explicit "CONTROL LOST" diagnostic rather than silently leaving a
comment nothing checks.

**Files.** `proxy_tunnel.go`, `proxy_tunnel_inspectbuf_test.go`,
`proxy_tunnel_inspectbuf_bench_test.go`,
`proxy_tunnel_inspectbuf_benchgate_test.go`. Root is already named in the Fast PR
Gate's `benchgate` job, so no workflow change is needed.

---

## Finding 2 — the inspected WebSocket upgrade strands its buffered bytes

**NOT fixed in this change.** A correctness defect, not a performance one, and
bundling it into this PR would be wrong on both counts. Recorded with its
evidence because it was found while reading this function and independently
confirmed, and because it is the one thing on this path more important than the
memory.

**Severity.** Correctness, on inspected WebSocket traffic. Data loss.

**Root cause.** In `runH1InspectLoop`'s `exUpgrade` arm, the 101 is written to
the client and the tunnel falls back to raw relay — reading the **conns**, not
the readers it has been parsing through:

```go
go rawRelay(upstreamTLS, clientTLS)
go rawRelay(clientTLS, upstreamTLS)
```

`clientBR` and `upstreamBR` are abandoned. `http.ReadResponse` on a 101 stops at
the headers (101 allows no body, so `Body` is `NoBody`) and `http.ReadRequest` on
the upgrade request stops at its blank line, so bytes a peer coalesced into the
same read remain in the buffer and the raw relay never sees them.

**Evidence.** The mechanism, against the real stdlib:

| | bytes left in the `bufio.Reader` |
|---|---|
| `http.ReadResponse` on `101` + a 7-byte server frame | **7** |
| `http.ReadRequest` on an upgrade request + an 11-byte client frame | **11** |

**Why this is not a judgement call.** The repository has already fixed this bug
class twice on neighbouring paths, with comments naming it. The non-inspected
WebSocket path (`handleWebSocket`):

> `client → target reads via clientBuf.Reader, NOT the raw clientConn: the HTTP
> server may have buffered client bytes (frames pipelined right after the Upgrade
> request) into the hijacked reader; relaying the raw conn would strand them and
> the target would block. Same class of bug as the CONNECT bypass path.`

— and it relays through `bidiRelayCounted(clientConn, br, destConn,
clientBuf.Reader)`. The CONNECT-bypass path and the strip path's non-TLS fallback
both route through their buffered reader for the same reason. The inspected path
is the same situation with two readers instead of one, and does not.

**Suggested remedy (for its own PR).** Relay the readers, not the conns — the
shape `handleWebSocket` already uses. `*bufio.Reader` implements `io.WriterTo`,
so `relayCopyReadsBuffer` still declines a 128 KB relay buffer for the pair and
the previous pass's residency fix is unaffected. It wants its own test: a 101
with a coalesced first frame in each direction, asserting the frame arrives.

**Relation to Finding 1.** The buffer size bounds how much can be stranded (up to
the buffer, not an unbounded amount), so a shrink would have *narrowed* the loss
window. That is not a reason to shrink, and since nothing changes here the window
is as it was.

---

## Non-finding 1 — `copyHeaders`: measured, and blocked on semantics rather than cost

Recorded because it is the largest object-count item attributable to Culvert on
the plain-HTTP response path, and because the reason not to act is worth writing
down. **No change proposed.**

`http.Header.Add` is `append(h[key], value)`, so a fresh key costs a one-element
`[]string`. Measured on `BenchmarkPerfQual_ProxyHTTPForward` (60,000 requests):
**294,916 objects, 4.9 per request, 2.93% of every object allocated** — on both
paths that scale with traffic, `proxy_http.go` (every plain-HTTP response) and
`proxy_tunnel_h2.go` (every inner response of an inspected H2 tunnel). Real
responses carry 10–20 headers, not the benchmark's 5. One shared backing array
would make that 1 allocation instead of *K*.

**Why no change.** Three reasons, in order:

1. **`Add` APPENDS; a map assignment REPLACES.** `dst` is `w.Header()`, which by
   then carries the proxy's own `X-Request-Id` (`setupRequestTracing` mirrors it
   onto the response). An origin that echoes that header today produces two
   values; the fast form would drop Culvert's own correlation ID.
2. **`Add` canonicalises the key.** `pluginOnResponse` and
   `rewriter.ApplyResponse` run first, so a direct map write could let a
   non-canonical key through. Correct, but it makes the helper a header-semantics
   decision rather than an allocation one.
3. **The byte volume is unchanged** — 4.9 × 16 B of one-element slices against
   one ~80 B array. The win is in `mallocgc` call count and sweep work (0.56% of
   allocated bytes), not GC pacing. Against the two branches above, not a trade
   to make without the owner.

---

## What was measured and found already appropriate

- **The `internal/ca` leaf-cert cache** (previous plan item 1). Lock-free
  `sync.Map` hit path, single-flight on the miss path, process-wide shared leaf
  key, and the `net.SplitHostPort`-on-SNI allocation already removed.
- **`internal/secscan.ReadScanBuffer`.** Pre-sized from `Content-Length`, hint
  capped at 1 MiB and spent only after a 512-byte seed read, so a
  declare-and-stall origin cannot commit the full window.
- **gzip/deflate decompression for scanning.** Already a pooled reader with
  `Reset`.
- **`decEnumOr`, `generateTraceIDs`, `setupRequestTracing`, the hop-by-hop header
  table.** Interface boxing, double CSPRNG draws, non-canonical header spellings
  and `strings.Split` all already removed, each with its measurement recorded.
- **SOCKS5** (previous plan item 3). Its relay goes through the shared
  `idleCopyCounted`, so it inherited the previous pass's relay-buffer fix; the
  per-connection parse allocations are 4–6 small reads bounded by one connection.
  Nothing scaling with load.
- **Lock contention.** `-mutexprofile` over 15,000 requests at 4-way
  parallelism: **4.60 ms total delay**, all of it `context` cancellation,
  `net/http` conn bookkeeping and the runtime scheduler. No Culvert lock appears.
- **The per-request `PolicyMatch` snapshot.** Still 4.93% of allocated bytes on
  the plain-HTTP path (`policy.go:1795`, 39.52 MB over 60,000 requests), still
  ~0.4% of end-to-end CPU. The previous pass's analysis and its decision not to
  act both stand.

---

## Gate baseline

| Check | Result |
|---|---|
| `go build ./...`, `go vet ./...`, `go vet -tags benchgate .` | clean |
| `go mod tidy -diff` | clean |
| `CGO_ENABLED=0 go build -ldflags="-s -w"`, `GOOS=linux GOARCH=arm64 go build` | clean |
| `go test -tags benchgate -run 'TestBenchGate_' -count=1 -p 1` (root + 7 packages, the Fast gate's own command) | pass |
| `golangci-lint v2.15.0 run --new-from-rev origin/main` (the Fast gate's command, built with the `go.mod` toolchain) | 0 issues |
| `TEST_SEED=20260421 go test -count=2 -shuffle=on -timeout=30m ./...` | pass — 116 packages ok, 0 failures, root 899.5 s (taken on the withdrawn 4 KiB revision) |
| `TEST_SEED=20260421 go test -count=2 -shuffle=on -timeout=30m .` | pass — root 828.5 s, on the SHIPPED revision |
| `go test -race` on the touched area and the new gate | pass |
| `python3 docs/agent-context/check.py --self-test --diff-base origin/main` | pass |

The full-tree determinism run was taken while the withdrawn 4 KiB variant was in
the tree; the shipped revision restores the pre-existing constant value, so it
changes no production behaviour relative to `origin/main`, and the root package's
shuffled double run, the full `benchgate` suite, `go vet` (tagged and untagged),
the cross builds, lint and the guidance checker were all re-run on it. No
existing performance contract regressed.

---

## Benchmark plan — what this review could not measure

1. **Residency at real scale, against RSS.** The previous pass's finding and
   Finding 1's cost figure both rest on a measured per-connection constant times
   a connection count. A scenario holding 10k concurrent inspected tunnels
   against **RSS** would convert the extrapolation into a measurement, and would
   expose the per-tunnel costs neither pass looked for: goroutine stacks, the two
   `tls.Conn` record buffers (~33 KiB each, comparable to the reader pair), and
   `registerDrainableTunnel` bookkeeping.
2. **Whether >4 KiB chunked trailer blocks occur in real traffic.** Finding 1's
   decision would be much easier with data. There is no in-tree telemetry for
   trailer sizes, so the practical width of the window the 32 KiB buys is
   unquantified. A counter on the inspect path would make this an evidence-based
   decision rather than a conservative one.
3. **The inspect path's handshake cost.** This pass profiled the inspect loop's
   steady state, not its establishment. Per-connection leaf mint, `internal/ca`
   cache hit/miss under a realistic host mix, and ALPN negotiation remain
   unprofiled — the previous pass's item 1 is half-closed, not closed.
4. **Per-inner-request allocation through `proxy_tunnel_h2.go`.** Still open.
   `copyHeaders` is one item on it, found from the plain-HTTP profile.
5. **The loopback ceiling.** 20.46% `Syscall6` and 15.95% `futex` in the
   end-to-end CPU profile: client, proxy and origin in one process over loopback,
   so Culvert's own share of a request is *understated as a fraction*. A
   two-machine `pprof` capture is the only honest instrument for a CPU claim.
6. **GC behaviour at a production heap.** Every allocation figure here came from
   a microbenchmark heap of a few MB.
7. **Contention at a realistic connection count.** The 4.60 ms result is a
   4-vCPU, 4-way measurement — evidence that no lock is hot *at this scale*, not
   evidence about 64 cores and 10k connections.
8. **The shared upstream transport's 64 KiB buffers.** Found while establishing
   Finding 1's comparison, not investigated: `newBaseUpstreamTransport` sets
   `ReadBufferSize`/`WriteBufferSize` to 64 KiB with no measurement behind it.
   In its favour, it reads a **plaintext** socket, where a larger buffer can
   absorb more per read, and it widens the same trailer window on the forward
   path. Against it, at `MaxIdleConns: 512` the pair is up to ~64 MiB of pooled
   residency. It wants the treatment Finding 1 got, not a guess either way.

---

## Residual risk

- Finding 1 ships no behaviour or performance change, so its risk is confined to
  the new tests. The trailer-window test depends on stdlib internals; it carries
  a two-sided control that fails loudly if the dependence disappears rather than
  going quietly vacuous.
- `TestBenchGate_InspectReadBufResidency` reads `runtime.MemStats`, a one-sided
  delta with a ~211 B/tunnel floor. It is therefore bounded BOTH ways: a
  lower-bound guard rejects a measurement that cannot see the buffers (a 4 KiB
  pair trips it), and the 80 KiB ceiling rejects an increase (a 64 KiB pair
  breaches it at ~131 KB/tunnel). Both were negative-controlled.
- The ~627 MiB and ~547 MiB figures are extrapolations from a measured
  per-tunnel constant, labelled as such wherever they appear. Neither is a
  measured RSS delta.
- Finding 2 is reported, not fixed. It remains a live defect on inspected
  WebSocket traffic until its own change lands.
- The H2 inspect path was read, not profiled. It has no equivalent reader pair —
  it hands `clientTLS` to `ServeConn` — so Finding 1 does not apply there, but
  that is the extent of what this pass establishes about it.
- The withdrawn 4 KiB variant is recorded here rather than kept on a branch. If
  the trailer window is later judged not worth ~57 KiB per tunnel, the
  measurements, the gate and the failing test are all in place to make that
  change deliberately.
- No claim here is a hosted-CI result. Local gates are not the Fast or Deep PR
  Gate verdict.
