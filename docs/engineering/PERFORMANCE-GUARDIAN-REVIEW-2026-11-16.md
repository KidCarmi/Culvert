# Performance Guardian Review — 2026-11-16

**Scope.** `51996b9` (`origin/main`), 57 commits after the 2026-11-15 pass's
`0b11474`. Measured, not read: every number below came from a benchmark or an
allocation/CPU profile run on this revision, on this machine (Go 1.27.4,
linux/amd64, 4 vCPU Xeon @ 2.10 GHz).

**Question asked.** The five preceding passes all worked inward from a suspicion
about a named owner. This one started from the opposite end — **profiles of the
two shipped end-to-end request paths** — and let the profile choose the target,
so that the pass could also answer whether the hot paths still have anything
worth taking.

`BenchmarkPerfQual_ProxyHTTPForward/rules=500` and
`BenchmarkPerfQual_ProxyCONNECT/rules=100` were profiled for allocations
(`-memprofilerate=1`) and CPU. The answer for the plain-HTTP forward path is
that it is **done**: at 166 allocs/op end to end, Culvert's own code contributes
**four** — one `PolicyMatch`, one decision line, one trace id, one `Sprintf` —
and every other allocation belongs to `net/http` on one side of the loopback or
the other. The CONNECT path is dominated by the upstream dial (46% of
`handleTunnelBypass`). Neither profile pointed at a defect.

What the profiles did do is make the *shape* of the remaining per-request work
visible, and one call on the SSL-inspection path turned out to be a
process-wide exclusive-word read that nobody had measured: the scan-exclusion
store.

**Outcome: one optimization, measured, shipped and gated. Two hot paths
profiled end to end and recorded as already appropriate. One previously
recorded candidate re-confirmed as still correctly deferred.**

---

## Executive Summary

**Every response Culvert decrypts took a process-wide reader lock to ask an
empty map a question.** `scanexcl.Store.IsHostExcluded` is called from
`scanInspectBody` (`proxy_tunnel.go:1501`) **unconditionally** — ahead of the
content-type gate, with no "is any scanner enabled" guard — for every response
on the SSL-inspection path, which is the primary SWG path. It is called again
from `scanHTTPResponseBody` (`proxy_http.go:324`) for every plain-HTTP response
whenever any body scanner is on, and the sibling `IsHashExcluded` runs once per
body scan from `internal/secscan`.

All three took `sync.RWMutex.RLock`. A reader lock is not free in this shape:
`RLock`/`RUnlock` are two atomic **read-modify-writes on one process-wide
word**, so every inspected response wrote the same cache line purely to read a
map that in steady state never changes — and in the default posture, to read a
map that is **empty**, because the exclusion lists are an admin opt-in for
known-good internal mirrors and most deployments configure none.

Measured with both arms in ONE interleaved invocation (`-benchtime=2s`,
`-count=1`), `RunParallel`, so ns/op is wall time per op across all workers — a
genuinely parallel read **falls** as cores are added and one that serialises
**rises**:

| arm | P=1 | P=2 | P=4 | 1→4 throughput |
|---|---|---|---|---|
| host, no exclusions, RWMutex | 41.7 ns | 141 ns | 154 ns | **0.27x** (cores SUBTRACT) |
| host, no exclusions, published view | 3.52 ns | 1.75 ns | 0.889 ns | **4.0x** |
| host, configured miss, RWMutex | 50.2 ns | 156 ns | 171 ns | **0.29x** |
| host, configured miss, published view | 42.1 ns | 23.0 ns | 12.6 ns | **3.3x** |
| hash, no exclusions, RWMutex | 79.0 ns | 88.2 ns | 96.6 ns | 0.82x |
| hash, no exclusions, published view | 2.62 ns | 1.37 ns | 0.651 ns | **4.0x** |

In the default posture that is **11.8x at one core and 173x at four** for the
host check, and **30x / 148x** for the hash check. Serially, the shapes that
still do the full lookup: a configured host hit 45.7 → 40.5 ns and a configured
hash hit 93.0 → 79.9 ns, which is the `RLock`/`RUnlock` pair and its deferred
unlock coming off the call.

**The sign is the finding, not the magnitude.** Before, adding cores subtracted
throughput in every posture; after, adding cores adds it in every posture. This
is the **fourth** instance of the identical shape in this tree —
`internal/threatfeed`, `internal/connlimit`, the IP filter and the top-hosts
counter in `store.go` all record the same reader-lock ceiling and the same
answer — and the first on the inspection path.

---

## Finding 1 — the scan-exclusion read path serialised on one word (FIXED)

**Severity.** Throughput ceiling on the SSL-inspection response path and on
every body scan, in the posture (no exclusions configured) that ~every
deployment runs.

**Root cause.** Two independent maps behind one `sync.RWMutex`, read at request
rate:

```go
func (s *Store) IsHostExcluded(host string) bool {
	if s == nil || host == "" {
		return false
	}
	host = hostutil.StripHostPort(host)   // ← paid even with nothing configured
	s.mu.RLock()                          // ← two atomic RMWs on one shared word
	defer s.mu.RUnlock()                  // ← plus a deferred unlock
	return s.hosts[strings.ToLower(host)] // ← case fold over the whole key
}
```

The package's own doc comment already identified the access pattern correctly
("an extreme read:write ratio… so it uses `sync.RWMutex` per the read-heavy
store convention"). The convention is the part that was wrong, and this tree had
already written down why three times: a read-heavy store whose readers are on a
per-request path wants an **immutable published view**, not a reader lock,
because a reader lock still costs a shared-word write per read.

**Fix.** Both maps are published as ONE immutable `view` behind
`atomic.Pointer[view]`. Readers take one atomic pointer load — a shared-line
*read*, which scales — and no lock. Writers build fresh maps and swap the
pointer; a published view is never mutated. `mu` survives, guarding only `path`
and serialising writers.

Two secondary consequences, both wanted:

- **The empty posture answers from a length check.** With nothing configured the
  function returns before `StripHostPort` and before `strings.ToLower`, which is
  what makes the first and third table rows total rather than incremental. That
  gate is held structurally by `TestEmptyPosture_AllocationFree`, an allocation
  budget, not a timing threshold.
- **The two lists are now atomically consistent with each other.** The two
  independent map fields could not promise that without the lock; one `view`
  does. No caller depended on it, so this is a strengthening, not a fix.

### Trade-offs, measured rather than asserted

- **A configured store is still 42 ns at P=1**, not 3.5 ns: it genuinely has to
  strip the port and fold the case before it can probe the map. The saving there
  is the lock (50.2 → 42.1 ns serial) and the scaling (0.29x → 3.3x). The large
  numbers belong to the default posture only, and the table says which is which.
- **One extra pointer indirection per read.** Measured as part of every row
  above; it does not show against what it replaces.
- **A write now allocates two maps instead of reusing none.** `Replace` and
  `Load` run when an admin edits the lists — a handful of times in a
  deployment's life. Garbage on a cold path bought a lock-free hot one.
- **No memory trade.** Unlike the 2026-11-15 pass's index, the view holds the
  same two maps that were there before; only their publication changed.

### How the change is held

- `TestLegacyStore_MatchesShipped` — the differential gate. `legacyStore` in
  `scanexcl_bench_test.go` is a **verbatim** copy of the pre-change RWMutex
  implementation, kept in-tree for the same reason `legacyRemoveHopHeaders` and
  `BenchmarkAddLegacyGate` are: the before/after comparison has to stay
  reproducible on hardware other than this box. Both arms are asked the whole
  corpus (case, surrounding space, ports, bracketed and bare IPv6, trailing
  dot, empty string, a digest in the wrong case, a truncated digest) under nine
  list configurations. It keeps its own state, so no arm can perturb the shipped
  `Store`, and it must **not** be "kept in sync" with `Store` — its value is
  that it does not move.
- `TestEmptyPosture_AllocationFree` / `TestConfiguredPosture_AllocationFree` —
  machine-independent allocation budgets on all five reachable read shapes.
- `TestPublishedViewIsNeverMutated` — pins the invariant the lock-free read
  rests on, by pointer identity *and* by content of a view captured before a
  `Replace`.
- `TestConcurrentReplaceAndRead` — 4 readers against 50 publishes, which is
  where a reintroduced unsynchronised map write is caught under `-race`.
- `TestZeroStore_UsableWithoutNew` — the zero `Store` must keep working, because
  `scan_host_ipv6_test.go` in package main constructs `&ScanExclusionStore{}`
  directly. A nil published pointer reads as the empty view.

### What this review could not measure

**The in-situ end-to-end delta.** One `IsHostExcluded` call is ~41 ns against a
CONNECT that this box serves in ~200 µs and a body scan that costs orders of
magnitude more than its own hash lookup, so the saving is **below the noise
floor of every end-to-end benchmark in the tree** and no claim is made that it
moves one. The claim is the one the three sibling fixes made: a non-scaling term
was removed from a per-request path, and the removal makes the code simpler
rather than more complex. A 16-/32-core appliance is where the 0.27x column
actually costs something, and this hardware cannot reach it.

---

## What was measured and found already appropriate

- **The plain-HTTP forward path.** `BenchmarkPerfQual_ProxyHTTPForward/rules=500`
  at `-memprofilerate=1`: 166 allocs/op end to end, of which Culvert's own code
  contributes four — `PolicyStore.Evaluate` (the `PolicyMatch` snapshot),
  `emitPolicyDecision` (the single `string(b)` conversion), `generateTraceIDs`,
  and one `Sprintf`. Everything else is `net/http` request/response parsing and
  `context` plumbing on one side of the loopback or the other. CPU: 13.2% of
  samples inside `handleRequest`, split `handleHTTP` 39% / `applyPolicyDecision`
  33% / `Evaluate` 17%. Nothing here is a defect; the path is at its floor.
- **The CONNECT establishment path.** `BenchmarkPerfQual_ProxyCONNECT/rules=100`:
  `handleTunnelBypass` is 46% dial, 18% write, 14% relay, 11% close. 45% of all
  allocated **bytes** on the path are `bufio.NewReaderSize`/`NewWriterSize`, and
  those are net/http's own per-connection buffers plus the benchmark client's —
  a per-connection cost on a benchmark that opens one connection per iteration,
  not a per-request one.
- **`internal/ca.GetCert`.** The leaf cache hit path is already a lock-free
  `sync.Map` load with the `net.SplitHostPort` allocation removed, and its
  single-flight collapses concurrent misses. Read in full; nothing to take.
- **`internal/sslbypass.Matches`.** Already has the empty-list fast path this
  finding adds to `scanexcl`, and already normalises the host once instead of
  per pattern. It is the pattern `scanexcl` now follows; the asymmetry between
  the two is what made the finding visible.
- **`internal/reqlog.Add`'s `ringMu`.** It *did* show up in this pass's CPU
  profile (66% of `Add`, 1.5% of all samples, as `sync.Mutex.Lock`), which is
  the trigger condition `ring_order_bench_test.go` wrote down for itself: "the
  sharded design IS the candidate to qualify if `ringMu` ever shows up in a real
  profile". Deliberately **not** taken here. That file's recommendation is
  explicit that a request-feed-ring rewrite must not ship on 4-vCPU evidence —
  the ordered alternative that wins costs 19–55% at one and two cores — and this
  box is still 4 vCPU. Recorded as confirmed-triggered, not acted on, and it
  needs its own pass on appliance hardware.
- **`internal/bandwidth`.** Token-bucket `AllowBytes` and `FindPolicy` look like
  data-plane code and are not: `bandwidth_health.go` already records that
  neither has a caller anywhere on the request path. Not a hot path, not
  touched.

## Benchmark plan — what should be measured next

- **This change on 16 and 32 cores.** The 0.27x→4.0x flip is the whole claim and
  four vCPUs is the narrowest hardware on which it can be stated. Re-run
  `go test -run XXX -bench 'BenchmarkIsHo|BenchmarkIsHa' -cpu=1,2,4,8,16,32
  -count=7 ./internal/scanexcl/` in one invocation and read the ratios, never
  the absolute nanoseconds.
- **A `-mutexprofile` over a live inspected-TLS run.** Every figure here is a
  microbenchmark. A mutex profile would attribute the removed lock-hold time to
  the waiting readers directly, as the 2026-11-10 pass did for `catdb`.
- **`internal/reqlog`'s sharded-ring arms on appliance hardware**, per the
  trigger above. That is the largest unclaimed scaling win the profiles found,
  and it is blocked on hardware, not on analysis.
- **An inspected-response end-to-end benchmark.** The tree has
  `proxy_tunnel_inspectbuf_bench_test.go` and `inspect_h2_perf_test.go` but no
  whole-path "decrypt → scan gate → deliver" arm, which is why this finding's
  in-situ effect could not be bounded from above as well as it was from below.

## Residual risk

- **The read path is now lock-free, so correctness depends on an invariant
  rather than on mutual exclusion.** A published view must never be written to.
  That is stated on the `view` type, held by
  `TestPublishedViewIsNeverMutated` and by `TestConcurrentReplaceAndRead` under
  `-race` — but a future writer that mutates `s.current()` in place instead of
  building a fresh view is a new class of bug this code did not previously
  admit.
- **The empty-posture gate is a behavioural shortcut, not just a faster path.**
  `IsHostExcluded` no longer calls `StripHostPort` when nothing is configured.
  Both are pure, so no decision changes; but a future change that gave
  `StripHostPort` a side effect (a counter, a cache warm) would silently lose it
  in the common posture.
- **`Load` and `Replace` still normalise differently** — `Load` lower-cases and
  keeps every entry, `Replace` also trims space and drops empties. That
  asymmetry predates this change and is preserved verbatim rather than fixed,
  because the file is written by `Save` from already-normalised keys and widening
  `Load` would change what a hand-edited file means. It is now documented on
  `Load` so the next reader does not take it for an oversight.
- **`Save` reads `path` and the lists under separate acquisitions.** Previously
  one `RLock` covered both. No caller sets a path and replaces lists
  concurrently (`Load` is startup, `Replace`+`Save` is one admin handler), so
  the window is unreachable today — but it is wider than it was.
- **`ringMu` is still there.** The largest scaling finding in this pass's
  profiles is recorded and deferred, exactly as the pass before it deferred
  `internal/authstate`.
