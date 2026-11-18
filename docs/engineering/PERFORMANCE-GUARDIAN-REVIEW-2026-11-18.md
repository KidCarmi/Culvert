# Performance Guardian Review — 2026-11-18

**Scope.** `348a2cf` (`origin/main`, clean tree at start of pass). Measured, not
read: every number below came from a benchmark or a profile run on this revision,
on this machine (Go 1.27.4, linux/amd64, 4 vCPU Xeon @ 2.10 GHz). Where a
before/after is claimed, **both arms were compiled into one binary** — the
`_Legacy` functions in `internal/alerts/dedup_alloc_bench_test.go` keep the
pre-change implementation alive as a negative control, so the A/B is re-runnable
rather than a frozen number.

**How this pass started.** Not from a hypothesis. From two profiles of the real
`handleRequest` dispatch (`BenchmarkPerfQual_ProxyHTTPForward/rules=100`:
198 µs/op, 13.8 KB/op, 166 allocs/op; `BenchmarkPerfQual_ProxyCONNECT/rules=100`:
250 µs/op, 21.4 KB/op, 131 allocs/op) plus the follow-up the 2026-11-17 pass
nominated in writing. The profiles found nothing left to take on the allowed
path — the detail is under "What was measured and found already appropriate" —
so the finding came from the nominated item, and it came back **with its premise
corrected**.

**Outcome: one optimization, measured, shipped and gated. One prior
nomination closed as a non-finding, with the measurement that closes it.**

---

## Executive Summary

**An alert the dedup window was about to drop still paid two heap allocations and
a process-wide mutex round trip to discover that.**

Yesterday's pass fixed `HasSubscriber`, the gate that decides whether firing an
event will reach anyone. It then nominated the next thing behind that gate:

> `Store.Dispatch` still takes `mu.RLock` and **copies the whole hook slice**
> per fire. […] under a flood with one webhook configured, the gate now passes
> and every blocked request allocates a `[]Webhook` copy. Worth measuring before
> assuming the dedup mutex absorbs it.

Measuring it refuted the model. **The gate passing does not mean the copy
happens**, because the *dedup check sits between them* — and under a flood the
dedup check is precisely what returns early. The hook copy is on the far side of
a branch a flood almost never takes. The cost was in the branch the flood *does*
take, and it was the cheap-looking one.

### Why suppression is the common answer, not the rare one

This is the whole finding, so it is worth being exact. Every producer that
reaches `Dispatch` at request rate is **fault-driven** — its rate is set by an
attack or an outage, not by an operator — and every one of them puts a
**low-cardinality** value in `Detail`:

| producer | event | `Detail` | cardinality under load |
|---|---|---|---|
| `recordStats` (`store.go:2804`) | `policy_block` | `ruleMatched` | one rule name |
| `recordStats` (`store.go:2798`) | `threat_detected` | `ruleMatched + " " + actionTaken` | one feed source + reason |
| `fireDNSFailureAlert` (`alerts.go:104`) | `dns_failure` | a bounded reason class (CHAOS-64) | ~a handful |
| `internal/secscan` | `scan_skipped`, `scan_clam_error` | scan source / error class | ~a handful |

The dedup key is `event + ":" + Detail` and the window is 30 s. So a scanning
flood against one policy rule produces **one key**, and after the first dispatch
every subsequent one in the window is suppressed *by construction*. At 10 k
blocked requests/s, 299,999 of every 300,000 dispatches in a window exist only
to discover they have nothing to do.

That is the branch that was paying:

- **`payload.Timestamp` was defaulted BEFORE the dedup gate.** A dispatch about
  to be dropped formatted an RFC3339 stamp — ~121 ns and one 24-byte allocation
  — that nothing would ever read. Not a scaling problem; pure waste, on the one
  path where the node has least headroom.
- **The dedup key was built by the caller as `event + ":" + payload.Detail`** — a
  32-byte heap allocation created only to be *looked up* and thrown away.

### Measured

n=5, medians, ns/op, `RunParallel` so ns/op is wall time per op across all
workers.

| case | impl | P=1 | P=2 | P=4 | allocs |
|---|---|---|---|---|---|
| **`Dispatch`, suppressed** | legacy | 240.5 | 286.1 | 360.0 | **2 / 56 B** |
| | now | **91.3** | **131.0** | **217.0** | **0** |
| dedup check alone | legacy | 116.3 | 151.3 | 266.2 | 1 / 32 B |
| | now | 93.0 | 131.4 | 195.4 | 0 |

**2.6x at P=1, 2.2x at P=2, 1.7x at P=4, and the allocation rate of the whole
suppressed path goes to zero.** The allocation column is the part that matters
most: these dispatches run on detached goroutines, so their only lasting cost is
the garbage they leave behind for the collector to mark — and it is left behind
at per-blocked-request rate during exactly the event the alert exists to report.

---

## Finding 1 — the suppressed dispatch paid for work it threw away (FIXED)

### Root cause

Two unrelated mistakes that happened to land on the same four lines, both of the
same *kind*: a cost placed where the answer does not need it.

1. **An ordering mistake.** `payload.Timestamp` is only meaningful to a payload
   that gets delivered. Defaulting it ahead of the gate charged the stamp to the
   dispatches that never would be.
2. **A signature mistake.** `dedupSuppressed(dedupKey string)` forced its caller
   to materialise a string on the heap. The function only ever *hashes* that
   string. Go's compiler can hash bytes in place for `m[string(b)]` — but only if
   the bytes are in hand, which an already-joined string parameter forbids.

### The fix

```go
// Dispatch
if as.dedupSuppressed(event, payload.Detail) {   // gate first
    return
}
if payload.Timestamp == "" {                     // stamp only what ships
    payload.Timestamp = time.Now().UTC().Format(time.RFC3339)
}
```

```go
// dedupSuppressed — renders the key before taking the lock, so the lock hold
// does not grow to pay for it.
var scratch [dedupKeyScratch]byte
key := append(scratch[:0], event...)
key = append(key, dedupKeySep)
key = append(key, detail...)
...
if last, ok := as.dedupMap[string(key)]; ok && now.Sub(last) < dedupTTL {
    return true          // no allocation: hashed in place
}
dedupKey := string(key)  // the ONE conversion, only for an admitted dispatch
as.dedupMap[dedupKey] = now
```

Confirmed at the compiler rather than asserted —
`go build -gcflags=-m ./internal/alerts/`:

```
store.go:887:36: string(key) does not escape     ← the suppressed lookup
store.go:893:21: string(key) escapes to heap     ← the admitted insert
```

An admitted dispatch is about to do at least one HTTPS POST, next to which one
32-byte string is nothing.

**The key bytes are unchanged.** Event names are validated to `[a-z0-9_]` plus
the `*` catch-all (`ValidateEventNames`), so `:` cannot appear in the left half
and one `(event, detail)` pair maps to exactly one key. That matters because the
joined spelling is load-bearing outside this function: the CHAOS-27 regression
tests index `dedupMap` by it.

### Trade-offs, measured rather than asserted

- **The scratch is zeroed on every call**, and that cost is linear in its size:
  measured at 6.7 ns (64 B), 8.1 ns (128 B), 11.8 ns (320 B), 26.4 ns (1024 B)
  for the same three appends. Sizing it for the theoretical maximum
  (`maxEventNameLen` + separator + a 253-byte FQDN detail = 318) would therefore
  **tax every dispatch to spare the rare one**. `dedupKeyScratch` is 128, which
  covers every key the request-rate producers above actually build.
- **A longer key is not truncated** — truncation would make two distinct floods
  share one suppression window and *silence a real alert*, which is the failure
  direction that matters. It spills to the heap for one allocation, i.e. exactly
  what the old code charged *every* dispatch. The uncommon case is never worse
  than the status quo.
- **At P=1 the dedup check alone improves only 1.25x** (116.3 → 93.0 ns). Most of
  the headline 2.6x is the timestamp, not the key. Said plainly here and in the
  source so a future reader is not misled by the larger number.
- **Mutation cost: none.** Nothing about the admitted path, the TTL, the
  `maxDedupEntries` cap, the amortised expiry scan or the eviction policy changed.

### Risk, and what carries it

The failure mode that matters is not slowness, it is **a key-encoding change
silently merging or forking suppression windows**. Merging two keys silences a
real alert; forking one defeats the dedup and floods the retry queue, where it
evicts real threat alerts (the WK-12/RS-5 defect). Both are security properties,
not tidiness ones. Four things hold it:

- `TestDedupKeyEncodingUnchanged` — the **differential oracle** on the encoding.
  Seven shapes, each asserting the map is keyed by the literal
  `event + ":" + detail` and holds exactly one key: an empty detail, the `*`
  catch-all event, and a detail that itself contains `:` (the one input where a
  separator-based encoding could plausibly diverge).
- `TestDedupSuppressedKeyLongerThanScratch` — the **spill path**: two keys
  differing only in their final byte, both past the scratch, must not share a
  window.
- `TestDedupSuppressedHitIsAllocationFree` and
  `TestDispatchSuppressedIsAllocationFree` — the **arming contract** for the
  allocation claim. A change that reintroduces a string conversion on the read
  path is correct and memory-safe and silently restores the allocation rate; only
  these tests distinguish the two.
- `TestDispatchSuppressedAllocationFree_LegacyIsNot` — the **negative control for
  the control**. It asserts the pre-change shape *did* allocate ≥2 times, so a
  future reader can see the gate measures a real difference rather than a
  tautology, and so a toolchain change that folds the legacy arm is caught
  instead of quietly flattering it. (That exact failure happened during this
  pass: the first `KeyOnly` benchmark pair concatenated two *constants*, which
  the compiler folded at compile time, and the legacy arm reported 84 ns and
  **zero** allocations. The inputs are now variables.)

The reordering has its own two gates, both observing the payload with **no
network at all** — by saturating `webhookSem`, which sends `Dispatch` down its
`default:` branch into `enqueueRetry` synchronously on the calling goroutine.
That is a real production branch (a saturated delivery semaphore), not a
test-only seam: `TestDispatchStampsTimestampOnDeliveredPayload` (a delivered
payload still carries a parseable RFC3339 stamp) and
`TestDispatchPreservesCallerTimestamp` (the default stays a *default* — a
producer that stamped its own payload, as the retry replay does, gets its value
through untouched).

### What this review could not measure

- **The in-situ end-to-end delta.** One suppressed dispatch saves ~150 ns against
  a request this box serves in ~200 µs, so the saving is **below the noise floor
  of every end-to-end benchmark in the tree**, and no claim is made that it moves
  one. The claim is narrower and checkable: a per-blocked-request path went from
  two heap allocations to zero.
- **GC pressure under a sustained real flood.** The allocation *rate* removed is
  measured; its effect on pause times at production block volume is not, because
  this harness cannot generate that volume.
- **The core count where the residual mutex actually costs.** The P=4 column is
  4 vCPUs. A 16- or 32-core appliance is where a contended cache line hurts.

---

## Non-finding 1 — the per-fire hook-slice copy: measured, and it is noise

Recorded because the 2026-11-17 pass nominated it by name and because the
measurement **corrects that pass's model**, not merely its priority.

`Dispatch` copies the whole `[]Webhook` under `mu.RLock` on every admitted fire.
Measured in isolation:

| hooks configured | ns/op | B/op | allocs/op |
|---|---|---|---|
| 1 | 116 | 128 | 1 |
| 5 | 700 | 640 | 1 |
| 50 | 6 100 | 6 144 | 1 |

**No change is proposed**, for two reasons in order:

1. **It is on the far side of the dedup gate.** The nomination reasoned that
   because `HasSubscriber` now passes, "every blocked request allocates a
   `[]Webhook` copy". It does not: the dedup check runs first, and under the
   flood that motivated the concern it returns early. The copy is paid per
   *admitted* dispatch — at most once per key per 30 s window.
2. **An admitted dispatch is about to do network I/O.** Each matching hook gets
   an SSRF-guarded HMAC-signed HTTPS POST, which is milliseconds. 116 ns beside
   that is ~0.01 %; even the 50-hook case (6 µs) is noise beside 50 POSTs. The
   50-hook row is also not latency an operator feels, because the whole fan-out
   is already bounded by the 10-slot `webhookSem`.

Optimizing it would be complexity spent on a term three to four orders of
magnitude below the thing it sits next to. Closed.

## Non-finding 2 — the dedup mutex still does not scale, and is left alone

Visible in this pass's own table: the dedup check is 93.0 ns at P=1 and 195.4 ns
at P=4, so four cores deliver **under half** of one core's throughput. That is
the same shape `subscriptions.go` records, one layer deeper, and it is the fifth
sighting of the class.

It is nonetheless **deliberately not fixed here**, and the reasoning is
different from the four fixes before it:

- **It is not on the request goroutine.** Every producer reaches `Dispatch`
  through `go fireAlert(...)`. The cost is CPU and scheduler pressure, not
  request latency — materially weaker than the `HasSubscriber` case, which was
  synchronous on the blocked request.
- **Sharding buys nothing in the case that matters.** Hashing the key across N
  mutexes removes contention between *distinct* keys. A flood collapses onto
  **one** key and therefore one shard, so the regime this would exist to fix is
  exactly the regime it cannot help.
- **A lock-free rewrite is the only shape that would work**, and the dedup map is
  written on every *admitted* dispatch — the state genuinely mutates, so the
  published-immutable-view pattern that fixed the other four does not transfer.

Per the standing rule that complexity needs a measurement to justify it, this
stays recorded rather than attempted. The benchmarks are in-tree so the next
pass starts from numbers.

---

## What was measured and found already appropriate

Profiled, not read. `BenchmarkPerfQual_ProxyHTTPForward/rules=100` over 34,006
requests with CPU and allocation profiles; the Culvert-owned share is ~6 % of
total CPU (the rest is `net/http` client, server and the in-process backend).

- **`emitPolicyDecision` / `logPolicyAllow`** (1.50 % of total CPU, the largest
  Culvert-owned item on the allowed path) — already a hand-rolled append-based
  builder into a `[policyLineBufSize]byte` frame scratch, and 80 ms of its 170 ms
  is the sink write itself, which `internal/logsink` already made asynchronous
  and batching. Nothing left to take.
- **`generateTraceIDs` / `setupRequestTracing`** (0.53 % / 0.97 %) — one CSPRNG
  draw and **one** allocation for both IDs, with the separate-generator shape
  kept in-tree as a control (222.7 ns / 2 allocs vs 186.3 ns / 1 alloc). Already
  the optimum of its shape.
- **`PolicyStore.Evaluate`** (0.97 % CPU) — allocates exactly one `*PolicyMatch`
  per matched request; `copyPolicyRuleForPublication`'s nested deep copies fell
  below the profile's 3 MB cut-off entirely. The structural question (a 632-byte
  detached snapshot per match) was measured and closed as a deliberate security
  contract by the 2026-11-08 pass; not re-litigated.
- **`internal/pseudonym.Pseudonymize`** — pooled key-bound HMAC with per-hasher
  scratch, published key state behind an `atomic.Pointer`, one allocation (the
  token). A memo cache would trade a plaintext→token map in memory for ~200 ns,
  which is the wrong trade for the control pseudonymisation exists to provide.
- **`internal/realclientip.Resolver.ClientIP`** — takes `mu.RLock` per call, the
  same class as this sweep's four fixes, but it serves only **admin-plane** per-IP
  decisions (login lockout, admin-API rate limit, UI allowlist). Operator-paced
  request rate; the contention shape has no load to express it. Correctly left.
- **`internal/blocklist.IsBlocked`, `internal/ca.Manager.GetCert`** — both already
  lock-free published-view reads with in-tree allocation-regression tests and
  legacy controls (`referenceIsBlocked`, `certcache_lockfree_test.go`).
- **Background tickers** — all 40 enumerated. The two sub-second ones
  (`proxy_tunnel_drain.go` at 10 ms, `main_shutdown.go` at 500 ms) are
  **shutdown-only**; no per-connection or per-request ticker exists. No ticker
  abuse or polling loop found.

## Benchmark plan — what should be measured next

1. **`alertStore()` + probe indirection** (carried forward from 2026-11-17,
   still unmeasured). `internal/*` producers reach the store through an
   `atomic.Pointer` holding a `*SubscriberProbe` — a double indirection plus a
   closure call per check. Now a measurable share of a ~2 ns read.
2. **A realistic-posture e2e profile.** Every end-to-end benchmark in the tree
   configures an **empty** blocklist, no threat feed, no plugins and no auth
   backend, so the profiles above under-represent a real deployment. A harness
   with a loaded feed and authentication enabled would profile a different
   function set — that is the most likely place an unswept cost remains.
3. **A 16-core run** of this pass's and 2026-11-17's benchmarks, on hardware that
   can show the ceiling the P=4 columns only imply.

## Residual risk

- **`dedupKeyScratch` is a performance choice sitting next to a correctness
  boundary.** 128 was chosen from a measurement of today's producers' `Detail`
  values. A future producer that puts a long attacker-influenced string in
  `Detail` would spill every time — no worse than before this change, but the win
  would be lost silently, because nothing reports the spill rate.
- **The allocation claim is held by `AllocsPerRun` tests, not by the type
  system.** A refactor that reintroduces a string conversion on the read path is
  a legal, memory-safe change. The arming tests and their negative control are
  what make it loud.
- **The reordering is safe because `payload` is a by-value copy and `Dispatch` is
  its only writer** — verified by inspection at this revision. A future change
  that takes `*Payload`, or that reads `payload.Timestamp` between the gate and
  the stamp, breaks that reasoning without breaking a test.
- **This pass changed no contract code path** (`contractcheck impact -base
  origin/main` reports none) and no API, UI, audit or persistence behavior. The
  on-disk `alert_webhooks.json` and retry-queue formats are untouched.
