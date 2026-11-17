# Performance Guardian Review — 2026-11-17

**Scope.** `84b1b4c` (`origin/main`, clean tree at start of pass). Measured, not
read: every number below came from a benchmark run on this revision, on this
machine (Go 1.27.4, linux/amd64, 4 vCPU Xeon @ 2.30 GHz), with both arms of each
comparison compiled into **one binary** so the A/B is not two runs stitched
together.

**Question asked.** The 2026-11-16 pass found that `scanexcl.Store.IsHostExcluded`
— called for every response on the SSL-inspection path — took a process-wide
reader lock to ask an empty map a question, and fixed it with an atomically
published view. That was the fourth instance of one defect class: `internal/threatfeed`,
`internal/connlimit`, the IP filter and the top-hosts counter had each already been
found taking `sync.RWMutex.RLock` on a per-request read of state that in steady
state never changes.

Four instances of one shape is not a coincidence, it is a **search pattern**. So
this pass did not start from a profile. It enumerated every remaining
synchronous call on a per-request path that reads operator-configured state, and
asked of each one: *does a read here write to a word that all cores share?*

One did, and it was the one the product's own source comments had twice
described as cheap.

**Outcome: one optimization, measured, shipped and gated. The finding is novel —
no prior pass mentions this owner.**

---

## Executive Summary

**The gate that exists to protect a degraded node was itself a throughput
ceiling on the degraded node.**

`alerts.Store.HasSubscriber` answers "will firing this event reach anyone?", so
that a producer can skip the goroutine spawn, the payload allocation and the
round trip through the process-wide dedup mutex needed to deliver an alert to
nobody. That gate is correct, deliberate and worth keeping. The product
documents why in two places, and both say the check itself is cheap:

- `internal/alerts/store.go`, on `HasSubscriber`: *"Cheap: one RLock, no allocation."*
- `store.go`, on the block path that calls it: *"The gate is a pure fast path."*

It was neither. `sync.RWMutex.RLock`/`RUnlock` are two atomic
**read-modify-WRITES on one shared word**, so every call wrote the same cache
line purely to read a webhook list that changes only when an operator edits it.
That is not a constant cost but a process-wide **throughput ceiling** — and
`hostCounter` in `store.go` already carried the refutation in-tree, verbatim:
*"It used to take mu.RLock around the map read, on the reasoning that a reader
lock is cheap. It is not."*

The reasoning had been written down, measured, and recorded as a lesson. It had
simply never been applied here.

### Why this call site is the bad one

Every producer behind this gate is **fault-driven** — its rate is set by an
attack or an outage, not by an operator. `internal/alerts/alerts.go` says so
itself: *"producers whose rate is set by a FAULT rather than by the operator must
gate, because the fault puts every request on that path."*

| producer | gated event | rate |
|---|---|---|
| `recordStats` (`store.go:2804,2810`) | `threat_detected`, `policy_block` | per **blocked** request |
| `fireDNSFailureAlert` (`alerts.go:104`) | `dns_failure` | per request, from **four** dial sites (`proxy_http.go:228`, `proxy_tunnel.go:107,580,788`) |
| `internal/secscan` (`remote.go:229`, `secscan.go:1640`) | `scan_skipped`, `scan_clam_error` | per oversized body / per scan error |
| `cdr_proxy.go:607` | `cdr_unavailable` | per CDR submission |

So the contention did not land during ordinary browsing. It landed during a
scanning or beaconing flood (when nearly every request is blocked), during a
DNS outage (when every request takes a dial-failure path), and during a scanner
outage. Precisely when the node is already degraded and has least headroom —
which is the exact scenario the gate was introduced to protect.

### Measured

n=5, medians, ns/op, `RunParallel` so ns/op is wall time per op across all
workers: a genuinely parallel read **falls** as cores are added, one that
serialises **rises**.

| case | impl | P=1 | P=2 | P=4 | 1→4 throughput |
|---|---|---|---|---|---|
| no hooks (**default posture**) | RWMutex | 13.07 | 96.35 | 101.70 | **0.13x** |
| | published index | 2.06 | 1.02 | 0.52 | **4.00x** |
| 3 hooks, subscribed (hit) | RWMutex | 13.87 | 122.30 | 129.50 | **0.11x** |
| | published index | 7.76 | 3.66 | 1.82 | **4.27x** |
| 5 hooks, not subscribed | RWMutex | 17.76 | 163.60 | 193.80 | **0.09x** |
| | published index | 9.08 | 4.54 | 2.28 | **3.98x** |
| 50 hooks, not subscribed | RWMutex | 200.80 | 352.20 | 335.10 | **0.60x** |
| | published index | 9.17 | 4.63 | 2.30 | **3.98x** |

Read the last column first, because it is the finding. **Under the RWMutex, four
cores delivered a ninth of one core's throughput**: adding hardware made the
check slower in absolute terms, from 13 ns to 102 ns. The index scales at ~4x on
4 cores. At P=4 the default posture is **197x** faster; the subscribed-hit case
**71x**.

The worst arm was the **default posture — zero webhooks configured** — where
every blocked request paid two atomic RMWs to iterate an empty slice and return
false. That default is also the state of every test binary in the tree.

---

## Finding 1 — `HasSubscriber` serialised on one word (FIXED)

### Root cause

A reader lock was used to protect state with a read:write ratio set by traffic
volume on one side and by human admin edits on the other. `RLock` is the wrong
primitive for that ratio not because it is slow but because it **writes**: all
cores contend for one cache line, so the cost grows with core count instead of
staying flat.

A second, independent defect sat underneath it. The scan was
`O(hooks × events)` and **ran to completion on a miss** — a miss being the
common answer, since a webhook subscribed to `cert_expiry` is asked about
`policy_block` on every blocked request. The 50-hook row shows what that cost:
200.8 ns at P=1, fifteen times the one-hook cost. An operator fanning alerts to
a large collector set was paying for their own fan-out on the block path.

### The fix

The answer is a pure function of the hook set, and the hook set is written only
by admin CRUD and startup load. So it is computed once per mutation and
published as an **immutable value** behind an `atomic.Pointer`:

```go
type subscriptions struct {
	catchAll bool                // some enabled hook subscribes to "*"
	events   map[string]struct{} // union of the enabled hooks' event names
}
```

A steady-state read is one atomic pointer **load** — no read-modify-write on any
shared word, nothing for cores to contend over — plus a bool test and at most
one lookup in a small map. `catchAll` is hoisted out of the map so a catch-all
store answers with no lookup at all (0.33 ns at P=4). Complexity in the hook
count goes from `O(hooks × events)` to `O(1)`.

`mu` still owns `hooks` and is still the only way to mutate it. It is simply no
longer taken by the read path.

### Trade-offs, measured rather than asserted

- **At P=1 with a handful of hooks the win is only ~2x** (13.87 → 7.76 ns), because
  an uncontended `RLock` is genuinely cheap and a map lookup is not free. The case
  for this change is the concurrency curve, not the single-core constant. Stated
  in the source comment too, so a future reader is not misled by the 197x.
- **Mutation now costs an O(hooks × events) derivation plus one small allocation**,
  under the write lock. That is operator-paced — `Add`/`Update`/`Delete` already
  fsync to disk, which is orders of magnitude more expensive — so it is free in
  any sense that matters.
- **Memory**: one small map per store, rebuilt per mutation. Bounded by the
  configured webhook count, which is admin-controlled, not attacker-controlled.
- **Deliberately not** a lazily invalidated cache. That would put the derivation
  back on the request path under exactly the conditions this change exists to
  fix. Republication is eager and synchronous with the mutation.

### Risk, and what carries it

The failure mode that matters is **not** slowness, it is a **stale index
silently unsubscribing a configured webhook**. Nothing in the product reports an
alert that was skipped, so that failure is silent, which makes it a security
property rather than a tidiness one. Two things hold it:

- `TestSubscriptionIndexMatchesScan` / `TestSubscriptionIndexEveryEventName` — the
  **differential oracle**. `hasSubscriberScan` in `subscriptions_test.go` is a
  verbatim copy of the pre-change implementation, kept in-tree for the same
  reason `legacyStore` and `legacyRemoveHopHeaders` are: it must **not** be "kept
  in sync" with the shipped code — its whole value is that it does not move. 16
  hook configurations are asked, each against every event name mentioned anywhere
  in it plus five probes, including the two queries that probe the catch-all
  encoding itself (asking for `"*"` when no hook has it, and when one does — the
  one place a union-set rewrite could plausibly diverge).
- `TestSubscriptionIndexRepublishedOnMutation` — the **arming contract**: `Add`,
  `Update` (including the enable→disable transition) and `Delete` must each leave
  an index that reflects the write. This test **found a real gap during this pass**:
  `Init` returns early when no `alert_webhooks.json` exists, so the fast path was
  left unarmed in the default posture — the single case that matters most. Fixed by
  publishing on every `Init` exit, with disk I/O still off `mu`.

Also: `TestSubscriptionIndexInitMalformedFileArms` (a partial `json.Unmarshal` can
leave `hooks` half-written, so `Init` republishes via `defer`),
`TestSubscriptionIndexConcurrentReadsDuringMutation` (4 readers against 50
add/update/delete cycles — where a reintroduced unsynchronised write is caught
under `-race`), and `TestSubscriptionIndexArmRaces`.

The pre-existing contract test `TestHasSubscriber` was left **untouched** — it
constructs `&Store{hooks: ...}` directly, and a nil published pointer is handled
by arming it, so that construction answers exactly as it always did.

### What this review could not measure

**The in-situ end-to-end delta.** One `HasSubscriber` call is ~13 ns against a
CONNECT this box serves in ~200 µs, so the saving is **below the noise floor of
every end-to-end benchmark in the tree**, and no claim is made that it moves one.
The claim is the one the four sibling fixes made: a non-scaling term was removed
from a fault-driven per-request path, and the removal made the code simpler
rather than more complex.

**The core count where it actually costs.** The 0.09x column is measured on 4
vCPUs. A 16- or 32-core appliance is where a contended cache line genuinely
hurts, and this hardware cannot reach it. The direction of the curve is the
evidence, not its magnitude on this box.

**Contention under a real flood**, as opposed to a benchmark loop. The benchmark
is a tight loop on one function and therefore an upper bound on the contention
share; a real blocked request does other work between calls.

---

## What was measured and found already appropriate

- **`handleRequest`'s front door** (`proxy.go:1553`) — the raw and canonical
  destination-host pre-caps, `connLimiter.Acquire`, `ipf.Allowed`, `rl.AllowAuto`.
  Every one of these is already either sharded, atomic or a published immutable
  view, and each carries its measurement in-tree. Nothing left to take.
- **Policy evaluation** (`policy.go:1693` `evalAccessRules`) — operates on a
  published `[]*PolicyRule` snapshot with a documented zero-alloc contract, a
  `scheduleClock` memo and a `hostCatScratch` reused across conditions. The
  `//nolint:gocognit` on it is explicit that the zero-alloc contract forbids
  extraction. Correctly left alone.
- **`persistLogEntry`** (`store.go:2933`) — one clock read per record, the
  human-readable stamp memoised per wall-clock second, destination pseudonymised
  once and threaded into the URI redactor so the HMAC runs a single time. Already
  allocation-free on the per-request path.
- **`topHosts.Record`** — `sync.Map` fast path, no lock on the tracked-host path.
  Fixed by an earlier pass; its measurement table is what made this pass's search
  pattern obvious.
- **In-function `regexp.Compile`** — swept the whole tree. Every hit is either
  package-level (`var` block), in `third_party/saml` on the login path (not
  per-request), or in a rule/config **compile** step rather than a match step.
  No per-request recompilation found.

## Benchmark plan — what should be measured next

1. **The remaining `Dispatch` path.** `Store.Dispatch` still takes `mu.RLock` and
   **copies the whole hook slice** per fire. It is behind the gate this change
   made cheap, and it already runs in a detached goroutine, so it is not on the
   request path — but under a flood with one webhook configured, the gate now
   passes and every blocked request allocates a `[]Webhook` copy. Worth measuring
   before assuming the dedup mutex absorbs it.
2. **`alertStore()` + probe indirection.** `internal/*` producers reach the store
   through an `atomic.Pointer` probe holding a `*SubscriberProbe` — a double
   indirection plus a closure call per check. Cheap, but now a measurable share of
   a 2 ns read.
3. **A 16-core run of this pass's benchmarks**, on hardware that can actually show
   the ceiling the 0.09x column implies.

## Residual risk

- **The nil-pointer fallback is a correctness escape hatch, not a fast path.** An
  unarmed store answers correctly but pays a one-off write lock. Production arms
  at `Init` on every exit; the arming tests exist so that can never silently
  regress into being the production path.
- **A future mutation site added to `Store` that forgets `publishSubscriptionsLocked`
  would publish a stale index.** `hooks` is unexported so this is confined to the
  package, and the arming test covers all four current sites — but it is an
  invariant held by a convention plus a test, not by the type system. A reviewer
  adding a mutator must add a republish. Recorded in the field comment.
- **This pass changed no contract code path** (`contractcheck impact` reports
  none) and no API, UI, audit or persistence behavior. The on-disk
  `alert_webhooks.json` format is untouched.
