# Performance Guardian Review — 2026-11-21

**Scope.** `ef94311` (`origin/main`, clean tree at start of pass). Measured, not
read: every number below came from a benchmark or a profile run on this revision,
on this machine (Go 1.27.4, linux/amd64, 4 vCPU Xeon @ 2.10 GHz). Where a
before/after is claimed, **both arms are compiled into one binary** —
`BenchmarkFeedCheckRequestURL_MissLegacy` keeps the pre-change call shape alive
as a negative control, and `TestCheckRequestURL_AllocationFree_LegacyIsNot`
keeps the pre-change *body* alive as the baseline the allocation gate is
measured against — so the A/B is re-runnable rather than a frozen number.

**How this pass started.** From the second item on 2026-11-18's written
benchmark plan, in its own words:

> **A realistic-posture e2e profile.** Every end-to-end benchmark in the tree
> configures an **empty** blocklist, no threat feed, no plugins and no auth
> backend, so the profiles above under-represent a real deployment. A harness
> with a loaded feed and authentication enabled would profile a different
> function set — that is the most likely place an unswept cost remains.

It was right, and the harness is the finding's instrument rather than a
by-product: building it is what turned "the empty posture probably hides
something" into a number.

**Outcome: the deployed content posture now costs ZERO additional allocations
per allowed plain-HTTP request, down from two. One optimization, measured,
shipped and gated; one new e2e harness; two items nominated with their
measurements.**

---

## Executive Summary

**Turning on the threat feed used to cost two heap allocations on every allowed
request. It now costs none, and the end-to-end benchmark can prove it.**

The 2026-11-18 pass profiled `handleRequest` and found nothing left to take.
Both of its profiles ran against `benchProxySetup`, which is the tree's only
end-to-end proxy harness, and which configures `bl = blocklist.New()` with zero
entries and a process-wide threat feed that has never been enabled. Under that
posture both content gates answer from a short-circuit — `blocklist.IsBlocked`
returns on `len(m) == 0`, and `secscan.Enabled()` is false, so `CheckDomain` and
`CheckRequestURL` are *never reached at all*. A deployed gateway runs neither
short-circuit, so a whole band of per-request code had never appeared in a
profile.

`BenchmarkPerfQual_ProxyHTTPForwardPosture` (new) runs one identical request
through the real `handleRequest` under both postures, with the posture as the
**only** variable, and measures the band:

| | ns/op | B/op | allocs/op |
|---|---|---|---|
| `posture=empty` | 136 984 – 153 929 | 14 172 – 14 195 | **170** |
| `posture=loaded` **(before this change)** | 151 207 – 192 441 | 14 281 – 14 297 | **172** |
| `posture=loaded` **(after)** | 137 458 – 165 741 | 14 168 – 14 176 | **170** |

Loading a 110 000-entry blocklist and an enabled 100 000-entry threat feed is
now allocation-neutral on the allowed request path. Wall time is **not** claimed
to move: the saving is ~150 ns against a request this box serves in ~150 µs, so
it is two orders of magnitude below the harness's own spread, and the table above
shows the postures overlapping in every timing column both before and after. The
claim is the narrower, checkable one — a per-request path went from two heap
allocations to zero.

### Where the two allocations were

Both were in `threatfeed.normaliseParsedURL`, the per-request derivation of the
full-URL lookup key, which `preDispatchBlocked` reaches on every forwarded
plain-HTTP request, on the request goroutine, **before the policy engine**. The
allocation profile attributes them exactly (3 000 000 ops,
`-sample_index=alloc_objects`):

```
3203267 48.04%  threatfeed.normaliseParsedURL      ← the key, one concatenation
2960177 44.39%  net/netip.parseIPv4Fields          ← net.ParseIP's FAILURE path
```

1. **`net.ParseIP(host)` allocates to report that an ordinary hostname is not
   an IP address.** `netip.ParseAddr` builds a `parseAddrError` for every string
   that is not an address, and the call site asks "is this destination a private
   IP?" about a value that is almost always a hostname. 48 bytes, every request.
2. **The canonical key was built on the heap only to be looked up and thrown
   away.** `scheme + "://" + host + path` is a 64-byte allocation whose sole
   consumer is `v.urls[normURL]`.

### Measured

n=5, medians, `./internal/threatfeed/`. `CheckDomain` is the standing control
and the whole argument: it does the same *kind* of work — canonicalise a host,
probe one map — and has cost ~95 ns at zero allocations since 2026-11-17.

| case | before | after | delta |
|---|---|---|---|
| `CheckRequestURL` miss, serial | 265 ns, 112 B, **2 allocs** | **177 ns, 0 B, 0 allocs** | **1.50x, −112 B** |
| `CheckRequestURL` miss, 4 workers | 93 ns, 112 B, **2 allocs** | **49 ns, 0 B, 0 allocs** | **1.90x** |
| `CheckURL(u.String())` (legacy arm) | 722 ns, 336 B, 4 allocs | 668 ns, 288 B, 3 allocs | −1 alloc |
| `CheckDomain` miss (control) | 95 ns, 0 B, 0 allocs | 95 ns, 0 B, 0 allocs | unchanged |

The legacy arm improving by one allocation is not incidental — it is the
**ingest** path. `NormaliseURL` runs once per feed row, ~100 000 times per sync
round for urlhaus alone, and it carried the same ungated `net.ParseIP`.

**Scaling.** `BenchmarkFeedCheckRequestURL_MissAtScale` reports 43–47, 42–44 and
42–44 ns/op at 1x, 2x and 4x GOMAXPROCS workers: flat, because this is a
lock-free read of a published view (`readView`) and always was. This change did
not alter the concurrency contract and makes no scaling claim; the arm exists so
that a future change which *does* regress it is caught.

---

## Finding 1 — the per-request URL key allocated twice for a verdict that needed
neither (FIXED)

### Root cause

Two mechanisms, recorded as **one concern** because they are one function, one
path and one kind of mistake — a cost placed where the answer does not need it —
and because the fix is one 90-line diff in one file with one before/after table.
(The 2026-11-18 pass made the same call for the same reason: "two unrelated
mistakes that happened to land on the same four lines, both of the same *kind*".)

1. **An allocation used as a return value.** `net.ParseIP`'s contract is
   `nil`-on-failure, but its *implementation* reports failure by constructing an
   error. A caller asking a yes/no question pays for a diagnostic it discards.
   This observation is already recorded one layer down, in
   `internal/hostutil`'s `NormalizeHostStrict` fast path — "net.ParseIP
   allocates on its FAILURE path (it builds a netip parse error for every non-IP
   string)" — and this is that observation applied to the two call sites in
   `internal/threatfeed`.
2. **A string materialised for a map index.** Go hashes bytes in place for
   `m[string(b)]`, but only when the conversion *is* the index expression. A key
   already joined into a `string` forbids that.

### The fix

```go
// couldBeIPLiteral MIRRORS netip.ParseAddr's own dispatch loop: ':' first →
// parseIPv6 (admit), '%' first → error (refuse), '.' first → parseIPv4, which
// accepts only digits and dots, none of the three → error (refuse).
if couldBeIPLiteral(host) {
    if ip := net.ParseIP(host); ip != nil && ssrf.PrivateIP(ip) {
        return nil, "", true
    }
}
```

```go
// CheckRequestURL — the key is rendered into a stack array and probed with the
// no-copy map-index form.
var scratch [urlKeyScratch]byte
key, host, handled := appendParsedURLKey(scratch[:0], u)
...
if e, ok := v.urls[string(key)]; ok {   // hashed in place: no allocation
    return true, e.Source
}
return tf.lookupDomain(v, host)
```

Confirmed at the compiler rather than asserted —
`go build -gcflags=-m ./internal/threatfeed/`:

```
threatfeed.go:545:29: string(key) does not escape   ← the request path's probe
threatfeed.go:628:16: string(key) escapes to heap   ← normaliseParsedURL's wrapper
```

**The key bytes are unchanged, by construction rather than by inspection.**
`normaliseParsedURL` keeps its exact signature and semantics and is now a
four-line wrapper over `appendParsedURLKey`, so the key-level differential that
already existed — `TestCheckRequestURL_MatchesCheckURL` and
`FuzzCheckRequestURL` assert `normaliseParsedURL`'s output equals
`NormaliseURL`'s for every shape — now covers the new core without a line being
added to it. That was the point of shaping it that way.

`strings.ToLower` is deliberately **kept** rather than folded into an ASCII byte
loop. A path may carry non-ASCII UTF-8, for which Unicode lowering is not the
ASCII fold, and a key that disagreed with the ingest side's spelling would
silently stop matching a real feed entry — a missed block, which is the failure
direction that matters. `ToLower` returns its input unchanged and without
allocating for the already-lowercase case that dominates, so exact semantics
cost nothing on the common path.

### Trade-offs, measured rather than asserted

- **The scratch is zeroed on every call, and that cost is linear in its size.**
  `urlKeyScratch` is 320 — large enough for the shapes a forward proxy sees.
  Sizing it for the theoretical maximum (a 253-byte FQDN plus a path `net/http`
  will accept up to its 1 MiB header budget) would tax every allowed request to
  spare a rare one that is not harmed anyway: **an overlong key simply spills**,
  `append` grows to the heap for one allocation, which is exactly what the
  pre-change concatenation charged *every* request. The uncommon case is never
  worse than the status quo.
- **A longer key is not truncated.** Truncation would make two distinct URLs
  share a key, so one would inherit the other's verdict. Pinned in both
  directions by `TestCheckRequestURL_SpilledKeysDoNotCollide`: a listed overlong
  URL must still match, and its neighbour differing only in the final byte must
  not.
- **The guard is a superset, never a filter.** Admitting a non-address is a
  missed optimisation; refusing a real one is a **security defect** — a
  private-IP destination would stop being recognised as one and would start
  being probed against the feed, which the private-IP exclusion exists to
  prevent.
- **`couldBeIPLiteral` costs 1.5 ns where `net.ParseIP` cost 45 ns** on an
  ordinary hostname, and it now shows at 1.8 % of the check's CPU.
- **`lookup` is split, not duplicated.** The request path spells out its own
  URL probe (four lines) and joins the shared `lookupDomain`. The domain half is
  the half carrying the allowlist-masking counter, and that is the half that must
  not be copied: a copy that forgot `tf.maskedHits.Add(1)` would blind the
  operator to an exemption overriding live threat intel. The pre-existing
  `TestCheckRequestURL_AllowlistMaskingIsStillCounted` pins exactly this and was
  written for exactly this risk.
- **No mutation cost.** The published-view concurrency contract, the sync path,
  the on-disk format and every verdict are untouched.

### Risk, and what carries it

The failure mode that matters is not slowness, it is **a verdict changing
silently**. Five things hold it, and one of them has already done its job:

- **`TestCouldBeIPLiteral_IsSupersetOfParseIP` and `FuzzCouldBeIPLiteral`** —
  the superset differential against the real `net.ParseIP`. **These caught a
  real defect in this change before it shipped.** The first draft of
  `couldBeIPLiteral` refused at the first byte that was not a digit, a dot or a
  colon, reasoning that an IPv6 literal "contains a colon". It does — but its
  leading bytes are **hex** digits, so `fe80::1` was refused and a link-local
  destination would have been handed to the feed. The guard now mirrors
  `netip.ParseAddr`'s dispatch loop byte for byte instead of reformulating it,
  the corpus names eight leading-hex shapes by name, and the mistake and its
  direction are recorded in the source. 2.28 M fuzz executions, clean.
- **`TestCouldBeIPLiteral_ActuallyRejectsOrdinaryHostnames`** — the **control
  for that differential**. Every superset assertion passes trivially if the
  guard always returns `true`, which is also the cheapest way to "fix" a failure
  there, and it would delete the optimisation while leaving a green suite.
- **`TestCheckRequestURL_MatchesCheckURL` + `FuzzCheckRequestURL`** (existing) —
  the key-level and verdict-level differential against the string path, which is
  the definition. 1.30 M fuzz executions on this revision, clean.
  `TestCheckRequestURL_FastPathIsActuallyTaken` is its control.
- **`TestAppendParsedURLKey_SpillMatchesStringPath`** — walks the spill
  boundary (1, 280, 319, 320, 321, 1280 bytes) rather than picking one length,
  because the bug a single length would miss is an off-by-one at the exact
  transition.
- **`TestBenchGate_CheckRequestURLAllocs` (tightened from `<= 2` to `== 0`),
  `TestCheckRequestURL_MissIsAllocationFree`, and
  `TestCheckRequestURL_AllocationFree_LegacyIsNot`** — the **arming contract**
  for the allocation claim, with its negative control. Reintroducing a string
  conversion on the read path is a legal, memory-safe, verdict-preserving change
  that silently restores the allocation rate; only these distinguish the two. The
  last one keeps the pre-change body alive and asserts it allocated ≥ 2, so a
  toolchain change that folded the baseline is caught instead of quietly
  flattering the gate.

The gate's own prose is updated too: it previously *named* the two allocations
it permitted as the irreducible cost of the check. Leaving that in place would
have been exactly the stale-prose conflict `AGENTS.md`'s evidence order warns
about.

### What this review could not measure

- **The in-situ wall-clock delta.** Stated plainly above: ~150 ns against a
  ~150 µs request is below the noise floor of every end-to-end benchmark in the
  tree, and no claim is made that it moves one.
- **GC pressure under a sustained real flood.** The allocation *rate* removed is
  measured; its effect on pause times at production request volume is not,
  because this harness cannot generate that volume.
- **The core count where this matters most.** Every parallel column here is
  4 vCPUs. The removed garbage is per-request, so its cost scales with request
  rate, which scales with cores; a 16- or 32-core appliance is where it would
  show. Carried forward, as 2026-11-18 carried it.
- **The deployed posture beyond the two content gates.** The harness loads the
  blocklist and the threat feed. It does **not** enable authentication, plugins,
  a category feed or a GeoIP database, so the nomination that produced this
  finding is only partly discharged — see below.

---

## The harness, and the mistake it made first

`BenchmarkPerfQual_ProxyHTTPForwardPosture` is in
`proxy_e2e_loaded_perfqual_test.go`, Benchmark-only (no `Test*`) like the
existing `proxy_e2e_perfqual_test.go` it extends, so `go test ./...` is
unaffected.

Two things about it are load-bearing, and both are recorded in the file because
the first draft got them wrong:

1. **The posture must be the only variable.** The draft measured a loaded
   posture against the *existing* `BenchmarkPerfQual_ProxyHTTPForward`, which
   requests a different (much shorter) URL. That reported **+6 allocations** for
   the posture — of which four were `net/http`'s cost for a longer request and
   had nothing to do with Culvert. The shipped harness runs both arms itself,
   sharing one rulebase, client, backend, destination URL and pinned dial.
2. **An httptest backend is reached at `127.0.0.1`, and a loopback destination
   short-circuits the gate the benchmark exists to exercise.** The threat feed's
   URL check returns `("", "")` for a private IP — deliberately, and verbatim
   from `NormaliseURL` — so it never builds a key and answers on two empty
   strings. Measured against `127.0.0.1` an enabled feed looks nearly free: the
   loopback destination hid **4 of the 6** allocations the loaded posture
   actually added. `benchPinUpstreamDial` points every upstream dial at the
   backend regardless of the authority asked for, so the request carries a
   public hostname while the bytes still land in-process. It mutates through
   `swapUpstreamTransport` with `old.Clone()`, never a write to the published
   transport, per `upstream_transport.go`'s contract.

The general lesson is worth keeping: **a benchmark's posture is part of its
measurement**, and a harness that short-circuits the code under test reports a
property of itself.

---

## Benchmark plan — what should be measured next

1. **Four redundant `strings.ToLower` scans per destination
   canonicalisation.** After this change, `strings.ToLower` is the single
   largest item in `CheckRequestURL`'s CPU profile — **320 ms of 1 090 ms,
   29.4 %** — because the same host value is case-folded up to four times on its
   way through `canonicalHost` → `hostutil.NormalizeHost` →
   `NormalizeHostStrict`, plus `u.Scheme` and `u.Path` at the key build. Each
   call is a full byte scan that returns its input unchanged. This is the
   measured next item and the reason it is **not** in this PR: it spans a
   different owner (`internal/hostutil`) and is a different concern, and the
   standing rule is one per change.
2. **The rest of the deployed posture.** This harness loads two gates.
   Authentication (`resolveRequestAuth`, Stage-1 rule matching with a roster and
   a session store), a loaded category feed, plugins and a GeoIP database are
   all still absent from every end-to-end profile in the tree, and 2026-11-18's
   nomination named authentication first. Extending
   `benchLoadPosture` is the cheap part; wiring a credential-capable backend is
   the work.
3. **`alertStore()` + probe indirection** — carried forward unmeasured from
   2026-11-17 and 2026-11-18, now its third pass. `internal/*` producers reach
   the store through an `atomic.Pointer` holding a `*SubscriberProbe`: a double
   indirection plus a closure call per check, against a ~2 ns read. It is
   recorded as carried rather than quietly dropped.
4. **A 16-core run** of this pass's and the two before it, on hardware that can
   show the ceiling the 4-vCPU columns only imply.

## Residual risk

- **`urlKeyScratch` is a performance choice sitting next to a correctness
  boundary.** 320 was chosen from the shapes a forward proxy sees. A destination
  pattern with consistently longer URLs would spill every time — no worse than
  before this change, but the win would be lost **silently**, because nothing
  reports the spill rate.
- **The allocation claim is held by `AllocsPerRun` tests, not by the type
  system.** Named above; the arming tests and their negative control are what
  make a regression loud rather than invisible.
- **The returned key aliases the caller's buffer.** `appendParsedURLKey`'s
  contract states it, and `CheckRequestURL`'s scratch is a function-local array
  used once, so today the property is structural rather than a rule to remember.
  A future caller that reused one buffer across two probes would break it
  without breaking a test.
- **`couldBeIPLiteral` is pinned against the toolchain's current `ParseAddr`.**
  The differential and fuzz target run against the real `net.ParseIP`, so a
  toolchain that *widens* the accepted syntax fails CI. A toolchain that
  *narrowed* it would only make the guard a looser superset, which is safe.
- **This pass changed no contract code path** (`contractcheck impact -base
  origin/main` reports none) and no API, UI, audit or persistence behaviour. The
  on-disk threat-feed DB format, the cluster `ImportFeedData` wire shape and
  every verdict are untouched.

## Verification

Commands and results on this revision, 4 vCPU Xeon @ 2.10 GHz, Go 1.27.4:

| check | result |
|---|---|
| `go build ./...`, `go vet ./...` | pass |
| `go test -count=1 .` (main, 435 s) | pass |
| `go test -count=1 ./internal/... ./cmd/...` | pass |
| `go test -race -count=2 -shuffle=on ./internal/threatfeed/` | pass |
| `go test -tags benchgate -run TestBenchGate_ ./internal/threatfeed ./internal/secscan` | pass |
| `go test -fuzz FuzzCouldBeIPLiteral -fuzztime=60s` | pass, 2 281 454 execs |
| `go test -fuzz FuzzCheckRequestURL -fuzztime=60s` | pass, 1 296 517 execs |
| `golangci-lint run --new-from-rev origin/main` (v2.15.0, the gate's own pin and command) | 0 issues |
| `golangci-lint run ./internal/threatfeed/...` full-tree, vs the same command on the base | no delta (one pre-existing `cyclop` finding on `loadFromDisk`, identical on both, line number only) |
| `go run ./cmd/contractcheck impact -base origin/main` | no contract code paths touched |

**Not run, and why:** the full hosted Fast PR Gate and its coverage floors — a
passing local check is not a passing merge gate, and the sharded `-race` matrix,
the CodeQL pass and the coverage-floor job run only there.
