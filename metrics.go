package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/secscan"
)

// ─── Per-rule hit counter ────────────────────────────────────────────────────
// Cardinality is capped at maxRuleMetrics to prevent unbounded label growth.

const maxRuleMetrics = 200

type ruleMetrics struct {
	mu            sync.RWMutex
	hits          map[string]*int64               // rule name → hit count
	last          map[string]*int64               // rule name → unix-seconds of last hit (policy-metadata P1)
	byID          map[string]persistedRuleCounter // stable rule ID → persisted accounting
	loadedByName  map[string]persistedRuleCounter // immutable legacy persistence baseline
	appliedByName map[string]int64                // greatest persisted hit baseline merged into telemetry
	order         []string                        // insertion order for cap enforcement

	// view is the lock-free READ path for RecordHit — see the block comment on
	// ruleCounter. It is DERIVED state: the mu-guarded maps above stay
	// authoritative, and every mutator republishes before releasing mu.
	view atomic.Pointer[map[string]ruleCounter]
}

// ruleCounter pairs one rule's two counter cells so the hot path resolves both
// with a SINGLE map lookup.
//
// ── Why RecordHit does not take rm.mu ────────────────────────────────────────
//
// RecordHit runs on EVERY proxied request that matched a policy rule
// (applyPolicyDecision, proxy.go) — i.e. on all ordinary allowed traffic. It
// used to take rm.mu.RLock to reach two maps that, in steady state, never
// change: rules are registered at most maxRuleMetrics (200) times per process,
// and every request after that is a pure read.
//
// sync.RWMutex.RLock is an atomic read-modify-write on ONE shared word, so this
// was not a constant cost but a THROUGHPUT CEILING — the same shape already
// recorded for internal/threatfeed, internal/connlimit and the IP filter. It
// also hashed the rule name TWICE, once for each of the two parallel maps.
//
// Measured on this machine (Go 1.26, 4-core, 50 registered rules, medians of
// n=11). The pre-view shape is kept in-tree as BenchmarkRecordHit_*_Legacy and
// both variants run in the SAME process, because the absolute numbers on a
// shared box are load-sensitive — quote the SHAPE, not the constant:
//
//	                 │ 1 core │ 2 cores │ 4 cores │ 1→4 throughput
//	─────────────────┼────────┼─────────┼─────────┼───────────────
//	50 rules, before │ 107 ns │  140 ns │  209 ns │  0.51x
//	50 rules, after  │  91 ns │   65 ns │   57 ns │  1.60x
//	hot rule, before │  98 ns │  163 ns │  229 ns │  0.43x
//	hot rule, after  │  77 ns │   79 ns │  119 ns │  0.65x
//
// The 50-rule row is the diagnostic one: those requests hit 50 DISTINCT
// counters, so no two share a counter cache line — yet throughput still FELL as
// cores were added (0.51x: four cores delivered half of one core). That isolates
// the lock, not the counters, as the ceiling. At 4 cores it is now 3.7x faster
// and scales up instead of down.
//
// The hot-rule row keeps a genuine residual: when all traffic matches ONE rule,
// every core still contends on that rule's single counter cache line, so it
// gains 1.9x but does not scale. That is inherent to a per-rule counter and is
// NOT worth sharding — 200 rules x N shards costs memory and a summing read for
// a value scraped once per interval. Recorded, not fixed.
//
// The read path is now one atomic pointer load plus one map lookup. Two
// invariants make that safe, and they are the whole contract:
//
//  1. A map reachable from a PUBLISHED view is never mutated in place. Writers
//     build a replacement and swap it (publishViewLocked). Registration is
//     bounded at 200 per process, so copy-on-write is free in practice.
//  2. Every mutator of hits/last republishes before releasing mu. Adding one
//     that does not is a silent CORRECTNESS failure — a restored counter that
//     never increments, or a rule whose hits vanish from /metrics — not merely a
//     performance one. Pinned per mutator by
//     TestRuleMetricsView_EveryMutatorRepublishes.
//
// The counters themselves are still shared int64s mutated atomically THROUGH
// the view; only the map structure is immutable. That is deliberate and matches
// the pre-existing contract: restoreRecordLocked increments a pointer it obtained
// under the write lock while RecordHit may hold the same pointer, and both are
// atomic operations on the same cell.
//
// last may be nil: the ruleMetrics literals used by tests construct `hits`
// without `last`, and the pre-view code guarded that case explicitly. The guard
// is preserved rather than tidied away.
type ruleCounter struct {
	hits *int64
	last *int64
}

// publishViewLocked rebuilds the lock-free read view from the authoritative
// maps. Callers MUST hold rm.mu for writing.
func (rm *ruleMetrics) publishViewLocked() {
	next := make(map[string]ruleCounter, len(rm.hits))
	for name, ptr := range rm.hits {
		next[name] = ruleCounter{hits: ptr, last: rm.last[name]}
	}
	rm.view.Store(&next)
}

var ruleMet = &ruleMetrics{hits: make(map[string]*int64), last: make(map[string]*int64), byID: make(map[string]persistedRuleCounter), loadedByName: make(map[string]persistedRuleCounter), appliedByName: make(map[string]int64)}

// RecordHit increments the telemetry counter for the given policy rule name and
// stamps its last-hit time. Live policy accounting is maintained by Evaluate;
// saveHitCounters overlays that rename-safe accounting before persistence.
func (rm *ruleMetrics) RecordHit(ruleName string) {
	if ruleName == "" {
		return
	}
	// ── Lock-free steady-state path ──────────────────────────────────────────
	// One atomic load + one map lookup. A nil view means nothing has been
	// registered yet (or this is a bare test literal), which falls through to the
	// locked registration path below exactly as an unknown rule name does.
	if v := rm.view.Load(); v != nil {
		if c, ok := (*v)[ruleName]; ok {
			atomic.AddInt64(c.hits, 1)
			if c.last != nil {
				atomicStoreMax(c.last, time.Now().Unix())
			}
			return
		}
	}
	now := time.Now().Unix()
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if rm.last == nil { // defensive: literals built with only `hits` set
		rm.last = make(map[string]*int64)
	}
	// Double-check after acquiring write lock.
	if ctr, ok := rm.hits[ruleName]; ok {
		atomic.AddInt64(ctr, 1)
		if lp := rm.last[ruleName]; lp != nil {
			atomicStoreMax(lp, now)
		}
		return
	}
	if len(rm.hits) >= maxRuleMetrics {
		return // cardinality cap reached; ignore new rules
	}
	v := int64(1)
	rm.hits[ruleName] = &v
	lv := now
	rm.last[ruleName] = &lv
	rm.order = append(rm.order, ruleName)
	rm.publishViewLocked()
}

// persistedRuleCounter is the on-disk shape of one rule's persisted counters
// (policy-metadata P1: lastHit joined the long-standing hit count). LastHit is
// omitempty so a never-matched rule and the legacy loader stay compatible.
type persistedRuleCounter struct {
	ID      string `json:"id,omitempty"`
	Hits    int64  `json:"hits"`
	LastHit int64  `json:"lastHit,omitempty"` // unix seconds; 0 = never
}

// saveHitCounters marshals the current hit counters + lastHit to JSON and
// writes them to path using a temp-file-then-rename pattern for crash safety.
func saveHitCounters(path string) {
	// Current policy definitions are authoritative for persisted accounting:
	// their stable counters cells survive rename and reorder. Populate them first
	// so a stale telemetry entry under a pre-rename name cannot win at restart.
	data := make(map[string]persistedRuleCounter, maxRuleMetrics)
	rules := policyStore.List()
	for i := range rules {
		rule := &rules[i]
		if rule.Name == "" || (rule.HitCount == 0 && rule.lastHitUnix == 0) || len(data) >= maxRuleMetrics {
			continue
		}
		data[rule.Name] = persistedRuleCounter{ID: rule.ID, Hits: rule.HitCount, LastHit: rule.lastHitUnix}
	}

	// An empty store is retained as a compatibility path for callers/tests that
	// use ruleMet before policy initialization. Once rules exist, persisting only
	// current names also drops stale pre-rename/deleted telemetry aliases.
	if len(rules) == 0 {
		ruleMet.mu.RLock()
		for name, ptr := range ruleMet.hits {
			if len(data) >= maxRuleMetrics {
				break
			}
			rec := persistedRuleCounter{Hits: atomic.LoadInt64(ptr)}
			if lp := ruleMet.last[name]; lp != nil {
				rec.LastHit = atomic.LoadInt64(lp)
			}
			data[name] = rec
		}
		ruleMet.mu.RUnlock()
	}

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		logger.Printf("HitCounters: marshal error: %v", err)
		return
	}
	if err := fileutil.AtomicWrite(path, b, 0o600); err != nil {
		logger.Printf("HitCounters: write error: %v", err)
	}
}

// loadHitCounters reads a JSON file of persisted hit counters and restores them
// into ruleMet. Accepts BOTH the current object format ({"r":{"hits","lastHit"}})
// and the legacy bare-count format ({"r":5}), so upgrading in place never drops
// counts.
func loadHitCounters(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return // file may not exist on first run; silently skip
	}
	// Current format first.
	var recs map[string]persistedRuleCounter
	if json.Unmarshal(data, &recs) == nil {
		ruleMet.restoreRecords(recs)
		logger.Printf("HitCounters: restored %d counter(s) from %s", len(recs), path)
		return
	}
	// Legacy fallback: bare name→count (no lastHit).
	var counts map[string]int64
	if json.Unmarshal(data, &counts) != nil {
		logger.Printf("HitCounters: unmarshal error from %s — starting fresh", path)
		return
	}
	legacy := make(map[string]persistedRuleCounter, len(counts))
	for name, c := range counts {
		legacy[name] = persistedRuleCounter{Hits: c}
	}
	ruleMet.restoreRecords(legacy)
	logger.Printf("HitCounters: restored %d counter(s) from %s (legacy format)", len(counts), path)
}

// restoreRecords inserts persisted counters into ruleMet, honoring the
// cardinality cap for new names and overwriting existing ones in place.
func (rm *ruleMetrics) restoreRecords(recs map[string]persistedRuleCounter) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	// Republish once, after the whole batch: restoreRecordLocked both inserts new
	// names and back-fills a missing `last` cell for an existing one, and the view
	// must reflect either. Deferred so it runs before mu is released.
	defer rm.publishViewLocked()
	if rm.last == nil {
		rm.last = make(map[string]*int64)
	}
	// This index represents exactly this persisted snapshot; rebuilding it also
	// prevents stale IDs and repeated loads from bypassing the cardinality cap.
	if rm.appliedByName == nil {
		rm.appliedByName = make(map[string]int64, min(len(recs), maxRuleMetrics))
	}
	rm.byID = make(map[string]persistedRuleCounter, min(len(recs), maxRuleMetrics))
	rm.loadedByName = make(map[string]persistedRuleCounter, min(len(recs), maxRuleMetrics))
	for name, rec := range recs {
		if !rm.restoreRecordLocked(name, rec) {
			continue
		}
		mergePersistedCounterByID(rm.byID, rec)
		rm.loadedByName[name] = rec
	}
}

func (rm *ruleMetrics) restoreRecordLocked(name string, rec persistedRuleCounter) bool {
	ptr := rm.hits[name]
	if ptr == nil {
		if len(rm.hits) >= maxRuleMetrics {
			return false
		}
		h := rec.Hits
		rm.hits[name] = &h
		rm.appliedByName[name] = rec.Hits
		l := rec.LastHit
		rm.last[name] = &l
		rm.order = append(rm.order, name)
		return true
	}

	// Add only growth in the immutable persisted baseline. Live RecordHit
	// increments may proceed through an already-obtained pointer while this lock
	// is held and must never be overwritten by a repeated runtime load.
	if delta := rec.Hits - rm.appliedByName[name]; delta > 0 {
		atomic.AddInt64(ptr, delta)
		rm.appliedByName[name] = rec.Hits
	}
	if lp := rm.last[name]; lp != nil {
		atomicStoreMax(lp, rec.LastHit)
		return true
	}
	l := rec.LastHit
	rm.last[name] = &l
	return true
}

func mergePersistedCounterByID(byID map[string]persistedRuleCounter, rec persistedRuleCounter) {
	if !validRuleID(rec.ID) {
		return
	}
	if prior, exists := byID[rec.ID]; exists {
		if prior.Hits > rec.Hits {
			rec.Hits = prior.Hits
		}
		if prior.LastHit > rec.LastHit {
			rec.LastHit = prior.LastHit
		}
	}
	byID[rec.ID] = rec
}

// startHitCounterPersistence starts a background goroutine that saves the hit
// counters every 5 minutes and once more when the context is cancelled
// (graceful shutdown). It must be called AFTER loadHitCounters and
// RestoreHitCounts have run: the goroutine's saves persist from the per-rule
// counter cells, which are still zero until RestoreHitCounts merges the loaded
// baseline into them. Starting the goroutine earlier lets a save that races the
// load→restore startup window (e.g. ctx cancelled mid-startup) clobber a
// non-empty hit_counters.json with zeros — the caller loads and restores first.
//
// It returns a channel that is closed once the goroutine has performed its
// final on-cancel save and exited. Production callers may ignore it; tests that
// point path at a t.TempDir() MUST cancel the context and then wait on this
// channel before the temp dir is cleaned up — otherwise the goroutine's final
// save races (and loses to) TempDir's RemoveAll, recreating a file in the dir
// ("directory not empty" cleanup failure).
func startHitCounterPersistence(ctx context.Context, path string) <-chan struct{} {
	// Ensure the directory exists for the saves below (and the caller's
	// immediate post-restore save).
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		os.MkdirAll(dir, 0o750) //nolint:errcheck // best-effort
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				saveHitCounters(path)
				return
			case <-t.C:
				// CHAOS-24: contain the ROUND so a marshal fault costs one
				// checkpoint rather than the process, and the loop survives to
				// take the next one (and the ctx.Done final save).
				runGuarded("metrics_persist", func() { saveHitCounters(path) })
			}
		}
	}()
	return done
}

// RestoreHitCounts copies persisted hit counter values + lastHit from ruleMet
// back into the matching PolicyRule fields. Called once at startup after both
// policyStore.Load() and loadHitCounters() have run. Lock order (ruleMet then
// policyStore) is the ONLY nesting of these two mutexes — List() reads the
// rule's own atomics and never touches ruleMet, so no reverse-order path exists.
func RestoreHitCounts() {
	ruleMet.mu.RLock()
	defer ruleMet.mu.RUnlock()
	policyStore.mu.Lock()
	defer policyStore.mu.Unlock()
	next := make([]*PolicyRule, len(policyStore.rules))
	for i, rule := range policyStore.rules {
		// Restore can run safely even if an evaluator still holds the current
		// revision. Never fill a nil cell on a published definition in place.
		next[i] = clonePolicyRuleForPublication(rule)
		counters := next[i].counters
		if rec, ok := ruleMet.byID[rule.ID]; ok {
			restorePolicyHitCount(counters, rec.Hits)
			atomicStoreMax(&counters.lastHitUnix, rec.LastHit)
			continue
		}
		// Backward-compatible fallback uses the immutable loaded snapshot, not
		// live telemetry that RecordHit continues to increment after startup.
		if rec, ok := ruleMet.loadedByName[rule.Name]; ok {
			restorePolicyHitCount(counters, rec.Hits)
			atomicStoreMax(&counters.lastHitUnix, rec.LastHit)
		}
	}
	policyStore.rules = next
	policyStore.sortLocked()
}

// restorePolicyHitCount adds only the not-yet-restored persisted baseline. The
// caller serializes restorations under policyStore.mu; Evaluate can increment the
// total concurrently without being overwritten.
func restorePolicyHitCount(counters *policyRuleCounters, persisted int64) {
	restored := atomic.LoadInt64(&counters.restoredHitCount)
	if persisted <= restored {
		return
	}
	atomic.AddInt64(&counters.hitCount, persisted-restored)
	atomic.StoreInt64(&counters.restoredHitCount, persisted)
}

func atomicStoreMax(dst *int64, value int64) {
	for current := atomic.LoadInt64(dst); value > current; current = atomic.LoadInt64(dst) {
		if atomic.CompareAndSwapInt64(dst, current, value) {
			return
		}
	}
}

// WritePrometheus writes per-rule metrics lines to the given builder.
func (rm *ruleMetrics) WritePrometheus(w *strings.Builder) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if len(rm.hits) == 0 {
		return
	}
	w.WriteString("\n# HELP culvert_policy_rule_hits_total Per-rule hit count (capped at 200 rules)\n")
	w.WriteString("# TYPE culvert_policy_rule_hits_total counter\n")
	for _, name := range rm.order {
		ctr := rm.hits[name]
		// Sanitise label value: escape backslash, double-quote, newline.
		safe := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(name)
		fmt.Fprintf(w, "culvert_policy_rule_hits_total{rule=%q} %d\n", safe, atomic.LoadInt64(ctr))
	}
}

// ─── Latency histogram ──────────────────────────────────────────────────────
// Fixed-bucket histogram in Prometheus text format. Generalized so multiple
// metrics can reuse the same implementation (CA-2 PR2): the name, help text,
// and bucket layout are per-instance. newLatencyHistogram preserves the
// original request-latency metric byte-for-byte.
//
// ── Sharding ─────────────────────────────────────────────────────────────────
//
// latencyHist.Observe runs on EVERY proxied request (recordRequestTelemetry,
// proxy.go) — HTTP, CONNECT, WebSocket alike. The original implementation was
// lock-free, which is not the same thing as contention-free: it wrote three
// atomics per observation onto two shared cache lines, and the first of them
// was a compare-and-swap LOOP over one process-wide float64 accumulator. A CAS
// loop under contention does not merely serialise — it degrades, because every
// losing core retries and the retries themselves generate the coherence traffic
// that makes the next round lose. So the metric got more expensive per request
// the more cores were carrying traffic, on 100% of traffic.
//
// The measurement that matters is not ns/op at one core, it is how ns/op MOVES
// with core count. BenchmarkLatencyHistogramObserveParallel, realistic
// nanosecond-resolution latency samples, median of n=15 (4-core, Go 1.26):
//
//	GOMAXPROCS │  before  │  after  │
//	     1     │   20.6ns │  18.3ns │
//	     2     │  179.6ns │  40.7ns │
//	     4     │  292.3ns │  30.3ns │
//
// Before, four cores delivered 3.4M observations/s — an order of magnitude LESS
// than the 49M/s a single core managed, i.e. adding cores subtracted throughput.
// After, the cost is flat in core count and four cores deliver 33M/s: 9.6x the
// old four-core ceiling, and the gap widens on the 16- and 32-core hardware this
// ships to. The single-core path is slightly better too, so unlike most sharding
// trades there is no low-concurrency price to pay.
//
// The absolute "before" figure is load-sensitive BY CONSTRUCTION — a contended
// CAS loop degrades further the busier the machine is — so it is not a stable
// constant: the same benchmark on a quieter run of the same box measured
// 15.0 / 125.5 / 158.9 against 13.6 / 16.6 / 12.0. Both runs agree on the shape
// and on an order-of-magnitude win at four cores; neither should be quoted as a
// precise number. That volatility is itself the argument: the cost of this path
// used to depend on what else the gateway was doing.
//
// Two changes get that, and both are cost-only — every number this renders is
// the same number, computed the same way:
//
//  1. Counters are split across histShardCount cache-line-isolated shards, so
//     concurrent observers usually write disjoint lines. Scrapes sum the shards;
//     a scrape is once per scrape interval against a per-request write path, so
//     moving work from Observe to WritePrometheus is the correct direction.
//
//  2. The separate `total` counter is gone: the observation count is the sum of
//     the bucket counters, which removes an atomic write from every observation
//     AND makes `_count` exactly equal the `+Inf` bucket, as the Prometheus
//     exposition format requires. The old shape incremented `total` before the
//     bucket, so a scrape landing between the two rendered a `_count` one
//     greater than `+Inf`.
//
// The sum stays a float64 CAS, now per shard. That is deliberate and the
// reasoning is on Observe: an integer-nanosecond accumulator is measurably
// cheaper but overflows after ~107 days on a busy gateway and exports a
// negative `_sum` when it does. Sharding is what removed the contention; the
// accumulator's type never had to change to get it. Per-shard partial sums are
// also ~128x smaller than the old global one, so float64 precision is better
// than before, not worse.
//
// ── What this does NOT fix ───────────────────────────────────────────────────
//
// Observe has no key to shard on, so the shard is chosen from the observation
// itself: latencies come from time.Since, so the low mantissa bits of the
// float64 are nanosecond noise and spread well (4096 realistic samples fill
// all 128 shards: min 19, max 49, mean 32, none empty). A caller that observes
// a CONSTANT value therefore lands every observation on one shard and scales
// exactly as the old code did — never worse, since that path is still two
// atomic adds rather than a CAS loop plus two. TestHistogramShardSpread pins
// the spread rather than assuming it, and the structural regression gate is
// TestBenchGate_ObservationsDoNotShareOneCounter.

const (
	// maxHistogramBuckets bounds the per-shard bucket array so a shard is a
	// flat, cache-line-sized value type instead of a slice header pointing
	// somewhere else. Every histogram in the tree today declares 10 or 11
	// bounds; newHistogram rejects anything larger rather than silently
	// truncating (TestHistogramBucketLimit pins that all of them fit).
	maxHistogramBuckets = 12

	// histShardCount is the number of cache-line-isolated counter sets. It is a
	// constant rather than a runtime probe for the same reason connlimit's is:
	// the useful property is that concurrent writers rarely collide, and the
	// collision rate is (writers/shards), so 128 keeps a 32-core box under 25%
	// while costing 16 KB per histogram (48 KB for the three in the tree).
	// 256 and 512 were measured and bought 1.5ns and 2.4ns at four cores — not
	// worth 2x and 4x the footprint.
	histShardCount = 128

	// histShardBytes is the per-shard stride: 8 + 13*8 = 112 bytes of counters
	// rounded up to two 64-byte cache lines, so one observer's write never
	// invalidates a neighbouring shard's line. Raising maxHistogramBuckets past
	// what this covers makes histShard's padding array negative, which is a
	// COMPILE error rather than a silently unpadded shard.
	// TestHistogramShardIsCacheLineSized pins the resulting size.
	histShardBytes = 128
)

// histShard is one observer-local set of counters. Padded to histShardBytes:
// unpacked, two shards would share a cache line and writing one would
// invalidate the other, handing back most of what splitting them just bought
// (the same false-sharing trap measured in internal/connlimit).
// sumBits is UNSIGNED because that is the type math.Float64bits speaks. The
// pre-sharding code kept the same value in an int64 and paid for it with a
// uint64<->int64 conversion on every read and every write, each carrying a
// `#nosec G115` that the linter does not in fact honour (those lines only
// survived because the gate runs --new-from-rev and they predated it). Using
// atomic.CompareAndSwapUint64 removes both conversions and both suppressions
// rather than carrying the debt forward.
type histShard struct {
	sumBits uint64                         // atomic float64 seconds, stored as bits
	counts  [maxHistogramBuckets + 1]int64 // atomic per-bucket counters (+1 for +Inf)
	_       [histShardBytes - 8 - (maxHistogramBuckets+1)*8]byte
}

type latencyHistogram struct {
	name    string    // metric name, e.g. culvert_request_duration_seconds
	help    string    // HELP text
	buckets []float64 // upper bounds (immutable after init)
	shards  [histShardCount]histShard
}

// newHistogram builds a histogram with a custom name, help text, and bucket
// upper bounds (seconds). Buckets should be ≥ 0.0001 so %g renders them as
// plain decimals rather than scientific notation.
//
// It panics when the caller declares more than maxHistogramBuckets bounds.
// Every call site is a package-level var, so this is a build-time programming
// error that fails on the first test run, not a runtime failure mode.
func newHistogram(name, help string, buckets []float64) *latencyHistogram {
	if len(buckets) > maxHistogramBuckets {
		panic(fmt.Sprintf("newHistogram(%s): %d bucket bounds exceeds maxHistogramBuckets=%d",
			name, len(buckets), maxHistogramBuckets))
	}
	return &latencyHistogram{
		name:    name,
		help:    help,
		buckets: buckets,
	}
}

var latencyHist = newLatencyHistogram()

// newLatencyHistogram returns the request-latency histogram.
// Buckets: 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s, +Inf.
func newLatencyHistogram() *latencyHistogram {
	return newHistogram(
		"culvert_request_duration_seconds",
		"Request latency histogram",
		[]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	)
}

// certSignHist records leaf-certificate signing latency (CA-2 PR2). Signing is
// an ECDSA P-256 keygen + x509.CreateCertificate — sub-millisecond to a few ms
// — so the buckets are finer at the low end than the request histogram.
var certSignHist = newHistogram(
	"culvert_cert_sign_duration_seconds",
	"Leaf certificate signing latency",
	[]float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1},
)

// histShardFor picks the shard for one observation.
//
// Observe carries no natural sharding key, so the entropy comes from the
// observation itself. Latencies originate from time.Since, so the low mantissa
// bits are nanosecond noise; the splitmix64 finalizer spreads them over the
// whole index space in three ALU ops rather than trusting any particular bit
// range to vary (a coarse clock would leave the low bits constant, and the mix
// keeps the higher-order variation usable when it does).
func (h *latencyHistogram) histShardFor(seconds float64) *histShard {
	x := math.Float64bits(seconds)
	x ^= x >> 33
	x *= 0xff51afd7ed558ccd
	x ^= x >> 33
	return &h.shards[x&(histShardCount-1)]
}

// Observe records a latency observation in seconds. Lock-free, allocation-free,
// and — unlike the single-accumulator version it replaces — contention-free
// between observers that land on different shards. See the sharding note above.
//
// The sum is still accumulated as float64 seconds via a CAS, which is NOT the
// pathology this file's sharding note describes. That was ONE process-wide CAS
// loop: every core in the process contended for the same word, so the retries
// themselves generated the traffic that caused the next round of retries. Here
// the loop is per shard, so concurrent observers are almost always CAS-ing
// different words and the loop does not iterate. An integer-nanosecond
// accumulator would be a single atomic add and measured 0.4ns/op cheaper
// serially and 2.9ns/op cheaper at four cores — but int64 nanoseconds overflow
// after 9.2e9 seconds of ACCUMULATED latency, which a 10k req/s gateway
// averaging 100ms reaches in about 107 days of uptime, and a wrapped sum
// exports a NEGATIVE, non-monotonic `_sum` to Prometheus and OTLP. float64
// cannot overflow at any reachable magnitude, so the 3ns buys the whole class
// away on a path this change already made ~140ns cheaper. Do not "optimize"
// this back into an integer accumulator without solving that.
//
// The non-finite guard has no equivalent in the pre-sharding code, which had
// the same shape: one NaN observation poisoned `_sum` to NaN for the lifetime
// of the process, with no way for a scrape to recover. A rejected observation
// is still counted in its bucket; only the sum skips it.
func (h *latencyHistogram) Observe(seconds float64) {
	s := h.histShardFor(seconds)
	if seconds > 0 && seconds < math.MaxFloat64 { // false for NaN and +Inf
		for {
			old := atomic.LoadUint64(&s.sumBits)
			sum := math.Float64frombits(old) + seconds
			if atomic.CompareAndSwapUint64(&s.sumBits, old, math.Float64bits(sum)) {
				break
			}
		}
	}
	for i, bound := range h.buckets {
		if seconds <= bound {
			atomic.AddInt64(&s.counts[i], 1)
			return
		}
	}
	atomic.AddInt64(&s.counts[len(h.buckets)], 1) // +Inf bucket
}

// snapshot folds every shard into one reading: per-bucket (NON-cumulative)
// counts, the observation count, and the summed duration in seconds.
//
// Shards are read one at a time, so a snapshot taken under live traffic is a
// near-consistent rather than atomic view — the same property the unsharded
// counters had, and the one Prometheus already assumes of a scrape. What it
// does guarantee is INTERNAL consistency: total is derived from the very
// counts returned, so `_count` can never disagree with the `+Inf` bucket.
func (h *latencyHistogram) snapshot() (counts []int64, total int64, sum float64) {
	counts = make([]int64, len(h.buckets)+1)
	for i := range h.shards {
		s := &h.shards[i]
		sum += math.Float64frombits(atomic.LoadUint64(&s.sumBits))
		for j := range counts {
			counts[j] += atomic.LoadInt64(&s.counts[j])
		}
	}
	for _, c := range counts {
		total += c
	}
	return counts, total, sum
}

// Count returns the number of observations recorded. Allocation-free; used by
// tests and by callers that need only the count, not the distribution.
func (h *latencyHistogram) Count() int64 {
	var total int64
	for i := range h.shards {
		for j := 0; j <= len(h.buckets); j++ {
			total += atomic.LoadInt64(&h.shards[i].counts[j])
		}
	}
	return total
}

// WritePrometheus writes the histogram in Prometheus text exposition format.
func (h *latencyHistogram) WritePrometheus(w *strings.Builder) { //nolint:errcheck // strings.Builder.Write never returns an error
	counts, total, sum := h.snapshot()
	fmt.Fprintf(w, "\n# HELP %s %s\n", h.name, h.help)
	fmt.Fprintf(w, "# TYPE %s histogram\n", h.name)
	var cumulative int64
	for i, bound := range h.buckets {
		cumulative += counts[i]
		fmt.Fprintf(w, "%s_bucket{le=\"%g\"} %d\n", h.name, bound, cumulative)
	}
	cumulative += counts[len(h.buckets)]
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", h.name, cumulative)
	fmt.Fprintf(w, "%s_sum %f\n", h.name, sum)
	fmt.Fprintf(w, "%s_count %d\n", h.name, total)
}

// metricsToken is the Bearer token required to access /metrics.
// Empty string = open access (backward-compatible default; not recommended).
var metricsToken string

// handleMetrics serves Prometheus-compatible text metrics on GET /metrics.
// If metricsToken is set, the request must carry: Authorization: Bearer <token>
func handleMetrics(w http.ResponseWriter, r *http.Request) { //nolint:errcheck // writes to http.ResponseWriter; errors mean client disconnected
	if metricsToken != "" {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(metricsToken)) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}
	total := atomic.LoadInt64(&statTotal)
	blocked := atomic.LoadInt64(&statBlocked)
	authFail := atomic.LoadInt64(&statAuthFail)
	fileBlocked := atomic.LoadInt64(&statFileBlocked)
	allowed := total - blocked - authFail
	if allowed < 0 {
		allowed = 0
	}

	rlLimit := int64(rl.Limit())
	rlEnabled := int64(0)
	if rl.Enabled() {
		rlEnabled = 1
	}

	scanCounters := secscan.Counters()
	clamBlocked := scanCounters.ClamBlocked
	yaraBlocked := scanCounters.YARABlocked
	feedBlocked := scanCounters.ThreatFeedBlocked
	dpiBlocked := atomic.LoadInt64(&statDPIBlocked)
	bytesSent := atomic.LoadInt64(&statBytesSent)
	bytesRecv := atomic.LoadInt64(&statBytesRecv)
	feedEntries, _, _ := globalThreatFeed.Stats()
	cacheHits, cacheMisses, cacheSize := globalSecScanner.CacheStats()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// Per-rule metrics (appended after the main block).
	var ruleMetBuf strings.Builder

	fmt.Fprintf(w, `# HELP culvert_requests_total Total proxy requests
# TYPE culvert_requests_total counter
culvert_requests_total %d

# HELP culvert_requests_allowed Total allowed requests
# TYPE culvert_requests_allowed counter
culvert_requests_allowed %d

# HELP culvert_requests_blocked Total blocked requests (domain + IP)
# TYPE culvert_requests_blocked counter
culvert_requests_blocked %d

# HELP culvert_requests_auth_fail Total auth failures
# TYPE culvert_requests_auth_fail counter
culvert_requests_auth_fail %d

# HELP culvert_blocklist_size Current number of blocked domains
# TYPE culvert_blocklist_size gauge
culvert_blocklist_size %d

# HELP culvert_uptime_seconds Proxy uptime in seconds
# TYPE culvert_uptime_seconds gauge
culvert_uptime_seconds %.0f

# HELP culvert_rate_limit_rpm Configured rate limit (requests per minute, 0=disabled)
# TYPE culvert_rate_limit_rpm gauge
culvert_rate_limit_rpm %d

# HELP culvert_rate_limit_enabled Whether rate limiting is active
# TYPE culvert_rate_limit_enabled gauge
culvert_rate_limit_enabled %d

# HELP culvert_file_blocked_total Total requests blocked by file-extension profile
# TYPE culvert_file_blocked_total counter
culvert_file_blocked_total %d

# HELP culvert_file_block_profile_size Number of blocked file extensions
# TYPE culvert_file_block_profile_size gauge
culvert_file_block_profile_size %d

# HELP culvert_dpi_blocked_total Total requests blocked by DPI content signatures
# TYPE culvert_dpi_blocked_total counter
culvert_dpi_blocked_total %d

# HELP culvert_clamav_blocked_total Total requests blocked by ClamAV antivirus
# TYPE culvert_clamav_blocked_total counter
culvert_clamav_blocked_total %d

# HELP culvert_yara_blocked_total Total requests blocked by YARA rules
# TYPE culvert_yara_blocked_total counter
culvert_yara_blocked_total %d

# HELP culvert_clam_scan_errors_total Total ClamAV scan errors mid-request (content forwarded unscanned, fail-open)
# TYPE culvert_clam_scan_errors_total counter
culvert_clam_scan_errors_total %d

# HELP culvert_scan_timeout_total Total body scans that exceeded the scan budget and were refused (fail-closed)
# TYPE culvert_scan_timeout_total counter
culvert_scan_timeout_total %d

# HELP culvert_clam_saturated_total Total body scans that could not obtain a ClamAV slot within the scan budget (daemon healthy, node at capacity)
# TYPE culvert_clam_saturated_total counter
culvert_clam_saturated_total %d

# HELP culvert_scan_late_discarded_total Total clean verdicts computed after the scan budget expired and discarded (the fail-closed refusal stands)
# TYPE culvert_scan_late_discarded_total counter
culvert_scan_late_discarded_total %d

# HELP culvert_scan_inflight Body scans currently running, including scans whose caller already gave up
# TYPE culvert_scan_inflight gauge
culvert_scan_inflight %d

# HELP culvert_remote_scan_fail_total Total remote scan-sidecar faults that forwarded content UNSCANNED (fail-open)
# TYPE culvert_remote_scan_fail_total counter
culvert_remote_scan_fail_total %d

# HELP culvert_remote_scan_saturated_total Total remote scans the sidecar refused for capacity (fail-closed, also counted as scan timeouts)
# TYPE culvert_remote_scan_saturated_total counter
culvert_remote_scan_saturated_total %d

# HELP culvert_remote_scan_inflight Remote scan round trips currently in flight
# TYPE culvert_remote_scan_inflight gauge
culvert_remote_scan_inflight %d

# HELP culvert_threat_feed_blocked_total Total requests blocked by threat intelligence feeds
# TYPE culvert_threat_feed_blocked_total counter
culvert_threat_feed_blocked_total %d

# HELP culvert_threat_feed_entries Total URLs in threat feed database
# TYPE culvert_threat_feed_entries gauge
culvert_threat_feed_entries %d

# HELP culvert_threat_feed_allowlist_masked_total Domain-level threat hits suppressed by the domain allowlist
# TYPE culvert_threat_feed_allowlist_masked_total counter
culvert_threat_feed_allowlist_masked_total %d

# HELP culvert_scan_cache_hits_total Total SHA256 scan-cache hits (decision reused without rescanning)
# TYPE culvert_scan_cache_hits_total counter
culvert_scan_cache_hits_total %d

# HELP culvert_scan_cache_misses_total Total SHA256 scan-cache misses (required a fresh scan)
# TYPE culvert_scan_cache_misses_total counter
culvert_scan_cache_misses_total %d

# HELP culvert_scan_cache_size Current number of entries in the SHA256 scan result cache
# TYPE culvert_scan_cache_size gauge
culvert_scan_cache_size %d

# HELP culvert_bytes_sent_total Total bytes sent upstream (request bodies)
# TYPE culvert_bytes_sent_total counter
culvert_bytes_sent_total %d

# HELP culvert_bytes_recv_total Total bytes received from upstream (response bodies)
# TYPE culvert_bytes_recv_total counter
culvert_bytes_recv_total %d

# HELP culvert_auth_exempt_decisions_total Total Stage-1 authentication-policy Exempt decisions
# TYPE culvert_auth_exempt_decisions_total counter
culvert_auth_exempt_decisions_total %d

# HELP culvert_auth_credential_required_total Total Stage-1 authentication-policy CredentialRequired decisions
# TYPE culvert_auth_credential_required_total counter
culvert_auth_credential_required_total %d

# HELP culvert_auth_sso_required_total Total Stage-1 authentication-policy SSORequired decisions
# TYPE culvert_auth_sso_required_total counter
culvert_auth_sso_required_total %d
`,
		total, allowed, blocked, authFail,
		int64(bl.Count()),
		time.Since(startTime).Seconds(),
		rlLimit, rlEnabled,
		fileBlocked, int64(fileBlocker.Count()),
		dpiBlocked,
		clamBlocked,
		yaraBlocked,
		scanCounters.ClamScanError,
		scanCounters.ScanTimeout,
		scanCounters.ClamSaturated,
		scanCounters.ScanLateDiscarded,
		scanCounters.ScanInflight,
		// Remote (sidecar) scanning. Emitted unconditionally, like every other
		// scan counter: a sidecar deployment used to export NO scanning signal
		// at all — every culvert_scan_* series is structurally zero there and
		// the sidecar's own fail-open counter reached only the admin JSON API,
		// so the paging rules in the scan-capacity runbook were silently dead
		// on exactly the deployment that runbook recommends.
		scanCounters.RemoteScanFail,
		scanCounters.RemoteScanSaturated,
		scanCounters.RemoteScanInflight,
		feedBlocked,
		feedEntries,
		globalThreatFeed.AllowlistMaskedTotal(),
		cacheHits,
		cacheMisses,
		int64(cacheSize),
		bytesSent,
		bytesRecv,
		atomic.LoadInt64(&statAuthExempt),
		atomic.LoadInt64(&statAuthCredentialRequired),
		atomic.LoadInt64(&statAuthSSORequired),
	)

	// Config-snapshot cluster-sync cap utilization is emitted for ALL capped
	// slices by writeConfigSnapshotSizeMetrics (cluster_metrics.go), sourced from
	// the sizes cached at publish — no per-scrape snapshot rebuild.

	// PR3d — inspected native-HTTP/2 tunnel drain observability. activeConns above
	// conflates H1-inspect, H2-inspect, and raw-bypass tunnels; these disambiguate
	// the H2-inspect subset so an operator can confirm a node GOAWAY'd cleanly on
	// shutdown. goaway = tunnels active when the drain STARTED (one-shot snapshot;
	// late registrants caught by the re-fire are not counted), forced = backstop
	// closes at the deadline. `goaway - forced` APPROXIMATES graceful drains but is
	// not an exact identity (a late-registered, force-closed tunnel is in forced but
	// not goaway), so treat it as an operator heuristic.
	_, _ = fmt.Fprintf(w, `# HELP culvert_h2_inspect_active Currently active inspected native-HTTP/2 tunnels
# TYPE culvert_h2_inspect_active gauge
culvert_h2_inspect_active %d

# HELP culvert_h2_inspect_drain_goaway_total Inspected H2 tunnels signaled with GOAWAY at shutdown-drain start
# TYPE culvert_h2_inspect_drain_goaway_total counter
culvert_h2_inspect_drain_goaway_total %d

# HELP culvert_h2_inspect_drain_forced_total Inspected H2 tunnels force-closed by the drain-deadline backstop
# TYPE culvert_h2_inspect_drain_forced_total counter
culvert_h2_inspect_drain_forced_total %d
`,
		atomic.LoadInt64(&statH2InspectActive),
		atomic.LoadInt64(&statH2InspectGoaway),
		atomic.LoadInt64(&statH2InspectForced),
	)

	// CHAOS-11: parent-proxy chain fail-open visibility. fallback_active=1
	// means the pool is CURRENTLY bypassed (all parents unhealthy or
	// circuit-open) and egress is direct; the counter tracks how many
	// requests egressed direct while the chain was configured.
	upFallbackActive, upFallbackTotal := upstreamPool.DirectFallback()
	upActiveVal := 0
	if upFallbackActive {
		upActiveVal = 1
	}
	_, _ = fmt.Fprintf(w, `# HELP culvert_upstream_direct_fallback_active 1 when the parent-proxy pool is currently failing open to direct egress (all parents down)
# TYPE culvert_upstream_direct_fallback_active gauge
culvert_upstream_direct_fallback_active %d

# HELP culvert_upstream_direct_fallback_total Requests that egressed DIRECT because no parent proxy was available (fail-open bypass of the chain)
# TYPE culvert_upstream_direct_fallback_total counter
culvert_upstream_direct_fallback_total %d
`,
		upActiveVal,
		upFallbackTotal,
	)

	// CHAOS-50: Layer-2 community category store boot health. `available` is 0
	// both when the store is unconfigured and when it failed to open — the
	// operator distinguishes them from the `category_feed_db` diagnostics row
	// (and from the absence of `-cat-feed-db`), while an alerting rule that only
	// cares "is Layer 2 serving?" needs a single series. `quarantined_copies`
	// counts `.corrupt.*` directories still on the volume, so an incident stays
	// visible across restarts even after the store self-healed.
	cfdb := catFeedDBState()
	cfdbAvailable, cfdbRecovered := 0, 0
	if cfdb.Available {
		cfdbAvailable = 1
	}
	if cfdb.Recovered {
		cfdbRecovered = 1
	}
	_, _ = fmt.Fprintf(w, `# HELP culvert_catfeeddb_available 1 when the Layer-2 community category store is open and serving lookups
# TYPE culvert_catfeeddb_available gauge
culvert_catfeeddb_available %d

# HELP culvert_catfeeddb_recovered 1 when a damaged community category store was quarantined and re-created at this startup
# TYPE culvert_catfeeddb_recovered gauge
culvert_catfeeddb_recovered %d

# HELP culvert_catfeeddb_quarantined_copies Quarantined (.corrupt.*) copies of the community category store still on the data volume
# TYPE culvert_catfeeddb_quarantined_copies gauge
culvert_catfeeddb_quarantined_copies %d
`,
		cfdbAvailable,
		cfdbRecovered,
		cfdb.ResidualCopies,
	)

	// CHAOS-54: SOCKS5 accept-loop health. Emitted ONLY when a SOCKS5 listener
	// is configured — on the ordinary appliance (-socks5-port 0) these series
	// are absent entirely, because `listener_up 0` on a node that never had
	// SOCKS5 is indistinguishable from a dead listener and the documented
	// paging rule is `== 0` (the cluster_ca gauge precedent).
	//
	// `up` is 0 only when the accept loop STOPPED (an unrecoverable socket
	// error or a contained panic) — terminal, restart required. A listener
	// that is retrying stays up=1 with `accept_degraded 1`, because it recovers
	// on its own the moment descriptors free up.
	if sk := socks5ListenerState(); sk.Configured {
		up, degraded := 1, 0
		if sk.Down {
			up = 0
		}
		if sk.Degraded {
			degraded = 1
		}
		_, _ = fmt.Fprintf(w, `# HELP culvert_socks5_listener_up 1 while the SOCKS5 accept loop is running; 0 once it has stopped and the port is closed
# TYPE culvert_socks5_listener_up gauge
culvert_socks5_listener_up %d

# HELP culvert_socks5_accept_errors_total Accept errors on the SOCKS5 listener since startup
# TYPE culvert_socks5_accept_errors_total counter
culvert_socks5_accept_errors_total %d

# HELP culvert_socks5_accept_degraded 1 while the SOCKS5 listener has been failing to accept for longer than the degradation threshold
# TYPE culvert_socks5_accept_degraded gauge
culvert_socks5_accept_degraded %d

# HELP culvert_socks5_accept_backoff_seconds Current SOCKS5 accept retry backoff; 0 when accepts are succeeding
# TYPE culvert_socks5_accept_backoff_seconds gauge
culvert_socks5_accept_backoff_seconds %g
`,
			up,
			sk.Total,
			degraded,
			sk.Backoff.Seconds(),
		)
	}

	// RISK-027: MCP Agent Security Gateway capability health. Emitted ONLY on a
	// node that requested MCP — `culvert_mcp_gateway_up 0` on a node that never had
	// MCP is indistinguishable from a dead listener, and the paging rule is `== 0`
	// (the socks5 rule, applied here). Every value is a plain total or a 0/1 gauge:
	// /metrics is unauthenticated on the proxy port, so no tenant, server id, path,
	// principal, policy content or bind address may appear, and nothing here is a
	// label.
	if m := mcpHealthState(); m.Configured {
		_, _ = fmt.Fprintf(w, `# HELP culvert_mcp_gateway_up 1 while the MCP gateway listener is accepting requests; 0 while it is not
# TYPE culvert_mcp_gateway_up gauge
culvert_mcp_gateway_up %d

# HELP culvert_mcp_gateway_faulted 1 while MCP enablement was requested but the capability is not serving (invalid, degraded or stopped)
# TYPE culvert_mcp_gateway_faulted gauge
culvert_mcp_gateway_faulted %d

# HELP culvert_mcp_requests_total MCP gateway requests received since startup
# TYPE culvert_mcp_requests_total counter
culvert_mcp_requests_total %d

# HELP culvert_mcp_requests_rejected_total MCP gateway requests rejected since startup
# TYPE culvert_mcp_requests_rejected_total counter
culvert_mcp_requests_rejected_total %d

# HELP culvert_mcp_auth_failures_total MCP gateway authentication failures since startup
# TYPE culvert_mcp_auth_failures_total counter
culvert_mcp_auth_failures_total %d

# HELP culvert_mcp_ambiguous_header_total MCP gateway requests refused for a duplicated singleton security header since startup (header-confusion / request-smuggling defense). Counts every guarded header; the credential-bearing subset is also counted by culvert_mcp_auth_failures_total
# TYPE culvert_mcp_ambiguous_header_total counter
culvert_mcp_ambiguous_header_total %d

# HELP culvert_mcp_host_origin_failures_total MCP gateway Host/Origin rejections since startup (DNS-rebinding / cross-origin defense)
# TYPE culvert_mcp_host_origin_failures_total counter
culvert_mcp_host_origin_failures_total %d

# HELP culvert_mcp_admission_rejected_total MCP gateway requests shed by admission since startup
# TYPE culvert_mcp_admission_rejected_total counter
culvert_mcp_admission_rejected_total %d

# HELP culvert_mcp_request_timeouts_total MCP gateway requests that exhausted their deadline since startup
# TYPE culvert_mcp_request_timeouts_total counter
culvert_mcp_request_timeouts_total %d

# HELP culvert_mcp_observe_drops_total MCP gateway observation records dropped by the bounded sink since startup
# TYPE culvert_mcp_observe_drops_total counter
culvert_mcp_observe_drops_total %d

# HELP culvert_mcp_active_sessions MCP gateway live protocol sessions
# TYPE culvert_mcp_active_sessions gauge
culvert_mcp_active_sessions %d

# HELP culvert_mcp_requests_in_flight MCP gateway requests currently being served
# TYPE culvert_mcp_requests_in_flight gauge
culvert_mcp_requests_in_flight %d

# HELP culvert_mcp_requests_queued MCP gateway requests admitted and waiting for a worker
# TYPE culvert_mcp_requests_queued gauge
culvert_mcp_requests_queued %d

# HELP culvert_mcp_policy_ready 1 while a node-local MCP policy snapshot is loaded and evaluable
# TYPE culvert_mcp_policy_ready gauge
culvert_mcp_policy_ready %d

# HELP culvert_mcp_inventory_ready 1 while an MCP server/tool inventory is published
# TYPE culvert_mcp_inventory_ready gauge
culvert_mcp_inventory_ready %d

# HELP culvert_mcp_telemetry_composed 1 while the MCP durable-event telemetry runtime is composed. Distinct from the labelled culvert_mcp_telemetry_ready{capability=...} series, which reports per-capability export readiness
# TYPE culvert_mcp_telemetry_composed gauge
culvert_mcp_telemetry_composed %d

# HELP culvert_mcp_distribution_composed 1 while a signed CP/DP MCP distribution applier is composed
# TYPE culvert_mcp_distribution_composed gauge
culvert_mcp_distribution_composed %d
`,
			boolGauge(m.ListenerReady),
			boolGauge(m.Faulted()),
			m.RequestsTotal,
			m.RequestsRejected,
			m.AuthFailures,
			m.AmbiguousHeaders,
			m.HostOriginFailures,
			m.AdmissionRejected,
			m.Timeouts,
			m.ObserveDrops,
			m.ActiveSessions,
			m.InFlight,
			m.Queued,
			boolGauge(m.PolicyState == "loaded"),
			boolGauge(m.InventoryReady),
			boolGauge(m.TelemetryReady),
			boolGauge(m.DistributionComposed),
		)
	}

	// CHAOS-45: durable-write (persistence) health. The boot-time writability
	// probe cannot see a volume that goes read-only or full LATER, and most
	// store Save() paths discard the write error — these series are the only
	// runtime signal that persisted state is being lost.
	// culvert_storage_write_degraded is 1 while a failure occurred inside
	// storageDegradedWindow; the age gauge is omitted entirely when no failure
	// has ever been observed (a "0" would read as "just failed").
	swSnap := storageWriteFailures()
	swDegraded := 0
	if storageDegraded() {
		swDegraded = 1
	}
	_, _ = fmt.Fprintf(w, `# HELP culvert_storage_write_failures_total Durable writes (fileutil.AtomicWrite) that failed since boot — persisted config/state was lost
# TYPE culvert_storage_write_failures_total counter
culvert_storage_write_failures_total %d

# HELP culvert_storage_write_degraded 1 when a durable write failed recently enough that persistence should be treated as broken
# TYPE culvert_storage_write_degraded gauge
culvert_storage_write_degraded %d
`,
		swSnap.Total,
		swDegraded,
	)
	if swSnap.Total > 0 {
		_, _ = fmt.Fprintf(w, `# HELP culvert_storage_write_last_failure_age_seconds Seconds since the most recent durable-write failure (absent when none has occurred)
# TYPE culvert_storage_write_last_failure_age_seconds gauge
culvert_storage_write_last_failure_age_seconds %d
`,
			int64(time.Since(swSnap.Last).Seconds()),
		)
	}

	// CHAOS-47: identity-backend reachability. culvert_requests_auth_fail
	// conflates "wrong password" with "the directory is down", which is exactly
	// the ambiguity that made an IdP outage look like a brute-force spike.
	// These series separate the infrastructure half: _unavailable_total counts
	// detected unreachable outcomes (one per probe, not per denied request),
	// _unavailable is 1 while a backend is in its cooldown, and
	// _gated_denials_total is the blast radius — requests denied without
	// contacting the backend while it was gated.
	abSnap := authBackendHealthStatus()
	abDegraded := 0
	if abSnap.Degraded {
		abDegraded = 1
	}
	_, _ = fmt.Fprintf(w, `# HELP culvert_auth_backend_unavailable_total Times an external identity backend (LDAP/OIDC) could not be reached — authentication failed closed
# TYPE culvert_auth_backend_unavailable_total counter
culvert_auth_backend_unavailable_total %d

# HELP culvert_auth_backend_unavailable 1 while an external identity backend is unreachable (cleared only by an observed successful reach)
# TYPE culvert_auth_backend_unavailable gauge
culvert_auth_backend_unavailable %d

# HELP culvert_auth_backend_gated_denials_total Authentication attempts denied during an identity-backend outage without contacting the backend
# TYPE culvert_auth_backend_gated_denials_total counter
culvert_auth_backend_gated_denials_total %d
`,
		abSnap.Unavailable,
		abDegraded,
		abSnap.GatedDenials,
	)

	// Decryption-profile success delta: which protocol inspected tunnels negotiated
	// on the upstream leg (h2 = Inspect-as-HTTP/2 working; http/1.1 = strip/downgrade).
	_, _ = fmt.Fprintf(w, `# HELP culvert_inspect_upstream_alpn_total Inspected-tunnel upstream (origin) leg negotiated protocol
# TYPE culvert_inspect_upstream_alpn_total counter
culvert_inspect_upstream_alpn_total{protocol="h2"} %d
culvert_inspect_upstream_alpn_total{protocol="http/1.1"} %d
`,
		atomic.LoadInt64(&statInspectUpstreamH2),
		atomic.LoadInt64(&statInspectUpstreamH1),
	)

	// Adaptive decryption-exclusion (fail-open) observability: sessions bypassed
	// because of a learned exclusion, and current cache occupancy (inspection-
	// coverage erosion the operator can alert on). Learn events (by reason) append
	// via autoExcludeLearns.writePrometheus below.
	aeStats := autoExclude().Stats()
	// hit_total{scope} and active{scope} are emitted as labelled series below (F6, via
	// autoExcludeHitsByScope + writeAutoExcludeActiveByScope); the process total is
	// sum()-able and also surfaced on /api/decryption/health.
	_, _ = fmt.Fprintf(w, `# HELP culvert_decrypt_autoexclude_pending Current count of in-progress (unconfirmed) exclusion observations
# TYPE culvert_decrypt_autoexclude_pending gauge
culvert_decrypt_autoexclude_pending %d
# HELP culvert_decrypt_autoexclude_rescue_total Sessions live-bypassed on the first client_cert_required signal (confirm-count-exempt, before any persistent promotion)
# TYPE culvert_decrypt_autoexclude_rescue_total counter
culvert_decrypt_autoexclude_rescue_total %d
# HELP culvert_decrypt_autoexclude_surge_total Abnormal-learning-rate alerts fired (promotion rate crossed the surge threshold within a window) — a poisoning-campaign indicator
# TYPE culvert_decrypt_autoexclude_surge_total counter
culvert_decrypt_autoexclude_surge_total %d
`,
		aeStats.Pending,
		atomic.LoadInt64(&autoExcludeRescueCounter),
		atomic.LoadInt64(&autoExcludeSurgeCounter),
	)

	// Append per-rule hit counters, latency histogram, and CDR metrics.
	ruleMet.WritePrometheus(&ruleMetBuf)
	decProfMintlsRejects.writePrometheus(&ruleMetBuf)
	autoExcludeLearns.writePrometheus(&ruleMetBuf)
	autoExcludeHitsByScope.writePrometheus(&ruleMetBuf) // F6: per-scope autoexclude hit counter
	writeAutoExcludeActiveByScope(&ruleMetBuf)          // F6: per-scope autoexclude active gauge
	decSessions.writePrometheus(&ruleMetBuf)            // culvert_decrypt_sessions_total (ADR-0011 coverage)
	decFailures.writePrometheus(&ruleMetBuf)            // culvert_decrypt_failures_total (ADR-0011 failure taxonomy)
	crashByComponent.writePrometheus(&ruleMetBuf)       // culvert_crash_records_* (panic recovery)
	latencyHist.WritePrometheus(&ruleMetBuf)
	urlcatWritePrometheus(&ruleMetBuf)
	caWritePrometheus(&ruleMetBuf)
	certSignHist.WritePrometheus(&ruleMetBuf)
	clusterWritePrometheus(&ruleMetBuf)
	cdrWritePrometheus(&ruleMetBuf)
	liveFeedWritePrometheus(&ruleMetBuf)
	releaseCatalogWritePrometheus(&ruleMetBuf)
	pacWritePrometheus(&ruleMetBuf)
	supportWritePrometheus(&ruleMetBuf)   // culvert_support_bundle_retention_* (M5 retention observability)
	saasFeedWritePrometheus(&ruleMetBuf)  // culvert_saasfeed_* (F3b-4 signed-feed observability)
	writeMCPTelemetryMetrics(&ruleMetBuf) // culvert_mcp_* (QUAL-3 durable telemetry, low-cardinality)
	writeMCPShadowMetrics(&ruleMetBuf)    // culvert_mcp_shadow_* (controlled Shadow activation, low-cardinality)
	fmt.Fprint(w, ruleMetBuf.String())    //nolint:errcheck // writes to http.ResponseWriter; an error only means the client disconnected
}
