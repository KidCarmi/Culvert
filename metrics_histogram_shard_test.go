package main

// metrics_histogram_shard_test.go — correctness + regression gates for the
// sharded latency histogram (metrics.go).
//
// latencyHist.Observe runs on EVERY proxied request, so this file has two
// jobs. The COST job is to keep the sharding from silently collapsing back to
// one contended counter set: TestBenchGate_ObservationsDoNotShareOneCounter is
// structural (it inspects which shards received writes) rather than
// timing-based, so it cannot flake on a shared runner or under -race — the
// lesson internal/connlimit's shard gate records.
//
// The CORRECTNESS job is larger, because sharding moved arithmetic from the
// write path to the read path: every count, sum and rendered line must be
// identical to the unsharded version, under concurrency and across shards.
//
// Run locally:
//
//	go test -run 'Histogram' .
//	go test -race -run 'Histogram' .
//	go test -run '^$' -bench 'LatencyHistogram' -benchmem -cpu=1,2,4 .

import (
	"math"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unsafe"
)

// ── Structure ────────────────────────────────────────────────────────────────

// TestHistogramShardIsCacheLineSized pins the padding. Unpadded, two shards
// share a cache line and one observer's atomic write invalidates its
// neighbour's line — false sharing that hands back most of what splitting the
// counters just bought (measured, not assumed, in internal/connlimit).
func TestHistogramShardIsCacheLineSized(t *testing.T) {
	if got := unsafe.Sizeof(histShard{}); got != histShardBytes {
		t.Fatalf("unsafe.Sizeof(histShard{}) = %d, want %d — the padding no longer "+
			"isolates a shard, so neighbouring shards will false-share a cache line", got, histShardBytes)
	}
}

// TestHistogramBucketLimit proves every histogram constructed in the tree fits
// the fixed per-shard counter array, so newHistogram's panic guard is
// unreachable in production.
func TestHistogramBucketLimit(t *testing.T) {
	for _, h := range []*latencyHistogram{latencyHist, certSignHist, dpPollHist} {
		if len(h.buckets) > maxHistogramBuckets {
			t.Errorf("%s declares %d bucket bounds, exceeding maxHistogramBuckets=%d",
				h.name, len(h.buckets), maxHistogramBuckets)
		}
	}
}

// TestHistogramRejectsTooManyBuckets pins the guard itself: silently
// truncating a caller's bucket layout would render a histogram whose top
// bounds simply never count.
func TestHistogramRejectsTooManyBuckets(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("newHistogram accepted more than maxHistogramBuckets bounds; " +
				"the extra bounds would silently never be counted")
		}
	}()
	bounds := make([]float64, maxHistogramBuckets+1)
	for i := range bounds {
		bounds[i] = float64(i + 1)
	}
	newHistogram("too_many", "help", bounds)
}

// ── Accounting ───────────────────────────────────────────────────────────────

// TestHistogramCountsAndSumAcrossShards is the core correctness proof: values
// chosen to land in different buckets AND (via the value-derived shard index)
// on different shards must still fold back into exactly the right per-bucket
// counts, total, and sum.
func TestHistogramCountsAndSumAcrossShards(t *testing.T) {
	h := newLatencyHistogram()

	// 0.001 → le=0.005 (index 0), 0.05 → le=0.05 (index 3),
	// 0.3 → le=0.5 (index 6), 100 → +Inf (last).
	obs := []float64{0.001, 0.05, 0.3, 100}
	var want float64
	for _, v := range obs {
		h.Observe(v)
		want += v
	}

	counts, total, sum := h.snapshot()
	if total != int64(len(obs)) {
		t.Fatalf("total = %d, want %d", total, len(obs))
	}
	if got := h.Count(); got != total {
		t.Fatalf("Count() = %d, want %d (must agree with snapshot)", got, total)
	}
	for _, idx := range []int{0, 3, 6, len(h.buckets)} {
		if counts[idx] != 1 {
			t.Errorf("counts[%d] = %d, want 1 (buckets: %v)", idx, counts[idx], counts)
		}
	}
	if math.Abs(sum-want) > 1e-9 {
		t.Errorf("sum = %v, want %v", sum, want)
	}
}

// TestHistogramSpreadObservationsAreNotLost walks a wide range of realistic
// latencies. Every one must be counted exactly once no matter which shard it
// hashes onto — a sharding bug that dropped or double-counted an observation
// would be invisible to a single-value test.
func TestHistogramSpreadObservationsAreNotLost(t *testing.T) {
	h := newLatencyHistogram()
	const n = 20000
	var want float64
	for i := 0; i < n; i++ {
		// Nanosecond-resolution durations, the shape time.Since produces.
		v := float64(1_000_000+int64(i)*7919) / 1e9
		h.Observe(v)
		want += v
	}
	counts, total, sum := h.snapshot()
	if total != n {
		t.Fatalf("total = %d, want %d", total, n)
	}
	var bucketed int64
	for _, c := range counts {
		bucketed += c
	}
	if bucketed != n {
		t.Fatalf("bucket counts sum to %d, want %d", bucketed, n)
	}
	if rel := math.Abs(sum-want) / want; rel > 1e-9 {
		t.Errorf("sum = %v, want %v (relative error %v)", sum, want, rel)
	}
}

// TestHistogramConcurrentObserversAreExact is the concurrency gate: the
// counters are only correct if every shard write is atomic and every
// observation lands in exactly one bucket. Run under -race this also proves
// the shard array is never written non-atomically.
func TestHistogramConcurrentObserversAreExact(t *testing.T) {
	h := newLatencyHistogram()
	const goroutines, perGoroutine = 16, 2000

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				h.Observe(float64(2_000_000+int64(g*perGoroutine+i)*3571) / 1e9)
			}
		}(g)
	}
	wg.Wait()

	_, total, _ := h.snapshot()
	if want := int64(goroutines * perGoroutine); total != want {
		t.Fatalf("total after concurrent observation = %d, want %d — observations were lost", total, want)
	}
}

// TestHistogramNonFiniteObservationDoesNotPoisonSum pins the finite guard.
// The pre-sharding accumulator had no equivalent: one NaN observation turned
// `_sum` into NaN for the lifetime of the process, and a scrape has no way to
// recover from that.
func TestHistogramNonFiniteObservationDoesNotPoisonSum(t *testing.T) {
	h := newLatencyHistogram()
	h.Observe(0.1)
	h.Observe(math.NaN())
	h.Observe(math.Inf(1))
	h.Observe(0.1)

	_, total, sum := h.snapshot()
	if total != 4 {
		t.Fatalf("total = %d, want 4 (every observation is still bucketed)", total)
	}
	if math.IsNaN(sum) || math.IsInf(sum, 0) {
		t.Fatalf("sum = %v — a non-finite observation poisoned the accumulator", sum)
	}
	if math.Abs(sum-0.2) > 1e-6 {
		t.Errorf("sum = %v, want 0.2 (finite observations only)", sum)
	}
}

// TestHistogramSumDoesNotOverflowAtHighAggregateLatency is the regression test
// for the review finding on PR #1200: an int64-NANOSECOND accumulator wraps
// once AGGREGATE observed latency passes ~9.2e9 seconds, which is only ~107
// days of uptime for a 10k req/s gateway averaging 100ms — and a wrapped sum
// exports a NEGATIVE, non-monotonic `_sum` to Prometheus and OTLP, which the
// pre-sharding float64 accumulator could never do.
//
// Each observation here is 1e9 seconds, so twenty of them total 2e10 seconds =
// 2e19 nanoseconds, comfortably past math.MaxInt64 (9.22e18). They also share
// one value, so they all land on ONE shard — which is the worst case, and the
// case a per-shard integer counter would still wrap in even if the fold were
// widened. The sum must come back positive and correct.
func TestHistogramSumDoesNotOverflowAtHighAggregateLatency(t *testing.T) {
	h := newLatencyHistogram()
	const each, n = 1e9, 20
	for i := 0; i < n; i++ {
		h.Observe(each)
	}

	_, total, sum := h.snapshot()
	if total != n {
		t.Fatalf("total = %d, want %d", total, n)
	}
	if sum <= 0 {
		t.Fatalf("sum = %v — the accumulator wrapped; a negative _sum breaks the "+
			"Prometheus monotonicity contract for histogram sums", sum)
	}
	if want := float64(each) * n; math.Abs(sum-want)/want > 1e-12 {
		t.Fatalf("sum = %v, want %v", sum, want)
	}

	// The rendered line must not carry a minus sign either.
	var buf strings.Builder
	h.WritePrometheus(&buf)
	got := metricValue(t, buf.String(), "culvert_request_duration_seconds_sum ")
	if strings.HasPrefix(got, "-") {
		t.Fatalf("_sum rendered as %s — negative sums are never valid", got)
	}
}

// ── Exposition ───────────────────────────────────────────────────────────────

// TestHistogramPrometheusCountEqualsInfBucket pins the exposition invariant
// the Prometheus text format requires and the unsharded version could violate:
// `total` used to be incremented BEFORE the bucket, so a scrape landing
// between the two rendered `_count` one greater than the `+Inf` bucket.
// Deriving the count from the very bucket counters that are rendered makes the
// two equal by construction.
func TestHistogramPrometheusCountEqualsInfBucket(t *testing.T) {
	h := newLatencyHistogram()
	for i := 0; i < 500; i++ {
		h.Observe(float64(500_000+int64(i)*104729) / 1e9)
	}

	var buf strings.Builder
	h.WritePrometheus(&buf)
	out := buf.String()

	inf := metricValue(t, out, `culvert_request_duration_seconds_bucket{le="+Inf"} `)
	count := metricValue(t, out, "culvert_request_duration_seconds_count ")
	if inf != count {
		t.Fatalf("+Inf bucket = %s but _count = %s — Prometheus requires them equal", inf, count)
	}
	if count != "500" {
		t.Fatalf("_count = %s, want 500", count)
	}
}

// TestHistogramPrometheusBucketsAreCumulative pins the other half of the
// exposition contract: bucket counts must be monotonically non-decreasing.
func TestHistogramPrometheusBucketsAreCumulative(t *testing.T) {
	h := newLatencyHistogram()
	for i := 0; i < 300; i++ {
		h.Observe(float64(i) * 0.05)
	}
	var buf strings.Builder
	h.WritePrometheus(&buf)

	var prev int64
	for _, line := range strings.Split(buf.String(), "\n") {
		if !strings.HasPrefix(line, "culvert_request_duration_seconds_bucket{") {
			continue
		}
		v, err := strconv.ParseInt(line[strings.LastIndex(line, " ")+1:], 10, 64)
		if err != nil {
			t.Fatalf("unparsable bucket line %q: %v", line, err)
		}
		if v < prev {
			t.Fatalf("bucket counts are not cumulative: %d after %d (line %q)", v, prev, line)
		}
		prev = v
	}
}

// metricValue extracts the value that follows prefix in a Prometheus text body.
func metricValue(t *testing.T, body, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	t.Fatalf("no line with prefix %q in:\n%s", prefix, body)
	return ""
}

// ── Sharding gates ───────────────────────────────────────────────────────────

// shardsTouched reports how many distinct shards hold at least one count.
func shardsTouched(h *latencyHistogram) int {
	n := 0
	for i := range h.shards {
		for j := range h.shards[i].counts {
			if h.shards[i].counts[j] != 0 {
				n++
				break
			}
		}
	}
	return n
}

// TestBenchGate_ObservationsDoNotShareOneCounter is the hard regression gate on
// the sharded histogram, and it is deliberately STRUCTURAL rather than
// timing-based.
//
// The obvious gate — measure ns/op at -cpu=1 and -cpu=4 and require the ratio
// not to grow — separates the two shapes decisively on a quiet machine (10.6x
// worse per op at four cores before, flat after) but its margin is thin on a
// shared CI runner and thinner still under -race. A gate that can flake is
// worse than no gate: it gets muted.
//
// This form has no margin to erode. It observes a realistic spread of
// latencies and requires them to land on many distinct shards. If the
// histogram reverts to one process-wide counter set — exactly the regression
// to catch — every observation lands on the single shard and this fails
// deterministically, on any hardware, at any load, with or without -race.
//
// The throughput this protects is recorded on the sharding note in metrics.go
// and on BenchmarkLatencyHistogramObserveParallel.
func TestBenchGate_ObservationsDoNotShareOneCounter(t *testing.T) {
	h := newLatencyHistogram()
	const n = 4096
	for i := 0; i < n; i++ {
		h.Observe(realisticLatency(i))
	}

	touched := shardsTouched(h)
	// With n >> histShardCount and a well-mixed index, every shard should be
	// hit; the floor is set well below that so the gate fires only on a real
	// collapse, never on hash luck.
	const floor = histShardCount / 2
	if touched < floor {
		t.Fatalf("REGRESSION: %d realistic observations touched only %d of %d shards (want ≥ %d) — "+
			"concurrent observers are writing the same cache line, which is the contended "+
			"single-counter shape this sharding replaced", n, touched, histShardCount, floor)
	}
}

// TestBenchGate_ConstantObservationsCollapseToOneShard is the control for the
// gate above: it proves the gate CAN fail, so a pass means the spread is real
// and not that shardsTouched counts something else. It also pins the honest
// limitation — a caller observing a CONSTANT value gets one shard, i.e. the
// old behaviour, never worse (that path is still two atomic adds rather than a
// CAS loop plus two).
func TestBenchGate_ConstantObservationsCollapseToOneShard(t *testing.T) {
	h := newLatencyHistogram()
	for i := 0; i < 4096; i++ {
		h.Observe(0.05)
	}
	if touched := shardsTouched(h); touched != 1 {
		t.Fatalf("constant observations touched %d shards, want exactly 1 — "+
			"shard selection is not a pure function of the observed value", touched)
	}
}

// TestHistogramShardSpread reports the distribution quality rather than
// asserting a tight bound on it, so a hash change shows its effect in the
// output instead of failing an arbitrary threshold. It fails only on an
// outright degenerate spread.
func TestHistogramShardSpread(t *testing.T) {
	var hits [histShardCount]int
	h := newLatencyHistogram()
	const n = 4096
	for i := 0; i < n; i++ {
		hits[shardIndexOf(h, realisticLatency(i))]++
	}
	minHits, maxHits, empty := 1<<30, 0, 0
	for _, c := range hits {
		if c < minHits {
			minHits = c
		}
		if c > maxHits {
			maxHits = c
		}
		if c == 0 {
			empty++
		}
	}
	t.Logf("n=%d shards=%d min=%d max=%d mean=%.1f empty=%d",
		n, histShardCount, minHits, maxHits, float64(n)/histShardCount, empty)
	if empty > histShardCount/4 {
		t.Errorf("%d of %d shards received nothing — shard selection is not spreading realistic latencies",
			empty, histShardCount)
	}
}

// shardIndexOf resolves the shard a value maps to, by pointer identity.
func shardIndexOf(h *latencyHistogram, seconds float64) int {
	target := h.histShardFor(seconds)
	for i := range h.shards {
		if &h.shards[i] == target {
			return i
		}
	}
	panic("shard not found")
}

// ── Benchmarks ───────────────────────────────────────────────────────────────

// realisticLatency returns a proxied-request latency in seconds: a bimodal
// distribution at nanosecond resolution, which is what time.Since produces and
// therefore what the value-derived shard index has to spread.
func realisticLatency(i int) float64 {
	var base int64
	switch i % 8 {
	case 0, 1, 2:
		base = 30_000_000
	case 3, 4, 5:
		base = 70_000_000
	case 6:
		base = 8_000_000
	default:
		base = 400_000_000
	}
	// Deterministic sub-millisecond jitter, so the low mantissa bits vary the
	// way a real clock's do without pulling in a PRNG.
	return float64(base+int64(i)*104729%(base/5)) / 1e9
}

var benchLatencies = func() []float64 {
	s := make([]float64, 4096)
	for i := range s {
		s[i] = realisticLatency(i)
	}
	return s
}()

// BenchmarkLatencyHistogramObserve measures the serial cost of one
// observation. The sharded form is no more expensive uncontended: the extra
// index mix is paid for by dropping the separate total counter, and the CAS
// that remains is per shard rather than process-wide.
func BenchmarkLatencyHistogramObserve(b *testing.B) {
	h := newLatencyHistogram()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Observe(benchLatencies[i&4095])
	}
}

// BenchmarkLatencyHistogramObserveParallel is the one that matters: it
// measures how the per-observation cost MOVES with core count, which is what
// the contended single-counter shape got wrong. Run it as:
//
//	go test -run '^$' -bench LatencyHistogramObserveParallel -cpu=1,2,4 .
//
// Reference 4-core box, median of n=10: before 15.0 / 125.5 / 158.9 ns/op at
// 1 / 2 / 4 cores (adding cores SUBTRACTED throughput — 6.3M obs/s on four
// cores against 67M on one); after 13.6 / 16.6 / 12.0 ns/op, i.e. flat.
func BenchmarkLatencyHistogramObserveParallel(b *testing.B) {
	h := newLatencyHistogram()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			h.Observe(benchLatencies[i&4095])
			i++
		}
	})
}

// BenchmarkLatencyHistogramWritePrometheus measures the read side, which is
// where sharding moved the work. A scrape happens once per scrape interval
// against a per-request write path, so this is the correct direction to trade
// — but it is measured rather than assumed.
func BenchmarkLatencyHistogramWritePrometheus(b *testing.B) {
	h := newLatencyHistogram()
	for i := 0; i < 100000; i++ {
		h.Observe(benchLatencies[i&4095])
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf strings.Builder
		h.WritePrometheus(&buf)
	}
}

// BenchmarkLatencyHistogramSnapshot isolates the shard fold from the
// formatting, so a future change to histShardCount can be costed directly.
func BenchmarkLatencyHistogramSnapshot(b *testing.B) {
	h := newLatencyHistogram()
	for i := 0; i < 100000; i++ {
		h.Observe(benchLatencies[i&4095])
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, total, _ := h.snapshot(); total == 0 {
			b.Fatal("empty snapshot")
		}
	}
}
