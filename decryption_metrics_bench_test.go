package main

// decryption_metrics_bench_test.go — before/after evidence for the decryption
// COVERAGE counter's write path (decryption_metrics.go), which runs once per
// CONNECT tunnel that carries a decryption decision and therefore once per
// HTTPS connection on a gateway.
//
// Run:
//
//	go test -run '^$' -bench 'BenchmarkDecSessionRecord' -benchmem -count=5 -cpu=1,2,4 .
//
// decSessionCounterLegacy is the FROZEN pre-change shape — an RWMutex read lock
// around a map keyed by "outcome\x00source\x00tlsVer". It is kept in-tree, like
// BenchmarkHTTPForward_LegacyClientPerRequest, so the comparison stays
// reproducible here rather than living only in a commit message. It is a
// deliberately verbatim copy of the code that was replaced; it is NOT called by
// production and must not be "kept in sync" with decSessionCounter — its whole
// value is that it does not move. TestDecSessionCounter_MatchesLegacyShape
// proves it still reproduces the shipped counter's exposition byte for byte, so
// its retirement rests on cost and not on a broken prototype.
//
// ── HOW TO READ THESE NUMBERS ───────────────────────────────────────────────
//
// The *Parallel arms are RunParallel, so ns/op is wall time per op across ALL
// workers: a genuinely parallel cost FALLS as cores are added and one that
// serialises RISES. Absolute ns/op on a shared vCPU is not comparable between
// invocations, so measure every arm in ONE invocation and read the RATIO.
//
// 4-vCPU Xeon @2.10GHz, go1.27.4/linux-amd64, all arms in one invocation,
// -count=5, medians:
//
//	arm                            │  P=1   │  P=2   │  P=4   │ allocs/op
//	legacy, serial                  │  86 ns │  77 ns │  78 ns │  1 (48 B)
//	shipped, serial                 │  25 ns │  24 ns │  25 ns │     0
//	legacy, one live series         │  91 ns │ 161 ns │ 175 ns │  1 (48 B)
//	shipped, one live series        │  25 ns │  96 ns │ 104 ns │     0
//	legacy, mixed live series       │  93 ns │ 175 ns │ 194 ns │  1 (41 B)
//	shipped, mixed live series      │  33 ns │  46 ns │  26 ns │     0
//
// Mixed is the shape a real fleet has (several outcomes and decision sources in
// flight at once) and it is the one that matters: it IMPROVES with core count
// (93 → 26 ns, 7.5x faster than the locked form at four cores) where the locked
// form degrades (93 → 194 ns). Serially the win is 3.4x and one allocation.
//
// The single-series arm records the FLOOR honestly: the shipped shape still
// rises 25 → 104 ns there, because every worker then atomically increments the
// same counter word. That is inherent to a shared counter and the locked form
// pays it too (91 → 175 ns, so the shipped form stays ~1.7x ahead even in that
// shape); this change removes only the reader lock and the per-call key
// allocation stacked on top of it.

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/decryptobs"
)

// ── FROZEN pre-change shape. Do not update. ─────────────────────────────────

type decSessionCounterLegacy struct {
	mu     sync.RWMutex
	counts map[string]*decSessionLabel
	order  []string
}

func newDecSessionCounterLegacy() *decSessionCounterLegacy {
	return &decSessionCounterLegacy{counts: map[string]*decSessionLabel{}}
}

func (c *decSessionCounterLegacy) record(outcome, source, tlsVer string) {
	k := outcome + "\x00" + source + "\x00" + tlsVer
	c.mu.RLock()
	ll, ok := c.counts[k]
	c.mu.RUnlock()
	if ok {
		atomic.AddInt64(&ll.n, 1)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ll, ok = c.counts[k]; ok { // double-check after upgrading the lock
		atomic.AddInt64(&ll.n, 1)
		return
	}
	c.counts[k] = &decSessionLabel{outcome: outcome, source: source, tlsVer: tlsVer, n: 1}
	c.order = append(c.order, k)
}

// snapshot is the legacy read path, verbatim. It is what the differential test
// compares against: the series in INSERTION ORDER with their counts, which is
// the observable contract both the Prometheus exposition and
// /api/decryption/health inherit. The test deliberately does NOT freeze the
// exposition's HELP text here — that would make a wording change look like a
// behavior change.
func (c *decSessionCounterLegacy) snapshot() []decSessionSample {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]decSessionSample, 0, len(c.order))
	for _, k := range c.order {
		ll := c.counts[k]
		out = append(out, decSessionSample{ll.outcome, ll.source, ll.tlsVer, atomic.LoadInt64(&ll.n)})
	}
	return out
}

// ── fixtures ────────────────────────────────────────────────────────────────

// decBenchSeries is the live label space the benchmarks rotate: the enum values
// production actually emits, taken from the vocabulary itself so a renamed enum
// cannot leave the benchmark measuring a series the product no longer has.
func decBenchSeries() (outcomes, sources, vers []string) {
	for _, o := range decryptobs.AllOutcomes {
		outcomes = append(outcomes, o.String())
	}
	for _, d := range decryptobs.AllDecisionSources {
		sources = append(sources, d.String())
	}
	for _, v := range decryptobs.AllTLSVersions {
		vers = append(vers, v.String())
	}
	return outcomes, sources, vers
}

// The dominant single series on a mixed-policy gateway: a tunnel a policy rule
// declined to inspect.
const (
	decBenchOutcome = "not_decrypted"
	decBenchSource  = "policy_inspect"
	decBenchTLS     = "unknown"
)

// warmDecSessions / warmDecSessionsLegacy pre-create every series, so the
// benchmarks measure the STEADY-STATE write and never the once-per-process
// insert. Production reaches this state within the first few hundred sessions.
func warmDecSessions() *decSessionCounter {
	c := &decSessionCounter{}
	outcomes, sources, vers := decBenchSeries()
	for _, o := range outcomes {
		for _, s := range sources {
			for _, v := range vers {
				c.record(o, s, v)
			}
		}
	}
	return c
}

func warmDecSessionsLegacy() *decSessionCounterLegacy {
	c := newDecSessionCounterLegacy()
	outcomes, sources, vers := decBenchSeries()
	for _, o := range outcomes {
		for _, s := range sources {
			for _, v := range vers {
				c.record(o, s, v)
			}
		}
	}
	return c
}

// ── arms ────────────────────────────────────────────────────────────────────

func BenchmarkDecSessionRecord_Serial(b *testing.B) {
	c := warmDecSessions()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.record(decBenchOutcome, decBenchSource, decBenchTLS)
	}
}

func BenchmarkDecSessionRecord_LegacyLockedSerial(b *testing.B) {
	c := warmDecSessionsLegacy()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.record(decBenchOutcome, decBenchSource, decBenchTLS)
	}
}

func BenchmarkDecSessionRecord_OneSeriesParallel(b *testing.B) {
	c := warmDecSessions()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.record(decBenchOutcome, decBenchSource, decBenchTLS)
		}
	})
}

func BenchmarkDecSessionRecord_LegacyLockedOneSeriesParallel(b *testing.B) {
	c := warmDecSessionsLegacy()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.record(decBenchOutcome, decBenchSource, decBenchTLS)
		}
	})
}

// decSeriesWalk rotates the whole live label space deterministically. It is a
// strided walk, not a PRNG: the stride is coprime with the space size, so every
// series is visited once per cycle with no repeats and no clustering, and the
// sequence is identical on every run and every runner — which a benchmark
// comparing two arms needs and a seeded generator only approximates. Each
// worker starts at its own offset so the workers are not marching in lockstep
// on one series (that case is the OneSeriesParallel arm, measured separately).
type decSeriesWalk struct {
	outcomes, sources, vers []string
	i, stride, mod          int
}

func newDecSeriesWalk(start int) *decSeriesWalk {
	outcomes, sources, vers := decBenchSeries()
	mod := len(outcomes) * len(sources) * len(vers)
	// 17 is coprime with every plausible product of the three enum sizes; assert
	// rather than assume, so a future enum change cannot silently turn this walk
	// into a short cycle that measures a handful of series.
	const stride = 17
	if mod%stride == 0 {
		panic("decSeriesWalk: stride must be coprime with the label space size")
	}
	return &decSeriesWalk{outcomes: outcomes, sources: sources, vers: vers, i: start % mod, stride: stride, mod: mod}
}

func (w *decSeriesWalk) next() (outcome, source, tlsVer string) {
	n := w.i
	w.i = (w.i + w.stride) % w.mod
	o := n % len(w.outcomes)
	n /= len(w.outcomes)
	s := n % len(w.sources)
	n /= len(w.sources)
	return w.outcomes[o], w.sources[s], w.vers[n%len(w.vers)]
}

// The realistic fleet shape: several outcomes and decision sources live at once,
// so the counter adds land on different series instead of one shared word.
func BenchmarkDecSessionRecord_MixedParallel(b *testing.B) {
	c := warmDecSessions()
	var worker atomic.Int64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		w := newDecSeriesWalk(int(worker.Add(1)) * 5)
		for pb.Next() {
			c.record(w.next())
		}
	})
}

func BenchmarkDecSessionRecord_LegacyLockedMixedParallel(b *testing.B) {
	c := warmDecSessionsLegacy()
	var worker atomic.Int64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		w := newDecSeriesWalk(int(worker.Add(1)) * 5)
		for pb.Next() {
			c.record(w.next())
		}
	})
}
