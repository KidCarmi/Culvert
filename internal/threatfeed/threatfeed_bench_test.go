package threatfeed

import (
	"fmt"
	"testing"
	"time"
)

// Threat-feed lookup benchmarks.
//
// CheckDomain runs on EVERY proxied request (proxy.go preDispatchBlocked) and
// CheckURL additionally on every plain-HTTP request, so their fixed cost is
// paid by all traffic — and in normal operation both MISS. The miss path is
// therefore the number that matters; a hit is a blocked request that is about
// to serve a block page anyway.
//
// Run:
//
//	go test -run '^$' -bench 'BenchmarkFeedCheck' -benchmem ./internal/threatfeed/

// benchFeed returns an enabled feed populated with n domain and n URL entries,
// none of which the benchmark queries match. Map size is varied because a real
// deployment carries tens of thousands of entries; a lookup that only ever runs
// against an empty map would flatter the map probe and hide the fixed
// normalisation cost that dominates it.
func benchFeed(n int) *Feed {
	tf := newEnabledFeed()
	for i := 0; i < n; i++ {
		host := fmt.Sprintf("malware-%d.example.invalid", i)
		tf.domains[host] = entry{Source: "urlhaus", AddedAt: time.Now()}
		tf.urls["http://"+host+"/payload"] = entry{Source: "urlhaus", AddedAt: time.Now()}
	}
	tf.totalEntries.Store(int64(n * 2))
	return tf
}

// BenchmarkFeedCheckDomain_Miss measures the per-request domain lookup on the
// clean-traffic path. The host handed in is the already-canonical form the
// proxy pipeline produced.
func BenchmarkFeedCheckDomain_Miss(b *testing.B) {
	for _, n := range []int{0, 1000, 100000} {
		tf := benchFeed(n)
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if hit, _ := tf.CheckDomain("www.example.com"); hit {
					b.Fatal("unexpected hit")
				}
			}
		})
	}
}

// BenchmarkFeedCheckURL_Miss measures the per-request full-URL lookup on the
// clean-traffic path.
func BenchmarkFeedCheckURL_Miss(b *testing.B) {
	for _, n := range []int{0, 1000, 100000} {
		tf := benchFeed(n)
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if hit, _ := tf.CheckURL("http://www.example.com/some/path?q=1"); hit {
					b.Fatal("unexpected hit")
				}
			}
		})
	}
}

// BenchmarkFeedCheckDomain_MissParallel is the contention measure — the number
// that motivated the lock-free readView, and the one that regresses first if a
// lock ever returns to the read path.
//
// Both checks used to take tf.mu.RLock twice (once inside Enabled(), once for
// the map probe), and sync.RWMutex.RLock is an atomic read-modify-write on one
// shared word, so every request wrote the same cache line. Measured here on a
// 4-core Xeon at 100k entries:
//
//	                      serial      4x parallel   scaling
//	before (RWMutex)     100.6 ns/op   211.7 ns/op   0.48x  ← slower with more cores
//	after  (readView)     88.8 ns/op    22.6 ns/op   3.93x  ← near-linear
//
// i.e. the old shape was not a constant cost but a throughput ceiling: adding
// cores REDUCED aggregate lookup throughput, on a per-request path, precisely
// when a gateway is busiest.
func BenchmarkFeedCheckDomain_MissParallel(b *testing.B) {
	tf := benchFeed(100000)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if hit, _ := tf.CheckDomain("www.example.com"); hit {
				b.Fatal("unexpected hit")
			}
		}
	})
}

// BenchmarkFeedCheckURL_MissParallel is the CheckURL half of the contention
// measure.
func BenchmarkFeedCheckURL_MissParallel(b *testing.B) {
	tf := benchFeed(100000)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if hit, _ := tf.CheckURL("http://www.example.com/some/path?q=1"); hit {
				b.Fatal("unexpected hit")
			}
		}
	})
}

// ── Regression gate ───────────────────────────────────────────────────────────

// TestBenchGate_LookupsTakeNoFeedLock is the hard gate on the lock-free read
// path, and it is deliberately STRUCTURAL rather than timing-based.
//
// The obvious gate — measure serial vs parallel ns/op and require positive
// scaling — was built and measured first. It separates the two shapes cleanly
// without instrumentation (0.48x before, 3.93x after), but under `-race` the
// margin narrows to 1.35x–2.29x across runs, which is too thin to put in front
// of every PR on a shared CI runner. A gate that can flake is worse than no
// gate: it gets muted.
//
// This form has no margin to erode. It takes the feed's write lock and holds
// it, then requires every per-request lookup to complete anyway. If any of them
// reverts to acquiring tf.mu — which is exactly the regression to catch — it
// blocks until the deadline and fails deterministically, on any hardware, at
// any load, with or without the race detector.
//
// The throughput numbers this protects are recorded on
// BenchmarkFeedCheckDomain_MissParallel above.
func TestBenchGate_LookupsTakeNoFeedLock(t *testing.T) {
	tf := benchFeed(1000)
	tf.domains["locked.example"] = entry{Source: "urlhaus", AddedAt: time.Now()}
	if mal, _ := tf.CheckDomain("locked.example"); !mal { // publish the view before locking
		t.Fatal("seeded domain does not block")
	}

	tf.mu.Lock()
	defer tf.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		tf.Enabled()
		tf.CheckDomain("locked.example")
		tf.CheckURL("http://www.example.com/some/path?q=1")
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("REGRESSION: a per-request lookup (Enabled / CheckDomain / CheckURL) blocked while " +
			"the feed's write lock was held — the read path has gone back to acquiring tf.mu. " +
			"That reintroduces the throughput ceiling readView removed (see threatfeed.go): " +
			"per-op cost then RISES with core count, and a large sync stalls every in-flight request.")
	}
}

// TestBenchGate_CheckDomainAllocs pins the domain lookup allocation-free. It
// runs on every proxied request, so any allocation here is per-request garbage.
func TestBenchGate_CheckDomainAllocs(t *testing.T) {
	const maxAllocs int64 = 0
	tf := benchFeed(1000)
	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			tf.CheckDomain("www.example.com")
		}
	})
	t.Logf("CheckDomain: %d allocs/op (bound %d), %d ns/op", res.AllocsPerOp(), maxAllocs, res.NsPerOp())
	if res.AllocsPerOp() > maxAllocs {
		t.Errorf("REGRESSION: CheckDomain allocates %d/op, exceeds bound %d — "+
			"the per-request threat-feed domain lookup must stay allocation-free",
			res.AllocsPerOp(), maxAllocs)
	}
}
