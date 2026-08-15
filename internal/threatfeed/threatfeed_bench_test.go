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

// BenchmarkFeedCheckDomain_MissParallel is the contention measure: it reports
// whether the lookup scales across cores or serialises on the feed lock.
//
// This used to take tf.mu.RLock TWICE per check — once inside Enabled(), once
// for the map probe — and the doubled round trip showed up here as anti-scaling
// (4-core parallel was SLOWER per op than single-goroutine serial). Enabled() is
// now lock-free, leaving exactly one acquisition for the map probe: measured
// 229.6n -> 166.6n, -27% (p=0.002, n=6). The residual is the map probe's own
// RLock, which is genuinely needed and is not this benchmark's target.
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
