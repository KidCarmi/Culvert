package main

import (
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// Benchmarks for PERF-AUTHCACHE-1: the cost of ONE insertion into the local
// credential cache when it is already at its cap.
//
// That is the steady state of the local bcrypt path under any sustained
// credential load: once len(entries) reaches maxAuthCacheSize every set() must
// displace an entry, so it pays evictOneLocked's victim selection while holding
// the cache mutex every proxy credential verification also needs.
//
// The sweep is over the number of distinct fairness keys. The fairness key is
// the client's own address (clientFairnessKey), so that is the number of
// ACTIVE CLIENTS, and it is exactly what the selection scans. The shape to
// watch is whether ns/op grows with `clients`.

// benchAuthCacheAtCap returns a store holding exactly maxAuthCacheSize live
// entries spread over `clients` fairness keys, ready for the measured insert.
func benchAuthCacheAtCap(clients int) *authCacheStore {
	a := &authCacheStore{}
	for i := 0; i < maxAuthCacheSize; i++ {
		a.set("client-"+strconv.Itoa(i%clients), "user", "pass-"+strconv.Itoa(i), true)
	}
	return a
}

// BenchmarkAuthCacheSetAtCap sweeps the active-client count with every entry
// live, so every insertion takes the fairness path rather than the free
// expired-front one.
//
// clients=5000 at a 5000 cap is one cached credential per client — the
// ORDINARY shape of a deployment with a few thousand active addresses, not an
// adversarial one. It is also the worst case for the scan: every bucket ties on
// live count, so the selection must visit all of them.
func BenchmarkAuthCacheSetAtCap(b *testing.B) {
	for _, clients := range []int{1, 10, 100, 1000, 5000} {
		b.Run("clients="+strconv.Itoa(clients), func(b *testing.B) {
			a := benchAuthCacheAtCap(clients)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				a.set("client-"+strconv.Itoa(i%clients), "user", "new-"+strconv.Itoa(i), true)
			}
		})
	}
}

// BenchmarkAuthCacheSetAtCapSkewed is the credential flood the eviction policy
// exists to survive (CHAOS-57): one client holds most of the cache while many
// others hold a single verdict each. The victim is then that one greedy
// bucket, so this measures the path where the fairness ordering has a clear
// winner rather than a wide tie.
func BenchmarkAuthCacheSetAtCapSkewed(b *testing.B) {
	for _, others := range []int{10, 100, 1000} {
		b.Run("others="+strconv.Itoa(others), func(b *testing.B) {
			a := &authCacheStore{}
			for i := 0; i < others; i++ {
				a.set("victim-"+strconv.Itoa(i), "user", "p-"+strconv.Itoa(i), true)
			}
			for i := others; i < maxAuthCacheSize; i++ {
				a.set("flooder", "user", "p-"+strconv.Itoa(i), true)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				a.set("flooder", "user", "new-"+strconv.Itoa(i), true)
			}
		})
	}
}

// BenchmarkAuthCacheSetAtCapExpired is the control: every entry is already
// expired, so evictOneLocked returns at the FIRST bucket it looks at via the
// free expired-front path and never runs the fairness comparison. If the
// sweeps above are flat here but not above, the cost is the selection and not
// the insertion machinery around it.
func BenchmarkAuthCacheSetAtCapExpired(b *testing.B) {
	for _, clients := range []int{1, 1000, 5000} {
		b.Run("clients="+strconv.Itoa(clients), func(b *testing.B) {
			a := benchAuthCacheAtCap(clients)
			a.mu.Lock()
			past := time.Now().Add(-time.Hour)
			for _, e := range a.entries {
				e.expiry = past
			}
			a.mu.Unlock()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				a.set("client-"+strconv.Itoa(i%clients), "user", "new-"+strconv.Itoa(i), true)
			}
		})
	}
}

// BenchmarkAuthCacheCredentialPathParallel measures what the eviction scan
// actually cost the product: time held on a.mu, which every concurrent
// credential verification needs.
//
// The read/write mix is the realistic one. A cached credential is read on every
// request for its whole TTL and written once per TTL, so get() dominates by
// orders of magnitude — but get() cannot start while an insertion is selecting
// a victim. The scan therefore showed up as latency on requests that were only
// reading, which is why the per-operation cost here moved even though almost
// every operation is a get.
//
// -cpu 1 vs -cpu 4 is the signal to watch: lock-hold time that scales with the
// active client count makes the parallel arm WORSE than the serial one.
func BenchmarkAuthCacheCredentialPathParallel(b *testing.B) {
	for _, clients := range []int{100, 1000, 5000} {
		b.Run("clients="+strconv.Itoa(clients), func(b *testing.B) {
			a := benchAuthCacheAtCap(clients)
			var n atomic.Int64
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					i := int(n.Add(1))
					// One insertion per 32 lookups: the write rate a 5-minute
					// TTL implies against per-request reads.
					if i%32 == 0 {
						a.set("client-"+strconv.Itoa(i%clients), "user", "new-"+strconv.Itoa(i), true)
						continue
					}
					a.get("user", "pass-"+strconv.Itoa(i%maxAuthCacheSize))
				}
			})
		})
	}
}
