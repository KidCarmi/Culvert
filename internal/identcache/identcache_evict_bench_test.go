package identcache

import (
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// Benchmarks for PERF-IDENTCACHE-1. The quantity under measurement is the cost
// of ONE insertion into a cache already at its cap, because that is the steady
// state of every identity backend on the proxy credential path once the cache
// fills: each insertion must displace an entry, so it pays the eviction
// selection. The sweep is over the number of distinct fairness keys, which is
// what the selection used to scan — and, the fairness key being the client's
// own address (main's clientFairnessKey), is the number of active clients.
//
// These are regression guards as much as measurements: the shape to watch is
// whether ns/op grows with `clients`. Before the eviction index it grew
// linearly, from 364 ns at one client to 271,017 ns at five thousand.

// benchCapacity is main's maxAuthCacheSize (store.go), the cap every identity
// backend's cache is built with.
const benchCapacity = 5_000

// benchFillAtCap returns a cache holding exactly cap_ live entries spread over
// `clients` fairness keys, ready for the measured insertion.
func benchFillAtCap(cap_, clients int, ttl time.Duration) *Cache[int] {
	c := New[int](Options{MaxEntries: cap_})
	for i := 0; i < cap_; i++ {
		c.Set("key-"+strconv.Itoa(i), "client-"+strconv.Itoa(i%clients), i, true, ttl)
	}
	return c
}

// BenchmarkStoreAtCap sweeps the client count with every entry live, so every
// insertion takes the fairness path rather than the free expired-front one.
//
// clients=5000 with the cap at 5000 is one cached verdict per client, which is
// the ORDINARY shape of a deployment with a few thousand active addresses, not
// an adversarial one: it is the case where every bucket ties on live count and
// the old scan had to visit all of them.
func BenchmarkStoreAtCap(b *testing.B) {
	for _, clients := range []int{1, 10, 100, 1000, 5000} {
		b.Run("clients="+strconv.Itoa(clients), func(b *testing.B) {
			c := benchFillAtCap(benchCapacity, clients, time.Hour)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c.Set("new-"+strconv.Itoa(i), "client-"+strconv.Itoa(i%clients), i, true, time.Hour)
			}
		})
	}
}

// BenchmarkStoreAtCapSkewed is the flood the eviction policy exists to
// survive: one client holds most of the cache while many others hold a single
// verdict each. The victim is then that one greedy bucket, so this measures the
// path where the fairness ordering has a clear winner rather than a wide tie.
func BenchmarkStoreAtCapSkewed(b *testing.B) {
	for _, clients := range []int{100, 1000, 5000} {
		b.Run("clients="+strconv.Itoa(clients), func(b *testing.B) {
			c := New[int](Options{MaxEntries: benchCapacity})
			// Every client but one holds exactly one entry; the flooder holds
			// the rest.
			for i := 0; i < clients-1; i++ {
				c.Set("honest-"+strconv.Itoa(i), "client-"+strconv.Itoa(i), i, true, time.Hour)
			}
			for i := len(c.entries); i < benchCapacity; i++ {
				c.Set("flood-"+strconv.Itoa(i), "flooder", i, true, time.Hour)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c.Set("new-"+strconv.Itoa(i), "flooder", i, true, time.Hour)
			}
		})
	}
}

// BenchmarkStoreAtCapExpiring measures the free path: entries whose deadlines
// have already passed, so eviction takes an expired front rather than
// displacing a live verdict. The TTL is shorter than the fill, so the cache is
// full of dead entries when the measurement starts.
func BenchmarkStoreAtCapExpiring(b *testing.B) {
	for _, clients := range []int{100, 5000} {
		b.Run("clients="+strconv.Itoa(clients), func(b *testing.B) {
			c := New[int](Options{MaxEntries: benchCapacity})
			past := time.Now().Add(-time.Hour)
			for i := 0; i < benchCapacity; i++ {
				c.SetUntil("key-"+strconv.Itoa(i), "client-"+strconv.Itoa(i%clients), i, true, past)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c.Set("new-"+strconv.Itoa(i), "client-"+strconv.Itoa(i%clients), i, true, time.Hour)
			}
		})
	}
}

// BenchmarkCredentialPathParallel is the contention measurement, and the one
// closest to what the proxy actually does: concurrent goroutines on the
// credential path, mostly hitting the cache and occasionally inserting a fresh
// verdict. Every operation takes the same c.mu, so eviction work done under
// that lock is latency every other goroutine on the path waits out — which is
// why the selection's cost matters beyond its own CPU time.
//
// storeEveryN approximates the backend miss rate: one operation in N is a
// store, the rest are hits.
func BenchmarkCredentialPathParallel(b *testing.B) {
	for _, clients := range []int{100, 5000} {
		for _, storeEveryN := range []int{64, 4} {
			name := "clients=" + strconv.Itoa(clients) + "/store=1in" + strconv.Itoa(storeEveryN)
			b.Run(name, func(b *testing.B) {
				c := benchFillAtCap(benchCapacity, clients, time.Hour)
				var goroutines atomic.Int32
				b.ReportAllocs()
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					// Each goroutine draws ONE identifier here and then counts
					// locally. A shared atomic incremented inside the measured
					// loop would add its own contention to a benchmark whose
					// subject is contention, and the distinct key ranges keep
					// the goroutines from colliding on the same entries.
					i := int(goroutines.Add(1)) * 1_000_000
					for pb.Next() {
						i++
						client := "client-" + strconv.Itoa(i%clients)
						if i%storeEveryN == 0 {
							c.Set("new-"+strconv.Itoa(i), client, i, true, time.Hour)
							continue
						}
						c.Get("key-" + strconv.Itoa(i%benchCapacity))
					}
				})
			})
		}
	}
}

// BenchmarkRefreshAtCap measures re-verifying a credential the cache already
// holds — Set on an existing key, which removes the old record and re-appends
// the key. It is the ordinary TTL-driven path (one NAT'd office is one bucket
// holding many credentials, each refreshed every TTL) and it exercises the
// bucket-front bookkeeping without changing the entry count.
func BenchmarkRefreshAtCap(b *testing.B) {
	for _, clients := range []int{1, 1000} {
		b.Run("clients="+strconv.Itoa(clients), func(b *testing.B) {
			c := benchFillAtCap(benchCapacity, clients, time.Hour)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				k := i % benchCapacity
				c.Set("key-"+strconv.Itoa(k), "client-"+strconv.Itoa(k%clients), i, true, time.Hour)
			}
		})
	}
}

// BenchmarkGetHit guards the read path, which the eviction index must not
// touch: a cache hit is the overwhelmingly common credential-path outcome and
// its cost should be unchanged.
func BenchmarkGetHit(b *testing.B) {
	c := benchFillAtCap(benchCapacity, 1000, time.Hour)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Get("key-" + strconv.Itoa(i%benchCapacity))
	}
}
