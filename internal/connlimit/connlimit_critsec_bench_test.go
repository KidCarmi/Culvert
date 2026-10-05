package connlimit

import (
	"hash/maphash"
	"sync"
	"sync/atomic"
	"testing"
)

// Before/after benchmarks for the one-critical-section change.
//
// The pre-change shapes are frozen here as the _Legacy arms so the comparison
// stays reproducible IN-TREE rather than living in a commit message (the
// BenchmarkPolicyDecisionLine_Legacy / security_ratelimit_window_bench_test.go
// convention). Both arms are timed in ONE run, which is what makes the RATIO
// machine-independent: this box drifted by half again between measurement
// rounds, so the absolute numbers in the package header are indicative and the
// ratio is the claim.
//
// Run:
//
//	go test -run '^$' -bench 'BenchmarkCritSec' -benchmem -count=6 -cpu 1,4 ./internal/connlimit

// ─── Frozen pre-change implementation ───────────────────────────────────────

type legacyShard struct {
	mu    sync.Mutex
	conns map[string]*int64
	_     [cacheLine - 16]byte
}

type legacyLimiter struct {
	shards   [shardCount]legacyShard
	seed     maphash.Seed
	maxPerIP atomic.Int64
	enabled  atomic.Bool
	rejected atomic.Int64
}

func newLegacyLimiter(capacity int64) *legacyLimiter {
	cl := &legacyLimiter{seed: maphash.MakeSeed()}
	for i := range cl.shards {
		cl.shards[i].conns = make(map[string]*int64)
	}
	cl.maxPerIP.Store(capacity)
	cl.enabled.Store(true)
	return cl
}

func (cl *legacyLimiter) shard(ip string) *legacyShard {
	return &cl.shards[maphash.String(cl.seed, ip)%shardCount]
}

func (cl *legacyLimiter) Acquire(ip string) bool {
	sh := cl.shard(ip)
	sh.mu.Lock()
	ctr, ok := sh.conns[ip]
	if !ok {
		v := int64(0)
		ctr = &v
		sh.conns[ip] = ctr
	}
	n := atomic.AddInt64(ctr, 1)
	enabled := cl.enabled.Load()
	limit := cl.maxPerIP.Load()
	sh.mu.Unlock()

	if enabled && n > limit {
		sh.mu.Lock()
		if cur, exists := sh.conns[ip]; exists && cur == ctr {
			if atomic.AddInt64(ctr, -1) <= 0 {
				delete(sh.conns, ip)
			}
		}
		sh.mu.Unlock()
		cl.rejected.Add(1)
		return false
	}
	return true
}

func (cl *legacyLimiter) Release(ip string) {
	sh := cl.shard(ip)
	sh.mu.Lock()
	ctr, ok := sh.conns[ip]
	sh.mu.Unlock()
	if ok {
		if atomic.AddInt64(ctr, -1) <= 0 {
			sh.mu.Lock()
			if atomic.LoadInt64(ctr) <= 0 {
				delete(sh.conns, ip)
			}
			sh.mu.Unlock()
		}
	}
}

// ─── Single NAT egress ──────────────────────────────────────────────────────
//
// The shape sharding deliberately did NOT fix (see the package header): every
// request in the process lands on one shard, so reducing the lock COUNT is the
// only lever left. This is an ordinary enterprise deployment, not a corner case.

const natIP = "203.0.113.7"

func BenchmarkCritSec_NATEgress_Legacy(b *testing.B) {
	cl := newLegacyLimiter(1024)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cl.Acquire(natIP)
			cl.Release(natIP)
		}
	})
}

func BenchmarkCritSec_NATEgress(b *testing.B) {
	cl := New()
	cl.Enable(1024)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cl.Acquire(natIP)
			cl.Release(natIP)
		}
	})
}

// ─── Distinct clients ───────────────────────────────────────────────────────

func BenchmarkCritSec_DistinctIPs_Legacy(b *testing.B) {
	cl := newLegacyLimiter(1024)
	ips := benchIPs(1024)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := ips[i&1023]
			cl.Acquire(ip)
			cl.Release(ip)
			i++
		}
	})
}

func BenchmarkCritSec_DistinctIPs(b *testing.B) {
	cl := New()
	cl.Enable(1024)
	ips := benchIPs(1024)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := ips[i&1023]
			cl.Acquire(ip)
			cl.Release(ip)
			i++
		}
	})
}

// ─── Entry churn vs steady state ────────────────────────────────────────────
//
// Churn is the ordinary shape and the one that allocated: on a keep-alive
// connection with no second request in flight the count returns to zero on
// every request, so the entry is created and destroyed every time. The steady
// state arm holds one connection open so the entry is retained, isolating the
// map insert/delete pair from the rest of the pair's cost.

func BenchmarkCritSec_Churn_Legacy(b *testing.B) {
	cl := newLegacyLimiter(1024)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cl.Acquire(natIP)
		cl.Release(natIP)
	}
}

func BenchmarkCritSec_Churn(b *testing.B) {
	cl := New()
	cl.Enable(1024)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cl.Acquire(natIP)
		cl.Release(natIP)
	}
}

func BenchmarkCritSec_SteadyState_Legacy(b *testing.B) {
	cl := newLegacyLimiter(1024)
	cl.Acquire(natIP) // held open: the entry is never dropped
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cl.Acquire(natIP)
		cl.Release(natIP)
	}
}

func BenchmarkCritSec_SteadyState(b *testing.B) {
	cl := New()
	cl.Enable(1024)
	cl.Acquire(natIP)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cl.Acquire(natIP)
		cl.Release(natIP)
	}
}

// ─── Reject path ────────────────────────────────────────────────────────────
//
// The path an attacker drives. Legacy incremented, detected the overflow, then
// undid the increment under a second lock behind an entry-identity guard; the
// current shape simply never commits the count.

func BenchmarkCritSec_Reject_Legacy(b *testing.B) {
	cl := newLegacyLimiter(1)
	cl.Acquire(natIP) // occupy the single slot
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cl.Acquire(natIP)
		}
	})
}

func BenchmarkCritSec_Reject(b *testing.B) {
	cl := New()
	cl.Enable(1)
	cl.Acquire(natIP)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cl.Acquire(natIP)
		}
	})
}
