package main

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
)

// Measurement harness for the Control Plane's centralized audit ring
// (clusterAuditLog in controlplane.go), the single point every Data Plane
// node's PushAuditEvents RPC funnels through.
//
// legacyClusterAuditLog is the pre-change implementation, kept here as the
// before-side of the comparison and as the differential oracle for the ring
// rewrite. It is a GROWING slice re-sliced down to maxSize rather than a
// circular buffer: each Append advances the slice start, so the spare capacity
// behind the window is consumed one entry at a time until append must
// reallocate, copying the whole live window under c.mu.
type legacyClusterAuditLog struct {
	mu      sync.Mutex
	entries []ClusterAuditEntry
	maxSize int
}

func (c *legacyClusterAuditLog) Append(nodeID string, events []AuditEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// gocritic's rangeValCopy is correct here and deliberately not fixed: the
	// 136-byte per-iteration copy is part of the shape being measured. This is
	// a FROZEN reproduction of the pre-change Append, so "improving" it would
	// silently move the before-side of every comparison below. The current
	// implementation indexes instead, per the repository's index-based-range
	// convention.
	for _, e := range events { //nolint:gocritic // frozen pre-change shape; its copy is the measurement
		c.entries = append(c.entries, ClusterAuditEntry{NodeID: nodeID, Entry: e})
	}
	// Ring buffer: trim to maxSize.
	if len(c.entries) > c.maxSize {
		c.entries = c.entries[len(c.entries)-c.maxSize:]
	}
}

func (c *legacyClusterAuditLog) Recent(n int) []ClusterAuditEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n <= 0 || len(c.entries) == 0 {
		return nil
	}
	if n > len(c.entries) {
		n = len(c.entries)
	}
	start := len(c.entries) - n
	out := make([]ClusterAuditEntry, n)
	copy(out, c.entries[start:])
	return out
}

func (c *legacyClusterAuditLog) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// clusterAuditBatch builds one DP push batch. The DP queue caps a batch at
// audit.maxPending (1000) events; batchSize models the realistic range from a
// quiet node (1) to a saturated one.
func clusterAuditBatch(batchSize int) []AuditEntry {
	b := make([]AuditEntry, batchSize)
	for i := range b {
		b[i] = AuditEntry{
			TS:     int64(i),
			Time:   "2026-11-20 23:00:00",
			Actor:  "10.1.2.3",
			Action: "policy.update",
			Object: "rule-01JAX9Q0000000000000000000",
			Detail: "priority 100 -> 110",
		}
	}
	return b
}

// clusterAuditAppender is the surface both implementations share, so one
// benchmark body measures either side.
type clusterAuditAppender interface {
	Append(nodeID string, events []AuditEntry)
	Recent(n int) []ClusterAuditEntry
	Count() int
}

const clusterAuditProdMaxSize = 5000 // globalClusterAudit's size

func benchClusterAuditAppend(b *testing.B, newLog func() clusterAuditAppender, batchSize int) {
	log := newLog()
	batch := clusterAuditBatch(batchSize)
	// Saturate the window first: the steady state, not the fill, is what the
	// CP spends its life in.
	for filled := 0; filled < clusterAuditProdMaxSize; filled += batchSize {
		log.Append("node-warm", batch)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.Append("node-a", batch)
	}
	b.StopTimer()
	b.ReportMetric(float64(batchSize), "events/op")
}

func BenchmarkClusterAuditAppend_Legacy(b *testing.B) {
	for _, bs := range []int{1, 10, 100, 1000} {
		b.Run(fmt.Sprintf("batch=%d", bs), func(b *testing.B) {
			benchClusterAuditAppend(b, func() clusterAuditAppender {
				return &legacyClusterAuditLog{maxSize: clusterAuditProdMaxSize}
			}, bs)
		})
	}
}

func BenchmarkClusterAuditAppend_Current(b *testing.B) {
	for _, bs := range []int{1, 10, 100, 1000} {
		b.Run(fmt.Sprintf("batch=%d", bs), func(b *testing.B) {
			benchClusterAuditAppend(b, func() clusterAuditAppender {
				return &clusterAuditLog{maxSize: clusterAuditProdMaxSize}
			}, bs)
		})
	}
}

// benchClusterAuditResidency reports the steady-state heap the ring holds once
// saturated: the live window plus whatever the growth strategy keeps behind it.
func benchClusterAuditResidency(b *testing.B, newLog func() clusterAuditAppender) {
	batch := clusterAuditBatch(100)
	var ms runtime.MemStats
	logs := make([]clusterAuditAppender, 0, b.N)
	runtime.GC()
	runtime.ReadMemStats(&ms)
	before := ms.HeapAlloc
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log := newLog()
		// Two full laps of the window: enough for the legacy growth strategy to
		// reach its steady-state backing array.
		for filled := 0; filled < 2*clusterAuditProdMaxSize; filled += len(batch) {
			log.Append("node-a", batch)
		}
		logs = append(logs, log)
	}
	b.StopTimer()
	runtime.GC()
	runtime.ReadMemStats(&ms)
	after := ms.HeapAlloc
	runtime.KeepAlive(logs)
	b.ReportMetric(float64(after-before)/float64(b.N), "resident-B/log")
}

func BenchmarkClusterAuditResidency_Legacy(b *testing.B) {
	benchClusterAuditResidency(b, func() clusterAuditAppender {
		return &legacyClusterAuditLog{maxSize: clusterAuditProdMaxSize}
	})
}

func BenchmarkClusterAuditResidency_Current(b *testing.B) {
	benchClusterAuditResidency(b, func() clusterAuditAppender {
		return &clusterAuditLog{maxSize: clusterAuditProdMaxSize}
	})
}

// benchClusterAuditFleet is the contention shape: N data planes pushing
// concurrently while the admin UI polls Recent(200), all through the one mutex.
func benchClusterAuditFleet(b *testing.B, log clusterAuditAppender) {
	batch := clusterAuditBatch(50)
	for filled := 0; filled < clusterAuditProdMaxSize; filled += len(batch) {
		log.Append("node-warm", batch)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if i%16 == 0 {
				log.Recent(200) // admin UI poll
			} else {
				log.Append("node-a", batch)
			}
			i++
		}
	})
}

func BenchmarkClusterAuditFleetParallel_Legacy(b *testing.B) {
	benchClusterAuditFleet(b, &legacyClusterAuditLog{maxSize: clusterAuditProdMaxSize})
}

func BenchmarkClusterAuditFleetParallel_Current(b *testing.B) {
	benchClusterAuditFleet(b, &clusterAuditLog{maxSize: clusterAuditProdMaxSize})
}

func BenchmarkClusterAuditRecent_Legacy(b *testing.B) {
	benchClusterAuditRecent(b, &legacyClusterAuditLog{maxSize: clusterAuditProdMaxSize})
}

func BenchmarkClusterAuditRecent_Current(b *testing.B) {
	benchClusterAuditRecent(b, &clusterAuditLog{maxSize: clusterAuditProdMaxSize})
}

func benchClusterAuditRecent(b *testing.B, log clusterAuditAppender) {
	batch := clusterAuditBatch(100)
	// Saturate, then half a lap so the read window straddles the ring wrap —
	// the two-bulk-copy case, not the contiguous one.
	for filled := 0; filled < clusterAuditProdMaxSize+clusterAuditProdMaxSize/2; filled += len(batch) {
		log.Append("node-a", batch)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := log.Recent(200); len(got) != 200 {
			b.Fatalf("Recent(200) = %d entries", len(got))
		}
	}
}
