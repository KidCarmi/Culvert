package connlimit

import (
	"runtime"
	"strconv"
	"sync"
	"testing"
)

// Footprint and reconfigure-stress gates for the by-value counter, ported from
// the closed #1625 (which reached the same map[string]int64 representation
// independently). TestBenchGate_AcquireReleaseIsAllocationFree in
// connlimit_critsec_test.go pins the per-REQUEST allocation; the two tests here
// pin what it cannot see: the per-TRACKED-IP heap cost across a large live set,
// and conservation of the count while Enable/Disable and the admin gauge race
// the churn shape.

// TestBenchGate_TrackedIPCostsNoHeapObject is the memory-footprint gate, and it
// is about the GC rather than about one request. A pointer map put one tiny heap
// object per tracked IP into the scan set, so a gateway holding 50k live client
// IPs handed the GC 50k extra objects to trace on every cycle, and allocated
// every one of them. With the count held inline there is no such object.
//
// The reading is MemStats.Mallocs — the process's CUMULATIVE allocation count —
// and not HeapObjects. HeapObjects is a live-set gauge: it moves when unrelated
// test garbage is collected between the two reads (it can even read lower after,
// and the unsigned subtraction then wraps). Mallocs is monotonic, so the delta
// is attributable to the loop between the reads, with no GC timing to depend on.
//
// The bound is deliberately generous (well under one allocation per IP rather
// than exactly zero): the shard maps must still grow as they fill, and this gate
// is here to catch the per-entry object coming back — which costs 1.0 per IP on
// top of that growth — not to freeze Go's map growth policy. Each shard is
// warmed to its final capacity first so even bucket growth is mostly outside
// the measured window.
func TestBenchGate_TrackedIPCostsNoHeapObject(t *testing.T) {
	const ips = 20000

	cl := New()
	// Build the keys and warm the shard maps to their final capacity BEFORE the
	// measurement, so neither key construction nor bucket growth lands in it.
	keys := make([]string, ips)
	for i := range keys {
		keys[i] = "203.0.113." + strconv.Itoa(i&0xff) + "-" + strconv.Itoa(i)
		cl.Acquire(keys[i])
	}
	for _, k := range keys {
		cl.Release(k)
	}

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for _, k := range keys {
		cl.Acquire(k)
	}
	runtime.ReadMemStats(&after)

	if got := cl.ActiveIPs(); got != ips {
		t.Fatalf("ActiveIPs = %d, want %d", got, ips)
	}
	for _, k := range keys {
		cl.Release(k)
	}

	perIP := float64(after.Mallocs-before.Mallocs) / float64(ips)
	if perIP > 0.5 {
		t.Fatalf("tracking an IP costs %.2f allocations, want < 0.5: the per-IP counter "+
			"is heap-allocated again (most likely moved back behind a pointer, "+
			"map[string]*int64); see the shard type's doc in connlimit.go", perIP)
	}
}

// TestStress_ChurnUnderConcurrentReconfigure races the churn shape against live
// Enable/Disable reconfigures and the admin gauge, with every admitted Acquire
// paired to its Release, and requires the limiter to come back to exactly zero
// tracked IPs. Run under -race it is the correctness counterpart to the
// benchmarks: the decrement now lives under the shard lock in one critical
// section, and a mistake there shows up as a leaked entry or a lost decrement
// rather than as a slowdown. Reconfiguring mid-flight exercises the
// unconditional-accounting contract (Acquire counts while disabled, Release
// never gates on enabled) under contention.
func TestStress_ChurnUnderConcurrentReconfigure(t *testing.T) {
	cl := New()
	cl.Enable(64)

	const workers = 8
	const iters = 2000
	ips := benchIPs(128)

	stop := make(chan struct{})
	var reconf sync.WaitGroup
	reconf.Add(1)
	go func() {
		defer reconf.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				cl.Enable(64)
			} else {
				cl.Disable()
			}
			cl.ActiveIPs() // the admin gauge touches every shard lock
		}
	}()

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				ip := ips[(w*iters+i)&127]
				// Release only what was admitted — releasing a rejected
				// acquire is what the #503 bug did, and it would mask a leak.
				if cl.Acquire(ip) {
					cl.Release(ip)
				}
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	reconf.Wait()

	if got := cl.ActiveIPs(); got != 0 {
		t.Fatalf("ActiveIPs after every admitted acquire was released = %d, want 0 "+
			"(a leaked entry means a decrement was lost)", got)
	}
	for _, ip := range ips {
		if got := cl.ActiveConns(ip); got != 0 {
			t.Fatalf("ActiveConns(%q) = %d, want 0", ip, got)
		}
	}
}
