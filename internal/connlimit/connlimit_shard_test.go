package connlimit

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

// errSingleLock is the diagnosis every gate below reports when the per-IP
// counters have collapsed back onto one lock. It is shared so that whichever
// gate notices first says the same thing.
const errSingleLock = "the per-IP counters are back behind a single process-wide mutex. " +
	"That reintroduces the throughput ceiling sharding removed (see connlimit.go): per-op " +
	"cost then RISES with core count, and every request in the process serialises on one " +
	"cache line regardless of which client sent it."

// distinctShardIPs returns two IPs that hash to DIFFERENT shards, and two that
// hash to the SAME shard. The seed is per-limiter and random, so the pairs are
// discovered against the live limiter rather than hard-coded.
//
// Finding no cross-shard pair at all is itself the regression — a limiter with
// one effective shard routes every client to the same lock — so that case is
// reported as such rather than as a flaky helper.
func distinctShardIPs(t *testing.T, cl *ConnLimiter) (a, b, sameAsA string) {
	t.Helper()
	base := "198.51.100.1"
	for i := 0; i < 4096; i++ {
		cand := "203.0.113." + strconv.Itoa(i&0xff) + "-" + strconv.Itoa(i)
		if b == "" && cl.shard(cand) != cl.shard(base) {
			b = cand
		}
		if sameAsA == "" && cand != base && cl.shard(cand) == cl.shard(base) {
			sameAsA = cand
		}
		if b != "" && sameAsA != "" {
			return base, b, sameAsA
		}
	}
	if b == "" {
		t.Fatal("REGRESSION: 4096 distinct client IPs all routed to ONE shard — " + errSingleLock)
	}
	t.Fatal("no two of 4096 distinct client IPs collided onto a shard; the same-shard control " +
		"below cannot be constructed")
	return "", "", ""
}

// TestBenchGate_DistinctIPsDoNotShareALock is the hard gate on the sharded
// counter map, and it is deliberately STRUCTURAL rather than timing-based.
//
// The obvious gate — measure ns/op at -cpu=1 and -cpu=4 and require the ratio
// not to grow — separates the two shapes cleanly on a quiet machine (0.35x
// before, 1.16x after) but its margin is thin on a shared CI runner and thinner
// still under -race. A gate that can flake is worse than no gate: it gets muted.
//
// This form has no margin to erode. It holds ONE shard's lock and requires an
// Acquire/Release pair for an IP on a DIFFERENT shard to complete anyway. If the
// limiter reverts to a single process-wide mutex — exactly the regression to
// catch — the pair blocks until the deadline and fails deterministically, on any
// hardware, at any load, with or without the race detector.
//
// The throughput this protects is recorded on the sharding note in connlimit.go
// and on BenchmarkAcquireRelease_EnabledParallel.
func TestBenchGate_DistinctIPsDoNotShareALock(t *testing.T) {
	cl := New()
	cl.Enable(64)
	held, other, _ := distinctShardIPs(t, cl)

	sh := cl.shard(held)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		cl.Acquire(other)
		cl.ActiveConns(other)
		cl.Release(other)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("REGRESSION: Acquire/Release for one client IP blocked while another client IP's " +
			"shard lock was held — " + errSingleLock)
	}
}

// TestBenchGate_SameShardStillSerialises is the control for the gate above. It
// proves the gate can actually fail: two IPs that DO land on the same shard must
// block each other, so a passing TestBenchGate_DistinctIPsDoNotShareALock means
// the shard split is real and not that the lock stopped being taken at all.
func TestBenchGate_SameShardStillSerialises(t *testing.T) {
	cl := New()
	cl.Enable(64)
	held, _, collides := distinctShardIPs(t, cl)

	sh := cl.shard(held)
	sh.mu.Lock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		cl.Acquire(collides)
		cl.Release(collides)
	}()

	select {
	case <-done:
		sh.mu.Unlock()
		t.Fatal("two IPs on the SAME shard did not serialise: the shard lock is no longer guarding " +
			"the counter map, so the cross-shard gate above proves nothing")
	case <-time.After(100 * time.Millisecond):
		// Expected: blocked on the shard lock.
	}
	sh.mu.Unlock()
	<-done
}

// TestShard_CapIsPerIPNotPerShard pins the invariant sharding could plausibly
// break: two client IPs that collide onto one shard share a lock but must NOT
// share a budget. A shard-keyed (rather than IP-keyed) counter would let one
// busy client exhaust an unrelated client's cap — a cross-tenant denial of
// service introduced by an optimisation.
func TestShard_CapIsPerIPNotPerShard(t *testing.T) {
	cl := New()
	cl.Enable(1)
	a, _, b := distinctShardIPs(t, cl)
	if cl.shard(a) != cl.shard(b) {
		t.Fatalf("test setup: %q and %q are meant to collide onto one shard", a, b)
	}

	if !cl.Acquire(a) {
		t.Fatal("first acquire for a should be admitted (cap 1)")
	}
	// b shares a's shard but must have its own untouched budget.
	if !cl.Acquire(b) {
		t.Fatal("cap leaked across a shard: b was rejected because a occupied the shard, not its own slot")
	}
	if cl.Acquire(a) {
		t.Fatal("a's own cap is not enforced (cap 1)")
	}
	if cl.Acquire(b) {
		t.Fatal("b's own cap is not enforced (cap 1)")
	}
	cl.Release(a)
	cl.Release(b)
	if got := cl.ActiveIPs(); got != 0 {
		t.Fatalf("ActiveIPs after releasing both = %d, want 0", got)
	}
}

// TestShard_RoutingIsStable pins the one property every per-IP invariant rests
// on: Acquire, Release and ActiveConns must all route a given IP to the SAME
// shard. If they ever disagreed, Release would decrement a counter Acquire never
// incremented and the per-IP accounting would drift in both directions.
func TestShard_RoutingIsStable(t *testing.T) {
	cl := New()
	for i := 0; i < 512; i++ {
		ip := "203.0.113." + strconv.Itoa(i&0xff) + "-" + strconv.Itoa(i)
		first := cl.shard(ip)
		for r := 0; r < 4; r++ {
			if cl.shard(ip) != first {
				t.Fatalf("shard(%q) is not stable across calls", ip)
			}
		}
	}
}

// TestShard_ManyIPsNoLeak races Acquire/Release across many client IPs (so the
// work spreads over every shard) while a reconfigure runs, and requires every
// counter and every map entry to be gone at the end. Run with -race.
func TestShard_ManyIPsNoLeak(t *testing.T) {
	cl := New()
	cl.Enable(1000)

	const workers, ips, iters = 16, 256, 200
	addrs := make([]string, ips)
	for i := range addrs {
		addrs[i] = "203.0.113." + strconv.Itoa(i&0xff) + "-" + strconv.Itoa(i)
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				ip := addrs[(w*iters+j)%ips]
				if cl.Acquire(ip) {
					cl.Release(ip)
				}
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 200; j++ {
			cl.Enable(500 + j%2)
		}
	}()
	wg.Wait()

	for _, ip := range addrs {
		if got := cl.ActiveConns(ip); got != 0 {
			t.Fatalf("ActiveConns(%q) = %d after all releases, want 0", ip, got)
		}
	}
	if got := cl.ActiveIPs(); got != 0 {
		t.Fatalf("ActiveIPs = %d after all releases, want 0 (a shard leaked its map entries)", got)
	}
}

// TestShard_DistributionIsNotDegenerate guards against a shard function that
// compiles and routes stably but collapses realistic client IPs onto a handful
// of shards — which would leave the contention it was meant to remove. Dotted
// quads across several /24s must reach most of the table.
func TestShard_DistributionIsNotDegenerate(t *testing.T) {
	cl := New()
	seen := map[*shard]int{}
	for a := 0; a < 4; a++ {
		for i := 0; i < 256; i++ {
			seen[cl.shard("10."+strconv.Itoa(a)+".0."+strconv.Itoa(i))]++
		}
	}
	if len(seen) < shardCount*3/4 {
		t.Fatalf("1024 client IPs reached only %d of %d shards; the shard function is clustering "+
			"and most of the contention split is lost", len(seen), shardCount)
	}
}
