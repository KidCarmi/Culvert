package connlimit

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"
)

// Tests for the one-critical-section Acquire/Release shapes.
//
// The cost half of that change is pinned by the benchmarks and by
// TestBenchGate_AcquireReleaseIsAllocationFree below. The CORRECTNESS half is
// pinned here, including a permanent DEFECT PROOF of the two-phase Release the
// change replaces: a cost change that also closes a fail-open window must carry
// evidence that the window was real, or a future "simplification" back to the
// two-phase shape reads as style rather than as a regression.

// ─── Defect proof: the two-phase Release could lose a live slot ──────────────

// legacyTwoPhaseLimiter reproduces the pre-change representation: the counter
// behind a *int64 so its IDENTITY can go stale.
type legacyTwoPhaseLimiter struct {
	mu    sync.Mutex
	conns map[string]*int64
	cap   int64
}

func newLegacyTwoPhase(capacity int64) *legacyTwoPhaseLimiter {
	return &legacyTwoPhaseLimiter{conns: make(map[string]*int64), cap: capacity}
}

// acquire is the pre-change Acquire, verbatim in structure (including the
// identity guard its reject path DID carry).
func (l *legacyTwoPhaseLimiter) acquire(ip string) bool {
	l.mu.Lock()
	ctr, ok := l.conns[ip]
	if !ok {
		v := int64(0)
		ctr = &v
		l.conns[ip] = ctr
	}
	n := atomic.AddInt64(ctr, 1)
	l.mu.Unlock()
	if n > l.cap {
		l.mu.Lock()
		if cur, exists := l.conns[ip]; exists && cur == ctr {
			if atomic.AddInt64(ctr, -1) <= 0 {
				delete(l.conns, ip)
			}
		}
		l.mu.Unlock()
		return false
	}
	return true
}

// release is the pre-change Release, verbatim, with ONE injected pause point in
// the window between the unlocked decrement and the re-lock. The hook is the
// only addition: it schedules the interleaving the window already permitted, so
// the defect is demonstrated deterministically instead of raced for.
func (l *legacyTwoPhaseLimiter) release(ip string, hook func()) {
	l.mu.Lock()
	ctr, ok := l.conns[ip]
	l.mu.Unlock()
	if ok {
		if atomic.AddInt64(ctr, -1) <= 0 {
			if hook != nil {
				hook() // ← nothing holds the lock here
			}
			l.mu.Lock()
			if atomic.LoadInt64(ctr) <= 0 { // VALUE re-checked; IDENTITY is not
				delete(l.conns, ip)
			}
			l.mu.Unlock()
		}
	}
}

func (l *legacyTwoPhaseLimiter) active(ip string) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ctr, ok := l.conns[ip]; ok {
		return atomic.LoadInt64(ctr)
	}
	return 0
}

func TestRelease_LegacyTwoPhaseLosesALiveSlot(t *testing.T) {
	const ip = "203.0.113.7"
	l := newLegacyTwoPhase(2)

	if !l.acquire(ip) {
		t.Fatal("setup: first acquire must be admitted")
	}

	var once sync.Once
	// Release A: decrements 1 -> 0, then pauses before re-locking.
	l.release(ip, func() {
		once.Do(func() {
			// B arrives and leaves: this deletes the counter A still points at.
			if !l.acquire(ip) {
				t.Error("B must be admitted")
			}
			l.release(ip, nil)
			// C arrives: a FRESH counter is allocated and mapped. C is LIVE.
			if !l.acquire(ip) {
				t.Error("C must be admitted")
			}
		})
	})

	// A's stale pointer still reads 0, so A deleted C's entry.
	if got := l.active(ip); got != 0 {
		t.Fatalf("defect proof is no longer reproducing the window: tracked=%d, "+
			"want 0 (C's accounting destroyed). The legacy shape must stay "+
			"verbatim for this proof to mean anything.", got)
	}

	// The fail-open consequence: with cap=2 and C live, only ONE further
	// connection may be admitted. Having forgotten C, legacy admits two, so the
	// IP holds three concurrent connections against a cap of two.
	admitted := 0
	for i := 0; i < 2; i++ {
		if l.acquire(ip) {
			admitted++
		}
	}
	if admitted != 2 {
		t.Fatalf("defect proof is no longer reproducing the fail-open: admitted %d, want 2", admitted)
	}
}

// TestRelease_OrdinaryChurnKeepsTheLiveSlot is a CONTROL, not a defect gate,
// and the distinction is recorded because it is easy to misread. It drives the
// same A/B/C sequence end to end against the shipped implementation — and it
// PASSES against the pre-fix shape too (verified), because without the injected
// pause the legacy two-phase Release is perfectly correct. That is precisely
// what makes it a control: the cheapest way to pass the defect proof above is to
// stop dropping entries at zero, which would grow the map by every client ever
// seen, so the ordinary churn sequence must keep working.
//
// The window itself cannot be scheduled against this implementation from a test
// — it does not exist here — so the regression instruments are the defect proof
// above (which owns a verbatim legacy copy) and
// TestWall_ReleaseTakesTheShardLockExactlyOnce below, which pins the mechanism.
func TestRelease_OrdinaryChurnKeepsTheLiveSlot(t *testing.T) {
	const ip = "203.0.113.7"
	cl := New()
	cl.Enable(2)

	if !cl.Acquire(ip) {
		t.Fatal("setup: first Acquire must be admitted")
	}
	cl.Release(ip) // 1 -> 0, entry dropped atomically with the decrement
	if !cl.Acquire(ip) {
		t.Fatal("B must be admitted")
	}
	cl.Release(ip)
	if !cl.Acquire(ip) { // C: live
		t.Fatal("C must be admitted")
	}

	if got := cl.ActiveConns(ip); got != 1 {
		t.Errorf("live connection C lost its accounting: tracked=%d, want 1", got)
	}

	admitted := 0
	for i := 0; i < 2; i++ {
		if cl.Acquire(ip) {
			admitted++
		}
	}
	if admitted != 1 {
		t.Errorf("admitted %d more with cap=2 and C live, want exactly 1 (fail-open past the cap)", admitted)
	}
}

// ─── Invariants preserved across the representation change ──────────────────

// TestAcquire_RepeatedRejectionLeavesNoResidue pins the property the reject-path
// rewrite actually changes. The previous shape incremented the counter, noticed
// it was over the cap, then undid the increment under a SECOND lock behind an
// entry-identity guard; this one never commits the count at all. The boundary
// itself is already pinned by TestAcquireRelease_LimitAndCleanup, so what is
// asserted here is that a SUSTAINED stream of refusals — the shape an attacker
// drives — never drifts the tracked count, never inflates Rejected, and never
// strands the entry once the admitted connections drain.
func TestAcquire_RepeatedRejectionLeavesNoResidue(t *testing.T) {
	const ip = "198.51.100.9"
	cl := New()
	cl.Enable(3)

	for i := 1; i <= 3; i++ {
		if !cl.Acquire(ip) {
			t.Fatalf("connection %d must be admitted with cap=3", i)
		}
		if got := cl.ActiveConns(ip); got != int64(i) {
			t.Fatalf("after admitting %d: tracked=%d", i, got)
		}
	}
	for i := 0; i < 5; i++ {
		if cl.Acquire(ip) {
			t.Fatalf("connection over cap=3 must be refused (attempt %d)", i)
		}
		// A refused connection is never Released, so it must not have been
		// counted — the count must sit exactly at the cap, not drift upward.
		if got := cl.ActiveConns(ip); got != 3 {
			t.Fatalf("refused Acquire left residue: tracked=%d, want 3", got)
		}
	}
	if got := cl.Rejected(); got != 5 {
		t.Errorf("Rejected()=%d, want 5", got)
	}
	for i := 0; i < 3; i++ {
		cl.Release(ip)
	}
	if got := cl.ActiveConns(ip); got != 0 {
		t.Errorf("after releasing every admitted connection: tracked=%d, want 0", got)
	}
	if got := cl.ActiveIPs(); got != 0 {
		t.Errorf("entry not dropped at zero: ActiveIPs=%d, want 0", got)
	}
}

// TestRelease_StrayReleaseIsASafeNoOp pins the underflow guard: releasing an IP
// with no live count must not create an entry, go negative, or wedge the IP.
func TestRelease_StrayReleaseIsASafeNoOp(t *testing.T) {
	cl := New()
	cl.Enable(1)
	cl.Release("203.0.113.44")
	cl.Release("203.0.113.44")
	if got := cl.ActiveConns("203.0.113.44"); got != 0 {
		t.Errorf("stray Release produced tracked=%d, want 0", got)
	}
	if got := cl.ActiveIPs(); got != 0 {
		t.Errorf("stray Release created an entry: ActiveIPs=%d, want 0", got)
	}
	if !cl.Acquire("203.0.113.44") {
		t.Error("a stray Release must not wedge the IP below its cap")
	}
}

// ─── Concurrency ────────────────────────────────────────────────────────────

// TestAcquireRelease_ConcurrentPairsConserveTheCount is the race-detector gate.
// It is a CONTROL for this change (it passes against the pre-fix shape too —
// verified): what it protects is that moving the decrement INSIDE the lock, and
// the counter out of a pointer, did not break accounting or leak entries.
// paired Acquire/Release across many goroutines and a mix of hot and distinct
// keys must leave nothing tracked and nothing leaked. A lost decrement wedges an
// IP over its cap forever; a lost delete grows the map by every client ever
// seen. Run with -race.
func TestAcquireRelease_ConcurrentPairsConserveTheCount(t *testing.T) {
	cl := New()
	cl.Enable(1 << 20) // never reject: this gate is about accounting, not admission

	const workers = 24
	const iters = 2000
	ips := make([]string, 16)
	for i := range ips {
		ips[i] = "203.0.113." + strconv.Itoa(i)
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				// Half the traffic on ONE hot key (the single-NAT shape), half
				// spread — so both the contended and the churning paths run.
				ip := ips[0]
				if i%2 == 1 {
					ip = ips[(w+i)%len(ips)]
				}
				if cl.Acquire(ip) {
					cl.Release(ip)
				}
			}
		}(w)
	}
	wg.Wait()

	for _, ip := range ips {
		if got := cl.ActiveConns(ip); got != 0 {
			t.Errorf("ip %s: tracked=%d after every pair completed, want 0", ip, got)
		}
	}
	if got := cl.ActiveIPs(); got != 0 {
		t.Errorf("ActiveIPs=%d after every pair completed, want 0 (entries leaked)", got)
	}
}

// TestAcquire_ConcurrentOverCapNeverExceedsTheLimit pins admission under
// contention: with a cap of N and many goroutines racing to Acquire without
// releasing, exactly N may be admitted. Acquire now reads the count and commits
// it in one critical section, so a TOCTOU between the two would admit more.
// Also a CONTROL (it passes against the pre-fix shape, which held its lock
// across the atomic increment for the same reason).
func TestAcquire_ConcurrentOverCapNeverExceedsTheLimit(t *testing.T) {
	const ip = "203.0.113.200"
	const cap64 = 8
	cl := New()
	cl.Enable(cap64)

	var admitted atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < 32; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if cl.Acquire(ip) {
					admitted.Add(1) // deliberately never released
				}
			}
		}()
	}
	wg.Wait()

	if got := admitted.Load(); got != cap64 {
		t.Errorf("admitted %d concurrent connections with cap=%d, want exactly %d", got, cap64, cap64)
	}
	if got := cl.ActiveConns(ip); got != cap64 {
		t.Errorf("tracked=%d, want %d", got, cap64)
	}
}

// ─── Allocation gate ────────────────────────────────────────────────────────

// TestBenchGate_AcquireReleaseIsAllocationFree pins the per-request allocation
// contract STRUCTURALLY via testing.AllocsPerRun rather than as a timing ratio,
// so it cannot flake on a loaded runner, under -race, or on other hardware (the
// repo's standing rule for hot-path gates).
//
// The churn shape is the load-bearing one: on a keep-alive connection with no
// second request in flight the entry is created and destroyed on EVERY request,
// which is precisely when the previous *int64 representation allocated. A gate
// that only measured the steady state — entry retained across iterations —
// would read zero against the defect too.
func TestBenchGate_AcquireReleaseIsAllocationFree(t *testing.T) {
	cl := New()
	cl.Enable(1024)
	const ip = "203.0.113.7"

	// Churning: entry created and destroyed every iteration.
	if got := testing.AllocsPerRun(200, func() {
		cl.Acquire(ip)
		cl.Release(ip)
	}); got != 0 {
		t.Errorf("churning Acquire/Release allocated %.1f objects/op, want 0", got)
	}

	// Steady state: one connection held open, a second pair on top of it.
	if !cl.Acquire(ip) {
		t.Fatal("holding Acquire must be admitted")
	}
	defer cl.Release(ip)
	if got := testing.AllocsPerRun(200, func() {
		cl.Acquire(ip)
		cl.Release(ip)
	}); got != 0 {
		t.Errorf("steady-state Acquire/Release allocated %.1f objects/op, want 0", got)
	}

	// The reject path must not allocate either — it is the path an attacker
	// drives, so a mitigation that allocates there is a vector of its own.
	rl := New()
	rl.Enable(1)
	if !rl.Acquire(ip) {
		t.Fatal("first Acquire must be admitted")
	}
	if got := testing.AllocsPerRun(200, func() {
		rl.Acquire(ip) // refused
	}); got != 0 {
		t.Errorf("refused Acquire allocated %.1f objects/op, want 0", got)
	}
}

// TestBenchGate_ShardStaysCacheLineSized is the control for the padding
// arithmetic: shard's filler is written as cacheLine-16 on the stated basis
// that a mutex plus a map header is 16 bytes. Changing the map's value type
// must not silently invalidate that, and a future stdlib change to either size
// should fail the build rather than quietly forfeit the padding.
func TestBenchGate_ShardStaysCacheLineSized(t *testing.T) {
	if got := int(unsafe.Sizeof(shard{})); got != cacheLine {
		t.Errorf("sizeof(shard)=%d, want %d — the padding arithmetic in the shard "+
			"type is stale and the false-sharing win is partly forfeit", got, cacheLine)
	}
}
