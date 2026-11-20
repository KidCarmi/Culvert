package sidecargate

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The two arithmetic tests moved here from the root package's
// scan_svc_admission_chaos_test.go with names and assertions unchanged
// (IM-016). The handler-level CHAOS-115 gates stay in root: they need the
// sidecar's HTTP server, the scan window and the secscan client.

// TestChaos115_SlotArithmetic pins the derivation directly, so no gate above
// has to fill a 32-slot sidecar to cover it.
func TestChaos115_SlotArithmetic(t *testing.T) {
	cases := []struct {
		name   string
		window int64
		want   int
	}{
		// A narrow window is capped by the engines' own concurrency, not by
		// memory: slots far above ClamAV's 4 buy no throughput.
		{"tiny window hits the ceiling", 4096, MaxSlots},
		{"shipped 5 MiB default hits the ceiling", 5 << 20, MaxSlots},
		// The budget starts binding once the window is wide enough that
		// 32 of them would exceed it.
		{"16 MiB window is budget-bound", 16 << 20, 15},
		{"64 MiB window is budget-bound", 64 << 20, 3},
		// A pathological window must not serialise the sidecar completely.
		{"512 MiB window hits the floor", 512 << 20, MinSlots},
		// Defensive: a zero/absent window must not divide by zero or return 0
		// slots, which would refuse every request and fail the fleet CLOSED.
		{"zero window hits the ceiling", 0, MaxSlots},
		{"negative window hits the ceiling", -1, MaxSlots},
	}
	for _, tc := range cases {
		if got := Slots(tc.window); got != tc.want {
			t.Errorf("%s: Slots(%d) = %d, want %d", tc.name, tc.window, got, tc.want)
		}
	}
	for _, tc := range cases {
		if got := Slots(tc.window); got < MinSlots {
			t.Errorf("%s: %d slots is below the floor — a sidecar that admits nothing blocks every download in the fleet", tc.name, got)
		}
	}
}

// TestChaos115_HeapCeilingIsStatedNotImplied pins the budget arithmetic the
// /health and /metrics surfaces publish: slots x (window+1) must stay within
// the stated budget wherever the ceiling is not the binding constraint.
func TestChaos115_HeapCeilingIsStatedNotImplied(t *testing.T) {
	for _, window := range []int64{8 << 20, 16 << 20, 32 << 20, 64 << 20, 128 << 20} {
		slots := int64(Slots(window))
		if slots == MaxSlots || slots == MinSlots {
			continue // a clamped count is a stated choice, not the budget
		}
		if ceiling := slots * (window + 1); ceiling > HeapBudget {
			t.Errorf("window %d: %d slots x %d bytes = %d, over the %d-byte budget",
				window, slots, window+1, ceiling, int64(HeapBudget))
		}
	}
}

// fill books every slot of g and returns the releases.
func fill(t *testing.T, g *Gate) []func() {
	t.Helper()
	held := make([]func(), 0, g.Slots())
	for i := 0; i < g.Slots(); i++ {
		release, ok := g.Acquire(context.Background())
		if !ok {
			t.Fatalf("slot %d of %d refused on an empty gate", i+1, g.Slots())
		}
		held = append(held, release)
	}
	return held
}

func releaseAll(held []func()) {
	for _, release := range held {
		release()
	}
}

// A full gate must wait out its bound and then refuse, with a nil release and
// the gauge still at the slot count: the refused request never held a slot.
func TestGate_FullGateRefusesAfterTheWait(t *testing.T) {
	const wait = 60 * time.Millisecond
	g := New(Options{Slots: 2, QueueWait: wait})
	held := fill(t, g)
	defer releaseAll(held)

	start := time.Now()
	release, ok := g.Acquire(context.Background())
	elapsed := time.Since(start)
	if ok || release != nil {
		t.Fatalf("a full gate admitted a third holder (ok=%v, release nil=%v)", ok, release == nil)
	}
	if elapsed < wait {
		t.Errorf("refused after %s, before the %s wait: a transient burst must be waited out, not refused on sight", elapsed, wait)
	}
	if elapsed >= QueueWait {
		t.Errorf("refused after %s: the configured %s wait was ignored in favour of the %s default", elapsed, wait, QueueWait)
	}
	if got := g.Inflight(); got != 2 {
		t.Errorf("inflight = %d after a refusal, want 2: a refused waiter must not move the gauge", got)
	}
}

// A context with no deadline is the production case (a server-side request
// context carries none). The gate's own wait is then the only bound.
func TestGate_DeadlinelessWaiterIsBoundedByTheGate(t *testing.T) {
	g := New(Options{Slots: 1, QueueWait: 40 * time.Millisecond})
	held := fill(t, g)
	defer releaseAll(held)

	done := make(chan bool, 1)
	go func() {
		_, ok := g.Acquire(context.Background())
		done <- ok
	}()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("a full gate admitted a waiter")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a waiter with no deadline of its own was never released by the gate's wait")
	}
}

// Cancellation that does arrive frees the waiter before the backstop.
func TestGate_CancellationFreesTheWaiterEarly(t *testing.T) {
	g := New(Options{Slots: 1, QueueWait: time.Minute})
	held := fill(t, g)
	defer releaseAll(held)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() {
		_, ok := g.Acquire(ctx)
		done <- ok
	}()
	cancel()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("a cancelled waiter was admitted to a full gate")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a cancelled waiter stayed parked until the one-minute backstop")
	}
	if got := g.Inflight(); got != 1 {
		t.Errorf("inflight = %d, want 1: the abandoned waiter leaked or stole a slot", got)
	}
}

// A waiter inside its bound is admitted as soon as a slot frees.
func TestGate_WaiterIsAdmittedWhenASlotFrees(t *testing.T) {
	g := New(Options{Slots: 1, QueueWait: time.Minute})
	held := fill(t, g)

	type result struct {
		release func()
		ok      bool
	}
	done := make(chan result, 1)
	go func() {
		release, ok := g.Acquire(context.Background())
		done <- result{release, ok}
	}()
	held[0]()
	select {
	case r := <-done:
		if !r.ok {
			t.Fatal("the waiter was refused although a slot freed inside its wait")
		}
		r.release()
	case <-time.After(10 * time.Second):
		t.Fatal("the waiter was not admitted after the slot freed")
	}
	if got := g.Inflight(); got != 0 {
		t.Errorf("inflight = %d after every release, want 0", got)
	}
}

// The gauge is decremented before the slot is returned, so a reader can never
// see more holders than slots. Every holder reads the gauge the moment it is
// admitted: with one slot, a release that freed the slot first would let the
// next holder count itself while the previous one is still counted.
func TestGate_GaugeNeverReadsAboveTheSlotCount(t *testing.T) {
	const slots = 1
	g := New(Options{Slots: slots})

	var over atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20000; i++ {
				release, ok := g.Acquire(context.Background())
				if !ok {
					t.Error("refused inside the default wait under a load that always drains")
					return
				}
				if cur := g.Inflight(); cur > slots || cur < 1 {
					over.Store(cur)
				}
				release()
			}
		}()
	}
	wg.Wait()
	if bad := over.Load(); bad != 0 {
		t.Errorf("a holder read the gauge at %d with %d slot(s): release must drop the gauge before it frees the slot", bad, slots)
	}
	if got := g.Inflight(); got != 0 {
		t.Errorf("inflight = %d after every release, want 0", got)
	}
}

// Two gates share nothing: filling one neither moves the other's gauge nor
// takes its slots.
func TestGate_InstancesAreIndependent(t *testing.T) {
	a := New(Options{Slots: 2, QueueWait: 20 * time.Millisecond})
	b := New(Options{Slots: 2, QueueWait: 20 * time.Millisecond})
	held := fill(t, a)
	defer releaseAll(held)

	if got := b.Inflight(); got != 0 {
		t.Fatalf("gate b reads %d in flight while only gate a is held", got)
	}
	release, ok := b.Acquire(context.Background())
	if !ok {
		t.Fatal("gate b refused although only gate a is full")
	}
	release()
	if _, ok := a.Acquire(context.Background()); ok {
		t.Fatal("gate a admitted past its slot count")
	}
}

// The owner's gauge is the one the gate maintains, and it is restored exactly:
// the sidecar publishes it on /metrics without holding the Gate.
func TestGate_InjectedGaugeIsMaintainedAndRestored(t *testing.T) {
	var gauge atomic.Int64
	gauge.Store(7) // an owner-side value the gate must leave in place
	a := New(Options{Slots: 2, Inflight: &gauge})
	b := New(Options{Slots: 1, Inflight: &gauge})

	heldA := fill(t, a)
	heldB := fill(t, b)
	if got := gauge.Load(); got != 10 {
		t.Errorf("shared gauge = %d with 3 holders over a base of 7, want 10", got)
	}
	if a.Inflight() != 10 || b.Inflight() != 10 {
		t.Errorf("Inflight() = %d, %d, want the shared gauge (10) from both", a.Inflight(), b.Inflight())
	}
	releaseAll(heldA)
	releaseAll(heldB)
	if got := gauge.Load(); got != 7 {
		t.Errorf("shared gauge = %d after every release, want the base of 7", got)
	}
}

// A gate that admitted nothing would refuse every request, and every caller of
// a refusing sidecar fails closed. New never builds one.
func TestGate_NonPositiveSlotsAdmitAtLeastTheFloor(t *testing.T) {
	for _, n := range []int{0, -1, -1 << 30} {
		g := New(Options{Slots: n, QueueWait: time.Millisecond})
		if g.Slots() != MinSlots {
			t.Errorf("New(Slots: %d).Slots() = %d, want the floor %d", n, g.Slots(), MinSlots)
		}
		releaseAll(fill(t, g))
	}
}

func TestGate_DefaultsAreTheProductionValues(t *testing.T) {
	g := New(Options{Slots: 4})
	if g.wait != QueueWait {
		t.Errorf("default wait = %s, want QueueWait (%s)", g.wait, QueueWait)
	}
	if g.Slots() != 4 || cap(g.sem) != 4 {
		t.Errorf("slots = %d, cap = %d, want 4 and 4", g.Slots(), cap(g.sem))
	}
	if g.inflight != &g.own {
		t.Error("a gate built without Options.Inflight must count privately")
	}
	if n := New(Options{Slots: 1, QueueWait: -time.Second}); n.wait != QueueWait {
		t.Errorf("negative wait became %s, want QueueWait", n.wait)
	}
}

// The uncontended path is every request on a sidecar that is not saturated.
// It allocated once (the bound release) before the move, measured on main
// 28de730, and must not start allocating a timer.
func TestGate_UncontendedAcquireDoesNotAllocateATimer(t *testing.T) {
	g := New(Options{Slots: 4})
	ctx := context.Background()
	allocs := testing.AllocsPerRun(1000, func() {
		if release, ok := g.Acquire(ctx); ok {
			release()
		}
	})
	if allocs > 1 {
		t.Errorf("uncontended acquire+release allocates %.0f times, want at most 1", allocs)
	}
}
