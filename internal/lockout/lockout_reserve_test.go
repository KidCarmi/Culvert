package lockout

import (
	"sync"
	"testing"
	"time"
)

// SEC-BASICAUTH-3 — the budget gate must be ATOMIC.
//
// The shape these tests replace was a read-only "am I over?" probe followed by a
// charge taken after the work. Each half was mutex-protected; the SEQUENCE was
// not. So a concurrent cohort all observed the same not-yet-incremented count,
// all passed, and the attempts admitted per window became the caller's
// CONCURRENCY rather than Burst — a bound that reads as a bound and is not one.
//
// Reserve closes that by charging inside the same critical section that admits,
// and Release/Keep decide afterwards whether the charge stands. These gates pin
// the atomicity, the window-scoped release, and the two controls that a
// too-eager Reserve (refusing everything) or a too-generous Release (crediting
// attempts nobody made) would otherwise pass.

// TestReserve_AdmitsExactlyBurstUnderConcurrency is the DEFECT GATE. It fails
// against the probe-then-charge shape, where every goroutine in the cohort
// observes count==0 and is admitted.
func TestReserve_AdmitsExactlyBurstUnderConcurrency(t *testing.T) {
	a := NewAPIRateLimiter()
	const ip = "198.51.100.7"
	const cohort = 400

	var (
		admitted sync.WaitGroup
		start    = make(chan struct{})
		granted  int64
		mu       sync.Mutex
	)
	for i := 0; i < cohort; i++ {
		admitted.Add(1)
		go func() {
			defer admitted.Done()
			<-start // synchronise so the whole cohort races the gate together
			if _, ok := a.Reserve(ip); ok {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		}()
	}
	close(start)
	admitted.Wait()

	if granted != Burst {
		t.Fatalf("granted = %d, want exactly Burst = %d (a cohort must not out-run the budget)", granted, Burst)
	}
	if got := a.Charged(ip); got != Burst {
		t.Fatalf("charged = %d, want %d — the charge must be taken by Reserve itself", got, Burst)
	}
}

// TestReserve_RefusalDoesNotCharge pins that a refused attempt does not push the
// window further out. Incrementing on refusal would let a flood starve the
// window for the whole period and make the counter unreadable.
func TestReserve_RefusalDoesNotCharge(t *testing.T) {
	a := NewAPIRateLimiter()
	const ip = "198.51.100.8"
	for i := 0; i < Burst; i++ {
		if _, ok := a.Reserve(ip); !ok {
			t.Fatalf("Reserve %d refused inside the budget", i)
		}
	}
	for i := 0; i < 50; i++ {
		if _, ok := a.Reserve(ip); ok {
			t.Fatal("Reserve admitted past the budget")
		}
	}
	if got := a.Charged(ip); got != Burst {
		t.Fatalf("charged = %d after 50 refusals, want %d — a refusal must not charge", got, Burst)
	}
}

// TestRelease_GivesTheChargeBack is the control for the other direction: a gate
// that only ever charged would throttle callers whose work the budget does not
// count. Release is what lets the gate sit AHEAD of the work.
func TestRelease_GivesTheChargeBack(t *testing.T) {
	a := NewAPIRateLimiter()
	const ip = "198.51.100.9"
	// Far more reserve/release cycles than Burst: if the charge were not given
	// back, this would exhaust the window.
	for i := 0; i < Burst*5; i++ {
		r, ok := a.Reserve(ip)
		if !ok {
			t.Fatalf("Reserve refused on cycle %d — Release is not returning the charge", i)
		}
		a.Release(&r)
	}
	if got := a.Charged(ip); got != 0 {
		t.Fatalf("charged = %d after balanced reserve/release, want 0", got)
	}
}

// TestRelease_IsIdempotentAndZeroSafe pins that a caller may `defer Release`
// unconditionally and also release early on the ordinary path, without the two
// double-crediting. A double credit would silently widen the budget.
func TestRelease_IsIdempotentAndZeroSafe(t *testing.T) {
	a := NewAPIRateLimiter()
	const ip = "198.51.100.10"

	r1, _ := a.Reserve(ip)
	r2, _ := a.Reserve(ip)
	if got := a.Charged(ip); got != 2 {
		t.Fatalf("charged = %d, want 2", got)
	}
	a.Release(&r1)
	a.Release(&r1) // second release must be inert
	a.Release(&r1)
	if got := a.Charged(ip); got != 1 {
		t.Fatalf("charged = %d after three releases of ONE reservation, want 1 (idempotence)", got)
	}
	a.Release(&r2)

	var zero Reservation
	a.Release(&zero) // a zero Reservation must be inert
	a.Release(nil)   // and so must nil
	if got := a.Charged(ip); got != 0 {
		t.Fatalf("charged = %d, want 0", got)
	}
}

// TestKeep_DisarmsTheDeferredRelease pins the commit path: the caller defers
// Release for panic safety and calls Keep when the work DID produce the thing
// the budget counts, so the charge must stand.
func TestKeep_DisarmsTheDeferredRelease(t *testing.T) {
	a := NewAPIRateLimiter()
	const ip = "198.51.100.11"

	func() {
		r, ok := a.Reserve(ip)
		if !ok {
			t.Fatal("Reserve refused on an empty budget")
		}
		defer a.Release(&r)
		r.Keep()
	}()
	if got := a.Charged(ip); got != 1 {
		t.Fatalf("charged = %d, want 1 — Keep must survive the deferred Release", got)
	}
}

// TestRelease_IgnoresAnExpiredWindow is the subtle one. If the window rolled
// while the reservation was held, the charge belongs to a window that no longer
// exists; decrementing the CURRENT one credits an attempt nobody made, which on
// a busy client widens the budget without bound.
func TestRelease_IgnoresAnExpiredWindow(t *testing.T) {
	a := NewAPIRateLimiter()
	const ip = "198.51.100.12"

	r, ok := a.Reserve(ip)
	if !ok {
		t.Fatal("Reserve refused on an empty budget")
	}
	// Age the entry past the window, then start a fresh one with real charges.
	a.mu.Lock()
	a.entries[ip].windowStart = time.Now().Add(-2 * RateWindow)
	a.mu.Unlock()

	fresh, ok := a.Reserve(ip)
	if !ok {
		t.Fatal("Reserve refused after the window rolled")
	}
	_ = fresh
	if got := a.Charged(ip); got != 1 {
		t.Fatalf("charged = %d in the new window, want 1", got)
	}

	a.Release(&r) // the stale reservation must NOT touch the new window
	if got := a.Charged(ip); got != 1 {
		t.Fatalf("charged = %d after releasing a stale reservation, want 1 — a rolled window must not be credited", got)
	}
}

// TestReserve_WindowRollRestoresTheBudget pins that the gate is a RATE bound,
// not a permanent cap: a client refused now is admitted in the next window.
func TestReserve_WindowRollRestoresTheBudget(t *testing.T) {
	a := NewAPIRateLimiter()
	const ip = "198.51.100.13"
	for i := 0; i < Burst; i++ {
		if _, ok := a.Reserve(ip); !ok {
			t.Fatalf("Reserve %d refused inside the budget", i)
		}
	}
	if _, ok := a.Reserve(ip); ok {
		t.Fatal("Reserve admitted past the budget")
	}
	a.mu.Lock()
	a.entries[ip].windowStart = time.Now().Add(-2 * RateWindow)
	a.mu.Unlock()
	if _, ok := a.Reserve(ip); !ok {
		t.Fatal("Reserve still refused after the window rolled — the bound must be a rate, not a cap")
	}
}

// TestReserve_IsPerClient is the control that the budget isolates clients: one
// source exhausting its window must not refuse anybody else. Keying the budget
// on anything shared would make it a denial-of-service lever.
func TestReserve_IsPerClient(t *testing.T) {
	a := NewAPIRateLimiter()
	const attacker, victim = "198.51.100.14", "203.0.113.9"
	for i := 0; i < Burst*2; i++ {
		a.Reserve(attacker)
	}
	if _, ok := a.Reserve(victim); !ok {
		t.Fatal("an unrelated client was refused by another client's exhausted budget")
	}
}

// TestReserveRelease_ConcurrentMixedTraffic runs the real access pattern under
// -race: many clients, each interleaving kept and released reservations.
func TestReserveRelease_ConcurrentMixedTraffic(t *testing.T) {
	a := NewAPIRateLimiter()
	var wg sync.WaitGroup
	for c := 0; c < 16; c++ {
		ip := "203.0.113." + string(rune('a'+c))
		for i := 0; i < 40; i++ {
			wg.Add(1)
			go func(keep bool) {
				defer wg.Done()
				r, ok := a.Reserve(ip)
				if !ok {
					return
				}
				defer a.Release(&r)
				if keep {
					r.Keep()
				}
			}(i%2 == 0)
		}
	}
	wg.Wait()
	// The invariant under test is only that the counter stays inside its bound
	// and never goes negative; exact values depend on scheduling.
	for c := 0; c < 16; c++ {
		ip := "203.0.113." + string(rune('a'+c))
		if got := a.Charged(ip); got < 0 || got > Burst {
			t.Fatalf("charged(%s) = %d, want within [0, %d]", ip, got, Burst)
		}
	}
}
