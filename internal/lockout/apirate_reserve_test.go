package lockout

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestReserve_ConcurrentWaveNeverExceedsBurst pins that Reserve is an atomic
// claim: however many callers race, at most Burst are admitted per window.
func TestReserve_ConcurrentWaveNeverExceedsBurst(t *testing.T) {
	a := NewAPIRateLimiter()
	var admitted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < Burst*4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := a.Reserve("198.51.100.7"); ok {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := admitted.Load(); got != Burst {
		t.Fatalf("admitted %d, want exactly %d", got, Burst)
	}
}

// TestRefund_ReturnsOneUnitAndNeverGoesNegative pins the refund half.
func TestRefund_ReturnsOneUnitAndNeverGoesNegative(t *testing.T) {
	a := NewAPIRateLimiter()
	const ip = "198.51.100.8"
	a.Refund(Reservation{}) // zero reservation: no-op
	var last Reservation
	for i := 0; i < Burst; i++ {
		last, _ = a.Reserve(ip)
	}
	if _, ok := a.Reserve(ip); ok {
		t.Fatal("reserve past Burst admitted")
	}
	a.Refund(last)
	if _, ok := a.Reserve(ip); !ok {
		t.Fatal("refunded unit not reusable")
	}
	for i := 0; i < Burst*2; i++ {
		a.Refund(last)
	}
	for i := 0; i < Burst; i++ {
		if _, ok := a.Reserve(ip); !ok {
			t.Fatalf("after over-refund, reserve %d refused — count went negative or stuck", i)
		}
	}
	if _, ok := a.Reserve(ip); ok {
		t.Fatal("over-refund minted extra budget beyond Burst")
	}
}

// TestRefund_AcrossWindowRolloverIsANoOp pins that a refund is bound to the
// window its unit was claimed in: a reservation taken in window N and
// refunded after a concurrent request rolled the entry into window N+1 must
// not decrement N+1's count (that would mint extra failure capacity).
func TestRefund_AcrossWindowRolloverIsANoOp(t *testing.T) {
	a := NewAPIRateLimiter()
	const ip = "198.51.100.9"
	old, ok := a.Reserve(ip)
	if !ok {
		t.Fatal("first reserve refused")
	}
	// Age the window so the next Reserve rolls it over.
	a.mu.Lock()
	a.entries[ip].windowStart = time.Now().Add(-2 * RateWindow)
	a.mu.Unlock()
	if _, ok := a.Reserve(ip); !ok {
		t.Fatal("reserve in the new window refused")
	}
	a.Refund(old)
	a.mu.Lock()
	got := a.entries[ip].count
	a.mu.Unlock()
	if got != 1 {
		t.Fatalf("new-window count = %d after a stale refund, want 1 — an expired reservation was refunded against a later window", got)
	}
}
