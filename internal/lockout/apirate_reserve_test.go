package lockout

import (
	"sync"
	"sync/atomic"
	"testing"
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
			if a.Reserve("198.51.100.7") {
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
	a.Refund(ip) // no entry: no-op
	for i := 0; i < Burst; i++ {
		a.Reserve(ip)
	}
	if a.Reserve(ip) {
		t.Fatal("reserve past Burst admitted")
	}
	a.Refund(ip)
	if !a.Reserve(ip) {
		t.Fatal("refunded unit not reusable")
	}
	for i := 0; i < Burst*2; i++ {
		a.Refund(ip)
	}
	for i := 0; i < Burst; i++ {
		if !a.Reserve(ip) {
			t.Fatalf("after over-refund, reserve %d refused — count went negative or stuck", i)
		}
	}
	if a.Reserve(ip) {
		t.Fatal("over-refund minted extra budget beyond Burst")
	}
}
