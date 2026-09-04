package main

// mcp_tooltrust_clock_test.go — the coordinator clock is swapped UNDER THE LOCK.
//
// mcpToolTrustCoordinator.now() reads nowFn under mu.RLock, and its own comment says
// why: "the background reconcile loop may call it concurrently with a test swapping the
// coordinator". A test that assigns the field directly upholds only one half of that
// contract, and the other half is a real data race — the race detector caught it on CI
// as an unsynchronised write in shadow_soak_test.go against a read from a
// startToolTrustReconcileLoop goroutine that an EARLIER test had left running.
//
// Nothing cancels that loop between tests (it is bound to the process lifecycle ctx), so
// "the loop belongs to a test that already finished" is not a defence: it ticks for the
// rest of the binary's life and can land inside any later test's clock swap.

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// swapToolTrustNowFn swaps the coordinator clock under the coordinator lock and returns
// the previous value, so a test restores it the same way it installed it.
//
// Every other writer in the tree already locks — resetMCPToolTrustForTest and both
// mcp_tooltrust_test.go sites. This exists so the soak helpers do too, rather than each
// call site open-coding a Lock/Unlock pair around a read-modify-write.
func swapToolTrustNowFn(fn func() time.Time) func() time.Time {
	mcpToolTrust.mu.Lock()
	prev := mcpToolTrust.nowFn
	mcpToolTrust.nowFn = fn
	mcpToolTrust.mu.Unlock()
	return prev
}

// TestToolTrustClock_SwapIsSynchronisedWithConcurrentReaders pins the contract directly.
// It reproduces the two racing accesses — a reader in now() and a writer swapping the
// clock — without needing a composed coordinator or a leaked reconcile loop, so it is
// deterministic and cheap.
//
// The gate is the RACE DETECTOR: under -race this fails if the swap stops taking the
// lock. It is written as a loop rather than a single swap because a race gate that
// offers one interleaving proves very little.
func TestToolTrustClock_SwapIsSynchronisedWithConcurrentReaders(t *testing.T) {
	restore := swapToolTrustNowFn(nil)
	t.Cleanup(func() { swapToolTrustNowFn(restore) })

	const rounds = 2000
	stop := make(chan struct{})
	var reads atomic.Int64
	var wg sync.WaitGroup

	// The reader stands in for the leaked reconcile loop: it does exactly what
	// reconcile() does to this field, which is call now().
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = mcpToolTrust.now()
				reads.Add(1)
			}
		}
	}()

	// Wait for the reader to actually run before swapping anything. Without this the
	// gate is VACUOUS and silently so: the first draft finished every swap before the
	// scheduler started the reader, observed ZERO reads, and therefore passed against a
	// deliberately unsynchronised swap. A race gate with no overlap proves nothing.
	for reads.Load() == 0 {
		runtime.Gosched()
	}

	fixed := time.Unix(0, 0)
	for i := 0; i < rounds; i++ {
		runtime.Gosched()
		prev := swapToolTrustNowFn(func() time.Time { return fixed })
		swapToolTrustNowFn(prev)
	}
	close(stop)
	wg.Wait()

	// Overlap is part of the contract this test claims to have tested, so assert it
	// rather than trusting the scheduler.
	if reads.Load() == 0 {
		t.Fatal("no concurrent reads were observed — the gate did not exercise the race it claims to")
	}

	// The clock must be back to where the swap found it — a helper that raced could also
	// lose the restore, and a silently-stuck test clock is its own hazard.
	mcpToolTrust.mu.RLock()
	got := mcpToolTrust.nowFn
	mcpToolTrust.mu.RUnlock()
	if got != nil {
		t.Fatal("the swap helper must restore the previous clock exactly")
	}
}
