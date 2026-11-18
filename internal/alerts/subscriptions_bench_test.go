package alerts

// subscriptions_bench_test.go — the regression gate for HasSubscriber's
// contention shape (subscriptions.go).
//
// These benchmarks exist to measure ONE property: that the per-call cost does not
// grow with core count. The absolute ns/op is machine-dependent and not the
// contract; the SHAPE across -cpu=1,2,4 is. Run them as:
//
//	go test ./internal/alerts -run XXX -bench HasSubscriber -benchmem -cpu=1,2,4
//
// A regression that restores a lock, an RWMutex read, or any other
// read-modify-write on a shared word shows up as the Parallel variants getting
// SLOWER per op as -cpu rises, while the serial variant stays flat. That is the
// signature the pre-change implementation had: 13.3 ns at P=1 and 83.9 ns at P=4
// with no webhooks configured, so four cores delivered a sixth of one core's
// throughput. See subscriptions.go for the full table.
//
// NoHooks is the DEFAULT posture (no webhooks configured) and therefore the case
// that matters most, not a degenerate one.

import (
	"strconv"
	"testing"
)

func benchSubscriberStore(hooks int, events []string) *Store {
	as := &Store{}
	for i := 0; i < hooks; i++ {
		as.hooks = append(as.hooks, Webhook{
			ID:      strconv.Itoa(i),
			Enabled: true,
			Events:  events,
		})
	}
	// Arm the index so the benchmark measures the steady-state read, not the
	// one-off derivation.
	as.publishSubscriptions()
	return as
}

// BenchmarkHasSubscriber_NoHooks is the serial control: it must stay flat across
// -cpu, which is what makes the Parallel variants' curve interpretable.
func BenchmarkHasSubscriber_NoHooks(b *testing.B) {
	as := benchSubscriberStore(0, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if as.HasSubscriber("policy_block") {
			b.Fatal("unexpected subscriber")
		}
	}
}

// BenchmarkHasSubscriber_NoHooksParallel is the DEFAULT-posture block path: every
// blocked request on a gateway with no webhooks configured runs exactly this.
func BenchmarkHasSubscriber_NoHooksParallel(b *testing.B) {
	as := benchSubscriberStore(0, nil)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			if as.HasSubscriber("policy_block") {
				b.Fatal("unexpected subscriber")
			}
		}
	})
}

// BenchmarkHasSubscriber_HitParallel is the configured-and-subscribed case: the
// answer is true, so the catch-all/map test is actually exercised.
func BenchmarkHasSubscriber_HitParallel(b *testing.B) {
	as := benchSubscriberStore(3, []string{"threat_detected", "policy_block"})
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			if !as.HasSubscriber("policy_block") {
				b.Fatal("expected a subscriber")
			}
		}
	})
}

// BenchmarkHasSubscriber_MissWithHooksParallel is the worst case for the OLD
// shape: webhooks are configured but none match, so the scan ran to completion
// over every hook and every event before returning false. The index answers it in
// one map lookup regardless of how many hooks exist.
func BenchmarkHasSubscriber_MissWithHooksParallel(b *testing.B) {
	as := benchSubscriberStore(5, []string{"cert_expiry", "dns_failure"})
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			if as.HasSubscriber("policy_block") {
				b.Fatal("unexpected subscriber")
			}
		}
	})
}

// BenchmarkHasSubscriber_CatchAllParallel is the "*" encoding: it must answer
// without a map lookup at all.
func BenchmarkHasSubscriber_CatchAllParallel(b *testing.B) {
	as := benchSubscriberStore(1, []string{catchAllEvent})
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			if !as.HasSubscriber("policy_block") {
				b.Fatal("expected a subscriber")
			}
		}
	})
}

// BenchmarkHasSubscriber_ManyHooksMissParallel pins the complexity change: with
// the scan, a miss cost O(hooks × events); with the index it is O(1). A gateway
// fanning alerts to a large collector set should not pay for that on the block
// path.
func BenchmarkHasSubscriber_ManyHooksMissParallel(b *testing.B) {
	as := benchSubscriberStore(50, []string{"cert_expiry", "dns_failure", "scan_skipped"})
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			if as.HasSubscriber("policy_block") {
				b.Fatal("unexpected subscriber")
			}
		}
	})
}

// BenchmarkHasSubscriber_ReadsDuringMutation is the concurrency benchmark: it
// measures the read path while an operator churns the hook set, so a design that
// moved cost onto readers during republication (a seqlock retry, a lazily
// invalidated cache re-deriving under load) would show here rather than in the
// quiet benchmarks above.
//
// Read its B/op with care: the republishing goroutine allocates a fresh
// subscriptions value per round, and the framework divides that by the READERS'
// iteration count, so a few bytes/op are reported. allocs/op stays 0 and the read
// path allocates nothing — the other benchmarks here are the ones that pin that.
func BenchmarkHasSubscriber_ReadsDuringMutation(b *testing.B) {
	as := benchSubscriberStore(3, []string{"threat_detected", "policy_block"})
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				as.mu.Lock()
				as.publishSubscriptionsLocked()
				as.mu.Unlock()
			}
		}
	}()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			as.HasSubscriber("policy_block")
		}
	})
	b.StopTimer()
	close(stop)
	<-done
}

// ── Legacy shape, retained as a permanent negative control ──────────────────
//
// hasSubscriberLegacy is the pre-change read path: the scan held under
// as.mu.RLock. It is kept and benchmarked alongside the current one so the A/B
// runs in ONE binary on ONE machine, and so the claim "cores subtracted
// throughput" stays checkable on whatever hardware a future reader has instead of
// being a number frozen in a comment. The repository uses this `_Legacy` pairing
// elsewhere for the same reason (see internal/connlimit's CritSec benchmarks).
//
// It deliberately duplicates hasSubscriberScan's body rather than calling it: the
// contention being measured comes from the LOCK, so the lock has to be here.
func (as *Store) hasSubscriberLegacy(event string) bool {
	as.mu.RLock()
	defer as.mu.RUnlock()
	for i := range as.hooks {
		if !as.hooks[i].Enabled {
			continue
		}
		for _, ev := range as.hooks[i].Events {
			if ev == event || ev == "*" {
				return true
			}
		}
	}
	return false
}

func BenchmarkHasSubscriber_NoHooksParallelLegacy(b *testing.B) {
	as := benchSubscriberStore(0, nil)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			if as.hasSubscriberLegacy("policy_block") {
				b.Fatal("unexpected subscriber")
			}
		}
	})
}

func BenchmarkHasSubscriber_HitParallelLegacy(b *testing.B) {
	as := benchSubscriberStore(3, []string{"threat_detected", "policy_block"})
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			if !as.hasSubscriberLegacy("policy_block") {
				b.Fatal("expected a subscriber")
			}
		}
	})
}

func BenchmarkHasSubscriber_MissWithHooksParallelLegacy(b *testing.B) {
	as := benchSubscriberStore(5, []string{"cert_expiry", "dns_failure"})
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			if as.hasSubscriberLegacy("policy_block") {
				b.Fatal("unexpected subscriber")
			}
		}
	})
}

func BenchmarkHasSubscriber_ManyHooksMissParallelLegacy(b *testing.B) {
	as := benchSubscriberStore(50, []string{"cert_expiry", "dns_failure", "scan_skipped"})
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			if as.hasSubscriberLegacy("policy_block") {
				b.Fatal("unexpected subscriber")
			}
		}
	})
}
