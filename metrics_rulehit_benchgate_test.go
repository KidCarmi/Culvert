//go:build benchgate

package main

// Regression gate for the lock-free per-rule hit counter (metrics.go).
//
//	go test -tags benchgate -run 'TestBenchGate_RuleHit' -v .

import (
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// TestBenchGate_RuleHitTakesNoLock pins the contract that made RecordHit scale:
// the steady-state path — a hit on an already-registered rule, which is every
// proxied request that matches a policy rule — must not touch ruleMetrics.mu.
//
// GATE DESIGN. This is STRUCTURAL, not timing-based, for the same reason the
// connlimit and IP-filter gates are: a scaling-ratio gate's margin narrows
// under -race on a shared CI runner, and a gate that can flake gets muted. Here
// the write lock is HELD for the duration and RecordHit is required to complete
// anyway. That is deterministic on any hardware, at any load, with or without
// -race — and it fails immediately if the read path ever reacquires the lock,
// because the call would deadlock until the timeout fires.
func TestBenchGate_RuleHitTakesNoLock(t *testing.T) {
	rm := newRuleMetrics()
	rm.RecordHit("gated-rule")

	rm.mu.Lock()
	defer rm.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		rm.RecordHit("gated-rule")
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RecordHit blocked on ruleMetrics.mu while the write lock was held — " +
			"the steady-state counter path must be lock-free (see metrics.go, ruleCounterView)")
	}
	if got := atomic.LoadInt64(rm.view().hits["gated-rule"]); got != 2 {
		t.Fatalf("hits = %d, want 2 — the lock-free path must still count", got)
	}
}

// TestBenchGate_RuleHitRegistrationStillSerialises is the CONTROL for the gate
// above. Without it, a passing gate could just mean the lock stopped being
// taken anywhere at all — including on the write path, where it is what keeps
// two concurrent first-hits from publishing divergent indexes. The COLD path
// (an unregistered name) must still block on the held write lock.
func TestBenchGate_RuleHitRegistrationStillSerialises(t *testing.T) {
	rm := newRuleMetrics()

	rm.mu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		rm.RecordHit("never-seen-before")
	}()

	select {
	case <-done:
		rm.mu.Unlock()
		t.Fatal("first-hit registration completed while the write lock was held — " +
			"registration must serialise, or two racing registrations publish divergent indexes")
	case <-time.After(100 * time.Millisecond):
	}
	rm.mu.Unlock()
	<-done

	if got := atomic.LoadInt64(rm.view().hits["never-seen-before"]); got != 1 {
		t.Fatalf("hits after the lock was released = %d, want 1", got)
	}
}

// TestBenchGate_RuleHitAllocsFree pins 0 allocs/op on the steady-state path, at
// the cardinalities a real rulebase reaches. An allocation here is paid on
// every proxied request and lands in the GC's per-request working set.
func TestBenchGate_RuleHitAllocsFree(t *testing.T) {
	for _, n := range []int{1, 20, maxRuleMetrics} {
		rm := newRuleMetrics()
		names := make([]string, n)
		for i := range names {
			names[i] = "alloc-rule-" + strconv.Itoa(i)
			rm.RecordHit(names[i])
		}
		got := testing.AllocsPerRun(200, func() {
			rm.RecordHit(names[0])
		})
		if got != 0 {
			t.Errorf("RecordHit at %d registered rules = %.1f allocs/op, want 0", n, got)
		}
	}
}
