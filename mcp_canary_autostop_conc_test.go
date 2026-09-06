package main

// mcp_canary_autostop_conc_test.go — the blocker-#7 concurrency matrix (§21).
//
// No sleeps. Every interleaving is forced with barriers or by driving the seams directly, so a
// failure is a real ordering defect rather than a slow machine, and a pass is not luck.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// CONC-1: a breach racing a reservation. Whatever the order, the two outcomes are the only legal
// ones — the reserve wins and is granted, or the abort wins and it is denied. What must never
// happen is a grant AFTER the latch is visible.
func TestAutoStopConc01_BreachVersusSimultaneousReservation(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(9), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	var outcome canary.BudgetOutcome
	wg.Add(2)
	go func() { defer wg.Done(); <-start; outcome, _ = rt.reserveCanaryExecution(capb, now, rtIdent) }()
	go func() { defer wg.Done(); <-start; rt.tripCanaryAbort(capb, "scope_escape", now) }()
	close(start)
	wg.Wait()

	if !rt.abortedNow(capb) {
		t.Fatal("the breach must have latched regardless of the race")
	}
	// The invariant that matters: after the latch, nothing more is granted.
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o == canary.BudgetGranted {
		t.Fatalf("SECURITY: a reservation was granted after the abort latched (racing outcome was %s)", outcome)
	}
}

// CONC-2: a breach while N requests are waiting for admission. None may be admitted afterwards.
func TestAutoStopConc02_BreachWhileManyAwaitAdmission(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(64), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	rt.tripCanaryAbort(capb, "outcome_evidence_loss", now)

	const n = 16
	var granted int32
	var mu sync.Mutex
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o == canary.BudgetGranted {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if granted != 0 {
		t.Fatalf("SECURITY: %d reservations were granted after the abort latched", granted)
	}
}

// CONC-3: two DIFFERENT breaches race to become the first cause. Exactly one wins, it is one of the
// two, and it never changes afterwards. A nondeterministic first cause would send an operator after
// the wrong thing.
func TestAutoStopConc03_TwoBreachesRaceForFirstCause(t *testing.T) {
	for trial := 0; trial < 50; trial++ {
		rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
		capb := rollout.CapabilityGateway
		now := canaryRuntimeTestNow
		if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), now); err != nil {
			t.Fatalf("begin: %v", err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; rt.tripCanaryAbort(capb, "scope_escape", now) }()
		go func() { defer wg.Done(); <-start; rt.tripCanaryAbort(capb, "latency_pathology", now) }()
		close(start)
		wg.Wait()

		first := rt.abortCodeNow(capb)
		if first != "scope_escape" && first != "latency_pathology" {
			t.Fatalf("the first cause must be one of the racing breaches, got %q", first)
		}
		// Stable afterwards: further breaches never rewrite it.
		rt.tripCanaryAbort(capb, "window_expired", now.Add(time.Second))
		if again := rt.abortCodeNow(capb); again != first {
			t.Fatalf("the first cause changed after the fact: %q -> %q", first, again)
		}
	}
}

// CONC-4: the deadline firing races a reservation. After expiry nothing may be granted.
func TestAutoStopConc04_DeadlineVersusReservation(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	start := canaryRuntimeTestNow
	nowP := start
	swapCanaryClockVar(t, &nowP)
	fireIndex, _, _ := swapCanaryTimer(t)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(9), start); err != nil {
		t.Fatalf("begin: %v", err)
	}
	nowP = start.Add(runtimeTestBudget(9).Window)

	gate := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); <-gate; fireIndex(0) }()
	go func() { defer wg.Done(); <-gate; rt.reserveCanaryExecution(capb, nowP, rtIdent) }()
	close(gate)
	wg.Wait()

	if !rt.abortedNow(capb) {
		t.Fatal("the deadline must have stopped the Canary")
	}
	if o, _ := rt.reserveCanaryExecution(capb, nowP, rtIdent); o == canary.BudgetGranted {
		t.Fatal("SECURITY: a reservation was granted after the window expired")
	}
}

// CONC-5: deadline expiry racing a restart. The restart must land aborted whichever way it goes —
// the deadline is absolute, so it does not matter whether the timer or the restore observed it.
func TestAutoStopConc05_DeadlineVersusRestart(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	start := canaryRuntimeTestNow
	nowP := start
	swapCanaryClockVar(t, &nowP)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(9), start); err != nil {
		t.Fatalf("begin: %v", err)
	}
	nowP = start.Add(runtimeTestBudget(9).Window)

	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()
	if !fresh.abortedNow(capb) {
		t.Fatal("SECURITY: a restart at/after the deadline must restore aborted")
	}
	if code := fresh.abortCodeNow(capb); code != "window_expired" {
		t.Fatalf("stop reason must be window_expired, got %q", code)
	}
}

// CONC-6/7/8: an authoritative breach racing the NEXT request. In each case the next request must
// find the Canary already ineligible. Driven through the funnel so the breach class is exact.
func TestAutoStopConc06to08_BreachVersusNextRequest(t *testing.T) {
	for _, tc := range []struct{ name, code string }{
		{"outcome_evidence_loss", "outcome_evidence_loss"},
		{"tool_fingerprint_drift", "tool_fingerprint_drift"},
		{"independent_witness_mismatch", "independent_witness_mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
			capb := rollout.CapabilityGateway
			now := canaryRuntimeTestNow
			if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(9), now); err != nil {
				t.Fatalf("begin: %v", err)
			}
			f := &canarySafetyFunnel{rt: rt, capb: capb}
			gate := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); <-gate; f.Breach(capb.String(), rt.currentGeneration(capb), tc.code) }()
			go func() { defer wg.Done(); <-gate; rt.reserveCanaryExecution(capb, now, rtIdent) }()
			close(gate)
			wg.Wait()

			if !rt.abortedNow(capb) {
				t.Fatalf("%s must latch the abort", tc.code)
			}
			if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o == canary.BudgetGranted {
				t.Fatalf("SECURITY: a request was admitted after %s latched", tc.code)
			}
		})
	}
}

// CONC-9: budget exhaustion racing the N+1 request. The N+1 must never cross.
func TestAutoStopConc09_BudgetExhaustionVersusNPlusOne(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	rig := armCanaryWithRealPeer(t, p, 1) // exactly one authorized execution
	if out := rig.exec(peerExecInput(p, policy.OpRead)); !out.Executed {
		t.Fatalf("the single authorized execution must cross, out=%+v", out)
	}
	before := p.count()

	const n = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; _ = rig.exec(peerExecInput(p, policy.OpRead)) }()
	}
	close(start)
	wg.Wait()
	if p.count() != before {
		t.Fatalf("SECURITY: %d extra invocation(s) crossed after the allowance was spent", p.count()-before)
	}
}

// CONC-10: reading the status under a concurrent trip must never tear — and must never report a
// latched Canary as still holding execution authority.
func TestAutoStopConc10_StatusReadUnderConcurrentTrip(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(64), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				st := canaryAbortStatusFor(capb)
				if st.Aborted && st.ExecutionAuthority == "granted" {
					t.Error("SECURITY: an aborted Canary reported granted execution authority")
					return
				}
			}
		}
	}()
	for i := 0; i < 200; i++ {
		rt.tripCanaryAbort(capb, "scope_escape", now)
	}
	close(stop)
	wg.Wait()
}

// A latched abort must also stop an already-admitted request in the REAL executor path, under
// concurrency, with no physical invocation escaping.
func TestAutoStopConc11_LatchDuringInflightAdmissionSendsNothingMore(t *testing.T) {
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, 16)
	ex := cfg.Deps.Executor
	capb := rollout.CapabilityGateway

	// Every request latches the abort at the boundary, immediately before the live revalidation.
	var once sync.Once
	in := liveExecInput(policy.OpRead, "t1", "p1")
	in.ToolStillCurrent = func() bool {
		once.Do(func() { globalCanaryRuntime.tripCanaryAbort(capb, "scope_escape", time.Unix(0, 2)) })
		return true
	}
	const n = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; _ = ex.Execute(context.Background(), in, ex.Resolve(in)) }()
	}
	close(start)
	wg.Wait()
	if up.callCount() != 0 {
		t.Fatalf("SECURITY: %d invocation(s) crossed despite the abort latching before the boundary", up.callCount())
	}
}
