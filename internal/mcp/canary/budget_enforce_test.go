package canary

import (
	"sync"
	"testing"
	"time"
)

func testBudget(total int) Budget {
	return Budget{
		MaxTotalExecutions:      total,
		MaxExecutionsPerMinute:  1000,
		MaxConcurrentExecutions: 1000,
		MaxPrincipals:           1,
		MaxTools:                1,
		MaxServers:              1,
		Window:                  time.Hour,
	}
}

// TestBudgetEnforcer_ExactNThenDeniesNPlus1 is the §3 core proof: with MaxTotalExecutions=N, the
// first N reservations are granted and the (N+1)th is denied at the budget boundary (no off-by-one,
// fail-closed). Each is released between reserves so concurrency/rate are never the binding cap.
func TestBudgetEnforcer_ExactNThenDeniesNPlus1(t *testing.T) {
	const N = 5
	now := time.Unix(1_700_000_000, 0)
	e := NewBudgetEnforcer(testBudget(N), 1, now)
	if e == nil {
		t.Fatal("valid budget must arm an enforcer")
	}
	for i := 0; i < N; i++ {
		if o := e.Reserve(1, now); o != BudgetGranted {
			t.Fatalf("reservation %d of %d must be granted, got %s", i+1, N, o)
		}
		e.Release()
	}
	if o := e.Reserve(1, now); o != BudgetDeniedTotal {
		t.Fatalf("the N+1th reservation must be denied on total, got %s", o)
	}
	if !e.Reserve(1, now).WholeCanaryExhaustion() {
		t.Fatal("a total-exhaustion denial must classify as a whole-Canary exhaustion (budget_exhausted)")
	}
	if e.TotalReserved() != N {
		t.Fatalf("total reserved must be exactly N=%d, got %d", N, e.TotalReserved())
	}
	if e.Remaining() != 0 {
		t.Fatalf("remaining must be 0 after N grants, got %d", e.Remaining())
	}
}

// TestBudgetEnforcer_MonotonicTotalNoReplay proves a Release never returns a TOTAL slot — the
// budget cannot be replayed by releasing (only concurrency is freed). Reserve N, Release N, then
// the next Reserve is still denied on total.
func TestBudgetEnforcer_MonotonicTotalNoReplay(t *testing.T) {
	const N = 3
	now := time.Unix(1_700_000_000, 0)
	e := NewBudgetEnforcer(testBudget(N), 1, now)
	for i := 0; i < N; i++ {
		if o := e.Reserve(1, now); o != BudgetGranted {
			t.Fatalf("reserve %d must be granted, got %s", i, o)
		}
	}
	for i := 0; i < N; i++ {
		e.Release()
	}
	if o := e.Reserve(1, now); o != BudgetDeniedTotal {
		t.Fatalf("releasing must not replay the total budget; N+1 must still be denied, got %s", o)
	}
}

// TestBudgetEnforcer_ConcurrencyCap proves the simultaneous-in-flight cap is a per-request throttle:
// C reservations without release fill the concurrency, the next is denied, and a Release frees one.
func TestBudgetEnforcer_ConcurrencyCap(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := testBudget(100)
	b.MaxConcurrentExecutions = 2
	e := NewBudgetEnforcer(b, 1, now)
	if o := e.Reserve(1, now); o != BudgetGranted {
		t.Fatalf("1st concurrent must be granted, got %s", o)
	}
	if o := e.Reserve(1, now); o != BudgetGranted {
		t.Fatalf("2nd concurrent must be granted, got %s", o)
	}
	if o := e.Reserve(1, now); o != BudgetDeniedConcurrency {
		t.Fatalf("3rd concurrent must be denied on concurrency, got %s", o)
	}
	if e.Reserve(1, now).WholeCanaryExhaustion() {
		t.Fatal("a concurrency denial is a per-request throttle, NOT a whole-Canary exhaustion")
	}
	e.Release()
	if o := e.Reserve(1, now); o != BudgetGranted {
		t.Fatalf("after a Release a concurrent slot must free up, got %s", o)
	}
}

// TestBudgetEnforcer_RateCapAndWindowReset proves the per-minute rate cap denies within a window and
// resets when the window rolls over.
func TestBudgetEnforcer_RateCapAndWindowReset(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := testBudget(100)
	b.MaxExecutionsPerMinute = 2
	e := NewBudgetEnforcer(b, 1, now)
	for i := 0; i < 2; i++ {
		if o := e.Reserve(1, now); o != BudgetGranted {
			t.Fatalf("rate reserve %d must be granted, got %s", i, o)
		}
		e.Release()
	}
	if o := e.Reserve(1, now); o != BudgetDeniedRate {
		t.Fatalf("the 3rd within a minute must be denied on rate, got %s", o)
	}
	// Roll the window forward one minute: the rate budget resets.
	later := now.Add(61 * time.Second)
	if o := e.Reserve(1, later); o != BudgetGranted {
		t.Fatalf("after the rate window rolls over a reservation must be granted, got %s", o)
	}
}

// TestBudgetEnforcer_WindowTTL proves the time-boxed window auto-stops the Canary: once the Window
// elapses, every reservation is denied on window (a whole-Canary exhaustion), regardless of total.
func TestBudgetEnforcer_WindowTTL(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := testBudget(100)
	b.Window = 10 * time.Minute
	e := NewBudgetEnforcer(b, 1, now)
	if o := e.Reserve(1, now); o != BudgetGranted {
		t.Fatalf("within the window a reservation must be granted, got %s", o)
	}
	e.Release()
	past := now.Add(10 * time.Minute) // exactly at the boundary is elapsed (>=)
	if o := e.Reserve(1, past); o != BudgetDeniedWindow {
		t.Fatalf("at/after the window a reservation must be denied on window, got %s", o)
	}
	if !e.Reserve(1, past).WholeCanaryExhaustion() {
		t.Fatal("a window denial must classify as a whole-Canary exhaustion (budget_exhausted)")
	}
}

// TestBudgetEnforcer_GenerationBinding proves a Reserve carrying a different generation is refused —
// a stale reservation against a superseded/rolled-back activation can never consume the budget.
func TestBudgetEnforcer_GenerationBinding(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	e := NewBudgetEnforcer(testBudget(10), 7, now)
	if e.Generation() != 7 {
		t.Fatalf("generation = %d, want 7", e.Generation())
	}
	if o := e.Reserve(6, now); o != BudgetDeniedGeneration {
		t.Fatalf("a reserve for the wrong generation must be denied, got %s", o)
	}
	if o := e.Reserve(8, now); o != BudgetDeniedGeneration {
		t.Fatalf("a reserve for a newer generation must be denied, got %s", o)
	}
	if o := e.Reserve(7, now); o != BudgetGranted {
		t.Fatalf("a reserve for the correct generation must be granted, got %s", o)
	}
	// A generation-denied reserve must NOT consume any budget.
	if e.TotalReserved() != 1 {
		t.Fatalf("only the correct-generation reserve may consume budget, total=%d", e.TotalReserved())
	}
}

// TestBudgetEnforcer_FailClosedConstruction proves an invalid budget or zero generation never arms
// a permissive enforcer.
func TestBudgetEnforcer_FailClosedConstruction(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if NewBudgetEnforcer(Budget{}, 1, now) != nil {
		t.Fatal("a zero (invalid) budget must not arm an enforcer")
	}
	if NewBudgetEnforcer(testBudget(10), 0, now) != nil {
		t.Fatal("generation 0 (no activation) must not arm an enforcer")
	}
	// A nil enforcer fails closed on every method.
	var nilE *BudgetEnforcer
	if o := nilE.Reserve(1, now); o != BudgetDeniedInvalid {
		t.Fatalf("a nil enforcer must deny, got %s", o)
	}
}

// TestBudgetEnforcer_RestartPreservesSpend proves the restart contract: a snapshot round-trips the
// monotonic spend for the SAME generation (never resetting to zero), and a snapshot from a
// different generation is refused (a stale activation cannot resurrect its budget after restart).
func TestBudgetEnforcer_RestartPreservesSpend(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := testBudget(5)
	e := NewBudgetEnforcer(b, 3, now)
	for i := 0; i < 3; i++ {
		if o := e.Reserve(3, now); o != BudgetGranted {
			t.Fatalf("reserve %d must be granted, got %s", i, o)
		}
		e.Release()
	}
	snap := e.Snapshot()
	if snap.Generation != 3 || snap.TotalReserved != 3 {
		t.Fatalf("snapshot = %+v, want gen 3 total 3", snap)
	}

	// Restore for the SAME generation: the spend carries forward (2 remaining, not 5).
	restored := RestoreBudgetEnforcer(b, 3, snap)
	if restored == nil {
		t.Fatal("a same-generation snapshot must restore")
	}
	if restored.Remaining() != 2 {
		t.Fatalf("restored budget must preserve spend (remaining 2), got %d", restored.Remaining())
	}
	if o := restored.Reserve(3, now); o != BudgetGranted {
		t.Fatalf("restored budget must still grant within remaining, got %s", o)
	}
	if o := restored.Reserve(3, now); o != BudgetGranted {
		t.Fatalf("restored budget: 2nd remaining grant, got %s", o)
	}
	if o := restored.Reserve(3, now); o != BudgetDeniedTotal {
		t.Fatalf("restored budget must deny once the preserved spend reaches the cap, got %s", o)
	}

	// A snapshot from a DIFFERENT generation must NOT restore into this generation.
	if RestoreBudgetEnforcer(b, 4, snap) != nil {
		t.Fatal("SECURITY: a stale-generation snapshot must not resurrect a budget after restart")
	}
	// A corrupt (over-cap) spend must not restore.
	if RestoreBudgetEnforcer(b, 3, BudgetSnapshot{Generation: 3, TotalReserved: 999, StartUnixNano: now.UnixNano()}) != nil {
		t.Fatal("an over-cap spend must fail closed on restore")
	}
}

// TestBudgetEnforcer_RestartDoesNotReplayRateWindow is the §3 restart-rate proof (Codex P1): a
// restart mid rate-window must NOT reset the rate budget and admit another full burst in the same
// wall-clock minute. The rate-window position is generation-bound durable state.
func TestBudgetEnforcer_RestartDoesNotReplayRateWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := testBudget(100)
	b.MaxExecutionsPerMinute = 2
	e := NewBudgetEnforcer(b, 1, now)
	// Spend the whole rate window (2 in this minute).
	for i := 0; i < 2; i++ {
		if o := e.Reserve(1, now); o != BudgetGranted {
			t.Fatalf("rate reserve %d must be granted, got %s", i, o)
		}
		e.Release()
	}
	if o := e.Reserve(1, now); o != BudgetDeniedRate {
		t.Fatalf("the 3rd within the minute must be denied on rate, got %s", o)
	}
	// Restart within the SAME minute: the rate window must be preserved (still spent).
	snap := e.Snapshot()
	restored := RestoreBudgetEnforcer(b, 1, snap)
	if restored == nil {
		t.Fatal("same-generation snapshot must restore")
	}
	if o := restored.Reserve(1, now); o != BudgetDeniedRate {
		t.Fatalf("SECURITY: a restart within the rate window must NOT replay the rate budget, got %s", o)
	}
	// Once the window rolls over, the restored enforcer grants again.
	later := now.Add(61 * time.Second)
	if o := restored.Reserve(1, later); o != BudgetGranted {
		t.Fatalf("after the window rolls over the restored enforcer must grant, got %s", o)
	}
}

// TestBudgetEnforcer_LegacySnapshotFailsClosedOnRate proves a snapshot predating the rate-window
// fields fails CLOSED (the window is treated as spent) rather than open.
func TestBudgetEnforcer_LegacySnapshotFailsClosedOnRate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := testBudget(100)
	b.MaxExecutionsPerMinute = 2
	// A legacy snapshot: total spend recorded, but no rate-window fields (both zero).
	legacy := BudgetSnapshot{Generation: 1, TotalReserved: 1, StartUnixNano: now.UnixNano()}
	restored := RestoreBudgetEnforcer(b, 1, legacy)
	if restored == nil {
		t.Fatal("a legacy snapshot must still restore")
	}
	if o := restored.Reserve(1, now); o != BudgetDeniedRate {
		t.Fatalf("a legacy snapshot must fail closed to a spent rate window, got %s", o)
	}
}

// TestBudgetEnforcer_ConcurrentReserveNeverExceedsTotal is the atomicity gate: many goroutines
// reserving at once must grant EXACTLY MaxTotalExecutions in total — never more (a race in the
// check-then-reserve would over-grant and breach the blast radius).
func TestBudgetEnforcer_ConcurrentReserveNeverExceedsTotal(t *testing.T) {
	const N = 50
	now := time.Unix(1_700_000_000, 0)
	b := testBudget(N)
	b.MaxConcurrentExecutions = N + 100 // do not let concurrency be the binding cap
	b.MaxExecutionsPerMinute = N + 100
	e := NewBudgetEnforcer(b, 1, now)

	var granted int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < N*4; i++ { // far more attempts than the budget
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.Reserve(1, now).Granted() {
				mu.Lock()
				granted++
				mu.Unlock()
				e.Release()
			}
		}()
	}
	wg.Wait()
	if granted != N {
		t.Fatalf("concurrent reserves must grant EXACTLY %d (the total cap), got %d", N, granted)
	}
	if e.TotalReserved() != N {
		t.Fatalf("total reserved must be exactly %d, got %d", N, e.TotalReserved())
	}
}
