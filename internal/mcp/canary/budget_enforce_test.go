package canary

import (
	"sync"
	"testing"
	"time"
)

// idOne is a single fixed execution identity for tests that are not exercising the
// distinct-identity caps: reusing it keeps the distinct principal/tool/server count at 1.
var idOne = ExecutionIdentity{Principal: "p1", Tool: "t1", Server: "s1"}

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
		if o := e.Reserve(1, now, idOne); o != BudgetGranted {
			t.Fatalf("reservation %d of %d must be granted, got %s", i+1, N, o)
		}
		e.Release()
	}
	if o := e.Reserve(1, now, idOne); o != BudgetDeniedTotal {
		t.Fatalf("the N+1th reservation must be denied on total, got %s", o)
	}
	if !e.Reserve(1, now, idOne).WholeCanaryExhaustion() {
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
		if o := e.Reserve(1, now, idOne); o != BudgetGranted {
			t.Fatalf("reserve %d must be granted, got %s", i, o)
		}
	}
	for i := 0; i < N; i++ {
		e.Release()
	}
	if o := e.Reserve(1, now, idOne); o != BudgetDeniedTotal {
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
	if o := e.Reserve(1, now, idOne); o != BudgetGranted {
		t.Fatalf("1st concurrent must be granted, got %s", o)
	}
	if o := e.Reserve(1, now, idOne); o != BudgetGranted {
		t.Fatalf("2nd concurrent must be granted, got %s", o)
	}
	if o := e.Reserve(1, now, idOne); o != BudgetDeniedConcurrency {
		t.Fatalf("3rd concurrent must be denied on concurrency, got %s", o)
	}
	if e.Reserve(1, now, idOne).WholeCanaryExhaustion() {
		t.Fatal("a concurrency denial is a per-request throttle, NOT a whole-Canary exhaustion")
	}
	e.Release()
	if o := e.Reserve(1, now, idOne); o != BudgetGranted {
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
		if o := e.Reserve(1, now, idOne); o != BudgetGranted {
			t.Fatalf("rate reserve %d must be granted, got %s", i, o)
		}
		e.Release()
	}
	if o := e.Reserve(1, now, idOne); o != BudgetDeniedRate {
		t.Fatalf("the 3rd within a minute must be denied on rate, got %s", o)
	}
	// Roll the window forward one minute: the rate budget resets.
	later := now.Add(61 * time.Second)
	if o := e.Reserve(1, later, idOne); o != BudgetGranted {
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
	if o := e.Reserve(1, now, idOne); o != BudgetGranted {
		t.Fatalf("within the window a reservation must be granted, got %s", o)
	}
	e.Release()
	past := now.Add(10 * time.Minute) // exactly at the boundary is elapsed (>=)
	if o := e.Reserve(1, past, idOne); o != BudgetDeniedWindow {
		t.Fatalf("at/after the window a reservation must be denied on window, got %s", o)
	}
	if !e.Reserve(1, past, idOne).WholeCanaryExhaustion() {
		t.Fatal("a window denial must classify as a whole-Canary exhaustion (budget_exhausted)")
	}
}

// TestBudgetEnforcer_WindowOpenMirrorsReserve proves the WindowOpen eligibility read agrees with the
// window gate a Reserve would apply (Codex P2): open inside the window, closed at/after the window
// boundary, and closed on a backward clock step (now earlier than the activation instant). A nil
// enforcer is never open.
func TestBudgetEnforcer_WindowOpenMirrorsReserve(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := testBudget(100)
	b.Window = 10 * time.Minute
	e := NewBudgetEnforcer(b, 1, now)
	if !e.WindowOpen(now) {
		t.Fatal("the window must be open at the activation instant")
	}
	if !e.WindowOpen(now.Add(9 * time.Minute)) {
		t.Fatal("the window must be open just before it elapses")
	}
	if e.WindowOpen(now.Add(10 * time.Minute)) {
		t.Fatal("the window must be closed at the boundary (>= elapsed), mirroring Reserve")
	}
	if e.WindowOpen(now.Add(-time.Second)) {
		t.Fatal("a backward clock step must read as closed (fail closed), mirroring Reserve")
	}
	var nilE *BudgetEnforcer
	if nilE.WindowOpen(now) {
		t.Fatal("a nil enforcer is never window-open")
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
	if o := e.Reserve(6, now, idOne); o != BudgetDeniedGeneration {
		t.Fatalf("a reserve for the wrong generation must be denied, got %s", o)
	}
	if o := e.Reserve(8, now, idOne); o != BudgetDeniedGeneration {
		t.Fatalf("a reserve for a newer generation must be denied, got %s", o)
	}
	if o := e.Reserve(7, now, idOne); o != BudgetGranted {
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
	if o := nilE.Reserve(1, now, idOne); o != BudgetDeniedInvalid {
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
		if o := e.Reserve(3, now, idOne); o != BudgetGranted {
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
	if o := restored.Reserve(3, now, idOne); o != BudgetGranted {
		t.Fatalf("restored budget must still grant within remaining, got %s", o)
	}
	if o := restored.Reserve(3, now, idOne); o != BudgetGranted {
		t.Fatalf("restored budget: 2nd remaining grant, got %s", o)
	}
	if o := restored.Reserve(3, now, idOne); o != BudgetDeniedTotal {
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
		if o := e.Reserve(1, now, idOne); o != BudgetGranted {
			t.Fatalf("rate reserve %d must be granted, got %s", i, o)
		}
		e.Release()
	}
	if o := e.Reserve(1, now, idOne); o != BudgetDeniedRate {
		t.Fatalf("the 3rd within the minute must be denied on rate, got %s", o)
	}
	// Restart within the SAME minute: the rate window must be preserved (still spent).
	snap := e.Snapshot()
	restored := RestoreBudgetEnforcer(b, 1, snap)
	if restored == nil {
		t.Fatal("same-generation snapshot must restore")
	}
	if o := restored.Reserve(1, now, idOne); o != BudgetDeniedRate {
		t.Fatalf("SECURITY: a restart within the rate window must NOT replay the rate budget, got %s", o)
	}
	// Once the window rolls over, the restored enforcer grants again.
	later := now.Add(61 * time.Second)
	if o := restored.Reserve(1, later, idOne); o != BudgetGranted {
		t.Fatalf("after the window rolls over the restored enforcer must grant, got %s", o)
	}
}

// TestBudgetEnforcer_LegacySnapshotFailsClosedOnRate proves a snapshot predating the rate-window
// fields fails CLOSED (the window is treated as spent) rather than open.
func TestBudgetEnforcer_LegacySnapshotFailsClosedOnRate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := testBudget(100)
	b.MaxExecutionsPerMinute = 2
	// A legacy snapshot: total spend recorded, but no rate-window fields (both zero). The identity
	// history IS present (a nonzero spend requires it — see the identity-invariant test below), so this
	// isolates the rate-window fail-closed behavior.
	legacy := BudgetSnapshot{
		Generation: 1, TotalReserved: 1, StartUnixNano: now.UnixNano(),
		Principals: []string{"p1"}, Tools: []string{"t1"}, Servers: []string{"s1"},
	}
	restored := RestoreBudgetEnforcer(b, 1, legacy)
	if restored == nil {
		t.Fatal("a legacy snapshot (with identity history) must still restore")
	}
	if o := restored.Reserve(1, now, idOne); o != BudgetDeniedRate {
		t.Fatalf("a legacy snapshot must fail closed to a spent rate window, got %s", o)
	}
}

// TestBudgetEnforcer_SnapshotWithSpendButNoIdentityFailsClosed is the Codex P1 (round-7) proof: a
// syntactically valid snapshot whose spend is nonzero but whose identity history is missing/cleared
// must fail CLOSED (nil) rather than rebuild empty sets — otherwise a fresh principal/tool/server
// could slip past a cap of one within the same generation after a restart.
func TestBudgetEnforcer_SnapshotWithSpendButNoIdentityFailsClosed(t *testing.T) {
	b := testBudget(100)
	b.MaxPrincipals, b.MaxTools, b.MaxServers = 1, 1, 1
	// Nonzero spend but a missing identity dimension (Principals cleared) — must not restore.
	for _, snap := range []BudgetSnapshot{
		{Generation: 1, TotalReserved: 3, StartUnixNano: 1, RateWindowStartNano: 1, Tools: []string{"t1"}, Servers: []string{"s1"}},
		{Generation: 1, TotalReserved: 3, StartUnixNano: 1, RateWindowStartNano: 1, Principals: []string{"p1"}, Servers: []string{"s1"}},
		{Generation: 1, TotalReserved: 3, StartUnixNano: 1, RateWindowStartNano: 1, Principals: []string{"p1"}, Tools: []string{"t1"}},
		{Generation: 1, TotalReserved: 1, StartUnixNano: 1, RateWindowStartNano: 1}, // all missing
	} {
		if RestoreBudgetEnforcer(b, 1, snap) != nil {
			t.Fatalf("SECURITY: a nonzero-spend snapshot missing identity history must fail closed (nil): %+v", snap)
		}
	}
	// A ZERO-spend snapshot with empty identity sets is legitimate (no grants yet) and must restore.
	zero := BudgetSnapshot{Generation: 1, TotalReserved: 0, StartUnixNano: 1, RateWindowStartNano: 1}
	if RestoreBudgetEnforcer(b, 1, zero) == nil {
		t.Fatal("a zero-spend snapshot with no identity history is valid and must restore")
	}
}

// TestBudgetEnforcer_IdentityCapsEnforced is the §3 blast-radius-identity proof (Codex P1): the
// distinct principal/tool/server ceilings are enforced at runtime — a NEW identity beyond its cap is
// denied, an already-admitted identity is always allowed, and the denial is classified as an
// identity/blast-radius breach (not a throttle). Restart preserves the admitted identity sets.
func TestBudgetEnforcer_IdentityCapsEnforced(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := testBudget(100)
	b.MaxPrincipals = 2
	b.MaxTools = 2
	b.MaxServers = 1
	e := NewBudgetEnforcer(b, 1, now)

	// Two distinct tools on one server for two principals — all within caps.
	if o := e.Reserve(1, now, ExecutionIdentity{Principal: "p1", Tool: "t1", Server: "s1"}); o != BudgetGranted {
		t.Fatalf("p1/t1/s1 must be granted, got %s", o)
	}
	if o := e.Reserve(1, now, ExecutionIdentity{Principal: "p2", Tool: "t2", Server: "s1"}); o != BudgetGranted {
		t.Fatalf("p2/t2/s1 must be granted, got %s", o)
	}
	// A THIRD distinct tool exceeds MaxTools=2.
	if o := e.Reserve(1, now, ExecutionIdentity{Principal: "p1", Tool: "t3", Server: "s1"}); o != BudgetDeniedToolCap {
		t.Fatalf("a 3rd distinct tool must be denied on the tool cap, got %s", o)
	}
	// A THIRD distinct principal exceeds MaxPrincipals=2.
	if o := e.Reserve(1, now, ExecutionIdentity{Principal: "p3", Tool: "t1", Server: "s1"}); o != BudgetDeniedPrincipalCap {
		t.Fatalf("a 3rd distinct principal must be denied on the principal cap, got %s", o)
	}
	// A SECOND distinct server exceeds MaxServers=1.
	if o := e.Reserve(1, now, ExecutionIdentity{Principal: "p1", Tool: "t1", Server: "s2"}); o != BudgetDeniedServerCap {
		t.Fatalf("a 2nd distinct server must be denied on the server cap, got %s", o)
	}
	if !e.Reserve(1, now, ExecutionIdentity{Principal: "p3", Tool: "t1", Server: "s1"}).IdentityCapExceeded() {
		t.Fatal("an identity-cap denial must classify as an identity/blast-radius breach")
	}
	// An ALREADY-admitted identity is still allowed at cap.
	if o := e.Reserve(1, now, ExecutionIdentity{Principal: "p1", Tool: "t1", Server: "s1"}); o != BudgetGranted {
		t.Fatalf("an already-admitted identity must remain grantable at cap, got %s", o)
	}

	// Restart must preserve the admitted identity sets: a new identity is still denied after restore.
	snap := e.Snapshot()
	restored := RestoreBudgetEnforcer(b, 1, snap)
	if restored == nil {
		t.Fatal("snapshot must restore")
	}
	if o := restored.Reserve(1, now, ExecutionIdentity{Principal: "p9", Tool: "t1", Server: "s1"}); o != BudgetDeniedPrincipalCap {
		t.Fatalf("SECURITY: a restart must not admit a fresh principal beyond the cap, got %s", o)
	}
	if o := restored.Reserve(1, now, ExecutionIdentity{Principal: "p1", Tool: "t1", Server: "s1"}); o != BudgetGranted {
		t.Fatalf("a restored already-admitted identity must remain grantable, got %s", o)
	}
}

// TestBudgetEnforcer_IncompleteIdentityFailsClosed is the Codex P1 (round-4) proof: a reservation
// whose ExecutionIdentity is missing any dimension (empty Principal/Tool/Server) must fail CLOSED —
// never admitted as the empty-string key. Without the guard, two distinct real tools that both
// resolve to an empty Tool would both execute under MaxTools:1, silently defeating the ceiling.
func TestBudgetEnforcer_IncompleteIdentityFailsClosed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := testBudget(100)
	b.MaxPrincipals = 1
	b.MaxTools = 1
	b.MaxServers = 1
	e := NewBudgetEnforcer(b, 1, now)

	// Each missing dimension is denied with the incomplete-identity outcome, and consumes no slot.
	for _, id := range []ExecutionIdentity{
		{Principal: "", Tool: "t1", Server: "s1"},
		{Principal: "p1", Tool: "", Server: "s1"},
		{Principal: "p1", Tool: "t1", Server: ""},
		{}, // all empty
	} {
		if o := e.Reserve(1, now, id); o != BudgetDeniedIdentityIncomplete {
			t.Fatalf("an incomplete identity %+v must be denied identity-incomplete, got %s", id, o)
		}
	}
	// No slot was consumed by any of the denials — a full valid identity still gets the first grant.
	if o := e.Reserve(1, now, ExecutionIdentity{Principal: "p1", Tool: "t1", Server: "s1"}); o != BudgetGranted {
		t.Fatalf("a complete identity must still be granted after incomplete denials, got %s", o)
	}
	// SECURITY: a SECOND execution with an empty Tool must NOT be admitted as the same "" key under
	// MaxTools:1 — it fails closed rather than collapsing onto an already-admitted slot.
	if o := e.Reserve(1, now, ExecutionIdentity{Principal: "p1", Tool: "", Server: "s1"}); o != BudgetDeniedIdentityIncomplete {
		t.Fatalf("SECURITY: an empty Tool must never bypass MaxTools via the empty key, got %s", o)
	}
}

// TestBudgetEnforcer_ClockRollbackFailsClosedOnWindow is the Codex P2 (round-11) proof: the stored
// activation instant is a wall-clock UnixNano, so a backward clock step after activation would make
// the elapsed delta shrink/negative and keep the window check passing — silently extending the
// Canary past its safety window. A `now` earlier than the recorded activation instant must fail
// closed on the window.
func TestBudgetEnforcer_ClockRollbackFailsClosedOnWindow(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	b := testBudget(100)
	b.Window = time.Hour
	e := NewBudgetEnforcer(b, 1, start)
	// A reserve BEFORE the activation instant (clock rolled back) must fail closed on the window.
	if o := e.Reserve(1, start.Add(-time.Second), idOne); o != BudgetDeniedWindow {
		t.Fatalf("a backward clock step must fail closed on the window, got %s", o)
	}
	// Sanity: a normal in-window reserve still grants.
	if o := e.Reserve(1, start.Add(time.Minute), idOne); o != BudgetGranted {
		t.Fatalf("an in-window reserve must still grant, got %s", o)
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
			if e.Reserve(1, now, idOne).Granted() {
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
