package canary

import (
	"sync"
	"time"
)

// Runtime blast-radius budget enforcement (§3, Canary Activation Gate). ValidateBudget (budget.go)
// proves a Budget is well-formed; BudgetEnforcer is the RUNTIME half that a live Canary would
// consult at the pre-side-effect boundary to refuse an execution the budget does not permit. It is
// pure (no I/O), clock-injected (callers pass the instant, like rollout.Scope), atomic under
// concurrency (one mutex guards the whole check-then-reserve), and GENERATION-BOUND: an enforcer
// belongs to exactly one activation generation, and a Reserve carrying a different generation is
// refused — so a demotion/rollback that bumps the generation structurally invalidates every
// in-flight reservation against the old one.
//
// It is exercised through a controlled test seam in this build (no LiveExecutor is composed), but
// the contract is real: budget exhaustion fails closed BEFORE the side-effect boundary, the total
// counter is MONOTONIC (a reservation is never rolled back — a crash between Reserve and the side
// effect must not let the budget be replayed), there is no off-by-one (exactly MaxTotalExecutions
// grants), memory is bounded (fixed scalar counters — no per-request growth), and restart is
// explicit (Snapshot/Restore carry the durable executed count so a restart never resets the
// budget to zero).

// BudgetOutcome is the result of a Reserve. Exactly one is returned; only BudgetGranted authorizes
// crossing the side-effect boundary and obliges the caller to Release when the execution finishes.
type BudgetOutcome uint8

const (
	// BudgetGranted — a slot was reserved; the caller MUST Release when the execution completes.
	BudgetGranted BudgetOutcome = iota
	// BudgetDeniedTotal — MaxTotalExecutions is spent. WHOLE-CANARY: maps to budget_exhausted.
	BudgetDeniedTotal
	// BudgetDeniedWindow — the time-boxed Window (TTL) elapsed. WHOLE-CANARY: maps to budget_exhausted.
	BudgetDeniedWindow
	// BudgetDeniedConcurrency — MaxConcurrentExecutions in flight. PER-REQUEST throttle (retryable).
	BudgetDeniedConcurrency
	// BudgetDeniedRate — MaxExecutionsPerMinute reached in the current minute. PER-REQUEST throttle.
	BudgetDeniedRate
	// BudgetDeniedGeneration — the Reserve's generation does not match this enforcer's activation
	// generation (a stale reservation against a superseded/rolled-back activation). Fail-closed.
	BudgetDeniedGeneration
	// BudgetDeniedInvalid — the enforcer is not armed with a valid budget (fail-closed default).
	BudgetDeniedInvalid
)

// String returns a stable token for logs/metrics.
func (o BudgetOutcome) String() string {
	switch o {
	case BudgetGranted:
		return "granted"
	case BudgetDeniedTotal:
		return "denied_total"
	case BudgetDeniedWindow:
		return "denied_window"
	case BudgetDeniedConcurrency:
		return "denied_concurrency"
	case BudgetDeniedRate:
		return "denied_rate"
	case BudgetDeniedGeneration:
		return "denied_generation"
	case BudgetDeniedInvalid:
		return "denied_invalid"
	default:
		return "unknown"
	}
}

// Granted reports whether the outcome authorizes crossing the side-effect boundary.
func (o BudgetOutcome) Granted() bool { return o == BudgetGranted }

// WholeCanaryExhaustion reports whether the outcome is a budget-EXHAUSTION denial (total spent or
// window elapsed) — a whole-Canary breach (budget_exhausted) rather than a per-request throttle.
func (o BudgetOutcome) WholeCanaryExhaustion() bool {
	return o == BudgetDeniedTotal || o == BudgetDeniedWindow
}

// budgetRateWindow is the fixed rate-limiter window (MaxExecutionsPerMinute is per this window).
const budgetRateWindow = time.Minute

// BudgetEnforcer is the generation-bound runtime budget gate for one Canary activation. Construct
// via NewBudgetEnforcer (fresh activation) or RestoreBudgetEnforcer (restart). All methods are
// safe for concurrent use.
type BudgetEnforcer struct {
	budget     Budget
	generation uint64
	startNanos int64 // activation instant (window start), UnixNano

	mu              sync.Mutex
	total           int   // MONOTONIC reserved count — never rolled back (no replay)
	inflight        int   // current in-flight reservations (Release decrements)
	rateWindowStart int64 // start of the current rate window, UnixNano
	rateCount       int   // reservations granted in the current rate window
}

// NewBudgetEnforcer arms an enforcer for a fresh activation at generation gen (which MUST be ≥1 —
// generation 0 is the "no activation" sentinel and is refused) with the window starting at now.
// The budget must be valid (ValidateBudget). Returns nil when the budget is invalid or gen is 0,
// so a caller that forgets to check cannot obtain a permissive enforcer.
func NewBudgetEnforcer(budget Budget, generation uint64, now time.Time) *BudgetEnforcer {
	if generation == 0 || ValidateBudget(budget) != BudgetOK {
		return nil
	}
	start := now.UnixNano()
	return &BudgetEnforcer{
		budget:          budget,
		generation:      generation,
		startNanos:      start,
		rateWindowStart: start,
	}
}

// Generation returns the activation generation this enforcer is bound to.
func (e *BudgetEnforcer) Generation() uint64 {
	if e == nil {
		return 0
	}
	return e.generation
}

// Reserve atomically decides whether one execution may cross the side-effect boundary NOW, for the
// activation generation gen, and — on grant — consumes the slot (monotonic total++, inflight++,
// rate++). It is fail-closed: a nil enforcer, invalid budget, generation mismatch, elapsed window,
// spent total, exhausted concurrency, or exhausted rate all deny. The generation check is FIRST so
// a stale reservation against a superseded activation can never consume the new one's budget.
func (e *BudgetEnforcer) Reserve(gen uint64, now time.Time) BudgetOutcome {
	if e == nil {
		return BudgetDeniedInvalid
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if ValidateBudget(e.budget) != BudgetOK {
		return BudgetDeniedInvalid
	}
	if gen != e.generation {
		return BudgetDeniedGeneration
	}
	// Window (TTL) — the experiment is time-boxed; once elapsed nothing more executes.
	if now.UnixNano()-e.startNanos >= int64(e.budget.Window) {
		return BudgetDeniedWindow
	}
	// Total — the absolute execution ceiling. Exactly MaxTotalExecutions grants (no off-by-one):
	// grants happen while total ∈ [0, N-1]; the Nth leaves total==N and every later Reserve denies.
	if e.total >= e.budget.MaxTotalExecutions {
		return BudgetDeniedTotal
	}
	// Concurrency — simultaneous in-flight cap (per-request throttle; Release frees a slot).
	if e.inflight >= e.budget.MaxConcurrentExecutions {
		return BudgetDeniedConcurrency
	}
	// Rate — sustained per-minute cap over a fixed window.
	if now.UnixNano()-e.rateWindowStart >= int64(budgetRateWindow) {
		e.rateWindowStart = now.UnixNano()
		e.rateCount = 0
	}
	if e.rateCount >= e.budget.MaxExecutionsPerMinute {
		return BudgetDeniedRate
	}
	// Grant: consume one slot on every dimension. total is MONOTONIC — never decremented, so a
	// crash between here and the side effect cannot replay the budget.
	e.total++
	e.inflight++
	e.rateCount++
	return BudgetGranted
}

// Release returns one in-flight concurrency slot after an execution completes. It NEVER decrements
// the monotonic total (the slot is spent whether the execution succeeded or failed — no replay).
// It is idempotent-safe against underflow (inflight never goes below zero).
func (e *BudgetEnforcer) Release() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.inflight > 0 {
		e.inflight--
	}
}

// TotalReserved returns the monotonic count of executions reserved so far (the durable budget
// spend). Used by the durable snapshot and the admin/status surface.
func (e *BudgetEnforcer) TotalReserved() int {
	if e == nil {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.total
}

// Inflight returns the current in-flight reservation count.
func (e *BudgetEnforcer) Inflight() int {
	if e == nil {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.inflight
}

// Remaining returns how many total executions are still permitted (never negative).
func (e *BudgetEnforcer) Remaining() int {
	if e == nil {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	r := e.budget.MaxTotalExecutions - e.total
	if r < 0 {
		return 0
	}
	return r
}

// BudgetSnapshot is the restart-durable, node-local budget state for one activation generation. It
// carries ONLY scalar counters and the generation/window instant — never a tenant/subject/secret.
type BudgetSnapshot struct {
	Generation    uint64 `json:"generation"`
	TotalReserved int    `json:"total_reserved"`
	StartUnixNano int64  `json:"start_unix_nano"`
}

// Snapshot returns the durable state so the composition layer can persist the budget spend. On
// restart the SAME generation restores the SAME total — the budget is never reset to zero, so a
// restart cannot replay a spent budget.
func (e *BudgetEnforcer) Snapshot() BudgetSnapshot {
	if e == nil {
		return BudgetSnapshot{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return BudgetSnapshot{Generation: e.generation, TotalReserved: e.total, StartUnixNano: e.startNanos}
}

// RestoreBudgetEnforcer rebuilds an enforcer from a durable snapshot for the SAME generation. It is
// fail-closed: a zero generation, invalid budget, generation mismatch, negative/over-cap total, or
// missing window instant returns nil, so a corrupt or stale-generation snapshot can never resurrect
// a permissive budget after restart. Inflight is intentionally reset to zero (no execution survives
// a restart), but the monotonic total is preserved so the spend carries forward.
func RestoreBudgetEnforcer(budget Budget, generation uint64, snap BudgetSnapshot) *BudgetEnforcer {
	if generation == 0 || ValidateBudget(budget) != BudgetOK {
		return nil
	}
	if snap.Generation != generation {
		return nil // a snapshot from a different (stale/newer) generation must not be restored here
	}
	if snap.TotalReserved < 0 || snap.TotalReserved > budget.MaxTotalExecutions {
		return nil // corrupt spend
	}
	if snap.StartUnixNano == 0 {
		return nil // no window instant ⇒ cannot bound the TTL, fail closed
	}
	return &BudgetEnforcer{
		budget:          budget,
		generation:      generation,
		startNanos:      snap.StartUnixNano,
		total:           snap.TotalReserved,
		rateWindowStart: snap.StartUnixNano,
	}
}
