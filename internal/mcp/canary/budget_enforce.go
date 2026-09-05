package canary

import (
	"sort"
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
	// BudgetDeniedPrincipalCap — this execution's principal is a NEW distinct principal that would
	// exceed MaxPrincipals. A blast-radius (identity) breach, not a throttle.
	BudgetDeniedPrincipalCap
	// BudgetDeniedToolCap — this execution's tool is a NEW distinct tool that would exceed MaxTools.
	BudgetDeniedToolCap
	// BudgetDeniedServerCap — this execution's server is a NEW distinct server that would exceed
	// MaxServers.
	BudgetDeniedServerCap
	// BudgetDeniedIdentityIncomplete — the execution's ExecutionIdentity is missing a dimension
	// (empty Principal, Tool, or Server). Fail-closed: an unresolved authoritative identity must
	// never be admitted as the empty-string key, which would collapse every distinct unresolved
	// identity onto one already-admitted slot and silently defeat the distinct-identity ceilings.
	BudgetDeniedIdentityIncomplete
)

// ExecutionIdentity carries the authoritative identity of one execution so the runtime budget can
// enforce the distinct-identity blast-radius ceilings (MaxPrincipals/MaxTools/MaxServers). It is
// supplied by the (future) live executor from resolved request state — never a request-supplied
// claim trusted without policy resolution.
type ExecutionIdentity struct {
	Principal string
	Tool      string
	Server    string
}

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
	case BudgetDeniedPrincipalCap:
		return "denied_principal_cap"
	case BudgetDeniedToolCap:
		return "denied_tool_cap"
	case BudgetDeniedServerCap:
		return "denied_server_cap"
	case BudgetDeniedIdentityIncomplete:
		return "denied_identity_incomplete"
	default:
		return "unknown"
	}
}

// IdentityCapExceeded reports whether the outcome is a distinct-identity blast-radius denial (a new
// principal/tool/server beyond the configured ceiling) — a scope/blast-radius breach the runtime
// treats as a whole-Canary abort signal, distinct from a transient throttle.
func (o BudgetOutcome) IdentityCapExceeded() bool {
	return o == BudgetDeniedPrincipalCap || o == BudgetDeniedToolCap || o == BudgetDeniedServerCap
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
	// Distinct-identity sets: the blast-radius ceilings (MaxPrincipals/MaxTools/MaxServers) are
	// enforced by admitting at most that many DISTINCT identities. Bounded by the caps (tiny). They
	// are durable so a restart cannot admit a fresh set of identities beyond the ceiling.
	principals map[string]struct{}
	tools      map[string]struct{}
	servers    map[string]struct{}
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
		principals:      make(map[string]struct{}),
		tools:           make(map[string]struct{}),
		servers:         make(map[string]struct{}),
	}
}

// Generation returns the activation generation this enforcer is bound to.
func (e *BudgetEnforcer) Generation() uint64 {
	if e == nil {
		return 0
	}
	return e.generation
}

// Reserve atomically decides whether one execution — for the identity ident — may cross the
// side-effect boundary NOW, for the activation generation gen, and — on grant — consumes the slot
// (monotonic total++, inflight++, rate++) and records the identity against the distinct-identity
// ceilings. It is fail-closed: a nil enforcer, invalid budget, generation mismatch, elapsed window,
// spent total, a NEW identity beyond MaxPrincipals/MaxTools/MaxServers, exhausted concurrency, or
// exhausted rate all deny. The generation check is FIRST so a stale reservation against a superseded
// activation can never consume the new one's budget. The identity caps are checked BEFORE the
// throttles so a blast-radius breach is reported as such, and no dimension is consumed on any denial.
func (e *BudgetEnforcer) Reserve(gen uint64, now time.Time, ident ExecutionIdentity) BudgetOutcome {
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
	// Window (TTL) — the experiment is time-boxed; once elapsed nothing more executes. The stored
	// activation instant is a wall-clock UnixNano (Go's monotonic reading is dropped on the struct and
	// cannot survive the durable snapshot), so a backward clock step (NTP correction, manual set) would
	// make the elapsed delta shrink or go NEGATIVE and keep this check passing until wall time catches
	// back up — silently extending the Canary past its safety window. A `now` earlier than the recorded
	// activation instant is therefore treated as window-expired and fails CLOSED (Codex P2).
	elapsed := now.UnixNano() - e.startNanos
	if elapsed < 0 || elapsed >= int64(e.budget.Window) {
		return BudgetDeniedWindow
	}
	// Total — the absolute execution ceiling. Exactly MaxTotalExecutions grants (no off-by-one):
	// grants happen while total ∈ [0, N-1]; the Nth leaves total==N and every later Reserve denies.
	if e.total >= e.budget.MaxTotalExecutions {
		return BudgetDeniedTotal
	}
	// Identity fail-closed + distinct-identity blast-radius ceilings (extracted to keep Reserve under
	// the cyclomatic-complexity budget). No slot is consumed on any identity denial.
	if d := e.identityDenial(ident); d != BudgetGranted {
		return d
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
	// Grant: consume one slot on every dimension and record the identities. total is MONOTONIC —
	// never decremented, so a crash between here and the side effect cannot replay the budget.
	e.total++
	e.inflight++
	e.rateCount++
	e.principals[ident.Principal] = struct{}{}
	e.tools[ident.Tool] = struct{}{}
	e.servers[ident.Server] = struct{}{}
	return BudgetGranted
}

// identityDenial fails an execution CLOSED on any identity problem, returning the specific denial
// outcome, or BudgetGranted when the identity is complete and within every distinct-identity ceiling.
// It first rejects a missing dimension (an empty Principal/Tool/Server must never be admitted as the
// empty-string key — Codex P1), then the blast-radius ceilings (a NEW principal/tool/server beyond
// its cap is a scope breach). No slot is consumed by any denial. Extracted from Reserve to keep that
// method under the cyclomatic-complexity budget. Caller holds e.mu.
func (e *BudgetEnforcer) identityDenial(ident ExecutionIdentity) BudgetOutcome {
	if ident.Principal == "" || ident.Tool == "" || ident.Server == "" {
		return BudgetDeniedIdentityIncomplete
	}
	if isNewBeyondCap(e.principals, ident.Principal, e.budget.MaxPrincipals) {
		return BudgetDeniedPrincipalCap
	}
	if isNewBeyondCap(e.tools, ident.Tool, e.budget.MaxTools) {
		return BudgetDeniedToolCap
	}
	if isNewBeyondCap(e.servers, ident.Server, e.budget.MaxServers) {
		return BudgetDeniedServerCap
	}
	return BudgetGranted
}

// isNewBeyondCap reports whether v is NOT already in set AND admitting it would exceed cap. An
// already-present value is always admissible (it does not grow the distinct count).
func isNewBeyondCap(set map[string]struct{}, v string, capLimit int) bool {
	if _, ok := set[v]; ok {
		return false
	}
	return len(set) >= capLimit
}

// windowOpenLocked reports whether the time-boxed window is still open at now. Caller holds e.mu.
func (e *BudgetEnforcer) windowOpenLocked(now time.Time) bool {
	elapsed := now.UnixNano() - e.startNanos
	return elapsed >= 0 && elapsed < int64(e.budget.Window)
}

// WindowDeadline returns the ABSOLUTE instant this activation's time box expires: the recorded
// activation instant plus the budget Window. It is derived from the SAME persisted activation
// instant the window check uses, so it cannot drift from Reserve's verdict, and a restart restoring
// that instant restores the SAME deadline — a restart can never hand the Canary a fresh full window.
// A nil enforcer or a non-positive window yields the zero time (no deadline to enforce).
func (e *BudgetEnforcer) WindowDeadline() time.Time {
	if e == nil || e.budget.Window <= 0 {
		return time.Time{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return time.Unix(0, e.startNanos).Add(e.budget.Window)
}

// WindowOpen reports whether the time-boxed window is still open at now: false once the configured
// Window has elapsed, AND false on a backward clock step (now earlier than the activation instant) —
// mirroring Reserve's window gate exactly, so a status/eligibility read agrees with what a Reserve
// would actually do rather than reporting eligible for an activation whose every reserve would return
// BudgetDeniedWindow (Codex P2). A nil enforcer is not open.
func (e *BudgetEnforcer) WindowOpen(now time.Time) bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.windowOpenLocked(now)
}

// reservableLocked reports whether a Reserve — ignoring generation and the specific execution
// identity — would be GRANTED at now: a valid budget, an open window, a total slot remaining, a free
// concurrency slot, AND rate budget in the current (or rolled-over) window. It is the non-consuming,
// identity-independent form of Reserve's window+total+throttle decision. It NEVER mutates state — in
// particular the rate-window rollover is COMPUTED, not applied (a read must not advance the window) —
// so it is exact for the identity-independent gates and can only be wrong in the permissive direction
// for the identity caps, which an eligibility read has no identity to evaluate. Caller holds e.mu.
func (e *BudgetEnforcer) reservableLocked(now time.Time) bool {
	if ValidateBudget(e.budget) != BudgetOK {
		return false
	}
	if !e.windowOpenLocked(now) {
		return false
	}
	if e.total >= e.budget.MaxTotalExecutions {
		return false
	}
	if e.inflight >= e.budget.MaxConcurrentExecutions {
		return false
	}
	// Rate: a Reserve rolls the window over (count resets to 0) once budgetRateWindow has elapsed, so
	// rate is available then; otherwise the current count must be below the per-window cap. Do NOT
	// mutate rateWindowStart/rateCount here — this is a read.
	if now.UnixNano()-e.rateWindowStart < int64(budgetRateWindow) && e.rateCount >= e.budget.MaxExecutionsPerMinute {
		return false
	}
	return true
}

// Reservable is the exported, locked form of reservableLocked: whether an execution could be reserved
// right now (ignoring generation and the specific execution identity — concurrency, rate, window, and
// total are all reflected). A nil enforcer is never reservable.
func (e *BudgetEnforcer) Reservable(now time.Time) bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.reservableLocked(now)
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
	// RateWindowStartNano + RateCount are the current rate-limit window position. They are durable
	// generation-bound state so a restart mid-window cannot reset the rate budget and admit another
	// full MaxExecutionsPerMinute burst (a restart-replay of the rate cap; Codex P1).
	RateWindowStartNano int64 `json:"rate_window_start_nano"`
	RateCount           int   `json:"rate_count"`
	// The distinct-identity sets consumed so far, so a restart cannot admit a fresh set of
	// identities beyond the MaxPrincipals/MaxTools/MaxServers ceilings.
	Principals []string `json:"principals,omitempty"`
	Tools      []string `json:"tools,omitempty"`
	Servers    []string `json:"servers,omitempty"`
}

// Snapshot returns the durable state so the composition layer can persist the budget spend. On
// restart the SAME generation restores the SAME total AND the current rate-window position — the
// budget is never reset to zero, so a restart cannot replay a spent total or a spent rate window.
func (e *BudgetEnforcer) Snapshot() BudgetSnapshot {
	if e == nil {
		return BudgetSnapshot{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return BudgetSnapshot{
		Generation:          e.generation,
		TotalReserved:       e.total,
		StartUnixNano:       e.startNanos,
		RateWindowStartNano: e.rateWindowStart,
		RateCount:           e.rateCount,
		Principals:          sortedSetKeys(e.principals),
		Tools:               sortedSetKeys(e.tools),
		Servers:             sortedSetKeys(e.servers),
	}
}

// sortedSetKeys returns the set's keys in deterministic order (so the snapshot is stable).
func sortedSetKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// setFromKeys rebuilds a set from persisted keys, capped defensively at cap (a corrupt over-cap
// list is truncated deterministically rather than admitting an over-budget identity set).
func setFromKeys(keys []string, capLimit int) map[string]struct{} {
	set := make(map[string]struct{}, len(keys))
	sorted := append([]string(nil), keys...)
	sort.Strings(sorted)
	for _, k := range sorted {
		if len(set) >= capLimit {
			break
		}
		set[k] = struct{}{}
	}
	return set
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
	// Every grant records exactly one principal, tool, and server, so a nonzero spend REQUIRES at
	// least one entry in each identity set. A syntactically valid snapshot whose spend is nonzero but
	// whose identity history is missing or cleared would otherwise rebuild EMPTY sets and let a fresh
	// principal/tool/server slip past a cap of one within the SAME generation after a restart — a
	// distinct-identity blast-radius escape. Fail closed rather than treat lost identity history as
	// unused capacity (Codex P1).
	if snap.TotalReserved > 0 && (len(snap.Principals) == 0 || len(snap.Tools) == 0 || len(snap.Servers) == 0) {
		return nil
	}
	if snap.StartUnixNano == 0 {
		return nil // no window instant ⇒ cannot bound the TTL, fail closed
	}
	// Restore the rate-window position so the rate cap is not replayed across a restart. A snapshot
	// predating these fields (zero start) or a corrupt count fails CLOSED: the window is anchored at
	// the activation instant and treated as SPENT, so the next Reserve grants only after
	// budgetRateWindow has elapsed — a restart never earns a fresh in-window burst.
	rateStart := snap.RateWindowStartNano
	rateCount := snap.RateCount
	if rateStart == 0 || rateCount < 0 || rateCount > budget.MaxExecutionsPerMinute {
		rateStart = snap.StartUnixNano
		rateCount = budget.MaxExecutionsPerMinute
	}
	return &BudgetEnforcer{
		budget:          budget,
		generation:      generation,
		startNanos:      snap.StartUnixNano,
		total:           snap.TotalReserved,
		rateWindowStart: rateStart,
		rateCount:       rateCount,
		principals:      setFromKeys(snap.Principals, budget.MaxPrincipals),
		tools:           setFromKeys(snap.Tools, budget.MaxTools),
		servers:         setFromKeys(snap.Servers, budget.MaxServers),
	}
}
