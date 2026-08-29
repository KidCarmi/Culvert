package canary

import "time"

// Budget is the machine-enforced first-Canary blast-radius ceiling (§15). Every field is a
// HARD cap the runtime must refuse to exceed; there is no "unlimited" sentinel — a zero cap
// is invalid (fail-closed), so a budget that forgot a dimension does not silently admit
// unbounded execution. These are the limits that make the first real side effect small: a
// bounded number of executions, over a bounded window, for a bounded set of principals /
// tools / servers, at a bounded rate and concurrency.
type Budget struct {
	// MaxTotalExecutions is the absolute number of real upstream executions the Canary may
	// ever perform before it must stop and be re-reviewed.
	MaxTotalExecutions int
	// MaxExecutionsPerMinute bounds the sustained rate.
	MaxExecutionsPerMinute int
	// MaxConcurrentExecutions bounds simultaneous in-flight upstream calls.
	MaxConcurrentExecutions int
	// MaxPrincipals bounds the distinct principals/clients that may trigger an execution.
	MaxPrincipals int
	// MaxTools bounds the distinct tools that may be executed.
	MaxTools int
	// MaxServers bounds the distinct servers that may be executed against.
	MaxServers int
	// Window is the wall-clock TTL after which the Canary auto-stops regardless of counts —
	// a Canary is a time-boxed experiment, not a standing mode.
	Window time.Duration
}

// BudgetReason is a bounded classification for an invalid budget. Fixed vocabulary.
type BudgetReason string

// Budget rejection sub-reasons (fixed vocabulary; BudgetOK is the empty admissible value).
const (
	BudgetOK                BudgetReason = ""
	BudgetNoTotal           BudgetReason = "budget_no_total_cap"
	BudgetNoRate            BudgetReason = "budget_no_rate_cap"
	BudgetNoConcurrency     BudgetReason = "budget_no_concurrency_cap"
	BudgetNoPrincipals      BudgetReason = "budget_no_principal_cap"
	BudgetNoTools           BudgetReason = "budget_no_tool_cap"
	BudgetNoServers         BudgetReason = "budget_no_server_cap"
	BudgetNoWindow          BudgetReason = "budget_no_window"
	BudgetTotalExceedsCeil  BudgetReason = "budget_total_exceeds_first_canary_ceiling"
	BudgetWindowExceedsCeil BudgetReason = "budget_window_exceeds_first_canary_ceiling"
	BudgetScopeInconsistent BudgetReason = "budget_tool_or_server_cap_exceeds_scope_bounds"
)

// First-Canary budget ceilings (§15). The budget may be TIGHTER than these but never looser;
// a later graduation phase raises them under its own review.
const (
	// FirstCanaryMaxTotalCeiling — a first Canary is a tiny controlled experiment, so even a
	// generous budget may not authorize more than this many real executions.
	FirstCanaryMaxTotalCeiling = 1000
	// FirstCanaryMaxWindowCeiling — a first Canary is time-boxed; the window may not exceed
	// this (a Canary that runs for weeks is a standing mode, not an experiment).
	FirstCanaryMaxWindowCeiling = 7 * 24 * time.Hour
)

// ValidateBudget enforces the first-Canary budget contract: every dimension has a positive
// cap, the total and window are within the first-Canary ceilings, and the tool/server caps
// are consistent with the bounded scope. Pure, fail-closed; returns BudgetOK ("") when
// admissible, else the first violated sub-reason. A zero-valued Budget (the default) is
// invalid on every axis — nothing runs without an explicit budget.
func ValidateBudget(b Budget) BudgetReason {
	switch {
	case b.MaxTotalExecutions <= 0:
		return BudgetNoTotal
	case b.MaxExecutionsPerMinute <= 0:
		return BudgetNoRate
	case b.MaxConcurrentExecutions <= 0:
		return BudgetNoConcurrency
	case b.MaxPrincipals <= 0:
		return BudgetNoPrincipals
	case b.MaxTools <= 0:
		return BudgetNoTools
	case b.MaxServers <= 0:
		return BudgetNoServers
	case b.Window <= 0:
		return BudgetNoWindow
	case b.MaxTotalExecutions > FirstCanaryMaxTotalCeiling:
		return BudgetTotalExceedsCeil
	case b.Window > FirstCanaryMaxWindowCeiling:
		return BudgetWindowExceedsCeil
	// The budget's tool/server caps must not exceed the scope's structural bounds — a budget
	// that permits more tools/servers than the first-Canary scope may name is inconsistent.
	case b.MaxTools > MaxCanaryTools || b.MaxServers > MaxCanaryServers || b.MaxPrincipals > MaxCanaryPrincipals:
		return BudgetScopeInconsistent
	default:
		return BudgetOK
	}
}
