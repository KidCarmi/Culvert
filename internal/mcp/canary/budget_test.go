package canary

import (
	"testing"
	"time"
)

func validBudget() Budget {
	return Budget{
		MaxTotalExecutions:      50,
		MaxExecutionsPerMinute:  5,
		MaxConcurrentExecutions: 1,
		MaxPrincipals:           1,
		MaxTools:                1,
		MaxServers:              1,
		Window:                  24 * time.Hour,
	}
}

func TestValidateBudget_ValidIsAccepted(t *testing.T) {
	if r := ValidateBudget(validBudget()); r != BudgetOK {
		t.Fatalf("valid budget rejected: %s", r)
	}
}

// TestValidateBudget_ZeroIsFailClosed proves the default (a forgotten budget) never admits
// unbounded execution — every axis must carry a positive cap.
func TestValidateBudget_ZeroIsFailClosed(t *testing.T) {
	if r := ValidateBudget(Budget{}); r != BudgetNoTotal {
		t.Fatalf("zero budget must fail closed, got %q", r)
	}
}

func TestValidateBudget_Rejections(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Budget)
		want   BudgetReason
	}{
		{"no_total", func(b *Budget) { b.MaxTotalExecutions = 0 }, BudgetNoTotal},
		{"no_rate", func(b *Budget) { b.MaxExecutionsPerMinute = 0 }, BudgetNoRate},
		{"no_concurrency", func(b *Budget) { b.MaxConcurrentExecutions = 0 }, BudgetNoConcurrency},
		{"no_principals", func(b *Budget) { b.MaxPrincipals = 0 }, BudgetNoPrincipals},
		{"no_tools", func(b *Budget) { b.MaxTools = 0 }, BudgetNoTools},
		{"no_servers", func(b *Budget) { b.MaxServers = 0 }, BudgetNoServers},
		{"no_window", func(b *Budget) { b.Window = 0 }, BudgetNoWindow},
		{"total_over_ceiling", func(b *Budget) { b.MaxTotalExecutions = FirstCanaryMaxTotalCeiling + 1 }, BudgetTotalExceedsCeil},
		{"window_over_ceiling", func(b *Budget) { b.Window = FirstCanaryMaxWindowCeiling + time.Hour }, BudgetWindowExceedsCeil},
		{"tools_over_scope", func(b *Budget) { b.MaxTools = MaxCanaryTools + 1 }, BudgetScopeInconsistent},
		{"servers_over_scope", func(b *Budget) { b.MaxServers = MaxCanaryServers + 1 }, BudgetScopeInconsistent},
		{"principals_over_scope", func(b *Budget) { b.MaxPrincipals = MaxCanaryPrincipals + 1 }, BudgetScopeInconsistent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := validBudget()
			tc.mutate(&b)
			if r := ValidateBudget(b); r != tc.want {
				t.Fatalf("ValidateBudget(%s) = %q, want %q", tc.name, r, tc.want)
			}
		})
	}
}
