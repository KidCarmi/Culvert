package canary

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// validFirstCanaryScope is the minimal admissible first-Canary scope: exactly one server,
// one exact fingerprinted tool, one principal, read-only operations.
func validFirstCanaryScope() rollout.ScopeSpec {
	return rollout.ScopeSpec{
		Capability: rollout.CapabilityGateway,
		Tenants:    []string{"t1"},
		Servers:    []string{"srv-canary"},
		Tools:      []rollout.ToolSel{{Server: "srv-canary", Name: "echo", Fingerprint: "abc123"}},
		Principals: []string{"synthetic-canary-principal"},
		Operations: []rollout.RiskClass{rollout.RiskRead},
	}
}

func TestValidateScope_MinimalValidIsAccepted(t *testing.T) {
	if r := ValidateScope(validFirstCanaryScope(), 1); r != ScopeOK {
		t.Fatalf("minimal valid first-Canary scope rejected: %s", r)
	}
	if !ScopeReadFirst(validFirstCanaryScope()) {
		t.Fatal("minimal valid scope must be read-first")
	}
}

func TestValidateScope_Rejections(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*rollout.ScopeSpec)
		want   ScopeReason
	}{
		{"management_capability", func(s *rollout.ScopeSpec) { s.Capability = rollout.CapabilityManagement }, ScopeNotGateway},
		{"empty_scope", func(s *rollout.ScopeSpec) { *s = rollout.ScopeSpec{Capability: rollout.CapabilityGateway} }, ScopeMatchesNothing},
		{"percentage_only", func(s *rollout.ScopeSpec) {
			*s = rollout.ScopeSpec{Capability: rollout.CapabilityGateway, Percent: 1, BucketSalt: "s"}
		}, ScopeNotEnumerable},
		{"percentage_over_enumerated", func(s *rollout.ScopeSpec) { s.Percent = 50; s.BucketSalt = "s" }, ScopeUsesPercentage},
		{"no_servers", func(s *rollout.ScopeSpec) { s.Servers = nil }, ScopeNoServers},
		{"no_tools", func(s *rollout.ScopeSpec) { s.Tools = nil }, ScopeNoTools},
		{"too_many_servers", func(s *rollout.ScopeSpec) { s.Servers = []string{"a", "b"} }, ScopeTooManyServers},
		{"too_many_tools", func(s *rollout.ScopeSpec) {
			s.Tools = []rollout.ToolSel{
				{Server: "srv-canary", Name: "a", Fingerprint: "f1"},
				{Server: "srv-canary", Name: "b", Fingerprint: "f2"},
				{Server: "srv-canary", Name: "c", Fingerprint: "f3"},
			}
		}, ScopeTooManyTools},
		{"too_many_principals", func(s *rollout.ScopeSpec) { s.Principals = []string{"a", "b", "c"} }, ScopeTooManyPrincipals},
		{"no_identity", func(s *rollout.ScopeSpec) { s.Principals = nil }, ScopeNoIdentity},
		{"group_only_identity", func(s *rollout.ScopeSpec) {
			// A group-only scope binds no exact principal — rejected as no-identity (groups are
			// not a bounded principal axis; Codex P1-D).
			s.Principals = nil
			s.Groups = []string{"g1"}
		}, ScopeNoIdentity},
		{"uses_groups", func(s *rollout.ScopeSpec) {
			// Even WITH an exact principal, adding a group is forbidden for a first Canary —
			// membership can change without a scope edit (Codex P1-D).
			s.Groups = []string{"g1"}
		}, ScopeUsesGroups},
		{"no_tenant", func(s *rollout.ScopeSpec) { s.Tenants = nil }, ScopeNoTenant},
		{"empty_tenant_string", func(s *rollout.ScopeSpec) { s.Tenants = []string{""} }, ScopeNoTenant},
		{"too_many_tenants", func(s *rollout.ScopeSpec) { s.Tenants = []string{"t1", "t2"} }, ScopeTooManyTenants},
		{"tool_server_not_in_scope", func(s *rollout.ScopeSpec) {
			// The only tool is on a server the scope's server dimension does not include, so no
			// subject can ever match — enumerable but contradictory (Codex P2).
			s.Tools = []rollout.ToolSel{{Server: "other-server", Name: "echo", Fingerprint: "abc123"}}
		}, ScopeNotRealizable},
		{"excluded_tenant", func(s *rollout.ScopeSpec) {
			// The sole tenant is also excluded — Contains rejects every subject (Codex P2).
			s.ExcludeTenants = []string{"t1"}
		}, ScopeNotRealizable},
		{"tool_missing_fingerprint", func(s *rollout.ScopeSpec) {
			s.Tools = []rollout.ToolSel{{Server: "srv-canary", Name: "echo"}} // no Fingerprint (wildcard-future-tool)
		}, ScopeToolMissingFingerprint},
		{"high_risk_flag", func(s *rollout.ScopeSpec) { s.HighRisk = true }, ScopeHighRisk},
		{"write_operation", func(s *rollout.ScopeSpec) { s.Operations = []rollout.RiskClass{rollout.RiskRead, rollout.RiskWrite} }, ScopeNotReadFirst},
		{"destructive_operation", func(s *rollout.ScopeSpec) { s.Operations = []rollout.RiskClass{rollout.RiskDestructive} }, ScopeNotReadFirst},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validFirstCanaryScope()
			tc.mutate(&s)
			if r := ValidateScope(s, 1); r != tc.want {
				t.Fatalf("ValidateScope(%s) = %q, want %q", tc.name, r, tc.want)
			}
		})
	}
}

// TestScopeReadFirst_IndependentOfBounds proves read-first is a distinct axis from
// boundedness: a well-bounded scope can still be non-read-first, and that must surface as
// its own signal (the readiness layer maps it to a distinct reason).
func TestScopeReadFirst_IndependentOfBounds(t *testing.T) {
	s := validFirstCanaryScope()
	s.Operations = []rollout.RiskClass{rollout.RiskWrite}
	if ScopeReadFirst(s) {
		t.Fatal("a write-admitting scope must not be read-first")
	}
	// Boundedness-wise it is otherwise fine, but ValidateScope rejects it on the read-first axis.
	if r := ValidateScope(s, 1); r != ScopeNotReadFirst {
		t.Fatalf("want scope_not_read_first, got %q", r)
	}
}
