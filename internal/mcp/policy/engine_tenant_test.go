package policy

import "testing"

// broadAllow is a priority-1, condition-free ALLOW — the strongest user rule a
// hostile or misconfigured policy could carry. QUAL-5 tenant isolation must beat it.
const broadAllow = `{"id":"BROAD","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`

// TestTenantIsolation_SameTenantAdmitted proves that when the authenticated tenant
// equals the addressed server's owner, the request is NOT denied by tenant isolation
// and reaches the ordinary user rules (ALLOW here). Covers tools/call and tools/list.
func TestTenantIsolation_SameTenantAdmitted(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*DecisionInput)
	}{
		{"tools/call", nil},
		{"tools/list discovery", func(in *DecisionInput) {
			in.Operation = Operation{Method: "tools/list", Class: OpDiscovery,
				Namespace: NamespaceGatewayTool, Operand: "list", DecisionPoint: "tool_catalog_discovery"}
			in.Tool = nil // discovery may carry no specific tool
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := gwInput()
			if in.Server.Owner != in.Principal.Tenant {
				t.Fatalf("fixture precondition: owner %q != tenant %q", in.Server.Owner, in.Principal.Tenant)
			}
			if tc.mutate != nil {
				tc.mutate(&in)
			}
			d, _ := eval(t, mustCompile(t, gwSnap(broadAllow)), in)
			if !d.Action.IsAllowClass() {
				t.Fatalf("same-tenant request must reach the ALLOW rule: got %v/%v", d.Action, d.Reason)
			}
			if d.HardOverride {
				t.Fatalf("same-tenant request must not be a hard override")
			}
		})
	}
}

// TestTenantIsolation_CrossTenantDenied proves that a request authenticated for one
// tenant addressing a server owned by another tenant is a TENANT_MISMATCH hard
// override — even under a broad priority-1 ALLOW, for both tools/call and tools/list.
func TestTenantIsolation_CrossTenantDenied(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*DecisionInput)
	}{
		{"tools/call", nil},
		{"tools/list discovery", func(in *DecisionInput) {
			in.Operation = Operation{Method: "tools/list", Class: OpDiscovery,
				Namespace: NamespaceGatewayTool, Operand: "list", DecisionPoint: "tool_catalog_discovery"}
			in.Tool = nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := gwInput()
			in.Principal.Tenant = "tenant-a"
			in.Client.Tenant = "tenant-a"
			in.Server.Owner = "tenant-b" // server owned by a DIFFERENT tenant
			if tc.mutate != nil {
				tc.mutate(&in)
			}
			d, _ := eval(t, mustCompile(t, gwSnap(broadAllow)), in)
			assertTenantDenied(t, d)
		})
	}
}

// TestTenantIsolation_EmptyOwnerFailsClosed proves an unscoped server (empty
// OwnerScope) is NEVER treated as "owned by every tenant": it fails closed.
func TestTenantIsolation_EmptyOwnerFailsClosed(t *testing.T) {
	in := gwInput()
	in.Server.Owner = ""
	d, _ := eval(t, mustCompile(t, gwSnap(broadAllow)), in)
	assertTenantDenied(t, d)
}

// TestTenantIsolation_ExactEqualityOnly proves the binding is byte-for-byte: no
// case-fold, prefix, substring, or wildcard match makes a foreign owner pass.
func TestTenantIsolation_ExactEqualityOnly(t *testing.T) {
	// Principal.Tenant is "tenant-a" in the fixture.
	owners := []struct {
		name  string
		owner string
	}{
		{"case difference", "Tenant-A"},
		{"trailing suffix", "tenant-a-extra"},
		{"leading prefix", "x-tenant-a"},
		{"owner is a prefix of tenant", "tenant"},
		{"whitespace padded", "tenant-a "},
		{"wildcard literal", "*"},
	}
	for _, o := range owners {
		t.Run(o.name, func(t *testing.T) {
			in := gwInput()
			in.Server.Owner = o.owner
			d, _ := eval(t, mustCompile(t, gwSnap(broadAllow)), in)
			assertTenantDenied(t, d)
		})
	}
}

// TestTenantIsolation_DominatesServerAndToolOverrides proves tenant isolation is the
// FIRST server-level override: a cross-tenant request to a disabled/mismatched server
// or a quarantined tool reports TENANT_MISMATCH, never the server/tool reason — so a
// cross-tenant caller never learns the foreign server's state (no foreign-tenant leak).
func TestTenantIsolation_DominatesServerAndToolOverrides(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*DecisionInput)
	}{
		{"foreign server disabled", func(in *DecisionInput) { in.Server.Enabled = false }},
		{"foreign server identity changed", func(in *DecisionInput) { in.Server.Verification = ServerIdentityMismatch }},
		{"foreign quarantined tool", func(in *DecisionInput) {
			in.Tool.Disposition = DispQuarantined
			in.Tool.Drift = DriftUnknownTool
		}},
		{"foreign privilege expansion", func(in *DecisionInput) { in.Tool.Drift = DriftPrivilegeExpansion }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := gwInput()
			in.Server.Owner = "tenant-b" // cross-tenant
			tc.mutate(&in)
			d, _ := eval(t, mustCompile(t, gwSnap(broadAllow)), in)
			assertTenantDenied(t, d)
		})
	}
}

// TestTenantIsolation_ManagementUnaffected proves Management inputs (which carry no
// Server) are never touched by Gateway tenant isolation.
func TestTenantIsolation_ManagementUnaffected(t *testing.T) {
	in := mgmtInput()
	if in.Server != nil {
		t.Fatal("management fixture must carry no server")
	}
	allow := `{"id":"M","priority":10,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"operation.method","op":"exact","value":"tools/list"}],"obligations":{"logging":"standard"}}`
	d, _ := eval(t, mustCompile(t, mgmtSnap(allow)), in)
	if d.Reason == ReasonTenantMismatch {
		t.Fatalf("management must not be denied by Gateway tenant isolation: %v/%v", d.Action, d.Reason)
	}
	if !d.Action.IsAllowClass() {
		t.Fatalf("management read must reach its ALLOW rule: %v/%v", d.Action, d.Reason)
	}
}

// assertTenantDenied asserts a decision is the exact QUAL-5 tenant-isolation hard
// override: DENY, TENANT_MISMATCH, HardOverride set, no matched user rule.
func assertTenantDenied(t *testing.T, d Decision) {
	t.Helper()
	if d.Action != ActionDeny {
		t.Fatalf("cross-tenant request must DENY: got %v", d.Action)
	}
	if d.Reason != ReasonTenantMismatch {
		t.Fatalf("cross-tenant reason = %v, want %v", d.Reason, ReasonTenantMismatch)
	}
	if !d.HardOverride {
		t.Fatal("tenant isolation must be a hard override")
	}
	if d.MatchedRule != "" {
		t.Fatalf("tenant isolation must not attribute a user rule: got %q", d.MatchedRule)
	}
}
