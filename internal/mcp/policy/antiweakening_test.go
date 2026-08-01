package policy

import "testing"

// The anti-weakening suite pins each security invariant of the engine against a
// concrete weakening a future refactor might introduce. Each subtest asserts the
// SECURE behavior; if someone weakens the engine to make the "mutant" pass, the
// corresponding assertion fails. These are behavioral tripwires, not mutation
// tooling — they name the exact property that must never regress.

// M1: default posture is DENY. An empty snapshot must never permit.
func TestAW_EmptySnapshotDefaultDenies(t *testing.T) {
	d, _ := eval(t, mustCompile(t, gwSnap("")), gwInput())
	if d.Action != ActionDeny || d.Reason != ReasonNoMatchDefaultDeny {
		t.Fatalf("empty snapshot must default-deny, got %v/%v", d.Action, d.Reason)
	}
}

// M2: the zero-value Action must fail closed (never an accidental permit).
func TestAW_ZeroActionFailsClosed(t *testing.T) {
	if ActionInvalid.IsAllowClass() || ActionInvalid.Valid() {
		t.Fatal("the zero action must be invalid and non-permitting")
	}
	if ActionInvalid.Effect() != EffectDenied {
		t.Fatalf("zero action effect must be denied, got %v", ActionInvalid.Effect())
	}
}

// M3: an unknown tool is QUARANTINE even under a broad ALLOW (no first-match
// laundering — the override runs before rules).
func TestAW_UnknownToolNotLaunderedByBroadAllow(t *testing.T) {
	in := gwInput()
	in.Tool.Drift = DriftUnknownTool
	in.Tool.Disposition = DispQuarantined
	broad := `{"id":"B","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`
	d, _ := eval(t, mustCompile(t, gwSnap(broad)), in)
	if d.Action != ActionQuarantine || !d.HardOverride {
		t.Fatalf("unknown tool must quarantine via override, got %v override=%v", d.Action, d.HardOverride)
	}
}

// M4: privilege expansion is QUARANTINE even under a broad ALLOW.
func TestAW_PrivilegeExpansionNotLaundered(t *testing.T) {
	in := gwInput()
	in.Tool.Drift = DriftPrivilegeExpansion
	broad := `{"id":"B","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`
	d, _ := eval(t, mustCompile(t, gwSnap(broad)), in)
	if d.Action != ActionQuarantine || d.Reason != ReasonToolPrivilegeExpansion {
		t.Fatalf("privilege expansion must quarantine, got %v/%v", d.Action, d.Reason)
	}
}

// M5: a destructive operation is NEVER implicitly allowed. A plain ALLOW rule on a
// destructive op is downgraded to REQUIRE_APPROVAL.
func TestAW_DestructiveNeverImplicitlyAllowed(t *testing.T) {
	in := gwInput()
	in.Operation.Class = OpDestructive
	in.Tool.Reversibility = Irreversible
	broad := `{"id":"B","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`
	d, _ := eval(t, mustCompile(t, gwSnap(broad)), in)
	if d.Action != ActionRequireApproval {
		t.Fatalf("destructive op under plain ALLOW must require approval, got %v", d.Action)
	}
}

// M6: a destructive op is only allowed by a rule that explicitly opts in with
// allow_destructive (bounded + audited), and the resulting action is ALLOW_ONCE.
func TestAW_DestructiveAllowedOnlyWithExplicitOptIn(t *testing.T) {
	in := gwInput()
	in.Operation.Class = OpDestructive
	rule := `{"id":"D","priority":1,"action":"ALLOW_ONCE","allow_destructive":true,"reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"once_call":true,"logging":"audit"}}`
	d, _ := eval(t, mustCompile(t, gwSnap(rule)), in)
	if d.Action != ActionAllowOnce {
		t.Fatalf("destructive op with explicit opt-in must allow-once, got %v", d.Action)
	}
}

// M7: a server-identity change fails closed even when a broad ALLOW matches.
func TestAW_ServerIdentityChangeFailsClosed(t *testing.T) {
	in := gwInput()
	in.Server.Verification = ServerIdentityMismatch
	broad := `{"id":"B","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`
	d, _ := eval(t, mustCompile(t, gwSnap(broad)), in)
	if d.Action != ActionDeny || d.Reason != ReasonServerIdentityChanged {
		t.Fatalf("server identity change must deny, got %v/%v", d.Action, d.Reason)
	}
}

// M8: a disabled server fails closed even under a broad ALLOW.
func TestAW_DisabledServerFailsClosed(t *testing.T) {
	in := gwInput()
	in.Server.Enabled = false
	broad := `{"id":"B","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`
	d, _ := eval(t, mustCompile(t, gwSnap(broad)), in)
	if d.Action != ActionDeny || d.Reason != ReasonServerDisabled {
		t.Fatalf("disabled server must deny, got %v/%v", d.Action, d.Reason)
	}
}

// M9: a cross-tenant resource reference fails closed regardless of matching rules.
func TestAW_CrossTenantFailsClosed(t *testing.T) {
	in := gwInput()
	in.Resource = &Resource{Type: "repo", ID: "r1", Tenant: "tenant-b"}
	broad := `{"id":"B","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`
	d, _ := eval(t, mustCompile(t, gwSnap(broad)), in)
	if d.Action != ActionDeny || d.Reason != ReasonTenantMismatch {
		t.Fatalf("cross-tenant must deny, got %v/%v", d.Action, d.Reason)
	}
}

// M10: ambiguous identity on a write is denied (MCP-ID-005), not silently allowed.
func TestAW_AmbiguousIdentityOnWriteDenied(t *testing.T) {
	in := gwInput()
	in.Operation.Class = OpWrite
	in.Principal.Assurance = AssuranceUnknown
	broad := `{"id":"B","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`
	d, _ := eval(t, mustCompile(t, gwSnap(broad)), in)
	if d.Action != ActionDeny || d.Reason != ReasonIdentityAmbiguous {
		t.Fatalf("ambiguous identity on write must deny, got %v/%v", d.Action, d.Reason)
	}
}

// M11: Management may never permit a mutation class (write/destructive/control).
func TestAW_ManagementMutationHardDenied(t *testing.T) {
	for _, cls := range []OperationClass{OpWrite, OpDestructive, OpControl} {
		in := mgmtInput()
		in.Operation.Class = cls
		// A broad ALLOW must not rescue it.
		rule := `{"id":"M","priority":1,"action":"ALLOW","reason":"MCP.MANAGEMENT.TENANT_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`
		d, _ := eval(t, mustCompile(t, mgmtSnap(rule)), in)
		if d.Action != ActionDeny || d.Reason != ReasonManagementMutationNotApproved {
			t.Fatalf("management %v must hard-deny, got %v/%v", cls, d.Action, d.Reason)
		}
	}
}

// M12: Management V1 cannot compile an ALLOW-once/monitor/quarantine rule (the
// action namespace is limited to {ALLOW, DENY, REQUIRE_APPROVAL}).
func TestAW_ManagementActionNamespaceLimited(t *testing.T) {
	for _, a := range []string{"MONITOR", "QUARANTINE", "ALLOW_ONCE", "ALLOW_FOR_SESSION", "ALLOW_WITH_REDACTION", "REQUIRE_CONFIRMATION"} {
		rule := `{"id":"M","priority":1,"action":"` + a + `","reason":"MCP.MANAGEMENT.TENANT_SCOPE","remediation":"none","conditions":[]}`
		if _, err := Compile([]byte(mgmtSnap(rule)), CreatedMeta{}, DefaultLimits()); err == nil {
			t.Fatalf("management action %s must not compile", a)
		}
	}
}

// M13: a Management rule may never select a Gateway credential profile.
func TestAW_ManagementCannotSelectGatewayCredential(t *testing.T) {
	rule := `{"id":"M","priority":1,"action":"ALLOW","reason":"MCP.MANAGEMENT.TENANT_SCOPE","remediation":"none","conditions":[],"obligations":{"credential_profile":"p","logging":"standard"}}`
	if _, err := Compile([]byte(mgmtSnap(rule)), CreatedMeta{}, DefaultLimits()); err == nil {
		t.Fatal("management rule selecting a gateway credential must not compile")
	}
}

// M14: a structurally invalid input yields INVALID_INPUT, NOT a no-match default
// deny — the two must stay distinguishable and both must fail closed.
func TestAW_InvalidInputDistinctFromDefaultDeny(t *testing.T) {
	snap := mustCompile(t, gwSnap(""))
	in := gwInput()
	in.Operation.Method = "" // structurally invalid
	e := NewEngine(DefaultLimits())
	d, _, err := e.Evaluate(snap, &in)
	if err == nil {
		t.Fatal("invalid input must return an error")
	}
	if d.Reason == ReasonNoMatchDefaultDeny {
		t.Fatal("invalid input must not masquerade as a no-match default deny")
	}
	if d.IsAllowClass() {
		t.Fatal("invalid input must fail closed")
	}
}

// M15: a missing snapshot fails closed with the exact SNAPSHOT_UNAVAILABLE reason
// (never permissive, never a silent skip).
func TestAW_MissingSnapshotFailsClosed(t *testing.T) {
	in := gwInput()
	e := NewEngine(DefaultLimits())
	d, _, err := e.Evaluate(nil, &in)
	if err == nil || d.Action != ActionDeny || d.Reason != ReasonSnapshotUnavailable {
		t.Fatalf("missing snapshot must fail closed with SNAPSHOT_UNAVAILABLE, got %v/%v err=%v", d.Action, d.Reason, err)
	}
}

// M16: a disabled rule is skipped — it cannot match and cannot permit.
func TestAW_DisabledRuleCannotMatch(t *testing.T) {
	rule := `{"id":"OFF","priority":1,"enabled":false,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`
	d, _ := eval(t, mustCompile(t, gwSnap(rule)), gwInput())
	if d.IsAllowClass() {
		t.Fatalf("a disabled rule must never permit, got %v", d.Action)
	}
}

// M17: an expired rule is skipped (the expiry check uses the input's EvalTime, not
// a wall clock).
func TestAW_ExpiredRuleSkipped(t *testing.T) {
	// expiry_unix strictly before the fixed testTime() (unix 1_700_000_000).
	rule := `{"id":"EXP","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","expiry_unix":1000,"conditions":[],"obligations":{"logging":"standard"}}`
	d, _ := eval(t, mustCompile(t, gwSnap(rule)), gwInput())
	if d.IsAllowClass() {
		t.Fatalf("an expired rule must never permit, got %v", d.Action)
	}
}
