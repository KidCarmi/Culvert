package policy

import "testing"

func TestSmoke_DefaultDeny(t *testing.T) {
	snap := mustCompile(t, gwSnap(""))
	d, _ := eval(t, snap, gwInput())
	if d.Action != ActionDeny || d.Reason != ReasonNoMatchDefaultDeny {
		t.Fatalf("empty snapshot: action=%v reason=%v, want DENY/NO_MATCH", d.Action, d.Reason)
	}
	if d.MatchedRule != "" {
		t.Fatalf("default deny stamped a matched rule: %q", d.MatchedRule)
	}
	if d.PolicyRevision != 1 || d.CatalogRevision != 7 {
		t.Fatalf("missing revision context: %+v", d)
	}
}

func TestSmoke_ExactAllow(t *testing.T) {
	rule := `{"id":"R1","priority":10,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none",
		"conditions":[
			{"field":"operation.method","op":"exact","value":"tools/call"},
			{"field":"tool.name","op":"exact","value":"read_file"},
			{"field":"principal.groups","op":"contains","value":"developers"}
		],"obligations":{"logging":"standard"}}`
	snap := mustCompile(t, gwSnap(rule))
	d, tr := eval(t, snap, gwInput())
	if d.Action != ActionAllow {
		t.Fatalf("action = %v, want ALLOW", d.Action)
	}
	if d.MatchedRule != "R1" {
		t.Fatalf("matched rule = %q, want R1", d.MatchedRule)
	}
	if !d.IsAllowClass() {
		t.Fatal("ALLOW should be allow-class")
	}
	if tr.Winner != "R1" {
		t.Fatalf("trace winner = %q", tr.Winner)
	}
}

func TestSmoke_UnknownToolQuarantine(t *testing.T) {
	in := gwInput()
	in.Tool.Drift = DriftUnknownTool
	in.Tool.Disposition = DispQuarantined
	// Even a broad ALLOW rule must not override the hard quarantine.
	rule := `{"id":"BROAD","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`
	snap := mustCompile(t, gwSnap(rule))
	d, _ := eval(t, snap, in)
	if d.Action != ActionQuarantine || d.Reason != ReasonToolUnknown {
		t.Fatalf("unknown tool: action=%v reason=%v, want QUARANTINE/TOOL.UNKNOWN", d.Action, d.Reason)
	}
	if !d.HardOverride {
		t.Fatal("unknown-tool quarantine must be a hard override")
	}
}

func TestSmoke_PrivilegeExpansionQuarantine(t *testing.T) {
	in := gwInput()
	in.Tool.Drift = DriftPrivilegeExpansion
	rule := `{"id":"BROAD","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`
	snap := mustCompile(t, gwSnap(rule))
	d, _ := eval(t, snap, in)
	if d.Action != ActionQuarantine || d.Reason != ReasonToolPrivilegeExpansion {
		t.Fatalf("priv expansion: action=%v reason=%v", d.Action, d.Reason)
	}
}

func TestSmoke_ManagementMutationHardDeny(t *testing.T) {
	in := mgmtInput()
	in.Operation = Operation{Method: "tools/call", Class: OpWrite, Namespace: NamespaceManagementOperation, Operand: "apply"}
	// A permissive Management ALLOW rule must not override the V1 mutation boundary.
	rule := `{"id":"M1","priority":1,"action":"ALLOW","reason":"MCP.MANAGEMENT.TENANT_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`
	snap := mustCompile(t, mgmtSnap(rule))
	d, _ := eval(t, snap, in)
	if d.Action != ActionDeny || d.Reason != ReasonManagementMutationNotApproved {
		t.Fatalf("mgmt mutation: action=%v reason=%v", d.Action, d.Reason)
	}
}

func TestSmoke_DestructiveNotImplicitlyAllowed(t *testing.T) {
	in := gwInput()
	in.Operation.Class = OpDestructive
	in.Tool.Reversibility = Irreversible
	// A broad ALLOW (not authorized for destructive) must not permit a destructive op.
	rule := `{"id":"BROAD","priority":10,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"operation.method","op":"exact","value":"tools/call"}],"obligations":{"logging":"standard"}}`
	snap := mustCompile(t, gwSnap(rule))
	d, _ := eval(t, snap, in)
	if d.Action != ActionRequireApproval {
		t.Fatalf("destructive via broad ALLOW: action=%v, want REQUIRE_APPROVAL", d.Action)
	}
}

func TestSmoke_NamespaceMismatchFailsCompile(t *testing.T) {
	// A Gateway-only field on a Management rule still compiles (fields are shared),
	// but a mixed capability at the snapshot level is impossible: the snapshot has
	// exactly one capability. Cross-capability is proven by evaluating a Gateway
	// input against a Management snapshot.
	snap := mustCompile(t, mgmtSnap(""))
	in := gwInput()
	e := NewEngine(DefaultLimits())
	d, _, err := e.Evaluate(snap, &in)
	if err == nil || d.Action != ActionDeny || d.Reason != ReasonCapabilityMismatch {
		t.Fatalf("cross-capability eval: action=%v reason=%v err=%v", d.Action, d.Reason, err)
	}
}

func TestSmoke_ManagementRejectsNonLegalAction(t *testing.T) {
	rule := `{"id":"M1","priority":1,"action":"ALLOW_ONCE","reason":"MCP.MANAGEMENT.TENANT_SCOPE","remediation":"none","conditions":[],"obligations":{"once_call":true}}`
	if _, err := Compile([]byte(mgmtSnap(rule)), CreatedMeta{}, DefaultLimits()); err == nil {
		t.Fatal("Management ALLOW_ONCE rule should fail compilation (not a V1-legal action)")
	}
}
