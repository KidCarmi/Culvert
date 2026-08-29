package policy

import "testing"

// ADR-0034 anti-weakening: tool TRUST (catalog Usable) is not invocation
// AUTHORIZATION. A tool becoming Usable merely SURVIVES to the default-deny
// matchRules step (DispUsable trips no override band); it must never weaken a
// matching DENY / REQUIRE_APPROVAL / REQUIRE_CONFIRMATION, nor turn a no-match into
// anything but the default deny. gwInput() is already a Usable, no-material-change
// tool, so these subtests pin the exact promotion-does-not-weaken invariant.
//
// If a future refactor made DispUsable confer any allow-band effect, each assertion
// below fails.

func TestAW_TT_UsablePlusDenyStaysDeny(t *testing.T) {
	in := gwInput()
	if in.Tool.Disposition != DispUsable || in.Tool.Drift != DriftNoMaterialChange {
		t.Fatal("fixture must be a usable, no-material-change tool")
	}
	deny := `{"id":"D","priority":1,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[]}`
	d, _ := eval(t, mustCompile(t, gwSnap(deny)), in)
	if d.Action != ActionDeny {
		t.Fatalf("usable + DENY must stay DENY, got %v", d.Action)
	}
}

func TestAW_TT_UsablePlusRequireApprovalStaysApproval(t *testing.T) {
	in := gwInput()
	rule := `{"id":"A","priority":1,"action":"REQUIRE_APPROVAL","reason":"MCP.POLICY.APPROVAL_REQUIRED","remediation":"request_approval","conditions":[],"obligations":{"approval":true}}`
	d, _ := eval(t, mustCompile(t, gwSnap(rule)), in)
	if d.Action != ActionRequireApproval {
		t.Fatalf("usable + REQUIRE_APPROVAL must stay REQUIRE_APPROVAL, got %v", d.Action)
	}
}

func TestAW_TT_UsablePlusRequireConfirmationStaysConfirmation(t *testing.T) {
	in := gwInput()
	rule := `{"id":"C","priority":1,"action":"REQUIRE_CONFIRMATION","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"request_confirmation","conditions":[],"obligations":{"confirmation":true}}`
	d, _ := eval(t, mustCompile(t, gwSnap(rule)), in)
	if d.Action != ActionRequireConfirmation {
		t.Fatalf("usable + REQUIRE_CONFIRMATION must stay REQUIRE_CONFIRMATION, got %v", d.Action)
	}
}

func TestAW_TT_UsablePlusNoRuleDefaultDenies(t *testing.T) {
	in := gwInput()
	d, _ := eval(t, mustCompile(t, gwSnap("")), in)
	if d.Action != ActionDeny || d.Reason != ReasonNoMatchDefaultDeny {
		t.Fatalf("usable + no rule must default-deny, got %v/%v", d.Action, d.Reason)
	}
	if d.IsAllowClass() {
		t.Fatal("a usable tool must never be allow-class by trust alone")
	}
}
