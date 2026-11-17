package main

import (
	"strings"
	"testing"
)

func TestCheckAdminRouteEnforcement(t *testing.T) {
	withC2Mode(t, c2ModeEnforce)
	if got := checkAdminRouteEnforcement(); len(got) != 0 {
		t.Fatalf("enforce: want no rows, got %+v", got)
	}

	withC2Mode(t, c2ModeShadow)
	got := checkAdminRouteEnforcement()
	if len(got) != 1 {
		t.Fatalf("shadow: want 1 row, got %d", len(got))
	}
	c := got[0]
	if c.Code != adminRouteEnforcementCode || c.Status != diagWarn {
		t.Fatalf("shadow: unexpected row %+v", c)
	}
	// The row must not claim authorization is off: handler checks still apply.
	if !strings.Contains(c.Message, "handler's own role check still applies") {
		t.Errorf("message must state the handler-level backstop, got %q", c.Message)
	}
	if !strings.Contains(c.OperatorAction, c2EnforceEnvVar) || !strings.Contains(c.OperatorAction, "restart") {
		t.Errorf("remediation must name %s and the restart, got %q", c2EnforceEnvVar, c.OperatorAction)
	}
}

func TestOperatorContract_AdminRouteEnforcementRowOnlyInShadow(t *testing.T) {
	resetDiagVerdictGlobals(t)

	withC2Mode(t, c2ModeShadow)
	contract := buildOperatorContract()
	c := findDiagnosticCheck(contract, adminRouteEnforcementCode)
	if c == nil {
		t.Fatal("admin_route_enforcement_shadow row missing from operator contract in shadow mode")
	}
	if c.Status != diagWarn {
		t.Fatalf("want warn, got %+v", *c)
	}
	// Viewer-readable unchanged: the row carries no roster posture, so the
	// below-admin rendering must pass it through verbatim.
	red := redactContractForRole(contract, false)
	if v := findDiagnosticCheck(red, adminRouteEnforcementCode); v == nil || v.Message != c.Message {
		t.Fatalf("below-admin rendering changed the row: %+v", v)
	}

	withC2Mode(t, c2ModeEnforce)
	if c := findDiagnosticCheck(buildOperatorContract(), adminRouteEnforcementCode); c != nil {
		t.Fatalf("enforce mode must not add a row, got %+v", *c)
	}
}
