package main

import "testing"

func TestAuthExemptKillSwitchDiagnostics(t *testing.T) {
	t.Cleanup(func() { setAuthExemptDisabled(false) })

	setAuthExemptDisabled(false)
	if authBypassDisabled() {
		t.Skip("env kill switch set in test environment")
	}
	if got := authExemptKillSwitchDiagnostics(); len(got) != 0 {
		t.Fatalf("released switch must add no row, got %+v", got)
	}

	setAuthExemptDisabled(true)
	got := authExemptKillSwitchDiagnostics()
	if len(got) != 1 || got[0].Code != "auth_exempt_kill_switch_engaged" || got[0].Status != diagWarn {
		t.Fatalf("engaged switch must emit one WARN row, got %+v", got)
	}
	if got[0].OperatorAction == "" {
		t.Fatal("row must carry an operator action")
	}

	found := false
	for _, c := range buildOperatorContract().Checks {
		if c.Code == "auth_exempt_kill_switch_engaged" {
			found = true
		}
	}
	if !found {
		t.Fatal("operator contract must include the engaged kill-switch row")
	}
}
