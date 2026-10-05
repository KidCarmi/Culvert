package main

import (
	"strings"
	"testing"
)

func TestAuthExemptKillSwitchRows(t *testing.T) {
	if rows := authExemptKillSwitchRows(false, false); len(rows) != 0 {
		t.Fatalf("clear switch must contribute nothing, got %+v", rows)
	}
	rt := authExemptKillSwitchRows(false, true)
	if len(rt) != 1 || rt[0].Code != "auth_exempt_kill_switch" || rt[0].Status != diagWarn ||
		!strings.Contains(rt[0].Message, "ENGAGED") || strings.Contains(rt[0].OperatorAction, "restart") {
		t.Fatalf("runtime-only: want warn, GUI-clearable, got %+v", rt)
	}
	env := authExemptKillSwitchRows(true, false)
	if len(env) != 1 || !strings.Contains(env[0].OperatorAction, "restart") {
		t.Fatalf("env layer must say restart is required, got %+v", env)
	}
	both := authExemptKillSwitchRows(true, true)
	if len(both) != 1 || !strings.Contains(both[0].OperatorAction, "runtime toggle") || !strings.Contains(both[0].OperatorAction, "restart") {
		t.Fatalf("both layers must name both steps, got %+v", both)
	}
}

func TestAuthExemptKillSwitchSurfacesInContract(t *testing.T) {
	t.Cleanup(func() { setAuthExemptDisabled(false) })
	setAuthExemptDisabled(true)
	found := false
	for _, c := range buildOperatorContract().Checks {
		if c.Code == "auth_exempt_kill_switch" {
			found = true
		}
	}
	if !found {
		t.Fatal("engaged kill switch must appear on the operator contract")
	}
}
