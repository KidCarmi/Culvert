package main

import (
	"strings"
	"testing"
)

func TestAuthExemptKillSwitchRows(t *testing.T) {
	if rows := authExemptKillSwitchRows(false, false, killSwitchBackendLive); len(rows) != 0 {
		t.Fatalf("clear switch must contribute nothing, got %+v", rows)
	}
	rt := authExemptKillSwitchRows(false, true, killSwitchBackendLive)
	if len(rt) != 1 || rt[0].Code != "auth_exempt_kill_switch" || rt[0].Status != diagWarn ||
		!strings.Contains(rt[0].Message, "ENGAGED") || !strings.Contains(rt[0].Message, "reverts on restart") ||
		strings.Contains(rt[0].OperatorAction, "CULVERT_AUTHBYPASS_DISABLE") {
		t.Fatalf("runtime-only: want warn, GUI-clearable, reverts-on-restart hint, got %+v", rt)
	}
	env := authExemptKillSwitchRows(true, false, killSwitchBackendLive)
	if len(env) != 1 || !strings.Contains(env[0].OperatorAction, "restart") {
		t.Fatalf("env layer must say restart is required, got %+v", env)
	}
	both := authExemptKillSwitchRows(true, true, killSwitchBackendLive)
	if len(both) != 1 || !strings.Contains(both[0].OperatorAction, "runtime toggle") || !strings.Contains(both[0].OperatorAction, "restart") {
		t.Fatalf("both layers must name both steps, got %+v", both)
	}
}

// Without a credential or SSO backend the engaged switch does not make formerly
// exempt clients authenticate (TestKillSwitchNoBackend_NoRule_InertStage2 pins
// the Stage-2 fall-through), so the row must not claim it does.
func TestAuthExemptKillSwitchRowsNoBackend(t *testing.T) {
	if rows := authExemptKillSwitchRows(false, false, killSwitchBackendNone); len(rows) != 0 {
		t.Fatalf("clear switch must contribute nothing without a backend, got %+v", rows)
	}
	for _, rows := range [][]OperatorContractCheck{
		authExemptKillSwitchRows(false, true, killSwitchBackendNone),
		authExemptKillSwitchRows(true, false, killSwitchBackendNone),
		authExemptKillSwitchRows(true, true, killSwitchBackendNone),
	} {
		if len(rows) != 1 || rows[0].Status != diagWarn || !strings.Contains(rows[0].Message, "ENGAGED") {
			t.Fatalf("engaged switch must warn without a backend, got %+v", rows)
		}
		if strings.Contains(rows[0].Message, "must now authenticate") {
			t.Fatalf("no-backend row must not claim clients now authenticate, got %q", rows[0].Message)
		}
		if !strings.Contains(rows[0].Message, "does not make formerly exempt clients authenticate") ||
			!strings.Contains(rows[0].Message, "remaining authentication rules and Stage 2 policy") {
			t.Fatalf("no-backend row must say the switch adds no authentication and who decides instead, got %q", rows[0].Message)
		}
		// Per-rule outcomes depend on the default, rule order and presented
		// headers; the row must not present a list of them as exhaustive.
		// The backend predicates are live: a configured profile that failed to
		// load is not usable, so the row must not claim nothing is configured.
		if strings.Contains(rows[0].Message, "backend is configured") || !strings.Contains(rows[0].Message, "SSO profile failed to load") {
			t.Fatalf("no-backend row must describe usable providers, not configured ones, got %q", rows[0].Message)
		}
		if strings.Contains(rows[0].Message, "407") || strings.Contains(rows[0].Message, "403") {
			t.Fatalf("no-backend row must not enumerate per-rule status codes, got %q", rows[0].Message)
		}
		if strings.Contains(rows[0].OperatorAction, "Policy Tester") {
			t.Fatalf("no-backend row must not point to the Policy Tester, which assumes a backend for Default: %q", rows[0].OperatorAction)
		}
	}
	withBackend := authExemptKillSwitchRows(false, true, killSwitchBackendLive)
	if !strings.Contains(withBackend[0].Message, "must now authenticate") {
		t.Fatalf("backend-present row must keep the authentication claim, got %q", withBackend[0].Message)
	}
}

func TestAuthExemptKillSwitchSurfacesInContract(t *testing.T) {
	prev := authExemptDisabledRuntimeState()
	t.Cleanup(func() { setAuthExemptDisabled(prev) })
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

// TestAuthExemptKillSwitchRowsCredentialProfileNotLoaded pins the third state:
// hasCredentialCapableProvider counts an enabled OIDC/LDAP profile that failed
// to compile, so the gate still challenges, but nothing loaded can validate.
func TestAuthExemptKillSwitchRowsCredentialProfileNotLoaded(t *testing.T) {
	rows := authExemptKillSwitchRows(false, true, killSwitchBackendNotLoaded)
	if len(rows) != 1 || rows[0].Status != diagWarn {
		t.Fatalf("want one warn row, got %+v", rows)
	}
	if strings.Contains(rows[0].Message, "must now authenticate") ||
		!strings.Contains(rows[0].Message, "no loaded provider can validate them") {
		t.Fatalf("not-loaded row must say challenged credentials cannot be validated, got %q", rows[0].Message)
	}
	if !strings.Contains(rows[0].OperatorAction, "Identity Providers") {
		t.Fatalf("not-loaded row must point at the failed profile, got %q", rows[0].OperatorAction)
	}
}
