package main

// auth_killswitch_diag_role_redaction_test.go — SEC-KSROSTER-1, Codex P1 on
// PR #1765.
//
// The roster-without-verifier rendering of the auth_exempt_kill_switch row
// states that the administrator roster holds accounts but no usable
// administrator, and that those accounts' effective role is not administrator.
// That is admin-roster posture (SEC-DIAG-ROSTER-1), and the operator contract
// is served at RoleVIEWER by GET /api/diagnostics and GET /api/health/explain.
// The state is reached by loadedRosterRole's restore clamp, which leaves the
// restored accounts signing in as viewers — so without redaction they read
// their own roster's admin posture off the contract.
//
// Least privilege as for the other classified rows: below admin the row keeps
// its code, its WARN status, the engaged layer and the traffic impact (an
// operator must still see that formerly exempt clients are refused, and
// escalate), and loses the cause and the remediation.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// killSwitchRowAt drives the real handler at role and returns the
// auth_exempt_kill_switch row and the verdict.
func killSwitchRowAt(t *testing.T, h http.HandlerFunc, path string, role UIRole) (row OperatorContractCheck, verdict string) {
	t.Helper()
	r := roleCtx(httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, http.NoBody), role)
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("%s role %q: status = %d, want 200", path, role, w.Code)
	}
	c := decodeContract(t, w)
	found := findDiagnosticCheck(c, authExemptKillSwitchCode)
	if found == nil {
		t.Fatalf("%s role %q: %s row missing from the contract", path, role, authExemptKillSwitchCode)
	}
	return *found, c.Verdict
}

// killSwitchAdminOnlyDetail is every fragment of the no-verifier admin row
// that describes roster posture or its remediation.
var killSwitchAdminOnlyDetail = []string{
	"administrator roster",
	"no usable administrator",
	"effective role",
	"pre-RBAC",
	"restored backup",
	"--reset-password",
	"requires authentication",
	"nothing on this node can verify",
}

// TestKillSwitchRow_NoVerifierDetailIsAdminOnly is the disclosure control on
// both renderers, for the clamp route (the one that produces viewer logins).
func TestKillSwitchRow_NoVerifierDetailIsAdminOnly(t *testing.T) {
	setupProxyTest(t)
	if roleEnrolled(UIRole("superadmin")) {
		t.Fatal("premise broken: this build enrolls 'superadmin'; pick another unenrolled role to provoke the clamp")
	}
	c := loadRoster(t, rosterWithRole(t, UIRole("superadmin")))
	if c.uiUsers["alice"].role != RoleViewer {
		t.Fatalf("premise broken: want the clamp to leave RoleViewer, got %q", c.uiUsers["alice"].role)
	}
	killSwitchProbeEnv(t) // runtime toggle engaged
	if got := currentKillSwitchBackend(); got != killSwitchBackendNoVerifier {
		t.Fatalf("premise broken: want killSwitchBackendNoVerifier, got %d", got)
	}

	for _, ep := range []struct {
		path string
		h    http.HandlerFunc
	}{{"/api/diagnostics", apiDiagnostics}, {"/api/health/explain", apiHealthExplain}} {
		admin, adminVerdict := killSwitchRowAt(t, ep.h, ep.path, RoleAdmin)
		// Positive control: the admin keeps every fact the row exists for.
		for _, want := range []string{"no usable administrator", "--reset-password", "Clearing the kill switch alone restores"} {
			if !strings.Contains(admin.Message+" "+admin.OperatorAction, want) {
				t.Errorf("%s admin row lost %q; row = %q / %q", ep.path, want, admin.Message, admin.OperatorAction)
			}
		}
		for _, role := range []UIRole{RoleViewer, RoleOperator} {
			row, verdict := killSwitchRowAt(t, ep.h, ep.path, role)
			assertKillSwitchRowRedacted(t, ep.path, role, row)
			if verdict != adminVerdict {
				t.Errorf("%s role %q: verdict %q differs from admin %q; the row's status is warn in both renderings",
					ep.path, role, verdict, adminVerdict)
			}
		}
	}
}

// assertKillSwitchRowRedacted checks one below-admin no-verifier row: the
// condition, the layer and the traffic impact stay; the roster posture goes.
func assertKillSwitchRowRedacted(t *testing.T, path string, role UIRole, row OperatorContractCheck) {
	t.Helper()
	if row.Status != diagWarn {
		t.Errorf("%s role %q: status = %q, want warn (the condition must stay visible)", path, role, row.Status)
	}
	detail := row.Message + " " + row.OperatorAction
	for _, leaked := range killSwitchAdminOnlyDetail {
		if strings.Contains(detail, leaked) {
			t.Errorf("%s role %q: kill-switch row discloses %q below admin; row = %q / %q",
				path, role, leaked, row.Message, row.OperatorAction)
		}
	}
	for _, want := range []string{"ENGAGED", "runtime toggle", "refused"} {
		if !strings.Contains(row.Message, want) {
			t.Errorf("%s role %q: redacted row lost viewer-safe %q; message = %q", path, role, want, row.Message)
		}
	}
	if row.OperatorAction != diagnosticsRedactedAction {
		t.Errorf("%s role %q: operator_action = %q, want the shared redacted action", path, role, row.OperatorAction)
	}
}

// TestKillSwitchRow_ViewerSafeStatesAreNotRedacted is the over-redaction
// control: the other backend states carry only provider facts and the switch
// layer, so every role receives the admin rendering verbatim.
func TestKillSwitchRow_ViewerSafeStatesAreNotRedacted(t *testing.T) {
	for _, backend := range []killSwitchBackend{killSwitchBackendNone, killSwitchBackendNotLoaded, killSwitchBackendLive} {
		admin := authExemptKillSwitchRow(true, true, backend)
		viewer := authExemptKillSwitchViewerRow(true, true, backend)
		if viewer != admin {
			t.Errorf("backend %d: viewer rendering differs from the admin row: %+v vs %+v", backend, viewer, admin)
		}
	}
	// End to end, on a fresh no-account gateway.
	setupProxyTest(t)
	killSwitchProbeEnv(t)
	admin, _ := killSwitchRowAt(t, apiDiagnostics, "/api/diagnostics", RoleAdmin)
	viewer, _ := killSwitchRowAt(t, apiDiagnostics, "/api/diagnostics", RoleViewer)
	if viewer != admin {
		t.Errorf("no-backend row must reach a viewer unchanged: viewer %+v, admin %+v", viewer, admin)
	}
}

// TestKillSwitchRow_HandAssembledContractFailsClosed pins the redactor's
// fallback: a contract that carries the row but not its viewer rendering must
// not fall through to the admin text.
func TestKillSwitchRow_HandAssembledContractFailsClosed(t *testing.T) {
	full := authExemptKillSwitchRow(false, true, killSwitchBackendNoVerifier)
	c := OperatorContract{Verdict: diagWarn, Checks: []OperatorContractCheck{full}}
	got := redactContractForRole(c, false).Checks[0]
	if got.Code != authExemptKillSwitchCode || got.Status != diagWarn {
		t.Fatalf("fallback must keep code and status, got %+v", got)
	}
	for _, leaked := range killSwitchAdminOnlyDetail {
		if strings.Contains(got.Message+" "+got.OperatorAction, leaked) {
			t.Errorf("fallback discloses %q: %+v", leaked, got)
		}
	}
	if c.Checks[0] != full {
		t.Error("redaction mutated the caller's contract in place")
	}
	if redactContractForRole(c, true).Checks[0] != full {
		t.Error("an admin must receive the row unredacted")
	}
}
