package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// SEC-HATOKEN-1 — the HA join token must not reach a non-admin role.
//
// GET /api/cluster/ha is gated at RoleViewer (by design — the HA panel is a
// read-only dashboard) and unconditionally included deploy_cmd on a leader.
// deploy_cmd embeds the live `--ha-token`, and that token is the SOLE
// credential for the HASync RPC: controlplane_server.go gates it on
// VerifyToken alone, and the CP listener uses tls.VerifyClientCertIfGiven so no
// client certificate is required. HASync answers with the exported cluster
// state, the whole published ConfigSnapshot, and the cluster CA PRIVATE KEY
// wrapped under PBKDF2 of that same token. So a read-only viewer could obtain
// the cluster CA key and mint node certificates the Control Plane trusts.

const haProbeToken = "SEC-HATOKEN-1-PROBE-TOKEN"

// haLeaderWithToken installs a leader HAState carrying a recognizable token.
func haLeaderWithToken(t *testing.T) {
	t.Helper()
	prev := globalHA
	t.Cleanup(func() { globalHA = prev })
	globalHA = &HAState{
		role:         "leader",
		token:        haProbeToken,
		peerAddr:     "cp2.internal:50051",
		since:        time.Now(),
		autoFailover: false,
	}
}

// getClusterHAAs drives GET /api/cluster/ha with role injected the way
// uiAuthMiddleware injects it.
func getClusterHAAs(t *testing.T, role UIRole) (int, string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/cluster/ha", http.NoBody)
	r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, role))
	rec := httptest.NewRecorder()
	apiClusterHA(rec, r)
	return rec.Code, rec.Body.String()
}

// TestSECHATOKEN1_NonAdminRolesNeverSeeTheJoinToken is the DEFECT GATE.
// Pre-fix both viewer and operator received deploy_cmd with the live token.
func TestSECHATOKEN1_NonAdminRolesNeverSeeTheJoinToken(t *testing.T) {
	haLeaderWithToken(t)
	for _, role := range []UIRole{RoleViewer, RoleOperator} {
		t.Run(string(role), func(t *testing.T) {
			code, body := getClusterHAAs(t, role)
			if code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (the panel must stay readable); body=%s", code, body)
			}
			if strings.Contains(body, haProbeToken) {
				t.Errorf("DEFECT: role %q obtained the live HA join token.\nbody=%s", role, body)
			}
			if strings.Contains(body, "--ha-token") {
				t.Errorf("DEFECT: role %q obtained the deploy command (it embeds --ha-token).\nbody=%s", role, body)
			}
			var resp map[string]any
			if err := json.Unmarshal([]byte(body), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if _, present := resp["deploy_cmd"]; present {
				t.Errorf("DEFECT: deploy_cmd present for role %q", role)
			}
			// Not-vacuous: the panel's own status fields must still be served,
			// so the fix is a field-level narrowing and not a 403.
			if resp["role"] != "leader" || resp["enabled"] != true {
				t.Errorf("role %q lost the HA status fields — the fix removed the panel instead of the field: %v", role, resp)
			}
		})
	}
}

// TestSECHATOKEN1_AdminStillReceivesTheDeployCommand is the positive control.
// Without it the gate above would be satisfied by deleting the feature.
func TestSECHATOKEN1_AdminStillReceivesTheDeployCommand(t *testing.T) {
	haLeaderWithToken(t)
	code, body := getClusterHAAs(t, RoleAdmin)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", code, body)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	cmd, _ := resp["deploy_cmd"].(string)
	if cmd == "" {
		t.Fatal("admin lost deploy_cmd — the fix over-narrowed")
	}
	if !strings.Contains(cmd, "--ha-token "+haProbeToken) {
		t.Errorf("admin deploy_cmd does not carry the join token: %q", cmd)
	}
}

// TestSECHATOKEN1_UnenrolledRoleSeesNoToken covers the fail-closed direction of
// the role lattice: HasRole is false for any value this build does not enroll,
// so a session carrying a role from a newer build cannot reach the token.
func TestSECHATOKEN1_UnenrolledRoleSeesNoToken(t *testing.T) {
	haLeaderWithToken(t)
	for _, role := range []UIRole{"", "superuser", "Admin", "ADMIN", "root", "owner"} {
		code, body := getClusterHAAs(t, role)
		if code == http.StatusOK && strings.Contains(body, haProbeToken) {
			t.Errorf("DEFECT: unenrolled role %q obtained the HA join token", role)
		}
	}
}

// TestSECHATOKEN1_StandbyAndDisabledEmitNoToken pins the surrounding
// conditions, so a future edit cannot reintroduce the field by relaxing them.
func TestSECHATOKEN1_StandbyAndDisabledEmitNoToken(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state *HAState
	}{
		{"standby", &HAState{role: "standby", token: haProbeToken, since: time.Now()}},
		{"disabled", &HAState{token: haProbeToken}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prev := globalHA
			t.Cleanup(func() { globalHA = prev })
			globalHA = tc.state
			for _, role := range []UIRole{RoleViewer, RoleOperator, RoleAdmin} {
				_, body := getClusterHAAs(t, role)
				if strings.Contains(body, haProbeToken) {
					t.Errorf("%s: role %q obtained the HA join token", tc.name, role)
				}
			}
		})
	}
}
