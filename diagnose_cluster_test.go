package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDiagnoseCluster_Roles drives every role/health branch through the pure core
// so the verdict logic is pinned without touching (and racing) the HA/cluster
// singletons.
func TestDiagnoseCluster_Roles(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()

	cases := []struct {
		name       string
		in         clusterInputs
		wantRole   string
		wantOK     bool
		wantLease  bool // lease_valid/epoch present in output
		wantDetail bool // a non-empty advisory detail is expected
	}{
		{
			name:     "standalone",
			in:       clusterInputs{leaseMode: "none", writeAllowed: true},
			wantRole: "standalone", wantOK: true,
		},
		{
			name:     "data-plane always presence-ok",
			in:       clusterInputs{leaseMode: "none", writeAllowed: true, dpActive: true},
			wantRole: "data-plane", wantOK: true, wantDetail: true,
		},
		{
			name:     "control-plane all nodes connected",
			in:       clusterInputs{leaseMode: "none", writeAllowed: true, total: 3, connected: 3},
			wantRole: "control-plane", wantOK: true,
		},
		{
			name:     "control-plane degraded node",
			in:       clusterInputs{leaseMode: "none", writeAllowed: true, total: 3, connected: 2},
			wantRole: "control-plane", wantOK: false, wantDetail: true,
		},
		{
			name: "leader with valid lease + all nodes",
			in: clusterInputs{
				haStatus: HAStatus{Enabled: true, Role: "leader", Term: 7}, leaseMode: "lease",
				leaseValid: true, epoch: 42, writeAllowed: true, total: 2, connected: 2,
			},
			wantRole: "leader", wantOK: true, wantLease: true,
		},
		{
			name: "leader lost write authority",
			in: clusterInputs{
				haStatus: HAStatus{Enabled: true, Role: "leader"}, leaseMode: "lease",
				leaseValid: false, epoch: 0, writeAllowed: false, total: 1, connected: 1,
			},
			wantRole: "leader", wantOK: false, wantLease: true, wantDetail: true,
		},
		{
			name: "standby healthy sync",
			in: clusterInputs{
				haStatus:   HAStatus{Enabled: true, Role: "standby", SyncFailCount: 0, LastSyncOK: now.Format(time.RFC3339)},
				leaseMode:  "none",
				leaseValid: false,
			},
			wantRole: "standby", wantOK: true,
		},
		{
			name: "standby failing sync",
			in: clusterInputs{
				haStatus:  HAStatus{Enabled: true, Role: "standby", SyncFailCount: 4},
				leaseMode: "none",
			},
			wantRole: "standby", wantOK: false, wantDetail: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := diagnoseClusterFrom(tc.in, now)
			if d.Role != tc.wantRole {
				t.Fatalf("role=%q want %q", d.Role, tc.wantRole)
			}
			if d.OK != tc.wantOK {
				t.Fatalf("ok=%v want %v", d.OK, tc.wantOK)
			}
			if d.SchemaVersion != diagnoseSchemaVersion {
				t.Fatalf("schema_version=%d want %d", d.SchemaVersion, diagnoseSchemaVersion)
			}
			if tc.wantLease {
				if d.LeaseMode != "lease" {
					t.Fatalf("lease_mode=%q want lease", d.LeaseMode)
				}
				if d.Epoch != tc.in.epoch {
					t.Fatalf("epoch=%d want %d", d.Epoch, tc.in.epoch)
				}
			}
			if tc.wantDetail && d.Detail == "" {
				t.Fatal("expected a non-empty advisory detail")
			}
		})
	}
}

// TestDiagnoseCluster_NoSecrets proves the diagnosis never surfaces the
// peer/standby CP addresses even when the HA snapshot carries them — the verb is
// a health summary, not an infrastructure map.
func TestDiagnoseCluster_NoSecrets(t *testing.T) {
	in := clusterInputs{
		haStatus: HAStatus{
			Enabled: true, Role: "leader",
			PeerAddr: "10.9.9.9:6443", StandbyAddr: "10.8.8.8:6443",
		},
		leaseMode: "lease", leaseValid: true, epoch: 5, writeAllowed: true,
	}
	d := diagnoseClusterFrom(in, time.Unix(1_700_000_000, 0).UTC())
	// The typed struct has no field for peer/standby addresses, but assert on the
	// rendered detail too so a future edit that folds an address into Detail fails.
	if d.Detail == "10.9.9.9:6443" || d.Detail == "10.8.8.8:6443" {
		t.Fatal("diagnosis detail leaked a CP address")
	}
}

// TestDiagnoseCluster_Gates covers method + RBAC on the handler. It runs against
// the live singletons (default: standalone), so it asserts only the gate outcomes,
// not the body.
func TestDiagnoseCluster_Gates(t *testing.T) {
	// GET → 405.
	gRec := httptest.NewRecorder()
	gr := roleReq(RoleOperator, http.MethodGet, "/api/diagnose/cluster", nil)
	apiDiagnoseCluster(gRec, gr)
	if gRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET code=%d want 405", gRec.Code)
	}
	// Viewer < operator → 403.
	vRec := httptest.NewRecorder()
	apiDiagnoseCluster(vRec, roleReq(RoleViewer, http.MethodPost, "/api/diagnose/cluster", nil))
	if vRec.Code != http.StatusForbidden {
		t.Fatalf("viewer code=%d want 403", vRec.Code)
	}
	// Operator POST → 200 with a typed body.
	oRec := httptest.NewRecorder()
	apiDiagnoseCluster(oRec, roleReq(RoleOperator, http.MethodPost, "/api/diagnose/cluster", nil))
	if oRec.Code != http.StatusOK {
		t.Fatalf("operator code=%d want 200 (body=%q)", oRec.Code, oRec.Body.String())
	}
}
