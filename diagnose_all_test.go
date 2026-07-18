package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDiagnoseAll_Aggregates proves the aggregate embeds every no-input local verb
// and that OK is the AND of the members.
func TestDiagnoseAll_Aggregates(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	d := diagnoseAll(time.Unix(1_700_000_000, 0).UTC())
	if d.SchemaVersion != diagnoseSchemaVersion {
		t.Fatalf("schema_version=%d want %d", d.SchemaVersion, diagnoseSchemaVersion)
	}
	// Each member must be populated (non-empty generated_at from its own builder).
	if d.Storage.GeneratedAt == "" || d.Upstream.GeneratedAt == "" ||
		d.Cluster.GeneratedAt == "" || d.Config.GeneratedAt == "" {
		t.Fatalf("a member diagnosis was not populated: %+v", d)
	}
	// OK is the conjunction of the members.
	want := d.Storage.OK && d.Upstream.OK && d.Cluster.OK && d.Config.OK
	if d.OK != want {
		t.Fatalf("aggregate ok=%v want %v (AND of members)", d.OK, want)
	}
}

// TestDiagnoseAll_Gates covers method + RBAC and confirms a 200 body carries all
// four sections.
func TestDiagnoseAll_Gates(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	gRec := httptest.NewRecorder()
	apiDiagnoseAll(gRec, roleReq(RoleOperator, http.MethodGet, "/api/diagnose/all", nil))
	if gRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET code=%d want 405", gRec.Code)
	}
	vRec := httptest.NewRecorder()
	apiDiagnoseAll(vRec, roleReq(RoleViewer, http.MethodPost, "/api/diagnose/all", nil))
	if vRec.Code != http.StatusForbidden {
		t.Fatalf("viewer code=%d want 403", vRec.Code)
	}
	oRec := httptest.NewRecorder()
	apiDiagnoseAll(oRec, roleReq(RoleOperator, http.MethodPost, "/api/diagnose/all", nil))
	if oRec.Code != http.StatusOK {
		t.Fatalf("operator code=%d want 200 (body=%q)", oRec.Code, oRec.Body.String())
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(oRec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"storage", "upstream", "cluster", "config", "ok"} {
		if _, ok := body[k]; !ok {
			t.Fatalf("aggregate body missing %q", k)
		}
	}
}
