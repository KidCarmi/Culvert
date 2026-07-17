package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestDiagnoseConfig_ValidAndOverCap drives the pass/fail verdict through the pure
// core with a fabricated snapshot — no dependence on the live config singletons.
func TestDiagnoseConfig_ValidAndOverCap(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()

	// A small, well-formed snapshot validates.
	ok := diagnoseConfigFrom(ConfigSnapshot{
		PolicyVersion: 7, Epoch: 3,
		PolicyRules:  make([]PolicyRule, 2),
		BlockedHosts: []string{"a.example", "b.example"},
	}, now)
	if !ok.OK {
		t.Fatalf("small snapshot reported not-ok: %q", ok.Error)
	}
	if ok.PolicyVersion != 7 || ok.Epoch != 3 {
		t.Fatalf("version/epoch not surfaced: %+v", ok)
	}
	// policy_rules size must be reflected.
	if sz := sizeOf(ok.Sizes, "policy_rules"); sz != 2 {
		t.Fatalf("policy_rules size=%d want 2", sz)
	}

	// A snapshot that blows a cap fails, and the error names the collection.
	over := diagnoseConfigFrom(ConfigSnapshot{
		BlockedHosts: make([]string, maxSnapBlockedHosts+1),
	}, now)
	if over.OK {
		t.Fatal("over-cap snapshot reported ok")
	}
	if !strings.Contains(over.Error, "blocked_hosts") {
		t.Fatalf("error %q does not name the offending collection", over.Error)
	}
}

// TestDiagnoseConfig_NoValues proves the diagnosis surfaces only counts, never the
// snapshot values (a blocked host string must not appear in the serialized output).
func TestDiagnoseConfig_NoValues(t *testing.T) {
	secretish := "internal-host.corp.example"
	d := diagnoseConfigFrom(ConfigSnapshot{
		BlockedHosts:      []string{secretish},
		SSLBypassPatterns: []string{secretish},
	}, time.Unix(1_700_000_000, 0).UTC())
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), secretish) {
		t.Fatalf("diagnosis leaked a snapshot value: %s", raw)
	}
}

// TestDiagnoseConfig_Gates covers method + RBAC on the handler (runs against the
// live singletons, so it asserts only gate outcomes).
func TestDiagnoseConfig_Gates(t *testing.T) {
	gRec := httptest.NewRecorder()
	apiDiagnoseConfig(gRec, roleReq(RoleOperator, http.MethodGet, "/api/diagnose/config", nil))
	if gRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET code=%d want 405", gRec.Code)
	}
	vRec := httptest.NewRecorder()
	apiDiagnoseConfig(vRec, roleReq(RoleViewer, http.MethodPost, "/api/diagnose/config", nil))
	if vRec.Code != http.StatusForbidden {
		t.Fatalf("viewer code=%d want 403", vRec.Code)
	}
	oRec := httptest.NewRecorder()
	apiDiagnoseConfig(oRec, roleReq(RoleOperator, http.MethodPost, "/api/diagnose/config", nil))
	if oRec.Code != http.StatusOK {
		t.Fatalf("operator code=%d want 200 (body=%q)", oRec.Code, oRec.Body.String())
	}
}

func sizeOf(sizes []configCollectionSize, name string) int {
	for _, s := range sizes {
		if s.Name == name {
			return s.Size
		}
	}
	return -1
}
