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

	// A small, well-formed snapshot validates (role does not matter here).
	ok := diagnoseConfigFrom(ConfigSnapshot{
		PolicyVersion: 7, Epoch: 3,
		PolicyRules:  make([]PolicyRule, 2),
		BlockedHosts: []string{"a.example", "b.example"},
	}, false, now)
	if !ok.OK || ok.Status != "ok" {
		t.Fatalf("small snapshot reported not-ok: status=%q err=%q", ok.Status, ok.Error)
	}
	if ok.PolicyVersion != 7 || ok.Epoch != 3 {
		t.Fatalf("version/epoch not surfaced: %+v", ok)
	}
	// policy_rules size must be reflected.
	if sz := sizeOf(ok.Sizes, "policy_rules"); sz != 2 {
		t.Fatalf("policy_rules size=%d want 2", sz)
	}

	// On a SYNCING node an over-cap snapshot is a hard failure; the error names
	// the collection.
	over := diagnoseConfigFrom(ConfigSnapshot{
		BlockedHosts: make([]string, maxSnapBlockedHosts+1),
	}, true, now)
	if over.OK || over.Status != "degraded" {
		t.Fatalf("over-cap syncing snapshot: OK=%v status=%q, want degraded", over.OK, over.Status)
	}
	if !strings.Contains(over.Error, "blocked_hosts") {
		t.Fatalf("error %q does not name the offending collection", over.Error)
	}
}

// TestDiagnoseConfig_StandaloneOverCapIsWarnNotDegraded pins the customer-facing
// fix: a STANDALONE node whose local config exceeds the cluster-sync cap must be
// advisory (warn, OK true), NOT DEGRADED — the cap gates CP→DP sync, which a
// lone appliance never performs. Regression guard for the reported false
// positive ("config snapshot blocked_hosts=... exceeds cap").
func TestDiagnoseConfig_StandaloneOverCapIsWarnNotDegraded(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	d := diagnoseConfigFrom(ConfigSnapshot{
		BlockedHosts: make([]string, maxSnapBlockedHosts+1),
	}, false, now) // syncing=false → standalone
	if !d.OK {
		t.Fatal("standalone over-cap must keep OK=true so the aggregate health is not DEGRADED")
	}
	if d.Status != "warn" {
		t.Fatalf("standalone over-cap status=%q, want warn", d.Status)
	}
	if d.Note == "" || !strings.Contains(d.Error, "blocked_hosts") {
		t.Fatalf("standalone over-cap should still surface the advisory note + error: note=%q err=%q", d.Note, d.Error)
	}
}

// TestDiagnoseConfig_ApproachingCapWarns proves the amber early-signal tier: a
// slice at/above the warn threshold trips warn even though it is under the cap.
func TestDiagnoseConfig_ApproachingCapWarns(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	near := maxSnapBlockedHosts * configWarnUtilPercent / 100 // exactly the threshold
	d := diagnoseConfigFrom(ConfigSnapshot{
		BlockedHosts: make([]string, near),
	}, true, now)
	if d.Status != "warn" || !d.OK {
		t.Fatalf("approaching-cap: status=%q OK=%v, want warn/OK", d.Status, d.OK)
	}
	if d.MaxUtilSlice != "blocked_hosts" || d.MaxUtilPercent < configWarnUtilPercent {
		t.Fatalf("utilization not surfaced: slice=%q pct=%d", d.MaxUtilSlice, d.MaxUtilPercent)
	}
}

// TestDiagnoseConfig_NoValues proves the diagnosis surfaces only counts, never the
// snapshot values (a blocked host string must not appear in the serialized output).
func TestDiagnoseConfig_NoValues(t *testing.T) {
	secretish := "internal-host.corp.example"
	d := diagnoseConfigFrom(ConfigSnapshot{
		BlockedHosts:      []string{secretish},
		SSLBypassPatterns: []string{secretish},
	}, false, time.Unix(1_700_000_000, 0).UTC())
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
