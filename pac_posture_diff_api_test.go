package main

// pac_posture_diff_api_test.go — P3 change-diff endpoint (POST
// /api/pac/posture/diff): a candidate config is diffed against the current
// active config to report added/removed/broadened DIRECT bypasses.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/pac"
)

func pacDiffReq(t *testing.T, method, body string, role UIRole) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, "/api/pac/posture/diff", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, "/api/pac/posture/diff", http.NoBody)
	}
	r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, role))
	rec := httptest.NewRecorder()
	apiPACPostureDiff(rec, r)
	return rec
}

// TestAPIPACPostureDiff_DetectsNewBroadBypass proves the endpoint reports a
// candidate that adds a broad DIRECT rule as a risk-increasing change.
func TestAPIPACPostureDiff_DetectsNewBroadBypass(t *testing.T) {
	peiResetGlobals(t)
	if err := pacStore.Set(PACConfig{ProxyHost: "proxy.example", ProxyPort: 8080}); err != nil {
		t.Fatal(err)
	}
	// Current: one proxy-only profile (DIRECT-capable via plain-host only).
	if err := pacProfiles.Set(pac.ProfilesConfig{
		Pools:    []pac.Pool{{ID: "p", Name: "P", Endpoints: []pac.PoolEndpoint{{Host: "px.example", Port: 8080}}}},
		Profiles: []pac.Profile{{ID: "hq", Name: "HQ", Enabled: true, PoolID: "p", PrivateNetworks: pac.PrivateProxy, AvailabilityMode: pac.ModeBalanced, Revision: 1}},
	}); err != nil {
		t.Fatal(err)
	}
	// Candidate: same profile but with a broad wildcard DIRECT rule added.
	candidate := `{"pools":[{"id":"p","name":"P","endpoints":[{"host":"px.example","port":8080}]}],
		"profiles":[{"id":"hq","name":"HQ","enabled":true,"poolId":"p","privateNetworks":"proxy","availabilityMode":"balanced","revision":1,
		"rules":[{"kind":"wildcard","pattern":"*.cdn.example","action":"direct"}]}]}`
	rec := pacDiffReq(t, http.MethodPost, candidate, RoleViewer)
	if rec.Code != http.StatusOK {
		t.Fatalf("diff: %d (%s)", rec.Code, rec.Body.String())
	}
	var d pac.DirectInventoryDiff
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if !d.RiskIncreased || d.BroadPathsAdded < 1 || d.PathsAdded < 1 {
		t.Errorf("adding a broad wildcard DIRECT rule must be a risk-increasing broad add: %+v", d)
	}
	if d.EvidenceClass != "config" {
		t.Errorf("evidence class = %q, want config", d.EvidenceClass)
	}
}

// TestAPIPACPostureDiff_IdenticalCandidateNoChange proves diffing the current
// config against itself reports no change.
func TestAPIPACPostureDiff_IdenticalCandidateNoChange(t *testing.T) {
	peiResetGlobals(t)
	if err := pacStore.Set(PACConfig{ProxyHost: "proxy.example", ProxyPort: 8080}); err != nil {
		t.Fatal(err)
	}
	cfg := pac.ProfilesConfig{
		Pools:    []pac.Pool{{ID: "p", Name: "P", Endpoints: []pac.PoolEndpoint{{Host: "px.example", Port: 8080}}}},
		Profiles: []pac.Profile{{ID: "hq", Name: "HQ", Enabled: true, PoolID: "p", PrivateNetworks: pac.PrivateProxy, AvailabilityMode: pac.ModeBalanced, Revision: 1}},
	}
	if err := pacProfiles.Set(cfg); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(cfg)
	rec := pacDiffReq(t, http.MethodPost, string(body), RoleViewer)
	if rec.Code != http.StatusOK {
		t.Fatalf("diff: %d (%s)", rec.Code, rec.Body.String())
	}
	var d pac.DirectInventoryDiff
	_ = json.Unmarshal(rec.Body.Bytes(), &d)
	if d.RiskIncreased || len(d.Deltas) != 0 {
		t.Errorf("identical candidate must report no change: %+v", d)
	}
}

// TestAPIPACPostureDiff_Errors covers the method, JSON, and validation guards.
func TestAPIPACPostureDiff_Errors(t *testing.T) {
	peiResetGlobals(t)

	if rec := pacDiffReq(t, http.MethodGet, "", RoleViewer); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET diff: %d, want 405", rec.Code)
	}
	if rec := pacDiffReq(t, http.MethodPost, "{not json", RoleViewer); rec.Code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d, want 400", rec.Code)
	}
	// Invalid candidate (bad pool endpoint) → 400 via structured issues.
	bad := `{"profiles":[{"id":"x","name":"X","enabled":true,"poolId":"missing","availabilityMode":"balanced","privateNetworks":"proxy","rules":[{"kind":"cidr4","pattern":"not-a-cidr","action":"direct"}]}]}`
	if rec := pacDiffReq(t, http.MethodPost, bad, RoleViewer); rec.Code != http.StatusBadRequest {
		t.Errorf("invalid candidate: %d, want 400", rec.Code)
	}
}
