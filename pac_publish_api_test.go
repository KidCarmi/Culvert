package main

// pac_publish_api_test.go — root tests for the PR 3 simulator + safe-publish
// API: simulate parity, lifecycle draft/publish/rollback, publish guardrails
// (incl. the new-DIRECT typed confirmation), and impact analysis.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/pac"
)

func resetPACPublishGlobals(t *testing.T) {
	t.Helper()
	oc := pacStore.Snapshot()
	op := pacProfiles.Snapshot()
	ol := pacLifecycle.Snapshot()
	t.Cleanup(func() {
		pacStore.Restore(oc)
		pacProfiles.Restore(op)
		pacLifecycle.Restore(ol)
	})
}

func seedPublishProfile(t *testing.T) {
	t.Helper()
	err := pacProfiles.Set(pac.ProfilesConfig{
		Profiles: []pac.Profile{{
			ID: "hq", Name: "HQ", Enabled: true, PoolID: "main",
			PrivateNetworks: pac.PrivateProxy, AvailabilityMode: pac.ModeBalanced, Revision: 1,
			Rules: []pac.Rule{{Kind: pac.RuleKindSuffix, Pattern: "cdn.example", Action: pac.ActionUsePool}},
		}},
		Pools: []pac.Pool{
			{ID: "main", Name: "Main", Endpoints: []pac.PoolEndpoint{{Host: "p1.example", Port: 8080}}},
			{ID: "alt", Name: "Alt", Endpoints: []pac.PoolEndpoint{{Host: "p2.example", Port: 8080}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func pacPost(t *testing.T, path, body string, role UIRole, ip string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, role))
	rec := httptest.NewRecorder()
	switch path {
	case "/api/pac/simulate":
		apiPACSimulate(rec, req)
	case "/api/pac/analyze":
		apiPACAnalyze(rec, req)
	default:
		apiPACProfileItem(rec, req) // routes the lifecycle sub-resource internally
	}
	return rec
}

// ─── Simulator ────────────────────────────────────────────────────────────────

func TestAPIPACSimulate(t *testing.T) {
	resetPACPublishGlobals(t)
	seedPublishProfile(t)

	rec := pacPost(t, "/api/pac/simulate",
		`{"profileId":"hq","input":{"host":"x.cdn.example"}}`, RoleViewer, "198.51.100.120:0")
	if rec.Code != http.StatusOK {
		t.Fatalf("simulate: %d (%s)", rec.Code, rec.Body.String())
	}
	var res pac.SimResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.MatchedRule.Kind != pac.RuleKindSuffix || res.Directive != "PROXY p1.example:8080" {
		t.Errorf("unexpected simulate result: %+v", res)
	}
	if res.Reason == "" || res.CompilerVersion == "" {
		t.Error("simulate must carry a reason + compiler version")
	}

	// default profile is simulatable.
	if err := pacStore.Set(PACConfig{ProxyHost: "proxy.example", ProxyPort: 8080, Exclusions: []string{"corp.local"}}); err != nil {
		t.Fatal(err)
	}
	rec = pacPost(t, "/api/pac/simulate", `{"profileId":"default","input":{"host":"corp.local"}}`, RoleViewer, "198.51.100.121:0")
	if rec.Code != http.StatusOK {
		t.Fatalf("simulate default: %d (%s)", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.Directive != "DIRECT" {
		t.Errorf("default profile corp.local should be DIRECT, got %q", res.Directive)
	}

	// unknown profile → 404.
	rec = pacPost(t, "/api/pac/simulate", `{"profileId":"nope","input":{"host":"x"}}`, RoleViewer, "198.51.100.122:0")
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown profile simulate: %d, want 404", rec.Code)
	}
}

// ─── Lifecycle: publish + rollback ─────────────────────────────────────────────

func TestAPIPACLifecycle_PublishAndRollback(t *testing.T) {
	resetPACPublishGlobals(t)
	seedPublishProfile(t)

	// Publish the current active spec (no changes) → revision 1.
	pub := `{"action":"publish","draft":{"id":"hq","name":"HQ","enabled":true,"poolId":"main","privateNetworks":"proxy","availabilityMode":"balanced","rules":[{"kind":"suffix","pattern":"cdn.example","action":"use_pool"}]}}`
	rec := pacPost(t, "/api/pac/profiles/hq/lifecycle", pub, RoleAdmin, "198.51.100.123:0")
	if rec.Code != http.StatusOK {
		t.Fatalf("publish v1: %d (%s)", rec.Code, rec.Body.String())
	}

	// Publish a benign change (pool swap, no new DIRECT) → revision 2.
	pub2 := `{"action":"publish","draft":{"id":"hq","name":"HQ","enabled":true,"poolId":"alt","privateNetworks":"proxy","availabilityMode":"balanced","rules":[{"kind":"suffix","pattern":"cdn.example","action":"use_pool"}]}}`
	rec = pacPost(t, "/api/pac/profiles/hq/lifecycle", pub2, RoleAdmin, "198.51.100.123:0")
	if rec.Code != http.StatusOK {
		t.Fatalf("publish v2: %d (%s)", rec.Code, rec.Body.String())
	}
	if p, _ := pacProfiles.ProfileByID("hq"); p.PoolID != "alt" {
		t.Errorf("active profile should be v2 (pool alt), got %q", p.PoolID)
	}

	// Rollback to revision 1 → active pool back to main, new revision minted.
	rb := `{"action":"rollback","targetN":1}`
	rec = pacPost(t, "/api/pac/profiles/hq/lifecycle", rb, RoleAdmin, "198.51.100.123:0")
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback: %d (%s)", rec.Code, rec.Body.String())
	}
	if p, _ := pacProfiles.ProfileByID("hq"); p.PoolID != "main" {
		t.Errorf("rollback should restore pool main, got %q", p.PoolID)
	}

	// GET lifecycle shows the revision history.
	greq := httptest.NewRequest(http.MethodGet, "/api/pac/profiles/hq/lifecycle", http.NoBody)
	greq = greq.WithContext(context.WithValue(greq.Context(), uiRoleKey{}, RoleViewer))
	grec := httptest.NewRecorder()
	apiPACProfileItem(grec, greq)
	if grec.Code != http.StatusOK {
		t.Fatalf("GET lifecycle: %d", grec.Code)
	}
	var lc map[string]any
	_ = json.Unmarshal(grec.Body.Bytes(), &lc)
	revs, _ := lc["revisions"].([]any)
	if len(revs) != 3 { // published v1 + v2, then rollback mints v3
		t.Errorf("expected 3 revisions in history, got %d", len(revs))
	}
}

// ─── Publish guardrail: new DIRECT path requires typed confirmation ────────────

func TestAPIPACLifecycle_NewDirectRequiresConfirmation(t *testing.T) {
	resetPACPublishGlobals(t)
	seedPublishProfile(t)

	// Draft adds a DIRECT rule → new DIRECT path → 409 confirmation required.
	draft := `{"action":"publish","draft":{"id":"hq","name":"HQ","enabled":true,"poolId":"main","privateNetworks":"proxy","availabilityMode":"balanced","rules":[{"kind":"domain","pattern":"x.example","action":"direct"}]}}`
	rec := pacPost(t, "/api/pac/profiles/hq/lifecycle", draft, RoleAdmin, "198.51.100.124:0")
	if rec.Code != http.StatusConflict {
		t.Fatalf("new DIRECT path must require confirmation (409), got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "newDirectPaths") {
		t.Errorf("409 body must list the new DIRECT paths: %s", rec.Body.String())
	}
	// Active is unchanged (nothing published).
	if p, _ := pacProfiles.ProfileByID("hq"); len(p.Rules) != 1 || p.Rules[0].Action != pac.ActionUsePool {
		t.Error("unconfirmed publish must not mutate the active profile")
	}

	// With the typed confirmation → publishes.
	confirmed := `{"action":"publish","confirmDirect":"hq","draft":{"id":"hq","name":"HQ","enabled":true,"poolId":"main","privateNetworks":"proxy","availabilityMode":"balanced","rules":[{"kind":"domain","pattern":"x.example","action":"direct"}]}}`
	rec = pacPost(t, "/api/pac/profiles/hq/lifecycle", confirmed, RoleAdmin, "198.51.100.124:0")
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed publish: %d (%s)", rec.Code, rec.Body.String())
	}
	if p, _ := pacProfiles.ProfileByID("hq"); p.Rules[0].Action != pac.ActionDirect {
		t.Error("confirmed publish should install the DIRECT rule")
	}
}

// ─── Publish guardrail: hard blocks ────────────────────────────────────────────

func TestAPIPACLifecycle_PublishBlockedByGuardrail(t *testing.T) {
	resetPACPublishGlobals(t)
	seedPublishProfile(t)
	// Missing pool → blocked (not a confirmation case).
	bad := `{"action":"publish","draft":{"id":"hq","name":"HQ","enabled":true,"poolId":"gone","privateNetworks":"proxy","availabilityMode":"balanced"}}`
	rec := pacPost(t, "/api/pac/profiles/hq/lifecycle", bad, RoleAdmin, "198.51.100.125:0")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing pool must hard-block (400), got %d (%s)", rec.Code, rec.Body.String())
	}
}

// ─── RBAC + DP gate on lifecycle mutations ─────────────────────────────────────

func TestAPIPACLifecycle_RBAC(t *testing.T) {
	resetPACPublishGlobals(t)
	seedPublishProfile(t)
	for _, role := range []UIRole{RoleViewer, RoleOperator} {
		rec := pacPost(t, "/api/pac/profiles/hq/lifecycle", `{"action":"rollback","targetN":1}`, role, "198.51.100.126:0")
		if rec.Code != http.StatusForbidden {
			t.Errorf("role %v lifecycle POST: %d, want 403", role, rec.Code)
		}
	}
}

// ─── Impact analysis (read-only /api/pac/analyze; viewer) ───────────────────────

func TestAPIPACAnalyze_Impact(t *testing.T) {
	resetPACPublishGlobals(t)
	seedPublishProfile(t)
	// Candidate flips cdn.example from pool to DIRECT. Read-only analyze route,
	// viewer-accessible, off the AuditExpected lifecycle POST.
	body := `{"profileId":"hq","action":"impact","sample":["a.cdn.example","b.other.example"],"draft":{"id":"hq","name":"HQ","enabled":true,"poolId":"main","privateNetworks":"proxy","availabilityMode":"balanced","rules":[{"kind":"suffix","pattern":"cdn.example","action":"direct"}]}}`
	rec := pacPost(t, "/api/pac/analyze", body, RoleViewer, "198.51.100.127:0")
	if rec.Code != http.StatusOK {
		t.Fatalf("impact: %d (%s)", rec.Code, rec.Body.String())
	}
	var rep pac.ImpactReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Counts[pac.ImpactBecameDirect] != 1 {
		t.Errorf("a.cdn.example should become DIRECT: %+v", rep.Counts)
	}
	if rep.Source != "test_vectors" {
		t.Errorf("source should be test_vectors, got %q", rep.Source)
	}
}

func TestAPIPACAnalyze_Diff(t *testing.T) {
	resetPACPublishGlobals(t)
	seedPublishProfile(t)
	body := `{"profileId":"hq","action":"diff","draft":{"id":"hq","name":"HQ","enabled":true,"poolId":"alt","privateNetworks":"proxy","availabilityMode":"balanced","rules":[{"kind":"suffix","pattern":"cdn.example","action":"use_pool"}]}}`
	rec := pacPost(t, "/api/pac/analyze", body, RoleViewer, "198.51.100.128:0")
	if rec.Code != http.StatusOK {
		t.Fatalf("diff: %d (%s)", rec.Code, rec.Body.String())
	}
	var d pac.ProfileDiff
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}

	// Unknown / default / empty profileId → 404.
	for _, id := range []string{"", "default", "nope/slash"} {
		rec := pacPost(t, "/api/pac/analyze",
			`{"profileId":"`+id+`","action":"diff","draft":{}}`, RoleViewer, "198.51.100.129:0")
		if rec.Code != http.StatusNotFound {
			t.Errorf("analyze profileId=%q: %d, want 404", id, rec.Code)
		}
	}
}
