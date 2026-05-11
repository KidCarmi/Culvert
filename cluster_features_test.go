package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// ── Full Policy Sync ────────────────────────────────────────────────────────

func TestConfigSnapshot_FullPolicySync(t *testing.T) {
	// Add a policy rule.
	origRules := policyStore.List()
	defer policyStore.ReplaceAll(origRules)

	policyStore.Add(PolicyRule{
		Priority: 100,
		Name:     "test-sync",
		DestFQDN: "example.com",
		Action:   "allow",
	})

	snap := CurrentConfigSnapshot()

	if len(snap.PolicyRules) == 0 {
		t.Error("expected policy rules in snapshot")
	}
	found := false
	for _, r := range snap.PolicyRules {
		if r.Name == "test-sync" {
			found = true
			break
		}
	}
	if !found {
		t.Error("test-sync rule not found in snapshot")
	}

	if snap.DefaultAction == "" {
		t.Error("expected non-empty default action")
	}
}

func TestPolicyStore_ReplaceAll(t *testing.T) {
	origRules := policyStore.List()
	defer policyStore.ReplaceAll(origRules)

	rules := []PolicyRule{
		{Priority: 1, Name: "r1", DestFQDN: "a.com", Action: "allow"},
		{Priority: 2, Name: "r2", DestFQDN: "b.com", Action: "block"},
	}
	policyStore.ReplaceAll(rules)
	got := policyStore.List()
	if len(got) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(got))
	}
	if got[0].Name != "r1" || got[1].Name != "r2" {
		t.Errorf("unexpected rule names: %s, %s", got[0].Name, got[1].Name)
	}
	// HitCount should be zeroed.
	if got[0].HitCount != 0 {
		t.Errorf("expected HitCount=0, got %d", got[0].HitCount)
	}
}

func TestCategoryStore_ReplaceAll(t *testing.T) {
	orig := catStore.All()
	defer catStore.ReplaceAll(orig)

	cats := []CategoryEntry{
		{Name: "social", Hosts: []string{"facebook.com", "twitter.com"}},
		{Name: "news", Hosts: []string{"cnn.com"}},
	}
	catStore.ReplaceAll(cats)
	got := catStore.All()
	if len(got) != 2 {
		t.Fatalf("expected 2 categories, got %d", len(got))
	}
	if got[0].Name != "social" && got[1].Name != "social" {
		t.Error("social category not found")
	}
}

func TestFileProfileStore_ReplaceAll(t *testing.T) {
	orig := globalProfileStore.List()
	defer func() {
		profiles := make([]FileExtProfile, len(orig))
		for i, p := range orig {
			profiles[i] = *p
		}
		globalProfileStore.ReplaceAll(profiles)
	}()

	profiles := []FileExtProfile{
		{ID: "p1", Name: "Executables", Extensions: []string{".exe", ".msi"}},
		{ID: "p2", Name: "Archives", Extensions: []string{".zip", ".tar.gz"}},
	}
	globalProfileStore.ReplaceAll(profiles)
	got := globalProfileStore.List()
	if len(got) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(got))
	}
}

// ── Node Labels ─────────────────────────────────────────────────────────────

func TestClusterStore_SetNodeLabels(t *testing.T) {
	cs := newTestClusterStore(t)
	cs.RegisterNode(&EnrolledNode{NodeID: "dp-1", Status: "connected", CertSerial: "s1"})

	// Set labels.
	err := cs.SetNodeLabels("dp-1", map[string]string{"region": "us-east", "tier": "dmz"})
	if err != nil {
		t.Fatalf("SetNodeLabels: %v", err)
	}

	nodes := cs.ListNodes()
	var n EnrolledNode
	for _, nd := range nodes {
		if nd.NodeID == "dp-1" {
			n = nd
			break
		}
	}
	if n.Labels["region"] != "us-east" {
		t.Errorf("expected region=us-east, got %s", n.Labels["region"])
	}
	if n.Labels["tier"] != "dmz" {
		t.Errorf("expected tier=dmz, got %s", n.Labels["tier"])
	}

	// Clear labels.
	err = cs.SetNodeLabels("dp-1", nil)
	if err != nil {
		t.Fatalf("SetNodeLabels(nil): %v", err)
	}
	nodes = cs.ListNodes()
	for _, nd := range nodes {
		if nd.NodeID == "dp-1" && len(nd.Labels) > 0 {
			t.Error("expected empty labels after clear")
		}
	}

	// Non-existent node.
	err = cs.SetNodeLabels("nonexistent", map[string]string{"a": "b"})
	if err == nil {
		t.Error("expected error for nonexistent node")
	}
}

func TestAPIClusterLabels(t *testing.T) {
	origStore := globalClusterStore
	defer func() { globalClusterStore = origStore }()
	globalClusterStore = newTestClusterStore(t)
	globalClusterStore.RegisterNode(&EnrolledNode{NodeID: "dp-1", Status: "connected", CertSerial: "s1"})

	body := `{"node_id":"dp-1","labels":{"env":"prod","region":"eu"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/labels", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	w := httptest.NewRecorder()
	apiClusterLabels(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify labels were set.
	nodes := globalClusterStore.ListNodes()
	for _, n := range nodes {
		if n.NodeID == "dp-1" {
			if n.Labels["env"] != "prod" || n.Labels["region"] != "eu" {
				t.Errorf("unexpected labels: %v", n.Labels)
			}
		}
	}
}

// ── Node Drain Mode ─────────────────────────────────────────────────────────

func TestClusterStore_SetNodeDraining(t *testing.T) {
	cs := newTestClusterStore(t)
	cs.RegisterNode(&EnrolledNode{NodeID: "dp-1", Status: "connected", CertSerial: "s1"})
	cs.RegisterNode(&EnrolledNode{NodeID: "dp-2", Status: "revoked", CertSerial: "s2"})

	// Drain connected node.
	err := cs.SetNodeDraining("dp-1", true)
	if err != nil {
		t.Fatalf("SetNodeDraining: %v", err)
	}
	nodes := cs.ListNodes()
	for _, n := range nodes {
		if n.NodeID == "dp-1" && n.Status != "draining" {
			t.Errorf("expected status=draining, got %s", n.Status)
		}
	}

	// Undrain.
	err = cs.SetNodeDraining("dp-1", false)
	if err != nil {
		t.Fatalf("SetNodeDraining(false): %v", err)
	}
	nodes = cs.ListNodes()
	for _, n := range nodes {
		if n.NodeID == "dp-1" && n.Status != "connected" {
			t.Errorf("expected status=connected, got %s", n.Status)
		}
	}

	// Can't drain revoked node.
	err = cs.SetNodeDraining("dp-2", true)
	if err == nil {
		t.Error("expected error draining revoked node")
	}
}

func TestAPIClusterDrain(t *testing.T) {
	origStore := globalClusterStore
	defer func() { globalClusterStore = origStore }()
	globalClusterStore = newTestClusterStore(t)
	globalClusterStore.RegisterNode(&EnrolledNode{NodeID: "dp-1", Status: "connected", CertSerial: "s1"})

	body := `{"node_id":"dp-1","draining":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/drain", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	w := httptest.NewRecorder()
	apiClusterDrain(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	nodes := globalClusterStore.ListNodes()
	for _, n := range nodes {
		if n.NodeID == "dp-1" && n.Status != "draining" {
			t.Errorf("expected draining, got %s", n.Status)
		}
	}
}

// ── Cluster Metrics ─────────────────────────────────────────────────────────

func TestAPIClusterMetrics(t *testing.T) {
	// Seed some metrics.
	nodeMetricsMu.Lock()
	origMetrics := make(map[string]MetricsReport, len(nodeMetrics))
	for k, v := range nodeMetrics {
		origMetrics[k] = v
	}
	nodeMetrics["dp-1"] = MetricsReport{NodeID: "dp-1", Total: 1000, Blocked: 50, AuthFail: 5, Uptime: "2h"}
	nodeMetrics["dp-2"] = MetricsReport{NodeID: "dp-2", Total: 2000, Blocked: 100, AuthFail: 10, Uptime: "4h"}
	nodeMetricsMu.Unlock()
	defer func() {
		nodeMetricsMu.Lock()
		nodeMetrics = origMetrics
		nodeMetricsMu.Unlock()
	}()

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/metrics", nil)
	w := httptest.NewRecorder()
	apiClusterMetrics(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if resp["cluster_total"].(float64) != 3000 {
		t.Errorf("expected cluster_total=3000, got %v", resp["cluster_total"])
	}
	if resp["cluster_blocked"].(float64) != 150 {
		t.Errorf("expected cluster_blocked=150, got %v", resp["cluster_blocked"])
	}
	if resp["node_count"].(float64) < 2 {
		t.Errorf("expected node_count>=2, got %v", resp["node_count"])
	}
}

// ── Apply Config Snapshot with Full Policy ──────────────────────────────────

func TestApplyConfigSnapshot_FullPolicy(t *testing.T) {
	origRules := policyStore.List()
	origCats := catStore.All()
	origProfiles := globalProfileStore.List()
	defer func() {
		policyStore.ReplaceAll(origRules)
		catStore.ReplaceAll(origCats)
		profiles := make([]FileExtProfile, len(origProfiles))
		for i, p := range origProfiles {
			profiles[i] = *p
		}
		globalProfileStore.ReplaceAll(profiles)
	}()

	snap := ConfigSnapshot{
		Version:       99,
		DefaultAction: "deny",
		PolicyRules: []PolicyRule{
			{Priority: 1, Name: "synced-rule", DestFQDN: "test.com", Action: "allow"},
		},
		SSLBypassPatterns: []string{"*.internal.corp"},
		URLCategories: []CategoryEntry{
			{Name: "test-cat", Hosts: []string{"a.com", "b.com"}},
		},
		FileProfiles: []FileExtProfile{
			{ID: "fp1", Name: "TestProfile", Extensions: []string{".test"}},
		},
		RewriteRules: []RewriteRule{
			{ID: 1, Host: "*.example.com", ReqSet: map[string]string{"X-Test": "1"}},
		},
		MaxConnsPerIP: 256,
	}

	applyConfigSnapshot(snap)

	// Verify policy rules applied.
	rules := policyStore.List()
	if len(rules) != 1 || rules[0].Name != "synced-rule" {
		t.Errorf("policy rules not applied: %v", rules)
	}

	// Verify default action.
	if defaultPolicyAction() != "deny" {
		t.Errorf("expected deny, got %s", defaultPolicyAction())
	}

	// Verify SSL bypass.
	if byp := sslBypass.List(); len(byp) != 1 || byp[0] != "*.internal.corp" {
		t.Errorf("SSL bypass not applied: %v", byp)
	}

	// Verify categories.
	cats := catStore.All()
	found := false
	for _, c := range cats {
		if c.Name == "test-cat" {
			found = true
		}
	}
	if !found {
		t.Error("test-cat category not applied")
	}

	// Verify file profiles.
	profiles := globalProfileStore.List()
	if len(profiles) != 1 || profiles[0].Name != "TestProfile" {
		t.Errorf("file profiles not applied: %v", profiles)
	}

	// Verify rewrite rules.
	rr := rewriter.List()
	if len(rr) != 1 || rr[0].Host != "*.example.com" {
		t.Errorf("rewrite rules not applied: %v", rr)
	}
}

// TestApplyConfigSnapshot_PolicyRulesPersist exercises P3.2b: applyConfigSnapshot
// must persist the cluster-pushed policy rules to disk so a DP node survives
// restart with the most recent CP-applied snapshot instead of stale state.
//
// Snapshot+restore the policyStore globals (rules + path) so this test stays
// deterministic under -shuffle=on. policyStore.path is empty by default in
// the test process; restoring it on cleanup keeps other tests that touch
// policyStore via applyConfigSnapshot from accidentally writing to a stale
// tempdir.
func TestApplyConfigSnapshot_PolicyRulesPersist(t *testing.T) {
	origRules := policyStore.List()
	origPath := policyStore.path
	t.Cleanup(func() {
		policyStore.path = origPath
		policyStore.ReplaceAll(origRules)
	})

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	policyStore.path = path

	snap := ConfigSnapshot{
		Version: 1,
		PolicyRules: []PolicyRule{
			{Priority: 1, Name: "persist-test", DestFQDN: "test.com", Action: ActionAllow},
		},
	}
	applyConfigSnapshot(snap)

	// Reload via a fresh PolicyStore and assert the rule is on disk.
	fresh := &PolicyStore{}
	if err := fresh.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	rules := fresh.List()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule on disk, got %d", len(rules))
	}
	if rules[0].Name != "persist-test" {
		t.Fatalf("expected rule Name=%q, got %q", "persist-test", rules[0].Name)
	}
	if rules[0].DestFQDN != "test.com" {
		t.Fatalf("expected rule DestFQDN=%q, got %q", "test.com", rules[0].DestFQDN)
	}
}
