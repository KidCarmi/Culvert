package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── NodeGroupStore unit tests ──────────────────────────────────────────────

func TestNodeGroupStore_AddListDelete(t *testing.T) {
	dir := t.TempDir()
	s := NewNodeGroupStore(filepath.Join(dir, "ng.json"))

	// Initially empty.
	if got := s.List(); len(got) != 0 {
		t.Fatalf("expected 0 groups, got %d", len(got))
	}

	// Add a group.
	g, err := s.Add(NodeGroup{
		Name:          "us-nodes",
		Description:   "US region nodes",
		LabelSelector: map[string]string{"geo:country": "US"},
		Priority:      10,
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if g.Name != "us-nodes" {
		t.Fatalf("expected name us-nodes, got %s", g.Name)
	}
	if g.CreatedAt == "" {
		t.Fatal("expected CreatedAt to be set")
	}

	// Duplicate name must fail.
	_, err = s.Add(NodeGroup{
		Name:          "us-nodes",
		LabelSelector: map[string]string{"geo:country": "US"},
	})
	if err == nil {
		t.Fatal("expected duplicate name error")
	}

	// Empty name must fail.
	_, err = s.Add(NodeGroup{LabelSelector: map[string]string{"a": "b"}})
	if err == nil {
		t.Fatal("expected empty-name error")
	}

	// Empty selector must fail.
	_, err = s.Add(NodeGroup{Name: "bad"})
	if err == nil {
		t.Fatal("expected empty-selector error")
	}

	// Add a second group.
	_, err = s.Add(NodeGroup{
		Name:          "eu-nodes",
		LabelSelector: map[string]string{"geo:country": "DE"},
	})
	if err != nil {
		t.Fatalf("Add eu-nodes: %v", err)
	}

	if got := s.List(); len(got) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(got))
	}

	// Delete.
	if !s.Delete("us-nodes") {
		t.Fatal("expected Delete to return true")
	}
	if s.Delete("nonexistent") {
		t.Fatal("expected Delete of nonexistent to return false")
	}
	if got := s.List(); len(got) != 1 {
		t.Fatalf("expected 1 group after delete, got %d", len(got))
	}
}

func TestNodeGroupStore_MatchingGroups(t *testing.T) {
	dir := t.TempDir()
	s := NewNodeGroupStore(filepath.Join(dir, "ng.json"))

	_, _ = s.Add(NodeGroup{
		Name:          "us-dmz",
		LabelSelector: map[string]string{"geo:country": "US", "tier": "dmz"},
	})
	_, _ = s.Add(NodeGroup{
		Name:          "all-us",
		LabelSelector: map[string]string{"geo:country": "US"},
	})
	_, _ = s.Add(NodeGroup{
		Name:          "eu-prod",
		LabelSelector: map[string]string{"geo:country": "DE", "tier": "prod"},
	})

	// Node with US+dmz matches both us-dmz and all-us.
	labels := map[string]string{"geo:country": "US", "tier": "dmz", "env": "staging"}
	names := s.MatchingGroups(labels)
	if len(names) != 2 {
		t.Fatalf("expected 2 matches, got %d: %v", len(names), names)
	}

	// Node with only US matches only all-us.
	names = s.MatchingGroups(map[string]string{"geo:country": "US"})
	if len(names) != 1 || names[0] != "all-us" {
		t.Fatalf("expected [all-us], got %v", names)
	}

	// Node with no labels matches nothing.
	names = s.MatchingGroups(nil)
	if len(names) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(names))
	}
}

func TestNodeGroupStore_NodesInGroup(t *testing.T) {
	dir := t.TempDir()
	s := NewNodeGroupStore(filepath.Join(dir, "ng.json"))

	_, _ = s.Add(NodeGroup{
		Name:          "us-nodes",
		LabelSelector: map[string]string{"geo:country": "US"},
	})

	nodes := []EnrolledNode{
		{NodeID: "n1", Labels: map[string]string{"geo:country": "US"}},
		{NodeID: "n2", Labels: map[string]string{"geo:country": "DE"}},
		{NodeID: "n3", Labels: map[string]string{"geo:country": "US", "tier": "prod"}},
		{NodeID: "n4"}, // no labels
	}

	matched := s.NodesInGroup("us-nodes", nodes)
	if len(matched) != 2 {
		t.Fatalf("expected 2 nodes in us-nodes, got %d", len(matched))
	}
	ids := map[string]bool{}
	for _, n := range matched {
		ids[n.NodeID] = true
	}
	if !ids["n1"] || !ids["n3"] {
		t.Fatalf("expected n1 and n3, got %v", ids)
	}

	// Unknown group returns nil.
	if got := s.NodesInGroup("nonexistent", nodes); got != nil {
		t.Fatalf("expected nil for unknown group, got %v", got)
	}
}

func TestNodeGroupStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ng.json")

	// Create store and add groups.
	s1 := NewNodeGroupStore(path)
	s1.Add(NodeGroup{
		Name:          "persistent-group",
		LabelSelector: map[string]string{"region": "us-east"},
		Priority:      5,
	})
	s1.Add(NodeGroup{
		Name:          "another-group",
		LabelSelector: map[string]string{"tier": "prod"},
	})

	// Verify file exists.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file to exist: %v", err)
	}

	// Load from same path.
	s2 := NewNodeGroupStore(path)
	groups := s2.List()
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups after reload, got %d", len(groups))
	}
	if groups[0].Name != "persistent-group" {
		t.Fatalf("expected first group persistent-group, got %s", groups[0].Name)
	}
	if groups[0].Priority != 5 {
		t.Fatalf("expected priority 5, got %d", groups[0].Priority)
	}
	if groups[1].Name != "another-group" {
		t.Fatalf("expected second group another-group, got %s", groups[1].Name)
	}
}

func TestNodeGroupStore_ReplaceAll(t *testing.T) {
	dir := t.TempDir()
	s := NewNodeGroupStore(filepath.Join(dir, "ng.json"))

	_, _ = s.Add(NodeGroup{
		Name:          "old",
		LabelSelector: map[string]string{"a": "1"},
	})

	replacement := []NodeGroup{
		{Name: "new1", LabelSelector: map[string]string{"b": "2"}, CreatedAt: "2026-01-01T00:00:00Z"},
		{Name: "new2", LabelSelector: map[string]string{"c": "3"}, CreatedAt: "2026-01-02T00:00:00Z"},
	}
	s.ReplaceAll(replacement)

	got := s.List()
	if len(got) != 2 {
		t.Fatalf("expected 2 groups after ReplaceAll, got %d", len(got))
	}
	if got[0].Name != "new1" || got[1].Name != "new2" {
		t.Fatalf("unexpected groups: %v", got)
	}
}

// ─── API handler tests ─────────────────────────────────────────────────────

func TestApiNodeGroups_MethodNotAllowed(t *testing.T) {
	origStore := globalNodeGroups
	defer func() { globalNodeGroups = origStore }()
	globalNodeGroups = NewNodeGroupStore(filepath.Join(t.TempDir(), "ng.json"))

	// PATCH is not a supported method.
	r := httptest.NewRequest(http.MethodPatch, "/api/cluster/node-groups", nil)
	r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, RoleAdmin))
	w := httptest.NewRecorder()
	apiNodeGroups(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestApiNodeGroups_DELETE_NoName(t *testing.T) {
	origStore := globalNodeGroups
	defer func() { globalNodeGroups = origStore }()
	globalNodeGroups = NewNodeGroupStore(filepath.Join(t.TempDir(), "ng.json"))

	r := httptest.NewRequest(http.MethodDelete, "/api/cluster/node-groups", nil)
	r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, RoleAdmin))
	w := httptest.NewRecorder()
	apiNodeGroups(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for DELETE without name, got %d", w.Code)
	}
}

func TestApiNodeGroups_GET(t *testing.T) {
	origStore := globalNodeGroups
	origCluster := globalClusterStore
	defer func() {
		globalNodeGroups = origStore
		globalClusterStore = origCluster
	}()

	globalNodeGroups = NewNodeGroupStore(filepath.Join(t.TempDir(), "ng.json"))
	// Reset cluster store so no nodes are present.
	globalClusterStore = &ClusterStore{
		st: ClusterState{
			Nodes:  make(map[string]*EnrolledNode),
			Tokens: make(map[string]*EnrollToken),
		},
	}

	// Add a group.
	_, _ = globalNodeGroups.Add(NodeGroup{
		Name:          "test-group",
		LabelSelector: map[string]string{"env": "test"},
	})

	r := httptest.NewRequest(http.MethodGet, "/api/cluster/node-groups", nil)
	r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, RoleViewer))
	w := httptest.NewRecorder()
	apiNodeGroups(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Groups []NodeGroupInfo `json:"groups"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(resp.Groups))
	}
	if resp.Groups[0].Name != "test-group" {
		t.Fatalf("expected test-group, got %s", resp.Groups[0].Name)
	}
	if resp.Groups[0].NodeCount != 0 {
		t.Fatalf("expected 0 node count, got %d", resp.Groups[0].NodeCount)
	}
}

func TestApiNodeGroups_POST_Unauthorized(t *testing.T) {
	origStore := globalNodeGroups
	defer func() { globalNodeGroups = origStore }()
	globalNodeGroups = NewNodeGroupStore(filepath.Join(t.TempDir(), "ng.json"))

	body := `{"name":"blocked","label_selector":{"a":"1"}}`
	r := httptest.NewRequest(http.MethodPost, "/api/cluster/node-groups", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	// Inject RoleViewer — should be rejected because POST requires admin.
	r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, RoleViewer))
	w := httptest.NewRecorder()
	apiNodeGroups(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer POST, got %d: %s", w.Code, w.Body.String())
	}

	// Verify group was not created.
	if got := globalNodeGroups.List(); len(got) != 0 {
		t.Fatalf("expected 0 groups, got %d", len(got))
	}
}
