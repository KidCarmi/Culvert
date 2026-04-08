package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

// ─── Node Group Definitions ─────────────────────────────────────────────────

// NodeGroup defines a named collection of Data Plane nodes matched by label
// selectors.  Used for geo-aware grouping, tiered routing, and policy scoping.
type NodeGroup struct {
	Name          string            `json:"name"`
	Description   string            `json:"description,omitempty"`
	LabelSelector map[string]string `json:"label_selector"` // all must match
	Priority      int               `json:"priority,omitempty"`
	CreatedAt     string            `json:"created_at"`
}

// NodeGroupInfo extends NodeGroup with runtime membership info for the API.
type NodeGroupInfo struct {
	NodeGroup
	NodeCount int      `json:"node_count"`
	NodeIDs   []string `json:"node_ids"`
}

// NodeGroupStore persists node group definitions to a JSON file.
type NodeGroupStore struct {
	mu     sync.RWMutex
	groups []NodeGroup
	path   string
}

// globalNodeGroups is the singleton node-group store.
var globalNodeGroups *NodeGroupStore

// NewNodeGroupStore loads (or creates) a NodeGroupStore backed by path.
func NewNodeGroupStore(path string) *NodeGroupStore {
	s := &NodeGroupStore{path: path}
	data, err := os.ReadFile(path)
	if err == nil {
		if err2 := json.Unmarshal(data, &s.groups); err2 != nil {
			logger.Printf("NodeGroups: failed to parse %q: %v", sanitizeLog(path), err2)
			s.groups = nil
		}
	}
	if s.groups == nil {
		s.groups = []NodeGroup{}
	}
	return s
}

// Get returns a copy of a named group and true if found.
func (s *NodeGroupStore) Get(name string) (NodeGroup, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, g := range s.groups {
		if g.Name == name {
			return g, true
		}
	}
	return NodeGroup{}, false
}

// List returns a copy of all node groups.
func (s *NodeGroupStore) List() []NodeGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]NodeGroup, len(s.groups))
	copy(out, s.groups)
	return out
}

// Add validates and appends a new node group.
func (s *NodeGroupStore) Add(g NodeGroup) (NodeGroup, error) {
	if g.Name == "" {
		return NodeGroup{}, fmt.Errorf("name is required")
	}
	if len(g.LabelSelector) == 0 {
		return NodeGroup{}, fmt.Errorf("label_selector must not be empty")
	}
	// Validate label keys/values: DNS-like alphanumeric + dots/dashes/colons/underscores.
	for k, v := range g.LabelSelector {
		if k == "" {
			return NodeGroup{}, fmt.Errorf("label key must not be empty")
		}
		if len(k) > 253 || len(v) > 253 {
			return NodeGroup{}, fmt.Errorf("label key/value must be <= 253 characters")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.groups {
		if existing.Name == g.Name {
			return NodeGroup{}, fmt.Errorf("group %q already exists", g.Name)
		}
	}
	g.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	s.groups = append(s.groups, g)
	s.saveLocked()
	return g, nil
}

// Delete removes a node group by name.  Returns true if found and removed.
func (s *NodeGroupStore) Delete(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, g := range s.groups {
		if g.Name == name {
			s.groups = append(s.groups[:i], s.groups[i+1:]...)
			s.saveLocked()
			return true
		}
	}
	return false
}

// Save persists the current groups to disk.
func (s *NodeGroupStore) Save() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.saveLocked()
}

// saveLocked writes groups to disk.  Caller must hold at least a read lock.
func (s *NodeGroupStore) saveLocked() {
	data, err := json.MarshalIndent(s.groups, "", "  ")
	if err != nil {
		logger.Printf("NodeGroups: marshal error: %v", err)
		return
	}
	if err := os.WriteFile(s.path, data, 0o600); err != nil {
		logger.Printf("NodeGroups: write error: %v", err)
	}
}

// ReplaceAll atomically replaces all groups (used by config snapshot sync).
func (s *NodeGroupStore) ReplaceAll(groups []NodeGroup) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groups = make([]NodeGroup, len(groups))
	copy(s.groups, groups)
	s.saveLocked()
}

// MatchingGroups returns the names of groups whose label selectors are
// satisfied by the given labels map.  A group matches when every key-value
// pair in its LabelSelector exists in labels.
func (s *NodeGroupStore) MatchingGroups(labels map[string]string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var names []string
	for _, g := range s.groups {
		if labelsMatch(g.LabelSelector, labels) {
			names = append(names, g.Name)
		}
	}
	return names
}

// NodesInGroup filters the provided nodes, returning only those whose labels
// satisfy the named group's selector.
func (s *NodeGroupStore) NodesInGroup(name string, nodes []EnrolledNode) []EnrolledNode {
	s.mu.RLock()
	var sel map[string]string
	for _, g := range s.groups {
		if g.Name == name {
			sel = g.LabelSelector
			break
		}
	}
	s.mu.RUnlock()
	if sel == nil {
		return nil
	}
	var out []EnrolledNode
	for i := range nodes {
		if labelsMatch(sel, nodes[i].Labels) {
			out = append(out, nodes[i])
		}
	}
	return out
}

// labelsMatch returns true when every k/v in selector exists in labels.
func labelsMatch(selector, labels map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// ─── Admin API ──────────────────────────────────────────────────────────────

// apiNodeGroups handles GET / POST / DELETE on /api/cluster/node-groups.
func apiNodeGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		listNodeGroupsAPI(w)
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		createNodeGroupAPI(w, r)
	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		deleteNodeGroupAPI(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func listNodeGroupsAPI(w http.ResponseWriter) {
	groups := globalNodeGroups.List()
	var nodes []EnrolledNode
	if globalClusterStore != nil {
		nodes = globalClusterStore.ListNodes()
	}
	infos := make([]NodeGroupInfo, len(groups))
	for i, g := range groups {
		var ids []string
		for j := range nodes {
			if labelsMatch(g.LabelSelector, nodes[j].Labels) {
				ids = append(ids, nodes[j].NodeID)
			}
		}
		if ids == nil {
			ids = []string{}
		}
		sort.Strings(ids)
		infos[i] = NodeGroupInfo{
			NodeGroup: g,
			NodeCount: len(ids),
			NodeIDs:   ids,
		}
	}
	jsonOK(w, map[string]any{"groups": infos})
}

func createNodeGroupAPI(w http.ResponseWriter, r *http.Request) {
	var g NodeGroup
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	created, err := globalNodeGroups.Add(g)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	auditEvent(r, "nodegroup.add", sanitizeLog(created.Name), fmt.Sprintf("label_selector=%v", created.LabelSelector))
	jsonOK(w, map[string]any{"ok": true, "group": created})
}

func deleteNodeGroupAPI(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name query parameter is required", http.StatusBadRequest)
		return
	}
	if !globalNodeGroups.Delete(name) {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	auditEvent(r, "nodegroup.delete", sanitizeLog(name), "deleted")
	jsonOK(w, map[string]any{"ok": true})
}

// apiNodeGroupMembership returns detailed membership info for a specific group (F9).
// GET /api/node-groups/membership?name=GroupName
func apiNodeGroupMembership(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name query parameter is required", http.StatusBadRequest)
		return
	}
	group, ok := globalNodeGroups.Get(name)
	if !ok {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}

	var nodes []EnrolledNode
	if globalClusterStore != nil {
		nodes = globalClusterStore.ListNodes()
	}

	type memberInfo struct {
		NodeID    string            `json:"node_id"`
		IPAddress string            `json:"ip_address"`
		Status    string            `json:"status"`
		Labels    map[string]string `json:"labels"`
		Version   string            `json:"version"`
	}
	var members []memberInfo
	for i := range nodes {
		if labelsMatch(group.LabelSelector, nodes[i].Labels) {
			members = append(members, memberInfo{
				NodeID:    nodes[i].NodeID,
				IPAddress: nodes[i].IPAddress,
				Status:    nodes[i].Status,
				Labels:    nodes[i].Labels,
				Version:   nodes[i].Version,
			})
		}
	}
	if members == nil {
		members = []memberInfo{}
	}
	jsonOK(w, map[string]any{
		"group":   group,
		"members": members,
		"count":   len(members),
	})
}
