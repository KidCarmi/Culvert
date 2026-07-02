// Package nodegroup is the node-group definition store: named collections of
// Data-Plane nodes matched by label selectors (geo-aware grouping, tiered
// routing, policy scoping), with atomic JSON persistence. It is extracted from
// package main per ADR-0002; the admin API handlers, the EnrolledNode-typed
// membership filter, and the globalNodeGroups singleton stay in main
// (nodegroup.go shim).
package nodegroup

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// Group defines a named collection of Data Plane nodes matched by label
// selectors. Used for geo-aware grouping, tiered routing, and policy scoping.
type Group struct {
	Name          string            `json:"name"`
	Description   string            `json:"description,omitempty"`
	LabelSelector map[string]string `json:"label_selector"` // all must match
	Priority      int               `json:"priority,omitempty"`
	CreatedAt     string            `json:"created_at"`
}

// Store persists node group definitions to a JSON file.
type Store struct {
	mu     sync.RWMutex
	groups []Group
	path   string
}

// NewStore loads (or creates) a Store backed by path.
func NewStore(path string) *Store {
	s := &Store{path: path}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured store path
	if err == nil {
		if err2 := json.Unmarshal(data, &s.groups); err2 != nil {
			obs.Printf("NodeGroups: failed to parse %q: %v", obs.Sanitize(path), err2)
			s.groups = nil
		}
	}
	if s.groups == nil {
		s.groups = []Group{}
	}
	// D1.1h: surface groups missing required fields. Loader keeps the
	// entry; warn so operators can spot match-nothing groups.
	for i, g := range s.groups {
		if g.Name == "" || len(g.LabelSelector) == 0 {
			obs.Printf("Loader: node_groups.json: group[%d] missing required field(s) at %q — keeping (D1.2-flag-F6)", i, obs.Sanitize(path))
		}
	}
	return s
}

// Get returns a copy of a named group and true if found.
func (s *Store) Get(name string) (Group, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, g := range s.groups {
		if g.Name == name {
			return g, true
		}
	}
	return Group{}, false
}

// List returns a copy of all node groups.
func (s *Store) List() []Group {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Group, len(s.groups))
	copy(out, s.groups)
	return out
}

// Add validates and appends a new node group.
func (s *Store) Add(g Group) (Group, error) {
	if g.Name == "" {
		return Group{}, fmt.Errorf("name is required")
	}
	if len(g.LabelSelector) == 0 {
		return Group{}, fmt.Errorf("label_selector must not be empty")
	}
	// Validate label keys/values: DNS-like alphanumeric + dots/dashes/colons/underscores.
	for k, v := range g.LabelSelector {
		if k == "" {
			return Group{}, fmt.Errorf("label key must not be empty")
		}
		if len(k) > 253 || len(v) > 253 {
			return Group{}, fmt.Errorf("label key/value must be <= 253 characters")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.groups {
		if existing.Name == g.Name {
			return Group{}, fmt.Errorf("group %q already exists", g.Name)
		}
	}
	g.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	s.groups = append(s.groups, g)
	s.saveLocked()
	return g, nil
}

// Delete removes a node group by name. Returns true if found and removed.
func (s *Store) Delete(name string) bool {
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
func (s *Store) Save() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.saveLocked()
}

// saveLocked writes groups to disk. Caller must hold at least a read lock.
func (s *Store) saveLocked() {
	data, err := json.MarshalIndent(s.groups, "", "  ")
	if err != nil {
		obs.Printf("NodeGroups: marshal error: %v", err)
		return
	}
	if err := fileutil.AtomicWrite(s.path, data, 0o600); err != nil {
		obs.Printf("NodeGroups: write error: %v", err)
	}
}

// ReplaceAll atomically replaces all groups (used by config snapshot sync).
func (s *Store) ReplaceAll(groups []Group) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groups = make([]Group, len(groups))
	copy(s.groups, groups)
	s.saveLocked()
}

// MatchingGroups returns the names of groups whose label selectors are
// satisfied by the given labels map. A group matches when every key-value
// pair in its LabelSelector exists in labels.
func (s *Store) MatchingGroups(labels map[string]string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var names []string
	for _, g := range s.groups {
		if LabelsMatch(g.LabelSelector, labels) {
			names = append(names, g.Name)
		}
	}
	return names
}

// LabelsMatch returns true when every k/v in selector exists in labels.
func LabelsMatch(selector, labels map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}
