// Package catgroup is the named category-group engine: bundles of URL
// categories (e.g. "AI", "Marketing", "Messaging") under a single name
// (e.g. "Prod Allowed") that policy rules reference instead of individual
// categories, enabling Zero Trust postures like: Auth Users → Prod Allowed
// → Allow, Deny Any Any. Extracted from package main's categorygroup.go per
// a recorded ADR-0002-style design (post-program extraction).
//
// Performance: each group maintains a pre-computed catSet (map[string]bool)
// for O(1) membership checks on the proxy hot path. The set is rebuilt on
// every mutation (admin edit, UT1 sync, cluster sync) — never during
// request evaluation. All category names are normalized to lowercase.
//
// Concurrency: RWMutex protects the store. Read path (GetByName) takes
// RLock; write path (ReplaceAll) builds the new map outside the lock, then
// swaps the pointer under a brief Lock.
//
// package main keeps: the `globalCategoryGroups` singleton, the API
// handlers, cluster sync, rollback, and — deliberately — the HOST-level
// match (`categoryGroupMatchesHost`): resolving a host to its category is
// the two-tier catStore+communityDB fusion that lives in main (same verdict
// as the urlcat extraction), so this engine exposes the pure
// MatchesCategory instead.
package catgroup

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// Group is a named bundle of URL category names.
type Group struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Categories []string `json:"categories"`
	CreatedAt  string   `json:"created_at,omitempty"`
	UpdatedAt  string   `json:"updated_at,omitempty"`

	// catSet is a pre-computed lowercase set for O(1) membership checks.
	// Not serialized — rebuilt on Load/Add/Update/ReplaceAll.
	catSet map[string]bool
}

// Store manages persistent category groups with O(1) lookups.
type Store struct {
	mu     sync.RWMutex
	groups map[string]*Group // keyed by lowercase name
	order  []string          // insertion order for stable list output
	path   string
}

// New builds an empty store.
func New() *Store {
	return &Store{groups: make(map[string]*Group)}
}

// normCats normalizes a category list to lowercase, trimmed, deduplicated.
func normCats(cats []string) []string {
	seen := make(map[string]bool, len(cats))
	out := make([]string, 0, len(cats))
	for _, c := range cats {
		c = strings.ToLower(strings.TrimSpace(c))
		if c != "" && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// buildCatSet creates the O(1) lookup map from a category list.
func buildCatSet(cats []string) map[string]bool {
	m := make(map[string]bool, len(cats))
	for _, c := range cats {
		m[strings.ToLower(c)] = true
	}
	return m
}

// Load reads groups from a JSON file and pre-computes catSets.
func (s *Store) Load(path string) error {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()

	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured path
	if err != nil {
		return nil // first run — no file
	}
	var groups []Group
	if err := json.Unmarshal(data, &groups); err != nil {
		obs.Printf("CategoryGroups: unmarshal error from %s", path)
		return err
	}

	built := make(map[string]*Group, len(groups))
	order := make([]string, 0, len(groups))
	for i := range groups {
		g := &groups[i]
		g.Categories = normCats(g.Categories)
		g.catSet = buildCatSet(g.Categories)
		key := strings.ToLower(g.Name)
		built[key] = g
		order = append(order, key)
	}

	s.mu.Lock()
	s.groups = built
	s.order = order
	s.mu.Unlock()

	obs.Printf("CategoryGroups: loaded %d group(s) from %s", len(groups), path)
	return nil
}

// Save persists the current groups to disk (atomic write).
func (s *Store) Save() {
	s.mu.RLock()
	path := s.path
	if path == "" {
		s.mu.RUnlock()
		return
	}
	groups := make([]Group, 0, len(s.order))
	for _, key := range s.order {
		if g, ok := s.groups[key]; ok {
			groups = append(groups, Group{
				ID: g.ID, Name: g.Name, Categories: g.Categories,
				CreatedAt: g.CreatedAt, UpdatedAt: g.UpdatedAt,
			})
		}
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(groups, "", "  ")
	if err != nil {
		return
	}
	// Bucket-4 durability hardening: fileutil.AtomicWrite gives unique
	// tmp + chmod + fsync(file) + rename + best-effort fsync(parent
	// dir) — replaces the previous os.WriteFile+os.Rename which was
	// atomic-via-rename but NOT fsynced (P6.1 UC-1).
	_ = fileutil.AtomicWrite(path, data, 0o600)
}

// List returns a copy of all groups (safe for JSON serialization).
func (s *Store) List() []Group {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Group, 0, len(s.order))
	for _, key := range s.order {
		if g, ok := s.groups[key]; ok {
			out = append(out, Group{
				ID: g.ID, Name: g.Name, Categories: g.Categories,
				CreatedAt: g.CreatedAt, UpdatedAt: g.UpdatedAt,
			})
		}
	}
	return out
}

// GetByName returns a group by name (case-insensitive). O(1).
// Returns nil if not found. The returned pointer is safe to read
// concurrently — catSet is immutable between mutations.
func (s *Store) GetByName(name string) *Group {
	s.mu.RLock()
	g := s.groups[strings.ToLower(name)]
	s.mu.RUnlock()
	return g
}

// Add creates a new category group. Returns error if name already exists.
func (s *Store) Add(name string, categories []string) (*Group, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	cats := normCats(categories)
	key := strings.ToLower(name)
	now := time.Now().UTC().Format(time.RFC3339)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.groups[key]; exists {
		return nil, fmt.Errorf("group %q already exists", name)
	}

	g := &Group{
		ID:         uuid.NewString()[:12],
		Name:       name,
		Categories: cats,
		catSet:     buildCatSet(cats),
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	s.groups[key] = g
	s.order = append(s.order, key)
	return g, nil
}

// Update replaces the categories in an existing group. Returns error if not found.
func (s *Store) Update(name string, categories []string) error {
	cats := normCats(categories)
	key := strings.ToLower(strings.TrimSpace(name))

	s.mu.Lock()
	defer s.mu.Unlock()

	g, ok := s.groups[key]
	if !ok {
		return fmt.Errorf("group %q not found", name)
	}
	g.Categories = cats
	g.catSet = buildCatSet(cats)
	g.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return nil
}

// Delete removes a group by name. Returns error if not found.
func (s *Store) Delete(name string) error {
	key := strings.ToLower(strings.TrimSpace(name))

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.groups[key]; !ok {
		return fmt.Errorf("group %q not found", name)
	}
	delete(s.groups, key)
	// Remove from order.
	for i, k := range s.order {
		if k == key {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	return nil
}

// ReplaceAll atomically replaces all groups (used by cluster config sync).
// Builds catSets outside the lock for zero contention.
func (s *Store) ReplaceAll(groups []Group) {
	built := make(map[string]*Group, len(groups))
	order := make([]string, 0, len(groups))
	for i := range groups {
		g := &groups[i]
		g.Categories = normCats(g.Categories)
		g.catSet = buildCatSet(g.Categories)
		key := strings.ToLower(g.Name)
		built[key] = g
		order = append(order, key)
	}

	s.mu.Lock()
	s.groups = built
	s.order = order
	s.mu.Unlock()
}

// ContainsCategory returns true if any group references the given category name.
// Used for referential integrity when deleting a base category.
func (s *Store) ContainsCategory(catName string) (groupName string, found bool) {
	cat := strings.ToLower(strings.TrimSpace(catName))
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, g := range s.groups {
		if g.catSet[cat] {
			return g.Name, true
		}
	}
	return "", false
}

// MatchesCategory reports whether the named group contains the given
// (already-resolved) category. This is the engine half of the hot-path
// group match: package main's categoryGroupMatchesHost resolves host →
// category through its two-tier fusion, then calls this O(1) check.
// Unknown group = no match (fail-closed); empty category never matches.
func (s *Store) MatchesCategory(groupName, category string) bool {
	g := s.GetByName(groupName)
	if g == nil || category == "" {
		return false
	}
	return g.catSet[strings.ToLower(category)]
}

// Names returns all group names (for UI dropdowns).
func (s *Store) Names() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.order))
	for _, key := range s.order {
		if g, ok := s.groups[key]; ok {
			out = append(out, g.Name)
		}
	}
	return out
}

// Path reports the persistence path ("" = persistence disabled).
func (s *Store) Path() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.path
}

// SetPathForTest points persistence at path without loading.
func (s *Store) SetPathForTest(path string) {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()
}
