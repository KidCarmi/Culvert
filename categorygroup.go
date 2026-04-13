package main

// categorygroup.go — Named Category Groups for policy rules.
//
// A CategoryGroup bundles multiple URL categories (e.g. "AI", "Marketing",
// "Messaging") under a single name (e.g. "Prod Allowed"). Policy rules
// reference the group name instead of individual categories, enabling
// Zero Trust postures like: Auth Users → Prod Allowed → Allow, Deny Any Any.
//
// Performance: each group maintains a pre-computed catSet (map[string]bool)
// for O(1) membership checks on the proxy hot path. The set is rebuilt on
// every mutation (admin edit, UT1 sync, cluster sync) — never during request
// evaluation. All category names are normalized to lowercase.
//
// Concurrency: RWMutex protects the store. Read path (GetByName) takes RLock;
// write path (ReplaceAll) builds the new map outside the lock, then swaps the
// pointer under a brief Lock.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// CategoryGroup is a named bundle of URL category names.
type CategoryGroup struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Categories []string `json:"categories"`
	CreatedAt  string   `json:"created_at,omitempty"`
	UpdatedAt  string   `json:"updated_at,omitempty"`

	// catSet is a pre-computed lowercase set for O(1) membership checks.
	// Not serialized — rebuilt on Load/Add/Update/ReplaceAll.
	catSet map[string]bool
}

// CategoryGroupStore manages persistent category groups with O(1) lookups.
type CategoryGroupStore struct {
	mu     sync.RWMutex
	groups map[string]*CategoryGroup // keyed by lowercase name
	order  []string                  // insertion order for stable list output
	path   string
}

var globalCategoryGroups = &CategoryGroupStore{
	groups: make(map[string]*CategoryGroup),
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
func (s *CategoryGroupStore) Load(path string) error {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil // first run — no file
	}
	var groups []CategoryGroup
	if err := json.Unmarshal(data, &groups); err != nil {
		logger.Printf("CategoryGroups: unmarshal error from %s", path)
		return err
	}

	built := make(map[string]*CategoryGroup, len(groups))
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

	logger.Printf("CategoryGroups: loaded %d group(s) from %s", len(groups), path)
	return nil
}

// Save persists the current groups to disk (atomic write).
func (s *CategoryGroupStore) Save() {
	s.mu.RLock()
	path := s.path
	if path == "" {
		s.mu.RUnlock()
		return
	}
	groups := make([]CategoryGroup, 0, len(s.order))
	for _, key := range s.order {
		if g, ok := s.groups[key]; ok {
			groups = append(groups, CategoryGroup{
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
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// List returns a copy of all groups (safe for JSON serialization).
func (s *CategoryGroupStore) List() []CategoryGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CategoryGroup, 0, len(s.order))
	for _, key := range s.order {
		if g, ok := s.groups[key]; ok {
			out = append(out, CategoryGroup{
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
func (s *CategoryGroupStore) GetByName(name string) *CategoryGroup {
	s.mu.RLock()
	g := s.groups[strings.ToLower(name)]
	s.mu.RUnlock()
	return g
}

// Add creates a new category group. Returns error if name already exists.
func (s *CategoryGroupStore) Add(name string, categories []string) (*CategoryGroup, error) {
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

	g := &CategoryGroup{
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
func (s *CategoryGroupStore) Update(name string, categories []string) error {
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
func (s *CategoryGroupStore) Delete(name string) error {
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
func (s *CategoryGroupStore) ReplaceAll(groups []CategoryGroup) {
	built := make(map[string]*CategoryGroup, len(groups))
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
func (s *CategoryGroupStore) ContainsCategory(catName string) (groupName string, found bool) {
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

// MatchesHost returns true if the given host belongs to any category in the group.
// This is the hot-path function called during policy evaluation.
// Uses lookupHostCategory (existing) then O(1) catSet check.
func (s *CategoryGroupStore) MatchesHost(groupName, host string) bool {
	g := s.GetByName(groupName)
	if g == nil {
		return false // unknown group = no match (fail-closed)
	}
	// lookupHostCategory returns (categoryName, tier, matchedBy).
	hostCat, _, _ := lookupHostCategory(host)
	if hostCat == "" {
		return false // host not in any category
	}
	return g.catSet[strings.ToLower(hostCat)]
}

// Names returns all group names (for UI dropdowns).
func (s *CategoryGroupStore) Names() []string {
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
