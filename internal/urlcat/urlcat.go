// Package urlcat is the admin-managed URL-category engine: named categories
// with lowercase host-set indexing for O(labels) membership checks during
// policy evaluation, JSON file persistence, and the built-in + embedded-SaaS
// default seed list. Extracted from package main's policy.go per ADR-0002
// (policy.go decomposition Phase A).
//
// package main keeps the surfaces: the `catStore` singleton, the TWO-TIER
// category resolution (matchCategory / lookupHostCategory compose this store
// with the community BadgerDB feed), the API handlers, cluster sync, and
// config-version rollback — all through aliases.
package urlcat

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// Category names a URL category referenced by policy rules.
type Category string

// Built-in category names (the policy engine's rule vocabulary).
const (
	Social    Category = "Social Media"
	Malicious Category = "Malicious"
	News      Category = "News"
	Streaming Category = "Streaming"
	Gambling  Category = "Gambling"
	Adult     Category = "Adult"
	Any       Category = "Any"
)

// Entry is one named URL category with its list of host patterns.
type Entry struct {
	Name    string   `json:"name"`
	Hosts   []string `json:"hosts"`
	BuiltIn bool     `json:"builtIn"` // seeded from built-in defaults; editable by admin
}

// Store manages URL categories with thread-safe, file-backed persistence.
// index maps lowercase(category-name) → set of lowercase host strings for O(1)
// host membership checks during policy evaluation. adminIndex is the same,
// restricted to admin-created (BuiltIn=false) categories — the signed-feed
// F3b-4 cutover consults it so the SaaS taxonomy (BuiltIn=true) is served by
// the atomic effective view instead of double-served from here.
type Store struct {
	mu         sync.RWMutex
	entries    []*Entry
	index      map[string]map[string]bool // lowercase cat → lowercase host set (ALL entries)
	adminIndex map[string]map[string]bool // same, BuiltIn=false entries only
	// hostIndex / adminHostIndex are the REVERSE direction: lowercase host
	// pattern → the position of the first entry that declares it. They serve
	// LookupHost / LookupHostAdmin; see patternRef.
	hostIndex      map[string]patternRef
	adminHostIndex map[string]patternRef
	path           string
}

// patternRef locates one host pattern inside s.entries: entry position, then
// position within that entry's Hosts. Positions — not the resolved strings —
// because the ORDER is the resolution rule (see lookupIn), and because two
// int32s per pattern keeps the index small on a taxonomy with tens of
// thousands of hosts.
type patternRef struct {
	entry int32
	host  int32
}

// less reports whether r precedes o in the entry-then-host scan order that
// LookupHost's original nested loop walked.
func (r patternRef) less(o patternRef) bool {
	if r.entry != o.entry {
		return r.entry < o.entry
	}
	return r.host < o.host
}

// New builds a store over entries and its derived host index.
func New(entries []*Entry) *Store {
	s := &Store{entries: entries}
	s.rebuildIndex()
	return s
}

// rebuildIndex reconstructs every derived index from s.entries.
// Caller must hold s.mu (write or be the sole owner).
//
// It is the SINGLE maintenance path: the mutators call it wholesale rather
// than patching individual index keys. A full rebuild is O(total patterns),
// but every mutator that reaches here also calls Save(), which marshals the
// entire store to JSON and atomically rewrites the file — so the rebuild is
// noise next to the work already being done, and the positional hostIndex
// below cannot be patched incrementally anyway (deleting a category shifts
// every later entry position).
func (s *Store) rebuildIndex() {
	idx := make(map[string]map[string]bool, len(s.entries))
	admin := make(map[string]map[string]bool)
	hostIdx := make(map[string]patternRef)
	adminHostIdx := make(map[string]patternRef)
	for ei, e := range s.entries {
		key := strings.ToLower(e.Name)
		set := make(map[string]bool, len(e.Hosts))
		for hi, h := range e.Hosts {
			set[strings.ToLower(strings.TrimSuffix(h, "."))] = true

			// NOTE the deliberately DIFFERENT key normalization: the
			// category→hosts set above trims a trailing dot, the reverse
			// index does not. That mirrors LookupHost's original comparison
			// (strings.ToLower(p), no TrimSuffix) exactly. The two matchers
			// have disagreed on a "example.com."-shaped pattern since before
			// this index existed; reproducing the difference keeps this a
			// pure cost change. Reconciling them is a separate decision.
			ref := patternRef{entry: int32(ei), host: int32(hi)}
			pk := strings.ToLower(h)
			// First declaration wins: entries are walked in order, so an
			// already-present key was declared by an earlier (entry, host)
			// position and therefore outranks this one.
			if _, dup := hostIdx[pk]; !dup {
				hostIdx[pk] = ref
			}
			if !e.BuiltIn {
				if _, dup := adminHostIdx[pk]; !dup {
					adminHostIdx[pk] = ref
				}
			}
		}
		idx[key] = set
		if !e.BuiltIn {
			admin[key] = set
		}
	}
	s.index = idx
	s.adminIndex = admin
	s.hostIndex = hostIdx
	s.adminHostIndex = adminHostIdx
}

// defaultCategoriesJSON is the embedded SaaS category seed list.
//
//go:embed default_categories.json
var defaultCategoriesJSON []byte

// DefaultEntries returns the built-in hardcoded categories merged with the
// embedded SaaS category seed list.
func DefaultEntries() []*Entry {
	// Start with the built-in hardcoded categories.
	entries := []*Entry{
		{Name: "Social Media", BuiltIn: true, Hosts: []string{
			"facebook.com", "twitter.com", "x.com", "instagram.com",
			"tiktok.com", "linkedin.com", "reddit.com", "snapchat.com", "pinterest.com",
		}},
		{Name: "Malicious", BuiltIn: true, Hosts: []string{
			"malware.com", "phishing.com", "eicar.org",
		}},
		{Name: "News", BuiltIn: true, Hosts: []string{
			"cnn.com", "bbc.com", "bbc.co.uk", "reuters.com", "nytimes.com",
			"theguardian.com", "foxnews.com", "nbcnews.com", "apnews.com",
		}},
		{Name: "Streaming", BuiltIn: true, Hosts: []string{
			"netflix.com", "youtube.com", "twitch.tv", "hulu.com",
			"disneyplus.com", "spotify.com", "primevideo.com",
		}},
		{Name: "Gambling", BuiltIn: true, Hosts: []string{
			"bet365.com", "pokerstars.com", "draftkings.com", "fanduel.com",
		}},
		{Name: "Adult", BuiltIn: true, Hosts: []string{}},
	}

	// Merge embedded SaaS categories (AI, Marketing, Messaging, etc.).
	var saas []Entry
	if json.Unmarshal(defaultCategoriesJSON, &saas) == nil {
		for i := range saas {
			e := &saas[i]
			e.BuiltIn = true
			entries = append(entries, e)
		}
	}
	return entries
}

// Load reads categories from a JSON file. If the file does not exist the
// built-in defaults are seeded and written to disk.
func (s *Store) Load(path string) error {
	s.path = path
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured path
	if err != nil {
		if os.IsNotExist(err) {
			s.mu.Lock()
			s.entries = DefaultEntries()
			s.rebuildIndex()
			s.mu.Unlock()
			s.Save()
			return nil
		}
		return err
	}
	var entries []*Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}
	s.mu.Lock()
	s.entries = entries
	s.rebuildIndex()
	s.mu.Unlock()
	return nil
}

// Save atomically persists categories to disk.
func (s *Store) Save() {
	if s.path == "" {
		return
	}
	s.mu.RLock()
	data, err := json.MarshalIndent(s.entries, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return
	}
	// Bucket-4 durability hardening: fileutil.AtomicWrite gives unique
	// tmp + chmod + fsync(file) + rename + best-effort fsync(parent
	// dir) — replaces the previous os.WriteFile+os.Rename which was
	// atomic-via-rename but NOT fsynced (P6.1 UC-1).
	_ = fileutil.AtomicWrite(s.path, data, 0o600)
}

// All returns a copy of all category entries.
func (s *Store) All() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, len(s.entries))
	for i, e := range s.entries {
		cp := *e
		cp.Hosts = append([]string(nil), e.Hosts...)
		out[i] = cp
	}
	return out
}

// ReplaceAll atomically replaces all categories (used by cluster config sync).
func (s *Store) ReplaceAll(cats []Entry) {
	s.mu.Lock()
	s.entries = make([]*Entry, len(cats))
	for i := range cats {
		cp := cats[i]
		cp.Hosts = append([]string(nil), cats[i].Hosts...)
		s.entries[i] = &cp
	}
	s.rebuildIndex()
	s.mu.Unlock()
}

// Set creates or replaces the host list for a named category.
func (s *Store) Set(name string, hosts []string, builtIn bool) error {
	if name == "" {
		return fmt.Errorf("category name must not be empty")
	}
	if hosts == nil {
		hosts = []string{}
	}
	s.mu.Lock()
	for _, e := range s.entries {
		if !strings.EqualFold(e.Name, name) {
			continue
		}
		e.Hosts = hosts
		s.rebuildIndex()
		s.mu.Unlock()
		s.Save()
		return nil
	}
	s.entries = append(s.entries, &Entry{Name: name, Hosts: hosts, BuiltIn: builtIn})
	s.rebuildIndex()
	s.mu.Unlock()
	s.Save()
	return nil
}

// Delete removes a category by name. Returns an error if not found.
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	for i, e := range s.entries {
		if !strings.EqualFold(e.Name, name) {
			continue
		}
		s.entries = append(s.entries[:i], s.entries[i+1:]...)
		s.rebuildIndex()
		s.mu.Unlock()
		s.Save()
		return nil
	}
	s.mu.Unlock()
	return fmt.Errorf("category %q not found", name)
}

// AddHost appends a host to the named category (no-op if already present).
func (s *Store) AddHost(category, host string) error {
	s.mu.Lock()
	key := strings.ToLower(category)
	for _, e := range s.entries {
		if !strings.EqualFold(e.Name, category) {
			continue
		}
		host = hostutil.NormalizeHost(strings.TrimSpace(host))
		if s.index[key][host] {
			s.mu.Unlock()
			return nil // already present
		}
		e.Hosts = append(e.Hosts, host)
		s.rebuildIndex()
		s.mu.Unlock()
		s.Save()
		return nil
	}
	s.mu.Unlock()
	return fmt.Errorf("category %q not found", category)
}

// RemoveHost deletes a host from the named category.
func (s *Store) RemoveHost(category, host string) error {
	s.mu.Lock()
	for _, e := range s.entries {
		if strings.EqualFold(e.Name, category) {
			host = hostutil.NormalizeHost(strings.TrimSpace(host))
			for i, h := range e.Hosts {
				if hostutil.NormalizeHost(h) != host {
					continue
				}
				e.Hosts = append(e.Hosts[:i], e.Hosts[i+1:]...)
				s.rebuildIndex()
				s.mu.Unlock()
				s.Save()
				return nil
			}
			s.mu.Unlock()
			return fmt.Errorf("host %q not in category %q", host, category)
		}
	}
	s.mu.Unlock()
	return fmt.Errorf("category %q not found", category)
}

// GetByName finds a category by name (case-insensitive). Returns the live
// entry pointer (callers treat it as read-only outside the store's lock —
// pre-extraction contract preserved).
func (s *Store) GetByName(name string) *Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if strings.EqualFold(e.Name, name) {
			return e
		}
	}
	return nil
}

// MatchesHost checks whether host belongs to the named URL category.
// Uses the pre-built index for O(labels) lookup instead of O(N×M) iteration.
func (s *Store) MatchesHost(cat Category, host string) bool {
	host = hostutil.NormalizeHost(host)
	catKey := strings.ToLower(string(cat))

	s.mu.RLock()
	hostSet := s.index[catKey]
	s.mu.RUnlock()

	if hostSet == nil {
		return false
	}
	// Exact match.
	if hostSet[host] {
		return true
	}
	// Subdomain match: foo.example.com → check "example.com", "com", etc.
	for i, ch := range host {
		if ch == '.' && hostSet[host[i+1:]] {
			return true
		}
	}
	return false
}

// MatchesHostAdmin is MatchesHost restricted to admin-created (BuiltIn=false)
// categories. The signed-feed F3b-4 policy path consults this so the built-in /
// embedded SaaS taxonomy is served exclusively by the atomic effective view and
// never double-served (or served stale) from this store after a signed
// activation supersedes it. Same normalization + exact-then-suffix semantics as
// MatchesHost.
func (s *Store) MatchesHostAdmin(cat Category, host string) bool {
	host = hostutil.NormalizeHost(host)
	catKey := strings.ToLower(string(cat))

	s.mu.RLock()
	hostSet := s.adminIndex[catKey]
	s.mu.RUnlock()

	if hostSet == nil {
		return false
	}
	if hostSet[host] {
		return true
	}
	for i, ch := range host {
		if ch == '.' && hostSet[host[i+1:]] {
			return true
		}
	}
	return false
}

// LookupHostAdmin is LookupHost restricted to admin-created (BuiltIn=false)
// categories (the admin layer of the F3b-4 source-aware resolution). Same
// exact-or-subdomain grammar as LookupHost.
func (s *Store) LookupHostAdmin(host string) (category, matchedBy string, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lookupIn(s.adminHostIndex, host)
}

// BuiltInHostCategories returns a normalized host→category map over the
// BuiltIn=true entries (the embedded/seeded SaaS taxonomy + rule-vocabulary
// built-ins). It is the initial effective-view baseline for the signed feed:
// building it from the live store — not the compiled DefaultEntries — preserves
// any admin host-additions to built-in categories and any legacy-merged SaaS
// hosts already persisted, so the pre-signed-activation policy result is
// byte-identical to today's full-store match. Empty-host entries (e.g. UT1
// name-seeds) contribute nothing. Later keys win on collision (deterministic;
// callers hold no ordering contract on duplicate host keys across categories).
func (s *Store) BuiltInHostCategories() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string)
	for _, e := range s.entries {
		if !e.BuiltIn {
			continue
		}
		for _, h := range e.Hosts {
			nh := hostutil.NormalizeHost(strings.TrimSpace(h))
			if nh != "" {
				out[nh] = e.Name
			}
		}
	}
	return out
}

// LookupHost resolves a hostname to its category (exact + suffix match),
// returning the original-case category name and the pattern that matched.
// matchedBy is the admin's configured pattern verbatim, not a normalized form
// (admin URL-lookup API contract) — hence the index resolves back through
// s.entries rather than answering from a lowercase key.
func (s *Store) LookupHost(host string) (category, matchedBy string, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lookupIn(s.hostIndex, host)
}

// lookupIn resolves host against one of the reverse pattern indices. Caller
// must hold s.mu.
//
// Why this is not the nested scan it replaced: LookupHost is not an
// admin-API-only call. package main's lookupHostCategory (policy.go) reaches
// it, and categoryGroupMatchesHostRule (categorygroup.go) reaches THAT once
// per proxied request for every enabled access rule carrying a
// DestCategoryGroup — so its cost was O(every pattern in the taxonomy) on the
// request path, and the clean-traffic MISS is the worst case because it walks
// all of them. Measured on the SHIPPED default taxonomy (657 patterns, 27
// categories) that was ~24 us per lookup per rule, growing linearly:
// ~69 us at 1657 patterns, ~252 us at 5657.
//
// The set of patterns that can match h is fixed and tiny — h itself, plus the
// remainder after each '.' — so the scan is replaced by probing exactly those
// keys. Cost becomes O(labels in h) and independent of taxonomy size.
//
// The RESULT is unchanged, which is the load-bearing part: the old loop
// returned the first (entry, host) position whose lowercased pattern matched,
// and hostIndex records, per pattern, the first position declaring it. Taking
// the minimum position over the matching keys is therefore the same winner —
// including the case where a LESS specific pattern in an EARLIER category
// beats a more specific one in a later category, which a plain
// most-specific-suffix walk would silently invert. matchedBy stays the
// admin's verbatim configured pattern.
func (s *Store) lookupIn(idx map[string]patternRef, host string) (category, matchedBy string, ok bool) {
	h := hostutil.NormalizeHost(host)
	var best patternRef
	found := false
	consider := func(key string) {
		if r, hit := idx[key]; hit && (!found || r.less(best)) {
			best, found = r, true
		}
	}
	consider(h)
	// Every suffix of h that starts just past a '.' — the exact set the old
	// strings.HasSuffix(h, "."+pattern) test accepted. Byte iteration is safe:
	// '.' is ASCII, and UTF-8 continuation bytes are all >= 0x80, so no
	// multi-byte rune can contain this byte.
	for i := 0; i < len(h); i++ {
		if h[i] == '.' {
			consider(h[i+1:])
		}
	}
	if !found {
		return "", "", false
	}
	e := s.entries[best.entry]
	return e.Name, e.Hosts[best.host], true
}

// Path reports the persistence path ("" = persistence disabled).
func (s *Store) Path() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.path
}

// SetPathForTest points persistence at path without loading (Load on a
// missing file would seed the defaults; tests often want an EMPTY store
// that saves to a temp location).
func (s *Store) SetPathForTest(path string) {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()
}
