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
	// hostIndex/adminHostIndex are the reverse direction: lowercase host
	// pattern → the entry that owns it, for the LookupHost family. See hostRef.
	hostIndex      map[string]hostRef // ALL entries
	adminHostIndex map[string]hostRef // BuiltIn=false entries only
	path           string
}

// hostRef is one host pattern's owning entry, as recorded in the reverse index.
//
// entryIdx/patIdx are the pattern's position in s.entries and in that entry's
// Hosts slice. They exist to reproduce the ordering of the nested-loop scan the
// index replaced, which returned the FIRST entry (in s.entries order) holding a
// matching pattern and, within it, that entry's FIRST matching pattern. A host
// can match several patterns at once ("foo.example.com" matches both
// "foo.example.com" and "example.com"), so the lookup must pick a winner by the
// same rule rather than by specificity — otherwise a host listed in two
// categories could change category, silently re-pointing a policy rule.
//
// category/pattern are stored in the admin's ORIGINAL case: matchedBy is an
// admin-facing API contract that reports the configured pattern verbatim.
type hostRef struct {
	entryIdx int
	patIdx   int
	category string
	pattern  string
}

// beats reports whether r should win over other under the first-match ordering
// described on hostRef.
func (r hostRef) beats(other hostRef) bool {
	if r.entryIdx != other.entryIdx {
		return r.entryIdx < other.entryIdx
	}
	return r.patIdx < other.patIdx
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
// The maps it publishes are treated as IMMUTABLE once installed: every mutator
// calls rebuildIndex to swap in freshly-built replacements rather than editing
// a published map in place. That is what lets the read paths copy a map header
// under the lock and then scan it after releasing.
//
// That immutability is a correctness requirement, not a style choice. AddHost
// and RemoveHost used to patch the PUBLISHED inner maps in place while
// MatchesHost read them with no lock held (it copies the header under RLock,
// then releases before probing). That is a concurrent map read/write — a
// confirmed -race failure, and in the worst case a fatal, unrecoverable
// "concurrent map read and map write" throw that would take down an in-line
// gateway. Publishing replacements removes the write from under the readers.
//
// The cost is on the WRITE side, and it is real rather than free: a mutation is
// now O(total configured hosts) instead of an O(1) patch. Measured against a
// ~1157-pattern taxonomy, AddHost went from 404 ns to 690 us in isolation — but
// every mutator that reaches here also calls Save(), which re-marshals and
// rewrites the whole JSON file, so the end-to-end admin mutation went 1.01 ms →
// 1.35 ms (+34%). Paying ~340 us on an admin edit to take ~23 us off EVERY
// proxied request is the trade this package should make. See LookupHost.
//
// The one caller where that +34% compounds is mergeSaaSCategories (saas_feed.go),
// which calls AddHost once per new host and so already performed one full file
// rewrite per host before this change. Batching it is a separate fix.
func (s *Store) rebuildIndex() {
	idx := make(map[string]map[string]bool, len(s.entries))
	admin := make(map[string]map[string]bool)
	hostIdx := make(map[string]hostRef)
	adminHostIdx := make(map[string]hostRef)
	for entryIdx, e := range s.entries {
		key := strings.ToLower(e.Name)
		set := make(map[string]bool, len(e.Hosts))
		for patIdx, h := range e.Hosts {
			set[strings.ToLower(strings.TrimSuffix(h, "."))] = true
			// Keyed by ToLower ALONE — deliberately not TrimSuffix'd like the
			// forward index above. The nested-loop scan this replaces compared
			// against strings.ToLower(p) verbatim, so a pattern stored with a
			// trailing dot never matched a (dot-stripped) normalized host. That
			// quirk is preserved here rather than quietly repaired: changing
			// which hosts resolve to a category is a policy change, not a
			// performance one. Tracked as a follow-up.
			ref := hostRef{entryIdx: entryIdx, patIdx: patIdx, category: e.Name, pattern: h}
			pl := strings.ToLower(h)
			if cur, ok := hostIdx[pl]; !ok || ref.beats(cur) {
				hostIdx[pl] = ref
			}
			if !e.BuiltIn {
				if cur, ok := adminHostIdx[pl]; !ok || ref.beats(cur) {
					adminHostIdx[pl] = ref
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

// lookupHostIn resolves host through one of the reverse indices.
//
// A pattern p matches host h exactly when h == p or h ends in "."+p, so the
// complete candidate set is h itself plus each suffix of h that begins after a
// dot — at most one map probe per label. Among the candidates the first-match
// winner (see hostRef) is selected, which is what makes this identical to the
// linear scan it replaces rather than merely similar.
func lookupHostIn(idx map[string]hostRef, host string) (category, matchedBy string, ok bool) {
	h := hostutil.NormalizeHost(host)
	var best hostRef
	found := false
	if r, hit := idx[h]; hit {
		best, found = r, true
	}
	// '.' is a single byte that cannot occur inside a multi-byte UTF-8
	// sequence, so a byte scan finds exactly the label boundaries.
	for i := 0; i < len(h); i++ {
		if h[i] != '.' {
			continue
		}
		r, hit := idx[h[i+1:]]
		if !hit {
			continue
		}
		if !found || r.beats(best) {
			best, found = r, true
		}
	}
	if !found {
		return "", "", false
	}
	return best.category, best.pattern, true
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
	replaced := false
	for _, e := range s.entries {
		if !strings.EqualFold(e.Name, name) {
			continue
		}
		e.Hosts = hosts
		replaced = true
		break
	}
	if !replaced {
		s.entries = append(s.entries, &Entry{Name: name, Hosts: hosts, BuiltIn: builtIn})
	}
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
	idx := s.adminHostIndex
	s.mu.RUnlock()
	return lookupHostIn(idx, host)
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
//
// This sits on the policy hot path: package main's lookupHostCategory is called
// per category-group rule, per request. It used to scan every host pattern in
// every category, lowercasing each pattern and building a "."+pattern string to
// suffix-test — O(total configured hosts) per call. Against the shipped default
// taxonomy alone (~665 patterns across 27 categories) an uncategorized host —
// the common case in real traffic, since a miss cannot short-circuit and must
// scan everything — measured 23 us per call, versus 400 ns for the indexed
// MatchesHost next to it. A 50-rule category-group policy therefore spent over
// a millisecond of CPU in here on every single request.
//
// It now probes the reverse index once per label. matchedBy still reports the
// admin's configured pattern verbatim, and the winner is still chosen by
// first-match order (see hostRef), so results are unchanged.
func (s *Store) LookupHost(host string) (category, matchedBy string, ok bool) {
	s.mu.RLock()
	idx := s.hostIndex
	s.mu.RUnlock()
	return lookupHostIn(idx, host)
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
