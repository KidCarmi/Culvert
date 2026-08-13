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
	lookup     map[string]lookupHit       // lowercase host pattern → answer (ALL entries)
	adminLook  map[string]lookupHit       // same, BuiltIn=false entries only
	path       string
}

// lookupHit is the answer LookupHost/LookupHostAdmin return for one indexed
// host pattern, plus the ordinal that pattern occupied in the linear
// (entry, host) scan these lookups used to perform.
//
// rank is what makes the index EQUIVALENT to that scan rather than merely
// similar. The scan returned the first pattern it reached that matched, in
// declaration order — NOT the most specific one. With entries
// [{A: "example.com"}, {B: "foo.example.com"}] and host "foo.example.com" it
// reached A's suffix pattern first and answered "A". A map probe that tried the
// exact host before its suffixes would answer "B" — a different policy
// decision. So the probe collects every pattern that matches and keeps the
// lowest rank, which is by construction the one the scan reached first.
type lookupHit struct {
	category string // e.Name, verbatim (original case) — API contract
	pattern  string // the configured host pattern, verbatim — API contract
	rank     int    // position in the linear (entry, host) scan order
}

// New builds a store over entries and its derived host index.
func New(entries []*Entry) *Store {
	s := &Store{entries: entries}
	s.rebuildIndex()
	return s
}

// rebuildIndex reconstructs every derived index from s.entries and publishes
// them as fresh maps. Caller must hold s.mu (write or be the sole owner).
//
// Publication is COPY-ON-WRITE, and that is load-bearing rather than stylistic:
// the read paths snapshot a map pointer under the read lock and then probe it
// with the lock released (the probe can be thousands of map reads, and holding
// the lock across it would stall every admin write behind the request path).
// That is only sound if a published map is never mutated afterwards, so every
// mutator rebuilds and republishes here instead of patching a live map. It used
// to patch: Set/AddHost/RemoveHost wrote into the very map MatchesHost was
// concurrently reading unlocked, which the race detector reports as a genuine
// data race between the admin category API and the per-request policy path
// (pinned by TestConcurrent_MatchesHostDuringAddHost).
//
// The cost moved onto the admin write is one pass over the taxonomy (~600 map
// inserts, tens of microseconds) and every mutator here already follows it with
// s.Save() — a JSON marshal plus an atomic file write, orders of magnitude
// more. The request path pays nothing.
func (s *Store) rebuildIndex() {
	idx := make(map[string]map[string]bool, len(s.entries))
	admin := make(map[string]map[string]bool)
	lookup := make(map[string]lookupHit)
	adminLook := make(map[string]lookupHit)
	rank := 0
	for _, e := range s.entries {
		key := strings.ToLower(e.Name)
		set := make(map[string]bool, len(e.Hosts))
		for _, h := range e.Hosts {
			set[strings.ToLower(strings.TrimSuffix(h, "."))] = true

			// The lookup index keys on strings.ToLower(h) with NO trailing-dot
			// trim, because that is exactly the key the scan it replaces
			// compared against (`pl := strings.ToLower(p)`). It deliberately
			// does NOT reuse the set key above, whose extra TrimSuffix belongs
			// to MatchesHost's grammar.
			//
			// First writer wins, so a pattern repeated across categories keeps
			// its lowest rank — the occurrence the scan reached first.
			pl := strings.ToLower(h)
			hit := lookupHit{category: e.Name, pattern: h, rank: rank}
			if _, dup := lookup[pl]; !dup {
				lookup[pl] = hit
			}
			if !e.BuiltIn {
				if _, dup := adminLook[pl]; !dup {
					adminLook[pl] = hit
				}
			}
			rank++
		}
		idx[key] = set
		if !e.BuiltIn {
			admin[key] = set
		}
	}
	s.index = idx
	s.adminIndex = admin
	s.lookup = lookup
	s.adminLook = adminLook
}

// lookupIn walks host's own suffix chain against idx and returns the matching
// pattern with the lowest rank — the one the linear scan would have reached
// first (see lookupHit).
//
// The candidate set is exactly the set the scan tested: a pattern p matched iff
// h == p or h ends with "."+p, and the strings satisfying that are h itself
// plus each h[i+1:] where h[i] is a dot. So this is O(labels) — a handful of
// probes for any real hostname — where the scan was O(total configured hosts).
func lookupIn(idx map[string]lookupHit, h string) (lookupHit, bool) {
	best, found := idx[h]
	// Byte indexing, not range: a UTF-8 continuation byte can never be 0x2E, so
	// scanning for '.' bytewise finds the same positions the rune loop did.
	for i := 0; i < len(h); i++ {
		if h[i] != '.' {
			continue
		}
		if hit, ok := idx[h[i+1:]]; ok && (!found || hit.rank < best.rank) {
			best, found = hit, true
		}
	}
	return best, found
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
	h := hostutil.NormalizeHost(host)
	s.mu.RLock()
	idx := s.adminLook
	s.mu.RUnlock()
	hit, found := lookupIn(idx, h)
	if !found {
		return "", "", false
	}
	return hit.category, hit.pattern, true
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
// returning the original-case category name and the admin's configured pattern
// verbatim — the admin URL-lookup API contract, which is why the lookup index
// carries both strings rather than reusing the lowercase membership index.
//
// This sits on the policy hot path, not just the admin API: a rule with a
// destination category GROUP resolves host → category through here on every
// request (policy.go categoryGroupMatchesHostRule → lookupHostCategory). It
// used to scan every configured host in every category, so the shipped taxonomy
// alone (~625 hosts) cost ~34us per rule per request — two orders of magnitude
// above the whole allow path — and the miss, which is the common case for
// ordinary destinations, was the branch that walked the entire list.
func (s *Store) LookupHost(host string) (category, matchedBy string, ok bool) {
	h := hostutil.NormalizeHost(host)
	s.mu.RLock()
	idx := s.lookup
	s.mu.RUnlock()
	hit, found := lookupIn(idx, h)
	if !found {
		return "", "", false
	}
	return hit.category, hit.pattern, true
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
