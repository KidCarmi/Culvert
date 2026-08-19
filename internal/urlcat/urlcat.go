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

	// lookupIdx / adminLookupIdx are the REVERSE indices — lowercase host
	// pattern → the entry that claims it — backing LookupHost /
	// LookupHostAdmin. See lookupHit for why the precedence order is carried.
	//
	// They are rebuilt LAZILY: every mutator clears lookupReady instead of
	// patching them, because AddHost is called once per host in the SaaS
	// feed-sync merge loop (saas_feed.go) and an eager rebuild there would be
	// O(hosts²). The first lookup after a mutation pays one rebuild.
	//
	// The flag is "ready", not "stale", so that the ZERO VALUE means "must
	// rebuild". A Store built as a struct literal rather than through New —
	// which tests do — would otherwise read a nil index and report every host
	// as uncategorized instead of scanning its entries.
	lookupIdx      map[string]lookupHit
	adminLookupIdx map[string]lookupHit
	lookupReady    bool

	path string
}

// lookupHit is one reverse-index cell: which category claims a host pattern,
// the pattern verbatim as the admin configured it, and the position that
// pattern held in the linear entry scan LookupHost used to perform.
//
// order is what makes the index EXACTLY equivalent to that scan rather than
// merely similar. The scan returned the first (entry, host) pair matching
// either exactly or as a dot-suffix, so when several patterns match one host
// — say "example.com" in an early category and "a.example.com" in a later one
// — the EARLIER pattern won, even though the later one is the more specific
// match. A plain host→category map would silently invert that and change which
// policy rule fires. Keeping the scan position lets the lookup reproduce the
// original winner by minimum order.
type lookupHit struct {
	name    string // Entry.Name, original case
	pattern string // the configured pattern, verbatim (admin URL-lookup contract)
	order   uint64 // entryIndex<<32 | hostIndex — the linear scan's precedence
}

// New builds a store over entries and its derived host index.
func New(entries []*Entry) *Store {
	s := &Store{entries: entries}
	s.rebuildIndex()
	return s
}

// rebuildIndex reconstructs the category→hosts indices from s.entries.
// Caller must hold s.mu (write or be the sole owner).
func (s *Store) rebuildIndex() {
	idx := make(map[string]map[string]bool, len(s.entries))
	admin := make(map[string]map[string]bool)
	for _, e := range s.entries {
		key := strings.ToLower(e.Name)
		set := make(map[string]bool, len(e.Hosts))
		for _, h := range e.Hosts {
			set[strings.ToLower(strings.TrimSuffix(h, "."))] = true
		}
		idx[key] = set
		if !e.BuiltIn {
			admin[key] = set
		}
	}
	s.index = idx
	s.adminIndex = admin
	s.lookupReady = false
}

// rebuildLookupIndex reconstructs the reverse host→category indices from
// s.entries. Caller must hold s.mu for writing (or be the sole owner).
func (s *Store) rebuildLookupIndex() {
	n := 0
	for _, e := range s.entries {
		n += len(e.Hosts)
	}
	all := make(map[string]lookupHit, n)
	admin := make(map[string]lookupHit)
	for ei := range s.entries {
		e := s.entries[ei]
		for hi, p := range e.Hosts {
			// strings.ToLower — NOT the forward index's ToLower+TrimSuffix
			// key — because the scan this replaces compared against exactly
			// that. A trailing-dot pattern must keep matching (or not) the
			// way it always has.
			pl := strings.ToLower(p)
			hit := lookupHit{name: e.Name, pattern: p, order: uint64(ei)<<32 | uint64(uint32(hi))}
			if cur, dup := all[pl]; !dup || hit.order < cur.order {
				all[pl] = hit
			}
			if !e.BuiltIn {
				if cur, dup := admin[pl]; !dup || hit.order < cur.order {
					admin[pl] = hit
				}
			}
		}
	}
	s.lookupIdx = all
	s.adminLookupIdx = admin
	s.lookupReady = true
}

// lookupIn resolves an already-normalized host against a reverse index using
// the same grammar as the scan it replaces: a pattern matches when it equals
// the host or is a dot-suffix of it. The candidate set is therefore the host
// itself plus each of its label suffixes — O(labels) map probes instead of
// O(total configured hosts) string comparisons — and the winner is the
// candidate with the lowest scan order.
func lookupIn(idx map[string]lookupHit, h string) (category, matchedBy string, ok bool) {
	// An empty index is the common shape for the admin-only lookup on a stock
	// appliance, where the whole taxonomy is BuiltIn. The scan this replaces
	// skipped those entries without comparing anything, so probing once per
	// label here would have made that case measurably slower (64 -> 94 ns)
	// rather than faster.
	if len(idx) == 0 {
		return "", "", false
	}

	var best lookupHit
	found := false
	if hit, hitOK := idx[h]; hitOK {
		best, found = hit, true
	}
	// Byte loop, not `range h`: '.' is ASCII, and no UTF-8 continuation byte
	// can be 0x2E, so byte-wise scanning finds exactly the same label
	// boundaries without decoding runes.
	for i := 0; i < len(h); i++ {
		if h[i] != '.' {
			continue
		}
		if hit, hitOK := idx[h[i+1:]]; hitOK && (!found || hit.order < best.order) {
			best, found = hit, true
		}
	}
	if !found {
		return "", "", false
	}
	return best.name, best.pattern, true
}

// resolveHost is the shared body of LookupHost and LookupHostAdmin. It reads
// under RLock on the hot path and only takes the write lock when a mutation
// has invalidated the reverse index.
func (s *Store) resolveHost(adminOnly bool, host string) (category, matchedBy string, ok bool) {
	h := hostutil.NormalizeHost(host)

	s.mu.RLock()
	if s.lookupReady {
		idx := s.lookupIdx
		if adminOnly {
			idx = s.adminLookupIdx
		}
		name, pattern, found := lookupIn(idx, h)
		s.mu.RUnlock()
		return name, pattern, found
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.lookupReady {
		s.rebuildLookupIndex()
	}
	idx := s.lookupIdx
	if adminOnly {
		idx = s.adminLookupIdx
	}
	return lookupIn(idx, h)
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
	// Both branches below mutate the entry set, so the reverse index is stale
	// either way.
	s.lookupReady = false
	key := strings.ToLower(name)
	set := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		set[strings.ToLower(strings.TrimSuffix(h, "."))] = true
	}
	for _, e := range s.entries {
		if !strings.EqualFold(e.Name, name) {
			continue
		}
		e.Hosts = hosts
		s.index[key] = set
		if e.BuiltIn {
			delete(s.adminIndex, key)
		} else {
			s.adminIndex[key] = set
		}
		s.mu.Unlock()
		s.Save()
		return nil
	}
	s.entries = append(s.entries, &Entry{Name: name, Hosts: hosts, BuiltIn: builtIn})
	s.index[key] = set
	if builtIn {
		delete(s.adminIndex, key)
	} else {
		s.adminIndex[key] = set
	}
	s.mu.Unlock()
	s.Save()
	return nil
}

// Delete removes a category by name. Returns an error if not found.
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	key := strings.ToLower(name)
	for i, e := range s.entries {
		if !strings.EqualFold(e.Name, name) {
			continue
		}
		s.entries = append(s.entries[:i], s.entries[i+1:]...)
		delete(s.index, key)
		delete(s.adminIndex, key)
		s.lookupReady = false
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
		s.index[key][host] = true
		s.lookupReady = false
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
	key := strings.ToLower(category)
	for _, e := range s.entries {
		if strings.EqualFold(e.Name, category) {
			host = hostutil.NormalizeHost(strings.TrimSpace(host))
			for i, h := range e.Hosts {
				if hostutil.NormalizeHost(h) != host {
					continue
				}
				e.Hosts = append(e.Hosts[:i], e.Hosts[i+1:]...)
				delete(s.index[key], host)
				s.lookupReady = false
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
	return s.resolveHost(true, host)
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

// LookupHost resolves a hostname to its category (exact + dot-suffix match),
// returning the original-case category name and the pattern that matched.
//
// matchedBy reports the admin's configured pattern VERBATIM (admin URL-lookup
// API contract). That contract is why this used to scan the entry lists rather
// than the lowercase forward index, which does not carry the original casing —
// but the scan was O(total configured hosts) on the proxy hot path, because
// categoryGroupMatchesHostRule reaches it through lookupHostCategory for every
// request evaluated against a DestCategoryGroup rule. On the shipped default
// taxonomy (~665 host patterns) an unmatched host cost 22.6 us of CPU per
// request; the indexed sibling MatchesHost answered the same shape in 160 ns.
//
// It now reads a reverse index that stores the verbatim pattern alongside the
// category, so the contract holds and the lookup is O(labels). See lookupHit
// for how the original scan's match precedence is preserved exactly.
func (s *Store) LookupHost(host string) (category, matchedBy string, ok bool) {
	return s.resolveHost(false, host)
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
