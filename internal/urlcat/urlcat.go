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
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

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
	path       string
	fp         atomic.Value // string: cached semantic ContentFingerprint (recomputed under mu on every semantic change)
}

// fingerprintDomain versions the ContentFingerprint framing. Bump it whenever
// the framed field set or encoding changes — consumers pin the returned value
// as an identity, so two framings must never collide. v2 (QB-2.1): entries
// are framed in RESOLVER SEQUENCE order, no longer sorted by name.
const fingerprintDomain = "culvert-urlcat-content-fp-v2"

// ContentFingerprint returns a deterministic semantic identity of the
// taxonomy: equal iff the RESOLUTION-RELEVANT content is equal, stable across
// restart/reload of identical persisted state (unlike a process-local
// revision counter). Consumed by the policy-learning category epoch
// (ADR-0025 §6, epoch scheme v2).
//
// Covered (exactly the state that can change a Lookup*/Matches* result):
//   - the ENTRY SEQUENCE ORDER (QB-2.1: LookupHost/LookupHostAdmin scan
//     s.entries in order and return the FIRST match, so order is
//     resolution-relevant whenever category patterns overlap; entries are
//     framed in sequence, never sorted — a reorder that cannot change any
//     resolution (no overlaps) still changes the identity, an accepted
//     CONSERVATIVE false-stale: safer than missing a real semantic change),
//   - every entry's Name in ORIGINAL case (the resolvers return it verbatim,
//     and downstream consumers key on it),
//   - the BuiltIn flag (it decides admin-tier membership: LookupHostAdmin /
//     MatchesHostAdmin see only BuiltIn=false entries),
//   - the entry's host patterns, lowercased (the resolver-input transform),
//     de-duplicated and sorted — WITHIN-entry host order stays canonical
//     because it can only affect the matchedBy display string, and Learning
//     consumes the resolved category, never matchedBy.
//
// Excluded by contract: process-local counters, timestamps, mutation history,
// map iteration order, host pattern CASE and duplicate patterns (matchedBy
// display only), empty patterns, and display-only or metrics state. Framing
// is length-prefixed under fingerprintDomain, so field boundaries are
// unambiguous.
//
// The value is cached; reads are one atomic load. Before the first
// load/mutation (zero-value store) it is computed on demand.
func (s *Store) ContentFingerprint() string {
	if v, ok := s.fp.Load().(string); ok && v != "" {
		return v
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return computeFingerprint(s.entries)
}

// recomputeFingerprintLocked refreshes the cached fingerprint. Caller must
// hold s.mu (write) — every semantic mutation path calls this before
// unlocking, so readers never observe a stale identity for new content.
func (s *Store) recomputeFingerprintLocked() {
	s.fp.Store(computeFingerprint(s.entries))
}

// computeFingerprint derives the canonical content hash (see
// ContentFingerprint for the field contract). Pure function of entries.
func computeFingerprint(entries []*Entry) string {
	type frameEntry struct {
		name    string
		builtIn bool
		hosts   []string
	}
	// Entries are framed in s.entries SEQUENCE order (QB-2.1) — the exact
	// order the resolvers scan — so a reorder is an identity change.
	fes := make([]frameEntry, 0, len(entries))
	for _, e := range entries {
		hs := make([]string, 0, len(e.Hosts))
		seen := make(map[string]bool, len(e.Hosts))
		for _, h := range e.Hosts {
			hl := strings.ToLower(h)
			if hl != "" && !seen[hl] {
				seen[hl] = true
				hs = append(hs, hl)
			}
		}
		sort.Strings(hs)
		fes = append(fes, frameEntry{name: e.Name, builtIn: e.BuiltIn, hosts: hs})
	}
	h := sha256.New()
	var n [8]byte
	frame := func(v string) {
		binary.BigEndian.PutUint64(n[:], uint64(len(v)))
		h.Write(n[:])
		h.Write([]byte(v))
	}
	frame(fingerprintDomain)
	for i := range fes {
		frame(fes[i].name)
		if fes[i].builtIn {
			h.Write([]byte{1})
		} else {
			h.Write([]byte{0})
		}
		binary.BigEndian.PutUint64(n[:], uint64(len(fes[i].hosts)))
		h.Write(n[:])
		for _, hh := range fes[i].hosts {
			frame(hh)
		}
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// New builds a store over entries and its derived host index.
func New(entries []*Entry) *Store {
	s := &Store{entries: entries}
	s.rebuildIndex()
	return s
}

// rebuildIndex reconstructs the category→hosts indices from s.entries and
// refreshes the cached content fingerprint.
// Caller must hold s.mu (write or be the sole owner).
func (s *Store) rebuildIndex() {
	s.recomputeFingerprintLocked()
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

// DefaultBusinessCategoryNames returns the sorted names of the embedded SaaS
// BUSINESS category seed list ONLY (default_categories.json) — deliberately
// excluding the hardcoded non-business built-ins (Social Media, Malicious,
// News, Streaming, Gambling, Adult). This is the fail-closed seed for the
// policy-learning recommendable-category allowlist (ADR-0025 M4): a category
// must be on this list (or a future governed surface's) before the learning
// engine may propose an Allow rule for it.
func DefaultBusinessCategoryNames() []string {
	var saas []Entry
	if json.Unmarshal(defaultCategoriesJSON, &saas) != nil {
		return nil // fail closed: no parse ⇒ nothing recommendable
	}
	names := make([]string, 0, len(saas))
	for i := range saas {
		if saas[i].Name != "" {
			names = append(names, saas[i].Name)
		}
	}
	sort.Strings(names)
	return names
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
		s.recomputeFingerprintLocked()
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
	s.recomputeFingerprintLocked()
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
		s.recomputeFingerprintLocked()
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
		s.recomputeFingerprintLocked()
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
				s.recomputeFingerprintLocked()
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
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if e.BuiltIn {
			continue
		}
		for _, p := range e.Hosts {
			pl := strings.ToLower(p)
			if h == pl || strings.HasSuffix(h, "."+pl) {
				return e.Name, p, true
			}
		}
	}
	return "", "", false
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

// LookupHost resolves a hostname to its category by scanning entries
// (exact + suffix match), returning the original-case category name and the
// pattern that matched. Deliberately scans the entry lists — not the
// lowercase index — so matchedBy reports the admin's configured pattern
// verbatim (admin URL-lookup API contract).
func (s *Store) LookupHost(host string) (category, matchedBy string, ok bool) {
	h := hostutil.NormalizeHost(host)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		for _, p := range e.Hosts {
			pl := strings.ToLower(p)
			if h == pl || strings.HasSuffix(h, "."+pl) {
				return e.Name, p, true
			}
		}
	}
	return "", "", false
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
