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
	// hostIndex / adminHostIndex are the REVERSE direction: lowercase host
	// pattern → the position of the first entry that declares it. They serve
	// LookupHost / LookupHostAdmin; see patternRef.
	hostIndex      map[string]patternRef
	adminHostIndex map[string]patternRef
	path           string
	fp             atomic.Value // string: cached semantic ContentFingerprint (recomputed under mu on every semantic change)

	// rev counts semantic mutations (every path that recomputes the
	// fingerprint). PROCESS-LOCAL change signal for memo/fence keys ONLY —
	// never an identity (the QB-2 lesson: identities must be content-derived
	// and restart-stable; this counter exists precisely because the content
	// fingerprint is ABA-blind, an A→B→A round trip restoring the same
	// string). Bumped INSIDE the write-lock critical section, so the unlock
	// that publishes new content also publishes the advanced revision.
	rev atomic.Uint64
}

// Revision returns the process-local semantic-mutation counter. Monotonic
// within a process; resets on restart — a fence key, not an identity.
func (s *Store) Revision() uint64 { return s.rev.Load() }

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

// fingerprintDomain versions the ContentFingerprint framing. Bump it whenever
// the framed field set or encoding changes — consumers pin the returned value
// as an identity, so two framings must never collide. v2 (QB-2.1): entries
// are framed in RESOLVER SEQUENCE order, no longer sorted by name.
const fingerprintDomain = "culvert-urlcat-content-fp-v3"

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
//   - the entry's host patterns, lowercased RAW — the trailing dot is KEPT
//     (v3, Codex round 26): the host→category resolver (LookupHost, the path
//     Learning consumes) compares strings.ToLower(pattern) with NO trailing-
//     dot trim while the incoming host IS trimmed, so a "example.com."
//     spelling is a DEAD pattern there and switching a live pattern to it is
//     resolution-relevant — the fingerprint must move. (The category→hosts
//     matcher MatchesHost trims, so for it this is a conservative
//     false-stale — the accepted direction. The two matchers have disagreed
//     on this spelling since before the reverse index existed; the
//     fingerprint mirrors the resolver Learning actually uses.)
//     De-duplicated and sorted — WITHIN-entry host order stays canonical
//     because it can only affect the matchedBy display string, and Learning
//     consumes the resolved category, never matchedBy.
//
// Excluded by contract: process-local counters, timestamps, mutation history,
// map iteration order, host pattern CASE and exact-duplicate patterns
// (matchedBy display only), empty patterns, and display-only or metrics
// state. Framing
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
	s.rev.Add(1) // under s.mu: content and change signal publish together
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
			// Mirror LookupHost's comparison exactly: lowercase, NO trailing-
			// dot trim (v3, Codex round 26 — supersedes the earlier trim,
			// which mirrored the category→hosts matcher instead and made a
			// live→dead "example.com"→"example.com." pattern edit invisible
			// to the fingerprint even though it changes what LookupHost — the
			// resolver Learning consumes — returns for that host).
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

// rebuildIndex reconstructs every derived index from s.entries and
// refreshes the cached content fingerprint.
// Caller must hold s.mu (write or be the sole owner).
//
// It is the maintenance path for every mutation EXCEPT a single-host append:
// Set/Delete/RemoveHost rebuild wholesale rather than patching individual
// index keys, because the positional hostIndex below cannot be patched
// incrementally for those shapes (deleting a category shifts every later
// entry position; a removed pattern's replacement winner is not enumerable
// from the index). A full rebuild is O(total patterns), but each of those
// mutators also calls Save(), which marshals the entire store to JSON and
// atomically rewrites the file — so the rebuild is noise next to the work
// already being done. AddHost alone folds incrementally (addHostToIndexes):
// the SaaS feed sync calls it once per merged host, and a wholesale rebuild
// there would stall the request path once per host (see that function).
func (s *Store) rebuildIndex() {
	s.recomputeFingerprintLocked()
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
	for ei, e := range s.entries {
		if !strings.EqualFold(e.Name, category) {
			continue
		}
		host = hostutil.NormalizeHost(strings.TrimSpace(host))
		if s.index[key][host] {
			s.mu.Unlock()
			return nil // already present
		}
		e.Hosts = append(e.Hosts, host)
		s.addHostToIndexes(ei, e, key, host)
		// Incremental index patch above; the semantic identity still moves —
		// refresh the fingerprint + revision (same cost this path always paid).
		s.recomputeFingerprintLocked()
		s.mu.Unlock()
		s.Save()
		return nil
	}
	s.mu.Unlock()
	return fmt.Errorf("category %q not found", category)
}

// addHostToIndexes folds ONE host just APPENDED to s.entries[ei].Hosts into
// every derived index, instead of rebuilding the whole taxonomy.
//
// Rebuilding here would be correct but pathological: the legacy SaaS feed
// sync calls AddHost once per merged host (saas_feed.go), so a large feed
// update would rebuild the ENTIRE index once per added host while holding the
// write lock — stalling the request path's RLock for O(hosts × patterns)
// total (the exact stall flagged as P1 on PR #1171). An APPEND is uniquely
// well-behaved: it adds one candidate at the END of one entry's host list, so
// no existing (entry, host) position shifts and the only reverse-index key
// whose winner can change is this pattern's — and only if the new position
// precedes the current holder in scan order. Removal has no such property,
// which is why RemoveHost/Delete/Set still rebuild wholesale.
//
// Lock discipline mirrors rebuildIndex exactly: the forward inner sets are
// probed OUTSIDE the lock by MatchesHost/MatchesHostAdmin (pointer snapshot
// under RLock), so the touched category's set is cloned-and-swapped, never
// mutated in place; the reverse indices are only ever probed under RLock
// (lookupIn), so an in-place insert under the write lock is safe.
//
// Degenerate config note: with DUPLICATE category names (already-recorded
// review follow-up; first-wins vs last-wins was inconsistent before the
// index existed), a wholesale rebuild keys the forward set off the LAST
// duplicate while this fold extends the currently-published set. AddHost
// targets the FIRST duplicate either way, so the fold's result is the more
// self-consistent of the two; no supported configuration reaches this.
func (s *Store) addHostToIndexes(ei int, e *Entry, key, host string) {
	set := make(map[string]bool, len(s.index[key])+1)
	for h := range s.index[key] {
		set[h] = true
	}
	set[strings.ToLower(strings.TrimSuffix(host, "."))] = true
	s.index[key] = set
	if !e.BuiltIn {
		s.adminIndex[key] = set
	}

	// Same deliberate normalization split as rebuildIndex: the reverse key
	// keeps a trailing dot.
	// #nosec G115 -- slice indices: non-negative and bounded by len
	ref := patternRef{entry: int32(ei), host: int32(len(e.Hosts) - 1)}
	pk := strings.ToLower(host)
	if cur, dup := s.hostIndex[pk]; !dup || ref.less(cur) {
		s.hostIndex[pk] = ref
	}
	if !e.BuiltIn {
		if cur, dup := s.adminHostIndex[pk]; !dup || ref.less(cur) {
			s.adminHostIndex[pk] = ref
		}
	}
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
// hosts already persisted. Empty-host entries (e.g. UT1 name-seeds) contribute
// nothing.
//
// A host that appears under SEVERAL built-in categories (the shipped taxonomy
// has such hosts — e.g. linkedin.com is both "Social Media" and
// "HR & Recruiting") collapses to ONE category here, because the map shape
// admits only one. FIRST entry wins, matching the entry-order precedence
// LookupHost applies when it scans s.entries top-down — so the collapsed value
// is the same category the pre-effective-view classification path returned.
// (It used to be LAST-wins, which silently changed which category a
// multi-category host classified as once the effective view went on the policy
// path.)
//
// This map is a CLASSIFICATION view ("what is this host?") and is lossy by
// construction. Never answer a MEMBERSHIP question ("is this host in category
// C?") from it — use BuiltInHostMemberships, which keeps every category.
func (s *Store) BuiltInHostCategories() map[string]string {
	out := make(map[string]string)
	for h, cats := range s.BuiltInHostMemberships() {
		out[h] = cats[0]
	}
	return out
}

// BuiltInHostMemberships returns a normalized host→categories map over the
// BuiltIn=true entries, keeping EVERY category a host belongs to rather than
// collapsing to one. Per-host category lists are in s.entries order (so index 0
// is the classification winner BuiltInHostCategories reports) and deduplicated.
//
// It is the membership source for the signed-feed effective view: MatchesHost
// answers "is host in category C?" across the full many-to-many taxonomy, and
// an effective view built from the collapsed single-category map cannot answer
// that question without losing a category — which drops a policy rule keyed on
// the losing category (a fail-open). Empty-host entries contribute nothing.
func (s *Store) BuiltInHostMemberships() map[string][]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string][]string)
	for _, e := range s.entries {
		if !e.BuiltIn {
			continue
		}
		for _, h := range e.Hosts {
			nh := hostutil.NormalizeHost(strings.TrimSpace(h))
			if nh == "" {
				continue
			}
			if !containsFold(out[nh], e.Name) {
				out[nh] = append(out[nh], e.Name)
			}
		}
	}
	return out
}

// containsFold reports whether cats already holds name (case-insensitively —
// category comparison everywhere else in the taxonomy is case-insensitive, so
// two entries differing only in case must not both be recorded).
func containsFold(cats []string, name string) bool {
	for _, c := range cats {
		if strings.EqualFold(c, name) {
			return true
		}
	}
	return false
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
