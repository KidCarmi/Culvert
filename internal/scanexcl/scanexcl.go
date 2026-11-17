// Package scanexcl holds the admin-managed scan-exclusion store: known-good
// SHA-256 content hashes and hostnames that bypass all body scanning. It is a
// self-contained leaf (stdlib + the hostutil seam) extracted from the flat
// package main per ADR-0002.
//
// It is designed for an extreme read:write ratio — IsHostExcluded runs once per
// inspected tunnel response and once per scanned plain-HTTP response,
// IsHashExcluded once per body scan, while writes happen only when an admin
// edits the lists — so the two maps are published as ONE immutable view behind
// an atomic pointer and the read path takes no lock at all. See Store.
package scanexcl

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// view is an immutable snapshot of both exclusion maps.
//
// A published view is NEVER mutated: every writer builds fresh maps and swaps
// the pointer, so a reader that has loaded a view can walk it without
// synchronisation for as long as it holds it. Both maps live in ONE view, so a
// reader also cannot observe the hash list from before a Replace together with
// the host list from after it — which the two independent map fields it
// replaced could not promise without the lock.
type view struct {
	hashes map[string]bool
	hosts  map[string]bool
}

// emptyView is the view a Store serves before anything is published. It is
// shared and must stay empty: nothing ever writes to a published view.
var emptyView = &view{}

// Store holds admin-managed exclusions: known-good content hashes and hostnames
// that bypass all body scanning. The zero value is a valid empty store.
//
// ── Why the read path is lock-free ──────────────────────────────────────────
//
// IsHostExcluded is called UNCONDITIONALLY from scanInspectBody
// (proxy_tunnel.go), ahead of the content-type gate, for every response
// decrypted on the SSL-inspection path — the primary SWG path — and from
// scanHTTPResponseBody (proxy_http.go) whenever any body scanner is enabled.
// IsHashExcluded is called once per body scan (internal/secscan). So all three
// run at request rate against lists that in steady state never change, and the
// overwhelmingly common posture is that no exclusion is configured at all:
// the lists are an admin opt-in for known-good internal mirrors.
//
// Those reads used to take sync.RWMutex.RLock. A reader lock is not cheap in
// this shape: RLock/RUnlock are two atomic read-modify-writes on ONE
// process-wide word, so every inspected response wrote the same cache line
// purely to read a map that never changes — and in the default posture, to read
// a map that is EMPTY. That is not a constant cost but a throughput ceiling,
// and it is the fourth instance of the identical shape in this tree
// (internal/threatfeed, internal/connlimit, the IP filter, and the top-hosts
// counter in store.go all record the same finding).
//
// Measured on a 4-core Xeon @2.10GHz, go1.27.4, -benchtime=2s, -count=1, both
// arms in ONE interleaved invocation against the verbatim RWMutex
// implementation kept as the legacy arm in scanexcl_bench_test.go. All rows are
// RunParallel over the rotating destination working set, so ns/op is wall time
// per op across ALL workers: a genuinely parallel read FALLS as cores are added
// and one that serialises on a shared word rises.
//
//	                            │   P=1   │   P=2   │   P=4   │ 1->4 throughput
//	host, no exclusions, RWMutex │ 41.7 ns │  141 ns │  154 ns │ 0.27x  (cores SUBTRACT)
//	host, no exclusions, view    │ 3.52 ns │ 1.75 ns │ 0.89 ns │ 4.0x
//	host, configured miss, RWMtx │ 50.2 ns │  156 ns │  171 ns │ 0.29x
//	host, configured miss, view  │ 42.1 ns │ 23.0 ns │ 12.6 ns │ 3.3x
//	hash, no exclusions, RWMutex │ 79.0 ns │ 88.2 ns │ 96.6 ns │ 0.82x
//	hash, no exclusions, view    │ 2.62 ns │ 1.37 ns │ 0.65 ns │ 4.0x
//
// Serially, the shapes that still do the full lookup: a configured host hit
// 45.7 -> 40.5 ns and a configured hash hit 93.0 -> 79.9 ns, which is the
// RLock/RUnlock pair and its deferred unlock coming off the call.
//
// Read the DIRECTION, not the exact percentage — absolute ns/op on a shared
// 4-vCPU VM is not comparable between invocations, which is why both arms are
// timed in the same run. What is robust is the sign: the lock made cores
// subtract throughput and the published view makes them add it, in every
// posture. Re-measure the whole set in one go; never compare a new arm against
// a number quoted here.
//
// The empty-posture gate below is what makes the "no exclusions" rows total: a
// store with nothing configured answers from the length check, so it pays
// neither the port strip nor the case fold that the lock used to be taken
// around. A configured store still pays both, and that is the cost the
// "configured miss" rows report. The gate is held structurally by
// TestEmptyPosture_AllocationFree, not by a timing threshold.
//
// mu now guards only path and serialises writers. Readers never take it.
type Store struct {
	// published is the current view. Readers load it with one atomic pointer
	// read — a shared-line READ, which scales — and never take a lock. nil
	// means "nothing published yet" and reads as emptyView, so the zero Store
	// is usable without New.
	published atomic.Pointer[view]

	mu   sync.Mutex // serialises writers; guards path
	path string     // JSON file for persistence (optional)
}

// New returns an empty Store ready for use.
func New() *Store {
	s := &Store{}
	s.published.Store(emptyView)
	return s
}

// current returns the published view, never nil. Callers must not mutate it.
func (s *Store) current() *view {
	if v := s.published.Load(); v != nil {
		return v
	}
	return emptyView
}

// exclusionsFile is the on-disk JSON envelope for Store.
type exclusionsFile struct {
	Hashes []string `json:"hashes"`
	Hosts  []string `json:"hosts"`
}

// Load reads the JSON file at path into the store. Missing file is not an error.
//
// The normalisation here is deliberately NOT Replace's: Load lower-cases what
// the file holds and keeps every entry, where Replace also trims surrounding
// space and drops entries that normalise to empty. That asymmetry predates the
// published view and is preserved verbatim — the file is written by Save from
// already-normalised keys, so the two agree on every value Culvert itself
// persists, and widening Load would silently change what a hand-edited file
// means.
func (s *Store) Load(path string) error {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()
	data, err := os.ReadFile(path) // #nosec G304 -- admin-configured path
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("scan exclusions read: %w", err)
	}
	var f exclusionsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("scan exclusions parse: %w", err)
	}
	next := &view{
		hashes: make(map[string]bool, len(f.Hashes)),
		hosts:  make(map[string]bool, len(f.Hosts)),
	}
	for _, h := range f.Hashes {
		next.hashes[strings.ToLower(h)] = true
	}
	for _, h := range f.Hosts {
		next.hosts[hostutil.StripHostPort(strings.ToLower(h))] = true
	}
	// Published only once both maps are fully built, so no reader can observe a
	// half-filled list.
	s.published.Store(next)
	return nil
}

// Save persists the exclusion lists to the configured file path using an
// atomic tmp+rename write. No-op if no path configured.
func (s *Store) Save() error {
	s.mu.Lock()
	path := s.path
	s.mu.Unlock()
	v := s.current()
	f := exclusionsFile{
		Hashes: make([]string, 0, len(v.hashes)),
		Hosts:  make([]string, 0, len(v.hosts)),
	}
	for h := range v.hashes {
		f.Hashes = append(f.Hashes, h)
	}
	for h := range v.hosts {
		f.Hosts = append(f.Hosts, h)
	}
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.AtomicWrite(path, data, 0o600)
}

// Replace atomically swaps the exclusion lists, normalising to lower case.
func (s *Store) Replace(hashes, hosts []string) {
	next := &view{
		hashes: make(map[string]bool, len(hashes)),
		hosts:  make(map[string]bool, len(hosts)),
	}
	for _, h := range hashes {
		h = strings.TrimSpace(strings.ToLower(h))
		if h != "" {
			next.hashes[h] = true
		}
	}
	for _, h := range hosts {
		h = hostutil.StripHostPort(strings.TrimSpace(strings.ToLower(h)))
		if h != "" {
			next.hosts[h] = true
		}
	}
	// One store publishes both lists together — see view.
	s.published.Store(next)
}

// IsHashExcluded reports whether the SHA-256 hex is on the hash allowlist.
// Hot path: called once per body scan. Lock-free — see Store.
func (s *Store) IsHashExcluded(hash string) bool {
	if s == nil {
		return false
	}
	hashes := s.current().hashes
	// Nothing configured (the default posture) ⇒ answer without folding the
	// case of a 64-byte hex digest. strings.ToLower does not allocate for an
	// already-lower-case digest, but it still scans every byte, and that scan
	// was most of this function's cost.
	if len(hashes) == 0 {
		return false
	}
	return hashes[strings.ToLower(hash)]
}

// IsHostExcluded reports whether the hostname is on the host allowlist.
// Hot path: called once per inspected tunnel response and once per scanned
// plain-HTTP response. Lock-free — see Store.
func (s *Store) IsHostExcluded(host string) bool {
	if s == nil || host == "" {
		return false
	}
	hosts := s.current().hosts
	// Nothing configured ⇒ answer before the port strip and the case fold.
	if len(hosts) == 0 {
		return false
	}
	// Strip port suffix and IPv6 brackets if present, then fold — the same
	// order, and therefore the same decision, as before the view existed.
	host = hostutil.StripHostPort(host)
	return hosts[strings.ToLower(host)]
}

// Lists returns copies of the current hash and host lists, sorted for stable
// admin output.
func (s *Store) Lists() (hashes, hosts []string) {
	v := s.current()
	hashes = make([]string, 0, len(v.hashes))
	for h := range v.hashes {
		hashes = append(hashes, h)
	}
	hosts = make([]string, 0, len(v.hosts))
	for h := range v.hosts {
		hosts = append(hosts, h)
	}
	sortStrings(hashes)
	sortStrings(hosts)
	return hashes, hosts
}

// sortStrings is a tiny insertion sort — exclusion lists are short (dozens of
// entries) so the constant-factor cost of reflection-based sort.Strings is not
// worth it.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
