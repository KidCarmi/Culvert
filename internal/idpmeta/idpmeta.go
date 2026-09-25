// Package idpmeta is the durable last-known-good store for the REMOTE
// documents an interactive IdP provider needs in order to exist at all: the
// SAML IdP EntityDescriptor (metadata_url) and the OIDC discovery document
// (issuer/.well-known/openid-configuration).
//
// # Why this package exists (CHAOS-71)
//
// Compiling an enabled SAML or OIDC profile used to perform a synchronous
// outbound fetch against the customer's IdP, with no cache and no fallback, on
// three paths that must not depend on a third party:
//
//   - the BOOT path (IdPRegistry.Load), where a failure was permanent for the
//     life of the process and left the profile enabled-but-not-live, reported
//     by exactly one log line;
//   - the admin write path (Upsert);
//   - the CP->DP CONFIG SYNC path (ReplaceAll, from syncSnapshotIdPProfiles),
//     where a failure ABORTED THE WHOLE SNAPSHOT — so an IdP maintenance
//     window stopped policy, blocklist and threat-feed distribution across the
//     entire fleet, and every data plane retried the fetch every 30 s for the
//     duration, aiming the fleet's full poll rate at the IdP that was already
//     down.
//
// The rule this package establishes: **a third party's availability decides
// whether an IdP's metadata is FRESH, never whether the IdP EXISTS.** A
// document that was fetched successfully once is kept, and a later fetch
// failure degrades to it instead of destroying the provider.
//
// # The staleness ceiling is the security half
//
// Serving a cached document forever would keep trusting an IdP signing
// certificate the IdP may have withdrawn — withdrawing a key from published
// metadata is the IdP's revocation lever, exactly as it is for a JWKS
// document. internal/auth's jwksStaleMaxAge (SEC-JWKS-1) reached the same
// conclusion one layer down and the answer is the same here: stale is a
// BOUNDED degradation. Past StaleMaxAge the entry is refused and the caller
// fails exactly as it did before this package existed.
//
// # Two invariants callers must preserve
//
//  1. CACHED BYTES GO THROUGH THE IDENTICAL PARSER AND VALIDATOR AS NETWORK
//     BYTES. This store returns raw bytes and nothing else; it never parses,
//     never validates, and must never become a path that admits a document
//     the network path would have rejected. An operator (or anything with
//     write access to dataDir) editing a cache file must not be able to widen
//     a trust decision.
//
//  2. THE KEY BINDS THE DOCUMENT TO ITS SOURCE. Entries are keyed by profile
//     id AND a digest of the source URL, so re-pointing a profile at a
//     different IdP can never be answered from the previous IdP's document.
//     A profile whose source changed has no cache until it fetches one.
package idpmeta

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

const (
	// StaleMaxAge bounds how long a cached document may substitute for a
	// live fetch. Past it the entry is refused and the caller fails closed
	// (pre-CHAOS-71 behaviour). Seven days comfortably covers an IdP
	// maintenance window, a weekend outage and an egress misconfiguration,
	// while staying far short of a key-rotation interval.
	//
	// It is a CONSTANT by design: an operator knob here could only ever
	// WIDEN the window in which a withdrawn IdP signing key keeps being
	// trusted, which is the one direction this value must not move. Same
	// reasoning as jwksStaleMaxAge.
	StaleMaxAge = 7 * 24 * time.Hour

	// MaxDocumentBytes bounds one cached document. The SAML fetch already
	// limits its read to 1 MiB and OIDC discovery to 64 KiB; this is the
	// store's own backstop so a future caller cannot make the cache a
	// disk-exhaustion vector.
	MaxDocumentBytes = 1 << 20

	// MaxEntries bounds the store. An appliance has a handful of IdP
	// profiles; the cap exists so repeated re-pointing of a profile's
	// source URL cannot grow the directory without limit. Eviction is
	// oldest-first by fetch time.
	MaxEntries = 64

	indexFile = "index.json"
	dirPerm   = 0o700
	filePerm  = 0o600
)

// ErrNoEntry means nothing usable is cached for this key: never fetched, past
// StaleMaxAge, or unreadable. The caller must treat it exactly as it treated a
// fetch failure before this package existed.
var ErrNoEntry = errors.New("idpmeta: no usable cached document")

// Kind distinguishes the two document types so one profile that somehow
// carries both cannot have them collide on disk.
type Kind string

// The two remote document kinds an interactive IdP profile can depend on.
const (
	// KindSAMLMetadata is a SAML IdP EntityDescriptor fetched from a
	// profile's metadata_url.
	KindSAMLMetadata Kind = "saml_metadata"
	// KindOIDCDiscovery is an OIDC discovery document fetched from a
	// profile's issuer.
	KindOIDCDiscovery Kind = "oidc_discovery"
)

// entry is the index record for one cached document.
//
// NOTE the absence of a path field. The document's filename is DERIVED from
// its key (docFileName) on every read and every eviction, never read back out
// of the index — a path taken from a file on disk is a path-traversal sink,
// and this index is itself a file. An index that has been tampered with can
// therefore cause a cache MISS and nothing else.
type entry struct {
	ProfileID string `json:"profile_id"`
	Kind      Kind   `json:"kind"`
	SourceSum string `json:"source_sum"`
	FetchedAt int64  `json:"fetched_at"`
	Bytes     int    `json:"bytes"`
}

// docFileName derives a document's filename from its key. Pure, and the only
// way a document path is ever produced.
func docFileName(k string) string { return sourceSum(k) + ".doc" }

// Store is a durable, bounded last-known-good document cache.
//
// A Store with an empty directory is INERT: Get always reports ErrNoEntry and
// Put is a no-op returning nil. That is the deliberate posture for a node with
// no writable state root — the cache is an availability aid, never a
// correctness dependency, so its absence must degrade to exactly the
// pre-CHAOS-71 behaviour rather than fail a compile.
type Store struct {
	mu      sync.Mutex
	dir     string
	entries map[string]*entry
	loaded  bool
	now     func() time.Time
}

// New returns a Store rooted at dir. An empty dir yields an inert store.
func New(dir string) *Store {
	return &Store{dir: dir, entries: map[string]*entry{}, now: time.Now}
}

// SetClockForTest injects a clock. Test-only.
func (s *Store) SetClockForTest(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now != nil {
		s.now = now
	}
}

// Enabled reports whether this store can persist anything.
func (s *Store) Enabled() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dir != ""
}

func sourceSum(source string) string {
	sum := sha256.Sum256([]byte(source))
	return hex.EncodeToString(sum[:8])
}

// key binds a cached document to BOTH the profile it belongs to and the exact
// source it came from. Re-pointing a profile at a different issuer or metadata
// URL therefore has no cache, rather than silently reusing the old IdP's
// document — which would let a deliberate migration be answered by the
// provider being migrated away from.
func key(profileID string, kind Kind, source string) string {
	return string(kind) + "|" + profileID + "|" + sourceSum(source)
}

func (s *Store) loadLocked() {
	if s.loaded || s.dir == "" {
		return
	}
	s.loaded = true
	data, err := os.ReadFile(filepath.Join(s.dir, indexFile))
	if err != nil {
		return // first run, or an unreadable index: start empty, never fail
	}
	var idx map[string]*entry
	if err := json.Unmarshal(data, &idx); err != nil {
		// A corrupt index is not worth failing a boot over: the documents it
		// names are a cache of a remote resource. Start empty; the next
		// successful fetch rewrites it.
		return
	}
	for k, e := range idx {
		if e != nil {
			s.entries[k] = e
		}
	}
}

// Get returns the cached document for (profileID, kind, source) together with
// its age, or ErrNoEntry when nothing usable is cached.
//
// "Usable" means: present, readable, its byte length matches what the index
// recorded, and its age is within StaleMaxAge. A NEGATIVE age — a document
// stamped in the future, which a clock rollback produces — is treated as
// UNUSABLE, not as maximally fresh: the same rule CHAOS-61 established for
// cluster rate-limit broadcast freshness, and for the same reason (a future
// stamp otherwise extends the trust window by however far the clock moved).
func (s *Store) Get(profileID string, kind Kind, source string) (doc []byte, age time.Duration, err error) {
	if s == nil {
		return nil, 0, ErrNoEntry
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir == "" {
		return nil, 0, ErrNoEntry
	}
	s.loadLocked()
	k := key(profileID, kind, source)
	e, ok := s.entries[k]
	if !ok {
		return nil, 0, ErrNoEntry
	}
	age = s.now().Sub(time.Unix(e.FetchedAt, 0))
	if age < 0 || age >= StaleMaxAge {
		return nil, age, ErrNoEntry
	}
	b, readErr := os.ReadFile(filepath.Join(s.dir, docFileName(k))) // #nosec G304 -- derived from a hash of the key, never from file content
	if readErr != nil || len(b) != e.Bytes {
		return nil, age, ErrNoEntry
	}
	return b, age, nil
}

// Put records doc as the last-known-good document for (profileID, kind,
// source). A failure to persist is returned but is never fatal to the caller:
// the fetch it came from already succeeded, so the only cost is that a FUTURE
// outage has no fallback.
func (s *Store) Put(profileID string, kind Kind, source string, doc []byte) error {
	if s == nil {
		return nil
	}
	if len(doc) == 0 {
		return fmt.Errorf("idpmeta: refusing to cache an empty document")
	}
	if len(doc) > MaxDocumentBytes {
		return fmt.Errorf("idpmeta: document is %d bytes, over the %d cap", len(doc), MaxDocumentBytes)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir == "" {
		return nil // inert store
	}
	s.loadLocked()
	if err := os.MkdirAll(s.dir, dirPerm); err != nil {
		return fmt.Errorf("idpmeta: create dir: %w", err)
	}
	k := key(profileID, kind, source)
	e := &entry{
		ProfileID: profileID,
		Kind:      kind,
		SourceSum: sourceSum(source),
		FetchedAt: s.now().Unix(),
		Bytes:     len(doc),
	}
	if err := fileutil.AtomicWrite(filepath.Join(s.dir, docFileName(k)), doc, filePerm); err != nil {
		return fmt.Errorf("idpmeta: write document: %w", err)
	}
	s.entries[k] = e
	s.evictLocked()
	return s.saveIndexLocked()
}

// evictLocked keeps the store within MaxEntries, oldest fetch first. The
// evicted document file is removed so the directory cannot outgrow the index.
func (s *Store) evictLocked() {
	if len(s.entries) <= MaxEntries {
		return
	}
	keys := make([]string, 0, len(s.entries))
	for k := range s.entries {
		keys = append(keys, k)
	}
	// Deterministic: oldest fetch first, ties broken by key so eviction never
	// depends on map iteration order.
	sort.Slice(keys, func(i, j int) bool {
		a, b := s.entries[keys[i]], s.entries[keys[j]]
		if a.FetchedAt != b.FetchedAt {
			return a.FetchedAt < b.FetchedAt
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys[:len(s.entries)-MaxEntries] {
		_ = os.Remove(filepath.Join(s.dir, docFileName(k)))
		delete(s.entries, k)
	}
}

func (s *Store) saveIndexLocked() error {
	data, err := json.MarshalIndent(s.entries, "", "  ")
	if err != nil {
		return fmt.Errorf("idpmeta: marshal index: %w", err)
	}
	if err := fileutil.AtomicWrite(filepath.Join(s.dir, indexFile), data, filePerm); err != nil {
		return fmt.Errorf("idpmeta: write index: %w", err)
	}
	return nil
}

// Dir reports the store's root directory ("" when inert). Observability and
// test support only.
func (s *Store) Dir() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dir
}

// Len reports how many documents are cached. Observability only.
func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir == "" {
		return 0
	}
	s.loadLocked()
	return len(s.entries)
}
