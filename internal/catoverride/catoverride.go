// Package catoverride is the admin-owned category-override engine for the signed
// SaaS URL-category feed (F3a-1, per roadmap/FEEDS-DISTRIBUTION-F3-DESIGN.md §7.2).
//
// It holds the three override kinds an administrator layers ON TOP of the
// feed-owned snapshot — additions, recategorizations, and tombstones — and the
// PURE composition function that folds them into an effective host→category view
// the policy engine reads. The override keys carry the SAME suffix semantics as a
// feed entry (a key `example.com` covers `example.com` and every subdomain,
// matching the engine's per-category suffix walk, F0 §7.5).
//
// SCOPE (F3a-1): this package is the schema, normalization/validation boundary,
// persistence (a schema-versioned, strict-decoded envelope via
// fileutil.AtomicWrite), and the pure composition. It carries NO API, NO CP→DP
// wire, NO GUI, and NO downloader — those are later slices. Normalization is
// delegated to internal/urlcatfeed so the override host/category grammar is
// byte-identical to the feed producer/verifier.
package catoverride

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// SchemaVersion is the on-disk envelope schema for overrides.json. A file
// carrying a HIGHER version was written by a newer binary this one cannot safely
// interpret, so Load fails closed rather than silently mis-reading it (the
// downgrade guard, F3a §A.5.1).
const SchemaVersion = 1

// Overrides is the admin-owned override set. Maps key on the NORMALIZED host
// (urlcatfeed.NormalizeHost) and values are CANONICAL category names
// (urlcatfeed.CanonicalCategoryName). All three kinds carry host+subdomain suffix
// scope (F0 §7.5).
type Overrides struct {
	Added         map[string]string `json:"added,omitempty"`         // host → category to insert
	Recategorized map[string]string `json:"recategorized,omitempty"` // host → category to repoint
	Tombstones    []string          `json:"tombstones,omitempty"`    // hosts to suppress (self + subdomains)
}

// fileEnvelope is the schema-versioned on-disk form. The schema marker is what
// lets a future migration/upgrade tell an old file from a new one and lets this
// binary refuse a file from a newer one (fail-closed downgrade guard).
type fileEnvelope struct {
	SchemaVersion int       `json:"schema_version"`
	Overrides     Overrides `json:"overrides"`
}

// Distinct load errors so callers/tests can assert the exact class.
var (
	// ErrSchemaTooNew is returned by Load when the file's schema_version exceeds
	// this binary's SchemaVersion — a downgrade into a binary that cannot safely
	// interpret the newer schema. Fail closed; never mutate the file.
	ErrSchemaTooNew = errors.New("catoverride: overrides file schema is newer than this binary supports")
	// ErrUnknownField is returned when the file carries JSON keys the contract
	// does not define (strict decode).
	ErrUnknownField = errors.New("catoverride: overrides file has unknown fields")
)

// Store holds the current overrides with race-safe access and file persistence.
type Store struct {
	mu   sync.RWMutex
	ov   Overrides
	path string
}

// New builds an empty store.
func New() *Store { return &Store{} }

// SetPathForTest points persistence at path without loading (test helper +
// used by callers that construct-then-Load).
func (s *Store) SetPathForTest(path string) {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()
}

// Path reports the persistence path ("" ⇒ persistence disabled).
func (s *Store) Path() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.path
}

// Load reads the schema-versioned envelope from path. A missing file is the
// normal first-run state (empty overrides, no error). A present file is STRICTLY
// decoded (unknown fields rejected), its schema is checked (a newer schema fails
// closed via ErrSchemaTooNew), and its overrides are normalized + validated
// before they become live — a structurally-corrupt or invalid file returns an
// error and leaves the store empty, never partially applied.
func (s *Store) Load(path string) error {
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()

	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured data-dir path
	if err != nil {
		if os.IsNotExist(err) {
			return nil // first run
		}
		return fmt.Errorf("catoverride: read %s: %w", path, err)
	}

	env, err := decodeEnvelope(data)
	if err != nil {
		return err
	}
	if env.SchemaVersion > SchemaVersion {
		return fmt.Errorf("%w: file=%d supported=%d", ErrSchemaTooNew, env.SchemaVersion, SchemaVersion)
	}
	norm, err := Normalize(env.Overrides)
	if err != nil {
		return fmt.Errorf("catoverride: invalid overrides in %s: %w", path, err)
	}

	s.mu.Lock()
	s.ov = norm
	s.mu.Unlock()
	return nil
}

// decodeEnvelope strictly decodes the envelope bytes: unknown fields and trailing
// data are rejected so a malformed or newer-shaped file cannot be silently
// half-read.
func decodeEnvelope(data []byte) (fileEnvelope, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var env fileEnvelope
	if err := dec.Decode(&env); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return fileEnvelope{}, fmt.Errorf("%w: %v", ErrUnknownField, err)
		}
		return fileEnvelope{}, fmt.Errorf("catoverride: decode envelope: %w", err)
	}
	if dec.More() {
		return fileEnvelope{}, errors.New("catoverride: trailing data after overrides envelope")
	}
	return env, nil
}

// Save persists the current overrides as the schema-versioned envelope via an
// atomic (temp+fsync+rename+parent-fsync) write. A no-path store is a no-op.
func (s *Store) Save() error {
	s.mu.RLock()
	path := s.path
	env := fileEnvelope{SchemaVersion: SchemaVersion, Overrides: cloneOverrides(s.ov)}
	s.mu.RUnlock()
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.AtomicWrite(path, data, 0o600)
}

// Get returns a deep copy of the current overrides (safe to mutate/serialize).
func (s *Store) Get() Overrides {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneOverrides(s.ov)
}

// ReplaceAll validates then wholesale-replaces the override set. An empty set is
// a legitimate value (clears every override) — the store-level counterpart to the
// wire deletion-propagation the later CP→DP slice adds. Invalid input is rejected
// and the current set is left untouched (all-or-nothing).
func (s *Store) ReplaceAll(o Overrides) error {
	norm, err := Normalize(o)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.ov = norm
	s.mu.Unlock()
	return nil
}

// cloneOverrides deep-copies an Overrides value.
func cloneOverrides(o Overrides) Overrides {
	out := Overrides{}
	if len(o.Added) > 0 {
		out.Added = make(map[string]string, len(o.Added))
		for k, v := range o.Added {
			out.Added[k] = v
		}
	}
	if len(o.Recategorized) > 0 {
		out.Recategorized = make(map[string]string, len(o.Recategorized))
		for k, v := range o.Recategorized {
			out.Recategorized[k] = v
		}
	}
	if len(o.Tombstones) > 0 {
		out.Tombstones = append([]string(nil), o.Tombstones...)
	}
	return out
}

// ComposeView folds the overrides onto a feed-owned snapshot and returns the
// effective host→category view (F0 §7.2). It is PURE and deterministic: the
// snapshot is not mutated, and repeated calls on equal input return equal output.
//
// Precedence (admin layer 1 over feed layer 2): start from the feed snapshot,
// drop every entry suppressed by a tombstone (self OR subdomain of a tombstone
// host), then apply recategorizations, then union additions. Tombstones only
// suppress feed entries — an admin `added`/`recategorized` host is authoritative
// and Validate already forbids tombstoning a host the admin also added or
// recategorized, so no override erases another.
func ComposeView(feed map[string]string, o Overrides) map[string]string {
	out := make(map[string]string, len(feed))
	for host, cat := range feed {
		if suffixSuppressed(host, o.Tombstones) {
			continue
		}
		out[host] = cat
	}
	for host, cat := range o.Recategorized {
		out[host] = cat
	}
	for host, cat := range o.Added {
		out[host] = cat
	}
	return out
}

// suffixSuppressed reports whether host is covered by any tombstone (equal to it
// or a subdomain of it) — the host+subdomain scope of an override key (F0 §7.5).
func suffixSuppressed(host string, tombstones []string) bool {
	for _, t := range tombstones {
		if host == t || strings.HasSuffix(host, "."+t) {
			return true
		}
	}
	return false
}

// sortedHosts returns the keys of an override map in deterministic order.
func sortedHosts(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
