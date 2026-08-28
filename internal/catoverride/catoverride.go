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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	// ErrPersist marks a durable full-set replacement failure: the replacement
	// was rolled back and the previous override set is live in memory AND on a
	// reload (2D-B.0b, the 2D-A doctrine).
	ErrPersist = errors.New("catoverride: override persistence failed")
)

// RevisionConflictError reports a failed optimistic-revision fence on the
// full-set replacement: the client asserted the override revision it loaded
// (the caller-supplied content fingerprint) and the current set differs. Same
// structured-409 contract as the other 2D fences.
type RevisionConflictError struct {
	Current  string
	Asserted string
}

func (e *RevisionConflictError) Error() string {
	return fmt.Sprintf("override revision conflict: current %s, asserted %s", e.Current, e.Asserted)
}

// writeFile is the persistence seam (tests inject failures / ErrReplacedNotSynced).
var writeFile = fileutil.AtomicWrite

// Store holds the current overrides with race-safe access and file persistence.
type Store struct {
	mu   sync.RWMutex
	ov   Overrides
	path string

	// mutMu serializes EVERY runtime writer — the fenced durable replacement,
	// the memory-only ReplaceAll (cluster apply / import / rollback), and
	// standalone Save — so the fence comparison, the replacement and the
	// durable publication are one transaction, no standalone save can publish
	// an in-flight replacement, and no bulk install can interleave (the 2D-A
	// fence + commit-boundary doctrine; 2D-B.0b). Startup-only Load is exempt
	// by ordering.
	mutMu sync.Mutex

	// saveMu is the durable-publication serializer: saveLocked runs snapshot →
	// marshal → AtomicWrite as one unit under it, so publications land in
	// acquisition order. LOCK ORDER (acyclic): mutMu → saveMu → mu; every
	// runtime persistence entry goes through mutMu first; saveLocked never
	// reacquires mutMu.
	saveMu sync.Mutex
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
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var env fileEnvelope
	if err := dec.Decode(&env); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return fileEnvelope{}, fmt.Errorf("%w: %v", ErrUnknownField, err)
		}
		return fileEnvelope{}, fmt.Errorf("catoverride: decode envelope: %w", err)
	}
	// Require EOF after the envelope: dec.More() is not a reliable whole-input
	// check (a trailing "}" or "]" can slip past it), so a SECOND decode must fail
	// with io.EOF for the input to be exactly one envelope. Any trailing token —
	// junk, a second value, or a stray closer — is rejected.
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return fileEnvelope{}, errors.New("catoverride: trailing data after overrides envelope")
	}
	return env, nil
}

// Save persists the current overrides as the schema-versioned envelope via an
// atomic (temp+fsync+rename+parent-fsync) write. A no-path store is a no-op.
// PUBLIC entry: acquires mutMu first (commit-boundary doctrine) so a
// standalone save can never observe — or publish — an in-flight durable
// replacement; the durable primitive holds mutMu and calls saveLocked
// directly (mutMu is not reentrant — never call Save from inside it).
func (s *Store) Save() error {
	s.mutMu.Lock()
	defer s.mutMu.Unlock()
	return s.saveLocked()
}

// saveLocked is the internal publication helper. Caller MUST hold mutMu. The
// whole helper runs under saveMu — snapshot included — so publications form
// one monotonic order.
func (s *Store) saveLocked() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

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
	return writeFile(path, data, 0o600)
}

// ReplaceAllDurable is the fenced durable FULL-SET replacement (2D-B.0b):
//
//	fence (optional expected revision, computed by the caller-supplied revOf
//	over the CURRENT set) → normalize/validate the target → replace → durable
//	save → success — all under mutMu, one serialization domain, no detached
//	check, no TOCTOU, no last-write-wins.
//
// revOf is the caller's canonical content-revision function (production: the
// saasFeedOverridesFingerprint that is already the durable authority
// revision truth). Fence mismatch ⇒ *RevisionConflictError (nothing ran).
// Validation failure ⇒ error, current set untouched. Persistence failure ⇒
// the previous set is restored (memory AND a reload agree) + ErrPersist —
// a failed full-set replacement is never present after restart.
// ErrReplacedNotSynced follows the landed-content doctrine. On success the
// stored (normalized) set is returned for the caller's response/recompose.
func (s *Store) ReplaceAllDurable(expectedRev *string, next Overrides, revOf func(Overrides) string) (Overrides, error) {
	s.mutMu.Lock()
	defer s.mutMu.Unlock()

	if expectedRev != nil {
		s.mu.RLock()
		cur := revOf(cloneOverrides(s.ov))
		s.mu.RUnlock()
		if *expectedRev != cur {
			return Overrides{}, &RevisionConflictError{Current: cur, Asserted: *expectedRev}
		}
	}
	norm, err := Normalize(next)
	if err != nil {
		return Overrides{}, err
	}
	s.mu.Lock()
	prev := s.ov
	s.ov = norm
	s.mu.Unlock()
	if werr := s.saveLocked(); werr != nil {
		if errors.Is(werr, fileutil.ErrReplacedNotSynced) {
			return cloneOverrides(norm), nil // landed-content success
		}
		s.mu.Lock()
		s.ov = prev
		s.mu.Unlock()
		return Overrides{}, fmt.Errorf("%w: %w", ErrPersist, werr)
	}
	return cloneOverrides(norm), nil
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
// and the current set is left untouched (all-or-nothing). Holds mutMu so a bulk
// install (cluster apply / import / rollback) orders against the fenced durable
// replacement; memory-only — the callers' separate Save() reacquires the domain
// and publishes the current committed state.
func (s *Store) ReplaceAll(o Overrides) error {
	norm, err := Normalize(o)
	if err != nil {
		return err
	}
	s.mutMu.Lock()
	defer s.mutMu.Unlock()
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
// Precedence (admin layer 1 over feed layer 2): every override key carries
// host+subdomain SUFFIX scope (F0 §7.5), so an override key GOVERNS ITS WHOLE
// SUBTREE. Start from the feed snapshot and drop every entry that is equal to or a
// subdomain of a tombstone OR of an added/recategorized key — a descendant feed
// host must not survive in a different category than the override that covers it
// (which the policy engine's per-category suffix walk could otherwise match in
// both, F0 §7.4). Then insert the recategorizations and additions. Validate
// already forbids tombstoning a host the admin also asserts, so no override erases
// another.
//
// Note: this makes each override key the sole authority over its subtree. A
// residual ancestor/descendant conflict between an override key and a feed
// ANCESTOR outside its subtree (e.g. an override for `app.example.com` while the
// feed keeps `example.com` in another category) is an override↔feed interaction
// that can only be detected against the live feed at activation (F3b), since
// overrides are validated in isolation here.
func ComposeView(feed map[string]string, o Overrides) map[string]string {
	assertKeys := make([]string, 0, len(o.Recategorized)+len(o.Added))
	for host := range o.Recategorized {
		assertKeys = append(assertKeys, host)
	}
	for host := range o.Added {
		assertKeys = append(assertKeys, host)
	}
	out := make(map[string]string, len(feed))
	for host, cat := range feed {
		if suffixSuppressed(host, o.Tombstones) || suffixSuppressed(host, assertKeys) {
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

// SealedKeys returns the set of override boundary keys — the hosts an override
// makes AUTHORITATIVE for their whole subtree (recategorizations, additions, and
// tombstones). A membership suffix-walk that reaches one of these keys must STOP
// there rather than climbing to an ancestor baseline category: the override is
// the sole authority for the key and its subdomains, so an ancestor category it
// did not assert must not leak back in. This mirrors the keys ComposeMembership
// makes authoritative (out[host] replacement + subtree suppression), so the two
// stay consistent by construction.
func SealedKeys(o Overrides) map[string]bool {
	sealed := make(map[string]bool, len(o.Recategorized)+len(o.Added)+len(o.Tombstones))
	for host := range o.Recategorized {
		sealed[host] = true
	}
	for host := range o.Added {
		sealed[host] = true
	}
	for _, host := range o.Tombstones {
		sealed[host] = true
	}
	return sealed
}

// ComposeMembership is ComposeView over a host→CATEGORIES map: the membership
// companion used when the baseline taxonomy is many-to-many (a host in several
// categories at once). Suppression and insertion semantics are IDENTICAL to
// ComposeView — same tombstone/assert-key suffix suppression, same override
// insertion — so the two compositions always agree on which keys survive.
//
// An override key is the sole authority over its subtree, so an inserted
// recategorization/addition replaces the WHOLE membership list for its key with
// the single override category. A tombstone removes every category for the
// covered subtree. That keeps a removal a real removal: a multi-category host
// cannot survive a tombstone through one of its other categories.
func ComposeMembership(feed map[string][]string, o Overrides) map[string][]string {
	assertKeys := make([]string, 0, len(o.Recategorized)+len(o.Added))
	for host := range o.Recategorized {
		assertKeys = append(assertKeys, host)
	}
	for host := range o.Added {
		assertKeys = append(assertKeys, host)
	}
	out := make(map[string][]string, len(feed))
	for host, cats := range feed {
		if suffixSuppressed(host, o.Tombstones) || suffixSuppressed(host, assertKeys) {
			continue
		}
		cp := make([]string, len(cats))
		copy(cp, cats)
		out[host] = cp
	}
	for host, cat := range o.Recategorized {
		out[host] = []string{cat}
	}
	for host, cat := range o.Added {
		out[host] = []string{cat}
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
