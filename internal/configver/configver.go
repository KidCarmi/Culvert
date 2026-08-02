// Package configver implements the numbered config-version snapshot store
// (ADR-0002 extraction; engine was the store half of configversion.go in
// package main).
//
// The store owns version numbering (mutex + startup dir-scan resume), the
// on-disk envelope ({meta, config} as vN.json, atomic 0o600 writes), the
// max-versions prune, and list/load. It deliberately never sees the typed
// configuration: the envelope's config half crosses the boundary as
// json.RawMessage, because the concrete type (main's configBackup) is a hub
// spanning every config store. Capture/apply/diff/validation and the API
// handlers stay in package main.
//
// On-disk format is unchanged: /<dir>/v{N}.json containing
// {"meta": {version, created_at, actor, action}, "config": {...}}.
package configver

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// DefaultMax is the default maximum number of retained versions.
const DefaultMax = 50

// Meta is the version metadata half of the on-disk envelope.
type Meta struct {
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`         // what triggered the snapshot (e.g. "policy.update", "blocklist.import")
	Note      string `json:"note,omitempty"` // optional free-text reason (e.g. a policy-draft commit comment)
}

// ErrCorrupt marks a version file that exists but cannot be parsed as an
// envelope. Callers use it to distinguish "not found" (read error) from
// "unusable" — the rollback API maps the former to 404, the latter to 500.
var ErrCorrupt = errors.New("corrupt version file")

// envelope is the on-disk shape. Config stays raw on both paths.
type envelope struct {
	Meta   Meta            `json:"meta"`
	Config json.RawMessage `json:"config"`
}

// Store is a numbered snapshot store rooted at one directory.
type Store struct {
	mu  sync.Mutex
	dir string
	max int
	seq int
}

// New returns a store rooted at dir keeping at most maxVersions versions
// (maxVersions <= 0 selects DefaultMax). Call Init before first use.
func New(dir string, maxVersions int) *Store {
	if maxVersions <= 0 {
		maxVersions = DefaultMax
	}
	return &Store{dir: dir, max: maxVersions}
}

// Init creates the directory and resumes the sequence counter from the
// highest existing vN.json.
func (s *Store) Init() {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = os.MkdirAll(s.dir, 0o750)
	entries, _ := os.ReadDir(s.dir)
	for _, e := range entries {
		if n, ok := versionOf(e.Name()); ok && n > s.seq {
			s.seq = n
		}
	}
}

// versionOf parses "v{N}.json" → N.
func versionOf(name string) (int, bool) {
	if !strings.HasPrefix(name, "v") || !strings.HasSuffix(name, ".json") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, "v"), ".json"))
	if err != nil {
		return 0, false
	}
	return n, true
}

// Save assigns the next version number, writes the envelope atomically
// (0o600), prunes beyond max, and returns the assigned version. The sequence
// number is consumed even when the write fails (unchanged behavior — a gap,
// not a reuse).
func (s *Store) Save(actor, action, createdAt string, config json.RawMessage) (int, error) {
	return s.SaveWithNote(actor, action, createdAt, "", config)
}

// SaveWithNote is Save plus an optional free-text note recorded in the version
// metadata (used by the policy-draft commit path to persist the commit comment).
func (s *Store) SaveWithNote(actor, action, createdAt, note string, config json.RawMessage) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.seq++
	seq := s.seq

	env := envelope{
		Meta: Meta{
			Version:   seq,
			CreatedAt: createdAt,
			Actor:     actor,
			Action:    action,
			Note:      note,
		},
		Config: config,
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("marshal envelope: %w", err)
	}

	path := filepath.Join(s.dir, fmt.Sprintf("v%d.json", seq))
	if err := fileutil.AtomicWrite(path, data, 0o600); err != nil {
		return 0, fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}

	s.pruneLocked()
	return seq, nil
}

// pruneLocked removes the oldest versions beyond max. Caller holds s.mu.
func (s *Store) pruneLocked() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	var versions []int
	for _, e := range entries {
		if n, ok := versionOf(e.Name()); ok {
			versions = append(versions, n)
		}
	}
	if len(versions) <= s.max {
		return
	}
	sort.Ints(versions)
	for _, n := range versions[:len(versions)-s.max] {
		_ = os.Remove(filepath.Join(s.dir, fmt.Sprintf("v%d.json", n)))
	}
}

// Load reads one version. A read failure is returned as-is (os.IsNotExist
// checkable → the API's 404); an unparseable envelope wraps ErrCorrupt.
// The config half is returned raw for the caller to unmarshal.
func (s *Store) Load(ver int) (Meta, json.RawMessage, error) {
	path := filepath.Join(s.dirSnapshot(), fmt.Sprintf("v%d.json", ver))
	data, err := os.ReadFile(path)
	if err != nil {
		return Meta{}, nil, err
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Meta{}, nil, fmt.Errorf("%w: v%d.json: %v", ErrCorrupt, ver, err)
	}
	return env.Meta, env.Config, nil
}

// listMetas is the shared List/ListMeta implementation: it scans the version
// dir, skips anything that isn't a version file, reads each candidate, and
// decodes it via the caller-supplied decode func — the only difference
// between List (full envelope, config included) and ListMeta (metaEnvelope,
// config parse-skipped). Unreadable or unparseable files are skipped with a
// log line (D1.2-flag-F5: the rollback UI never sees them otherwise) — never
// an error. The result is always non-nil, sorted descending by version.
func (s *Store) listMetas(decode func([]byte) (Meta, error)) []Meta {
	dir := s.dirSnapshot()
	metas := make([]Meta, 0)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return metas
	}
	for _, e := range entries {
		if _, ok := versionOf(e.Name()); !ok {
			continue
		}
		fullPath := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(fullPath)
		if err != nil {
			obs.Printf("Loader: config_versions: skipping unreadable %q: %v (D1.2-flag-F5)", obs.Sanitize(fullPath), err)
			continue
		}
		meta, derr := decode(data)
		if derr != nil {
			obs.Printf("Loader: config_versions: skipping unparseable %q: %v (D1.2-flag-F5)", obs.Sanitize(fullPath), derr)
			continue
		}
		metas = append(metas, meta)
	}
	sort.Slice(metas, func(i, j int) bool { return metas[i].Version > metas[j].Version })
	return metas
}

// List returns all readable version metadata sorted descending by version.
// Unreadable or unparseable files are skipped with a log line (D1.2-flag-F5:
// the rollback UI never sees them otherwise) — never an error. The result is
// always non-nil.
func (s *Store) List() []Meta {
	return s.listMetas(func(data []byte) (Meta, error) {
		var env envelope
		err := json.Unmarshal(data, &env)
		return env.Meta, err
	})
}

// metaEnvelope decodes ONLY the meta half of a version file. Because the
// "config" field is absent from this struct, json.Unmarshal parse-skips the
// config body instead of allocating a json.RawMessage copy of it — so ListMeta
// never holds a (potentially large) config snapshot's bytes in memory.
type metaEnvelope struct {
	Meta Meta `json:"meta"`
}

// ListMeta is List without the config bodies: it decodes only each file's meta
// object, so a metadata-only caller (e.g. the support-bundle collector) never
// copies up to `max` config snapshots into memory. Same descending order and
// skip-on-error semantics as List; the result is always non-nil.
func (s *Store) ListMeta() []Meta {
	return s.listMetas(func(data []byte) (Meta, error) {
		var env metaEnvelope
		err := json.Unmarshal(data, &env)
		return env.Meta, err
	})
}

// Integrity scans the version directory and reports how many candidate
// v{N}.json files exist (present) versus how many parsed cleanly via
// ListMeta (readable). present > readable means one or more files are
// corrupt or unreadable and have been silently excluded from List/ListMeta
// (D1.2-flag-F5) — those versions are unusable rollback targets even though
// they still count toward the max-versions retention window. Callers use
// this to raise an operator-visible diagnostic instead of relying on the
// obs.Printf skip lines, which are invisible without log/SSH access.
func (s *Store) Integrity() (present, readable int) {
	dir := s.dirSnapshot()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0
	}
	for _, e := range entries {
		if _, ok := versionOf(e.Name()); ok {
			present++
		}
	}
	readable = len(s.ListMeta())
	return present, readable
}

// Seq returns the current sequence counter (the last assigned version).
func (s *Store) Seq() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq
}

// Dir returns the store directory (read by the diagnostics summarizer).
func (s *Store) Dir() string { return s.dirSnapshot() }

func (s *Store) dirSnapshot() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dir
}

// SetDirForTest redirects the store to dir. Test isolation only.
func (s *Store) SetDirForTest(dir string) {
	s.mu.Lock()
	s.dir = dir
	s.mu.Unlock()
}

// SetSeqForTest overrides the sequence counter. Test isolation only.
func (s *Store) SetSeqForTest(n int) {
	s.mu.Lock()
	s.seq = n
	s.mu.Unlock()
}
