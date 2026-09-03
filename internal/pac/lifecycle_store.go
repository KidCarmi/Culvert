package pac

// lifecycle_store.go — persistence for per-profile draft/revision lifecycle
// metadata (initiative PR 3). This is NODE-LOCAL operator history (like the
// numbered config-version store): the ACTIVE profile specs already sync
// CP→DP via the PR2 ProfilesConfig surface, so the revision timeline and
// drafts are not cluster-synced and are not on the config-version rollback
// surface. Persisted to <dataDir>/pac_profiles_lifecycle.json.

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// LifecycleStore persists per-profile ProfileLifecycle records keyed by
// profile ID. Like the other stores, Set is tolerant; the zero value is a
// ready, empty store.
type LifecycleStore struct {
	mu      sync.RWMutex
	byID    map[string]*ProfileLifecycle
	path    string
	modTime time.Time
}

// Load reads the store from path; a missing file is a no-op.
func (s *LifecycleStore) Load(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = path
	if s.byID == nil {
		s.byID = map[string]*ProfileLifecycle{}
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured store path
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("pac lifecycle: read %s: %w", path, err)
	}
	var loaded map[string]*ProfileLifecycle
	if err := json.Unmarshal(data, &loaded); err != nil {
		// This is NODE-LOCAL operator history, not serving-critical config (the
		// active served spec lives in pac_profiles.json). A corrupt/truncated
		// file must NOT brick the proxy at startup — quarantine it and start
		// with an empty store so serving comes up fail-open.
		quarantine := path + ".corrupt"
		_ = os.Rename(path, quarantine) //nolint:errcheck // best-effort; empty-start is the fallback
		s.byID = map[string]*ProfileLifecycle{}
		s.modTime = time.Now()
		return fmt.Errorf("pac lifecycle: parse %s failed, quarantined to %s and started empty: %w", path, quarantine, err)
	}
	s.byID = loaded
	if s.byID == nil {
		s.byID = map[string]*ProfileLifecycle{}
	}
	// Pre-2F-A records carry no draft token; migrate them to 1 so every
	// stored draft hands out a non-zero optimistic-concurrency token.
	for id, lc := range s.byID {
		if lc == nil {
			delete(s.byID, id)
			continue
		}
		if lc.DraftRevision < 1 {
			lc.DraftRevision = 1
		}
	}
	s.modTime = time.Now()
	return nil
}

// Get returns a deep copy of the lifecycle for id (a fresh empty one when
// absent) and whether it existed.
func (s *LifecycleStore) Get(id string) (*ProfileLifecycle, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	lc, ok := s.byID[id]
	if !ok {
		return &ProfileLifecycle{ProfileID: id}, false
	}
	return cloneLifecycle(lc), true
}

// All returns deep copies of every lifecycle record (for the GET listing).
func (s *LifecycleStore) All() map[string]*ProfileLifecycle {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]*ProfileLifecycle, len(s.byID))
	for id, lc := range s.byID {
		out[id] = cloneLifecycle(lc)
	}
	return out
}

// Put stores lc (deep-copied) under its ProfileID and persists.
func (s *LifecycleStore) Put(lc *ProfileLifecycle) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byID == nil {
		s.byID = map[string]*ProfileLifecycle{}
	}
	// Persist-before-swap (2F-B, C1): write the candidate map durably first;
	// memory is replaced only on success, so a failed write leaves the
	// in-memory record exactly where it was.
	next := make(map[string]*ProfileLifecycle, len(s.byID)+1)
	for id, cur := range s.byID {
		next[id] = cur
	}
	next[lc.ProfileID] = cloneLifecycle(lc)
	if err := s.persistMap(next); err != nil {
		return err
	}
	s.byID = next
	s.modTime = time.Now()
	return nil
}

// Delete removes a profile's lifecycle record (called when the profile is
// deleted) and persists.
func (s *LifecycleStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[id]; !ok {
		return nil
	}
	next := make(map[string]*ProfileLifecycle, len(s.byID))
	for k, cur := range s.byID {
		if k != id {
			next[k] = cur
		}
	}
	if err := s.persistMap(next); err != nil {
		return err
	}
	s.byID = next
	s.modTime = time.Now()
	return nil
}

// persistMap durably writes the given map (the candidate of a
// persist-before-swap mutation) without touching s.byID.
func (s *LifecycleStore) persistMap(m map[string]*ProfileLifecycle) error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.AtomicWrite(s.path, data, 0o600)
}

// LifecycleState is a full LifecycleStore snapshot for test isolation.
type LifecycleState struct {
	ByID    map[string]*ProfileLifecycle
	Path    string
	ModTime time.Time
}

// Snapshot returns the store state for -shuffle test hermeticity (pair with
// Restore).
func (s *LifecycleStore) Snapshot() LifecycleState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make(map[string]*ProfileLifecycle, len(s.byID))
	for id, lc := range s.byID {
		cp[id] = cloneLifecycle(lc)
	}
	return LifecycleState{ByID: cp, Path: s.path, ModTime: s.modTime}
}

// Restore resets the store to a captured state (test support).
func (s *LifecycleStore) Restore(st LifecycleState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID = make(map[string]*ProfileLifecycle, len(st.ByID))
	for id, lc := range st.ByID {
		s.byID[id] = cloneLifecycle(lc)
	}
	s.path = st.Path
	s.modTime = st.ModTime
}

func cloneLifecycle(lc *ProfileLifecycle) *ProfileLifecycle {
	out := *lc
	out.Draft.Rules = append([]Rule(nil), lc.Draft.Rules...)
	out.Revisions = make([]PublishedRevision, len(lc.Revisions))
	copy(out.Revisions, lc.Revisions)
	for i := range out.Revisions {
		out.Revisions[i].Spec.Rules = append([]Rule(nil), lc.Revisions[i].Spec.Rules...)
	}
	if lc.PendingOp != nil {
		op := *lc.PendingOp
		op.CandidateSpec.Rules = append([]Rule(nil), lc.PendingOp.CandidateSpec.Rules...)
		out.PendingOp = &op
	}
	if lc.Ambiguous != nil {
		amb := *lc.Ambiguous
		amb.Op.CandidateSpec.Rules = append([]Rule(nil), lc.Ambiguous.Op.CandidateSpec.Rules...)
		out.Ambiguous = &amb
	}
	if lc.Operations != nil {
		out.Operations = make([]DecidedOp, len(lc.Operations))
		copy(out.Operations, lc.Operations)
	}
	return &out
}
