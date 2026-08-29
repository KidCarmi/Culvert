package fileblock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// ErrRevisionConflict is returned by a fenced mutation whose asserted revision
// no longer matches the committed profile set (another admin mutated it in
// between). Carries the CURRENT revision so the API can render a structured
// 409 the client uses to refresh.
type ErrRevisionConflict struct{ Current string }

func (e *ErrRevisionConflict) Error() string {
	return "file profiles changed since you loaded them — refresh and retry"
}

// FileExtProfile is a named set of file extensions used for per-policy-rule blocking.
type FileExtProfile struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Extensions []string `json:"extensions"`
}

// FileProfileStore manages a persistent collection of file extension profiles.
// All operations are safe for concurrent use.
//
// DURABILITY + PUBLICATION CONTRACT (2D-C.0B):
//
//   - Elements are IMMUTABLE after publication: every mutation builds a NEW
//     slice with NEW element values (copy-on-write pointer swap) — never an
//     in-place field write, which would race the lock-free p.Extensions reads
//     on the enforcement path (FileProfileBlocked reads the returned pointer
//     outside the store lock).
//   - Mutations are durable-or-nothing: the TARGET set is persisted FIRST
//     (AtomicWrite) and the in-memory swap happens only after the write
//     landed. A hard persistence failure returns the error with memory (and
//     therefore restart truth) unchanged. fileutil.ErrReplacedNotSynced
//     follows the landed-content doctrine: the file visibly contains the new
//     set, so memory swaps forward and the sentinel is surfaced, never rolled
//     back against landed content.
//   - The revision is a CONTENT-DERIVED semantic fingerprint (Revision) over
//     the sorted (id, name, normalized extensions) tuples — restart-stable
//     with no on-disk format migration, which is exactly what a browser
//     optimistic fence needs. A fenced mutation compares the asserted
//     revision INSIDE the same critical section that mutates and persists.
type FileProfileStore struct {
	mu       sync.RWMutex
	profiles []*FileExtProfile
	path     string
}

// builtInProfiles seeds the store on first use so existing policy rules that
// reference the legacy hardcoded profile names continue to work.
var builtInProfiles = []*FileExtProfile{
	{
		ID:   "builtin-executables",
		Name: "Executables",
		Extensions: []string{
			".exe", ".dll", ".bat", ".cmd", ".ps1",
			".scr", ".msi", ".pif", ".com", ".vbs",
		},
	},
	{
		ID:   "builtin-archives",
		Name: "Archives",
		Extensions: []string{
			".zip", ".rar", ".7z", ".tar", ".gz",
			".bz2", ".xz", ".cab", ".iso",
		},
	},
	{
		ID:   "builtin-documents",
		Name: "Documents",
		Extensions: []string{
			".docm", ".xlsm", ".pptm", ".xlam", ".dotm",
		},
	},
	{
		ID:   "builtin-media",
		Name: "Media",
		Extensions: []string{
			".mp3", ".mp4", ".avi", ".mkv", ".mov",
			".flv", ".wmv", ".webm",
		},
	},
	{
		ID:   "builtin-strict",
		Name: "Strict",
		Extensions: []string{
			".exe", ".dll", ".bat", ".cmd", ".ps1", ".scr", ".msi", ".pif", ".com", ".vbs",
			".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".iso",
			".docm", ".xlsm", ".pptm",
		},
	},
}

// Load reads profiles from disk. If the file does not exist the built-in
// profiles are seeded and persisted so policy rules continue to work.
func (s *FileProfileStore) Load(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = path

	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured profiles path
	if errors.Is(err, os.ErrNotExist) {
		// First run — seed built-ins and persist.
		s.profiles = make([]*FileExtProfile, len(builtInProfiles))
		copy(s.profiles, builtInProfiles)
		return s.saveLocked()
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &s.profiles)
}

// SetPath sets the persistence file path without reading from disk (use Load to
// also read existing profiles). Added for the package boundary: package main
// integration tests need to redirect persistence without the whitebox field
// access they relied on before the move.
func (s *FileProfileStore) SetPath(p string) {
	s.mu.Lock()
	s.path = p
	s.mu.Unlock()
}

func (s *FileProfileStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.profiles, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.AtomicWrite(s.path, data, 0o600)
}

// Save persists the current profile set to the configured path.
func (s *FileProfileStore) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

// List returns a copy of all profiles.
func (s *FileProfileStore) List() []*FileExtProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*FileExtProfile, len(s.profiles))
	copy(out, s.profiles)
	return out
}

// ReplaceAll atomically replaces all profiles in memory and persists the new
// set. FOLLOWER semantics by design (2D-C.0B §12 audit): the ONLY production
// caller is the CP→DP ConfigSnapshot apply, where the CONTROL PLANE is the
// source of truth — the in-memory swap is authoritative so the DP enforces the
// CP's profiles even on a wedged local disk, the persist failure is logged
// (and observed by the CHAOS-45 durable-write chokepoint), and the next CP
// sync re-converges. Local confirmed administrative mutations must NEVER use
// this path — they go through Create/Update/Delete, which are
// durable-or-nothing. Tests are the other callers (state seeding).
func (s *FileProfileStore) ReplaceAll(profiles []FileExtProfile) {
	s.mu.Lock()
	s.profiles = make([]*FileExtProfile, len(profiles))
	for i := range profiles {
		p := profiles[i]
		s.profiles[i] = &p
	}
	if err := s.saveLocked(); err != nil {
		obs.Printf("FileProfileStore: ReplaceAll persist: %v", err)
	}
	s.mu.Unlock()
}

// GetByName returns the profile with the given name (case-insensitive), or nil.
func (s *FileProfileStore) GetByName(name string) *FileExtProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.profiles {
		if strings.EqualFold(p.Name, name) {
			return p
		}
	}
	return nil
}

// GetByID returns the profile with the given ID, or nil.
func (s *FileProfileStore) GetByID(id string) *FileExtProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.profiles {
		if p.ID == id {
			return p
		}
	}
	return nil
}

// NameByID returns the profile's name (a value copy, read under the lock) and
// whether it exists. Callers needing only the name must use this rather than
// GetByID().Name — GetByID returns the LIVE pointer, and reading .Name off it
// outside the lock races a concurrent Update (which mutates p.Name in place).
func (s *FileProfileStore) NameByID(id string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.profiles {
		if p.ID == id {
			return p.Name, true
		}
	}
	return "", false
}

// Revision returns the content-derived semantic fingerprint of the committed
// profile set. Restart-stable: same profiles ⇒ same revision across restarts.
func (s *FileProfileStore) Revision() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return fingerprintProfiles(s.profiles)
}

// SnapshotWithRevision returns the profile rows AND the revision that
// describes exactly them, captured under ONE read lock (coherent-read
// doctrine, 2D-A/2D-B): a management GET must never pair rows from one state
// with another state's fence token. The returned pointers are immutable
// published values (see the store contract).
func (s *FileProfileStore) SnapshotWithRevision() ([]*FileExtProfile, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*FileExtProfile, len(s.profiles))
	copy(out, s.profiles)
	return out, fingerprintProfiles(s.profiles)
}

// fingerprintProfiles hashes the sorted (id, name, extensions) tuples.
// Length-framed fields under a version tag; extensions are already normalized
// (normExts) so the fingerprint is canonical.
func fingerprintProfiles(profiles []*FileExtProfile) string {
	rows := make([]string, 0, len(profiles))
	for _, p := range profiles {
		rows = append(rows, p.ID+"\x00"+p.Name+"\x00"+strings.Join(p.Extensions, ","))
	}
	sort.Strings(rows)
	h := sha256.New()
	h.Write([]byte("fpv1\x00"))
	for _, r := range rows {
		fmt.Fprintf(h, "%d\x00%s\x00", len(r), r)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// fenceLocked compares an asserted revision against the committed set; "" =
// no fence (legacy/non-v2 callers keep working unchanged). Caller holds s.mu.
func (s *FileProfileStore) fenceLocked(ifRevision string) error {
	if ifRevision == "" {
		return nil
	}
	if cur := fingerprintProfiles(s.profiles); cur != ifRevision {
		return &ErrRevisionConflict{Current: cur}
	}
	return nil
}

// commitLocked persists the target set and, only after the write landed,
// publishes it as the in-memory truth. Landed-content doctrine: a replaced-
// not-synced write DID land the new content, so memory moves forward and the
// sentinel is returned for the caller to surface. Caller holds s.mu.
func (s *FileProfileStore) commitLocked(target []*FileExtProfile) error {
	if s.path != "" {
		data, err := json.MarshalIndent(target, "", "  ")
		if err != nil {
			return err
		}
		if err := fileutil.AtomicWrite(s.path, data, 0o600); err != nil {
			if !errors.Is(err, fileutil.ErrReplacedNotSynced) {
				return err // hard failure: memory and restart truth stay OLD
			}
			s.profiles = target
			return err // landed content: new truth, degraded durability surfaced
		}
	}
	s.profiles = target
	return nil
}

// Create adds a new profile, durable-or-nothing. ifRevision "" skips the
// optimistic fence. Returns an error if the name is already taken.
func (s *FileProfileStore) Create(name string, exts []string) (*FileExtProfile, error) {
	return s.CreateFenced("", name, exts)
}

// CreateFenced is Create with the v2 optimistic-revision fence: comparison,
// mutation, and durable publish share this one critical section.
func (s *FileProfileStore) CreateFenced(ifRevision, name string, exts []string) (*FileExtProfile, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("profile name must not be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.fenceLocked(ifRevision); err != nil {
		return nil, err
	}
	for _, p := range s.profiles {
		if strings.EqualFold(p.Name, name) {
			return nil, fmt.Errorf("profile %q already exists", name)
		}
	}
	prof := &FileExtProfile{
		ID:         uuid.NewString(),
		Name:       name,
		Extensions: normExts(exts),
	}
	target := append(append(make([]*FileExtProfile, 0, len(s.profiles)+1), s.profiles...), prof)
	if err := s.commitLocked(target); err != nil {
		if errors.Is(err, fileutil.ErrReplacedNotSynced) {
			return prof, err // landed content — created; degraded durability surfaced
		}
		return nil, err
	}
	return prof, nil
}

// Update replaces the name and/or extensions of an existing profile,
// durable-or-nothing (copy-on-write — the published element is never mutated
// in place). ifRevision "" skips the fence (legacy callers).
func (s *FileProfileStore) Update(id, name string, exts []string) error {
	return s.UpdateFenced("", id, name, exts)
}

// UpdateFenced is Update with the v2 optimistic-revision fence.
func (s *FileProfileStore) UpdateFenced(ifRevision, id, name string, exts []string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("profile name must not be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.fenceLocked(ifRevision); err != nil {
		return err
	}
	for i, p := range s.profiles {
		if p.ID != id {
			continue
		}
		// Check name uniqueness (allow keeping the same name).
		if !strings.EqualFold(p.Name, name) {
			for _, other := range s.profiles {
				if other.ID != id && strings.EqualFold(other.Name, name) {
					return fmt.Errorf("profile %q already exists", name)
				}
			}
		}
		np := &FileExtProfile{ID: p.ID, Name: name, Extensions: normExts(exts)}
		target := append([]*FileExtProfile(nil), s.profiles...)
		target[i] = np
		return s.commitLocked(target)
	}
	return fmt.Errorf("profile %q not found", id)
}

// Delete removes a profile by ID, durable-or-nothing. ifRevision "" skips the
// fence (legacy callers).
func (s *FileProfileStore) Delete(id string) error {
	return s.DeleteFenced("", id)
}

// DeleteFenced is Delete with the v2 optimistic-revision fence.
func (s *FileProfileStore) DeleteFenced(ifRevision, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.fenceLocked(ifRevision); err != nil {
		return err
	}
	for i, p := range s.profiles {
		if p.ID == id {
			target := append(append(make([]*FileExtProfile, 0, len(s.profiles)-1), s.profiles[:i]...), s.profiles[i+1:]...)
			return s.commitLocked(target)
		}
	}
	return fmt.Errorf("profile %q not found", id)
}

// normExts normalises a list of extensions to lowercase with a leading dot.
func normExts(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, e := range in {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" || e == "." {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return out
}
