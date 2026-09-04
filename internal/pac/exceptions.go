package pac

// exceptions.go — PAC Exception Intelligence P2: governance metadata for PAC
// DIRECT bypasses. Attaches owner / justification / business-app / ticket /
// expiry / review cadence to each profile that can emit a full-security-path
// bypass, so every DIRECT exception is owned, justified, and time-bounded.
//
// This is NODE-LOCAL operator metadata (like the lifecycle store): it does not
// affect the served PAC and is NOT cluster-synced — DP nodes never need it.
// Persisted to <dataDir>/pac_exceptions.json and on the backup surface;
// restore it on a promoted node after failover. Governance status is a pure
// function of the record + a caller-supplied clock (no wall-clock in the
// engine), evaluated only for profiles the inventory finds DIRECT-capable.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// Governance status values (stable API strings). Empty means "not applicable"
// (the profile cannot emit DIRECT, so it needs no exception governance).
const (
	// GovUngoverned: a DIRECT-capable profile with no owner or no reason — an
	// unowned/unjustified bypass.
	GovUngoverned = "ungoverned"
	// GovExpired: the exception's expiry is in the past — it should be renewed
	// or removed.
	GovExpired = "expired"
	// GovReviewDue: past the review cadence since the last review (or never
	// reviewed) — due for re-attestation.
	GovReviewDue = "review_due"
	// GovGoverned: owned, justified, not expired, and review-current.
	GovGoverned = "governed"
)

// ExceptionRecord is the governance metadata for one profile's DIRECT
// exposure. All timestamps are RFC3339 UTC strings; the engine takes no wall
// clock, so status is evaluated against a caller-supplied now.
type ExceptionRecord struct {
	ProfileID         string `json:"profileId"`
	Owner             string `json:"owner,omitempty"`
	Reason            string `json:"reason,omitempty"`
	BusinessApp       string `json:"businessApp,omitempty"`
	Ticket            string `json:"ticket,omitempty"`
	CreatedBy         string `json:"createdBy,omitempty"`
	CreatedAt         string `json:"createdAt,omitempty"`
	UpdatedAt         string `json:"updatedAt,omitempty"`
	ExpiresAt         string `json:"expiresAt,omitempty"`         // optional
	ReviewCadenceDays int    `json:"reviewCadenceDays,omitempty"` // 0 = no cadence
	LastReviewedAt    string `json:"lastReviewedAt,omitempty"`
	// Revision is the record's optimistic-concurrency token (2F-A): 1 on
	// create, +1 on every PUT. The store is node-local and deliberately OFF
	// config-version rollback and cluster sync, which is a different property
	// from being unfenced — a PUT/DELETE must echo the revision it loaded.
	// Records persisted before 2F-A load as 1 (see ExceptionStore.Load).
	Revision int64 `json:"revision,omitempty"`
}

// Status classifies the governance posture of a DIRECT-capable profile at
// time now. directCapable=false returns "" (governance is not applicable).
// A malformed ExpiresAt is treated as expired (fail-safe — an unparseable
// deadline must not read as "still valid").
func (e ExceptionRecord) Status(now time.Time, directCapable bool) string {
	if !directCapable {
		return ""
	}
	// Trim before the empty check so a whitespace-only owner/reason (reachable
	// via a hand-edited or restored pac_exceptions.json — the API write path
	// already rejects it) reads as ungoverned, not governed. The pure function
	// must be self-sufficiently fail-safe rather than rely on the caller.
	if strings.TrimSpace(e.Owner) == "" || strings.TrimSpace(e.Reason) == "" {
		return GovUngoverned
	}
	if e.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, e.ExpiresAt)
		if err != nil || !now.Before(t) {
			return GovExpired
		}
	}
	// A non-zero cadence is active. A NEGATIVE cadence is invalid config (the
	// API rejects it; only the load/restore path can carry it) — treat it as
	// review-due (fail-safe nudge) rather than silently disabling review.
	if e.ReviewCadenceDays != 0 {
		last, err := time.Parse(time.RFC3339, e.LastReviewedAt)
		if err != nil || now.After(last.AddDate(0, 0, e.ReviewCadenceDays)) {
			return GovReviewDue
		}
	}
	return GovGoverned
}

// ExceptionStore persists ExceptionRecords keyed by profile ID. The zero
// value is a ready, empty store; mutation is race-safe.
type ExceptionStore struct {
	mu      sync.RWMutex
	byID    map[string]ExceptionRecord
	path    string
	modTime time.Time
}

// Load reads the store from path; a missing file is a no-op. A corrupt file is
// quarantined and the store starts empty (node-local metadata must never brick
// startup).
func (s *ExceptionStore) Load(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = path
	if s.byID == nil {
		s.byID = map[string]ExceptionRecord{}
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured store path
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("pac exceptions: read %s: %w", path, err)
	}
	var loaded map[string]ExceptionRecord
	if err := json.Unmarshal(data, &loaded); err != nil {
		quarantine := path + ".corrupt"
		_ = os.Rename(path, quarantine) //nolint:errcheck // best-effort; empty-start is the fallback
		s.byID = map[string]ExceptionRecord{}
		s.modTime = time.Now()
		return fmt.Errorf("pac exceptions: parse %s failed, quarantined to %s and started empty: %w", path, quarantine, err)
	}
	s.byID = loaded
	if s.byID == nil {
		s.byID = map[string]ExceptionRecord{}
	}
	for id := range s.byID {
		if s.byID[id].Revision < 1 {
			rec := s.byID[id]
			rec.Revision = 1
			s.byID[id] = rec
		}
	}
	s.modTime = time.Now()
	return nil
}

// Get returns the record for id and whether it existed.
func (s *ExceptionStore) Get(id string) (ExceptionRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.byID[id]
	return rec, ok
}

// All returns a copy of every record.
func (s *ExceptionStore) All() map[string]ExceptionRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]ExceptionRecord, len(s.byID))
	for id := range s.byID {
		out[id] = s.byID[id]
	}
	return out
}

// Put stores rec under its ProfileID and persists.
func (s *ExceptionStore) Put(rec ExceptionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byID == nil {
		s.byID = map[string]ExceptionRecord{}
	}
	if rec.Revision < 1 {
		rec.Revision = 1 // every stored record hands out a non-zero token (2F-A)
	}
	s.byID[rec.ProfileID] = rec
	s.modTime = time.Now()
	return s.persistLocked()
}

// Delete removes a profile's record (e.g. when the profile is deleted) and
// persists. Missing is a no-op.
func (s *ExceptionStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[id]; !ok {
		return nil
	}
	delete(s.byID, id)
	s.modTime = time.Now()
	return s.persistLocked()
}

// exceptionsMarshal is the marshaler persistLocked uses. It is a package var
// (not a direct json.MarshalIndent call) only so a test can force the otherwise
// unreachable marshal-error path and prove it propagates rather than being
// swallowed. Production always uses json.MarshalIndent.
var exceptionsMarshal = func(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }

func (s *ExceptionStore) persistLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := exceptionsMarshal(s.byID)
	if err != nil {
		return err
	}
	return fileutil.AtomicWrite(s.path, data, 0o600)
}

// ExceptionState is a full ExceptionStore snapshot for test isolation.
type ExceptionState struct {
	ByID    map[string]ExceptionRecord
	Path    string
	ModTime time.Time
}

// Snapshot returns the store state for -shuffle test hermeticity.
func (s *ExceptionStore) Snapshot() ExceptionState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make(map[string]ExceptionRecord, len(s.byID))
	for id := range s.byID {
		cp[id] = s.byID[id]
	}
	return ExceptionState{ByID: cp, Path: s.path, ModTime: s.modTime}
}

// Restore resets the store to a captured state (test support).
func (s *ExceptionStore) Restore(st ExceptionState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID = make(map[string]ExceptionRecord, len(st.ByID))
	for id := range st.ByID {
		s.byID[id] = st.ByID[id]
	}
	s.path = st.Path
	s.modTime = st.ModTime
}
