package pac

// lifecycle_store.go — persistence for per-profile draft/revision lifecycle
// metadata (initiative PR 3). This is NODE-LOCAL operator history (like the
// numbered config-version store): the ACTIVE profile specs already sync
// CP→DP via the PR2 ProfilesConfig surface, so the revision timeline and
// drafts are not cluster-synced and are not on the config-version rollback
// surface. Persisted to <dataDir>/pac_profiles_lifecycle.json.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/google/uuid"
)

// newHistoryIncarnation mints the identity of a fresh history epoch (see
// ProfileLifecycle.HistoryIncarnation).
func newHistoryIncarnation() string { return uuid.NewString() }

// hasHistoryContent reports whether a record carries operator history (a
// saved draft, revisions, an intent) as opposed to being an epoch-identity
// placeholder minted by EnsureIncarnation for a profile nobody has drafted
// against yet.
func hasHistoryContent(lc *ProfileLifecycle) bool {
	return lc.Draft.ID != "" || len(lc.Revisions) > 0 || lc.PendingOp != nil || lc.Ambiguous != nil || len(lc.Operations) > 0
}

// LifecycleStore persists per-profile ProfileLifecycle records keyed by
// profile ID. Like the other stores, Set is tolerant; the zero value is a
// ready, empty store.
type LifecycleStore struct {
	mu      sync.RWMutex
	byID    map[string]*ProfileLifecycle
	path    string
	modTime time.Time
	reset   *HistoryReset // store-level history reset (see HistoryReset)
}

// HistoryReset is the durable, store-level record that the lifecycle file
// was found corrupt and quarantined (2F-B correction, C1). The ACTIVE profile
// store stays the sole authority; what was lost is the node-local history
// (revisions, drafts, pending intents, decided operations). Every active
// profile that existed at the reset is reported as historyState
// history_reset and refuses publish/rollback until an admin acknowledges the
// loss for that profile, bound to the active revision + ProfileSpecDigest it
// reviewed. The record lives beside the store (<path minus .json>.reset.json)
// so it survives restarts until acknowledged; it is written BEFORE the
// corrupt file is moved aside, so a boot that cannot record the reset leaves
// the corrupt file in place and repeats the attempt next time (fail-closed).
type HistoryReset struct {
	At            string `json:"at"`
	QuarantinedTo string `json:"quarantinedTo"`
	Cause         string `json:"cause"`
	// Scoped is true once ActiveAtReset carries the profiles that were active
	// when the reset was recorded; until then EVERY active profile is treated
	// as affected (the conservative reading).
	Scoped        bool                       `json:"scoped"`
	ActiveAtReset []string                   `json:"activeAtReset"`
	Acknowledged  map[string]HistoryResetAck `json:"acknowledged"`
}

// HistoryResetAck is one admin acknowledgement of a lost history.
type HistoryResetAck struct {
	OperationID      string `json:"operationId"`
	By               string `json:"by"`
	At               string `json:"at"`
	ActiveRevision   int64  `json:"activeRevision"`
	ActiveSpecDigest string `json:"activeSpecDigest"`
}

// ErrHistoryReset wraps the Load error returned when the lifecycle file was
// quarantined into a history reset.
var ErrHistoryReset = errors.New("pac lifecycle: history reset")

func resetPathFor(path string) string {
	if path == "" {
		return ""
	}
	return strings.TrimSuffix(path, ".json") + ".reset.json"
}

// Load reads the store from path; a missing file is a no-op. A corrupt file
// is quarantined into a durable HistoryReset (see the type) and the error
// returned wraps ErrHistoryReset; the store then starts empty.
func (s *LifecycleStore) Load(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = path
	if s.byID == nil {
		s.byID = map[string]*ProfileLifecycle{}
	}
	s.loadResetRecordLocked()
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured store path
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("pac lifecycle: read %s: %w", path, err)
	}
	var loaded map[string]*ProfileLifecycle
	if err := json.Unmarshal(data, &loaded); err != nil {
		return s.quarantineLocked(path, err)
	}
	s.byID = loaded
	if s.byID == nil {
		s.byID = map[string]*ProfileLifecycle{}
	}
	// Pre-2F-A records carry no draft token; migrate them to 1 so every
	// stored draft hands out a non-zero optimistic-concurrency token (an
	// epoch-identity placeholder holds no draft and keeps 0). Records that
	// predate the history epoch identity (2F-E correction round 2) are
	// minted one and persisted, so the identity is durable from this boot on.
	minted := false
	for id, lc := range s.byID {
		if lc == nil {
			delete(s.byID, id)
			continue
		}
		if lc.DraftRevision < 1 && hasHistoryContent(lc) {
			lc.DraftRevision = 1
		}
		if lc.HistoryIncarnation == "" {
			lc.HistoryIncarnation = newHistoryIncarnation()
			minted = true
		}
	}
	s.modTime = time.Now()
	if minted {
		if err := s.persistMap(s.byID); err != nil {
			return fmt.Errorf("pac lifecycle: history epoch identities could not be persisted (%w); they are held in memory and re-minted at the next boot", err)
		}
	}
	return nil
}

// EnsureIncarnation returns the identity of profileID's current history
// epoch, minting and durably recording one when the record has none (or does
// not exist yet). Persist-before-swap: a failed write mints nothing.
func (s *LifecycleStore) EnsureIncarnation(profileID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byID == nil {
		s.byID = map[string]*ProfileLifecycle{}
	}
	if cur, ok := s.byID[profileID]; ok && cur.HistoryIncarnation != "" {
		return cur.HistoryIncarnation, nil
	}
	var rec *ProfileLifecycle
	if cur, ok := s.byID[profileID]; ok {
		rec = cloneLifecycle(cur)
	} else {
		rec = &ProfileLifecycle{ProfileID: profileID}
	}
	rec.HistoryIncarnation = newHistoryIncarnation()
	next := make(map[string]*ProfileLifecycle, len(s.byID)+1)
	for id, cur := range s.byID {
		next[id] = cur
	}
	next[profileID] = rec
	if err := s.persistMap(next); err != nil {
		return "", err
	}
	s.byID = next
	s.modTime = time.Now()
	return rec.HistoryIncarnation, nil
}

// loadResetRecordLocked reads the sidecar reset record. An unreadable record
// means acknowledgements can no longer be verified, which is itself a reset
// condition: it is replaced by a fresh, unscoped one (conservative).
func (s *LifecycleStore) loadResetRecordLocked() {
	rp := resetPathFor(s.path)
	if rp == "" {
		return
	}
	data, err := os.ReadFile(rp) // #nosec G304 -- derived from the operator-configured store path
	if os.IsNotExist(err) {
		s.reset = nil
		return
	}
	var r HistoryReset
	if err == nil {
		err = json.Unmarshal(data, &r)
	}
	if err != nil {
		r = s.replaceUnreadableResetLocked(rp, data, err)
	}
	if r.Acknowledged == nil {
		r.Acknowledged = map[string]HistoryResetAck{}
	}
	s.reset = &r
}

// replaceUnreadableResetLocked supersedes an unreadable reset record with a
// fresh, unscoped one WITHOUT ever leaving a window in which no durable
// reset evidence exists (2F-B correction round 2, blocker 1): the unreadable
// bytes are first COPIED aside as evidence, then the replacement is written
// over the record path atomically (temp + rename — the original stays in
// place until the rename lands). If the copy or the write fails, the
// original record is left untouched so the next boot repeats this exact
// path, and the reset stays fail-closed in memory meanwhile.
func (s *LifecycleStore) replaceUnreadableResetLocked(rp string, data []byte, cause error) HistoryReset {
	r := HistoryReset{
		At: time.Now().UTC().Format(time.RFC3339), Cause: "history reset record unreadable: " + cause.Error(),
		Acknowledged: map[string]HistoryResetAck{},
	}
	evidence := fmt.Sprintf("%s.corrupt.%d", rp, time.Now().UnixNano())
	if data == nil {
		// Unreadable rather than unparseable: nothing to copy; leave it.
		return r
	}
	if err := fileutil.AtomicWrite(evidence, data, 0o600); err != nil {
		return r // evidence not preserved → the original stays where it is
	}
	r.QuarantinedTo = evidence
	if err := s.persistReset(&r); err != nil {
		// The original (unreadable) record is still in place: durable reset
		// evidence survives, and the next boot repeats this replacement.
		return r
	}
	return r
}

// quarantineLocked records the reset durably, THEN moves the corrupt file
// aside (never deletes it) and starts empty.
func (s *LifecycleStore) quarantineLocked(path string, cause error) error {
	quarantine := fmt.Sprintf("%s.corrupt.%d", path, time.Now().UnixNano())
	r := &HistoryReset{
		At: time.Now().UTC().Format(time.RFC3339), QuarantinedTo: quarantine,
		Cause: "parse failed: " + cause.Error(), Acknowledged: map[string]HistoryResetAck{},
	}
	if err := s.persistReset(r); err != nil {
		// The reset could not be recorded: leave the corrupt file where it is
		// so the next boot repeats this exact path, and fail closed in memory.
		s.reset = r
		s.byID = map[string]*ProfileLifecycle{}
		s.modTime = time.Now()
		return fmt.Errorf("%w: parse %s failed (%v) and the reset record could not be written (%v); file left in place, publish/rollback refused until acknowledged", ErrHistoryReset, path, cause, err)
	}
	if err := os.Rename(path, quarantine); err != nil {
		r.QuarantinedTo = ""
		_ = s.persistReset(r) //nolint:errcheck // best-effort correction of the recorded location
		s.reset = r
		s.byID = map[string]*ProfileLifecycle{}
		s.modTime = time.Now()
		return fmt.Errorf("%w: parse %s failed (%v); could not move the file aside (%v); started empty, publish/rollback refused until acknowledged", ErrHistoryReset, path, cause, err)
	}
	s.reset = r
	s.byID = map[string]*ProfileLifecycle{}
	s.modTime = time.Now()
	return fmt.Errorf("%w: parse %s failed (%v); quarantined to %s and started empty; publish/rollback refused for the affected profiles until acknowledged", ErrHistoryReset, path, cause, quarantine)
}

// ResetWriteHook is a TEST-ONLY fault-injection seam consulted immediately
// before every durable write of the history-reset record; a non-nil error is
// treated exactly like the underlying write failing. Production leaves it nil.
var ResetWriteHook func(path string) error

func (s *LifecycleStore) persistReset(r *HistoryReset) error {
	rp := resetPathFor(s.path)
	if rp == "" {
		return nil
	}
	if h := ResetWriteHook; h != nil {
		if err := h(rp); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.AtomicWrite(rp, data, 0o600)
}

func cloneReset(r *HistoryReset) *HistoryReset {
	if r == nil {
		return nil
	}
	out := *r
	out.ActiveAtReset = append([]string(nil), r.ActiveAtReset...)
	out.Acknowledged = make(map[string]HistoryResetAck, len(r.Acknowledged))
	for k, v := range r.Acknowledged {
		out.Acknowledged[k] = v
	}
	return &out
}

// HistoryResetRecord returns a copy of the store-level reset record, or nil.
func (s *LifecycleStore) HistoryResetRecord() *HistoryReset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneReset(s.reset)
}

// NoteActiveAtReset scopes a fresh reset to the profiles that were active
// when it was recorded (persist-before-swap). A no-op when there is no
// reset or it is already scoped.
func (s *LifecycleStore) NoteActiveAtReset(activeIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reset == nil || s.reset.Scoped {
		return nil
	}
	next := cloneReset(s.reset)
	next.Scoped = true
	next.ActiveAtReset = append([]string{}, activeIDs...)
	sort.Strings(next.ActiveAtReset)
	if err := s.persistReset(next); err != nil {
		return err
	}
	s.reset = next
	return nil
}

// ResetAffects reports whether profileID (activeExists = an active profile
// exists for it) is in history_reset: a reset is recorded, the profile is
// in its scope (or the scope is unknown), and no acknowledgement exists.
func (s *LifecycleStore) ResetAffects(profileID string, activeExists bool) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.resetAffectsLocked(profileID, activeExists)
}

func (s *LifecycleStore) resetAffectsLocked(profileID string, activeExists bool) bool {
	r := s.reset
	if r == nil || !activeExists {
		return false
	}
	if _, acked := r.Acknowledged[profileID]; acked {
		return false
	}
	if !r.Scoped {
		return true
	}
	for _, id := range r.ActiveAtReset {
		if id == profileID {
			return true
		}
	}
	return false
}

// AcknowledgeReset records an admin acknowledgement for profileID
// (persist-before-swap): a failed write leaves the reset exactly as it was.
func (s *LifecycleStore) AcknowledgeReset(profileID string, ack HistoryResetAck) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reset == nil {
		return errors.New("pac lifecycle: no history reset to acknowledge")
	}
	next := cloneReset(s.reset)
	next.Acknowledged[profileID] = ack
	if err := s.persistReset(next); err != nil {
		return err
	}
	s.reset = next
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
	// The history epoch identity is never dropped by a write: a record
	// written from a clone that predates the identity inherits the stored
	// one; a brand-new record is minted its own.
	if lc.HistoryIncarnation == "" {
		if cur, ok := s.byID[lc.ProfileID]; ok && cur.HistoryIncarnation != "" {
			lc.HistoryIncarnation = cur.HistoryIncarnation
		} else {
			lc.HistoryIncarnation = newHistoryIncarnation()
		}
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
	Reset   *HistoryReset
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
	return LifecycleState{ByID: cp, Path: s.path, ModTime: s.modTime, Reset: cloneReset(s.reset)}
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
	s.reset = cloneReset(st.Reset)
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
