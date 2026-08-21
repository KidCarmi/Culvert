package apply

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// PersistedState is the durable activation metadata for one capability: the
// current + previous signed snapshots, the trusted epoch, the pending
// acknowledgement, and rollback metadata. It is written atomically as one file so
// a crash never leaves current/previous inconsistent.
type PersistedState struct {
	Version      int                    `json:"version"`
	Capability   cpdp.Capability        `json:"capability"`
	Current      *cpdp.Envelope         `json:"current"`
	Previous     *cpdp.Envelope         `json:"previous,omitempty"`
	Epoch        int64                  `json:"epoch"`
	Revisions    cpdp.Revisions         `json:"revisions"`
	PendingAck   *cpdp.Acknowledgement  `json:"pending_ack,omitempty"`
	RollbackMeta *PersistedRollbackMeta `json:"rollback_meta,omitempty"`
}

// PersistedRollbackMeta records that the current active snapshot is the result of
// a rollback, keeping the reverted-from hash explicit.
type PersistedRollbackMeta struct {
	RolledBackFromHash string `json:"rolled_back_from_hash"`
	CommandID          string `json:"command_id"`
}

const persistStateVersion = 1

// SnapStore is the durable persistence seam. The default implementation writes an
// atomic, fsync'd file; tests inject a failing implementation to prove that a
// persistence/fsync/rename failure leaves active state byte-unchanged.
type SnapStore interface {
	// Persist durably writes the state (atomic replacement + file/dir sync). It
	// must return an error WITHOUT leaving a partially-written or corrupt file.
	Persist(st *PersistedState) error
	// Load reads the persisted state, or (nil, nil) if none exists. A corrupt or
	// ambiguous file returns an error (never a permissive empty state).
	Load() (*PersistedState, error)
}

// fileStore is the production SnapStore backed by a single atomic file per
// capability under dir, mode 0600.
type fileStore struct {
	path string
}

// NewFileStore returns a file-backed SnapStore for a capability under dir.
func NewFileStore(dir string, capability cpdp.Capability) SnapStore {
	name := "mcp_" + capability.String() + "_active.json"
	return &fileStore{path: filepath.Join(dir, name)}
}

// Persist writes the state atomically (temp + fsync + rename + parent-dir sync).
func (f *fileStore) Persist(st *PersistedState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return mcperr.Wrap(mcperr.ReasonSnapshotPersistFailed, "cpdp.apply.persist", "marshal state", err)
	}
	// fileutil.AtomicWrite writes to a temp file, fsyncs it, renames over the
	// target, and fsyncs the parent directory — atomic replacement with durability.
	if err := fileutil.AtomicWrite(f.path, raw, 0o600); err != nil {
		return mcperr.Wrap(mcperr.ReasonSnapshotPersistFailed, "cpdp.apply.persist", "atomic write", err)
	}
	return nil
}

// Load reads the persisted state, returning (nil, nil) when no file exists and an
// error (never a permissive empty state) when the file is unreadable or corrupt.
func (f *fileStore) Load() (*PersistedState, error) {
	raw, err := os.ReadFile(f.path) // #nosec G304 -- path is a fixed capability file under the data dir
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil // no persisted state — a fresh DP
		}
		return nil, mcperr.Wrap(mcperr.ReasonSnapshotPersistFailed, "cpdp.apply.persist", "read state", err)
	}
	var st PersistedState
	if err := json.Unmarshal(raw, &st); err != nil {
		// A corrupt file is NEVER turned into a permissive empty state — fail closed.
		return nil, mcperr.Wrap(mcperr.ReasonSnapshotPersistFailed, "cpdp.apply.persist", "corrupt state file", err)
	}
	return &st, nil
}

// verifyRecovered re-verifies a recovered persisted state: signatures + hashes +
// minimum-version on both current and previous, and structural consistency.
// Corrupt/ambiguous metadata returns an error so the caller stays disabled rather
// than activating an unverifiable snapshot.
func verifyRecovered(st *PersistedState, capability cpdp.Capability, trust *cpdp.TrustStore, dpVersion cpdp.CompatVersion, limits cpdp.Limits) error {
	if st == nil {
		return nil
	}
	if st.Version != persistStateVersion {
		return mcperr.New(mcperr.ReasonSnapshotPersistFailed, "cpdp.apply.persist", "unknown persisted-state version")
	}
	if st.Capability != capability {
		return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.apply.persist", "persisted capability mismatch")
	}
	if st.Current == nil {
		if st.Previous != nil {
			return mcperr.New(mcperr.ReasonSnapshotPersistFailed, "cpdp.apply.persist", "previous without current")
		}
		return nil // empty but well-formed — a DP that never activated
	}
	if err := recheck(st.Current, capability, trust, dpVersion, limits); err != nil {
		return err
	}
	if st.Previous != nil {
		if err := recheck(st.Previous, capability, trust, dpVersion, limits); err != nil {
			return err
		}
	}
	return nil
}

func recheck(env *cpdp.Envelope, capability cpdp.Capability, trust *cpdp.TrustStore, dpVersion cpdp.CompatVersion, limits cpdp.Limits) error {
	if env.Manifest.Capability != capability {
		return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.apply.persist", "recovered snapshot capability mismatch")
	}
	if err := cpdp.VerifySignature(env, trust, limits); err != nil {
		return err
	}
	if err := cpdp.CheckMinVersion(env.Manifest.MinDPVersion, dpVersion); err != nil {
		return err
	}
	return nil
}
