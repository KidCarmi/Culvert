package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

const snapshotVersion = 1

var errStateCorrupt = errors.New("state: metadata integrity check failed")

// stateSnapshot is the integrity-protected persistent degraded-state metadata. It
// stores no secrets — only state enums, a scope id, a reason string, timestamps
// and loss counters. The self-digest makes corruption DETECTABLE so a corrupt
// file is never silently replaced with a fresh normal one.
type stateSnapshot struct {
	Version       int    `json:"version"`
	Capability    byte   `json:"capability"`
	Critical      byte   `json:"critical"`
	Denial        byte   `json:"denial"`
	Scope         string `json:"scope"`
	Reason        string `json:"reason"`
	EntryNano     int64  `json:"entry_nano"`
	TransitionSeq uint64 `json:"transition_seq"`
	MarkerDigest  string `json:"marker_digest"`
	CriticalLoss  uint64 `json:"critical_loss"`
	DenialLoss    uint64 `json:"denial_loss"`
	Digest        string `json:"digest"`
}

func (s stateSnapshot) encode() ([]byte, error) {
	s.Digest = ""
	body, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	s.Digest = hex.EncodeToString(sum[:])
	return json.Marshal(s)
}

func decodeSnapshot(b []byte) (stateSnapshot, error) {
	var s stateSnapshot
	// Strict decode: a corrupted JSON KEY (not just a value) must be rejected, not
	// silently ignored — otherwise a byte flip on a field name would decode to the
	// default value and reproduce the original digest.
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return stateSnapshot{}, errStateCorrupt
	}
	if s.Version != snapshotVersion {
		return stateSnapshot{}, errStateCorrupt
	}
	want := s.Digest
	s.Digest = ""
	body, err := json.Marshal(s)
	if err != nil {
		return stateSnapshot{}, errStateCorrupt
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != want {
		return stateSnapshot{}, errStateCorrupt
	}
	s.Digest = want
	return s, nil
}

// FilePersist stores the metadata as a single integrity-protected file in the
// spool's durable location, written atomically via fileutil.AtomicWrite.
type FilePersist struct {
	path string
}

// NewFilePersist returns a file-backed Persist writing to path (0600).
func NewFilePersist(path string) *FilePersist { return &FilePersist{path: path} }

// Save atomically writes the metadata.
func (f *FilePersist) Save(data []byte) error {
	return fileutil.AtomicWrite(f.path, data, 0o600)
}

// Load reads the metadata; an absent file returns (nil, nil).
func (f *FilePersist) Load() ([]byte, error) {
	b, err := os.ReadFile(filepath.Clean(f.path))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return b, nil
}

// MemPersist is an in-memory Persist for tests.
type MemPersist struct {
	mu   sync.Mutex
	data []byte
	// FailLoad, when set, makes Load return an error (corrupt-metadata path).
	FailLoad bool
}

// NewMemPersist returns an empty in-memory Persist.
func NewMemPersist() *MemPersist { return &MemPersist{} }

// Save stores a copy of data.
func (m *MemPersist) Save(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = append([]byte(nil), data...)
	return nil
}

// Load returns a copy of the stored data, or an injected error.
func (m *MemPersist) Load() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailLoad {
		return nil, errStateCorrupt
	}
	if m.data == nil {
		return nil, nil
	}
	return append([]byte(nil), m.data...), nil
}

// Corrupt overwrites the stored bytes to simulate on-disk corruption.
func (m *MemPersist) Corrupt() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.data) > 0 {
		m.data[len(m.data)/2] ^= 0xFF
	}
}
