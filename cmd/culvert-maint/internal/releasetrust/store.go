// Package releasetrust owns the agent's durable signed-release authorization.
// Socket callers supply evidence, never trust roots, policy or recovery floors.
package releasetrust

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/releaseproof"
)

const (
	maxLedgerBytes = 24 << 20
	ledgerName     = "ledger.json"
)

// maxEntries bounds the offline-rollback cache.
const maxEntries = 4

// Store retains at most four authorized releases. Cached entries may
// recover offline after expiry; a caller-supplied old proof never gains that privilege.
type Store struct {
	mu       sync.Mutex
	path     string
	verifier *releaseproof.Verifier
	now      func() time.Time
	write    func(string, []byte) error
	owner    int  // uid that must own the ledger (the agent's own euid)
	poisoned bool // a failed durability barrier must not become a cached authorization
}

type ledger struct {
	Schema    int                              `json:"schema"`
	Version   int                              `json:"catalog_version"`
	Generated time.Time                        `json:"generated_at"`
	Entries   map[string]releaseproof.Evidence `json:"entries"`
}

// New constructs a fail-closed store inside the private agent state directory.
func New(stateDir string, policy releaseproof.Policy) (*Store, error) {
	v, err := releaseproof.NewVerifier(policy)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(stateDir, "release-trust")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := privateDirectory(dir, os.Geteuid()); err != nil {
		return nil, err
	}
	if err := syncDirectory(stateDir); err != nil {
		return nil, err
	}
	if err := syncDirectory(dir); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, ledgerName), verifier: v, now: time.Now, write: atomicWrite, owner: os.Geteuid()}
	if _, err = s.read(); err != nil {
		return nil, err
	}
	return s, nil
}

// Check verifies fresh caller evidence without persisting authorization.
func (s *Store) Check(ref string, proof *releaseproof.Evidence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, err := s.read()
	if err != nil {
		return err
	}
	_, err = s.fresh(l, ref, proof)
	return err
}

// Prepare binds a fresh target to the observed signed baseline and durably
// records both before the first upgrade side effect. A missing baseline fails.
func (s *Store) Prepare(ref string, proof *releaseproof.Evidence, prior string, priorProof *releaseproof.Evidence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, err := s.read()
	if err != nil {
		return err
	}
	a, err := s.fresh(l, ref, proof)
	if err != nil {
		return err
	}
	pa, err := s.authorizeBaseline(l, prior, priorProof)
	if err != nil {
		return err
	}
	if err := a.CheckUpgradeFrom(pa); err != nil {
		return err
	}
	if a.CatalogVersion < l.Version || (a.CatalogVersion == l.Version && a.GeneratedAt.Before(l.Generated)) {
		return errors.New("release trust: target catalog predates signed baseline")
	}
	// Baseline and target must both satisfy the preexisting floor. The floor
	// advances to the maximum only after the pair is validated.
	l.Entries[ref] = *proof
	advance(l, a)
	return s.persist(l, ref, prior)
}

// AdmitRollback authorizes standalone image activation. Cached target evidence
// may be expired, but its signed minimum still constrains the observed baseline.
// Inline/journal recovery uses Known for an already-authorized exact transition.
func (s *Store) AdmitRollback(ref string, proof *releaseproof.Evidence, prior string, priorProof *releaseproof.Evidence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, err := s.read()
	if err != nil {
		return err
	}
	a, err := s.knownAuthorization(l, ref)
	if proof != nil {
		a, err = s.fresh(l, ref, proof)
	}
	if err != nil {
		return err
	}
	_, baselineCached := l.Entries[prior]
	if a.MinUpgradeFrom != "" {
		pa, err := s.authorizeBaseline(l, prior, priorProof)
		if err != nil {
			return err
		}
		if err := a.CheckUpgradeFrom(pa); err != nil {
			return err
		}
	}
	if proof == nil && (a.MinUpgradeFrom == "" || baselineCached) {
		return nil
	}
	if proof != nil {
		if a.CatalogVersion < l.Version || (a.CatalogVersion == l.Version && a.GeneratedAt.Before(l.Generated)) {
			return errors.New("release trust: target catalog predates signed baseline")
		}
		l.Entries[ref] = *proof
		advance(l, a)
	}
	return s.persist(l, ref, prior)
}

// authorizeBaseline authenticates the captured reference; additions are only
// in the private in-memory candidate ledger until the caller persists success.
func (s *Store) authorizeBaseline(l *ledger, prior string, proof *releaseproof.Evidence) (releaseproof.Authorization, error) {
	if prior == "" {
		return releaseproof.Authorization{}, errors.New("release trust: observed signed baseline required")
	}
	if a, err := s.knownAuthorization(l, prior); err == nil {
		return a, nil
	}
	a, err := s.fresh(l, prior, proof)
	if err != nil {
		return a, fmt.Errorf("release trust: baseline: %w", err)
	}
	l.Entries[prior] = *proof
	advance(l, a)
	return a, nil
}

// Known re-verifies persisted evidence, deliberately ignoring only expiry and
// replay floor for the exact previously authorized recovery reference.
func (s *Store) Known(ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, err := s.read()
	if err != nil {
		return err
	}
	return s.known(l, ref)
}

func (s *Store) known(l *ledger, ref string) error {
	_, err := s.knownAuthorization(l, ref)
	return err
}

func (s *Store) knownAuthorization(l *ledger, ref string) (releaseproof.Authorization, error) {
	p, ok := l.Entries[ref]
	if !ok {
		return releaseproof.Authorization{}, errors.New("release trust: no durable authorization for target")
	}
	return s.verifier.VerifyAuthenticity(p, ref)
}

func (s *Store) fresh(l *ledger, ref string, p *releaseproof.Evidence) (releaseproof.Authorization, error) {
	if p == nil {
		return releaseproof.Authorization{}, errors.New("release trust: signed release proof required")
	}
	a, err := s.verifier.Verify(*p, ref, s.now())
	if err != nil {
		return a, err
	}
	if a.CatalogVersion < l.Version || (a.CatalogVersion == l.Version && a.GeneratedAt.Before(l.Generated)) {
		return a, errors.New("release trust: catalog replay rejected")
	}
	return a, nil
}

func advance(l *ledger, a releaseproof.Authorization) {
	if a.CatalogVersion > l.Version || (a.CatalogVersion == l.Version && a.GeneratedAt.After(l.Generated)) {
		l.Version = a.CatalogVersion
		l.Generated = a.GeneratedAt
	}
}

func (s *Store) read() (*ledger, error) {
	if s.poisoned {
		return nil, errors.New("release trust: durability failure requires agent restart")
	}
	l, _, err := loadLedger(s.path, s.owner)
	if err != nil {
		return nil, err
	}
	if err := s.validateEntries(l); err != nil {
		return nil, err
	}
	return l, nil
}

// loadLedger performs the file-safety checks and the structural decode of the
// ledger, including its replay floor. It does NOT verify persisted evidence
// (validateEntries does). A missing file yields an empty ledger and exists=false.
// Every refusal is a *LedgerError naming its class, so startup can say which
// recovery applies.
func loadLedger(path string, owner int) (l *ledger, exists bool, err error) {
	l = &ledger{Schema: 1, Entries: make(map[string]releaseproof.Evidence)}
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return l, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	if err := ledgerFileSafety(fi, owner); err != nil {
		return nil, true, err
	}
	f, err := os.Open(path) //nolint:gosec // fixed name under the private agent state dir
	if err != nil {
		return nil, true, err
	}
	defer func() { _ = f.Close() }()
	d := json.NewDecoder(io.LimitReader(f, maxLedgerBytes+1))
	d.DisallowUnknownFields()
	if err = d.Decode(l); err != nil {
		return nil, true, &LedgerError{Reason: ReasonCorrupt, Detail: "ledger is not a decodable ledger document"}
	}
	if err = d.Decode(&struct{}{}); err != io.EOF {
		return nil, true, &LedgerError{Reason: ReasonCorrupt, Detail: "trailing ledger data"}
	}
	if l.Schema != 1 || l.Version < 1 || l.Generated.IsZero() {
		return nil, true, &LedgerError{Reason: ReasonCorrupt, Detail: "ledger replay floor is missing or invalid"}
	}
	if l.Entries == nil {
		l.Entries = make(map[string]releaseproof.Evidence)
	}
	return l, true, nil
}

// ledgerFileSafety refuses a ledger that is not a bounded, private, regular
// file owned by owner. Such a file is never rewritten by recovery: the
// operator fixes ownership/mode instead, so the content is preserved.
func ledgerFileSafety(fi os.FileInfo, owner int) error {
	switch {
	case !fi.Mode().IsRegular():
		return &LedgerError{Reason: ReasonUnsafe, Detail: "ledger is not a regular file (" + fi.Mode().Type().String() + ")"}
	case !privateFileOwner(fi, owner):
		return &LedgerError{Reason: ReasonUnsafe, Detail: fmt.Sprintf("ledger is not owned by the agent identity (uid %d)", owner)}
	case fi.Mode().Perm()&0o077 != 0:
		return &LedgerError{Reason: ReasonUnsafe, Detail: fmt.Sprintf("ledger mode %04o grants group/other access (must be 0600)", fi.Mode().Perm())}
	case fi.Size() > maxLedgerBytes:
		return &LedgerError{Reason: ReasonUnsafe, Detail: "ledger exceeds the size bound"}
	}
	return nil
}

func (s *Store) persist(l *ledger, target, prior string) error {
	// Never evict the newly authorized target or captured rollback baseline.
	keys := make([]string, 0, len(l.Entries))
	for k := range l.Entries {
		if k != target && k != prior {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for len(l.Entries) > maxEntries {
		delete(l.Entries, keys[0])
		keys = keys[1:]
	}
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if len(b) > maxLedgerBytes {
		return errors.New("release trust: ledger capacity exceeded")
	}
	if err = s.write(s.path, b); err != nil {
		s.poisoned = true
		return fmt.Errorf("release trust: authorization not durable: %w", err)
	}
	return nil
}

func atomicWrite(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".trust-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err = f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}

// validateEntries re-verifies every persisted entry under the CURRENT host
// policy and requires each to lie at or below the recorded replay floor. An
// empty entry set is a valid floor-only ledger (the state an offline recovery
// leaves when no cached evidence verifies under a rotated policy): the replay
// floor is still enforced, only the offline-rollback cache is empty.
func (s *Store) validateEntries(l *ledger) error {
	if len(l.Entries) > maxEntries {
		return &LedgerError{Reason: ReasonPolicyMismatch, Detail: fmt.Sprintf("ledger holds %d entries (bound %d)", len(l.Entries), maxEntries)}
	}
	for ref, p := range l.Entries {
		a, e := s.verifier.VerifyAuthenticity(p, ref)
		if e != nil {
			return &LedgerError{Reason: ReasonPolicyMismatch, Detail: "persisted evidence does not verify under the current host release-trust policy"}
		}
		if aboveFloor(a, l) {
			return &LedgerError{Reason: ReasonPolicyMismatch, Detail: "persisted evidence is newer than the recorded replay floor"}
		}
	}
	return nil
}

func aboveFloor(a releaseproof.Authorization, l *ledger) bool {
	return a.CatalogVersion > l.Version || (a.CatalogVersion == l.Version && a.GeneratedAt.After(l.Generated))
}
