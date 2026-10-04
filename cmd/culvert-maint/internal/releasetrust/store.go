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

const maxLedgerBytes = 24 << 20

// Store retains at most four authorized releases. Cached entries may
// recover offline after expiry; a caller-supplied old proof never gains that privilege.
type Store struct {
	mu       sync.Mutex
	path     string
	verifier *releaseproof.Verifier
	now      func() time.Time
	write    func(string, []byte) error
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
	if err := privateDirectory(dir); err != nil {
		return nil, err
	}
	if err := syncDirectory(stateDir); err != nil {
		return nil, err
	}
	if err := syncDirectory(dir); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "ledger.json"), verifier: v, now: time.Now, write: atomicWrite}
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
	l := &ledger{Schema: 1, Entries: make(map[string]releaseproof.Evidence)}
	fi, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || !privateFileOwner(fi) || fi.Mode().Perm()&0o077 != 0 || fi.Size() > maxLedgerBytes {
		return nil, errors.New("release trust: unsafe ledger")
	}
	f, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	d := json.NewDecoder(io.LimitReader(f, maxLedgerBytes+1))
	d.DisallowUnknownFields()
	if err = d.Decode(l); err != nil {
		return nil, errors.New("release trust: corrupt ledger")
	}
	if err = d.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("release trust: trailing ledger data")
	}
	if err := s.validateLedger(l); err != nil {
		return nil, err
	}
	return l, nil
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
	for len(l.Entries) > 4 {
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

func (s *Store) validateLedger(l *ledger) error {
	if l.Schema != 1 || l.Version < 1 || l.Generated.IsZero() || len(l.Entries) == 0 || len(l.Entries) > 4 {
		return errors.New("release trust: invalid ledger")
	}
	for ref, p := range l.Entries {
		a, e := s.verifier.VerifyAuthenticity(p, ref)
		if e != nil || a.CatalogVersion > l.Version || (a.CatalogVersion == l.Version && a.GeneratedAt.After(l.Generated)) {
			return errors.New("release trust: invalid persisted evidence")
		}
	}
	return nil
}
