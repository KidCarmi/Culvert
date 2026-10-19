package releasetrust

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/KidCarmi/Culvert/releaseproof"
)

// Offline recovery of a refused ledger. Startup stays fail-closed for every
// refusal class; this is the explicit, operator-run way back that never erases
// trust history:
//
//   - the old ledger is preserved byte-for-byte as ledger.json.quarantine.<UTC>;
//   - the replay floor (catalog_version + generated_at) is carried forward and
//     can only move UP — never reset, never lowered;
//   - only cached entries that still verify under the CURRENT host policy are
//     kept, re-verified exactly as the startup load does;
//   - an unsafe file is never rewritten, and a corrupt one is rewritten only
//     with a floor the operator states explicitly.

// RecoverOptions selects the recovery action. The zero value is a dry run.
type RecoverOptions struct {
	Confirm bool
	// FloorVersion/FloorGenerated is an operator-stated replay floor. It is
	// REQUIRED for a corrupt ledger and may RAISE (never lower) a readable one.
	FloorVersion   int
	FloorGenerated time.Time
	Now            func() time.Time
}

// DroppedEntry names a cached authorization that is not carried forward.
type DroppedEntry struct {
	Ref    string
	Reason string
}

// RecoverReport summarizes what recovery found and did. It never carries
// evidence bytes.
type RecoverReport struct {
	Path            string
	Reason          Reason // "" when the ledger is absent or healthy
	Action          string // "none" | "dry-run" | "recovered"
	OldFloorKnown   bool
	OldFloorVersion int
	OldFloorTime    time.Time
	FloorVersion    int
	FloorTime       time.Time
	Kept            []string
	Dropped         []DroppedEntry
	Quarantine      string
}

const (
	actionNone      = "none"
	actionDryRun    = "dry-run"
	actionRecovered = "recovered"
)

// Recover inspects <stateDir>/release-trust/ledger.json under policy and, with
// opt.Confirm, replaces a refused ledger with one that loads under policy while
// keeping the replay floor. The caller is responsible for running it offline
// (agent stopped, host maintenance lock held) and as root.
func Recover(stateDir string, policy releaseproof.Policy, opt RecoverOptions) (*RecoverReport, error) {
	v, err := releaseproof.NewVerifier(policy)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(stateDir, "release-trust")
	rep := &RecoverReport{Path: filepath.Join(dir, ledgerName), Action: actionNone}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return rep, nil
	}
	uid, gid, err := directoryOwner(dir)
	if err != nil {
		return rep, err
	}
	if err := privateDirectory(dir, uid); err != nil {
		return rep, err
	}
	s := &Store{path: rep.Path, verifier: v, owner: uid}
	next, err := s.plan(rep, opt)
	if err != nil || next == nil {
		return rep, err
	}
	if !opt.Confirm {
		rep.Action = actionDryRun
		return rep, nil
	}
	if err := s.commitRecovery(rep, next, uid, gid, opt); err != nil {
		return rep, err
	}
	rep.Action = actionRecovered
	return rep, nil
}

// plan decides the replacement ledger, or nil when there is nothing to do.
func (s *Store) plan(rep *RecoverReport, opt RecoverOptions) (*ledger, error) {
	l, exists, err := loadLedger(s.path, s.owner)
	if !exists {
		return nil, err
	}
	if err != nil {
		reason, ok := ReasonOf(err)
		if !ok {
			return nil, err
		}
		rep.Reason = reason
		if reason != ReasonCorrupt {
			return nil, err // unsafe: fix ownership/mode, never rewrite
		}
		return planFromStatedFloor(rep, opt)
	}
	verr := s.validateEntries(l)
	if verr == nil {
		return nil, nil // healthy under the current policy: nothing to recover
	}
	rep.Reason, _ = ReasonOf(verr)
	return s.planFromReadableFloor(rep, l, opt)
}

func planFromStatedFloor(rep *RecoverReport, opt RecoverOptions) (*ledger, error) {
	if opt.FloorVersion < 1 || opt.FloorGenerated.IsZero() {
		return nil, errors.New("release trust: the corrupt ledger's replay floor cannot be read; refusing to reset it — supply the last known signed catalog floor with --floor-catalog-version and --floor-generated-at")
	}
	n := &ledger{Schema: 1, Version: opt.FloorVersion, Generated: opt.FloorGenerated.UTC(), Entries: map[string]releaseproof.Evidence{}}
	rep.FloorVersion, rep.FloorTime = n.Version, n.Generated
	return n, nil
}

func (s *Store) planFromReadableFloor(rep *RecoverReport, old *ledger, opt RecoverOptions) (*ledger, error) {
	rep.OldFloorKnown, rep.OldFloorVersion, rep.OldFloorTime = true, old.Version, old.Generated
	n := &ledger{Schema: 1, Version: old.Version, Generated: old.Generated, Entries: map[string]releaseproof.Evidence{}}
	if err := raiseToStatedFloor(n, opt); err != nil {
		return nil, err
	}
	refs := make([]string, 0, len(old.Entries))
	for ref := range old.Entries {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		a, err := s.verifier.VerifyAuthenticity(old.Entries[ref], ref)
		if err != nil {
			rep.Dropped = append(rep.Dropped, DroppedEntry{Ref: ref, Reason: "does not verify under the current host policy"})
			continue
		}
		n.Entries[ref] = old.Entries[ref]
		advance(n, a) // a signed entry above a stale floor only RAISES it
	}
	for len(n.Entries) > maxEntries { // same deterministic pruning as persist
		ref := firstKey(n.Entries)
		delete(n.Entries, ref)
		rep.Dropped = append(rep.Dropped, DroppedEntry{Ref: ref, Reason: "capacity"})
	}
	for ref := range n.Entries {
		rep.Kept = append(rep.Kept, ref)
	}
	sort.Strings(rep.Kept)
	rep.FloorVersion, rep.FloorTime = n.Version, n.Generated
	return n, nil
}

// raiseToStatedFloor applies an operator-stated floor to a READABLE one. It
// may only raise it: a stated floor below the recorded one is refused.
func raiseToStatedFloor(n *ledger, opt RecoverOptions) error {
	if opt.FloorVersion == 0 && opt.FloorGenerated.IsZero() {
		return nil
	}
	if opt.FloorVersion < 1 || opt.FloorGenerated.IsZero() {
		return errors.New("release trust: --floor-catalog-version and --floor-generated-at must be supplied together")
	}
	stated := releaseproof.Authorization{CatalogVersion: opt.FloorVersion, GeneratedAt: opt.FloorGenerated.UTC()}
	if stated.CatalogVersion < n.Version || (stated.CatalogVersion == n.Version && stated.GeneratedAt.Before(n.Generated)) {
		return fmt.Errorf("release trust: refusing to lower the recorded replay floor (catalog_version %d, generated_at %s)", n.Version, n.Generated.Format(time.RFC3339))
	}
	advance(n, stated)
	return nil
}

func firstKey(m map[string]releaseproof.Evidence) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys[0]
}

// commitRecovery preserves the old ledger and installs next. The old file is
// first HARD-LINKED to its quarantine name, then next atomically renamed over
// ledger.json: the end state is a move, but there is never an instant with no
// ledger — an absent ledger loads as an EMPTY floor, which is exactly the
// trust-history reset this procedure exists to avoid.
func (s *Store) commitRecovery(rep *RecoverReport, next *ledger, uid, gid int, opt RecoverOptions) error {
	if err := s.validateEntries(next); err != nil {
		return fmt.Errorf("release trust: recovered ledger would not load: %w", err)
	}
	b, err := json.Marshal(next)
	if err != nil {
		return err
	}
	now := time.Now
	if opt.Now != nil {
		now = opt.Now
	}
	dir := filepath.Dir(s.path)
	q := s.path + ".quarantine." + now().UTC().Format("20060102T150405.000000000Z")
	if err := os.Link(s.path, q); err != nil {
		return fmt.Errorf("release trust: preserve old ledger: %w", err)
	}
	if err := syncDirectory(dir); err != nil {
		return err
	}
	rep.Quarantine = q
	if err := writeOwned(s.path, b, uid, gid); err != nil {
		return fmt.Errorf("release trust: install recovered ledger: %w", err)
	}
	// Prove the result is exactly what the agent will accept at startup.
	l, _, err := loadLedger(s.path, uid)
	if err == nil {
		err = s.validateEntries(l)
	}
	if err != nil {
		return fmt.Errorf("release trust: recovered ledger failed its own load check: %w", err)
	}
	return nil
}

// writeOwned is atomicWrite for a root-run recovery: the file is created 0600
// and handed to the agent identity BEFORE it becomes visible as the ledger.
func writeOwned(path string, b []byte, uid, gid int) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".trust-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	steps := []func() error{
		func() error { return f.Chmod(0o600) },
		func() error { return f.Chown(uid, gid) },
		func() error { _, werr := f.Write(b); return werr },
		f.Sync,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
