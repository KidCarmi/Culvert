//go:build linux

package releasetrust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/releaseproof"
)

// rotationFixture is a host whose keyring held two keys ("test" = old,
// "new" = new) and is then rotated to the new key only.
type rotationFixture struct {
	oldKey, newKey fixture
	both, rotated  releaseproof.Policy
}

func newRotationFixture(t *testing.T) rotationFixture {
	t.Helper()
	old := newFixture(t)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nk := fixture{policy: old.policy, key: key, kid: "new", now: old.now}
	both := releaseproof.Policy{CatalogRepository: "test/repo", ProxyRepository: "test/repo",
		Ed25519Keys: map[string][]byte{"test": old.policy.Ed25519Keys["test"], "new": pub}}
	rotated := releaseproof.Policy{CatalogRepository: "test/repo", ProxyRepository: "test/repo",
		Ed25519Keys: map[string][]byte{"new": pub}}
	return rotationFixture{oldKey: old, newKey: nk, both: both, rotated: rotated}
}

// seedRotatedLedger authorizes a (old key, v3), b (new key, v4) and
// c (old key, v5): the replay floor (v5) comes from an entry the rotation
// will invalidate, so a recovery that recomputed the floor from what it kept
// would silently LOWER it to v4.
func seedRotatedLedger(t *testing.T, rf rotationFixture, dir string) (keptRef, droppedA, droppedC string) {
	t.Helper()
	s, err := New(dir, rf.both)
	if err != nil {
		t.Fatal(err)
	}
	now := rf.oldKey.now
	s.now = func() time.Time { return now }
	a, pa := rf.oldKey.proof("a", 3, now)
	b, pb := rf.newKey.proof("b", 4, now)
	c, pc := rf.oldKey.proof("c", 5, now)
	for _, x := range []struct {
		ref string
		p   *releaseproof.Evidence
	}{{a, pa}, {b, pb}, {c, pc}} {
		if err := s.AdmitRollback(x.ref, x.p, "", nil); err != nil {
			t.Fatalf("seed %s: %v", x.ref, err)
		}
	}
	return b, a, c
}

func ledgerPath(dir string) string { return filepath.Join(dir, "release-trust", ledgerName) }

func quarantines(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(ledgerPath(dir) + ".quarantine.*")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func wantReason(t *testing.T, err error, want Reason) {
	t.Helper()
	got, ok := ReasonOf(err)
	if !ok || got != want {
		t.Fatalf("want reason %q, got %v (%v)", want, got, err)
	}
	if !strings.Contains(err.Error(), "signed-update-agent-boundary.md") {
		t.Fatalf("refusal does not name the recovery procedure: %v", err)
	}
	if want != ReasonUnsafe && !strings.Contains(err.Error(), "--recover-release-trust") {
		t.Fatalf("refusal does not name the recovery command: %v", err)
	}
}

func TestRecoverKeyRotationKeepsFloorAndHistory(t *testing.T) {
	rf := newRotationFixture(t)
	dir := t.TempDir()
	kept, droppedA, droppedC := seedRotatedLedger(t, rf, dir)
	before := mustRead(t, ledgerPath(dir))

	// A legitimate key rotation makes valid history fail: startup refuses.
	_, err := New(dir, rf.rotated)
	wantReason(t, err, ReasonPolicyMismatch)

	// Dry run reports the plan and changes nothing.
	rep, err := Recover(dir, rf.rotated, RecoverOptions{})
	if err != nil || rep.Action != actionDryRun || rep.Reason != ReasonPolicyMismatch {
		t.Fatalf("dry run: %+v %v", rep, err)
	}
	if !bytes.Equal(before, mustRead(t, ledgerPath(dir))) || len(quarantines(t, dir)) != 0 {
		t.Fatal("dry run changed state")
	}

	rep, err = Recover(dir, rf.rotated, RecoverOptions{Confirm: true})
	if err != nil || rep.Action != actionRecovered {
		t.Fatalf("recover: %+v %v", rep, err)
	}
	if len(rep.Kept) != 1 || rep.Kept[0] != kept {
		t.Fatalf("kept %v, want only %s", rep.Kept, kept)
	}
	if len(rep.Dropped) != 2 || rep.Dropped[0].Ref != droppedA || rep.Dropped[1].Ref != droppedC {
		t.Fatalf("dropped %+v", rep.Dropped)
	}
	if rep.FloorVersion != 5 || !rep.FloorTime.Equal(rf.oldKey.now) || rep.OldFloorVersion != 5 {
		t.Fatalf("replay floor not preserved: %+v", rep)
	}
	// Trust history is preserved byte-for-byte.
	q := quarantines(t, dir)
	if len(q) != 1 || q[0] != rep.Quarantine || !bytes.Equal(mustRead(t, q[0]), before) {
		t.Fatalf("quarantine copy missing or altered: %v", q)
	}

	s, err := New(dir, rf.rotated)
	if err != nil {
		t.Fatalf("startup after recovery: %v", err)
	}
	now := rf.oldKey.now
	s.now = func() time.Time { return now }
	if err := s.Known(kept); err != nil {
		t.Fatalf("kept entry lost: %v", err)
	}
	if err := s.Known(droppedC); err == nil {
		t.Fatal("entry signed by the rotated-out key still authorized")
	}
	// The floor survived: a fresh catalog BELOW it is still refused, even
	// one newer than every entry the recovery kept.
	old, op := rf.newKey.proof("d", 4, now)
	if err := s.Check(old, op); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("catalog below the preserved floor accepted: %v", err)
	}
	cur, cp := rf.newKey.proof("d", 5, now)
	if err := s.Check(cur, cp); err != nil {
		t.Fatalf("catalog at the floor refused: %v", err)
	}
}

func TestRecoverDisjointRotationLeavesFloorOnlyLedger(t *testing.T) {
	rf := newRotationFixture(t)
	dir := t.TempDir()
	s, err := New(dir, rf.oldKey.policy)
	if err != nil {
		t.Fatal(err)
	}
	now := rf.oldKey.now
	s.now = func() time.Time { return now }
	r, p := rf.oldKey.proof("a", 6, now)
	if err := s.AdmitRollback(r, p, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(dir, rf.rotated, RecoverOptions{Confirm: true}); err != nil {
		t.Fatal(err)
	}
	s, err = New(dir, rf.rotated)
	if err != nil {
		t.Fatalf("floor-only ledger refused: %v", err)
	}
	s.now = func() time.Time { return now }
	old, op := rf.newKey.proof("b", 5, now)
	if err := s.Check(old, op); err == nil {
		t.Fatal("floor-only ledger stopped enforcing the replay floor")
	}
}

func TestRecoverRefusesToLowerFloor(t *testing.T) {
	rf := newRotationFixture(t)
	dir := t.TempDir()
	seedRotatedLedger(t, rf, dir)
	before := mustRead(t, ledgerPath(dir))
	_, err := Recover(dir, rf.rotated, RecoverOptions{Confirm: true, FloorVersion: 4, FloorGenerated: rf.oldKey.now})
	if err == nil || !strings.Contains(err.Error(), "lower") {
		t.Fatalf("stated floor below the recorded one accepted: %v", err)
	}
	if !bytes.Equal(before, mustRead(t, ledgerPath(dir))) || len(quarantines(t, dir)) != 0 {
		t.Fatal("refused recovery changed state")
	}
}

func TestRecoverCorruptRequiresExplicitFloor(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	if _, err := New(dir, f.policy); err != nil {
		t.Fatal(err)
	}
	corrupt := []byte(`{"schema":1,"catalog_version":`)
	if err := os.WriteFile(ledgerPath(dir), corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(dir, f.policy)
	wantReason(t, err, ReasonCorrupt)

	if _, err := Recover(dir, f.policy, RecoverOptions{Confirm: true}); err == nil || !strings.Contains(err.Error(), "--floor-catalog-version") {
		t.Fatalf("corrupt ledger reset without an explicit floor: %v", err)
	}
	if !bytes.Equal(corrupt, mustRead(t, ledgerPath(dir))) || len(quarantines(t, dir)) != 0 {
		t.Fatal("refused recovery changed state")
	}

	floorAt := f.now.Add(-time.Hour)
	rep, err := Recover(dir, f.policy, RecoverOptions{FloorVersion: 7, FloorGenerated: floorAt})
	if err != nil || rep.Action != actionDryRun || !bytes.Equal(corrupt, mustRead(t, ledgerPath(dir))) {
		t.Fatalf("dry run with floor: %+v %v", rep, err)
	}
	rep, err = Recover(dir, f.policy, RecoverOptions{Confirm: true, FloorVersion: 7, FloorGenerated: floorAt})
	if err != nil || rep.FloorVersion != 7 || !rep.FloorTime.Equal(floorAt) || rep.OldFloorKnown {
		t.Fatalf("recover: %+v %v", rep, err)
	}
	if q := quarantines(t, dir); len(q) != 1 || !bytes.Equal(mustRead(t, q[0]), corrupt) {
		t.Fatalf("corrupt bytes not preserved: %v", q)
	}
	s, err := New(dir, f.policy)
	if err != nil {
		t.Fatalf("startup after recovery: %v", err)
	}
	s.now = func() time.Time { return f.now }
	l, err := s.read()
	if err != nil || l.Version != 7 || !l.Generated.Equal(floorAt) {
		t.Fatalf("floor is not the stated one: %+v %v", l, err)
	}
	below, bp := f.proof("a", 6, f.now)
	if err := s.Check(below, bp); err == nil {
		t.Fatal("catalog below the stated floor accepted")
	}
	at, ap := f.proof("a", 7, f.now)
	if err := s.Check(at, ap); err != nil {
		t.Fatalf("catalog at the stated floor refused: %v", err)
	}
}

func TestRecoverRefusesUnsafeLedgerUntouched(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	s, err := New(dir, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return f.now }
	r, p := f.proof("a", 2, f.now)
	if err := s.AdmitRollback(r, p, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ledgerPath(dir), 0o644); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, ledgerPath(dir))
	_, err = New(dir, f.policy)
	wantReason(t, err, ReasonUnsafe)
	for _, opt := range []RecoverOptions{{}, {Confirm: true}, {Confirm: true, FloorVersion: 9, FloorGenerated: f.now}} {
		rep, err := Recover(dir, f.policy, opt)
		if reason, _ := ReasonOf(err); reason != ReasonUnsafe || rep.Action != actionNone {
			t.Fatalf("unsafe ledger not refused: %+v %v", rep, err)
		}
	}
	fi, err := os.Stat(ledgerPath(dir))
	if err != nil || fi.Mode().Perm() != 0o644 || !bytes.Equal(before, mustRead(t, ledgerPath(dir))) || len(quarantines(t, dir)) != 0 {
		t.Fatal("unsafe ledger was rewritten")
	}
	// The documented remedy (fix the mode) restores startup with history intact.
	if err := os.Chmod(ledgerPath(dir), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err = New(dir, f.policy); err != nil || s.Known(r) != nil {
		t.Fatalf("remedied ledger: %v", err)
	}
}

func TestRecoverHealthyOrAbsentIsNoOp(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	if rep, err := Recover(dir, f.policy, RecoverOptions{Confirm: true}); err != nil || rep.Action != actionNone {
		t.Fatalf("absent: %+v %v", rep, err)
	}
	s, err := New(dir, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return f.now }
	r, p := f.proof("a", 2, f.now)
	if err := s.AdmitRollback(r, p, "", nil); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, ledgerPath(dir))
	if rep, err := Recover(dir, f.policy, RecoverOptions{Confirm: true}); err != nil || rep.Action != actionNone || rep.Reason != "" {
		t.Fatalf("healthy: %+v %v", rep, err)
	}
	if !bytes.Equal(before, mustRead(t, ledgerPath(dir))) || len(quarantines(t, dir)) != 0 {
		t.Fatal("healthy ledger rewritten")
	}
}

// Root-run recovery must hand the new ledger to the agent identity: a
// root-owned ledger would be refused as unsafe by a non-root agent.
func TestRecoverPreservesAgentOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to chown")
	}
	const agent = 65534
	rf := newRotationFixture(t)
	dir := t.TempDir()
	seedRotatedLedger(t, rf, dir)
	for _, p := range []string{dir, filepath.Join(dir, "release-trust"), ledgerPath(dir)} {
		if err := os.Chown(p, agent, agent); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := Recover(dir, rf.rotated, RecoverOptions{Confirm: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{ledgerPath(dir), rep.Quarantine} {
		fi, err := os.Lstat(p)
		if err != nil || !privateFileOwner(fi, agent) || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s not agent-owned 0600", p)
		}
	}
	if _, _, err := loadLedger(ledgerPath(dir), agent); err != nil {
		t.Fatalf("agent would refuse the recovered ledger: %v", err)
	}
}
