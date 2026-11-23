//go:build unix

package journal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestLockReconcile_ExclusiveAndReleasable: a second taker is refused with
// ErrLockHeld while the first holds it, and succeeds after Release. flock is
// per open file description, so two opens in one process exercise it.
func TestLockReconcile_ExclusiveAndReleasable(t *testing.T) {
	j := newTestJournal(t)
	l1, err := j.LockReconcile()
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if _, err := j.LockReconcile(); !errors.Is(err, ErrLockHeld) {
		t.Fatalf("second lock while held: err=%v, want ErrLockHeld", err)
	}
	if err := l1.Release(); err != nil {
		t.Fatal(err)
	}
	l2, err := j.LockReconcile()
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	_ = l2.Release()
	_ = l2.Release() // idempotent
	var nilLock *ReconcileLock
	if err := nilLock.Release(); err != nil {
		t.Errorf("nil Release: %v", err)
	}
}

// TestLockReconcile_RefusesSymlink: a symlink planted at the lock path is not
// followed (O_NOFOLLOW), so the lock cannot be redirected to another file.
func TestLockReconcile_RefusesSymlink(t *testing.T) {
	j := newTestJournal(t)
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(j.Dir(), lockFileName)); err != nil {
		t.Fatal(err)
	}
	if l, err := j.LockReconcile(); err == nil {
		_ = l.Release()
		t.Fatal("lock taken through a symlink")
	}
}

// TestLockReconcile_NotListedAsRecord: the lock file never reads as a record.
func TestLockReconcile_NotListedAsRecord(t *testing.T) {
	j := newTestJournal(t)
	l, err := j.LockReconcile()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Release() }()
	recs, err := j.List()
	if err != nil || len(recs) != 0 {
		t.Errorf("List with only the lock present: %d records, err=%v", len(recs), err)
	}
}
