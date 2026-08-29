package logstore

// enckey_chaos_test.go — CHAOS-57 gates for the salt sidecar.
//
// The defect these pin is a one-way destruction of key material by the READ
// path: EncKey used to mint and WRITE a fresh salt whenever the sidecar was
// unreadable or the wrong length, including when an encrypted store was sitting
// right next to it. The derived key is a pure function of (passphrase, salt), so
// that overwrite replaced the only value that could ever decrypt the store —
// and the resulting failure ("different encryption key") is indistinguishable
// from an ordinary passphrase change, so the operator's remedy became "purge",
// destroying history that was intact until EncKey ran.
//
// It is reachable by exactly the fault this store has to survive: a torn 32-byte
// sidecar after an unclean kill.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The defect gate. A damaged sidecar beside an existing store must fail LOUD
// and leave the sidecar alone, so restoring it from a backup still recovers the
// history.
func TestChaos57_TornSaltNeverMintsOverAnExistingStore(t *testing.T) {
	dir := seedHistory(t, 50)
	good, err := os.ReadFile(dir + ".salt")
	if err != nil {
		t.Fatalf("read salt: %v", err)
	}

	torn := []byte("xx") // a partial write of the 32-byte sidecar
	if err := os.WriteFile(dir+".salt", torn, 0o600); err != nil {
		t.Fatalf("torn salt: %v", err)
	}

	key, err := EncKey(dir, chaosPass)
	if err == nil {
		t.Fatal("EncKey minted a key over an existing store — the history is now permanently unreadable")
	}
	if !errors.Is(err, ErrSaltUnusable) {
		t.Errorf("err = %v, want ErrSaltUnusable", err)
	}
	if key != nil {
		t.Error("a key was returned alongside the error")
	}

	after, err := os.ReadFile(dir + ".salt")
	if err != nil {
		t.Fatalf("salt sidecar disappeared: %v", err)
	}
	if !bytes.Equal(after, torn) {
		t.Fatal("EncKey WROTE to the salt sidecar on the failure path — the original key material is unrecoverable")
	}

	// The recovery the refusal preserves: restore the sidecar, open the store,
	// read the history back.
	if err := os.WriteFile(dir+".salt", good, 0o600); err != nil { //nolint:gosec // G703: test fixture under t.TempDir()
		t.Fatalf("restore salt: %v", err)
	}
	restored, err := EncKey(dir, chaosPass)
	if err != nil {
		t.Fatalf("EncKey after restoring the sidecar: %v", err)
	}
	s, _, err := OpenResilientTTL(dir, 0, 0, restored, nil)
	if err != nil {
		t.Fatalf("store did not reopen after restoring the sidecar: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close the recovered store: %v", err)
	}
}

// A MISSING sidecar next to an existing store is the same condition — the
// commonest way to reach it is restoring a backup that (correctly) excludes key
// material.
func TestChaos57_MissingSaltNeverMintsOverAnExistingStore(t *testing.T) {
	dir := seedHistory(t, 20)
	if err := os.Remove(dir + ".salt"); err != nil {
		t.Fatalf("remove salt: %v", err)
	}
	if _, err := EncKey(dir, chaosPass); !errors.Is(err, ErrSaltUnusable) {
		t.Fatalf("EncKey = %v, want ErrSaltUnusable", err)
	}
	if _, err := os.Stat(dir + ".salt"); err == nil {
		t.Fatal("EncKey created a salt sidecar next to an existing store")
	}
}

// The other half of the rule: minting stays reachable whenever there is nothing
// to lose, or the feature is off. Refusing here would break first-ever enable
// and the documented purge-and-re-enable migration.
func TestChaos57_SaltIsMintedWhenThereIsNothingToLose(t *testing.T) {
	t.Run("no directory at all (first enable, or post-purge)", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "history")
		key, err := EncKey(dir, chaosPass)
		if err != nil {
			t.Fatalf("EncKey on a fresh path: %v", err)
		}
		if len(key) != encKeyLen {
			t.Errorf("key length = %d, want %d", len(key), encKeyLen)
		}
	})

	t.Run("directory present but empty (a previous open failed early)", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "history")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if _, err := EncKey(dir, chaosPass); err != nil {
			t.Fatalf("EncKey on an empty directory: %v", err)
		}
	})

	t.Run("no passphrase configured (encryption off)", func(t *testing.T) {
		dir := seedHistory(t, 5)
		key, err := EncKey(dir, "")
		if err != nil || key != nil {
			t.Fatalf("EncKey with no passphrase = (%v, %v), want (nil, nil)", key, err)
		}
	})

	t.Run("a stable salt derives a stable key", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "history")
		first, err := EncKey(dir, chaosPass)
		if err != nil {
			t.Fatalf("first: %v", err)
		}
		second, err := EncKey(dir, chaosPass)
		if err != nil {
			t.Fatalf("second: %v", err)
		}
		if !bytes.Equal(first, second) {
			t.Fatal("EncKey is not stable across calls — every restart would lose the store")
		}
	})
}

// An unreadable store directory answers "has content" so the refusal wins: the
// alternative overwrites key material on a guess about a directory we could not
// see. Skipped for root, which bypasses the permission bits.
func TestChaos57_UnreadableStoreDirectoryRefusesRatherThanMinting(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: directory permissions are not enforced")
	}
	dir := seedHistory(t, 5)
	if err := os.Remove(dir + ".salt"); err != nil {
		t.Fatalf("remove salt: %v", err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if _, err := EncKey(dir, chaosPass); !errors.Is(err, ErrSaltUnusable) {
		t.Fatalf("EncKey on an unreadable store directory = %v, want ErrSaltUnusable", err)
	}
}
