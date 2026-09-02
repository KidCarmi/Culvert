package main

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// TestPersistCustomUITLS_KeyWriteFailureDoesNotCorruptExistingCert is the
// regression test for a gap in the CHAOS-50-style durability fix:
// persistCustomUITLS writes the cert and the key as two SEPARATE
// fileutil.AtomicWrite calls. customUITLSPairValid's doc comment already
// calls out that a process killed BETWEEN the two writes can leave a NEW
// cert paired with the OLD key — but the SAME hazard also fires on an
// ordinary, non-crash error return: if the cert write succeeds and the
// SECOND (key) write then fails (ENOSPC, a permissions change mid-upload,
// a wedged volume), persistCustomUITLS returns an error and
// apiCertsUpload (ui_security.go) tells the admin:
//
//	"...the current UI certificate is unchanged."
//
// That is false whenever a PREVIOUSLY VALID custom pair was already on
// disk: the cert half has just been overwritten with the new (rejected)
// upload, corrupting what used to be a working, persisted pair. On the
// next restart, resolveUITLSCertKey's customUITLSPairValid check (rightly)
// refuses the now-mismatched pair and falls back to a freshly generated
// self-signed certificate — silently discarding the admin's previously
// working custom UI certificate, exactly the kind of "restart changed
// nothing" -> "restart changed everything" surprise this whole file exists
// to prevent, triggered by an upload the admin was told had NO effect.
func TestPersistCustomUITLS_KeyWriteFailureDoesNotCorruptExistingCert(t *testing.T) {
	withTempDataDirForUITLS(t)

	cert1, key1, _ := generateSelfSignedECDSA(t)
	if err := persistCustomUITLS(cert1, key1); err != nil {
		t.Fatalf("initial persist: %v", err)
	}
	gotCert, err := os.ReadFile(customUITLSCertPath())
	if err != nil || !bytes.Equal(gotCert, cert1) {
		t.Fatalf("sanity: initial cert not persisted as expected (err=%v)", err)
	}

	// Force the SECOND write (the key) to fail without touching the first:
	// replace the key path with a directory, so fileutil.AtomicWrite's
	// os.Rename(tmp, path) fails with EISDIR renaming a file onto an
	// existing directory.
	if err := os.Remove(customUITLSKeyPath()); err != nil {
		t.Fatalf("remove key to stage failure: %v", err)
	}
	if err := os.Mkdir(customUITLSKeyPath(), 0o755); err != nil {
		t.Fatalf("mkdir over key path: %v", err)
	}

	cert2, key2, _ := generateSelfSignedECDSA(t) // a distinct replacement pair
	if err := persistCustomUITLS(cert2, key2); err == nil {
		t.Fatal("expected persistCustomUITLS to fail when the key write fails")
	}

	// The bug: the cert half was already overwritten with cert2 before the
	// key write failed, so the previously-valid (cert1, key1) pair on disk
	// is now corrupted even though the call reported failure and the admin
	// API told the caller "the current UI certificate is unchanged".
	gotCert, err = os.ReadFile(customUITLSCertPath())
	if err != nil {
		t.Fatalf("read cert after failed persist: %v", err)
	}
	if !bytes.Equal(gotCert, cert1) {
		t.Fatalf("persistCustomUITLS corrupted the previously-persisted cert on a failed key write: "+
			"on-disk cert changed from the original upload to the rejected one (got %d bytes matching cert2=%v, cert1=%v)",
			len(gotCert), bytes.Equal(gotCert, cert2), bytes.Equal(gotCert, cert1))
	}
}

// TestPersistCustomUITLS_KeyReplacedNotSyncedDoesNotRollback is the
// regression test for the Codex P1 finding on this PR (#1297): when the key
// write fails with fileutil.ErrReplacedNotSynced, the key RENAME has already
// landed — the new key is live and visible on disk, only the best-effort
// parent-directory fsync afterward failed. Rolling the cert back to its
// previous value in this case would pair the OLD cert with the NEW key,
// producing exactly the mismatched-pair hazard this whole rollback exists to
// prevent — just inverted. persistCustomUITLS must leave the (new cert, new
// key) pair that was actually uploaded in place.
func TestPersistCustomUITLS_KeyReplacedNotSyncedDoesNotRollback(t *testing.T) {
	withTempDataDirForUITLS(t)

	cert1, key1, _ := generateSelfSignedECDSA(t)
	if err := persistCustomUITLS(cert1, key1); err != nil {
		t.Fatalf("initial persist: %v", err)
	}

	cert2, key2, _ := generateSelfSignedECDSA(t)
	prev := uiTLSAtomicWrite
	t.Cleanup(func() { uiTLSAtomicWrite = prev })
	uiTLSAtomicWrite = func(path string, data []byte, perm os.FileMode) error {
		if path != customUITLSKeyPath() {
			t.Fatalf("rollback must not run on ErrReplacedNotSynced — unexpected write to %s", path)
		}
		// Simulate the rename having actually landed: the new key content
		// is genuinely on disk, and only the post-rename parent-dir fsync
		// is reported as failed.
		if err := os.WriteFile(path, data, perm); err != nil {
			return err
		}
		return fileutil.ErrReplacedNotSynced
	}

	err := persistCustomUITLS(cert2, key2)
	if !errors.Is(err, fileutil.ErrReplacedNotSynced) {
		t.Fatalf("expected fileutil.ErrReplacedNotSynced, got %v", err)
	}

	gotCert, rerr := os.ReadFile(customUITLSCertPath())
	if rerr != nil || !bytes.Equal(gotCert, cert2) {
		t.Fatalf("cert must NOT be rolled back on ErrReplacedNotSynced (the new key already landed): "+
			"read err=%v, matches cert2=%v, matches cert1=%v", rerr, bytes.Equal(gotCert, cert2), bytes.Equal(gotCert, cert1))
	}
	gotKey, rerr := os.ReadFile(customUITLSKeyPath())
	if rerr != nil || !bytes.Equal(gotKey, key2) {
		t.Fatalf("key must reflect the landed write: read err=%v, matches key2=%v", rerr, bytes.Equal(gotKey, key2))
	}
}

// TestPersistCustomUITLS_RollbackFailureIsSurfaced is the regression test
// for the Codex P2 finding on this PR (#1297): when the key write fails for
// an ordinary reason (not ErrReplacedNotSynced) AND the compensating cert
// rollback ALSO fails — the same wedged/full/read-only volume plausibly
// fails both — persistCustomUITLS must not silently discard the rollback
// error. The caller (apiCertsUpload) needs to distinguish this from a clean
// rollback so it stops claiming "the current certificate is unchanged" when
// the on-disk cert may now be the rejected upload.
func TestPersistCustomUITLS_RollbackFailureIsSurfaced(t *testing.T) {
	withTempDataDirForUITLS(t)

	cert1, key1, _ := generateSelfSignedECDSA(t)
	if err := persistCustomUITLS(cert1, key1); err != nil {
		t.Fatalf("initial persist: %v", err)
	}

	cert2, key2, _ := generateSelfSignedECDSA(t)
	keyErr := errors.New("simulated wedged volume: key write")
	rollbackErr := errors.New("simulated wedged volume: rollback write")
	prev := uiTLSAtomicWrite
	t.Cleanup(func() { uiTLSAtomicWrite = prev })
	uiTLSAtomicWrite = func(path string, _ []byte, _ os.FileMode) error {
		switch path {
		case customUITLSKeyPath():
			return keyErr
		case customUITLSCertPath():
			return rollbackErr
		default:
			t.Fatalf("unexpected write to %s", path)
			return nil
		}
	}

	err := persistCustomUITLS(cert2, key2)
	if !errors.Is(err, errUITLSRollbackFailed) {
		t.Fatalf("expected errUITLSRollbackFailed, got %v", err)
	}
	if !errors.Is(err, keyErr) {
		t.Fatalf("expected the original key-write error to still be wrapped, got %v", err)
	}
	if !errors.Is(err, rollbackErr) {
		t.Fatalf("expected the rollback error to be wrapped, got %v", err)
	}

	// The cert half was actually replaced with cert2 on disk (a real,
	// unstubbed write) before the stubbed rollback failed to restore it —
	// exactly the indeterminate on-disk state errUITLSRollbackFailed exists
	// to make callers aware of, rather than reporting "unchanged".
	gotCert, rerr := os.ReadFile(customUITLSCertPath())
	if rerr != nil || !bytes.Equal(gotCert, cert2) {
		t.Fatalf("sanity: expected the rejected cert2 to be left on disk after a failed rollback, "+
			"read err=%v, matches cert2=%v", rerr, bytes.Equal(gotCert, cert2))
	}
	gotKey, rerr := os.ReadFile(customUITLSKeyPath())
	if rerr != nil || !bytes.Equal(gotKey, key1) {
		t.Fatalf("sanity: key write was stubbed to fail before any write, key should still be key1: "+
			"read err=%v, matches key1=%v", rerr, bytes.Equal(gotKey, key1))
	}
}
