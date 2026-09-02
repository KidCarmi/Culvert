package main

import (
	"bytes"
	"os"
	"testing"
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
