package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// The persisted UI cert/key pair is a STAGED, MARKER-COMMITTED transition
// (ui_tls_custom.go, FE-6B.0 round 3): the live paths are never written
// directly, so no failure before the commit point can touch the previous
// pair, a post-rename synchronisation failure leaves the NEW complete pair
// live and is reported as unproven durability (never "unchanged"), and a
// transition interrupted after its commit point is completed by
// recoverUITLSTransition from the marker — at boot or at the next
// settlement — without a guess.

func uiTLSNoTransitionRemnants(t *testing.T) {
	t.Helper()
	for _, p := range []string{customUITLSCertStagePath(), customUITLSKeyStagePath(), customUITLSTransitionPath()} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("transition remnant left behind: %s", filepath.Base(p))
		}
	}
}

// A key STAGING failure (before the commit point) leaves the previous pair
// intact and valid — the certificate is never overwritten first — and
// leaves no staged file or marker behind.
func TestPersistCustomUITLS_KeyWriteFailureDoesNotCorruptExistingCert(t *testing.T) {
	withTempDataDirForUITLS(t)

	cert1, key1, _ := generateSelfSignedECDSA(t)
	if err := persistCustomUITLS(cert1, key1); err != nil {
		t.Fatalf("initial persist: %v", err)
	}
	uiTLSNoTransitionRemnants(t)

	keyErr := errors.New("simulated: no space left on device")
	prev := uiTLSAtomicWrite
	t.Cleanup(func() { uiTLSAtomicWrite = prev })
	uiTLSAtomicWrite = func(path string, data []byte, perm os.FileMode) error {
		if strings.HasPrefix(filepath.Base(path), customUITLSKeyFile) {
			return keyErr
		}
		return fileutil.AtomicWrite(path, data, perm)
	}

	cert2, key2, _ := generateSelfSignedECDSA(t)
	err := persistCustomUITLS(cert2, key2)
	if !errors.Is(err, keyErr) || errors.Is(err, errUITLSDurabilityUnproven) || errors.Is(err, errUITLSTransitionIncomplete) {
		t.Fatalf("a pre-commit failure must be an ordinary error carrying the cause, got %v", err)
	}
	gotCert, _ := os.ReadFile(customUITLSCertPath())
	gotKey, _ := os.ReadFile(customUITLSKeyPath())
	if !bytes.Equal(gotCert, cert1) || !bytes.Equal(gotKey, key1) || !customUITLSPairValid() {
		t.Fatalf("the previous pair was touched by a failed replacement (cert1=%v key1=%v valid=%v)",
			bytes.Equal(gotCert, cert1), bytes.Equal(gotKey, key1), customUITLSPairValid())
	}
	uiTLSNoTransitionRemnants(t)
}

// A post-rename synchronisation failure on the key write means the staged
// key LANDED: the transition completes, the new pair is live and valid, and
// the caller learns that the durability is unproven — never that nothing
// changed, and never a rollback that would pair the old certificate with
// the new key.
func TestPersistCustomUITLS_KeyReplacedNotSyncedCompletesThePair(t *testing.T) {
	withTempDataDirForUITLS(t)

	cert1, key1, _ := generateSelfSignedECDSA(t)
	if err := persistCustomUITLS(cert1, key1); err != nil {
		t.Fatalf("initial persist: %v", err)
	}

	cert2, key2, _ := generateSelfSignedECDSA(t)
	prev := uiTLSAtomicWrite
	t.Cleanup(func() { uiTLSAtomicWrite = prev })
	uiTLSAtomicWrite = func(path string, data []byte, perm os.FileMode) error {
		if !strings.HasPrefix(filepath.Base(path), customUITLSKeyFile) {
			t.Fatalf("unexpected write through the key seam: %s", path)
		}
		if err := fileutil.AtomicWrite(path, data, perm); err != nil {
			return err
		}
		return fileutil.ErrReplacedNotSynced
	}

	err := persistCustomUITLS(cert2, key2)
	if !errors.Is(err, errUITLSDurabilityUnproven) || !errors.Is(err, fileutil.ErrReplacedNotSynced) {
		t.Fatalf("expected errUITLSDurabilityUnproven wrapping ErrReplacedNotSynced, got %v", err)
	}
	gotCert, _ := os.ReadFile(customUITLSCertPath())
	gotKey, _ := os.ReadFile(customUITLSKeyPath())
	if !bytes.Equal(gotCert, cert2) || !bytes.Equal(gotKey, key2) || !customUITLSPairValid() {
		t.Fatalf("the NEW complete pair must be live after a post-rename failure (cert2=%v key2=%v valid=%v)",
			bytes.Equal(gotCert, cert2), bytes.Equal(gotKey, key2), customUITLSPairValid())
	}
	if bytes.Equal(gotCert, cert1) {
		t.Fatal("the certificate was rolled back beside the new key")
	}
	uiTLSNoTransitionRemnants(t)
}

// A transition that reached its commit point but could not be completed
// (the certificate rename fails) is reported as incomplete with the marker
// left in place, and recoverUITLSTransition completes it once the fault is
// gone — the pair is then the new complete pair, never a mixture.
func TestPersistCustomUITLS_IncompleteCommitIsRecoveredFromTheMarker(t *testing.T) {
	withTempDataDirForUITLS(t)

	cert1, key1, _ := generateSelfSignedECDSA(t)
	if err := persistCustomUITLS(cert1, key1); err != nil {
		t.Fatalf("initial persist: %v", err)
	}
	// The certificate's live path becomes a NON-EMPTY directory, so the
	// commit-phase rename of the staged certificate fails after the key was
	// already renamed.
	if err := os.Remove(customUITLSCertPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(customUITLSCertPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(customUITLSCertPath(), "occupant"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	cert2, key2, _ := generateSelfSignedECDSA(t)
	err := persistCustomUITLS(cert2, key2)
	if !errors.Is(err, errUITLSTransitionIncomplete) {
		t.Fatalf("expected errUITLSTransitionIncomplete, got %v", err)
	}
	tr, terr := readUITLSTransition()
	if terr != nil || tr == nil || tr.Kind != uiTLSTransitionReplace || tr.CertDigest != hexDigest(cert2) {
		t.Fatalf("the marker must stay for the next recovery: %+v %v", tr, terr)
	}
	if _, serr := os.Stat(customUITLSCertStagePath()); serr != nil {
		t.Fatal("the staged certificate must stay until the rename can be done")
	}

	// Fault gone: the recovery completes the transition from the marker.
	if err := os.RemoveAll(customUITLSCertPath()); err != nil {
		t.Fatal(err)
	}
	rec := recoverUITLSTransition()
	if rec.Err != nil || !rec.Completed || rec.Kind != uiTLSTransitionReplace {
		t.Fatalf("recovery = %+v", rec)
	}
	gotCert, _ := os.ReadFile(customUITLSCertPath())
	gotKey, _ := os.ReadFile(customUITLSKeyPath())
	if !bytes.Equal(gotCert, cert2) || !bytes.Equal(gotKey, key2) || !customUITLSPairValid() {
		t.Fatalf("recovery did not complete the new pair (cert2=%v key2=%v valid=%v)",
			bytes.Equal(gotCert, cert2), bytes.Equal(gotKey, key2), customUITLSPairValid())
	}
	uiTLSNoTransitionRemnants(t)
	_ = key1
}

// Staged files WITHOUT a marker never committed: the recovery abandons them
// and the previous pair is untouched; a marker with both files still staged
// is a committed transition and is completed.
func TestRecoverUITLSTransition_AbandonsUncommittedAndCompletesCommitted(t *testing.T) {
	withTempDataDirForUITLS(t)
	cert1, key1, _ := generateSelfSignedECDSA(t)
	if err := persistCustomUITLS(cert1, key1); err != nil {
		t.Fatal(err)
	}
	cert2, key2, _ := generateSelfSignedECDSA(t)

	// Uncommitted: staged certificate only (the process died before the key
	// was staged).
	if err := os.WriteFile(customUITLSCertStagePath(), cert2, 0o600); err != nil {
		t.Fatal(err)
	}
	rec := recoverUITLSTransition()
	if rec.Err != nil || rec.Completed || !rec.Abandoned {
		t.Fatalf("recovery = %+v", rec)
	}
	if got, _ := os.ReadFile(customUITLSCertPath()); !bytes.Equal(got, cert1) || !customUITLSPairValid() {
		t.Fatal("an abandoned staging touched the previous pair")
	}
	uiTLSNoTransitionRemnants(t)

	// Committed: both files staged and the marker written (the process died
	// before the renames).
	if err := os.WriteFile(customUITLSCertStagePath(), cert2, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(customUITLSKeyStagePath(), key2, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeUITLSTransition(uiTLSTransition{Kind: uiTLSTransitionReplace, OperationID: "op-x", CertDigest: hexDigest(cert2)}); err != nil {
		t.Fatal(err)
	}
	rec = recoverUITLSTransition()
	if rec.Err != nil || !rec.Completed || rec.OperationID != "op-x" {
		t.Fatalf("recovery = %+v", rec)
	}
	gotCert, _ := os.ReadFile(customUITLSCertPath())
	gotKey, _ := os.ReadFile(customUITLSKeyPath())
	if !bytes.Equal(gotCert, cert2) || !bytes.Equal(gotKey, key2) || !customUITLSPairValid() {
		t.Fatal("a committed transition was not completed")
	}
	uiTLSNoTransitionRemnants(t)
}
