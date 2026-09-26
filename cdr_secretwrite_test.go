package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// SEC-SECRETWRITE-1 — installRenewedPEMs stages the renewed CDR mTLS bundle at
// "<bundle>.tmp" before renaming it into place. Those names are a deliberate
// rendezvous (finishStagedRenewal looks them up by exactly this path at the
// next boot), and a PREDICTABLE path is precisely where os.WriteFile is unsafe
// for a private key: it follows a planted symlink, and its perm argument
// applies only on creation, so a wide-mode file planted at the path receives
// the key and keeps its mode.
//
// Each gate below was verified failing against the pre-fix os.WriteFile shape.

func newRenewalInstance(t *testing.T) CDREnrolledInstance {
	t.Helper()
	dir := t.TempDir()
	return CDREnrolledInstance{
		Name:           "sec-secretwrite",
		ClientCertPath: filepath.Join(dir, "client.crt"),
		ClientKeyPath:  filepath.Join(dir, "client.key"),
	}
}

func TestInstallRenewedPEMs_KeyStagingDoesNotInheritAPlantedMode(t *testing.T) {
	inst := newRenewalInstance(t)
	keyTmp := inst.ClientKeyPath + ".tmp"
	if err := os.WriteFile(keyTmp, []byte("planted"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(keyTmp, 0o666); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if !installRenewedPEMs(inst, []byte("CERT"), []byte("-----BEGIN EC PRIVATE KEY-----")) {
		t.Fatal("installRenewedPEMs failed")
	}
	fi, err := os.Stat(inst.ClientKeyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("the CDR client private key is mode %v (inherited from the planted tmp file), want 0600", perm)
	}
}

func TestInstallRenewedPEMs_CertStagingDoesNotInheritAPlantedMode(t *testing.T) {
	inst := newRenewalInstance(t)
	certTmp := inst.ClientCertPath + ".tmp"
	if err := os.WriteFile(certTmp, []byte("planted"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(certTmp, 0o666); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if !installRenewedPEMs(inst, []byte("CERT"), []byte("KEY")) {
		t.Fatal("installRenewedPEMs failed")
	}
	fi, err := os.Stat(inst.ClientCertPath)
	if err != nil {
		t.Fatalf("stat cert: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("cert mode = %v, want 0600", perm)
	}
}

func TestInstallRenewedPEMs_StagingDoesNotFollowAPlantedSymlink(t *testing.T) {
	inst := newRenewalInstance(t)
	outside := t.TempDir()
	certTarget := filepath.Join(outside, "cert-escape")
	keyTarget := filepath.Join(outside, "key-escape")
	if err := os.Symlink(certTarget, inst.ClientCertPath+".tmp"); err != nil {
		t.Fatalf("plant cert symlink: %v", err)
	}
	if err := os.Symlink(keyTarget, inst.ClientKeyPath+".tmp"); err != nil {
		t.Fatalf("plant key symlink: %v", err)
	}

	if !installRenewedPEMs(inst, []byte("CERT"), []byte("-----BEGIN EC PRIVATE KEY-----")) {
		t.Fatal("installRenewedPEMs failed")
	}
	for _, p := range []string{certTarget, keyTarget} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("renewal material escaped the bundle directory to %s", p)
		}
	}
	got, err := os.ReadFile(inst.ClientKeyPath)
	if err != nil || string(got) != "-----BEGIN EC PRIVATE KEY-----" { //nolint:gosec // G101: PEM header placeholder, no key material
		t.Fatalf("the key did not land at its own path: %q err=%v", got, err)
	}
}

// CONTROL 1: the ordinary renewal still works end to end, the bundle lands at
// the real paths, and no ".tmp" rendezvous file survives a successful swap —
// a leftover would be a predictable path holding the previous private key.
func TestInstallRenewedPEMs_HappyPathSwapsAndLeavesNoStagingFiles(t *testing.T) {
	inst := newRenewalInstance(t)
	if err := os.WriteFile(inst.ClientCertPath, []byte("OLD-CERT"), 0o600); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	if err := os.WriteFile(inst.ClientKeyPath, []byte("OLD-KEY"), 0o600); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	if !installRenewedPEMs(inst, []byte("NEW-CERT"), []byte("NEW-KEY")) {
		t.Fatal("installRenewedPEMs failed")
	}
	if b, _ := os.ReadFile(inst.ClientCertPath); string(b) != "NEW-CERT" {
		t.Fatalf("cert = %q, want NEW-CERT", b)
	}
	if b, _ := os.ReadFile(inst.ClientKeyPath); string(b) != "NEW-KEY" {
		t.Fatalf("key = %q, want NEW-KEY", b)
	}
	for _, p := range []string{inst.ClientCertPath + ".tmp", inst.ClientKeyPath + ".tmp"} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("staging file %s survived the swap", p)
		}
	}
}

// CONTROL 2: the cheapest way to pass the gates above is to refuse whenever
// anything already occupies the rendezvous path — which would wedge renewals
// permanently after the first crash-interrupted attempt. A STALE regular
// staging file must still be superseded, exactly as the truncating write
// superseded it before.
func TestInstallRenewedPEMs_SupersedesStaleStagingFiles(t *testing.T) {
	inst := newRenewalInstance(t)
	if err := os.WriteFile(inst.ClientCertPath+".tmp", []byte("STALE-CERT"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.WriteFile(inst.ClientKeyPath+".tmp", []byte("STALE-KEY"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if !installRenewedPEMs(inst, []byte("NEW-CERT"), []byte("NEW-KEY")) {
		t.Fatal("a stale staging file must not wedge the renewal")
	}
	if b, _ := os.ReadFile(inst.ClientKeyPath); string(b) != "NEW-KEY" {
		t.Fatalf("key = %q, want NEW-KEY", b)
	}
}

// BOUNDARY: an unwritable bundle directory fails CLOSED — no partial bundle,
// and the previous material is left intact for the running client.
func TestInstallRenewedPEMs_FailsClosedOnAnUnwritableDirectory(t *testing.T) {
	inst := newRenewalInstance(t)
	if err := os.WriteFile(inst.ClientCertPath, []byte("OLD-CERT"), 0o600); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	if err := os.WriteFile(inst.ClientKeyPath, []byte("OLD-KEY"), 0o600); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	dir := filepath.Dir(inst.ClientCertPath)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if os.Geteuid() == 0 {
		t.Skip("running as root: a read-only directory does not deny writes")
	}
	if installRenewedPEMs(inst, []byte("NEW-CERT"), []byte("NEW-KEY")) {
		t.Fatal("expected the renewal to fail on an unwritable bundle directory")
	}
	if b, _ := os.ReadFile(inst.ClientKeyPath); string(b) != "OLD-KEY" {
		t.Fatalf("the running key was disturbed by a failed renewal: %q", b)
	}
}
