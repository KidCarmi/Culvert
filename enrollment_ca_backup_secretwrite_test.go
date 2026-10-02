package main

// SEC-SECRETWRITE-1 (completion) — backupCAFiles.
//
// The original SEC-SECRETWRITE-1 sweep (#1467) closed four writers of
// node-local key material that used os.WriteFile on a PREDICTABLE path. It was
// scoped to the writers introduced in its own review window, and backupCAFiles
// predates it — so the one remaining production os.WriteFile of private key
// material survived, and it carries the HIGHEST-value key in the tree after the
// MITM root: the cluster CA private key signs every Data Plane node
// certificate, so disclosure lets an attacker mint a node cert, impersonate a
// DP to the Control Plane and receive the full ConfigSnapshot (SessionHMAC and
// the IdP secrets included).
//
// os.WriteFile is unsafe there in the two ways #1467 recorded, and both are
// pinned below as defect gates:
//
//  1. It opens O_WRONLY|O_CREATE|O_TRUNC, which FOLLOWS a symlink planted at
//     the path — so an attacker who can create files in the CA directory
//     redirects the key to a location they can read.
//  2. Its perm argument applies only on CREATION — so a 0666 file pre-created
//     at "cluster-ca.key.bak" receives the key and stays world-readable.
//
// fileutil.AtomicWrite creates a RANDOM O_EXCL temp beside the target, chmods
// and fsyncs it, then renames over the target, which closes both.
//
// Both defect gates were verified FAILING against the reintroduced
// os.WriteFile shape, and the controls were verified failing against a
// backupCAFiles that simply writes nothing — the cheapest way to pass every
// defect gate here is to delete the dual-CA overlap backup, which would remove
// the operator's only recovery copy of the previous root.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// caBackupFixture returns a CA directory and a freshly generated key.
func caBackupFixture(t *testing.T) (dir string, key *ecdsa.PrivateKey, certPEM []byte) {
	t.Helper()
	// The plaintext branch is the default posture and is the one under test;
	// the encrypted branch already routes through secret.SealToFile →
	// fileutil.AtomicWrite. Clearing the env makes the branch explicit rather
	// than inherited from whatever ran before us.
	t.Setenv(clusterCAEncryptEnvVar, "")
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return t.TempDir(), k, []byte("-----BEGIN CERTIFICATE-----\nnotarealcert\n-----END CERTIFICATE-----\n")
}

// TestSecSecretWrite1_CABackupDoesNotFollowAPlantedKeySymlink is the primary
// defect gate: the cluster CA private key must never be written THROUGH a
// symlink an attacker planted at the predictable .bak path.
func TestSecSecretWrite1_CABackupDoesNotFollowAPlantedKeySymlink(t *testing.T) {
	dir, key, certPEM := caBackupFixture(t)

	// The attacker's chosen destination, outside the CA directory.
	exfil := filepath.Join(t.TempDir(), "harvested.key")
	if err := os.Symlink(exfil, filepath.Join(dir, "cluster-ca.key.bak")); err != nil {
		t.Skipf("symlinks unavailable on this filesystem: %v", err)
	}

	backupCAFiles(dir, certPEM, key)

	if body, err := os.ReadFile(exfil); err == nil && len(body) > 0 {
		t.Errorf("cluster CA PRIVATE KEY was written through a planted symlink to %s (%d bytes): "+
			"an attacker who can create files in the CA directory harvests the trust root that signs "+
			"every DP node certificate", exfil, len(body))
	}
	// The real .bak must be a regular file this call created, not the link.
	fi, err := os.Lstat(filepath.Join(dir, "cluster-ca.key.bak"))
	if err != nil {
		t.Fatalf("lstat key backup: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Error("cluster-ca.key.bak is still a symlink after the backup: the planted link was not replaced")
	}
}

// TestSecSecretWrite1_CABackupDoesNotFollowAPlantedCertSymlink covers the cert
// half. The cert is PUBLIC, so this is not a confidentiality finding — it is
// pinned because writing through an attacker-chosen path is an integrity and
// arbitrary-write primitive regardless of what the bytes are.
func TestSecSecretWrite1_CABackupDoesNotFollowAPlantedCertSymlink(t *testing.T) {
	dir, key, certPEM := caBackupFixture(t)

	target := filepath.Join(t.TempDir(), "clobbered")
	if err := os.WriteFile(target, []byte("pre-existing"), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "cluster-ca.crt.bak")); err != nil {
		t.Skipf("symlinks unavailable on this filesystem: %v", err)
	}

	backupCAFiles(dir, certPEM, key)

	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(body) != "pre-existing" {
		t.Errorf("CA backup wrote through a planted symlink and clobbered %s: an attacker who can "+
			"create files in the CA directory gets an arbitrary write with this process's privileges", target)
	}
}

// TestSecSecretWrite1_CABackupKeyIsNotWorldReadableOnAPrePlantedFile is the
// second defect gate: os.WriteFile applies its perm argument only on CREATION,
// so a file pre-created at the predictable path with loose permissions receives
// the key and KEEPS those permissions.
func TestSecSecretWrite1_CABackupKeyIsNotWorldReadableOnAPrePlantedFile(t *testing.T) {
	dir, key, certPEM := caBackupFixture(t)

	keyBak := filepath.Join(dir, "cluster-ca.key.bak")
	if err := os.WriteFile(keyBak, nil, 0o666); err != nil {
		t.Fatalf("pre-plant permissive file: %v", err)
	}
	// Defeat umask, which would otherwise mask the bits the defect needs.
	if err := os.Chmod(keyBak, 0o666); err != nil {
		t.Fatalf("chmod pre-planted file: %v", err)
	}

	backupCAFiles(dir, certPEM, key)

	fi, err := os.Stat(keyBak)
	if err != nil {
		t.Fatalf("stat key backup: %v", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("cluster CA private key backup has mode %#o on a pre-planted file, want no group/other bits: "+
			"every local user can read the trust root that signs every DP node certificate", perm)
	}
}

// ─── Controls ───────────────────────────────────────────────────────────────
//
// The cheapest way to pass all three gates above is for backupCAFiles to write
// nothing at all, which would silently delete the dual-CA overlap recovery
// copy. These fail against that.

// TestSecSecretWrite1_CABackupStillWritesBothArtifacts is the positive control.
func TestSecSecretWrite1_CABackupStillWritesBothArtifacts(t *testing.T) {
	dir, key, certPEM := caBackupFixture(t)

	backupCAFiles(dir, certPEM, key)

	gotCert, err := os.ReadFile(filepath.Join(dir, "cluster-ca.crt.bak"))
	if err != nil {
		t.Fatalf("cert backup missing: %v", err)
	}
	if string(gotCert) != string(certPEM) {
		t.Errorf("cert backup content = %q, want the CA cert PEM verbatim", gotCert)
	}

	keyBak := filepath.Join(dir, "cluster-ca.key.bak")
	gotKey, err := os.ReadFile(keyBak)
	if err != nil {
		t.Fatalf("key backup missing: %v", err)
	}
	if len(gotKey) == 0 {
		t.Error("key backup is empty: the dual-CA overlap recovery copy is gone")
	}
	fi, err := os.Stat(keyBak)
	if err != nil {
		t.Fatalf("stat key backup: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("key backup mode = %#o, want 0600", perm)
	}
}

// TestSecSecretWrite1_CABackupWithNilKeyStillWritesTheCert is the negative
// path: a nil key writes no key file and must not suppress the cert backup.
func TestSecSecretWrite1_CABackupWithNilKeyStillWritesTheCert(t *testing.T) {
	dir, _, certPEM := caBackupFixture(t)

	backupCAFiles(dir, certPEM, nil)

	if _, err := os.ReadFile(filepath.Join(dir, "cluster-ca.crt.bak")); err != nil {
		t.Errorf("cert backup missing when key is nil: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "cluster-ca.key.bak")); !os.IsNotExist(err) {
		t.Errorf("a nil key must leave no key backup behind, stat err = %v", err)
	}
}

// TestSecSecretWrite1_CABackupIsOverwritableAcrossRotations pins that the
// O_EXCL temp does not make a SECOND rotation fail. AtomicWrite renames over an
// existing target; a naive O_EXCL write at the FINAL path would refuse here and
// silently leave the previous root as the recovery copy.
func TestSecSecretWrite1_CABackupIsOverwritableAcrossRotations(t *testing.T) {
	dir, key, certPEM := caBackupFixture(t)

	backupCAFiles(dir, certPEM, key)
	second := []byte("-----BEGIN CERTIFICATE-----\nsecondrotation\n-----END CERTIFICATE-----\n")
	backupCAFiles(dir, second, key)

	got, err := os.ReadFile(filepath.Join(dir, "cluster-ca.crt.bak"))
	if err != nil {
		t.Fatalf("cert backup missing after second rotation: %v", err)
	}
	if string(got) != string(second) {
		t.Errorf("second rotation did not replace the backup: got %q, want %q", got, second)
	}
}

// TestSecSecretWrite1_CABackupLeavesNoTempBehind pins that the atomic temp is
// cleaned up: a leftover "cluster-ca.key.bak.tmp.*" would be an unreferenced
// copy of the private key nobody rotates or audits.
func TestSecSecretWrite1_CABackupLeavesNoTempBehind(t *testing.T) {
	dir, key, certPEM := caBackupFixture(t)

	backupCAFiles(dir, certPEM, key)

	leftovers, err := filepath.Glob(filepath.Join(dir, "*.tmp.*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(leftovers) > 0 {
		t.Errorf("atomic write left %d temp file(s) behind: %v — an unreferenced copy of the "+
			"cluster CA private key", len(leftovers), leftovers)
	}
}
