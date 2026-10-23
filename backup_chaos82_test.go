package main

// backup_chaos82_test.go — CHAOS-82 gates for the backup plane's archive
// publication and the restore-side encryption trust boundary.
//
// Three findings the CHAOS-74 sweep recorded in §42 and did not fix, each of
// which had no test at all:
//
//   - BKP-2 the unencrypted writer published the archive world-readable
//     (os.Create → 0666 before umask, typically 0644) although the archive
//     aggregates cluster-ca.key, ui_users.json and idp_profiles.json.
//   - BKP-4 that same writer published through a fixed, symlink-following
//     "<out>.tmp" that the encrypted writer deliberately abandoned.
//   - BKP-1 a PLAINTEXT archive was accepted although a passphrase was
//     configured, with the passphrase never examined — the substitution
//     attack that installs an attacker-authored admin roster.
//
// Negative controls are load-bearing here: the BKP-1 refusal must fire ONLY on
// the downgrade, so the legitimate no-passphrase plaintext restore and the
// encrypted restore are both pinned alongside it.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedBackupDataDir seeds the Tier-1 artifacts a backup needs to pack, with
// the owner-only modes they carry in production.
func seedBackupDataDir(t *testing.T) string {
	t.Helper()
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json",
		[]byte(`{"users":[{"username":"admin","role":"admin","pass_hash":"deadbeef"}]}`), 0o600)
	seedFile(t, dataDir, "cluster.json", []byte(`{"nodes":{}}`), 0o600)
	seedFile(t, dataDir, "cluster-ca.key", []byte("-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n"), 0o600)
	seedFile(t, dataDir, "config_versions/v1.json", []byte(`{"meta":{"version":1}}`), 0o600)
	return dataDir
}

// BKP-2: the published archive is owner-only on BOTH paths. The unencrypted
// writer used os.Create with no Chmod anywhere in the file, so under the
// ordinary 022 umask it published 0644 — any local account or co-mounted
// container with read access to /backup obtained the fleet's MITM-capable
// cluster CA key. The encrypted path already went through
// atomicWriteFile(..., 0o600) and is pinned here so neither writer can drift.
func TestChaos82_PublishedArchiveIsOwnerOnly(t *testing.T) {
	for _, tc := range []struct {
		name       string
		passphrase string
		file       string
	}{
		{"unencrypted", "", "backup.tar.gz"},
		{"encrypted", testBackupPassphrase, "backup.tar.gz.enc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := seedBackupDataDir(t)
			out := filepath.Join(t.TempDir(), tc.file)

			var err error
			if tc.passphrase == "" {
				err = runBackup(out, dataDir)
			} else {
				err = runBackupEncrypted(out, dataDir, tc.passphrase)
			}
			if err != nil {
				t.Fatalf("backup: %v", err)
			}

			fi, serr := os.Stat(out)
			if serr != nil {
				t.Fatalf("stat published archive: %v", serr)
			}
			if got := fi.Mode().Perm(); got != 0o600 {
				t.Fatalf("published archive mode = %04o, want 0600 "+
					"(the archive carries cluster-ca.key, ui_users.json and idp_profiles.json)", got)
			}
			// Under the ordinary 022 umask the pre-fix os.Create published
			// 0644, so this assertion discriminates the defect without
			// touching the process umask. A umask-independence gate would
			// have to flip a process-global value inside the root package,
			// whose tests share process state and run shuffled and parallel;
			// the explicit Chmod that provides that property is the same
			// construction fileutil.AtomicWrite uses on the encrypted path.
			// See §45 for why that gate was deliberately not added here.
		})
	}
}

// BKP-4, the litter half: no "<out>.tmp" is left in the destination directory.
// Mirrors TestBackupEncrypt_NoFixedTmpFile, which pins the same contract for
// the writer that already abandoned the pattern.
//
// Deliberately recorded: this assertion alone does NOT discriminate the defect.
// The pre-fix writer renamed its fixed temp file onto outPath, so after a
// SUCCESSFUL backup no "<out>.tmp" was left behind either — mutation-testing
// this gate against the restored os.Create version passes. It guards only
// against a writer that abandons litter. The two gates that actually fail on
// the defect are TestChaos82_PlantedSymlinkAtFixedTmpIsNotFollowed (the
// security property) and TestChaos82_StaleTmpAtFixedPathIsUntouched below.
func TestChaos82_UnencryptedWriterLeavesNoFixedTmp(t *testing.T) {
	dataDir := seedBackupDataDir(t)
	outDir := t.TempDir()
	out := filepath.Join(outDir, "backup.tar.gz")

	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}

	if _, err := os.Lstat(out + ".tmp"); err == nil {
		t.Errorf("fixed temp file %q must not exist after a successful backup", out+".tmp")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("unexpected stat err on fixed temp file: %v", err)
	}

	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(out) {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected only %q in outDir, got %v", filepath.Base(out), names)
	}
}

// BKP-4, the collision half: a leftover file at the fixed path must not be
// consumed. os.Create TRUNCATES an existing file, so the pre-fix writer
// silently destroyed whatever sat at "<out>.tmp" — and, with two concurrent
// backups to one outPath, both opened that same inode and interleaved, after
// which the CLI printed success over a corrupt archive. os.CreateTemp cannot
// collide with the legacy name. Mirrors TestBackupEncrypt_StaleTmpDoesNotAffect.
func TestChaos82_StaleTmpAtFixedPathIsUntouched(t *testing.T) {
	dataDir := seedBackupDataDir(t)
	outDir := t.TempDir()
	out := filepath.Join(outDir, "backup.tar.gz")

	staleTmp := out + ".tmp"
	const staleBody = "STALE — a prior aborted run; the writer must not consume this"
	if err := os.WriteFile(staleTmp, []byte(staleBody), 0o600); err != nil {
		t.Fatalf("seed stale tmp: %v", err)
	}

	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}

	body, err := os.ReadFile(staleTmp) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("stale tmp must survive untouched, but: %v", err)
	}
	if string(body) != staleBody {
		t.Fatalf("the writer consumed the fixed temp path: stale file is now %d bytes, want the original %d",
			len(body), len(staleBody))
	}

	if _, err := os.Stat(out); err != nil {
		t.Fatalf("archive must still publish at outPath: %v", err)
	}
}

// BKP-4, the security half: a symlink planted at the PREDICTABLE temp path
// must not redirect the archive. os.Create follows symlinks, so before the fix
// an attacker who could create one entry in the output directory ahead of the
// run sent an archive carrying cluster-ca.key wherever the link pointed —
// outside /backup entirely — and the CLI still reported success. os.CreateTemp
// picks a random name under O_EXCL, so the planted link is never opened.
func TestChaos82_PlantedSymlinkAtFixedTmpIsNotFollowed(t *testing.T) {
	dataDir := seedBackupDataDir(t)
	outDir := t.TempDir()
	out := filepath.Join(outDir, "backup.tar.gz")

	// The attacker's exfiltration target, outside the output directory.
	canaryDir := t.TempDir()
	canary := filepath.Join(canaryDir, "stolen.tar.gz")
	const canaryBody = "CANARY — the archive must never be written here"
	if err := os.WriteFile(canary, []byte(canaryBody), 0o600); err != nil {
		t.Fatalf("seed canary: %v", err)
	}

	planted := out + ".tmp"
	if err := os.Symlink(canary, planted); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}

	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}

	// The canary must be byte-identical: nothing was written through the link.
	body, err := os.ReadFile(canary) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("read canary: %v", err)
	}
	if string(body) != canaryBody {
		t.Fatalf("archive was written THROUGH the planted symlink: canary is %d bytes, want the original %d",
			len(body), len(canaryBody))
	}

	// The planted link itself is untouched (it was never a rename target).
	fi, err := os.Lstat(planted)
	if err != nil {
		t.Fatalf("lstat planted link: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("planted path is no longer a symlink (mode %v) — the writer replaced it", fi.Mode())
	}

	// And the real archive still published, owner-only.
	afi, err := os.Stat(out)
	if err != nil {
		t.Fatalf("stat published archive: %v", err)
	}
	if got := afi.Mode().Perm(); got != 0o600 {
		t.Fatalf("published archive mode = %04o, want 0600", got)
	}
}

// BKP-1: a plaintext archive must be REFUSED when a passphrase is configured.
// loadAndMaybeDecrypt chose the envelope by magic-byte sniff and consulted the
// passphrase only in the encrypted branch, so the downgrade was accepted with
// the passphrase never examined. The manifest is self-referential, so every
// content check still passed and a substituted ui_users.json installed an
// attacker-authored admin roster.
func TestChaos82_PlaintextArchiveRefusedWhenPassphraseSet(t *testing.T) {
	dataDir := seedBackupDataDir(t)
	out := filepath.Join(t.TempDir(), "substituted.tar.gz")

	// The attacker's hand-built archive: structurally valid, just not encrypted.
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}

	_, _, err := readTarball(out, testBackupPassphrase)
	if err == nil {
		t.Fatal("a PLAINTEXT archive was accepted although a passphrase was set: " +
			"this is the BKP-1 encryption downgrade — a substituted archive installs its own admin roster")
	}
	if !strings.Contains(err.Error(), "NOT encrypted") {
		t.Fatalf("expected an encryption-downgrade refusal naming the cause, got: %v", err)
	}
	// The remedy must be actionable: the message names the variable to unset.
	if !strings.Contains(err.Error(), backupPassphraseEnv) {
		t.Fatalf("refusal does not name %s, so the operator cannot act on it: %v", backupPassphraseEnv, err)
	}
}

// Negative control for BKP-1: the legitimate plaintext restore — no passphrase
// supplied — must still work. This is the case the maintenance agent drives
// (ComposeRestoreDryRun resolves an empty passphrase for an unencrypted
// archive; the unencrypted backup/list templates suppress the variable with an
// explicit unset), so a refusal here would break the shipped restore flow.
func TestChaos82_PlaintextArchiveStillAcceptedWithoutPassphrase(t *testing.T) {
	dataDir := seedBackupDataDir(t)
	out := filepath.Join(t.TempDir(), "backup.tar.gz")

	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}

	files, _, err := readTarball(out, "")
	if err != nil {
		t.Fatalf("plaintext archive must still restore with no passphrase: %v", err)
	}
	if _, ok := files["data/ui_users.json"]; !ok {
		t.Fatalf("expected data/ui_users.json in the archive, got %d entries", len(files))
	}
}

// Negative control for BKP-1: the encrypted archive with its correct
// passphrase is unaffected by the new refusal.
func TestChaos82_EncryptedArchiveStillRestores(t *testing.T) {
	dataDir := seedBackupDataDir(t)
	out := filepath.Join(t.TempDir(), "backup.tar.gz.enc")

	if err := runBackupEncrypted(out, dataDir, testBackupPassphrase); err != nil {
		t.Fatalf("runBackupEncrypted: %v", err)
	}

	files, _, err := readTarball(out, testBackupPassphrase)
	if err != nil {
		t.Fatalf("encrypted archive must still restore with its passphrase: %v", err)
	}
	if _, ok := files["data/ui_users.json"]; !ok {
		t.Fatalf("expected data/ui_users.json in the archive, got %d entries", len(files))
	}
}
