package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRunListBackups_EmitsStableJSON(t *testing.T) {
	dir := t.TempDir()
	// Two regular files, one looks like an encrypted backup.
	enc := append([]byte(backupEncMagic), make([]byte, 64)...)
	if err := os.WriteFile(filepath.Join(dir, "b-encrypted.tar.gz.enc"), enc, 0o600); err != nil {
		t.Fatalf("write encrypted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a-plain.tar.gz"), []byte("plaincontent"), 0o600); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	// Subdir, symlink, and unreadable byte-zero file: none should
	// appear in the listing.
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink("nowhere", filepath.Join(dir, "danglesym")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	var buf bytes.Buffer
	if err := runListBackups(dir, &buf); err != nil {
		t.Fatalf("runListBackups: %v", err)
	}
	var got []backupListEntry
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(got), got)
	}
	// Sorted ascending by filename.
	if got[0].Filename != "a-plain.tar.gz" || got[1].Filename != "b-encrypted.tar.gz.enc" {
		t.Errorf("not sorted: %+v", got)
	}
	if got[0].Encrypted {
		t.Errorf("plain file flagged encrypted")
	}
	if !got[1].Encrypted {
		t.Errorf("encrypted file flagged plain")
	}
	if got[1].SizeBytes < int64(backupEncMagicLen) {
		t.Errorf("encrypted size suspicious: %d", got[1].SizeBytes)
	}
}

func TestRunListBackups_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	if err := runListBackups(dir, &buf); err != nil {
		t.Fatalf("runListBackups: %v", err)
	}
	var got []backupListEntry
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	if len(got) != 0 {
		t.Errorf("empty dir should yield 0 entries, got %d", len(got))
	}
}

func TestRunListBackups_RejectsRelativeDir(t *testing.T) {
	if err := runListBackups("relative/path", &bytes.Buffer{}); err == nil {
		t.Error("expected error for relative --backup-dir")
	}
	if err := runListBackups("", &bytes.Buffer{}); err == nil {
		t.Error("expected error for empty --backup-dir")
	}
}

func TestRunListBackups_NonexistentDir(t *testing.T) {
	if err := runListBackups("/nonexistent-d16b-test-path", &bytes.Buffer{}); err == nil {
		t.Error("expected error when dir does not exist")
	}
}

// Symlink safety: a symlink in the backup dir, even pointing at a
// regular file with the encrypted-magic prefix, must NOT show up in
// the listing. peekEncryptedMagic must refuse to follow symlinks.
func TestRunListBackups_IgnoresSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.tar.gz.enc")
	enc := append([]byte(backupEncMagic), make([]byte, 64)...)
	if err := os.WriteFile(target, enc, 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	// A symlink pointing at the real file. The listing must skip it.
	link := filepath.Join(dir, "linked.tar.gz.enc")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// And one pointing OUTSIDE the dir (e.g. a planted /etc/passwd
	// pointer). Must also be skipped — and peekEncryptedMagic must
	// not even try to open it.
	outside := filepath.Join(dir, "evil")
	if err := os.Symlink("/etc/passwd", outside); err != nil {
		t.Fatalf("evil symlink: %v", err)
	}

	var buf bytes.Buffer
	if err := runListBackups(dir, &buf); err != nil {
		t.Fatalf("runListBackups: %v", err)
	}
	var got []backupListEntry
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	if len(got) != 1 {
		t.Fatalf("symlinks must NOT appear in listing; got %d entries: %+v", len(got), got)
	}
	if got[0].Filename != "real.tar.gz.enc" {
		t.Errorf("only the real file should be listed, got %q", got[0].Filename)
	}
}

// peekEncryptedMagic must refuse to open a symlink, even one that
// points at a real file with the encrypted-magic prefix. This guards
// against TOCTOU between DirEntry.Type() and the Open call.
func TestPeekEncryptedMagic_RefusesToFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	enc := append([]byte(backupEncMagic), make([]byte, 64)...)
	if err := os.WriteFile(target, enc, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	link := filepath.Join(dir, "linked")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if peekEncryptedMagic(link) {
		t.Errorf("peekEncryptedMagic must NOT follow symlinks (NOFOLLOW); but reported encrypted=true via %q", link)
	}
	// Sanity: the underlying real file is correctly classified.
	if !peekEncryptedMagic(target) {
		t.Errorf("peekEncryptedMagic should classify the real file as encrypted")
	}
}

func TestPeekEncryptedMagic_TooShort(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "short")
	if err := os.WriteFile(p, []byte("ab"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if peekEncryptedMagic(p) {
		t.Error("file shorter than magic must not be flagged encrypted")
	}
}
