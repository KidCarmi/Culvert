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
