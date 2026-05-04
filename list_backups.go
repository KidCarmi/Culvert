// D1.6b: --list-backups one-shot CLI.
//
// The Maintenance Agent's GET /v1/backups endpoint shells out to the cli
// container (via `docker compose --profile cli run --rm cli --list-backups
// --backup-dir /backup`) and parses the JSON array this command emits to
// stdout. Operators can also invoke it manually for debugging — same
// output format either way.
//
// Encryption detection uses the D1.4 magic prefix `CVRTBK01` at byte 0
// (see backup_encrypt.go: backupEncMagic). We peek 8 bytes; entries whose
// first 8 bytes match are flagged encrypted=true. Anything else is
// reported as encrypted=false; we do NOT attempt deeper validation
// (gzip-magic, tar header, etc.) because the agent only needs an
// operator-facing "encrypted-or-not" hint here, and partial reads are
// cheap.
//
// Symlinks, directories, and unreadable entries are skipped silently
// rather than failing the whole listing — the human (or agent) can act
// on whatever IS readable. Errors at the directory level (e.g.
// non-existent --backup-dir) DO fail the command.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

// backupListEntry is the on-the-wire shape of one entry in the JSON
// array emitted by --list-backups. Field names are stable; the agent's
// internal/server status handler depends on them.
type backupListEntry struct {
	Filename   string    `json:"filename"`
	Path       string    `json:"path"`
	SizeBytes  int64     `json:"size_bytes"`
	ModifiedAt time.Time `json:"modified_at"`
	Encrypted  bool      `json:"encrypted"`
}

// runListBackups scans dir for regular files, classifies each as
// encrypted/unencrypted via magic-bytes peek, and emits a JSON array
// (sorted by filename ascending) on out.
func runListBackups(dir string, out io.Writer) error {
	if dir == "" {
		return fmt.Errorf("--backup-dir is required")
	}
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("--backup-dir must be absolute, got %q", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read backup dir %s: %w", dir, err)
	}
	out_entries := make([]backupListEntry, 0, len(entries))
	for _, e := range entries {
		// Skip non-regular entries via DirEntry.Type() — this does
		// NOT follow symlinks (unlike os.Stat). Symlinks, dirs,
		// devices, sockets, etc. are filtered out on the cheap.
		if !e.Type().IsRegular() {
			continue
		}
		// Also Lstat (NOT Stat) the entry to confirm it's still a
		// regular file at the moment we care about size/mtime; this
		// guards against TOCTOU where a real file at ReadDir time is
		// replaced by a symlink before we read it.
		full := filepath.Join(dir, e.Name())
		fi, ferr := os.Lstat(full) //nolint:gosec // listing the operator-supplied backup dir is the whole point
		if ferr != nil {
			continue
		}
		if !fi.Mode().IsRegular() {
			continue
		}
		out_entries = append(out_entries, backupListEntry{
			Filename:   e.Name(),
			Path:       full,
			SizeBytes:  fi.Size(),
			ModifiedAt: fi.ModTime().UTC(),
			Encrypted:  peekEncryptedMagic(full),
		})
	}
	sort.Slice(out_entries, func(i, j int) bool {
		return out_entries[i].Filename < out_entries[j].Filename
	})
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out_entries); err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}
	return nil
}

// peekEncryptedMagic returns true iff the first backupEncMagicLen bytes
// of path equal backupEncMagic. Returns false on any read error
// (unreadable file, too short, etc.) — the caller treats false as
// "encrypted=unknown-or-no" and that is fine for an informational list.
//
// Open uses O_NOFOLLOW so a symlink-replacement race after the
// caller's DirEntry.Type() / Lstat checks cannot trick us into
// reading from an unintended target.
func peekEncryptedMagic(path string) bool {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // intentional: classify the operator-supplied backup file
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, backupEncMagicLen)
	n, err := io.ReadFull(f, buf)
	if err != nil || n < backupEncMagicLen {
		return false
	}
	return isEncryptedBackupBlob(buf)
}
