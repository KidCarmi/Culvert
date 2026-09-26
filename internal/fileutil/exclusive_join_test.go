package fileutil

// exclusive_join_test.go — FE-6AR merge 12: the package carries TWO exclusive
// file-creation primitives with DIFFERENT contracts, and this file pins that
// they stay different.
//
//   - PublishExclusive (FE-6A.2 round 3): first-writer-wins PUBLICATION. A
//     value that must exist exactly once (the IdP candidate-commitment key)
//     is created durably; a concurrent loser learns the winner exists
//     (created=false) and reads the winner's bytes; an existing entry is
//     never replaced.
//   - WriteFileExclusive (SEC-SECRETWRITE-1): safe REPLACEMENT of a
//     rendezvous entry at a predictable path (a stale "<bundle>.tmp" from an
//     interrupted predecessor is superseded), created with O_EXCL at the
//     requested mode so a planted link or wide-mode file never receives the
//     secret.
//
// The two are not interchangeable, and the cheapest wrong "simplification" —
// implementing one in terms of the other — silently changes a security
// contract: a key that commitments depend on would be replaceable, or a stale
// staging file would never be superseded. Each proof below FAILS against that
// substitution.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// PublishExclusive never replaces an existing entry: a second publisher is
// told the winner exists and the bytes on disk stay the winner's.
func TestExclusiveJoin_PublishExclusiveNeverReplacesTheWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	created, err := PublishExclusive(path, []byte("winner"), 0o600)
	if err != nil || !created {
		t.Fatalf("first publish: created=%v err=%v", created, err)
	}
	created, err = PublishExclusive(path, []byte("loser"), 0o600)
	if err != nil {
		t.Fatalf("second publish must not fail: %v", err)
	}
	if created {
		t.Fatal("second publish reported created=true: a first-writer-wins publication was replaced")
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, []byte("winner")) {
		t.Fatalf("on-disk bytes = %q, want the winner's", got)
	}
}

// WriteFileExclusive DOES replace an existing entry — that is its job for a
// rendezvous path — and the replacement carries the requested mode.
func TestExclusiveJoin_WriteFileExclusiveReplacesARendezvous(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.tmp")
	if err := os.WriteFile(path, []byte("stale"), 0o666); err != nil { // #nosec G306 -- the planted wide-mode stale file under test
		t.Fatal(err)
	}
	if err := WriteFileExclusive(path, []byte("fresh"), 0o600); err != nil {
		t.Fatalf("WriteFileExclusive over a stale rendezvous: %v", err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, []byte("fresh")) {
		t.Fatalf("on-disk bytes = %q, want the fresh write", got)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 0600 (a planted 0666 file must not keep its mode)", st.Mode().Perm())
	}
}

// The DIVERGENCE is the contract: the same starting state (an existing entry)
// yields opposite outcomes, so neither primitive can stand in for the other.
func TestExclusiveJoin_ThePrimitivesDivergeOnAnExistingEntry(t *testing.T) {
	dir := t.TempDir()
	pub := filepath.Join(dir, "pub")
	wfe := filepath.Join(dir, "wfe")
	for _, p := range []string{pub, wfe} {
		if err := os.WriteFile(p, []byte("existing"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	created, err := PublishExclusive(pub, []byte("new"), 0o600)
	if err != nil || created {
		t.Fatalf("PublishExclusive over an existing entry: created=%v err=%v, want (false, nil)", created, err)
	}
	if got, _ := os.ReadFile(pub); string(got) != "existing" {
		t.Fatalf("PublishExclusive changed the existing entry to %q", got)
	}
	if err := WriteFileExclusive(wfe, []byte("new"), 0o600); err != nil {
		t.Fatalf("WriteFileExclusive over an existing entry: %v", err)
	}
	if got, _ := os.ReadFile(wfe); string(got) != "new" {
		t.Fatalf("WriteFileExclusive left the existing entry as %q", got)
	}
}

// Concurrency: N publishers of DIFFERENT bytes produce exactly one creation
// and every caller ends up agreeing on the one value on disk (the loser reads
// the winner) — the property the IdP commitment key depends on.
func TestExclusiveJoin_ConcurrentPublishersAgreeOnOneValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	createdCount := 0
	var errs []error
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			created, err := PublishExclusive(path, []byte{byte('a' + i)}, 0o600)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			if created {
				createdCount++
			}
		}(i)
	}
	wg.Wait()
	if len(errs) != 0 {
		t.Fatalf("publishers failed: %v", errors.Join(errs...))
	}
	if createdCount != 1 {
		t.Fatalf("created reported %d times, want exactly 1", createdCount)
	}
	got, err := os.ReadFile(path)
	if err != nil || len(got) != 1 || got[0] < 'a' || got[0] >= 'a'+n {
		t.Fatalf("on-disk value %q is not one publisher's byte", got)
	}
}

// A dangling symlink planted at a PublishExclusive path must not redirect the
// publication either — the FE-6A.2 round-4 rule (a key is validated with
// non-following metadata) needs the file that was published to be the file
// at the path. link(2) onto an existing name fails with EEXIST, so the
// planted link wins as "existing" and the publisher REUSES it — which the
// read side then refuses as exposed (idpInspectCandidateKey). Here we pin
// only that the secret bytes never travel through the link.
func TestExclusiveJoin_PublishExclusiveDoesNotWriteThroughAPlantedLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	path := filepath.Join(dir, "key")
	if err := os.Symlink(target, path); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	_, _ = PublishExclusive(path, []byte("secret"), 0o600)
	if _, err := os.Stat(target); err == nil {
		t.Fatal("the publication was written THROUGH the planted symlink to its target")
	}
	// The temp file is cleaned up whatever happened.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "key" && e.Name() != "elsewhere" {
			t.Fatalf("stray temp file left behind: %s", e.Name())
		}
	}
}
