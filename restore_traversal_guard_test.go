package main

// restore_traversal_guard_test.go — regression wall for readTarball's zip-slip
// guard (CWE-22 / OWASP A01, restore.go).
//
// Why this file exists: readTarball has three sibling entry-name guards —
// absolute path, path traversal, duplicate name — and only two of them were
// pinned (TestRestore_DryRun_AbsoluteTarPathRejected,
// TestRestore_DryRun_DuplicateTarEntryRejected). The traversal guard, the one
// that actually carries the CWE-22 contract, had no test at all, and it was
// rewritten in place (per-component `part == ".."` → `strings.Contains(name,
// "..")`) with nothing standing behind the new form.
//
// That is the shape of an unnoticed regression: the backup tarball is
// operator-supplied input on a path whose stated contract (restore.go, and the
// guardWithinDir comment) is that ".." never survives readTarball. D1.3b.2
// extraction and stageArtifacts both rely on that upstream rejection. A future
// "simplification" back toward a narrower check — or a well-meaning revert to
// the per-component split — would compile, pass every existing test, and
// silently re-open the class.
//
// The tests below pin the guard from both sides: hostile names are rejected
// (negative), legitimate names that merely contain dots are NOT (positive), the
// deliberately-broader substring rejection is recorded as intentional rather
// than incidental (boundary), the rejection survives the full dry-run entry
// point without touching /data (end-to-end), and the guard holds under
// concurrent readers (it must stay stateless).

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// tarballWithEntry builds a valid backup and splices in one extra entry with
// the given name, returning the path to the repacked archive. The manifest is
// deliberately NOT rebuilt: readTarball's entry-name guards run before any
// manifest parsing, so a stale manifest cannot mask (or cause) the rejection
// under test.
func tarballWithEntry(t *testing.T, name string) string {
	t.Helper()
	src := makeValidBackup(t)
	dest := filepath.Join(t.TempDir(), "spliced.tar.gz")
	repackTarball(t, src, dest, func(files map[string][]byte, order *[]string) {
		files[name] = []byte("smuggled")
		*order = append(*order, name)
	})
	return dest
}

// ── Negative: hostile entry names must be rejected ──────────────────

func TestReadTarball_TraversalEntryRejected(t *testing.T) {
	cases := []struct {
		name  string
		entry string
		why   string
	}{
		{
			name:  "classic_zip_slip",
			entry: "data/../../etc/passwd",
			why:   "the canonical zip-slip payload: escape the namespace, then the extraction root",
		},
		{
			name:  "leading_traversal",
			entry: "../etc/passwd",
			why:   "traversal in the first component, before any namespace prefix",
		},
		{
			name:  "deep_traversal",
			entry: "data/sub/../../../etc/shadow",
			why:   "traversal interleaved with legitimate components — the form a per-component check must still catch",
		},
		{
			name:  "bare_parent_component",
			entry: "data/..",
			why:   "a trailing parent reference with nothing after it",
		},
		{
			name:  "traversal_after_namespace",
			entry: "data/ui_users.json/../../../root/.ssh/authorized_keys",
			why:   "traversal appended to an otherwise well-formed, in-namespace artifact name",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := tarballWithEntry(t, tc.entry)
			files, order, err := readTarball(path, "")
			if err == nil {
				t.Fatalf("readTarball accepted a traversal entry %q (%s)", tc.entry, tc.why)
			}
			if !strings.Contains(err.Error(), "path traversal") {
				t.Errorf("entry %q: want a path-traversal rejection, got: %v", tc.entry, err)
			}
			// Fail closed, not partially: a caller must never be handed a
			// half-read archive it could iterate.
			if files != nil || order != nil {
				t.Errorf("entry %q: rejection must return no files/order, got %d files, %d order entries",
					tc.entry, len(files), len(order))
			}
		})
	}
}

// TestReadTarball_TraversalRejectionIsDeliberatelyBroad pins the widening the
// current guard chose on purpose.
//
// `strings.Contains(name, "..")` rejects names where ".." is a substring of a
// component rather than a whole component ("data/config..json"). The
// per-component form it replaced accepted those. Backup artifact names are
// controlled system filenames, so nothing legitimate is lost — but the
// broadening must be a recorded decision rather than an accident, because the
// obvious "fix" for a false positive here is to narrow the check back to
// per-component and silently give up the CodeQL-visible sanitiser with it.
//
// If a future backup artifact genuinely needs ".." inside a filename, this test
// is the place that decision gets made — not a quiet edit to restore.go.
func TestReadTarball_TraversalRejectionIsDeliberatelyBroad(t *testing.T) {
	path := tarballWithEntry(t, "data/config..json")
	if _, _, err := readTarball(path, ""); err == nil {
		t.Fatal("readTarball accepted \"data/config..json\": the substring rejection is intentional — " +
			"narrowing it back to a per-component check gives up the CWE-22 sanitiser CodeQL traces")
	} else if !strings.Contains(err.Error(), "path traversal") {
		t.Errorf("want a path-traversal rejection, got: %v", err)
	}
}

// ── Positive: legitimate dotted names must NOT be rejected ──────────

// TestReadTarball_LegitimateDottedNamesAccepted is the other half of the wall.
// A traversal guard that rejects everything is not a guard, it is an outage:
// these names carry dots, live in the data/ namespace, and must read cleanly.
func TestReadTarball_LegitimateDottedNamesAccepted(t *testing.T) {
	for _, entry := range []string{
		"data/.hidden.json",              // leading dot
		"data/v1.0.json",                 // dots as version separators
		"data/config_versions/v99.json",  // nested path, one dot
		"data/threat.feed.snapshot.json", // several dots, none adjacent
	} {
		t.Run(entry, func(t *testing.T) {
			path := tarballWithEntry(t, entry)
			files, _, err := readTarball(path, "")
			if err != nil {
				t.Fatalf("readTarball rejected the legitimate entry %q: %v", entry, err)
			}
			if _, ok := files[entry]; !ok {
				t.Errorf("entry %q missing from the returned file map", entry)
			}
		})
	}
}

// ── End-to-end: the rejection survives the real entry point ─────────

// TestRestore_DryRun_TraversalTarPathRejected mirrors its absolute-path sibling
// exactly: the guard must fire through runRestoreDryRun (not only through a
// direct readTarball call) and the dry-run must leave /data untouched.
func TestRestore_DryRun_TraversalTarPathRejected(t *testing.T) {
	dest := tarballWithEntry(t, "data/../../etc/passwd")
	dataDir := t.TempDir()
	err := runRestoreDryRun(dest, dataDir, "", restoreOpts{})
	if err == nil || !strings.Contains(err.Error(), "path traversal") {
		t.Errorf("expected path-traversal error, got: %v", err)
	}
	assertNoDataMutation(t, dataDir)
}

// ── Concurrency: the guard must stay stateless ──────────────────────

// TestReadTarball_TraversalRejectedConcurrently reads one hostile archive from
// many goroutines at once. readTarball holds no shared state today, and this
// pins that: a future change that hoisted the seen-names set, the decompressor,
// or any buffer to package scope would turn "every caller rejects" into "the
// first caller rejects and the rest race", which is a traversal bypass reachable
// by simply restoring twice at the same time.
func TestReadTarball_TraversalRejectedConcurrently(t *testing.T) {
	path := tarballWithEntry(t, "data/../../etc/passwd")

	const readers = 16
	var wg sync.WaitGroup
	errs := make([]error, readers)
	wg.Add(readers)
	for i := range readers {
		go func(i int) {
			defer wg.Done()
			_, _, errs[i] = readTarball(path, "")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err == nil {
			t.Fatalf("reader %d accepted the traversal entry — the guard is not stateless", i)
		}
		if !strings.Contains(err.Error(), "path traversal") {
			t.Errorf("reader %d: want a path-traversal rejection, got: %v", i, err)
		}
	}
}
