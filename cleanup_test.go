package main

// D1.3c — restore leftover cleanup tests.
//
// 15 cases covering the safety contract: admission rules, dry-run vs.
// confirm, Lstat-only discovery, TOCTOU re-Lstat, keep-last/older-than
// filters, deterministic order, partial-failure continuation, and the
// guarantee that current /data is never deleted.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// ── helpers ─────────────────────────────────────────────────────────

// makeDir creates dir under parent with mode 0o700 and returns full path.
func makeDir(t *testing.T, parent, name string) string {
	t.Helper()
	full := filepath.Join(parent, name)
	if err := os.Mkdir(full, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", full, err)
	}
	return full
}

// seedDataDir creates an empty dataDir with a marker file inside.
func seedDataDir(t *testing.T, parent string) string {
	t.Helper()
	d := makeDir(t, parent, "data")
	if err := os.WriteFile(filepath.Join(d, "marker.txt"), []byte("keep me"), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	return d
}

// leftoverName builds a valid leftover dirname. Tests always exercise the
// "data" base name (the seed used by seedDataDir), so the function takes
// only kind/ts/pid.
func leftoverName(kind string, ts time.Time, pid int) string {
	return fmt.Sprintf("data.%s.%s-%d", kind, ts.UTC().Format("20060102T150405Z"), pid)
}

// pathsOf returns the .Path field of each leftover, in order.
func pathsOf(in []leftover) []string {
	out := make([]string, len(in))
	for i := range in {
		out[i] = in[i].Path
	}
	return out
}

// ── tests ───────────────────────────────────────────────────────────

func TestCleanup_ListFindsValidBak(t *testing.T) {
	parent := t.TempDir()
	dataDir := seedDataDir(t, parent)
	want := makeDir(t, parent, leftoverName("bak", time.Now().UTC().Add(-2*time.Hour), 1234))

	valid, skipped, err := discoverLeftovers(dataDir)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(valid) != 1 || valid[0].Path != want {
		t.Fatalf("want one entry %q, got %v", want, pathsOf(valid))
	}
	if valid[0].Kind != leftoverBak {
		t.Fatalf("want kind=bak, got %q", valid[0].Kind)
	}
	if len(skipped) != 0 {
		t.Fatalf("unexpected skips: %v", skipped)
	}
}

func TestCleanup_ListFindsValidStaging(t *testing.T) {
	parent := t.TempDir()
	dataDir := seedDataDir(t, parent)
	want := makeDir(t, parent, leftoverName("staging", time.Now().UTC().Add(-1*time.Hour), 5))

	valid, _, err := discoverLeftovers(dataDir)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(valid) != 1 || valid[0].Path != want {
		t.Fatalf("want one entry %q, got %v", want, pathsOf(valid))
	}
	if valid[0].Kind != leftoverStaging {
		t.Fatalf("want kind=staging, got %q", valid[0].Kind)
	}
}

func TestCleanup_IgnoresNonMatchingDirs(t *testing.T) {
	parent := t.TempDir()
	dataDir := seedDataDir(t, parent)

	// Silent ignores — names don't match the regex shape at all.
	makeDir(t, parent, "data.bak")                     // missing timestamp+pid
	makeDir(t, parent, "data.bak.notatimestamp")       // bad timestamp
	makeDir(t, parent, "data.bak.20260101T120000Z")    // missing pid suffix
	makeDir(t, parent, "databak.20260101T120000Z-1")   // missing dot
	makeDir(t, parent, "random")                       // unrelated
	makeDir(t, parent, "datax.bak.20260101T120000Z-1") // different base
	if err := os.WriteFile(filepath.Join(parent, "data.bak.20260101T120000Z-99"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	// Regex-near-misses → WARN: name matches but is a regular file (not a dir).
	// The above file matches the regex but is not a directory → skipped with reason.

	valid, skipped, err := discoverLeftovers(dataDir)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(valid) != 0 {
		t.Fatalf("expected zero valid, got %v", pathsOf(valid))
	}
	// The one "near miss" is the regular file with a regex-shaped name.
	if len(skipped) != 1 {
		t.Fatalf("expected exactly 1 skip warning, got %d: %+v", len(skipped), skipped)
	}
	if skipped[0].Reason != "not a directory" {
		t.Fatalf("expected 'not a directory', got %q", skipped[0].Reason)
	}
}

func TestCleanup_DryRunDeletesNothing(t *testing.T) {
	parent := t.TempDir()
	dataDir := seedDataDir(t, parent)
	bak := makeDir(t, parent, leftoverName("bak", time.Now().UTC().Add(-3*time.Hour), 7))
	stg := makeDir(t, parent, leftoverName("staging", time.Now().UTC().Add(-1*time.Hour), 9))

	if err := runCleanupLeftovers(dataDir, cleanupOpts{Confirm: false}); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	for _, p := range []string{bak, stg, dataDir} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("dry-run unexpectedly removed %s: %v", p, err)
		}
	}
}

func TestCleanup_ConfirmDeletes(t *testing.T) {
	parent := t.TempDir()
	dataDir := seedDataDir(t, parent)
	bak := makeDir(t, parent, leftoverName("bak", time.Now().UTC().Add(-3*time.Hour), 7))
	stg := makeDir(t, parent, leftoverName("staging", time.Now().UTC().Add(-1*time.Hour), 9))
	keepRandom := makeDir(t, parent, "unrelated")

	if err := runCleanupLeftovers(dataDir, cleanupOpts{Confirm: true}); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	for _, p := range []string{bak, stg} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected %s gone, stat err = %v", p, err)
		}
	}
	for _, p := range []string{dataDir, keepRandom} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("unrelated path %s removed: %v", p, err)
		}
	}
}

func TestCleanup_RefusesSymlinkCandidate(t *testing.T) {
	parent := t.TempDir()
	dataDir := seedDataDir(t, parent)

	// Real target dir lives elsewhere; a regex-matching symlink points to it.
	target := t.TempDir()
	targetMarker := filepath.Join(target, "must_survive.txt")
	if err := os.WriteFile(targetMarker, []byte("safe"), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	link := filepath.Join(parent, leftoverName("bak", time.Now().UTC().Add(-1*time.Hour), 1))
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	valid, skipped, err := discoverLeftovers(dataDir)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(valid) != 0 {
		t.Fatalf("expected symlink to be skipped, got %v", pathsOf(valid))
	}
	if len(skipped) != 1 || skipped[0].Path != link {
		t.Fatalf("expected one warning for symlink, got %+v", skipped)
	}
	if skipped[0].Reason != "symlink (refusing to follow)" {
		t.Fatalf("unexpected reason: %q", skipped[0].Reason)
	}

	// Run cleanup with confirm — symlink target must remain intact and
	// the symlink itself must remain (we never delete files/symlinks).
	if err := runCleanupLeftovers(dataDir, cleanupOpts{Confirm: true}); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(targetMarker); err != nil {
		t.Fatalf("symlink target was followed/destroyed: %v", err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink itself was modified/removed: fi=%v err=%v", fi, err)
	}
}

func TestCleanup_ReLstatBeforeDeletion(t *testing.T) {
	parent := t.TempDir()
	dataDir := seedDataDir(t, parent)
	cand := makeDir(t, parent, leftoverName("bak", time.Now().UTC().Add(-1*time.Hour), 1))

	// Sentinel target that the swapped-in symlink will point to.
	sentinel := t.TempDir()
	sentinelMarker := filepath.Join(sentinel, "do_not_delete.txt")
	if err := os.WriteFile(sentinelMarker, []byte("safe"), 0o600); err != nil {
		t.Fatalf("seed sentinel: %v", err)
	}

	preDeleteHook = func(path string) {
		if path != cand {
			return
		}
		if err := os.RemoveAll(cand); err != nil {
			t.Logf("pre-delete swap removeAll: %v", err)
		}
		if err := os.Symlink(sentinel, cand); err != nil {
			t.Logf("pre-delete swap symlink: %v", err)
		}
	}
	t.Cleanup(func() { preDeleteHook = nil })

	err := runCleanupLeftovers(dataDir, cleanupOpts{Confirm: true})
	if err == nil {
		t.Fatalf("expected error from re-Lstat guard, got nil")
	}
	// Sentinel target must still exist intact.
	if _, err := os.Stat(sentinelMarker); err != nil {
		t.Fatalf("sentinel was followed/destroyed: %v", err)
	}
}

func TestCleanup_NeverDeletesCurrentDataDir(t *testing.T) {
	parent := t.TempDir()
	dataDir := seedDataDir(t, parent)
	marker := filepath.Join(dataDir, "marker.txt")
	bak := makeDir(t, parent, leftoverName("bak", time.Now().UTC().Add(-1*time.Hour), 1))

	if err := runCleanupLeftovers(dataDir, cleanupOpts{Confirm: true}); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(dataDir); err != nil {
		t.Fatalf("data dir was deleted: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("data dir contents were deleted: %v", err)
	}
	if _, err := os.Stat(bak); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected leftover gone, stat err = %v", err)
	}
}

func TestCleanup_KeepLastN(t *testing.T) {
	parent := t.TempDir()
	dataDir := seedDataDir(t, parent)
	now := time.Now().UTC()
	// 5 baks, oldest first.
	var dirs []string
	for i := 0; i < 5; i++ {
		ts := now.Add(time.Duration(-(5 - i)) * time.Hour)
		dirs = append(dirs, makeDir(t, parent, leftoverName("bak", ts, 100+i)))
	}

	if err := runCleanupLeftovers(dataDir, cleanupOpts{Confirm: true, KeepLast: 2}); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	// dirs[0..2] (3 oldest) should be gone; dirs[3..4] (2 newest) should remain.
	for i, d := range dirs {
		_, err := os.Stat(d)
		if i < 3 {
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected %s gone, stat err = %v", d, err)
			}
		} else {
			if err != nil {
				t.Fatalf("expected %s preserved, stat err = %v", d, err)
			}
		}
	}
}

func TestCleanup_OlderThan(t *testing.T) {
	parent := t.TempDir()
	dataDir := seedDataDir(t, parent)
	now := time.Now().UTC()
	dRecent := makeDir(t, parent, leftoverName("bak", now.Add(-1*time.Hour), 1))
	dMid := makeDir(t, parent, leftoverName("bak", now.Add(-24*time.Hour), 2))
	dStale := makeDir(t, parent, leftoverName("bak", now.Add(-240*time.Hour), 3))

	if err := runCleanupLeftovers(dataDir, cleanupOpts{Confirm: true, OlderThan: 168 * time.Hour}); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(dStale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected stale gone, stat err = %v", err)
	}
	for _, d := range []string{dRecent, dMid} {
		if _, err := os.Stat(d); err != nil {
			t.Fatalf("expected %s preserved, stat err = %v", d, err)
		}
	}
}

func TestCleanup_KeepLastDoesNotApplyToStaging(t *testing.T) {
	parent := t.TempDir()
	dataDir := seedDataDir(t, parent)
	now := time.Now().UTC()
	// Two .bak (so keep-last=2 retains both) plus three .staging.
	bak1 := makeDir(t, parent, leftoverName("bak", now.Add(-2*time.Hour), 1))
	bak2 := makeDir(t, parent, leftoverName("bak", now.Add(-1*time.Hour), 2))
	stg1 := makeDir(t, parent, leftoverName("staging", now.Add(-3*time.Hour), 10))
	stg2 := makeDir(t, parent, leftoverName("staging", now.Add(-2*time.Hour), 11))
	stg3 := makeDir(t, parent, leftoverName("staging", now.Add(-1*time.Hour), 12))

	if err := runCleanupLeftovers(dataDir, cleanupOpts{Confirm: true, KeepLast: 2}); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	for _, d := range []string{bak1, bak2} {
		if _, err := os.Stat(d); err != nil {
			t.Fatalf("expected %s preserved by keep-last, stat err = %v", d, err)
		}
	}
	for _, d := range []string{stg1, stg2, stg3} {
		if _, err := os.Stat(d); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected staging %s deleted regardless of keep-last, stat err = %v", d, err)
		}
	}
}

func TestCleanup_RefusesIfDataDirRoot(t *testing.T) {
	if err := discoverLeftoversWrapper("/"); err == nil {
		t.Fatalf("expected error for dataDir=/")
	}
	if err := discoverLeftoversWrapper(""); err == nil {
		t.Fatalf("expected error for empty dataDir")
	}
}

// discoverLeftoversWrapper exists so the test never accidentally calls
// discoverLeftovers on the real "/" root if the guard regresses. Returns
// only the error since the leftover/skipReason results are unused here.
func discoverLeftoversWrapper(d string) error {
	if d == "/" || d == "" {
		_, _, _, err := resolveDataDirRoots(d)
		return err
	}
	_, _, err := discoverLeftovers(d)
	return err
}

func TestCleanup_DeterministicOrder(t *testing.T) {
	parent := t.TempDir()
	dataDir := seedDataDir(t, parent)
	now := time.Now().UTC()
	// Out-of-order creation; identical-timestamp pair tests pid tie-break.
	a := makeDir(t, parent, leftoverName("bak", now.Add(-2*time.Hour), 50))
	b := makeDir(t, parent, leftoverName("bak", now.Add(-1*time.Hour), 1))
	c := makeDir(t, parent, leftoverName("staging", now.Add(-2*time.Hour), 2))

	valid, _, err := discoverLeftovers(dataDir)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	got := pathsOf(valid)
	// Ascending by timestamp; ties broken by pid asc (c.pid=2 < a.pid=50);
	// then by name asc (only matters if both prior keys tie).
	want := []string{c, a, b}
	if !cleanupEqualSlices(got, want) {
		t.Fatalf("order mismatch:\n  got  %v\n  want %v", got, want)
	}
}

func TestCleanup_PartialFailureContinues(t *testing.T) {
	parent := t.TempDir()
	dataDir := seedDataDir(t, parent)
	now := time.Now().UTC()
	a := makeDir(t, parent, leftoverName("bak", now.Add(-3*time.Hour), 1))
	b := makeDir(t, parent, leftoverName("bak", now.Add(-2*time.Hour), 2))
	c := makeDir(t, parent, leftoverName("bak", now.Add(-1*time.Hour), 3))

	// Hook causes the middle candidate's re-Lstat to fail closed by
	// swapping the dir for a regular file.
	preDeleteHook = func(path string) {
		if path != b {
			return
		}
		if err := os.RemoveAll(b); err != nil {
			t.Logf("swap removeAll: %v", err)
		}
		if err := os.WriteFile(b, []byte("not a dir"), 0o600); err != nil {
			t.Logf("swap write: %v", err)
		}
	}
	t.Cleanup(func() { preDeleteHook = nil })

	err := runCleanupLeftovers(dataDir, cleanupOpts{Confirm: true})
	if err == nil {
		t.Fatalf("expected error due to partial failure, got nil")
	}

	if _, err := os.Stat(a); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected a deleted, stat err = %v", err)
	}
	if _, err := os.Stat(c); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected c deleted, stat err = %v", err)
	}
	// b is now a regular file (the swap result); cleanup must not have
	// deleted it because the re-Lstat refused.
	fi, err := os.Lstat(b)
	if err != nil {
		t.Fatalf("expected b still present (as regular file), got err=%v", err)
	}
	if fi.IsDir() {
		t.Fatalf("expected b to be a regular file after swap, got dir")
	}
}

func TestCleanup_NestedPathRefused(t *testing.T) {
	parent := t.TempDir()
	dataDir := seedDataDir(t, parent)

	// A regex-matching dir buried two levels below parent. Discovery is
	// non-recursive, so it must be invisible.
	sub := makeDir(t, parent, "subdir")
	subsub := makeDir(t, sub, "deeper")
	hidden := makeDir(t, subsub, leftoverName("bak", time.Now().UTC().Add(-1*time.Hour), 1))

	valid, _, err := discoverLeftovers(dataDir)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(valid) != 0 {
		t.Fatalf("expected nested leftover to be invisible, got %v", pathsOf(valid))
	}
	if _, err := os.Stat(hidden); err != nil {
		t.Fatalf("nested dir should be untouched: %v", err)
	}
}

// ── filter unit tests (white-box) ───────────────────────────────────

func TestApplyCleanupFilters_KeepLastReservesNewest(t *testing.T) {
	now := time.Now().UTC()
	in := []leftover{
		{Path: "/p/data.bak.1", Kind: leftoverBak, Timestamp: now.Add(-5 * time.Hour), PID: 1},
		{Path: "/p/data.bak.2", Kind: leftoverBak, Timestamp: now.Add(-4 * time.Hour), PID: 2},
		{Path: "/p/data.bak.3", Kind: leftoverBak, Timestamp: now.Add(-3 * time.Hour), PID: 3},
	}
	got := applyCleanupFilters(in, cleanupOpts{KeepLast: 1}, now)
	want := []string{"/p/data.bak.1", "/p/data.bak.2"}
	gotPaths := pathsOf(got)
	sort.Strings(gotPaths)
	sort.Strings(want)
	if !cleanupEqualSlices(gotPaths, want) {
		t.Fatalf("got %v want %v", gotPaths, want)
	}
}

// ── small utils ─────────────────────────────────────────────────────

func cleanupEqualSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
