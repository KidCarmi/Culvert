package blocklist

// Core matcher/exception/persistence tests, moved in-package from package
// main's blocklist_test.go with the extraction (ADR-0002, store.go
// decomposition Phase A).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// assertNoTmpLeak is a local copy of main's test helper: fails if any
// *.tmp.* file from the atomic writer remains in dir.
func assertNoTmpLeak(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Errorf("orphaned tmp file: %s", e.Name())
		}
	}
}

func freshBL() *Store {
	return New()
}

func TestBlocklist_AddAndIsBlocked(t *testing.T) {
	b := freshBL()
	b.Add("evil.com")
	b.Add("ads.tracker.net")

	cases := []struct {
		host    string
		blocked bool
	}{
		{"evil.com", true},
		{"EVIL.COM", true}, // case-insensitive
		{"ads.tracker.net", true},
		{"good.com", false},
		{"evil.com.fakeout", false},
	}
	for _, c := range cases {
		if got := b.IsBlocked(c.host); got != c.blocked {
			t.Errorf("IsBlocked(%q) = %v, want %v", c.host, got, c.blocked)
		}
	}
}

func TestBlocklist_Wildcard(t *testing.T) {
	b := freshBL()
	b.Add("*.evil.com")

	cases := []struct {
		host    string
		blocked bool
	}{
		{"sub.evil.com", true},
		{"deep.sub.evil.com", true},
		{"evil.com", true}, // apex match
		{"notevil.com", false},
		{"evil.com.proxy", false},
	}
	for _, c := range cases {
		if got := b.IsBlocked(c.host); got != c.blocked {
			t.Errorf("IsBlocked(%q) = %v, want %v", c.host, got, c.blocked)
		}
	}
}

func TestBlocklist_Remove(t *testing.T) {
	b := freshBL()
	b.Add("evil.com")
	b.Remove("evil.com")
	if b.IsBlocked("evil.com") {
		t.Error("expected evil.com to be unblocked after Remove")
	}
}

func TestBlocklist_Count(t *testing.T) {
	b := freshBL()
	if b.Count() != 0 {
		t.Errorf("expected 0, got %d", b.Count())
	}
	b.Add("a.com")
	b.Add("b.com")
	if b.Count() != 2 {
		t.Errorf("expected 2, got %d", b.Count())
	}
}

func TestBlocklist_LoadSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.txt")

	// Write a file with hosts + comments.
	content := "# comment\nevil.com\n*.bad.org\n\ngood.com\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	b := freshBL()
	if err := b.Load(path); err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if !b.IsBlocked("evil.com") {
		t.Error("evil.com should be blocked after Load")
	}
	if !b.IsBlocked("sub.bad.org") {
		t.Error("sub.bad.org should match *.bad.org wildcard")
	}

	// Save and reload.
	b.Add("extra.com")
	b.Save()

	b2 := freshBL()
	if err := b2.Load(path); err != nil {
		t.Fatalf("reload error: %v", err)
	}
	if !b2.IsBlocked("extra.com") {
		t.Error("extra.com should survive Save/Load round-trip")
	}
}

// ── Sidecar atomic-write regression guards (D1.1c) ─────────────────────────

// freshBLWithSidecars returns a Blocklist with all map fields initialized,
// including the sidecar-backed `manual` and `exceptions` sets which freshBL
// does not initialize. Required for AddManual / AddException to not panic.
func freshBLWithSidecars(path string) *Store {
	b := New()
	b.path = path
	return b
}

func TestBlocklist_SaveMode_NoTmpLeak(t *testing.T) {
	dir := t.TempDir()
	b := freshBLWithSidecars(filepath.Join(dir, "blocklist.txt"))
	b.SetMode("block")
	assertNoTmpLeak(t, dir)
}

func TestBlocklist_SaveExceptions_NoTmpLeak(t *testing.T) {
	dir := t.TempDir()
	b := freshBLWithSidecars(filepath.Join(dir, "blocklist.txt"))
	b.AddException("ok.example.com")
	assertNoTmpLeak(t, dir)
}

func TestBlocklist_SaveManual_NoTmpLeak(t *testing.T) {
	dir := t.TempDir()
	b := freshBLWithSidecars(filepath.Join(dir, "blocklist.txt"))
	b.AddManual("manual.example.com")
	assertNoTmpLeak(t, dir)
}
