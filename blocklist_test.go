package main

import (
	"os"
	"path/filepath"
	"testing"
)

func freshBL() *Blocklist {
	return &Blocklist{exact: map[string]bool{}, wildcards: map[string]bool{}}
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
		{"EVIL.COM", true},       // case-insensitive
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
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
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
