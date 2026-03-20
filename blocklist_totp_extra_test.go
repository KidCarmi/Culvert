package main

// blocklist_totp_extra_test.go — additional coverage for Blocklist.MergeFromLines
// and session/store paths that are easy to reach without external services.

import (
	"testing"
)

// ── Blocklist.MergeFromLines ──────────────────────────────────────────────────

func newBlocklist() *Blocklist {
	return &Blocklist{exact: map[string]bool{}, wildcards: map[string]bool{}}
}

func TestBlocklist_MergeFromLines_Basic(t *testing.T) {
	b := newBlocklist()

	lines := []string{
		"example.com",
		"*.wildcard.org",
		"# this is a comment",
		"",
		"  spaces.net  ",
		"https://stripped.com/path?q=1",
		"http://also-stripped.net:8080/foo",
		"UPPERCASE.COM",
		"example.com", // duplicate — should not count twice
	}

	added := b.MergeFromLines(lines)
	// Expect: example.com, *.wildcard.org, spaces.net, stripped.com, also-stripped.net, uppercase.com = 6
	if added != 6 {
		t.Errorf("expected 6 new entries, got %d", added)
	}

	// Exact match.
	if !b.isListed("example.com") {
		t.Error("example.com should be in blocklist")
	}
	// Wildcard match.
	if !b.isListed("sub.wildcard.org") {
		t.Error("sub.wildcard.org should match *.wildcard.org")
	}
	// Stripped scheme.
	if !b.isListed("stripped.com") {
		t.Error("stripped.com should be in blocklist after scheme strip")
	}
	// Port/path stripped.
	if !b.isListed("also-stripped.net") {
		t.Error("also-stripped.net should be in blocklist")
	}
	// Case normalised.
	if !b.isListed("uppercase.com") {
		t.Error("UPPERCASE.COM should be lowercased and in blocklist")
	}

	// Merge again — all duplicates, added should be 0.
	added2 := b.MergeFromLines([]string{"example.com", "*.wildcard.org"})
	if added2 != 0 {
		t.Errorf("re-merging existing entries should add 0, got %d", added2)
	}
}

func TestBlocklist_MergeFromLines_Empty(t *testing.T) {
	b := newBlocklist()
	added := b.MergeFromLines(nil)
	if added != 0 {
		t.Errorf("nil input should add 0 entries, got %d", added)
	}
	added = b.MergeFromLines([]string{"", "#comment", "   "})
	if added != 0 {
		t.Errorf("blank/comment-only input should add 0 entries, got %d", added)
	}
}

func TestBlocklist_MergeFromLines_SchemeOnlyStripsToEmpty(t *testing.T) {
	b := newBlocklist()
	// "https://" alone — after stripping scheme gets "", should be skipped.
	added := b.MergeFromLines([]string{"https://", "http://"})
	if added != 0 {
		t.Errorf("scheme-only lines should be skipped, got %d added", added)
	}
}

// ── Blocklist mode helpers ────────────────────────────────────────────────────

func TestBlocklist_ModeSetGet(t *testing.T) {
	b := newBlocklist()

	// Default mode is "block".
	if b.Mode() != "block" {
		t.Errorf("default mode should be block, got %s", b.Mode())
	}

	// Switch to allow mode (no file path — save is a no-op).
	b.SetMode("allow")
	if b.Mode() != "allow" {
		t.Errorf("expected allow mode, got %s", b.Mode())
	}

	// Invalid mode falls back to "block".
	b.SetMode("invalid")
	if b.Mode() != "block" {
		t.Errorf("invalid mode should fall back to block, got %s", b.Mode())
	}
}

func TestBlocklist_IsBlockedAndAllowlist(t *testing.T) {
	b := newBlocklist()
	b.MergeFromLines([]string{"evil.com", "*.bad.org"})

	// Block mode (default): listed host → blocked.
	if !b.IsBlocked("evil.com") {
		t.Error("evil.com should be blocked in block mode")
	}
	if !b.IsBlocked("sub.bad.org") {
		t.Error("sub.bad.org should be blocked via wildcard in block mode")
	}
	if b.IsBlocked("safe.com") {
		t.Error("safe.com should not be blocked in block mode")
	}

	// Allow mode: listed hosts are allowed (not blocked), unlisted are blocked.
	b.SetMode("allow")
	if b.IsBlocked("evil.com") {
		t.Error("evil.com should NOT be blocked in allowlist mode (it's in the allow list)")
	}
	if b.IsBlocked("sub.bad.org") {
		t.Error("sub.bad.org should NOT be blocked in allowlist mode")
	}
	if !b.IsBlocked("safe.com") {
		t.Error("safe.com SHOULD be blocked in allowlist mode (not in allow list)")
	}
}
