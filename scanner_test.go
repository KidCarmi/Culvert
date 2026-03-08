package main

import (
	"os"
	"path/filepath"
	"testing"
)

// ── ContentScanner unit tests ──────────────────────────────────────────────────

func freshScanner() *ContentScanner {
	return &ContentScanner{maxBytes: 1 << 20}
}

func TestScanner_EmptyDoesNotMatch(t *testing.T) {
	s := freshScanner()
	if s.Enabled() {
		t.Error("new scanner should not be enabled")
	}
	if _, matched := s.Scan([]byte("evil payload")); matched {
		t.Error("empty scanner should never match")
	}
}

func TestScanner_SetAndMatch(t *testing.T) {
	s := freshScanner()
	if err := s.Set([]string{`evil`, `badword`}); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	if !s.Enabled() {
		t.Error("scanner should be enabled after Set")
	}

	pattern, matched := s.Scan([]byte("this contains evil content"))
	if !matched {
		t.Error("expected match for 'evil'")
	}
	if pattern != "evil" {
		t.Errorf("expected pattern 'evil', got %q", pattern)
	}
}

func TestScanner_NoMatchOnCleanContent(t *testing.T) {
	s := freshScanner()
	if err := s.Set([]string{`evil`, `malware`}); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	if _, matched := s.Scan([]byte("totally safe content here")); matched {
		t.Error("should not match clean content")
	}
}

func TestScanner_InvalidPatternRejected(t *testing.T) {
	s := freshScanner()
	err := s.Set([]string{`[invalid`})
	if err == nil {
		t.Error("Set with invalid regex should return error")
	}
	// Existing patterns must be unchanged on error.
	if s.Enabled() {
		t.Error("scanner should remain disabled after failed Set")
	}
}

func TestScanner_AddAndRemove(t *testing.T) {
	s := freshScanner()
	if err := s.Add(`pattern1`); err != nil {
		t.Fatalf("Add error: %v", err)
	}
	if err := s.Add(`pattern2`); err != nil {
		t.Fatalf("Add error: %v", err)
	}
	if got := s.List(); len(got) != 2 {
		t.Fatalf("expected 2 patterns, got %d", len(got))
	}

	removed := s.Remove(`pattern1`)
	if !removed {
		t.Error("Remove should return true for existing pattern")
	}
	if got := s.List(); len(got) != 1 || got[0] != "pattern2" {
		t.Errorf("after remove, expected [pattern2], got %v", got)
	}

	notRemoved := s.Remove(`nonexistent`)
	if notRemoved {
		t.Error("Remove should return false for nonexistent pattern")
	}
}

func TestScanner_RegexMatch(t *testing.T) {
	s := freshScanner()
	// Match a credit-card-like pattern (simplified signature).
	if err := s.Add(`\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`); err != nil {
		t.Fatalf("Add error: %v", err)
	}
	body := []byte("Your card 4111 1111 1111 1111 was charged.")
	if _, matched := s.Scan(body); !matched {
		t.Error("expected CC-like pattern to match")
	}
	if _, matched := s.Scan([]byte("no card number here")); matched {
		t.Error("should not match content without CC-like number")
	}
}

func TestScanner_LoadSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dpi.json")

	s := freshScanner()
	if err := s.Load(path); err != nil {
		t.Fatalf("Load on missing file should succeed, got: %v", err)
	}
	if s.Enabled() {
		t.Error("scanner should be empty after loading nonexistent file")
	}

	// Set patterns and save.
	if err := s.Set([]string{`evil`, `malware`}); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	s.mu.Lock()
	s.path = path
	s.mu.Unlock()
	s.Save()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Save should have created file: %v", err)
	}

	// Load into a fresh scanner and verify.
	s2 := freshScanner()
	if err := s2.Load(path); err != nil {
		t.Fatalf("Load error: %v", err)
	}
	got := s2.List()
	if len(got) != 2 {
		t.Fatalf("expected 2 patterns after Load, got %d", len(got))
	}
}

func TestScanner_SetReplacesPrevious(t *testing.T) {
	s := freshScanner()
	if err := s.Set([]string{`old`}); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	if err := s.Set([]string{`new1`, `new2`}); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	got := s.List()
	if len(got) != 2 {
		t.Fatalf("expected 2 patterns, got %d", len(got))
	}
	if _, matched := s.Scan([]byte("old")); matched {
		t.Error("old pattern should have been replaced")
	}
	if _, matched := s.Scan([]byte("new1")); !matched {
		t.Error("new1 should match after Set")
	}
}

// ── isTextContentType tests ────────────────────────────────────────────────────

func TestIsTextContentType(t *testing.T) {
	cases := []struct {
		ct   string
		want bool
	}{
		{"text/html; charset=utf-8", true},
		{"text/plain", true},
		{"application/json", true},
		{"application/xml; charset=utf-8", true},
		{"application/javascript", true},
		{"image/png", false},
		{"video/mp4", false},
		{"application/octet-stream", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isTextContentType(tc.ct); got != tc.want {
			t.Errorf("isTextContentType(%q) = %v, want %v", tc.ct, got, tc.want)
		}
	}
}
