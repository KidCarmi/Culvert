package scanner

import (
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

func TestNew_DisabledEmpty(t *testing.T) {
	s := New(1 << 20)
	if s.Enabled() {
		t.Error("a fresh scanner with no patterns should be disabled")
	}
	if s.MaxBytes() != 1<<20 {
		t.Errorf("MaxBytes = %d, want %d", s.MaxBytes(), 1<<20)
	}
	if got, ok := s.Scan([]byte("anything")); ok || got != "" {
		t.Errorf("empty scanner Scan = (%q, %v), want (\"\", false)", got, ok)
	}
}

func TestSetScanRemove(t *testing.T) {
	s := New(1 << 20)
	if err := s.Set([]string{`evil`, `malware`}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if !s.Enabled() {
		t.Error("scanner should be enabled after Set")
	}
	if got, ok := s.Scan([]byte("this is evil content")); !ok || got != "evil" {
		t.Errorf("Scan = (%q, %v), want (evil, true)", got, ok)
	}
	if _, ok := s.Scan([]byte("totally clean")); ok {
		t.Error("clean input should not match")
	}
	if !s.Remove("evil") {
		t.Error("Remove should report the pattern existed")
	}
	if _, ok := s.Scan([]byte("this is evil content")); ok {
		t.Error("removed pattern should no longer match")
	}

	// Invalid pattern leaves the set unchanged.
	if err := s.Set([]string{"("}); err == nil {
		t.Error("Set should reject an uncompilable pattern")
	}
}

func TestBypassHosts(t *testing.T) {
	s := New(1 << 20)
	s.SetBypassHosts([]string{"Example.com:443", "  internal.local  ", ""})
	list := s.BypassHosts()
	if len(list) != 2 || list[0] != "example.com" || list[1] != "internal.local" {
		t.Fatalf("BypassHosts = %v, want [example.com internal.local]", list)
	}
	if !s.IsBypassHost("EXAMPLE.COM:8080") {
		t.Error("IsBypassHost should match case-insensitively and strip the port")
	}
	if s.IsBypassHost("other.com") {
		t.Error("non-listed host should not be a bypass host")
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dpi.json")

	s := New(1 << 20)
	s.SetPath(path)
	if err := s.Set([]string{`rt-pattern`}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	s.SetBypassHosts([]string{"skip.example"})
	s.Save()

	fresh := New(0)
	if err := fresh.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := fresh.List(); len(got) != 1 || got[0] != "rt-pattern" {
		t.Errorf("loaded patterns = %v, want [rt-pattern]", got)
	}
	if !fresh.IsBypassHost("skip.example") {
		t.Error("bypass host should survive the save/load envelope round-trip")
	}
	if fresh.Path() != path {
		t.Errorf("Path() = %q, want %q", fresh.Path(), path)
	}
}

func TestMatchRegexWithTimeout_FailsClosed(t *testing.T) {
	re := regexp.MustCompile(`^(a+)+$`) //nolint:gocritic // intentional pathological regex to exercise the timeout path
	// Catastrophic backtracking input with a near-zero timeout → fail-closed.
	if !MatchRegexWithTimeout(re, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"), time.Nanosecond) {
		t.Error("a timed-out match must fail closed (return true)")
	}
	// A fast, non-matching pattern returns its real result.
	if MatchRegexWithTimeout(regexp.MustCompile(`evil`), []byte("clean"), time.Second) {
		t.Error("non-matching pattern should return false")
	}
}
