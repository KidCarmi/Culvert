package ops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenOpLog_RejectsNonULIDOpID(t *testing.T) {
	dir := t.TempDir()
	bad := []string{
		"",
		"not-a-ulid",
		"../escape",
		"/etc/passwd",
		"01ARZ3NDEKTSV4RRFFQ69G5FA", // 25 chars (one short)
		"01ARZ3NDEKTSV4RRFFQ69G5FAVX",
	}
	for _, b := range bad {
		l, err := OpenOpLog(dir, b)
		if err == nil {
			_ = l.Close()
			t.Errorf("OpenOpLog accepted bogus op_id %q", b)
		}
	}
}

func TestOpenOpLog_RequiresAbsoluteStateDir(t *testing.T) {
	id := NewID()
	if _, err := OpenOpLog("relative/path", id); err == nil {
		t.Error("expected error for relative state dir")
	}
	if _, err := OpenOpLog("", id); err == nil {
		t.Error("expected error for empty state dir")
	}
}

func TestOpenOpLog_CreatesParentAndFile(t *testing.T) {
	dir := t.TempDir()
	id := NewID()
	l, err := OpenOpLog(dir, id)
	if err != nil {
		t.Fatalf("OpenOpLog: %v", err)
	}
	defer func() { _ = l.Close() }()

	want := filepath.Join(dir, "operations", id+".log")
	if l.Path() != want {
		t.Errorf("path mismatch: got %s want %s", l.Path(), want)
	}
	fi, err := os.Stat(want)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := fi.Mode().Perm(); mode != 0o640 {
		t.Errorf("log mode: got %o want 0640", mode)
	}
	parent, err := os.Stat(filepath.Join(dir, "operations"))
	if err != nil {
		t.Fatalf("stat parent: %v", err)
	}
	if mode := parent.Mode().Perm(); mode != 0o750 {
		t.Errorf("parent mode: got %o want 0750", mode)
	}
}

func TestOpLog_StageStartEndAppend(t *testing.T) {
	dir := t.TempDir()
	id := NewID()
	l, err := OpenOpLog(dir, id)
	if err != nil {
		t.Fatalf("OpenOpLog: %v", err)
	}
	if err := l.StageStart("preflight"); err != nil {
		t.Fatalf("StageStart: %v", err)
	}
	if err := l.Note("preflight", "args validated"); err != nil {
		t.Fatalf("Note: %v", err)
	}
	if err := l.StageEnd("preflight", StateSucceeded, ""); err != nil {
		t.Fatalf("StageEnd: %v", err)
	}
	_ = l.Close()

	body, err := os.ReadFile(l.Path()) //nolint:gosec // test path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(body)
	if !strings.Contains(s, "\tpreflight\tSTART\n") {
		t.Errorf("missing START line:\n%s", s)
	}
	if !strings.Contains(s, "\tpreflight\tNOTE\targs validated\n") {
		t.Errorf("missing NOTE line:\n%s", s)
	}
	if !strings.Contains(s, "\tpreflight\tEND succeeded\n") {
		t.Errorf("missing END line:\n%s", s)
	}
}

func TestOpLog_CaptureSplitsLinesAndStripsControls(t *testing.T) {
	dir := t.TempDir()
	id := NewID()
	l, err := OpenOpLog(dir, id)
	if err != nil {
		t.Fatalf("OpenOpLog: %v", err)
	}
	body := []byte("line1\nline2 with NUL \x00 inside\nline3\n")
	if err := l.Capture("run", "out", body, 0); err != nil {
		t.Fatalf("Capture: %v", err)
	}
	_ = l.Close()
	got, _ := os.ReadFile(l.Path()) //nolint:gosec // test path
	s := string(got)
	if !strings.Contains(s, "\trun\tout\tline1\n") {
		t.Errorf("missing line1: %q", s)
	}
	if strings.Contains(s, "\x00") {
		t.Errorf("NUL not stripped: %q", s)
	}
	if !strings.Contains(s, "line2 with NUL ? inside") {
		t.Errorf("NUL not replaced with '?': %q", s)
	}
	if !strings.Contains(s, "\trun\tout\tline3\n") {
		t.Errorf("missing line3: %q", s)
	}
}

func TestOpLog_CaptureTruncatesLargeBodies(t *testing.T) {
	dir := t.TempDir()
	id := NewID()
	l, err := OpenOpLog(dir, id)
	if err != nil {
		t.Fatalf("OpenOpLog: %v", err)
	}
	big := strings.Repeat("X", 4096)
	if err := l.Capture("run", "out", []byte(big), 64); err != nil {
		t.Fatalf("Capture: %v", err)
	}
	_ = l.Close()
	got, _ := os.ReadFile(l.Path()) //nolint:gosec // test path
	if !strings.Contains(string(got), "<truncated>") {
		t.Errorf("expected truncated marker, log:\n%s", got)
	}
	// The original 4 KiB must NOT all be present after a 64-byte cap.
	if strings.Count(string(got), "X") > 200 {
		t.Errorf("body not actually truncated (X count=%d)", strings.Count(string(got), "X"))
	}
}

func TestOpLog_NoteSanitizesMultilineToOne(t *testing.T) {
	dir := t.TempDir()
	id := NewID()
	l, _ := OpenOpLog(dir, id)
	if err := l.Note("stage", "first line\nsecond line\nthird"); err != nil {
		t.Fatalf("Note: %v", err)
	}
	_ = l.Close()
	got, _ := os.ReadFile(l.Path()) //nolint:gosec // test path
	if strings.Count(string(got), "\n") != 1 {
		t.Errorf("Note must produce exactly 1 newline (single log entry); got %q", got)
	}
	if !strings.Contains(string(got), "first line") {
		t.Errorf("first line missing from sanitized note")
	}
	if strings.Contains(string(got), "second line") {
		t.Errorf("second line should have been dropped")
	}
}

func TestOpLog_CloseIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	id := NewID()
	l, _ := OpenOpLog(dir, id)
	if err := l.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("second Close should be no-op: %v", err)
	}
	if err := l.Note("stage", "after close"); err == nil {
		t.Error("Note after Close must error")
	}
}
