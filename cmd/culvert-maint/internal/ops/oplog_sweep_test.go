package ops

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSweepOpLogs(t *testing.T) {
	stateDir := t.TempDir()
	opsDir := filepath.Join(stateDir, "operations")
	if err := os.MkdirAll(opsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	write := func(name string, age time.Duration) string {
		p := filepath.Join(opsDir, name)
		if err := os.WriteFile(p, []byte("log\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		mt := now.Add(-age)
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
		return p
	}

	old1 := write("01OLD1.log", 40*24*time.Hour) // 40 days — swept
	old2 := write("01OLD2.log", 31*24*time.Hour) // 31 days — swept
	fresh := write("01NEW.log", 2*24*time.Hour)  // 2 days — kept
	// A non-.log file and a directory must be ignored even if old.
	other := write("notes.txt", 90*24*time.Hour)
	if err := os.MkdirAll(filepath.Join(opsDir, "01DIR.log"), 0o750); err != nil {
		t.Fatal(err)
	}

	removed := SweepOpLogs(stateDir, 30*24*time.Hour, now)
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	for _, p := range []string{old1, old2} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("expected %s to be swept", filepath.Base(p))
		}
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("fresh log must be kept: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Error("non-.log file must be ignored, not swept")
	}
	if _, err := os.Stat(filepath.Join(opsDir, "01DIR.log")); err != nil {
		t.Error("directory ending in .log must be ignored")
	}
}

func TestSweepOpLogs_NoDirOrDisabled(t *testing.T) {
	// Missing operations dir → 0, no panic.
	if n := SweepOpLogs(t.TempDir(), 24*time.Hour, time.Now()); n != 0 {
		t.Errorf("missing dir sweep = %d, want 0", n)
	}
	// maxAge <= 0 disables the sweep.
	if n := SweepOpLogs(t.TempDir(), 0, time.Now()); n != 0 {
		t.Errorf("disabled sweep = %d, want 0", n)
	}
}
