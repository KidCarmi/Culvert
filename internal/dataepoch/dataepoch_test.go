package dataepoch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRead_AbsentIsTheImplicitEpoch(t *testing.T) {
	r, err := Read(t.TempDir())
	if err != nil || r.Epoch != ImplicitEpoch || r.Present {
		t.Fatalf("Read(empty) = %+v, %v; want implicit epoch %d, absent", r, err, ImplicitEpoch)
	}
}

func TestRead_AMissingDataDirectoryIsNotTheImplicitEpoch(t *testing.T) {
	if r, err := Read(filepath.Join(t.TempDir(), "gone")); err == nil {
		t.Fatalf("Read(missing dir) = %+v, want an error", r)
	}
}

func TestRead_RefusesWhatIsNotAMarker(t *testing.T) {
	cases := map[string]string{
		"not json":       "2",
		"unknown field":  `{"schema":1,"epoch":2,"x":1}`,
		"wrong schema":   `{"schema":2,"epoch":2}`,
		"epoch zero":     `{"schema":1,"epoch":0}`,
		"negative epoch": `{"schema":1,"epoch":-1}`,
		"too large":      `{"schema":1,"epoch":2}` + strings.Repeat(" ", maxMarker),
		"trailing bytes": `{"schema":1,"epoch":1}garbage`,
		"two objects":    `{"schema":1,"epoch":1}{"schema":1,"epoch":3}`,
	}
	for name, body := range cases {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, MarkerName), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if r, err := Read(dir); err == nil {
			t.Errorf("%s: Read = %+v, want an error (never an absent marker)", name, r)
		}
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, MarkerName), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir); err == nil {
		t.Error("a directory at the marker path was read as a marker")
	}
}

func TestRaiseTo_NeverLowersAndWritesOnlyToRaise(t *testing.T) {
	dir := t.TempDir()
	// Epoch 1 on an unmarked directory: nothing to write.
	if out, r, err := RaiseTo(dir, 1); err != nil || out != Unchanged || r.Present {
		t.Fatalf("RaiseTo(1) on absent = %v %+v %v; want Unchanged, still absent", out, r, err)
	}
	if _, err := os.Stat(filepath.Join(dir, MarkerName)); !os.IsNotExist(err) {
		t.Fatalf("a build at the implicit epoch wrote a marker: %v", err)
	}
	if out, r, err := RaiseTo(dir, 3); err != nil || out != Raised || r.Epoch != 3 {
		t.Fatalf("RaiseTo(3) = %v %+v %v", out, r, err)
	}
	if out, r, err := RaiseTo(dir, 2); err != nil || out != Newer || r.Epoch != 3 {
		t.Fatalf("RaiseTo(2) over 3 = %v %+v %v; want Newer, 3 kept", out, r, err)
	}
	if r, _ := Read(dir); r.Epoch != 3 || !r.Present {
		t.Fatalf("marker after a lower raise = %+v, want 3", r)
	}
	if out, _, err := RaiseTo(dir, 3); err != nil || out != Unchanged {
		t.Fatalf("RaiseTo(3) again = %v %v", out, err)
	}
}

func TestRaiseTo_LeavesAnUnreadableMarker(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, MarkerName)
	if err := os.WriteFile(p, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RaiseTo(dir, 2); err == nil {
		t.Fatal("RaiseTo over an unreadable marker succeeded")
	}
	if b, _ := os.ReadFile(p); string(b) != "garbage" {
		t.Fatalf("an unreadable marker was overwritten: %q", b)
	}
}

func TestReportFor(t *testing.T) {
	r, err := ReportFor(t.TempDir())
	if err != nil || r.Epoch != 1 || r.MarkerPresent || r.BuildMin != OldestReadable || r.BuildMax != Current || r.Schema != 1 {
		t.Fatalf("ReportFor = %+v, %v", r, err)
	}
}

// The build range is well formed.
func TestConstants(t *testing.T) {
	if OldestReadable < 1 || OldestReadable > Current {
		t.Fatalf("OldestReadable %d, Current %d", OldestReadable, Current)
	}
}
