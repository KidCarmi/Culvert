package geoip

// freshness_test.go — CHAOS-127. FileBuildTime against REAL .mmdb files.
//
// The main-package gates for the freshness plane drive a seam, which is right
// for the shapes that are about the PLANE's logic. These are the cases that
// are about the FILE, and they need a real MaxMind database: a seam cannot
// tell you that geoip2.Open accepts what geoiptest writes, that the epoch
// survives the round trip, or that reading a file does not disturb the reader
// this process is serving.

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/geoip/geoiptest"
)

func TestFileBuildTimeReadsTheEmbeddedEpoch(t *testing.T) {
	// Second granularity: the .mmdb carries a Unix epoch, not a monotonic
	// clock, so the assertion is on the truncated value the format can hold.
	want := time.Unix(time.Date(2026, 11, 20, 8, 30, 0, 0, time.UTC).Unix(), 0).UTC()
	path := filepath.Join(t.TempDir(), "GeoLite2-Country.mmdb")
	if err := geoiptest.WriteCountryDB(path, "US", "United States", want); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	got, err := FileBuildTime(path)
	if err != nil {
		t.Fatalf("FileBuildTime: %v", err)
	}
	if !got.Equal(want) {
		t.Errorf("FileBuildTime = %s, want %s", got, want)
	}
}

// TestFileBuildTimeDoesNotDisturbTheLoadedReader is the lifetime property.
// The whole reason this function exists rather than a reload is GEO-1: closing
// a published reader munmaps a buffer an in-flight lookup may hold, which is a
// SIGSEGV recover() cannot catch. FileBuildTime must therefore read a file
// WITHOUT touching package state in either direction.
func TestFileBuildTimeDoesNotDisturbTheLoadedReader(t *testing.T) {
	dir := t.TempDir()
	servingPath := filepath.Join(dir, "serving.mmdb")
	servingBuilt := time.Unix(time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC).Unix(), 0).UTC()
	if err := geoiptest.WriteCountryDB(servingPath, "US", "United States", servingBuilt); err != nil {
		t.Fatalf("write serving fixture: %v", err)
	}
	if err := InitGeoDB(servingPath); err != nil {
		t.Fatalf("InitGeoDB: %v", err)
	}
	t.Cleanup(ResetForTest)

	otherPath := filepath.Join(dir, "newer.mmdb")
	otherBuilt := time.Unix(time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC).Unix(), 0).UTC()
	if err := geoiptest.WriteCountryDB(otherPath, "DE", "Germany", otherBuilt); err != nil {
		t.Fatalf("write newer fixture: %v", err)
	}

	got, err := FileBuildTime(otherPath)
	if err != nil {
		t.Fatalf("FileBuildTime: %v", err)
	}
	if !got.Equal(otherBuilt) {
		t.Errorf("FileBuildTime = %s, want %s", got, otherBuilt)
	}

	// The published reader is untouched: same build time, still enabled, and
	// still answering lookups against the SERVING database's data (US, not
	// the DE record in the file we just read).
	if built, ok := BuildTime(); !ok || !built.Equal(servingBuilt) {
		t.Errorf("BuildTime() = (%s, %v) after reading another file, want (%s, true)", built, ok, servingBuilt)
	}
	if !Enabled() {
		t.Error("Enabled() went false after reading another file")
	}
	code, _ := LookupByIP(net.ParseIP(geoiptest.MatchedIP))
	if code != "US" {
		t.Errorf("lookup returned %q after reading a DE database off disk, want %q — the published reader was replaced", code, "US")
	}
}

func TestFileBuildTimeRefusesWhatItCannotRead(t *testing.T) {
	dir := t.TempDir()
	notMMDB := filepath.Join(dir, "garbage.mmdb")
	if err := os.WriteFile(notMMDB, []byte("this is not a MaxMind database"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, path string }{
		{"empty path", ""},
		{"missing file", filepath.Join(dir, "absent.mmdb")},
		{"not a .mmdb", notMMDB},
		{"a directory", dir},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FileBuildTime(tc.path)
			if err == nil {
				t.Fatalf("FileBuildTime(%q) = (%s, nil), want an error", tc.path, got)
			}
			if !got.IsZero() {
				t.Errorf("FileBuildTime returned %s alongside an error, want the zero time", got)
			}
		})
	}
}
