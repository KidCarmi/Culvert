package catdb

import (
	"strings"
	"testing"
)

func TestOpen_CreateAndClose(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestCommunityDB_BulkWrite_And_Lookup(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	entries := map[string]string{
		"facebook.com":  "Social Media",
		"malware.io":    "Malicious",
		"example.co.uk": "News",
	}
	if err := db.BulkWrite(entries); err != nil {
		t.Fatalf("BulkWrite: %v", err)
	}

	tests := []struct {
		host    string
		wantCat string
		wantHit bool
	}{
		{"facebook.com", "Social Media", true},
		{"malware.io", "Malicious", true},
		{"example.co.uk", "News", true},
		{"unknown.example.com", "", false},
	}
	for _, tc := range tests {
		cat, ok := db.Lookup(tc.host)
		if ok != tc.wantHit || cat != tc.wantCat {
			t.Errorf("Lookup(%q) = (%q, %v), want (%q, %v)",
				tc.host, cat, ok, tc.wantCat, tc.wantHit)
		}
	}
}

func TestCommunityDB_Lookup_DomainWalking(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	if err := db.BulkWrite(map[string]string{
		"facebook.com": "Social Media",
	}); err != nil {
		t.Fatalf("BulkWrite: %v", err)
	}

	// Subdomain should resolve to parent via domain walking.
	cat, ok := db.Lookup("sub.facebook.com")
	if !ok || cat != "Social Media" {
		t.Errorf("Lookup subdomain: got (%q, %v), want (Social, true)", cat, ok)
	}
}

func TestCommunityDB_Lookup_TrailingDot(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	if err := db.BulkWrite(map[string]string{"example.com": "News"}); err != nil {
		t.Fatalf("BulkWrite: %v", err)
	}

	// FQDN with trailing dot should still match (hostutil.NormalizeHost strips it).
	cat, ok := db.Lookup("example.com.")
	if !ok || cat != "News" {
		t.Errorf("Lookup trailing dot: got (%q, %v), want (News, true)", cat, ok)
	}
}

func TestCommunityDB_Lookup_StopsAtTLD(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	// "com" entry should NOT be reached by domain walking from "only.com".
	if err := db.BulkWrite(map[string]string{"com": "TLD"}); err != nil {
		t.Fatalf("BulkWrite: %v", err)
	}

	_, ok := db.Lookup("only.com")
	if ok {
		t.Error("Lookup should stop before bare TLD (com)")
	}
}

func TestCommunityDB_Stats(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	// Empty DB — Stats may return 0 or a small estimate.
	_ = db.Stats()

	entries := make(map[string]string, 10)
	for i := 0; i < 10; i++ {
		entries[strings.Repeat("x", i+2)+".com"] = "Test"
	}
	if err := db.BulkWrite(entries); err != nil {
		t.Fatalf("BulkWrite: %v", err)
	}

	// After write, stats should be non-negative.
	keys := db.Stats()
	if keys < 0 {
		t.Errorf("Stats returned negative key count: %d", keys)
	}
}

func TestCommunityDB_BulkWrite_Empty(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup
	if err := db.BulkWrite(map[string]string{}); err != nil {
		t.Errorf("BulkWrite empty map: %v", err)
	}
}
