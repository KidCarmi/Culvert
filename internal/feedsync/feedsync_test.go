package feedsync

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/catdb"
)

// UT1 feed-syncer engine tests, moved in-package with the ADR-0002
// extraction. The syncer is driven against a real catdb.CommunityDB opened
// in a temp dir.

// ─── classifyTarEntry tests ───────────────────────────────────────────────────

func TestClassifyTarEntry(t *testing.T) {
	tests := []struct {
		path    string
		wantCat string
		wantOK  bool
	}{
		{"blacklists/adult/domains", "Adult", true},
		{"blacklists/malware/domains", "Malicious", true},
		{"blacklists/gambling/domains", "Gambling", true},
		{"blacklists/social_networks/domains", "Social Media", true},
		{"blacklists/streamingmedia/domains", "Streaming", true},
		{"blacklists/news/domains", "News", true},
		{"blacklists/games/domains", "Gaming", true},
		// Leading "./" should be stripped
		{"./blacklists/adult/domains", "Adult", true},
		// Backslash normalisation
		{"blacklists\\adult\\domains", "Adult", true},
		// Unknown category → skip
		{"blacklists/unknown_category/domains", "", false},
		// Wrong filename (not "domains")
		{"blacklists/adult/urls", "", false},
		// Too few parts
		{"blacklists/adult", "", false},
		// Too many parts
		{"blacklists/adult/domains/extra", "", false},
		// Empty path
		{"", "", false},
	}
	for _, tc := range tests {
		cat, ok := classifyTarEntry(tc.path)
		if ok != tc.wantOK || cat != tc.wantCat {
			t.Errorf("classifyTarEntry(%q) = (%q, %v), want (%q, %v)",
				tc.path, cat, ok, tc.wantCat, tc.wantOK)
		}
	}
}

// ─── parseDomainFile tests ────────────────────────────────────────────────────

func TestParseDomainFile_Basic(t *testing.T) {
	input := "facebook.com\ngoogle.com\n# comment\n\nbad_no_dot\nexample.org\n"
	out := make(map[string]string)
	if err := parseDomainFile(strings.NewReader(input), "Social Media", out); err != nil {
		t.Fatalf("parseDomainFile: %v", err)
	}
	expected := map[string]string{
		"facebook.com": "Social Media",
		"google.com":   "Social Media",
		"example.org":  "Social Media",
	}
	for k, v := range expected {
		if out[k] != v {
			t.Errorf("out[%q] = %q, want %q", k, out[k], v)
		}
	}
	// "bad_no_dot" and comments should be excluded
	if _, ok := out["bad_no_dot"]; ok {
		t.Error("bad_no_dot should be excluded (no dot)")
	}
}

func TestParseDomainFile_NoTrailingNewline(t *testing.T) {
	// Last line without trailing newline should still be parsed.
	input := "example.com\nlast.org"
	out := make(map[string]string)
	if err := parseDomainFile(strings.NewReader(input), "News", out); err != nil {
		t.Fatalf("parseDomainFile: %v", err)
	}
	if out["last.org"] != "News" {
		t.Errorf("last.org not found in output: %v", out)
	}
}

func TestParseDomainFile_CRLFLineEndings(t *testing.T) {
	input := "example.com\r\nexample.org\r\n"
	out := make(map[string]string)
	if err := parseDomainFile(strings.NewReader(input), "News", out); err != nil {
		t.Fatalf("parseDomainFile: %v", err)
	}
	if out["example.com"] != "News" || out["example.org"] != "News" {
		t.Errorf("CRLF entries not parsed: %v", out)
	}
}

func TestParseDomainFile_CaseNormalization(t *testing.T) {
	input := "FACEBOOK.COM\nGOOGLE.COM\n"
	out := make(map[string]string)
	if err := parseDomainFile(strings.NewReader(input), "Social Media", out); err != nil {
		t.Fatalf("parseDomainFile: %v", err)
	}
	if out["facebook.com"] != "Social Media" {
		t.Errorf("domain should be lowercased: %v", out)
	}
}

// ─── parseTarball tests ───────────────────────────────────────────────────────

func makeTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		hdr := &tar.Header{
			Name:     name,
			Typeflag: tar.TypeReg,
			Size:     int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar WriteHeader: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar Write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return buf.Bytes()
}

func TestParseTarball_Basic(t *testing.T) {
	tarData := makeTarGz(t, map[string]string{
		"blacklists/adult/domains":           "playboy.com\nnaughty.io\n",
		"blacklists/social_networks/domains": "facebook.com\ntwitter.com\n",
		"blacklists/unknown_cat/domains":     "skip.me\n",
	})

	entries, err := parseTarball(bytes.NewReader(tarData))
	if err != nil {
		t.Fatalf("parseTarball: %v", err)
	}
	if entries["playboy.com"] != "Adult" {
		t.Errorf("playboy.com not Adult: %q", entries["playboy.com"])
	}
	if entries["facebook.com"] != "Social Media" {
		t.Errorf("facebook.com not Social: %q", entries["facebook.com"])
	}
	if _, ok := entries["skip.me"]; ok {
		t.Error("unknown category should be skipped")
	}
}

func TestParseTarball_SkipsNonFileEntries(t *testing.T) {
	// Tarball with a directory entry — should not panic.
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	_ = tw.WriteHeader(&tar.Header{Name: "blacklists/adult/", Typeflag: tar.TypeDir})
	_ = tw.WriteHeader(&tar.Header{
		Name: "blacklists/adult/domains", Typeflag: tar.TypeReg,
		Size: int64(len("example.com\n")),
	})
	_, _ = tw.Write([]byte("example.com\n"))
	_ = tw.Close()
	_ = gw.Close()

	entries, err := parseTarball(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("parseTarball with dir entry: %v", err)
	}
	if entries["example.com"] != "Adult" {
		t.Errorf("example.com not Adult: %q", entries["example.com"])
	}
}

func TestParseTarball_BadGzip(t *testing.T) {
	_, err := parseTarball(strings.NewReader("not gzip data"))
	if err == nil {
		t.Error("parseTarball with bad gzip should return error")
	}
}

// ─── FeedSyncer constructor + Stats tests ────────────────────────────────────

func TestNewFeedSyncer_Defaults(t *testing.T) {
	dir := t.TempDir()
	db, err := catdb.Open(dir)
	if err != nil {
		t.Fatalf("openCommunityDB: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	// Empty URL and zero interval → defaults applied.
	fs := New(db, "", 0)
	if fs.feedURL != defaultUT1FeedURL {
		t.Errorf("feedURL = %q, want %q", fs.feedURL, defaultUT1FeedURL)
	}
	if fs.syncInterval != 24*time.Hour {
		t.Errorf("syncInterval = %v, want 24h", fs.syncInterval)
	}
}

func TestNewFeedSyncer_CustomValues(t *testing.T) {
	dir := t.TempDir()
	db, err := catdb.Open(dir)
	if err != nil {
		t.Fatalf("openCommunityDB: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	fs := New(db, "http://custom.example/feed.tar.gz", 6*time.Hour)
	if fs.feedURL != "http://custom.example/feed.tar.gz" {
		t.Errorf("feedURL = %q", fs.feedURL)
	}
	if fs.syncInterval != 6*time.Hour {
		t.Errorf("syncInterval = %v, want 6h", fs.syncInterval)
	}
}

func TestFeedSyncer_Stats_Initial(t *testing.T) {
	dir := t.TempDir()
	db, err := catdb.Open(dir)
	if err != nil {
		t.Fatalf("openCommunityDB: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	fs := New(db, "http://example.com/feed.tar.gz", time.Hour)
	domains, lastSync, interval := fs.Stats()
	if domains != 0 {
		t.Errorf("initial domains = %d, want 0", domains)
	}
	if !lastSync.IsZero() {
		t.Errorf("initial lastSync = %v, want zero", lastSync)
	}
	if interval != time.Hour {
		t.Errorf("interval = %v, want 1h", interval)
	}
}

// ─── downloadAndParse via httptest server ────────────────────────────────────

func TestDownloadAndParse_OK(t *testing.T) {
	tarData := makeTarGz(t, map[string]string{
		"blacklists/adult/domains": "playboy.com\nexample-adult.io\n",
		"blacklists/news/domains":  "bbc.com\ncnn.com\n",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(tarData)
	}))
	defer srv.Close()

	entries, err := downloadAndParse(srv.URL)
	if err != nil {
		t.Fatalf("downloadAndParse: %v", err)
	}
	if entries["playboy.com"] != "Adult" {
		t.Errorf("playboy.com = %q, want Adult", entries["playboy.com"])
	}
	if entries["bbc.com"] != "News" {
		t.Errorf("bbc.com = %q, want News", entries["bbc.com"])
	}
}

func TestDownloadAndParse_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := downloadAndParse(srv.URL)
	if err == nil {
		t.Error("downloadAndParse should return error on HTTP 500")
	}
}

func TestDownloadAndParse_BadBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not gzip at all"))
	}))
	defer srv.Close()

	_, err := downloadAndParse(srv.URL)
	if err == nil {
		t.Error("downloadAndParse should return error on non-gzip body")
	}
}

// ─── FeedSyncer.Sync via httptest server ─────────────────────────────────────

func TestFeedSyncer_Sync_OK(t *testing.T) {
	tarData := makeTarGz(t, map[string]string{
		"blacklists/gambling/domains": "casino.example.com\npoker.example.com\n",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(tarData)
	}))
	defer srv.Close()

	dir := t.TempDir()
	db, err := catdb.Open(dir)
	if err != nil {
		t.Fatalf("openCommunityDB: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	fs := New(db, srv.URL, time.Hour)
	fs.Sync()

	total, lastSync, _ := fs.Stats()
	if total == 0 {
		t.Error("Sync should have written domains; totalDomains == 0")
	}
	if lastSync.IsZero() {
		t.Error("lastSync should be set after successful Sync")
	}

	// Verify the data landed in the DB.
	cat, ok := db.Lookup("casino.example.com")
	if !ok || cat != "Gambling" {
		t.Errorf("casino.example.com = (%q, %v), want (Gambling, true)", cat, ok)
	}
}

func TestFeedSyncer_Sync_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	dir := t.TempDir()
	db, err := catdb.Open(dir)
	if err != nil {
		t.Fatalf("openCommunityDB: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	fs := New(db, srv.URL, time.Hour)
	// Sync should not panic on HTTP failure.
	fs.Sync()

	_, lastSync, _ := fs.Stats()
	if !lastSync.IsZero() {
		t.Error("lastSync should remain zero after failed Sync")
	}
}

// ─── FeedSyncer.Start context cancellation ───────────────────────────────────

func TestFeedSyncer_Start_CancelContext(t *testing.T) {
	// Non-empty DB so Start doesn't trigger an immediate Sync (avoids network call).
	dir := t.TempDir()
	db, err := catdb.Open(dir)
	if err != nil {
		t.Fatalf("openCommunityDB: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	// Pre-populate so Stats() > 0 → no immediate sync on Start.
	_ = db.BulkWrite(map[string]string{"seed.example.com": "News"})

	ctx, cancel := context.WithCancel(context.Background())
	fs := New(db, "http://invalid.example.invalid/feed.tar.gz", time.Hour)
	fs.Start(ctx)

	// Cancel immediately — goroutine should exit without panic.
	cancel()
	// Allow the goroutine time to observe cancellation.
	time.Sleep(20 * time.Millisecond)
}
