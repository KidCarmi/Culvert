package main

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// ── decompressForScan tests (1.1 fix) ────────────────────────────────────────

func TestDecompressForScan_Identity(t *testing.T) {
	data := []byte("plain text content")
	got := decompressForScan(data, "")
	if !bytes.Equal(got, data) {
		t.Error("empty Content-Encoding should return data unchanged")
	}
	got = decompressForScan(data, "identity")
	if !bytes.Equal(got, data) {
		t.Error("identity encoding should return data unchanged")
	}
}

func TestDecompressForScan_Gzip(t *testing.T) {
	original := []byte("EICAR test content that should be decompressed for scanning")

	// Compress with gzip.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write(original) //nolint:errcheck
	gz.Close()
	compressed := buf.Bytes()

	// Verify compressed is different from original.
	if bytes.Equal(compressed, original) {
		t.Fatal("gzip compression produced identical output")
	}

	got := decompressForScan(compressed, "gzip")
	if !bytes.Equal(got, original) {
		t.Errorf("gzip decompression failed:\n  got:  %q\n  want: %q", got, original)
	}
}

func TestDecompressForScan_InvalidGzip(t *testing.T) {
	data := []byte("this is not gzip data")
	got := decompressForScan(data, "gzip")
	// Should fall back to returning raw bytes.
	if !bytes.Equal(got, data) {
		t.Error("invalid gzip should return raw data")
	}
}

func TestDecompressForScan_Brotli(t *testing.T) {
	data := []byte("brotli content")
	got := decompressForScan(data, "br")
	// Brotli not yet supported — should return raw data.
	if !bytes.Equal(got, data) {
		t.Error("brotli should return raw data (not yet supported)")
	}
}

func TestDecompressForScan_GzipBomb(t *testing.T) {
	// Create a gzip stream with a large uncompressed payload (>64MB).
	// decompressForScan should limit to maxDecompressBytes.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	// Write 65MB of zeros (compresses very well).
	chunk := make([]byte, 1<<20) // 1MB
	for i := 0; i < 65; i++ {
		gz.Write(chunk) //nolint:errcheck
	}
	gz.Close()

	got := decompressForScan(buf.Bytes(), "gzip")
	if len(got) > maxDecompressBytes {
		t.Errorf("gzip bomb protection failed: got %d bytes, max %d", len(got), maxDecompressBytes)
	}
}

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

// ── ScanBody timeout (F2/F3 fix) ──────────────────────────────────────────────

func TestScanBodyTimeout_FailClosed(t *testing.T) {
	// Verify the constant exists and is reasonable.
	if scanBodyTimeout <= 0 || scanBodyTimeout > 30*time.Second {
		t.Errorf("scanBodyTimeout = %s, want 0 < x <= 30s", scanBodyTimeout)
	}
}

// Q8: Test that DPI regex timeout returns true (fail-closed).
func TestMatchDPIRegexWithTimeout_Normal(t *testing.T) {
	re := regexp.MustCompile(`evil`)
	if !matchDPIRegexWithTimeout(re, []byte("this is evil"), time.Second) {
		t.Error("expected match")
	}
	if matchDPIRegexWithTimeout(re, []byte("this is fine"), time.Second) {
		t.Error("expected no match")
	}
}

func TestMatchDPIRegexWithTimeout_TimeoutReturnsTrue(t *testing.T) {
	// Use a pattern that's fast to compile but we force a tiny timeout.
	re := regexp.MustCompile(`^(a+)+$`)
	// With a near-zero timeout, the match should time out and return true (fail-closed).
	result := matchDPIRegexWithTimeout(re, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"), time.Nanosecond)
	if !result {
		t.Error("timeout should return true (fail-closed)")
	}
}
