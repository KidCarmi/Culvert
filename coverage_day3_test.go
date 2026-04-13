package main

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── buildMovedPriorities ────────────────────────────────────────────────────

func TestBuildMovedPriorities_First(t *testing.T) {
	rules := []PolicyRule{
		{Priority: 1, Name: "A"},
		{Priority: 2, Name: "B"},
		{Priority: 3, Name: "C"},
	}
	got, err := buildMovedPriorities(rules, 3, "first", "")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{3, 1, 2}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pos %d: got %d, want %d", i, got[i], want[i])
		}
	}
}

func TestBuildMovedPriorities_Last(t *testing.T) {
	rules := []PolicyRule{
		{Priority: 1, Name: "A"},
		{Priority: 2, Name: "B"},
		{Priority: 3, Name: "C"},
	}
	got, err := buildMovedPriorities(rules, 1, "last", "")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{2, 3, 1}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pos %d: got %d, want %d", i, got[i], want[i])
		}
	}
}

func TestBuildMovedPriorities_Before(t *testing.T) {
	rules := []PolicyRule{
		{Priority: 1, Name: "A"},
		{Priority: 2, Name: "B"},
		{Priority: 3, Name: "C"},
	}
	got, err := buildMovedPriorities(rules, 3, "before", "B")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{1, 3, 2}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pos %d: got %d, want %d", i, got[i], want[i])
		}
	}
}

func TestBuildMovedPriorities_After(t *testing.T) {
	rules := []PolicyRule{
		{Priority: 1, Name: "A"},
		{Priority: 2, Name: "B"},
		{Priority: 3, Name: "C"},
	}
	got, err := buildMovedPriorities(rules, 1, "after", "B")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{2, 1, 3}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pos %d: got %d, want %d", i, got[i], want[i])
		}
	}
}

func TestBuildMovedPriorities_RuleNotFound(t *testing.T) {
	rules := []PolicyRule{{Priority: 1, Name: "A"}}
	_, err := buildMovedPriorities(rules, 99, "first", "")
	if err == nil {
		t.Error("expected error for nonexistent rule")
	}
}

func TestBuildMovedPriorities_TargetNotFound(t *testing.T) {
	rules := []PolicyRule{
		{Priority: 1, Name: "A"},
		{Priority: 2, Name: "B"},
	}
	_, err := buildMovedPriorities(rules, 1, "before", "NonExistent")
	if err == nil {
		t.Error("expected error for nonexistent target")
	}
}

func TestBuildMovedPriorities_SingleRule(t *testing.T) {
	rules := []PolicyRule{{Priority: 1, Name: "A"}}
	got, err := buildMovedPriorities(rules, 1, "first", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != 1 {
		t.Errorf("got %v, want [1]", got)
	}
}

// ── findRuleIdxByName ───────────────────────────────────────────────────────

func TestFindRuleIdxByName_Found(t *testing.T) {
	rules := []PolicyRule{
		{Priority: 1, Name: "Alpha"},
		{Priority: 2, Name: "Beta"},
		{Priority: 3, Name: "Gamma"},
	}
	priorities := []int{1, 2, 3}
	idx := findRuleIdxByName(rules, priorities, "Beta")
	if idx != 1 {
		t.Errorf("got %d, want 1", idx)
	}
}

func TestFindRuleIdxByName_CaseInsensitive(t *testing.T) {
	rules := []PolicyRule{{Priority: 1, Name: "MyRule"}}
	priorities := []int{1}
	idx := findRuleIdxByName(rules, priorities, "myrule")
	if idx != 0 {
		t.Errorf("got %d, want 0 (case-insensitive)", idx)
	}
}

func TestFindRuleIdxByName_NotFound(t *testing.T) {
	rules := []PolicyRule{{Priority: 1, Name: "Alpha"}}
	priorities := []int{1}
	idx := findRuleIdxByName(rules, priorities, "NonExistent")
	if idx != -1 {
		t.Errorf("got %d, want -1", idx)
	}
}

// ── extractCDFilename ───────────────────────────────────────────────────────

func TestExtractCDFilename(t *testing.T) {
	tests := []struct {
		cd   string
		want string
	}{
		{`attachment; filename="setup.exe"`, "setup.exe"},
		{`attachment; filename="report.pdf"`, "report.pdf"},
		{`inline`, ""},
		{"", ""},
		{`attachment; filename*=UTF-8''eXeScope_Setup.exe`, "eXeScope_Setup.exe"},
	}
	for _, tt := range tests {
		got := extractCDFilename(tt.cd)
		if got != tt.want {
			t.Errorf("extractCDFilename(%q) = %q, want %q", tt.cd, got, tt.want)
		}
	}
}

// ── cspNonce ────────────────────────────────────────────────────────────────

func TestCspNonce_Length(t *testing.T) {
	nonce := cspNonce()
	if len(nonce) != 32 {
		t.Errorf("nonce length = %d, want 32 (16 bytes hex)", len(nonce))
	}
}

func TestCspNonce_Unique(t *testing.T) {
	a := cspNonce()
	b := cspNonce()
	if a == b {
		t.Error("two consecutive nonces should not be identical")
	}
}

func TestCspNonce_HexOnly(t *testing.T) {
	nonce := cspNonce()
	for _, c := range nonce {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Errorf("nonce contains non-hex char %q: %s", c, nonce)
			break
		}
	}
}

// ── FileBlocker.SetPath ─────────────────────────────────────────────────────

func TestFileBlocker_SetPath_PersistAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fileblock.json")

	fb1 := &FileBlocker{extensions: map[string]bool{}}
	fb1.Add(".exe")
	fb1.Add(".dll")
	fb1.SetPath(path) // saves current state

	// Verify file was written (Add after SetPath triggers save on next Add)
	fb1.Add(".bat") // triggers save with all 3

	// Create a new FileBlocker and load from the same file.
	fb2 := &FileBlocker{extensions: map[string]bool{}}
	fb2.SetPath(path)
	if fb2.Count() != 3 {
		t.Errorf("reloaded count = %d, want 3", fb2.Count())
	}
	if fb2.CheckPath("/file.exe") == "" {
		t.Error("expected .exe to be blocked after reload")
	}
	if fb2.CheckPath("/file.dll") == "" {
		t.Error("expected .dll to be blocked after reload")
	}
}

func TestFileBlocker_SetPath_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fileblock.json")
	os.WriteFile(path, []byte("[]"), 0o600) //nolint:errcheck

	fb := &FileBlocker{extensions: map[string]bool{".default": true}}
	fb.SetPath(path) // load empty file → clears defaults
	if fb.Count() != 0 {
		t.Errorf("expected 0 after loading empty JSON array, got %d", fb.Count())
	}
}

// ── decompressForScan — zstd path (gzip/identity/unknown already tested in scanner_test.go)

func TestDecompressForScan_ZstdFallback(t *testing.T) {
	// Invalid zstd data should return raw bytes (graceful fallback).
	data := []byte("not valid zstd data at all")
	result := decompressForScan(data, "zstd")
	if !bytes.Equal(result, data) {
		t.Errorf("invalid zstd should return raw data, got %q", string(result))
	}
}

// ── OTLPSpanExporter Configure/Stop/Enabled ─────────────────────────────────

func TestOTLPSpanExporter_ConfigureAndStop(t *testing.T) {
	e := &OTLPSpanExporter{
		interval: 100 * time.Millisecond,
		client:   &http.Client{Timeout: 5 * time.Second},
		buf:      make([]SpanRecord, spanBufferCap),
	}

	if e.Enabled() {
		t.Error("should not be enabled before Configure")
	}

	e.Configure("http://localhost:4318", nil)
	if !e.Enabled() {
		t.Error("should be enabled after Configure")
	}

	e.Stop()
	if e.Enabled() {
		t.Error("should not be enabled after Stop")
	}
}

func TestOTLPSpanExporter_ConfigureEmpty(t *testing.T) {
	e := &OTLPSpanExporter{
		interval: 100 * time.Millisecond,
		client:   &http.Client{Timeout: 5 * time.Second},
		buf:      make([]SpanRecord, spanBufferCap),
	}
	e.Configure("", nil)
	if e.Enabled() {
		t.Error("empty endpoint should not enable")
	}
}

// ── policyMeta persistence ──────────────────────────────────────────────────

func TestPolicyMeta_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	os.WriteFile(path, []byte("[]"), 0o600) //nolint:errcheck

	ps := &PolicyStore{}
	ps.Load(path) //nolint:errcheck
	ps.mu.Lock()
	ps.version = 42
	ps.updatedAt = "2026-01-01T00:00:00Z"
	ps.mu.Unlock()
	ps.saveMeta()

	// Reload and verify version survived.
	ps2 := &PolicyStore{}
	ps2.path = path
	ps2.loadMeta()
	ps2.mu.RLock()
	if ps2.version != 42 {
		t.Errorf("version = %d, want 42", ps2.version)
	}
	if ps2.updatedAt != "2026-01-01T00:00:00Z" {
		t.Errorf("updatedAt = %q, want 2026-01-01T00:00:00Z", ps2.updatedAt)
	}
	ps2.mu.RUnlock()
}
