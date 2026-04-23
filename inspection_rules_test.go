package main

// inspection_rules_test.go — PR3 pilot test coverage.
//
// Exercises resolveInspectionRulesConfig (audit point) and
// loadInspectionRules error paths. Happy paths are covered indirectly by
// the existing startup integration tests that already exercise sslBypass
// and dpiScanner.
//
// Every test snapshots and restores sslBypass and dpiScanner so the
// qa-determinism gate stays green regardless of shuffle order.

import (
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// ── helpers ────────────────────────────────────────────────────────────────

// resetInspectionStores replaces sslBypass and dpiScanner with fresh empty
// instances for the duration of the test and restores the originals on
// cleanup. Isolates tests from each other AND from sibling tests in other
// files that mutate the same globals.
func resetInspectionStores(t *testing.T) {
	t.Helper()
	origBypass := sslBypass
	origScanner := dpiScanner
	sslBypass = &SSLBypassMatcher{}
	dpiScanner = &ContentScanner{}
	t.Cleanup(func() {
		sslBypass = origBypass
		dpiScanner = origScanner
	})
}

// serializedTest guards tests that flip logger + stores in ways that
// might race under -shuffle. The mutex is unexported so callers in this
// file share it.
var inspectionRulesLoggerMu sync.Mutex

// ensureTestLogger installs a minimal log.Logger on the package global
// when one is not already present, so loadInspectionRules' Printf calls
// do not nil-panic when the test runs in isolation.
func ensureTestLogger(t *testing.T) {
	t.Helper()
	inspectionRulesLoggerMu.Lock()
	defer inspectionRulesLoggerMu.Unlock()
	if logger == nil {
		logger = log.New(os.Stderr, "[test] ", 0)
	}
}

// ── resolveInspectionRulesConfig ──────────────────────────────────────────

// The resolver is the single audit point between FileConfig and the
// inspection-rules loader. This test locks in the exact field mapping so
// any future FileConfig schema change either preserves it or flips here.
func TestResolveInspectionRulesConfig_FieldMapping(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.SSLBypassFile = "/etc/culvert/ssl_bypass.json"
	fc.Proxy.SSLBypassPatterns = []string{"*.example.com", "internal.corp"}
	fc.Proxy.ContentScanFile = "/etc/culvert/content_scan.json"
	fc.Proxy.ContentScanPatterns = []string{"SECRET", `password=\w+`}

	got := resolveInspectionRulesConfig(fc)

	if got.SSLBypassFile != fc.Proxy.SSLBypassFile {
		t.Errorf("SSLBypassFile mismapped: got %q, want %q", got.SSLBypassFile, fc.Proxy.SSLBypassFile)
	}
	if len(got.SSLBypassPatterns) != 2 || got.SSLBypassPatterns[0] != "*.example.com" {
		t.Errorf("SSLBypassPatterns mismapped: got %v", got.SSLBypassPatterns)
	}
	if got.ContentScanFile != fc.Proxy.ContentScanFile {
		t.Errorf("ContentScanFile mismapped: got %q, want %q", got.ContentScanFile, fc.Proxy.ContentScanFile)
	}
	if len(got.ContentScanPatterns) != 2 || got.ContentScanPatterns[1] != `password=\w+` {
		t.Errorf("ContentScanPatterns mismapped: got %v", got.ContentScanPatterns)
	}
}

func TestResolveInspectionRulesConfig_EmptyFileConfig(t *testing.T) {
	got := resolveInspectionRulesConfig(&FileConfig{})
	if got.SSLBypassFile != "" || got.ContentScanFile != "" ||
		len(got.SSLBypassPatterns) != 0 || len(got.ContentScanPatterns) != 0 {
		t.Errorf("empty FileConfig should yield zero-value inspectionRulesConfig, got %+v", got)
	}
}

// ── loadInspectionRules error paths ───────────────────────────────────────

// A zero-value config must load cleanly. Regression guard for the
// "--skip-these-init-steps" path real deployments use.
func TestLoadInspectionRules_ZeroValueIsNoop(t *testing.T) {
	resetInspectionStores(t)
	ensureTestLogger(t)
	if err := loadInspectionRules(inspectionRulesConfig{}); err != nil {
		t.Fatalf("zero config should not error: %v", err)
	}
}

// An unreadable SSLBypassFile must surface wrapped as "ssl bypass: ..." so
// main's Fatalf message identifies the failing domain.
func TestLoadInspectionRules_SSLBypassFileInvalid(t *testing.T) {
	resetInspectionStores(t)
	ensureTestLogger(t)

	// Write a file whose contents the matcher can't parse (Load expects a
	// JSON array of strings or an envelope object).
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write bad file: %v", err)
	}

	cfg := inspectionRulesConfig{SSLBypassFile: badPath}
	err := loadInspectionRules(cfg)
	if err == nil {
		t.Fatal("expected error for malformed SSLBypassFile")
	}
	if !strings.HasPrefix(err.Error(), "ssl bypass:") {
		t.Errorf("error should be namespaced 'ssl bypass:', got %q", err.Error())
	}
}

// Same shape for ContentScanFile. Confirms each sub-loader's error wrap
// reaches the caller independently.
func TestLoadInspectionRules_ContentScanFileInvalid(t *testing.T) {
	resetInspectionStores(t)
	ensureTestLogger(t)

	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write bad file: %v", err)
	}

	cfg := inspectionRulesConfig{ContentScanFile: badPath}
	err := loadInspectionRules(cfg)
	if err == nil {
		t.Fatal("expected error for malformed ContentScanFile")
	}
	if !strings.HasPrefix(err.Error(), "dpi scanner:") {
		t.Errorf("error should be namespaced 'dpi scanner:', got %q", err.Error())
	}
}

// An invalid regex pattern in ContentScanPatterns must surface as a seed
// error without leaving the scanner in a half-configured state.
func TestLoadInspectionRules_InvalidDPIRegex(t *testing.T) {
	resetInspectionStores(t)
	ensureTestLogger(t)

	cfg := inspectionRulesConfig{
		ContentScanPatterns: []string{"[invalid regex"},
	}
	err := loadInspectionRules(cfg)
	if err == nil {
		t.Fatal("expected error for invalid DPI regex")
	}
	if !strings.HasPrefix(err.Error(), "dpi scanner:") {
		t.Errorf("error namespacing lost: %q", err.Error())
	}
}

// Seed-on-first-run: when the file exists but is empty, SSLBypassPatterns
// must be written through and readable from the matcher.
func TestLoadInspectionRules_SSLBypassSeedsEmptyFile(t *testing.T) {
	resetInspectionStores(t)
	ensureTestLogger(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "ssl_bypass.json")
	if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatalf("write empty json: %v", err)
	}

	cfg := inspectionRulesConfig{
		SSLBypassFile:     path,
		SSLBypassPatterns: []string{"seed.example.com"},
	}
	if err := loadInspectionRules(cfg); err != nil {
		t.Fatalf("loadInspectionRules: %v", err)
	}
	list := sslBypass.List()
	if len(list) != 1 || list[0] != "seed.example.com" {
		t.Errorf("seed patterns not applied, got %v", list)
	}
}

// In-memory-only mode: no file path, only patterns. Both stores must end
// up populated without any file I/O.
func TestLoadInspectionRules_InMemoryOnly(t *testing.T) {
	resetInspectionStores(t)
	ensureTestLogger(t)

	// Use a regex that the DPI pattern parser will accept.
	validDPI := regexp.MustCompile(`SECRET-\d+`).String()

	cfg := inspectionRulesConfig{
		SSLBypassPatterns:   []string{"memory-only.example"},
		ContentScanPatterns: []string{validDPI},
	}
	if err := loadInspectionRules(cfg); err != nil {
		t.Fatalf("in-memory load: %v", err)
	}
	if list := sslBypass.List(); len(list) != 1 {
		t.Errorf("sslBypass in-memory seeding failed: %v", list)
	}
	if list := dpiScanner.List(); len(list) != 1 {
		t.Errorf("dpiScanner in-memory seeding failed: %v", list)
	}
}

