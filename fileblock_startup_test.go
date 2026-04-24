package main

// fileblock_startup_test.go — PR3 follow-up pilot test coverage.
//
// Exercises resolveFileBlockStartupConfig (audit point) and loadFileBlocking
// error + happy paths. Each test snapshots and restores fileBlocker +
// globalProfileStore so the qa-determinism gate stays green regardless of
// shuffle order.

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ── helpers ────────────────────────────────────────────────────────────────

// fileblockStartupLoggerMu guards tests that touch the package-global
// logger. Reused across tests in this file only.
var fileblockStartupLoggerMu sync.Mutex

// ensureFileblockTestLogger installs a minimal log.Logger on the package
// global when one is not already present so loadFileBlocking's Printf
// calls do not nil-panic when the test runs in isolation.
func ensureFileblockTestLogger(t *testing.T) {
	t.Helper()
	fileblockStartupLoggerMu.Lock()
	defer fileblockStartupLoggerMu.Unlock()
	if logger == nil {
		logger = log.New(os.Stderr, "[test] ", 0)
	}
}

// resetFileBlockingStores replaces fileBlocker and globalProfileStore with
// fresh empty instances for the duration of the test and restores the
// originals on cleanup. Each also gets a freshly-allocated map / nil path
// so the test starts from a known state.
func resetFileBlockingStores(t *testing.T) {
	t.Helper()
	origBlocker := fileBlocker
	origProfiles := globalProfileStore
	fileBlocker = &FileBlocker{extensions: map[string]bool{}}
	globalProfileStore = &FileProfileStore{}
	t.Cleanup(func() {
		fileBlocker = origBlocker
		globalProfileStore = origProfiles
	})
}

// withTempDataDir swaps the dataDir package global to t.TempDir() so
// fileBlocker.SetPath writes end up in an isolated directory. Restored on
// cleanup.
func withTempDataDir(t *testing.T) string {
	t.Helper()
	orig := dataDir
	tmp := t.TempDir()
	dataDir = tmp
	t.Cleanup(func() { dataDir = orig })
	return tmp
}

// ── resolveFileBlockStartupConfig ─────────────────────────────────────────

// CLI flag override beats FileConfig value.
func TestResolveFileBlockStartupConfig_CLIWinsOverFileConfig(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.FileProfilesFile = "/etc/culvert/fileprofiles.json"
	fc.FileBlock.Extensions = []string{".exe", ".dll"}

	got := resolveFileBlockStartupConfig(fc, "/override/fileprofiles.json")

	if got.ProfilesPath != "/override/fileprofiles.json" {
		t.Errorf("CLI flag should win: got %q", got.ProfilesPath)
	}
	if len(got.Extensions) != 2 || got.Extensions[0] != ".exe" {
		t.Errorf("Extensions mismapped: got %v", got.Extensions)
	}
}

// With no CLI override and no FileConfig path, the resolver falls back to
// the default filename.
func TestResolveFileBlockStartupConfig_DefaultPath(t *testing.T) {
	got := resolveFileBlockStartupConfig(&FileConfig{}, "")
	if got.ProfilesPath != "fileprofiles.json" {
		t.Errorf("expected default 'fileprofiles.json', got %q", got.ProfilesPath)
	}
	if len(got.Extensions) != 0 {
		t.Errorf("empty FileConfig should yield empty Extensions, got %v", got.Extensions)
	}
}

// FileConfig path is used when CLI flag is empty.
func TestResolveFileBlockStartupConfig_FileConfigPathUsedWhenNoCLI(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.FileProfilesFile = "/from/config.json"
	got := resolveFileBlockStartupConfig(fc, "")
	if got.ProfilesPath != "/from/config.json" {
		t.Errorf("expected FileConfig path, got %q", got.ProfilesPath)
	}
}

// ── loadFileBlocking happy + error paths ──────────────────────────────────

// Happy path with explicit extensions: fileBlocker should end up populated
// from cfg.Extensions. A missing profile store file is NOT an error —
// FileProfileStore.Load treats first-run as a seed+persist of built-ins.
func TestLoadFileBlocking_ExplicitExtensions(t *testing.T) {
	resetFileBlockingStores(t)
	ensureFileblockTestLogger(t)
	withTempDataDir(t)

	dir := t.TempDir()
	cfg := fileBlockStartupConfig{
		Extensions:   []string{".exe", ".dll"},
		ProfilesPath: filepath.Join(dir, "fileprofiles.json"),
	}
	if err := loadFileBlocking(cfg); err != nil {
		t.Fatalf("loadFileBlocking: %v", err)
	}
	if got := fileBlocker.Count(); got != 2 {
		t.Errorf("fileBlocker.Count = %d, want 2", got)
	}
}

// With empty cfg.Extensions, loader seeds from defaultBlockedExts. Regression
// guard — this is the in-container default behaviour operators rely on.
func TestLoadFileBlocking_SeedsFromDefaultsWhenEmpty(t *testing.T) {
	resetFileBlockingStores(t)
	ensureFileblockTestLogger(t)
	withTempDataDir(t)

	cfg := fileBlockStartupConfig{
		Extensions:   nil,
		ProfilesPath: filepath.Join(t.TempDir(), "fileprofiles.json"),
	}
	_ = loadFileBlocking(cfg)
	if got := fileBlocker.Count(); got != len(defaultBlockedExts) {
		t.Errorf("fileBlocker.Count = %d, want %d (defaultBlockedExts)", got, len(defaultBlockedExts))
	}
}

// Happy path: a valid profile store file exists and loads without error.
func TestLoadFileBlocking_ProfilesFileLoads(t *testing.T) {
	resetFileBlockingStores(t)
	ensureFileblockTestLogger(t)
	withTempDataDir(t)

	dir := t.TempDir()
	profilesPath := filepath.Join(dir, "fileprofiles.json")
	// Empty JSON array is the simplest valid payload for the profile store.
	if err := os.WriteFile(profilesPath, []byte("[]"), 0o600); err != nil {
		t.Fatalf("write profiles file: %v", err)
	}

	cfg := fileBlockStartupConfig{
		Extensions:   []string{".exe"},
		ProfilesPath: profilesPath,
	}
	if err := loadFileBlocking(cfg); err != nil {
		t.Fatalf("loadFileBlocking: %v", err)
	}
}

// SetPath overrides the in-memory seed with the on-disk list when a
// persisted file exists. Locks in the "UI changes survive restart" semantic.
func TestLoadFileBlocking_SetPathOverridesSeed(t *testing.T) {
	resetFileBlockingStores(t)
	ensureFileblockTestLogger(t)
	dataDirTmp := withTempDataDir(t)

	// Write a pre-existing fileblock.json with a single ".custom" entry.
	blockerPath := filepath.Join(dataDirTmp, "fileblock.json")
	if err := os.WriteFile(blockerPath, []byte(`[".custom"]`), 0o600); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}

	cfg := fileBlockStartupConfig{
		// Seed from different extensions — SetPath should replace them
		// with the on-disk [".custom"] content.
		Extensions:   []string{".exe", ".dll"},
		ProfilesPath: filepath.Join(t.TempDir(), "fileprofiles.json"),
	}
	_ = loadFileBlocking(cfg)

	if got := fileBlocker.Count(); got != 1 {
		t.Errorf("fileBlocker.Count after SetPath = %d, want 1 (.custom from disk)", got)
	}
}

// Loader wraps the profile-store error with a clear namespace so operators
// can distinguish it from other startup warnings in the log.
func TestLoadFileBlocking_ProfilesErrorIsWrapped(t *testing.T) {
	resetFileBlockingStores(t)
	ensureFileblockTestLogger(t)
	withTempDataDir(t)

	// Write a malformed profiles file so globalProfileStore.Load errors.
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write bad file: %v", err)
	}

	cfg := fileBlockStartupConfig{ProfilesPath: bad}
	err := loadFileBlocking(cfg)
	if err == nil {
		t.Fatal("expected wrapped error for malformed profiles file")
	}
	// Wrapping contract: the error must mention 'profile store' so
	// the init shim's Printf message is namespaced for operators.
	if msg := err.Error(); !strings.Contains(msg, "profile store") {
		t.Errorf("error namespace lost: %q", msg)
	}
}
