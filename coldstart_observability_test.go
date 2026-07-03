package main

// D1.1h log-only observability tests.
//
// Each test runs an existing loader against a curated bad-state fixture
// and asserts that the expected `Loader:` warning fires while the
// loader's documented behavior remains unchanged. Behavior assertions
// are intentionally minimal here — D1.2a/D1.2b already pin the full
// behavior matrix; this file only covers the new log lines.

import (
	"bytes"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/blocklist"
)

// captureLogger swaps the package-level logger to a buffer for the
// duration of fn, restores via t.Cleanup, and returns the captured
// output. Tests must not run in parallel (default behavior); the
// global is shared across the binary.
func captureLogger(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	orig := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = orig })
	fn()
	return buf.String()
}

// ─── F1 ─────────────────────────────────────────────────────────────

func TestObservability_F1_UIUsers_MissingFile(t *testing.T) {
	dir := t.TempDir()
	c, _ := newTestUIUsersConfig(t, dir)

	out := captureLogger(t, func() {
		if err := c.LoadUIUsersFile(); err != nil {
			t.Fatalf("LoadUIUsersFile: %v", err)
		}
	})

	if !strings.Contains(out, "Loader: ui_users.json: file") ||
		!strings.Contains(out, "missing") ||
		!strings.Contains(out, "D1.2-flag-F1") {
		t.Errorf("expected F1 warning in log, got: %q", out)
	}
}

// ─── F2 ─────────────────────────────────────────────────────────────

func TestObservability_F2_CABundle_PlainPEMWithPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.bundle")

	cm := makeInitedCertManager(t)
	if err := cm.SaveCA(path, ""); err != nil {
		t.Fatalf("SaveCA plain: %v", err)
	}

	out := captureLogger(t, func() {
		cm2 := &CertManager{cache: map[string]*certCacheEntry{}}
		if err := cm2.LoadCA(path, "operator-set-this-later"); err != nil {
			t.Fatalf("LoadCA: %v", err)
		}
	})

	if !strings.Contains(out, "Loader: ca.bundle: plain PEM accepted while passphrase is set") ||
		!strings.Contains(out, "D1.2-flag-F2") {
		t.Errorf("expected F2 warning in log, got: %q", out)
	}
}

// ─── F3 ─────────────────────────────────────────────────────────────

func TestObservability_F3_BlocklistMode_UnrecognizedValue(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, "blocklist.txt")
	if err := os.WriteFile(primary, []byte{}, 0o600); err != nil {
		t.Fatalf("write primary: %v", err)
	}
	if err := os.WriteFile(primary+".mode", []byte("BLOCK"), 0o600); err != nil {
		t.Fatalf("write .mode: %v", err)
	}

	out := captureLogger(t, func() {
		b := blocklist.New()
		if err := b.Load(primary); err != nil {
			t.Fatalf("Load: %v", err)
		}
	})

	if !strings.Contains(out, "Loader: blocklist.mode: unrecognized value") ||
		!strings.Contains(out, "D1.2-flag-F3") {
		t.Errorf("expected F3 warning in log, got: %q", out)
	}
}

// ─── F4 ─────────────────────────────────────────────────────────────

func TestObservability_F4_BlocklistManual_InvalidLine(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, "blocklist.txt")
	if err := os.WriteFile(primary, []byte{}, 0o600); err != nil {
		t.Fatalf("write primary: %v", err)
	}
	if err := os.WriteFile(primary+".manual", []byte("not a hostname\nfoo.example.com\n"), 0o600); err != nil {
		t.Fatalf("write .manual: %v", err)
	}

	out := captureLogger(t, func() {
		b := blocklist.New()
		if err := b.Load(primary); err != nil {
			t.Fatalf("Load: %v", err)
		}
	})

	if !strings.Contains(out, "Loader: blocklist.manual:") ||
		!strings.Contains(out, "does not look like a hostname") ||
		!strings.Contains(out, "D1.2-flag-F4") {
		t.Errorf("expected F4 warning in log, got: %q", out)
	}
}

func TestObservability_F4_BlocklistExceptions_InvalidLine(t *testing.T) {
	dir := t.TempDir()
	primary := filepath.Join(dir, "blocklist.txt")
	if err := os.WriteFile(primary, []byte{}, 0o600); err != nil {
		t.Fatalf("write primary: %v", err)
	}
	if err := os.WriteFile(primary+".exceptions", []byte("STRANGE INPUT\n"), 0o600); err != nil {
		t.Fatalf("write .exceptions: %v", err)
	}

	out := captureLogger(t, func() {
		b := blocklist.New()
		if err := b.Load(primary); err != nil {
			t.Fatalf("Load: %v", err)
		}
	})

	if !strings.Contains(out, "Loader: blocklist.exceptions:") ||
		!strings.Contains(out, "does not look like a hostname") ||
		!strings.Contains(out, "D1.2-flag-F4") {
		t.Errorf("expected F4 warning in log, got: %q", out)
	}
}

// ─── F5 ─────────────────────────────────────────────────────────────

func TestObservability_F5_ConfigVersions_SkippedFile(t *testing.T) {
	dir := t.TempDir()
	withTempConfigVersionsDir(t, dir)
	writeVersionFile(t, dir, 1, "this is not json")

	out := captureLogger(t, func() {
		w := httptest.NewRecorder()
		listConfigVersions(w)
	})

	if !strings.Contains(out, "Loader: config_versions: skipping") ||
		!strings.Contains(out, "D1.2-flag-F5") {
		t.Errorf("expected F5 warning in log, got: %q", out)
	}
}

// ─── F6 ─────────────────────────────────────────────────────────────

func TestObservability_F6_Bandwidth_MissingRequiredFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bandwidth.json")
	body := []byte(`[{"max_bytes_per_sec":4096}]`) // no name, no label_selector
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	out := captureLogger(t, func() {
		_ = NewBandwidthManager(path)
	})

	if !strings.Contains(out, "Loader: bandwidth.json: policy[0] missing required field") ||
		!strings.Contains(out, "D1.2-flag-F6") {
		t.Errorf("expected F6 warning in log, got: %q", out)
	}
}

func TestObservability_F6_NodeGroups_MissingRequiredFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node_groups.json")
	body := []byte(`[{"priority":3}]`) // no name, no label_selector
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	out := captureLogger(t, func() {
		_ = NewNodeGroupStore(path)
	})

	if !strings.Contains(out, "Loader: node_groups.json: group[0] missing required field") ||
		!strings.Contains(out, "D1.2-flag-F6") {
		t.Errorf("expected F6 warning in log, got: %q", out)
	}
}
