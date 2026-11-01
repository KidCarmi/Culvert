package main

// admin_settings_corruption_test.go — a present-but-corrupt admin_settings.json used
// to log-and-continue, and the NEXT SaveAdminSettings (any admin mutation) then
// atomically OVERWROTE it with a defaults-only snapshot — destroying every GUI-saved
// admin setting with one log line as the trace. These pin the fix: route the load
// through the CHAOS-05/07 quarantine-don't-overwrite mechanism shared with
// ui_users.json / cluster.json (alert + /readyz row + preserved evidence).

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadAdminSettings_CorruptFileQuarantinedNotOverwritten proves a corrupt settings
// file is moved aside (so a later save can't clobber it), fires the state_file_corrupt
// alert, and records a /readyz fail row.
func TestLoadAdminSettings_CorruptFileQuarantinedNotOverwritten(t *testing.T) {
	captured := captureStartupAlerts(t)
	isolateStateCorruption(t)
	isolateRewriterForTest(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "admin_settings.json")
	corrupt := []byte(`{"default_action":"deny","rate_limit_rpm":42,`) // truncated mid-object
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}

	swapAdminSettingsPath(t, path) // restore the global path after the test
	LoadAdminSettings(path)

	// The corrupt file must be MOVED, not left where the next save lands.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("corrupt file still present at %s — the next SaveAdminSettings would overwrite the only copy", path)
	}
	qfiles := quarantinedFiles(t, path)
	if len(qfiles) != 1 {
		t.Fatalf("want exactly 1 quarantine file, got %v", qfiles)
	}
	if got, _ := os.ReadFile(qfiles[0]); !bytes.Equal(got, corrupt) {
		t.Fatal("quarantine content differs from the original corrupt bytes")
	}

	// The exact pre-fix destruction scenario: an admin mutation saves a fresh
	// defaults snapshot afterwards. The evidence must survive byte-identical.
	if err := SaveAdminSettings(); err != nil {
		t.Fatalf("save after quarantine: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fresh settings not written after quarantine: %v", err)
	}
	if after, _ := os.ReadFile(qfiles[0]); !bytes.Equal(after, corrupt) {
		t.Fatal("post-quarantine save destroyed the quarantined evidence")
	}

	// Alert is queued until the webhook store loads, then fires once.
	if len(*captured) != 0 {
		t.Fatalf("alert fired before webhook store loaded (got %d)", len(*captured))
	}
	flushStartupAlerts()
	if len(*captured) != 1 || (*captured)[0].event != "state_file_corrupt" || (*captured)[0].payload.Source != "storage" {
		t.Fatalf("want 1 state_file_corrupt/storage alert, got %+v", *captured)
	}
	if _, ok := stateCorruptionSnapshot()["admin_settings"]; !ok {
		t.Fatal("admin_settings corruption not recorded for /readyz")
	}
}

// TestLoadAdminSettings_MissingFile_NoQuarantineNoAlert — a missing file is first-run,
// not corruption: silent, no quarantine, no alert, no /readyz row.
func TestLoadAdminSettings_MissingFile_NoQuarantineNoAlert(t *testing.T) {
	captured := captureStartupAlerts(t)
	isolateStateCorruption(t)

	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	swapAdminSettingsPath(t, path)
	LoadAdminSettings(path)

	flushStartupAlerts()
	if len(*captured) != 0 {
		t.Fatalf("missing file fired %d alerts, want 0 (first run is not corruption)", len(*captured))
	}
	if snap := stateCorruptionSnapshot(); len(snap) != 0 {
		t.Fatalf("missing file recorded corruption: %v", snap)
	}
}

// TestLoadAdminSettings_ResidualQuarantineResurfacedAcrossRestart proves the CHAOS-05
// cross-restart guarantee for admin_settings: after a corrupt load the node writes a
// fresh clean file, so on the next boot the current file parses — but the unreconciled
// .corrupt.* sibling must still re-surface the alert + /readyz row until repaired.
func TestLoadAdminSettings_ResidualQuarantineResurfacedAcrossRestart(t *testing.T) {
	isolateRewriterForTest(t)
	captured := captureStartupAlerts(t)
	isolateStateCorruption(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "admin_settings.json")
	// A prior-boot quarantine sibling + a now-clean ({} ⇒ no field mutations) current file.
	if err := os.WriteFile(path+".corrupt.123456789", []byte("old corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	swapAdminSettingsPath(t, path)
	LoadAdminSettings(path)

	flushStartupAlerts()
	if len(*captured) != 1 || (*captured)[0].event != "state_file_corrupt" {
		t.Fatalf("residual quarantine did not re-surface: %+v", *captured)
	}
	if _, ok := stateCorruptionSnapshot()["admin_settings"]; !ok {
		t.Fatal("residual admin_settings quarantine not recorded for /readyz")
	}
}

// isolateRewriterForTest gives the test an EMPTY global rewriter and restores
// the predecessor's rules afterwards. LoadAdminSettings finalizes the
// YAML-seeded rewrite identities on every load path — after a quarantine it
// deliberately writes a fresh minimal ledger at the settings path whenever
// rules are live — so an assertion about the settings file's absence holds
// only against a rewriter this test owns (PR-C7 order dependency, pinned by
// test_order_isolation_red_test.go).
func isolateRewriterForTest(t *testing.T) {
	t.Helper()
	t.Cleanup(rewriter.Snapshot())
	publishRewriteRules(nil)
}

// TestLoadAdminSettings_UnreadableFileSurfacedNotQuarantined pins the operator
// signal for an EXISTING but unreadable settings file (EACCES/EIO): it used to
// be log-only. The file must stay untouched, the authenticated diagnostics row
// must name the condition, and /ready's row set must not change.
func TestLoadAdminSettings_UnreadableFileSurfacedNotQuarantined(t *testing.T) {
	captured := captureStartupAlerts(t)
	isolateStateCorruption(t)
	isolateRewriterForTest(t)

	// A directory at the settings path makes os.ReadFile fail with a
	// non-IsNotExist error even when the test runs as root.
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	swapAdminSettingsPath(t, path)
	LoadAdminSettings(path)

	if len(quarantinedFiles(t, path)) != 0 {
		t.Fatal("an unreadable (not corrupt) file must never be quarantined")
	}
	rows := checkStateFileIntegrity()
	if len(rows) != 1 || rows[0].Code != "state_file_admin_settings" || rows[0].Status != diagFail ||
		!strings.Contains(rows[0].Message, "could not be read") {
		t.Fatalf("want one failing 'could not be read' row, got %+v", rows)
	}
	if strings.Contains(rows[0].Message+rows[0].OperatorAction, path) {
		t.Fatal("viewer-role diagnostics row must stay path-free")
	}
	if len(stateCorruptionSnapshot()) != 0 {
		t.Fatal("/ready state_file rows must be unchanged by a read failure")
	}
	if len(*captured) != 0 {
		t.Fatalf("alert must be queued until the webhook store loads, got %d", len(*captured))
	}
}
