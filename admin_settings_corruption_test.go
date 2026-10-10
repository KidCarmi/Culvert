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
	"testing"
)

// TestLoadAdminSettings_CorruptFileQuarantinedNotOverwritten proves a corrupt settings
// file is moved aside (so a later save can't clobber it), fires the state_file_corrupt
// alert, and records a /readyz fail row.
func TestLoadAdminSettings_CorruptFileQuarantinedNotOverwritten(t *testing.T) {
	resetUIAccessPolicyGlobals(t)
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

	// Unknown management policy must not be replaced by an open defaults
	// snapshot. Local repair is required; the quarantined evidence survives.
	if err := SaveAdminSettings(); err == nil {
		t.Fatal("save must refuse while stored management policy is unknown")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("refused save wrote a defaults-only replacement")
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
	resetUIAccessPolicyGlobals(t)
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
	resetUIAccessPolicyGlobals(t)
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
