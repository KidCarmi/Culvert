package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSaveAdminSettings_NilBlFeedSyncerDoesNotPanic is a regression test for a
// pre-existing flaky crash: SaveAdminSettings read blFeedSyncer.Stats() with no
// nil guard, but blFeedSyncer is nil until main() runs loadBlocklistFeed.
// Because adminSettingsSave fires `go SaveAdminSettings()` (a detached
// goroutine), under some test orderings the goroutine ran while blFeedSyncer
// was still nil and panicked at blocklist_feed.go:114, crashing the whole test
// binary. SaveAdminSettings must tolerate a nil blFeedSyncer (the same way it
// already guards globalSyslog).
func TestSaveAdminSettings_NilBlFeedSyncerDoesNotPanic(t *testing.T) {
	origSyncer := blFeedSyncer
	adminSettingsMu.Lock()
	origPath := adminSettingsPath
	adminSettingsMu.Unlock()
	t.Cleanup(func() {
		blFeedSyncer = origSyncer
		adminSettingsMu.Lock()
		adminSettingsPath = origPath
		adminSettingsMu.Unlock()
	})

	blFeedSyncer = nil // simulate the test-binary / pre-main() state

	path := filepath.Join(t.TempDir(), "admin_settings.json")
	adminSettingsMu.Lock()
	adminSettingsPath = path
	adminSettingsMu.Unlock()

	// Before the fix this panicked (nil deref); it must now return cleanly and
	// still persist the settings file.
	SaveAdminSettings()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("SaveAdminSettings did not write settings file with nil blFeedSyncer: %v", err)
	}
}
