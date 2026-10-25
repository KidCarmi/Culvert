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
// already guards globalSyslogHandle).
func TestSaveAdminSettings_NilBlFeedSyncerDoesNotPanic(t *testing.T) {
	// THE TEMPDIR IS CREATED BEFORE THE RESTORE CLEANUP IS REGISTERED, and the
	// order is the whole point. t.Cleanup runs LIFO, so registering the
	// directory first makes it the LAST thing removed — after adminSettingsPath
	// has been pointed away from it.
	//
	// Written the other way round (t.TempDir() inline below the cleanup, which
	// is how this read until the CHAOS-87 determinism lane caught it) the
	// directory is removed while the package global still points INSIDE it, and
	// any detached adminSettingsSave() goroutine landing in that window
	// recreates admin_settings.json underneath RemoveAll. The failure surfaces
	// as "TempDir RemoveAll cleanup: directory not empty" attributed to THIS
	// test, while the writer is whichever admin handler an earlier test
	// exercised — so it moves with the shuffle order and is invisible to a
	// targeted -run.
	//
	// Restoring under adminSettingsMu is sufficient on its own and no
	// adminSettingsSaveWG drain is needed: saveAdminSettingsWithOverrides holds
	// that mutex across its ENTIRE snapshot → write → apply sequence, not just
	// the path read, so a save either completes before this restore takes the
	// lock or starts after it and writes to the restored path. See the contract
	// comment on saveAdminSettingsWithOverrides.
	dir := t.TempDir()

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

	path := filepath.Join(dir, "admin_settings.json")
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
