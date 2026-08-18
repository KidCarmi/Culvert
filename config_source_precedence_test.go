package main

import (
	"path/filepath"
	"testing"
)

// withAdminSettingsDurableState isolates adminSettingsDurablySaved and
// adminSettingsPath across a test so it can drive LoadAdminSettings /
// SaveAdminSettings without leaking process-global state into neighbours.
func withAdminSettingsDurableState(t *testing.T) {
	t.Helper()
	prevDurable := adminSettingsDurablySaved.Load()
	adminSettingsMu.Lock()
	prevPath := adminSettingsPath
	adminSettingsMu.Unlock()
	t.Cleanup(func() {
		adminSettingsDurablySaved.Store(prevDurable)
		adminSettingsMu.Lock()
		adminSettingsPath = prevPath
		adminSettingsMu.Unlock()
	})
}

// TestCheckConfigSourcePrecedence_NoSaveYet verifies the diagnostics row
// reports config.yaml/CLI as the source when admin_settings.json has never
// been durably saved.
func TestCheckConfigSourcePrecedence_NoSaveYet(t *testing.T) {
	withAdminSettingsDurableState(t)
	adminSettingsDurablySaved.Store(false)

	c := checkConfigSourcePrecedence()
	if c.Code != "config_source_precedence" {
		t.Fatalf("Code = %q, want config_source_precedence", c.Code)
	}
	if c.Status != diagOK {
		t.Fatalf("Status = %q, want ok", c.Status)
	}
	if c.OperatorAction != "" {
		t.Fatalf("OperatorAction = %q, want empty when no admin override is active", c.OperatorAction)
	}
}

// TestCheckConfigSourcePrecedence_AfterSave verifies that once
// SaveAdminSettings has succeeded, the diagnostics row flips to reporting a
// GUI/API-durable override and explains that config.yaml/CLI edits to the
// affected settings no longer take effect.
func TestCheckConfigSourcePrecedence_AfterSave(t *testing.T) {
	withAdminSettingsDurableState(t)
	adminSettingsDurablySaved.Store(false)

	path := filepath.Join(t.TempDir(), "admin_settings.json")
	adminSettingsMu.Lock()
	adminSettingsPath = path
	adminSettingsMu.Unlock()

	if err := SaveAdminSettings(); err != nil {
		t.Fatalf("SaveAdminSettings: %v", err)
	}
	if !AdminSettingsDurablyOverridden() {
		t.Fatal("AdminSettingsDurablyOverridden() = false after a successful save, want true")
	}

	c := checkConfigSourcePrecedence()
	if c.Status != diagOK {
		t.Fatalf("Status = %q, want ok (informational, not a fault)", c.Status)
	}
	if c.OperatorAction == "" {
		t.Fatal("OperatorAction is empty, want guidance once settings are durably overridden")
	}
}

// TestAdminSettingsHasSavedSentinel covers the field list LoadAdminSettings
// relies on to detect a pre-existing durable override on disk, independent
// of LoadAdminSettings' broader apply pipeline (which has real, deliberately
// process-global side effects — e.g. it can disable the live YARA engine —
// so it is not something this test should invoke just to check one flag).
func TestAdminSettingsHasSavedSentinel(t *testing.T) {
	if adminSettingsHasSavedSentinel(AdminSettings{}) {
		t.Fatal("zero-value AdminSettings reported as saved, want false")
	}
	cases := []AdminSettings{
		{LogRetentionSaved: true},
		{LogStoreEnabledSaved: true},
		{TrustedProxyCIDRsSaved: true},
		{BlocklistFeedsSaved: true},
		{UpstreamProxiesSaved: true},
		{YARASettingsSaved: true},
		{AutoExcludeTunablesSaved: true},
		{SupportRetentionSaved: true},
	}
	for i, s := range cases {
		if !adminSettingsHasSavedSentinel(s) {
			t.Fatalf("case %d: %+v reported as not saved, want true", i, s)
		}
	}
}
