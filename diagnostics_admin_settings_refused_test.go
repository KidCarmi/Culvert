package main

import (
	"strings"
	"testing"
)

func TestAdminSettingsRefusedRows(t *testing.T) {
	if rows := adminSettingsRefusedRows(false, false); len(rows) != 0 {
		t.Fatalf("nothing refused: want no rows, got %+v", rows)
	}
	rows := adminSettingsRefusedRows(true, true)
	if len(rows) != 1 || rows[0].Code != "admin_settings_refused" || rows[0].Status != diagWarn || rows[0].OperatorAction == "" {
		t.Fatalf("want one admin_settings_refused WARN row, got %+v", rows)
	}
	for _, want := range []string{"auto-exclusion tunables", "retention caps"} {
		if !strings.Contains(rows[0].Message, want) {
			t.Errorf("message should name %q, got %q", want, rows[0].Message)
		}
	}
	for _, want := range []string{"Decryption Exclusions → Cache Tuning", "Support → Retention tuning"} {
		if !strings.Contains(rows[0].OperatorAction, want) {
			t.Errorf("action should point at %q, got %q", want, rows[0].OperatorAction)
		}
	}
	if only := adminSettingsRefusedRows(false, true); strings.Contains(only[0].Message, "auto-exclusion") {
		t.Errorf("retention-only row must not name the tunables, got %q", only[0].Message)
	}
}

// The load-time refusal sets the latch, the row reaches the assembled report,
// and a load without the refused slice clears it. Only the refusal path runs,
// which installs nothing, so no engine state needs restoring.
func TestAdminSettingsRefusedAtLoad_LatchReachesReport(t *testing.T) {
	t.Cleanup(func() {
		autoExcludeTunablesRefusedAtLoad.Store(false)
		supportRetentionRefusedAtLoad.Store(false)
	})
	applyAdminAutoExcludeTunables(&AdminSettings{AutoExcludeTunablesSaved: true, AutoExcludeConfirmN: autoExcludeConfirmNMax + 1})
	applyAdminSupportRetention(&AdminSettings{SupportRetentionSaved: true, SupportRetentionKeep: supportRetentionKeepMax + 1})
	if !autoExcludeTunablesRefusedAtLoad.Load() || !supportRetentionRefusedAtLoad.Load() {
		t.Fatal("out-of-range persisted slices must latch the refusal")
	}
	found := false
	for _, c := range buildOperatorContract().Checks {
		if c.Code == "admin_settings_refused" {
			found = true
		}
	}
	if !found {
		t.Fatal("refused slices must surface admin_settings_refused in the report")
	}

	// A later load whose file never saved these slices clears the latch.
	applyAdminAutoExcludeTunables(&AdminSettings{})
	applyAdminSupportRetention(&AdminSettings{})
	if rows := checkAdminSettingsRefusedAtLoad(); len(rows) != 0 {
		t.Fatalf("latch must clear on a load that refuses nothing, got %+v", rows)
	}
}
