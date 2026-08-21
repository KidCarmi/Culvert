package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// withAdminSettingsDurableState isolates the overridden-surfaces snapshot and
// adminSettingsPath across a test so it can drive LoadAdminSettings /
// SaveAdminSettings without leaking process-global state into neighbours.
func withAdminSettingsDurableState(t *testing.T) {
	t.Helper()
	prevSurfaces := adminSettingsOverriddenSurfaces.Load()
	adminSettingsMu.Lock()
	prevPath := adminSettingsPath
	adminSettingsMu.Unlock()
	t.Cleanup(func() {
		adminSettingsOverriddenSurfaces.Store(prevSurfaces)
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
	adminSettingsOverriddenSurfaces.Store(&[]string{})

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
	adminSettingsOverriddenSurfaces.Store(&[]string{})

	path := filepath.Join(t.TempDir(), "admin_settings.json")
	adminSettingsMu.Lock()
	adminSettingsPath = path
	adminSettingsMu.Unlock()

	if err := SaveAdminSettings(); err != nil {
		t.Fatalf("SaveAdminSettings: %v", err)
	}
	if len(AdminSettingsOverriddenSurfaces()) == 0 {
		t.Fatal("AdminSettingsOverriddenSurfaces() empty after a successful save, want the saved sentinels listed")
	}

	c := checkConfigSourcePrecedence()
	if c.Status != diagOK {
		t.Fatalf("Status = %q, want ok (informational, not a fault)", c.Status)
	}
	if c.OperatorAction == "" {
		t.Fatal("OperatorAction is empty, want guidance once settings are durably overridden")
	}
}

// TestCheckConfigSourcePrecedence_PerSentinelAccuracy pins the review finding
// against the original all-or-nothing flag: an admin_settings.json written by
// an OLDER build carries only the sentinels that existed then, and the row
// must name exactly the overridden surfaces — never claim a surface whose
// sentinel is absent (it still follows config.yaml/CLI).
func TestCheckConfigSourcePrecedence_PerSentinelAccuracy(t *testing.T) {
	withAdminSettingsDurableState(t)
	// The shape of an upgraded file: blocklist feeds saved long ago, the newer
	// autoexclude-tunables sentinel never written.
	snapshotOverriddenSurfaces(AdminSettings{BlocklistFeedsSaved: true, TrustedProxyCIDRsSaved: true})

	c := checkConfigSourcePrecedence()
	if !strings.Contains(c.Message, "blocklist feeds") || !strings.Contains(c.Message, "trusted-proxy CIDRs") {
		t.Fatalf("Message must name the overridden surfaces; got %q", c.Message)
	}
	if strings.Contains(c.Message, "auto-exclusion tunables are now") ||
		strings.Contains(c.Message, "Durable admin overrides are active for: log retention") {
		t.Fatalf("Message claims un-sentineled surfaces are overridden; got %q", c.Message)
	}
	for _, name := range []string{"decryption auto-exclusion tunables", "support-bundle retention", "YARA engine settings"} {
		if strings.Contains(strings.SplitN(c.Message, ". ", 2)[0], name) {
			t.Fatalf("override list wrongly includes %q; got %q", name, c.Message)
		}
	}
}

// TestSnapshotOverriddenSurfaces covers the field list the load/save paths
// rely on, independent of LoadAdminSettings' broader apply pipeline (which
// has real, deliberately process-global side effects — e.g. it can disable
// the live YARA engine — so it is not something this test should invoke just
// to check the snapshot).
func TestSnapshotOverriddenSurfaces(t *testing.T) {
	withAdminSettingsDurableState(t)

	snapshotOverriddenSurfaces(AdminSettings{})
	if got := AdminSettingsOverriddenSurfaces(); len(got) != 0 {
		t.Fatalf("zero-value AdminSettings produced overrides %v, want none", got)
	}

	cases := []struct {
		s    AdminSettings
		want string
	}{
		{AdminSettings{LogRetentionSaved: true}, "log retention"},
		{AdminSettings{LogStoreEnabledSaved: true}, "log-store enable"},
		{AdminSettings{TrustedProxyCIDRsSaved: true}, "trusted-proxy CIDRs"},
		{AdminSettings{BlocklistFeedsSaved: true}, "blocklist feeds"},
		{AdminSettings{UpstreamProxiesSaved: true}, "upstream proxy pool"},
		{AdminSettings{YARASettingsSaved: true}, "YARA engine settings"},
		{AdminSettings{AutoExcludeTunablesSaved: true}, "decryption auto-exclusion tunables"},
		{AdminSettings{SupportRetentionSaved: true}, "support-bundle retention"},
	}
	for i, tc := range cases {
		snapshotOverriddenSurfaces(tc.s)
		got := AdminSettingsOverriddenSurfaces()
		if len(got) != 1 || got[0] != tc.want {
			t.Fatalf("case %d: snapshot = %v, want exactly [%q]", i, got, tc.want)
		}
	}
}
