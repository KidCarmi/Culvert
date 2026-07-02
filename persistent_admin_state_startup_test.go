package main

// persistent_admin_state_startup_test.go — per-slice tests for the
// persistent-admin-state startup slice. The loader is a fixed sequence of
// side effects owned (and already exercised) by their own subsystems'
// tests; the slice-level contract here is the path resolution and the
// resolver's purity (the latter also pinned by the cross-slice contract
// table in startup_slice_contract_test.go).

import (
	"path/filepath"
	"testing"
)

func TestResolvePersistentAdminStateStartupConfig_Paths(t *testing.T) {
	dir := t.TempDir()
	got := resolvePersistentAdminStateStartupConfig(dir)

	want := persistentAdminStateStartupConfig{
		NodeGroupsPath:    filepath.Join(dir, "node_groups.json"),
		BandwidthPath:     filepath.Join(dir, "bandwidth.json"),
		HitCountersPath:   filepath.Join(dir, "hit_counters.json"),
		AdminSettingsPath: filepath.Join(dir, "admin_settings.json"),
	}
	if got != want {
		t.Errorf("resolved paths mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestResolvePersistentAdminStateStartupConfig_ZeroValueSafe(t *testing.T) {
	// Zero-value input must not panic and must still yield the four leaf
	// names (relative), matching the cross-slice purity contract.
	got := resolvePersistentAdminStateStartupConfig("")
	if got.NodeGroupsPath != "node_groups.json" || got.AdminSettingsPath != "admin_settings.json" {
		t.Errorf("zero-value resolution unexpected: %+v", got)
	}
}
