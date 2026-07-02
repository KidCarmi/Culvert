package main

// persistent_admin_state_startup_config.go — resolved config for the
// persistent-admin-state slice. Pure DTO + a single side-effect-free resolver
// invoked from the initPersistentAdminState shim. No globals are read or
// written here; the data-dir value is passed IN by the shim so the resolver
// stays pure (slice convention pinned by startup_slice_contract_test.go).

import "path/filepath"

// persistentAdminStateStartupConfig carries the resolved on-disk locations of
// the four persistent admin stores initialised at startup. The loader consumes
// this struct and owns the store constructions + restore side effects.
type persistentAdminStateStartupConfig struct {
	NodeGroupsPath    string // node group definitions (label selectors)
	BandwidthPath     string // per-group bandwidth/QoS policies
	HitCountersPath   string // per-rule hit-counter persistence (Finding 2.3)
	AdminSettingsPath string // GUI-changed settings restored across restarts
}

// resolvePersistentAdminStateStartupConfig derives the four store paths from
// the data dir. Pure and deterministic.
func resolvePersistentAdminStateStartupConfig(dataDirVal string) persistentAdminStateStartupConfig {
	return persistentAdminStateStartupConfig{
		NodeGroupsPath:    filepath.Join(dataDirVal, "node_groups.json"),
		BandwidthPath:     filepath.Join(dataDirVal, "bandwidth.json"),
		HitCountersPath:   filepath.Join(dataDirVal, "hit_counters.json"),
		AdminSettingsPath: filepath.Join(dataDirVal, "admin_settings.json"),
	}
}
