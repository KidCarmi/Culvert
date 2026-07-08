package main

// persistent_admin_state_startup.go — loader for the persistent-admin-state
// slice. Owns the side effects: the storage writability probe, config
// versioning bootstrap, the node-group / bandwidth store constructions,
// hit-counter persistence + restore, and the admin-settings restore. The
// resolver + DTO live in persistent_admin_state_startup_config.go; the
// initPersistentAdminState shim in main.go wires them.

import "context"

// loadPersistentAdminState runs the persistent-admin-state startup sequence.
// ORDER IS THE CONTRACT (verbatim from the pre-slice init):
//
//  1. probeStorageWritability — one-shot, cached for /api/diagnostics so the
//     handler stays side-effect-free; never retries, never blocks startup.
//  2. initConfigVersioning — scans configVersionsDir to seed the version seq.
//  3. node-group + bandwidth stores — constructed before anything can consume
//     them (ConfigSnapshot building, admin API).
//  4. alert-webhook store Init — RISK-017 closure: this call was never wired
//     pre-slice (webhooks silently vanished on restart; the RISK-003
//     encryption-at-rest protected a file production never wrote). NOT part
//     of the verbatim pre-slice order — added 2026-07-03. The F16 retry loop
//     (background-services slice, started earlier in main()) reads the store
//     through a provider closure on each 10s tick, so it picks up the loaded
//     webhooks without an ordering dependency.
//  5. hit-counter persistence goroutine (parented to ctx) + RestoreHitCounts,
//     which copies persisted counters back into PolicyRule.HitCount and must
//     run AFTER the policy store is loaded (initPolicy precedes this slice in
//     main()).
//  6. LoadAdminSettings LAST — it restores GUI-saved state (e.g. re-enables
//     the log store) and therefore must run after the subsystems it toggles
//     have been initialised earlier in startup.
func loadPersistentAdminState(cfg persistentAdminStateStartupConfig, ctx context.Context) {
	probeStorageWritability()
	initConfigVersioning()
	globalNodeGroups = NewNodeGroupStore(cfg.NodeGroupsPath)
	globalBandwidth = NewBandwidthManager(cfg.BandwidthPath)
	globalAlertStore.Init(cfg.AlertWebhooksPath)
	startHitCounterPersistence(ctx, cfg.HitCountersPath)
	RestoreHitCounts()
	LoadAdminSettings(cfg.AdminSettingsPath)
}
