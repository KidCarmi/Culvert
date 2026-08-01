package main

// catoverride_vars.go — package-main glue for the admin-owned category-override
// store, which lives in internal/catoverride (mirrors categorygroup.go /
// decryptprofile_vars.go). The alias shim keeps the F3a-2 admin API handlers,
// export/import, config-version rollback, and CP→DP sync (ConfigSnapshot.
// CategoryOverrides) on the original unqualified names.
//
// SCOPE (F3a-2): the store is CP-authoritative fleet policy — persisted node-local,
// exported/imported, rollback-able, and CP→DP synced. Nothing here downloads,
// verifies, activates, or composes a live view: F3a-2 is configuration plumbing.
// The overrides are folded onto a feed-owned snapshot (catoverride.ComposeView)
// only by the future downloader/activation slice (F3b); until then they are inert
// admin-managed configuration.

import "github.com/KidCarmi/Culvert/internal/catoverride"

// CategoryOverrides is a re-exported alias for the engine's admin-override set
// (engine type catoverride.Overrides). It is the on-wire + on-disk shape shared
// by the ConfigSnapshot binding, configBackup, and overrides.json.
type CategoryOverrides = catoverride.Overrides

// globalCategoryOverrides is the process-wide admin category-override store,
// mutated by the admin API, config import, config-version rollback, and CP→DP
// snapshot apply. Loaded at startup from <dataDir>/saas_feed/overrides.json.
var globalCategoryOverrides = catoverride.New()
