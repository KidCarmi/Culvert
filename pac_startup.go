package main

// pac_startup.go — startup-time loader for the PAC slice (PR3 expansion,
// Batch 3). Loads the PAC JSON store and wires the default proxy port.

import (
	"fmt"
	"os"
	"path/filepath"
)

// loadPAC applies cfg. Returns an error wrapped with "PAC config load
// error:" — the shim log.Fatalf's it verbatim to match the pre-pilot
// message. The default port is assigned unconditionally (matches original
// behaviour; the former pacDefaultProxyPort global is store-owned now).
//
// The store lives at <dataDir>/pac_config.json; a legacy CWD pac_config.json
// (pre-backup-surface location) is one-way migrated on first load. The legacy
// file is left in place, frozen — see docs/operator/pac-traffic-steering.md.
func loadPAC(cfg pacStartupConfig) error {
	if dir := filepath.Dir(cfg.ConfigPath); dir != "." {
		// Best-effort: Store.Set surfaces real write failures later.
		_ = os.MkdirAll(dir, 0o700) //nolint:errcheck // best-effort; Store.Set surfaces real failures
	}
	migrated, err := pacStore.LoadMigrate(cfg.ConfigPath, cfg.LegacyConfigPath)
	if err != nil {
		return fmt.Errorf("PAC config load error: %w", err)
	}
	if migrated {
		logger.Printf("PAC config migrated from %s to %s (legacy file left in place, now frozen)",
			cfg.LegacyConfigPath, cfg.ConfigPath)
	} else if warnStaleLegacyPAC(cfg.ConfigPath, cfg.LegacyConfigPath) {
		// Downgrade→edit→re-upgrade hazard (Palo ops F5a): the store already
		// exists but a newer legacy CWD file means edits made by a downgraded
		// binary are being silently ignored. Warn loudly instead.
		logger.Printf("PAC config WARNING: legacy %s is newer than the active store %s — edits made by a downgraded binary are being ignored; re-apply them or copy the legacy file over the store",
			cfg.LegacyConfigPath, cfg.ConfigPath)
	}
	if cfg.ProfilesPath != "" {
		if err := pacProfiles.Load(cfg.ProfilesPath); err != nil {
			return fmt.Errorf("PAC config load error: %w", err)
		}
	}
	if cfg.LifecyclePath != "" {
		// The lifecycle store is NODE-LOCAL operator history, not serving-
		// critical config. A corrupt file self-quarantines and starts empty
		// inside Load; treat any load error as a warning (never fatal) so a
		// bad history file cannot brick the proxy at startup.
		if err := pacLifecycle.Load(cfg.LifecyclePath); err != nil {
			logger.Printf("PAC lifecycle history WARNING: %v", err)
		}
		// 2F-B correction (C1): a quarantined history is a durable, visible
		// history_reset. Scope it to the profiles that are active right now
		// (the ACTIVE store is loaded above and stays the sole authority);
		// every one of them refuses publish/rollback until an admin
		// acknowledges the loss. A scope that cannot be persisted stays
		// unscoped, which is the conservative reading (all active affected).
		if hr := pacLifecycle.HistoryResetRecord(); hr != nil && !hr.Scoped {
			ids := pacActiveProfileIDs()
			if err := pacLifecycle.NoteActiveAtReset(ids); err != nil {
				logger.Printf("PAC lifecycle history RESET WARNING: scope could not be persisted (%v); every active profile is treated as affected", err)
			}
			logger.Printf("PAC lifecycle history RESET: node-local publish history quarantined to %q; publish/rollback refused for %d active profile(s) until acknowledged (action acknowledge_history_reset)",
				sanitizeLog(hr.QuarantinedTo), len(ids))
		}
	}
	if cfg.ExceptionsPath != "" {
		// Governance metadata is NODE-LOCAL operator state, not serving-critical
		// config. A corrupt file self-quarantines and starts empty in Load;
		// treat any load error as a warning (never fatal).
		if err := pacExceptions.Load(cfg.ExceptionsPath); err != nil {
			logger.Printf("PAC exception governance WARNING: %v", err)
		}
	}
	// 2F-B: settle every publish/rollback intent that was in flight when the
	// previous process stopped, against the authoritative active store just
	// loaded (committed → durable committed + history, aborted → record,
	// else ambiguous). The post-commit effects that need the WHOLE
	// configuration (config version, cluster publication, audit, terminal
	// record) run in main.go's pacReconcileAllLifecycles once every store is
	// loaded — capturing a config version here would snapshot a partial
	// configuration that a later rollback would treat as authoritative.
	pacSettleLifecycleIntents()
	pacStore.SetDefaultPort(cfg.DefaultProxyPort)
	return nil
}

// pacActiveProfileIDs lists the IDs of the loaded active profiles.
func pacActiveProfileIDs() []string {
	cfg := pacProfiles.Get()
	ids := make([]string, 0, len(cfg.Profiles))
	for i := range cfg.Profiles {
		ids = append(ids, cfg.Profiles[i].ID)
	}
	return ids
}

// warnStaleLegacyPAC reports whether both the active store and the legacy CWD
// file exist AND the legacy file is strictly newer — the signature of a
// downgrade-window edit that the re-upgraded binary is about to ignore.
func warnStaleLegacyPAC(path, legacyPath string) bool {
	if legacyPath == "" {
		return false
	}
	ps, err := os.Stat(path)
	if err != nil {
		return false
	}
	ls, err := os.Stat(legacyPath)
	if err != nil {
		return false
	}
	return ls.ModTime().After(ps.ModTime())
}
