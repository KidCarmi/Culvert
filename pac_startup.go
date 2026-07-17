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
	}
	pacStore.SetDefaultPort(cfg.DefaultProxyPort)
	return nil
}
