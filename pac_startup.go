package main

// pac_startup.go — startup-time loader for the PAC slice (PR3 expansion,
// Batch 3). Loads the PAC JSON store and wires the default proxy port.

import "fmt"

// loadPAC applies cfg. Returns an error wrapped with "PAC config load
// error:" — the shim log.Fatalf's it verbatim to match the pre-pilot
// message. pacDefaultProxyPort is assigned unconditionally (matches
// original behaviour).
func loadPAC(cfg pacStartupConfig) error {
	if err := pacStore.Load(cfg.ConfigPath); err != nil {
		return fmt.Errorf("PAC config load error: %w", err)
	}
	pacDefaultProxyPort = cfg.DefaultProxyPort
	return nil
}
