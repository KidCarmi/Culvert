package main

// pac_startup.go — startup-time loader for the PAC slice (PR3 expansion,
// Batch 3). Loads the PAC JSON store and wires the default proxy port.

import "fmt"

// loadPAC applies cfg. Returns an error wrapped with "PAC config load
// error:" — the shim log.Fatalf's it verbatim to match the pre-pilot
// message. The default port is assigned unconditionally (matches original
// behaviour; the former pacDefaultProxyPort global is store-owned now).
func loadPAC(cfg pacStartupConfig) error {
	if err := pacStore.Load(cfg.ConfigPath); err != nil {
		return fmt.Errorf("PAC config load error: %w", err)
	}
	pacStore.SetDefaultPort(cfg.DefaultProxyPort)
	return nil
}
