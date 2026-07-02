package main

// rootca_startup.go — loader for the Root-CA slice. Owns the side effects:
// loading/initialising the inspection CA on certMgr, publishing the caRuntime
// rotation config, and starting the auto-rotation background check. The
// resolver + DTO live in rootca_startup_config.go; the initRootCA shim in
// main.go wires them.

import "context"

// loadRootCA loads (or initialises) the Root CA for SSL inspection. A CA
// failure is non-fatal by design — the proxy serves with SSL inspection
// disabled rather than refusing to start. caRuntime is published for the
// API-driven rotation handlers regardless of load success (rotation needs the
// path+passphrase to write the new bundle). NOTE: caRuntime remains the
// pre-existing unsynchronised global flagged by ARCH_DISCOVERY — moved
// verbatim; hardening it is a separate, out-of-scope change.
func loadRootCA(cfg rootCAStartupConfig, ctx context.Context) {
	initInspectionCA(cfg)
	// Store CA runtime config for API-driven rotation.
	caRuntime.path = cfg.Path
	caRuntime.passphrase = cfg.Passphrase
	// Start CA auto-rotation background check.
	if certMgr.Ready() {
		StartCAAutoRotation(ctx, cfg.Path, cfg.Passphrase)
	}
}

// initInspectionCA performs the load-or-init half of loadRootCA: persisted
// bundle when a path is configured, ephemeral in-memory CA otherwise.
func initInspectionCA(cfg rootCAStartupConfig) {
	if cfg.Path == "" {
		if err := certMgr.InitCA(); err != nil {
			logger.Printf("Warning: Root CA init failed (%v) — SSL inspection disabled", err)
			return
		}
		logger.Printf("SSLCA: Root CA ready in-memory (set -ca-path + %s for persistence)", caPassphraseEnv)
		return
	}
	if err := certMgr.LoadOrInitCA(cfg.Path, cfg.Passphrase); err != nil {
		logger.Printf("Warning: Root CA load/init failed (%v) — SSL inspection disabled", err)
		return
	}
	logger.Printf("SSLCA: Root CA ready (persisted at %s, encrypted=%v)", cfg.Path, cfg.Passphrase != "")
}
