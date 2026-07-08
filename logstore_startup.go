package main

// logstore_startup.go — loader for the persistent log-store slice. Owns the
// side effects: publishing the logStoreDir / logStorePassphrase globals and
// (when seed-enabled via config) opening the store. The resolver + DTO live
// in logstore_startup_config.go; the initLogStore shim in main.go wires them.

import "context"

// loadLogStore publishes the log-store globals and, when the config
// seed-enables the store (log_store_path set), opens it. A store open
// failure is non-fatal: history is an enhancement over the in-memory ring,
// so it must not stop the proxy from serving traffic.
func loadLogStore(cfg logStoreStartupConfig, ctx context.Context) {
	logStoreDir = cfg.Dir
	logStorePassphrase = cfg.Passphrase

	if !cfg.SeedEnable {
		logger.Printf("LogStore: off (enable from the admin UI, or set log_store_path)")
		return
	}
	if err := enableLogStore(ctx, cfg.Dir, cfg.RetentionDays, cfg.RetentionMaxGB); err != nil {
		logger.Printf("LogStore: cannot open at %s: %v — history disabled", cfg.Dir, err)
		return
	}
	logger.Printf("LogStore: history at %s (retention: %d days, %.2f GB)", cfg.Dir, cfg.RetentionDays, cfg.RetentionMaxGB)
}
