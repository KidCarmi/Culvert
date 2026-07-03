package main

// scanning_startup.go — loader for the security-scanning slice. Owns the side
// effects: the remote-scanner/local-scanner mode split, the hash cache, YARA
// seeding+load, scan exclusions, the threat-feed goroutine, and the optional
// scan-service sidecar. The resolver + DTO live in scanning_startup_config.go;
// the initScanning shim in main.go wires them.

import "context"

// loadScanning applies the resolved scanning config and returns the sidecar
// scan service (nil unless SvcListenAddr is set) so the shim can stash it on
// startupState for graceful shutdown. Mode split (verbatim from the pre-slice
// init): a remote scan URL delegates body scanning to the sidecar (local
// ClamAV/YARA off, threat feeds still local); otherwise local scanning
// initialises when enabled or any backend is configured.
func loadScanning(cfg scanningStartupConfig, ctx context.Context) *ScanService {
	switch {
	case cfg.RemoteScanURL != "":
		globalRemoteScanner.Init(cfg.RemoteScanURL)
		logger.Printf("ScanSvc: remote mode, delegating to %s", cfg.RemoteScanURL)
		startThreatFeedIfEnabled(cfg, ctx)
	case cfg.LocalEnabled:
		globalSecScanner.Init(cfg.ClamAddr, cfg.MaxScanBytes, newHashCache(cfg.CacheSize, cfg.CacheTTL))
		loadYARARules(cfg.YaraDir)
		if cfg.ScanExclusionsPath != "" {
			if err := globalScanExclusions.Load(cfg.ScanExclusionsPath); err != nil {
				logger.Printf("ScanExclusions: load error: %v", err)
			}
		}
		startThreatFeedIfEnabled(cfg, ctx)
	}
	return startScanServiceSidecar(cfg.SvcListenAddr)
}

// startThreatFeedIfEnabled starts the threat-feed syncer (identical gate in
// remote and local modes: feed DB set OR scanning enabled).
func startThreatFeedIfEnabled(cfg scanningStartupConfig, ctx context.Context) {
	if !cfg.ThreatFeedEnabled {
		return
	}
	globalThreatFeed.Init(cfg.FeedDB, cfg.SyncInterval)
	globalThreatFeed.Start(ctx)
	logger.Printf("ThreatFeed: sync every %s, db=%q", cfg.SyncInterval, cfg.FeedDB)
}

// loadYARARules seeds the rules directory from the bundled /app/yara on first
// boot (only when the target is empty/missing — so starter rules exist even on
// a fresh persistent volume) and loads it; "" leaves YARA disabled.
func loadYARARules(yaraDir string) {
	if yaraDir == "" {
		logger.Printf("YARA: disabled (set -yara-rules-dir to enable)")
		return
	}
	seedYARARules(yaraDir)
	if err := globalYARA.LoadDir(yaraDir); err != nil {
		logger.Printf("YARA: load error: %v", err)
		return
	}
	logger.Printf("YARA: %d rule(s) from %s", globalYARA.Count(), yaraDir)
}

// startScanServiceSidecar exposes the local scanners as an HTTP microservice
// when a listen address is configured. Returns the service handle (non-nil
// even on a Listen error, preserving pre-slice semantics — the shutdown path
// tolerates a never-started service) or nil when disabled.
func startScanServiceSidecar(listenAddr string) *ScanService {
	if listenAddr == "" {
		return nil
	}
	svc := NewScanService(listenAddr)
	if err := svc.Listen(); err != nil {
		logger.Printf("ScanSvc: listen error: %v", err)
		return svc
	}
	go func() {
		if err := svc.Start(); err != nil {
			logger.Printf("ScanSvc: error: %v", err)
		}
	}()
	return svc
}
