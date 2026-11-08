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
		globalRemoteScanner.SetExclusions(globalScanExclusions)
		// Userinfo-redacted: an operator URL may carry an embedded credential
		// and the process log is shipped in support bundles.
		logger.Printf("ScanSvc: remote mode, delegating to %s", redactURLUserinfo(cfg.RemoteScanURL))
		loadScanExclusions(cfg.ScanExclusionsPath)
		startThreatFeedIfEnabled(cfg, ctx)
	case cfg.LocalEnabled:
		globalSecScanner.Init(cfg.ClamAddr, cfg.MaxScanBytes, newHashCache(cfg.CacheSize, cfg.CacheTTL))
		loadYARARules(cfg.YaraDir)
		loadScanExclusions(cfg.ScanExclusionsPath)
		startThreatFeedIfEnabled(cfg, ctx)
	}
	return startScanServiceSidecar(ctx, cfg.SvcListenAddr)
}

// loadScanExclusions loads the admin-managed scan allowlist. It runs in BOTH
// scanning modes, which is the CHAOS-53 fix: it used to run only on the local
// branch, so a sidecar deployment never loaded the file — and, because
// scanexcl.Store learns its path from Load, never had one to save to either.
// Store.Save() is a documented no-op without a path, so every admin edit to
// the exclusion lists returned 200, wrote an audit entry, took a config-version
// snapshot, and persisted nothing: the lists silently reverted to empty on the
// next restart. The HOST list is consulted on the request path in remote mode
// too (proxy_tunnel.go, proxy_http.go), so this also restored a setting that
// was being ignored outright.
func loadScanExclusions(path string) {
	if path == "" {
		return
	}
	if err := globalScanExclusions.Load(path); err != nil {
		logger.Printf("ScanExclusions: load error: %v", err)
	}
}

// startThreatFeedIfEnabled starts the threat-feed syncer (identical gate in
// remote and local modes: feed DB set OR scanning enabled).
func startThreatFeedIfEnabled(cfg scanningStartupConfig, ctx context.Context) {
	if !cfg.ThreatFeedEnabled {
		return
	}
	globalThreatFeed.Init(cfg.FeedDB, cfg.SyncInterval)
	// Arm the staleness plane BEFORE Start: Start may run an immediate sync
	// (empty on-disk DB), and that round's outcome — the cold-start case where
	// a failure leaves the node enforcing with no threat intelligence at all —
	// is exactly the one the observer must not miss.
	noteThreatFeedConfigured()
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
// even on a bind error, preserving pre-slice semantics — the shutdown path
// tolerates a never-started service) or nil when disabled.
//
// CHAOS-113: the bind and the serve loop are now owned by
// superviseScanSvcListener, not performed here. What this function used to do
// was bind ONCE, log one line on failure and return a service that would never
// serve again, then `go svc.Start()` and log one line if the serve loop ever
// ended. Neither outcome was counted, gauged, surfaced on a health row or
// alerted, and neither was retried — so a port held by a predecessor at boot,
// or a lost socket at hour nine, silently removed the scanning plane from
// every node pointed at this address, which fails OPEN (internal/secscan
// remoteScanFail, WK-2b).
func startScanServiceSidecar(ctx context.Context, listenAddr string) *ScanService {
	if listenAddr == "" {
		return nil
	}
	svc := NewScanService(listenAddr)
	go superviseScanSvcListener(ctx, svc)
	return svc
}
