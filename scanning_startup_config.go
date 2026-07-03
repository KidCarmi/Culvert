package main

// scanning_startup_config.go — resolved config for the security-scanning
// slice (ClamAV + YARA + threat feeds + remote-scan / sidecar modes). Pure
// DTO + a single side-effect-free resolver invoked from the initScanning
// shim. CLI flag values and the data dir are passed IN so the resolver stays
// pure (slice convention pinned by startup_slice_contract_test.go).

import (
	"path/filepath"
	"time"
)

// scanningCLIFlags carries the scanning CLI flag values (read in the shim).
// Empty values mean "flag not set" — config file values win.
type scanningCLIFlags struct {
	ClamAVAddr    string
	YARARulesDir  string
	ThreatFeedDB  string
	ScanSvcURL    string
	ScanSvcListen string
}

// scanningStartupConfig carries the resolved scanning inputs. The loader
// consumes this struct and owns the scanner/cache/feed side effects.
type scanningStartupConfig struct {
	// RemoteScanURL != "" selects REMOTE mode: body scanning is delegated to
	// a sidecar and local ClamAV/YARA stay off (threat feeds still run
	// locally — URL/domain checks are cheap).
	RemoteScanURL string

	// Local-mode inputs (CLI wins over config for each address/path).
	ClamAddr string
	YaraDir  string
	FeedDB   string

	// LocalEnabled mirrors the pre-slice gate: scanning is on when the
	// config says so OR any concrete backend is configured.
	LocalEnabled bool

	// ThreatFeedEnabled mirrors the pre-slice gate (identical in remote and
	// local modes): a feed DB is set OR scanning is enabled.
	ThreatFeedEnabled bool

	// CacheTTL / SyncInterval use VERBATIM parse-ok-wins semantics (any
	// parseable duration overrides the default; unparseable falls back).
	CacheTTL     time.Duration // scan result cache TTL (default 1h)
	SyncInterval time.Duration // threat feed sync cadence (default 6h)

	// CacheSize is the scan-cache entry cap (non-positive → 10_000).
	CacheSize int

	// MaxScanBytes caps scanned body size (0 = unlimited; from MaxScanMB).
	MaxScanBytes int64

	// ScanExclusionsPath is the admin-managed allowlist store; "" (no data
	// dir) skips the load.
	ScanExclusionsPath string

	// SvcListenAddr != "" runs the scan microservice sidecar.
	SvcListenAddr string
}

// resolveScanningStartupConfig is the single startup-time reader of
// fc.SecurityScan for this slice. Pure and deterministic; safe on a
// zero-value *FileConfig.
func resolveScanningStartupConfig(fc *FileConfig, flags scanningCLIFlags, dataDirVal string) scanningStartupConfig {
	secCfg := fc.SecurityScan
	clamAddr := firstStr(flags.ClamAVAddr, secCfg.ClamAVAddr)
	yaraDir := firstStr(flags.YARARulesDir, secCfg.YARARulesDir)
	feedDB := firstStr(flags.ThreatFeedDB, secCfg.ThreatFeedDB)

	cacheTTL := time.Hour
	if secCfg.CacheTTL != "" {
		if d, err := time.ParseDuration(secCfg.CacheTTL); err == nil {
			cacheTTL = d
		}
	}
	syncInterval := 6 * time.Hour
	if secCfg.SyncInterval != "" {
		if d, err := time.ParseDuration(secCfg.SyncInterval); err == nil {
			syncInterval = d
		}
	}
	cacheSize := secCfg.CacheSize
	if cacheSize <= 0 {
		cacheSize = 10_000
	}
	var maxScanBytes int64
	if secCfg.MaxScanMB > 0 {
		maxScanBytes = int64(secCfg.MaxScanMB) << 20
	}
	exclusionsPath := ""
	if dataDirVal != "" {
		exclusionsPath = filepath.Join(dataDirVal, "scan_exclusions.json")
	}

	return scanningStartupConfig{
		RemoteScanURL:      firstStr(flags.ScanSvcURL, secCfg.ScanSvcURL),
		ClamAddr:           clamAddr,
		YaraDir:            yaraDir,
		FeedDB:             feedDB,
		LocalEnabled:       secCfg.Enabled || clamAddr != "" || yaraDir != "" || feedDB != "",
		ThreatFeedEnabled:  feedDB != "" || secCfg.Enabled,
		CacheTTL:           cacheTTL,
		SyncInterval:       syncInterval,
		CacheSize:          cacheSize,
		MaxScanBytes:       maxScanBytes,
		ScanExclusionsPath: exclusionsPath,
		SvcListenAddr:      firstStr(flags.ScanSvcListen, secCfg.ScanSvcListen),
	}
}
