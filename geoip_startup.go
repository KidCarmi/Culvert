package main

import "github.com/KidCarmi/Culvert/internal/geoip"

// geoip_startup.go — startup-time loader for the GeoIP database slice
// (PR3 expansion, Batch 1).
//
// No error return: InitGeoDB failures are non-fatal and logged internally,
// matching the pre-pilot init body. The caller stashes cfg.DBPath on
// startupState (for startAdminUI) directly from the resolved config.

// loadGeoIP opens the GeoIP database at cfg.DBPath. Failures are logged as
// "GeoIP disabled" warnings and startup continues; a failed open of a
// configured path is armed for the background retry.
func loadGeoIP(cfg geoIPStartupConfig) {
	if cfg.DBPath == "" {
		logger.Printf("GeoIP: disabled (no -geoip-db set; destCountry rules will be skipped)")
		return
	}
	if err := geoip.InitGeoDB(cfg.DBPath); err != nil {
		logger.Printf("GeoIP: failed to open %s (%v) — GeoIP disabled", cfg.DBPath, err)
		// The path stays the operator's intent: retry it in the background
		// (geoip_load_retry.go) instead of requiring a restart.
		armGeoIPDeferredLoad(cfg.DBPath)
		return
	}
	logger.Printf("GeoIP: loaded %s", cfg.DBPath)
}
