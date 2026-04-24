package main

// geoip_startup_config.go — resolved config for the GeoIP database slice
// (PR3 expansion, Batch 1).

// geoIPStartupConfig carries the resolved GeoIP database path.
type geoIPStartupConfig struct {
	// DBPath is the MaxMind GeoLite2-Country.mmdb path. Empty ⇒ GeoIP
	// disabled (destCountry rules will be skipped at runtime).
	DBPath string
}

// resolveGeoIPStartupConfig is the single startup-time reader of
// fc.Proxy.GeoIPDB. cliFlag is the dereferenced --geoip-db override
// (pass "" when unset). CLI precedence: flag > FileConfig.
func resolveGeoIPStartupConfig(fc *FileConfig, cliFlag string) geoIPStartupConfig {
	return geoIPStartupConfig{
		DBPath: firstStr(cliFlag, fc.Proxy.GeoIPDB),
	}
}
