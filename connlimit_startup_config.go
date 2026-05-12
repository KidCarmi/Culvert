package main

// connlimit_startup_config.go — resolved config for the
// connection-limit + IP-filter + rate-limit startup slice (P4.2 / S1).
// Pure DTO + a single side-effect-free resolver invoked from the
// initConnAndRateLimit shim. No globals are read or written here.

// connAndRateLimitStartupConfig carries the resolved inputs for the
// three security limiters configured at startup. The loader consumes
// this struct and owns the side effects on connLimiter, ipf, rl, and
// the optional rate-limit cleanup goroutine.
type connAndRateLimitStartupConfig struct {
	// MaxConnsPerIP is the per-source-IP connection cap. 0 disables
	// connLimiter (no Enable call). No CLI flag exists — YAML-only,
	// so the resolver reads fc.Security.MaxConnsPerIP directly.
	MaxConnsPerIP int

	// IPMode is the IP-filter mode ("allow" / "deny" / ""). ""
	// skips ipf setup entirely. Pre-resolved upstream by
	// loadFileConfigAndFlags from the CLI flag and FileConfig.
	IPMode string

	// IPList is the raw entries appended to ipf via ipf.Add. The
	// resolver aliases fc.Security.IPList — the loader iterates and
	// warn-skips invalid entries. No CLI flag exists — YAML-only.
	IPList []string

	// RateLimitRPM is the per-IP request-per-minute limit. 0
	// disables both rl.Configure AND the 5-minute cleanup goroutine.
	// Pre-resolved upstream by loadFileConfigAndFlags.
	RateLimitRPM int
}

// resolveConnAndRateLimitStartupConfig is the single startup-time
// reader of fc.Security.{MaxConnsPerIP,IPList} plus the pre-resolved
// IPMode / RateLimitRPM. resolvedIPMode and resolvedRateLimitRPM are
// the values already computed by loadFileConfigAndFlags for s.ipModeVal
// and s.rlRPM — passing them through keeps a single source of truth
// for the CLI / FileConfig precedence rules.
//
// Pure and deterministic; safe on a zero-value *FileConfig.
func resolveConnAndRateLimitStartupConfig(fc *FileConfig, resolvedIPMode string, resolvedRateLimitRPM int) connAndRateLimitStartupConfig {
	return connAndRateLimitStartupConfig{
		MaxConnsPerIP: fc.Security.MaxConnsPerIP,
		IPMode:        resolvedIPMode,
		IPList:        fc.Security.IPList,
		RateLimitRPM:  resolvedRateLimitRPM,
	}
}
