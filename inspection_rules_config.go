package main

// inspection_rules_config.go — resolved configuration for the inspection
// rules pilot (PR3, Phase 1). Contains the shape and the resolver only.
//
// Pilot scope (do not widen without approval):
//   - owns: the four fc.Proxy.{SSLBypass{File,Patterns},ContentScan{File,Patterns}}
//           fields during startup
//   - does NOT own: the sslBypass / dpiScanner package globals, or the
//           config export/import / runtime paths that also read those fields
//
// Every field is a value type. No pointers to mutable state, no methods,
// no interfaces. This is a DTO — a fixed audit point between FileConfig
// and the inspection-rules loader.

// inspectionRulesConfig carries the resolved configuration required to
// initialise the SSL bypass matcher (MITM decision) and the DPI content
// scanner (response-body inspection). "Resolved" means CLI-flag → file-
// config precedence has already been applied upstream by
// loadFileConfigAndFlags; this struct is consumed as-is.
type inspectionRulesConfig struct {
	// SSLBypassFile is the persistent JSON path for runtime-managed SSL
	// bypass entries. Empty means in-memory only (no /api/ssl-bypass
	// writes persist across restart).
	SSLBypassFile string
	// SSLBypassPatterns are seed patterns applied when SSLBypassFile is
	// empty or when the loaded file contains zero entries. They are
	// persisted back to the file on first run.
	SSLBypassPatterns []string
	// ContentScanFile is the persistent JSON path for DPI patterns.
	// Empty means in-memory only.
	ContentScanFile string
	// ContentScanPatterns are seed patterns applied when ContentScanFile
	// is empty or when the loaded file contains zero entries.
	ContentScanPatterns []string
}

// resolveInspectionRulesConfig extracts the inspection-rules slice from the
// raw FileConfig. Intentionally the ONLY startup-time reader of the four
// fc.Proxy.{SSLBypass{File,Patterns},ContentScan{File,Patterns}} fields —
// future schema changes land here.
func resolveInspectionRulesConfig(fc *FileConfig) inspectionRulesConfig {
	return inspectionRulesConfig{
		SSLBypassFile:       fc.Proxy.SSLBypassFile,
		SSLBypassPatterns:   fc.Proxy.SSLBypassPatterns,
		ContentScanFile:     fc.Proxy.ContentScanFile,
		ContentScanPatterns: fc.Proxy.ContentScanPatterns,
	}
}
