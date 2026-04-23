package main

// inspection_rules.go — startup-time loader for the inspection rules
// pilot (PR3, Phase 1).
//
// Responsibility:
//   - read an already-resolved inspectionRulesConfig
//   - populate the package-global sslBypass and dpiScanner stores
//   - return errors instead of calling logger.Fatalf; the caller (main)
//     decides fail-fast vs degrade
//
// The two stores remain package-global for this pilot. Moving them into a
// subpackage is a follow-up decision dependent on this pilot's outcome.

import "fmt"

// loadInspectionRules initialises the SSL bypass matcher and the DPI
// content scanner from cfg. Returns the first unrecoverable error; partial
// state is acceptable (the matcher/scanner are both internally safe to use
// with empty contents).
func loadInspectionRules(cfg inspectionRulesConfig) error {
	if err := loadSSLBypass(cfg); err != nil {
		return fmt.Errorf("ssl bypass: %w", err)
	}
	if err := loadDPIScanner(cfg); err != nil {
		return fmt.Errorf("dpi scanner: %w", err)
	}
	return nil
}

// loadSSLBypass populates the package-global sslBypass matcher. Behaviour
// mirrors the pre-pilot init body byte-for-byte: when a file path is set
// we load it, then seed from config patterns if the file is empty; when
// no file path is set we seed from config patterns directly.
func loadSSLBypass(cfg inspectionRulesConfig) error {
	if cfg.SSLBypassFile != "" {
		if err := sslBypass.Load(cfg.SSLBypassFile); err != nil {
			return fmt.Errorf("file %q: %w", cfg.SSLBypassFile, err)
		}
		if len(sslBypass.List()) == 0 && len(cfg.SSLBypassPatterns) > 0 {
			if err := sslBypass.Set(cfg.SSLBypassPatterns); err != nil {
				return fmt.Errorf("seed patterns: %w", err)
			}
			sslBypass.Save() // persist seed patterns on first run
		}
		logger.Printf("SSLBypass: %d pattern(s) (file: %s)", len(sslBypass.List()), cfg.SSLBypassFile)
		return nil
	}
	if len(cfg.SSLBypassPatterns) > 0 {
		if err := sslBypass.Set(cfg.SSLBypassPatterns); err != nil {
			return fmt.Errorf("patterns: %w", err)
		}
		logger.Printf("SSLBypass: %d pattern(s) (in-memory; set ssl_bypass_file for dynamic management)", len(sslBypass.List()))
	}
	return nil
}

// loadDPIScanner populates the package-global dpiScanner. Same file-first /
// seed-if-empty pattern as loadSSLBypass.
func loadDPIScanner(cfg inspectionRulesConfig) error {
	if cfg.ContentScanFile != "" {
		if err := dpiScanner.Load(cfg.ContentScanFile); err != nil {
			return fmt.Errorf("file %q: %w", cfg.ContentScanFile, err)
		}
		if len(dpiScanner.List()) == 0 && len(cfg.ContentScanPatterns) > 0 {
			if err := dpiScanner.Set(cfg.ContentScanPatterns); err != nil {
				return fmt.Errorf("seed patterns: %w", err)
			}
			dpiScanner.Save()
		}
		logger.Printf("DPIScan: %d pattern(s) (file: %s)", len(dpiScanner.List()), cfg.ContentScanFile)
		return nil
	}
	if len(cfg.ContentScanPatterns) > 0 {
		if err := dpiScanner.Set(cfg.ContentScanPatterns); err != nil {
			return fmt.Errorf("patterns: %w", err)
		}
		logger.Printf("DPIScan: %d pattern(s) (in-memory; set content_scan_file for persistence)", len(dpiScanner.List()))
	}
	return nil
}
