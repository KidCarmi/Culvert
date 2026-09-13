package main

import (
	"path/filepath"
	"strings"
)

// cdr_startup_config.go — resolved config for the CDR (Sluice) slice. Pure
// DTO + a single side-effect-free resolver invoked from the initCDR shim.
// The CLI flag values are passed IN as a value struct so the resolver stays
// pure (slice convention pinned by startup_slice_contract_test.go). The
// runtime enable-sentinel (/data/cdr_enabled) is deliberately NOT read here —
// it is a filesystem side effect and belongs to the loader.

// cdrCLIFlags carries the CDR CLI flag values (read in the shim). Zero values
// mean "flag not set" — config file values win.
type cdrCLIFlags struct {
	Enabled     bool
	Endpoint    string
	FailMode    string
	Profile     string
	Mode        string
	TimeoutSec  int
	MaxSizeMB   int
	Fingerprint string
	CertsDir    string
}

// cdrStartupConfig carries the resolved CDR init inputs: the flag-merged
// CDRConfig (sentinel NOT yet applied) and the persistent store paths.
type cdrStartupConfig struct {
	CDR CDRConfig

	// InstancesPath / PoliciesPath are loaded UNCONDITIONALLY (even when CDR
	// is disabled) so GUI enrolls/toggles persist across restarts — a
	// registry with path=="" silently no-ops its Save.
	InstancesPath string
	PoliciesPath  string

	// EnrollReceiptsPath holds the bounded enrollment recovery receipts
	// (2E-C R8, cdr_enroll_receipts.go) — non-secret operation identities
	// that let an unknown-outcome enrollment be resolved after a restart.
	EnrollReceiptsPath string
}

// resolveCDRStartupConfig merges CLI flags over the config file (CLI wins,
// zero values fall through). Pure and deterministic; safe on a zero-value
// *FileConfig. fc.CDR is a value field, so the merge mutates a copy — never
// the caller's FileConfig.
func resolveCDRStartupConfig(fc *FileConfig, dataDir string, flags cdrCLIFlags) cdrStartupConfig {
	cfg := fc.CDR
	if flags.Enabled {
		cfg.Enabled = true
	}
	if ep := firstStr(flags.Endpoint, cfg.Endpoint); ep != "" {
		cfg.Endpoint = ep
	}
	if fm := firstStr(flags.FailMode, cfg.FailMode); fm != "" {
		cfg.FailMode = fm
	}
	if pn := firstStr(flags.Profile, cfg.DefaultProfile); pn != "" {
		cfg.DefaultProfile = pn
	}
	if m := firstStr(flags.Mode, cfg.DefaultMode); m != "" {
		cfg.DefaultMode = m
	}
	if t := firstNonZero(flags.TimeoutSec, cfg.TimeoutSec); t != 0 {
		cfg.TimeoutSec = t
	}
	if sz := firstNonZero(flags.MaxSizeMB, cfg.MaxFileSizeMB); sz != 0 {
		cfg.MaxFileSizeMB = sz
	}
	// TrimSpace the CLI value BEFORE the emptiness check: firstStr treats any
	// non-empty string as "the flag was set", and a whitespace-only
	// -cdr-server-fingerprint would otherwise count as set and silently
	// override (discard) a valid config.yaml pin with a value that itself
	// trims back to empty — weakening TLS verification from
	// fingerprint-pinned to CA-only (or disabling CDR entirely) with nothing
	// pointing at the cause (Codex review, PR #1374).
	if fp := firstStr(strings.TrimSpace(flags.Fingerprint), cfg.ServerFingerprint); fp != "" {
		cfg.ServerFingerprint = fp
	}
	if d := firstStr(flags.CertsDir, cfg.CertsDir); d != "" {
		cfg.CertsDir = d
	}
	return cdrStartupConfig{
		CDR:                cfg,
		InstancesPath:      filepath.Join(dataDir, "cdr_instances.json"),
		PoliciesPath:       filepath.Join(dataDir, "cdr_policies.json"),
		EnrollReceiptsPath: filepath.Join(dataDir, "cdr_enroll_receipts.json"),
	}
}
