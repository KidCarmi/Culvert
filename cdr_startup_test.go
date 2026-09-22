package main

// cdr_startup_test.go — per-slice tests for the CDR startup slice (resolver
// CLI-over-config merge). The loader's collaborators (sentinel, stores,
// client, poller) are owned and tested by the cdr_*.go suites.

import "testing"

func TestResolveCDRStartupConfig_FlagsWinOverConfig(t *testing.T) {
	fc := &FileConfig{}
	fc.CDR.Endpoint = "config:9000"
	fc.CDR.FailMode = "fail-open"
	fc.CDR.TimeoutSec = 10

	got := resolveCDRStartupConfig(fc, defaultDataDir, cdrCLIFlags{
		Enabled:    true,
		Endpoint:   "cli:9000",
		TimeoutSec: 30,
	})
	if !got.CDR.Enabled {
		t.Error("CLI --cdr-enabled must enable")
	}
	if got.CDR.Endpoint != "cli:9000" {
		t.Errorf("Endpoint = %q, want the CLI value", got.CDR.Endpoint)
	}
	if got.CDR.TimeoutSec != 30 {
		t.Errorf("TimeoutSec = %d, want 30 (CLI wins)", got.CDR.TimeoutSec)
	}
	if got.CDR.FailMode != "fail-open" {
		t.Errorf("FailMode = %q, want the config fallback", got.CDR.FailMode)
	}
}

// TestResolveCDRStartupConfig_YAMLTimeoutBelowFloorSurvivesCLIEnable pins the
// exact scenario a PR #1465 review comment identified: config.yaml's
// validateCDR (config.go) skips the WHOLE cdr block — including the
// timeout_sec range check — whenever cdr.enabled is false, so a config with
// cdr.enabled: false and an out-of-range timeout_sec (e.g. carried over from
// a disabled draft, or a value an operator plans to flip on later) passes
// YAML validation untouched. If CDR is then enabled via -cdr-enabled with
// -cdr-timeout-sec left unset (0, "not passed" in this package's
// firstNonZero convention), resolveCDRStartupConfig merges in the
// still-unvalidated YAML timeout_sec verbatim. Validating only the raw CLI
// flag (initCDR's first shape) never sees this — the flag itself is 0/valid;
// the invalid value is hiding in the config-fallthrough side of the merge.
// initCDR must therefore validate the RESOLVED value this test proves is
// produced, not just the CLI flag in isolation.
func TestResolveCDRStartupConfig_YAMLTimeoutBelowFloorSurvivesCLIEnable(t *testing.T) {
	fc := &FileConfig{}
	fc.CDR.Enabled = false // validateCDR() never inspects TimeoutSec below
	fc.CDR.Endpoint = "sluice:8443"
	fc.CDR.TimeoutSec = 3 // below the 30s floor, but unreachable by validateCDR while disabled
	if err := fc.validate(); err != nil {
		t.Fatalf("validate() rejected a disabled CDR block with an out-of-range timeout_sec (should be unchecked while disabled): %v", err)
	}

	got := resolveCDRStartupConfig(fc, defaultDataDir, cdrCLIFlags{
		Enabled:    true, // -cdr-enabled
		TimeoutSec: 0,    // -cdr-timeout-sec not passed
	})
	if !got.CDR.Enabled {
		t.Fatal("CLI --cdr-enabled must enable")
	}
	if got.CDR.TimeoutSec != 3 {
		t.Fatalf("TimeoutSec = %d, want 3 (the unvalidated YAML value falling through)", got.CDR.TimeoutSec)
	}
	// The value initCDR must catch: resolved, enabled, and out of range —
	// even though the raw CLI flag alone (0) is perfectly valid.
	if msg := validCDRTimeoutSec(got.CDR.TimeoutSec); msg == "" {
		t.Fatal("validCDRTimeoutSec accepted the resolved TimeoutSec=3, want a rejection — this is the value initCDR must validate")
	}
}

func TestResolveCDRStartupConfig_ConfigFallthroughAndPaths(t *testing.T) {
	fc := &FileConfig{}
	fc.CDR.Enabled = true
	fc.CDR.DefaultProfile = "strict"

	got := resolveCDRStartupConfig(fc, defaultDataDir, cdrCLIFlags{})
	if !got.CDR.Enabled || got.CDR.DefaultProfile != "strict" {
		t.Errorf("config values must fall through: %+v", got.CDR)
	}
	if got.InstancesPath != "/data/cdr_instances.json" || got.PoliciesPath != "/data/cdr_policies.json" {
		t.Errorf("store paths = (%q, %q)", got.InstancesPath, got.PoliciesPath)
	}
}

func TestResolveCDRStartupConfig_DoesNotMutateFileConfig(t *testing.T) {
	fc := &FileConfig{}
	fc.CDR.Endpoint = "config:9000"
	_ = resolveCDRStartupConfig(fc, defaultDataDir, cdrCLIFlags{Endpoint: "cli:9000", Enabled: true})
	if fc.CDR.Endpoint != "config:9000" || fc.CDR.Enabled {
		t.Errorf("resolver mutated the caller's FileConfig: %+v", fc.CDR)
	}
}

// TestResolveCDRStartupConfig_WhitespaceOnlyCLIFingerprintDoesNotOverrideYAML
// proves a whitespace-only -cdr-server-fingerprint value does not silently
// discard a valid config.yaml pin (Codex review, PR #1374): firstStr treats
// ANY non-empty string — including one that is pure whitespace — as "the CLI
// flag was set", so an untrimmed merge would replace a real pin with a value
// that itself trims back to empty, weakening TLS verification from
// fingerprint-pinned to CA-only (or disabling CDR entirely, depending on
// whether a CA cert is also configured) with nothing pointing at the cause.
func TestResolveCDRStartupConfig_WhitespaceOnlyCLIFingerprintDoesNotOverrideYAML(t *testing.T) {
	const yamlPin = "abababababababababababababababababababababababababababababab" // #nosec G101 -- synthetic 64-hex fixture, not a real credential
	fc := &FileConfig{}
	fc.CDR.ServerFingerprint = yamlPin

	got := resolveCDRStartupConfig(fc, defaultDataDir, cdrCLIFlags{Fingerprint: "   "})
	if got.CDR.ServerFingerprint != yamlPin {
		t.Errorf("ServerFingerprint = %q, want the config.yaml pin %q preserved (a whitespace-only CLI flag must not override it)",
			got.CDR.ServerFingerprint, yamlPin)
	}
}

// TestResolveCDRStartupConfig_NonBlankCLIFingerprintStillWins is the
// companion sanity check: a genuinely non-blank CLI value must still take
// precedence over config.yaml, unaffected by the whitespace-handling fix
// above.
func TestResolveCDRStartupConfig_NonBlankCLIFingerprintStillWins(t *testing.T) {
	const cliPin = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" // #nosec G101 -- synthetic 64-hex fixture, not a real credential
	fc := &FileConfig{}
	fc.CDR.ServerFingerprint = "abababababababababababababababababababababababababababababab"

	got := resolveCDRStartupConfig(fc, defaultDataDir, cdrCLIFlags{Fingerprint: cliPin})
	if got.CDR.ServerFingerprint != cliPin {
		t.Errorf("ServerFingerprint = %q, want the CLI value %q to win", got.CDR.ServerFingerprint, cliPin)
	}
}
