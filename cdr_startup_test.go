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
