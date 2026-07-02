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

	got := resolveCDRStartupConfig(fc, cdrCLIFlags{
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

	got := resolveCDRStartupConfig(fc, cdrCLIFlags{})
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
	_ = resolveCDRStartupConfig(fc, cdrCLIFlags{Endpoint: "cli:9000", Enabled: true})
	if fc.CDR.Endpoint != "config:9000" || fc.CDR.Enabled {
		t.Errorf("resolver mutated the caller's FileConfig: %+v", fc.CDR)
	}
}
