package main

// rootca_startup_test.go — per-slice tests for the Root-CA startup slice
// (resolver precedence). The loader's collaborators (certMgr load/init,
// rotation) are owned and tested by the ca.go suites.

import "testing"

func TestResolveRootCAStartupConfig_CLIPathWins(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.CAPath = "/from/config/ca.bundle"
	got := resolveRootCAStartupConfig(fc, "/from/cli/ca.bundle", "pass")
	if got.Path != "/from/cli/ca.bundle" {
		t.Errorf("Path = %q, want the CLI value (CLI wins over config)", got.Path)
	}
	if got.Passphrase != "pass" {
		t.Errorf("Passphrase = %q, want pass", got.Passphrase)
	}
}

func TestResolveRootCAStartupConfig_ConfigFallbackAndEmpty(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.CAPath = "/from/config/ca.bundle"
	if got := resolveRootCAStartupConfig(fc, "", ""); got.Path != "/from/config/ca.bundle" {
		t.Errorf("Path = %q, want the config fallback", got.Path)
	}
	// Both empty → ephemeral in-memory CA.
	if got := resolveRootCAStartupConfig(&FileConfig{}, "", ""); got.Path != "" {
		t.Errorf("Path = %q, want empty (in-memory CA)", got.Path)
	}
}
