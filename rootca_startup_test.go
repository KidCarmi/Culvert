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

// TestResolveRootCAStartupConfig_WhitespaceOnlyCLIPathDoesNotOverrideYAML
// proves a whitespace-only -ca-path value does not silently discard a valid
// config.yaml proxy.ca_path pin. firstStr treats any non-empty string —
// including one that is pure whitespace — as "the CLI flag was set", so an
// untrimmed merge (the same class of defect fixed for
// -cdr-server-fingerprint, see cdr_startup_config.go) would pass the
// whitespace value straight to certMgr.LoadOrInitCA as a literal path. That
// either creates a bogus bundle at a nonsensical location or fails to load
// (most container working directories are read-only), and a load failure is
// non-fatal by design (rootca_startup.go initInspectionCA) — it silently
// disables SSL inspection fail-open, with no earlier warning that the
// configured -ca-path was ever discarded.
func TestResolveRootCAStartupConfig_WhitespaceOnlyCLIPathDoesNotOverrideYAML(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.CAPath = "/from/config/ca.bundle"

	got := resolveRootCAStartupConfig(fc, "   ", "pass")
	if got.Path != "/from/config/ca.bundle" {
		t.Errorf("Path = %q, want the config.yaml pin %q preserved (a whitespace-only CLI flag must not override it)",
			got.Path, "/from/config/ca.bundle")
	}
}

// TestResolveRootCAStartupConfig_NonBlankCLIPathStillWins is the companion
// sanity check: a genuinely non-blank CLI value must still take precedence
// over config.yaml, unaffected by the whitespace-handling fix above.
func TestResolveRootCAStartupConfig_NonBlankCLIPathStillWins(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.CAPath = "/from/config/ca.bundle"

	got := resolveRootCAStartupConfig(fc, "/from/cli/ca.bundle", "pass")
	if got.Path != "/from/cli/ca.bundle" {
		t.Errorf("Path = %q, want the CLI value %q to win", got.Path, "/from/cli/ca.bundle")
	}
}

// TestResolveRootCAStartupConfig_SurroundingWhitespaceInAGenuinePathIsPreservedVerbatim
// guards the other direction of the whitespace fix (Codex review, PR #1415):
// a filename is legally allowed to begin or end with whitespace on
// supported filesystems (quotable on the CLI), so TrimSpace must be used
// ONLY to decide whether the CLI flag counts as "set" — never applied to
// the stored value itself. Silently trimming a genuinely intended path
// would redirect certMgr.LoadOrInitCA to a different, likely-absent path,
// which mints and persists a brand-new root instead of loading the
// configured trust anchor — breaking inspection for every client that
// already trusts the original CA.
func TestResolveRootCAStartupConfig_SurroundingWhitespaceInAGenuinePathIsPreservedVerbatim(t *testing.T) {
	const padded = "  /from/cli/ ca.bundle  "
	fc := &FileConfig{}
	fc.Proxy.CAPath = "/from/config/ca.bundle"

	got := resolveRootCAStartupConfig(fc, padded, "pass")
	if got.Path != padded {
		t.Errorf("Path = %q, want the CLI value preserved verbatim (including surrounding whitespace) %q", got.Path, padded)
	}
}
