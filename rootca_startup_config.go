package main

import "strings"

// rootca_startup_config.go — resolved config for the Root-CA slice (the CA
// used for SSL inspection). Pure DTO + a single side-effect-free resolver
// invoked from the initRootCA shim. The passphrase env value is passed IN by
// the shim so the resolver stays pure (slice convention pinned by
// startup_slice_contract_test.go).

// rootCAStartupConfig carries the resolved Root-CA init inputs. The loader
// consumes this struct and owns the CA load/init, the caRuntime publish, and
// the auto-rotation goroutine.
type rootCAStartupConfig struct {
	// Path is the CA bundle location (CLI -ca-path wins over config
	// proxy.ca_path). "" = ephemeral in-memory CA (no persistence).
	Path string

	// Passphrase encrypts the CA bundle at rest (CULVERT_CA_PASSPHRASE,
	// read from env in the shim so it never appears in CLI history).
	// Empty = unencrypted / in-memory.
	Passphrase string
}

// resolveRootCAStartupConfig applies the CLI-over-config path precedence.
// Pure and deterministic; safe on a zero-value *FileConfig.
func resolveRootCAStartupConfig(fc *FileConfig, cliPath, passphraseEnvVal string) rootCAStartupConfig {
	// TrimSpace is used ONLY to decide whether the CLI flag was "set": a
	// whitespace-only -ca-path (e.g. from a wrapper script that always
	// passes -ca-path="$MAYBE_EMPTY_VAR") must not count as set and silently
	// override (discard) a valid config.yaml proxy.ca_path pin. The RAW,
	// untrimmed cliPath is what gets stored once it is chosen — a filename
	// is legally allowed to begin or end with whitespace on supported
	// filesystems (quotable on the CLI), and silently trimming a genuinely
	// intended path would redirect certMgr.LoadOrInitCA to a different,
	// likely-absent path: LoadOrInitCA mints and persists a brand-new root
	// in that case rather than loading the configured trust anchor,
	// breaking inspection for every client that already trusts the
	// original CA (Codex review, PR #1415). This mirrors the
	// -cdr-server-fingerprint fix (cdr_startup_config.go) in spirit — CLI
	// wins only when it is genuinely non-blank — but a fingerprint is
	// safely normalized by trimming, while a filesystem path is not.
	path := fc.Proxy.CAPath
	if strings.TrimSpace(cliPath) != "" {
		path = cliPath
	}
	return rootCAStartupConfig{
		Path:       path,
		Passphrase: passphraseEnvVal,
	}
}
