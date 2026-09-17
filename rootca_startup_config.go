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
	// TrimSpace the CLI value BEFORE the emptiness check: firstStr treats any
	// non-empty string as "the flag was set", and a whitespace-only -ca-path
	// would otherwise count as set and silently override (discard) a valid
	// config.yaml proxy.ca_path pin with a value that is not a usable path.
	// certMgr.LoadOrInitCA then either creates a bogus bundle at a
	// nonsensical location or fails to load — and a load failure is
	// non-fatal by design (rootca_startup.go initInspectionCA), so it
	// silently disables SSL inspection fail-open with nothing pointing at
	// the cause (same defect class fixed for -cdr-server-fingerprint, see
	// cdr_startup_config.go).
	return rootCAStartupConfig{
		Path:       firstStr(strings.TrimSpace(cliPath), fc.Proxy.CAPath),
		Passphrase: passphraseEnvVal,
	}
}
