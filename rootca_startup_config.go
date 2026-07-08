package main

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
	return rootCAStartupConfig{
		Path:       firstStr(cliPath, fc.Proxy.CAPath),
		Passphrase: passphraseEnvVal,
	}
}
