package main

// logstore_startup_config.go — resolved config for the persistent log-store
// slice. Pure DTO + a single side-effect-free resolver invoked from the
// initLogStore shim. No globals are read or written here; env values are
// passed IN by the shim so the resolver stays pure (slice convention pinned
// by startup_slice_contract_test.go).

import "path/filepath"

// logStoreStartupConfig carries the resolved log-store init inputs. The
// loader consumes this struct and owns the actual global writes +
// enableLogStore side effect.
type logStoreStartupConfig struct {
	// Dir is where the store lives. Config log_store_path wins; otherwise
	// it defaults under the data dir so GUI-enablement needs no YAML.
	Dir string

	// Passphrase is the encryption-at-rest key material: the dedicated
	// CULVERT_LOG_PASSPHRASE, falling back to the CA passphrase (already
	// set when SSL-inspecting — the case where URL logging is most
	// sensitive). Empty = encryption off.
	Passphrase string

	// SeedEnable is true only when log_store_path is set in config
	// (back-compat): the store opens at startup. Otherwise it stays off
	// until the admin enables it from the UI; LoadAdminSettings (later in
	// startup) restores the GUI-saved enabled state.
	SeedEnable bool

	// RetentionDays / RetentionMaxGB are passed through to enableLogStore
	// when seed-enabled.
	RetentionDays  int
	RetentionMaxGB float64
}

// resolveLogStoreStartupConfig is the single startup-time reader of
// fc.LogStorePath / fc.LogRetention*. dataDirVal and the two passphrase env
// values are passed in (never read here) so the resolver is pure and
// deterministic; safe on a zero-value *FileConfig.
func resolveLogStoreStartupConfig(fc *FileConfig, dataDirVal, logPassEnvVal, caPassEnvVal string) logStoreStartupConfig {
	dir := fc.LogStorePath
	if dir == "" {
		dir = filepath.Join(dataDirVal, "logstore")
	}
	pass := logPassEnvVal
	if pass == "" {
		pass = caPassEnvVal
	}
	return logStoreStartupConfig{
		Dir:            dir,
		Passphrase:     pass,
		SeedEnable:     fc.LogStorePath != "",
		RetentionDays:  fc.LogRetentionDays,
		RetentionMaxGB: fc.LogRetentionMaxGB,
	}
}
