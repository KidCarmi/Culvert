package main

// session_startup_config.go — resolved config for the session-management
// slice (PR3 expansion, Batch 2): HMAC secret + revocations file + TTL.

// sessionStartupConfig carries the resolved session-layer configuration
// consumed at startup. Value-type DTO; no methods.
type sessionStartupConfig struct {
	// Secret is the configured HMAC signing secret (empty ⇒ keep the
	// random key seeded by initSessionSecret()).
	Secret string
	// RevocationsFile is the persistence path for the revocation list.
	// Empty ⇒ in-memory only; revocations reset on restart.
	RevocationsFile string
	// TimeoutHours is the admin-UI session lifetime. 0 ⇒ use defaults.
	TimeoutHours int
}

// resolveSessionStartupConfig is the single startup-time reader of
// fc.SessionSecret and fc.SessionTimeoutHours. revocationsFlag and
// sessionHrsFlag are the dereferenced --revocations-file and
// --session-timeout CLI overrides.
func resolveSessionStartupConfig(fc *FileConfig, revocationsFlag string, sessionHrsFlag int) sessionStartupConfig {
	return sessionStartupConfig{
		Secret:          fc.SessionSecret,
		RevocationsFile: revocationsFlag,
		TimeoutHours:    firstNonZero(sessionHrsFlag, fc.SessionTimeoutHours),
	}
}
