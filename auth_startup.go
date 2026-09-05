package main

// auth_startup.go — startup-time loader for the auth slice
// (P4.4 / S1). Mirrors the pre-extraction body of initAuth
// (main.go:508–528), parameterized, plus one closed gap: a
// validateAuthStartupCredentials gate (nightly QA finding) ahead of
// cfg.SetAuth so a non-empty -user/-pass or auth.user/auth.pass that
// fails validatePasswordComplexity is rejected fatally at startup
// instead of silently creating a "configured" admin account that
// bypasses the same floor every other credential entry point
// (apiSetupComplete, the admin config-auth API, --reset-password)
// already enforces.
//
// Behaviour invariants preserved:
//   - cfg.ProxyPort and cfg.UIPort assigned directly (the two
//     fields are exported and unguarded; safe to write pre-
//     goroutine, which is where this loader runs).
//   - cfg.SetAuth is invoked with the resolved AuthUser/AuthPass.
//     log.Fatalf on error — sole fatal site, byte-equivalent to
//     the pre-extraction body. The only documented SetAuth error
//     is bcrypt.GenerateFromPassword on a >72-byte password.
//   - UI users file load is guarded by UIUsersFile != "". When
//     non-empty: cfg.SetUIUsersFile + cfg.LoadUIUsersFile; load
//     errors are logged at warn level (non-fatal) and the success
//     line emits ONLY when cfg.AuthEnabled() is true after load.
//   - Log strings unchanged so operators see the same startup
//     banner and the same fallback warning.
//   - The `cfg` package-global singleton, its lock, and its
//     surface are untouched — this slice only wraps callers of
//     its existing methods.

import "log"

// loadAuth applies auth to the package-global cfg singleton.
// Parameter is named `auth` rather than `cfg` to avoid shadowing
// the package-global *Config singleton declared at store.go:1107.
func loadAuth(auth authStartupConfig) {
	cfg.ProxyPort = auth.ProxyPort
	cfg.UIPort = auth.UIPort
	if err := validateAuthStartupCredentials(auth); err != nil {
		log.Fatalf("Rejecting -user/-pass (or auth.user/auth.pass): %v", err)
	}
	if err := cfg.SetAuth(auth.AuthUser, auth.AuthPass); err != nil {
		log.Fatalf("Failed to set auth: %v", err)
	}

	if auth.UIUsersFile != "" {
		cfg.SetUIUsersFile(auth.UIUsersFile)
		if err := cfg.LoadUIUsersFile(); err != nil {
			logger.Printf("UIUsers: failed to load %s: %v", auth.UIUsersFile, err)
		} else if cfg.AuthEnabled() {
			logger.Printf("UIUsers: loaded from %s", auth.UIUsersFile)
		}
	}
	warnOversizeConfiguredUsernames()
}

// warnOversizeConfiguredUsernames reports admin accounts whose name exceeds the
// login endpoint's maxUsernameLen bound (CHAOS-58).
//
// Such an account still authenticates — rejectOversizeLoginUser exempts any
// configured name — so this is deliberately a WARNING and never fatal: the
// stores have never bounded the name, so failing the boot would brick an
// appliance whose config was legal when it was written, over a hardening
// change. The operator is told once, at startup, so they learn it here rather
// than from a login that behaves unlike every other account.
func warnOversizeConfiguredUsernames() {
	for _, u := range cfg.ListUIUsers() {
		if len(u.Username) > maxUsernameLen {
			logWarnf("Auth: admin username is %d bytes, above the %d-byte login limit — "+
				"it still authenticates, but rename it: every other credential entry point caps at 64",
				len(u.Username), maxUsernameLen)
		}
	}
}
