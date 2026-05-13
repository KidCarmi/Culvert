package main

// auth_startup_config.go — resolved config for the auth startup
// slice (P4.4 / S1). Covers the caller-side mutation of the `cfg`
// singleton that `initAuth` performs at startup:
//   - cfg.ProxyPort + cfg.UIPort (unguarded exported fields)
//   - cfg.SetAuth (local bcrypt admin credentials)
//   - cfg.SetUIUsersFile + cfg.LoadUIUsersFile (persisted UI users)
//
// Out of scope (each owned elsewhere): LDAP / OIDC (legacy_auth_
// providers slice + IdP registry), SAML / OIDC-flow (runtime IdP
// registry in auth_idp.go), session (session_startup slice), MFA /
// TOTP (admin API), middleware routing, RBAC, and the `cfg`
// singleton's ownership / lock / surface.

// authStartupConfig carries the resolved inputs for initAuth.
// Value-type DTO; no methods.
type authStartupConfig struct {
	// ProxyPort is assigned to cfg.ProxyPort. Set pre-goroutine and
	// read by the admin UI config display path.
	ProxyPort int

	// UIPort is assigned to cfg.UIPort.
	UIPort int

	// AuthUser is the local bcrypt admin username — passed to
	// cfg.SetAuth. "" plus AuthPass "" clears local auth (matches
	// the pre-extraction behaviour and existing test cleanup
	// patterns in d0_helpers_test.go / pkce_ui2_test.go).
	AuthUser string

	// AuthPass is the plain admin password. bcrypt hashing runs
	// inside cfg.SetAuth — the slice never holds plaintext beyond
	// the immediate call.
	AuthPass string

	// UIUsersFile is the path to the persisted UI users JSON. ""
	// skips the SetUIUsersFile / LoadUIUsersFile pair entirely.
	UIUsersFile string
}

// resolveAuthStartupConfig is a trivial constructor: all five
// inputs are already-resolved scalars from startupState. Four come
// from loadFileConfigAndFlags' CLI/FileConfig precedence (s.pPort,
// s.uPort, s.authU, s.authP). The fifth is the CLI pointer deref
// (*s.uiUsersFile) — no FileConfig counterpart exists, so the
// resolver does not consult *FileConfig (pac convention).
//
// Pure; deterministic; safe on all-zero inputs.
func resolveAuthStartupConfig(proxyPort, uiPort int, authUser, authPass, uiUsersFile string) authStartupConfig {
	return authStartupConfig{
		ProxyPort:   proxyPort,
		UIPort:      uiPort,
		AuthUser:    authUser,
		AuthPass:    authPass,
		UIUsersFile: uiUsersFile,
	}
}
