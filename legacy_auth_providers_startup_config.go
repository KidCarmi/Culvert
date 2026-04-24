package main

// legacy_auth_providers_startup_config.go — resolved config for the
// legacy-auth-provider slice (PR3 expansion, Batch 2). Covers the
// LDAP / OIDC-introspection providers that the generic IdP registry is
// meant to supersede but which remain supported for back-compat.

// legacyAuthProvidersStartupConfig carries the resolved legacy-auth
// configuration. Value-type DTO; no methods.
type legacyAuthProvidersStartupConfig struct {
	// LDAP is the LDAP provider configuration. Precedence: when
	// LDAP.URL is non-empty, LDAP wins over OIDC.
	LDAP LDAPConfig
	// OIDC is the OIDC-introspection provider configuration.
	OIDC OIDCConfig
	// LocalUser is the already-resolved local bcrypt username (from
	// s.authU). Used for a status log line only — no auth decision.
	LocalUser string
}

// resolveLegacyAuthProvidersStartupConfig is the single startup-time
// reader of fc.LDAP and (in this slice's context) fc.OIDC for the
// legacy-introspection path. authU is the already-resolved local bcrypt
// username, passed in so the resolver stays independent of startupState.
func resolveLegacyAuthProvidersStartupConfig(fc *FileConfig, authU string) legacyAuthProvidersStartupConfig {
	return legacyAuthProvidersStartupConfig{
		LDAP:      fc.LDAP,
		OIDC:      fc.OIDC,
		LocalUser: authU,
	}
}
