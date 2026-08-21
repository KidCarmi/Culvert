package main

// legacy_auth_providers_startup.go — startup-time loader for the legacy
// LDAP / OIDC-introspection provider slice (PR3 expansion, Batch 2).
//
// Preserves the original precedence: LDAP wins when configured, then
// OIDC introspection, then fall-through to local bcrypt (status-log only).

import "fmt"

// loadLegacyAuthProviders applies cfg. Returns an error that already
// carries the correct "LDAP config error:" or "OIDC config error:" prefix
// — the shim log.Fatalf's it verbatim to match the pre-pilot message.
//
// The parameter is named c to avoid shadowing the package-global cfg
// (*Config) used internally via cfg.SetProvider.
func loadLegacyAuthProviders(c legacyAuthProvidersStartupConfig) error {
	if c.LDAP.URL != "" {
		// Retain the resolved YAML block (read-only) so the admin API can
		// summarize it and offer the explicit registry import (ADR-0025).
		setLegacyLDAPYAMLConfig(c.LDAP)
		// ADR-0025 authority rule: an enabled LDAP profile in the IdP registry
		// (loaded by initUIAccessPolicy, which runs before this loader) is the
		// SOLE operational LDAP authority. The legacy YAML block is then not
		// wired at all — never merged field-by-field, never a second
		// authenticator — and the customer's YAML file is left untouched.
		// The one guarded exception (canShadowLegacyLDAP) keeps the legacy
		// provider armed when deactivating it would flip cfg.IsConfigured()
		// false and fail the admin-UI setup gate OPEN.
		if idpRegistry != nil && idpRegistry.HasEnabledLDAP() && canShadowLegacyLDAP() {
			logWarnf("Auth: legacy YAML ldap config is SHADOWED by an enabled LDAP identity provider in the IdP registry — " +
				"the registry is authoritative and the YAML ldap block is ignored for authentication " +
				"(remove it, or manage LDAP from Objects → Identity Providers)")
			return nil
		}
		ldapProvider, err := NewLDAPAuth(c.LDAP)
		if err != nil {
			return fmt.Errorf("LDAP config error: %w", err)
		}
		cfg.SetProvider(ldapProvider)
		if idpRegistry != nil && idpRegistry.HasEnabledLDAP() {
			// canShadowLegacyLDAP was false: no local admin account and not the
			// open default, so the legacy provider stays wired as the setup-gate
			// / SOCKS5 anchor. The registry LDAP provider still takes precedence
			// in the proxy's Basic-credential chain (registry providers are
			// tried first), so the registry remains operationally authoritative.
			logWarnf("Auth: an enabled registry LDAP identity provider exists alongside the legacy YAML ldap config; " +
				"the registry takes precedence for proxy authentication. The legacy provider remains wired only because " +
				"no local admin account exists — create one and restart to retire the YAML provider")
		}
		logger.Printf("Auth: LDAP (%s, base=%s)", c.LDAP.URL, c.LDAP.BaseDN)
		return nil
	}
	if c.OIDC.IntrospectionURL != "" {
		oidcProvider, err := NewOIDCAuth(c.OIDC)
		if err != nil {
			return fmt.Errorf("OIDC config error: %w", err)
		}
		cfg.SetProvider(oidcProvider)
		if c.OIDC.LoginURL != "" {
			SetOIDCLoginURL(c.OIDC.LoginURL)
			logger.Printf("Auth: OIDC login redirect: %s", c.OIDC.LoginURL)
		}
		logger.Printf("Auth: OIDC introspection (%s)", c.OIDC.IntrospectionURL)
		return nil
	}
	if c.LocalUser != "" {
		logger.Printf("Auth: local bcrypt (user=%s)", c.LocalUser)
	}
	return nil
}
