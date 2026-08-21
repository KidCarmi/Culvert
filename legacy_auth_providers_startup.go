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
		// ADR-0025 single-authority rule (P1-2): the legacy YAML block is
		// never wired once the node has CUT OVER to the IdP registry — either
		// durably (the legacy_ldap_retired sentinel; loaded from
		// admin_settings.json later in boot and re-enforced there, or set by
		// a prior test/boot in-process) or observed right now via an enabled
		// registry LDAP profile (the registry loads before this shim; the
		// observation marks the durable sentinel). The customer's YAML file
		// is never modified; after cutover it is import source material only.
		if legacyLDAPRetired() || (idpRegistry != nil && idpRegistry.HasEnabledLDAP()) {
			markLegacyLDAPRetired("enabled LDAP identity provider present in the IdP registry at startup")
			logWarnf("Auth: legacy YAML ldap block is RETIRED — the IdP registry is the sole operational LDAP " +
				"authority (durable cutover). The ldap block is ignored for authentication; remove it, or manage " +
				"LDAP from Objects → Identity Providers")
			return nil
		}
		ldapProvider, err := NewLDAPAuth(c.LDAP)
		if err != nil {
			return fmt.Errorf("LDAP config error: %w", err)
		}
		cfg.SetProvider(ldapProvider)
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
