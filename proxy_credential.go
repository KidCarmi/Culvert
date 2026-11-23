package main

import "strings"

// proxy_credential.go — the ONE resolver for an in-band proxy credential.
//
// Two data-plane protocols carry a username/password inline: HTTP proxy Basic
// (Proxy-Authorization, resolveRequestAuth arm 2) and SOCKS5 RFC 1929
// USER/PASS (socks5Negotiate). Both resolve it here, so a credential a channel
// accepts means the same principal whichever listener it arrives on: the same
// providers in the same order, the same fairness-attributed caches and
// verification gates, and the same identity, groups and authSource stamped
// onto Stage-2 policy and the request log.
//
// Before SWG-901 stage 3 SOCKS5 had its own check (cfg.VerifyAuthFrom) that
// consulted only the legacy single provider or the local admin-console pair and
// returned a bool: directory users in an IdP-registry LDAP profile could not
// authenticate, the admin's console credential could, and no identity, group
// or auth source ever reached policy. That path is gone.
//
// The channel decides which verifiers may answer (owner direction 2026-11-23):
//
//   - credentialChannelHTTPBasic — every credential-capable verifier, unchanged:
//     IdP-registry credential providers (LDAP bind, OIDC token introspection),
//     then the legacy single provider, else the local account.
//   - credentialChannelSOCKS5 — RFC 1929 is a NON-interactive, password-only
//     exchange. Only verifiers that check a username and a password directly:
//     registry profiles of a PasswordVerifying type (LDAP) and a legacy LDAP
//     provider. Never OIDC (its credential is a bearer token and its login is
//     interactive), never SAML, and NEVER the local admin-console account: an
//     administrative credential is not a proxy identity and is not a fallback
//     when nothing else is configured.
//
// A resolution that yields no subject is a failure: the username is never
// substituted for an identity-capable provider's canonical subject.
//
// clientKey is the caller's fairness key (clientFairnessKey shape). It reaches
// the registry providers' result caches (CHAOS-76) and the bcrypt governor
// (CHAOS-57); HTTP derives it through realClientIP, SOCKS5 from the raw peer.

// proxyCredentialChannel names the in-band channel a credential arrived on.
type proxyCredentialChannel int

const (
	credentialChannelHTTPBasic proxyCredentialChannel = iota
	credentialChannelSOCKS5
)

func resolvePresentedCredential(ch proxyCredentialChannel, clientKey, user, pass string) (identity string, groups []string, source string, ok bool) {
	for _, prov := range credentialProvidersFor(ch) {
		id, resolved := resolveIdentityAttributed(prov, clientKey, user, pass)
		if !resolved || id == nil || strings.TrimSpace(id.Sub) == "" {
			continue
		}
		return id.Sub, id.Groups, identityAuthSource(id, prov.Name()), true
	}
	id, resolved := legacyCredentialFor(ch, clientKey, user, pass)
	if !resolved || id == nil || strings.TrimSpace(id.Sub) == "" {
		return "", nil, "", false
	}
	return id.Sub, id.Groups, identityAuthSource(id, "local"), true
}

// credentialProvidersFor is the registry half of the chain for ch.
func credentialProvidersFor(ch proxyCredentialChannel) []IdentityProvider {
	if idpRegistry == nil {
		return nil
	}
	if ch == credentialChannelSOCKS5 {
		return idpRegistry.EnabledPasswordProviders()
	}
	return idpRegistry.EnabledCredentialProviders()
}

// legacyCredentialFor is the Config half of the chain for ch: the legacy single
// provider, else the local account (HTTP Basic). SOCKS5 may use only a legacy
// LDAP provider; with any other legacy backend — a legacy OIDC provider, or the
// local admin-console pair — it resolves nothing. Handing
// resolveAuthIdentityFromSnapshot a snapshot whose provider is set is what keeps
// the local pair out by construction: that function consults the pair only
// when no provider is configured.
func legacyCredentialFor(ch proxyCredentialChannel, clientKey, user, pass string) (*Identity, bool) {
	if ch != credentialChannelSOCKS5 {
		return cfg.resolveAuthIdentityFrom(clientKey, user, pass)
	}
	snap := cfg.snapshotAuthBackend()
	if !isPasswordVerifyingLegacyProvider(snap.provider) {
		return nil, false
	}
	return cfg.resolveAuthIdentityFromSnapshot(snap, clientKey, user, pass)
}

// isPasswordVerifyingLegacyProvider reports whether a legacy (YAML) provider
// verifies a username and password directly: the legacy LDAP bind provider.
func isPasswordVerifyingLegacyProvider(p AuthProvider) bool {
	_, ok := p.(*LDAPAuth)
	return ok
}

// passwordProviderConfigured reports whether anything a password-only channel
// can use is configured: an enabled registry profile of a PasswordVerifying
// type, or a legacy LDAP provider.
func passwordProviderConfigured() bool {
	if idpRegistry != nil && idpRegistry.HasEnabledPasswordProvider() {
		return true
	}
	return isPasswordVerifyingLegacyProvider(cfg.snapshotAuthBackend().provider)
}
