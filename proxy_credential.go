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
// Management and data-plane identities are distinct (owner Decision 2,
// 2026-11-23). The local admin-console account — the legacy admin pair and
// every RBAC roster account — authenticates the ADMIN plane only (session
// login, admin Basic, the --reset-password break-glass). It is never a proxy
// identity on ANY channel, and never a fallback when no proxy provider is
// configured or when a configured one rejects the credential.
//
// The channel decides which proxy verifiers may answer:
//
//   - credentialChannelHTTPBasic — every credential-capable PROXY verifier:
//     IdP-registry credential providers (LDAP bind, OIDC token introspection),
//     then the legacy single provider (LDAP or OIDC).
//   - credentialChannelSOCKS5 — RFC 1929 is a NON-interactive, password-only
//     exchange. Only verifiers that check a username and a password directly:
//     registry profiles of a PasswordVerifying type (LDAP) and a legacy LDAP
//     provider. Never OIDC (its credential is a bearer token and its login is
//     interactive), never SAML.
//
// With no usable verifier the resolver answers "not resolved" and the caller
// refuses (HTTP 407, RFC 1929 failure status): proxy authentication that is
// required but cannot be satisfied fails CLOSED and never degrades to
// unauthenticated access. Explicitly configured unauthenticated access (an
// Exempt rule or the Exempt global default) is decided before any credential
// is resolved, in resolveRequestAuth, and is unaffected.
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
// (YAML) provider only. HTTP Basic may use a legacy LDAP or OIDC provider;
// SOCKS5 only a legacy LDAP provider. The local admin-console pair is NEVER
// consulted, on either channel (owner Decision 2): with no legacy provider, or
// one the channel cannot use, this resolves nothing.
//
// Handing resolveAuthIdentityFromSnapshot only a snapshot whose provider is
// set is what keeps the local pair out by construction: that function, and the
// verifyAuthFrom it delegates to, consult the pair only when no provider is
// configured. Both reads come from ONE snapshot, so a concurrent SetProvider(nil)
// cannot slip the pair in between the check and the resolution. Do not replace
// this with a resolution that takes its own, unchecked snapshot (the former
// cfg.resolveAuthIdentityFrom did, and reached the pair; pinned by
// TestProxyCredential_AdminPairNeverResolves).
//
// The auth source of a legacy provider that supplies no identity of its own
// (the legacy LDAP bind provider) stays the historical "local" label —
// resolveAuthIdentityFromSnapshot stamps it, identically on both channels.
func legacyCredentialFor(ch proxyCredentialChannel, clientKey, user, pass string) (*Identity, bool) {
	snap := cfg.snapshotAuthBackend()
	if snap.provider == nil {
		return nil, false
	}
	if ch == credentialChannelSOCKS5 && !isPasswordVerifyingLegacyProvider(snap.provider) {
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
