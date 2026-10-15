package main

import "net/http"

// Identity is the normalised representation of an authenticated user produced
// by any IdP backend (OIDC, SAML, LDAP).  It is attached to every proxied
// request after successful authentication and is the only identity object
// consumed by the Policy Engine.
type Identity struct {
	// Sub is the unique, stable identifier for the user within the provider
	// (OIDC "sub" claim, SAML NameID, or LDAP DN).
	Sub string

	// Email is the primary e-mail address.  Used for email-domain routing.
	Email string

	// Name is the human-readable display name.
	Name string

	// Groups lists group / role memberships asserted by the IdP.
	// All provider-specific claim names (e.g. "groups", "roles",
	// "memberOf") are normalised into this flat slice.
	Groups []string

	// Provider is the IdP profile ID that authenticated this identity.
	Provider string
}

// IdentityProvider extends AuthProvider with the ability to return a full
// Identity object (including groups/roles) rather than a plain boolean.
// Providers that support it implement this interface; the proxy will call
// ResolveIdentity instead of Verify when it is available.
type IdentityProvider interface {
	AuthProvider
	// ResolveIdentity authenticates the supplied credentials and returns the
	// full Identity on success.  Returns (nil, false) on auth failure.
	ResolveIdentity(username, credential string) (*Identity, bool)
	// CaptiveLoginURL returns the browser-redirect URL for the captive portal
	// for a given email domain hint (may be empty).  Returns "" if this
	// provider does not support browser-based SSO.
	CaptiveLoginURL(emailDomain string, r *http.Request) string
	// DisplayName returns the admin-configured label for this provider
	// (IdPProfile.Name, e.g. "Corporate Okta") for use anywhere a human
	// reads the provider's identity — Name() stays the "type:ID" machine
	// key used for policy/filtering lookups.
	DisplayName() string
}

// clientAttributedVerifier and clientAttributedResolver are the OPTIONAL
// client-attributed forms of AuthProvider.Verify and
// IdentityProvider.ResolveIdentity (CHAOS-76).
//
// Why they are separate optional interfaces rather than a change to the two
// contracts above: every identity backend that keeps a RESULT CACHE needs the
// caller's fairness key, and the backends that keep none (SAML, which is
// browser-mediated and never sees a proxy credential) have no use for it.
// Widening IdentityProvider would force a parameter on providers that cannot
// act on it, so the dispatcher in store.go prefers these when a provider
// implements them and falls back to the historical signature otherwise.
//
// client is an opaque fairness key derived from the resolved peer address
// (authStateClientKey for HTTP, clientFairnessKey for SOCKS5). It is never
// compared against anything a caller supplies later and never reaches a
// lookup, so a wrong or empty value can only make cache eviction less fair —
// it can never admit a credential that should be rejected. The empty key is
// legitimate and means "attribute this to the shared bucket".
type clientAttributedVerifier interface {
	VerifyFrom(client, username, credential string) bool
}

type clientAttributedResolver interface {
	ResolveIdentityFrom(client, username, credential string) (*Identity, bool)
}

func identityAuthSource(id *Identity, fallback string) string {
	if id != nil && id.Provider != "" {
		return id.Provider
	}
	return fallback
}
