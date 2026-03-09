package main

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
	CaptiveLoginURL(emailDomain string) string
}
