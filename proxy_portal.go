package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const maxUsernameLen = 256

// resolveCaptivePortalURL picks the best IdP login URL for an unauthenticated
// browser request.  Resolution priority:
//  1. Email domain hint from "X-Proxy-Email-Hint" header or "email" query param.
//  2. First enabled IdP in registry (if exactly one — skips selection screen).
//  3. Proxy selection page (/auth/select) when multiple providers are registered.
//  4. Legacy OIDCLoginURL from single-provider config.
func resolveCaptivePortalURL(r *http.Request) string {
	// Determine the original URL the browser was trying to reach (relay URL).
	relayURL := r.URL.String()
	if r.Host != "" {
		relayURL = "http://" + r.Host + r.URL.RequestURI()
	}

	// Email domain hint.
	emailHint := r.Header.Get("X-Proxy-Email-Hint")
	if emailHint == "" {
		emailHint = r.URL.Query().Get("email")
	}
	if emailHint != "" {
		if at := strings.LastIndex(emailHint, "@"); at >= 0 {
			domain := emailHint[at+1:]
			if prov := idpRegistry.RouteByDomain(domain); prov != nil {
				return prov.CaptiveLoginURL(relayURL, r)
			}
		}
	}

	// Single provider — redirect directly without selection screen.
	// INTERACTIVE providers only (ADR-0025): a credential-only provider
	// (LDAP) cannot fulfil a captive redirect and must not swallow it.
	providers := idpRegistry.EnabledInteractiveProviders()
	if len(providers) == 1 {
		return providers[0].CaptiveLoginURL(relayURL, r)
	}
	// Multiple providers — send to selection page.
	if len(providers) > 1 {
		return fmt.Sprintf("/auth/select?relay=%s", url.QueryEscape(relayURL))
	}

	// Legacy single OIDC provider.
	return cfg.OIDCLoginURL()
}

// resolveSSOPortalURL resolves the captive-portal redirect for a matched
// SSORequired rule (Phase 3 Slice 4), scoped by the rule's providerRefs. It
// returns the redirect URL and the number of ELIGIBLE providers (enabled,
// interactive OIDC/SAML). providerRefs are registry IDs, never URLs:
//   - empty refs → all enabled interactive providers.
//   - non-empty → only refs that resolve to an enabled interactive provider;
//     disabled/deleted/non-interactive refs are ignored at runtime (DR-4).
//
// By eligible-set cardinality:
//   - 0  → ("", 0): the caller fails closed (403).
//   - 1  → that provider's CaptiveLoginURL (direct redirect).
//   - >1 → "/auth/select?relay=…&providers=<ids>" (scoped selection page).
func resolveSSOPortalURL(r *http.Request, providerRefs []string) (portalURL string, eligibleCount int) {
	elig := eligibleSSOProviders(providerRefs)
	switch len(elig) {
	case 0:
		return "", 0
	case 1:
		return elig[0].prov.CaptiveLoginURL(ssoRelayURL(r), r), 1
	default:
		ids := make([]string, 0, len(elig))
		for i := range elig {
			ids = append(ids, elig[i].id)
		}
		return fmt.Sprintf("/auth/select?relay=%s&providers=%s",
			url.QueryEscape(ssoRelayURL(r)), url.QueryEscape(strings.Join(ids, ","))), len(elig)
	}
}

// ssoEligibleProvider pairs an IdP profile ID with its live provider.
type ssoEligibleProvider struct {
	id   string
	prov IdentityProvider
}

// eligibleSSOProviders returns the enabled, interactive (OIDC/SAML) providers
// selected by providerRefs (empty → all). Disabled, deleted, or non-interactive
// refs are skipped. Pure registry reads — no side effects (it never calls
// CaptiveLoginURL), so it is safe to invoke for eligibility counting.
func eligibleSSOProviders(providerRefs []string) []ssoEligibleProvider {
	if idpRegistry == nil {
		return nil
	}
	ids := providerRefs
	if len(ids) == 0 {
		all := idpRegistry.All()
		ids = make([]string, 0, len(all))
		for _, p := range all {
			ids = append(ids, p.ID)
		}
	}
	var out []ssoEligibleProvider
	for _, ref := range ids {
		id := strings.TrimSpace(ref)
		p := idpRegistry.Get(id)
		if p == nil || !p.Enabled || !p.Type.Interactive() {
			continue
		}
		if live, ok := idpRegistry.LiveProvider(id); ok {
			out = append(out, ssoEligibleProvider{id: id, prov: live})
		}
	}
	return out
}

// ssoRelayURL is the original URL the browser was trying to reach (carried
// through the SSO flow as the post-login return target).
func ssoRelayURL(r *http.Request) string {
	if r.Host != "" {
		return "http://" + r.Host + r.URL.RequestURI()
	}
	return r.URL.String()
}

func parseProxyAuth(r *http.Request) (username, password string, ok bool) {
	auth := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	if len(parts[0]) > maxUsernameLen {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// isSafeRedirectURL returns true only for absolute http/https URLs whose host
// resolves to a public IP. This prevents javascript: URIs, protocol-relative
// open redirects, and SSRF via redirect to internal/private destinations.
func isSafeRedirectURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	// isPrivateHost returns nil only when all resolved IPs are public.
	// DNS failure now also returns an error (fail-closed), so unresolvable
	// hosts are rejected as unsafe redirect destinations.
	return isPrivateHost(u.Host) == nil
}

// isSafeCaptiveRedirect validates a captive-portal redirect target produced
// by resolveCaptivePortalURL. Two shapes are accepted:
//  1. A same-origin path beginning with "/" (but not "//", which would be a
//     protocol-relative URL pointing at an attacker host).
//  2. An absolute http(s) URL — admin-configured via the IdP registry.
//
// Anything else is rejected. This duplicates a small amount of logic so the
// shape check is visible to static analysis at the http.Redirect call site.
func isSafeCaptiveRedirect(raw string) bool {
	if raw == "" {
		return false
	}
	// Same-origin path. Reject "//evil" (protocol-relative) and "/\" (which
	// some browsers normalize to "//").
	if strings.HasPrefix(raw, "/") {
		return !strings.HasPrefix(raw, "//") && !strings.HasPrefix(raw, "/\\")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return u.Host != ""
}

// isDNSError returns true when err wraps a *net.DNSError.
func isDNSError(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}
