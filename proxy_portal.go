package main

import (
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

const maxUsernameLen = 256

// uiSelectURL is the ONLY captive-portal target: the sign-in page on the UI
// host (<proxy.base_url>/auth/select), which sets the browser's login-binding
// cookie before any login state is minted (auth_login_binding.go). The proxy
// never mints IdP state itself any more — on the proxy path the browser is on
// some OTHER host, where a UI-host cookie cannot be set, so state minted there
// could be finished by any browser (login CSRF). Without proxy.base_url there
// is no UI origin to send the browser to (the request's own Host is the
// destination site), so the redirect is withheld and the caller falls back to
// its 407/403 — loudly, rate-limited.
func uiSelectURL(relay string, providerIDs []string) string {
	base := strings.TrimRight(cfg.ProxyBaseURL(), "/")
	if base == "" {
		noteCaptiveNoBaseURL()
		return ""
	}
	q := url.Values{"relay": {relay}}
	if len(providerIDs) > 0 {
		q.Set("providers", strings.Join(providerIDs, ","))
	}
	signSelectQuery(q, time.Now()) // the page honours only a relay Culvert chose (auth_select_relay.go)
	return base + "/auth/select?" + q.Encode()
}

var captiveNoBaseURLLast atomic.Int64

// noteCaptiveNoBaseURL logs at most once a minute that captive SSO redirects
// are withheld because proxy.base_url is unset.
func noteCaptiveNoBaseURL() {
	now := time.Now().Unix()
	last := captiveNoBaseURLLast.Load()
	// A clock that moved backwards re-arms the gate (now < last) instead of
	// silencing the warning until the clock catches up.
	if (now >= last && now-last < 60) || !captiveNoBaseURLLast.CompareAndSwap(last, now) {
		return
	}
	logger.Printf("WARN SSO captive redirect withheld: proxy.base_url is not set, so there is no admin-UI origin to send the browser to for sign-in (set it in Settings → Network)")
}

// resolveCaptivePortalURL picks the sign-in target for an unauthenticated
// browser request (the Default no-credentials path):
//  1. Email domain hint ("X-Proxy-Email-Hint" header or "email" query param)
//     → the sign-in page scoped to the provider routed for that domain.
//  2. Any enabled interactive IdP → the sign-in page (it continues straight
//     to the IdP when exactly one is eligible).
//  3. Legacy OIDCLoginURL from single-provider config (an admin-configured
//     external URL; no Culvert login state involved).
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
			if prov := idpRegistry.RouteByDomain(emailHint[at+1:]); prov != nil {
				return uiSelectURL(relayURL, []string{stripIdPPrefix(prov.Name())})
			}
		}
	}

	// INTERACTIVE providers only (ADR-0027): a credential-only provider
	// (LDAP) cannot fulfil a captive redirect and must not swallow it.
	if idpRegistry.HasEnabledInteractiveProvider() {
		return uiSelectURL(relayURL, nil)
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
// 0 eligible → ("", 0): the caller fails closed (403). Otherwise the sign-in
// page scoped to the eligible IDs (it continues straight to the IdP when
// exactly one is eligible); "" with a non-zero count when proxy.base_url is
// unset (the caller then fails closed too).
func resolveSSOPortalURL(r *http.Request, providerRefs []string) (portalURL string, eligibleCount int) {
	elig := eligibleSSOProviders(providerRefs)
	if len(elig) == 0 {
		return "", 0
	}
	ids := make([]string, 0, len(elig))
	for i := range elig {
		ids = append(ids, elig[i].id)
	}
	return uiSelectURL(ssoRelayURL(r), ids), len(elig)
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
