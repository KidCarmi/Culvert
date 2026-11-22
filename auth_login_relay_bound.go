package main

import "strings"

// auth_login_relay_bound.go — the size bound on the post-login return target
// ("relay") retained by the interactive-login state stores.
//
// globalPKCEStore and globalSAMLStateStore are populated by UNAUTHENTICATED
// requests (the proxy's no-credentials captive-portal path and the public
// /auth/select page), and each entry keeps the URL the browser was trying to
// reach so the callback can send it back there. internal/authstate caps those
// stores by entry COUNT (1000 each) and by TTL (10 min), but the relay is the
// client's own request target — "http://" + Host + RequestURI on the proxy
// listener, the raw ?relay= value on /auth/select — and neither listener sets
// MaxHeaderBytes, so net/http admits ~1 MiB of it. A count cap on entries of
// attacker-chosen size is not a memory bound: 1000 requests pinned ~1 GiB of
// live heap per store for the full TTL, from one anonymous source. It is
// reachable heap, so the GOMEMLIMIT backstop cannot reclaim it, and the
// fair-share eviction policy does not help because the flooder only ever
// evicts its own (equally large) entries.
//
// The bound goes on RETENTION, not admission — the same split
// proxy_path_bounds.go makes. The request is still served and the login still
// starts; only the copy kept for ten minutes is limited. A relay above the
// limit is not truncated, because a truncated URL is a DIFFERENT URL (and a
// broken one if it carried a signature); it degrades to the origin root of the
// same destination, or to "" (which both callbacks already treat as "/").
// Either way the value is still validated by isSafeRedirectURL / the inline
// SAML guard at the callback, exactly as before, so this cannot widen what a
// login may redirect to.

// maxLoginRelayBytes is the longest relay URL retained verbatim. 8 KiB is the
// request-line ceiling of the mainstream origins (Apache LimitRequestLine
// 8190, nginx large_client_header_buffers 8k), so a longer return target
// names nothing an origin would have answered. It bounds each store's relay
// retention at maxEntries × 8 KiB ≈ 8 MiB.
const maxLoginRelayBytes = 8192

// maxLoginRelayOriginBytes bounds the scheme://authority prefix kept as the
// fallback: a DNS name is at most 255 octets (RFC 1035 §2.3.4), so anything
// longer cannot name a resolvable destination.
const maxLoginRelayOriginBytes = 512

// boundLoginRelay returns relay unchanged when it is within
// maxLoginRelayBytes. An oversized relay is reduced to its http(s) origin
// root ("https://host/"), or to "" when no bounded origin can be read off its
// front. The result never aliases the oversized input.
func boundLoginRelay(relay string) string {
	if len(relay) <= maxLoginRelayBytes {
		return relay
	}
	var schemeLen int
	switch {
	case strings.HasPrefix(relay, "http://"):
		schemeLen = len("http://")
	case strings.HasPrefix(relay, "https://"):
		schemeLen = len("https://")
	default:
		return ""
	}
	head := relay[schemeLen : schemeLen+maxLoginRelayOriginBytes]
	end := strings.IndexAny(head, "/?#")
	if end <= 0 {
		// No authority, or one longer than any resolvable name.
		return ""
	}
	// Concatenation copies, so the ~1 MiB backing array is not pinned by the
	// short value that is retained.
	return relay[:schemeLen+end] + "/"
}
