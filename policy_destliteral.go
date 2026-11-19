package main

import (
	"net/netip"
	"strings"
)

// canonicalDestLiteral returns the one spelling the policy engine compares an
// IP-literal destination by, and returns every other host unchanged.
//
// A rule whose DestFQDN is an IP literal names an ADDRESS, and the dialer
// connects to the address whatever its spelling. Compared as text, a Drop or
// Block rule on "192.0.2.7" did not match "::ffff:192.0.2.7", and one on
// "2001:db8::1" did not match "2001:db8:0::1" or the bracketed "[2001:db8::1]"
// that r.Host carries on a port-less absolute-URI request — the request fell
// through to a lower rule or the default action and was forwarded to the
// address the rule names. It is applied to BOTH sides of the FQDN comparison
// (the published pattern in sortLocked, the request host in
// hostCatScratch.fqdnHost), so the operator's spelling does not matter either.
// It is NOT applied to the host the category and country checks receive.
//
// The canonical form is the bare netip text with a 4-in-6 address unmapped:
// exactly the shape the common "[v6]:port" and dotted-quad paths already hand
// the matchers, so no downstream consumer sees a new shape.
//
// Only a host containing ':' can be re-spelled: netip accepts exactly one
// IPv4 text form, and normalizeHost already folds case and the trailing dot.
// That makes the hostname path one byte scan and no allocation. A ZONED
// address is link-scoped and is left as it is, the same decision
// sourceLiteralPrefix makes on the source side.
func canonicalDestLiteral(host string) string {
	if strings.IndexByte(host, ':') < 0 {
		return host
	}
	bare := strings.TrimSuffix(host, ".") // normalizeHost drops it too
	if len(bare) >= 2 && bare[0] == '[' && bare[len(bare)-1] == ']' {
		bare = bare[1 : len(bare)-1]
	}
	addr, err := netip.ParseAddr(bare)
	if err != nil || addr.Zone() != "" {
		return host
	}
	return addr.Unmap().String()
}
