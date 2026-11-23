package authstate

import "net"

// ClientKey collapses a resolved client address into the fairness key that
// attributes an entry to a client (the "client key" of the package comment).
// It lives here, beside the eviction policy it feeds, so every caller derives
// the SAME key shape: the interactive-login stores, and the callers that
// charge authentication cost or identity-cache entries to a client (CHAOS-57).
//
//   - IPv4 stays RAW: a /24 is a network of many distinct devices, and folding
//     it would penalise a legitimate enterprise subnet.
//   - IPv6 collapses to its /64. A single host legitimately owns a whole /64
//     (SLAAC / privacy addressing), so keying on the full address would let
//     one machine present thousands of "clients".
//   - An unparseable address yields "", which is a valid key: all such entries
//     share one bucket and can only evict each other.
//
// The caller is responsible for having resolved addr correctly. An HTTP caller
// must resolve it so a forwarded header counts only from a trusted proxy; a
// SOCKS5 caller passes the raw peer, because that protocol carries no
// forwarding header at all. The key is used for eviction ordering and cost
// attribution only, never for lookup, authentication or authorization.
func ClientKey(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
