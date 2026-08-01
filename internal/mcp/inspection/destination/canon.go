package destination

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Canonicalize validates and canonicalizes a raw destination URL under the
// immutable policy and limits, BEFORE any resolution. It returns the canonical
// facts and the destination Class (ClassPublic/private/… for an IP literal, or
// ClassUnknown for a hostname that must still be resolved). It rejects — with a
// typed mcperr — a blocked scheme, userinfo, a fragment, a missing host, a
// malformed/over-bound URL, control chars, ambiguous percent-encoding, a
// non-canonical numeric-IP spelling, an IPv6 zone identifier, or (in V1) a
// non-ASCII host.
func Canonicalize(raw string, pol Policy, lim limits.InspectionLimits) (Canonical, Class, error) {
	if raw == "" {
		return Canonical{}, ClassMalformed, destErr(mcperr.ReasonDestinationMalformed, "empty url")
	}
	if len(raw) > lim.MaxURLBytes() {
		return Canonical{}, ClassMalformed, destErr(mcperr.ReasonDestinationMalformed, "url too long")
	}
	if hasControlBytes(raw) {
		return Canonical{}, ClassMalformed, destErr(mcperr.ReasonDestinationMalformed, "control bytes in url")
	}
	if badPercent(raw) {
		return Canonical{}, ClassMalformed, destErr(mcperr.ReasonDestinationMalformed, "ambiguous percent-encoding")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Canonical{}, ClassMalformed, destErr(mcperr.ReasonDestinationMalformed, "unparseable url")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		return Canonical{}, ClassMalformed, destErr(mcperr.ReasonDestinationMalformed, "missing scheme")
	}
	if !pol.schemeAllowed(scheme) {
		return Canonical{}, ClassBlockedScheme, destErr(mcperr.ReasonDestinationSchemeRejected, "scheme not allowlisted")
	}
	if u.User != nil {
		return Canonical{}, ClassMalformed, destErr(mcperr.ReasonDestinationMalformed, "userinfo not permitted")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return Canonical{}, ClassMalformed, destErr(mcperr.ReasonDestinationMalformed, "fragment not permitted")
	}
	host := u.Hostname()
	if host == "" {
		return Canonical{}, ClassMalformed, destErr(mcperr.ReasonDestinationMalformed, "missing host")
	}
	if len(host) > lim.MaxHostBytes() {
		return Canonical{}, ClassMalformed, destErr(mcperr.ReasonDestinationMalformed, "host too long")
	}
	if len(u.RawQuery) > lim.MaxQueryBytes() {
		return Canonical{}, ClassMalformed, destErr(mcperr.ReasonDestinationMalformed, "query too long")
	}
	port, err := canonPort(scheme, u.Port())
	if err != nil {
		return Canonical{}, ClassMalformed, err
	}
	c := Canonical{Scheme: scheme, Port: port, HasQuery: u.RawQuery != "", path: u.EscapedPath(), query: u.RawQuery}
	return finishHost(c, host)
}

// finishHost resolves the host into either a canonical IP literal or a validated
// ASCII hostname and assigns the initial class.
func finishHost(c Canonical, host string) (Canonical, Class, error) {
	if ip, ok := parseIPLiteral(host); ok {
		if ip.Zone() != "" {
			return Canonical{}, ClassMalformed, destErr(mcperr.ReasonDestinationMalformed, "ipv6 zone identifier not permitted")
		}
		c.IsIP = true
		c.IP = ip
		c.Host = ip.String() // canonical text form
		return c, classifyIP(ip), nil
	}
	if looksNumericIP(host) {
		// Digits/hex/dots that are NOT a canonical IP: a non-canonical spelling
		// (octal 0177.., decimal 2130706433, hex 0x7f.., short 127.1).
		return Canonical{}, ClassMalformed, destErr(mcperr.ReasonDestinationMalformed, "non-canonical numeric ip")
	}
	h, err := canonHostname(host)
	if err != nil {
		return Canonical{}, ClassMalformed, err
	}
	c.Host = h
	// A hostname's network class is unknown until DNS resolution.
	return c, ClassUnknown, nil
}

// parseIPLiteral parses a host as an IP literal. url.Hostname already strips the
// [] from an IPv6 literal.
func parseIPLiteral(host string) (addr netip.Addr, ok bool) {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

// canonPort returns the explicit or scheme-default port, or an error for a
// malformed/out-of-range port.
func canonPort(scheme, port string) (string, error) {
	if port == "" {
		switch scheme {
		case "https":
			return "443", nil
		case "http":
			return "80", nil
		default:
			return "", destErr(mcperr.ReasonDestinationMalformed, "no default port for scheme")
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", destErr(mcperr.ReasonDestinationMalformed, "malformed port")
	}
	return strconv.Itoa(n), nil
}

// canonHostname validates and lowercases an ASCII DNS hostname. V1 rejects any
// non-ASCII host (ambiguous Unicode / IDNA is a documented residual) — never a
// silent Unicode normalization of an opaque identifier.
func canonHostname(host string) (string, error) {
	if len(host) > 253 {
		return "", destErr(mcperr.ReasonDestinationMalformed, "hostname too long")
	}
	host = strings.TrimSuffix(host, ".") // a single trailing root dot is tolerated then dropped
	if host == "" {
		return "", destErr(mcperr.ReasonDestinationMalformed, "empty hostname")
	}
	lower := strings.ToLower(host)
	for i := 0; i < len(lower); i++ {
		if lower[i] >= 0x80 {
			return "", destErr(mcperr.ReasonDestinationMalformed, "non-ascii host rejected in v1")
		}
	}
	for _, label := range strings.Split(lower, ".") {
		if err := validLabel(label); err != nil {
			return "", err
		}
	}
	return lower, nil
}

func validLabel(label string) error {
	if label == "" || len(label) > 63 {
		return destErr(mcperr.ReasonDestinationMalformed, "invalid host label length")
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return destErr(mcperr.ReasonDestinationMalformed, "host label hyphen boundary")
	}
	for i := 0; i < len(label); i++ {
		if !isLabelChar(label[i]) {
			return destErr(mcperr.ReasonDestinationMalformed, "invalid host label char")
		}
	}
	return nil
}

// isLabelChar reports whether c is a valid LDH (letter/digit/hyphen) host-label byte.
func isLabelChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
}

// looksNumericIP reports whether host is composed only of characters an IP literal
// spelling would use (hex digits, dots, colons, and the 0x prefix) — used to
// reject non-canonical numeric spellings that ParseAddr refused.
func looksNumericIP(host string) bool {
	hasDigit := false
	for i := 0; i < len(host); i++ {
		c := host[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'):
			// hex digit — allowed in the numeric-spelling class
		case c == '.' || c == ':' || c == 'x' || c == 'X':
			// separators / hex prefix
		default:
			return false // a normal hostname letter → not a numeric-IP spelling
		}
	}
	return hasDigit
}

func hasControlBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// badPercent reports an ambiguous percent-encoding (a '%' not followed by two hex
// digits).
func badPercent(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		if i+2 >= len(s) || !isHexByte(s[i+1]) || !isHexByte(s[i+2]) {
			return true
		}
	}
	return false
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
