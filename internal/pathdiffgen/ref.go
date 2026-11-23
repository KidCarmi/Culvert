//go:build policy_pathdiff

package pathdiffgen

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Relation is what the reference says about two spellings of a destination.
type Relation int

const (
	// Unspecified: the cited sources do not settle it. Reported, never asserted.
	Unspecified Relation = iota
	// Same: both spellings name one destination, so a path must decide them alike.
	Same
)

// splitAuthority separates host and port the way RFC 3986 section 3.2 writes an
// authority: an optional ":port" after the host, where an IPv6 literal is
// bracketed. ok is false when the string is not of that shape.
func splitAuthority(a string) (host string, ok bool) {
	if strings.HasPrefix(a, "[") {
		end := strings.Index(a, "]")
		if end < 0 {
			return "", false
		}
		rest := a[end+1:]
		if rest != "" && !validPort(rest) {
			return "", false
		}
		if !strings.Contains(a[1:end], ":") {
			return "", false // brackets are for IPv6 literals only (RFC 3986 3.2.2)
		}
		return a[1:end], true
	}
	if i := strings.LastIndex(a, ":"); i >= 0 {
		if strings.Contains(a[:i], ":") || !validPort(a[i:]) {
			return "", false
		}
		return a[:i], true
	}
	return a, true
}

func validPort(s string) bool { // ":" followed by *DIGIT, RFC 3986 section 3.2.3
	if !strings.HasPrefix(s, ":") {
		return false
	}
	if s == ":" {
		return true
	}
	n, err := strconv.Atoi(s[1:])
	return err == nil && n >= 0 && n <= 65535 && strings.Trim(s[1:], "0123456789") == ""
}

func isLDH(h string) bool {
	if h == "" {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// canon returns a canonical key for a host the reference understands, and
// whether it understands it. Clauses:
//
//	D1  the port is not part of the host            (RFC 3986 3.2.2 / 3.2.3)
//	D2  registered names compare case-insensitively (RFC 4343, RFC 3986 6.2.2.1)
//	D3  one trailing dot names the same absolute name (RFC 1034 3.1)
//	D4  textual forms of one IPv6 address are one address (RFC 5952, RFC 4291 2.2)
//
// Everything else is outside the reference: IPv4-mapped IPv6 against the bare
// IPv4 address, non-dotted-decimal IPv4 forms, zones, IDN U-labels against
// A-labels, percent-encoding, and any host with characters outside
// letters, digits and hyphen.
func canon(authority string) (string, bool) {
	h, ok := splitAuthority(authority)
	if !ok {
		return "", false
	}
	if a, err := netip.ParseAddr(h); err == nil {
		if a.Zone() != "" || a.Is4In6() {
			return "", false
		}
		if a.Is4() && a.String() != h {
			return "", false
		}
		return "ip:" + a.String(), true
	}
	if strings.ContainsAny(h, ":%") {
		return "", false
	}
	h = strings.TrimSuffix(h, ".") // D3: at most one
	if !isLDH(h) {
		return "", false
	}
	if last := h[strings.LastIndex(h, ".")+1:]; strings.Trim(last, "0123456789") == "" || strings.HasPrefix(strings.ToLower(last), "0x") {
		return "", false // all-numeric or hex-looking last label: may be an IPv4 spelling, out of scope
	}
	for _, l := range strings.Split(strings.ToLower(h), ".") {
		if strings.HasPrefix(l, "xn--") {
			return "", false // A-labels: IDNA validity is out of scope
		}
	}
	return "dns:" + strings.ToLower(h), true // D2
}

// Relate reports whether two authority spellings name the same destination.
func Relate(a, b string) Relation {
	ka, oka := canon(a)
	kb, okb := canon(b)
	if oka && okb && ka == kb {
		return Same
	}
	return Unspecified
}

// DecidePlain is the reference decision for the "plain" and "publish" strata:
// enabled rules in ascending priority, first match decides (contract POL-001).
// A destination matches when it is "*", equals the request host, or is a parent
// of it on a label boundary: a bare name covers its subdomains, which is the
// documented matcher contract (internal/hostutil MatchFQDN). It returns the rule name,
// or "" for no match. ok is false if any rule or the request is outside the
// literal fragment, in which case the reference has no opinion.
func DecidePlain(rules []Rule, authority string) (name string, ok bool) {
	k, ok := canon(authority)
	if !ok || !strings.HasPrefix(k, "dns:") {
		return "", false
	}
	rs := append([]Rule(nil), rules...)
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].Priority < rs[j].Priority })
	for i := range rs {
		if i > 0 && rs[i].Priority == rs[i-1].Priority {
			return "", false // tie order is an open contract question
		}
	}
	for _, ru := range rs {
		if ru.SourceIP != "" || ru.SourceIdentity != "" || ru.SourceGroup != "" || ru.AuthSource != "" || ru.DestCategory != "" || ru.DestCatGroup != "" {
			return "", false
		}
		if ru.DestFQDN != "*" && (ru.DestFQDN != strings.ToLower(ru.DestFQDN) || !isLDH(ru.DestFQDN)) {
			return "", false
		}
		if ru.Disabled {
			continue
		}
		if ru.DestFQDN == "*" || "dns:"+ru.DestFQDN == k || strings.HasSuffix(k, "."+ru.DestFQDN) {
			return ru.Name, true
		}
	}
	return "", true
}

// ApplyOps is the reference state transition for publication steps.
func ApplyOps(rules []Rule, ops []Op) []Rule {
	out := append([]Rule(nil), rules...)
	for _, op := range ops {
		switch op.Kind {
		case "disable":
			for i := range out {
				if out[i].Name == op.Name {
					out[i].Disabled = true
				}
			}
		case "delete":
			kept := out[:0:0]
			for _, ru := range out {
				if ru.Name != op.Name {
					kept = append(kept, ru)
				}
			}
			out = kept
		case "replace": // republish the current set unchanged
		}
	}
	return out
}
