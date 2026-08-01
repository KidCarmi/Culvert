package schema

import (
	"net/netip"
	"strings"
)

// formatOK applies one of the CLOSED, deterministic `format` validators. These
// are fixed, developer-authored checks — never user-supplied regex and never an
// executable custom format. An unknown format never reaches here (compile rejects
// it), so the default returns true (defensive; unreachable).
func formatOK(format, s string) bool {
	switch format {
	case "email":
		return isEmail(s)
	case "uuid":
		return isUUID(s)
	case "date-time":
		return isDateTime(s)
	case "uri":
		return isURI(s)
	case "ipv4":
		if a, err := netip.ParseAddr(s); err == nil {
			return a.Is4()
		}
		return false
	case "ipv6":
		if a, err := netip.ParseAddr(s); err == nil {
			return a.Is6() && !a.Is4In6()
		}
		return false
	default:
		return true
	}
}

// isEmail is a conservative structural check: exactly one '@', non-empty local
// and domain, a dot in the domain, no spaces/control bytes. It is deliberately
// stricter-than-RFC and precision-first (a real address passes; obvious junk
// fails); it is NOT a deliverability check.
func isEmail(s string) bool {
	if len(s) < 3 || len(s) > 254 {
		return false
	}
	at := strings.IndexByte(s, '@')
	if at <= 0 || at != strings.LastIndexByte(s, '@') || at == len(s)-1 {
		return false
	}
	local, domain := s[:at], s[at+1:]
	if strings.IndexByte(domain, '.') < 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] == 0x7f {
			return false
		}
	}
	return local != "" && domain != ""
}

// isUUID checks the canonical 8-4-4-4-12 hex form (any case).
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range []byte(s) {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isHex(c) {
				return false
			}
		}
	}
	return true
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// isDateTime does a conservative RFC3339-shape check WITHOUT a clock (no time.Now,
// no calendar arithmetic that could differ across runs): fixed positions, digit
// classes, a 'T' separator, and a zone marker. It is structure-only by design.
func isDateTime(s string) bool {
	// Minimum: 2006-01-02T15:04:05Z (20 chars).
	if len(s) < 20 || len(s) > 40 {
		return false
	}
	if !dtDatePart(s[0:10]) {
		return false
	}
	if s[10] != 'T' && s[10] != 't' {
		return false
	}
	if !dtTimePart(s[11:19]) {
		return false
	}
	return dtZonePart(dtStripFraction(s[19:]))
}

// dtDatePart validates "YYYY-MM-DD".
func dtDatePart(s string) bool {
	return dtDigits(s[0:4]) && s[4] == '-' && dtDigits(s[5:7]) && s[7] == '-' && dtDigits(s[8:10])
}

// dtTimePart validates "HH:MM:SS".
func dtTimePart(s string) bool {
	return dtDigits(s[0:2]) && s[2] == ':' && dtDigits(s[3:5]) && s[5] == ':' && dtDigits(s[6:8])
}

// dtStripFraction removes an optional ".<digits>" fractional-seconds segment; a
// lone "." with no digits is left in place so the zone check rejects it.
func dtStripFraction(rest string) string {
	if rest == "" || rest[0] != '.' {
		return rest
	}
	i := 1
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		i++
	}
	if i == 1 {
		return rest // no digits after '.' — invalid, keep so zone check fails
	}
	return rest[i:]
}

// dtZonePart validates the zone marker: Z | z | (+|-)HH:MM.
func dtZonePart(rest string) bool {
	if rest == "Z" || rest == "z" {
		return true
	}
	if len(rest) == 6 && (rest[0] == '+' || rest[0] == '-') && rest[3] == ':' {
		return dtDigits(rest[1:3]) && dtDigits(rest[4:6])
	}
	return false
}

func dtDigits(seg string) bool {
	for i := 0; i < len(seg); i++ {
		if seg[i] < '0' || seg[i] > '9' {
			return false
		}
	}
	return true
}

// isURI is a conservative structural check: an absolute URI must begin with a
// scheme (ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )) then ':'. It does NOT
// validate destination safety — that is the destination package's job — it only
// asserts the schema `format: uri` shape.
func isURI(s string) bool {
	if s == "" || len(s) > 8192 {
		return false
	}
	colon := strings.IndexByte(s, ':')
	if colon <= 0 {
		return false
	}
	scheme := s[:colon]
	if !isAlpha(scheme[0]) {
		return false
	}
	for i := 1; i < len(scheme); i++ {
		c := scheme[i]
		if !isAlpha(c) && !isDigit(c) && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	// no control bytes anywhere
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
