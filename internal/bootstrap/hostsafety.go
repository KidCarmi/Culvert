package bootstrap

// hostsafety.go — SEC-BOOTSTRAP-HOST-1.
//
// This package renders two artifacts that a human is told to execute with root
// authority on a brand-new host: the install script (`curl … | sudo bash`) and
// the docker-compose.yml it downloads. Both are text templates, and until this
// file existed two of the values interpolated into them came straight off the
// wire — `r.Host`, and `X-Forwarded-Host` when the operator has enabled
// trustForwardedHeaders.
//
// That was an OS-command-injection sink. The script carried
//
//	CP_BASE="{{.CPBase}}"
//
// and a double-quoted shell word still performs command substitution, so a
// request whose Host header was `cp.example.com$(…)` produced a script that ran
// the attacker's command as root before it did anything else. Go's own header
// validation is NOT a mitigation here and must not be mistaken for one:
// httpguts rejects `"`, a backtick, `{` and space, but it ACCEPTS every byte
// `$( ; ' )` needs — measured against net/http, and pinned by
// TestSafeAuthority_RejectsEveryByteGoAcceptsInAHostHeader. `X-Forwarded-Host`
// is an ordinary header and is not filtered at all, so on a
// trustForwardedHeaders deployment the injection is unconstrained.
//
// The fix is validation, not escaping, and it is FAIL-CLOSED: a request whose
// derived authority is not a plain host[:port] is refused and no artifact is
// rendered. Escaping is kept underneath it as defence in depth (the templates
// single-quote what they interpolate), but escaping alone would be the wrong
// primary control — `'` is one of the bytes a Host header may legally carry, so
// a quoting-only fix is one missing byte away from being no fix at all.
//
// Nothing legitimate is refused by this: every real Control-Plane authority is
// a DNS name or an IP literal with an optional numeric port, which is exactly
// what SafeAuthority accepts.

import (
	"net"
	"strconv"
	"strings"
)

// maxAuthorityLen bounds the authority before any parsing. 253 bytes is the
// maximum length of a DNS name, plus room for brackets and ":65535".
const maxAuthorityLen = 273

// maxDNSNameLen is the maximum length of a DNS name in presentation form.
const maxDNSNameLen = 253

// SafeAuthority validates an "host" or "host:port" authority taken from an
// untrusted request and returns it in canonical form.
//
// It accepts exactly three shapes:
//
//	a DNS name          cp.example.com          cp.example.com:9090
//	an IPv4 literal     10.0.0.7                10.0.0.7:9090
//	an IPv6 literal     [2001:db8::1]           [2001:db8::1]:9090
//
// Everything else — an empty host, a shell metacharacter, a space, a port that
// is not a decimal 1-65535, a bare unbracketed IPv6 address, a userinfo or path
// fragment — is refused. The second return value is the ONLY signal callers may
// act on; the string is empty when it is false.
func SafeAuthority(authority string) (string, bool) {
	if authority == "" || len(authority) > maxAuthorityLen {
		return "", false
	}

	host, port, ok := splitAuthority(authority)
	if !ok || host == "" {
		return "", false
	}
	if ip := net.ParseIP(host); ip != nil {
		// An IP literal. JoinHostPort re-brackets IPv6 for us; do the same by
		// hand for the portless form so both branches agree.
		canonical := ip.String()
		if port != "" {
			return net.JoinHostPort(canonical, port), true
		}
		if ip.To4() == nil {
			return "[" + canonical + "]", true
		}
		return canonical, true
	}
	if !validDNSName(host) {
		return "", false
	}
	if port != "" {
		return host + ":" + port, true
	}
	return host, true
}

// splitAuthority separates an authority into its host and optional port. The
// port, when present, must be a decimal 1-65535; a bare (unbracketed) IPv6
// address is refused because re-emitting one produces an authority no URL
// parser reads back the same way.
func splitAuthority(authority string) (host, port string, ok bool) {
	if h, p, err := net.SplitHostPort(authority); err == nil {
		// SplitHostPort accepts an empty port ("host:"); a rendered artifact
		// must never carry one, so require it to be present and numeric.
		if !validPort(p) {
			return "", "", false
		}
		return h, p, true
	}
	if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
		// A bracketed IPv6 literal with no port: SplitHostPort rejects it.
		return authority[1 : len(authority)-1], "", true
	}
	if strings.Contains(authority, ":") {
		return "", "", false
	}
	return authority, "", true
}

// validPort reports whether p is a decimal port in 1-65535, with no sign, no
// leading "+", and no leading zeros beyond what strconv would accept anyway.
func validPort(p string) bool {
	if p == "" || len(p) > 5 {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(p)
	return err == nil && n >= 1 && n <= 65535
}

// validDNSName reports whether name is a syntactically valid DNS name in
// presentation form: 1-253 bytes, dot-separated labels of 1-63 bytes drawn from
// [A-Za-z0-9_-] that neither start nor end with a hyphen. One trailing dot (the
// fully-qualified form) is permitted.
//
// Deliberately stricter than "whatever resolves": this string is about to be
// pasted into a shell script, so the allowlist is the point.
//
// The underscore is in the allowlist deliberately, and it is NOT a widening of
// the security boundary: RFC 1123 does not permit it in a hostname, but Docker
// Compose service names do, and a Control Plane addressed as `culvert_cp:50051`
// on a compose network is an ordinary deployment. The byte is inert everywhere
// it lands — it cannot close a single-quoted shell word, cannot open a command
// substitution, and cannot be read as YAML structure — so refusing it would buy
// no safety and would turn this fix into an availability regression, which is
// the trade this repository refuses elsewhere. A byte is only added here when
// that argument can be made for it.
func validDNSName(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > maxDNSNameLen {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}

func validDNSLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// SafeToken reports whether tok is a Culvert enrollment token in the shape this
// appliance mints: base64url without padding (ClusterStore.GenerateToken), i.e.
// 1-128 bytes of [A-Za-z0-9-_].
//
// The handler has already proved the token exists in the cluster store before
// this is reached, so in production this can only fail if the store itself is
// carrying something it did not mint. It is checked anyway because the token is
// the second value interpolated into the root-executed script, and a template
// whose safety rests on "the other end only ever stores well-formed values" is
// one storage change away from being an injection sink again.
func SafeToken(tok string) bool {
	if tok == "" || len(tok) > 128 {
		return false
	}
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// SafeImageRef reports whether ref is a plain OCI image reference:
// [host[:port]/]path[:tag] over [A-Za-z0-9._:/@-], 1-512 bytes, no whitespace
// and no shell or YAML metacharacter.
//
// The reference is read from an operator-managed settings file and rendered
// into the compose document the DP node runs, so it is trusted-but-verified:
// a value that fails here falls back to the built-in default rather than
// reaching the artifact.
func SafeImageRef(ref string) bool {
	if ref == "" || len(ref) > 512 {
		return false
	}
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '.', c == '_', c == '-', c == '/', c == ':', c == '@':
		default:
			return false
		}
	}
	return true
}
