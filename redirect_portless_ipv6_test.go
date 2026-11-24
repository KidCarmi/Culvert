package main

import "testing"

// A Redirect target written as a bracketed IPv6 literal with no port is the
// address it names. The serve-time guard used to look the bracketed string up
// as a host NAME, which fails, so every such target was refused: rule ingress
// accepted a public one and the rule then answered 403 on every match.
func TestSafeRedirectURL_PortlessIPv6LiteralIsClassifiedAsItsAddress(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		safe bool
	}{
		{"http://[2606:2800:220:1::1]/", true},
		{"https://[2606:2800:220:1::1]:443/x", true},
		{"http://[::1]/", false},
		{"http://[fd00::1]/x", false},
		{"http://[fe80::1]/", false},
		{"http://[::ffff:10.0.0.1]/", false},
		{"http://[::]/", false},
		// A zone names a local interface: never a public destination, with or
		// without a port (review finding: stripping the brackets must not turn
		// a zoned literal into a lookup the guard then waves through).
		{"http://[fe80::1%25eth0]/", false},
		{"http://[::1%25lo]/", false},
		{"http://[fd00::1%25lo]/", false},
		{"http://[fe80::1%25eth0]:80/", false},
		{"http://[2606:2800:220:1::1%25eth0]/", false},
	} {
		if got := isSafeRedirectURL(tc.raw); got != tc.safe {
			t.Errorf("isSafeRedirectURL(%q) = %v, want %v", tc.raw, got, tc.safe)
		}
	}
}

// Ingress and serve agree: what rule validation accepts as a public literal the
// proxy will actually redirect to, and what it refuses the proxy refuses too.
func TestRedirectLiteral_IngressAndServeAgree(t *testing.T) {
	for _, raw := range []string{
		"http://[2606:2800:220:1::1]/",
		"http://[2606:2800:220:1::1]:8080/",
		"http://93.184.216.34/",
		"http://[::1]/",
		"http://[fd00::1]:80/",
		"http://127.0.0.1/",
		"http://169.254.169.254/x",
		"http://[fe80::1%25eth0]/",
		"http://[::1%25lo]:80/",
	} {
		rule := PolicyRule{Name: "r", Action: ActionRedirect, RedirectURL: raw, DestFQDN: "x.example"}
		ingressOK := validateRuleIngress(rule) == nil
		if serveOK := isSafeRedirectURL(raw); ingressOK != serveOK {
			t.Errorf("%q: ingress accepts=%v but serve accepts=%v", raw, ingressOK, serveOK)
		}
	}
}
