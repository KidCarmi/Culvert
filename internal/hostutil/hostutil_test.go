package hostutil

import "testing"

func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		name, input, want string
	}{
		{"trailing dot + case", "Example.COM.", "example.com"},
		{"empty", "", ""},
		{"ipv4 fast path", "192.168.0.1", "192.168.0.1"},
		{"ascii hostname", "sub.example.com", "sub.example.com"},
		{"unicode IDN to punycode", "bücher.de", "xn--bcher-kva.de"},
		{"already punycode", "xn--bcher-kva.de", "xn--bcher-kva.de"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NormalizeHost(c.input); got != c.want {
				t.Errorf("NormalizeHost(%q) = %q, want %q", c.input, got, c.want)
			}
		})
	}
}

func TestNormalizeHostStrict(t *testing.T) {
	cases := []struct {
		name, input, wantNorm string
		wantOK                bool
	}{
		// Valid → ok=true, canonical form.
		{"trailing dot + case", "Example.COM.", "example.com", true},
		{"empty (validity handled upstream)", "", "", true},
		{"ipv4 literal", "192.168.0.1", "192.168.0.1", true},
		{"ascii hostname", "sub.example.com", "sub.example.com", true},
		{"unicode IDN to punycode", "bücher.de", "xn--bcher-kva.de", true},
		// IPv6 literals — the bracketed forms reach the request-path gate
		// (default-port r.Host, SOCKS5 IPv6 ATYP) and MUST be accepted, by
		// construction rather than by idna leniency (regression guard: Codex
		// P2 on PR #572 / RISK-013).
		{"bare ipv6", "2001:db8::2", "2001:db8::2", true},
		{"bracketed ipv6", "[2001:db8::2]", "[2001:db8::2]", true},
		{"bracketed ipv6 loopback", "[::1]", "[::1]", true},
		// Fail-closed → ok=false (invalid punycode label).
		{"invalid punycode dollar", "xn--$$$.com", "", false},
		{"invalid punycode zero", "xn--0.com", "", false},
		{"invalid punycode dash", "xn---", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotNorm, gotOK := NormalizeHostStrict(c.input)
			if gotOK != c.wantOK {
				t.Fatalf("NormalizeHostStrict(%q) ok = %v, want %v", c.input, gotOK, c.wantOK)
			}
			if gotOK && gotNorm != c.wantNorm {
				t.Errorf("NormalizeHostStrict(%q) norm = %q, want %q", c.input, gotNorm, c.wantNorm)
			}
		})
	}
}

func TestStripHostPort(t *testing.T) {
	cases := []struct {
		name, input, want string
	}{
		{"host:port", "example.com:443", "example.com"},
		{"bare host", "example.com", "example.com"},
		{"bracketed v6 + port", "[2001:db8::1]:443", "2001:db8::1"},
		{"bracketed v6 no port", "[2001:db8::1]", "2001:db8::1"},
		{"bare v6 literal preserved", "2001:db8::1", "2001:db8::1"},
		{"ipv4:port", "10.0.0.1:8080", "10.0.0.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := StripHostPort(c.input); got != c.want {
				t.Errorf("StripHostPort(%q) = %q, want %q", c.input, got, c.want)
			}
		})
	}
}
