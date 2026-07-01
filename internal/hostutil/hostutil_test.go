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
