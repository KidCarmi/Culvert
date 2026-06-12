package main

import "testing"

// IPv6 hosts on the DPI bypass and scan-exclusion lists must match in every
// shape the lookups receive: the tunnel-inspect path passes a bare,
// de-bracketed literal (net.SplitHostPort output), while the plain-HTTP path
// passes r.Host, which may be bracketed with a port. The old
// LastIndex(host, ":") port-strip corrupted bare literals ("2001:db8::1" →
// "2001:db8:"), silently disabling IPv6 entries on both lists.

func TestStripHostPort(t *testing.T) {
	cases := map[string]string{
		"example.com":       "example.com",
		"example.com:8080":  "example.com",
		"2001:db8::1":       "2001:db8::1",
		"[2001:db8::1]":     "2001:db8::1",
		"[2001:db8::1]:443": "2001:db8::1",
		"::1":               "::1",
		"192.0.2.10:3128":   "192.0.2.10",
		"192.0.2.10":        "192.0.2.10",
	}
	for in, want := range cases {
		if got := stripHostPort(in); got != want {
			t.Errorf("stripHostPort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsBypassHost_IPv6(t *testing.T) {
	s := &ContentScanner{}
	s.SetBypassHosts([]string{"2001:db8::1", "[2001:db8::aa]", "example.com"})

	for _, host := range []string{"2001:db8::1", "[2001:db8::1]:443", "[2001:db8::1]", "2001:db8::aa"} {
		if !s.IsBypassHost(host) {
			t.Errorf("IsBypassHost(%q) = false, want true", host)
		}
	}
	if s.IsBypassHost("2001:db8::2") {
		t.Error("IsBypassHost matched an IPv6 host not on the list")
	}
	if !s.IsBypassHost("example.com:8080") {
		t.Error("IsBypassHost(example.com:8080) = false, want true (port strip regression)")
	}
}

func TestIsHostExcluded_IPv6(t *testing.T) {
	s := &ScanExclusionStore{}
	s.Replace(nil, []string{"2001:db8::1", "internal.example.com"})

	for _, host := range []string{"2001:db8::1", "[2001:db8::1]:8080", "[2001:db8::1]"} {
		if !s.IsHostExcluded(host) {
			t.Errorf("IsHostExcluded(%q) = false, want true", host)
		}
	}
	if !s.IsHostExcluded("internal.example.com:443") {
		t.Error("IsHostExcluded(internal.example.com:443) = false, want true (port strip regression)")
	}
	if s.IsHostExcluded("2001:db8::2") {
		t.Error("IsHostExcluded matched an IPv6 host not on the list")
	}
}
