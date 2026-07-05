package main

import (
	"net/http"
	"testing"
)

// withTrustedProxies swaps the trusted-proxy set for the duration of a test.
func withTrustedProxies(t *testing.T, cidrs []string) {
	t.Helper()
	orig := ListTrustedProxyCIDRs()
	if err := SetTrustedProxyCIDRs(cidrs); err != nil {
		t.Fatalf("SetTrustedProxyCIDRs(%v): %v", cidrs, err)
	}
	t.Cleanup(func() { _ = SetTrustedProxyCIDRs(orig) })
}

func rciReq(remoteAddr, xff string) *http.Request {
	r := &http.Request{RemoteAddr: remoteAddr, Header: http.Header{}}
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func TestRealClientIP(t *testing.T) {
	cases := []struct {
		name    string
		trusted []string
		remote  string
		xff     string
		want    string
	}{
		{
			name:   "no trusted proxies → direct peer, XFF ignored",
			remote: "203.0.113.9:44321", xff: "1.2.3.4",
			want: "203.0.113.9",
		},
		{
			name:    "peer NOT a trusted proxy → peer, XFF ignored (spoofing defense)",
			trusted: []string{"10.0.0.0/8"},
			remote:  "203.0.113.9:5", xff: "8.8.8.8",
			want: "203.0.113.9",
		},
		{
			name:    "trusted peer + single client hop → client",
			trusted: []string{"10.0.0.0/8"},
			remote:  "10.0.0.5:5", xff: "203.0.113.9",
			want: "203.0.113.9",
		},
		{
			name:    "trusted peer + client,proxy chain → rightmost untrusted (client)",
			trusted: []string{"10.0.0.0/8"},
			remote:  "10.0.0.5:5", xff: "203.0.113.9, 10.0.0.7",
			want: "203.0.113.9",
		},
		{
			name:    "trusted peer + multiple trusted hops then client → client",
			trusted: []string{"10.0.0.0/8"},
			remote:  "10.0.0.5:5", xff: "203.0.113.9, 10.0.0.7, 10.0.0.8",
			want: "203.0.113.9",
		},
		{
			name:    "trusted peer + all-trusted XFF → fall back to peer",
			trusted: []string{"10.0.0.0/8"},
			remote:  "10.0.0.5:5", xff: "10.0.0.9, 10.0.0.7",
			want: "10.0.0.5",
		},
		{
			name:    "trusted peer + no XFF → peer",
			trusted: []string{"10.0.0.0/8"},
			remote:  "10.0.0.5:5", xff: "",
			want: "10.0.0.5",
		},
		{
			name:    "trusted peer + malformed hop skipped → next untrusted client",
			trusted: []string{"10.0.0.0/8"},
			remote:  "10.0.0.5:5", xff: "203.0.113.9, garbage",
			want: "203.0.113.9",
		},
		{
			name:    "bare-IP trusted entry (/32) matches",
			trusted: []string{"192.0.2.1"},
			remote:  "192.0.2.1:9", xff: "198.51.100.4",
			want: "198.51.100.4",
		},
		{
			name:    "IPv6 trusted proxy + IPv6 client",
			trusted: []string{"2001:db8::/32"},
			remote:  "[2001:db8::5]:9", xff: "2606:4700::1111, 2001:db8::7",
			want: "2606:4700::1111",
		},
		{
			name:   "remote addr without port tolerated",
			remote: "203.0.113.9", xff: "",
			want: "203.0.113.9",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withTrustedProxies(t, c.trusted)
			if got := realClientIP(rciReq(c.remote, c.xff)); got != c.want {
				t.Errorf("realClientIP(remote=%q, xff=%q) = %q, want %q", c.remote, c.xff, got, c.want)
			}
		})
	}
}

// TestRealClientIP_SpoofDefense is the core security invariant: a direct
// attacker (peer not in any trusted-proxy CIDR) can NEVER forge their client
// IP via X-Forwarded-For, no matter what they put in the header.
func TestRealClientIP_SpoofDefense(t *testing.T) {
	withTrustedProxies(t, []string{"10.0.0.0/8"})
	spoofs := []string{
		"10.0.0.1",               // pretend to be an internal trusted host
		"127.0.0.1",              // pretend to be localhost
		"203.0.113.50, 10.0.0.1", // chain that ends in a trusted hop
		"10.0.0.1, 10.0.0.2",     // all-trusted forgery
	}
	for _, xff := range spoofs {
		got := realClientIP(rciReq("198.51.100.66:1234", xff))
		if got != "198.51.100.66" {
			t.Errorf("spoof via XFF=%q leaked client IP %q — must stay the direct peer 198.51.100.66", xff, got)
		}
	}
}

func TestSetTrustedProxyCIDRs_Validation(t *testing.T) {
	orig := ListTrustedProxyCIDRs()
	t.Cleanup(func() { _ = SetTrustedProxyCIDRs(orig) })

	if err := SetTrustedProxyCIDRs([]string{"10.0.0.0/8", "not-an-ip"}); err == nil {
		t.Fatal("expected error on invalid CIDR")
	}
	// Invalid input must not partially mutate — set a known-good value first,
	// then a failing one, and confirm the good value survives.
	if err := SetTrustedProxyCIDRs([]string{"172.16.0.0/12"}); err != nil {
		t.Fatalf("valid set failed: %v", err)
	}
	_ = SetTrustedProxyCIDRs([]string{"192.168.0.0/16", "bad/33"})
	got := ListTrustedProxyCIDRs()
	if len(got) != 1 || got[0] != "172.16.0.0/12" {
		t.Errorf("failed set mutated state: got %v, want [172.16.0.0/12]", got)
	}

	// Empty/blank entries are skipped; empty list clears.
	if err := SetTrustedProxyCIDRs([]string{"", "  "}); err != nil {
		t.Fatalf("blank entries should be skipped, got %v", err)
	}
	if got := ListTrustedProxyCIDRs(); len(got) != 0 {
		t.Errorf("blank-only list should clear the set, got %v", got)
	}
}
