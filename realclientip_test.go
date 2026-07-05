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
		{
			// review F2: a non-canonical spelling of the client IP must
			// canonicalize so it can't fork the per-IP lockout key.
			name:    "IPv4-mapped IPv6 client canonicalizes to dotted form",
			trusted: []string{"10.0.0.0/8"},
			remote:  "10.0.0.5:5", xff: "::ffff:198.51.100.9",
			want: "198.51.100.9",
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

// TestRealClientIP_MultipleXFFHeaderFields is the Codex P1 regression guard:
// when a request carries TWO X-Forwarded-For header FIELDS (a client-spoofed
// first line + a proxy-appended real-client second line), realClientIP must
// consider BOTH — Header.Get would drop the second and honor the spoof.
func TestRealClientIP_MultipleXFFHeaderFields(t *testing.T) {
	withTrustedProxies(t, []string{"10.0.0.0/8"})

	// Peer is the trusted proxy. Client spoofs a first XFF field claiming an
	// allowlisted/internal IP; the proxy appends the real client as a second
	// field. The real client (rightmost untrusted) must win.
	r := &http.Request{RemoteAddr: "10.0.0.5:9", Header: http.Header{}}
	r.Header.Add("X-Forwarded-For", "10.0.0.99")   // client-forged (trusted-looking) first field
	r.Header.Add("X-Forwarded-For", "203.0.113.7") // proxy-appended real client
	if got := realClientIP(r); got != "203.0.113.7" {
		t.Errorf("multi-field XFF: got %q, want 203.0.113.7 (proxy-appended real client, not the forged first field)", got)
	}

	// Client forges an allowlisted public IP in the first field; proxy appends
	// the attacker's real IP. The forged value must NOT win.
	r2 := &http.Request{RemoteAddr: "10.0.0.5:9", Header: http.Header{}}
	r2.Header.Add("X-Forwarded-For", "198.51.100.1") // forged "allowed" IP
	r2.Header.Add("X-Forwarded-For", "45.33.22.11")  // attacker's real IP (proxy-appended)
	if got := realClientIP(r2); got != "45.33.22.11" {
		t.Errorf("multi-field XFF spoof: got %q, want 45.33.22.11 — forged first field must not win", got)
	}
}

// TestTrustedProxyCIDRs_SentinelDurability is the review-F1 regression guard:
// once saved, an EMPTY persisted list must AUTHORITATIVELY clear the trust set
// (a GUI removal survives restart), and a sentinel-less legacy file must NOT
// wipe a startup/YAML seed.
func TestTrustedProxyCIDRs_SentinelDurability(t *testing.T) {
	orig := ListTrustedProxyCIDRs()
	t.Cleanup(func() { _ = SetTrustedProxyCIDRs(orig) })

	// Simulate a YAML/startup seed.
	if err := SetTrustedProxyCIDRs([]string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Saved=false (legacy file) with empty list → must NOT wipe the seed.
	applyAdminNetwork(&AdminSettings{TrustedProxyCIDRs: nil, TrustedProxyCIDRsSaved: false})
	if got := ListTrustedProxyCIDRs(); len(got) != 1 {
		t.Errorf("sentinel-less empty list wiped the seed: got %v, want [10.0.0.0/8]", got)
	}

	// Saved=true with empty list → authoritative clear (the GUI removal).
	applyAdminNetwork(&AdminSettings{TrustedProxyCIDRs: nil, TrustedProxyCIDRsSaved: true})
	if got := ListTrustedProxyCIDRs(); len(got) != 0 {
		t.Errorf("Saved empty list did not clear the trust set: got %v", got)
	}

	// Saved=true with a value → authoritative replace.
	applyAdminNetwork(&AdminSettings{TrustedProxyCIDRs: []string{"172.16.0.0/12"}, TrustedProxyCIDRsSaved: true})
	if got := ListTrustedProxyCIDRs(); len(got) != 1 || got[0] != "172.16.0.0/12" {
		t.Errorf("Saved value not applied: got %v", got)
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
