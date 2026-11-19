package main

import (
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A rule whose DestFQDN is an IP literal names an ADDRESS. The proxy dials the
// address, not the spelling, so every spelling the dialer accepts for that
// address has to reach the same rule — otherwise a Drop/Block rule is bypassed
// by re-spelling the destination, and the request falls through to a lower
// rule or the default action.

// TestPolicyDestLiteral_SpellingsReachTheSameRule is the engine-level proof:
// one rule, many spellings of the address it names, in both directions (the
// operator's spelling and the client's).
func TestPolicyDestLiteral_SpellingsReachTheSameRule(t *testing.T) {
	cases := []struct {
		rule  string
		hosts []string
	}{
		{"2001:db8::1", []string{
			"2001:db8::1",
			"[2001:db8::1]",        // r.Host of an absolute-URI request with no port
			"2001:DB8::1",          // case
			"2001:db8:0:0:0:0:0:1", // expanded zeros
			"2001:db8:0::1",        // partially compressed
			"2001:0db8::0001",      // leading zeros
			"2001:db8:0::1.",       // root-dot form, which normalizeHost also folds
		}},
		{"192.0.2.7", []string{
			"192.0.2.7",
			"::ffff:192.0.2.7",   // 4-in-6: dials the IPv4 address
			"[::ffff:192.0.2.7]", // same, bracketed
			"::ffff:c000:207",    // 4-in-6, hex form
		}},
		// The operator's spelling must not matter either.
		{"[2001:db8::1]", []string{"2001:db8::1", "[2001:db8::1]"}},
		{"2001:DB8:0:0:0:0:0:1", []string{"2001:db8::1"}},
		{"::ffff:192.0.2.7", []string{"192.0.2.7", "::ffff:192.0.2.7"}},
	}
	for _, tc := range cases {
		ps := &PolicyStore{}
		ps.Add(PolicyRule{Priority: 1, Name: "drop-literal", DestFQDN: tc.rule, Action: ActionDrop})
		for _, host := range tc.hosts {
			if m := ps.Evaluate("10.0.0.1", "", "", host, nil); m == nil {
				t.Errorf("rule DestFQDN=%q: host %q matched no rule, want the Drop rule (same address)", tc.rule, host)
			}
			// The Policy Tester and the unpublished-rule fallback share the verdict.
			if !matchDest(&PolicyRule{DestFQDN: tc.rule}, host) {
				t.Errorf("matchDest(DestFQDN=%q, %q) = false, want true (same address)", tc.rule, host)
			}
		}
	}
}

// TestPolicyDestLiteral_DistinctAddressesStayDistinct is the negative control:
// canonicalization must not widen a literal rule onto another address, and
// must leave hostname and wildcard rules alone.
func TestPolicyDestLiteral_DistinctAddressesStayDistinct(t *testing.T) {
	cases := []struct{ rule, host string }{
		{"2001:db8::1", "2001:db8::2"},
		{"2001:db8::1", "[2001:db8::10]"},
		{"192.0.2.7", "::ffff:192.0.2.8"},
		{"192.0.2.7", "::192.0.2.7"}, // IPv4-compatible, NOT 4-in-6: a different address
		{"192.0.2.7", "64:ff9b::192.0.2.7"},
		{"example.com", "[2001:db8::1]"},
		{"2001:db8::1", "example.com"},
		{"fe80::1", "fe80::1%eth0"}, // a zoned address is link-scoped, not the bare one
	}
	for _, tc := range cases {
		ps := &PolicyStore{}
		ps.Add(PolicyRule{Priority: 1, Name: "drop-literal", DestFQDN: tc.rule, Action: ActionDrop})
		if m := ps.Evaluate("10.0.0.1", "", "", tc.host, nil); m != nil {
			t.Errorf("rule DestFQDN=%q matched host %q, want no match (different destination)", tc.rule, tc.host)
		}
	}
	// Hostname semantics are untouched.
	ps := &PolicyStore{}
	ps.Add(PolicyRule{Priority: 1, Name: "drop-host", DestFQDN: "*.example.com", Action: ActionDrop})
	if ps.Evaluate("10.0.0.1", "", "", "WWW.Example.com.", nil) == nil {
		t.Error("wildcard hostname rule stopped matching a re-cased, dot-terminated host")
	}
	for in, want := range map[string]string{
		"example.com":        "example.com",
		"":                   "",
		"not:an:ip":          "not:an:ip",
		"[example.com]":      "[example.com]",
		"[2001:db8::1":       "[2001:db8::1",
		"fe80::1%eth0":       "fe80::1%eth0",
		"[::FFFF:192.0.2.7]": "192.0.2.7",
	} {
		if got := canonicalDestLiteral(in); got != want {
			t.Errorf("canonicalDestLiteral(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestPolicyFlow_BlockedIPv4LiteralNotBypassedByMappedSpelling is the
// end-to-end proof through the real proxy socket: a block rule on the backend's
// IPv4 literal must also stop the 4-in-6 spelling of that same address. Before
// the fix the request matched no rule, took the default action and REACHED the
// upstream.
func TestPolicyFlow_BlockedIPv4LiteralNotBypassedByMappedSpelling(t *testing.T) {
	backend, cb := startCountingBackend(t) // http://127.0.0.1:PORT
	proxyURL := startTestProxy(t)          // default action: allow
	policyStore.rules = nil
	policyStore.Add(PolicyRule{Priority: 1, Name: "block-v4-literal", DestFQDN: "127.0.0.1", Action: ActionBlockPage})

	_, port, err := net.SplitHostPort(strings.TrimPrefix(backend.URL, "http://"))
	if err != nil {
		t.Fatalf("backend address: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	resp, err := ctxGet(client, "http://[::ffff:127.0.0.1]:"+port+"/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("4-in-6 spelling of a blocked IPv4 literal: status %d, want 403", resp.StatusCode)
	}
	if cb.hitCount() != 0 {
		t.Errorf("4-in-6 spelling of a blocked IPv4 literal reached the upstream %d time(s), want 0", cb.hitCount())
	}
	if got := ruleHitCount("block-v4-literal"); got != 1 {
		t.Errorf("block rule hit count = %d, want 1", got)
	}
}
