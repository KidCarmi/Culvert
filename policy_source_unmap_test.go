package main

// A bare-IP source predicate is compared as an ADDRESS, and an IPv4-mapped
// client ("::ffff:10.0.0.5") is the same address as "10.0.0.5". Both matchers
// below Unmap the client before the comparison. The mutation campaign showed
// nothing pinned that for either function: removing the Unmap from
// matchIPOrCIDRAddr (the Stage-1 subject predicate) survived the whole suite,
// and removing it from matchIPOrCIDR was caught only by the path-differential
// baseline (test/policy-pathdiff/mutation/RESULTS.md, M13a and M13b).
//
// Why it matters: a rule written for a client's IPv4 address must still apply
// when that client's address arrives in its 4-in-6 spelling, as a trusted
// forwarded-for value can. If the unmap is lost, a Drop or credential-required
// rule for the address silently stops matching it.

import (
	"net"
	"testing"
)

func TestSourceLiteral_MappedClientIsTheSameAddress(t *testing.T) {
	cases := []struct {
		literal, client string
		want            bool
	}{
		{"10.0.0.5", "::ffff:10.0.0.5", true},        // mapped client, plain rule
		{"10.0.0.5", "::ffff:a00:5", true},           // same, hex spelling
		{"::ffff:10.0.0.5", "10.0.0.5", true},        // mapped rule, plain client
		{"::ffff:10.0.0.5", "::ffff:10.0.0.5", true}, // identical strings
		{"2001:DB8::10", "2001:db8:0::10", true},     // IPv6 spelling
		// Controls: a different address never matches, mapped or not.
		{"10.0.0.5", "::ffff:10.0.0.6", false},
		{"10.0.0.5", "10.0.0.6", false},
		{"2001:db8::10", "2001:db8::11", false},
		// A zoned client is never folded into a zone-free literal.
		{"fe80::1", "fe80::1%eth0", false},
	}
	for _, c := range cases {
		if got := matchIPOrCIDR(c.literal, c.client); got != c.want {
			t.Errorf("matchIPOrCIDR(%q, %q) = %v, want %v", c.literal, c.client, got, c.want)
		}
		if got := matchIPOrCIDRAddr(c.literal, c.client, net.ParseIP(c.client)); got != c.want {
			t.Errorf("matchIPOrCIDRAddr(%q, %q) = %v, want %v", c.literal, c.client, got, c.want)
		}
	}
}
