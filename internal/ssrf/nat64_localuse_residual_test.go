package ssrf

import (
	"net/netip"
	"testing"
)

// RISK-030 / review finding F-2 — THIS TEST PINS A KNOWN GAP AS A FACT, NOT A WISH.
//
// privateRanges lists the RFC 6052 WELL-KNOWN NAT64 prefix 64:ff9b::/96 but not
// the RFC 8215 LOCAL-USE translation prefix 64:ff9b:1::/48. The two are disjoint
// (they differ in the third 16-bit group), so an address inside the local-use
// prefix is classified PUBLIC — and a NAT64 translator on the egress path will
// translate it to the IPv4 address it embeds. The same cloud-metadata address is
// therefore refused through one NAT64 prefix and admitted through the other.
//
// The coverage is INVERTED, which is what makes this more than a missing row:
// RFC 6052 §3.1 forbids the well-known prefix from representing non-global IPv4,
// so the prefix that IS blocked cannot legitimately carry 127.0.0.1 or
// 169.254.169.254, while RFC 8215's local-use prefix — which exists precisely so
// operators can translate non-global IPv4 — is the one left open.
//
// It is pinned rather than fixed because the fix is NOT "add the /48 to
// privateRanges". A /48 holds the /96 a translator actually uses and the embedded
// IPv4 may be PUBLIC; on an IPv6-only network NAT64 is how clients reach the IPv4
// internet, so blanket-blocking the /48 would deny legitimate egress. The correct
// shape is to decode the embedded IPv4 from a recognised NAT64 prefix and classify
// THAT — a behaviour change in both directions that needs its own decision.
//
// WHEN THAT FIX LANDS, THIS TEST IS THE ONE TO INVERT — deliberately, not by
// accident. Flipping it without the decode is how legitimate NAT64 egress breaks.
//
// Analysis: docs/engineering/security-reviews/
//
//	2026-10-03-admission-extraction-and-diagnostics-roster-window.md (F-2)
func TestRisk030_NAT64LocalUsePrefixIsNotClassifiedPrivate(t *testing.T) {
	// CONTROL: the well-known prefix IS classified private today. Without this
	// half the test would read as "NAT64 is simply unhandled", and a change that
	// dropped 64:ff9b::/96 from the table would still pass.
	wellKnown := []string{
		"64:ff9b::7f00:1",    // 127.0.0.1
		"64:ff9b::a9fe:a9fe", // 169.254.169.254 (cloud metadata)
		"64:ff9b::a00:1",     // 10.0.0.1
	}
	for _, s := range wellKnown {
		addr := netip.MustParseAddr(s)
		if !PrivateAddr(addr) {
			t.Errorf("control broken: %s (RFC 6052 well-known NAT64) must be private; "+
				"64:ff9b::/96 appears to have been dropped from privateRanges", s)
		}
	}

	// THE GAP: the same embeddings through the RFC 8215 local-use prefix are
	// classified public.
	localUse := []struct {
		addr     string
		embedded string
	}{
		{"64:ff9b:1::7f00:1", "127.0.0.1 (loopback)"},
		{"64:ff9b:1::a9fe:a9fe", "169.254.169.254 (cloud metadata)"},
		{"64:ff9b:1::a00:1", "10.0.0.1 (RFC 1918)"},
		{"64:ff9b:1:0:0:0:c0a8:1", "192.168.0.1 (RFC 1918)"},
	}
	for _, c := range localUse {
		addr := netip.MustParseAddr(c.addr)
		if PrivateAddr(addr) {
			t.Errorf("RISK-030 appears FIXED: %s (embeds %s) is now classified private. "+
				"If that was deliberate, invert this test and confirm a PUBLIC embedding "+
				"such as 64:ff9b:1::808:808 (8.8.8.8) is still reachable — a blanket "+
				"/48 block denies legitimate NAT64 egress.", c.addr, c.embedded)
		}
	}

	// Boundary: 64:ff9b:2:: is OUTSIDE the local-use prefix and is unrelated to
	// NAT64. Recorded so a future /48 entry is not widened to /47 or /32 by
	// accident.
	if PrivateAddr(netip.MustParseAddr("64:ff9b:2::1")) {
		t.Error("64:ff9b:2::1 is outside 64:ff9b:1::/48 and should not be classified " +
			"private by a NAT64 rule; a prefix entry looks too wide")
	}
}
