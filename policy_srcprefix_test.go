package main

// Correctness + cost gates for the precomputed source-CIDR prefix
// (PolicyRule.srcPrefix, policy.go).
//
// The change swaps the per-rule source-IP test from net.(*IPNet).Contains to
// netip.Prefix.Contains. That is a COST change only: every rule must reach the
// same verdict it reached before, for every client address. The spine of this
// file is therefore a DIFFERENTIAL test against the verbatim pre-change
// matcher, not a table of expectations someone could write to match the new
// behaviour.

import (
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// legacySourceIPMatch is the VERBATIM pre-change source-IP arm of
// matchSourceAddr, kept as the oracle. Do not "modernise" it — its whole value
// is being the old code.
//
//	ipOK := true
//	if rule.SourceIP != "" {
//	    if rule.srcIPNet != nil {
//	        ipOK = clientAddr != nil && rule.srcIPNet.Contains(clientAddr)
//	    } else {
//	        ipOK = matchIPOrCIDR(rule.SourceIP, clientIP)
//	    }
//	}
func legacySourceIPMatch(rule *PolicyRule, clientIP string, clientAddr net.IP) bool {
	if rule.SourceIP == "" {
		return true
	}
	if rule.srcIPNet != nil {
		return clientAddr != nil && rule.srcIPNet.Contains(clientAddr)
	}
	return matchIPOrCIDR(rule.SourceIP, clientIP)
}

// matchSourceAddrFor is the production matcher driven the way the scan drives
// it: one clientSource per evaluation, parsed lazily on first use.
func matchSourceAddrFor(rule *PolicyRule, clientIP string) bool {
	src := newClientSource(clientIP)
	return matchSourceAddr(rule, &src, "", "", nil)
}

// publishRule runs a single rule through the real store mutator so it carries
// exactly the precomputed state (srcIPNet AND srcPrefix) the hot path sees.
func publishRule(t *testing.T, sourceIP string) *PolicyRule {
	t.Helper()
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{
		Priority: 1,
		Name:     "src",
		SourceIP: sourceIP,
		Action:   ActionAllow,
	}})
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	if len(ps.rules) != 1 {
		t.Fatalf("expected 1 published rule, got %d", len(ps.rules))
	}
	return ps.rules[0]
}

// divergenceShapes are the inputs where a net.IPNet -> netip.Prefix swap is
// most likely to disagree: the v4/v6 family boundary, IPv4-mapped IPv6 on
// either side, zoned addresses (accepted by netip.ParseAddr, rejected by
// net.ParseIP), boundary addresses, /0 and /32 and /128, and non-CIDR literals.
var divergenceShapes = []struct {
	sourceIP string
	clients  []string
}{
	// Ordinary IPv4 CIDRs, including both boundaries and both neighbours.
	{"203.0.113.0/24", []string{"203.0.113.0", "203.0.113.1", "203.0.113.255", "203.0.112.255", "203.0.114.0"}},
	{"10.0.0.0/8", []string{"10.0.0.0", "10.255.255.255", "9.255.255.255", "11.0.0.0"}},
	{"192.168.1.128/25", []string{"192.168.1.127", "192.168.1.128", "192.168.1.255", "192.168.2.0"}},
	// Host routes and the catch-alls.
	{"198.51.100.7/32", []string{"198.51.100.7", "198.51.100.6", "198.51.100.8"}},
	{"0.0.0.0/0", []string{"0.0.0.0", "1.2.3.4", "255.255.255.255", "::1", "2001:db8::1"}},
	{"::/0", []string{"::", "2001:db8::1", "1.2.3.4", "::ffff:1.2.3.4"}},
	// IPv6.
	{"2001:db8::/32", []string{"2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db9::1", "2001:db7::1"}},
	{"2001:db8::1/128", []string{"2001:db8::1", "2001:db8::2", "2001:db8::"}},
	{"fe80::/10", []string{"fe80::1", "febf:ffff::1", "fec0::1"}},
	// The 4-in-6 boundary, on BOTH sides. A v4-mapped network expressed over
	// 128 bits is the shape prefixFromIPNet has to rewrite to 32 bits, and a
	// v4-mapped client address is the shape Unmap has to fold.
	{"::ffff:10.0.0.0/104", []string{"10.0.0.1", "::ffff:10.0.0.1", "10.255.255.255", "11.0.0.1", "::ffff:11.0.0.1"}},
	{"::ffff:0:0/96", []string{"1.2.3.4", "::ffff:1.2.3.4", "2001:db8::1", "::1"}},
	{"10.0.0.0/8", []string{"::ffff:10.0.0.1", "::ffff:11.0.0.1"}},
	{"2001:db8::/32", []string{"::ffff:10.0.0.1", "10.0.0.1"}},
	// Cross-family: a v4 client against a v6 net and vice versa.
	{"2001:db8::/64", []string{"203.0.113.1"}},
	{"203.0.113.0/24", []string{"2001:db8::1"}},
	// Non-CIDR literals take the matchIPOrCIDR arm (no precompute at all).
	{"203.0.113.7", []string{"203.0.113.7", "203.0.113.8", "2001:db8::1", ""}},
	{"2001:db8::1", []string{"2001:db8::1", "2001:db8::2"}},
	// Malformed / hostile client addresses, and a zoned address — which
	// net.ParseIP rejects and netip.ParseAddr would have accepted.
	{"10.0.0.0/8", []string{"", "not-an-ip", "10.0.0.1%eth0", "fe80::1%eth0", "010.0.0.1", "10.0.0.1:8080", "[10.0.0.1]"}},
	{"fe80::/10", []string{"fe80::1%eth0", "fe80::1%1"}},
	// A CIDR net.ParseCIDR rejects: no precompute, matchIPOrCIDR arm.
	{"10.0.0.0/99", []string{"10.0.0.1"}},
	{"garbage/24", []string{"10.0.0.1"}},
}

func TestSrcPrefix_DifferentialAgainstLegacyMatcher(t *testing.T) {
	for _, shape := range divergenceShapes {
		rule := publishRule(t, shape.sourceIP)
		for _, clientIP := range shape.clients {
			want := legacySourceIPMatch(rule, clientIP, net.ParseIP(clientIP))
			got := matchSourceAddrFor(rule, clientIP)
			if got != want {
				t.Errorf("SourceIP=%q client=%q: got %v, legacy matcher says %v (srcPrefix=%v valid=%v, srcIPNet=%v)",
					shape.sourceIP, clientIP, got, want, rule.srcPrefix, rule.srcPrefix.IsValid(), rule.srcIPNet)
			}
		}
	}
}

// TestSrcPrefix_DifferentialRandomized widens the differential beyond the
// hand-picked shapes: random networks at every prefix length in both families,
// each probed with addresses drawn from inside, from the boundaries, and from
// just outside.
func TestSrcPrefix_DifferentialRandomized(t *testing.T) {
	// #nosec G404 -- deterministic seeded generator for reproducible test data
	rng := rand.New(rand.NewSource(20260828))

	// Addresses are formatted straight from rng.Intn rather than assembled out
	// of bytes: same distribution, and it keeps the generator free of int->byte
	// narrowing. Mirrors TestIPFilterView_DifferentialRandomized.
	randV4 := func() string {
		return fmt.Sprintf("%d.%d.%d.%d", rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256))
	}
	randV6 := func() string {
		return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x", rng.Intn(65536), rng.Intn(65536),
			rng.Intn(65536), rng.Intn(65536), rng.Intn(65536), rng.Intn(65536), rng.Intn(65536), rng.Intn(65536))
	}

	// Uniformly random addresses almost never land inside a long prefix, so
	// without probes derived FROM the network the randomized half would only
	// ever exercise the miss branch. Each family contributes its own network
	// plus near neighbours on either side of the boundary.
	derivedV4 := func(ipNet *net.IPNet) []string {
		base := ipNet.IP.To4()
		if base == nil {
			return nil
		}
		return []string{
			base.String(),
			net.IPv4(base[0], base[1], base[2], base[3]^0x01).String(),
			net.IPv4(base[0], base[1], base[2]^0xff, base[3]).String(),
			"::ffff:" + base.String(), // the 4-in-6 spelling of an in-network address
		}
	}
	derivedV6 := func(ipNet *net.IPNet) []string {
		flipped := append(net.IP(nil), ipNet.IP...)
		flipped[len(flipped)-1] ^= 0x01
		return []string{ipNet.IP.String(), flipped.String()}
	}

	// gen returns one random network and the probes to test it with. Split per
	// family so neither branch nests generation inside the driver loop.
	gen := func(v4 bool) (sourceIP string, probes []string) {
		randAddr, ones, derived := randV6, rng.Intn(129), derivedV6
		if v4 {
			randAddr, ones, derived = randV4, rng.Intn(33), derivedV4
		}
		sourceIP = fmt.Sprintf("%s/%d", randAddr(), ones)
		for j := 0; j < 6; j++ {
			probes = append(probes, randAddr())
		}
		if _, ipNet, err := net.ParseCIDR(sourceIP); err == nil {
			probes = append(probes, derived(ipNet)...)
		}
		return sourceIP, probes
	}

	for i := 0; i < 400; i++ {
		sourceIP, probes := gen(i%2 == 0)
		rule := publishRule(t, sourceIP)
		for _, clientIP := range probes {
			want := legacySourceIPMatch(rule, clientIP, net.ParseIP(clientIP))
			got := matchSourceAddrFor(rule, clientIP)
			if got != want {
				t.Fatalf("SourceIP=%q client=%q: got %v, legacy matcher says %v", sourceIP, clientIP, got, want)
			}
		}
	}
}

// TestSrcPrefix_PrecomputeAgreesWithIPNet pins the invariant the fast path
// rests on: whenever srcPrefix is populated it describes the SAME network as
// srcIPNet. Both are derived from one net.ParseCIDR, so a disagreement would
// mean prefixFromIPNet mis-converted rather than that the two drifted.
func TestSrcPrefix_PrecomputeAgreesWithIPNet(t *testing.T) {
	for _, shape := range divergenceShapes {
		if !strings.Contains(shape.sourceIP, "/") {
			continue
		}
		rule := publishRule(t, shape.sourceIP)
		if rule.srcIPNet == nil {
			if rule.srcPrefix.IsValid() {
				t.Errorf("SourceIP=%q: srcPrefix populated without srcIPNet", shape.sourceIP)
			}
			continue
		}
		if !rule.srcPrefix.IsValid() {
			// Legal (non-contiguous mask), but net.ParseCIDR cannot produce
			// one — so if this fires, the precompute silently stopped working
			// and every rule quietly fell back to the slow arm.
			t.Errorf("SourceIP=%q: srcIPNet populated but srcPrefix is invalid — fast path disabled", shape.sourceIP)
			continue
		}
		if got, want := rule.srcPrefix.String(), rule.srcIPNet.String(); got != want {
			t.Errorf("SourceIP=%q: srcPrefix=%s but srcIPNet=%s", shape.sourceIP, got, want)
		}
	}
}

// TestSrcPrefix_ClearedOnPublicationCopy pins srcPrefix into the same
// discipline as srcIPNet/normFQDN: a rule copied for publication must not
// carry a precompute derived from a since-edited SourceIP. sortLocked
// repopulates it on the published definition.
func TestSrcPrefix_ClearedOnPublicationCopy(t *testing.T) {
	src := publishRule(t, "203.0.113.0/24")
	if !src.srcPrefix.IsValid() {
		t.Fatal("precondition: published rule should carry a valid srcPrefix")
	}
	cp := clonePolicyRuleForPublication(src)
	if cp.srcPrefix.IsValid() {
		t.Errorf("copyPolicyRuleForPublication left srcPrefix populated (%v); it must be reset like srcIPNet", cp.srcPrefix)
	}
	if cp.srcIPNet != nil {
		t.Errorf("copyPolicyRuleForPublication left srcIPNet populated; test premise broken")
	}
}

// TestSrcPrefix_NotContentForDraftComparison pins srcPrefix as a derived cache
// rather than rule content: the SAME rule with and without its precompute must
// compare equal, or a no-op draft save would read as "modified" and a genuine
// no-op would never reconcile away.
func TestSrcPrefix_NotContentForDraftComparison(t *testing.T) {
	withPrecompute := *publishRule(t, "203.0.113.0/24")
	if !withPrecompute.srcPrefix.IsValid() {
		t.Fatal("precondition: published rule should carry a valid srcPrefix")
	}
	// Same rule, precompute stripped — the only difference between the two.
	bare := withPrecompute
	bare.srcPrefix, bare.srcIPNet, bare.normFQDN, bare.matchedConds = netip.Prefix{}, nil, "", ""

	if !sameRuleContent(withPrecompute, bare) {
		t.Error("sameRuleContent treats the srcPrefix precompute as content; it must be ignored like srcIPNet")
	}
}

// TestSrcPrefix_ConcurrentEvaluateAndReplace runs the scan against a rulebase
// being republished underneath it. Under -race this proves the precompute is
// published with the rule rather than mutated in place.
func TestSrcPrefix_ConcurrentEvaluateAndReplace(t *testing.T) {
	ps := &PolicyStore{}
	build := func(cidr string) []PolicyRule {
		out := make([]PolicyRule, 16)
		for i := range out {
			out[i] = PolicyRule{
				Priority: i + 1,
				Name:     fmt.Sprintf("r%d", i),
				SourceIP: cidr,
				DestFQDN: "target.example.com",
				Action:   ActionAllow,
			}
		}
		return out
	}
	ps.ReplaceAll(build("203.0.113.0/24"))

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil)
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		if i%2 == 0 {
			ps.ReplaceAll(build("203.0.113.0/24"))
		} else {
			ps.ReplaceAll(build("198.51.100.0/24"))
		}
	}
	close(stop)
	wg.Wait()
}
