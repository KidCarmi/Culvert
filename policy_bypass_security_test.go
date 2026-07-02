package main

// Policy host-matching security regression suite (CI quality program).
//
// For a forward proxy, the #1 risk is POLICY EVASION: a request that should be
// blocked slipping through (or a request that should be denied being allowed)
// because the destination host can be written in an equivalent-but-different
// form — different case, a trailing dot, a Unicode/punycode spelling, etc.
//
// These tests are doubly important here because the FQDN-matching hot path was
// just optimized (per-rule `normFQDN` precomputed at load + host normalized once
// per Evaluate). This suite proves that optimization is SECURITY-EQUIVALENT to
// the canonical `matchFQDN`, and that the equivalence classes the proxy relies
// on for enforcement still hold. A failure here is a policy-evasion finding.

import "testing"

// hostVariants returns spellings of host that MUST resolve to the same policy
// decision as host itself (the proxy normalizes all of these to one form).
func hostEquivalents(host string) []string {
	return []string{
		host,
		toUpperASCII(host),   // BLOCKED.EXAMPLE
		titleEachLabel(host), // Blocked.Example
		host + ".",           // trailing dot (FQDN root)
	}
}

func toUpperASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}

func titleEachLabel(s string) string {
	b := []byte(s)
	upNext := true
	for i := range b {
		if b[i] == '.' {
			upNext = true
			continue
		}
		if upNext && b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
		upNext = false
	}
	return string(b)
}

// evalBlocks reports whether a single block rule with DestFQDN=pattern blocks
// host, going through the OPTIMIZED Evaluate path (precomputed normFQDN).
func evalBlocks(pattern, host string) bool {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "b", DestFQDN: pattern, Action: ActionBlockPage}})
	return ps.Evaluate("203.0.113.7", "", "unauth", host, nil) != nil
}

// TestPolicySecurity_OptimizedMatchesCanonical is a differential fuzz: for a
// corpus of (pattern, host) pairs heavy with evasion tricks, the optimized
// Evaluate path MUST agree with the canonical matchFQDN (which re-normalizes
// both sides on every call). Any divergence means the perf optimization changed
// matching semantics — a potential bypass.
func TestPolicySecurity_OptimizedMatchesCanonical(t *testing.T) {
	patterns := []string{
		"blocked.example",
		"*.corp.example",
		"deep.sub.blocked.example",
		"café.example",        // Unicode → punycode under IDNA
		"xn--caf-dma.example", // the punycode form
		"EVIL.Example",        // mixed-case pattern
		"a.example",
		"*",
	}
	hosts := []string{
		"blocked.example", "BLOCKED.EXAMPLE", "Blocked.Example", "blocked.example.",
		"x.blocked.example", "evil-blocked.example", "notblocked.example",
		"blocked.example.attacker.com",
		"corp.example", "a.corp.example", "a.b.corp.example", "xcorp.example",
		"café.example", "CAFÉ.example", "xn--caf-dma.example", "XN--CAF-DMA.EXAMPLE",
		"a.example", "a.example.", "b.example",
		"anything.at.all",
	}
	for _, p := range patterns {
		for _, h := range hosts {
			got := evalBlocks(p, h) // optimized: precomputed normFQDN + once-normalized host
			want := matchFQDN(p, h) // canonical: normalizes both fresh
			if got != want {
				t.Errorf("DIVERGENCE pattern=%q host=%q: optimized Evaluate=%v, canonical matchFQDN=%v "+
					"(perf optimization changed FQDN matching semantics — possible policy evasion)", p, h, got, want)
			}
		}
	}
}

// TestPolicySecurity_BlockRuleNotBypassable proves a block rule blocks every
// equivalence-class spelling of the host (the fail-OPEN direction is the
// dangerous one: a blocked host must never slip through).
func TestPolicySecurity_BlockRuleNotBypassable(t *testing.T) {
	const blocked = "malware.example"
	for _, variant := range hostEquivalents(blocked) {
		if !evalBlocks(blocked, variant) {
			t.Errorf("BYPASS: rule blocks %q but variant %q was NOT blocked", blocked, variant)
		}
	}
	// Palo Alto-style: a bare domain blocks its subdomains too.
	for _, sub := range []string{"a." + blocked, "a.b." + blocked, toUpperASCII("a." + blocked), "a." + blocked + "."} {
		if !evalBlocks(blocked, sub) {
			t.Errorf("BYPASS: bare-domain rule %q must block subdomain %q", blocked, sub)
		}
	}
	// Unicode/punycode equivalence: a rule on the Unicode form blocks the
	// punycode wire form and vice versa.
	if !evalBlocks("café.example", "xn--caf-dma.example") {
		t.Errorf("BYPASS: Unicode rule must block its punycode host form")
	}
	if !evalBlocks("xn--caf-dma.example", "CAFÉ.example") {
		t.Errorf("BYPASS: punycode rule must block its (upper) Unicode host form")
	}
}

// TestPolicySecurity_BlockRuleNotOverbroad proves a block rule does NOT block
// unrelated hosts that merely share a substring (the fail-CLOSED-too-much /
// availability direction, and a correctness guard on the suffix logic).
func TestPolicySecurity_BlockRuleNotOverbroad(t *testing.T) {
	const blocked = "ads.example"
	for _, allowed := range []string{
		"notads.example",          // prefix glued without a dot boundary
		"ads.example.trusted.com", // blocked label as a left prefix of a different domain
		"ads-cdn.example",
		"example",    // parent
		"adsexample", // no separator
	} {
		if evalBlocks(blocked, allowed) {
			t.Errorf("OVER-BLOCK: rule %q must NOT block unrelated host %q", blocked, allowed)
		}
	}
}

// TestPolicySecurity_AllowRuleNotOverbroad proves an allow rule cannot be abused
// to reach an unintended host — the most dangerous fail-open: an allow whose
// pattern is a suffix/prefix of an attacker-controlled host.
func TestPolicySecurity_AllowRuleNotOverbroad(t *testing.T) {
	evalAllows := func(pattern, host string) bool {
		ps := &PolicyStore{}
		ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "a", DestFQDN: pattern, Action: ActionAllow}})
		m := ps.Evaluate("203.0.113.7", "", "unauth", host, nil)
		return m != nil && m.Action == ActionAllow
	}
	const allowed = "trusted.example"
	for _, host := range []string{
		"trusted.example.attacker.com", // suffix-confusion: attacker domain ending visually similar
		"nottrusted.example",
		"trusted.example.evil",
		"eviltrusted.example",
	} {
		if evalAllows(allowed, host) {
			t.Errorf("OVER-ALLOW (fail-open): rule allows %q but ALSO allowed unintended host %q", allowed, host)
		}
	}
	// The legitimate matches must still pass.
	for _, host := range hostEquivalents(allowed) {
		if !evalAllows(allowed, host) {
			t.Errorf("rule should allow equivalent host %q of %q", host, allowed)
		}
	}
}

// TestPolicySecurity_WildcardScoping locks the wildcard semantics so a "*.x"
// rule cannot be widened or narrowed unexpectedly by the optimization.
func TestPolicySecurity_WildcardScoping(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"a.corp.example", true},
		{"a.b.corp.example", true},
		{"corp.example", true},    // documented: "*.corp.example" includes the apex
		{"A.CORP.EXAMPLE", true},  // case-insensitive
		{"a.corp.example.", true}, // trailing dot
		{"xcorp.example", false},  // not under .corp.example
		{"corp.example.evil", false},
		{"evilcorp.example", false},
	}
	for _, c := range cases {
		if got := evalBlocks("*.corp.example", c.host); got != c.want {
			t.Errorf("wildcard *.corp.example vs %q = %v, want %v", c.host, got, c.want)
		}
	}
}
