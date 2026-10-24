package main

import (
	"net"
	"testing"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// SEC-GEOHOST-1 — the geo host key must be canonical.
//
// geoHostKey only stripped a port: no lowercasing, no IDNA, no trailing-dot
// trim. It is the key for the host->IP cache that geoResolver.LookupCached
// consults, and matchDestNorm passes it the RAW host (policy.go's comment
// "Country checks keep using the raw host (they normalize internally)" was
// false). On a cache miss the country is unknown and the rule does NOT match —
// fail-closed for an allow rule, but for a DENY rule it means the rule is
// skipped and evaluation falls through to a lower-priority allow.
//
// So a client could evade every destCountry-scoped deny rule by varying the
// case of the Host header / CONNECT authority: each spelling is a distinct
// cache key, the warm is off-path, so the first request for each spelling
// always missed. A 19-character hostname has ~2^15 spellings, which is an
// unlimited supply of first requests. Every other destination matcher
// (blocklist, urlcat, policy FQDN) already normalized.

// TestSECGEOHOST1_HostKeyIsCanonical is the DEFECT GATE: every spelling of one
// destination must collapse to one key. Pre-fix each row returned its input.
func TestSECGEOHOST1_HostKeyIsCanonical(t *testing.T) {
	const canonical = "blocked.example.com"
	for _, variant := range []string{
		"blocked.example.com",
		"BLOCKED.EXAMPLE.COM",
		"Blocked.Example.Com",
		"bLoCkEd.eXaMpLe.CoM",
		"blocked.example.com.", // trailing dot
		"BLOCKED.Example.COM.", // both
		"blocked.example.com:443",
		"BLOCKED.EXAMPLE.COM:443",
		"Blocked.Example.Com.:8080",
	} {
		if got := geoHostKey(variant); got != canonical {
			t.Errorf("DEFECT: geoHostKey(%q) = %q, want %q — this spelling gets its own cache key and evades every destCountry rule",
				variant, got, canonical)
		}
	}
}

// TestSECGEOHOST1_HostKeyFoldsIDNSpellings covers the other evasion axis: a
// U-label and its A-label are the same destination and must share one key.
func TestSECGEOHOST1_HostKeyFoldsIDNSpellings(t *testing.T) {
	for _, pair := range []struct{ u, a string }{
		{"bücher.example.com", "xn--bcher-kva.example.com"},
		{"BÜCHER.example.com", "xn--bcher-kva.example.com"},
		{"bücher.example.com:443", "xn--bcher-kva.example.com"},
	} {
		if got := geoHostKey(pair.u); got != pair.a {
			t.Errorf("DEFECT: geoHostKey(%q) = %q, want the A-label %q", pair.u, got, pair.a)
		}
	}
}

// TestSECGEOHOST1_IPLiteralsSurviveUnchanged is the regression control for the
// resolver path: geoHostKey's output feeds net.ParseIP in resolveHost and
// resolveHostCached, so an IP literal must come through byte-for-byte or geo
// lookup for IP destinations breaks.
func TestSECGEOHOST1_IPLiteralsSurviveUnchanged(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"203.0.113.10", "203.0.113.10"},
		{"203.0.113.10:443", "203.0.113.10"},
		{"2001:db8::1", "2001:db8::1"},
		{"[2001:db8::1]", "[2001:db8::1]"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"::1", "::1"},
	} {
		got := geoHostKey(tc.in)
		if got != tc.want {
			t.Errorf("geoHostKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
		// The literal rows must still parse as IPs — that is what the two
		// resolver entry points do with this value.
		if tc.in != "[2001:db8::1]" && net.ParseIP(got) == nil {
			t.Errorf("geoHostKey(%q) = %q, which no longer parses as an IP", tc.in, got)
		}
	}
}

// TestSECGEOHOST1_HostKeyAgreesWithTheOtherMatchers pins the cross-engine
// property that was broken: the geo key must be the same canonical form every
// other destination matcher keys on, so one host cannot be two destinations.
func TestSECGEOHOST1_HostKeyAgreesWithTheOtherMatchers(t *testing.T) {
	for _, host := range []string{
		"Blocked.Example.Com", "BLOCKED.EXAMPLE.COM.", "bücher.example.com",
		"xn--bcher-kva.example.com", "203.0.113.10", "2001:db8::1",
	} {
		want := hostutil.NormalizeHost(host)
		if got := geoHostKey(host); got != want {
			t.Errorf("geoHostKey(%q) = %q but the other matchers use %q — one destination, two identities",
				host, got, want)
		}
	}
}

// TestSECGEOHOST1_CachedLookupHitsAcrossSpellings is the end-to-end gate on the
// layer matchDestNorm actually consults: warm the cache ONCE under the
// canonical name, then look it up under each attacker spelling. Pre-fix every
// variant was a miss, which is what made the deny rule not match.
func TestSECGEOHOST1_CachedLookupHitsAcrossSpellings(t *testing.T) {
	const canonical = "geo-probe.example.com"
	want := net.ParseIP("203.0.113.10")
	resolvedHostCache.put(canonical, want)

	for _, variant := range []string{
		canonical,
		"GEO-PROBE.EXAMPLE.COM",
		"Geo-Probe.Example.Com",
		"geo-probe.example.com.",
		"GEO-PROBE.EXAMPLE.COM:443",
	} {
		ip, ok := resolveHostCached(variant)
		if !ok {
			t.Errorf("DEFECT: resolveHostCached(%q) reported a cache MISS for an already-warmed destination — a destCountry deny rule would not match and the request would fall through",
				variant)
			continue
		}
		if !ip.Equal(want) {
			t.Errorf("resolveHostCached(%q) = %v, want %v", variant, ip, want)
		}
	}
}
