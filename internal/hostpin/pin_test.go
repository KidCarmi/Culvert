package hostpin

import (
	"bufio"
	"net/http"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// The predicate's own gates, moved from package main's inspect_host_pin_test.go
// with their names and assertions unchanged (ADR-0052). The gates that drive
// runInspectExchange, the refusal counter and the block responders stay there.

// TestInnerHostPinnedToTunnel_Equivalences pins the predicate directly, which is
// where the boundary and malformed-input cases belong: driving each through the
// whole pipeline would assert the same thing far more slowly.
//
// The spellings that must be ACCEPTED are the ones the downstream matchers
// already fold to one destination (case, a trailing dot, the A-label of a
// U-label, an explicit port, IPv6 brackets). Accepting them is not laxity — a
// pin that refused them would reject traffic policy allowed, for spellings that
// name the very same host.
func TestInnerHostPinnedToTunnel_Equivalences(t *testing.T) {
	cases := []struct {
		name       string
		inner      string
		tunnel     string
		wantPinned bool
		why        string
	}{
		// ── Same destination, different spelling: must be PINNED ──────────
		{"identical", "a.example.com", "a.example.com", true, "the ordinary case"},
		{"inner carries the default port", "a.example.com:443", "a.example.com", true,
			"the TCP connection already fixes the port; a port claim redirects nothing"},
		{"inner carries a non-default port", "a.example.com:8443", "a.example.com", true,
			"same host, same pinned connection"},
		{"case differs", "A.Example.COM", "a.example.com", true,
			"IDNA canonicalization lowercases both sides"},
		{"trailing dot", "a.example.com.", "a.example.com", true,
			"the root label is stripped by NormalizeHostStrict"},
		{"U-label against the A-label the CONNECT carried", "bücher.example.com", "xn--bcher-kva.example.com", true,
			"both canonicalize to the same A-label"},
		{"A-label against a U-label tunnel", "xn--bcher-kva.example.com", "bücher.example.com", true,
			"symmetric"},
		{"IPv4 literal", "203.0.113.5", "203.0.113.5", true, "IP literals have no IDNA form"},
		{"bracketed IPv6 inner against de-ported tunnel", "[2001:db8::1]", "2001:db8::1", true,
			"the Host header brackets IPv6; SplitHostPort already de-bracketed the tunnel side"},
		{"bracketed IPv6 with a port", "[2001:db8::1]:8443", "2001:db8::1", true,
			"the legitimate bracket form must keep working, with and without a port"},
		// SCOPE: a CONNECT to an address carries no name to pin against. The
		// client resolved the origin itself and names it in SNI and Host — the
		// shape connectAndTLS models and real clients produce (curl --resolve).
		{"named inner host against an IPv4 CONNECT target", "inspect.test", "127.0.0.1", true,
			"client-side resolution: refusing would break supported traffic"},
		{"named inner host against an IPv6 CONNECT target", "inspect.test", "2001:db8::1", true,
			"same, over IPv6"},
		{"named inner host against a ported IPv4 CONNECT target", "inspect.test:8443", "127.0.0.1:8443", true,
			"the port is stripped from both sides before the address test"},
		{"empty inner host", "", "a.example.com", false,
			"Request.Write serializes a literal \"Host: \"; a shared front end may answer from its default vhost"},
		{"empty inner host against an address tunnel", "", "127.0.0.1", false,
			"refused ahead of the IP-literal scope skip: the default-vhost risk does not depend on the tunnel being a name"},
		// SEC-TUNHOST-2: an ASCII-case difference in an A-label is the same DNS
		// name (labels are case-insensitive), so this spelling must keep
		// pinning even though the wire bytes differ from the authorized form.
		// It is the boundary against the mixed-case U-label case below, whose
		// punycode PAYLOAD differs, not just its case.
		{"U-label whose A-label differs only in ASCII case", "Bücher.example.com", "xn--bcher-kva.example.com", true,
			"punycode of \"Bücher\" is \"xn--Bcher-kva\": the same label, differently cased, so the same destination"},

		// ── Different destination: must NOT be pinned ─────────────────────
		{"different host", "blocked.example.com", "allowed.example.com", false, "the defect"},
		{"subdomain of the authorized host", "evil.allowed.example.com", "allowed.example.com", false,
			"a subdomain is a DIFFERENT destination and got no policy decision of its own"},
		{"parent of the authorized host", "example.com", "a.example.com", false, "likewise"},
		{"suffix-extension of the authorized host", "allowed.example.com.evil.test", "allowed.example.com", false,
			"a suffix match would be the classic almost-right comparison"},
		{"prefix-truncation of the authorized host", "allowed.example.co", "allowed.example.com", false,
			"not a prefix game either"},
		{"different IP literal", "203.0.113.6", "203.0.113.5", true,
			"the tunnel side is an address, so the pin does not fire at all (scope)"},
		// Brackets are legal ONLY around an IP literal. StripHostPort would
		// repair "[name]" to a bare name that MATCHES, while Request.Write
		// forwards the bracketed bytes verbatim — so the comparison and the wire
		// would disagree. Codex P1 on PR #1632.
		{"bracketed DNS name posing as the authorized host", "[allowed.example.com]", "allowed.example.com", false,
			"StripHostPort repairs it to a match; the wire keeps the brackets and no vhost is configured for them"},
		{"bracketed DNS name with a port", "[allowed.example.com]:443", "allowed.example.com", false,
			"SplitHostPort de-brackets this shape too, so it needs the same refusal"},
		{"stray closing bracket", "allowed.example.com]", "allowed.example.com", false,
			"a bracket without a matched surrounding pair is malformed"},
		{"stray opening bracket", "[allowed.example.com", "allowed.example.com", false,
			"likewise"},
		{"nested brackets", "[[2001:db8::1]]", "allowed.example.com", false,
			"never a valid authority"},
		{"inner IP literal against a named tunnel", "203.0.113.5", "allowed.example.com", false,
			"no conforming client sends an address in Host for a connection it opened to a name"},
		{"unnormalizable inner host", "xn--.example.com", "allowed.example.com", false,
			"fail-closed: no canonical form means no comparison, not a free pass"},
		{"empty tunnel host", "anything.example.com", "", false,
			"no recorded authorized destination means nothing to forward a client-chosen host against"},
		{"both empty", "", "", false,
			"no authority on either side: nothing to authorize against and nothing routable"},

		// ── SEC-TUNHOST-2: the repair gap the bracket case generalizes to ──
		//
		// StripHostPort ends in net.SplitHostPort, which splits on the LAST
		// colon and never validates the port, so each of these reduces to the
		// authorized host and used to PIN. Request.write then runs
		// httpguts.ValidHostHeader on the same value, finds the '/', '@' or
		// '?', and (usingProxy=false) ZEROES the authority — emitting a literal
		// "Host: ", byte-for-byte the state the empty-inner-host branch above
		// refuses, reached THROUGH the comparison. Measured, go1.27.3.
		{"invalid pseudo-port carrying a path separator", "allowed.example.com:0/x", "allowed.example.com", false,
			"pin saw the authorized host; the wire would carry no authority at all"},
		{"userinfo-shaped pseudo-port naming another host", "allowed.example.com:@blocked.example.com", "allowed.example.com", false,
			"same repair gap, with the blocked host hidden after the '@'"},
		{"query-shaped pseudo-port", "allowed.example.com:443?x", "allowed.example.com", false,
			"a valid-looking port plus a '?' is still a Host header net/http will not send"},
		{"invalid pseudo-port against an address tunnel", "203.0.113.5:0/x", "203.0.113.5", false,
			"refused ahead of the IP-literal scope skip, as the empty inner host is"},
		// The other half: IDNA case is not preserved through punycode.
		// NormalizeHostStrict lowercases BEFORE idna.ToASCII while
		// httpguts.PunycodeHostPort does not, and punycode encodes case in its
		// payload — so this pinned while the wire carried
		// "xn--BCHER-2pa.example.com", a DIFFERENT A-label (not a case variant:
		// "bcher-2pa" != "bcher-kva"), i.e. a name policy never evaluated.
		{"mixed-case U-label against an A-label tunnel", "BÜCHER.example.com", "xn--bcher-kva.example.com", false,
			"punycode of \"BÜCHER\" is \"xn--BCHER-2pa\", a different label from the authorized \"xn--bcher-kva\""},
		{"empty port is still the authorized host", "allowed.example.com:", "allowed.example.com", true,
			"net/http sends \"host:\" verbatim and every origin stack strips the empty port, so it is the same destination"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Pinned(tc.inner, tc.tunnel); got != tc.wantPinned {
				t.Errorf("Pinned(%q, %q) = %v, want %v — %s",
					tc.inner, tc.tunnel, got, tc.wantPinned, tc.why)
			}
		})
	}
}

// TestInnerHostPin_SuffixMatchWouldNotHaveCaught is the differential statement of
// the one comparison that would look right and be wrong. MatchFQDNNorm's
// bare-domain semantics treat "evil.allowed.example.com" as matching
// "allowed.example.com" — correct for a POLICY RULE, catastrophic for this pin,
// because a subdomain is a separate destination that policy never evaluated.
//
// Pinning the distinction here means a future refactor that reaches for the
// policy matcher to "reuse the host comparison" fails CI.
func TestInnerHostPin_SuffixMatchWouldNotHaveCaught(t *testing.T) {
	const tunnel = "allowed.example.com"
	const inner = "evil." + tunnel

	if !hostutil.MatchFQDNNorm(tunnel, inner) {
		t.Fatal("precondition: the policy matcher is expected to treat the subdomain as matching the bare domain")
	}
	if Pinned(inner, tunnel) {
		t.Errorf("Pinned(%q, %q) = true — the pin must demand the SAME host, "+
			"not the policy matcher's subdomain-inclusive match", inner, tunnel)
	}
}

// TestInnerHostPin_WireAgreesWithWhatWasPinned is the differential ORACLE for
// SEC-TUNHOST-2, and the reason that fix is not a list of refused spellings.
//
// The pin's whole value rests on one invariant: whenever it says "pinned", the
// authority the UPSTREAM receives must be the destination policy authorized.
// Both defects it closed were violations of exactly that — the pin compared a
// value hostutil.StripHostPort had repaired, while net/http serialized the
// unrepaired one (zeroing it outright for an invalid Host, or punycoding it to
// a differently-cased A-label).
//
// So this test does not assert verdicts. It drives the real stdlib path for a
// corpus of inner authorities — http.ReadRequest exactly as runH1InspectLoop
// does, then Request.Write exactly as the H1 leg does — and for every one the
// pin ACCEPTS it asserts that the serialized Host still canonicalizes to the
// tunnel's host. A future repair added on either side of the comparison fails
// here even if nobody thought to add its spelling to the table above.
func TestInnerHostPin_WireAgreesWithWhatWasPinned(t *testing.T) {
	const tunnel = "allowed.example.com"
	corpus := []string{
		// Accepted spellings (the invariant must hold for these).
		tunnel, tunnel + ".", tunnel + ":443", tunnel + ":8443", tunnel + ":",
		"ALLOWED.example.com", "Allowed.Example.Com.",
		// Repair-gap candidates: either refused, or forwarded as the authorized host.
		tunnel + ":0/x", tunnel + ":443?x", tunnel + ":@blocked.example.com",
		tunnel + ":443#f", tunnel + ":44 3", tunnel + ":443\\x", tunnel + ":{}",
		tunnel + ":443|x", tunnel + ":443<x", tunnel + ":443\"x",
		"[" + tunnel + "]", "[" + tunnel + "]:443", tunnel + "]", "[" + tunnel,
		// Different destinations (must be refused; included so a change that
		// accepts them is caught by the invariant rather than only by the table).
		"blocked.example.com", "evil." + tunnel, tunnel + ".evil.test",
	}

	wantHost, ok := hostutil.NormalizeHostStrict(tunnel)
	if !ok {
		t.Fatalf("fixture tunnel %q does not normalize", tunnel)
	}

	accepted := 0
	for _, inner := range corpus {
		t.Run(inner, func(t *testing.T) {
			if assertPinnedAuthorityReachesTheTunnel(t, inner, tunnel, wantHost) {
				accepted++
			}
		})
	}
	// Non-vacuity: a corpus that pinned nothing would pass every assertion.
	if accepted == 0 {
		t.Fatal("no corpus entry was pinned — the oracle asserted nothing")
	}
}

// assertPinnedAuthorityReachesTheTunnel drives one corpus entry of the oracle
// above and reports whether the pin ACCEPTED it. When it did, the authority
// net/http actually serializes must still canonicalize to tunnelHost; when it
// did not, there is nothing to assert, because nothing is forwarded.
//
// Extracted from the loop body so the oracle stays inside the repository's
// cognitive-complexity budget (gocognit, .golangci.yml) without weakening any
// assertion.
func assertPinnedAuthorityReachesTheTunnel(t *testing.T, inner, tunnelHost, wantHost string) (pinned bool) {
	t.Helper()
	raw := "GET /x HTTP/1.1\r\nHost: " + inner + "\r\n\r\n"
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		return false // ReadRequest refused it, so it never reaches the pin at all
	}
	// Production passes ex.req.Host — the value Request.Write will serialize —
	// not the raw header bytes. Feed the pin the same thing.
	if !Pinned(req.Host, tunnelHost+":443") {
		return false
	}

	var sb strings.Builder
	if err := req.Write(&sb); err != nil {
		t.Fatalf("pinned %q but Request.Write refused it: %v", req.Host, err)
	}
	wire, found := serializedHostHeader(sb.String())
	if !found {
		t.Fatalf("pinned %q but the serialized request carries no Host line", req.Host)
	}
	if wire == "" {
		t.Fatalf("pinned %q but the wire carries an EMPTY authority — a shared front end "+
			"would answer from its default vhost, the bypass this gate exists to close", req.Host)
	}
	got, gotOK := hostutil.NormalizeHostStrict(hostutil.StripHostPort(wire))
	if !gotOK {
		t.Fatalf("pinned %q but the wire authority %q does not normalize", req.Host, wire)
	}
	// ASCII case is not a difference: DNS labels and Host matching are
	// case-insensitive, and NormalizeHostStrict has already folded both.
	if got != wantHost {
		t.Fatalf("pinned %q but the wire names %q (canonically %q), not the authorized %q — "+
			"a destination policy never evaluated", req.Host, wire, got, wantHost)
	}
	return true
}

// serializedHostHeader returns the value of the Host header in a serialized
// HTTP/1.1 request, and whether one was emitted at all. An invalid Host makes
// Request.write emit "Host: " with an empty value rather than omit the line, so
// the two cases are reported separately.
func serializedHostHeader(serialized string) (value string, found bool) {
	for _, line := range strings.Split(serialized, "\r\n") {
		if after, cut := strings.CutPrefix(line, "Host: "); cut {
			return after, true
		}
	}
	return "", false
}

// FuzzPinned_WireAgreesWithWhatWasPinned runs the oracle above over arbitrary
// inner authorities: whatever Pinned accepts, the Host net/http serializes
// must still canonicalize to the tunnel's host. New with the package
// (ADR-0052); the seeds are the oracle's own corpus.
func FuzzPinned_WireAgreesWithWhatWasPinned(f *testing.F) {
	const tunnel = "allowed.example.com"
	for _, seed := range []string{
		tunnel, tunnel + ".", tunnel + ":443", tunnel + ":", "ALLOWED.example.com",
		tunnel + ":0/x", tunnel + ":@blocked.example.com", "[" + tunnel + "]",
		"blocked.example.com", "evil." + tunnel, "bücher.example.com", "",
	} {
		f.Add(seed)
	}
	wantHost, ok := hostutil.NormalizeHostStrict(tunnel)
	if !ok {
		f.Fatalf("fixture tunnel %q does not normalize", tunnel)
	}
	f.Fuzz(func(t *testing.T, inner string) {
		assertPinnedAuthorityReachesTheTunnel(t, inner, tunnel, wantHost)
	})
}

// TestPinned_ConcurrentCallsAgree runs the predicate from many goroutines
// under -race: it has no state of its own, so every call must return what a
// lone call returns.
func TestPinned_ConcurrentCallsAgree(t *testing.T) {
	type pair struct {
		inner, tunnel string
		want          bool
	}
	pairs := []pair{
		{"a.example.com:443", "a.example.com", true},
		{"b.example.com", "a.example.com", false},
		{"BÜCHER.example.com", "xn--bcher-kva.example.com", false},
		{"bücher.example.com", "xn--bcher-kva.example.com", true},
		{"anything.example.com", "203.0.113.5", true},
		{"", "203.0.113.5", false},
	}
	done := make(chan string, 16)
	for w := 0; w < 16; w++ {
		go func() {
			for i := 0; i < 200; i++ {
				p := pairs[i%len(pairs)]
				if got := Pinned(p.inner, p.tunnel); got != p.want {
					done <- p.inner + " against " + p.tunnel
					return
				}
			}
			done <- ""
		}()
	}
	for w := 0; w < 16; w++ {
		if bad := <-done; bad != "" {
			t.Errorf("concurrent Pinned(%s) disagreed with the single-call verdict", bad)
		}
	}
}
