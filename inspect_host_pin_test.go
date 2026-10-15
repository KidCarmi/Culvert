package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// ── Inner-host pinning on a TLS-inspected tunnel ─────────────────────────────
//
// The defect these gates gate: a CONNECT tunnel is authorized ONCE, against the
// CONNECT authority, but every inner request on the decrypted stream carries its
// own Host/:authority and was forwarded upstream verbatim. Policy, the forged
// leaf, the scan verdicts and every log row are all keyed on the CONNECT host,
// so a client could reuse an allowed tunnel to fetch a different vhost from a
// shared front end while the operator's log named the allowed one.
//
// All of these drive runInspectExchange, the protocol-neutral seam BOTH the H1
// keep-alive loop and the H2 per-stream handler run (invariant C5), so one gate
// covers both protocols. Asserting on the seam rather than on a live tunnel is
// deliberate: it is the single enforcement point, and a protocol-specific test
// could pass while the other protocol regressed.

// pinExchange builds an exchange whose tunnel was authorized for tunnelHost and
// whose inner request claims innerHost. The round-trip hook records whether the
// upstream was contacted at all and with which host — the two facts that decide
// whether the pin held.
func pinExchange(tunnelHost, innerHost string) (ex *inspectExchange, forwarded *bool, sawHost *string, spy *spyResponder) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://placeholder.invalid/x", http.NoBody)
	req.Host = innerHost

	didForward := false
	upstreamHost := ""
	spy = &spyResponder{}
	ex = &inspectExchange{
		outer:     req,
		req:       req,
		host:      tunnelHost,
		clientIP:  "198.51.100.7",
		responder: spy,
		roundTrip: func(rq *http.Request) (*http.Response, error) {
			didForward = true
			upstreamHost = rq.Host
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		},
		deliver: func(*http.Response) error { return nil },
	}
	return ex, &didForward, &upstreamHost, spy
}

// TestInnerHostPin_MismatchIsRefusedBeforeTheUpstreamIsContacted is the DEFECT
// GATE. Verified failing against the verbatim pre-fix runInspectExchange body,
// which delivered the exchange (exDelivered) with the upstream having received
// the client's own Host.
//
// The assertion is NOT merely "blocked": it is that the upstream was never
// contacted. A refusal taken after the round trip would still have fetched the
// unauthorized resource, which on a shared front end is the whole harm.
func TestInnerHostPin_MismatchIsRefusedBeforeTheUpstreamIsContacted(t *testing.T) {
	resetInnerHostMismatchStateForTest()
	t.Cleanup(resetInnerHostMismatchStateForTest)
	logs := chaos66CaptureLog(t)

	ex, forwarded, sawHost, spy := pinExchange("allowed.example.com", "blocked.example.com")
	out := runInspectExchange(ex)

	if *forwarded {
		t.Errorf("upstream was contacted with Host %q on a tunnel authorized for %q — "+
			"the unauthorized destination was fetched", *sawHost, ex.host)
	}
	if out.kind != exBlocked {
		t.Errorf("kind = %v, want exBlocked", out.kind)
	}
	if spy.calls != 1 {
		t.Errorf("responder calls = %d, want 1 (exactly one block emitted)", spy.calls)
	}
	if !strings.Contains(spy.lastBd, "does not match") {
		t.Errorf("block body = %q, want it to name the mismatch", spy.lastBd)
	}
	if got := proxyInnerHostMismatchBlocked.Load(); got != 1 {
		t.Errorf("counter = %d, want 1 — the operator's only signal for this class", got)
	}
	// Both hosts must reach the operator: either alone says nothing.
	line := logs.String()
	if !strings.Contains(line, "INNER_HOST_MISMATCH") ||
		!strings.Contains(line, `tunnel="allowed.example.com"`) ||
		!strings.Contains(line, `inner="blocked.example.com"`) {
		t.Errorf("log line = %q, want INNER_HOST_MISMATCH naming both hosts", line)
	}
}

// TestInnerHostPin_AuthorizedDestinationStillFlows is the NEGATIVE CONTROL. A
// gate that refused everything would pass the defect gate above while taking
// the proxy offline, so the matching case must be proven to still reach the
// upstream untouched.
func TestInnerHostPin_AuthorizedDestinationStillFlows(t *testing.T) {
	resetInnerHostMismatchStateForTest()
	t.Cleanup(resetInnerHostMismatchStateForTest)

	ex, forwarded, sawHost, spy := pinExchange("allowed.example.com", "allowed.example.com")
	out := runInspectExchange(ex)

	if !*forwarded {
		t.Fatal("an inner request naming the authorized destination was refused — the pin is over-tight")
	}
	if *sawHost != "allowed.example.com" {
		t.Errorf("upstream Host = %q, want it forwarded unchanged", *sawHost)
	}
	if out.kind != exDelivered {
		t.Errorf("kind = %v, want exDelivered", out.kind)
	}
	if spy.calls != 0 {
		t.Errorf("responder calls = %d, want 0 on the clean path", spy.calls)
	}
	if got := proxyInnerHostMismatchBlocked.Load(); got != 0 {
		t.Errorf("counter = %d, want 0 — a matching host must not be charged", got)
	}
}

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
		// SCOPE: a CONNECT to an address carries no name to pin against. The
		// client resolved the origin itself and names it in SNI and Host — the
		// shape connectAndTLS models and real clients produce (curl --resolve).
		{"named inner host against an IPv4 CONNECT target", "inspect.test", "127.0.0.1", true,
			"client-side resolution: refusing would break supported traffic"},
		{"named inner host against an IPv6 CONNECT target", "inspect.test", "2001:db8::1", true,
			"same, over IPv6"},
		{"named inner host against a ported IPv4 CONNECT target", "inspect.test:8443", "127.0.0.1:8443", true,
			"the port is stripped from both sides before the address test"},
		{"empty inner host", "", "a.example.com", true,
			"names no competing destination, so it cannot reach another vhost"},

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
		{"inner IP literal against a named tunnel", "203.0.113.5", "allowed.example.com", false,
			"no conforming client sends an address in Host for a connection it opened to a name"},
		{"unnormalizable inner host", "xn--.example.com", "allowed.example.com", false,
			"fail-closed: no canonical form means no comparison, not a free pass"},
		{"empty tunnel host", "anything.example.com", "", false,
			"no recorded authorized destination means nothing to forward a client-chosen host against"},
		{"both empty", "", "", true,
			"the empty inner host short-circuits first; it names nothing either way"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := innerHostPinnedToTunnel(tc.inner, tc.tunnel); got != tc.wantPinned {
				t.Errorf("innerHostPinnedToTunnel(%q, %q) = %v, want %v — %s",
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
	if innerHostPinnedToTunnel(inner, tunnel) {
		t.Errorf("innerHostPinnedToTunnel(%q, %q) = true — the pin must demand the SAME host, "+
			"not the policy matcher's subdomain-inclusive match", inner, tunnel)
	}
}

// TestInnerHostPin_ConcurrentMismatchesAreAllCharged exercises the counter and
// the shared seam under -race: the exchange carries per-request state, and the
// counter is a process global that every inspected tunnel in the proxy charges.
func TestInnerHostPin_ConcurrentMismatchesAreAllCharged(t *testing.T) {
	resetInnerHostMismatchStateForTest()
	t.Cleanup(resetInnerHostMismatchStateForTest)
	chaos66CaptureLog(t)

	const workers, each = 8, 50
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				ex, forwarded, _, _ := pinExchange("allowed.example.com", "blocked.example.com")
				if out := runInspectExchange(ex); out.kind != exBlocked || *forwarded {
					t.Errorf("concurrent exchange was not refused (kind=%v forwarded=%v)", out.kind, *forwarded)
					return
				}
			}
		}()
	}
	wg.Wait()

	if got, want := proxyInnerHostMismatchBlocked.Load(), int64(workers*each); got != want {
		t.Errorf("counter = %d, want %d — every refusal must be charged exactly once", got, want)
	}
}

// TestInnerHostPin_RefusalIsEmittedOnBothProtocolWires proves the refusal
// reaches the client correctly on each transport, since the two responders write
// different bytes: H1 writes a raw HTTP/1.1 403 with Connection: close, H2 writes
// a 403 through the ResponseWriter and must NOT send a connection-specific
// header (illegal in HTTP/2, RFC 9113 §8.2.2).
func TestInnerHostPin_RefusalIsEmittedOnBothProtocolWires(t *testing.T) {
	resetInnerHostMismatchStateForTest()
	t.Cleanup(resetInnerHostMismatchStateForTest)
	chaos66CaptureLog(t)

	t.Run("h1 writes a complete 403 onto the conn", func(t *testing.T) {
		var sink strings.Builder
		blockInnerHostMismatch(h1BlockResponder{w: &sink}, "198.51.100.7", "allowed.example.com", "blocked.example.com")
		got := sink.String()
		for _, want := range []string{"HTTP/1.1 403 Forbidden", "Connection: close", "does not match"} {
			if !strings.Contains(got, want) {
				t.Errorf("H1 refusal missing %q; got:\n%s", want, got)
			}
		}
	})

	t.Run("h2 writes a 403 with no connection header", func(t *testing.T) {
		rec := newH2PinRecorder()
		blockInnerHostMismatch(&h2BlockResponder{w: rec}, "198.51.100.7", "allowed.example.com", "blocked.example.com")
		if rec.status != http.StatusForbidden {
			t.Errorf("H2 status = %d, want 403", rec.status)
		}
		if v := rec.Header().Get("Connection"); v != "" {
			t.Errorf("H2 refusal set Connection: %q — illegal in HTTP/2", v)
		}
		if !strings.Contains(rec.body.String(), "does not match") {
			t.Errorf("H2 body = %q, want it to name the mismatch", rec.body.String())
		}
	})
}

// h2PinRecorder is a minimal http.ResponseWriter capturing what the H2 responder
// wrote. httptest.ResponseRecorder would serve, but this keeps the assertion to
// the three facts that matter and carries no default-header behaviour of its own.
type h2PinRecorder struct {
	hdr    http.Header
	status int
	body   strings.Builder
}

func newH2PinRecorder() *h2PinRecorder { return &h2PinRecorder{hdr: make(http.Header)} }

func (r *h2PinRecorder) Header() http.Header  { return r.hdr }
func (r *h2PinRecorder) WriteHeader(code int) { r.status = code }
func (r *h2PinRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(p)
}

// TestInnerHostPin_ClientResolvedAddressTunnelStillFlows is the scope gate, and
// the one the repository's own inspect e2e suite would otherwise have caught the
// hard way: connectAndTLS CONNECTs to a loopback ADDRESS and then presents
// "inspect.test" as both SNI and inner Host. That is the client-side-resolution
// shape (curl --resolve, any client with its own resolver), it is supported, and
// a pin that compared a name against an address would refuse every one of those
// requests.
//
// Keeping it at the pipeline level rather than only in the predicate table is
// deliberate: this is the shape a future tightening of the pin would break, and
// a table row is easier to "fix" than a flowing exchange.
func TestInnerHostPin_ClientResolvedAddressTunnelStillFlows(t *testing.T) {
	resetInnerHostMismatchStateForTest()
	t.Cleanup(resetInnerHostMismatchStateForTest)

	for _, tunnel := range []string{"127.0.0.1", "2001:db8::1"} {
		t.Run(tunnel, func(t *testing.T) {
			ex, forwarded, sawHost, spy := pinExchange(tunnel, "inspect.test")
			out := runInspectExchange(ex)

			if !*forwarded {
				t.Fatalf("a CONNECT to address %q with inner Host %q was refused — "+
					"client-side resolution is a supported shape", tunnel, "inspect.test")
			}
			if *sawHost != "inspect.test" {
				t.Errorf("upstream Host = %q, want the client's own host forwarded unchanged", *sawHost)
			}
			if out.kind != exDelivered {
				t.Errorf("kind = %v, want exDelivered", out.kind)
			}
			if spy.calls != 0 {
				t.Errorf("responder calls = %d, want 0", spy.calls)
			}
		})
	}
}

// TestInnerHostPin_SNIAgreementDoesNotExcuseTheMismatch states why the pin
// anchors on the CONNECT authority rather than the client's SNI. A client
// controls both its SNI and its Host header, so it can make them agree with each
// other and still name a destination the policy engine never evaluated. Only the
// authorizing value — the CONNECT authority — is a safe anchor.
//
// Anchoring on SNI would make this case pass, which is why this gate exists: it
// fails CI if the pin is ever "simplified" to compare against the SNI.
func TestInnerHostPin_SNIAgreementDoesNotExcuseTheMismatch(t *testing.T) {
	resetInnerHostMismatchStateForTest()
	t.Cleanup(resetInnerHostMismatchStateForTest)
	chaos66CaptureLog(t)

	// The client presented SNI "blocked.example.com" (so the forged leaf names
	// it) and sends the matching Host — over a tunnel policy authorized for
	// allowed.example.com.
	ex, forwarded, _, _ := pinExchange("allowed.example.com", "blocked.example.com")
	if out := runInspectExchange(ex); out.kind != exBlocked || *forwarded {
		t.Errorf("a self-consistent SNI/Host pair naming an unauthorized destination was forwarded "+
			"(kind=%v forwarded=%v) — the pin must anchor on the CONNECT authority policy evaluated",
			out.kind, *forwarded)
	}
}
