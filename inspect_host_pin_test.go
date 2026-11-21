package main

import (
	"bufio"
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

// The predicate's own gates (TestInnerHostPinnedToTunnel_Equivalences,
// TestInnerHostPin_SuffixMatchWouldNotHaveCaught and the wire oracle
// TestInnerHostPin_WireAgreesWithWhatWasPinned) live beside it in
// internal/hostpin, where the boundary and malformed-input cases belong:
// driving each through the whole pipeline would assert the same thing far more
// slowly.

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

// TestInnerHostPin_EmptyInnerHostIsRefused is the second DEFECT GATE (Codex P1
// on PR #1632). The first revision of this gate treated an absent inner
// authority as pinned, on the reasoning that it names no competing destination
// and that the origin would reject it anyway. The second half was the real
// error — it assumed the ORIGIN's behaviour instead of enforcing here.
//
// This test states the mechanism rather than trusting the claim, so the gate
// cannot be "simplified" back by someone who repeats the original reasoning:
// it first proves against the real stdlib that the request is BOTH accepted by
// the reader this path uses AND serialized upstream with an empty Host, then
// asserts the pin refuses it.
func TestInnerHostPin_EmptyInnerHostIsRefused(t *testing.T) {
	resetInnerHostMismatchStateForTest()
	t.Cleanup(resetInnerHostMismatchStateForTest)
	chaos66CaptureLog(t)

	// PRECONDITION 1: runH1InspectLoop reads inner requests with
	// http.ReadRequest, NOT through an http.Server — so the server's "missing
	// required Host header" 400 never runs on this path.
	parsed, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"GET /secret HTTP/1.1\r\nConnection: close\r\n\r\n")))
	if err != nil {
		t.Fatalf("precondition: http.ReadRequest must ACCEPT a Host-less HTTP/1.1 request "+
			"(it is what this path uses); got %v", err)
	}
	if parsed.Host != "" {
		t.Fatalf("precondition: expected req.Host == \"\", got %q", parsed.Host)
	}

	// PRECONDITION 2: Request.Write serializes that as a literal "Host: " and
	// does NOT error — i.e. absent the pin, the Host-less request reaches the
	// upstream, where a default/fallback vhost can answer it.
	var wire strings.Builder
	parsed.URL.Scheme = "https"
	if werr := parsed.Write(&wire); werr != nil {
		t.Fatalf("precondition: expected Write to serialize an empty Host, got error %v", werr)
	}
	if !strings.Contains(wire.String(), "Host: \r\n") {
		t.Fatalf("precondition: expected a literal empty \"Host: \" line on the wire, got:\n%s", wire.String())
	}

	// THE GATE: the pin must refuse it, on a named tunnel and on an address
	// tunnel alike.
	for _, tunnel := range []string{"allowed.example.com", "127.0.0.1"} {
		t.Run(tunnel, func(t *testing.T) {
			ex, forwarded, _, spy := pinExchange(tunnel, "")
			out := runInspectExchange(ex)
			if *forwarded {
				t.Errorf("a Host-less inner request was forwarded upstream on a tunnel for %q — "+
					"a front end's default vhost can answer it, unevaluated by policy", tunnel)
			}
			if out.kind != exBlocked {
				t.Errorf("kind = %v, want exBlocked", out.kind)
			}
			if spy.calls != 1 {
				t.Errorf("responder calls = %d, want 1", spy.calls)
			}
		})
	}

	if got, want := proxyInnerHostMismatchBlocked.Load(), int64(2); got != want {
		t.Errorf("counter = %d, want %d", got, want)
	}
}

// TestInnerHostPin_BracketedDNSAuthorityIsRefused is the third DEFECT GATE
// (Codex P1 on PR #1632). It states the MECHANISM against the real stdlib
// rather than trusting the claim, because the defect is precisely that the
// comparison and the wire disagree — a test that only checked the predicate
// would not show why the predicate has to care.
//
// It also pins what must NOT be refused alongside it: Request.Write converts a
// U-label to the A-label on the wire, so that spelling's forwarded bytes
// already match what the pin authorized and refusing it would reject a
// conforming client.
func TestInnerHostPin_BracketedDNSAuthorityIsRefused(t *testing.T) {
	resetInnerHostMismatchStateForTest()
	t.Cleanup(resetInnerHostMismatchStateForTest)
	chaos66CaptureLog(t)

	wireHost := func(t *testing.T, hostHdr string) string {
		t.Helper()
		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
			"GET /x HTTP/1.1\r\nHost: " + hostHdr + "\r\nConnection: close\r\n\r\n")))
		if err != nil {
			t.Fatalf("precondition: http.ReadRequest must accept Host %q on this path; got %v", hostHdr, err)
		}
		req.URL.Scheme = "https"
		var sb strings.Builder
		if werr := req.Write(&sb); werr != nil {
			t.Fatalf("precondition: Request.Write(%q) errored: %v", hostHdr, werr)
		}
		for _, line := range strings.Split(sb.String(), "\r\n") {
			if strings.HasPrefix(strings.ToLower(line), "host:") {
				return strings.TrimSpace(strings.TrimPrefix(line, "Host:"))
			}
		}
		t.Fatalf("precondition: no Host line serialized for %q", hostHdr)
		return ""
	}

	// PRECONDITION: the bracketed authority survives to the wire unrepaired,
	// while StripHostPort repairs it into the authorized name.
	const bracketed = "[allowed.example.com]"
	if got := wireHost(t, bracketed); got != bracketed {
		t.Fatalf("precondition: expected %q forwarded verbatim, got %q", bracketed, got)
	}
	if repaired := hostutil.StripHostPort(bracketed); repaired != "allowed.example.com" {
		t.Fatalf("precondition: expected StripHostPort to repair %q to the bare name, got %q",
			bracketed, repaired)
	}

	// THE GATE: the pin must refuse it rather than compare the repaired value.
	ex, forwarded, _, spy := pinExchange("allowed.example.com", bracketed)
	if out := runInspectExchange(ex); out.kind != exBlocked || *forwarded {
		t.Errorf("a bracketed authority posing as the authorized host was forwarded "+
			"(kind=%v forwarded=%v) — the wire would carry %q, which no vhost is configured for, "+
			"so a shared front end can answer from its default", out.kind, *forwarded, bracketed)
	}
	if spy.calls != 1 {
		t.Errorf("responder calls = %d, want 1", spy.calls)
	}

	// CONTROL: a U-label is NOT this defect — Go sends the A-label, so the
	// forwarded bytes already match the authorized host.
	t.Run("u-label is not refused because the wire carries the A-label", func(t *testing.T) {
		const ulabel = "bücher.example.com"
		const alabel = "xn--bcher-kva.example.com"
		if got := wireHost(t, ulabel); got != alabel {
			t.Fatalf("precondition: expected Request.Write to send %q for %q, got %q", alabel, ulabel, got)
		}
		if !innerHostPinnedToTunnel(ulabel, alabel) {
			t.Error("a U-label inner host against its own A-label tunnel must stay pinned")
		}
	})
}
