package main

// proxy_tunnel_inspectbuf_test.go — the contract on inspectLoopReadBufSize
// (proxy_tunnel.go), the bufio.Reader size runH1InspectLoop gives each leg of a
// decrypted HTTP/1.1 tunnel.
//
// This file exists because that size was two bare `32*1024` literals with no
// recorded reason, and the obvious reading of it — "a buffer size is a cost
// knob; parsing cannot depend on it" — is WRONG on this path. net/http reads a
// chunked body's trailers through the same bufio.Reader and bounds the trailer
// block by the reader's buffer size (net/http/transfer.go, readTrailer ->
// seeUpcomingDoubleCRLF). So the constant decides which traffic an inspected
// tunnel accepts, and shrinking it for memory would silently refuse chunked
// responses that are delivered today.
//
// The tests below therefore split the claim in two, instead of asserting the
// comfortable half:
//
//   - TestInspectLoopReadBuf_TrailerWindowIsLoadBearing proves the DEPENDENCE,
//     by execution against the real stdlib, so a future shrink fails here with
//     the reason attached rather than in production.
//   - TestInspectLoopReadBuf_HeaderShapesDoNotDependOnTheSize proves the
//     INDEPENDENCE where it genuinely holds — header blocks and over-long
//     header lines, which textproto reassembles across refills — so the
//     load-bearing part is scoped to what actually bears load and a future
//     reader does not have to re-derive the boundary.
//
// Negative controls are included for the usual reason: an oracle that only ever
// compares two successes would also pass if both arms stopped parsing.

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// inspectLoopReadBufShrunkSize is the size a memory-motivated change would
// reach for: what net/http's own server and http.Transport use for the
// identical two roles. It is the counter-arm of the trailer-window test, and
// the hypothetical arm of the residency benchmarks — NOT a candidate value, for
// the reason that test demonstrates.
const inspectLoopReadBufShrunkSize = 4 * 1024

// TestInspectLoopReaders_UseTheConfiguredSize pins the production constructor to
// the documented constant on BOTH legs.
//
// Without this, the constant and the readers could drift apart: someone
// re-inlining bufio.NewReaderSize with a literal would leave the trailer-window
// contract below asserting a size production no longer uses, and it would still
// pass.
func TestInspectLoopReaders_UseTheConfiguredSize(t *testing.T) {
	clientBR, upstreamBR := newInspectLoopReaders(strings.NewReader(""), strings.NewReader(""))
	if got := clientBR.Size(); got != inspectLoopReadBufSize {
		t.Errorf("client leg reader size = %d, want inspectLoopReadBufSize (%d)", got, inspectLoopReadBufSize)
	}
	if got := upstreamBR.Size(); got != inspectLoopReadBufSize {
		t.Errorf("upstream leg reader size = %d, want inspectLoopReadBufSize (%d)", got, inspectLoopReadBufSize)
	}
}

// ── the load-bearing half ────────────────────────────────────────────────────

// chunkedBodyWithTrailerBlock renders a chunked message body whose trailer block
// is at least `want` bytes of header lines, terminated by the blank line.
func chunkedBodyWithTrailerBlock(want int) string {
	var tr strings.Builder
	for i := 0; tr.Len() < want; i++ {
		fmt.Fprintf(&tr, "X-Trace-%05d: %s\r\n", i, strings.Repeat("v", 40))
	}
	return "5\r\nhello\r\n0\r\n" + tr.String() + "\r\n"
}

// readChunkedTrailers parses a chunked response through a reader of the given
// size and reports how far it got. The body is read to completion, because the
// trailer block is only consulted after the terminating 0-length chunk — which
// is exactly why this cost is invisible to a header-only test.
func readChunkedTrailers(size int, trailerBlockBytes int) (body string, trailers int, err error) {
	wire := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trace-00000\r\n\r\n" +
		chunkedBodyWithTrailerBlock(trailerBlockBytes)
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/x", http.NoBody) //nolint:noctx // in-memory template for ReadResponse; never dialled
	br := bufio.NewReaderSize(strings.NewReader(wire), size)
	resp, rerr := http.ReadResponse(br, req)
	if rerr != nil {
		return "", 0, rerr
	}
	b, berr := io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck // in-memory reader; nothing to fail
	return string(b), len(resp.Trailer), berr
}

// TestInspectLoopReadBuf_TrailerWindowIsLoadBearing is the reason
// inspectLoopReadBufSize is not a free cost knob.
//
// net/http bounds a chunked message's trailer block by the bufio.Reader's
// buffer size (transfer.go: readTrailer calls seeUpcomingDoubleCRLF, which Peeks
// until the buffer is full; its own comment says "This limits the trailer to the
// underlying buffer size"). Both legs of an inspected tunnel read chunked bodies
// through these readers, so the constant sets the trailer block the tunnel will
// accept — on the response leg AND on a chunked inner request serialized
// upstream.
//
// The assertion is deliberately two-sided. A block that fits the shipped size
// must be ACCEPTED, and the same block must be REJECTED at the size a
// memory-motivated change would reach for. Both halves matter: the first is the
// traffic contract, and without the second the test would keep passing if the
// dependence disappeared, leaving a comment nothing checks.
//
// If this fails after a change to inspectLoopReadBufSize, the change is not a
// performance tweak: it narrows the traffic an inspected tunnel accepts, and
// with scanning on the refusal tears the tunnel down (scanInspectBody ->
// scanReadError -> exDeliverError).
func TestInspectLoopReadBuf_TrailerWindowIsLoadBearing(t *testing.T) {
	// Comfortably inside the shrunk size: must work either way, so a failure
	// here means the harness, not the window.
	t.Run("small-block-works-at-both-sizes", func(t *testing.T) {
		for _, size := range []int{inspectLoopReadBufShrunkSize, inspectLoopReadBufSize} {
			body, n, err := readChunkedTrailers(size, 512)
			if err != nil || body != "hello" || n == 0 {
				t.Fatalf("harness: a 512-byte trailer block must parse at size %d; got body=%q trailers=%d err=%v",
					size, body, n, err)
			}
		}
	})

	// The window itself. 8 KiB of trailers is past the shrunk size and inside
	// the shipped one.
	t.Run("block-past-the-shrunk-size", func(t *testing.T) {
		const block = 8 * 1024
		body, n, err := readChunkedTrailers(inspectLoopReadBufSize, block)
		if err != nil {
			t.Errorf("TRAFFIC CONTRACT: a ~%d-byte chunked trailer block must be ACCEPTED at the "+
				"shipped inspect-leg reader size (%d); got err=%v. An inspected tunnel now refuses "+
				"trailered chunked traffic the plain-HTTP forward path accepts (its http.Transport "+
				"ReadBufferSize is 64 KiB — upstream_transport.go), i.e. enabling inspection now "+
				"breaks responses that pass with it off.", block, inspectLoopReadBufSize, err)
		}
		if body != "hello" || n == 0 {
			t.Errorf("expected the body and trailers to survive at size %d; got body=%q trailers=%d",
				inspectLoopReadBufSize, body, n)
		}

		if _, _, serr := readChunkedTrailers(inspectLoopReadBufShrunkSize, block); serr == nil {
			t.Errorf("CONTROL LOST: a ~%d-byte trailer block was accepted at %d bytes too, so this "+
				"test no longer demonstrates that the reader size bounds the trailer window. Either "+
				"the stdlib's readTrailer/seeUpcomingDoubleCRLF bound changed, or the block is no "+
				"longer past the smaller buffer — re-establish the dependence before trusting the "+
				"assertion above, and re-read the rationale on inspectLoopReadBufSize.",
				block, inspectLoopReadBufShrunkSize)
		}
	})

	// The edge, so the comment's measured table cannot drift from reality: a
	// block just over the shrunk size already fails there.
	t.Run("edge-just-past-the-shrunk-size", func(t *testing.T) {
		if _, _, err := readChunkedTrailers(inspectLoopReadBufShrunkSize, inspectLoopReadBufShrunkSize); err == nil {
			t.Errorf("expected a ~%d-byte trailer block to be refused by a %d-byte reader; it was "+
				"accepted, so the measured table on inspectLoopReadBufSize is stale",
				inspectLoopReadBufShrunkSize, inspectLoopReadBufShrunkSize)
		}
	})
}

// ── the independent half, scoped ─────────────────────────────────────────────

// padHeaders renders n header lines of the given value width, used to build a
// header block deliberately larger than any candidate buffer size.
func padHeaders(n, width int) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "X-Pad-%03d: %s\r\n", i, strings.Repeat("a", width))
	}
	return sb.String()
}

// reqFingerprint renders every parsed field this path acts on, plus the body and
// everything left unread on the stream, into one comparable string.
//
// It deliberately does NOT include br.Buffered(): how much of a pipelined stream
// sits in the buffer is a function of the buffer size by definition, and
// asserting it would make the oracle fail for the one reason that is not a
// defect. What must match is the parse and the bytes still available after it.
func reqFingerprint(wire string, size int) string {
	br := bufio.NewReaderSize(strings.NewReader(wire), size)
	req, err := http.ReadRequest(br)
	if err != nil {
		return "ERR:" + err.Error()
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "method=%s uri=%s proto=%s host=%s cl=%d te=%v close=%v\n",
		req.Method, req.URL.RequestURI(), req.Proto, req.Host, req.ContentLength,
		req.TransferEncoding, req.Close)
	writeSortedHeader(&sb, req.Header)
	body, berr := io.ReadAll(req.Body)
	fmt.Fprintf(&sb, "body=%d/%s err=%v\n", len(body), shortHash(body), berr)
	req.Body.Close() //nolint:errcheck // in-memory reader; nothing to fail
	rest, rerr := io.ReadAll(br)
	fmt.Fprintf(&sb, "rest=%d/%s err=%v\n", len(rest), shortHash(rest), rerr)
	return sb.String()
}

// respFingerprint is reqFingerprint for the upstream leg (http.ReadResponse on
// upstreamBR).
func respFingerprint(wire string, size int) string {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/x", http.NoBody) //nolint:noctx // in-memory template for ReadResponse; never dialled
	br := bufio.NewReaderSize(strings.NewReader(wire), size)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return "ERR:" + err.Error()
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "status=%d proto=%s cl=%d te=%v close=%v\n",
		resp.StatusCode, resp.Proto, resp.ContentLength, resp.TransferEncoding, resp.Close)
	writeSortedHeader(&sb, resp.Header)
	body, berr := io.ReadAll(resp.Body)
	fmt.Fprintf(&sb, "body=%d/%s err=%v\n", len(body), shortHash(body), berr)
	resp.Body.Close() //nolint:errcheck // in-memory reader; nothing to fail
	writeSortedHeader(&sb, resp.Trailer)
	rest, rerr := io.ReadAll(br)
	fmt.Fprintf(&sb, "rest=%d/%s err=%v\n", len(rest), shortHash(rest), rerr)
	return sb.String()
}

func writeSortedHeader(sb *strings.Builder, h http.Header) {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	// Insertion sort: the corpus has tens of keys and this keeps the helper
	// dependency-free next to the oracle it serves.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	for _, k := range keys {
		fmt.Fprintf(sb, "  %s: %s\n", k, strings.Join(h[k], "\x1f"))
	}
}

// shortHash renders a length-and-content digest so a fingerprint mismatch names
// the divergence without dumping kilobytes of corpus into the failure.
func shortHash(b []byte) string {
	var h uint64 = 1469598103934665603
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return fmt.Sprintf("%016x", h)
}

// TestInspectLoopReadBuf_HeaderShapesDoNotDependOnTheSize scopes the
// independence claim to where it actually holds.
//
// Header parsing is genuinely size-independent — textproto's readLineSlice loops
// on bufio's ReadLine and accumulates while isPrefix is set, so neither an
// over-long single line nor a header block larger than the buffer is affected —
// and that is worth pinning, because it is the half of the boundary a future
// change may rely on. The chunked-trailer half, which is NOT independent, is
// pinned separately above. Keeping them apart is the point: a single
// "parses identically" test over a corpus that happened to omit trailers is what
// made the size look free in the first place.
func TestInspectLoopReadBuf_HeaderShapesDoNotDependOnTheSize(t *testing.T) {
	ordinary := "GET /some/path/resource.json HTTP/1.1\r\n" +
		"Host: www.example.com\r\n" +
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0.0.0 Safari/537.36\r\n" +
		"Accept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.8\r\n" +
		"Cookie: sid=0123456789abcdef0123456789abcdef; prefs=aaaabbbbccccdddd\r\n" +
		"\r\n"
	reqCorpus := []struct {
		name string
		wire string
	}{
		{"ordinary", ordinary},
		{"header-block-larger-than-the-shrunk-buffer",
			"GET /x HTTP/1.1\r\nHost: example.com\r\n" + padHeaders(40, 200) + "\r\n"},
		// A SINGLE line larger than the shrunk buffer. bufio.ReadSlice cannot
		// return it; textproto's readLineSlice loop reassembles it.
		{"single-header-line-larger-than-the-shrunk-buffer",
			"GET /x HTTP/1.1\r\nHost: example.com\r\nX-Huge: " + strings.Repeat("b", 9000) + "\r\n\r\n"},
		{"body-content-length",
			"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6000\r\n\r\n" +
				strings.Repeat("c", 6000)},
		{"body-chunked-no-trailer",
			"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n" +
				"1000\r\n" + strings.Repeat("d", 4096) + "\r\n" +
				"800\r\n" + strings.Repeat("e", 2048) + "\r\n0\r\n\r\n"},
		// Pipelining matters: a larger reader pre-reads more of the FOLLOWING
		// request, which is why the oracle compares the drained remainder rather
		// than Buffered().
		{"pipelined-pair", ordinary + ordinary},
		{"websocket-upgrade",
			"GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n" +
				"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
				"Sec-WebSocket-Version: 13\r\n\r\n"},
	}
	for _, tc := range reqCorpus {
		t.Run("request/"+tc.name, func(t *testing.T) {
			small := reqFingerprint(tc.wire, inspectLoopReadBufShrunkSize)
			big := reqFingerprint(tc.wire, inspectLoopReadBufSize)
			if small != big {
				t.Errorf("inner-request parse DIVERGED between reader sizes for a shape documented as "+
					"size-independent — the boundary recorded on inspectLoopReadBufSize is wrong.\n"+
					"at %d bytes:\n%s\nat %d bytes:\n%s",
					inspectLoopReadBufShrunkSize, small, inspectLoopReadBufSize, big)
			}
			if strings.HasPrefix(small, "ERR:") {
				t.Errorf("corpus entry failed to parse at BOTH sizes (%s) — a positive case that "+
					"errors proves nothing about size independence", small)
			}
		})
	}

	ordinaryResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 11\r\n\r\nhello world"
	respCorpus := []struct {
		name string
		wire string
	}{
		{"ordinary", ordinaryResp},
		{"header-block-larger-than-the-shrunk-buffer",
			"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n" + padHeaders(40, 200) + "\r\n"},
		{"single-header-line-larger-than-the-shrunk-buffer",
			"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Huge: " + strings.Repeat("b", 9000) + "\r\n\r\n"},
		// A SMALL trailer block, inside every candidate size. The size-dependent
		// large-trailer case belongs to the load-bearing test, not here.
		{"chunked-with-small-trailer",
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n" +
				"1000\r\n" + strings.Repeat("f", 4096) + "\r\n0\r\nX-Sum: 42\r\n\r\n"},
		// The 101 the inspect loop turns into a raw relay. Its body is not
		// allowed, so ReadResponse stops at the headers at either size — and the
		// `rest=` field records the bytes left buffered behind it, which the
		// upgrade arm currently drops (see the Performance Guardian review of
		// 2026-11-09, Finding 2; not a property this test asserts).
		{"switching-protocols",
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" +
				"\x81\x05hello"},
		{"pipelined-pair", ordinaryResp + ordinaryResp},
	}
	for _, tc := range respCorpus {
		t.Run("response/"+tc.name, func(t *testing.T) {
			small := respFingerprint(tc.wire, inspectLoopReadBufShrunkSize)
			big := respFingerprint(tc.wire, inspectLoopReadBufSize)
			if small != big {
				t.Errorf("upstream-response parse DIVERGED between reader sizes for a shape documented "+
					"as size-independent.\nat %d bytes:\n%s\nat %d bytes:\n%s",
					inspectLoopReadBufShrunkSize, small, inspectLoopReadBufSize, big)
			}
			if strings.HasPrefix(small, "ERR:") {
				t.Errorf("corpus entry failed to parse at BOTH sizes (%s)", small)
			}
		})
	}
}

// TestInspectLoopReadBuf_NegativeControls is the oracle's own control: malformed
// input must be REJECTED, identically, at both sizes.
//
// Without it, the comparison above would be satisfied by an arm that had stopped
// parsing altogether — two equal "ERR:" strings compare equal.
func TestInspectLoopReadBuf_NegativeControls(t *testing.T) {
	cases := []struct {
		name string
		wire string
	}{
		{"truncated-request-line", "GET /x HT"},
		{"no-terminating-blank-line", "GET /x HTTP/1.1\r\nHost: example.com\r\n"},
		{"bad-method-token", "G\x00ET /x HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{"non-numeric-content-length", "POST /x HTTP/1.1\r\nHost: e\r\nContent-Length: abc\r\n\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			small := reqFingerprint(tc.wire, inspectLoopReadBufShrunkSize)
			big := reqFingerprint(tc.wire, inspectLoopReadBufSize)
			if !strings.HasPrefix(small, "ERR:") {
				t.Errorf("malformed input ACCEPTED at %d bytes — the oracle's positive cases "+
					"cannot be read as evidence if the parser accepts anything: %s",
					inspectLoopReadBufShrunkSize, small)
			}
			if small != big {
				t.Errorf("rejection DIVERGED between reader sizes.\nat %d: %s\nat %d: %s",
					inspectLoopReadBufShrunkSize, small, inspectLoopReadBufSize, big)
			}
		})
	}
}
