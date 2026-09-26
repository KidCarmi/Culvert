package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// SEC-REQID-2 — the WIRE wall under SEC-REQID-1's tracing-header bound.
//
// Every one of SEC-REQID-1's gates (request_tracing_bounds_test.go) drives
// httptest.NewRequestWithContext + Header.Set, which installs a header value
// the WIRE MAY NOT BE ABLE TO DELIVER. That is the exact trap this repository
// already names one subsystem over — bootstrap_host_injection_test.go exists
// because "httptest.NewRequest lets a test set an r.Host the wire could never
// deliver, which would make the gate prove less than it claims" — and the
// Host-header case therefore carries an EMPIRICAL wall measuring which bytes a
// real net/http server will actually carry. The tracing headers had no such
// wall, leaving two things unproven: that the bound holds on a value that
// arrived over a socket, and how much of the charset gate is load-bearing
// rather than a restatement of what net/http already refuses.
//
// Measured here against a real net/http server: of 256 byte values, 224 are
// delivered into a header value VERBATIM and 32 draw a 400 before the handler
// runs — exactly C0 minus TAB, plus DEL (0x7F). So the charset gate earns its
// keep on 130 DELIVERED byte values: TAB (0x09), SPACE (0x20) and every byte
// 0x80..0xFF. SPACE and TAB are the ones that forge extra key=value tokens
// inside the `{req_id=… identity=… action=…}` block, which is the reason
// request_tracing_bounds.go gives for barring them; that reasoning is correct
// AND wire-reachable, and the length bound is reachable in full.
//
// What is NOT wire-reachable is that file's illustrative payload
// ("abc\x1b[2Kdef\x00ghi\x07jkl\x7fmno"). net/http answers 400 and the handler
// never runs — on every path that reaches setupRequestTracing, which has
// exactly ONE caller (handleRequest, whose request comes from net/http's own
// parser; the inspected-H2 server dispatches to h2InspectStream instead, and
// the SSL-inspect inner loop's http.ReadRequest goes through the same textproto
// validation). The claim is corrected in that file, and THIS wall is what keeps
// the corrected version true: a future Go release that began carrying a C0 byte
// into a header value fails TestSecReqID2Wire_DeliverableByteSpaceIsPinned
// rather than quietly widening what reaches the forensic log.
//
// These gates deliberately assert on the ADOPTED id and on the rejection
// counters, never on captured log output: the handler runs on a server
// goroutine, so swapping the process-global logger from the test goroutine is
// the data-race class this tree has already paid for twice.
// ---------------------------------------------------------------------------

// tracingWireProbe is a real net/http server whose handler is the real
// setupRequestTracing. It reports what that function adopted, and what the
// parser handed it, for a request delivered over a real socket.
type tracingWireProbe struct {
	addr    string
	adopted chan string
	seen    chan []string
}

func newTracingWireProbe(t *testing.T, header string) *tracingWireProbe {
	t.Helper()
	p := &tracingWireProbe{
		adopted: make(chan string, 1),
		seen:    make(chan []string, 1),
	}
	srv := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			vals := append([]string(nil), r.Header[header]...)
			id := setupRequestTracing(w, r)
			select {
			case p.seen <- vals:
			default:
			}
			select {
			case p.adopted <- id:
			default:
			}
			io.WriteString(w, "ok") //nolint:errcheck // probe body is never read
		}),
	}
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go srv.Serve(ln) //nolint:errcheck // Serve always returns on Close
	t.Cleanup(func() { _ = srv.Close() })
	p.addr = ln.Addr().String()
	return p
}

// send delivers one raw request carrying header: value and reports whether
// net/http carried it through to the handler. reached is false when the parser
// refused the request outright (a 400 the handler never sees).
func (p *tracingWireProbe) send(t *testing.T, header, value string) (reached bool, adopted string, seen []string) {
	t.Helper()
	// Drain any stale report so one probe can never read another's.
	select {
	case <-p.adopted:
	default:
	}
	select {
	case <-p.seen:
	default:
	}

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", p.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close() //nolint:errcheck // probe connection
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	raw := "GET /probe HTTP/1.1\r\nHost: probe.invalid\r\n" + header + ": " + value + "\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, raw); err != nil {
		// A value large enough to be refused mid-write is still a refusal.
		return false, "", nil
	}
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return false, "", nil
	}
	if strings.HasPrefix(status, "HTTP/1.1 400") {
		return false, "", nil
	}
	select {
	case adopted = <-p.adopted:
		select {
		case seen = <-p.seen:
		default:
		}
		return true, adopted, seen
	case <-time.After(2 * time.Second):
		t.Fatalf("handler never reported for %q (status %q)", value, strings.TrimSpace(status))
		return false, "", nil
	}
}

// assertAdoptedForDeliveredByte carries the per-byte half of the wall above: the
// parser handed this value through unchanged, so Culvert's bound is the only
// thing standing between the byte and ~20 log sites. Split out of the test to
// keep each piece one job — the sweep classifies, this decides.
func assertAdoptedForDeliveredByte(t *testing.T, b int, value, adopted string, seen []string) {
	t.Helper()
	if len(seen) != 1 || seen[0] != value {
		t.Errorf("byte 0x%02x: parser delivered %q, want exactly [%q]", b, seen, value)
	}
	if b >= 0x21 && b <= 0x7e {
		if adopted != value {
			t.Errorf("byte 0x%02x: adopted %q, want the client's %q", b, adopted, value)
		}
		return
	}
	// Outside the charset: must be replaced by a minted id, never adopted.
	if adopted == value {
		t.Errorf("byte 0x%02x: adopted the client value %q verbatim over the wire", b, value)
	}
	if len(adopted) != requestIDHexLen {
		t.Errorf("byte 0x%02x: adopted %q, want a freshly minted %d-char id", b, adopted, requestIDHexLen)
	}
}

// expectedParserRefusedBytes is the MEASURED partition, pinned: C0 minus TAB is
// 31 byte values, DEL is the 32nd.
func expectedParserRefusedBytes() map[byte]bool {
	want := map[byte]bool{0x7f: true}
	for b := 0x00; b < 0x20; b++ {
		if b != 0x09 {
			want[byte(b)] = true
		}
	}
	return want
}

// assertParserRefusedPartition compares the observed refusal set against the
// measured one in BOTH directions, which is what makes the wall fail for a Go
// release that widens the deliverable set AND for one that narrows it.
func assertParserRefusedPartition(t *testing.T, refusedByParser []byte) {
	t.Helper()
	want := expectedParserRefusedBytes()
	got := make(map[byte]bool, len(refusedByParser))
	for _, b := range refusedByParser {
		got[b] = true
	}

	if len(refusedByParser) != len(want) {
		t.Errorf("net/http refused %d byte values, expected %d: %#v", len(refusedByParser), len(want), refusedByParser)
	}
	for _, b := range refusedByParser {
		if !want[b] {
			t.Errorf("net/http refused 0x%02x, which this wall did not expect — the deliverable set NARROWED; re-check which gates still prove anything", b)
		}
	}
	for b := range want {
		if !got[b] {
			t.Errorf("net/http now DELIVERS 0x%02x into a header value; the deliverable set WIDENED and request_tracing_bounds.go's reachability note is stale", b)
		}
	}
}

// TestSecReqID2Wire_DeliverableByteSpaceIsPinned is the empirical wall. It
// measures, byte by byte, what a real net/http server will carry into a header
// value, and requires that every DELIVERED byte outside the accepted charset is
// refused by the bound rather than adopted.
//
// The partition itself is asserted, not just the refusals, so this fails in
// BOTH directions: a Go release that starts delivering a C0 byte fails it (the
// forensic log's exposure would have widened), and one that starts refusing a
// byte the bound relies on also fails it (a gate would have gone vacuous).
func TestSecReqID2Wire_DeliverableByteSpaceIsPinned(t *testing.T) {
	p := newTracingWireProbe(t, headerRequestID)

	var delivered, refusedByParser []byte
	for b := 0; b < 256; b++ {
		value := "a" + string([]byte{byte(b)}) + "b"
		reached, adopted, seen := p.send(t, headerRequestID, value)
		if !reached {
			refusedByParser = append(refusedByParser, byte(b))
			continue
		}
		delivered = append(delivered, byte(b))
		assertAdoptedForDeliveredByte(t, b, value, adopted, seen)
	}

	assertParserRefusedPartition(t, refusedByParser)

	// NOT VACUOUS: the wall is worthless if almost nothing is delivered.
	if len(delivered) != 224 {
		t.Errorf("delivered %d byte values, expected 224 — the measurement this wall records has changed", len(delivered))
	}
}

// TestSecReqID2Wire_CharsetGateIsLoadBearingOverTheWire is the control for the
// wall above. The cheapest way to satisfy "no out-of-charset byte is adopted"
// is for net/http to have refused them all already, which would make the
// charset half of SEC-REQID-1 a second opinion rather than a bound. It is not:
// TAB, SPACE and all 128 non-ASCII bytes ARE delivered and ARE refused here.
func TestSecReqID2Wire_CharsetGateIsLoadBearingOverTheWire(t *testing.T) {
	p := newTracingWireProbe(t, headerRequestID)

	cases := []struct {
		name string
		b    byte
	}{
		{"TAB forges a token in the decision block", 0x09},
		{"SPACE forges a token in the decision block", 0x20},
		{"first non-ASCII byte", 0x80},
		{"last non-ASCII byte", 0xff},
	}
	earned := 0
	for _, c := range cases {
		value := "a" + string([]byte{c.b}) + "b"
		reached, adopted, seen := p.send(t, headerRequestID, value)
		if !reached {
			t.Errorf("%s (0x%02x): net/http refused it, so the charset gate is not what stops it", c.name, c.b)
			continue
		}
		if len(seen) != 1 || seen[0] != value {
			t.Errorf("%s (0x%02x): parser delivered %q, want [%q]", c.name, c.b, seen, value)
		}
		if adopted == value {
			t.Fatalf("%s (0x%02x): adopted over the wire", c.name, c.b)
		}
		earned++
	}
	if earned != len(cases) {
		t.Errorf("the charset gate is load-bearing for %d of %d probed bytes; it must be all of them", earned, len(cases))
	}
}

// TestSecReqID2Wire_OversizeIsRefusedOverTheWire proves the LENGTH half end to
// end. This is the half that is fully wire-reachable: net/http bounds header
// bytes only by MaxHeaderBytes, which the proxy listener does not set.
func TestSecReqID2Wire_OversizeIsRefusedOverTheWire(t *testing.T) {
	p := newTracingWireProbe(t, headerRequestID)
	resetTracingBoundsStateForTest()

	// Comfortably inside net/http's 1 MiB default so delivery is the thing
	// under test, not the parser's own ceiling.
	payload := strings.Repeat("A", 200*1024)
	reached, adopted, seen := p.send(t, headerRequestID, payload)
	if !reached {
		t.Fatal("net/http refused a 200 KiB header value; the length bound cannot be proven over the wire this way")
	}
	if len(seen) != 1 || len(seen[0]) != len(payload) {
		t.Fatalf("parser delivered %d values (first %d bytes), want one of %d bytes", len(seen), len(seen[0]), len(payload))
	}
	if adopted == payload {
		t.Fatal("a 200 KiB client request id was adopted over the wire")
	}
	if len(adopted) != requestIDHexLen {
		t.Errorf("adopted %d bytes, want a freshly minted %d-char id", len(adopted), requestIDHexLen)
	}
	if got := requestIDRejected.Load(); got != 1 {
		t.Errorf("rejections counted = %d, want 1 — the operator's only signal did not move", got)
	}
}

// TestSecReqID2Wire_LengthBoundaryOverTheWire pins both sides of the bound on
// values that really traversed a socket. An off-by-one here widens by exactly
// one byte the value a client can write into every log line the request makes.
func TestSecReqID2Wire_LengthBoundaryOverTheWire(t *testing.T) {
	p := newTracingWireProbe(t, headerRequestID)

	atLimit := strings.Repeat("a", maxClientRequestIDLen)
	overLimit := strings.Repeat("a", maxClientRequestIDLen+1)

	reached, adopted, _ := p.send(t, headerRequestID, atLimit)
	if !reached {
		t.Fatal("net/http refused a value at the limit")
	}
	if adopted != atLimit {
		t.Errorf("a value exactly at the limit was not adopted: got %q", adopted)
	}

	reached, adopted, _ = p.send(t, headerRequestID, overLimit)
	if !reached {
		t.Fatal("net/http refused a value one byte over the limit")
	}
	if adopted == overLimit {
		t.Error("a value one byte over the limit was adopted")
	}
	if len(adopted) != requestIDHexLen {
		t.Errorf("adopted %q, want a freshly minted id", adopted)
	}
}

// TestSecReqID2Wire_DuplicateHeaderOverTheWire proves the duplicate collapse on
// the shape that motivated it: two field lines really sent by a client, which
// the probe above confirms net/http delivers as two values.
func TestSecReqID2Wire_DuplicateHeaderOverTheWire(t *testing.T) {
	p := newTracingWireProbe(t, headerRequestID)

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", p.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close() //nolint:errcheck // probe connection
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	const good = "0af7651916cd43dd8448eb211c80319c"
	const hostile = "second value with spaces"
	raw := "GET /probe HTTP/1.1\r\nHost: probe.invalid\r\n" +
		headerRequestID + ": " + good + "\r\n" +
		headerRequestID + ": " + hostile + "\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
		t.Fatalf("read status: %v", err)
	}

	var seen []string
	var adopted string
	select {
	case adopted = <-p.adopted:
		select {
		case seen = <-p.seen:
		default:
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler never reported")
	}

	if len(seen) != 2 {
		t.Fatalf("parser delivered %d values, want 2 — this gate no longer probes a duplicate", len(seen))
	}
	if adopted == good {
		t.Error("the first of two values was adopted; ambiguous correlation is not correlation")
	}
	if adopted == hostile {
		t.Error("the hostile second value was adopted")
	}
	if len(adopted) != requestIDHexLen {
		t.Errorf("adopted %q, want a freshly minted id", adopted)
	}
}

// TestSecReqID2Wire_Control_LegitimateIDsPropagateOverTheWire is the control
// for the whole file. The cheapest way to pass every gate above is to stop
// honouring client tracing headers at all, which would silently delete
// distributed tracing through the gateway — so a real correlation id delivered
// over a real socket must still come through byte for byte.
func TestSecReqID2Wire_Control_LegitimateIDsPropagateOverTheWire(t *testing.T) {
	p := newTracingWireProbe(t, headerRequestID)
	resetTracingBoundsStateForTest()

	for _, id := range []string{
		"0af7651916cd43dd8448eb211c80319c",         // W3C trace-id shape
		"3f2504e0-4f89-11d3-9a0c-0305e82c3301",     // UUID
		"01ARZ3NDEKTSV4RRFFQ69G5FAV",               // ULID
		strings.Repeat("a", maxClientRequestIDLen), // exactly at the bound
		"~!#$%&'*+-.^_`|",                          // the awkward-but-visible tail of the charset
	} {
		reached, adopted, _ := p.send(t, headerRequestID, id)
		if !reached {
			t.Fatalf("net/http refused a legitimate id %q", id)
		}
		if adopted != id {
			t.Errorf("legitimate id %q was replaced with %q", id, adopted)
		}
	}
	if got := requestIDRejected.Load(); got != 0 {
		t.Errorf("legitimate ids counted %d rejections, want 0", got)
	}
}

// TestSecReqID2Wire_TraceparentBoundHoldsOverTheWire covers the second header.
// Its bound is checked before any scrub, so it has always been the cheap shape;
// this proves it on a socket rather than on a hand-built request.
func TestSecReqID2Wire_TraceparentBoundHoldsOverTheWire(t *testing.T) {
	p := newTracingWireProbe(t, headerTraceparent)
	resetTracingBoundsStateForTest()

	const valid = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	reached, _, seen := p.send(t, headerTraceparent, valid)
	if !reached {
		t.Fatal("net/http refused a valid traceparent")
	}
	if len(seen) != 1 || seen[0] != valid {
		t.Fatalf("parser delivered %q, want [%q]", seen, valid)
	}
	if got := traceparentRejected.Load(); got != 0 {
		t.Errorf("a valid traceparent counted %d rejections, want 0", got)
	}

	// Over the bound: refused, counted, and replaced.
	over := strings.Repeat("a", maxClientTraceparentLen+1)
	reached, _, _ = p.send(t, headerTraceparent, over)
	if !reached {
		t.Fatal("net/http refused an over-long traceparent; the bound cannot be proven this way")
	}
	if got := traceparentRejected.Load(); got != 1 {
		t.Errorf("traceparent rejections = %d, want 1", got)
	}
}
