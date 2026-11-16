package syslog

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

// lineformat_test.go — the differential oracle for line assembly.
//
// The bytes this package puts on the wire are a SIEM ingestion contract: a
// collector parses the header positionally and the body as JSON, and a
// regression here is silent (lines keep flowing, parsed wrong or not at all).
// So the optimized builder in lineformat.go is not trusted on inspection; it
// is compared, line for line, against the implementation it replaced, which is
// retained below as legacyFormatLine/legacyMarshalBody and is also the baseline
// arm of the benchmarks.

// legacyFormatLine is the pre-lineformat.go implementation of formatLine,
// verbatim: two fmt.Sprintf header forms, a time.Format per line and a
// three-way concatenation. Retained as the oracle and the benchmark baseline;
// do not "simplify" it to call the new path.
func legacyFormatLine(s *Writer, pri int, msg string, at time.Time) queuedLine {
	var hdr string
	format := s.format
	switch format {
	case "rfc5424":
		hdr = fmt.Sprintf("<%d>1 %s %s %s %s - - ", pri, at.Format(time.RFC3339Nano), s.host, s.tag, s.pid)
	default:
		format = "rfc3164"
		hdr = fmt.Sprintf("<%d>%s %s %s: ", pri, at.Format("Jan 02 15:04:05"), s.host, s.tag)
	}
	return queuedLine{line: hdr + msg + "\n", format: format, pri: pri, hdr: len(hdr), at: at}
}

// legacyMarshalBody is the pre-change WriteRequest/WriteAudit body step:
// json.Marshal into a fresh slice, then a copy into a string for send.
func legacyMarshalBody(v any) (string, bool) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// identityValues are the bodies where a switch from json.Marshal to
// json.Encoder could plausibly diverge: default HTML escaping, the JSONP line
// terminators encoding/json escapes, invalid UTF-8 (replaced, not rejected),
// an explicit nil, the zero struct, and a nested pointer block.
func identityValues() []any {
	return []any{
		realEntryFixture(),
		benchEntry,
		benchRealEntry{},
		nil,
		map[string]any{"html": "<script>&amp;</script>", "ps": "  "},
		map[string]any{"bad": string([]byte{0xff, 0xfe, 'a'})},
		map[string]any{"nested": &benchDecFixture{SchemaVersion: 1, Outcome: "bypass"}},
		[]string{},
		map[string]string(nil),
	}
}

func identityWriters() []*Writer {
	return []*Writer{
		{host: "gw-1", tag: "culvert", pid: "4242", format: "rfc3164"},
		{host: "gw-1", tag: "culvert", pid: "4242", format: "rfc5424"},
		{host: "gw-1", tag: "culvert", pid: "4242", format: ""},        // resolves to rfc3164
		{host: "gw-1", tag: "culvert", pid: "4242", format: "unknown"}, // ditto
	}
}

// TestLineFormat_ByteIdentity_TextBody pins the header and terminator for a
// string body against the legacy builder, for every wire format.
func TestLineFormat_ByteIdentity_TextBody(t *testing.T) {
	at := time.Date(2026, 11, 14, 12, 34, 56, 123456789, time.UTC)
	msgs := []string{"", "plain message", `{"ts":1,"host":"a.example"}`, strings.Repeat("x", 4096)}
	for _, w := range identityWriters() {
		for _, pri := range []int{13, 14, 0, 191} {
			for _, msg := range msgs {
				want := legacyFormatLine(w, pri, msg, at)
				got := w.formatLine(pri, msg, at)
				if got.line != want.line {
					t.Errorf("format=%q pri=%d: line mismatch\n got %q\nwant %q", w.format, pri, got.line, want.line)
				}
				if got.hdr != want.hdr || got.format != want.format || got.pri != want.pri || !got.at.Equal(want.at) {
					t.Errorf("format=%q pri=%d: metadata mismatch got %+v want %+v", w.format, pri, got, want)
				}
			}
		}
	}
}

// TestLineFormat_ByteIdentity_JSONBody is the same comparison for the
// structured senders: encoding the body straight into the line buffer must
// produce exactly json.Marshal's bytes plus the one terminator the text path
// appends itself.
func TestLineFormat_ByteIdentity_JSONBody(t *testing.T) {
	at := time.Date(2026, 11, 14, 12, 34, 56, 123456789, time.UTC)
	for _, w := range identityWriters() {
		for i, v := range identityValues() {
			body, ok := legacyMarshalBody(v)
			if !ok {
				t.Fatalf("value %d is not legacy-encodable; identityValues must only hold encodable bodies", i)
			}
			want := legacyFormatLine(w, 14, body, at)
			got, gotOK := w.formatBody(14, jsonBody(v), at)
			if !gotOK {
				t.Errorf("format=%q value %d: formatBody refused a body json.Marshal accepted", w.format, i)
				continue
			}
			if got.line != want.line {
				t.Errorf("format=%q value %d: line mismatch\n got %q\nwant %q", w.format, i, got.line, want.line)
			}
			if got.hdr != want.hdr || got.format != want.format {
				t.Errorf("format=%q value %d: metadata mismatch got hdr=%d format=%q want hdr=%d format=%q",
					w.format, i, got.hdr, got.format, want.hdr, want.format)
			}
			// The recorded body offset is what a format handoff re-encodes
			// from (forWriter), so it must still bracket exactly the body.
			if gotBody := got.line[got.hdr : len(got.line)-1]; gotBody != body {
				t.Errorf("format=%q value %d: body at hdr offset is %q, want %q", w.format, i, gotBody, body)
			}
		}
	}
}

// TestLineFormat_HandoffReEncodeStillMatches drives the real handoff path: a
// line formatted by an rfc3164 writer, re-encoded for an rfc5424 successor,
// must equal what that successor would have produced for the same body.
func TestLineFormat_HandoffReEncodeStillMatches(t *testing.T) {
	at := time.Date(2026, 11, 14, 12, 34, 56, 123456789, time.UTC)
	src := &Writer{host: "gw-1", tag: "culvert", pid: "7", format: "rfc3164"}
	dst := &Writer{host: "gw-2", tag: "culvert", pid: "9", format: "rfc5424"}
	body, _ := legacyMarshalBody(realEntryFixture())

	item, ok := src.formatBody(14, jsonBody(realEntryFixture()), at)
	if !ok {
		t.Fatal("formatBody refused the fixture")
	}
	re := item.forWriter(dst)
	want := legacyFormatLine(dst, 14, body, at)
	if re.line != want.line {
		t.Errorf("re-encoded line mismatch\n got %q\nwant %q", re.line, want.line)
	}
}

// TestLineFormat_UnencodableBodyDeliversNothing pins the preserved failure
// contract: a body json cannot serialize is DROPPED SILENTLY, exactly as the
// json.Marshal-then-return form did. It must not reach the collector
// truncated, and it must not be charged as a collector drop.
func TestLineFormat_UnencodableBodyDeliversNothing(t *testing.T) {
	bad := map[string]any{"inf": math.Inf(1)}
	if _, ok := legacyMarshalBody(bad); ok {
		t.Fatal("fixture is encodable; the test proves nothing")
	}

	conn := &recordingConn{}
	w := newBenchWriter(conn, true)
	defer func() { _ = w.Close() }()

	dropsBefore := w.Drops()
	w.WriteRequest(bad)
	w.WriteAudit(bad)
	// A good line after the bad ones proves the writer is still usable and
	// that nothing from the failures was left in the buffer it reused.
	w.WriteRequest(realEntryFixture())
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Assert on the RAW bytes, not on newline-split lines. A regression that
	// sent the failed records as header-only lines would emit them WITHOUT a
	// terminator (nothing was encoded after the header), so splitting on '\n'
	// would glue all three together and report one line that still ends in the
	// good body — the shape this test exists to reject would pass. Counting
	// the PRI marker, one per line, catches it: verified by deleting
	// formatBody's error branch, which turns the count into 2 (the refused
	// WriteRequest emits a second <14> header) and the terminator count
	// stays 1.
	raw := conn.raw()
	if got := strings.Count(raw, "<14>"); got != 1 {
		t.Fatalf("collector received %d syslog lines, want exactly the one encodable record (raw %q)", got, raw)
	}
	if got := strings.Count(raw, "\n"); got != 1 {
		t.Errorf("collector received %d terminators, want exactly one (raw %q)", got, raw)
	}
	wantBody, _ := legacyMarshalBody(realEntryFixture())
	if !strings.HasSuffix(raw, wantBody+"\n") {
		t.Errorf("surviving line %q does not end in the expected body %q", raw, wantBody)
	}
	if got := w.Drops() - dropsBefore; got != 0 {
		t.Errorf("an unserializable body was charged as %d collector drop(s); it never reached a writer that refused it", got)
	}
}

// TestLineFormat_PoolDropsOversizeBuffers pins the residency bound: a line
// larger than maxPooledLineBuf is still assembled and sent, and the buffer it
// grew is NOT parked, so one oversized record cannot raise the pool's floor
// for the process.
//
// The assertion is pointer IDENTITY, not capacity. A capacity check is only
// probabilistic — sync.Pool caches per-P and a parked buffer need not come
// back to this goroutine — whereas a buffer that WAS parked lands in this P's
// private slot and is handed back by the very next Get, so identity fails
// deterministically in the direction that matters. In the passing direction
// the loop simply never sees it, which is also what a GC-cleared pool looks
// like, so the test cannot flake the other way.
func TestLineFormat_PoolDropsOversizeBuffers(t *testing.T) {
	w := &Writer{host: "gw", tag: "culvert", pid: "1", format: "rfc3164"}
	big := strings.Repeat("y", maxPooledLineBuf*2)
	item := w.formatLine(14, big, time.Now())
	if !strings.Contains(item.line, big) {
		t.Fatal("oversize line was truncated")
	}

	oversize := getLineBuf()
	oversize.buf.Grow(maxPooledLineBuf + 1)
	if got := oversize.buf.Cap(); got <= maxPooledLineBuf {
		t.Fatalf("fixture buffer is %d bytes, not above the %d-byte bound — the test proves nothing", got, maxPooledLineBuf)
	}
	putLineBuf(oversize)
	for i := 0; i < 256; i++ {
		lb := getLineBuf()
		if lb == oversize {
			t.Fatalf("putLineBuf parked a %d-byte buffer, above the %d-byte residency bound", lb.buf.Cap(), maxPooledLineBuf)
		}
		putLineBuf(lb)
	}
}

// TestLineFormat_ResetOnAcquireNotRelease pins why getLineBuf resets: a buffer
// dropped mid-assembly (a panicking encode) must not hand its partial bytes to
// the next line.
func TestLineFormat_ResetOnAcquireNotRelease(t *testing.T) {
	lb := getLineBuf()
	lb.buf.WriteString("partial record left behind")
	putLineBuf(lb) // released WITHOUT a reset, as a panic unwind would
	for i := 0; i < 64; i++ {
		got := getLineBuf()
		if got.buf.Len() != 0 {
			t.Fatalf("getLineBuf returned a buffer holding %q — a dropped partial record can leak into the next line", got.buf.String())
		}
		putLineBuf(got)
	}
}
