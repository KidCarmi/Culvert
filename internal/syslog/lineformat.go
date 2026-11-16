package syslog

import (
	"bytes"
	"encoding/json"
	"strconv"
	"sync"
	"time"
)

// lineformat.go — assembly of the bytes one syslog message puts on the wire.
//
// WHY THIS FILE EXISTS. Delivery is already asynchronous: the drain goroutine
// owns the socket, so a slow collector costs a caller a channel send and
// nothing more (see the package header). What stayed on the CALLER's goroutine
// is the part that builds the line — and for WriteRequest that caller is a
// proxy request goroutine, once per logged request, on every protocol.
//
// Three avoidable costs were paid there, all measurable on a realistic
// request-log record (25 fields, 375 bytes of JSON — the shape logstore.Entry
// actually produces; Go 1.27.4, linux/amd64, 4 vCPU Xeon @2.10GHz, -count=3
// medians, BenchmarkWriteRequest_RealEntry* below):
//
//	stage                                     allocs      bytes      ns
//	any-box of the 352-byte Entry                  1        352     180
//	json.Marshal                                   3      1 088   1 700
//	string(b) handing the body to send             1        384     250
//	formatLine: Format + Sprintf + concat          6        528     570
//	WriteRequest, whole                           11      2 017   3 550
//
// For scale: the whole in-process plain-HTTP forward path measures 94 allocs
// and 11.9 KB per request (BenchmarkHTTPForward_HandleHTTP, root package), so
// with a SIEM collector configured — the ordinary enterprise posture — this one
// sink was adding ~12% to the per-request allocation count and ~17% to its
// garbage, for a record two OTHER sinks on the same Entry already serialize
// without any per-record allocation at all (internal/reqlog/persist.go's
// retained Encoder over a bufio.Writer, and internal/logstore/batchencode.go's
// retained encoder over one batch buffer). This sink was simply the third one
// and had not been given the same treatment.
//
// WHAT CHANGED. One pooled buffer per line carries BOTH the header and the
// body: the header is appended with strconv/AppendFormat instead of being
// built by fmt.Sprintf and concatenated, and a structured body is JSON-encoded
// STRAIGHT INTO that buffer by a retained json.Encoder rather than marshalled
// into an intermediate slice and copied into an intermediate string. The line
// is converted to a string exactly once, at the end, and the drain goroutine
// borrows a buffer from the same pool to put it on the socket. Same bytes on
// the wire:
//
//	WriteRequest, whole                                     2      768
//
// The two that remain are irreducible here: the caller's `any` box (the
// package is a stdlib-only leaf by contract — it cannot name the concrete
// entry type, so it cannot avoid the interface conversion) and the one string
// the queued line is made of. TestBenchGate_SyslogLineAllocs bounds both, and
// lineformat_bench_test.go carries the full before/after table, measured
// against the pristine parent commit through the same benchmark arm.
//
// The residual this does NOT remove is the reflective encode itself, ~1.6 µs of
// the ~2.4 µs that remains. Closing it means a hand-written encoder for a type
// this package deliberately cannot name, which is a different change with a
// different risk profile (the wire bytes are a SIEM ingestion contract) and
// belongs behind the same differential oracle, not folded in here.
//
// WHY ENCODER OUTPUT IS THE SAME BYTES. json.Encoder.Encode writes exactly
// json.Marshal's compact output plus one '\n', with the same default HTML
// escaping, so the only adjustment is that formatBody appends no terminator of
// its own for a JSON body. The TestLineFormat_ByteIdentity_* tests pin the
// whole line — header, body and terminator — against the fmt.Sprintf +
// json.Marshal form this replaces, across both wire formats and including the
// cases where an encoder could plausibly differ (HTML-escapable runes, U+2028/U+2029,
// invalid UTF-8, a nil value, the zero struct).

// Timestamp layouts of the two supported wire formats. RFC 5424 uses
// time.RFC3339Nano.
const rfc3164Layout = "Jan 02 15:04:05"

// maxPooledLineBuf bounds what one pooled assembly buffer may RETAIN between
// lines. The pool exists to keep the steady state allocation-free, not to let
// one oversized record raise the floor for the process: a record that grew its
// buffer past this (a rule with a very long URI, a deeply populated audit
// event) is served normally and then its buffer is dropped instead of parked,
// so the pool's residency stays bounded by this constant times the number of
// goroutines the pool happens to hold buffers for — not by the largest line
// ever sent. 16 KiB is well above the ~0.5 KB formatted line queueCap is sized
// for while staying far below the queue's own worst case.
const maxPooledLineBuf = 16 << 10

// lineBuf is one line-assembly buffer together with the json.Encoder bound to
// it. The encoder is retained with the buffer because that is what makes a
// structured body cost no allocation: a fresh json.Encoder per line would
// allocate the encoder, and json.Marshal would additionally allocate the
// result slice this buffer replaces.
type lineBuf struct {
	buf bytes.Buffer
	enc *json.Encoder
}

var lineBufPool = sync.Pool{New: func() any {
	lb := new(lineBuf)
	lb.enc = json.NewEncoder(&lb.buf)
	return lb
}}

// getLineBuf returns an empty assembly buffer. It is reset on acquisition
// rather than on release so a buffer dropped by a panicking encode can never
// hand its partial bytes to the next line.
func getLineBuf() *lineBuf {
	lb := lineBufPool.Get().(*lineBuf)
	lb.buf.Reset()
	return lb
}

// putLineBuf parks a buffer for reuse unless it has outgrown the residency
// bound (see maxPooledLineBuf). Not called on the encode-failure path: a
// buffer holding a partial record is dropped, not reused.
func putLineBuf(lb *lineBuf) {
	if lb.buf.Cap() > maxPooledLineBuf {
		return
	}
	lineBufPool.Put(lb)
}

// msgBody is the body of one message before assembly: either text that is
// ready to copy, or a value to be JSON-encoded directly into the line buffer.
//
// It exists so the delivery walk in send stays ONE code path. The walk is
// where a line is charged as a drop, or handed to a successor writer, exactly
// once (several Codex P2 corrections live in it), so the value-bodied senders
// must not grow a parallel copy of it. Passing the body as this value instead
// of as a closure also keeps the fused path allocation-free: a closure
// capturing the body would be the allocation the fusion exists to remove.
type msgBody struct {
	text string
	val  any
	json bool // true: encode val; false: copy text
}

func textBody(s string) msgBody { return msgBody{text: s} }

func jsonBody(v any) msgBody { return msgBody{val: v, json: true} }

// formatBody builds one complete line — header, body, terminator — stamped
// with the event time at, and records where the body starts so a handoff can
// re-encode it for a successor with a different wire format (see forWriter).
//
// ok=false means a structured body could not be encoded. The caller sends
// nothing, which is what the json.Marshal form it replaces did: a record that
// cannot be serialized was dropped silently rather than sent truncated.
func (s *Writer) formatBody(pri int, body msgBody, at time.Time) (queuedLine, bool) {
	lb := getLineBuf()
	format := s.appendHeader(&lb.buf, pri, at)
	hdr := lb.buf.Len()
	if body.json {
		// Encode emits the terminator itself, so nothing is appended after it.
		if err := lb.enc.Encode(body.val); err != nil {
			return queuedLine{}, false
		}
	} else {
		lb.buf.WriteString(body.text)
		lb.buf.WriteByte('\n')
	}
	line := lb.buf.String()
	putLineBuf(lb)
	return queuedLine{line: line, format: format, pri: pri, hdr: hdr, at: at}, true
}

// appendHeader appends the wire header for pri stamped at into b, and returns
// the format name the line is encoded in (an unrecognized configured format
// resolves to rfc3164, as it did when this was a switch default).
//
// The numeric priority and the timestamp are appended through the buffer's own
// spare capacity, so a warm buffer formats a header with no allocation at all;
// the fmt.Sprintf form it replaces boxed every argument and then allocated the
// header string and the concatenation separately.
func (s *Writer) appendHeader(b *bytes.Buffer, pri int, at time.Time) string {
	b.WriteByte('<')
	b.Write(strconv.AppendInt(b.AvailableBuffer(), int64(pri), 10))
	if s.format == "rfc5424" {
		// <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA SP MSG
		b.WriteString(">1 ")
		b.Write(at.AppendFormat(b.AvailableBuffer(), time.RFC3339Nano))
		b.WriteByte(' ')
		b.WriteString(s.host)
		b.WriteByte(' ')
		b.WriteString(s.tag)
		b.WriteByte(' ')
		b.WriteString(s.pid)
		b.WriteString(" - - ")
		return "rfc5424"
	}
	b.WriteByte('>')
	b.Write(at.AppendFormat(b.AvailableBuffer(), rfc3164Layout))
	b.WriteByte(' ')
	b.WriteString(s.host)
	b.WriteByte(' ')
	b.WriteString(s.tag)
	b.WriteString(": ")
	return "rfc3164"
}
