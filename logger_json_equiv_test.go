package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

// pinnedLogClock is the fixed instant every differential comparison stamps, so
// the only thing that can differ between the two encoders is the encoding.
var pinnedLogClock = time.Date(2026, 3, 5, 15, 4, 5, 0, time.UTC)

// TestAppendJSONString_BytewiseAgainstStdlib pins the fast path's correctness
// claim at the level it is actually made: per BYTE. jsonStringVerbatim asserts
// that encoding/json emits a given byte unchanged inside a string; this walks
// all 256 values and fails if that is wrong in either direction, so widening the
// table by hand (or a future Go release changing the escaping defaults) is
// caught here rather than in a downstream log consumer.
func TestAppendJSONString_BytewiseAgainstStdlib(t *testing.T) {
	for c := 0; c < 256; c++ {
		in := []byte{byte(c)}
		want, err := json.Marshal(string(in))
		if err != nil {
			t.Fatalf("byte %#02x: stdlib marshal: %v", c, err)
		}
		if got := appendJSONString(nil, in); !bytes.Equal(got, want) {
			t.Errorf("byte %#02x: appendJSONString = %s, stdlib = %s", c, got, want)
		}
		// The escape table's own claim, re-derived here independently of the
		// append path: for printable ASCII, the entry must be "" exactly when
		// stdlib emits the byte verbatim, and otherwise must be the exact
		// escape text stdlib produces.
		if c >= 0x20 && c < 0x80 {
			body := string(want[1 : len(want)-1])
			wantEsc := ""
			if body != string([]byte{byte(c)}) {
				wantEsc = body
			}
			if got := jsonASCIIEscape[c]; got != wantEsc {
				t.Errorf("byte %#02x: jsonASCIIEscape = %q, stdlib = %q", c, got, wantEsc)
			}
		}
	}
}

// TestAppendJSONString_MultiByteAgainstStdlib covers the sequences a per-byte
// walk cannot: every byte paired with an escape-forcing neighbour, the
// UTF-8/U+2028/U+2029 rewrites, and invalid UTF-8 (which stdlib replaces with
// U+FFFD rather than rejecting).
func TestAppendJSONString_MultiByteAgainstStdlib(t *testing.T) {
	var cases []string
	for c := 0; c < 256; c++ {
		b := byte(c)
		cases = append(cases,
			string([]byte{b}),
			"a"+string([]byte{b})+"z",
			string([]byte{b, b}),
			`"`+string([]byte{b}),
			string([]byte{b})+`\`,
			"<"+string([]byte{b})+">",
			"&"+string([]byte{b}),
		)
	}
	cases = append(cases,
		"", "plain", "ünïcodé.example", " ", " ", "a b c",
		"\xff", "\xfe\xff", "\xc3", "\xc3\x28", "\xed\xa0\x80", // lone surrogate
		"emoji \U0001F600 tail", strings.Repeat("x", 1024),
		"\x00", "\x1f\x7f", "tab\there", "nl\nhere", "cr\rhere",
	)
	for _, s := range cases {
		want, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("stdlib marshal %q: %v", s, err)
		}
		if got := appendJSONString(nil, []byte(s)); !bytes.Equal(got, want) {
			t.Errorf("appendJSONString(%q) = %s, stdlib = %s", s, got, want)
		}
	}
}

// TestAppendJSONString_AppendsToExistingBuffer guards the append contract: the
// encoder must extend dst, never replace or truncate it. The fallback arm
// returns through a different path than the fast arm, so both are checked.
func TestAppendJSONString_AppendsToExistingBuffer(t *testing.T) {
	for _, s := range []string{"plain", `needs"escape`, "ünï", "\xff"} {
		prefix := []byte("KEEP:")
		got := appendJSONString(prefix, []byte(s))
		want, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(got, []byte("KEEP:")) {
			t.Errorf("%q: prefix lost: %s", s, got)
		}
		if !bytes.Equal(got[len("KEEP:"):], want) {
			t.Errorf("%q: appended %s, want %s", s, got[len("KEEP:"):], want)
		}
	}
}

// TestJSONLogWriter_DifferentialAgainstLegacy is the primary equivalence gate:
// the swept encoder and the pre-sweep oracle must agree byte-for-byte on the
// whole corpus, including the per-request proxy decision lines.
func TestJSONLogWriter_DifferentialAgainstLegacy(t *testing.T) {
	for _, c := range jsonLogCorpus {
		t.Run(c.name, func(t *testing.T) {
			want := legacyJSONLogRecord([]byte(c.line), pinnedLogClock)
			got := appendJSONLogRecord(nil, []byte(c.line), pinnedLogClock)
			if !bytes.Equal(got, want) {
				t.Errorf("encoding diverged\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

// TestJSONLogWriter_CorpusIsValidJSON is the negative control for the
// differential test: two encoders agreeing proves they match each other, not
// that either emits valid newline-delimited JSON. Every record must be exactly
// one line and must parse, with the message and the promoted fields intact.
func TestJSONLogWriter_CorpusIsValidJSON(t *testing.T) {
	for _, c := range jsonLogCorpus {
		t.Run(c.name, func(t *testing.T) {
			rec := appendJSONLogRecord(nil, []byte(c.line), pinnedLogClock)
			if n := bytes.Count(rec, []byte("\n")); n != 1 || rec[len(rec)-1] != '\n' {
				t.Fatalf("record is not exactly one line (%d newlines): %q", n, rec)
			}
			var m map[string]any
			if err := json.Unmarshal(rec, &m); err != nil {
				t.Fatalf("record is not valid JSON: %v\nrecord: %s", err, rec)
			}
			if _, ok := m["time"]; !ok {
				t.Error("missing time field")
			}
			if _, ok := m["level"]; !ok {
				t.Error("missing level field")
			}
			if _, ok := m["msg"]; !ok {
				t.Error("missing msg field")
			}
		})
	}
}

// TestJSONLogWriter_WriteMatchesLegacyWriter exercises the real Write path —
// pooled buffer, mutex, reported byte count — rather than the encoder alone,
// with the timestamp masked since both writers read the wall clock themselves.
func TestJSONLogWriter_WriteMatchesLegacyWriter(t *testing.T) {
	maskTime := func(b []byte) []byte {
		i := bytes.Index(b, []byte(`","level":"`))
		if i < 0 {
			t.Fatalf("no time field in %q", b)
		}
		return append([]byte(`{"time":"<masked>`), b[i:]...)
	}
	for _, c := range jsonLogCorpus {
		t.Run(c.name, func(t *testing.T) {
			var gotBuf, wantBuf bytes.Buffer
			nGot, err := (&jsonLogWriter{dst: &gotBuf}).Write([]byte(c.line))
			if err != nil {
				t.Fatal(err)
			}
			nWant, err := (&legacyJSONLogWriter{dst: &wantBuf}).Write([]byte(c.line))
			if err != nil {
				t.Fatal(err)
			}
			if nGot != nWant || nGot != len(c.line) {
				t.Errorf("reported length = %d, legacy = %d, input = %d", nGot, nWant, len(c.line))
			}
			if g, w := maskTime(gotBuf.Bytes()), maskTime(wantBuf.Bytes()); !bytes.Equal(g, w) {
				t.Errorf("writer output diverged\n got: %s\nwant: %s", g, w)
			}
		})
	}
}

// TestJSONLogWriter_PooledBufferIsNotRetainedAcrossRecords guards the pool
// reuse introduced with the []byte pool: a long record must not leave its tail
// visible in the next, shorter one.
func TestJSONLogWriter_PooledBufferIsNotRetainedAcrossRecords(t *testing.T) {
	var buf bytes.Buffer
	w := &jsonLogWriter{dst: &buf}
	if _, err := w.Write([]byte("LONG " + strings.Repeat("z", 400) + " {k=1}\n")); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if _, err := w.Write([]byte("short\n")); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("zzz")) {
		t.Errorf("previous record leaked into the next: %s", buf.Bytes())
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("second record invalid: %v (%s)", err, buf.Bytes())
	}
	if m["msg"] != "short" {
		t.Errorf("msg = %v, want \"short\"", m["msg"])
	}
}

// TestJSONLogWriter_OversizeRecordNotPinnedInPool pins the capacity guard: a
// pathological line (an oversize authority in a refusal message) must not park
// its buffer in the pool for the life of the process.
func TestJSONLogWriter_OversizeRecordNotPinnedInPool(t *testing.T) {
	w := &jsonLogWriter{dst: io.Discard}
	huge := "INVALID_HOST " + strings.Repeat("h", 64*1024) + " {k=1}\n"
	if _, err := w.Write([]byte(huge)); err != nil {
		t.Fatal(err)
	}
	// Whatever the pool now holds, the next record must still be correct and
	// must not carry the oversize buffer's contents.
	var buf bytes.Buffer
	w.dst = &buf
	if _, err := w.Write([]byte("after\n")); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("hhh")) {
		t.Errorf("oversize record leaked: %s", buf.Bytes())
	}
	if got := bytes.Count(buf.Bytes(), []byte("\n")); got != 1 {
		t.Errorf("record is not one line: %q", buf.Bytes())
	}
}

// FuzzJSONLogRecord_MatchesLegacy is the unbounded arm of the differential
// gate. The fast path's byte table and the field parser both make claims about
// arbitrary input, and log lines carry attacker-influenced bytes (hostnames,
// headers) even after sanitizeLog, so equivalence is fuzzed rather than only
// sampled.
func FuzzJSONLogRecord_MatchesLegacy(f *testing.F) {
	for _, c := range jsonLogCorpus {
		f.Add([]byte(c.line))
	}
	f.Add([]byte("\xff{=}"))
	f.Add([]byte(" { = }"))
	f.Add([]byte("DEBUG {a=\xc3}"))
	f.Fuzz(func(t *testing.T, p []byte) {
		want := legacyJSONLogRecord(p, pinnedLogClock)
		got := appendJSONLogRecord(nil, p, pinnedLogClock)
		if !bytes.Equal(got, want) {
			t.Fatalf("diverged on %q\n got: %s\nwant: %s", p, got, want)
		}
	})
}

// ── Allocation regression gate ───────────────────────────────────────────────

// asciiOnly reports whether every byte of s is in the printable-ASCII range the
// zero-allocation fast path covers. The non-ASCII corpus entries deliberately
// fall back to encoding/json and are therefore excluded from the gate below.
func asciiOnly(s string) bool {
	// The encoder trims trailing newlines/CRs before encoding anything, so they
	// never reach the fast-path decision; drop them the same way first rather
	// than treating the first one as a verdict for the whole line.
	s = strings.TrimRight(s, "\r\n")
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c >= 0x80 {
			return false
		}
	}
	return true
}

// TestAllocGate_JSONLogRecordIsAllocationFree is the regression gate for the
// sweep. It is STRUCTURAL, not a timing gate: allocation counts are exact
// integers, machine-independent and stable under -race and on a loaded runner,
// so it runs in the normal suite rather than behind the benchgate tag (the
// benchgate build tag exists for the timing gates, whose margins can flake).
//
// The contract: encoding one printable-ASCII log record into an already-sized
// buffer must allocate NOTHING. Every per-record allocation on this path is paid
// once per proxied request in JSON log mode, on the request goroutine — see
// setupLogger, which keeps the encoding there deliberately on the grounds that
// it is "pure CPU that scales with cores". Allocation is what would falsify
// that, because the allocator and the resulting GC are process-wide.
//
// Measured before the sweep: 14 allocs / 528 B for a POLICY_ALLOW record.
func TestAllocGate_JSONLogRecordIsAllocationFree(t *testing.T) {
	for _, c := range jsonLogCorpus {
		if !asciiOnly(c.line) {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			p := []byte(c.line)
			// Size the buffer once, as the pooled buffer is in steady state.
			buf := make([]byte, 0, len(c.line)+jsonLogBufSize)
			if got := testing.AllocsPerRun(200, func() {
				buf = appendJSONLogRecord(buf[:0], p, pinnedLogClock)
			}); got != 0 {
				t.Errorf("appendJSONLogRecord allocated %.0f times per record; want 0.\n"+
					"This path runs once per proxied request in JSON log mode, on the "+
					"request goroutine. If a new field genuinely needs encoding/json, "+
					"say so here and move the gate rather than deleting it.", got)
			}
		})
	}
}

// TestAllocGate_NonASCIIRecordStaysBounded is the companion bound on the
// fallback arm: a record the fast path cannot encode must still not regress to
// the pre-sweep allocation count. It is a BOUND rather than an equality because
// the exact count depends on encoding/json internals, which are not this
// repository's contract to pin.
func TestAllocGate_NonASCIIRecordStaysBounded(t *testing.T) {
	const bound = 8 // pre-sweep: 11 for the same records
	for _, c := range jsonLogCorpus {
		if asciiOnly(c.line) {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			p := []byte(c.line)
			buf := make([]byte, 0, len(c.line)+jsonLogBufSize)
			got := testing.AllocsPerRun(200, func() {
				buf = appendJSONLogRecord(buf[:0], p, pinnedLogClock)
			})
			if got > bound {
				t.Errorf("appendJSONLogRecord allocated %.0f times per record; bound %d", got, bound)
			}
		})
	}
}

// TestAllocGate_WriterReusesPooledBuffer checks the gate above actually reaches
// production through jsonLogWriter.Write — the encoder being allocation-free is
// worth nothing if the writer allocates a buffer per record anyway.
//
// The bound is 1 rather than 0 on purpose: sync.Pool is drained by every GC, so
// a collection triggered by unrelated work during the measurement costs one
// re-allocation. The strict zero-allocation claim is the encoder gate above.
func TestAllocGate_WriterReusesPooledBuffer(t *testing.T) {
	w := &jsonLogWriter{dst: io.Discard}
	p := []byte(jsonLogCorpus[0].line)
	if got := testing.AllocsPerRun(200, func() {
		if _, err := w.Write(p); err != nil {
			t.Fatal(err)
		}
	}); got > 1 {
		t.Errorf("jsonLogWriter.Write allocated %.0f times per record; want <= 1 "+
			"(pre-sweep: 14). The pooled encode buffer is not being reused.", got)
	}
}
