package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── Baseline oracle ──────────────────────────────────────────────────────────
//
// legacyJSONLogRecord is the jsonLogWriter.Write encoding as it stood before the
// allocation sweep in logger.go, reshaped only so the timestamp is a parameter
// instead of an inline time.Now() — nothing else about it is changed.
//
// It is the differential oracle: appendJSONLogRecord must produce BYTE-IDENTICAL
// output to this function for every input, pinned over the corpus by
// TestJSONLogWriter_DifferentialAgainstLegacy and over arbitrary bytes by
// FuzzJSONLogRecord_MatchesLegacy. It is also the "before" arm of the
// before/after benchmark comparison.
//
// Do not modernize or "fix" this function. Its entire value is that it is the
// OLD behavior; editing it moves the oracle instead of catching a regression.
func legacyJSONLogRecord(p []byte, now time.Time) []byte {
	raw := p
	for len(raw) > 0 && (raw[len(raw)-1] == '\n' || raw[len(raw)-1] == '\r') {
		raw = raw[:len(raw)-1]
	}
	line := string(raw)

	level := "INFO"
	for _, lvl := range []string{"DEBUG", "INFO", "WARN", "ERROR"} {
		if strings.HasPrefix(line, lvl+" ") {
			level = lvl
			line = line[len(lvl)+1:]
			break
		}
	}

	var buf strings.Builder
	buf.WriteString(`{"time":"`)
	buf.WriteString(now.UTC().Format(time.RFC3339))
	buf.WriteString(`","level":"`)
	buf.WriteString(level)
	buf.WriteString(`","msg":`)

	var fields string
	msg := line
	if idx := strings.LastIndex(line, " {"); idx >= 0 && strings.HasSuffix(line, "}") {
		fields = line[idx+2 : len(line)-1]
		msg = line[:idx]
	}

	msgJSON, _ := json.Marshal(msg)
	buf.Write(msgJSON)

	if fields != "" {
		for fields != "" {
			tok := fields
			if sp := strings.IndexByte(fields, ' '); sp >= 0 {
				tok = fields[:sp]
				fields = fields[sp+1:]
			} else {
				fields = ""
			}
			if eqIdx := strings.IndexByte(tok, '='); eqIdx > 0 {
				key := tok[:eqIdx]
				val := tok[eqIdx+1:]
				buf.WriteString(`,"`)
				buf.WriteString(key)
				buf.WriteString(`":`)
				valJSON, _ := json.Marshal(val)
				buf.Write(valJSON)
			}
		}
	}

	buf.WriteString("}\n")
	return []byte(buf.String())
}

// legacyJSONLogWriter is the pre-sweep writer, reproduced VERBATIM — including
// its pooled bytes.Buffer and the mutex around the destination write — so the
// benchmark's "before" arm measures the real old per-record cost.
//
// It deliberately does NOT call legacyJSONLogRecord: that helper returns a fresh
// []byte for the differential oracle, which would add allocations the original
// never paid and inflate the "before" numbers. The duplication is the point.
type legacyJSONLogWriter struct {
	mu  sync.Mutex
	dst io.Writer
}

var legacyJSONBufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

func (j *legacyJSONLogWriter) Write(p []byte) (int, error) {
	raw := p
	for len(raw) > 0 && (raw[len(raw)-1] == '\n' || raw[len(raw)-1] == '\r') {
		raw = raw[:len(raw)-1]
	}
	line := string(raw)

	level := "INFO"
	for _, lvl := range []string{"DEBUG", "INFO", "WARN", "ERROR"} {
		if strings.HasPrefix(line, lvl+" ") {
			level = lvl
			line = line[len(lvl)+1:]
			break
		}
	}

	buf := legacyJSONBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	buf.WriteString(`{"time":"`)
	buf.WriteString(time.Now().UTC().Format(time.RFC3339))
	buf.WriteString(`","level":"`)
	buf.WriteString(level)
	buf.WriteString(`","msg":`)

	var fields string
	msg := line
	if idx := strings.LastIndex(line, " {"); idx >= 0 && strings.HasSuffix(line, "}") {
		fields = line[idx+2 : len(line)-1]
		msg = line[:idx]
	}

	msgJSON, _ := json.Marshal(msg)
	buf.Write(msgJSON)

	if fields != "" {
		for fields != "" {
			tok := fields
			if sp := strings.IndexByte(fields, ' '); sp >= 0 {
				tok = fields[:sp]
				fields = fields[sp+1:]
			} else {
				fields = ""
			}
			if eqIdx := strings.IndexByte(tok, '='); eqIdx > 0 {
				key := tok[:eqIdx]
				val := tok[eqIdx+1:]
				buf.WriteString(`,"`)
				buf.WriteString(key)
				buf.WriteString(`":`)
				valJSON, _ := json.Marshal(val)
				buf.Write(valJSON)
			}
		}
	}

	buf.WriteString("}\n")

	j.mu.Lock()
	_, err := j.dst.Write(buf.Bytes())
	j.mu.Unlock()

	legacyJSONBufPool.Put(buf)
	return len(p), err
}

// ── Corpus ───────────────────────────────────────────────────────────────────

// jsonLogCorpus is the shared differential/benchmark corpus. The first entries
// are verbatim shapes the proxy hot path emits once per request
// (emitPolicyDecision in proxy.go, and the IP_BLOCKED / RATE_LIMITED /
// INVALID_HOST lines in handleRequest); the rest are the escaping and
// field-parser edge cases, including the ones that must fall back to
// encoding/json.
var jsonLogCorpus = []struct {
	name string
	line string
}{
	{"PolicyAllow", `POLICY_ALLOW rule="Allow Corp Web" pri=10 10.1.2.3 GET "www.example.com" [srcIP=10.0.0.0/8 destFQDN=www.example.com] {req_id=9f2c1ab47de35081 identity=alice@corp.example action=allow}` + "\n"},
	{"PolicyBlock", `POLICY_BLOCK rule="Block Malware" pri=3 198.51.100.7 -> "bad.example.net" [destCat=malware] {req_id=11aa22bb33cc44dd identity=bob@corp.example action=block}` + "\n"},
	{"IPBlocked", `IP_BLOCKED 203.0.113.9 {req_id=aabbccddeeff0011 action=block}` + "\n"},
	{"NoFields", `Proxy listening on :3128` + "\n"},
	{"LevelPrefixWarn", `WARN upstream handshake slow {req_id=deadbeefcafebabe action=allow}` + "\n"},
	{"ManyFields", `POLICY_REDIRECT rule="R" pri=1 10.0.0.1 -> "a.example" => "https://portal.example/login" [any] {req_id=0123456789abcdef identity=carol action=redirect ssl=inspect cat=business geo=US dur=12ms}` + "\n"},
	{"QuoteInMsg", `INVALID_HOST 10.0.0.2 -> "ex\"ample.com" {req_id=1 action=block}` + "\n"},
	{"BackslashInMsg", `BLOCKED path C:\\temp\\x {req_id=2 action=block}` + "\n"},
	{"HTMLChars", `BLOCKED <script>&amp;</script> {req_id=3 action=block}` + "\n"},
	{"ControlBytes", "BLOCKED \x01\x02\x1f tail {req_id=4 action=block}\n"},
	{"NonASCII", `BLOCKED "ünïcodé.example" {req_id=5 action=block}` + "\n"},
	{"InvalidUTF8", "BLOCKED \xff\xfe bad {req_id=6 action=block}\n"},
	{"LineSeparators", "BLOCKED \u2028\u2029 {req_id=7 action=block}\n"},
	{"EmptyFieldBlock", `msg {}` + "\n"},
	{"FieldNoEquals", `msg {bare token}` + "\n"},
	{"FieldEmptyValue", `msg {k= j=1}` + "\n"},
	{"BraceNotSuffix", `msg {k=1} trailing` + "\n"},
	{"OnlyNewline", "\n"},
	{"Empty", ""},
	{"CRLF", "msg {k=1}\r\n"},
	{"HTMLInFieldValue", `msg {url=http://x/?a=1&b=<2>}` + "\n"},
	{"NonASCIIFieldValue", `msg {host=ünï.example}` + "\n"},
	{"LevelPrefixOnly", "ERROR\n"},
	{"DebugPrefix", `DEBUG cache hit {req_id=8}` + "\n"},
	{"TabInValue", "msg {k=a\tb}\n"},
	{"DELByte", "msg \x7f {k=1}\n"},
	{"HighByteInKey", "msg {k\xc3\xa9=1}\n"},
	{"OnlyBraces", "{}\n"},
	{"SpaceBraceOnly", " {}\n"},
	{"LongHost", "INVALID_HOST 10.0.0.3 -> \"" + strings.Repeat("a", 300) + "\" {req_id=9 action=block}\n"},
}

// ── Benchmarks ───────────────────────────────────────────────────────────────

// benchJSONLog drives one writer over one corpus line. The destination is
// io.Discard so the measurement isolates the ENCODE cost — the per-request work
// logger.go deliberately keeps on the caller's goroutine (setupLogger: in JSON
// mode the encoding must happen before the async sink, once per record) — from
// the write(2) that the async sink already moved off that goroutine.
func benchJSONLog(b *testing.B, line string) {
	w := &jsonLogWriter{dst: io.Discard}
	p := []byte(line)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := w.Write(p); err != nil {
			b.Fatal(err)
		}
	}
}

func benchJSONLogLegacy(b *testing.B, line string) {
	w := &legacyJSONLogWriter{dst: io.Discard}
	p := []byte(line)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := w.Write(p); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJSONLogWrite(b *testing.B) {
	for _, c := range jsonLogCorpus {
		b.Run(c.name, func(b *testing.B) { benchJSONLog(b, c.line) })
	}
}

func BenchmarkJSONLogWrite_Legacy(b *testing.B) {
	for _, c := range jsonLogCorpus {
		b.Run(c.name, func(b *testing.B) { benchJSONLogLegacy(b, c.line) })
	}
}

// BenchmarkJSONLogWrite_Parallel is the scalability arm. logger.go's contract is
// that JSON encoding is "pure CPU that scales with cores", which is what lets it
// stay on the request goroutine; per-record allocation is what weakens that,
// because the allocator and the resulting GC are process-wide. Compare against
// the _LegacyParallel arm at the same -cpu.
func BenchmarkJSONLogWrite_Parallel(b *testing.B) {
	w := &jsonLogWriter{dst: io.Discard}
	p := []byte(jsonLogCorpus[0].line)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := w.Write(p); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkJSONLogWrite_LegacyParallel(b *testing.B) {
	w := &legacyJSONLogWriter{dst: io.Discard}
	p := []byte(jsonLogCorpus[0].line)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := w.Write(p); err != nil {
				b.Fatal(err)
			}
		}
	})
}
