package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/logsink"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// ── Log levels ───────────────────────────────────────────────────────────────

// LogLevel represents the severity of a log message.
type LogLevel int32

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l LogLevel) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// ParseLogLevel converts a string to a LogLevel.
func ParseLogLevel(s string) LogLevel {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DEBUG":
		return LevelDebug
	case "INFO", "":
		return LevelInfo
	case "WARN", "WARNING":
		return LevelWarn
	case "ERROR":
		return LevelError
	default:
		return LevelInfo
	}
}

// logLevel is the global minimum log level. Atomically accessed.
var logLevel atomic.Int32

// SetLogLevel sets the global minimum log level. The debug-enabled boolean is
// mirrored into the obs facade so internal/* packages (which cannot read
// main's level state) gate their Debugf lines identically.
func SetLogLevel(l LogLevel) {
	logLevel.Store(int32(l))
	obs.SetDebugEnabled(l <= LevelDebug)
}

// GetLogLevel returns the current global minimum log level.
func GetLogLevel() LogLevel {
	return LogLevel(logLevel.Load())
}

// ── Leveled logging helpers ──────────────────────────────────────────────────
// These wrap the global logger with level filtering.
// Printf remains an alias for Infof (backward compatibility — all 418 existing
// logger.Printf calls continue to work at INFO level).
// logDebugf was removed when its last caller moved to internal/threatfeed
// (which uses the level-gated obs.Debugf); main code needing a debug line
// uses obs.Debugf too, or logger.Printf("DEBUG ...") behind GetLogLevel.

func logWarnf(format string, args ...any) {
	if GetLogLevel() <= LevelWarn {
		logger.Print("WARN " + sanitizeLog(fmt.Sprintf(format, args...)))
	}
}

func logErrorf(format string, args ...any) {
	// Error is always logged regardless of level.
	logger.Print("ERROR " + sanitizeLog(fmt.Sprintf(format, args...)))
}

// ── Fatal exit ───────────────────────────────────────────────────────────────

// logFatalf logs at fatal severity, FLUSHES the async log sink, and exits(1).
//
// It replaces logger.Fatalf everywhere. log.Logger.Fatalf writes and then calls
// os.Exit immediately, which is fine for a synchronous writer but would discard
// whatever is still queued behind the asynchronous sink installed by
// setupLogger — and the one line that must never be lost is the one explaining
// why the process is exiting. flushLogSink is a no-op before setupLogger has
// run (bootstrap failures, tests), so the pre-async behavior is preserved
// wherever the sink does not exist yet.
func logFatalf(format string, args ...any) {
	logger.Printf(format, args...)
	flushLogSink()
	os.Exit(1)
}

// logSink holds the process log's asynchronous sink so the fatal-exit path can
// flush it. Published once by setupLogger; nil until then.
var logSink atomic.Pointer[logsink.Writer]

// flushLogSink blocks until every line already logged has reached the
// destination writer. Bounded internally, so a wedged log volume degrades the
// exit path rather than hanging it. Safe to call before setupLogger.
func flushLogSink() {
	if w := logSink.Load(); w != nil {
		w.Sync()
	}
}

// logSinkBackpressure reports how many log lines had to wait for room in the
// sink queue — non-zero means the log volume is not keeping up with the request
// rate and request latency is coupled to it again. Zero when no async sink is
// installed.
func logSinkBackpressure() int64 {
	if w := logSink.Load(); w != nil {
		return w.Backpressure()
	}
	return 0
}

// logSinkWriteErrors reports how many process-log lines (console + process
// log file, e.g. POLICY_ALLOW/BLOCK/DROP entries) never reached their
// destination writer — non-zero means the process-log record has gaps, the
// same class of loss request-log and audit-log writes already surface via
// reqlog.WriteErrors()/auditWriteErrors(). Zero when no async sink is
// installed.
func logSinkWriteErrors() int64 {
	if w := logSink.Load(); w != nil {
		return w.WriteErrors()
	}
	return 0
}

// ── Rotating file writer ─────────────────────────────────────────────────────
// rotatingFile moved to internal/fileutil (ADR-0002, store.go decomposition
// Phase B — the audit engine shares it); the aliases keep the logger and
// request-log call sites unchanged.

type rotatingFile = fileutil.RotatingFile

func newRotatingFile(path string, maxMB int) (*rotatingFile, error) {
	return fileutil.NewRotatingFile(path, maxMB)
}

// ── JSON log writer ──────────────────────────────────────────────────────────

// jsonLogWriter wraps an io.Writer and converts each log line into a JSON object.
// The standard log package emits lines like "[Culvert] 2026/03/05 15:04:05 message".
// jsonLogWriter drops that prefix and re-encodes the message with a proper RFC3339 timestamp.
//
// Structured fields can be embedded in the log message using key=value pairs
// enclosed in braces at the end: "msg {key1=val1 key2=val2}". The parser
// extracts these and promotes them to top-level JSON fields.
type jsonLogWriter struct {
	mu  sync.Mutex
	dst io.Writer
}

// jsonBufPool avoids allocating an encode buffer for every log line. It holds
// *[]byte rather than *bytes.Buffer because the record encoder below is
// append-based: every field is appended straight into these bytes, so the whole
// record is built with no intermediate allocation at all.
var jsonBufPool = sync.Pool{New: func() any {
	b := make([]byte, 0, jsonLogBufSize)
	return &b
}}

// jsonLogBufSize is the pooled encode buffer's starting capacity. The proxy's
// own per-request decision lines (emitPolicyDecision in proxy.go) land around
// 200–260 bytes once encoded; 512 keeps those, and the longer identity/category
// variants, inside the first allocation for the life of the pooled buffer.
const jsonLogBufSize = 512

// jsonLogLevels are the level prefixes recognized on an incoming log line, in
// the order they are tested. The order is load-bearing only in that the first
// match wins, exactly as the pre-sweep implementation's inline slice did.
var jsonLogLevels = [...]string{"DEBUG", "INFO", "WARN", "ERROR"}

// jsonFieldOpen is the " {" marker that introduces the trailing structured
// field block. Package-level so the search below never allocates it per call.
var jsonFieldOpen = []byte(" {")

// jsonASCIIEscape[c] is the exact text encoding/json emits for byte c inside a
// JSON string, for the printable-ASCII range the fast path below handles. The
// empty string means "emitted verbatim"; a non-empty entry is the escape that
// replaces the byte.
//
// Only [0x20,0x80) is covered, and that bound is what makes the fast path
// provable: every byte in that range is a complete single-byte UTF-8 rune, so
// the encoding of such a string is exactly the concatenation of its per-byte
// entries. Outside it the encoding is NOT a per-byte function — a byte >= 0x80
// is part of a multi-byte sequence needing UTF-8 validation (invalid bytes
// become U+FFFD) and U+2028/U+2029 rewriting — so those values are handed to
// encoding/json whole.
//
// The table is DERIVED from encoding/json at init rather than written out,
// because the exact set is not obvious and a hand-maintained range gets it
// wrong: the first draft used [0x20,0x7e] and so excluded DEL (0x7f), which
// encoding/json in fact emits verbatim. Asking the oracle removes that class of
// mistake, and the 96 one-byte marshals cost microseconds once per process.
//
// In practice the five non-empty entries are encoding/json's own rewrites:
// the quote and backslash get their short escapes, and '<', '>' and '&' get
// the six-character \u003c, \u003e and \u0026 forms, because Marshal's
// HTML-escaping default is on. They are not hardcoded here, and
// TestAppendJSONString_BytewiseAgainstStdlib re-derives the whole table
// independently, so a future Go release that changes the escaping defaults is
// caught by a failing test rather than by a downstream log consumer.
var jsonASCIIEscape = func() (t [0x80]string) {
	for c := 0x20; c < 0x80; c++ {
		enc, err := json.Marshal(string([]byte{byte(c)}))
		if err != nil || len(enc) < 2 {
			// Unreachable: marshalling a one-byte printable-ASCII string cannot
			// fail and always yields at least `"x"`. Leaving the entry empty
			// treats the byte as verbatim, which is what every byte in this
			// range that reaches here would be anyway.
			continue
		}
		body := string(enc[1 : len(enc)-1]) // strip the surrounding quotes
		if body != string([]byte{byte(c)}) {
			t[c] = body
		}
	}
	return t
}()

// appendJSONString appends s to dst as a JSON string value — including the
// surrounding quotes — byte-for-byte identically to encoding/json.Marshal(s).
//
// encoding/json.Marshal is the fallback, not the implementation: marshalling a
// plain string still goes through the reflection encoder, which showed up on the
// per-request log path as reflect.unsafe_New plus a bytes.Clone of the result
// (55% of the allocated objects on that path, measured). Printable ASCII needs
// neither, so it is encoded here.
//
// The fast path deliberately covers the ESCAPES too, not just verbatim bytes.
// The proxy's own per-request decision lines (emitPolicyDecision in proxy.go)
// embed %q-quoted rule names and hostnames, so '"' appears in essentially every
// hot-path record; a fast path that bailed out on the first escape would have
// handed the hottest line in the process straight back to the reflection
// encoder, which is what the first draft of this function did.
//
// On a Marshal error the pre-sweep code appended nothing (it discarded the error
// and wrote the nil result), and that is preserved exactly. For a Go string the
// case is unreachable — invalid UTF-8 is replaced, not rejected.
func appendJSONString(dst, s []byte) []byte {
	// Decide the path first. A single byte outside printable ASCII makes the
	// encoding non-per-byte, so the whole value goes to encoding/json.
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c >= 0x80 {
			enc, _ := json.Marshal(string(s))
			return append(dst, enc...)
		}
	}

	// Every byte is a printable single-byte rune: emit runs of verbatim bytes
	// and substitute the fixed escape for the rest.
	dst = append(dst, '"')
	run := 0
	for i := 0; i < len(s); i++ {
		esc := jsonASCIIEscape[s[i]]
		if esc == "" {
			continue
		}
		dst = append(dst, s[run:i]...)
		dst = append(dst, esc...)
		run = i + 1
	}
	dst = append(dst, s[run:]...)
	return append(dst, '"')
}

// appendJSONLogRecord encodes one log line as one JSON object, newline
// terminated, and appends it to dst.
//
// now is a parameter rather than a time.Now() call inside so that the
// differential test can pin the instant and compare this encoder's output
// against the pre-sweep implementation byte-for-byte; a wall-clock read inside
// would make every such comparison differ in the "time" field for reasons that
// have nothing to do with encoding.
//
// It operates on the raw []byte throughout. The pre-sweep implementation's first
// act was `line := string(raw)`, which copied every log line onto the heap once
// per record purely to get string-typed helpers; nothing here needs a string, so
// nothing copies.
func appendJSONLogRecord(dst, p []byte, now time.Time) []byte {
	// Trim trailing newline/CR without allocating.
	raw := p
	for len(raw) > 0 && (raw[len(raw)-1] == '\n' || raw[len(raw)-1] == '\r') {
		raw = raw[:len(raw)-1]
	}

	// Extract the level prefix if present (e.g. "DEBUG ...", "WARN ..."). The
	// string(raw[:n]) comparison is compiled as a byte compare, not a copy.
	level := "INFO"
	for _, lvl := range jsonLogLevels {
		if len(raw) > len(lvl) && raw[len(lvl)] == ' ' && string(raw[:len(lvl)]) == lvl {
			level = lvl
			raw = raw[len(lvl)+1:]
			break
		}
	}

	// Split the trailing "{key=val key2=val2}" block off the message.
	msg, fields := raw, []byte(nil)
	if idx := bytes.LastIndex(raw, jsonFieldOpen); idx >= 0 && raw[len(raw)-1] == '}' {
		fields = raw[idx+2 : len(raw)-1]
		msg = raw[:idx]
	}

	dst = append(dst, `{"time":"`...)
	dst = now.UTC().AppendFormat(dst, time.RFC3339)
	dst = append(dst, `","level":"`...)
	dst = append(dst, level...)
	dst = append(dst, `","msg":`...)
	dst = appendJSONString(dst, msg)

	// Promote the structured fields to top-level JSON keys.
	//
	// The KEY goes through appendJSONString like the value, rather than being
	// appended raw. The raw append rested on the premise that keys "come from
	// the process's own format strings, never from request data", and that
	// premise is a property of every CALLER, not of this encoder: a key is
	// whatever precedes the first '=' of a space-separated token, so any caller
	// that renders an untrusted value bare inside the field block donates its
	// bytes to a key. One such caller exists — emitPolicyDecision's `identity`,
	// an IdP-asserted claim (proxy.go) — and a key carrying a '"' there made
	// the whole record UNPARSEABLE, which a strict log shipper drops: the
	// request's decision record disappears from the SIEM rather than arriving
	// wrong. Escaping here makes a well-formed record the encoder's own
	// guarantee, independent of how carefully each call site is written.
	//
	// This is byte-for-byte identical to the raw append for every key that
	// needs no escaping, which is every key the tree actually emits (including
	// non-ASCII ones — appendJSONString hands those to encoding/json, which
	// emits valid UTF-8 verbatim). It diverges only where the raw append
	// produced invalid JSON. Keeping an untrusted key OUT of the structured
	// namespace is the call site's job, not this loop's; see
	// sanitizeLogFieldToken in proxy.go.
	for len(fields) > 0 {
		tok := fields
		if sp := bytes.IndexByte(fields, ' '); sp >= 0 {
			tok, fields = fields[:sp], fields[sp+1:]
		} else {
			fields = nil
		}
		if eq := bytes.IndexByte(tok, '='); eq > 0 {
			dst = append(dst, ',')
			dst = appendJSONString(dst, tok[:eq])
			dst = append(dst, ':')
			dst = appendJSONString(dst, tok[eq+1:])
		}
	}

	return append(dst, '}', '\n')
}

func (j *jsonLogWriter) Write(p []byte) (int, error) {
	bp := jsonBufPool.Get().(*[]byte)
	b := appendJSONLogRecord((*bp)[:0], p, time.Now())

	j.mu.Lock()
	_, err := j.dst.Write(b)
	j.mu.Unlock()

	// Keep the grown buffer for the next record, but do not let one pathological
	// line (a 64 KiB authority in a refusal message) pin that capacity in the
	// pool for the process's lifetime.
	if cap(b) <= 4*jsonLogBufSize {
		*bp = b
		jsonBufPool.Put(bp)
	}
	return len(p), err // always return original length so log.Logger doesn't retry
}

// ── Logger setup ─────────────────────────────────────────────────────────────

// setupLogger builds a *log.Logger that writes to stdout and optionally a
// rotating file. format controls output style: "" or "text" → plain text,
// "json" → one JSON object per line.
//
// The composed destination is wrapped in internal/logsink so the write(2)s
// happen on a dedicated drain goroutine instead of the proxy request goroutine.
// handleRequest emits one line per proxied request, and both underlying writers
// are unbuffered behind mutexes held across the syscall (log.Logger's own, and
// fileutil.RotatingFile's), so the pre-wrap sink serialized every request in the
// process and got SLOWER as cores were added. See the internal/logsink package
// doc for the measurements and the never-worse-than-synchronous contract.
//
// The returned Closer flushes the sink before closing the file, so the orderly
// shutdown path loses nothing. It is now always non-nil — even with no log file
// there is a sink to flush — where it used to be nil for the stdout-only case.
func setupLogger(logPath string, maxMB int, format string) (*log.Logger, io.Closer, error) {
	var fileWriter io.Writer
	var fileCloser io.Closer

	if logPath != "" {
		rf, err := newRotatingFile(logPath, maxMB)
		if err != nil {
			return nil, nil, err
		}
		fileWriter = rf
		fileCloser = rf
	}

	prefix, flags := "[Culvert] ", log.LstdFlags
	writers := []io.Writer{os.Stdout}
	if fileWriter != nil {
		writers = append(writers, fileWriter)
	}

	// The async sink batches: under backlog its bufio coalesces several queued
	// lines into ONE downstream Write. That is correct for the raw stdout/file
	// byte streams, but a record-oriented writer — jsonLogWriter turns each
	// Write into exactly one JSON object — would then fold several log records
	// into a single object with embedded newlines, breaking record boundaries
	// for downstream JSON ingestion. So in JSON mode the encoding must happen
	// BEFORE the sink: once per log.Logger call, i.e. once per record. The sink
	// then only ever transports complete `{...}\n` lines, whose concatenation
	// is valid newline-delimited JSON. This also encodes once total rather than
	// once per destination. The expensive per-request work the async sink exists
	// to remove — the log.Logger and RotatingFile mutexes held across the
	// write(2) and the rotation stall — still runs on the drain goroutine; JSON
	// marshalling is pure CPU that scales with cores (the package doc's "format
	// only" row), so keeping it on the caller does not reintroduce the ceiling.
	sink := logsink.New(io.MultiWriter(writers...))
	logSink.Store(sink)

	var loggerDst io.Writer = sink
	if format == "json" {
		// JSON mode: no flags (we add our own timestamp), no prefix.
		prefix, flags = "", 0
		loggerDst = &jsonLogWriter{dst: sink}
	}
	return log.New(loggerDst, prefix, flags), &logCloser{sink: sink, file: fileCloser}, nil
}

// logCloser flushes the async sink and then releases the log file descriptor,
// in that order — closing the file first would strand the queued lines.
type logCloser struct {
	sink *logsink.Writer
	file io.Closer
}

func (c *logCloser) Close() error {
	if c.sink != nil {
		_ = c.sink.Close() // drains and flushes; bounded, never hangs shutdown
	}
	if c.file != nil {
		return c.file.Close()
	}
	return nil
}
