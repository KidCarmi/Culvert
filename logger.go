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

// jsonBufPool avoids allocating a new bytes.Buffer for every log line.
var jsonBufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

func (j *jsonLogWriter) Write(p []byte) (int, error) {
	// Trim trailing newline/CR without allocating a new string.
	raw := p
	for len(raw) > 0 && (raw[len(raw)-1] == '\n' || raw[len(raw)-1] == '\r') {
		raw = raw[:len(raw)-1]
	}
	line := string(raw)

	// Extract log level prefix if present (e.g., "DEBUG ...", "WARN ...").
	level := "INFO"
	for _, lvl := range []string{"DEBUG", "INFO", "WARN", "ERROR"} {
		if strings.HasPrefix(line, lvl+" ") {
			level = lvl
			line = line[len(lvl)+1:]
			break
		}
	}

	// Build JSON directly into a pooled buffer to avoid map + json.Marshal overhead.
	buf := jsonBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	buf.WriteString(`{"time":"`)
	buf.WriteString(time.Now().UTC().Format(time.RFC3339))
	buf.WriteString(`","level":"`)
	buf.WriteString(level)
	buf.WriteString(`","msg":`)

	// Extract structured fields from "{key=val key2=val2}" suffix.
	var fields string
	msg := line
	if idx := strings.LastIndex(line, " {"); idx >= 0 && strings.HasSuffix(line, "}") {
		fields = line[idx+2 : len(line)-1]
		msg = line[:idx]
	}

	// JSON-encode the message value.
	msgJSON, _ := json.Marshal(msg)
	buf.Write(msgJSON)

	// Append structured fields as top-level JSON keys.
	if fields != "" {
		for fields != "" {
			// Find next space-separated token.
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

	jsonBufPool.Put(buf)
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
	if format == "json" {
		// JSON mode: no flags (we add our own timestamp), no prefix. The JSON
		// encoding moves onto the drain goroutine along with the syscall.
		prefix, flags = "", 0
		writers = []io.Writer{&jsonLogWriter{dst: os.Stdout}}
		if fileWriter != nil {
			writers = append(writers, &jsonLogWriter{dst: fileWriter})
		}
	} else if fileWriter != nil {
		writers = append(writers, fileWriter)
	}

	sink := logsink.New(io.MultiWriter(writers...))
	logSink.Store(sink)
	return log.New(sink, prefix, flags), &logCloser{sink: sink, file: fileCloser}, nil
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
