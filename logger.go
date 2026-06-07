package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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

// SetLogLevel sets the global minimum log level.
func SetLogLevel(l LogLevel) {
	logLevel.Store(int32(l))
}

// GetLogLevel returns the current global minimum log level.
func GetLogLevel() LogLevel {
	return LogLevel(logLevel.Load())
}

// ── Leveled logging helpers ──────────────────────────────────────────────────
// These wrap the global logger with level filtering.
// Printf remains an alias for Infof (backward compatibility — all 418 existing
// logger.Printf calls continue to work at INFO level).

func logDebugf(format string, args ...any) {
	if GetLogLevel() <= LevelDebug {
		logger.Printf("DEBUG "+format, args...)
	}
}

func logInfof(format string, args ...any) {
	if GetLogLevel() <= LevelInfo {
		logger.Printf("INFO "+format, args...)
	}
}

func logWarnf(format string, args ...any) {
	if GetLogLevel() <= LevelWarn {
		logger.Printf("WARN "+format, args...)
	}
}

func logErrorf(format string, args ...any) {
	// Error is always logged regardless of level.
	logger.Printf("ERROR "+format, args...)
}

// ── Rotating file writer ─────────────────────────────────────────────────────

// rotatingFile wraps a log file and rotates it when it exceeds maxBytes.
type rotatingFile struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	file     *os.File
	size     int64
}

func newRotatingFile(path string, maxMB int) (*rotatingFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	info, _ := f.Stat()
	var sz int64
	if info != nil {
		sz = info.Size()
	}
	maxBytes := int64(maxMB) * 1024 * 1024
	if maxBytes == 0 {
		maxBytes = 50 * 1024 * 1024 // 50 MB default
	}
	return &rotatingFile{path: path, maxBytes: maxBytes, file: f, size: sz}, nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.size+int64(len(p)) > r.maxBytes {
		r.file.Close()
		// Remove any previous rotated file before renaming the current one.
		// This prevents unbounded growth from accumulating stale .1 files.
		_ = os.Remove(r.path + ".1")
		_ = os.Rename(r.path, r.path+".1")
		f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return 0, err
		}
		r.file = f
		r.size = 0
	}

	n, err := r.file.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) Close() error {
	return r.file.Close()
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
func setupLogger(logPath string, maxMB int, format string) (*log.Logger, io.Closer, error) {
	var fileWriter io.Writer
	var closer io.Closer

	if logPath != "" {
		rf, err := newRotatingFile(logPath, maxMB)
		if err != nil {
			return nil, nil, err
		}
		fileWriter = rf
		closer = rf
	}

	if format == "json" {
		// JSON mode: no flags (we add our own timestamp), no prefix.
		writers := []io.Writer{&jsonLogWriter{dst: os.Stdout}}
		if fileWriter != nil {
			writers = append(writers, &jsonLogWriter{dst: fileWriter})
		}
		l := log.New(io.MultiWriter(writers...), "", 0)
		return l, closer, nil
	}

	// Plain-text mode (default).
	writers := []io.Writer{os.Stdout}
	if fileWriter != nil {
		writers = append(writers, fileWriter)
	}
	l := log.New(io.MultiWriter(writers...), "[Culvert] ", log.LstdFlags)
	return l, closer, nil
}
