package main

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

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

func (j *jsonLogWriter) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\n\r")

	entry := make(map[string]string)
	entry["time"] = time.Now().UTC().Format(time.RFC3339)

	// Extract structured fields from "{key=val key2=val2}" suffix.
	if idx := strings.LastIndex(line, " {"); idx >= 0 && strings.HasSuffix(line, "}") {
		fields := line[idx+2 : len(line)-1]
		msg := line[:idx]
		entry["msg"] = msg
		for _, kv := range strings.Fields(fields) {
			if eqIdx := strings.IndexByte(kv, '='); eqIdx > 0 {
				entry[kv[:eqIdx]] = kv[eqIdx+1:]
			}
		}
	} else {
		entry["msg"] = line
	}

	b, _ := json.Marshal(entry)
	b = append(b, '\n')

	j.mu.Lock()
	_, err := j.dst.Write(b)
	j.mu.Unlock()
	return len(p), err // always return original length so log.Logger doesn't retry
}

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
