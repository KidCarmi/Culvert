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
		os.Remove(r.path + ".1") //nolint:errcheck -- best-effort cleanup
		os.Rename(r.path, r.path+".1")
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
type jsonLogWriter struct {
	mu  sync.Mutex
	dst io.Writer
}

func (j *jsonLogWriter) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\n\r")

	// Strip the standard log timestamp prefix "YYYY/MM/DD HH:MM:SS " (20 chars) if present.
	// The go log package adds it before the user message when flags include date+time.
	// In JSON mode we create the logger with no flags so there is no prefix to strip.
	entry := struct {
		Time string `json:"time"`
		Msg  string `json:"msg"`
	}{
		Time: time.Now().UTC().Format(time.RFC3339),
		Msg:  line,
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
