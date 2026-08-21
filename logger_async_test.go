package main

// Contract tests for the asynchronous process-log sink installed by
// setupLogger (internal/logsink).
//
// handleRequest emits one line per proxied request. Before the sink was made
// asynchronous, that line was written straight through log.Logger's mutex into
// an unbuffered os.Stdout AND an unbuffered fileutil.RotatingFile (its own mutex
// held across the syscall), so every request in the process serialized on it.
// These tests pin the two halves of the replacement contract: the request
// goroutine is decoupled from the sink, and nothing is lost or reordered.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// restoreLogSink captures the process-wide async-sink pointer and puts it back
// on cleanup. setupLogger publishes into logSink as a side effect, so any test
// that calls it must restore the pointer or it leaves a CLOSED sink installed
// for whatever runs next (the suite runs shuffled).
func restoreLogSink(t *testing.T) {
	t.Helper()
	prev := logSink.Load()
	t.Cleanup(func() { logSink.Store(prev) })
}

// withSetupLogger installs a real setupLogger-built logger writing to a temp
// file, restores the previous globals, and returns the log path.
func withSetupLogger(t *testing.T, format string) string {
	t.Helper()
	restoreLogSink(t)
	path := filepath.Join(t.TempDir(), "culvert.log")
	l, closer, err := setupLogger(path, 1, format)
	if err != nil {
		t.Fatalf("setupLogger: %v", err)
	}
	prevLogger := logger
	logger = l
	t.Cleanup(func() {
		_ = closer.Close()
		logger = prevLogger
	})
	return path
}

// TestSetupLogger_ReturnsFlushingCloser pins that the Closer setupLogger hands
// back drains the queue before releasing the file. Shutdown calls it last
// (main_shutdown.go log-closer hook), so anything it fails to flush is lost.
func TestSetupLogger_ReturnsFlushingCloser(t *testing.T) {
	restoreLogSink(t)
	path := filepath.Join(t.TempDir(), "culvert.log")
	l, closer, err := setupLogger(path, 1, "text")
	if err != nil {
		t.Fatalf("setupLogger: %v", err)
	}
	if closer == nil {
		t.Fatal("setupLogger returned a nil Closer — shutdown would never flush the async sink")
	}
	for i := 0; i < 500; i++ {
		l.Printf("shutdown-line-%d", i)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	for i := 0; i < 500; i++ {
		if !bytes.Contains(data, []byte("shutdown-line-"+strconv.Itoa(i)+"\n")) {
			t.Fatalf("line %d missing from the log file after Close — the shutdown path is losing queued lines", i)
		}
	}
}

// TestSetupLogger_NoFile_StillReturnsCloser pins the wiring change: with no log
// file there is still a sink to flush, so the Closer must be non-nil (it used
// to be nil, and main_shutdown.go skips a nil one).
func TestSetupLogger_NoFile_StillReturnsCloser(t *testing.T) {
	restoreLogSink(t)
	_, closer, err := setupLogger("", 0, "text")
	if err != nil {
		t.Fatalf("setupLogger: %v", err)
	}
	if closer == nil {
		t.Fatal("setupLogger(\"\") returned a nil Closer — the stdout sink would never be flushed at shutdown")
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestSetupLogger_PreservesOrderAndContent pins that moving the write off the
// caller's goroutine changed neither the bytes written nor their order. A
// single drain goroutine owns the file, so the log stays strictly FIFO.
func TestSetupLogger_PreservesOrderAndContent(t *testing.T) {
	path := withSetupLogger(t, "text")

	const n = 2000
	for i := 0; i < n; i++ {
		logger.Printf("POLICY_ALLOW seq=%d", i)
	}
	flushLogSink()

	f, err := os.Open(path) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close() //nolint:errcheck // test cleanup

	sc := bufio.NewScanner(f)
	seq := 0
	for sc.Scan() {
		line := sc.Text()
		want := "POLICY_ALLOW seq=" + strconv.Itoa(seq)
		if !strings.HasSuffix(line, want) {
			t.Fatalf("log line %d = %q, want it to end with %q — FIFO ordering is broken", seq, line, want)
		}
		if !strings.HasPrefix(line, "[Culvert] ") {
			t.Fatalf("log line %d = %q — the [Culvert] prefix / LstdFlags header changed", seq, line)
		}
		seq++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if seq != n {
		t.Fatalf("log holds %d lines, want %d — lines were lost", seq, n)
	}
}

// TestSetupLogger_JSONModeStillEncodes pins that JSON mode survives the wrap:
// each record is encoded once, before the async sink, so the fields land as
// top-level JSON keys.
func TestSetupLogger_JSONModeStillEncodes(t *testing.T) {
	path := withSetupLogger(t, "json")

	logger.Printf("POLICY_ALLOW rule=%q {req_id=abc123 action=allow}", "Allow SaaS")
	flushLogSink()

	data, err := os.ReadFile(path) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	out := string(data)
	for _, want := range []string{`"level":"INFO"`, `"msg":`, `"req_id":"abc123"`, `"action":"allow"`} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON log output missing %s: %q", want, out)
		}
	}
}

// TestSetupLogger_JSONModeBatchingPreservesRecordBoundaries is the regression
// test for the record-boundary bug: with JSON encoding BEHIND the batching
// sink, a backlog flush coalesced several queued lines into one downstream
// Write, and the encoder folded them into a single JSON object with embedded
// newlines. Encoding now happens once per log.Logger call, before the sink, so
// every output line must be exactly one well-formed JSON object regardless of
// how the sink batched. A high volume with no intervening flush forces the
// drain goroutine to batch.
func TestSetupLogger_JSONModeBatchingPreservesRecordBoundaries(t *testing.T) {
	path := withSetupLogger(t, "json")

	const n = 2000
	for i := 0; i < n; i++ {
		logger.Printf("POLICY_ALLOW seq=%d", i)
	}
	flushLogSink()

	f, err := os.Open(path) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close() //nolint:errcheck // test cleanup

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	seq := 0
	for sc.Scan() {
		line := sc.Bytes()
		var rec struct {
			Time  string `json:"time"`
			Level string `json:"level"`
			Msg   string `json:"msg"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("output line %d is not a standalone JSON object (record boundaries broken): %v\nline=%q", seq, err, line)
		}
		want := "POLICY_ALLOW seq=" + strconv.Itoa(seq)
		if rec.Msg != want {
			t.Fatalf("line %d msg=%q, want %q — records were merged or reordered", seq, rec.Msg, want)
		}
		if strings.Contains(rec.Msg, "\n") {
			t.Fatalf("line %d msg contains an embedded newline — a batch was folded into one record", seq)
		}
		seq++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if seq != n {
		t.Fatalf("log holds %d JSON records, want %d — records were merged or lost", seq, n)
	}
}

// TestSetupLogger_ConcurrentWritersLoseNothing is the -race exercise on the
// real composition: many goroutines logging like many request goroutines do.
func TestSetupLogger_ConcurrentWritersLoseNothing(t *testing.T) {
	path := withSetupLogger(t, "text")

	const goroutines, perG = 16, 250
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				logger.Printf("POLICY_ALLOW g=%d i=%d", g, i)
			}
		}(g)
	}
	wg.Wait()
	flushLogSink()

	data, err := os.ReadFile(path) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if got := bytes.Count(data, []byte("\n")); got != goroutines*perG {
		t.Fatalf("log holds %d lines, want %d — concurrent writers lost lines", got, goroutines*perG)
	}
}
