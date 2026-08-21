package logsink

// Benchmarks for the process-log sink.
//
// The pairs below are before/after: Sync* is the pre-change composition
// (log.Logger writing straight through io.MultiWriter to stdout + the rotating
// file, both unbuffered, both under mutexes held across the syscall); Async* is
// the same composition behind this package.
//
//	go test -run '^$' -bench . ./internal/logsink/
//
// The Duty* pair is the one that matters for the product: a proxied request
// does a few microseconds of real work and emits ONE log line, so what these
// measure is the latency the log line ADDS to a request — not the throughput of
// a pathological 100%-duty-cycle log flood.

import (
	"crypto/sha256"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
)

// ── the production sink shape ────────────────────────────────────────────────

// rotatingStub mirrors fileutil.RotatingFile's concurrency contract: one mutex
// held ACROSS the write(2). internal/* packages do not import each other, so
// the shape is reproduced rather than imported.
type rotatingStub struct {
	mu sync.Mutex
	f  *os.File
}

func (r *rotatingStub) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Write(p)
}

func prodWriters(b *testing.B) io.Writer {
	stdout, err := os.CreateTemp(b.TempDir(), "stdout")
	if err != nil {
		b.Fatal(err)
	}
	file, err := os.CreateTemp(b.TempDir(), "culvert.log")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { stdout.Close(); file.Close() })
	return io.MultiWriter(stdout, &rotatingStub{f: file})
}

func syncLogger(b *testing.B) *log.Logger {
	return log.New(prodWriters(b), "[Culvert] ", log.LstdFlags)
}

func asyncLogger(b *testing.B) *log.Logger {
	w := New(prodWriters(b))
	b.Cleanup(func() { _ = w.Close() })
	return log.New(w, "[Culvert] ", log.LstdFlags)
}

// emit reproduces the per-request POLICY_ALLOW line handleRequest writes for
// every allowed request, so the measured line length and argument count match
// production.
func emit(l *log.Logger) {
	l.Printf("POLICY_ALLOW rule=%q pri=%s %s %s %q [%s] {req_id=%s identity=%s rule=%s action=allow}",
		"Allow Corporate SaaS", "120", "203.0.113.7", "CONNECT",
		"graph.microsoft.com:443", "fqdn=*.microsoft.com,category=business",
		"0f3a9c1d5e7b2a48", "alice@corp.example.com", "Allow Corporate SaaS")
}

// ── A. log-flood throughput (upper bound, not a realistic duty cycle) ────────

func BenchmarkSyncSink(b *testing.B) {
	l := syncLogger(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		emit(l)
	}
}

func BenchmarkAsyncSink(b *testing.B) {
	l := asyncLogger(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		emit(l)
	}
}

func BenchmarkSyncSinkParallel(b *testing.B) {
	l := syncLogger(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			emit(l)
		}
	})
}

func BenchmarkAsyncSinkParallel(b *testing.B) {
	l := asyncLogger(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			emit(l)
		}
	})
}

// ── B. realistic duty cycle: request work + ONE log line ─────────────────────

// requestWork burns a deterministic few microseconds of CPU, standing in for
// the non-logging part of a proxied request (policy eval, transport, headers).
func requestWork(sink *[32]byte) {
	var b [64]byte
	for i := 0; i < 40; i++ {
		*sink = sha256.Sum256(b[:])
		b[0]++
	}
}

func benchDuty(b *testing.B, l *log.Logger, doLog bool) {
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var sink [32]byte
		for pb.Next() {
			requestWork(&sink)
			if doLog {
				emit(l)
			}
		}
	})
}

// BenchmarkDutyNoLog is the floor: the request work alone.
func BenchmarkDutyNoLog(b *testing.B) { benchDuty(b, log.New(io.Discard, "", 0), false) }

func BenchmarkDutySyncSink(b *testing.B) { benchDuty(b, syncLogger(b), true) }

func BenchmarkDutyAsyncSink(b *testing.B) { benchDuty(b, asyncLogger(b), true) }

// ── C. the write path in isolation (allocation contract) ─────────────────────

// BenchmarkWriteEnqueue measures just the producer side: the buffer copy and
// the channel send that replaced two syscalls under a global mutex. The sink is
// io.Discard so the drain goroutine never becomes the limit.
func BenchmarkWriteEnqueue(b *testing.B) {
	w := New(io.Discard)
	defer func() { _ = w.Close() }()
	line := []byte(strings.Repeat("x", 180) + "\n")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = w.Write(line)
	}
}

func BenchmarkWriteEnqueueParallel(b *testing.B) {
	w := New(io.Discard)
	defer func() { _ = w.Close() }()
	line := []byte(strings.Repeat("x", 180) + "\n")
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = w.Write(line)
		}
	})
}

// ── D. allocation gate ───────────────────────────────────────────────────────

// TestBenchGateWriteAllocs pins the producer-side allocation contract. The
// pooled carrier means enqueueing a line is allocation-free in steady state;
// any reintroduction of a per-line []byte (dropping the pool, or sending a
// value instead of a pointer through the channel) shows up here immediately.
// Allocations are the gate, not ns/op: they are deterministic and
// hardware-independent, so this bound holds across CI runners.
func TestBenchGateWriteAllocs(t *testing.T) {
	const maxAllocs int64 = 1 // steady state 0; one alloc of headroom for pool churn
	w := New(io.Discard)
	defer func() { _ = w.Close() }()
	line := []byte(strings.Repeat("x", 180) + "\n")

	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = w.Write(line)
		}
	})
	allocs := res.AllocsPerOp()
	t.Logf("logsink.Write: %d allocs/op (bound %d), %d ns/op", allocs, maxAllocs, res.NsPerOp())
	if allocs > maxAllocs {
		t.Errorf("REGRESSION: logsink.Write allocates %d/op, exceeds bound %d — "+
			"the pooled line carrier has been bypassed and every logged request now allocates", allocs, maxAllocs)
	}
}
