package syslog

// Before/after benchmarks for the async delivery decoupling. The zero-value
// Writer still runs the pre-async synchronous path (send → writeMsg under
// s.mu), so both generations are measurable side by side:
//
//   Sync  = what every logged request used to pay: the collector write —
//           and the wait for every OTHER request's write — under one mutex.
//   Async = what a logged request pays now: json.Marshal + formatMsg + one
//           non-blocking channel send, independent of collector speed.
//
//   go test ./internal/syslog -bench 'WriteRequest' -benchmem

import (
	"net"
	"testing"
	"time"
)

// discardConn is an instantly-draining collector (healthy-UDP-like).
type discardConn struct{ deadlineRecordingConn }

func (c *discardConn) Write(p []byte) (int, error) { return len(p), nil }

// slowConn models a congested TCP collector: each line takes ~200µs to drain.
type slowConn struct{ deadlineRecordingConn }

func (c *slowConn) Write(p []byte) (int, error) {
	time.Sleep(200 * time.Microsecond)
	return len(p), nil
}

// benchEntry approximates a logstore.Entry-sized request-log record without
// importing it (this package is a stdlib-only leaf).
var benchEntry = map[string]any{
	"ts": int64(1752700000000), "time": "12:34:56", "ip": "203.0.113.7",
	"identity": "alice@corp.example", "method": "GET", "host": "www.example.com",
	"status": "OK", "level": "INFO", "rule_matched": "allow-web", "action_taken": "allow",
	"bytes_sent": int64(1234), "bytes_recv": int64(56789), "ssl_action": "inspect",
}

func newBenchWriter(conn net.Conn, async bool) *Writer {
	w := &Writer{
		network: "tcp",
		addr:    "192.0.2.1:514", // TEST-NET-1, never dialed: conn is pre-injected
		host:    "bench",
		tag:     "culvert",
		format:  "rfc3164",
		pid:     "1",
		conn:    conn,
	}
	if async {
		w.startAsync()
	}
	return w
}

// BenchmarkWriteRequest_SyncSlowCollector is the BEFORE: request goroutines
// serialize on s.mu around a ~200µs socket write, so per-caller latency is
// ~200µs × the number of concurrent loggers.
func BenchmarkWriteRequest_SyncSlowCollector(b *testing.B) {
	w := newBenchWriter(&slowConn{}, false)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w.WriteRequest(benchEntry)
		}
	})
}

// BenchmarkWriteRequest_AsyncSlowCollector is the AFTER against the same slow
// collector: caller cost is format + non-blocking enqueue (overflow drops),
// independent of collector speed.
func BenchmarkWriteRequest_AsyncSlowCollector(b *testing.B) {
	w := newBenchWriter(&slowConn{}, true)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w.WriteRequest(benchEntry)
		}
	})
	// Close flushes up to flushTimeout against the slow collector — cleanup,
	// not caller cost, so keep it out of the timed region.
	b.StopTimer()
	_ = w.Close()
}

// BenchmarkWriteRequest_SyncHealthyCollector / _AsyncHealthyCollector compare
// the healthy-collector steady state (instant drain): the async path should
// match or beat sync while removing the shared-mutex serialization.
func BenchmarkWriteRequest_SyncHealthyCollector(b *testing.B) {
	w := newBenchWriter(&discardConn{}, false)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w.WriteRequest(benchEntry)
		}
	})
}

func BenchmarkWriteRequest_AsyncHealthyCollector(b *testing.B) {
	w := newBenchWriter(&discardConn{}, true)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w.WriteRequest(benchEntry)
		}
	})
	b.StopTimer()
	_ = w.Close()
}
