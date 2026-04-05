package main

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestGenerateRequestID(t *testing.T) {
	id := generateRequestID()
	if len(id) != 16 {
		t.Fatalf("request ID length = %d, want 16", len(id))
	}
	id2 := generateRequestID()
	if id == id2 {
		t.Fatal("two generated IDs should be unique")
	}
}

func TestConnLimiter_Disabled(t *testing.T) {
	cl := &ConnLimiter{conns: make(map[string]*int64)}
	// Disabled by default: should always allow.
	if !cl.Acquire("1.2.3.4") {
		t.Fatal("disabled limiter should always allow")
	}
	cl.Release("1.2.3.4")
}

func TestConnLimiter_Enabled(t *testing.T) {
	cl := &ConnLimiter{conns: make(map[string]*int64)}
	cl.Enable(3)

	if !cl.Acquire("10.0.0.1") {
		t.Fatal("first acquire should succeed")
	}
	if !cl.Acquire("10.0.0.1") {
		t.Fatal("second acquire should succeed")
	}
	if !cl.Acquire("10.0.0.1") {
		t.Fatal("third acquire should succeed (at limit)")
	}
	if cl.Acquire("10.0.0.1") {
		t.Fatal("fourth acquire should fail (over limit)")
	}

	if cl.ActiveConns("10.0.0.1") != 3 {
		t.Fatalf("active conns = %d, want 3", cl.ActiveConns("10.0.0.1"))
	}

	cl.Release("10.0.0.1")
	if cl.ActiveConns("10.0.0.1") != 2 {
		t.Fatalf("after release: active conns = %d, want 2", cl.ActiveConns("10.0.0.1"))
	}

	// Now acquire should succeed again.
	if !cl.Acquire("10.0.0.1") {
		t.Fatal("should succeed after release")
	}
}

func TestConnLimiter_DifferentIPs(t *testing.T) {
	cl := &ConnLimiter{conns: make(map[string]*int64)}
	cl.Enable(1)

	if !cl.Acquire("ip-a") {
		t.Fatal("ip-a should succeed")
	}
	if cl.Acquire("ip-a") {
		t.Fatal("ip-a second should fail")
	}
	if !cl.Acquire("ip-b") {
		t.Fatal("ip-b should succeed (independent)")
	}

	cl.Release("ip-a")
	cl.Release("ip-b")
}

func TestConnLimiter_ReleaseCleanup(t *testing.T) {
	cl := &ConnLimiter{conns: make(map[string]*int64)}
	cl.Enable(10)
	cl.Acquire("clean-ip")
	cl.Release("clean-ip")

	if cl.ActiveConns("clean-ip") != 0 {
		t.Fatalf("should be 0 after full release, got %d", cl.ActiveConns("clean-ip"))
	}
}

func TestConnLimiter_Concurrent(t *testing.T) {
	cl := &ConnLimiter{conns: make(map[string]*int64)}
	cl.Enable(100)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				cl.Acquire("shared-ip")
				cl.Release("shared-ip")
			}
		}()
	}
	wg.Wait()

	if cl.ActiveConns("shared-ip") != 0 {
		t.Fatalf("all conns released but active = %d", cl.ActiveConns("shared-ip"))
	}
}

func TestLatencyHistogram_Observe(t *testing.T) {
	h := newLatencyHistogram()
	h.Observe(0.001) // 1ms → 5ms bucket
	h.Observe(0.05)  // 50ms bucket
	h.Observe(100)   // +Inf bucket

	if total := atomic.LoadInt64(&h.total); total != 3 {
		t.Fatalf("total = %d, want 3", total)
	}
}

func TestLatencyHistogram_WritePrometheus(t *testing.T) {
	h := newLatencyHistogram()
	h.Observe(0.1)

	var buf strings.Builder
	h.WritePrometheus(&buf)
	out := buf.String()

	if !strings.Contains(out, "culvert_request_duration_seconds_bucket") {
		t.Fatal("should contain bucket metrics")
	}
	if !strings.Contains(out, "culvert_request_duration_seconds_sum") {
		t.Fatal("should contain sum metric")
	}
	if !strings.Contains(out, "culvert_request_duration_seconds_count") {
		t.Fatal("should contain count metric")
	}
	if !strings.Contains(out, `le="+Inf"`) {
		t.Fatal("should contain +Inf bucket")
	}
}
