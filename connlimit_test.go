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

// Enable is called at runtime (admin API, config import, CP snapshot sync)
// while Acquire runs on the proxy hot path; the race detector must not flag
// the maxPerIP read/write.
func TestConnLimiter_ConcurrentEnableReconfigure(t *testing.T) {
	cl := &ConnLimiter{conns: make(map[string]*int64)}
	cl.Enable(100)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if cl.Acquire("reconf-ip") {
					cl.Release("reconf-ip")
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 100; j++ {
			cl.Enable(50 + j%2)
		}
	}()
	wg.Wait()

	if cl.ActiveConns("reconf-ip") != 0 {
		t.Fatalf("all conns released but active = %d", cl.ActiveConns("reconf-ip"))
	}
}

// TestConnLimiter_ReleaseWhileDisabled verifies that Release correctly decrements
// the counter even when the limiter is disabled between Acquire and Release. A
// connection acquired while the limiter is enabled, released while it is
// disabled, must not leave a phantom counter entry that blocks future connections
// after the limiter is re-enabled.
func TestConnLimiter_ReleaseWhileDisabled(t *testing.T) {
	cl := &ConnLimiter{conns: make(map[string]*int64)}
	cl.Enable(1)

	if !cl.Acquire("1.2.3.4") {
		t.Fatal("first acquire should succeed")
	}

	cl.Disable()
	cl.Release("1.2.3.4") // must decrement even though limiter is now disabled

	cl.Enable(1)
	// Counter must be 0; the next acquire must succeed (no live connections).
	if !cl.Acquire("1.2.3.4") {
		t.Fatal("acquire after disable/enable cycle should succeed: Release leaked the counter while disabled")
	}
	cl.Release("1.2.3.4")
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
