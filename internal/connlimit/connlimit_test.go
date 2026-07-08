package connlimit

import (
	"sync"
	"testing"
)

func TestNew_DisabledByDefault(t *testing.T) {
	cl := New()
	if cl.Enabled() {
		t.Error("New limiter should be disabled by default")
	}
	if cl.MaxPerIP() != defaultMaxConnsPerIP {
		t.Errorf("MaxPerIP = %d, want %d", cl.MaxPerIP(), defaultMaxConnsPerIP)
	}
	// Disabled: always allow, never tracks.
	if !cl.Acquire("1.2.3.4") {
		t.Error("disabled limiter should allow")
	}
	if cl.ActiveIPs() != 0 {
		t.Error("disabled limiter should not track connections")
	}
}

func TestEnableDisable_Toggle(t *testing.T) {
	cl := New()
	cl.Enable(50)
	if !cl.Enabled() || cl.MaxPerIP() != 50 {
		t.Errorf("after Enable(50): enabled=%v max=%d", cl.Enabled(), cl.MaxPerIP())
	}
	cl.Disable()
	if cl.Enabled() {
		t.Error("after Disable: should report not enabled")
	}
	// Enable(<=0) falls back to the default cap.
	cl.Enable(0)
	if cl.MaxPerIP() != defaultMaxConnsPerIP {
		t.Errorf("Enable(0) cap = %d, want default %d", cl.MaxPerIP(), defaultMaxConnsPerIP)
	}
}

func TestAcquireRelease_LimitAndCleanup(t *testing.T) {
	cl := New()
	cl.Enable(2)

	if !cl.Acquire("ip") {
		t.Fatal("first acquire should succeed")
	}
	if !cl.Acquire("ip") {
		t.Fatal("second acquire should succeed (at limit)")
	}
	if cl.Acquire("ip") {
		t.Fatal("third acquire should fail (over limit)")
	}
	if got := cl.ActiveConns("ip"); got != 2 {
		t.Fatalf("ActiveConns = %d, want 2 (rejected acquire must not leak a count)", got)
	}
	if cl.ActiveIPs() != 1 {
		t.Errorf("ActiveIPs = %d, want 1", cl.ActiveIPs())
	}

	cl.Release("ip")
	cl.Release("ip")
	if got := cl.ActiveConns("ip"); got != 0 {
		t.Fatalf("ActiveConns after full release = %d, want 0", got)
	}
	if cl.ActiveIPs() != 0 {
		t.Errorf("ActiveIPs after cleanup = %d, want 0", cl.ActiveIPs())
	}
}

// TestConcurrent_NoLeak races Acquire/Release with a live Enable reconfigure,
// exercising the maxPerIP lock contract on the hot path (run with -race).
func TestConcurrent_NoLeak(t *testing.T) {
	cl := New()
	cl.Enable(100)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if cl.Acquire("ip") {
					cl.Release("ip")
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

	if got := cl.ActiveConns("ip"); got != 0 {
		t.Fatalf("all conns released but ActiveConns = %d", got)
	}
}
