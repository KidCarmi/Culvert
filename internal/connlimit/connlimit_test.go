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
	// Disabled: always ADMITS (never rejects). Accounting is still maintained
	// so that a disable/re-enable transition mid-connection stays correct
	// (see Acquire's doc) — a disabled Acquire is tracked and cleaned up by
	// its paired Release.
	if !cl.Acquire("1.2.3.4") {
		t.Error("disabled limiter should always admit")
	}
	if got := cl.ActiveConns("1.2.3.4"); got != 1 {
		t.Errorf("disabled Acquire should still be counted for transition-safety; ActiveConns = %d, want 1", got)
	}
	cl.Release("1.2.3.4")
	if cl.ActiveIPs() != 0 {
		t.Errorf("paired Release must clean up the tracked entry; ActiveIPs = %d, want 0", cl.ActiveIPs())
	}
	// Many admits while disabled never get rejected.
	for i := 0; i < 1000; i++ {
		if !cl.Acquire("5.6.7.8") {
			t.Fatal("disabled limiter must never reject")
		}
	}
	for i := 0; i < 1000; i++ {
		cl.Release("5.6.7.8")
	}
	if cl.ActiveIPs() != 0 {
		t.Errorf("all disabled acquires released; ActiveIPs = %d, want 0", cl.ActiveIPs())
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

// TestConnLimiter_ReleaseWhileDisabled pins the disable-during-connection
// contract: a connection acquired while enabled must decrement the per-IP
// counter even if Release runs after the limiter was disabled. Otherwise the
// counter leaks and, after re-enable, that IP is permanently over-limit —
// a self-inflicted DoS reachable via the admin API / config import (the #503
// fail-closed bug). Against a Release that early-returned when disabled, the
// Release below is a no-op, the counter stays at 1, and the final Acquire
// fails (limit=1).
func TestConnLimiter_ReleaseWhileDisabled(t *testing.T) {
	cl := New()

	cl.Enable(1)
	if !cl.Acquire("ip") {
		t.Fatal("acquire while enabled (limit 1) should succeed")
	}

	// Disable, then release the connection that was counted while enabled.
	cl.Disable()
	cl.Release("ip")

	// Re-enable at limit 1. If Release decremented the counter, the IP is back
	// to zero and this acquire must succeed; if it leaked, this fails.
	cl.Enable(1)
	if !cl.Acquire("ip") {
		t.Fatal("acquire after disable/release/re-enable should succeed; counter leaked")
	}
}

// TestConnLimiter_DisabledAcquireDoesNotBypassCap pins the mirror of the #503
// contract (Codex P2 on the rebuild): a connection admitted while the limiter
// was DISABLED must still be accounted, so that after re-enable a still-open
// connection counted earlier keeps the cap enforced. If a disabled Acquire
// were untracked while Release still decremented unconditionally, releasing
// the disabled-era connection would decrement the older counted slot, and a
// subsequent Acquire would be admitted past the per-IP cap (fail-open).
func TestConnLimiter_DisabledAcquireDoesNotBypassCap(t *testing.T) {
	cl := New()

	cl.Enable(1)
	if !cl.Acquire("ip") { // connection A, counted, still open for the whole test
		t.Fatal("first acquire (limit 1) should succeed")
	}

	cl.Disable()
	if !cl.Acquire("ip") { // connection B, admitted while disabled
		t.Fatal("disabled limiter must admit")
	}
	cl.Release("ip") // B finishes first

	// A is still open. Re-enabling at limit 1 must REJECT a new connection,
	// because A occupies the single slot. A fail-open bug would admit here.
	cl.Enable(1)
	if cl.Acquire("ip") {
		t.Fatal("cap bypassed: a new acquire was admitted while connection A is still open")
	}

	// Releasing A frees the slot; the next acquire is admitted.
	cl.Release("ip")
	if !cl.Acquire("ip") {
		t.Fatal("after releasing A the slot should be free")
	}
}
