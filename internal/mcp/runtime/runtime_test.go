package runtime

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"
)

func TestRuntime_DisabledByDefault(t *testing.T) {
	before := runtime.NumGoroutine()
	rt, err := NewRuntime(Config{})
	if err != nil {
		t.Fatalf("NewRuntime(disabled): %v", err)
	}
	if rt.Enabled() {
		t.Fatal("empty runtime reports enabled")
	}
	if err := rt.Start(); err != nil {
		t.Fatalf("Start(disabled): %v", err)
	}
	if rt.Addr(false) != "" || rt.Addr(true) != "" {
		t.Fatal("disabled runtime bound a socket")
	}
	if len(rt.Health()) != 0 {
		t.Fatal("disabled runtime reported listener health")
	}
	// No goroutine/timer started.
	time.Sleep(20 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+1 {
		t.Fatalf("disabled runtime started goroutines: before=%d after=%d", before, after)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := rt.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown(disabled): %v", err)
	}
}

func TestRuntime_StartServeShutdownNoLeak(t *testing.T) {
	k := newESKey(t, "k1")
	before := runtime.NumGoroutine()
	rt, addr := startInsecureRuntime(t, k) // registers cleanup Shutdown
	if addr == "" {
		t.Fatal("runtime did not bind")
	}
	// A live request works.
	dialTCP(t, addr).Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rt.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	// Shutdown is idempotent.
	if err := rt.Shutdown(ctx); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
	// Allow goroutines to unwind.
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Fatalf("goroutine leak: before=%d after=%d", before, after)
	}
}

func TestRuntime_TransactionalStartupRollback(t *testing.T) {
	k := newESKey(t, "k1")
	// Occupy a port so the Management listener's bind fails.
	var lc net.ListenConfig
	occupied, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy: %v", err)
	}
	defer occupied.Close()
	busyPort := occupied.Addr().(*net.TCPAddr).Port

	g := gwListenerConfig(t)
	g.Port = 0 // ephemeral — binds fine
	m := mgmtListenerConfig(t)
	m.Port = busyPort // will fail to bind
	m.BindAddress = "127.0.0.1"

	rt, err := NewRuntime(Config{Gateway: g, Management: m, Deps: testDeps(t, k, nil)})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if err := rt.Start(); err == nil {
		t.Fatal("expected Start to fail on management bind conflict")
	}
	// Rollback: the already-bound gateway socket must be closed (nothing serving).
	if gwAddr := rt.Addr(false); gwAddr != "" {
		dctx, dcancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer dcancel()
		if c, derr := (&net.Dialer{}).DialContext(dctx, "tcp", gwAddr); derr == nil {
			c.Close()
			t.Fatal("gateway listener still serving after rollback")
		}
	}
}

func TestListener_AdmissionBounded(t *testing.T) {
	k := newESKey(t, "k1")
	cfg := gwListenerConfig(t)
	lc := validLimitConfig()
	lc.MaxConcurrent = 1
	lc.QueueDepth = 1
	lim, err := NewLimits(lc)
	if err != nil {
		t.Fatalf("limits: %v", err)
	}
	cfg.Limits = lim
	l, err := newListener(cfg, testDeps(t, k, nil), "gw", 1)
	if err != nil {
		t.Fatalf("newListener: %v", err)
	}
	ctx := context.Background()
	// Grab the single worker slot (not released).
	rel1, ok := l.admit(ctx)
	if !ok {
		t.Fatal("first admit failed")
	}
	defer rel1()
	// Simulate a request occupying the single queue slot.
	l.queue <- struct{}{}
	// The next admit must be shed immediately (queue full) — bounded, never blocks.
	rctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if _, ok := l.admit(rctx); ok {
		t.Fatal("admit succeeded past the queue+worker bound")
	}
}

func TestRuntime_ListenerIsolation(t *testing.T) {
	k := newESKey(t, "k1")
	// Two dedicated listeners; saturating one's admission pool must not affect the
	// other's (separate sem/queue/counters).
	gcfg := gwListenerConfig(t)
	mcfg := mgmtListenerConfig(t)
	lc := validLimitConfig()
	lc.MaxConcurrent = 1
	lc.QueueDepth = 1
	lim, _ := NewLimits(lc)
	gcfg.Limits, mcfg.Limits = lim, lim

	gl, err := newListener(gcfg, testDeps(t, k, nil), "gw", 1)
	if err != nil {
		t.Fatalf("gw listener: %v", err)
	}
	ml, err := newListener(mcfg, testDeps(t, k, nil), "mgmt", 1)
	if err != nil {
		t.Fatalf("mgmt listener: %v", err)
	}
	// Exhaust the gateway pool.
	rel, ok := gl.admit(context.Background())
	if !ok {
		t.Fatal("gw admit")
	}
	defer rel()
	gl.queue <- struct{}{}
	gctx, gcancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer gcancel()
	if _, ok := gl.admit(gctx); ok {
		t.Fatal("gateway pool not saturated")
	}
	// The management pool is completely unaffected.
	relM, ok := ml.admit(context.Background())
	if !ok {
		t.Fatal("management admission degraded by gateway saturation (isolation broken)")
	}
	relM()
}
