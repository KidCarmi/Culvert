package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// CHAOS-56 — the shutdown path under a hook that does not return.
//
// The domain is SIGTERM → exit. Culvert's shutdown sequence is 17 ordered
// hooks split into an "early" phase (stop accepting) and a "late" phase (drain
// + durable flush). Before this file the sequence was bounded by nothing it
// owned:
//
//   - the early phase ran under context.Background(), by design, and its
//     second hook is gRPC GracefulStop, which does not return until every
//     client transport closes. grpc-go bounds the IDLE case at a 5s GOAWAY
//     ping-ack timer (measured 6.0s end to end on v1.83.1), but a transport
//     with an ACTIVE STREAM at the second GOAWAY is left open with no timer at
//     all — so a handler blocked on a wedged volume, or a response the peer
//     stopped reading, held the whole sequence with no bound;
//   - the late phase's ctx was ADVISORY: shutdownRegistry ran every hook
//     synchronously regardless of ctx, and several hooks ignore the parameter
//     entirely (the tunnel drain ran its own independent 15s timer; the
//     syslog/badger/logstore/reqlog/audit/log closers take no ctx at all);
//   - a panicking hook killed the process mid-sequence;
//   - a SECOND SIGTERM was swallowed, because signal.Notify had taken the
//     runtime's default terminate behaviour away and nothing read the channel
//     again.
//
// The container's stop_grace_period was therefore the only real bound, and
// reaching it means SIGKILL — which skips the cluster-store flush, the
// request-log queue drain, a clean badger close (CHAOS-50 showed an unclean
// one is what manufactures a quarantined category store on the next boot) and
// the log-sink flush that would have named the stalled hook.
//
// Every gate whose name carries a defect ID was verified failing against the
// pre-fix tree; the ones pinning new behaviour have no pre-fix counterpart.

// blockUntil returns a hook that blocks until stop is closed, recording that
// it started. Used to simulate the hook that does not return.
func blockUntil(stop <-chan struct{}, started *atomic.Bool) func(context.Context) error {
	return func(context.Context) error {
		started.Store(true)
		<-stop
		return nil
	}
}

// shortHookGrace lowers the watchdog's per-phase grace for the duration of a
// test so a wedged-hook gate costs milliseconds rather than the production
// grace, restoring it via Cleanup.
func shortHookGrace(t *testing.T, d time.Duration) {
	t.Helper()
	prev := shutdownHookGrace
	shutdownHookGrace = d
	t.Cleanup(func() { shutdownHookGrace = prev })
}

// TestChaos56_EarlyPhaseHookCannotStallTheSequence is the SD-1 gate: the
// early phase used to run under context.Background(), so a hook that does not
// return — gRPC GracefulStop against a half-open peer — held SIGTERM open
// until the container killed the process. Against the pre-fix tree this test
// does not fail with an assertion, it HANGS until the package timeout, which
// is precisely the production symptom.
func TestChaos56_EarlyPhaseHookCannotStallTheSequence(t *testing.T) {
	shortHookGrace(t, 100*time.Millisecond)
	stop := make(chan struct{})
	defer close(stop)

	var early, late shutdownRegistry
	var wedgedStarted, flushRan atomic.Bool
	early.Register("test-wedged-early", 1, blockUntil(stop, &wedgedStarted))
	late.Register("test-flush", shutdownFlushBoundary+1, func(context.Context) error {
		flushRan.Store(true)
		return nil
	})

	budget := shutdownBudget{Total: 900 * time.Millisecond, Early: 200 * time.Millisecond, Flush: 200 * time.Millisecond}
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		runShutdownSequence(&early, &late, budget)
		done <- time.Since(start)
	}()

	select {
	case elapsed := <-done:
		// Early share + its watchdog grace, plus the rest of the envelope.
		if max := budget.Total + 3*shutdownHookGrace; elapsed > max {
			t.Errorf("shutdown took %v; envelope bound is %v", elapsed, max)
		}
	case <-time.After(budget.Total + 4*shutdownHookGrace):
		t.Fatal("shutdown sequence never returned — a wedged early hook is stalling the whole sequence")
	}
	if !wedgedStarted.Load() {
		t.Error("the wedged hook never ran; the test proved nothing")
	}
	if !flushRan.Load() {
		t.Error("flush hook did not run — a wedged early hook is still starving the durable flushes")
	}
}

// TestChaos56_StuckDrainCannotSpendTheFlushReserve is the SD-2 gate. The late
// phase used to be one budget shared by hooks with opposite failure costs:
// drain hooks (best-effort, loss costs a retry) and flush hooks (durable, loss
// costs a corrupt store). A drain that did not return consumed the whole
// budget and every flush behind it never ran at all.
func TestChaos56_StuckDrainCannotSpendTheFlushReserve(t *testing.T) {
	shortHookGrace(t, 100*time.Millisecond)
	stop := make(chan struct{})
	defer close(stop)

	var early, late shutdownRegistry
	var wedgedStarted atomic.Bool
	var flushOrder []string
	late.Register("test-wedged-drain", shutdownFlushBoundary-1, blockUntil(stop, &wedgedStarted))
	late.Register("test-flush-a", shutdownFlushBoundary+1, func(ctx context.Context) error {
		flushOrder = append(flushOrder, "a")
		if _, ok := ctx.Deadline(); !ok {
			t.Error("flush hook ctx has no deadline")
		}
		return nil
	})
	late.Register("test-flush-b", shutdownFlushBoundary+2, func(context.Context) error {
		flushOrder = append(flushOrder, "b")
		return nil
	})

	budget := shutdownBudget{Total: 800 * time.Millisecond, Early: 100 * time.Millisecond, Flush: 300 * time.Millisecond}
	runShutdownSequence(&early, &late, budget)

	if !wedgedStarted.Load() {
		t.Fatal("the wedged drain hook never ran; the test proved nothing")
	}
	if len(flushOrder) != 2 || flushOrder[0] != "a" || flushOrder[1] != "b" {
		t.Errorf("flush hooks ran = %v; want [a b] — a stuck drain is still starving the durable flushes", flushOrder)
	}
}

// TestChaos56_HookPanicDoesNotAbortTheSequence is the SD-4 gate. RunAll's
// contract says "all hooks run even if one returns an error", which was only
// ever true for ERRORS: an unrecovered panic (badger's Close can panic; so can
// any hook a future PR adds) unwound the whole sequence and killed the process
// before the durable flushes and the log-sink flush.
//
// Containment lands the opposite way from CHAOS-24's HA keepalive for the
// reason recorded there: a shutdown hook holds no authority that containing it
// would extend.
func TestChaos56_HookPanicDoesNotAbortTheSequence(t *testing.T) {
	var reg shutdownRegistry
	var after atomic.Bool
	reg.Register("test-panics", 1, func(context.Context) error { panic("boom") })
	reg.Register("test-after", 2, func(context.Context) error { after.Store(true); return nil })

	err := reg.RunAll(context.Background())
	if !after.Load() {
		t.Fatal("hook after the panicking one did not run — a panic still aborts the sequence")
	}
	if err == nil || !strings.Contains(err.Error(), "test-panics") {
		t.Errorf("RunAll error = %v; must name the panicking hook", err)
	}
	if err != nil && !strings.Contains(err.Error(), "boom") {
		t.Errorf("RunAll error = %v; must carry the panic value", err)
	}
}

// TestChaos56_AbandonedHookIsReportedByName pins the operator-visible half:
// the watchdog names the hook it gave up on, and does so at the point of
// abandonment rather than only in the aggregated error — the last flush hook
// closes the log sink, so anything logged after a phase returns is enqueued
// into a channel nobody drains.
func TestChaos56_AbandonedHookIsReportedByName(t *testing.T) {
	shortHookGrace(t, 100*time.Millisecond)
	stop := make(chan struct{})
	defer close(stop)

	var reg shutdownRegistry
	var started atomic.Bool
	var err error
	reg.Register("test-wedged", 1, blockUntil(stop, &started))

	out := captureLogger(t, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		err = reg.RunAll(ctx)
	})

	if !errors.Is(err, errShutdownHookAbandoned) {
		t.Errorf("RunAll error = %v; want errShutdownHookAbandoned", err)
	}
	if !strings.Contains(out, `"test-wedged"`) {
		t.Errorf("log did not name the abandoned hook; got %q", out)
	}
}

// TestChaos56_HealthyHooksAreNotAbandonedEarly is the control for the two
// gates above: the watchdog must not turn a hook that simply takes a moment
// into an abandonment. A gate that passes because hooks stopped running at
// all would be worse than the defect.
func TestChaos56_HealthyHooksAreNotAbandonedEarly(t *testing.T) {
	var reg shutdownRegistry
	var ran atomic.Bool
	reg.Register("test-slow-but-fine", 1, func(context.Context) error {
		time.Sleep(120 * time.Millisecond)
		ran.Store(true)
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := reg.RunAll(ctx); err != nil {
		t.Errorf("RunAll error = %v; a hook well inside its budget must not be abandoned", err)
	}
	if !ran.Load() {
		t.Error("hook did not complete")
	}
}

// TestChaos56_TunnelDrainHonoursThePhaseDeadline is the SD-2b gate. The drain
// documented its 15s window as "independent of the parent ctx", so it was
// ADDED to the late budget rather than spent inside it — which is why
// docker-compose.yml's stop_grace_period comment describes an envelope
// ("up to a 15s tunnel-drain window inside the ~30s late-phase budget") that
// no code enforced.
func TestChaos56_TunnelDrainHonoursThePhaseDeadline(t *testing.T) {
	atomic.StoreInt64(&activeConns, 1)
	defer atomic.StoreInt64(&activeConns, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	if err := drainActiveTunnels(ctx); err != nil {
		t.Fatalf("drainActiveTunnels: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed >= tunnelDrainWindow {
		t.Errorf("drain took %v — it is still spending its full %v window past the phase deadline",
			elapsed, tunnelDrainWindow)
	}
	if elapsed > 2*time.Second {
		t.Errorf("drain took %v; expected it to return shortly after the 150ms phase deadline", elapsed)
	}
}

// TestChaos56_TunnelDrainStillWaitsWhenItHasBudget is the control for the
// gate above: clamping the window to the phase deadline must not turn the
// drain into a no-op when there IS budget, or in-flight decrypted flows would
// be cut at every restart.
func TestChaos56_TunnelDrainStillWaitsWhenItHasBudget(t *testing.T) {
	atomic.StoreInt64(&activeConns, 1)
	defer atomic.StoreInt64(&activeConns, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = drainActiveTunnels(ctx)
	}()

	select {
	case <-done:
		t.Error("drain returned immediately with a live tunnel and 30s of budget")
	case <-time.After(700 * time.Millisecond):
		// Still waiting, as it should be. Release it.
	}
	atomic.StoreInt64(&activeConns, 0)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("drain did not return after the last tunnel closed")
	}
}

// TestChaos56_SecondSignalForcesExit is the SD-3 gate. signal.Notify takes
// SIGINT/SIGTERM away from the Go runtime's default terminate behaviour, and
// after the first one nothing read the channel again — so a second signal sat
// in the buffer and did nothing. An operator's only escalation was SIGKILL,
// which is the outcome the escalation exists to avoid.
func TestChaos56_SecondSignalForcesExit(t *testing.T) {
	quit := make(chan os.Signal, 1)
	exited := make(chan int, 1)
	stop := armShutdownEscalation(quit, func(code int) { exited <- code })
	defer stop()

	quit <- syscall.SIGTERM
	select {
	case code := <-exited:
		if code == 0 {
			t.Error("forced exit reported success; an incomplete shutdown must not read as a clean stop")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second signal did not force an exit — the escalation path is not armed")
	}
}

// TestChaos56_EscalationStopsWhenShutdownCompletes pins the other half: a
// signal that arrives AFTER the sequence finished must not kill a process
// that is already exiting cleanly, and the watcher must not outlive it.
func TestChaos56_EscalationStopsWhenShutdownCompletes(t *testing.T) {
	quit := make(chan os.Signal, 1)
	exited := make(chan int, 1)
	stop := armShutdownEscalation(quit, func(code int) { exited <- code })
	stop()

	// Give the watcher a moment to observe the stop, then signal.
	time.Sleep(100 * time.Millisecond)
	quit <- syscall.SIGTERM
	select {
	case code := <-exited:
		t.Errorf("disarmed escalation still exited with %d", code)
	case <-time.After(300 * time.Millisecond):
	}
}

// startBlockedRPCServer stands up a real gRPC server whose single method
// never returns, invokes it from a real client, and returns the server once
// the handler is confirmed running. This is the shape that makes GracefulStop
// UNBOUNDED: grpc-go's outgoingGoAwayHandler bounds the idle case with a 5s
// ping-ack timer, but when the second GOAWAY finds a live stream it leaves the
// connection open with no timer at all, and GracefulStop's
// `for len(s.conns) != 0` wait has nothing to end it.
//
// In production the blocked handler is not synthetic: Enroll/RenewCert sign
// and persist, PushAuditEvents appends to a RotatingFile, and on a wedged
// volume those block in write(2). The same stall is reachable without a
// blocked handler at all, via a peer that stops reading a large GetConfig
// response (TCP zero-window persist retries indefinitely).
func startBlockedRPCServer(t *testing.T, release <-chan struct{}) *grpc.Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	entered := make(chan struct{})
	var once sync.Once
	// Registered through the same wrapUnary + rawCodec machinery as the real
	// ConfigService (registerConfigService), so the wedged stream is carried by
	// production's own codec and dispatch path rather than a synthetic one.
	srv.RegisterService(&grpc.ServiceDesc{
		ServiceName: "culvert.test.Wedged",
		HandlerType: (*controlPlaneServer)(nil),
		Methods: []grpc.MethodDesc{{
			MethodName: "Block",
			Handler: wrapUnary(func(context.Context, json.RawMessage) (json.RawMessage, error) {
				once.Do(func() { close(entered) })
				<-release
				return nil, status.Error(codes.Unavailable, "released")
			}),
		}},
	}, nil)
	go func() { _ = srv.Serve(ln) }()

	cc, err := grpc.NewClient(ln.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodecV2(rawCodec{})))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	go func() {
		var out json.RawMessage
		_ = cc.Invoke(context.Background(), "/culvert.test.Wedged/Block", json.RawMessage(`{}`), &out)
	}()

	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("handler never started; the wedged-stream shape was not reproduced")
	}
	return srv
}

// TestChaos56_GracefulStopIsBoundedAgainstAWedgedStream is the SD-1 gate at
// the call site: with an in-flight RPC that never completes, GracefulStop has
// no bound of its own, so the bounded wrapper must supply one and must leave
// the server actually stopped.
func TestChaos56_GracefulStopIsBoundedAgainstAWedgedStream(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	srv := startBlockedRPCServer(t, release)

	const budget = 750 * time.Millisecond
	done := make(chan bool, 1)
	start := time.Now()
	go func() { done <- gracefulStopBounded(srv, budget) }()

	select {
	case graceful := <-done:
		if graceful {
			t.Error("reported a graceful drain while a stream was still wedged")
		}
		if elapsed := time.Since(start); elapsed > budget+5*time.Second {
			t.Errorf("bounded stop took %v; budget is %v", elapsed, budget)
		}
	case <-time.After(budget + 20*time.Second):
		t.Fatal("gracefulStopBounded never returned — a wedged stream still holds the shutdown open")
	}
}

// TestChaos56_BareGracefulStopIsUnboundedOnAWedgedStream is the DEFECT proof
// for the gate above: the same server, stopped the way the pre-CHAOS-56 code
// stopped it, does not return. It asserts the stall rather than waiting one
// out — a gate that waited for "unbounded" could only ever time out the suite.
func TestChaos56_BareGracefulStopIsUnboundedOnAWedgedStream(t *testing.T) {
	release := make(chan struct{})
	srv := startBlockedRPCServer(t, release)

	done := make(chan struct{})
	go func() { defer close(done); srv.GracefulStop() }()

	// Well past grpc-go's 5s idle GOAWAY ping-ack timer, which is the only
	// bound the drain path has.
	select {
	case <-done:
		t.Error("bare GracefulStop returned with a wedged stream — the SD-1 defect is no longer reproducible here, so the bounded wrapper's gate proves less than it claims")
	case <-time.After(8 * time.Second):
	}

	close(release) // let the handler finish so the goroutine and server exit
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		srv.Stop()
	}
}

// TestChaos56_GracefulStopReturnsPromptlyWhenIdle is the control: bounding
// the drain must not make an ordinary shutdown pay the budget.
func TestChaos56_GracefulStopReturnsPromptlyWhenIdle(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	go func() { _ = srv.Serve(ln) }()

	start := time.Now()
	if !gracefulStopBounded(srv, 10*time.Second) {
		t.Error("idle server did not drain gracefully")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("idle graceful stop took %v; must be near-instant", elapsed)
	}
}

// TestChaos56_DurableCloserssAreInTheFlushPartition is the structural gate on
// the reserve. The split is only meaningful if the hooks whose loss costs
// durability actually land above the boundary; a future PR that registers a
// new closer below it silently puts the next boot's cleanliness back inside a
// budget a stuck drain can spend.
func TestChaos56_DurableClosersAreInTheFlushPartition(t *testing.T) {
	var late shutdownRegistry
	registerLateShutdownHooks(&late, &startupState{}, nil)
	drain, flush := late.partitionAt(shutdownFlushBoundary)

	mustFlush := []string{"syslog-close", "community-db-close", "log-store-close",
		"request-log-close", "audit-log-close", "log-closer"}
	inFlush := map[string]bool{}
	for _, h := range flush.hooksSnapshot() {
		inFlush[h.name] = true
	}
	for _, name := range mustFlush {
		if !inFlush[name] {
			t.Errorf("hook %q must be above shutdownFlushBoundary (%d): losing it costs durability or leaves a store the next boot has to quarantine",
				name, shutdownFlushBoundary)
		}
	}
	// And the reserve must not swallow the drains — a flush phase that owns
	// the tunnel drain would spend the durability budget on in-flight traffic.
	for _, h := range drain.hooksSnapshot() {
		if inFlush[h.name] {
			t.Errorf("hook %q landed in both partitions", h.name)
		}
	}
	if len(drain.hooksSnapshot())+len(flush.hooksSnapshot()) != len(late.hooksSnapshot()) {
		t.Error("partitionAt lost or duplicated a hook")
	}
}

// TestChaos56_EnvelopeFitsTheContainerStopGrace is the cross-artifact gate.
// The shutdown envelope is only a bound if it is smaller than the grace the
// orchestrator gives the process; past that it is SIGKILL, which skips every
// remaining hook. docker-compose.yml is the shipped deployment, so its
// stop_grace_period is the number the envelope has to fit inside — and it is
// set in a different file from the constants, which is exactly how the two
// drift apart.
func TestChaos56_EnvelopeFitsTheContainerStopGrace(t *testing.T) {
	raw, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}
	m := regexp.MustCompile(`(?m)^\s*stop_grace_period:\s*([0-9]+)s\s*$`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("docker-compose.yml has no stop_grace_period; the shutdown envelope has nothing to fit inside")
	}
	grace, err := time.ParseDuration(string(m[1]) + "s")
	if err != nil {
		t.Fatalf("parse stop_grace_period: %v", err)
	}

	// Worst case: the whole envelope, plus one watchdog grace for each of the
	// two late phases (the early phase's grace is inside Total).
	worst := defaultShutdownBudget.Total + 2*shutdownHookGrace
	if worst >= grace {
		t.Errorf("worst-case shutdown %v does not fit inside stop_grace_period %v — the container will SIGKILL mid-sequence, skipping the durable flushes",
			worst, grace)
	}
	if defaultShutdownBudget.Early+defaultShutdownBudget.Flush >= defaultShutdownBudget.Total {
		t.Errorf("Early (%v) + Flush (%v) leaves no drain budget inside Total (%v)",
			defaultShutdownBudget.Early, defaultShutdownBudget.Flush, defaultShutdownBudget.Total)
	}
}
