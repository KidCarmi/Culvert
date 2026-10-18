package main

// cp_deactivate_drain_chaos_test.go — CHAOS-71, Codex P1 4303232156 on #1645:
// a failed promote's undo must finish its release even when it outlives the
// wait.
//
// The undo (deactivateControlPlane) waited 5 s for the supervisor to stop,
// but Stop's graceful drain is cpGRPCGracefulStopBudget (8 s). With a Data
// Plane RPC in flight the wait expired first; the undo had already cleared
// cpSupervisor and returned without releaseActivation. Once the old
// supervisor exited nothing restored the Control Plane role or released
// address-list ownership, so every later promote failed "already running as
// control-plane". The release now runs from the supervisor's exit, the handle
// is kept until it completes, and an activation that arrives meanwhile waits
// or is told to retry (errCPDeactivating).
//
// The gates hold a real RPC in flight on a real listener and shorten the
// drain through the cpGRPCStopBudget seam, so they run in well under a
// second while keeping the production ordering: caller wait < drain.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/KidCarmi/Culvert/internal/halease"
)

// cpShortDrain sets the gRPC drain budget for one test. Call it BEFORE
// cpChaosSetup: t.Cleanup is LIFO, so the supervisor and any deactivation
// that cpChaosSetup's cleanup joins are gone before the budget is restored.
func cpShortDrain(t *testing.T, d time.Duration) {
	t.Helper()
	prev := cpGRPCStopBudget
	cpGRPCStopBudget = d
	t.Cleanup(func() { cpGRPCStopBudget = prev })
}

// cpHoldInFlightRPC opens a ConfigService call on addr that sends its
// headers but never its request message, so the server's handler stays
// blocked reading it and the stream stays active: a GracefulStop cannot
// finish until it is force-closed. The stream is confirmed active on the
// server, not just opened: a second, complete call on the same connection
// returns only after the server has read the first one's headers (HTTP/2
// frames on one connection are processed in order).
func cpHoldInFlightRPC(t *testing.T, addr string) {
	t.Helper()
	cc, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodecV2(rawCodec{})))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = cc.Close()
	})
	method := "/" + configServiceName + "/GetConfig"
	if _, err := cc.NewStream(ctx, &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, method); err != nil {
		t.Fatalf("open the held stream: %v", err)
	}
	callCtx, callCancel := context.WithTimeout(ctx, 5*time.Second)
	defer callCancel()
	var out json.RawMessage
	// Its result does not matter (an empty store may refuse it); that the
	// server answered it does.
	_ = cc.Invoke(callCtx, method, json.RawMessage(`{}`), &out)
	if callCtx.Err() != nil {
		t.Fatal("the confirming call did not return — the connection never reached the server")
	}
}

// cpIsCP reports whether the process holds the Control Plane role.
func cpIsCP() bool {
	clusterRoleMu.RLock()
	defer clusterRoleMu.RUnlock()
	return clusterRole.role == "control-plane"
}

// cpArmedSupervisor returns the supervisor handle.
func cpArmedSupervisor() *cpListenerSupervisor {
	cpActivationMu.Lock()
	defer cpActivationMu.Unlock()
	return cpSupervisor
}

// cpDeactivationInProgress reports whether an undo is still running.
func cpDeactivationInProgress() bool {
	cpActivationMu.Lock()
	defer cpActivationMu.Unlock()
	return cpDeactivation != nil
}

// cpAwaitExit waits for a supervisor's loop to exit.
func cpAwaitExit(t *testing.T, sup *cpListenerSupervisor) {
	t.Helper()
	select {
	case <-sup.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the old supervisor never exited")
	}
}

// cpAssertReleased asserts the undo left nothing behind: no Control Plane
// role, no supervisor, no address-list ownership.
func cpAssertReleased(t *testing.T, when string) {
	t.Helper()
	sup := cpArmedSupervisor()
	owned := globalConfigStore.currentCPAddrOwner().src != nil
	if cpIsCP() || sup != nil || owned {
		t.Fatalf("%s: cp role=%v supervisor=%v address owner=%v, want none — the undo never released the activation",
			when, cpIsCP(), sup != nil, owned)
	}
}

// TestChaos71_UndoOutlivingItsWaitStillReleases is the defect gate. An RPC
// holds the drain past the undo's wait: the wait returns an error, the
// handle is kept and the deactivation is visible while the drain runs, and
// once the old supervisor exits the role is restored, ownership released and
// the same activation runs again.
//
// Mutation (the pre-fix order: clear cpSupervisor, return on the wait's
// timeout, release only on a clean stop): after the old supervisor exits the
// role is still "control-plane" and the activation fails "already running".
func TestChaos71_UndoOutlivingItsWaitStillReleases(t *testing.T) {
	clusterDB := cpIsolateActivation(t)
	cpShortDrain(t, 500*time.Millisecond)
	cpChaosSetup(t)
	cpInsecure(t)
	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))

	if err := enableControlPlane(addr, "", "", "", clusterDB); err != nil || !cpIsCP() {
		t.Fatalf("precondition: activation err=%v cp=%v", err, cpIsCP())
	}
	sup := cpArmedSupervisor()
	cpHoldInFlightRPC(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := deactivateControlPlane(ctx); err == nil {
		t.Fatal("precondition: the undo's wait outlasted a drain held by an in-flight RPC — the gate no longer reproduces the race")
	}
	select {
	case <-sup.done:
		t.Fatal("precondition: the old supervisor exited inside the wait — the RPC did not hold the drain")
	default:
	}
	if !cpDeactivationInProgress() || cpArmedSupervisor() != sup {
		t.Errorf("while draining: deactivating=%v handle kept=%v, want both — an activation would read the claimed role as \"already running\"",
			cpDeactivationInProgress(), cpArmedSupervisor() == sup)
	}

	cpAwaitExit(t, sup)
	if err := awaitCPDeactivation(5 * time.Second); err != nil {
		t.Fatalf("the release did not follow the supervisor's exit: %v", err)
	}
	cpAssertReleased(t, "after the old supervisor exited")
	if err := enableControlPlane(addr, "", "", "", clusterDB); err != nil || !cpIsCP() {
		t.Fatalf("the activation after the undo: err=%v cp=%v — the node is unactivatable", err, cpIsCP())
	}
}

// TestChaos71_ActivationDuringTheUndoDrainWaitsForIt: a promote retry that
// arrives while the old supervisor is still draining waits for the release
// and then activates. It never fails "already running".
func TestChaos71_ActivationDuringTheUndoDrainWaitsForIt(t *testing.T) {
	clusterDB := cpIsolateActivation(t)
	cpShortDrain(t, 500*time.Millisecond)
	cpChaosSetup(t)
	cpInsecure(t)
	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))

	if err := enableControlPlane(addr, "", "", "", clusterDB); err != nil {
		t.Fatalf("precondition: activation: %v", err)
	}
	sup := cpArmedSupervisor()
	cpHoldInFlightRPC(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := deactivateControlPlane(ctx); err == nil {
		t.Fatal("precondition: the undo completed inside its wait — the RPC did not hold the drain")
	}

	err := enableControlPlane(addr, "", "", "", clusterDB) // the retry, mid-drain
	if err != nil {
		t.Fatalf("the activation during the drain: %v — want it to wait for the undo and activate", err)
	}
	select {
	case <-sup.done:
	default:
		t.Fatal("the retry activated while the old supervisor was still serving its drain")
	}
	if !cpIsCP() || cpArmedSupervisor() == nil || cpArmedSupervisor() == sup {
		t.Fatalf("after the retry: cp=%v new supervisor=%v, want a fresh activation", cpIsCP(),
			cpArmedSupervisor() != nil && cpArmedSupervisor() != sup)
	}
}

// TestChaos71_ActivationDuringALongUndoIsRetryable: while an undo's release
// is still running past the activation's own wait, the activation is refused
// with the retryable errCPDeactivating, never "already running", and the
// retry after the release activates. The waiter does not run the release
// itself: it returns while the release is still blocked.
func TestChaos71_ActivationDuringALongUndoIsRetryable(t *testing.T) {
	clusterDB := cpIsolateActivation(t)
	cpShortDrain(t, 100*time.Millisecond) // the activation waits 150 ms
	cpChaosSetup(t)
	cpInsecure(t)
	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))

	unblock := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(unblock) }) }
	prevWithdraw := cpWithdrawCPAddress
	cpWithdrawCPAddress = func(a string) (bool, error) {
		<-unblock
		return prevWithdraw(a)
	}
	t.Cleanup(func() {
		release()
		if err := awaitCPDeactivation(10 * time.Second); err != nil {
			t.Errorf("cleanup: %v", err)
		}
		cpWithdrawCPAddress = prevWithdraw
	})

	if err := enableControlPlane(addr, "", "", "", clusterDB); err != nil {
		t.Fatalf("precondition: activation: %v", err)
	}
	waited := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		waited <- deactivateControlPlane(ctx)
	}()
	select {
	case err := <-waited:
		if err == nil {
			t.Fatal("the undo reported done while its release was blocked")
		}
	case <-time.After(5 * time.Second):
		release()
		t.Fatal("the undo's waiter ran the release itself: it did not return on its wait")
	}

	for i := 0; i < 2; i++ {
		err := enableControlPlane(addr, "", "", "", clusterDB)
		if err == nil || !errors.Is(err, errCPDeactivating) || strings.Contains(err.Error(), "already running") {
			t.Fatalf("activation %d during the undo: %v, want the retryable errCPDeactivating", i+1, err)
		}
	}
	release()
	if err := awaitCPDeactivation(5 * time.Second); err != nil {
		t.Fatalf("the undo did not complete after its release unblocked: %v", err)
	}
	cpAssertReleased(t, "after the undo")
	if err := enableControlPlane(addr, "", "", "", clusterDB); err != nil || !cpIsCP() {
		t.Fatalf("the retry after the undo: err=%v cp=%v", err, cpIsCP())
	}
}

// TestChaos71_FailedPromoteUndoCoversAnInFlightDrain is the HA path end to
// end: a promote whose grant is lost after its real Control Plane activation,
// with a Data Plane RPC in flight, is undone by the production undo
// (undoPromoteControlPlane), whose wait covers the drain. The node is left a
// standby with no Control Plane role, supervisor or address ownership, and
// the next promote succeeds.
func TestChaos71_FailedPromoteUndoCoversAnInFlightDrain(t *testing.T) {
	tempHADir(t)
	clusterDB := cpIsolateActivation(t)
	cpShortDrain(t, 400*time.Millisecond)
	cpChaosSetup(t)
	cpInsecure(t)
	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))

	h := &HAState{}
	f := halease.NewFake(3 * time.Second)
	h.SetLeaseProvider(f, "cp-a")
	var calls int
	onPromote := func() error {
		calls++
		if err := enableControlPlane(addr, "", "", "", clusterDB); err != nil || calls > 1 {
			return err
		}
		// The first promote: a Data Plane is mid-RPC, then the grant is lost
		// before the exposure, so the promote fails and undoes the activation.
		cpHoldInFlightRPC(t, addr)
		f.ExpireForTest()
		cpAwait(t, "the keepalive to drop the lost grant", func() bool {
			h.mu.RLock()
			defer h.mu.RUnlock()
			return h.grantEpoch == 0
		})
		return nil
	}
	h.mu.Lock()
	h.role = "standby"
	h.peerAddr = "10.0.0.9:50051"
	h.stopCh = make(chan struct{})
	h.pc = promoteContext{grpcAddr: addr, onPromote: onPromote, undoPromote: undoPromoteControlPlane, set: true}
	h.mu.Unlock()
	t.Cleanup(h.Stop)

	if err := h.PromoteManually(); err == nil {
		t.Fatal("precondition: the promote succeeded although its grant was lost before the exposure")
	}
	if st := h.Status(); st.Role != "standby" || h.promoted.Load() {
		t.Fatalf("role=%q promoted=%v, want a retryable standby", st.Role, h.promoted.Load())
	}
	cpAssertReleased(t, "after the failed promote")

	if err := h.PromoteManually(); err != nil || !h.IsLeader() {
		t.Fatalf("the promote after the undo: err=%v leader=%v — the failed promote left the node unpromotable", err, h.IsLeader())
	}
	if !cpIsCP() {
		t.Error("the promote after the undo holds no Control Plane role")
	}
}

// TestChaos71_Wall_SupervisorStopWaitsCoverTheDrain: every bound on a wait
// for a supervisor stop is derived from the drain budget and covers it, and
// the release of an undone activation has one caller, the deactivation's own
// goroutine, never a waiter.
func TestChaos71_Wall_SupervisorStopWaitsCoverTheDrain(t *testing.T) {
	if cpGRPCStopBudget != cpGRPCGracefulStopBudget {
		t.Fatalf("the production drain budget seam is %s, want cpGRPCGracefulStopBudget (%s)", cpGRPCStopBudget, cpGRPCGracefulStopBudget)
	}
	if w := cpListenerStopWait(); w <= cpGRPCGracefulStopBudget {
		t.Errorf("cpListenerStopWait = %s, not above the %s drain: a wait would expire while an RPC holds it", w, cpGRPCGracefulStopBudget)
	}
	if defaultShutdownBudget.Early <= cpGRPCGracefulStopBudget {
		t.Errorf("the shutdown early phase (%s) does not cover the %s gRPC drain", defaultShutdownBudget.Early, cpGRPCGracefulStopBudget)
	}

	body := cpReadSource(t, "cp_grpc_bind.go")
	for i, rest := 0, body; ; i++ {
		j := strings.Index(rest, "context.WithTimeout(")
		if j < 0 {
			if i == 0 {
				t.Fatal("no context.WithTimeout in cp_grpc_bind.go — this wall is not reading the stop waits")
			}
			break
		}
		line := rest[j:]
		if k := strings.IndexByte(line, '\n'); k >= 0 {
			line = line[:k]
		}
		if !strings.Contains(line, "cpListenerStopWait()") {
			t.Errorf("a supervisor stop wait is not derived from the drain budget: %s", line)
		}
		rest = rest[j+1:]
	}

	// The activation's own wait for an undo in progress is a waiter on a
	// supervisor stop too: derived, and ahead of its "already running" check.
	act := cpFuncBody(t, cpReadSource(t, "main.go"), "func activateControlPlane(")
	await := strings.Index(act, "awaitCPDeactivation(cpListenerStopWait())")
	if await < 0 || await > strings.Index(act, "already running as control-plane") {
		t.Error("activateControlPlane does not wait for an undo in progress (awaitCPDeactivation(cpListenerStopWait())) before its \"already running\" check")
	}

	sites := 0
	for _, name := range []string{"cp_grpc_bind.go", "cp_grpc_activation.go", "main.go", "cluster_startup.go", "ha.go"} {
		sites += strings.Count(cpReadSource(t, name), ".releaseActivation()")
	}
	dBody := cpFuncBody(t, body, "func (s *cpListenerSupervisor) deactivate(")
	if sites != 1 || !strings.Contains(dBody, "s.releaseActivation()") {
		t.Errorf("releaseActivation has %d call site(s), want exactly one, in deactivate (after the loop's exit)", sites)
	}
	if !strings.Contains(dBody, "s.Stop(context.Background())") {
		t.Error("deactivate does not wait for the supervisor's exit without a deadline before it releases")
	}
	undo := cpFuncBody(t, body, "func deactivateControlPlane(")
	if strings.Contains(undo, "releaseActivation") || strings.Contains(undo, "cpSupervisor = nil") {
		t.Error("the waiter (deactivateControlPlane) releases or drops the handle itself — a wait that expires skips the release")
	}
}
