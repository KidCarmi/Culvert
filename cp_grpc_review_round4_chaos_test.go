package main

// cp_grpc_review_round4_chaos_test.go — CHAOS-71 gates for the fourth review
// round on #1556 (Codex 4294124284/4294124289/4294124293 and CodeRabbit review
// 5547132283 A/B/C). Each was verified failing with its guard removed.

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/KidCarmi/Culvert/internal/halease"
)

// TestChaos71_ServeEndRetiresTheOldServer — Codex P1 (4294124284). On a fatal
// Accept error grpc-go's Serve closes the listener but NOT the transports Data
// Planes already hold; only Server.Stop does. The supervisor must stop the
// retired server before rebinding, or each listener fault leaves an orphaned
// server generation that stopControlPlaneListener can never reach. Driven with
// a real established client transport across a forced Accept failure (the
// bound listener is closed underneath Serve).
func TestChaos71_ServeEndRetiresTheOldServer(t *testing.T) {
	cpChaosSetup(t)
	cpInsecure(t)

	var lnMu sync.Mutex
	var lns []net.Listener
	prevWrap := cpWrapListener
	cpWrapListener = func(ln net.Listener) net.Listener {
		lnMu.Lock()
		lns = append(lns, ln)
		lnMu.Unlock()
		return ln
	}
	t.Cleanup(func() { cpWrapListener = prevWrap })

	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	if _, err := cpStartSupervised(t, cpListenerConfig{addr: addr}, true, nil); err != nil {
		t.Fatalf("boot path: %v", err)
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	conn.Connect()
	readyCtx, cancelReady := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancelReady()
	for st := conn.GetState(); st != connectivity.Ready; st = conn.GetState() {
		if !conn.WaitForStateChange(readyCtx, st) {
			t.Fatalf("the client never established a transport (state %s)", st)
		}
	}

	// Force the Accept failure.
	lnMu.Lock()
	first := lns[0]
	lnMu.Unlock()
	_ = first.Close()

	// Stopping the retired server closes the established transport, so the
	// client must leave READY. Without the Stop the old transport stays open
	// against an orphaned server and the client stays READY.
	closedCtx, cancelClosed := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancelClosed()
	if !conn.WaitForStateChange(closedCtx, connectivity.Ready) {
		t.Fatal("the established transport to the retired server stayed open — an orphaned server generation " +
			"that stopControlPlaneListener can no longer reach")
	}
}

// TestChaos71_ServeEndSharesTheClampAndTheAlertLatch — Codex P2 (4294124289).
// The serve-end path must go through the SAME failure-and-wait path as a failed
// bind: its jittered sleep clamped at the unavailability threshold (at the
// ceiling it could reach 36 s and carry a dark listener past it unobserved),
// and the alert latch evaluated. Deterministic: frozen/injected health clock
// and an injected sleeper that records the wait instead of sleeping.
func TestChaos71_ServeEndSharesTheClampAndTheAlertLatch(t *testing.T) {
	alerts := cpChaosSetup(t)
	base := cpGRPCHealthNow()
	var waits []time.Duration
	prevSleep := cpGRPCSleep
	cpGRPCSleep = func(_ <-chan struct{}, d time.Duration) bool {
		waits = append(waits, d)
		return true
	}
	t.Cleanup(func() { cpGRPCSleep = prevSleep })

	s := &cpListenerSupervisor{cfg: cpListenerConfig{addr: "127.0.0.1:50051"},
		stopping: make(chan struct{}), firstAttempt: make(chan struct{})}
	noteCPGRPCConfigured(s.cfg.addr)
	acceptErr := errors.New("accept tcp: use of closed network connection")

	// A 40 s backoff jitters to 32–48 s: every value exceeds the threshold, so
	// the clamp must engage whatever the jitter draws.
	if !s.handleServeEnded(acceptErr, 40*time.Second) {
		t.Fatal("handleServeEnded reported a stop")
	}
	if len(waits) != 1 || waits[0] > cpGRPCUnavailableAfter {
		t.Fatalf("serve-end sleep = %v, want one sleep clamped to at most %s", waits, cpGRPCUnavailableAfter)
	}

	// The episode the serve-end opened is older than the threshold at the next
	// serve-end: that path must page.
	cpSwapHealthClock(t, func() time.Time { return base.Add(cpGRPCUnavailableAfter + time.Second) })
	if !s.handleServeEnded(acceptErr, time.Second) {
		t.Fatal("handleServeEnded reported a stop")
	}
	if len(alerts()) == 0 {
		t.Error("a listener dark past the threshold through serve-ends raised no cp_grpc_listener_down alert — the " +
			"serve-end path does not evaluate the alert latch")
	}
}

// TestChaos71_FullPublishCannotOverwriteTheOwnedCPAddressList — CodeRabbit (A).
// A full publish (a PAC update, say) builds its snapshot BEFORE taking the
// store lock, so it can capture the CP address list before a delayed bind and
// commit after the activation published the new one. Once a source owns the
// list, a full publish keeps the committed list, and a legitimate change rides
// the reconcile that follows it. The interleaving is driven step by step.
func TestChaos71_FullPublishCannotOverwriteTheOwnedCPAddressList(t *testing.T) {
	s := &ConfigStore{}
	var mu sync.Mutex
	cur := []string{"10.0.0.1:50051"}
	src := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), cur...)
	}
	set := func(v ...string) {
		mu.Lock()
		cur = v
		mu.Unlock()
	}
	s.setCPAddressSource(src)
	if err := s.Update(ConfigSnapshot{CPAddresses: src()}); err != nil {
		t.Fatalf("seed publish: %v", err)
	}

	// 1. A full publish captures its snapshot (old address list).
	stale := ConfigSnapshot{BlockedHosts: []string{"pac-change.example"}, CPAddresses: src()}
	// 2. The delayed bind commits the role and publishes the new list.
	set("10.0.0.1:50051", "10.0.0.2:50051")
	if _, err := s.UpdateCPAddressesFrom(src); err != nil {
		t.Fatalf("activation publish: %v", err)
	}
	// 3. The full publish commits.
	before := s.Version()
	if err := s.Update(stale); err != nil {
		t.Fatalf("stale full publish: %v", err)
	}
	// Exactly ONE commit: had the stale list been committed and then repaired
	// by the reconcile, a DP polling between the two versions would have
	// applied (and, since updateDPAddresses replaces, kept) the stale list.
	if v := s.Version(); v != before+1 {
		t.Errorf("the stale full publish took %d commits — the captured CP address list was published before being repaired", v-before)
	}
	got := s.Get()
	if !cpListNames(got.CPAddresses, "10.0.0.2:50051") {
		t.Errorf("a full publish captured before the activation overwrote the CP address list with %v — DPs lose the new Control Plane", got.CPAddresses)
	}
	if !cpListNames(got.BlockedHosts, "pac-change.example") {
		t.Error("the full publish itself was lost")
	}

	// A legitimate change still propagates through the reconcile.
	set("10.0.0.3:50051")
	if err := s.Update(ConfigSnapshot{}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if got := s.Get().CPAddresses; len(got) != 1 || got[0] != "10.0.0.3:50051" {
		t.Errorf("an address change did not propagate after a full publish: %v", got)
	}
}

// TestChaos71_HAAutoPromoteRefusedWhileTheListenerIsDark — CodeRabbit (B). A
// self-fenced ex-leader still runs its CP supervisor; auto-promoting it while
// its listener is unavailable would re-acquire the lease only for
// leaseRenewOnce to withhold it again, a promote/fence flap. The AUTO path
// refuses; the control shows it promotes once the listener serves.
func TestChaos71_HAAutoPromoteRefusedWhileTheListenerIsDark(t *testing.T) {
	tempHADir(t)
	cpChaosSetup(t)
	base := cpGRPCHealthNow()

	f := halease.NewFake(time.Minute)
	h := leaseStandby(f, "cp-exleader")
	h.mu.Lock()
	h.lastSyncOK = time.Now()
	h.mu.Unlock()
	t.Cleanup(h.Stop)

	noteCPGRPCConfigured("127.0.0.1:50051")
	noteCPGRPCBindFailure("port_in_use", time.Second, base)
	later := base.Add(cpGRPCUnavailableAfter + time.Second)
	cpSwapHealthClock(t, func() time.Time { return later })
	noteCPGRPCBindFailure("port_in_use", 2*time.Second, later)
	if !cpGRPCListenerState().Unavailable {
		t.Fatal("precondition: the listener must be unavailable")
	}

	if h.leaseAutoPromote() || h.IsLeader() {
		t.Fatal("auto-promotion proceeded while this node's CP listener is dark — the promote/fence flap")
	}
	if st, _ := f.Read(context.Background()); st.Holder != "" {
		t.Errorf("the refused auto-promotion still acquired the lease (holder %q)", st.Holder)
	}

	noteCPGRPCBound()
	if !h.leaseAutoPromote() {
		t.Error("control: auto-promotion refused although the listener is serving again")
	}
}

// TestChaos71_ClusterRoleReadersAreRaceFreeDuringDelayedClaim — Codex P2
// (4294124293). The CP claim lands asynchronously while handlers serve, so
// every production reader of the role tuple must go through the arbiter's
// locked snapshot. Run under -race: a concurrent reader hammers the real
// readers (apiClusterStatus, isManagedDataPlane, cluster_posture,
// buildCPAddressList) through a delayed-claim recovery, and the tuple it sees
// must never mix states.
func TestChaos71_ClusterRoleReadersAreRaceFreeDuringDelayedClaim(t *testing.T) {
	clusterDB := cpIsolateActivation(t)
	cpChaosSetup(t)
	cpInsecure(t)
	port, release := occupyPort(t)
	defer release()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var mixed, reads atomic.Int64
	// One goroutine PER reader, so no reader's own locked access is followed
	// in the same goroutine by another reader's — the race detector keeps one
	// shadow entry per goroutine and word, so a locked read would overwrite
	// (and hide) an unlocked one before the claim's write is checked against
	// it. The structural wall below is the deterministic guard; this is the
	// dynamic backstop plus the tuple-consistency check.
	readers := []func(){
		func() {
			if v := clusterRoleSnapshot(); v.role == "control-plane" && v.grpcAddr != addr {
				mixed.Add(1)
			}
		},
		func() { _ = isManagedDataPlane() },
		func() { _ = checkClusterPosture() },
		func() { _ = buildCPAddressList() },
		func() {
			w := httptest.NewRecorder()
			apiClusterStatus(w, httptest.NewRequest(http.MethodGet, "/api/cluster/status", http.NoBody))
		},
	}
	for _, read := range readers {
		wg.Add(1)
		go func(read func()) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				read()
				reads.Add(1)
			}
		}(read)
	}

	if err := enableControlPlaneResilient(addr, "", "", "", clusterDB, nil); err != nil {
		t.Fatalf("boot path: %v", err)
	}
	release()
	cpWaitFor(t, 15*time.Second, "the delayed claim", func() bool { return cpGRPCListenerState().Serving })
	cpWaitFor(t, 5*time.Second, "reads after the claim", func() bool { return reads.Load() > 10 })
	close(stop)
	wg.Wait()
	if mixed.Load() != 0 {
		t.Errorf("%d read(s) saw the control-plane role with a different address — a mixed tuple", mixed.Load())
	}
}

// TestChaos71_Wall_ClusterRoleIsReadOnlyThroughTheArbiter extends the write
// wall to READS: outside cluster_role_arbiter.go no production file may touch
// a clusterRole field or clusterRoleMu at all — readers use
// clusterRoleSnapshot()/isControlPlaneRole(). A direct read raced the
// asynchronous CP claim (apiClusterStatus, the token-create role gate).
func TestChaos71_Wall_ClusterRoleIsReadOnlyThroughTheArbiter(t *testing.T) {
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	inArbiter := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || (id.Name != "clusterRole" && id.Name != "clusterRoleMu") {
				return true
			}
			if name == "cluster_role_arbiter.go" {
				inArbiter++
				return true
			}
			t.Errorf("%s: %s.%s accessed outside the cluster-role arbiter — read through clusterRoleSnapshot() "+
				"(the CP claim is asynchronous, so a direct read races it and can see a mixed tuple)",
				fset.Position(sel.Pos()), id.Name, sel.Sel.Name)
			return true
		})
	}
	if inArbiter < 10 {
		t.Fatalf("the wall found only %d accesses in the arbiter — its selector has gone stale", inArbiter)
	}
}
