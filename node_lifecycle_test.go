package main

// node_lifecycle_test.go — the start-up lifecycle, its wire statuses, and the
// control plane's early listener.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// nlSetPhase puts the lifecycle in phase p for the test and restores it.
func nlSetPhase(t *testing.T, p nodePhase) {
	t.Helper()
	prev := nodeLifecyclePhase.Load()
	nodeLifecyclePhase.Store(int32(p))
	t.Cleanup(func() { nodeLifecyclePhase.Store(prev) })
}

// nlCall is one RPC over a real gRPC connection to addr.
func nlCall(t *testing.T, addr, method string) (json.RawMessage, error) {
	t.Helper()
	c, err := NewDataPlaneClient("nl-probe", addr, "", "", "")
	if err != nil {
		t.Fatalf("probe client: %v", err)
	}
	defer func() {
		c.mu.Lock()
		_ = c.conn.Close() //nolint:errcheck // test teardown
		c.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return c.call(ctx, "/"+configServiceName+"/"+method, json.RawMessage(`{}`))
}

// ── the lifecycle itself ────────────────────────────────────────────────────

func TestNodeLifecycle_AccessorsPerPhase(t *testing.T) {
	nlSetPhase(t, nodePhaseUnmanaged)
	for _, tc := range []struct {
		phase                 nodePhase
		name                  string
		ready, publishReached bool
	}{
		{nodePhaseUnmanaged, "unmanaged", true, true},
		{nodePhaseIdentity, "identity", false, false},
		{nodePhaseLoadingStores, "loading-stores", false, false},
		{nodePhaseActivating, "activating", false, true},
		{nodePhaseReady, "ready", true, true},
	} {
		nodeLifecyclePhase.Store(int32(tc.phase))
		if got := currentNodePhase().String(); got != tc.name {
			t.Errorf("phase %d named %q, want %q", tc.phase, got, tc.name)
		}
		if !nodeLive() {
			t.Errorf("%s: a running process must be live", tc.name)
		}
		if nodeReady() != tc.ready || nodePublishPhaseReached() != tc.publishReached {
			t.Errorf("%s: ready=%v publishReached=%v, want %v/%v", tc.name, nodeReady(), nodePublishPhaseReached(), tc.ready, tc.publishReached)
		}
		st := currentNodeLifecycleStatus()
		if st.Phase != tc.name || st.Ready != tc.ready || !st.Live {
			t.Errorf("%s: reported status %+v", tc.name, st)
		}
	}
	// Forward only.
	nodeLifecyclePhase.Store(int32(nodePhaseActivating))
	enterStartupIdentityPhase()
	enterStartupStoresPhase()
	if got := currentNodePhase(); got != nodePhaseActivating {
		t.Errorf("the lifecycle went backwards to %s", got)
	}
}

func TestNodeLifecycle_WireStatusesAreDistinct(t *testing.T) {
	nlSetPhase(t, nodePhaseLoadingStores)
	starting := cpStartingStatus("HASync")
	refused := cpPublishNotAuthorizedStatus("GetConfig", "the publication safety gate is closed")
	if status.Code(starting) != codes.Unavailable || status.Code(refused) != codes.Unavailable {
		t.Fatalf("both statuses must be Unavailable (what every released peer already retries on): %v / %v", starting, refused)
	}
	if !isCPStartingStatus(starting) || isCPPublishNotAuthorizedStatus(starting) {
		t.Errorf("starting status misclassified: %v", starting)
	}
	if !isCPPublishNotAuthorizedStatus(refused) || isCPStartingStatus(refused) {
		t.Errorf("publish-not-authorized status misclassified: %v", refused)
	}
	phase, elapsed, ok := cpStartingStatusFields(starting)
	if !ok || phase != "loading-stores" || elapsed < 0 {
		t.Errorf("starting status fields = (%q, %d, %v) from %q, want the phase and the seconds since process start", phase, elapsed, ok, status.Convert(starting).Message())
	}
	for name, other := range map[string]error{
		"nil":                       nil,
		"a transport failure":       status.Error(codes.Unavailable, "connection refused"),
		"the non-leader refusal":    status.Errorf(codes.Unavailable, "HASync refused: this node is not the HA leader"),
		"no valid config":           status.Errorf(codes.Unavailable, "control plane has no valid config to distribute: x"),
		"the token with other code": status.Error(codes.Internal, cpStartingStatusMarker+": x"),
		"the token mid-message":     status.Error(codes.Unavailable, "x "+cpStartingStatusMarker+": y"),
		"a plain error":             errors.New(cpStartingStatusMarker + ": x"),
	} {
		if isCPStartingStatus(other) || isCPPublishNotAuthorizedStatus(other) {
			t.Errorf("%s was classified as a lifecycle status", name)
		}
	}
}

// ── the early listener ──────────────────────────────────────────────────────

// TestCPStartingListener_EveryMethodAnswersStartingAndNothingElse: over a real
// connection, EVERY ConfigService method the real server registers is answered
// CULVERT_NODE_STARTING with the phase and elapsed time; and the file that
// builds the listener reaches no store, publish, enrolment or leadership code.
func TestCPStartingListener_EveryMethodAnswersStartingAndNothingElse(t *testing.T) {
	cpInsecure(t)
	nlSetPhase(t, nodePhaseLoadingStores)
	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	l := startCPStartingListener(cpListenerConfig{addr: addr})
	if l == nil {
		t.Fatal("the early listener did not bind")
	}
	t.Cleanup(l.stopEarlyListener)

	methods := cpStartingMethods()
	if len(methods) != len(cpRPCPolicies) || len(methods) < 9 {
		t.Fatalf("the early listener registers %d methods, the policy table has %d", len(methods), len(cpRPCPolicies))
	}
	for _, m := range methods {
		raw, err := nlCall(t, addr, m)
		if !isCPStartingStatus(err) || len(raw) != 0 {
			t.Errorf("%s on the early listener answered (%q, %v), want only %s", m, raw, err, cpStartingStatusMarker)
			continue
		}
		if phase, _, ok := cpStartingStatusFields(err); !ok || phase != "loading-stores" {
			t.Errorf("%s: starting answer carries phase %q", m, phase)
		}
	}
	// A method the service does not have is NOT answered "starting".
	if _, err := nlCall(t, addr, "NoSuchMethod"); isCPStartingStatus(err) || status.Code(err) != codes.Unimplemented {
		t.Errorf("an unknown method answered %v, want Unimplemented", err)
	}

	// By construction: what the early listener's code may call.
	allowed := map[string]bool{
		"cpStartingMethods": true, "registerStartingConfigService": true, "cpStartingHandler": true,
		"cpStartingStatus": true, "cpServerOptionMode": true, "newControlPlaneGRPCServer": true,
		"nodeStartupElapsed": true, "sanitizeLog": true,
		// stdlib / grpc / logging
		"make": true, "len": true, "append": true, "close": true, "dec": true, "Strings": true, "Listen": true, "Background": true,
		"RegisterService": true, "Serve": true, "Stop": true, "Printf": true, "Error": true, "Round": true,
	}
	file := parseMainPkgFileForTest(t, "cp_starting_listener.go")
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		for callee := range calleeNames(fn) {
			if !allowed[callee] {
				t.Errorf("cp_starting_listener.go %s calls %s: the early listener must have no path to a store, a publish, enrolment or leadership", fn.Name.Name, callee)
			}
		}
	}

	l.stopEarlyListener()
	l.stopEarlyListener() // idempotent
	if _, err := nlCall(t, addr, "GetConfig"); isCPStartingStatus(err) || err == nil {
		t.Errorf("the early listener still answers after stop: %v", err)
	}
	var none *cpStartingListener
	none.stopEarlyListener() // nil-safe
}

// TestCPStartingListener_UnbindableAddressIsNotFatal: a taken port (or TLS
// material that does not load) yields no early listener and no failure — the
// activation owns the real bind and its reporting.
func TestCPStartingListener_UnbindableAddressIsNotFatal(t *testing.T) {
	cpInsecure(t)
	port, release := occupyPort(t)
	defer release()
	if l := startCPStartingListener(cpListenerConfig{addr: fmt.Sprintf("127.0.0.1:%d", port)}); l != nil {
		l.stopEarlyListener()
		t.Error("an early listener was returned for a port that is taken")
	}
	prev := clusterInsecure
	clusterInsecure = false
	defer func() { clusterInsecure = prev }()
	if l := startCPStartingListener(cpListenerConfig{addr: fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))}); l != nil {
		l.stopEarlyListener()
		t.Error("an early listener was started with no TLS material and no insecure opt-in")
	}
}

// ── the real server behind the lifecycle gate ───────────────────────────────

// TestNodeLifecycle_RealServerServesNothingUntilReady: the REAL ConfigService
// (registerConfigService, over a real connection). Until start-up has
// completed every method answers CULVERT_NODE_STARTING — bound or not,
// published or not. Once it has, the server serves; with publication not authorized the three
// snapshot methods answer CULVERT_PUBLISH_NOT_AUTHORIZED and nothing else
// changes.
func TestNodeLifecycle_RealServerServesNothingUntilReady(t *testing.T) {
	env := suIsolate(t)
	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	act := loadClusterIdentity(clusterStartupConfig{ClusterDBPath: env.clusterDB, CPAddr: addr}, t.Context(), nil)
	env.loadStores(t, "allow")
	nlSetPhase(t, nodePhaseActivating)
	act.activate()
	cpWaitFor(t, 15*time.Second, "the control-plane listener", func() bool { return cpGRPCListenerState().Serving })
	if globalConfigStore.Version() == 0 {
		t.Fatal("control: the activation did not publish")
	}

	// Bound, published, role claimed — and still not ready.
	for _, m := range cpStartingMethods() {
		if raw, err := nlCall(t, addr, m); !isCPStartingStatus(err) || len(raw) != 0 {
			t.Errorf("%s answered (%q, %v) while the node was activating, want %s", m, raw, err, cpStartingStatusMarker)
		}
	}

	markNodeReady()
	snap, err := suPoll(t, addr)
	if err != nil {
		t.Fatalf("GetConfig once ready: %v", err)
	}
	suWantLoadedConfig(t, "once ready", snap)

	prev := nodePublishAuthorized
	nodePublishAuthorized = func() (bool, string) { return false, "the publication safety gate is closed" }
	t.Cleanup(func() { nodePublishAuthorized = prev })
	for m := range cpSnapshotServingMethods {
		if _, err := nlCall(t, addr, m); !isCPPublishNotAuthorizedStatus(err) {
			t.Errorf("%s with publication not authorized answered %v, want %s", m, err, cpPublishRefusedMarker)
		}
	}
	if _, err := nlCall(t, addr, "PushMetrics"); isCPPublishNotAuthorizedStatus(err) || isCPStartingStatus(err) {
		t.Errorf("a method that serves no snapshot was refused for publication authority: %v", err)
	}
}

// nlAnswer is one poll result of nlPollUntilStopped.
type nlAnswer struct {
	ready   bool // observed after readyFlag was closed
	snap    *ConfigSnapshot
	err     error
	started bool // a CULVERT_NODE_STARTING answer
}

// nlPollUntilStopped polls GetConfig on ONE long-lived connection, as a data
// plane does, until stop is closed.
func nlPollUntilStopped(addr string, readyFlag, stop <-chan struct{}, done chan<- struct{}, answers chan<- nlAnswer) {
	defer close(done)
	c, err := NewDataPlaneClient("handover-poller", addr, "", "", "")
	if err != nil {
		return
	}
	defer func() { c.mu.Lock(); _ = c.conn.Close(); c.mu.Unlock() }() //nolint:errcheck // test teardown
	for {
		select {
		case <-stop:
			return
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		raw, err := c.call(ctx, methodGetConfig, json.RawMessage(`{}`))
		cancel()
		a := nlAnswer{err: err, started: isCPStartingStatus(err)}
		select {
		case <-readyFlag:
			a.ready = true
		default:
		}
		if err == nil {
			var s ConfigSnapshot
			if json.Unmarshal(raw, &s) == nil {
				a.snap = &s
			}
		}
		answers <- a
		time.Sleep(5 * time.Millisecond)
	}
}

// TestNodeLifecycle_HandOver_PollerNeverSeesConfigBeforeReady: a poller running
// across the whole start-up of a control plane — early listener, hand-over,
// real bind, ready. Every answer before ready is CULVERT_NODE_STARTING or a
// connection error at the hand-over; the first configuration it is ever served
// is the loaded one.
func TestNodeLifecycle_HandOver_PollerNeverSeesConfigBeforeReady(t *testing.T) {
	env := suIsolate(t)
	nlSetPhase(t, nodePhaseIdentity)
	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	act := loadClusterIdentity(clusterStartupConfig{ClusterDBPath: env.clusterDB, CPAddr: addr}, t.Context(), nil)

	readyFlag := make(chan struct{})
	answers := make(chan nlAnswer, 1<<16)
	stop := make(chan struct{})
	done := make(chan struct{})
	go nlPollUntilStopped(addr, readyFlag, stop, done, answers)

	time.Sleep(50 * time.Millisecond) // the poller meets the early listener
	enterStartupStoresPhase()
	env.loadStores(t, "allow")
	enterStartupActivationPhase()
	act.activate()
	cpWaitFor(t, 15*time.Second, "the control-plane listener", func() bool { return cpGRPCListenerState().Serving })
	time.Sleep(50 * time.Millisecond) // the poller meets the real server while it is still not ready
	markNodeReady()
	close(readyFlag)

	// The poller's connection met a closed port at the hand-over, so gRPC is
	// in its reconnect backoff (about a second): it keeps reporting that one
	// connection error until it redials. Drain until the first served answer.
	var starting, startingAfterReady, connErrs, served int
	deadline := time.After(20 * time.Second)
	for served < 3 {
		var a nlAnswer
		select {
		case a = <-answers:
		case <-deadline:
			t.Fatalf("the poller was never served after the node was ready (%d starting, %d connection errors)", starting, connErrs)
		}
		switch {
		case a.snap != nil:
			served++
			if !a.ready {
				t.Fatalf("a poller was served a configuration (v%d) BEFORE the node was ready", a.snap.Version)
			}
			if got := suRuleNames(a.snap.PolicyRules); got != "on-disk-a,on-disk-b" || len(a.snap.BlockedHosts) != 1 {
				t.Fatalf("a poller was served rules=[%s] hosts=%d — not the loaded configuration", got, len(a.snap.BlockedHosts))
			}
		case a.started:
			starting++
			if a.ready {
				startingAfterReady++
			}
		default:
			connErrs++
		}
	}
	close(stop)
	<-done
	t.Logf("poller: %d starting answers, %d connection errors (the hand-over, repeated by the client's reconnect backoff), then served the loaded configuration",
		starting, connErrs)
	if starting == 0 {
		t.Fatal("the poller never saw a starting answer")
	}
	if startingAfterReady > 1 {
		t.Errorf("%d starting answers after the node was ready", startingAfterReady)
	}
}

// ── publishing is gated on the lifecycle and, separately, on leadership ─────

func TestNodeLifecycle_PublishIsRefusedBeforeStoresLoadAndWithoutLeadership(t *testing.T) {
	suIsolate(t)
	nlSetPhase(t, nodePhaseUnmanaged)
	for _, p := range []nodePhase{nodePhaseIdentity, nodePhaseLoadingStores} {
		nodeLifecyclePhase.Store(int32(p))
		if err := publishCurrentConfigSnapshot(); !errors.Is(err, errPublishBeforeStoresLoaded) {
			t.Errorf("phase %s: publish returned %v, want errPublishBeforeStoresLoaded", p, err)
		}
	}
	nodeLifecyclePhase.Store(int32(nodePhaseActivating))
	if v := globalConfigStore.Version(); v != 0 {
		t.Fatalf("a refused publish committed version %d", v)
	}
	if msg, _ := globalConfigStore.LastPublishError(); msg != "" {
		t.Errorf("a premature publish latched a fleet-facing rejection (%q); it is a start-up ordering refusal, not a rejected configuration", msg)
	}

	prev := nodeLeadershipHeld
	nodeLeadershipHeld = func() bool { return false }
	t.Cleanup(func() { nodeLeadershipHeld = prev })
	if err := publishCurrentConfigSnapshot(); !errors.Is(err, errPublishWithoutLeadership) {
		t.Errorf("publish without leadership returned %v, want errPublishWithoutLeadership", err)
	}
	if globalConfigStore.Version() != 0 {
		t.Error("a publish without leadership committed")
	}
	if msg, _ := globalConfigStore.LastPublishError(); !strings.Contains(msg, "leadership") {
		t.Errorf("a publish refused for leadership is not operator-visible: LastPublishError=%q", msg)
	}

	nodeLeadershipHeld = prev
	if err := publishCurrentConfigSnapshot(); err != nil || globalConfigStore.Version() == 0 {
		t.Errorf("with the stores loaded and leadership held the publish must commit: %v", err)
	}
}

// TestNodeLifecycle_AuthorityStubsBehaveAsBefore pins the stub contract until
// the HA authority change replaces ha_authority.go: both answers are the ones
// the code gave before the call sites existed.
func TestNodeLifecycle_AuthorityStubsBehaveAsBefore(t *testing.T) {
	if !haLeadershipHeld() {
		t.Error("stub haLeadershipHeld must be true")
	}
	if ok, reason := haPublishAuthorized(); !ok || reason != "" {
		t.Errorf("stub haPublishAuthorized = (%v, %q), want authorized", ok, reason)
	}
}

// ── lease mode: the lease stays the only leadership authority ───────────────

// TestNodeLifecycle_Lease_PeerTookTheLeaseDuringSlowStoreLoad: a restarting
// leader in lease mode. While it is starting it holds NO lease — it neither
// acquires nor renews before its activation — so when its store loading runs
// past the lease TTL the peer takes over. At activation its resume is denied
// by the fence: it comes up as a standby and never serves a snapshot, not even
// the freshly loaded one.
func TestNodeLifecycle_Lease_PeerTookTheLeaseDuringSlowStoreLoad(t *testing.T) {
	env := suIsolate(t)
	nlSetPhase(t, nodePhaseIdentity)
	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	act := loadClusterIdentity(clusterStartupConfig{ClusterDBPath: env.clusterDB, CPAddr: addr}, t.Context(), nil)
	lease := halease.NewFake(time.Minute)
	globalHA.SetLeaseProvider(lease, "cp-a")
	if err := saveHAConfig(&haConfig{Enabled: true, Role: "leader", PeerAddr: "10.0.0.9:50051", Token: "tok", Term: 2, StandbyAddr: "10.0.0.9:50051"}); err != nil {
		t.Fatal(err)
	}

	// Phase 1–2: starting. Nothing this node does touches the lease.
	enterStartupStoresPhase()
	env.loadStores(t, "allow")
	if held, _ := lease.Read(context.Background()); held.Holder != "" {
		t.Fatalf("the starting node acquired the lease (%+v) before its activation", held)
	}
	if _, err := suPoll(t, addr); !isCPStartingStatus(err) {
		t.Fatalf("starting node answered %v", err)
	}
	// The store load was slow: the peer promoted and holds the lease.
	if granted, _, err := lease.Acquire(context.Background(), "cp-b"); !granted || err != nil {
		t.Fatalf("peer acquire: %v %v", granted, err)
	}
	peer, _ := lease.Read(context.Background())

	enterStartupActivationPhase()
	act.activate()
	cpWaitFor(t, 15*time.Second, "the control-plane listener", func() bool { return cpGRPCListenerState().Serving })
	cpWaitFor(t, 15*time.Second, "the resume decision", func() bool { return globalHA.Status().Role != "" })
	markNodeReady()

	if st := globalHA.Status(); st.Role != "standby" {
		t.Fatalf("the restarted ex-leader has HA role %q, want standby (its resume must be denied by the lease)", st.Role)
	}
	if e := globalHA.CurrentEpoch(); e >= peer.Epoch && e != 0 {
		t.Errorf("the denied node holds epoch %d, the real leader %d", e, peer.Epoch)
	}
	if now, _ := lease.Read(context.Background()); now.Holder != "cp-b" || now.Epoch != peer.Epoch {
		t.Errorf("the lease moved to %+v; the peer's grant must be untouched", now)
	}
	if snap, err := suPoll(t, addr); err == nil {
		t.Fatalf("the fenced ex-leader served a snapshot (v%d, %d rules) — a stale leader must never serve", snap.Version, len(snap.PolicyRules))
	} else if isCPStartingStatus(err) || status.Code(err) != codes.Unavailable {
		t.Errorf("the fenced ex-leader answered %v, want the not-the-leader Unavailable", err)
	}
}

// TestNodeLifecycle_Lease_SimultaneousRestart_OneLeader: both nodes of a pair
// restart together. Neither holds the lease while starting. The first to
// activate acquires it and serves under its epoch; the other's acquisition is
// then denied — two leaders are not possible.
func TestNodeLifecycle_Lease_SimultaneousRestart_OneLeader(t *testing.T) {
	env := suIsolate(t)
	nlSetPhase(t, nodePhaseIdentity)
	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	act := loadClusterIdentity(clusterStartupConfig{ClusterDBPath: env.clusterDB, CPAddr: addr}, t.Context(), nil)
	lease := halease.NewFake(time.Minute)
	globalHA.SetLeaseProvider(lease, "cp-a")
	if err := saveHAConfig(&haConfig{Enabled: true, Role: "leader", PeerAddr: "10.0.0.9:50051", Token: "tok", Term: 2}); err != nil {
		t.Fatal(err)
	}
	enterStartupStoresPhase()
	env.loadStores(t, "allow")
	enterStartupActivationPhase()
	act.activate() // this node activates first
	cpWaitFor(t, 15*time.Second, "the lease-mode leadership resume", func() bool { return globalHA.Status().Role == "leader" && globalHA.CurrentEpoch() != 0 })
	markNodeReady()

	if granted, _, _ := lease.Acquire(context.Background(), "cp-b"); granted {
		t.Fatal("the second node of a simultaneous restart was ALSO granted the lease")
	}
	snap, err := suPoll(t, addr)
	if err != nil {
		t.Fatalf("the one leader does not serve: %v", err)
	}
	if snap.Epoch != globalHA.CurrentEpoch() || snap.Epoch == 0 {
		t.Errorf("served epoch %d, held epoch %d", snap.Epoch, globalHA.CurrentEpoch())
	}
	suWantLoadedConfig(t, "the one leader", snap)
}

// ── health surfaces ─────────────────────────────────────────────────────────

// TestNodeLifecycle_HealthSurfacesReportThePhase: liveness is "ok" in every
// phase and names the phase; readiness FAILS (gating) until the node is ready;
// the admin health response reports readiness, leadership and publication
// authority as separate fields. An unmanaged process adds nothing.
func TestNodeLifecycle_HealthSurfacesReportThePhase(t *testing.T) {
	nlSetPhase(t, nodePhaseUnmanaged)
	if h := computeHealth(); h.Startup != "" {
		t.Errorf("an unmanaged process reports startup=%q on /health", h.Startup)
	}
	if rep, _ := computeReadiness(); rep.Checks["startup"] != nil {
		t.Error("an unmanaged process has a startup readiness row")
	}
	baseline, baseCode := computeReadiness()

	for _, p := range []nodePhase{nodePhaseIdentity, nodePhaseLoadingStores, nodePhaseActivating} {
		nodeLifecyclePhase.Store(int32(p))
		if h := computeHealth(); h.Status != "ok" || h.Startup != p.String() {
			t.Errorf("%s: /health = status %q startup %q, want ok and the phase (liveness holds from phase 1)", p, h.Status, h.Startup)
		}
		rep, code := computeReadiness()
		row := rep.Checks["startup"]
		if row == nil || row.Status != "fail" || !strings.Contains(row.Detail, p.String()) || code != 503 || rep.Status == baseline.Status && baseCode == 200 {
			t.Errorf("%s: /ready = %d %q startup row %+v, want 503 with a failing startup row naming the phase", p, code, rep.Status, row)
		}
		resp := map[string]any{}
		addLifecycleHealth(resp)
		if resp["startup_phase"] != p.String() || resp["ready"] != false || resp["leadership_held"] != true || resp["publish_authorized"] != true {
			t.Errorf("%s: admin lifecycle fields = %v", p, resp)
		}
	}

	nodeLifecyclePhase.Store(int32(nodePhaseReady))
	rep, code := computeReadiness()
	if row := rep.Checks["startup"]; row == nil || row.Status != "ok" || code != baseCode {
		t.Errorf("ready: startup row %+v, code %d (baseline %d)", rep.Checks["startup"], code, baseCode)
	}
	prevLead, prevPub := nodeLeadershipHeld, nodePublishAuthorized
	nodeLeadershipHeld = func() bool { return false }
	nodePublishAuthorized = func() (bool, string) { return false, "gate closed" }
	t.Cleanup(func() { nodeLeadershipHeld, nodePublishAuthorized = prevLead, prevPub })
	resp := map[string]any{}
	addLifecycleHealth(resp)
	if resp["ready"] != true || resp["leadership_held"] != false || resp["publish_authorized"] != false {
		t.Errorf("ready, no leadership, publication refused: %v — the three must be reported independently", resp)
	}
}

// TestCPStartingListener_TeardownExceptionIsPinnedToTheMethod: the CHAOS-71
// teardown wall exempts (*cpStartingListener).stopEarlyListener and nothing
// else — a plain function, or a method on another type, that borrows the name
// and stops a *grpc.Server is still a violation.
func TestCPStartingListener_TeardownExceptionIsPinnedToTheMethod(t *testing.T) {
	parse := func(src string) []*ast.File {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", "package main\nimport \"google.golang.org/grpc\"\n"+src, 0)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return []*ast.File{f}
	}
	for name, src := range map[string]string{
		"a plain function":         "func stopEarlyListener(srv *grpc.Server) { srv.Stop() }",
		"a method on another type": "type other struct{ srv *grpc.Server }\nfunc (o *other) stopEarlyListener() { o.srv.Stop() }",
	} {
		found := false
		for _, v := range cpGRPCTeardownViolations(parse(src)) {
			if strings.Contains(v, "references Stop on a *grpc.Server") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s named stopEarlyListener was exempted from the teardown wall", name)
		}
	}
	actual := "type cpStartingListener struct{ srv *grpc.Server }\nfunc (l *cpStartingListener) stopEarlyListener() { l.srv.Stop() }"
	for _, v := range cpGRPCTeardownViolations(parse(actual)) {
		if strings.Contains(v, "references Stop on a *grpc.Server") {
			t.Errorf("the real method is not exempt: %s", v)
		}
	}
}
