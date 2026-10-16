package main

// cp_grpc_ha_chaos_test.go — CHAOS-71 gates where the Control Plane gRPC
// listener supervisor meets HA: the promote path, the boot-path leadership
// resume, the fencing lease, the cluster-role lock, and the rebind backoff.
//
// The first three gates are ported from the closed CHAOS-71 sweep (#1534) and
// adapted to this supervisor's buildControlPlaneServer; the rest close the
// owner-review items on #1556 (self-fence a dark leader, reset the backoff
// after a successful serve, one leadership resume across rebinds).

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
)

// TestChaos71_EnableControlPlaneDoesNotDeadlockWithHAEnabled (ported from
// #1534): with HA enabled, enableControlPlane must bind and return rather than
// re-read the cluster role under a held write lock — main's shape held
// clusterRoleMu.Lock across CurrentConfigSnapshot → buildCPAddressList RLock, a
// certain self-deadlock on any HA node. A deadlock is not a panic, so CHAOS-25's
// promote guard had nothing to catch.
func TestChaos71_EnableControlPlaneDoesNotDeadlockWithHAEnabled(t *testing.T) {
	clusterDB := cpIsolateActivation(t)
	cpChaosSetup(t)
	cpInsecure(t)
	// Status().Enabled is (role != ""), and buildCPAddressList takes the role
	// lock ONLY on that branch.
	cpWithGlobalHARole(t, "leader", "10.0.0.9:50051")
	if !globalHA.Status().Enabled {
		t.Fatal("could not arm HA status — the gate would not reach the locking branch")
	}

	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	done := make(chan error, 1)
	go func() { done <- enableControlPlane(addr, "", "", "", clusterDB) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("enableControlPlane with HA enabled: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("DEADLOCK: enableControlPlane did not return with HA enabled — the pre-bind config snapshot " +
			"re-reads the cluster role under a held write lock")
	}

	// The lock is genuinely free afterwards: every cluster-role reader depends on it.
	if !clusterRoleMu.TryLock() {
		t.Error("clusterRoleMu is still held after enableControlPlane returned")
	} else {
		clusterRoleMu.Unlock()
	}
	clusterRoleMu.RLock()
	role := clusterRole.role
	clusterRoleMu.RUnlock()
	if role != "control-plane" {
		t.Errorf("role = %q after a successful HA-enabled activation, want control-plane", role)
	}
}

// TestChaos71_Wall_NoCurrentConfigSnapshotUnderTheRoleLock (ported from #1534,
// adapted to track RELEASE as well as acquire): no function in package main may
// call CurrentConfigSnapshot — or anything that reaches it — while it holds
// clusterRoleMu in either mode. The class is enumerated from the PRIMITIVE, not
// from the file being edited (§40 round 3's lesson).
//
// #1534's scanner flagged any such call AFTER the first Lock in a function.
// This supervisor's activateControlPlane legitimately takes the lock for its
// alreadyCP check, RELEASES it, and only then publishes, so the scan here models
// the held state in source order: a non-deferred Unlock/RUnlock releases, a
// `defer clusterRoleMu.Unlock()` keeps it held to the end of the function, and
// closures are not scanned as part of their enclosing body (they run later).
func TestChaos71_Wall_NoCurrentConfigSnapshotUnderTheRoleLock(t *testing.T) {
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	fset := token.NewFileSet()
	scannedFuncs, lockedFuncs := 0, 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			scannedFuncs++
			locks, offenders := cpScanRoleLockReentrancy(fn.Body)
			if locks > 0 {
				lockedFuncs++
			}
			for _, call := range offenders {
				t.Errorf("%s: %s calls %s() while holding clusterRoleMu — CurrentConfigSnapshot re-reads the role "+
					"through buildCPAddressList's RLock and sync.RWMutex is not reentrant, so this deadlocks the "+
					"goroutine while it holds the lock (certain on any node with HA enabled)",
					fset.Position(call.Pos()), fn.Name.Name, cpCalleeName(call))
			}
		}
	}

	// Not-vacuous checks: the wall must be reading package main, and the lock
	// selector must still match something.
	if scannedFuncs < 500 {
		t.Fatalf("the wall scanned only %d functions — it is not reading package main", scannedFuncs)
	}
	if lockedFuncs == 0 {
		t.Fatal("the wall found no function taking clusterRoleMu — its selector has gone stale")
	}
}

// cpRoleLockReentrantCalls read the cluster role BACK (directly or through
// CurrentConfigSnapshot), so a function holding clusterRoleMu must never call
// them.
var cpRoleLockReentrantCalls = map[string]bool{
	"CurrentConfigSnapshot": true,
	"buildCPAddressList":    true,
}

// cpScanRoleLockReentrancy walks body in source order, modelling whether
// clusterRoleMu is held, and returns how many acquisitions it saw plus every
// re-entrant call made while held.
func cpScanRoleLockReentrancy(body *ast.BlockStmt) (locks int, offenders []*ast.CallExpr) {
	held := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false // runs later, not as part of this body's lock region
		case *ast.DeferStmt:
			// `defer clusterRoleMu.Unlock()` releases at return: the lock stays
			// held for the rest of the body, so do not treat it as a release.
			if _, ok := cpRoleLockOp(n.Call); ok {
				return false
			}
		case *ast.CallExpr:
			if op, ok := cpRoleLockOp(n); ok {
				if op == "Lock" || op == "RLock" {
					held = true
					locks++
				} else {
					held = false
				}
				return true
			}
			if held && cpRoleLockReentrantCalls[cpCalleeName(n)] {
				offenders = append(offenders, n)
			}
		}
		return true
	})
	return locks, offenders
}

// cpRoleLockOp reports the clusterRoleMu method a call invokes, if any.
func cpRoleLockOp(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || id.Name != "clusterRoleMu" {
		return "", false
	}
	switch sel.Sel.Name {
	case "Lock", "RLock", "Unlock", "RUnlock":
		return sel.Sel.Name, true
	}
	return "", false
}

// cpCalleeName returns a plain-identifier callee's name, or "".
func cpCalleeName(call *ast.CallExpr) string {
	if id, ok := call.Fun.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// TestChaos71_ListenFailureDoesNotLeakTheGRPCServer (ported from #1534,
// adapted to buildControlPlaneServer): a failed bind must neither publish a
// grpc.Server handle nor leave the server it built behind. At the retry ceiling
// a leak per attempt is ~2880 registered servers a day.
func TestChaos71_ListenFailureDoesNotLeakTheGRPCServer(t *testing.T) {
	cpChaosSetup(t)
	// REQUIRED, and its absence made #1534's first draft VACUOUS: without it
	// cpServerOptionMode refuses for want of certificates BEFORE the server is
	// built, so the failure would hold for the wrong reason.
	cpInsecure(t)

	port, release := occupyPort(t)
	defer release()

	srv, ln, _, err := buildControlPlaneServer(cpListenerConfig{addr: fmt.Sprintf("127.0.0.1:%d", port)})
	if err == nil {
		srv.Stop()
		_ = ln.Close()
		t.Fatal("buildControlPlaneServer succeeded against an occupied port")
	}
	// Not vacuous: the failure must be the SOCKET one — the only path on which
	// a server has already been built.
	if got := classifyCPGRPCBindError(err); got != "port_in_use" {
		t.Fatalf("the gate did not reach the bind: classify = %q, want port_in_use (err: %v)", got, err)
	}
	if srv != nil || ln != nil {
		t.Error("a failed bind returned a server/listener handle alongside its error — nobody owns stopping it")
	}
	// The supervisor is the only owner of a server handle (clusterRole.grpcSrv
	// was removed); a bare build attempt must not have armed one.
	cpActivationMu.Lock()
	sup := cpSupervisor
	cpActivationMu.Unlock()
	if sup.currentServer() != nil {
		t.Error("a failed bind published a grpc.Server handle that nothing serves and nothing stops")
	}

	// The handle is the leak's fingerprint, not the leak itself, so the cleanup
	// call is ALSO pinned structurally.
	body := cpReadSource(t, "cp_grpc_bind.go")
	i := strings.Index(body, `return nil, nil, "", fmt.Errorf("gRPC listen: %w", err)`)
	if i < 0 {
		t.Fatal("the listen-failure branch is no longer recognisable — this wall is not reading it")
	}
	if window := body[max(0, i-200):i]; !strings.Contains(window, "srv.Stop()") {
		t.Error("the listen-failure branch does not stop the grpc.Server it just built — one leaked server per retry")
	}
}

// TestChaos71_HAPromoteBindFailureLeavesTheNodeStandby is the HA-transition
// gate for the PROMOTE path. onPromote is the synchronous enableControlPlane,
// so a listener that cannot bind must fail the promotion — the node stays a
// retryable STANDBY, claims no CP role and leaves no supervisor — instead of
// becoming a "leader" no Data Plane can reach. Once the port frees, the same
// standby promotes and the published CP list names it (the address-republish rider).
func TestChaos71_HAPromoteBindFailureLeavesTheNodeStandby(t *testing.T) {
	tempHADir(t)
	clusterDB := cpIsolateActivation(t)
	cpChaosSetup(t)
	cpInsecure(t)
	const peer = "10.0.0.9:50051"
	// globalHA carries the standby role so buildCPAddressList takes the role
	// lock on the promotion path (the promote-deadlock condition).
	cpWithGlobalHARole(t, "standby", peer)

	port, release := occupyPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	h := &HAState{}
	h.mu.Lock()
	h.role = "standby"
	h.term = 4
	h.peerAddr = peer
	h.stopCh = make(chan struct{})
	h.pc = promoteContext{
		grpcAddr:  addr,
		onPromote: func() error { return enableControlPlane(addr, "", "", "", clusterDB) },
		set:       true,
	}
	h.mu.Unlock()
	t.Cleanup(h.Stop)

	promote := func() error {
		t.Helper()
		got := make(chan error, 1)
		go func() { got <- h.PromoteManually() }()
		select {
		case err := <-got:
			return err
		case <-time.After(30 * time.Second):
			t.Fatal("PromoteManually did not return — the promotion path is deadlocked")
			return nil
		}
	}

	if err := promote(); err == nil {
		t.Fatal("promotion succeeded although the Control Plane listener could not bind")
	}
	if h.IsLeader() || h.Status().Role != "standby" {
		t.Fatalf("a promotion whose listener failed to bind left role %q, want standby", h.Status().Role)
	}
	if h.promoted.Load() {
		t.Error("the promote guard stayed armed after a failed bind — the standby could never be promoted again")
	}
	clusterRoleMu.RLock()
	role := clusterRole.role
	clusterRoleMu.RUnlock()
	if role == "control-plane" {
		t.Error("a failed promote-path bind claimed the CP role")
	}
	cpActivationMu.Lock()
	sup := cpSupervisor
	cpActivationMu.Unlock()
	if sup != nil {
		t.Error("a failed promote-path bind left a supervisor retrying in the background — it would later claim " +
			"the CP role on a node HA still records as standby")
	}
	// The refused activation must leave the health plane as it found it
	// (unconfigured) while keeping the lifetime counter that proves the bind
	// was really attempted.
	if snap := cpGRPCListenerState(); snap.Configured || snap.Total == 0 {
		t.Errorf("after a refused promote-path activation: configured=%v total=%d, want configured=false and "+
			"the failed attempt counted", snap.Configured, snap.Total)
	}

	// The standby is retryable: free the port and promote again.
	release()
	if err := promote(); err != nil {
		t.Fatalf("promotion after the port freed: %v", err)
	}
	if !h.IsLeader() {
		t.Fatal("the retried promotion did not make the node leader")
	}
	clusterRoleMu.RLock()
	role = clusterRole.role
	clusterRoleMu.RUnlock()
	if role != "control-plane" {
		t.Errorf("role = %q after a successful promotion, want control-plane", role)
	}
	if pub := globalConfigStore.Get().CPAddresses; !cpListNames(pub, addr) {
		t.Errorf("published CP list %v does not name the promoted node %q (address-republish rider)", pub, addr)
	}
}

// TestChaos71_HABootOnActivatedRunsOnceAcrossRebinds is the HA-transition gate
// for the BOOT path: the leadership resume (onActivated) must not run while the
// listener is unbindable, must run exactly once on the first observed bind, and
// must NOT run again when the supervisor rebinds after a serve death — a second
// ResumeAsLeader would re-assert a term on every socket fault.
func TestChaos71_HABootOnActivatedRunsOnceAcrossRebinds(t *testing.T) {
	clusterDB := cpIsolateActivation(t)
	cpChaosSetup(t)
	cpInsecure(t)

	port, release := occupyPort(t)
	defer release()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	var resumes atomic.Int32
	if err := enableControlPlaneResilient(addr, "", "", "", clusterDB, func() { resumes.Add(1) }); err != nil {
		t.Fatalf("boot path must tolerate an unbindable listener: %v", err)
	}
	if n := resumes.Load(); n != 0 {
		t.Fatalf("leadership resumed %d time(s) while the listener could not bind — a leader nobody can reach", n)
	}

	release()
	cpWaitFor(t, 15*time.Second, "the first bind after the port freed", func() bool { return cpGRPCListenerState().Serving })
	if n := resumes.Load(); n != 1 {
		t.Fatalf("leadership resumed %d time(s) on the first observed bind, want exactly 1", n)
	}

	firstBinds := cpGRPCListenerState().Binds
	cpActivationMu.Lock()
	sup := cpSupervisor
	cpActivationMu.Unlock()
	if srv := sup.currentServer(); srv != nil {
		srv.Stop() // kill the serve the way an unrecoverable socket fault does
	}
	cpWaitFor(t, 20*time.Second, "the listener to rebind after its serve ended", func() bool {
		s := cpGRPCListenerState()
		return s.Serving && s.Binds > firstBinds
	})
	if n := resumes.Load(); n != 1 {
		t.Errorf("leadership resumed %d time(s) across a rebind, want exactly 1", n)
	}
}

// cpCountingRenewProvider counts Renew calls so a gate can prove a renewal was
// WITHHELD rather than merely unsuccessful.
type cpCountingRenewProvider struct {
	halease.Provider
	renews atomic.Int64
}

func (c *cpCountingRenewProvider) Renew(ctx context.Context, holderID string, epoch int64) (bool, time.Duration, error) {
	c.renews.Add(1)
	return c.Provider.Renew(ctx, holderID, epoch)
}

// TestChaos71_HADarkLeaderStopsRenewingTheFence is the owner-review fencing
// gate: after an HA promote, a leader whose CP gRPC listener has been
// unavailable past the 30 s threshold must STOP renewing its lease so the
// fence no longer vouches for it, self-fence when its confirmed window ends,
// and let the standby acquire — and must resume renewing if the listener
// serves again first.
//
// Fully deterministic, no wall-clock sleeps: the listener plane runs on the
// frozen/injected cpGRPCHealthNow, the lease backend on halease.Fake's injected
// clock, the keepalive loop is stopped so every round is driven explicitly, and
// the confirmed window is collapsed by assignment.
func TestChaos71_HADarkLeaderStopsRenewingTheFence(t *testing.T) {
	tempHADir(t)
	cpChaosSetup(t)
	base := cpGRPCHealthNow()
	at := func(d time.Duration) {
		now := base.Add(d)
		cpSwapHealthClock(t, func() time.Time { return now })
	}

	var clockMu sync.Mutex
	leaseNow := time.Now()
	f := halease.NewFake(30 * time.Minute)
	f.SetNowForTest(func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return leaseNow
	})
	p := &cpCountingRenewProvider{Provider: f}

	h := leaseStandby(p, "cp-leader")
	if err := h.PromoteManually(); err != nil {
		t.Fatalf("PromoteManually: %v", err)
	}
	t.Cleanup(h.Stop)
	h.stopLeaseKeepalive() // drive every round explicitly

	renewed := func(step string) {
		t.Helper()
		before := p.renews.Load()
		if fenced := h.leaseRenewOnce(); fenced {
			t.Fatalf("%s: the leader self-fenced", step)
		}
		if p.renews.Load() != before+1 {
			t.Fatalf("%s: the lease was not renewed", step)
		}
	}

	// The promoted leader's listener is configured and serving: renew.
	noteCPGRPCConfigured("127.0.0.1:50051")
	noteCPGRPCBound()
	renewed("serving listener")

	// Rebinding INSIDE the threshold (an ordinary rollout): keep renewing.
	noteCPGRPCServeEnded("serve_ended", time.Second) // episode starts at base
	at(10 * time.Second)
	noteCPGRPCBindFailure("port_in_use", time.Second, base.Add(10*time.Second))
	if cpGRPCListenerState().Unavailable {
		t.Fatal("precondition: 10 s of rebinding must not be unavailable")
	}
	renewed("rebinding inside the threshold")

	// Dark PAST the threshold: withhold, without fencing while the confirmed
	// window still covers us.
	at(31 * time.Second)
	noteCPGRPCBindFailure("port_in_use", 2*time.Second, base.Add(31*time.Second))
	if !cpGRPCListenerState().Unavailable {
		t.Fatal("precondition: 31 s of failure must be unavailable")
	}
	before := p.renews.Load()
	if fenced := h.leaseRenewOnce(); fenced {
		t.Fatal("fenced while the confirmed window was still open — withholding must not shorten it")
	}
	if p.renews.Load() != before {
		t.Fatal("a leader whose CP listener has been dark past the threshold still RENEWED the fence — it vouches " +
			"for a leader no Data Plane or standby can reach, and the standby can never take over")
	}
	if !h.IsLeader() || !h.WriteAllowed() {
		t.Fatal("withholding must not drop authority before the confirmed window ends")
	}

	// Serving again before the window ends: resume renewing.
	noteCPGRPCBound()
	renewed("listener serving again")
	if h.leaseRenewWithheld.Load() {
		t.Error("the withholding latch did not clear when the listener served again")
	}

	// Dark past the threshold again, and this time the window runs out.
	at(40 * time.Second)
	noteCPGRPCServeEnded("serve_ended", time.Second) // episode starts at base+40s
	at(71 * time.Second)
	noteCPGRPCBindFailure("port_in_use", 4*time.Second, base.Add(71*time.Second))
	h.mu.Lock()
	h.leaseValidFor = haLeaseWriteMargin // the confirmed window ends now
	h.mu.Unlock()
	before = p.renews.Load()
	if fenced := h.leaseRenewOnce(); !fenced {
		t.Fatal("a dark leader whose confirmed window ended did not self-fence")
	}
	if p.renews.Load() != before {
		t.Error("the fencing round renewed the lease")
	}
	if h.IsLeader() || h.WriteAllowed() {
		t.Fatal("the self-fenced leader kept its role or write authority")
	}

	// The standby takes over — but only once the UNRENEWED backend lease has
	// lapsed, so the old leader was fenced before anyone else could write.
	standby := leaseStandby(f, "cp-standby")
	t.Cleanup(standby.Stop)
	if err := standby.PromoteManually(); err == nil {
		t.Fatal("the standby acquired a lease that had not lapsed yet")
	}
	clockMu.Lock()
	leaseNow = leaseNow.Add(31 * time.Minute) // TTL passes with no renewal
	clockMu.Unlock()
	if err := standby.PromoteManually(); err != nil {
		t.Fatalf("the standby could not take over once the dark leader stopped renewing: %v", err)
	}
}

// TestChaos71_HANonCPLeaderKeepsRenewing is the negative control: the listener
// predicate must not withhold for a node that never asked to be a Control Plane
// (legacy/lease tests, a Data Plane), or every lease-mode leader would fence.
func TestChaos71_HANonCPLeaderKeepsRenewing(t *testing.T) {
	cpChaosSetup(t)
	if reason, withhold := cpGRPCLeaseRenewWithheld(); withhold {
		t.Fatalf("an unconfigured listener withheld the lease: %s", reason)
	}
	noteCPGRPCConfigured("127.0.0.1:50051")
	noteCPGRPCListenerStopped() // clean shutdown
	if _, withhold := cpGRPCLeaseRenewWithheld(); withhold {
		t.Error("a listener stopped for shutdown withheld the lease")
	}
	// A re-armed listener whose supervisor then died is TERMINAL.
	noteCPGRPCConfigured("127.0.0.1:50051")
	noteCPGRPCSupervisorDown("bind loop panicked")
	if _, withhold := cpGRPCLeaseRenewWithheld(); !withhold {
		t.Error("a TERMINAL supervisor (nothing will ever rebind) did not withhold the lease")
	}
}

// TestChaos71_BackoffResetsOnlyAfterAStableServe pins owner-review item 6: a
// serve that stayed up resets the rebind backoff to the floor, while a socket
// that dies right after every bind keeps escalating to the ceiling.
func TestChaos71_BackoffResetsOnlyAfterAStableServe(t *testing.T) {
	if got := cpGRPCBackoffAfterServe(cpGRPCBindBackoffMax, cpGRPCServeStableAfter); got != cpGRPCBindBackoffInitial {
		t.Errorf("a serve that ran %s left the backoff at %s, want the %s floor", cpGRPCServeStableAfter, got, cpGRPCBindBackoffInitial)
	}
	if got := cpGRPCBackoffAfterServe(16*time.Second, 3*time.Second); got != 16*time.Second {
		t.Errorf("a serve that died after 3 s changed the backoff to %s, want it left at 16s", got)
	}
	if cpGRPCServeStableAfter <= cpGRPCBindBackoffMax {
		t.Errorf("cpGRPCServeStableAfter (%s) must exceed the backoff ceiling (%s), or a flapping socket earns a reset every cycle",
			cpGRPCServeStableAfter, cpGRPCBindBackoffMax)
	}

	// Wiring: the loop must apply the policy to the serve it just observed,
	// between Serve returning and the post-serve sleep.
	body := cpReadSource(t, "cp_grpc_bind.go")
	i := strings.Index(body, "serveErr := srv.Serve(ln)")
	j := strings.Index(body, "if !s.handleServeEnded(serveErr, backoff) {")
	if i < 0 || j < 0 || j < i {
		t.Fatal("the serve/rebind section of cpListenerSupervisor.run is no longer recognisable")
	}
	if !strings.Contains(body[i:j], "cpGRPCBackoffAfterServe(") {
		t.Error("cpListenerSupervisor.run does not reset the backoff after a successful serve")
	}
}

// cpRecordBootResumes swaps the boot-path resume action for a counter.
func cpRecordBootResumes(t *testing.T) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	prev := haBootResumeAsLeader
	haBootResumeAsLeader = func(*haConfig) { n.Add(1) }
	t.Cleanup(func() { haBootResumeAsLeader = prev })
	return &n
}

// TestChaos71_HABootResumeReReadsTheHAConfigAtBindTime is the CodeRabbit
// finding on #1556: the boot-path leadership resume runs on the FIRST OBSERVED
// bind, which with the retrying supervisor can be minutes after boot, so it
// must decide from the HA config as persisted at BIND time. The pre-fix closure
// captured the boot-time config and would resume — and re-persist — a leader
// the operator had since flipped to standby or disabled.
//
// The bind is delayed deterministically by holding the port; the persisted
// config is changed while the supervisor retries; then the port is released.
func TestChaos71_HABootResumeReReadsTheHAConfigAtBindTime(t *testing.T) {
	leader := &haConfig{Enabled: true, Role: "leader", PeerAddr: "10.0.0.9:50051", Token: "tok"}
	cases := []struct {
		name       string
		changeTo   *haConfig // persisted while the bind is failing; nil = unchanged
		wantResume int32
	}{
		{"control_unchanged_leader_resumes", nil, 1},
		{"flipped_to_standby", &haConfig{Enabled: true, Role: "standby", PeerAddr: "10.0.0.9:50051", Token: "tok"}, 0},
		{"ha_disabled", &haConfig{Enabled: false}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tempHADir(t)
			clusterDB := cpIsolateActivation(t)
			cpChaosSetup(t)
			cpInsecure(t)
			cpWithGlobalHARole(t, "", "")
			resumes := cpRecordBootResumes(t)
			if err := saveHAConfig(leader); err != nil {
				t.Fatalf("seed HA config: %v", err)
			}

			port, release := occupyPort(t)
			defer release()
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			if err := enableControlPlaneResilient(addr, "", "", "", clusterDB, resumeLeadershipIfStillPersisted); err != nil {
				t.Fatalf("boot path: %v", err)
			}
			if resumes.Load() != 0 {
				t.Fatal("leadership resumed before any bind")
			}
			if tc.changeTo != nil {
				if err := saveHAConfig(tc.changeTo); err != nil {
					t.Fatalf("change HA config: %v", err)
				}
			}

			release()
			cpWaitFor(t, 15*time.Second, "the delayed bind", func() bool { return cpGRPCListenerState().Serving })
			if got := resumes.Load(); got != tc.wantResume {
				t.Errorf("leadership resumed %d time(s) on the delayed bind, want %d — the resume must follow the "+
					"HA config persisted at bind time, not the one read at boot", got, tc.wantResume)
			}
		})
	}
}

// TestChaos71_HABootResumeSkipsWhenTheNodeAlreadyHoldsAnHARole covers the other
// half of the finding: an operator acting through the live HA API while the
// listener retried has already given this process a role, and the delayed
// resume must not overwrite it. Also: an unreadable config never resumes.
func TestChaos71_HABootResumeSkipsWhenTheNodeAlreadyHoldsAnHARole(t *testing.T) {
	tempHADir(t)
	resumes := cpRecordBootResumes(t)

	// Unreadable (absent) config: no resume.
	cpWithGlobalHARole(t, "", "")
	resumeLeadershipIfStillPersisted()
	if resumes.Load() != 0 {
		t.Fatal("resumed leadership with no persisted HA config")
	}

	if err := saveHAConfig(&haConfig{Enabled: true, Role: "leader", PeerAddr: "10.0.0.9:50051"}); err != nil {
		t.Fatalf("seed HA config: %v", err)
	}
	// Control: no live role, persisted leader → resumes.
	resumeLeadershipIfStillPersisted()
	if resumes.Load() != 1 {
		t.Fatalf("control: a persisted leader with no live role resumed %d time(s), want 1", resumes.Load())
	}
	// A live role is already set → no further resume.
	cpWithGlobalHARole(t, "standby", "10.0.0.9:50051")
	resumeLeadershipIfStillPersisted()
	if resumes.Load() != 1 {
		t.Error("the delayed resume overwrote an HA role this process already holds")
	}
}
