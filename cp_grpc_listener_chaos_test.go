package main

// cp_grpc_listener_chaos_test.go — CHAOS-73 gates.
//
// Structure, following §25/§36's discipline:
//
//   - DEFECT gates, each verified failing against the pre-fix shape it targets
//     (the fatal boot branch, the silent serve-loop exit, the once-only
//     certificate read, the per-attempt announcement).
//   - CONTROLS, verified failing against the cheapest WRONG fixes. They matter
//     more than usual here because the cheapest way to pass every defect gate
//     is to stop asserting leadership and stop reporting anything, which would
//     delete HA and the whole plane while leaving a green suite.
//   - WALLS, structural, for the properties behavioural coverage cannot reach:
//     that no listener path in this file family is fatal, and that there is
//     exactly ONE copy of the socket-error classifier.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// cpChaosSetup isolates the process-global listener record and the recovery
// loop's stop machinery. A leaked `running` flag makes armCPGRPCRecovery a
// no-op for the rest of the binary and a leaked closed stop channel makes every
// later loop exit on its first iteration — both silent, both the pollution
// class the determinism gate catches.
func cpChaosSetup(t *testing.T) {
	t.Helper()
	resetCPGRPCHealthForTest()
	origAlert := fireCPGRPCListenerAlert
	origAttempt := cpGRPCRecoveryAttempt
	t.Cleanup(func() {
		fireCPGRPCListenerAlert = origAlert
		cpGRPCRecoveryAttempt = origAttempt
		stopCPGRPCRecovery()
		resetCPGRPCHealthForTest()
	})
}

// captureCPAlerts installs a synchronous alert sink and returns the collected
// details. Synchronous so a transition is observable without racing the
// process-global alerts goroutine.
func captureCPAlerts(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var got []string
	fireCPGRPCListenerAlert = func(detail string) {
		mu.Lock()
		got = append(got, detail)
		mu.Unlock()
	}
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// DEFECT gates
// ─────────────────────────────────────────────────────────────────────────────

// TestChaos73_DefectBootBindFailureIsNotFatal is the headline gate.
//
// The pre-fix branch was `logFatalf("ControlPlane gRPC: %v", err)`, which
// os.Exit(1)s — so against that tree this test KILLS THE TEST BINARY mid-run
// and takes the whole package with it. That is what makes the defect
// impossible to reintroduce and keep green (the §33 observation about its own
// defect gates), and it is why the fatality property also has a STRUCTURAL
// wall below: a behavioural gate against an os.Exit cannot report a failure,
// it can only fail to produce a result.
func TestChaos73_DefectBootBindFailureIsNotFatal(t *testing.T) {
	cpChaosSetup(t)

	// A squatter on the port the "boot" will try.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("squatter listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	noteCPGRPCConfigured(addr)
	noteCPGRPCRequested(addr, "", "", "")

	// cpServerOption is consulted BEFORE the listen, so without this the
	// refusal is `tls_required` and the bind is never attempted. That ordering
	// is correct — there is no point binding a socket with nothing to serve on
	// it — and it is why `tls_required` is a separate reason class with a
	// non-environmental remedy.
	origInsecure := clusterInsecure
	clusterInsecure = true
	t.Cleanup(func() { clusterInsecure = origInsecure })

	// The real one-shot, against a held port.
	bindErr := StartControlPlaneGRPC(addr, "", "", "")
	if bindErr == nil {
		t.Fatal("expected a bind failure against a held port")
	}
	if got := classifyCPGRPCListenError(bindErr); got != "port_in_use" {
		t.Errorf("reason class = %q, want port_in_use", got)
	}

	// The process must still be here, and the fault must be VISIBLE rather
	// than merely survived — "it did not crash" is not the property; "an
	// operator can see why" is.
	noteCPGRPCListenFailure("port_in_use", cpGRPCListenBackoffInitial, time.Now())
	if got := cpGRPCListenerStatus(); got != "degraded" {
		t.Errorf("/health cp_grpc = %q, want degraded", got)
	}
	row := checkCPGRPCListener()
	if row.Status != diagWarn {
		t.Errorf("contract row status = %v, want warn while still retrying", row.Status)
	}
	if !strings.Contains(row.Message, "port_in_use") {
		t.Errorf("contract row does not name the reason class: %q", row.Message)
	}
}

// TestChaos73_DefectUnavailableListenerIsReportedNotSilent pins the surfaces
// that did not exist: before this change a Control Plane whose listener was
// down reported `role: "control-plane"` and nothing else, so every probe was
// green on a dead listener (PX-18 in the control plane).
func TestChaos73_DefectUnavailableListenerIsReportedNotSilent(t *testing.T) {
	cpChaosSetup(t)
	alerts := captureCPAlerts(t)

	noteCPGRPCConfigured("127.0.0.1:50051")
	start := time.Now()
	// First failure opens the episode; the second lands past the threshold.
	noteCPGRPCListenFailure("port_in_use", time.Second, start)
	noteCPGRPCListenFailure("port_in_use", 2*time.Second, start.Add(cpGRPCUnavailableAfter+time.Second))

	if got := cpGRPCListenerStatus(); got != "unavailable" {
		t.Errorf("/health cp_grpc = %q, want unavailable", got)
	}
	if row := checkCPGRPCListener(); row.Status != diagFail {
		t.Errorf("contract row status = %v, want fail past the threshold", row.Status)
	}
	checks := map[string]*readinessCheck{}
	appendCPGRPCReadinessCheck(checks)
	if checks["cp_grpc"] == nil || checks["cp_grpc"].Status != "fail" {
		t.Errorf("/ready cp_grpc = %+v, want a fail row", checks["cp_grpc"])
	}
	if got := alerts(); len(got) != 1 {
		t.Fatalf("alerts fired = %d, want exactly 1 per episode", len(got))
	}
	// The alert must name the real casualty. An operator reading "the control
	// plane is down" on a node whose proxy is fine needs to be told which
	// plane is affected, or they will take the gateway out of rotation.
	detail := alerts()[0]
	for _, want := range []string{"UNAFFECTED", "Data Plane", "port_in_use"} {
		if !strings.Contains(detail, want) {
			t.Errorf("alert detail missing %q: %s", want, detail)
		}
	}
}

// TestChaos73_DefectServeLoopExitIsNotSilent is the second half of the finding.
//
// Against the pre-fix tree the serve goroutine's only action was one
// logger.Printf, so nothing moved: no counter, no gauge, no row, no alert, no
// rebind. This gate drives the observer the serve goroutine now calls and
// requires every one of those to move.
func TestChaos73_DefectServeLoopExitIsNotSilent(t *testing.T) {
	cpChaosSetup(t)

	noteCPGRPCConfigured("127.0.0.1:50051")
	noteCPGRPCServing()
	if got := cpGRPCListenerStatus(); got != "ready" {
		t.Fatalf("precondition: status = %q, want ready", got)
	}

	noteCPGRPCServeExit()
	snap := cpGRPCListenerState()
	if snap.Serving {
		t.Error("listener still reports serving after its serve loop exited")
	}
	if snap.ServeExits != 1 {
		t.Errorf("serve exits = %d, want 1", snap.ServeExits)
	}
	if !snap.EverServed {
		t.Error("everServed must stay true — it is what separates 'never came up' from 'fell over'")
	}
	if got := cpGRPCListenerStatus(); got == "ready" {
		t.Error("/health still reports ready on a listener whose serve loop is dead")
	}

	// And after recovery the history must survive, because a serve-exit count
	// on an otherwise-healthy row is exactly the evidence that was missing.
	noteCPGRPCServing()
	if row := checkCPGRPCListener(); !strings.Contains(row.Message, "serve-loop exit") {
		t.Errorf("recovered row hides the serve-exit history: %q", row.Message)
	}
}

// TestChaos73_DefectCertificateIsReReadOnEveryAttempt pins CHAOS-57 rule 4 in
// this plane: the pre-fix path read -cp-grpc-cert/-cp-grpc-key exactly once at
// boot, so a rotation window that briefly truncated the pair was a permanent
// crash loop. The loop must pick the repaired pair up with no restart.
func TestChaos73_DefectCertificateIsReReadOnEveryAttempt(t *testing.T) {
	cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:50051")

	dir := t.TempDir()
	certPath := dir + "/cp.crt"
	keyPath := dir + "/cp.key"

	// Mid-rotation: the key exists and is empty, exactly as reproduced against
	// the real binary.
	if err := os.WriteFile(certPath, []byte("not-a-cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	var reads atomic.Int64
	cpGRPCRecoveryAttempt = func() error {
		reads.Add(1)
		_, _, err := cpServerOption("127.0.0.1:0", certPath, keyPath, "")
		return err
	}

	// Two attempts against the broken pair must both FAIL and both must have
	// actually read the files — a cached decision would pass the first
	// assertion and fail the read count.
	if err := cpGRPCAttempt(); err == nil {
		t.Fatal("expected a credentials failure against a truncated key")
	} else if got := classifyCPGRPCListenError(err); got != "tls_certificate" {
		t.Errorf("reason class = %q, want tls_certificate", got)
	}
	if err := cpGRPCAttempt(); err == nil {
		t.Fatal("second attempt should still fail while the pair is broken")
	}
	if reads.Load() != 2 {
		t.Errorf("credential reads = %d, want 2 (one per attempt)", reads.Load())
	}

	// The rotation completes. The SAME paths must now succeed, with no
	// restart and no re-configuration.
	writeCPTestPair(t, certPath, keyPath)
	if err := cpGRPCAttempt(); err != nil {
		t.Fatalf("attempt after the rotation completed still fails: %v", err)
	}
	if reads.Load() != 3 {
		t.Errorf("credential reads = %d, want 3", reads.Load())
	}
}

// TestChaos73_WallTheTransportAnnouncementIsNotPerAttempt pins the defect this
// change introduced into itself, and it is STRUCTURAL because the first version
// of this gate was VACUOUS — which is the transferable lesson.
//
// The defect: the first working version of the fix retried a failed bind, and
// `cpServerOption` logged its transport mode on EVERY call, from BEFORE the
// bind. Measured during the fix's own verification run against the real binary:
// six "(insecure — all cluster data unencrypted!)" WARN lines in fifteen
// seconds, each announcing a listener that did not exist, against a failure
// line the loop deliberately rate-limits to one per minute. Two defects in one
// line — CHAOS-57's rule 6 (announce AFTER the bind, not before) and this
// register's standing rule that a mitigation for a log-amplification defect
// must not be one itself.
//
// The first gate written for it asserted only the rate gate on the FAILURE
// line, and PASSED with the per-attempt announcement reinstated (verified by
// mutation) — because the announcement is a different line, emitted by a
// different function, and no amount of asserting the failure line's cadence
// can see it. Behavioural coverage cannot reach this at all without a logger
// seam that does not exist on this path, so the property is asserted where it
// lives: `cpServerOption` must contain no logging call, and the announcement
// must appear in `StartControlPlaneGRPC` AFTER the listen.
//
// A GATE THAT PASSES AGAINST THE DEFECT IS WORSE THAN NO GATE — it is the
// reason to believe the defect cannot come back.
func TestChaos73_WallTheTransportAnnouncementIsNotPerAttempt(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(pkgSourceDir(), "controlplane_server.go"), nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	logCalls := func(fn *ast.FuncDecl) []string {
		var got []string
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch c := call.Fun.(type) {
			case *ast.Ident:
				if strings.HasPrefix(c.Name, "logWarnf") || strings.HasPrefix(c.Name, "logErrorf") || strings.HasPrefix(c.Name, "logFatalf") {
					got = append(got, c.Name)
				}
			case *ast.SelectorExpr:
				if id, ok := c.X.(*ast.Ident); ok && id.Name == "logger" {
					got = append(got, "logger."+c.Sel.Name)
				}
			}
			return true
		})
		return got
	}

	var sawOption, sawStart bool
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		switch fn.Name.Name {
		case "cpServerOption":
			sawOption = true
			if calls := logCalls(fn); len(calls) != 0 {
				t.Errorf("cpServerOption logs %v — it is called once per rebind attempt, so a retried bind "+
					"turns this into one line per attempt for the whole outage, each announcing a listener "+
					"that does not exist yet (CHAOS-57 rule 6)", calls)
			}
		case "StartControlPlaneGRPC":
			sawStart = true
			// The announcement must come AFTER the listen, so it only ever
			// claims a listener that exists. Compare source positions of the
			// lc.Listen call and the announcement.
			var listenPos, announcePos token.Pos
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Listen" && listenPos == token.NoPos {
					listenPos = call.Pos()
				}
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "logWarnf" && announcePos == token.NoPos {
					announcePos = call.Pos()
				}
				return true
			})
			if listenPos == token.NoPos {
				t.Error("StartControlPlaneGRPC no longer calls Listen — this wall is scanning the wrong thing")
			}
			if announcePos == token.NoPos {
				t.Error("StartControlPlaneGRPC does not announce the transport mode — the insecure WARNING is security-relevant and must still be emitted somewhere")
			}
			if listenPos != token.NoPos && announcePos != token.NoPos && announcePos < listenPos {
				t.Errorf("the transport announcement (line %d) precedes the Listen (line %d) — it claims a listener that does not exist yet",
					fset.Position(announcePos).Line, fset.Position(listenPos).Line)
			}
		}
	}
	// NOT VACUOUS: both functions must have been found, or the scan matched
	// nothing and would pass forever.
	if !sawOption || !sawStart {
		t.Errorf("scan did not find both functions (cpServerOption=%v StartControlPlaneGRPC=%v) — the selector is stale", sawOption, sawStart)
	}
}

// TestChaos73_DefectFailureLogIsRateLimited is the other half: the recovery
// loop's own failure line must be rate-limited across an episode, with the
// magnitude in the counter and the suppressed count stated at recovery.
//
// Relabelled from a "does not amplify the log" gate, because that is NOT what
// it proves — see the wall above.
func TestChaos73_DefectFailureLogIsRateLimited(t *testing.T) {
	cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:50051")

	// Half one: the rate gate. The FIRST failure of an episode always logs —
	// the operator must see the onset — then at most one line per interval.
	start := time.Now()
	logged := 0
	for i := 0; i < 20; i++ {
		if noteCPGRPCListenFailure("port_in_use", time.Second, start.Add(time.Duration(i)*time.Second)) {
			logged++
		}
	}
	if logged != 1 {
		t.Errorf("log lines emitted for 20 failures inside one %s window = %d, want 1",
			cpGRPCListenLogInterval, logged)
	}
	if snap := cpGRPCListenerState(); snap.Total != 20 {
		t.Errorf("total failures = %d, want 20 — the COUNTER must never be rate-limited, only the line", snap.Total)
	}

	// Half two: the recovery line states what the gate swallowed, so a long
	// episode is not mistaken for a single blip.
	suppressed := noteCPGRPCServing()
	if suppressed != 19 {
		t.Errorf("suppressed count reported at recovery = %d, want 19", suppressed)
	}
}

// TestChaos73_DefectServeExitDuringAnAttemptIsNotSwallowed pins a hole this
// sweep found in its OWN fix, in self-review before the push.
//
// `armCPGRPCRecovery` returns false when a loop is already running — correct, to
// stop two loops fighting over one listener. But a serve-loop exit that arrives
// while the live loop is INSIDE an attempt was then dropped on the floor: the
// loop returned on its own successful bind, and the exit that landed in between
// left a listener whose serve loop is dead with every surface reporting ready.
// That is this sweep's own headline finding (a dead serve loop reporting
// healthy) reintroduced by the mechanism that fixes it — the class §30, §33 and
// §36 each record hitting inside their own remedy.
//
// An arm request is therefore LATCHED (`pending`) rather than dropped, and the
// loop re-checks it before returning.
func TestChaos73_DefectServeExitDuringAnAttemptIsNotSwallowed(t *testing.T) {
	cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:50051")

	var attempts atomic.Int64
	armedDuringAttempt := make(chan struct{}, 1)
	cpGRPCRecoveryAttempt = func() error {
		n := attempts.Add(1)
		if n == 1 {
			// Simulate the serve goroutine dying WHILE this first attempt is in
			// flight: it calls armCPGRPCRecovery, which sees a loop already
			// running and spawns nothing.
			noteCPGRPCServeExit()
			if armed := armCPGRPCRecovery(); armed {
				t.Error("armCPGRPCRecovery spawned a SECOND loop while one was running")
			}
			select {
			case armedDuringAttempt <- struct{}{}:
			default:
			}
		}
		return nil // both attempts "bind" successfully
	}

	if !armCPGRPCRecovery() {
		t.Fatal("the first arm should have started a loop")
	}
	select {
	case <-armedDuringAttempt:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop never ran its first attempt")
	}

	// The loop must NOT settle after one attempt: the latched request means it
	// has to rebind. The backoff makes that a short wait, so poll.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if attempts.Load() >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := attempts.Load(); got < 2 {
		t.Fatalf("attempts = %d, want >= 2 — the serve exit that arrived during the first attempt was SWALLOWED, "+
			"leaving a dead serve loop with every surface reporting ready", got)
	}
	if snap := cpGRPCListenerState(); snap.ServeExits != 1 {
		t.Errorf("serve exits = %d, want 1", snap.ServeExits)
	}
}

// TestChaos73_ControlNoOutstandingRequestMeansTheLoopSettles is the control for
// the gate above: the cheapest way to pass it is to make the loop never return,
// which would leave a goroutine rebinding forever on every healthy node.
func TestChaos73_ControlNoOutstandingRequestMeansTheLoopSettles(t *testing.T) {
	cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:50051")

	var attempts atomic.Int64
	cpGRPCRecoveryAttempt = func() error {
		attempts.Add(1)
		return nil
	}
	if !armCPGRPCRecovery() {
		t.Fatal("expected a loop to start")
	}

	// Give it well past one backoff interval to prove it does NOT attempt again.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if attempts.Load() > 1 {
			t.Fatalf("the loop attempted %d times with no outstanding rebind request — it never settles, "+
				"so a healthy node carries a goroutine rebinding forever", attempts.Load())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if attempts.Load() != 1 {
		t.Errorf("attempts = %d, want exactly 1", attempts.Load())
	}
	if cpGRPCRebindRequested() {
		t.Error("a rebind request is still outstanding after a clean recovery")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CONTROLS — each verified failing against a cheapest-wrong-fix shape
// ─────────────────────────────────────────────────────────────────────────────

// ControlHealthyControlPlaneIsSilent: the cheapest way to pass every defect
// gate above is to report a fault unconditionally. A healthy CP must produce
// an ok row, a ready status, and NO alert.
func TestChaos73_ControlHealthyControlPlaneIsSilent(t *testing.T) {
	cpChaosSetup(t)
	alerts := captureCPAlerts(t)

	noteCPGRPCConfigured("127.0.0.1:50051")
	noteCPGRPCServing()

	if got := cpGRPCListenerStatus(); got != "ready" {
		t.Errorf("/health cp_grpc = %q, want ready", got)
	}
	if row := checkCPGRPCListener(); row.Status != diagOK {
		t.Errorf("contract row = %v, want ok on a healthy CP", row.Status)
	}
	checks := map[string]*readinessCheck{}
	appendCPGRPCReadinessCheck(checks)
	if checks["cp_grpc"] == nil || checks["cp_grpc"].Status != "ok" {
		t.Errorf("/ready cp_grpc = %+v, want ok", checks["cp_grpc"])
	}
	if got := alerts(); len(got) != 0 {
		t.Errorf("alerts fired on a healthy CP: %v", got)
	}
}

// ControlNonControlPlaneNodeGrowsNoRows: a standalone proxy or a Data Plane
// node never asked to be a Control Plane. Emitting rows and a `0` gauge there
// would make "never configured" indistinguishable from "dead", which is the
// socks5/cluster_ca emission rule and the whole reason the metrics block is
// gated on Configured.
func TestChaos73_ControlNonControlPlaneNodeGrowsNoRows(t *testing.T) {
	cpChaosSetup(t)

	if got := cpGRPCListenerStatus(); got != "disabled" {
		t.Errorf("/health cp_grpc = %q, want disabled on a non-CP node", got)
	}
	if row := checkCPGRPCListener(); row.Status != diagOK {
		t.Errorf("contract row = %v, want ok on a non-CP node", row.Status)
	}
	checks := map[string]*readinessCheck{}
	appendCPGRPCReadinessCheck(checks)
	if _, ok := checks["cp_grpc"]; ok {
		t.Error("/ready grew a cp_grpc row on a node that is not a Control Plane")
	}
	if snap := cpGRPCListenerState(); snap.Configured {
		t.Error("Configured is true without a Control Plane having been requested")
	}
}

// ControlReadinessRowIsReportOnly is §33's rule, and the sharpest control in
// the file: a node whose CP gRPC listener is down is PROXYING PERFECTLY, so
// gating the default /ready verdict on it would eject a healthy gateway from
// the load balancer over its cluster plane — converting a control-plane outage
// into the traffic outage this change exists to prevent.
//
// Asserted as a DIFFERENTIAL over the real computeReadiness rather than as a
// property of the helper's signature. The signature form (the shape the
// admin-UI control uses) proves the helper returns no verdict channel, which a
// future change could satisfy while flipping allOK somewhere else; and an
// absolute assertion that the verdict is "ready" would be vacuous in the other
// direction, because an unrelated global in a fresh test binary can already
// make it not_ready. Requiring the verdict to be UNCHANGED between a healthy
// and an unavailable listener holds whatever else the binary's globals say.
func TestChaos73_ControlReadinessRowIsReportOnly(t *testing.T) {
	cpChaosSetup(t)

	noteCPGRPCConfigured("127.0.0.1:50051")
	noteCPGRPCServing()
	healthyReport, healthyCode := computeReadiness()

	start := time.Now()
	noteCPGRPCListenFailure("port_in_use", time.Second, start)
	noteCPGRPCListenFailure("port_in_use", time.Second, start.Add(cpGRPCUnavailableAfter+time.Second))
	if got := cpGRPCListenerStatus(); got != "unavailable" {
		t.Fatalf("precondition: status = %q, want unavailable", got)
	}
	downReport, downCode := computeReadiness()

	// NOT VACUOUS: the row itself must have moved, or this gate proves nothing.
	if downReport.Checks["cp_grpc"] == nil || downReport.Checks["cp_grpc"].Status != "fail" {
		t.Fatalf("cp_grpc row did not go to fail: %+v", downReport.Checks["cp_grpc"])
	}
	if healthyReport.Checks["cp_grpc"] == nil || healthyReport.Checks["cp_grpc"].Status != "ok" {
		t.Fatalf("cp_grpc row was not ok while serving: %+v", healthyReport.Checks["cp_grpc"])
	}

	if downCode != healthyCode || downReport.Status != healthyReport.Status {
		t.Errorf("a dead control plane changed the AGGREGATE readiness verdict: %s/%d -> %s/%d; "+
			"a healthy gateway would be ejected from the load balancer over its cluster plane",
			healthyReport.Status, healthyCode, downReport.Status, downCode)
	}
}

// ControlShutdownIsNotAFault: a node being torn down must not report its
// control plane as failed on the way out, and must not page.
func TestChaos73_ControlShutdownIsNotAFault(t *testing.T) {
	cpChaosSetup(t)
	alerts := captureCPAlerts(t)

	noteCPGRPCConfigured("127.0.0.1:50051")
	noteCPGRPCServing()
	noteCPGRPCStopped()

	if got := cpGRPCListenerStatus(); got != "stopped" {
		t.Errorf("/health cp_grpc = %q, want stopped", got)
	}
	if row := checkCPGRPCListener(); row.Status != diagOK {
		t.Errorf("contract row = %v, want ok during shutdown", row.Status)
	}
	checks := map[string]*readinessCheck{}
	appendCPGRPCReadinessCheck(checks)
	if _, ok := checks["cp_grpc"]; ok {
		t.Error("/ready grew a cp_grpc row during shutdown")
	}
	if got := alerts(); len(got) != 0 {
		t.Errorf("alerted during a clean shutdown: %v", got)
	}
}

// ControlRecoveryRequiresObservedEvidence: elapsed time must never clear the
// unavailable state. A retry loop that has stopped failing because it has
// stopped attempting looks identical to a bound listener, and declaring
// recovery on silence is the mistake ca_health.go and storage_health.go both
// call out by name.
func TestChaos73_ControlRecoveryRequiresObservedEvidence(t *testing.T) {
	cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:50051")
	start := time.Now()
	noteCPGRPCListenFailure("port_in_use", time.Second, start)
	noteCPGRPCListenFailure("port_in_use", time.Second, start.Add(cpGRPCUnavailableAfter+time.Second))
	if got := cpGRPCListenerStatus(); got != "unavailable" {
		t.Fatalf("precondition: status = %q", got)
	}

	// Reading the state repeatedly — i.e. time passing with no attempt — must
	// change nothing.
	for i := 0; i < 5; i++ {
		_ = cpGRPCListenerState()
	}
	if got := cpGRPCListenerStatus(); got != "unavailable" {
		t.Errorf("status drifted to %q with no observed bind — recovery was declared on silence", got)
	}

	// Only an observed bind clears it, and a second episode must page again.
	noteCPGRPCServing()
	if got := cpGRPCListenerStatus(); got != "ready" {
		t.Errorf("status = %q after an observed bind, want ready", got)
	}
	alerts := captureCPAlerts(t)
	later := start.Add(time.Hour)
	noteCPGRPCListenFailure("port_in_use", time.Second, later)
	noteCPGRPCListenFailure("port_in_use", time.Second, later.Add(cpGRPCUnavailableAfter+time.Second))
	if got := alerts(); len(got) != 1 {
		t.Errorf("second episode fired %d alerts, want 1 — the latch must be cleared by an observed bind", len(got))
	}
}

// ControlRemediesAreDistinctPerReasonClass is §36's third-round lesson: *"a
// bounded classifier is worth nothing if one remedy is printed for every
// class"*. A switch returning one string satisfies every "names its own
// remedy" assertion, so the property has to be asserted as DISTINCTNESS.
func TestChaos73_ControlRemediesAreDistinctPerReasonClass(t *testing.T) {
	classes := []string{"port_in_use", "permission_denied", "address_unavailable", "descriptors_exhausted", "tls_certificate", "tls_required"}
	seen := map[string]string{}
	for _, c := range classes {
		r := cpGRPCListenRemedy(c)
		if r == "" {
			t.Errorf("class %q has no remedy", c)
			continue
		}
		if prev, dup := seen[r]; dup {
			t.Errorf("classes %q and %q print the SAME remedy — the classifier buys nothing", prev, c)
		}
		seen[r] = c
	}
	// Two clauses must be invariant across every ENVIRONMENTAL class, because
	// both are true in all of them and both are what stops an operator
	// reaching for the wrong lever.
	for _, c := range classes {
		if c == "tls_required" {
			// The one class whose remedy is NOT environmental: nothing will
			// change on its own, so promising an automatic rebind there would
			// send the operator away from the fix (§36's split-recorder
			// lesson, where a blanket reword was wrong in the other direction).
			if strings.Contains(cpGRPCListenRemedy(c), "rebinds automatically once the fault clears") {
				t.Errorf("%q promises automatic recovery for a configuration refusal", c)
			}
			continue
		}
		r := cpGRPCListenRemedy(c)
		if !strings.Contains(r, "rebinds automatically") {
			t.Errorf("class %q does not say the listener rebinds by itself: %q", c, r)
		}
		if !strings.Contains(r, "proxy data plane is unaffected") {
			t.Errorf("class %q does not say the proxy is unaffected: %q", c, r)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// The classifier — one copy, and the network_error narrowing CHAOS-66 had to
// apply twice
// ─────────────────────────────────────────────────────────────────────────────

func TestChaos73_ClassifierCoversTheBoundedVocabulary(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "none"},
		{"addrinuse", wrapCPOpErr(syscall.EADDRINUSE), "port_in_use"},
		{"eacces", wrapCPOpErr(syscall.EACCES), "permission_denied"},
		{"eperm", wrapCPOpErr(syscall.EPERM), "permission_denied"},
		{"addrnotavail", wrapCPOpErr(syscall.EADDRNOTAVAIL), "address_unavailable"},
		{"emfile", wrapCPOpErr(syscall.EMFILE), "descriptors_exhausted"},
		{"enfile", wrapCPOpErr(syscall.ENFILE), "descriptors_exhausted"},
		{"credentials", fmt.Errorf("gRPC TLS: %w: boom", errCPGRPCCredentials), "tls_certificate"},
		{"tls required", fmt.Errorf("%w: no certs", errCPGRPCTLSRequired), "tls_required"},
		{"unrecognised errno", wrapCPOpErr(syscall.EINVAL), "listen_failed"},
		{"bare error", errors.New("something else"), "listen_failed"},
	}
	for _, tc := range cases {
		if got := classifyCPGRPCListenError(tc.err); got != tc.want {
			t.Errorf("%s: class = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestChaos73_DefectUnrecognisedErrnoIsNotReportedAsANetworkFault pins
// CHAOS-66's narrowing in the NEW plane.
//
// *net.OpError satisfies net.Error UNCONDITIONALLY — Timeout() is false for a
// bind EINVAL — so an unqualified errors.As(&ne) branch reports every
// unrecognised errno as a network fault, sending the operator down a
// network-troubleshooting path for a socket fault, and makes `listen_failed`
// reachable only by an error the net package never produced. CHAOS-66 had to
// fix exactly this in BOTH existing copies; the shared classifier is what
// stops it being a third.
func TestChaos73_DefectUnrecognisedErrnoIsNotReportedAsANetworkFault(t *testing.T) {
	err := wrapCPOpErr(syscall.EINVAL)

	// The premise, asserted rather than assumed: this error DOES satisfy
	// net.Error, which is why the unqualified branch was wrong.
	var ne net.Error
	if !errors.As(err, &ne) {
		t.Fatal("premise broken: a bind *net.OpError no longer satisfies net.Error")
	}
	if ne.Timeout() {
		t.Fatal("premise broken: a bind EINVAL now reports Timeout()")
	}

	for name, got := range map[string]string{
		"cp":       classifyCPGRPCListenError(err),
		"admin_ui": classifyAdminUIListenError(err),
		"socks5":   classifySOCKS5BindError(err),
	} {
		if got == "network_error" {
			t.Errorf("%s: an unrecognised bind errno is classified %q", name, got)
		}
		if got != "listen_failed" {
			t.Errorf("%s: class = %q, want listen_failed", name, got)
		}
	}
}

// TestChaos73_ClassifiersShareOneSocketVocabulary is the DIFFERENTIAL that
// makes the shared copy safe: all three planes must agree, class for class, on
// every socket fault. A divergence is an operator reading one runbook for a
// fault the other names differently.
func TestChaos73_ClassifiersShareOneSocketVocabulary(t *testing.T) {
	errs := []error{
		nil,
		wrapCPOpErr(syscall.EADDRINUSE),
		wrapCPOpErr(syscall.EACCES),
		wrapCPOpErr(syscall.EPERM),
		wrapCPOpErr(syscall.EADDRNOTAVAIL),
		wrapCPOpErr(syscall.EMFILE),
		wrapCPOpErr(syscall.ENFILE),
		wrapCPOpErr(syscall.EINVAL),
		errors.New("bare"),
	}
	for _, err := range errs {
		cp := classifyCPGRPCListenError(err)
		ui := classifyAdminUIListenError(err)
		s5 := classifySOCKS5BindError(err)
		if cp != ui || ui != s5 {
			t.Errorf("classifiers disagree on %v: cp=%q admin_ui=%q socks5=%q", err, cp, ui, s5)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// STRUCTURAL WALLS
// ─────────────────────────────────────────────────────────────────────────────

// TestChaos73_WallNoListenerPathIsFatal is the structural half of the headline
// gate, and it is not redundant with it: a behavioural gate against a
// logFatalf cannot FAIL, it can only kill the test binary, so the property
// that no listener path exits the process needs an assertion that survives.
//
// §36 shipped the same wall over the three listener sources; this extends the
// set to the cluster boot path. main.go's own `logFatalf("Proxy error")` stays
// deliberately out of scope and is correct: the proxy IS the product, and a
// gateway that cannot serve must exit loudly rather than linger as a black
// hole. That asymmetry is the whole finding.
func TestChaos73_WallNoListenerPathIsFatal(t *testing.T) {
	// Anchored to the package source dir, never CWD-relative: a concurrent
	// os.Chdir in another test would otherwise make this wall read the wrong
	// file and flake (pinned repo-wide by TestTestFileReadsAreCWDIndependent,
	// which caught exactly this in the first version of this suite).
	dir := pkgSourceDir()
	files := []string{"cluster_startup.go", "controlplane_server.go", "cp_grpc_recovery.go", "cp_grpc_health.go"}
	for _, f := range files {
		src, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			code := line
			if idx := strings.Index(code, "//"); idx >= 0 {
				code = code[:idx]
			}
			if strings.Contains(code, "logFatalf(") && strings.Contains(strings.ToLower(code), "grpc") {
				t.Errorf("%s:%d reintroduces a fatal gRPC listener path: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
	// NOT VACUOUS: the one remaining logFatalf in cluster_startup.go is the HA
	// LEASE, which is deliberately fatal (a requested fence that cannot be
	// built must not silently run legacy), so the file must still contain one.
	src, err := os.ReadFile(filepath.Join(dir, "cluster_startup.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "logFatalf(\"HA lease:") {
		t.Error("the HA-lease fatal is gone — either it was removed (a safety downgrade) or this wall is now scanning the wrong file")
	}
}

// TestChaos73_WallOneCopyOfTheSocketClassifier pins the governance property.
//
// Two independent copies of this errno switch existed, and CHAOS-66 found the
// SAME defect in BOTH and had to fix it twice in one change. A third copy is a
// third place to fix it, so the switch must live in exactly one function and
// every plane must delegate. Asserted structurally because the differential
// above would keep passing against three identical copies right up until one
// of them drifted.
func TestChaos73_WallOneCopyOfTheSocketClassifier(t *testing.T) {
	fset := token.NewFileSet()
	dir := pkgSourceDir() // anchored, never CWD-relative (see the wall above)
	names, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	owners := map[string]string{}
	for _, e := range names {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, 0)
		if err != nil {
			continue
		}
		ast.Inspect(f, func(node ast.Node) bool {
			sel, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "syscall" {
				return true
			}
			switch sel.Sel.Name {
			case "EADDRINUSE", "EADDRNOTAVAIL":
				owners[sel.Sel.Name+"@"+n] = n
			}
			return true
		})
	}
	// Every reference to the bind-specific errnos must be in the one shared
	// classifier (plus nothing else). A plane that re-derives them is a new
	// copy of the table.
	for k, file := range owners {
		if file != "listener_error_class.go" {
			t.Errorf("%s: bind errno classification outside the shared classifier — this is the second-copy class CHAOS-66 had to fix twice", k)
		}
	}
	if len(owners) == 0 {
		t.Error("NOT VACUOUS check failed: no syscall.EADDRINUSE/EADDRNOTAVAIL reference found at all — the scan is matching nothing")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

// wrapCPOpErr builds the error shape net really produces for a bind failure:
// *net.OpError{Err: *os.SyscallError{Err: syscall.Errno}}. Hand-rolling it is
// deliberate — a bare errno would not exercise the errors.As unwrapping that
// the "never match by string" rule depends on.
func wrapCPOpErr(errno syscall.Errno) error {
	return &net.OpError{
		Op:  "listen",
		Net: "tcp",
		Err: &os.SyscallError{Syscall: "bind", Err: errno},
	}
}

// writeCPTestPair writes a valid self-signed cert/key pair, standing in for a
// completed certificate rotation.
func writeCPTestPair(t *testing.T, certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cp.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}
