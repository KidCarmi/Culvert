package main

// cp_grpc_chaos_test.go — CHAOS-71 gates.
//
// The finding has two coupled halves (see cp_grpc_supervisor.go's header):
//
//   - the Control Plane gRPC bind was FATAL on the boot path, before the proxy
//     and admin UI existed; and
//   - a listener that never bound, or bound and then died, was invisible on
//     every surface while the fencing lease kept vouching for it.
//
// The defect gates below were each verified FAILING against the shape they
// target, and the controls were each verified failing against the cheapest
// wrong fix — because the cheapest way to pass "the listener is reported
// unavailable" is to report every Control Plane as unavailable, and the
// cheapest way to pass "the boot is not fatal" is to stop starting a Control
// Plane at all.

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// cpChaosSetup isolates the process-global CP listener record.
func cpChaosSetup(t *testing.T) {
	t.Helper()
	resetCPGRPCHealthForTest()
	t.Cleanup(resetCPGRPCHealthForTest)
}

// occupyCPPort binds a listener and returns its address plus a release func, so
// a test can reproduce the EADDRINUSE case the finding was reproduced with.
//
// Named distinctly from admin_ui_listener_chaos_test.go's occupyPort, which
// returns a PORT NUMBER for a listener identified by port; the CP listener is
// identified by a full host:port address.
func occupyCPPort(t *testing.T) (addr string, release func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy: %v", err)
	}
	var closed bool
	return ln.Addr().String(), func() {
		if !closed {
			closed = true
			_ = ln.Close()
		}
	}
}

// ── Defect gates ─────────────────────────────────────────────────────────────

// TestChaos71_DefectBindFailureIsNotFatalAndKeepsRetrying pins the boot half.
//
// Against the pre-fix tree the equivalent path called
// logFatalf("ControlPlane gRPC: %v", err) → os.Exit(1), which kills the TEST
// BINARY mid-run rather than failing an assertion — so the defect cannot be
// reintroduced and kept green, and the structural wall below names it.
//
// What this asserts is the contract the boot path depends on: the supervisor
// returns the first attempt's error AND stays alive retrying.
func TestChaos71_DefectBindFailureIsNotFatalAndKeepsRetrying(t *testing.T) {
	cpChaosSetup(t)
	clusterInsecure = true
	t.Cleanup(func() { clusterInsecure = false })

	addr, release := occupyCPPort(t)
	defer release()

	sup, err := startCPGRPCSupervisor(addr, "", "", "")
	if sup == nil {
		t.Fatal("startCPGRPCSupervisor returned a nil supervisor")
	}
	defer sup.Stop()

	if err == nil {
		t.Fatal("expected the first bind attempt against an occupied port to report an error")
	}
	if got := classifyCPGRPCListenError(err); got != "port_in_use" {
		t.Errorf("reason class = %q, want port_in_use", got)
	}

	// The supervisor must still be retrying: the attempt count has to grow.
	first := cpGRPCListenerState().Total
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if cpGRPCListenerState().Total > first {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	snap := cpGRPCListenerState()
	if snap.Total <= first {
		t.Errorf("bind attempts did not grow past %d (now %d) — the supervisor gave up instead of retrying at a bounded rate",
			first, snap.Total)
	}
	if !snap.Configured {
		t.Error("a Control Plane that never bound must still report as CONFIGURED — otherwise it is " +
			"indistinguishable from a node that never asked for one")
	}
	if snap.Serving {
		t.Error("a listener that never bound must not report serving")
	}
}

// TestChaos71_DefectAServeExitIsRecorded pins the half that had no surface at
// all: `srv.Serve(ln)` returned, one log line was emitted, and the goroutine
// exited leaving a dark Control Plane that every surface reported as healthy.
//
// Driven through the recorder rather than by killing a real listener, because
// the observable is whether the state is WRITTEN — a real Serve exit is what
// the production loop already routes here, and the wiring is pinned separately.
func TestChaos71_DefectAServeExitIsRecorded(t *testing.T) {
	cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:19999")
	noteCPGRPCBound()

	if !cpGRPCListenerState().Serving {
		t.Fatal("precondition: a bound listener must report serving")
	}

	noteCPGRPCServeExit("listen_failed", time.Now())

	snap := cpGRPCListenerState()
	if snap.Serving {
		t.Error("a listener whose Serve returned must not still report serving")
	}
	if snap.ServeExits != 1 {
		t.Errorf("serve exits = %d, want 1 — a dead listener left no trace", snap.ServeExits)
	}
	if !snap.Failing {
		t.Error("a serve exit must open a failing episode, or the unavailability threshold can never be reached")
	}
	if got := cpGRPCListenerStatus(); got != "degraded" && got != "unavailable" {
		t.Errorf("/health posture after a serve exit = %q, want degraded or unavailable", got)
	}
}

// TestChaos71_DefectDarkControlPlaneIsVisibleOnEverySurface is the core gate.
//
// Before this change a Control Plane whose listener was unusable past the
// threshold was reported by NOTHING: no /health field, no /ready row, no
// /metrics series, no /api/diagnostics row, no alert. All five are asserted
// together because the finding is specifically that each one individually was
// absent while the admin UI and SOCKS5 listeners beside it had all of them.
func TestChaos71_DefectDarkControlPlaneIsVisibleOnEverySurface(t *testing.T) {
	cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:19999")

	// Drive an episode past the unavailability threshold using synthetic
	// stamps, the way every other listener gate does.
	start := time.Now().Add(-2 * cpGRPCUnavailableAfter)
	noteCPGRPCBindFailure("port_in_use", time.Second, start)
	noteCPGRPCBindFailure("port_in_use", time.Second, start.Add(cpGRPCUnavailableAfter+time.Second))

	if !cpGRPCUnavailableNow() {
		t.Fatal("precondition: the episode should be past the unavailability threshold")
	}

	t.Run("health_field", func(t *testing.T) {
		if got := computeHealth().ControlPlane; got != "unavailable" {
			t.Errorf("/health control_plane = %q, want unavailable", got)
		}
	})

	t.Run("ready_row", func(t *testing.T) {
		checks := map[string]*readinessCheck{}
		appendCPGRPCReadinessCheck(checks)
		row, ok := checks["control_plane"]
		if !ok {
			t.Fatal("/ready has no control_plane row for a dark control plane")
		}
		if row.Status != "fail" {
			t.Errorf("/ready control_plane status = %q, want fail", row.Status)
		}
		// Fixed detail: /ready is unauthenticated on the proxy port, so the
		// reason class must not leak there.
		if strings.Contains(row.Detail, "port_in_use") {
			t.Errorf("/ready detail leaks the reason class to an unauthenticated surface: %q", row.Detail)
		}
	})

	t.Run("metrics_series", func(t *testing.T) {
		body := scrapeMetricsForCPTest(t)
		for _, want := range []string{
			"culvert_cp_grpc_up 0",
			"culvert_cp_grpc_unavailable 1",
			"culvert_cp_grpc_bind_failures_total 2",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("/metrics missing %q", want)
			}
		}
	})

	t.Run("diagnostics_row", func(t *testing.T) {
		row := checkCPGRPCListener()
		if row.Code != "control_plane_listener" {
			t.Fatalf("row code = %q", row.Code)
		}
		if row.Status != diagFail {
			t.Errorf("row status = %q, want fail", row.Status)
		}
		if row.OperatorAction == "" {
			t.Error("a fail row must name an operator action")
		}
	})

	t.Run("healthz_fields", func(t *testing.T) {
		resp := map[string]any{}
		cpGRPCHealthzFields(resp)
		if resp["control_plane"] != "unavailable" {
			t.Errorf("/healthz control_plane = %v, want unavailable", resp["control_plane"])
		}
		if resp["control_plane_unavailable"] != true {
			t.Errorf("/healthz control_plane_unavailable = %v, want true", resp["control_plane_unavailable"])
		}
	})
}

// TestChaos71_DefectTheAlertFiresOncePerEpisodeWithABoundedDetail.
//
// The alert is new, so the "defect" is its absence. The BOUNDED detail is the
// part that needs a gate beyond existence: Store.Dispatch dedups on
// event+Detail, so an unbounded detail gives the key one value per failure and
// the fan-out evicts real threat alerts from the retry queue (WK-12/RS-5).
func TestChaos71_DefectTheAlertFiresOncePerEpisodeWithABoundedDetail(t *testing.T) {
	cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:19999")

	var details []string
	orig := fireCPGRPCListenerAlert
	fireCPGRPCListenerAlert = func(d string) { details = append(details, d) }
	t.Cleanup(func() { fireCPGRPCListenerAlert = orig })

	start := time.Now().Add(-4 * cpGRPCUnavailableAfter)
	for i := 0; i < 5; i++ {
		noteCPGRPCBindFailure("port_in_use", time.Second,
			start.Add(time.Duration(i)*(cpGRPCUnavailableAfter+time.Second)))
	}

	if len(details) != 1 {
		t.Fatalf("alert fired %d times for one episode, want exactly 1 (fire-once latch)", len(details))
	}
	if strings.Contains(details[0], "127.0.0.1:19999") {
		t.Error("alert Detail embeds the bind address — it is the dedup key and must stay bounded")
	}
	if !strings.Contains(details[0], "port_in_use") {
		t.Errorf("alert Detail should carry the bounded reason class: %q", details[0])
	}

	// An observed bind clears the latch, so a SECOND episode can page again.
	noteCPGRPCBound()
	noteCPGRPCBindFailure("port_in_use", time.Second, time.Now().Add(-2*cpGRPCUnavailableAfter))
	noteCPGRPCBindFailure("port_in_use", time.Second, time.Now())
	if len(details) != 2 {
		t.Errorf("a new episode after a recovery fired %d alerts in total, want 2", len(details))
	}
}

// TestChaos71_DefectRecoveryRequiresObservedEvidence.
//
// Elapsed time must never clear the failing state: a loop that stopped failing
// because it stopped attempting looks identical to a bound one. Only a bind
// clears it.
func TestChaos71_DefectRecoveryRequiresObservedEvidence(t *testing.T) {
	cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:19999")
	noteCPGRPCBindFailure("port_in_use", time.Second, time.Now().Add(-10*time.Minute))

	// A long time passes with no further attempt. Nothing may clear.
	if !cpGRPCListenerState().Failing {
		t.Fatal("the failing episode cleared without a bind — recovery must be evidence-based")
	}
	if cpGRPCListenerStatus() == "ready" {
		t.Fatal("posture reported ready with no listener bound")
	}

	noteCPGRPCBound()
	snap := cpGRPCListenerState()
	if snap.Failing {
		t.Error("an observed bind must clear the failing episode")
	}
	if !snap.Serving || snap.Binds != 1 {
		t.Errorf("after an observed bind: serving=%v binds=%d, want true/1", snap.Serving, snap.Binds)
	}
}

// TestChaos71_DefectClampKeepsTheCadenceInsideTheThreshold.
//
// CHAOS-66's round-3 bound. FailingFor is derived from two stored stamps, so it
// FREEZES between attempts, and the alert is attempt-driven — nothing else
// wakes the loop. A sleep that straddles the threshold therefore leaves the
// page unfired past the documented window.
func TestChaos71_DefectClampKeepsTheCadenceInsideTheThreshold(t *testing.T) {
	cases := []struct {
		name       string
		wait       time.Duration
		failingFor time.Duration
	}{
		{"straddles the threshold", cpGRPCBindBackoffMax, cpGRPCUnavailableAfter - time.Second},
		{"well short", cpGRPCBindBackoffMax, 2 * time.Second},
		{"all but reached", cpGRPCBindBackoffMax, cpGRPCUnavailableAfter - time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := clampCPGRPCBindSleep(tc.wait, tc.failingFor)
			if tc.failingFor+got > cpGRPCUnavailableAfter+cpGRPCBindClampFloor {
				t.Errorf("clamped sleep %s at failingFor=%s lands past the threshold (%s) — the episode "+
					"would sit below the unavailability window with no attempt to observe it",
					got, tc.failingFor, cpGRPCUnavailableAfter)
			}
			if got <= 0 {
				t.Errorf("clamped sleep = %s, must stay positive or the loop spins", got)
			}
		})
	}

	// Past the threshold the clamp must NOT shorten anything — otherwise a long
	// outage retries at the floor forever, which is the cost the clamp exists
	// to avoid paying permanently.
	if got := clampCPGRPCBindSleep(cpGRPCBindBackoffMax, 10*time.Minute); got != cpGRPCBindBackoffMax {
		t.Errorf("past the threshold the clamp returned %s, want the full %s", got, cpGRPCBindBackoffMax)
	}
}

// TestChaos71_DefectAnUnresolvedFirstAttemptFailsClosed.
//
// A defect found in SELF-REVIEW of this change, and it is worth a named gate
// because it reintroduced the finding through the fix.
//
// run() carries a deferred fallback marker so startCPGRPCSupervisor cannot hang
// if the loop exits without resolving an attempt (today: a contained panic
// before the first bind). The first version passed nil there — i.e. SUCCESS. So
// a panic before the first bind would have made StartControlPlaneGRPC return
// nil, enableControlPlane set role=control-plane, and **HA promotion promote
// this node to leader with no listener and no supervisor** — the dark-leader
// state this whole section exists to eliminate.
//
// The invariant: an UNRESOLVED first attempt is never reported as a successful
// one. Asserted on the marker directly, because a panic inside the production
// loop cannot be induced from a test without injecting a fault into the bind
// path itself — and the observable that matters is the fail-closed direction of
// the signal, not the panic.
func TestChaos71_DefectAnUnresolvedFirstAttemptFailsClosed(t *testing.T) {
	// Half 1 — the marker's own contract: idempotent, and a resolved attempt
	// WINS so the fallback can never overwrite a real success with a failure.
	s := &cpGRPCSupervisor{firstAttempt: make(chan struct{})}
	s.markFirstAttempt(errCPGRPCSupervisorStopped)
	select {
	case <-s.firstAttempt:
	default:
		t.Fatal("the fallback marker did not release the caller — startCPGRPCSupervisor would hang")
	}
	if !errors.Is(s.firstErr, errCPGRPCSupervisorStopped) {
		t.Errorf("first-attempt error = %v, want errCPGRPCSupervisorStopped", s.firstErr)
	}
	s2 := &cpGRPCSupervisor{firstAttempt: make(chan struct{})}
	s2.markFirstAttempt(nil)
	s2.markFirstAttempt(errCPGRPCSupervisorStopped)
	if s2.firstErr != nil {
		t.Errorf("the fallback overwrote a resolved successful attempt: %v", s2.firstErr)
	}

	// Half 2 — THE CALL SITE, and this half is why the gate is structural.
	//
	// The first version of this test asserted only half 1 and PASSED against
	// the reintroduced defect (measured), because it calls markFirstAttempt
	// directly and never reaches run()'s deferred call site — so flipping that
	// defer's argument back to nil was invisible to it. That is this
	// repository's standing rule in its sharpest form: a gate that passes
	// against the defect is worse than no gate.
	//
	// The defect cannot be reached behaviourally either: inducing a panic
	// before the first bind means injecting a fault into the bind path itself,
	// and a healthy supervisor resolves its first attempt long before the
	// fallback ever fires. So the ARGUMENT is asserted where it lives.
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "cp_grpc_supervisor.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var run *ast.FuncDecl
	for _, d := range parsed.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "run" || fn.Recv == nil {
			continue
		}
		run = fn
	}
	if run == nil {
		t.Fatal("cpGRPCSupervisor.run not found — the gate is not reading what it claims to")
	}

	deferred := 0
	for _, stmt := range run.Body.List {
		d, ok := stmt.(*ast.DeferStmt)
		if !ok {
			continue
		}
		ast.Inspect(d.Call, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "markFirstAttempt" {
				return true
			}
			deferred++
			if len(call.Args) != 1 {
				t.Fatalf("deferred markFirstAttempt takes %d args, want 1", len(call.Args))
			}
			if id, isIdent := call.Args[0].(*ast.Ident); isIdent && id.Name == "nil" {
				t.Error("run()'s deferred markFirstAttempt passes nil — an UNRESOLVED first attempt would " +
					"be reported as SUCCESS, so StartControlPlaneGRPC returns nil, enableControlPlane " +
					"adopts the control-plane role, and HA PROMOTION PROMOTES THIS NODE TO LEADER WITH " +
					"NO LISTENER AND NO SUPERVISOR — the dark-leader state §41 exists to eliminate")
			}
			return true
		})
	}
	// Not-vacuous check: the fallback defer must actually be there. Without it
	// a panic before the first attempt hangs startup forever, which is a worse
	// failure than the one the argument guards against.
	if deferred != 1 {
		t.Fatalf("found %d deferred markFirstAttempt calls in run(), want exactly 1 — the fail-closed "+
			"fallback that keeps startCPGRPCSupervisor from hanging is missing or duplicated", deferred)
	}
}

// ── Controls ─────────────────────────────────────────────────────────────────

// TestChaos71_ControlAHealthyControlPlaneReportsReady.
//
// The cheapest way to pass every defect gate above is to report every Control
// Plane as unavailable, which would page every CP in the field permanently.
// Verified failing against a cpGRPCListenerStatus that always answers
// "unavailable".
func TestChaos71_ControlAHealthyControlPlaneReportsReady(t *testing.T) {
	cpChaosSetup(t)
	clusterInsecure = true
	t.Cleanup(func() { clusterInsecure = false })

	sup, err := startCPGRPCSupervisor("127.0.0.1:0", "", "", "")
	if err != nil {
		t.Fatalf("a bind to an ephemeral port must succeed: %v", err)
	}
	defer sup.Stop()

	snap := cpGRPCListenerState()
	if !snap.Serving {
		t.Fatal("a successfully bound listener must report serving")
	}
	if snap.Total != 0 || snap.ServeExits != 0 {
		t.Errorf("a clean bind recorded %d failures / %d serve exits, want 0/0", snap.Total, snap.ServeExits)
	}
	if got := cpGRPCListenerStatus(); got != "ready" {
		t.Errorf("/health control_plane = %q, want ready", got)
	}
	if cpGRPCUnavailableNow() {
		t.Error("a serving control plane must not report unavailable")
	}
	if row := checkCPGRPCListener(); row.Status != diagOK {
		t.Errorf("diagnostics row = %q, want ok", row.Status)
	}
	checks := map[string]*readinessCheck{}
	appendCPGRPCReadinessCheck(checks)
	if row := checks["control_plane"]; row == nil || row.Status != "ok" {
		t.Errorf("/ready control_plane row = %+v, want ok", row)
	}
	if body := scrapeMetricsForCPTest(t); !strings.Contains(body, "culvert_cp_grpc_up 1") {
		t.Error("/metrics should report culvert_cp_grpc_up 1 for a serving listener")
	}
}

// TestChaos71_ControlNoControlPlaneConfiguredEmitsNothing.
//
// The emission rule (socks5/cluster_ca/dns): `culvert_cp_grpc_up 0` on a
// standalone appliance that never asked for a control plane is
// indistinguishable from a CP whose listener is dead, and the documented paging
// rule is `== 0`. The /health field and the /ready row must be ABSENT too.
func TestChaos71_ControlNoControlPlaneConfiguredEmitsNothing(t *testing.T) {
	cpChaosSetup(t)

	if got := computeHealth().ControlPlane; got != "" {
		t.Errorf("/health control_plane = %q on a node with no control plane, want omitted", got)
	}
	checks := map[string]*readinessCheck{}
	appendCPGRPCReadinessCheck(checks)
	if _, ok := checks["control_plane"]; ok {
		t.Error("/ready carries a control_plane row on a node with no control plane")
	}
	resp := map[string]any{}
	cpGRPCHealthzFields(resp)
	if len(resp) != 0 {
		t.Errorf("/healthz carries %v on a node with no control plane, want nothing", resp)
	}
	if body := scrapeMetricsForCPTest(t); strings.Contains(body, "culvert_cp_grpc_") {
		t.Error("/metrics emits culvert_cp_grpc_* on a node that never configured a control plane — " +
			"a flat zero there is indistinguishable from a dead listener")
	}
	if row := checkCPGRPCListener(); row.Status != diagOK {
		t.Errorf("diagnostics row = %q on an unconfigured node, want ok", row.Status)
	}
	if cpGRPCUnavailableNow() {
		t.Error("an unconfigured node must never report its control plane unavailable")
	}
}

// TestChaos71_ControlTheReadyRowIsReportOnly.
//
// REPORT-ONLY is load-bearing: a CP node whose cluster listener cannot bind is
// proxying its own traffic perfectly, so gating the default readiness verdict
// would eject a healthy gateway from the load balancer over a fleet-control
// fault — converting a management outage into the traffic outage the row exists
// to make visible. This is CHAOS-57's decision for the admin_ui row, and it is
// asserted rather than trusted.
//
// Verified failing against a version that sets allOK = false for this row.
func TestChaos71_ControlTheReadyRowIsReportOnly(t *testing.T) {
	cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:19999")
	start := time.Now().Add(-2 * cpGRPCUnavailableAfter)
	noteCPGRPCBindFailure("port_in_use", time.Second, start)
	noteCPGRPCBindFailure("port_in_use", time.Second, start.Add(cpGRPCUnavailableAfter+time.Second))

	report, code := computeReadiness()
	row, ok := report.Checks["control_plane"]
	if !ok || row.Status != "fail" {
		t.Fatalf("precondition: expected a failing control_plane row, got %+v (ok=%v)", row, ok)
	}
	if code != http.StatusOK {
		t.Errorf("a dark control plane made /ready answer %d — the row must NOT gate the default verdict, "+
			"or a healthy proxy is ejected from rotation over a cluster-control fault", code)
	}
	if report.Status != "ready" {
		t.Errorf("/ready status = %q, want ready (report-only row)", report.Status)
	}
}

// TestChaos71_ControlRuntimeCallersKeepAllOrNothing.
//
// StartControlPlaneGRPC is reached from the admin API and from HA promotion,
// and both need a synchronous error AND no supervisor left retrying. The HA
// case is a cluster-safety property, not a preference: promote() treats the
// error as "stay standby" and a retained supervisor would bind the CP port on a
// node that is not the leader.
//
// A STANDBY MUST NEVER HOLD THE CP PORT.
func TestChaos71_ControlRuntimeCallersKeepAllOrNothing(t *testing.T) {
	cpChaosSetup(t)
	clusterInsecure = true
	t.Cleanup(func() { clusterInsecure = false })

	addr, release := occupyCPPort(t)
	defer release()

	if err := StartControlPlaneGRPC(addr, "", "", ""); err == nil {
		t.Fatal("StartControlPlaneGRPC must return an error when the port is occupied — " +
			"the admin API and HA promotion both depend on the synchronous verdict")
	}

	// Nothing may be retrying. Free the port and confirm no listener appears:
	// a retained supervisor would grab it within a backoff interval.
	release()
	before := cpGRPCListenerState().Binds
	time.Sleep(3 * time.Second)
	if got := cpGRPCListenerState().Binds; got != before {
		t.Fatalf("a failed StartControlPlaneGRPC left a supervisor retrying (binds %d → %d): "+
			"on the HA promotion path that binds the Control Plane port on a STANDBY", before, got)
	}
	if cpGRPCListenerState().Serving {
		t.Error("a failed StartControlPlaneGRPC must not leave a serving listener")
	}
}

// TestChaos71_ControlEachReasonClassNamesItsOwnRemedy.
//
// CHAOS-66's round-3 finding: a bounded classifier is worth nothing if one
// remedy is printed for every class — a node out of descriptors or with an
// interface not yet up was sent to hunt the owner of a port nobody holds.
//
// Also pins the two clauses that must be invariant in EVERY branch: the
// listener rebinds by itself (so nobody restarts a CP to achieve what is
// already in progress) and this node's proxy and admin UI are unaffected.
func TestChaos71_ControlEachReasonClassNamesItsOwnRemedy(t *testing.T) {
	diagnosable := []string{"port_in_use", "permission_denied", "address_unavailable", "descriptors_exhausted", "tls_material"}
	seen := map[string]string{}
	for _, reason := range diagnosable {
		remedy := cpGRPCBindRemedy(reason)
		if prev, dup := seen[remedy]; dup {
			t.Errorf("reason %q shares its remedy with %q — a switch returning one string satisfies every "+
				"\"names its own remedy\" assertion while telling the operator the wrong thing", reason, prev)
		}
		seen[remedy] = reason
		if !strings.Contains(remedy, "rebinds by itself") {
			t.Errorf("remedy for %q does not say the listener recovers on its own: %q", reason, remedy)
		}
		if !strings.Contains(remedy, "unaffected") {
			t.Errorf("remedy for %q does not say the proxy/admin UI are unaffected: %q", reason, remedy)
		}
	}
	if len(seen) != len(diagnosable) {
		t.Errorf("only %d distinct remedies for %d diagnosable classes", len(seen), len(diagnosable))
	}
}

// ── The shared classifier (listener_fault_class.go) ──────────────────────────

// TestChaos71_SharedClassifierMapsEveryFaultClass.
func TestChaos71_SharedClassifierMapsEveryFaultClass(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, "none"},
		{&net.OpError{Op: "listen", Err: syscall.EADDRINUSE}, "port_in_use"},
		{&net.OpError{Op: "listen", Err: syscall.EACCES}, "permission_denied"},
		{&net.OpError{Op: "listen", Err: syscall.EPERM}, "permission_denied"},
		{&net.OpError{Op: "listen", Err: syscall.EADDRNOTAVAIL}, "address_unavailable"},
		{&net.OpError{Op: "listen", Err: syscall.EMFILE}, "descriptors_exhausted"},
		{&net.OpError{Op: "listen", Err: syscall.ENFILE}, "descriptors_exhausted"},
		{errors.New("something else"), "listen_failed"},
		// The CHAOS-66 defect: *net.OpError satisfies net.Error UNCONDITIONALLY,
		// so an unqualified errors.As(&ne) branch reports this as a network
		// fault and makes listen_failed unreachable for any real listen error.
		{&net.OpError{Op: "listen", Err: syscall.EINVAL}, "listen_failed"},
	}
	for _, tc := range cases {
		if got := classifyListenerFault(tc.err); got != tc.want {
			t.Errorf("classifyListenerFault(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// TestChaos71_SharedClassifierVocabularyIsClosed.
//
// These strings reach an alert Detail (the dedup key) and viewer-role surfaces,
// so the set must stay bounded. A class that is returned but not declared would
// slip past the runbook.
func TestChaos71_SharedClassifierVocabularyIsClosed(t *testing.T) {
	declared := map[string]bool{}
	for _, c := range listenerFaultClasses {
		declared[c] = true
	}
	errs := []error{
		nil,
		&net.OpError{Op: "listen", Err: syscall.EADDRINUSE},
		&net.OpError{Op: "listen", Err: syscall.EACCES},
		&net.OpError{Op: "listen", Err: syscall.EPERM},
		&net.OpError{Op: "listen", Err: syscall.EADDRNOTAVAIL},
		&net.OpError{Op: "listen", Err: syscall.EMFILE},
		&net.OpError{Op: "listen", Err: syscall.ENFILE},
		&net.OpError{Op: "listen", Err: syscall.EINVAL},
		&net.OpError{Op: "listen", Err: syscall.ECONNREFUSED},
		errors.New("plain"),
		fmt.Errorf("wrapped: %w", syscall.EADDRINUSE),
	}
	for _, e := range errs {
		if got := classifyListenerFault(e); !declared[got] {
			t.Errorf("classifyListenerFault(%v) returned %q, which is not in listenerFaultClasses", e, got)
		}
	}
}

// TestChaos71_AllThreeListenersAgreeOnTheSharedClasses.
//
// The three planes must speak ONE vocabulary — that is the whole reason the
// mapping was extracted. A divergence means an operator reading one listener's
// runbook is misled about another's, and it is exactly what two verbatim copies
// produced once already (the unqualified network_error branch).
func TestChaos71_AllThreeListenersAgreeOnTheSharedClasses(t *testing.T) {
	errs := []error{
		&net.OpError{Op: "listen", Err: syscall.EADDRINUSE},
		&net.OpError{Op: "listen", Err: syscall.EACCES},
		&net.OpError{Op: "listen", Err: syscall.EADDRNOTAVAIL},
		&net.OpError{Op: "listen", Err: syscall.EMFILE},
		&net.OpError{Op: "listen", Err: syscall.EINVAL},
		errors.New("plain"),
	}
	for _, e := range errs {
		shared := classifyListenerFault(e)
		if got := classifyAdminUIListenError(e); got != shared {
			t.Errorf("admin UI classifier diverged on %v: %q vs shared %q", e, got, shared)
		}
		if got := classifySOCKS5BindError(e); got != shared {
			t.Errorf("SOCKS5 classifier diverged on %v: %q vs shared %q", e, got, shared)
		}
		if got := classifyCPGRPCListenError(e); got != shared {
			t.Errorf("CP gRPC classifier diverged on %v: %q vs shared %q", e, got, shared)
		}
	}

	// Each plane's own pre-check must still win, and must NOT appear in the
	// others' vocabularies — that is the line between shared and per-plane.
	if got := classifyAdminUIListenError(fmt.Errorf("x: %w", errAdminUITLSMaterial)); got != "tls_certificate" {
		t.Errorf("admin UI TLS pre-check = %q, want tls_certificate", got)
	}
	if got := classifyCPGRPCListenError(wrapCPGRPCTLSMaterial(errors.New("bad key"))); got != "tls_material" {
		t.Errorf("CP TLS pre-check = %q, want tls_material", got)
	}
	if got := classifyCPGRPCListenError(fmt.Errorf("x: %w", errAdminUITLSMaterial)); got == "tls_certificate" {
		t.Error("the CP classifier recognises the admin UI's private fault class — per-plane classes must not leak")
	}
}

// ── Structural walls ─────────────────────────────────────────────────────────

// TestChaos71_TheControlPlaneListenerPathHasNoFatal is the wall against
// reintroduction.
//
// Behavioural coverage cannot catch this: a reintroduced logFatalf kills the
// test binary rather than failing an assertion, so the signal would be an
// unexplained package-wide crash rather than a named failure.
//
// It deliberately does NOT cover main.go's `logFatalf("Proxy error")`, which is
// correct and must stay: the proxy IS the product, and a gateway that cannot
// serve must exit loudly rather than linger as a black hole. The asymmetry
// between the cluster control plane and the primary data plane is the finding.
func TestChaos71_TheControlPlaneListenerPathHasNoFatal(t *testing.T) {
	files := []string{"cluster_startup.go", "cp_grpc_supervisor.go", "cp_grpc_health.go", "controlplane_server.go"}
	checked, allowed := 0, 0
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			code, _, _ := strings.Cut(line, "//")
			checked++
			if !strings.Contains(code, "logFatalf(") && !strings.Contains(code, "log.Fatal") {
				continue
			}
			// THE ONE ALLOWANCE, and it is self-checking: the HA fencing-lease
			// arming fatal is CORRECT and must stay, so the gate must not
			// demand its removal — but the allowance must not become a hole
			// that covers a re-added listener fatal either.
			//
			// Why that fatal is right and this one is not, which is the whole
			// asymmetry: armHALease fails only on config validation (a TTL
			// below the minimum) and client CONSTRUCTION (TLS material, etcd
			// client build) — never on etcd REACHABILITY, which is lazily
			// denied leadership instead. So it is a deterministic
			// misconfiguration that cannot self-heal, and degrading past it
			// would mean silently running UNFENCED after the operator
			// explicitly asked for fencing: an invisible safety downgrade, and
			// a split-brain risk. A bind fault is the opposite on both counts —
			// environmental, self-healing, and degrading costs only the
			// subsystem.
			//
			// The allowance is pinned to the lease-arming call specifically. A
			// logFatalf on any other line, or one whose argument stops naming
			// the lease, fails the gate.
			if strings.Contains(code, `logFatalf("HA lease:`) {
				allowed++
				continue
			}
			t.Errorf("%s:%d reintroduces a fatal on the Control Plane listener path: %s",
				f, i+1, strings.TrimSpace(line))
		}
	}
	// Not-vacuous checks. Without the first, a selector that stops matching
	// real files would pass forever while proving nothing. Without the second,
	// the allowance could silently stop corresponding to anything — if the
	// lease fatal is ever removed or renamed, this gate must be revisited
	// deliberately rather than carrying a dead exemption.
	if checked < 500 {
		t.Fatalf("the fatal scan only examined %d lines — it is not reading the listener sources", checked)
	}
	if allowed != 1 {
		t.Fatalf("expected exactly 1 allowed fatal (the HA fencing-lease arming), found %d — "+
			"the allowance no longer corresponds to the code it was written for", allowed)
	}
}

// TestChaos71_CPServerOptionDoesNotLog is the wall for a defect this change
// INTRODUCED and then fixed, and it needs a structural gate because behavioural
// coverage cannot see it: on a healthy bind the function runs once and the
// flood never appears.
//
// cpServerOption used to emit the mTLS line (or the insecure WARN) itself,
// which was correct while it was reached exactly once per boot. The
// bind/serve/rebind loop reaches it on EVERY attempt, so a persistently
// unbindable CP emitted one line per retry — forever, one per 30 s at the
// ceiling. Measured against the real binary before the fix: three WARN lines in
// the first seven seconds of a failing bind.
//
// That is this repository's own standing rule broken by the change that
// introduced the loop: a mitigation for a crash loop must not itself be a log
// flood. The rate-limited line in the supervisor is the only one allowed on the
// failure path.
func TestChaos71_CPServerOptionDoesNotLog(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "controlplane_server.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var found *ast.FuncDecl
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "cpServerOption" {
			found = fn
			break
		}
	}
	if found == nil {
		t.Fatal("cpServerOption not found — the wall is not reading what it claims to")
	}
	logCalls := 0
	ast.Inspect(found.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch f := call.Fun.(type) {
		case *ast.Ident:
			name = f.Name
		case *ast.SelectorExpr:
			if x, ok := f.X.(*ast.Ident); ok {
				name = x.Name + "." + f.Sel.Name
			}
		}
		if strings.HasPrefix(name, "logger.") || name == "logWarnf" || name == "logErrorf" ||
			strings.HasPrefix(name, "log.") {
			logCalls++
			t.Errorf("cpServerOption calls %s — it is reached on EVERY bind attempt, so a persistently "+
				"unbindable Control Plane turns this into one log line per retry forever", name)
		}
		return true
	})
	_ = logCalls
}

// TestChaos71_WallTheClassifierIsSharedNotCopied.
//
// The mapping was extracted because two verbatim copies already shared a defect
// that had to be fixed in both; a fourth copy would be the same trap again. The
// gate asserts each plane's classifier DELEGATES rather than re-spelling the
// errno switch, which is a property no behavioural test can see — a fresh copy
// that happens to be correct today passes every agreement test above.
func TestChaos71_WallTheClassifierIsSharedNotCopied(t *testing.T) {
	targets := map[string]string{
		"admin_ui_health.go": "classifyAdminUIListenError",
		"socks5_health.go":   "classifySOCKS5BindError",
		"cp_grpc_health.go":  "classifyCPGRPCListenError",
	}
	for file, fnName := range targets {
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		var fn *ast.FuncDecl
		for _, d := range parsed.Decls {
			if f, ok := d.(*ast.FuncDecl); ok && f.Name.Name == fnName {
				fn = f
				break
			}
		}
		if fn == nil {
			t.Fatalf("%s: %s not found — the wall is not reading what it claims to", file, fnName)
		}

		delegates := false
		errnoSwitch := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "classifyListenerFault" {
					delegates = true
				}
			}
			// A re-spelled copy is recognisable by matching syscall.E* in a
			// switch body.
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == "syscall" && strings.HasPrefix(sel.Sel.Name, "E") {
					errnoSwitch = true
				}
			}
			return true
		})
		if !delegates {
			t.Errorf("%s: %s does not call classifyListenerFault — a per-plane copy of the errno mapping is "+
				"how the two existing copies came to share a defect", file, fnName)
		}
		if errnoSwitch {
			t.Errorf("%s: %s re-spells the syscall.E* mapping instead of delegating to the shared classifier",
				file, fnName)
		}
	}
}

// scrapeMetricsForCPTest renders /metrics into a string.
func scrapeMetricsForCPTest(t *testing.T) string {
	t.Helper()
	rec := httptest.NewRecorder()
	handleMetrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}
