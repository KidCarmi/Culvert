package main

// cp_grpc_activation_chaos_test.go — CHAOS-71 gates for commitActivation, the
// ONE post-bind activation step (cp_grpc_activation.go). One gate per face of
// the Codex review of #1556 (activation became ASYNCHRONOUS, so it raced
// everything that changed since boot). Each is deterministic: the race is
// opened by an injected hook or a pre-set flag, never by a sleep, and each was
// verified failing with its guard removed.

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// cpInjectPublish swaps the CP-address publish for fn.
func cpInjectPublish(t *testing.T, fn func() (bool, error)) {
	t.Helper()
	prev := cpPublishCPAddresses
	cpPublishCPAddresses = fn
	t.Cleanup(func() { cpPublishCPAddresses = prev })
}

// cpRoleNow reads clusterRole.role under its lock.
func cpRoleNow() string {
	clusterRoleMu.RLock()
	defer clusterRoleMu.RUnlock()
	return clusterRole.role
}

// cpRequirePortReleased asserts the listener the supervisor built was closed.
// No wait is needed: on every non-serve path Serve never ran, and ln.Close is
// synchronous.
func cpRequirePortReleased(t *testing.T, addr string) {
	t.Helper()
	probe, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatalf("the refused activation left %s bound: %v", addr, err)
	}
	_ = probe.Close()
}

// TestChaos71_ActivationPublishFailureIsNotASuccess — Codex P1 (4292927421).
// When the CP-address publish is rejected at commit (e.g. a near-cap snapshot
// pushed over the wire budget by the added address), activation must NOT
// report success: the runtime/promote path returns the error, no role stays
// claimed, onActivated does not run, and the boot path records a RETRYING
// failure (not success, not terminal) so the supervisor tries again.
func TestChaos71_ActivationPublishFailureIsNotASuccess(t *testing.T) {
	rejected := errors.New("config snapshot wire size=99 bytes exceeds budget 98")

	t.Run("runtime_path_refuses", func(t *testing.T) {
		cpChaosSetup(t)
		cpInsecure(t)
		cpInjectPublish(t, func() (bool, error) { return false, rejected })
		var resumed atomic.Int32
		addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))

		sup, err := cpStartSupervised(t, cpListenerConfig{addr: addr}, false, func() { resumed.Add(1) })
		if err == nil || sup != nil {
			t.Fatalf("activation reported success although the address publish was rejected (sup=%v err=%v) — "+
				"a promotion would leave Data Planes with only the dead leader's address", sup, err)
		}
		if !strings.Contains(err.Error(), "address_publish_rejected") {
			t.Errorf("the refusal does not name the publish rejection: %v", err)
		}
		if r := cpRoleNow(); r == "control-plane" {
			t.Error("the CP role stayed claimed after its address publish was rejected")
		}
		if resumed.Load() != 0 {
			t.Error("onActivated ran although activation failed")
		}
		cpRequirePortReleased(t, addr)
	})

	t.Run("boot_path_retries", func(t *testing.T) {
		cpChaosSetup(t)
		cpInsecure(t)
		cpInjectPublish(t, func() (bool, error) { return false, rejected })
		var resumed atomic.Int32
		addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))

		if _, err := cpStartSupervised(t, cpListenerConfig{addr: addr}, true, func() { resumed.Add(1) }); err != nil {
			t.Fatalf("boot path: %v", err)
		}
		snap := cpGRPCListenerState()
		if snap.Serving || !snap.Failing || snap.SupervisorDown || snap.LastReason != "address_publish_rejected" {
			t.Errorf("a rejected publish must be a RETRYING failure: serving=%v failing=%v supervisorDown=%v reason=%q",
				snap.Serving, snap.Failing, snap.SupervisorDown, snap.LastReason)
		}
		if r := cpRoleNow(); r == "control-plane" || resumed.Load() != 0 {
			t.Errorf("role=%q resumed=%d after a rejected publish, want no role and no resume", r, resumed.Load())
		}
	})
}

// TestChaos71_AddressPublishMergesOntoTheLatestCommit — Codex P1 (4292927411).
// The pre-fix republish built a FULL CurrentConfigSnapshot() and Update()d it,
// so an admin publish committing in between was rolled back at a higher
// version. UpdateCPAddresses merges onto the latest COMMITTED snapshot under
// the store's own commit lock: a competing commit inside its window forces a
// re-merge onto it. The race is opened deterministically by the seam.
func TestChaos71_AddressPublishMergesOntoTheLatestCommit(t *testing.T) {
	s := &ConfigStore{}
	if err := s.Update(ConfigSnapshot{BlockedHosts: []string{"old.example"}}); err != nil {
		t.Fatalf("seed publish: %v", err)
	}
	stale := s.Get() // what the pre-fix republish would have captured

	admin := ConfigSnapshot{BlockedHosts: []string{"old.example", "admin-added.example"}}
	fired := false
	cpAddrMergeBeforeCommit = func() {
		if !fired {
			fired = true
			if err := s.Update(admin); err != nil {
				t.Errorf("admin publish: %v", err)
			}
		}
	}
	t.Cleanup(func() { cpAddrMergeBeforeCommit = nil })

	changed, err := s.UpdateCPAddressesFrom(func() []string { return []string{"10.0.0.2:50051"} })
	if err != nil || !changed {
		t.Fatalf("UpdateCPAddresses: changed=%v err=%v", changed, err)
	}
	got := s.Get()
	if !cpListNames(got.BlockedHosts, "admin-added.example") {
		t.Errorf("the address publish rolled back the admin publish that committed in its window: hosts=%v", got.BlockedHosts)
	}
	if !cpListNames(got.CPAddresses, "10.0.0.2:50051") {
		t.Errorf("the address list was lost: %v", got.CPAddresses)
	}
	if got.Version != 3 {
		t.Errorf("version = %d, want 3 (seed, admin, merged address list)", got.Version)
	}

	// Negative control — the pre-fix SHAPE (a full publish of a snapshot
	// captured before the admin commit) really does roll the admin change back,
	// so the assertion above is not vacuous.
	stale.CPAddresses = []string{"10.0.0.2:50051"}
	if err := s.Update(stale); err != nil {
		t.Fatalf("stale publish: %v", err)
	}
	if cpListNames(s.Get().BlockedHosts, "admin-added.example") {
		t.Fatal("negative control: a full publish of a stale snapshot did not roll back — the merge gate proves nothing")
	}
}

// TestChaos71_AddressPublishIsANoOpWhenUnchangedOrUnpublished pins the two
// no-publish branches: nothing committed yet (nothing to correct — and merging
// onto a zero snapshot would publish an EMPTY config), and an unchanged list
// (an ordinary rebind must not spend a config version).
func TestChaos71_AddressPublishIsANoOpWhenUnchangedOrUnpublished(t *testing.T) {
	s := &ConfigStore{}
	a1 := func() []string { return []string{"a:1"} }
	if changed, err := s.UpdateCPAddressesFrom(a1); changed || err != nil {
		t.Fatalf("unpublished store: changed=%v err=%v, want a no-op", changed, err)
	}
	if err := s.Update(ConfigSnapshot{CPAddresses: []string{"a:1"}}); err != nil {
		t.Fatal(err)
	}
	if changed, err := s.UpdateCPAddressesFrom(a1); changed || err != nil || s.Version() != 1 {
		t.Fatalf("unchanged list: changed=%v err=%v version=%d, want a no-op at v1", changed, err, s.Version())
	}
}

// TestChaos71_ShutdownBeforeActivationAbortsTheClaim — Codex P1 (4292927436).
// Shutdown closes the activation gate in the ha-stop hook (order 10) BEFORE the
// supervisor is stopped (order 20). A bind adopted after that must neither
// claim the role nor run onActivated (the HA resume would re-acquire the lease
// after globalHA.Stop was joined), and must release its socket.
func TestChaos71_ShutdownBeforeActivationAbortsTheClaim(t *testing.T) {
	t.Run("gate_closed_before_the_claim", func(t *testing.T) {
		cpChaosSetup(t)
		cpInsecure(t)
		var resumed atomic.Int32
		addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))

		beginCPActivationShutdown()
		if _, err := cpStartSupervised(t, cpListenerConfig{addr: addr}, true, func() { resumed.Add(1) }); err != nil {
			t.Fatalf("boot path: %v", err)
		}
		if resumed.Load() != 0 || cpRoleNow() == "control-plane" {
			t.Fatalf("a bind adopted after shutdown began claimed the role (%q) or ran onActivated (%d)", cpRoleNow(), resumed.Load())
		}
		cpRequirePortReleased(t, addr)
	})

	t.Run("gate_closed_between_claim_and_onActivated", func(t *testing.T) {
		cpChaosSetup(t)
		cpInsecure(t)
		var resumed atomic.Int32
		addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
		// Shutdown begins after the role is claimed but before the gated
		// publish/onActivated step: the gate's re-check must catch it, and
		// NEITHER the address publish nor onActivated may run.
		var published atomic.Int32
		cpInjectPublish(t, func() (bool, error) {
			published.Add(1)
			return false, nil
		})
		cpActivationAfterClaim = beginCPActivationShutdown
		t.Cleanup(func() { cpActivationAfterClaim = nil })

		if _, err := cpStartSupervised(t, cpListenerConfig{addr: addr}, true, func() { resumed.Add(1) }); err != nil {
			t.Fatalf("boot path: %v", err)
		}
		if resumed.Load() != 0 {
			t.Fatal("onActivated ran after shutdown had begun — the HA resume could re-acquire the fencing lease during teardown")
		}
		if published.Load() != 0 {
			t.Error("the CP address list was published after shutdown had begun — the fleet would be told a dying node is its Control Plane")
		}
		if r := cpRoleNow(); r == "control-plane" {
			t.Error("the role claimed before shutdown began was not rolled back")
		}
		cpRequirePortReleased(t, addr)
	})

	t.Run("in_flight_onActivated_runs_outside_the_gate", func(t *testing.T) {
		cpChaosSetup(t)
		cpInsecure(t)
		addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
		var gateFree, ran atomic.Bool
		// The reverse of the earlier contract (Codex review of #1556): the boot
		// onActivated is the HA resume, whose lease wait can outlast the
		// shutdown watchdog, so it must NOT hold the gate the ha-stop hook
		// takes. Its shutdown safety is the HA shutdown latch instead
		// (TestChaos71_ShutdownInsideTheGhostWaitAbortsTheResume).
		onActivated := func() {
			ran.Store(true)
			if cpActivationGateMu.TryLock() {
				cpActivationGateMu.Unlock()
				gateFree.Store(true)
			}
		}
		if _, err := cpStartSupervised(t, cpListenerConfig{addr: addr}, true, onActivated); err != nil {
			t.Fatalf("boot path: %v", err)
		}
		if !ran.Load() {
			t.Fatal("onActivated did not run on the first bind")
		}
		if !gateFree.Load() {
			t.Error("onActivated ran HOLDING the activation gate — a resume waiting on the fencing backend would block the ha-stop hook past its watchdog")
		}
	})
}

// TestChaos71_DelayedBindNeverReplacesAnEstablishedRole — Codex P2 (4292927446).
// A CP whose first bind failed lets boot continue into Data-Plane wiring; a
// later successful retry must not overwrite `data-plane` (the DP client keeps
// running, and isManagedDataPlane would flip false). It is refused, raised as
// the listener-down alert, and the supervisor stops.
func TestChaos71_DelayedBindNeverReplacesAnEstablishedRole(t *testing.T) {
	alerts := cpChaosSetup(t)
	cpInsecure(t)
	clusterRoleMu.Lock()
	clusterRole.role = "data-plane"
	clusterRoleMu.Unlock()
	var resumed atomic.Int32
	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))

	sup, err := cpStartSupervised(t, cpListenerConfig{addr: addr}, true, func() { resumed.Add(1) })
	if err != nil {
		t.Fatalf("boot path: %v", err)
	}
	if r := cpRoleNow(); r != "data-plane" {
		t.Fatalf("a delayed CP bind replaced the established data-plane role with %q", r)
	}
	if !isManagedDataPlane() {
		t.Error("isManagedDataPlane flipped false — the node would accept CP-authoritative local mutations while still consuming remote config")
	}
	if resumed.Load() != 0 {
		t.Error("onActivated ran for a refused activation")
	}
	snap := cpGRPCListenerState()
	if !snap.SupervisorDown || snap.LastReason != "role_conflict" || !snap.Unavailable {
		t.Errorf("the refusal is not reported as a terminal listener-down state: %+v", snap)
	}
	if len(alerts()) == 0 {
		t.Error("the refused activation raised no cp_grpc_listener_down alert")
	}
	// The supervisor exits on its own. The starter is released by the loop's
	// deferred markFirstAttempt, which runs just BEFORE the deferred close(done),
	// so wait for done (bounded) rather than assume it is already closed.
	select {
	case <-sup.done:
	case <-time.After(5 * time.Second):
		t.Error("the supervisor is still running after refusing to replace the role")
	}
	cpRequirePortReleased(t, addr)
}

// TestChaos71_RejectedRuntimeActivationLeavesThePlaneUnconfigured — Codex P2
// (4292927456). The 409 says no Control Plane exists; the health plane must
// agree, as it read before the attempt — not `stopped` (shutting down), not a
// dropped readiness row, not `up 0`. Lifetime counters survive (a Prometheus
// counter must never go backwards).
func TestChaos71_RejectedRuntimeActivationLeavesThePlaneUnconfigured(t *testing.T) {
	cpChaosSetup(t)
	cpInsecure(t)
	port, release := occupyPort(t)
	defer release()

	if _, err := cpStartSupervised(t, cpListenerConfig{addr: fmt.Sprintf("127.0.0.1:%d", port)}, false, nil); err == nil {
		t.Fatal("runtime activation against an occupied port succeeded")
	}
	snap := cpGRPCListenerState()
	if snap.Configured || snap.Stopped {
		t.Errorf("a refused runtime activation left configured=%v stopped=%v — /health would report %q for a node that is not a Control Plane",
			snap.Configured, snap.Stopped, cpGRPCHealthPosture())
	}
	if got := cpGRPCHealthPosture(); got != "not_configured" {
		t.Errorf("/health cp_grpc = %q, want not_configured", got)
	}
	if snap.Total == 0 {
		t.Error("the failed attempt was erased from the lifetime counter")
	}
}

// TestChaos71_ClusterRoleArbiter_CPClaimFirstRefusesTheDataPlane — Codex P2
// (4293559910), ordering 1: the CP supervisor's retried bind claims the role
// BEFORE boot reaches Data-Plane wiring. startDataPlane must then be refused —
// pre-fix it did UNLOCKED writes that replaced role and gRPC address with DP
// values while the CP listener, heartbeat monitor and HA leadership stayed
// live. Deterministic: the claim is driven to completion first, then the real
// startDataPlane entry point runs.
func TestChaos71_ClusterRoleArbiter_CPClaimFirstRefusesTheDataPlane(t *testing.T) {
	cpChaosSetup(t)
	cpInsecure(t)
	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	if _, err := cpStartSupervised(t, cpListenerConfig{addr: addr}, true, nil); err != nil {
		t.Fatalf("boot path: %v", err)
	}
	if r := cpRoleNow(); r != "control-plane" {
		t.Fatalf("precondition: the CP claim did not land (role %q)", r)
	}

	startDataPlane(t.Context(), "10.9.9.9:50051", "dp-node", "", "", "")

	clusterRoleMu.RLock()
	role, gotAddr := clusterRole.role, clusterRole.grpcAddr
	clusterRoleMu.RUnlock()
	if role != "control-plane" || gotAddr != addr {
		t.Fatalf("startDataPlane replaced a live Control Plane's role/address with (%q, %q) — the node would "+
			"consume DP config while still serving as a CP", role, gotAddr)
	}
	if !cpGRPCListenerState().Serving {
		t.Error("the CP listener stopped serving after the refused Data Plane claim")
	}
	if c := checkClusterPosture(); c.Status != diagFail || !strings.Contains(c.Message, "data-plane role was refused") {
		t.Errorf("the refused Data Plane claim is not operator-visible: cluster_posture = %s %q", c.Status, c.Message)
	}
}

// TestChaos71_ClusterRoleArbiter_DPClaimFirstRefusesTheDelayedCP — ordering 2:
// the Data Plane claimed first (the CP's first bind failed), then the delayed
// CP bind succeeds. The arbiter refuses the CP (supervisor stops,
// role_conflict, alert) and the conflict is latched for diagnostics.
func TestChaos71_ClusterRoleArbiter_DPClaimFirstRefusesTheDelayedCP(t *testing.T) {
	alerts := cpChaosSetup(t)
	cpInsecure(t)
	if _, err := claimDataPlaneRole("10.9.9.9:50051", "dp-node"); err != nil {
		t.Fatalf("precondition: DP claim: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	if _, err := cpStartSupervised(t, cpListenerConfig{addr: addr}, true, nil); err != nil {
		t.Fatalf("boot path: %v", err)
	}
	clusterRoleMu.RLock()
	role, gotAddr := clusterRole.role, clusterRole.grpcAddr
	clusterRoleMu.RUnlock()
	if role != "data-plane" || gotAddr != "10.9.9.9:50051" {
		t.Fatalf("the delayed CP claim replaced the Data Plane's role/address with (%q, %q)", role, gotAddr)
	}
	if snap := cpGRPCListenerState(); snap.LastReason != "role_conflict" || !snap.SupervisorDown {
		t.Errorf("the refused CP claim is not reported terminal: %+v", snap)
	}
	if len(alerts()) == 0 {
		t.Error("no cp_grpc_listener_down alert for the refused CP claim")
	}
	if c := checkClusterPosture(); c.Status != diagFail || !strings.Contains(c.Message, "control-plane role was refused") {
		t.Errorf("cluster_posture = %s %q, want a FAIL naming the refused control-plane claim", c.Status, c.Message)
	}
	cpRequirePortReleased(t, addr)
}

// TestChaos71_Wall_ClusterRoleIsWrittenOnlyByTheArbiter: no production file
// other than cluster_role_arbiter.go may assign clusterRole.role, its
// advertised grpcAddr, or the identity fields that travel with them — and no
// file may replace the whole struct. A direct write elsewhere is how
// startDataPlane overwrote a live Control Plane. Test files are exempt (they
// stage state deliberately and restore it).
func TestChaos71_Wall_ClusterRoleIsWrittenOnlyByTheArbiter(t *testing.T) {
	guarded := map[string]bool{"role": true, "grpcAddr": true, "nodeID": true, "certFile": true, "keyFile": true, "caFile": true}
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	arbiterWrites := 0
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
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, lhs := range as.Lhs {
				if !cpIsClusterRoleWrite(lhs, guarded) {
					continue
				}
				if name == "cluster_role_arbiter.go" {
					arbiterWrites++
					continue
				}
				t.Errorf("%s: writes the cluster role outside the arbiter — claim it through "+
					"cluster_role_arbiter.go so an already-claimed role is never silently replaced", fset.Position(lhs.Pos()))
			}
			return true
		})
	}
	if arbiterWrites < 6 {
		t.Fatalf("the wall found only %d role writes in the arbiter — its selector has gone stale", arbiterWrites)
	}
}

// cpIsClusterRoleWrite reports whether an assignment target is clusterRole
// itself or one of its guarded fields.
func cpIsClusterRoleWrite(lhs ast.Expr, guarded map[string]bool) bool {
	if id, ok := lhs.(*ast.Ident); ok {
		return id.Name == "clusterRole"
	}
	sel, ok := lhs.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "clusterRole" && guarded[sel.Sel.Name]
}
