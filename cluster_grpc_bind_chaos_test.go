package main

// cluster_grpc_bind_chaos_test.go — CHAOS-71 gates.
//
// The finding: the boot path used to `logFatalf` on any failure to activate the
// Control Plane gRPC listener, which exited the process from `initCluster` —
// before the proxy, the admin UI, SOCKS5 and every health endpoint exist. See
// cluster_grpc_bind.go for the reproduction against the real binary.
//
// Two notes on how these gates are built, both learned the expensive way by
// earlier sweeps in this family:
//
//   - THE HEADLINE DEFECT CANNOT BE GATED BEHAVIOURALLY. A reintroduced
//     `logFatalf` calls os.Exit(1) and kills the TEST BINARY rather than
//     failing an assertion, so the signal would be an unexplained package-wide
//     crash instead of a named failure (CHAOS-57 recorded exactly this). The
//     structural wall at the bottom of this file names it instead, and carries
//     its own not-vacuous check.
//
//   - THE READ CLOCK IS FROZEN for every gate. CHAOS-66's round-3 determinism
//     finding: giving the health snapshot a clock while gates drive the write
//     path with synthetic stamps mixes two clocks, and `cpGRPCElapsed`'s max()
//     lets the real one dominate — so a gate recording failures 19 s apart
//     synthetically and asserting "not yet unavailable" would invisibly also be
//     asserting that under 30 s of WALL time passed between two of its own
//     statements. True locally in milliseconds, false on a loaded shared runner
//     under -count=2. A gate that wants an episode to AGE advances the injected
//     clock explicitly, as the condition under test.

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// ── Harness ──────────────────────────────────────────────────────────────────

// cpChaosSetup isolates the process-global records this file writes and FREEZES
// the read clock (see the file header).
func cpChaosSetup(t *testing.T) *time.Time {
	t.Helper()
	resetCPGRPCHealthForTest()

	frozen := time.Date(2026, 10, 2, 22, 0, 0, 0, time.UTC)
	prevNow := cpGRPCHealthNow
	cpGRPCHealthNow = func() time.Time { return frozen }

	// `enableControlPlane` starts the cluster heartbeat monitor on
	// appLifecycleCtx.Done(), and a test binary never ran initLifecycleContext
	// — so without this a healthy activation nil-panics. It is a harness
	// artifact, not a production hazard: main.go runs initLifecycleContext at
	// line 216 of the init block and initCluster at 228, so the context is
	// always live on every path that reaches activation (boot, the admin API,
	// and the HA promote callback). Found by the healthy-boot CONTROL, which is
	// the only gate that gets far enough to call it — the defect gates all stop
	// at a failed bind.
	if appLifecycleCtx == nil {
		ctx, cancel := context.WithCancel(context.Background())
		appLifecycleCtx = ctx
		t.Cleanup(func() {
			cancel()
			appLifecycleCtx = nil
		})
	}

	prevAlert := fireCPGRPCUnavailableAlert
	prevRole := clusterRole.role
	prevAddr := clusterRole.grpcAddr
	prevSrv := clusterRole.grpcSrv
	prevSup := clusterRole.grpcSupervisor
	clusterRole.role = "standalone"

	t.Cleanup(func() {
		cpGRPCHealthNow = prevNow
		fireCPGRPCUnavailableAlert = prevAlert

		// Stop any gRPC server that appeared DURING this test before restoring
		// the previous handle, or the socket and its heartbeat monitor outlive
		// the test with nothing holding a pointer to stop them. Gates that call
		// `enableControlPlane` / `StartControlPlaneGRPC` directly (rather than
		// through cpStartSupervised) bind a real listener, so restoring the
		// handle without stopping it leaks one listener per run — which bites
		// under -count=2 and -shuffle, where it is also the harder failure to
		// read. CLAUDE.md's rule for setupProxyTest, one file over: a PARTIAL
		// cleanup is worse than none.
		clusterRoleMu.Lock()
		if clusterRole.grpcSrv != nil && clusterRole.grpcSrv != prevSrv {
			clusterRole.grpcSrv.Stop()
		}
		clusterRole.role = prevRole
		clusterRole.grpcAddr = prevAddr
		clusterRole.grpcSrv = prevSrv
		clusterRole.grpcSupervisor = prevSup
		clusterRoleMu.Unlock()

		resetCPGRPCHealthForTest()
	})
	return &frozen
}

// cpOccupyPort binds an ephemeral port and holds it, returning the port and a
// release func. The supervisor under test is then given an address the kernel
// will refuse — the real `port_in_use` fault, not a simulated error.
func cpOccupyPort(t *testing.T) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy a port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	var once sync.Once
	return port, func() { once.Do(func() { _ = ln.Close() }) }
}

// cpStartSupervised starts the real production entry point and guarantees it is
// stopped when the test ends, so a gate can never leak a retry loop into the
// next test.
func cpStartSupervised(t *testing.T, cfg clusterStartupConfig) *cpGRPCSupervisor {
	t.Helper()
	s := startControlPlaneSupervised(cfg, context.Background())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Stop(ctx)
		// The listener itself is stopped by cpChaosSetup's cleanup, which runs
		// after this one (t.Cleanup is LIFO) and owns restoring the handle. Two
		// places stopping it would be a double-Stop; grpc tolerates that, but
		// one owner is the point.
	})
	return s
}

// cpWaitFor polls cond until it holds or the deadline passes.
func cpWaitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", d, what)
}

// cpBindErr builds a bind error in the exact shape the net package produces:
// *net.OpError wrapping *os.SyscallError wrapping a syscall.Errno. Matching the
// real wrapping matters — classifyCPGRPCBindError uses errors.As, and a gate
// that handed it a bare Errno would not prove it sees through the wrapper the
// kernel path actually produces.
func cpBindErr(errno syscall.Errno) error {
	return &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", errno)}
}

// cpInsecureCfg is a Control Plane config that needs no certificates, so a gate
// exercises the socket path rather than the TLS one.
func cpInsecureCfg(t *testing.T, addr string) clusterStartupConfig {
	t.Helper()
	prev := clusterInsecure
	clusterInsecure = true
	t.Cleanup(func() { clusterInsecure = prev })
	return clusterStartupConfig{CPAddr: addr, ClusterDBPath: t.TempDir() + "/cluster.json"}
}

// ── DEFECT GATES ─────────────────────────────────────────────────────────────

// TestChaos71_BindFailureIsNotFatal is the headline behavioural gate.
//
// Reaching the end of this function at all is half the assertion: against the
// pre-fix shape `startControlPlaneWithHAResume` calls logFatalf → os.Exit(1)
// and the test binary dies, failing this and every other test in the package.
func TestChaos71_BindFailureIsNotFatal(t *testing.T) {
	cpChaosSetup(t)
	port, release := cpOccupyPort(t)
	defer release()

	cfg := cpInsecureCfg(t, fmt.Sprintf("127.0.0.1:%d", port))
	if s := cpStartSupervised(t, cfg); s == nil {
		t.Fatal("startControlPlaneSupervised returned no handle for an unbindable address")
	}

	snap := cpGRPCListenerState()
	if !snap.Failing {
		t.Error("an unbindable Control Plane listener is not recorded as failing")
	}
	if snap.LastReason != "port_in_use" {
		t.Errorf("reason = %q, want %q", snap.LastReason, "port_in_use")
	}
	if snap.EverBound {
		t.Error("a listener that never bound is recorded as having bound")
	}
}

// TestChaos71_RoleIsNotAssertedWithoutAnObservedBind is the gate that keeps the
// FIX from being worse than the defect — CHAOS-71 rule 3.
//
// A node that claims the control-plane role while serving no gRPC is a black
// hole for config distribution AND, in legacy ADR-0004 mode (no etcd fence),
// lets the standby's auto-failover promote as well, because the standby cannot
// reach it. That is a SPLIT BRAIN introduced by the change that removes an
// outage. The old fatal happened to prevent it, so the exit was load-bearing
// for a reason that has nothing to do with why it was written.
func TestChaos71_RoleIsNotAssertedWithoutAnObservedBind(t *testing.T) {
	cpChaosSetup(t)
	port, release := cpOccupyPort(t)
	defer release()

	cpStartSupervised(t, cpInsecureCfg(t, fmt.Sprintf("127.0.0.1:%d", port)))

	clusterRoleMu.RLock()
	role := clusterRole.role
	clusterRoleMu.RUnlock()
	if role == "control-plane" {
		t.Error("a node whose gRPC listener never bound took the control-plane role — a standby's auto-failover would now produce two leaders")
	}
	if snap := cpGRPCListenerState(); snap.RoleAsserted {
		t.Error("roleAsserted is set for a listener that never bound")
	}
}

// TestChaos71_ConfiguredIsRecordedBeforeTheFirstAttempt pins the observability
// half of the fix.
//
// noteCPGRPCConfigured gates EVERY surface in cluster_grpc_health.go. Recorded
// after a successful bind, a Control Plane whose listener has never come up
// reports "Not a Control Plane", which is byte-identical to the ordinary
// standalone appliance — the wrong answer on precisely the node where an
// operator is trying to find out why the fleet stopped syncing. CHAOS-66 moved
// the equivalent SOCKS5 call for the same reason.
func TestChaos71_ConfiguredIsRecordedBeforeTheFirstAttempt(t *testing.T) {
	cpChaosSetup(t)
	port, release := cpOccupyPort(t)
	defer release()

	cpStartSupervised(t, cpInsecureCfg(t, fmt.Sprintf("127.0.0.1:%d", port)))

	snap := cpGRPCListenerState()
	if !snap.Configured {
		t.Fatal("a Control Plane whose listener never bound reports as not configured — indistinguishable from a standalone appliance")
	}
	if got := checkCPGRPCListener(); got.Status == diagOK {
		t.Errorf("the contract row is ok for a Control Plane that is not serving: %+v", got)
	}
}

// TestChaos71_FirstAttemptResolvesBeforeStartReturns pins rule 4.
//
// Without it `configured` is true while the supervisor goroutine has not run
// yet, and in that window every surface describes a Control Plane that does not
// exist: /health says `ready`, the readiness row says `ok`, the contract row
// says "serving", and culvert_cluster_grpc_up reads 1 — with no socket bound.
// Reporting the window accurately would be the weaker fix; better not to have
// it.
func TestChaos71_FirstAttemptResolvesBeforeStartReturns(t *testing.T) {
	cpChaosSetup(t)
	port, release := cpOccupyPort(t)
	defer release()

	cpStartSupervised(t, cpInsecureCfg(t, fmt.Sprintf("127.0.0.1:%d", port)))

	// No polling: the claim is that the state is already written when
	// startControlPlaneSupervised RETURNS, so observing it after a wait would
	// prove nothing about the window.
	snap := cpGRPCListenerState()
	if snap.Total == 0 {
		t.Fatal("startControlPlaneSupervised returned before its first attempt resolved — every surface described a listener that does not exist")
	}
	if snap.Serving {
		t.Error("a listener that has never bound is reported as serving")
	}
	if cpGRPCListenerStatus() == "ready" {
		t.Error("/health reports ready for a Control Plane that never bound")
	}
}

// TestChaos71_PrepareRunsOncePerSupervisor pins rule 7.
//
// `enableControlPlane`'s pre-bind work arms the durable config-version floor,
// publishes an initial snapshot and initialises the cluster CA — each of which
// emits a log line. Re-running it per retry would be exactly the log flood the
// bind-failure rate limiting exists to prevent, and would rewrite the version
// floor once per attempt for no benefit.
//
// Counted through the `cpPrepareFn` seam rather than by reading the
// supervisor's private flag, which only the supervisor goroutine writes and
// would be a data race to observe.
func TestChaos71_PrepareRunsOncePerSupervisor(t *testing.T) {
	cpChaosSetup(t)
	port, release := cpOccupyPort(t)
	defer release()

	var prepares atomic.Int64
	prev := cpPrepareFn
	cpPrepareFn = func(string) { prepares.Add(1) }
	t.Cleanup(func() { cpPrepareFn = prev })

	cpStartSupervised(t, cpInsecureCfg(t, fmt.Sprintf("127.0.0.1:%d", port)))

	// Wait for several attempts, so the count is observed after retries rather
	// than after the first one.
	cpWaitFor(t, 8*time.Second, "a third bind attempt", func() bool {
		return cpGRPCListenerState().Total >= 3
	})
	if got := prepares.Load(); got != 1 {
		t.Errorf("the one-time pre-bind work ran %d times across %d attempts, want 1 — one config publish and one cluster-CA line per retry",
			got, cpGRPCListenerState().Total)
	}
}

// TestChaos71_PrepareRunsWithTheRoleLockReleased is the DEADLOCK gate, and it
// pins a defect this sweep did not introduce.
//
// `prepareControlPlane` calls `CurrentConfigSnapshot()`, which reads the cluster
// role BACK through `buildCPAddressList`'s `clusterRoleMu.RLock()`.
// `sync.RWMutex` is not reentrant, so running it inside the write lock
// deadlocks the goroutine WHILE IT HOLDS THAT LOCK — blocking every reader of
// the cluster role for the life of the process.
//
// `buildCPAddressList` returns early, taking no lock, only when HA is DISABLED
// — so the fault was latent on a standalone CP and CERTAIN on any node with HA
// enabled, which is definitionally the HA PROMOTE path. Reproduced on the
// pre-CHAOS-71 tree.
//
// The gate asserts the MECHANISM (the lock is free when prepare runs) rather
// than timing out on the symptom, because a hang gate is a 10-minute test
// failure with no name attached — which is exactly how this was found, and a
// poor way to find it twice.
func TestChaos71_PrepareRunsWithTheRoleLockReleased(t *testing.T) {
	cpChaosSetup(t)
	port, release := cpOccupyPort(t)
	defer release()

	locked := make(chan bool, 4)
	prev := cpPrepareFn
	cpPrepareFn = func(string) {
		// TryLock on the write lock: it can only succeed if the caller is NOT
		// holding clusterRoleMu in either mode.
		if clusterRoleMu.TryLock() {
			clusterRoleMu.Unlock()
			locked <- false
			return
		}
		locked <- true
	}
	t.Cleanup(func() { cpPrepareFn = prev })

	cpStartSupervised(t, cpInsecureCfg(t, fmt.Sprintf("127.0.0.1:%d", port)))

	select {
	case held := <-locked:
		if held {
			t.Error("the one-time pre-bind work runs while clusterRoleMu is held — CurrentConfigSnapshot re-reads the role through buildCPAddressList and RWMutex is not reentrant, so this deadlocks the process on any node with HA enabled")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the prepare seam was never reached — the gate proves nothing")
	}
}

// TestChaos71_EnableControlPlaneDoesNotDeadlockWithHAEnabled is the same defect
// gate on the ADMIN API and HA-PROMOTE path, which is where it was already
// live before this sweep.
//
// Verified failing against the pre-fix tree, where it hangs for the full
// timeout: a standby promoting itself after a leader failure stopped here,
// holding the cluster-role write lock, with no leader in the cluster — and
// because a deadlock is not a panic, CHAOS-25's promote guard had nothing to
// catch.
func TestChaos71_EnableControlPlaneDoesNotDeadlockWithHAEnabled(t *testing.T) {
	cpChaosSetup(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick a port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	// Status().Enabled is (role != ""), and buildCPAddressList takes the role
	// lock ONLY on that branch — which is why the fault is certain on a
	// promoted standby and merely latent on a standalone CP.
	globalHA.mu.Lock()
	prevRole := globalHA.role
	prevPeer := globalHA.peerAddr
	globalHA.role = "leader"
	globalHA.peerAddr = "10.0.0.9:50051"
	globalHA.mu.Unlock()
	t.Cleanup(func() {
		globalHA.mu.Lock()
		globalHA.role = prevRole
		globalHA.peerAddr = prevPeer
		globalHA.mu.Unlock()
	})
	if !globalHA.Status().Enabled {
		t.Fatal("could not arm HA status — the gate would not reach the locking branch")
	}

	cfg := cpInsecureCfg(t, fmt.Sprintf("127.0.0.1:%d", port))
	done := make(chan error, 1)
	go func() {
		done <- enableControlPlane(cfg.CPAddr, "", "", "", cfg.ClusterDBPath)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("enableControlPlane with HA enabled: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("DEADLOCK: enableControlPlane did not return with HA enabled — the pre-bind config snapshot re-reads the cluster role under a held write lock")
	}

	// And the lock is genuinely free afterwards, which is the property the
	// fleet depends on: every cluster-role reader would otherwise be blocked.
	if !clusterRoleMu.TryLock() {
		t.Error("clusterRoleMu is still held after enableControlPlane returned")
	} else {
		clusterRoleMu.Unlock()
	}
}

// TestChaos71_ListenFailureDoesNotLeakTheGRPCServer pins the rider found while
// reading StartControlPlaneGRPC.
//
// It built and registered a grpc.Server BEFORE binding and returned without
// stopping it when the bind failed. grpc.NewServer spawns no goroutines before
// Serve, so it is a pure memory leak — but it was already reachable from the
// admin API's enable endpoint, and CHAOS-71 adds an AUTOMATIC retry at up to
// one attempt per 30 s, which turns "a few clicks" into ~2880 leaked servers a
// day.
//
// The observable is that the handle is never published: clusterRole.grpcSrv
// must stay nil after a failed bind, which is both the leak's fingerprint (a
// published-but-unserved server) and the invariant StopControlPlaneGRPC relies
// on.
func TestChaos71_ListenFailureDoesNotLeakTheGRPCServer(t *testing.T) {
	cpChaosSetup(t)
	port, release := cpOccupyPort(t)
	defer release()

	// clusterInsecure is REQUIRED here, and its absence is why the first
	// version of this gate was VACUOUS: without it cpServerOption refuses for
	// want of certificates and returns BEFORE grpc.NewServer is called at all,
	// so the gate's `err != nil` precondition held for the wrong reason and the
	// leak assertion was an absence that could not fail. Verified by mutation —
	// the gate passed against a reintroduced `clusterRole.grpcSrv = srv` on the
	// listen-failure path.
	//
	// This is CHAOS-69's standing rule arriving from a new direction: a gate
	// must assert the REFUSAL IT CLAIMS, never merely the absence of what the
	// refusal would have prevented — absence is what an unreached code path and
	// a working guard have in common. Hence the reason-class assertion below:
	// it proves the bind was actually attempted.
	prev := clusterInsecure
	clusterInsecure = true
	t.Cleanup(func() { clusterInsecure = prev })

	clusterRoleMu.Lock()
	clusterRole.grpcSrv = nil
	clusterRoleMu.Unlock()

	err := StartControlPlaneGRPC(fmt.Sprintf("127.0.0.1:%d", port), "", "", "")
	if err == nil {
		t.Fatal("StartControlPlaneGRPC succeeded against an occupied port")
	}
	// Not-vacuous check: the failure must be the SOCKET one, which is the only
	// path on which a server has already been built.
	if got := classifyCPGRPCBindError(err); got != "port_in_use" {
		t.Fatalf("the gate did not reach the bind: classify = %q, want port_in_use (err: %v)", got, err)
	}

	clusterRoleMu.RLock()
	srv := clusterRole.grpcSrv
	clusterRoleMu.RUnlock()
	if srv != nil {
		t.Error("a failed bind published a grpc.Server handle that nothing serves and nothing stops")
	}
	// The published handle is the leak's fingerprint, not the leak itself, so
	// the cleanup call is ALSO pinned structurally — a future change could stop
	// publishing the handle and still forget to stop the server.
	src, rerr := os.ReadFile(filepath.Join(pkgSourceDir(), "controlplane_server.go"))
	if rerr != nil {
		t.Fatalf("read controlplane_server.go: %v", rerr)
	}
	body := string(src)
	i := strings.Index(body, `return fmt.Errorf("gRPC listen: %w", err)`)
	if i < 0 {
		t.Fatal("the listen-failure branch is no longer recognisable — this wall is not reading it")
	}
	// Look back over the branch body only, not the whole function.
	window := body[max(0, i-400):i]
	if !strings.Contains(window, "srv.Stop()") {
		t.Error("the listen-failure branch does not stop the grpc.Server it just built — one leaked registered server per retry, ~2880/day at the backoff ceiling")
	}
}

// TestChaos71_TLSMaterialFailureIsItsOwnReasonClass pins the second reproduced
// trigger.
//
// A certbot / cert-manager / Docker-secret rotation caught mid-write makes the
// mTLS pair momentarily unreadable, and `cpServerOption` loads it at bind time
// — so a rotation window used to be a boot that ended in exit 1 with no port
// collision anywhere. Its remedy differs completely from a socket fault (a
// completing rotation needs no intervention at all, since the pair is re-read
// on every attempt), so it must not collapse into `listen_failed`.
func TestChaos71_TLSMaterialFailureIsItsOwnReasonClass(t *testing.T) {
	cpChaosSetup(t)
	dir := t.TempDir()
	crt := dir + "/cp.crt"
	key := dir + "/cp.key"
	// Empty files: exactly what a rotation looks like between truncate and
	// write.
	for _, p := range []string{crt, key} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	err := StartControlPlaneGRPC("127.0.0.1:0", crt, key, "")
	if err == nil {
		t.Fatal("StartControlPlaneGRPC accepted an empty certificate pair")
	}
	if got := classifyCPGRPCBindError(err); got != "tls_certificate" {
		t.Errorf("classify(empty cert pair) = %q, want %q — the operator is sent to hunt a port owner for a certificate fault", got, "tls_certificate")
	}
	if !errors.Is(err, errCPGRPCTLSMaterial) {
		t.Error("the credential failure is not marked, so the classifier would have to string-match whatever crypto/tls chose")
	}
}

// TestChaos71_ClassifierIsBoundedAndNarrow pins the reason vocabulary.
//
// `network_error` requires an actual TIMEOUT. Every bind failure arrives as
// *net.OpError, which satisfies net.Error UNCONDITIONALLY (Timeout() is false
// for a bind EINVAL), so an unqualified errors.As(&ne) branch swallows every
// unrecognised errno into a class that names the wrong subsystem and makes
// `listen_failed` unreachable. classifyAdminUIListenError and
// classifySOCKS5BindError both shipped with exactly that shape and had to be
// narrowed; this gate is why this one starts narrow.
func TestChaos71_ClassifierIsBoundedAndNarrow(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "none"},
		{"in use", cpBindErr(syscall.EADDRINUSE), "port_in_use"},
		{"eacces", cpBindErr(syscall.EACCES), "permission_denied"},
		{"eperm", cpBindErr(syscall.EPERM), "permission_denied"},
		{"addr not avail", cpBindErr(syscall.EADDRNOTAVAIL), "address_unavailable"},
		{"emfile", cpBindErr(syscall.EMFILE), "descriptors_exhausted"},
		{"enfile", cpBindErr(syscall.ENFILE), "descriptors_exhausted"},
		// The defect this gate exists for: an UNRECOGNISED errno arriving in
		// the real net wrapper must be listen_failed, never network_error.
		{"unrecognised errno", cpBindErr(syscall.EINVAL), "listen_failed"},
		{"bare error", errors.New("something else"), "listen_failed"},
	}
	for _, c := range cases {
		if got := classifyCPGRPCBindError(c.err); got != c.want {
			t.Errorf("%s: classify = %q, want %q", c.name, got, c.want)
		}
	}
}

// ── Recovery ─────────────────────────────────────────────────────────────────

// TestChaos71_RecoveryBindsAndAssertsTheRole is the automatic-recovery gate.
//
// The whole point of a RATE-bounded rather than COUNT-bounded retry is that a
// fault which clears on its own needs no operator. This gate frees the port and
// requires the supervisor to bind, assert the role, and clear the episode — and
// it requires the clearing to come from the OBSERVED bind, not from elapsed
// time (the storage_health.go / ca_health.go house rule).
func TestChaos71_RecoveryBindsAndAssertsTheRole(t *testing.T) {
	cpChaosSetup(t)
	port, release := cpOccupyPort(t)

	cpStartSupervised(t, cpInsecureCfg(t, fmt.Sprintf("127.0.0.1:%d", port)))
	cpWaitFor(t, 5*time.Second, "a recorded bind failure", func() bool {
		return cpGRPCListenerState().Total > 0
	})

	release() // the fault clears, with nobody intervening

	cpWaitFor(t, 20*time.Second, "an observed bind after the port freed", func() bool {
		return cpGRPCListenerState().Serving
	})

	snap := cpGRPCListenerState()
	if !snap.EverBound || snap.Binds == 0 {
		t.Errorf("recovery did not record an observed bind: %+v", snap)
	}
	if snap.Failing {
		t.Error("the failure episode survived an observed bind")
	}
	if snap.Total == 0 {
		t.Error("the cumulative failure count was reset by recovery — the HISTORY of a transient fault must stay visible")
	}
	if !snap.RoleAsserted {
		t.Error("the role was not asserted after an observed bind")
	}
	clusterRoleMu.RLock()
	role := clusterRole.role
	clusterRoleMu.RUnlock()
	if role != "control-plane" {
		t.Errorf("role = %q after a successful bind, want control-plane", role)
	}
	if got := cpGRPCListenerStatus(); got != "ready" {
		t.Errorf("/health posture = %q after recovery, want ready", got)
	}
}

// TestChaos71_StopIsPromptDuringBackoff pins the interruptible sleep.
//
// A MANY-TRIAL gate on purpose: where Stop lands inside a non-interruptible
// sleep is uniform, so a single trial passes a broken build most of the time —
// the TestChaos54_StopIsPromptDuringAcceptBackoff precedent.
func TestChaos71_StopIsPromptDuringBackoff(t *testing.T) {
	const trials = 12
	for i := 0; i < trials; i++ {
		func() {
			cpChaosSetup(t)
			port, release := cpOccupyPort(t)
			defer release()

			s := startControlPlaneSupervised(cpInsecureCfg(t, fmt.Sprintf("127.0.0.1:%d", port)), context.Background())
			// Let it enter a backoff sleep.
			time.Sleep(time.Duration(10+i*7) * time.Millisecond)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			start := time.Now()
			if err := s.Stop(ctx); err != nil {
				t.Fatalf("trial %d: Stop did not complete: %v", i, err)
			}
			if took := time.Since(start); took > 500*time.Millisecond {
				t.Fatalf("trial %d: Stop waited out a backoff sleep (%s) — shutdown is not interruptible", i, took)
			}
		}()
	}
}

// ── Alerting ─────────────────────────────────────────────────────────────────

// TestChaos71_AlertFiresOncePerEpisodeWithABoundedDetail pins the paging
// contract.
//
// The Detail is the DEDUP KEY — `Dispatch` dedups on `event + ":" + Detail` —
// so an unbounded reason gives it one value per failure (the WK-12/RS-5 defect)
// and the fan-out evicts real threat alerts from the 500-entry retry queue. It
// must also never carry the listener address, which would put it on the alert
// payload of a fault that is otherwise address-free.
func TestChaos71_AlertFiresOncePerEpisodeWithABoundedDetail(t *testing.T) {
	now := cpChaosSetup(t)
	noteCPGRPCConfigured("10.9.8.7:50051")

	var mu sync.Mutex
	var details []string
	fireCPGRPCUnavailableAlert = func(d string) {
		mu.Lock()
		details = append(details, d)
		mu.Unlock()
	}

	// Under the threshold: no page. A predecessor draining a port clears in
	// seconds and paging on that would page on every ordinary redeploy.
	noteCPGRPCBindFailure("port_in_use", time.Second, *now)
	mu.Lock()
	n := len(details)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("paged %d time(s) before the unavailability threshold", n)
	}

	// Cross the threshold, then keep failing: exactly one page.
	for i := 1; i <= 4; i++ {
		noteCPGRPCBindFailure("port_in_use", time.Second, now.Add(cpGRPCUnavailableAfter+time.Duration(i)*time.Second))
	}
	mu.Lock()
	got := append([]string(nil), details...)
	mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("fired %d alerts for one episode, want 1: %v", len(got), got)
	}
	if strings.Contains(got[0], "10.9.8.7") {
		t.Errorf("the alert Detail carries the listener address, so the dedup key is address-bearing: %q", got[0])
	}
	if !strings.Contains(got[0], "port_in_use") {
		t.Errorf("the alert Detail does not name the bounded reason class: %q", got[0])
	}

	// An observed bind clears the latch, so a SECOND incident pages again.
	//
	// The second episode is driven with TWO stamps, because an episode's
	// elapsed time is measured from ITS OWN first failure: a single failure
	// opens an episode at zero elapsed and correctly does not page, however
	// late in the process it arrives. The first version of this gate used one
	// stamp far in the future and read the (correct) absence of a page as a
	// stuck latch — the gate was wrong, not the code.
	noteCPGRPCBound()
	base := now.Add(time.Hour)
	noteCPGRPCBindFailure("port_in_use", time.Second, base)
	mu.Lock()
	n = len(details)
	mu.Unlock()
	if n != 1 {
		t.Errorf("a fresh episode's FIRST failure paged (%d total) — unavailability is a duration, not a count", n)
	}
	noteCPGRPCBindFailure("port_in_use", time.Second, base.Add(cpGRPCUnavailableAfter+time.Second))
	mu.Lock()
	n = len(details)
	mu.Unlock()
	if n != 2 {
		t.Errorf("a second incident fired %d total alerts, want 2 — the fire-once latch did not clear on an observed bind", n)
	}
}

// ── The outage clock ─────────────────────────────────────────────────────────

// TestChaos71_HealthSnapshotDependsOnlyOnTheInjectedClock is the wall for
// CHAOS-66's round-3 finding, applied here before it can be reintroduced.
//
// An episode duration derived from two stored stamps FREEZES between attempts,
// so at the 30 s backoff ceiling with ±20% jitter a failure landing at 29 s left
// every read surface reporting "retrying" for up to 36 s past the documented
// threshold. Both halves of this gate are required: the second alone would pass
// against a read path that ignores the clock entirely.
func TestChaos71_HealthSnapshotDependsOnlyOnTheInjectedClock(t *testing.T) {
	base := cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:50051")
	noteCPGRPCBindFailure("port_in_use", time.Second, *base)

	// Half one: hold the injected clock still across REAL elapsed time. The
	// duration must not move.
	before := cpGRPCListenerState().FailingFor
	time.Sleep(60 * time.Millisecond)
	if after := cpGRPCListenerState().FailingFor; after != before {
		t.Errorf("the snapshot moved with WALL time (%s → %s) — it is not a pure function of the injected clock", before, after)
	}

	// Half two: advance the injected clock alone. The duration must move, and
	// the episode must become unavailable without any further attempt.
	frozen := *base
	cpGRPCHealthNow = func() time.Time { return frozen.Add(cpGRPCUnavailableAfter + time.Second) }
	snap := cpGRPCListenerState()
	if snap.FailingFor <= before {
		t.Errorf("advancing the injected clock did not age the episode (%s → %s) — the duration is latched to the stored stamps", before, snap.FailingFor)
	}
	if !snap.Unavailable {
		t.Error("an episode aged past the threshold by the clock alone is not reported unavailable — the alert and every read surface would lag by up to a full backoff ceiling")
	}
}

// TestChaos71_ClockRollbackCannotShrinkAnObservedOutage pins the direction of
// cpGRPCElapsed's max().
//
// Deliberately the OPPOSITE of CHAOS-61's rollback verdict: there the fail-safe
// answer is distrusting a remote value, here it is the LONGER duration — an
// outage that has already been observed must not be erased by a clock that
// moved backwards (NTP step, VM restore).
func TestChaos71_ClockRollbackCannotShrinkAnObservedOutage(t *testing.T) {
	first := time.Date(2026, 10, 2, 22, 0, 0, 0, time.UTC)
	last := first.Add(5 * time.Minute)
	rolledBack := first.Add(-time.Hour)

	if got := cpGRPCElapsed(first, last, rolledBack); got != 5*time.Minute {
		t.Errorf("elapsed under a rolled-back clock = %s, want the observed %s", got, 5*time.Minute)
	}
	if got := cpGRPCElapsed(time.Time{}, time.Time{}, first); got != 0 {
		t.Errorf("elapsed with no episode = %s, want 0", got)
	}
}

// TestChaos71_BackoffClampKeepsAnAttemptInsideTheThreshold pins CHAOS-55's
// recoveryPollCeiling rule.
//
// The alert is produced by an ATTEMPT (noteCPGRPCBindFailure holds the
// fire-once latch and nothing else wakes the loop), so a sleep that straddles
// the unavailability threshold defers the page by up to a whole ceiling.
// Capping the CEILING instead was rejected: that pays permanently for a
// property that matters on one sleep.
func TestChaos71_BackoffClampKeepsAnAttemptInsideTheThreshold(t *testing.T) {
	// A full-ceiling sleep at 29 s of a 30 s threshold must be shortened.
	if got := clampCPGRPCBindSleep(cpGRPCBindBackoffMax, cpGRPCUnavailableAfter-time.Second); got > time.Second {
		t.Errorf("clamp(ceiling, 29s elapsed) = %s — the sleep straddles the threshold and defers the page", got)
	}
	// Never below the floor, so the clamp cannot become a spin.
	if got := clampCPGRPCBindSleep(cpGRPCBindBackoffMax, cpGRPCUnavailableAfter-time.Millisecond); got < cpGRPCBindClampFloor {
		t.Errorf("clamp produced %s, below the %s floor — a near-reached threshold becomes a hot loop", got, cpGRPCBindClampFloor)
	}
	// Past the threshold there is nothing left to protect: full backoff.
	if got := clampCPGRPCBindSleep(cpGRPCBindBackoffMax, 2*cpGRPCUnavailableAfter); got != cpGRPCBindBackoffMax {
		t.Errorf("clamp past the threshold = %s, want the full %s", got, cpGRPCBindBackoffMax)
	}
	// A sleep already inside the window is untouched.
	if got := clampCPGRPCBindSleep(time.Second, 0); got != time.Second {
		t.Errorf("clamp(1s, 0 elapsed) = %s, want 1s", got)
	}
}

// TestChaos71_BackoffIsRateBoundedAndMonotonic pins rule 2.
func TestChaos71_BackoffIsRateBoundedAndMonotonic(t *testing.T) {
	cur := time.Duration(0)
	for i := 0; i < 20; i++ {
		next := nextCPGRPCBindBackoff(cur)
		if next < cur {
			t.Fatalf("backoff went backwards: %s → %s", cur, next)
		}
		if next > cpGRPCBindBackoffMax {
			t.Fatalf("backoff %s exceeded the ceiling %s", next, cpGRPCBindBackoffMax)
		}
		cur = next
	}
	if cur != cpGRPCBindBackoffMax {
		t.Errorf("backoff settled at %s, want the ceiling %s", cur, cpGRPCBindBackoffMax)
	}
	// The ceiling must stay BELOW the unavailability threshold, or the episode
	// could cross it with no attempt scheduled to observe it and the clamp
	// would be doing all the work.
	if cpGRPCBindBackoffMax > cpGRPCUnavailableAfter {
		t.Errorf("the backoff ceiling (%s) exceeds the unavailability threshold (%s)", cpGRPCBindBackoffMax, cpGRPCUnavailableAfter)
	}
}

// ── CONTROLS ─────────────────────────────────────────────────────────────────
//
// The cheapest way to pass every defect gate above is to stop activating the
// Control Plane at all — which would silently delete clustering. These five
// gates fail against that shape.

// TestChaos71_ControlHealthyBootStillServesAndLeads is the primary control.
func TestChaos71_ControlHealthyBootStillServesAndLeads(t *testing.T) {
	cpChaosSetup(t)

	// A free ephemeral address: bind one, learn the port, release it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick a port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cpStartSupervised(t, cpInsecureCfg(t, fmt.Sprintf("127.0.0.1:%d", port)))

	snap := cpGRPCListenerState()
	if !snap.Serving || !snap.EverBound {
		t.Fatalf("a healthy Control Plane boot did not bind: %+v", snap)
	}
	if snap.Total != 0 {
		t.Errorf("a healthy boot recorded %d bind failures", snap.Total)
	}
	if !snap.RoleAsserted {
		t.Error("a healthy boot did not assert the control-plane role")
	}
	if got := cpGRPCListenerStatus(); got != "ready" {
		t.Errorf("/health posture = %q on a healthy boot, want ready", got)
	}
	if got := checkCPGRPCListener(); got.Status != diagOK {
		t.Errorf("the contract row is not ok on a healthy boot: %+v", got)
	}
	// And the listener is really there.
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("the Control Plane reports serving but nothing is listening: %v", err)
	}
	_ = c.Close()
}

// TestChaos71_ControlSurfacesAreAbsentWhenNotAControlPlane pins the emission
// rule.
//
// A `culvert_cluster_grpc_up 0` on the ordinary standalone appliance that never
// asked for a cluster is indistinguishable from a Control Plane whose listener
// is dead, and the documented paging rule is `== 0` (the socks5 / cluster_ca /
// dns rule).
func TestChaos71_ControlSurfacesAreAbsentWhenNotAControlPlane(t *testing.T) {
	cpChaosSetup(t)

	if got := cpGRPCListenerStatus(); got != "disabled" {
		t.Errorf("/health posture = %q on a node that is not a Control Plane, want disabled", got)
	}
	if got := checkCPGRPCListener(); got.Status != diagOK {
		t.Errorf("the contract row is not ok on a node with no cluster: %+v", got)
	}
	checks := map[string]*readinessCheck{}
	appendCPGRPCReadinessCheck(checks)
	if _, ok := checks["cluster_grpc"]; ok {
		t.Error("a node that is not a Control Plane grew a permanently-green cluster_grpc readiness row")
	}
}

// TestChaos71_ControlReadinessRowIsReportOnly is the control that keeps this
// change from causing the outage it exists to prevent.
//
// A node whose cluster gRPC cannot bind is proxying traffic perfectly. Gating
// the DEFAULT readiness verdict on it would pull a fully-functional gateway out
// of the load balancer over a plane that has nothing to do with serving traffic
// — converting a control-plane outage into a traffic outage. CHAOS-57 recorded
// the same control for the admin UI row.
func TestChaos71_ControlReadinessRowIsReportOnly(t *testing.T) {
	cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:50051")
	noteCPGRPCBindFailure("port_in_use", time.Second, cpGRPCHealthNow())

	checks := map[string]*readinessCheck{}
	appendCPGRPCReadinessCheck(checks)
	row, ok := checks["cluster_grpc"]
	if !ok {
		t.Fatal("a failing Control Plane listener produced no readiness row at all")
	}
	if row.Status == "ok" {
		t.Error("the readiness row reports ok for a listener that is not serving")
	}
	// The row's STATUS is a report; what must not happen is it moving the
	// DEFAULT verdict. Asserted as a DIFFERENTIAL against the same node with no
	// cluster configured, so the gate is robust to whatever else this test
	// binary's globals make computeReadiness say — the claim is that the row
	// changes nothing, not that the verdict is 200.
	_, failingCode := computeReadiness()
	resetCPGRPCHealthForTest()
	_, baselineCode := computeReadiness()
	if failingCode != baselineCode {
		t.Errorf("a failing cluster_grpc row moved the default readiness verdict (%d → %d) — a cluster-plane fault would now eject a healthy proxy from the load balancer",
			baselineCode, failingCode)
	}
	// Detail must be a FIXED string: /ready is unauthenticated on the proxy
	// port, so the attempt count and reason class stay on the role-gated row.
	if strings.Contains(row.Detail, "port_in_use") || strings.Contains(row.Detail, "50051") {
		t.Errorf("the unauthenticated readiness detail leaks the reason class or the address: %q", row.Detail)
	}
}

// TestChaos71_ControlEachReasonClassCarriesItsOwnRemedy is CHAOS-66's round-3
// control.
//
// A bounded classifier is worth nothing if one remedy is printed for every
// class: a node out of descriptors, or with an interface not yet up, was being
// sent to hunt the owner of a port nobody holds. A switch returning one string
// satisfies every "names its own remedy" assertion, so the distinctness is
// asserted directly.
func TestChaos71_ControlEachReasonClassCarriesItsOwnRemedy(t *testing.T) {
	classes := []string{"port_in_use", "permission_denied", "address_unavailable", "descriptors_exhausted", "tls_certificate"}
	seen := map[string]string{}
	for _, c := range classes {
		r := cpGRPCBindRemedy(c, "127.0.0.1:50051")
		if prev, dup := seen[r]; dup {
			t.Errorf("reason %q and %q share one remedy — the classifier buys the operator nothing", c, prev)
		}
		seen[r] = c
		// Two clauses are invariant in EVERY branch, because they are what an
		// operator most needs before reaching for a restart.
		if !strings.Contains(r, "rebinds automatically") {
			t.Errorf("remedy for %q does not say the listener rebinds by itself: %q", c, r)
		}
		if !strings.Contains(r, "proxy data plane") {
			t.Errorf("remedy for %q does not say the proxy is unaffected: %q", c, r)
		}
	}
	// The unrecognised class must point at the log rather than invent advice.
	if r := cpGRPCBindRemedy("listen_failed", ":50051"); !strings.Contains(r, "process log") {
		t.Errorf("the unclassified remedy does not point at the log line: %q", r)
	}
}

// TestChaos71_ControlAnotherPlanesRoleIsNotOverwritten pins the refusal branch.
//
// A Data Plane enrollment can complete while the supervisor is retrying — the
// retry window is now minutes long rather than nonexistent. A node silently
// switching from data-plane back to control-plane is a worse surprise than a
// cluster listener that stays down and says so.
func TestChaos71_ControlAnotherPlanesRoleIsNotOverwritten(t *testing.T) {
	cpChaosSetup(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick a port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	clusterRoleMu.Lock()
	clusterRole.role = "data-plane"
	clusterRoleMu.Unlock()

	s := &cpGRPCSupervisor{
		cfg:          cpInsecureCfg(t, fmt.Sprintf("127.0.0.1:%d", port)),
		ctx:          context.Background(),
		stopping:     make(chan struct{}),
		done:         make(chan struct{}),
		firstAttempt: make(chan struct{}),
	}
	if err := s.attempt(); !errors.Is(err, errCPGRPCRoleTaken) {
		t.Errorf("attempt() on a data-plane node = %v, want errCPGRPCRoleTaken", err)
	}
	clusterRoleMu.RLock()
	role := clusterRole.role
	clusterRoleMu.RUnlock()
	if role != "data-plane" {
		t.Errorf("the supervisor overwrote the data-plane role with %q", role)
	}
}

// ── Rate-limited logging ─────────────────────────────────────────────────────

// TestChaos71_LogIsRateLimitedAndTheCountIsNot pins the log/counter split.
//
// The log carries the SIGNAL, the counter the MAGNITUDE. A mitigation for a
// crash loop must not itself be a log flood — but the COUNT must never be
// suppressed, or the operator loses the magnitude as well as the noise.
func TestChaos71_LogIsRateLimitedAndTheCountIsNot(t *testing.T) {
	now := cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:50051")
	fireCPGRPCUnavailableAlert = func(string) {}

	logged := 0
	for i := 0; i < 30; i++ {
		// All inside one log interval.
		shouldLog, _ := noteCPGRPCBindFailure("port_in_use", time.Second, now.Add(time.Duration(i)*time.Second))
		if shouldLog {
			logged++
		}
	}
	if logged == 0 {
		t.Fatal("the onset of an episode was never logged")
	}
	if logged > 2 {
		t.Errorf("emitted %d log lines inside one %s interval — the mitigation is a log flood", logged, cpGRPCBindLogInterval)
	}
	if got := cpGRPCListenerState().Total; got != 30 {
		t.Errorf("counted %d failures, want 30 — the counter was rate-limited along with the log", got)
	}

	// Past the interval, exactly one more line.
	shouldLog, _ := noteCPGRPCBindFailure("port_in_use", time.Second, now.Add(2*cpGRPCBindLogInterval))
	if !shouldLog {
		t.Error("no line was emitted after the rate-limit interval elapsed — a long outage would go silent")
	}
}

// TestChaos71_ConcurrentObserversAreRaceFree exercises the record under -race.
func TestChaos71_ConcurrentObserversAreRaceFree(t *testing.T) {
	now := cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:50051")
	fireCPGRPCUnavailableAlert = func(string) {}

	var wg sync.WaitGroup
	var reads atomic.Int64
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if i%2 == 0 {
					noteCPGRPCBindFailure("port_in_use", time.Second, now.Add(time.Duration(j)*time.Second))
				} else {
					_ = cpGRPCListenerState()
					_ = checkCPGRPCListener()
					_ = cpGRPCListenerStatus()
					reads.Add(1)
				}
			}
		}(i)
	}
	wg.Wait()
	if reads.Load() == 0 {
		t.Fatal("no concurrent reads ran — the gate proves nothing")
	}
}

// TestChaos71_SupervisorPanicClaimMatchesTheEvidence pins the panic guard.
//
// A contained panic is terminal for the loop either way, but it can land in two
// places with opposite truths: BEFORE a bind (the listener really is down) or
// AFTER one, in the leadership-resolution step that follows a successful
// activation (the listener is bound and serving the fleet). An unconditional
// `noteCPGRPCBindFailure` in the guard reports the second case as a dead
// listener — sending an operator to hunt a bind fault that does not exist, and
// dropping `culvert_cluster_grpc_up` to 0 on a node whose gRPC is answering.
//
// That is a surface saying the opposite of the truth, i.e. the whole class of
// defect this sweep exists to remove, reintroduced inside the sweep's own
// mitigation. Found in self-review; the CHAOS-57 "the evidence must match the
// claim" family.
func TestChaos71_SupervisorPanicClaimMatchesTheEvidence(t *testing.T) {
	t.Run("panic with no listener is recorded as a failure", func(t *testing.T) {
		cpChaosSetup(t)
		noteCPGRPCConfigured("127.0.0.1:50051")
		fireCPGRPCUnavailableAlert = func(string) {}

		noteCPGRPCSupervisorPanic()

		snap := cpGRPCListenerState()
		if !snap.Failing {
			t.Error("a panic before any bind is not recorded as a failure — every surface would stay green on a dead control plane")
		}
		if snap.LastReason != "supervisor_panicked" {
			t.Errorf("reason = %q, want supervisor_panicked", snap.LastReason)
		}
		if got := cpGRPCListenerStatus(); got == "ready" {
			t.Errorf("/health posture = %q after a pre-bind panic", got)
		}
	})

	t.Run("panic after a bind does not report the listener down", func(t *testing.T) {
		cpChaosSetup(t)
		noteCPGRPCConfigured("127.0.0.1:50051")
		fireCPGRPCUnavailableAlert = func(string) {}
		// An OBSERVED bind, exactly as attempt() records before it resolves
		// leadership — which is where a post-bind panic comes from.
		noteCPGRPCBound()
		noteCPGRPCRoleAsserted()

		noteCPGRPCSupervisorPanic()

		snap := cpGRPCListenerState()
		if snap.Failing {
			t.Error("a panic AFTER the listener bound reported the listener as failing — the gRPC port is answering and every surface now says it is not")
		}
		if !snap.Serving {
			t.Error("a panic after the bind cleared `serving` on a listener that is still serving the fleet")
		}
		if got := cpGRPCListenerStatus(); got != "ready" {
			t.Errorf("/health posture = %q after a post-bind panic, want ready — the listener is still serving", got)
		}
	})
}

// TestChaos71_ServeEndedIsNotReportedAsServing closes a lie this sweep's own
// gauge would otherwise introduce.
//
// `StartControlPlaneGRPC`'s serve goroutine has always just LOGGED when
// `srv.Serve` returns, which was harmless while nothing claimed the listener
// was up. This sweep adds `culvert_cluster_grpc_up`, so without an observer
// that gauge reads 1 forever on a listener whose socket has died — the exact
// defect class the sweep exists to remove, reintroduced inside its own fix
// (CHAOS-66's PX-18-in-miniature note).
//
// Found by `Deep · staticcheck` flagging `noteCPGRPCServeEnded` as UNUSED. The
// lint was right that it was dead; deleting it to satisfy the linter would have
// been the wrong instinct, because it would have certified the blind spot
// instead of closing it.
func TestChaos71_ServeEndedIsNotReportedAsServing(t *testing.T) {
	t.Run("a dead socket is reported unavailable, not serving", func(t *testing.T) {
		cpChaosSetup(t)
		noteCPGRPCConfigured("127.0.0.1:50051")
		var alerts int
		fireCPGRPCUnavailableAlert = func(string) { alerts++ }
		noteCPGRPCBound()
		noteCPGRPCRoleAsserted()

		noteCPGRPCServeEnded()

		snap := cpGRPCListenerState()
		if snap.Serving {
			t.Error("a listener whose Serve returned is still reported as serving — culvert_cluster_grpc_up would read 1 on a dead socket")
		}
		if !snap.ServeEnded {
			t.Error("the serve-ended state was not recorded")
		}
		// No retry is in flight, so there is no episode to age: unavailable is
		// immediate rather than after the duration threshold, which exists only
		// to avoid paging on an ordinary redeploy's few seconds of rebinding.
		if !snap.Unavailable {
			t.Error("a dead listener is not reported unavailable — it will never rebind, so there is nothing to wait for")
		}
		if got := cpGRPCListenerStatus(); got == "ready" {
			t.Errorf("/health posture = %q on a listener whose socket is gone", got)
		}
		if alerts != 1 {
			t.Errorf("fired %d alerts, want exactly 1", alerts)
		}
		// The remedy must NOT promise an automatic rebind: nothing
		// re-establishes a listener that was already serving, and sending an
		// operator away from the one restart that IS needed is CHAOS-66's
		// round-2 finding.
		row := checkCPGRPCListener()
		if row.Status != diagFail {
			t.Errorf("contract row status = %v, want fail", row.Status)
		}
		if !strings.Contains(row.OperatorAction, "Restart this node") {
			t.Errorf("the remedy does not tell the operator to restart: %q", row.OperatorAction)
		}
		if strings.Contains(row.OperatorAction, "rebinds automatically") {
			t.Errorf("the remedy promises an automatic rebind that will never happen: %q", row.OperatorAction)
		}
	})

	t.Run("a clean teardown is not reported as a dead socket", func(t *testing.T) {
		cpChaosSetup(t)
		noteCPGRPCConfigured("127.0.0.1:50051")
		fireCPGRPCUnavailableAlert = func(string) {
			t.Error("a clean shutdown fired the unavailable alert")
		}
		noteCPGRPCBound()
		// GracefulStop makes Serve return NIL, so the observer runs on every
		// clean shutdown too. The supervisor's Stop recording `stopped` is what
		// lets it tell the two apart.
		noteCPGRPCStopped()

		noteCPGRPCServeEnded()

		if snap := cpGRPCListenerState(); snap.ServeEnded {
			t.Error("a clean teardown was recorded as the socket dying")
		}
		if got := cpGRPCListenerStatus(); got != "stopped" {
			t.Errorf("/health posture = %q during a clean teardown, want stopped", got)
		}
	})

	t.Run("a never-bound listener is left to the bind-failure path", func(t *testing.T) {
		cpChaosSetup(t)
		noteCPGRPCConfigured("127.0.0.1:50051")
		fireCPGRPCUnavailableAlert = func(string) {
			t.Error("a listener that never bound fired the serve-ended alert")
		}

		noteCPGRPCServeEnded()

		if snap := cpGRPCListenerState(); snap.ServeEnded {
			t.Error("a listener that never bound was recorded as having stopped serving — there is nothing to contradict, and the bind-failure path owns that state")
		}
	})

	t.Run("an observed bind clears a previous serve-ended state", func(t *testing.T) {
		cpChaosSetup(t)
		noteCPGRPCConfigured("127.0.0.1:50051")
		fireCPGRPCUnavailableAlert = func(string) {}
		noteCPGRPCBound()
		noteCPGRPCServeEnded()

		noteCPGRPCBound() // a fresh socket IS the recovery

		snap := cpGRPCListenerState()
		if snap.ServeEnded {
			t.Error("the serve-ended state stayed latched after an observed bind — a fail row and a page would outlive the outage (CHAOS-66's rule)")
		}
		if !snap.Serving || snap.Unavailable {
			t.Errorf("a re-bound listener is not reported healthy: %+v", snap)
		}
	})
}

// TestChaos71_StopRecordsTheTeardownOnTheHappyPath pins the other half.
//
// On a successful activation the supervisor loop RETURNS — there is nothing
// left to retry — so `noteCPGRPCStopped` on the loop's exit paths is never
// reached for a healthy Control Plane. Without Stop recording it, a clean
// shutdown left `/health cluster_grpc` reporting `ready` on its way out, the
// fixed enum's `stopped` value was unreachable on the happy path, and
// noteCPGRPCServeEnded would mistake GracefulStop's nil return for a dead
// socket.
func TestChaos71_StopRecordsTheTeardownOnTheHappyPath(t *testing.T) {
	cpChaosSetup(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick a port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	s := startControlPlaneSupervised(cpInsecureCfg(t, fmt.Sprintf("127.0.0.1:%d", port)), context.Background())
	if snap := cpGRPCListenerState(); !snap.Serving {
		t.Fatalf("the gate did not reach a serving listener: %+v", snap)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if snap := cpGRPCListenerState(); !snap.Stopped {
		t.Error("a clean shutdown of a HEALTHY Control Plane did not record the teardown — /health keeps reporting ready on the way out")
	}
	if got := cpGRPCListenerStatus(); got != "stopped" {
		t.Errorf("/health posture = %q after Stop, want stopped", got)
	}
}

// ── Structural walls ─────────────────────────────────────────────────────────

// TestChaos71_TheControlPlaneActivationPathHasNoFatal is the wall against
// reintroduction.
//
// Behavioural coverage cannot catch this: a reintroduced logFatalf calls
// os.Exit(1) and kills the test binary rather than failing an assertion, so the
// signal would be an unexplained package-wide crash rather than a named
// failure. The scan names it.
//
// ONE fatal is allowed and is deliberately named rather than pattern-excused:
// `armHALease`'s. A requested etcd fence that cannot be built IS fatal on
// purpose — silently running legacy ADR-0004 when the operator asked for
// fencing would be an invisible safety downgrade (ADR-0005 S5). That is a
// different decision from "a socket could not be bound", and keeping the
// allowance narrow is what makes this wall mean anything.
//
// It deliberately does NOT cover main.go's `logFatalf("Proxy error")`, which is
// correct and must stay: the proxy IS the product, and a gateway that cannot
// serve must exit loudly rather than linger as a black hole. The asymmetry
// between an auxiliary plane and the primary one is the whole finding.
func TestChaos71_TheControlPlaneActivationPathHasNoFatal(t *testing.T) {
	files := []string{"cluster_startup.go", "cluster_grpc_bind.go", "cluster_grpc_health.go"}
	const allowed = `logFatalf("HA lease: %v", err)`

	checked, allowances := 0, 0
	for _, f := range files {
		src, err := os.ReadFile(filepath.Join(pkgSourceDir(), f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			checked++
			code, _, _ := strings.Cut(line, "//")
			if !strings.Contains(code, "logFatalf(") && !strings.Contains(code, "log.Fatal") {
				continue
			}
			if strings.Contains(code, allowed) {
				allowances++
				continue
			}
			t.Errorf("%s:%d reintroduces a fatal on the Control Plane activation path: %s",
				f, i+1, strings.TrimSpace(line))
		}
	}
	// Not-vacuous checks. Without the first the gate passes forever if the
	// selector stops matching real files; without the second it passes forever
	// if the one legitimate fatal is deleted, which would mean the allowance is
	// no longer pinning anything.
	if checked < 500 {
		t.Fatalf("the fatal scan only examined %d lines — it is not reading the activation sources", checked)
	}
	if allowances != 1 {
		t.Errorf("found %d instances of the one allowed fatal, want exactly 1 — the allowance no longer pins the ADR-0005 fence decision", allowances)
	}
}

// TestChaos71_Wall_RunbookNamesRegisteredEndpoints pins the runbook's API paths
// against the route table.
//
// Written because this sweep nearly shipped the exact defect CHAOS-70's round 2
// found and fixed: the first draft of the runbook sent operators to
// `POST /api/cluster/control-plane`, which is registered nowhere — the handler
// lives at `/api/cluster/mode` — so anyone following the manual-recovery step
// mid-incident would have got a 404. Prose cannot be unit-tested, but a PATH
// can: uiRoutes is the single source of truth for what exists, so the two are
// compared directly.
func TestChaos71_Wall_RunbookNamesRegisteredEndpoints(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(pkgSourceDir(), "docs", "operator", "control-plane-grpc-bind.md")) // #nosec G304 -- fixed in-repo path
	if err != nil {
		t.Fatalf("read runbook: %v", err)
	}

	registered := map[string]bool{}
	for i := range uiRoutes {
		registered[uiRoutes[i].Path] = true
	}

	found := 0
	for _, m := range regexp.MustCompile(`/api/[A-Za-z0-9/_-]+`).FindAllString(string(data), -1) {
		path := strings.TrimRight(m, "/-_")
		if registered[path] {
			found++
			continue
		}
		t.Errorf("the runbook names %q, which is not registered in uiRoutes — an operator following "+
			"these steps gets a 404", path)
	}
	if found == 0 {
		t.Fatal("the wall matched no /api/ paths in the runbook; its selector has gone stale")
	}
}

// TestChaos71_Wall_RunbookMetricNamesMatchTheEmitter pins the other half of the
// same class.
//
// A runbook that names a metric /metrics does not emit sends an operator to
// build an alert rule on a series that will never appear — and the paging rule
// in §3 of that runbook is the whole point of the observability in this sweep.
// CHAOS-69's round-3 lesson, which pinned a documented LOG line against its
// emitter, applied to the metric names.
func TestChaos71_Wall_RunbookMetricNamesMatchTheEmitter(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join(pkgSourceDir(), "docs", "operator", "control-plane-grpc-bind.md")) // #nosec G304 -- fixed in-repo path
	if err != nil {
		t.Fatalf("read runbook: %v", err)
	}
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "metrics.go")) // #nosec G304 -- fixed in-repo path
	if err != nil {
		t.Fatalf("read metrics.go: %v", err)
	}

	named := map[string]bool{}
	for _, m := range regexp.MustCompile(`culvert_cluster_grpc_[a-z_]+`).FindAllString(string(doc), -1) {
		named[m] = true
	}
	if len(named) == 0 {
		t.Fatal("the wall found no culvert_cluster_grpc_* names in the runbook; its selector has gone stale")
	}
	emitted := string(src)
	for name := range named {
		if !strings.Contains(emitted, name+" ") {
			t.Errorf("the runbook names metric %q, which metrics.go does not emit — an alert rule built on it would never fire", name)
		}
	}
	// And the converse: every emitted series must be documented, or an operator
	// reading the runbook does not know it exists.
	for _, m := range regexp.MustCompile(`culvert_cluster_grpc_[a-z_]+`).FindAllString(emitted, -1) {
		if !named[m] {
			t.Errorf("metrics.go emits %q, which the runbook does not document", m)
		}
	}
}

// TestChaos71_Wall_NoCurrentConfigSnapshotUnderTheRoleLock is the general wall
// for the deadlock, and it is deliberately wider than the two call sites this
// sweep touched.
//
// `CurrentConfigSnapshot()` reads the cluster role back through
// `buildCPAddressList`'s `clusterRoleMu.RLock()`, and `sync.RWMutex` is not
// reentrant — so calling it from a function that holds `clusterRoleMu` in
// EITHER mode deadlocks that goroutine while holding the lock. It is a
// whole-package invariant, not a property of `enableControlPlane`, and the
// behavioural gates above can only reach the paths a test can drive; the lock
// branch inside `buildCPAddressList` is taken only when HA is enabled, so a new
// offender would be latent on a standalone node and certain on an HA one.
//
// This is the governance lesson §40 (CHAOS-70) round 3 recorded, applied
// preventively: *enumerate such a class from the PRIMITIVE, not from the file
// being edited.* The primitive here is `clusterRoleMu`.
//
// The scan walks every non-test file in package main, finds each function that
// takes `clusterRoleMu.Lock()` or `.RLock()`, and reports a call to
// `CurrentConfigSnapshot` or `prepareControlPlane` that appears after it in the
// same function body.
func TestChaos71_Wall_NoCurrentConfigSnapshotUnderTheRoleLock(t *testing.T) {
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	reentrant := map[string]bool{"CurrentConfigSnapshot": true, "prepareControlPlane": true}

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

			// Find the earliest position at which this function takes
			// clusterRoleMu, and the positions of any re-entrant calls.
			lockAt := token.NoPos
			var offenders []*ast.CallExpr
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if ok {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "clusterRoleMu" &&
						(sel.Sel.Name == "Lock" || sel.Sel.Name == "RLock") {
						if lockAt == token.NoPos || call.Pos() < lockAt {
							lockAt = call.Pos()
						}
					}
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && reentrant[id.Name] {
					offenders = append(offenders, call)
				}
				return true
			})
			if lockAt == token.NoPos {
				continue
			}
			lockedFuncs++
			for _, call := range offenders {
				if call.Pos() <= lockAt {
					continue
				}
				id := call.Fun.(*ast.Ident)
				t.Errorf("%s: %s calls %s() after taking clusterRoleMu — CurrentConfigSnapshot re-reads the role "+
					"through buildCPAddressList's RLock and sync.RWMutex is not reentrant, so this deadlocks the "+
					"goroutine while it holds the lock (certain on any node with HA enabled)",
					fset.Position(call.Pos()), fn.Name.Name, id.Name)
			}
		}
	}

	// Not-vacuous checks: without these the wall passes forever if the parser
	// stops reading the package or if nothing takes the lock any more.
	if scannedFuncs < 500 {
		t.Fatalf("the wall scanned only %d functions — it is not reading package main", scannedFuncs)
	}
	if lockedFuncs == 0 {
		t.Fatal("the wall found no function taking clusterRoleMu — its selector has gone stale")
	}
}

// TestChaos71_ShutdownStopsTheSupervisorBeforeDrainingTheServer pins the
// ordering in the shutdown hook.
//
// The supervisor retries up to once per 30 s, so stopping it AFTER the drain
// would let it bind a FRESH listener and begin serving RPCs on a node that is
// already tearing down. Behavioural coverage of a shutdown-hook ordering would
// have to drive the whole sequence; the order is a one-line property, so it is
// pinned structurally.
func TestChaos71_ShutdownStopsTheSupervisorBeforeDrainingTheServer(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "main_shutdown.go"))
	if err != nil {
		t.Fatalf("read main_shutdown.go: %v", err)
	}
	body := string(src)
	stopSup := strings.Index(body, "clusterRole.grpcSupervisor.Stop(ctx)")
	drain := strings.Index(body, "StopControlPlaneGRPC()")
	if stopSup < 0 {
		t.Fatal("the shutdown sequence never stops the gRPC bind supervisor — it could bind a fresh listener mid-teardown")
	}
	if drain < 0 {
		t.Fatal("the shutdown sequence no longer drains the gRPC server")
	}
	if stopSup > drain {
		t.Error("the bind supervisor is stopped AFTER the gRPC drain — it can bind a fresh listener and serve RPCs on a node that is shutting down")
	}
}
