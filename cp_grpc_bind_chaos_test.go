package main

// cp_grpc_bind_chaos_test.go — CHAOS-73 gates for the Control Plane gRPC
// listener's BIND, SERVE and REBIND.
//
// The finding: the boot path called `logFatalf("ControlPlane gRPC: %v", err)`
// on any listener failure, from `initCluster` — which main.go runs BEFORE
// `initSOCKS5`, `startAdminUI` and `buildAndStartProxyServer`. So an occupied
// gRPC port or an unreadable mTLS pair terminated the whole appliance with no
// proxy, no admin UI and no health endpoint. Separately, the listener's death
// after a successful bind was SILENT and TERMINAL while every surface kept
// reporting a healthy Control Plane. See cp_grpc_bind.go for the reproduction
// against the real binary.
//
// On "verified failing against the pre-fix shape": for the fatal, that has the
// stronger meaning §33/§36 rely on — the pre-fix shape calls os.Exit(1), which
// kills the TEST BINARY mid-run and takes the whole package with it, so the
// defect cannot be reintroduced and kept green. For the non-fatal halves (the
// missing health plane, the silent serve death, the optimistic role claim) the
// gates were each run against a reverted shape and observed red; the mutations
// are named on the individual gates.
//
// The CONTROLS matter as much as the defect gates, and here there are two
// cheapest-wrong-fixes to guard against, pointing in opposite directions:
//
//   - Delete the fatal and report the listener healthy. That is strictly WORSE
//     than the defect — a Control Plane that is silently absent forever on a
//     node whose every probe reads green, and a fleet that quietly stops
//     receiving config. ControlUnboundListenerIsNeverReportedReady and
//     ControlRoleIsNotClaimedWithoutASocket pin it.
//   - Make the retry loop so loud or so eager that the mitigation becomes the
//     incident. ControlHealthyBindIsSilent and
//     DefectBindFailureLogIsRateLimited pin that direction.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ── Harness ─────────────────────────────────────────────────────────────────

// cpChaosSetup isolates every process-global this plane touches and FREEZES the
// health read clock.
//
// The freeze is CHAOS-66 round 3's lesson applied from the start rather than
// rediscovered: these gates drive the WRITE path with synthetic stamps anchored
// at time.Now(), and the READ path ages an in-progress episode against a clock.
// Leaving that clock real mixes the two, so a gate recording failures 19 s apart
// synthetically and asserting "not yet unavailable" would ALSO be asserting,
// invisibly, that under 30 s of WALL time passed between two of its own
// statements — true in milliseconds locally, false on a loaded runner under
// `-count=2`. A gate that wants an episode to AGE advances the clock explicitly
// via cpSwapHealthClock, which is then the condition under test rather than an
// accident of scheduling.
//
// Returns an accessor for the alerts fired, so a test never reads the slice
// without the mutex that guards it.
func cpChaosSetup(t *testing.T) func() []string {
	t.Helper()
	resetCPGRPCListenerHealthForTest()
	t.Cleanup(resetCPGRPCListenerHealthForTest)

	frozen := time.Now()
	prevNow := cpGRPCHealthNow
	cpGRPCHealthNow = func() time.Time { return frozen }
	t.Cleanup(func() { cpGRPCHealthNow = prevNow })

	var mu sync.Mutex
	var fired []string
	prevAlert := fireCPGRPCListenerAlert
	fireCPGRPCListenerAlert = func(detail string) {
		mu.Lock()
		fired = append(fired, detail)
		mu.Unlock()
	}
	t.Cleanup(func() { fireCPGRPCListenerAlert = prevAlert })

	cpSnapshotRoleAndSupervisor(t)

	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), fired...)
	}
}

// cpSnapshotRoleAndSupervisor snapshot-and-restores the cluster role and the
// supervisor handle.
//
// Required, not hygiene: a gate that leaves `clusterRole.role` as
// "control-plane" makes every later test in the package behave as a Control
// Plane (isManagedDataPlane, the PAC profile writer gate, the SaaS feed
// authority resolver, the diagnostics rows), and a leaked supervisor leaves a
// rebind loop running against a port the next test may want. This is the
// `setupProxyTest` trap the CLAUDE.md test-pitfalls note names: a reset at
// test START stops the previous test's state flowing IN and does nothing to
// stop this test's flowing OUT.
func cpSnapshotRoleAndSupervisor(t *testing.T) {
	t.Helper()
	clusterRoleMu.Lock()
	prev := clusterRole
	clusterRoleMu.Unlock()

	cpActivationMu.Lock()
	prevSup := cpSupervisor
	cpSupervisor = nil
	cpActivationMu.Unlock()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = stopControlPlaneListener(ctx)

		cpActivationMu.Lock()
		cpSupervisor = prevSup
		cpActivationMu.Unlock()

		clusterRoleMu.Lock()
		clusterRole = prev
		clusterRoleMu.Unlock()
	})
}

// cpReadSource reads one of this package's own source files for the structural
// walls below, anchored to the package directory via pkgSourceDir().
//
// Never `os.ReadFile("cp_grpc_bind.go")`: a bare relative read races any
// concurrent `os.Chdir` in the test binary, which is the flake class
// TestTestFileReadsAreCWDIndependent (static_read_wall_test.go) exists to
// forbid — and it caught the first draft of these walls.
func cpReadSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pkgSourceDir(), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// cpSwapHealthClock points the health READ path at a clock the test drives, so
// an episode can age without recording another attempt.
func cpSwapHealthClock(t *testing.T, now func() time.Time) {
	t.Helper()
	prev := cpGRPCHealthNow
	cpGRPCHealthNow = now
	t.Cleanup(func() { cpGRPCHealthNow = prev })
}

// cpStartSupervised starts the real production supervisor entry point and
// guarantees it is stopped when the test ends, so no gate leaks a rebind loop.
func cpStartSupervised(t *testing.T, cfg cpListenerConfig, tolerate bool, onActivated func()) (*cpListenerSupervisor, error) {
	t.Helper()
	sup, err := startControlPlaneListener(cfg, tolerate, onActivated)
	if sup != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = sup.Stop(ctx)
		})
	}
	return sup, err
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

// cpInsecure arms --cluster-insecure for the duration of a test so the gates
// exercise the bind rather than the TLS material. The TLS path has its own
// gate (DefectTLSMaterialFaultIsNotFatal).
func cpInsecure(t *testing.T) {
	t.Helper()
	prev := clusterInsecure
	clusterInsecure = true
	t.Cleanup(func() { clusterInsecure = prev })
}

// cpFreePort returns a port that was bindable a moment ago, plus a loopback
// address for it. Inherently racy in the abstract; every gate that needs the
// port FREE confirms it by observing the supervisor actually bind.
func cpFreePort(t *testing.T) int {
	t.Helper()
	port, release := occupyPort(t)
	release()
	return port
}

// ── Defect gates ────────────────────────────────────────────────────────────

// TestChaos73_DefectBindFailureIsNotFatal is the primary gate.
//
// Pre-fix shape (cluster_startup.go):
//
//	if err := enableControlPlane(...); err != nil {
//	        logFatalf("ControlPlane gRPC: %v", err)
//	}
//
// Reintroducing that kills the test binary rather than failing this assertion,
// which is what makes the defect unreintroducible-and-green.
func TestChaos73_DefectBindFailureIsNotFatal(t *testing.T) {
	cpChaosSetup(t)
	cpInsecure(t)

	port, release := occupyPort(t)
	defer release()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	sup, err := cpStartSupervised(t, cpListenerConfig{addr: addr}, true, nil)
	if err != nil {
		t.Fatalf("boot path must tolerate an unbindable listener, got %v", err)
	}
	if sup == nil {
		t.Fatal("boot path returned no supervisor")
	}
	// We are still running — that is the whole assertion — and the fault was
	// recorded rather than swallowed.
	snap := cpGRPCListenerState()
	if !snap.Configured {
		t.Error("a requested Control Plane listener must be recorded as CONFIGURED before the first bind attempt, " +
			"or a CP that never came up is indistinguishable from a node that never asked to be one")
	}
	if snap.Total == 0 {
		t.Error("the bind failure was not counted")
	}
	if snap.LastReason != "port_in_use" {
		t.Errorf("reason = %q, want port_in_use", snap.LastReason)
	}
	if snap.Serving {
		t.Error("an unbindable listener must never report serving")
	}
}

// TestChaos73_DefectRoleIsNotClaimedWithoutASocket pins the invariant
// `enableControlPlane` stated in a comment — "Only set role after gRPC is
// successfully started" — across the new retry path.
//
// A supervisor that claimed the role optimistically would have fixed the crash
// loop by replacing it with an operational lie: `GET /api/cluster/status`
// reporting a Control Plane with an address nothing is listening on, which is
// exactly the pre-existing silent-serve-death defect arriving by a new road.
func TestChaos73_DefectRoleIsNotClaimedWithoutASocket(t *testing.T) {
	cpChaosSetup(t)
	cpInsecure(t)

	port, release := occupyPort(t)
	defer release()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	clusterRoleMu.Lock()
	clusterRole.role = "standalone"
	clusterRoleMu.Unlock()

	if _, err := cpStartSupervised(t, cpListenerConfig{addr: addr}, true, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	clusterRoleMu.RLock()
	role := clusterRole.role
	clusterRoleMu.RUnlock()
	if role == "control-plane" {
		t.Error("the node claimed the control-plane role with no listening socket — every clusterRole.role " +
			"gate, /api/cluster/status and /api/diagnostics now report a Control Plane that does not exist")
	}
	if got := cpGRPCHealthPosture(); got != "rebinding" {
		t.Errorf("/health cp_grpc = %q, want rebinding", got)
	}
}

// TestChaos73_DefectUnbindableListenerSelfHealsWithoutARestart is the recovery
// gate: before this change there was no rebind loop at all, so the ONLY way
// back from a transient bind fault was a process restart (and on the boot path
// the process had already exited).
func TestChaos73_DefectUnbindableListenerSelfHealsWithoutARestart(t *testing.T) {
	cpChaosSetup(t)
	cpInsecure(t)

	port, release := occupyPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	activated := make(chan struct{})
	var once sync.Once
	sup, err := cpStartSupervised(t, cpListenerConfig{addr: addr}, true, func() {
		once.Do(func() { close(activated) })
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sup.currentServer() != nil {
		t.Fatal("precondition: the listener must not be bound while the port is held")
	}

	// The fault clears on its own, as a draining predecessor or a completed
	// certificate rotation does.
	release()

	cpWaitFor(t, 20*time.Second, "the listener to bind after the port was freed", func() bool {
		return cpGRPCListenerState().Serving
	})

	snap := cpGRPCListenerState()
	if snap.Binds == 0 {
		t.Error("a successful bind was not counted")
	}
	if snap.Consecutive != 0 {
		t.Errorf("consecutive failures = %d after recovery, want 0 — recovery must clear the episode", snap.Consecutive)
	}
	if snap.Unavailable {
		t.Error("a recovered listener must not still report unavailable")
	}
	if got := cpGRPCHealthPosture(); got != "ready" {
		t.Errorf("/health cp_grpc = %q after recovery, want ready", got)
	}

	// The role is claimed by the SUPERVISOR on this later bind — the boot
	// caller already returned.
	select {
	case <-activated:
	case <-time.After(5 * time.Second):
		t.Error("onActivated never ran: the work deferred until the listener is real (the HA leadership resume " +
			"on the boot path) would be lost forever on any boot whose first bind attempt failed")
	}
	clusterRoleMu.RLock()
	role := clusterRole.role
	clusterRoleMu.RUnlock()
	if role != "control-plane" {
		t.Errorf("role = %q after an observed bind, want control-plane", role)
	}
}

// TestChaos73_DefectTLSMaterialFaultIsNotFatal covers the second production
// trigger, reproduced against the real binary: `cpServerOption` reads the mTLS
// pair at call time, so a cert-manager/certbot rotation that briefly truncates
// the key is a boot that ended in exit 1.
//
// It also pins that the material is RE-READ on every attempt, which is what
// makes the rotation self-heal with no restart (§33 rule 4).
func TestChaos73_DefectTLSMaterialFaultIsNotFatal(t *testing.T) {
	cpChaosSetup(t)

	dir := t.TempDir()
	certPath := dir + "/cp.crt"
	keyPath := dir + "/cp.key"
	// A truncated key — exactly what a rotation window leaves behind.
	if err := os.WriteFile(certPath, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	if _, err := cpStartSupervised(t, cpListenerConfig{addr: addr, certFile: certPath, keyFile: keyPath}, true, nil); err != nil {
		t.Fatalf("a TLS-material fault must not be fatal on the boot path, got %v", err)
	}

	snap := cpGRPCListenerState()
	if snap.LastReason != "tls_certificate" {
		t.Errorf("reason = %q, want tls_certificate — the operator remedy for a certificate fault is not the "+
			"remedy for an occupied port", snap.LastReason)
	}
	if snap.Serving {
		t.Error("a listener whose TLS material will not load must not report serving")
	}
}

// TestChaos73_DefectBuildLeaksNoListenerOnAFailedBind pins §33 rule 5 in this
// plane's shape.
//
// There the defect was `ServeTLS` returning a certificate error WITHOUT closing
// the listener it was handed, leaking one socket per attempt against a
// persistently bad cert and turning a config fault into descriptor exhaustion.
// Here the TLS material is loaded BEFORE the bind, so that exact shape cannot
// occur — but a gRPC server built before a FAILED Listen is still a resource,
// and an unbounded retry loop is precisely where leaking one per attempt
// matters.
func TestChaos73_DefectBuildLeaksNoListenerOnAFailedBind(t *testing.T) {
	cpChaosSetup(t)
	cpInsecure(t)

	port, release := occupyPort(t)
	defer release()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	before := cpOpenFDs(t)
	for i := 0; i < 50; i++ {
		srv, ln, _, err := buildControlPlaneServer(cpListenerConfig{addr: addr})
		if err == nil {
			srv.Stop()
			_ = ln.Close()
			t.Fatalf("attempt %d bound a port that is held", i)
		}
		if srv != nil || ln != nil {
			t.Fatalf("attempt %d returned a non-nil handle alongside an error — the caller cannot know it "+
				"owns cleanup, so the retry loop leaks one per attempt", i)
		}
	}
	after := cpOpenFDs(t)
	// Generous: the point is a LEAK PER ATTEMPT, which over 50 attempts would
	// be unmistakable.
	if after-before > 10 {
		t.Errorf("file descriptors grew by %d over 50 failed bind attempts (%d → %d) — an unbounded retry loop "+
			"that leaks per attempt converts a config fault into the descriptor exhaustion CHAOS-54 exists for",
			after-before, before, after)
	}
}

// cpOpenFDs counts this process's open descriptors. Linux-specific; the gate
// skips elsewhere rather than asserting something it cannot measure.
func cpOpenFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot count descriptors on this platform: %v", err)
	}
	return len(ents)
}

// TestChaos73_DefectServeDeathIsObservableAndRebinds is the gate for the third
// defect, the one with no fatal to blame.
//
// Pre-fix:
//
//	go func() {
//	        if err := srv.Serve(ln); err != nil {
//	                logger.Printf("ControlPlane gRPC error: %v", err)
//	        }
//	}()
//
// One log line, no rebind, and `clusterRole.role` left at "control-plane" with
// `grpcAddr` still set — so `GET /api/cluster/status` reported a healthy
// Control Plane on a node with no listener, forever. PX-18 in miniature.
func TestChaos73_DefectServeDeathIsObservableAndRebinds(t *testing.T) {
	cpChaosSetup(t)
	cpInsecure(t)

	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	sup, err := cpStartSupervised(t, cpListenerConfig{addr: addr}, true, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cpWaitFor(t, 10*time.Second, "the first bind", func() bool { return cpGRPCListenerState().Serving })

	firstBinds := cpGRPCListenerState().Binds

	// Kill the serve the way an unrecoverable listener fault does: stop the
	// server under it. Serve returns, which pre-fix was terminal.
	if srv := sup.currentServer(); srv != nil {
		srv.Stop()
	}

	cpWaitFor(t, 20*time.Second, "the listener to REBIND after its serve ended", func() bool {
		s := cpGRPCListenerState()
		return s.Serving && s.Binds > firstBinds
	})

	snap := cpGRPCListenerState()
	if snap.Total == 0 {
		t.Error("a serve that ended on its own was not counted as a failure — with no counter, no metric and no " +
			"contract row, the operator's only evidence was one log line")
	}
	if !snap.EverServed {
		t.Error("everServed must stay true: an operator needs to distinguish a listener that NEVER came up " +
			"(misconfiguration) from one that fell over (environmental fault)")
	}
}

// TestChaos73_DefectRuntimeAdminPathStillReportsTheFault pins the ASYMMETRY
// that is this sweep's governance point, from the other side.
//
// `apiClusterMode` must keep answering 409 for an address it cannot bind: an
// admin at the keyboard can retype it, and a background retry loop there would
// answer 200 for a Control Plane that may never exist — the same operational
// lie, in the one place the operator can be told the truth immediately. The
// gate also requires no loop is left behind.
func TestChaos73_DefectRuntimeAdminPathStillReportsTheFault(t *testing.T) {
	cpChaosSetup(t)
	cpInsecure(t)

	port, release := occupyPort(t)
	defer release()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	sup, err := cpStartSupervised(t, cpListenerConfig{addr: addr}, false, nil)
	if err == nil {
		t.Fatal("the runtime admin path must return an error for an unbindable address, so apiClusterMode " +
			"answers 409 instead of reporting success for a Control Plane that does not exist")
	}
	if sup != nil {
		t.Error("a refused runtime activation must leave no supervisor behind — a background loop retrying an " +
			"address the admin is about to correct would later claim the CP role on its own")
	}
	if !strings.Contains(err.Error(), addr) {
		t.Errorf("error %q does not name the address the admin typed", err)
	}
}

// TestChaos73_DefectUnavailabilityIsADurationNotACount pins the CHAOS-54/57
// rule. The backoff ceiling is reached in under a minute, so paging on the
// ATTEMPT COUNT would page on every ordinary rollout of the Control Plane —
// the one node in a cluster that gets rolled most carefully.
func TestChaos73_DefectUnavailabilityIsADurationNotACount(t *testing.T) {
	alerts := cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:50051")

	base := time.Now()
	cpSwapHealthClock(t, func() time.Time { return base })

	// Twenty failures in one second — a redeploy, not an outage.
	for i := 0; i < 20; i++ {
		noteCPGRPCBindFailure("port_in_use", cpGRPCBindBackoffInitial, base.Add(time.Duration(i)*50*time.Millisecond))
	}
	if snap := cpGRPCListenerState(); snap.Unavailable {
		t.Error("20 failures inside one second were reported UNAVAILABLE — that pages on every redeploy in " +
			"which a predecessor is still holding the port")
	}
	if row := checkCPGRPCListener(); row.Status != diagWarn {
		t.Errorf("contract row = %q during a short burst, want warn", row.Status)
	}
	if got := alerts(); len(got) != 0 {
		t.Errorf("alert fired during a short burst: %v", got)
	}

	// Now the same episode ages past the threshold.
	noteCPGRPCBindFailure("port_in_use", cpGRPCBindBackoffMax, base.Add(cpGRPCUnavailableAfter+time.Second))
	if snap := cpGRPCListenerState(); !snap.Unavailable {
		t.Error("an episode past the unavailability threshold must report unavailable")
	}
	if row := checkCPGRPCListener(); row.Status != diagFail {
		t.Errorf("contract row = %q past the threshold, want fail", row.Status)
	}
	if got := alerts(); len(got) != 1 {
		t.Errorf("want exactly one page per episode, got %d: %v", len(got), got)
	}
}

// TestChaos73_DefectUnavailabilityIsObservedWhileWaitingBetweenRetries carries
// CHAOS-66 round 3's finding forward.
//
// A duration derived from two STORED stamps freezes the instant an attempt
// returns, so at the 30 s ceiling with ±20% jitter an outage that crossed its
// threshold would stay reported as "merely retrying" for up to 36 s. Nothing
// here records a second failure: the point is that the passage of time ALONE
// must move the verdict.
func TestChaos73_DefectUnavailabilityIsObservedWhileWaitingBetweenRetries(t *testing.T) {
	cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:50051")

	start := time.Now()
	clock := start
	cpSwapHealthClock(t, func() time.Time { return clock })

	noteCPGRPCBindFailure("port_in_use", cpGRPCBindBackoffInitial, start)
	noteCPGRPCBindFailure("port_in_use", cpGRPCBindBackoffMax, start.Add(cpGRPCUnavailableAfter-time.Second))

	clock = start.Add(cpGRPCUnavailableAfter - time.Second)
	if cpGRPCListenerState().Unavailable {
		t.Fatal("precondition: one second short of the threshold must not be unavailable yet")
	}

	// No further attempt — only the clock moves.
	clock = start.Add(cpGRPCUnavailableAfter + 5*time.Second)
	if !cpGRPCListenerState().Unavailable {
		t.Error("the episode did not age: a duration derived from two stored stamps freezes between attempts, " +
			"so an outage past its threshold stayed reported as 'retrying' for the whole gap")
	}
}

// TestChaos73_DefectSleepIsClampedToTheThreshold is the other half of round 3's
// fix. The alert is produced by an ATTEMPT — noteCPGRPCBindFailure holds the
// fire-once latch and nothing else wakes the supervisor — so a sleep that
// straddles the threshold delays the page by up to the ceiling plus jitter.
func TestChaos73_DefectSleepIsClampedToTheThreshold(t *testing.T) {
	cases := []struct {
		name       string
		sleep      time.Duration
		failingFor time.Duration
		want       time.Duration
	}{
		{"well short of the threshold is untouched", 2 * time.Second, time.Second, 2 * time.Second},
		{"a sleep that would straddle it is shortened", cpGRPCBindBackoffMax, cpGRPCUnavailableAfter - 5*time.Second, 5 * time.Second},
		{"already past the threshold is untouched", cpGRPCBindBackoffMax, cpGRPCUnavailableAfter + time.Second, cpGRPCBindBackoffMax},
		{"a near-exhausted threshold floors rather than spins", cpGRPCBindBackoffMax, cpGRPCUnavailableAfter - time.Millisecond, cpGRPCBindClampFloor},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clampCPGRPCBindSleep(tc.sleep, tc.failingFor); got != tc.want {
				t.Errorf("clampCPGRPCBindSleep(%s, %s) = %s, want %s", tc.sleep, tc.failingFor, got, tc.want)
			}
		})
	}
}

// TestChaos73_DefectAlertDetailIsBounded pins the WK-12/RS-5 rule. `Dispatch`
// dedups on event + ":" + Detail, so a raw error — which embeds the bind
// address — mints one key per failure and defeats the dedup window BY
// CONSTRUCTION, fanning out into the 500-entry retry queue where it can evict
// real threat alerts.
func TestChaos73_DefectAlertDetailIsBounded(t *testing.T) {
	alerts := cpChaosSetup(t)
	noteCPGRPCConfigured("10.42.7.9:50051")

	base := time.Now()
	cpSwapHealthClock(t, func() time.Time { return base })
	noteCPGRPCBindFailure("port_in_use", cpGRPCBindBackoffInitial, base)
	noteCPGRPCBindFailure("port_in_use", cpGRPCBindBackoffMax, base.Add(cpGRPCUnavailableAfter+time.Second))

	got := alerts()
	if len(got) != 1 {
		t.Fatalf("want one alert, got %d", len(got))
	}
	for _, needle := range []string{"10.42.7.9", "50051", "address already in use", "bind:"} {
		if strings.Contains(got[0], needle) {
			t.Errorf("alert detail carries %q — the detail is the dedup key, so an unbounded value gives it one "+
				"distinct value per failure:\n%s", needle, got[0])
		}
	}
	if !strings.Contains(got[0], "port_in_use") {
		t.Errorf("alert detail must still carry the BOUNDED reason class, got:\n%s", got[0])
	}
}

// TestChaos73_DefectBindFailureLogIsRateLimited pins that the mitigation for a
// crash loop is not itself a log flood.
//
// The pre-fix crash loop was measurable: each iteration re-published a config
// version and minted log lines before exiting. An unbounded retry loop logging
// per attempt would be the same amplification without the exit — and the
// process log is a RotatingFile keeping one archive, so it is also how the
// evidence gets destroyed (CHAOS-54's 7.6M-attempt finding, CHAOS-63's
// write-amplification rule).
func TestChaos73_DefectBindFailureLogIsRateLimited(t *testing.T) {
	cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:50051")

	base := time.Now()
	cpSwapHealthClock(t, func() time.Time { return base })

	logged := 0
	for i := 0; i < 200; i++ {
		if ok, _ := noteCPGRPCBindFailure("port_in_use", cpGRPCBindBackoffMax, base.Add(time.Duration(i)*100*time.Millisecond)); ok {
			logged++
		}
	}
	// 200 attempts across 20 s, against a 60 s gate: the first one only.
	if logged != 1 {
		t.Errorf("emitted %d log lines for 200 failures inside one rate window, want 1 — the log carries the "+
			"SIGNAL, the counter carries the MAGNITUDE", logged)
	}
	if snap := cpGRPCListenerState(); snap.Total != 200 {
		t.Errorf("total = %d, want 200: suppressing the LINE must never suppress the COUNT", snap.Total)
	}

	// The suppressed count is carried to the recovery line, so the magnitude is
	// never silently dropped.
	suppressed, recovered := noteCPGRPCBound()
	if !recovered {
		t.Error("a bind that ends a failure episode must report recovered, so the operator gets a recovery line")
	}
	if suppressed != 199 {
		t.Errorf("suppressed = %d, want 199", suppressed)
	}
}

// TestChaos73_DefectShutdownIsNotDelayedByABackoff pins rule 4: the
// control-plane-grpc-stop hook (order 20, inside the 12 s early phase) must
// never wait out a 30 s backoff.
func TestChaos73_DefectShutdownIsNotDelayedByABackoff(t *testing.T) {
	cpChaosSetup(t)
	cpInsecure(t)

	port, release := occupyPort(t)
	defer release()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	sup, err := cpStartSupervised(t, cpListenerConfig{addr: addr}, true, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Let the backoff escalate past its floor before stopping, so the sleep in
	// flight is comfortably longer than the bound below.
	//
	// This is not padding, it is what makes the gate able to SEE the defect.
	// The first version allowed 3 s, and the first jittered sleep at the floor
	// is 0.8–1.2 s, so a `time.Sleep(wait)` with no interrupt PASSED it
	// (verified by mutation). Two failures put the pending sleep at 1.6–2.4 s
	// against a 400 ms bound — a ~4x margin over the defect, and ~1000x over
	// what an interruptible Stop actually costs, which is microseconds.
	cpWaitFor(t, 15*time.Second, "the backoff to escalate past its floor", func() bool {
		return cpGRPCListenerState().Total >= 2
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	if err := sup.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if d := time.Since(start); d > 400*time.Millisecond {
		t.Errorf("Stop took %s while a ~2s backoff sleep was in flight — the sleep is not interruptible, so "+
			"the control-plane-grpc-stop hook (order 20, inside the 12s early phase) waits out the rebind "+
			"schedule", d)
	}
	if !cpGRPCListenerState().Stopped {
		t.Error("a clean shutdown must be recorded as stopped, or the node reports a CP failure on its way out")
	}
}

// TestChaos73_DefectSupervisorPanicIsTerminalAndSaysSo pins CHAOS-66's round-2
// conclusion: a dead supervisor and an unbindable listener point at OPPOSITE
// operator actions, so they must be separate states with separate remedies.
//
// A rebinding listener recovers on its own and restarting the node costs a
// production outage to achieve what is already in progress. A panicked
// supervisor is terminal and the restart is the ONLY remedy. One field for both
// sends the operator the wrong way half the time.
func TestChaos73_DefectSupervisorPanicIsTerminalAndSaysSo(t *testing.T) {
	alerts := cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:50051")

	noteCPGRPCSupervisorDown("bind loop panicked")

	snap := cpGRPCListenerState()
	if !snap.SupervisorDown {
		t.Fatal("a panicked supervisor must be recorded as such")
	}
	if !snap.Unavailable {
		t.Error("a terminal supervisor must report unavailable immediately — there is no threshold to wait for, " +
			"because nothing is going to try again")
	}
	row := checkCPGRPCListener()
	if row.Status != diagFail {
		t.Errorf("contract row = %q, want fail", row.Status)
	}
	if !strings.Contains(strings.ToLower(row.OperatorAction), "restart") {
		t.Errorf("the TERMINAL state's remedy must name the restart — it is the only one that works:\n%s", row.OperatorAction)
	}
	if got := alerts(); len(got) != 1 || !strings.Contains(got[0], "NOT rebind") {
		t.Errorf("the terminal alert must say the listener will not rebind on its own, got %v", got)
	}

	// The CONTRAST, in the same gate: an ordinary unavailable episode must NOT
	// tell the operator to restart.
	resetCPGRPCListenerHealthForTest()
	noteCPGRPCConfigured("127.0.0.1:50051")
	base := time.Now()
	cpSwapHealthClock(t, func() time.Time { return base })
	noteCPGRPCBindFailure("port_in_use", cpGRPCBindBackoffInitial, base)
	noteCPGRPCBindFailure("port_in_use", cpGRPCBindBackoffMax, base.Add(cpGRPCUnavailableAfter+time.Second))
	row = checkCPGRPCListener()
	if row.Status != diagFail {
		t.Fatalf("precondition: want fail, got %q", row.Status)
	}
	if strings.Contains(strings.ToLower(row.OperatorAction), "restart this node") {
		t.Errorf("a REBINDING listener's remedy tells the operator to restart, which costs an outage to achieve "+
			"what is already in progress:\n%s", row.OperatorAction)
	}
	if !strings.Contains(row.OperatorAction, "no restart is required") {
		t.Errorf("a rebinding listener's remedy must say the recovery is automatic:\n%s", row.OperatorAction)
	}
}

// TestChaos73_DefectReasonClassesAreBoundedAndMatchedStructurally pins rule 5.
// Matched via errors.As on syscall.Errno, never by string: net wraps as
// *net.OpError{*os.SyscallError{syscall.Errno}} and the text is
// platform-specific.
func TestChaos73_DefectReasonClassesAreBoundedAndMatchedStructurally(t *testing.T) {
	wrap := func(e syscall.Errno) error {
		return &net.OpError{Op: "listen", Net: "tcp", Err: &os.SyscallError{Syscall: "bind", Err: e}}
	}
	cases := []struct {
		err  error
		want string
	}{
		{nil, "none"},
		{wrap(syscall.EADDRINUSE), "port_in_use"},
		{wrap(syscall.EACCES), "permission_denied"},
		{wrap(syscall.EPERM), "permission_denied"},
		{wrap(syscall.EADDRNOTAVAIL), "address_unavailable"},
		{wrap(syscall.EMFILE), "descriptors_exhausted"},
		{wrap(syscall.ENFILE), "descriptors_exhausted"},
		{fmt.Errorf("%w: tls: failed to find any PEM data in key input", errCPGRPCTLSMaterial), "tls_certificate"},
		{errors.New("something nobody enumerated"), "listen_failed"},
	}
	for _, tc := range cases {
		if got := classifyCPGRPCBindError(tc.err); got != tc.want {
			t.Errorf("classify(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}

	// CHAOS-66's correction, carried forward: *net.OpError satisfies net.Error
	// UNCONDITIONALLY (Timeout() false for a bind EINVAL), so an unqualified
	// `errors.As(err, &ne)` reports every unrecognised errno as a network fault
	// — sending the operator down a network-troubleshooting path for a socket
	// or permission fault — and makes `listen_failed` reachable only by an
	// error the net package did not produce.
	if got := classifyCPGRPCBindError(wrap(syscall.EINVAL)); got != "listen_failed" {
		t.Errorf("an unrecognised errno classified as %q — the network_error branch must require an actual "+
			"Timeout(), not merely an error the net package wrapped", got)
	}
}

// TestChaos73_DefectEveryDiagnosableReasonHasItsOwnRemedy is CHAOS-66's round-3
// control, applied here: a bounded classifier is worth nothing if one remedy is
// printed for every class. A node out of descriptors must not be sent to hunt
// the owner of a port nobody holds.
func TestChaos73_DefectEveryDiagnosableReasonHasItsOwnRemedy(t *testing.T) {
	diagnosable := []string{"port_in_use", "permission_denied", "address_unavailable", "descriptors_exhausted", "tls_certificate"}
	seen := map[string]string{}
	for _, r := range diagnosable {
		got := cpGRPCBindRemedy(r)
		if prev, dup := seen[got]; dup {
			t.Errorf("reason %q and %q print the SAME remedy — a switch returning one string satisfies every "+
				"'names its own remedy' assertion while telling four different faults to do the same thing", r, prev)
		}
		seen[got] = r

		// The two invariant clauses must survive in every branch.
		if !strings.Contains(got, "no restart is required") {
			t.Errorf("remedy for %q omits that the listener rebinds by itself:\n%s", r, got)
		}
		if !strings.Contains(got, "proxy data plane and admin UI are unaffected") {
			t.Errorf("remedy for %q omits that this is not a traffic incident:\n%s", r, got)
		}
	}
}

// TestChaos73_DefectThePlaneHasEveryOperatorSurface is the gate for the
// observability half of the finding: before this change the Control Plane gRPC
// listener was the ONLY listener in the appliance with no health plane at all.
func TestChaos73_DefectThePlaneHasEveryOperatorSurface(t *testing.T) {
	cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:50051")

	base := time.Now()
	cpSwapHealthClock(t, func() time.Time { return base })
	noteCPGRPCBindFailure("port_in_use", cpGRPCBindBackoffInitial, base)
	noteCPGRPCBindFailure("port_in_use", cpGRPCBindBackoffMax, base.Add(cpGRPCUnavailableAfter+time.Second))

	t.Run("operator contract row", func(t *testing.T) {
		row := checkCPGRPCListener()
		if row.Code != "cp_grpc_listener" {
			t.Errorf("row code = %q", row.Code)
		}
		if row.Status != diagFail {
			t.Errorf("row status = %q, want fail", row.Status)
		}
		// The row must say what the operator loses — it is a FLEET-wide fault
		// whose blast radius is not this node.
		for _, needle := range []string{"fleet-wide", "enrollment"} {
			if !strings.Contains(row.Message, needle) {
				t.Errorf("row message omits %q — the operator cannot tell the blast radius:\n%s", needle, row.Message)
			}
		}
	})

	t.Run("the row is registered on /api/diagnostics", func(t *testing.T) {
		if !strings.Contains(cpReadSource(t, "diagnostics.go"), "checkCPGRPCListener()") {
			t.Error("the row exists but is not wired into the diagnostics aggregate — a surface nothing renders " +
				"is not a surface")
		}
	})

	t.Run("health posture", func(t *testing.T) {
		if got := cpGRPCHealthPosture(); got != "unavailable" {
			t.Errorf("posture = %q, want unavailable", got)
		}
		if got := cpGRPCListenerStatus(); got == "" {
			t.Error("the /health field is empty on a CONFIGURED Control Plane")
		}
	})

	t.Run("readiness row is present and report-only", func(t *testing.T) {
		checks := map[string]*readinessCheck{}
		appendCPGRPCReadinessCheck(checks)
		row, ok := checks["cp_grpc"]
		if !ok {
			t.Fatal("no cp_grpc readiness row on a configured Control Plane")
		}
		if row.Status != "fail" {
			t.Errorf("readiness row status = %q, want fail", row.Status)
		}
		// FIXED detail: /ready is unauthenticated on the proxy port, so the
		// attempt count and reason class must not leak there.
		for _, needle := range []string{"port_in_use", "50051", "2"} {
			if strings.Contains(row.Detail, needle) {
				t.Errorf("readiness detail carries %q on an UNAUTHENTICATED surface: %q", needle, row.Detail)
			}
		}
	})
}

// TestChaos73_DefectCPServerOptionIsSilent is a STRUCTURAL gate, and the
// structure is the point.
//
// `cpServerOption` used to emit "ControlPlane: gRPC %s (mTLS)" (or the insecure
// WARN) itself. That was correct while it was called exactly once per process
// and became a log flood the moment the listener acquired a rebind loop — one
// line per attempt, forever, beside a failure line that is carefully rate
// limited. Behavioural coverage cannot see this: the lines go to the process
// logger, every assertion still passes, and the only symptom is a destroyed
// process log on a node already in trouble.
func TestChaos73_DefectCPServerOptionIsSilent(t *testing.T) {
	lines := strings.Split(cpReadSource(t, "controlplane_server.go"), "\n")

	start, end := -1, -1
	for i, l := range lines {
		if strings.HasPrefix(l, "func cpServerOptionMode(") {
			start = i
		}
		if start >= 0 && i > start && l == "}" {
			end = i
			break
		}
	}
	if start < 0 || end < 0 {
		t.Fatal("could not locate cpServerOptionMode — the gate is not reading what it claims to")
	}
	checked := 0
	for i := start; i <= end; i++ {
		code, _, _ := strings.Cut(lines[i], "//")
		checked++
		for _, sink := range []string{"logger.Print", "logWarnf(", "logErrorf(", "logger.Printf"} {
			if strings.Contains(code, sink) {
				t.Errorf("controlplane_server.go:%d logs from the per-attempt TLS path (%s): the rebind loop "+
					"calls this on every attempt, so a log here is one line per attempt forever", i+1, sink)
			}
		}
	}
	if checked < 10 {
		t.Fatalf("the scan only examined %d lines — it is not reading the function", checked)
	}
}

// TestChaos73_TheControlPlaneListenerPathHasNoFatal is the structural wall, and
// it is what makes the fix durable.
//
// Behavioural coverage cannot catch a reintroduction directly: a restored
// logFatalf kills the test binary rather than failing an assertion, so the
// signal would be an unexplained package-wide crash rather than a named
// failure. The scan names it.
//
// It deliberately does NOT cover `armHALease`'s fatal (also in
// cluster_startup.go) — see the allowance below — nor main.go's
// `logFatalf("Proxy error")`, which is correct and must stay: the proxy IS the
// product, and a gateway that cannot serve must exit loudly rather than linger
// as a black hole. The asymmetry between the cluster plane and the primary data
// plane is the whole finding.
func TestChaos73_TheControlPlaneListenerPathHasNoFatal(t *testing.T) {
	files := []string{"cluster_startup.go", "cp_grpc_bind.go", "cp_grpc_health.go", "controlplane_server.go"}
	checked := 0
	haLeaseAllowance := 0
	for _, f := range files {
		for i, line := range strings.Split(cpReadSource(t, f), "\n") {
			checked++
			code, _, _ := strings.Cut(line, "//")
			if !strings.Contains(code, "logFatalf(") && !strings.Contains(code, "log.Fatal") {
				continue
			}
			// The ONE allowance, and it is argued rather than assumed: a
			// malformed fencing-lease config that fell back to legacy would be
			// an invisible safety DOWNGRADE — the operator asked for fencing
			// and would not get it. That is a fault whose only safe resolution
			// is refusing to run, which is exactly the test this sweep applies
			// to the listener and the listener fails. See cp_grpc_bind.go's
			// "Deliberately NOT done".
			if strings.Contains(code, `logFatalf("HA lease:`) {
				haLeaseAllowance++
				continue
			}
			t.Errorf("%s:%d reintroduces a fatal on the Control Plane listener path: %s",
				f, i+1, strings.TrimSpace(line))
		}
	}
	// Not-vacuous checks. If the selector stops matching real files the gate
	// would pass forever while proving nothing; and if the HA-lease fatal is
	// ever removed the allowance becomes a silent hole, so its absence fails
	// here and forces the allowance to be deleted with it.
	if checked < 1500 {
		t.Fatalf("the fatal scan only examined %d lines — it is not reading the cluster sources", checked)
	}
	if haLeaseAllowance != 1 {
		t.Fatalf("expected exactly 1 allowed HA-lease fatal, found %d — if it moved or was removed, delete the "+
			"allowance rather than leaving a hole the scan no longer needs", haLeaseAllowance)
	}
}

// ── Controls ────────────────────────────────────────────────────────────────

// TestChaos73_ControlHealthyBindIsSilent is the control for the "make it loud"
// direction. A Control Plane whose listener binds on its first attempt must
// produce NO failure count, NO alert, NO warn row and NO backoff — the
// overwhelmingly common case must be indistinguishable from the pre-change
// behaviour.
func TestChaos73_ControlHealthyBindIsSilent(t *testing.T) {
	alerts := cpChaosSetup(t)
	cpInsecure(t)

	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	activated := make(chan struct{})
	var once sync.Once
	if _, err := cpStartSupervised(t, cpListenerConfig{addr: addr}, true, func() {
		once.Do(func() { close(activated) })
	}); err != nil {
		t.Fatalf("a healthy bind must not error: %v", err)
	}

	cpWaitFor(t, 10*time.Second, "the first bind", func() bool { return cpGRPCListenerState().Serving })

	snap := cpGRPCListenerState()
	if snap.Total != 0 {
		t.Errorf("a healthy bind counted %d failures", snap.Total)
	}
	if snap.Backoff != 0 {
		t.Errorf("a healthy bind reports a backoff of %s", snap.Backoff)
	}
	if row := checkCPGRPCListener(); row.Status != diagOK {
		t.Errorf("contract row = %q on a healthy Control Plane, want ok (%s)", row.Status, row.Message)
	}
	if got := cpGRPCHealthPosture(); got != "ready" {
		t.Errorf("posture = %q, want ready", got)
	}
	if got := alerts(); len(got) != 0 {
		t.Errorf("a healthy bind fired an alert: %v", got)
	}

	// The role IS claimed, and the deferred work DOES run — synchronously, on
	// the first attempt, so the happy-path ordering is byte-identical to the
	// pre-change code.
	select {
	case <-activated:
	default:
		t.Error("onActivated did not run synchronously on a first-attempt bind — the HA leadership resume would " +
			"be reordered on every healthy boot")
	}
	clusterRoleMu.RLock()
	role, gotAddr := clusterRole.role, clusterRole.grpcAddr
	clusterRoleMu.RUnlock()
	if role != "control-plane" {
		t.Errorf("role = %q on a bound Control Plane, want control-plane", role)
	}
	if gotAddr != addr {
		t.Errorf("grpcAddr = %q, want %q", gotAddr, addr)
	}
}

// TestChaos73_ControlUnboundListenerIsNeverReportedReady is the control for the
// cheapest wrong fix: delete the fatal and report the listener healthy. That
// would be strictly WORSE than the defect — a Control Plane silently absent
// forever on a node whose every probe reads green, and a fleet that quietly
// stops receiving config, which is the §19/§33 "found nothing wrong and never
// consulted are the same scrape" failure.
func TestChaos73_ControlUnboundListenerIsNeverReportedReady(t *testing.T) {
	cpChaosSetup(t)
	noteCPGRPCConfigured("127.0.0.1:50051")

	base := time.Now()
	cpSwapHealthClock(t, func() time.Time { return base })
	noteCPGRPCBindFailure("port_in_use", cpGRPCBindBackoffInitial, base)

	if got := cpGRPCHealthPosture(); got == "ready" {
		t.Error("/health reports a Control Plane with no socket as ready")
	}
	if row := checkCPGRPCListener(); row.Status == diagOK {
		t.Errorf("the contract row reports an unbound listener as ok: %s", row.Message)
	}
	checks := map[string]*readinessCheck{}
	appendCPGRPCReadinessCheck(checks)
	if row := checks["cp_grpc"]; row == nil || row.Status == "ok" {
		t.Error("/ready reports an unbound Control Plane listener as ok")
	}
	if cpGRPCListenerState().Serving {
		t.Error("an unbound listener reports serving")
	}
}

// TestChaos73_ControlNotAControlPlaneEmitsNothing pins the CHAOS-54 emission
// rule in both directions.
//
// A flat `culvert_cp_grpc_up 0` from every standalone proxy and every Data
// Plane in the fleet is indistinguishable from a broken Control Plane, and the
// documented paging rule is `== 0`. Equally, a permanently-green row on a node
// that is not a CP is noise that trains operators to ignore the row.
func TestChaos73_ControlNotAControlPlaneEmitsNothing(t *testing.T) {
	cpChaosSetup(t)

	if cpGRPCConfigured() {
		t.Fatal("precondition: the plane must start unconfigured")
	}
	if got := cpGRPCListenerStatus(); got != "" {
		t.Errorf("/health cp_grpc = %q on a node that is not a Control Plane — the field must be omitted", got)
	}
	checks := map[string]*readinessCheck{}
	appendCPGRPCReadinessCheck(checks)
	if _, ok := checks["cp_grpc"]; ok {
		t.Error("a node that is not a Control Plane grew a cp_grpc readiness row")
	}
	row := checkCPGRPCListener()
	if row.Status != diagOK {
		t.Errorf("row status = %q on a non-CP node, want ok", row.Status)
	}
	if !strings.Contains(row.Message, "Not a Control Plane") {
		t.Errorf("the row must say why it is green: %s", row.Message)
	}
	if snap := cpGRPCListenerState(); snap.Configured {
		t.Error("state reports configured on a node that never asked to be a Control Plane")
	}
}

// TestChaos73_ControlReadinessIsReportOnly pins the load-bearing half of the
// readiness row, exactly as §33 does for admin_ui.
//
// A Control Plane whose gRPC listener cannot bind is proxying its OWN traffic
// perfectly. Gating the DEFAULT readiness verdict on it would pull a
// fully-functional gateway out of the load balancer because the plane that
// serves config to OTHER nodes is down — converting a fleet-management outage
// into the traffic outage this whole change exists to prevent.
func TestChaos73_ControlReadinessIsReportOnly(t *testing.T) {
	s := cpReadSource(t, "healthcheck.go")
	if !strings.Contains(s, "appendCPGRPCReadinessCheck(checks)") {
		t.Fatal("the readiness row is not wired into /ready")
	}
	// The report-only set is enumerated in one place; cp_grpc must be in it.
	// A row that GATED the verdict would have to be named in the strict-only
	// exclusion list, so this is the structural statement of report-only.
	idx := strings.Index(s, "appendCPGRPCReadinessCheck(checks)")
	window := s[max(0, idx-900):idx]
	if !strings.Contains(window, "REPORT-ONLY") {
		t.Error("the cp_grpc readiness row is not documented as REPORT-ONLY at its call site; if it ever gates " +
			"the default verdict, a Control Plane bind fault ejects a healthy gateway from rotation")
	}
}

// TestChaos73_ControlRebindDoesNotRestartTheHeartbeatMonitor pins the
// idempotence activateControlPlaneAfterBind depends on. It runs again on every
// rebind, and the heartbeat monitor is a goroutine: starting a second one per
// rebind would leak one per listener fault for the life of the process.
func TestChaos73_ControlRebindDoesNotRestartTheHeartbeatMonitor(t *testing.T) {
	cpChaosSetup(t)

	cfg := cpListenerConfig{addr: "127.0.0.1:50051"}

	clusterRoleMu.Lock()
	clusterRole.role = "standalone"
	clusterRoleMu.Unlock()

	// First activation claims the role. A nil server handle is deliberate: the
	// gate is about the role transition and the monitor guard, not the handle.
	activateControlPlaneAfterBind(cfg, nil)
	clusterRoleMu.RLock()
	role := clusterRole.role
	clusterRoleMu.RUnlock()
	if role != "control-plane" {
		t.Fatalf("role = %q after activation, want control-plane", role)
	}

	// A rebind re-runs it; the role stays, and the gate below pins that the
	// monitor-start is guarded rather than unconditional.
	activateControlPlaneAfterBind(cfg, nil)

	body := cpReadSource(t, "cp_grpc_bind.go")
	i := strings.Index(body, "func activateControlPlaneAfterBind(")
	if i < 0 {
		t.Fatal("could not locate activateControlPlaneAfterBind")
	}
	fnBody := body[i:]
	if j := strings.Index(fnBody, "\n}\n"); j > 0 {
		fnBody = fnBody[:j]
	}
	if !strings.Contains(fnBody, "if !alreadyCP {") || !strings.Contains(fnBody, "StartHeartbeatMonitor") {
		t.Error("the heartbeat monitor start is not guarded on a first activation — a rebind would start a " +
			"second monitor goroutine, one per listener fault, for the life of the process")
	}
}

// TestChaos73_WallThePanicGuardUsesTheTerminalRecorder is a STRUCTURAL wall,
// and it exists because mutation testing proved the behavioural gate above is
// not enough.
//
// `TestChaos73_DefectSupervisorPanicIsTerminalAndSaysSo` drives the two
// recorders directly and asserts each produces the right state and remedy. It
// says nothing about which one the panic guard CALLS. Swapping them —
//
//	noteCPGRPCServeEnded("bind loop panicked")   // instead of ...SupervisorDown
//
// leaves that gate green (verified: `ok`), while a panicked supervisor is then
// reported as an ordinary rebinding listener whose remedy says the recovery is
// automatic. Nothing is going to rebind, so the operator is told to wait for a
// recovery that cannot happen — the single worst wrong answer this plane can
// give, and the one CHAOS-66 reached the same way in its round 2.
//
// Behavioural coverage cannot close it: provoking a real panic inside the
// supervisor loop means injecting a fault into production code, and the only
// observable afterwards is a state both recorders can produce. So the WIRING is
// pinned instead — the same conclusion, for the same reason, as
// §36's TestChaos66 recorder wall and the sanitizeLog scan-count gate.
func TestChaos73_WallThePanicGuardUsesTheTerminalRecorder(t *testing.T) {
	body := cpReadSource(t, "cp_grpc_bind.go")
	i := strings.Index(body, "func (s *cpListenerSupervisor) run() {")
	if i < 0 {
		t.Fatal("could not locate the supervisor run loop — the wall is not reading what it claims to")
	}
	// The guard is the deferred recover at the top of run(); bound the window
	// to it rather than the whole loop, so a legitimate noteCPGRPCServeEnded
	// later in the loop does not satisfy this.
	guardStart := strings.Index(body[i:], "if v := recover(); v != nil {")
	if guardStart < 0 {
		t.Fatal("the supervisor run loop has no panic guard — a panic there leaves the Control Plane " +
			"permanently gone with every surface still green (the CHAOS-24 objection)")
	}
	guard := body[i+guardStart:]
	if j := strings.Index(guard, "}()"); j > 0 {
		guard = guard[:j]
	}

	if !strings.Contains(guard, "noteCPGRPCSupervisorDown(") {
		t.Error("the panic guard does not call noteCPGRPCSupervisorDown: a dead supervisor reported as a " +
			"rebinding listener tells the operator to wait for a recovery that will never come")
	}
	if strings.Contains(guard, "noteCPGRPCServeEnded(") {
		t.Error("the panic guard calls noteCPGRPCServeEnded, the NON-terminal recorder — the two states point " +
			"at opposite operator actions and must not be interchangeable at the call site")
	}
	if !strings.Contains(guard, "recordCrash(") {
		t.Error("the panic guard does not record the crash, so the stack that explains it is lost")
	}
}

// TestChaos73_WallTheBootPathDefersLeadershipToAnObservedBind is the structural
// half of the HA-ordering decision, and it is pinned structurally for the same
// reason as the wall above: the behavioural gates observe that onActivated RAN,
// not that the boot path routed the leadership resume through it.
//
// Moving `globalHA.ResumeAsLeader` back to a statement after the activation
// call would leave every gate in this file green while restoring the thing the
// deferral exists to prevent: a node asserting a leadership term it cannot
// exercise, because a "leader" no Data Plane can reach cannot serve HASync.
func TestChaos73_WallTheBootPathDefersLeadershipToAnObservedBind(t *testing.T) {
	body := cpReadSource(t, "cluster_startup.go")
	i := strings.Index(body, "func startControlPlaneWithHAResume(")
	if i < 0 {
		t.Fatal("could not locate startControlPlaneWithHAResume")
	}
	fn := body[i:]
	if j := strings.Index(fn, "\n}\n"); j > 0 {
		fn = fn[:j]
	}

	resume := strings.Index(fn, "globalHA.ResumeAsLeader(")
	if resume < 0 {
		t.Fatal("the boot path no longer resumes leadership at all — a persisted leader would silently stop " +
			"leading after a restart")
	}
	enable := strings.Index(fn, "enableControlPlaneResilient(")
	if enable < 0 {
		t.Error("the boot path does not go through enableControlPlaneResilient — if it calls the synchronous " +
			"enableControlPlane instead, a listener fault is an error nobody tolerates and the fatal is one " +
			"line away from coming back")
	}
	// The resume must sit INSIDE the callback, i.e. textually before the call
	// that consumes it, never as a statement after it.
	if enable >= 0 && resume > enable {
		t.Error("globalHA.ResumeAsLeader runs AFTER the activation call rather than inside its onActivated " +
			"callback — this node now asserts a leadership term while its listener may never have bound, and " +
			"a leader no Data Plane can reach cannot serve HASync")
	}
	if !strings.Contains(fn, "resumeLeadership := func()") {
		t.Error("the leadership resume is not expressed as the deferred callback the design depends on")
	}

	// The callback must be HANDED OVER and never invoked here, and these two
	// assertions are not redundant — mutation testing proved the ordering check
	// above passes against a shape that keeps the closure, passes `nil` in its
	// place and then calls it as a bare statement:
	//
	//	enableControlPlaneResilient(..., nil)
	//	resumeLeadership()                      // ← asserts the term regardless
	//
	// which is the defect with the deferral's own vocabulary wrapped around it.
	// The ordering check cannot see it (the closure is still defined first), so
	// the handover is pinned by identity.
	if !strings.Contains(fn, "cfg.ClusterDBPath, resumeLeadership)") {
		t.Error("the leadership callback is not passed to enableControlPlaneResilient — whatever else the " +
			"function does with it, the activation path is no longer what triggers the resume")
	}
	for _, line := range strings.Split(fn, "\n") {
		code, _, _ := strings.Cut(line, "//")
		if strings.TrimSpace(code) == "resumeLeadership()" {
			t.Error("resumeLeadership() is invoked directly in the boot path: the callback exists so the " +
				"OBSERVED bind triggers the resume, and calling it here asserts the leadership term whether " +
				"or not the listener ever came up")
		}
	}
}

// TestChaos73_DefectStarterIsReleasedOnlyAfterActivation pins the ordering
// inside the supervisor's success path, DETERMINISTICALLY.
//
// It exists because the behavioural control gate could not be trusted with
// this property. `TestChaos73_ControlHealthyBindIsSilent` checks, with a
// non-blocking receive, that onActivated has run by the time the starter
// returned — and it *did* catch the window once, under `-race`, which is how
// the defect was found. But re-running the mutation afterwards
// (`markFirstAttempt` moved back above the activation) it passed 3/3 under
// `-race` and 3/3 without: the window is microseconds wide and whether the
// starter's goroutine wins is pure scheduling. A gate that passes against the
// defect is worse than no gate, and a gate that can flake gets muted — the
// standing rule from §36's vacuous adopt/Stop gate and §40's two
// self-calibration findings.
//
// So the ordering is pinned by CONSTRUCTION instead of by timing: onActivated
// blocks, and the starter must not have returned while it is blocked. That
// fails every time against the defect and cannot flake against the fix,
// because the gate controls the schedule rather than racing it.
//
// Why the ordering matters: `startControlPlaneListener` returning is what lets
// `activateControlPlane` log "ControlPlane: enabled" and hand control back to
// main.go, which goes straight on to Data-Plane wiring, the admin UI and the
// proxy. Releasing it before the role is claimed means those steps run against
// a node still reporting `standalone`, with the HA leadership resume not yet
// done — the same class of lie this whole change exists to remove.
func TestChaos73_DefectStarterIsReleasedOnlyAfterActivation(t *testing.T) {
	cpChaosSetup(t)
	cpInsecure(t)

	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))

	entered := make(chan struct{})
	release := make(chan struct{})
	returned := make(chan struct{})

	// The handle is published through a mutex, not a bare variable: the
	// cleanup below can run while the starter goroutine is still blocked (that
	// is exactly the mutation case), so a plain assignment would be a data
	// race under -race rather than a clean failure.
	var supMu sync.Mutex
	var sup *cpListenerSupervisor
	go func() {
		defer close(returned)
		got, err := startControlPlaneListener(cpListenerConfig{addr: addr}, true, func() {
			close(entered)
			<-release // hold activation open
		})
		supMu.Lock()
		sup = got
		supMu.Unlock()
		if err != nil {
			t.Errorf("startControlPlaneListener: %v", err)
		}
	}()
	t.Cleanup(func() {
		// Let the held activation finish however the test ends, then stop the
		// supervisor — otherwise a failing run leaks a blocked goroutine and a
		// bound listener into the next test.
		select {
		case <-release:
		default:
			close(release)
		}
		// BOUNDED, not `<-returned`. Against the "never release the starter"
		// mutation the goroutine never finishes, and an unbounded wait here
		// turned the gate's failure into a HANG — which is nearly as useless as
		// passing, because the signal becomes an unexplained package timeout
		// rather than a named failure. Found by running that very mutation.
		select {
		case <-returned:
		case <-time.After(5 * time.Second):
			t.Errorf("startControlPlaneListener never returned — the boot would hang before the proxy " +
				"listener ever starts")
		}
		supMu.Lock()
		got := sup
		supMu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = got.Stop(ctx) // nil-safe
	})

	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("onActivated never ran on a healthy first-attempt bind")
	}

	// Activation is in flight and deliberately not finishing. The starter must
	// still be blocked.
	select {
	case <-returned:
		t.Fatal("startControlPlaneListener returned while the CP role was still being claimed: main.go would " +
			"go on to Data-Plane wiring, the admin UI and the proxy with this node still reporting " +
			"`standalone` and the HA leadership resume not yet run")
	case <-time.After(250 * time.Millisecond):
	}

	// And it DOES return once activation completes — the other half, so a fix
	// that simply never releases the starter cannot pass this.
	close(release)
	select {
	case <-returned:
	case <-time.After(15 * time.Second):
		t.Fatal("startControlPlaneListener never returned after activation completed — the boot would hang " +
			"before the proxy listener ever starts, which is worse than the defect")
	}
}
