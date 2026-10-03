package main

// cluster_grpc_bind_chaos_test.go — CHAOS-71 gates.
//
// The finding and the four rules are in cluster_grpc_bind.go's header. Every
// DEFECT gate below was verified failing against the reintroduced pre-fix
// shape; the CONTROLS exist because the cheapest way to pass every defect gate
// is to never bring the Control Plane up at all, which would be far worse than
// the defect.
//
// A NOTE ON WHY A STRUCTURAL WALL IS REQUIRED HERE, verified by mutation
// rather than assumed.
//
// The first draft of this file claimed that reintroducing the pre-fix
// `logFatalf` would kill the test binary and so could never be kept green —
// the property §33 records for the admin UI gates. That claim was MEASURED AND
// FALSE for this path: the fatal lives in `loadCluster`, nothing in the test
// binary drives `loadCluster` (the behavioural gates below call
// `startControlPlaneWithBindRetry` directly), so reverting cluster_startup.go
// to `logFatalf` left this entire suite PASSING. A gate that passes against
// the defect is worse than no gate.
//
// `TestChaos71_TheControlPlaneListenerPathHasNoFatal` is therefore the wall
// that actually holds the finding closed, and the behavioural gates below
// pin the mechanism that replaced it. The evidence for the fatal ITSELF is the
// real-binary reproduction recorded in cluster_grpc_bind.go's header, which is
// the only place it can be observed — a boot that ends in exit 1.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// cpGRPCChaosSetup isolates the process-global CP health record and the
// clusterRole/prelude globals, and FREEZES the read clock.
//
// Freezing is §36 round 3's determinism lesson: the read path ages an episode
// against the clock while these gates drive the write path with synthetic
// stamps, so leaving the real clock in place silently also asserts that under
// 30 s of WALL time passes between two statements of a test — true locally,
// false on a loaded CI runner under `-count=2`. A gate that wants an episode
// to AGE advances the injected clock explicitly, as the condition under test.
func cpGRPCChaosSetup(t *testing.T) time.Time {
	t.Helper()
	resetCPGRPCHealthForTest()
	t.Cleanup(resetCPGRPCHealthForTest)

	// Restore EVERY clusterRole field enableControlPlane writes, not just the
	// role. A PARTIAL cleanup is worse than none (CLAUDE.md's setupProxyTest
	// note): a leaked `grpcAddr` of "127.0.0.1:0" is read by
	// bootstrap.EnrollmentAddr (bootstrap.go) to build the DP enrollment
	// authority, so leaking it made the SEC-BOOTSTRAP-HOST-1 compose gates
	// answer 400 "invalid host" to their own legitimate-request CONTROL —
	// reachable only under -shuffle, as a red determinism gate. Found exactly
	// that way.
	prevPrelude := cpPreludeDone
	prevRuns := cpPreludeRuns
	prevClusterRole := clusterRole
	t.Cleanup(func() {
		cpPreludeDone = prevPrelude
		cpPreludeRuns = prevRuns
		clusterRole = prevClusterRole
	})

	// enableControlPlane starts the heartbeat monitor off appLifecycleCtx,
	// which main() owns and a test binary never sets — a nil deref, not a
	// production defect. Give it a context scoped to this test.
	prevCtx := appLifecycleCtx
	ctx, cancel := context.WithCancel(context.Background())
	appLifecycleCtx = ctx
	t.Cleanup(func() {
		cancel()
		appLifecycleCtx = prevCtx
	})

	base := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	cpGRPCHealthNow = func() time.Time { return base }
	return base
}

// captureCPGRPCAlerts swaps the alert seam for a recorder.
func captureCPGRPCAlerts(t *testing.T) *[]string {
	t.Helper()
	var mu sync.Mutex
	got := []string{}
	prev := fireCPGRPCListenerAlert
	fireCPGRPCListenerAlert = func(detail string) {
		mu.Lock()
		got = append(got, detail)
		mu.Unlock()
	}
	t.Cleanup(func() { fireCPGRPCListenerAlert = prev })
	return &got
}

// ─── DEFECT GATES ───────────────────────────────────────────────────────────

// TestChaos71_DefectOccupiedPortDoesNotKillTheProcess is the primary gate.
//
// Pre-fix this path reached `logFatalf`. Reproduced against the real binary:
// `ControlPlane gRPC: gRPC listen: listen tcp :19443: bind: address already in
// use` → exit 1, `proxy http_code=000`, admin UI never started. Here the
// equivalent must RETURN, with the fault recorded, and leave the supervisor
// retrying.
func TestChaos71_DefectOccupiedPortDoesNotKillTheProcess(t *testing.T) {
	cpGRPCChaosSetup(t)
	captureCPGRPCAlerts(t)

	port, release := occupyPort(t)
	defer release()

	cfg := clusterStartupConfig{
		CPAddr:        "127.0.0.1:" + strconv.Itoa(port),
		ClusterDBPath: filepath.Join(t.TempDir(), "cluster.json"),
	}
	prevInsecure := clusterInsecure
	clusterInsecure = true
	t.Cleanup(func() { clusterInsecure = prevInsecure })

	sup := startControlPlaneWithBindRetry(cfg, context.Background())
	if sup == nil {
		t.Fatal("expected a rebind supervisor to be armed after a failed bind")
	}
	t.Cleanup(func() { _ = sup.Stop(context.Background()) })

	snap := cpGRPCState()
	if !snap.Configured {
		t.Error("the node asked to be a Control Plane, so the plane must report CONFIGURED even though " +
			"the listener never came up — otherwise it is indistinguishable from a node that never asked " +
			"(the §36 noteSOCKS5Configured finding)")
	}
	if snap.Serving {
		t.Error("reported serving with no socket bound")
	}
	if snap.LastReason != "port_in_use" {
		t.Errorf("reason class = %q, want %q", snap.LastReason, "port_in_use")
	}
	if snap.Consecutive != 1 {
		t.Errorf("consecutive failures = %d, want 1", snap.Consecutive)
	}
	// clusterRole must NOT claim control-plane on a failed bind.
	if clusterRole.role == "control-plane" {
		t.Error("clusterRole claims control-plane with no listener bound")
	}
}

// TestChaos71_DefectBindRetrySucceedsOnceThePortFrees proves the retry is real:
// the whole point of not exiting is that the fault self-heals.
func TestChaos71_DefectBindRetrySucceedsOnceThePortFrees(t *testing.T) {
	cpGRPCChaosSetup(t)
	captureCPGRPCAlerts(t)

	port, release := occupyPort(t)
	cfg := clusterStartupConfig{
		CPAddr:        "127.0.0.1:" + strconv.Itoa(port),
		ClusterDBPath: filepath.Join(t.TempDir(), "cluster.json"),
	}
	prevInsecure := clusterInsecure
	clusterInsecure = true
	t.Cleanup(func() { clusterInsecure = prevInsecure })

	sup := startControlPlaneWithBindRetry(cfg, context.Background())
	if sup == nil {
		t.Fatal("expected a supervisor after the first bind failed")
	}
	t.Cleanup(func() { _ = sup.Stop(context.Background()) })

	release() // the predecessor finishes draining

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cpGRPCState().Serving {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	snap := cpGRPCState()
	if !snap.Serving {
		t.Fatalf("listener never rebound after the port freed: %+v", snap)
	}
	if snap.Binds < 1 {
		t.Errorf("binds = %d, want >= 1", snap.Binds)
	}
	// Recovery clears the failure episode — on OBSERVED evidence.
	if snap.Consecutive != 0 {
		t.Errorf("consecutive = %d after an observed bind, want 0", snap.Consecutive)
	}
	if clusterRole.role != "control-plane" {
		t.Errorf("clusterRole = %q after a successful rebind, want control-plane", clusterRole.role)
	}
	StopControlPlaneGRPC()
}

// TestChaos71_DefectPreludeRunsOnceAcrossRetries is the gate for rule 4, the
// half specific to THIS listener.
//
// `enableControlPlane`'s prelude calls
// `globalConfigStore.Update(CurrentConfigSnapshot())`, which INCREMENTS and
// PERSISTS the durable config-version floor and records an O(N) blocklist
// delta. Un-guarded, a retry loop ratchets the floor once per attempt and
// re-diffs the fleet's blocklist once per attempt — for a listener no Data
// Plane can reach. A mitigation for a crash loop must not itself be a churn
// loop.
func TestChaos71_DefectPreludeRunsOnceAcrossRetries(t *testing.T) {
	cpGRPCChaosSetup(t)

	prevInsecure := clusterInsecure
	clusterInsecure = true
	t.Cleanup(func() { clusterInsecure = prevInsecure })

	port, release := occupyPort(t)
	t.Cleanup(release) // occupyPort's release is sync.Once-guarded, so the
	// explicit release below plus this cleanup is safe.
	addr := "127.0.0.1:" + strconv.Itoa(port)
	dbPath := filepath.Join(t.TempDir(), "cluster.json")

	cpPreludeDone = false
	cpPreludeRuns = 0

	// Ten failed attempts, exactly as the supervisor makes them.
	for i := 0; i < 10; i++ {
		if err := enableControlPlane(addr, "", "", "", dbPath); err == nil {
			t.Fatalf("attempt %d unexpectedly bound an occupied port", i)
		}
	}

	if cpPreludeRuns != 1 {
		t.Errorf("the one-time prelude ran %d times across 10 failed bind attempts (want exactly 1): "+
			"each run increments and PERSISTS the durable config-version floor and re-diffs a "+
			"blocklist of up to 2M hosts, so a rebind loop would ratchet the floor and rebuild the "+
			"fleet snapshot once per attempt — for a listener no Data Plane can reach", cpPreludeRuns)
	}

	// And a LATER successful bind must still not re-run it.
	release()
	if err := enableControlPlane(addr, "", "", "", dbPath); err != nil {
		t.Fatalf("bind after the port freed: %v", err)
	}
	t.Cleanup(StopControlPlaneGRPC)
	if cpPreludeRuns != 1 {
		t.Errorf("the prelude ran again on the successful bind (%d total, want 1)", cpPreludeRuns)
	}
}

// TestChaos71_DefectTLSMaterialIsClassifiedAndSelfHeals covers trigger 2 — the
// certificate-rotation window that was a fatal boot.
func TestChaos71_DefectTLSMaterialIsClassifiedAndSelfHeals(t *testing.T) {
	cpGRPCChaosSetup(t)
	captureCPGRPCAlerts(t)

	dir := t.TempDir()
	certPath, keyPath := writeTestKeyPair(t, dir)
	goodKey, err := os.ReadFile(keyPath) // #nosec G304 -- test-owned temp dir
	if err != nil {
		t.Fatal(err)
	}

	// The rotation window: the key file is present but truncated, exactly as a
	// certbot / cert-manager / Docker-secret replacement leaves it for a moment.
	if err := os.WriteFile(keyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := clusterStartupConfig{
		CPAddr:        "127.0.0.1:0",
		CPCert:        certPath,
		CPKey:         keyPath,
		ClusterDBPath: filepath.Join(dir, "cluster.json"),
	}
	sup := startControlPlaneWithBindRetry(cfg, context.Background())
	if sup == nil {
		t.Fatal("expected a supervisor after the TLS material failed to load")
	}
	t.Cleanup(func() { _ = sup.Stop(context.Background()) })

	if got := cpGRPCState().LastReason; got != "tls_certificate" {
		t.Errorf("reason class = %q, want %q — the operator remedy for a rotation window is "+
			"\"do nothing, it self-heals\", which a generic listen_failed cannot say", got, "tls_certificate")
	}

	// The rotation completes: the material is re-read on the NEXT attempt.
	if err := os.WriteFile(keyPath, goodKey, 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cpGRPCState().Serving {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !cpGRPCState().Serving {
		t.Fatal("the listener never came up after the certificate rotation completed — the TLS " +
			"material must be re-read on every attempt, or a rotation window needs a restart")
	}
	StopControlPlaneGRPC()
}

// TestChaos71_DefectPortCollisionWithProxyIsRefusedPreBoot covers the third
// reproduced trigger. `-cp-grpc-addr :8080` with `-port 8080` had the Control
// Plane (initCluster, main.go:228) win the port and the PROXY
// (buildAndStartProxyServer, :271) die on logFatalf("Proxy error") — an
// unattended crash loop whose log line sends the operator hunting an external
// squatter on a port Culvert itself took.
func TestChaos71_DefectPortCollisionWithProxyIsRefusedPreBoot(t *testing.T) {
	cases := []struct {
		name          string
		proxy, ui, s5 int
		cpAddr        string
		wantErr       bool
	}{
		{"cp collides with proxy", 8080, 9090, 0, ":8080", true},
		{"cp collides with ui", 8080, 9090, 0, "0.0.0.0:9090", true},
		{"cp collides with socks5", 8080, 9090, 1080, "[::]:1080", true},
		{"cp on its own port", 8080, 9090, 1080, ":50051", false},
		{"cp unset", 8080, 9090, 1080, "", false},
		// An address the helper cannot parse is the listener's own problem to
		// report with the real kernel error; inventing a collision from a
		// failed parse would be the "evidence must match the claim" defect.
		{"cp address unparseable", 8080, 9090, 0, "not-an-address", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePortCollisions(tc.proxy, tc.ui, tc.s5, tc.cpAddr)
			if tc.wantErr && err == nil {
				t.Errorf("validatePortCollisions(%d,%d,%d,%q) = nil, want a pre-boot refusal",
					tc.proxy, tc.ui, tc.s5, tc.cpAddr)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validatePortCollisions(%d,%d,%d,%q) = %v, want nil",
					tc.proxy, tc.ui, tc.s5, tc.cpAddr, err)
			}
		})
	}
}

// TestChaos71_DefectTerminalStateIsNotReportedAsRetrying pins §36 round 2's
// finding: one wording for both states either sends an operator to restart a
// gateway to achieve what is already in progress, or promises an automatic
// rebind that is not coming.
func TestChaos71_DefectTerminalStateIsNotReportedAsRetrying(t *testing.T) {
	base := cpGRPCChaosSetup(t)
	captureCPGRPCAlerts(t)
	noteCPGRPCConfigured(":50051")

	// Retrying: warn, and the action must say no action is needed yet.
	noteCPGRPCBindFailure("port_in_use", time.Second, base)
	row := checkControlPlaneGRPC()
	if row.Status != diagWarn {
		t.Errorf("a listener still retrying under the threshold: status = %q, want %q", row.Status, diagWarn)
	}
	if !strings.Contains(row.OperatorAction, "No action yet") {
		t.Errorf("retrying action = %q, want it to say no action is needed yet", row.OperatorAction)
	}

	// Terminal: fail, and the action must name the restart.
	noteCPGRPCSupervisorDown("bind loop panicked")
	row = checkControlPlaneGRPC()
	if row.Status != diagFail {
		t.Errorf("a terminally down listener: status = %q, want %q", row.Status, diagFail)
	}
	if !strings.Contains(strings.ToLower(row.OperatorAction), "restart") {
		t.Errorf("terminal action = %q, want it to name the restart that is genuinely required", row.OperatorAction)
	}
	// The message legitimately contains the word "retrying" — inside "nothing
	// is retrying it". What it must not do is CLAIM a retry is in progress.
	if strings.Contains(row.Message, "is retrying (") {
		t.Errorf("terminal message = %q, must not claim a retry is in progress", row.Message)
	}
	if !strings.Contains(row.Message, "nothing is retrying") {
		t.Errorf("terminal message = %q, want it to state plainly that nothing is retrying the bind", row.Message)
	}
}

// TestChaos71_DefectUnavailabilityIsADurationNotACount pins the CHAOS-54/57/66
// rule: paging on a count would page on every ordinary redeploy, where a
// predecessor still holds the port for a few seconds.
func TestChaos71_DefectUnavailabilityIsADurationNotACount(t *testing.T) {
	base := cpGRPCChaosSetup(t)
	alerts := captureCPGRPCAlerts(t)
	noteCPGRPCConfigured(":50051")

	// A burst of failures inside a few seconds must NOT page.
	for i := 0; i < 40; i++ {
		noteCPGRPCBindFailure("port_in_use", time.Second, base.Add(time.Duration(i)*100*time.Millisecond))
	}
	if len(*alerts) != 0 {
		t.Errorf("a %v burst of 40 bind failures paged (%d alert(s)) — unavailability is a DURATION",
			4*time.Second, len(*alerts))
	}
	if cpGRPCState().Unavailable {
		t.Error("reported unavailable after 4s of a 30s threshold")
	}

	// Past the threshold it pages exactly once per episode.
	noteCPGRPCBindFailure("port_in_use", time.Second, base.Add(cpGRPCBindUnavailableAfter+time.Second))
	noteCPGRPCBindFailure("port_in_use", time.Second, base.Add(cpGRPCBindUnavailableAfter+2*time.Second))
	if len(*alerts) != 1 {
		t.Fatalf("alerts = %d, want exactly 1 fire-once-per-episode page: %v", len(*alerts), *alerts)
	}
	if d := (*alerts)[0]; !strings.Contains(d, "unaffected") {
		t.Errorf("the page must state that the proxy and admin UI are unaffected — before CHAOS-71 "+
			"this condition meant the whole gateway was gone, so an operator who remembers the old "+
			"behaviour must not go looking for a dead data plane. Got: %q", d)
	}
}

// TestChaos71_DefectSleepCannotStraddleTheThreshold pins CHAOS-55's
// recoveryPollCeiling rule: the alert is ATTEMPT-driven and nothing else wakes
// the loop, so a sleep longer than the time remaining to the threshold leaves
// a documented outage unpaged for the difference.
func TestChaos71_DefectSleepCannotStraddleTheThreshold(t *testing.T) {
	cases := []struct {
		name             string
		wait, failingFor time.Duration
		wantMax          time.Duration
	}{
		{"would overshoot the threshold", 30 * time.Second, 25 * time.Second, 5 * time.Second},
		{"fits inside the threshold", 2 * time.Second, 5 * time.Second, 2 * time.Second},
		{"threshold already crossed: ceiling governs freely", 30 * time.Second, time.Minute, 30 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := clampCPGRPCBindSleep(tc.wait, tc.failingFor)
			if got > tc.wantMax {
				t.Errorf("clamp(%v, failingFor=%v) = %v, want <= %v", tc.wait, tc.failingFor, got, tc.wantMax)
			}
			if got < cpGRPCBindClampFloor && got != tc.wait {
				t.Errorf("clamp produced %v, below the %v floor — a near-zero spin", got, cpGRPCBindClampFloor)
			}
		})
	}
}

// TestChaos71_DefectClassifierNamesEachFaultDistinctly pins the bounded
// vocabulary and §36's timeout-qualification of network_error: *net.OpError
// satisfies net.Error UNCONDITIONALLY, so the unqualified form reports every
// unrecognised errno as a network fault and makes listen_failed unreachable.
func TestChaos71_DefectClassifierNamesEachFaultDistinctly(t *testing.T) {
	seen := map[string]bool{}
	for _, reason := range []string{
		"port_in_use", "permission_denied", "address_unavailable",
		"descriptors_exhausted", "tls_certificate",
	} {
		remedy := cpGRPCBindRemedy(reason, ":50051")
		if seen[remedy] {
			t.Errorf("reason %q reuses another class's remedy — a bounded classifier is worth "+
				"nothing if one remedy is printed for every class (§36 round 3)", reason)
		}
		seen[remedy] = true
		// Two clauses are invariant in every branch and must stay.
		if !strings.Contains(remedy, "rebinds automatically") {
			t.Errorf("remedy for %q does not say the listener rebinds by itself, so an operator "+
				"may restart a gateway to achieve what is already happening: %q", reason, remedy)
		}
		if !strings.Contains(remedy, "unaffected") {
			t.Errorf("remedy for %q does not say the proxy and admin UI are unaffected: %q", reason, remedy)
		}
	}
}

// TestChaos71_DefectHealthSnapshotDependsOnlyOnTheInjectedClock is the
// determinism wall, §36 round 3.
//
// Both halves are required: holding the clock still across real elapsed time
// must NOT move the duration, AND advancing the injected clock alone MUST move
// it — without the second half a read path that ignores the clock entirely
// would pass.
func TestChaos71_DefectHealthSnapshotDependsOnlyOnTheInjectedClock(t *testing.T) {
	base := cpGRPCChaosSetup(t)
	captureCPGRPCAlerts(t)
	noteCPGRPCConfigured(":50051")
	noteCPGRPCBindFailure("port_in_use", time.Second, base)

	first := cpGRPCState().FailingFor
	time.Sleep(120 * time.Millisecond) // real wall time passes
	if second := cpGRPCState().FailingFor; second != first {
		t.Errorf("the snapshot moved with WALL time while the injected clock was held still "+
			"(%v → %v): a health snapshot must be a pure function of recorded state and the "+
			"injected clock", first, second)
	}

	cpGRPCHealthNow = func() time.Time { return base.Add(45 * time.Second) }
	aged := cpGRPCState()
	if aged.FailingFor < 45*time.Second {
		t.Errorf("advancing the injected clock did not age the episode (%v) — a duration derived "+
			"from two stored stamps FREEZES between attempts, which is the §36 round-3 defect", aged.FailingFor)
	}
	if !aged.Unavailable {
		t.Error("an episode aged past the threshold by the clock alone must read as unavailable; " +
			"otherwise the row says \"retrying\" and the gauge reads 1 after the documented threshold elapsed")
	}
}

// TestChaos71_DefectClockRollbackCannotShrinkAnObservedOutage — the max() in
// cpGRPCElapsedSince. Deliberately the opposite of CHAOS-61's rollback verdict:
// there the fail-safe answer is distrusting a remote value, here it is the
// longer duration.
func TestChaos71_DefectClockRollbackCannotShrinkAnObservedOutage(t *testing.T) {
	first := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	last := first.Add(90 * time.Second)
	rolledBack := first.Add(-time.Hour)

	if got := cpGRPCElapsedSince(first, last, rolledBack); got < 90*time.Second {
		t.Errorf("a clock rollback shrank an outage already observed to last for 90s: got %v", got)
	}
	if got := cpGRPCElapsedSince(time.Time{}, time.Time{}, first); got != 0 {
		t.Errorf("no episode must report 0 elapsed, got %v", got)
	}
}

// ─── CONTROLS ───────────────────────────────────────────────────────────────

// TestChaos71_ControlHealthyControlPlaneStillBindsAndServes.
//
// The cheapest way to pass every defect gate above is to stop bringing the
// Control Plane up at all, which would silently delete cluster config
// distribution. This control fails against that.
func TestChaos71_ControlHealthyControlPlaneStillBindsAndServes(t *testing.T) {
	cpGRPCChaosSetup(t)
	captureCPGRPCAlerts(t)

	prevInsecure := clusterInsecure
	clusterInsecure = true
	t.Cleanup(func() { clusterInsecure = prevInsecure })

	cfg := clusterStartupConfig{
		CPAddr:        "127.0.0.1:0",
		ClusterDBPath: filepath.Join(t.TempDir(), "cluster.json"),
	}
	sup := startControlPlaneWithBindRetry(cfg, context.Background())
	if sup != nil {
		t.Error("a healthy bind must arm NO supervisor and register no shutdown hook it does not need")
		_ = sup.Stop(context.Background())
	}
	snap := cpGRPCState()
	if !snap.Serving {
		t.Fatalf("a healthy Control Plane did not come up: %+v", snap)
	}
	if snap.Total != 0 {
		t.Errorf("bind failures = %d on a healthy bind, want 0", snap.Total)
	}
	if clusterRole.role != "control-plane" {
		t.Errorf("clusterRole = %q, want control-plane", clusterRole.role)
	}
	if got := cpGRPCListenerStatus(); got != "ready" {
		t.Errorf("/health posture = %q, want ready", got)
	}
	if row := checkControlPlaneGRPC(); row.Status != diagOK {
		t.Errorf("contract row = %q, want %q", row.Status, diagOK)
	}
	StopControlPlaneGRPC()
}

// TestChaos71_ControlReadinessRowIsReportOnly.
//
// A node whose Control Plane listener cannot bind is proxying perfectly, so
// gating the default readiness verdict would eject a healthy gateway from the
// load balancer over its cluster-configuration plane — converting a management
// outage into the traffic outage this change exists to prevent. Strict callers
// opt in via ?strict=1.
func TestChaos71_ControlReadinessRowIsReportOnly(t *testing.T) {
	base := cpGRPCChaosSetup(t)
	captureCPGRPCAlerts(t)
	noteCPGRPCConfigured(":50051")
	noteCPGRPCBindFailure("port_in_use", time.Second, base)
	cpGRPCHealthNow = func() time.Time { return base.Add(5 * time.Minute) }

	checks := map[string]*readinessCheck{}
	appendCPGRPCReadinessCheck(checks)

	row, ok := checks["control_plane_grpc"]
	if !ok {
		t.Fatal("no control_plane_grpc readiness row on a configured Control Plane")
	}
	if row.Status != "fail" {
		t.Errorf("row status = %q, want fail on a listener that cannot bind", row.Status)
	}
	// FIXED detail: /ready is unauthenticated on the proxy port, so a count or
	// a reason class would fingerprint the node's state to anyone who can
	// reach it.
	for _, leak := range []string{"port_in_use", ":50051", "1"} {
		if strings.Contains(row.Detail, leak) {
			t.Errorf("readiness detail %q leaks %q — /ready is unauthenticated and its details are FIXED",
				row.Detail, leak)
		}
	}

	// appendCPGRPCReadinessCheck returns NOTHING and mutates only the map,
	// which is what makes it report-only BY CONSTRUCTION — it has no channel
	// through which to fail the default verdict. Assert the signature contract
	// has not grown one, the same way §33's control does.
	if len(checks) != 1 {
		t.Errorf("the readiness helper wrote %d rows, want exactly 1", len(checks))
	}

	// The two-tier contract: the row does NOT gate the default verdict, and a
	// caller that explicitly opts in via ?strict=1 DOES see it fail. Both
	// halves are needed — without the second, a row that was silently dropped
	// would satisfy "report-only" while telling nobody anything.
	lenient := httptest.NewRequest(http.MethodGet, "/ready", nil)
	if strictVerdictFails(lenient, checks) {
		t.Error("a plain /ready failed on the Control Plane listener row: a node whose CP listener " +
			"cannot bind is proxying perfectly, so gating the default verdict would eject a healthy " +
			"gateway from the load balancer over its cluster-configuration plane — turning a " +
			"management outage into the traffic outage this change exists to prevent")
	}
	strict := httptest.NewRequest(http.MethodGet, "/ready?strict=1", nil)
	if !strictVerdictFails(strict, checks) {
		t.Error("/ready?strict=1 did not fail on a failing Control Plane listener row — strict " +
			"callers must be able to opt in, or the row is unreachable for anyone who wants it")
	}

	// The row is absent on a node that is not a Control Plane.
	resetCPGRPCHealthForTest()
	bare := map[string]*readinessCheck{}
	appendCPGRPCReadinessCheck(bare)
	if _, present := bare["control_plane_grpc"]; present {
		t.Error("a node with no Control Plane listener configured must carry NO row — a flat row " +
			"on every standalone proxy is indistinguishable from a broken Control Plane")
	}
}

// TestChaos71_ControlUnconfiguredNodeIsSilent — the emission rule. A `0` on a
// standalone proxy that never asked to be a Control Plane is indistinguishable
// from a broken one, and the documented paging rule is `== 0`.
func TestChaos71_ControlUnconfiguredNodeIsSilent(t *testing.T) {
	cpGRPCChaosSetup(t)

	if snap := cpGRPCState(); snap.Configured {
		t.Fatal("a fresh record must not report configured")
	}
	if got := cpGRPCListenerStatus(); got != "disabled" {
		t.Errorf("/health posture on a non-Control-Plane node = %q, want disabled", got)
	}
	row := checkControlPlaneGRPC()
	if row.Status != diagOK {
		t.Errorf("contract row on a non-Control-Plane node = %q, want %q — nothing is wrong with a "+
			"standalone proxy, and a warn here would dirty every appliance's aggregate verdict",
			row.Status, diagOK)
	}
	if row.OperatorAction != "" {
		t.Errorf("an ok row must carry no operator action, got %q", row.OperatorAction)
	}
}

// TestChaos71_ControlCleanShutdownIsNotAFault — a teardown must never be
// reported as a listener fault, or every graceful stop pages.
func TestChaos71_ControlCleanShutdownIsNotAFault(t *testing.T) {
	cpGRPCChaosSetup(t)
	alerts := captureCPGRPCAlerts(t)
	noteCPGRPCConfigured(":50051")
	noteCPGRPCBound()
	noteCPGRPCStopped()

	if got := cpGRPCListenerStatus(); got != "stopped" {
		t.Errorf("/health posture after a clean stop = %q, want stopped", got)
	}
	if row := checkControlPlaneGRPC(); row.Status != diagOK {
		t.Errorf("contract row after a clean stop = %q, want %q", row.Status, diagOK)
	}
	if len(*alerts) != 0 {
		t.Errorf("a clean shutdown paged: %v", *alerts)
	}
	checks := map[string]*readinessCheck{}
	appendCPGRPCReadinessCheck(checks)
	if _, present := checks["control_plane_grpc"]; present {
		t.Error("a node that is shutting down must carry no readiness row")
	}
}

// TestChaos71_ControlSupervisorStopIsPromptDuringBackoff — a shutdown must
// never have to wait out a backoff (the CHAOS-54 rule). The supervisor's first
// sleep is at the 1 s floor, so an un-interruptible sleep shows up immediately.
func TestChaos71_ControlSupervisorStopIsPromptDuringBackoff(t *testing.T) {
	cpGRPCChaosSetup(t)
	captureCPGRPCAlerts(t)

	prevInsecure := clusterInsecure
	clusterInsecure = true
	t.Cleanup(func() { clusterInsecure = prevInsecure })

	port, release := occupyPort(t)
	defer release()

	cfg := clusterStartupConfig{
		CPAddr:        "127.0.0.1:" + strconv.Itoa(port),
		ClusterDBPath: filepath.Join(t.TempDir(), "cluster.json"),
	}
	sup := startControlPlaneWithBindRetry(cfg, context.Background())
	if sup == nil {
		t.Fatal("expected a supervisor")
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sup.Stop(ctx); err != nil {
		t.Fatalf("Stop did not complete: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 900*time.Millisecond {
		t.Errorf("Stop took %v — it waited out a backoff sleep instead of interrupting it", elapsed)
	}

	// Stop is idempotent and nil-safe.
	if err := sup.Stop(context.Background()); err != nil {
		t.Errorf("second Stop returned %v, want nil (idempotent)", err)
	}
	var nilSup *cpGRPCSupervisor
	if err := nilSup.Stop(context.Background()); err != nil {
		t.Errorf("nil Stop returned %v, want nil", err)
	}
}

// ── Structural wall ─────────────────────────────────────────────────────────

// TestChaos71_TheControlPlaneListenerPathHasNoFatal is the wall against
// reintroduction, and the measurement in this file's header is why it exists:
// behavioural coverage of this path cannot see the defect at all, because the
// fatal sits in a boot function no test binary calls.
//
// `cluster_startup.go` keeps exactly ONE deliberate fatal, allowlisted below.
// Everything else on the Control Plane listener path must degrade.
func TestChaos71_TheControlPlaneListenerPathHasNoFatal(t *testing.T) {
	// The ONE justified fatal on this path: a fencing lease the operator
	// explicitly asked for and that cannot be built. Silently running legacy
	// HA when the operator configured a fence is an invisible SAFETY
	// downgrade (ADR-0005), which is a different trade from an unavailable
	// listener — there is no degraded mode that preserves the guarantee.
	allowed := map[string]bool{"HA lease": true}

	files := []string{"cluster_startup.go", "cluster_grpc_bind.go", "cluster_grpc_health.go"}
	checked := 0
	for _, f := range files {
		src, err := os.ReadFile(f) // #nosec G304 -- fixed in-repo list
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			code, _, _ := strings.Cut(line, "//")
			checked++
			if !strings.Contains(code, "logFatalf(") && !strings.Contains(code, "log.Fatal") {
				continue
			}
			exempt := false
			for marker := range allowed {
				if strings.Contains(code, marker) {
					exempt = true
					break
				}
			}
			if !exempt {
				t.Errorf("%s:%d reintroduces a fatal on the Control Plane listener path: %s\n"+
					"A management-plane listener may never terminate the proxy data plane: initCluster "+
					"runs BEFORE startAdminUI and buildAndStartProxyServer, so this exits with no proxy, "+
					"no admin UI and no health endpoint (CHAOS-71).",
					f, i+1, strings.TrimSpace(line))
			}
		}
	}
	// NOT-VACUOUS: a selector that stops matching real files would leave this
	// green forever while proving nothing.
	if checked < 500 {
		t.Fatalf("the fatal scan examined only %d lines — it is not reading the listener sources", checked)
	}
}

// TestChaos71_TheFatalWallDetectsAReintroducedFatal is the CONTROL for the wall
// above: it runs the wall's own predicate over a synthetic line, so a scan that
// silently stopped recognising `logFatalf` cannot pass forever.
func TestChaos71_TheFatalWallDetectsAReintroducedFatal(t *testing.T) {
	reintroduced := `\tlogFatalf("ControlPlane gRPC: %v", err)`
	code, _, _ := strings.Cut(reintroduced, "//")
	if !strings.Contains(code, "logFatalf(") {
		t.Fatal("control failed: the wall's predicate no longer recognises a reintroduced logFatalf")
	}
	// And the allowlist must not swallow it.
	if strings.Contains(code, "HA lease") {
		t.Fatal("control failed: the allowlist marker matches a CP gRPC fatal")
	}

	// The deliberate fatal must still be recognised as exempt, or the wall
	// would fail the moment anyone reads cluster_startup.go.
	deliberate := `\t\t\tlogFatalf("HA lease: %v", err)`
	dcode, _, _ := strings.Cut(deliberate, "//")
	if !strings.Contains(dcode, "HA lease") {
		t.Fatal("control failed: the ADR-0005 lease fatal is no longer matched by its allowlist marker")
	}
}
