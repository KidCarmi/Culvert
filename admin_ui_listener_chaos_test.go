package main

// admin_ui_listener_chaos_test.go — CHAOS-57 gates.
//
// The headline gate is structural and needs no assertion of its own: every test
// in this file drives the code path that USED to call logFatalf. logFatalf
// os.Exit(1)s, so reintroducing it anywhere in the admin UI listen path makes
// the TEST BINARY ITSELF exit mid-run and takes the whole package down with a
// non-zero status. There is no way to reintroduce the defect and keep this file
// green.
//
// Defect gates (verified failing against the pre-fix tree):
//   - OccupiedPortDoesNotKillTheProcess
//   - UnreadableCertificateDoesNotKillTheProcess
//   - ListenerRebindsWhenThePortFrees        (no recovery path existed at all)
//   - CertificateRotationSelfHeals           (certs were read once, at boot)
//   - ProxyHealthReportsTheAdminPlane        (no surface existed at all)
//
// Controls (a fix that passed the defect gates while being worse):
//   - ReadinessRowIsReportOnly       — a fix that failed /ready would convert a
//     management outage into the traffic outage the change exists to prevent.
//   - RecoveryRequiresEvidence       — a loop that "recovered" on elapsed time
//     would report a still-dead admin plane as healthy.
//   - HealthyPathIsUnchanged         — a fix that reported a fault on a normal
//     boot would page on every appliance.
//   - RepeatedFailuresDoNotLeakListeners — the ServeTLS-does-not-close hazard.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// occupyPort binds a listener and returns its port plus a release func, so a
// test can hold the admin UI's port the way a draining predecessor or an
// unrelated host service does.
func occupyPort(t *testing.T) (port int, release func()) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupyPort: %v", err)
	}
	var once sync.Once
	return ln.Addr().(*net.TCPAddr).Port, func() { once.Do(func() { _ = ln.Close() }) }
}

// newTestAdminServer is a bare *http.Server standing in for the admin UI, so
// these gates exercise the listen/retry machinery without dragging in the admin
// mux's global state.
func newTestAdminServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/probe", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	return &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
}

// runAdminUILoop runs the retry loop for one test and, at cleanup, stops it and
// WAITS for it to return. Closing stop ends a backoff wait, but a listener that
// is serving sits in http.Server.Serve, which does not watch stop, so the
// server is closed as well. Without the wait the goroutine outlived its test
// and raced the next test's globals (it logs "UIHTTP: …" through `logger` just
// after recording Serving; CI caught the race against
// TestAdmissionMigration_TransitionLoggingUsesEngineObservation swapping it).
func runAdminUILoop(t *testing.T, srv *http.Server, port int, certFile, keyFile string) {
	t.Helper()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveAdminUIWithRetry(srv, port, certFile, keyFile, stop)
	}()
	t.Cleanup(func() {
		close(stop)
		_ = srv.Close() // a later Serve returns ErrServerClosed at once
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("admin UI retry loop did not return after stop + Close")
		}
	})
}

// captureAdminUIAlerts swaps the alert seam so a test observes transitions
// synchronously rather than racing the process-global alert sink.
func captureAdminUIAlerts(t *testing.T) *[]string {
	t.Helper()
	prev := fireAdminUIListenerAlert
	var mu sync.Mutex
	got := []string{}
	fireAdminUIListenerAlert = func(detail string) {
		mu.Lock()
		got = append(got, detail)
		mu.Unlock()
	}
	t.Cleanup(func() { fireAdminUIListenerAlert = prev })
	return &got
}

// waitFor polls cond until it holds or the budget expires.
func waitForAdminUI(t *testing.T, budget time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", budget, what)
}

// writeTestKeyPair writes a valid self-signed cert/key pair.
func writeTestKeyPair(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "culvert-admin-ui-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	certPath = filepath.Join(dir, "ui.crt")
	keyPath = filepath.Join(dir, "ui.key")
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalkey: %v", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// ── defect gates ─────────────────────────────────────────────────────────────

// TestChaos57_OccupiedPortDoesNotKillTheProcess is the core gate.
//
// Pre-fix, `startUI`'s goroutine called logFatalf on a bind failure, so an
// admin-plane port conflict terminated the whole appliance — proxy included.
// Reproduced against the real binary: with :19090 held, the process logged
// "UI server error: listen tcp :19090: bind: address already in use" and
// exited 1, having already announced "Proxy: http://localhost:18080".
//
// If that branch returns, THIS TEST BINARY exits and the package fails.
func TestChaos57_OccupiedPortDoesNotKillTheProcess(t *testing.T) {
	resetAdminUIHealthForTest()
	t.Cleanup(resetAdminUIHealthForTest)
	captureAdminUIAlerts(t)

	port, release := occupyPort(t)
	defer release()

	noteAdminUIConfigured(port)
	runAdminUILoop(t, newTestAdminServer(), port, "", "")

	waitForAdminUI(t, 5*time.Second, "a recorded bind failure", func() bool {
		return adminUIListenerState().Total > 0
	})

	snap := adminUIListenerState()
	if snap.Serving {
		t.Fatal("listener reports serving while the port is held by another process")
	}
	if snap.LastReason != "port_in_use" {
		t.Errorf("LastReason = %q, want %q", snap.LastReason, "port_in_use")
	}
	if snap.EverServed {
		t.Error("EverServed set although the listener never bound")
	}
	// The process is alive, and — the point of the change — the data plane's
	// own posture surface says so.
	if got := adminUIListenerStatus(); got != "degraded" {
		t.Errorf("adminUIListenerStatus() = %q, want %q", got, "degraded")
	}
}

// TestChaos57_UnreadableCertificateDoesNotKillTheProcess covers the second
// reproduced trigger: ListenAndServeTLS reads -tls-cert/-tls-key at call time,
// so a rotation that briefly leaves the pair unreadable was a boot that ended
// in "UI TLS error: tls: failed to find any PEM data in certificate input" and
// exit 1.
func TestChaos57_UnreadableCertificateDoesNotKillTheProcess(t *testing.T) {
	resetAdminUIHealthForTest()
	t.Cleanup(resetAdminUIHealthForTest)
	captureAdminUIAlerts(t)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "bad.crt")
	keyPath := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(certPath, []byte("not-a-cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("not-a-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	port, release := occupyPort(t)
	release() // free the port: the ONLY fault here is the certificate

	noteAdminUIConfigured(port)
	runAdminUILoop(t, newTestAdminServer(), port, certPath, keyPath)

	waitForAdminUI(t, 5*time.Second, "a recorded certificate failure", func() bool {
		return adminUIListenerState().Total > 0
	})
	if got := adminUIListenerState().LastReason; got != "tls_certificate" {
		t.Errorf("LastReason = %q, want %q", got, "tls_certificate")
	}
}

// TestChaos57_ListenerRebindsWhenThePortFrees is the recovery gate. Pre-fix
// there was no recovery path of any kind: the process was gone.
//
// Recovery must be declared on EVIDENCE — a listener that actually bound and
// serves a request — never on elapsed time.
func TestChaos57_ListenerRebindsWhenThePortFrees(t *testing.T) {
	resetAdminUIHealthForTest()
	t.Cleanup(resetAdminUIHealthForTest)
	captureAdminUIAlerts(t)

	port, release := occupyPort(t)
	noteAdminUIConfigured(port)
	runAdminUILoop(t, newTestAdminServer(), port, "", "")

	waitForAdminUI(t, 5*time.Second, "a recorded bind failure", func() bool {
		return adminUIListenerState().Total > 0
	})

	release() // the predecessor finishes draining

	waitForAdminUI(t, 20*time.Second, "the listener to rebind on its own", func() bool {
		return adminUIListenerState().Serving
	})

	// Evidence, not bookkeeping: the rebound listener must actually serve.
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/probe", port)) //nolint:noctx // short-lived test probe
	if err != nil {
		t.Fatalf("rebound admin listener does not serve: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("probe status = %d, want 200", resp.StatusCode)
	}

	snap := adminUIListenerState()
	if !snap.EverServed || snap.Binds != 1 {
		t.Errorf("EverServed=%v Binds=%d, want true/1", snap.EverServed, snap.Binds)
	}
	if snap.Failing || snap.Consecutive != 0 {
		t.Errorf("failure state not cleared on an observed bind: Failing=%v Consecutive=%d", snap.Failing, snap.Consecutive)
	}
	if got := adminUIListenerStatus(); got != "ready" {
		t.Errorf("status = %q, want %q", got, "ready")
	}
}

// TestChaos57_CertificateRotationSelfHeals pins the per-attempt certificate
// re-read. Pre-fix the pair was read exactly once, at boot, so a rotation that
// momentarily broke it required a restart — which, since the failure was fatal,
// is what the operator got, in a loop.
func TestChaos57_CertificateRotationSelfHeals(t *testing.T) {
	resetAdminUIHealthForTest()
	t.Cleanup(resetAdminUIHealthForTest)
	captureAdminUIAlerts(t)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ui.crt")
	keyPath := filepath.Join(dir, "ui.key")
	// Mid-rotation: the files exist but are not yet valid material.
	if err := os.WriteFile(certPath, []byte("-----BEGIN NONSENSE-----"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("-----BEGIN NONSENSE-----"), 0o600); err != nil {
		t.Fatal(err)
	}

	port, release := occupyPort(t)
	release()
	noteAdminUIConfigured(port)
	runAdminUILoop(t, newTestAdminServer(), port, certPath, keyPath)

	waitForAdminUI(t, 5*time.Second, "the certificate failure to be recorded", func() bool {
		return adminUIListenerState().Total > 0
	})

	// The rotation completes.
	goodCert, goodKey := writeTestKeyPair(t, dir)
	if goodCert != certPath || goodKey != keyPath {
		t.Fatalf("test key pair landed on unexpected paths: %s %s", goodCert, goodKey)
	}

	waitForAdminUI(t, 20*time.Second, "the listener to pick up the rotated certificate", func() bool {
		return adminUIListenerState().Serving
	})

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, // #nosec G402 -- test probe against a self-signed pair
	}}
	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/probe", port)) //nolint:noctx // short-lived test probe
	if err != nil {
		t.Fatalf("listener did not come up on the rotated certificate: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("probe status = %d, want 200", resp.StatusCode)
	}
}

// TestChaos57_ProxyHealthReportsTheAdminPlane pins the surface that survives
// the fault. The admin port's own /healthz cannot report that the admin port is
// unreachable, so the posture rides the PROXY port's /health — where it did not
// exist at all before this change.
func TestChaos57_ProxyHealthReportsTheAdminPlane(t *testing.T) {
	resetAdminUIHealthForTest()
	t.Cleanup(resetAdminUIHealthForTest)

	if got := adminUIListenerStatus(); got != "disabled" {
		t.Errorf("unconfigured status = %q, want %q", got, "disabled")
	}

	// A monotonic fake timeline: the FIRST failure opens the episode, so
	// everything after it must be at or past that instant.
	t0 := time.Now()
	noteAdminUIConfigured(9090)
	noteAdminUIListenFailure("port_in_use", time.Second, t0)
	if got := adminUIListenerStatus(); got != "degraded" {
		t.Errorf("failing status = %q, want %q", got, "degraded")
	}

	// Past the threshold the posture escalates.
	noteAdminUIListenFailure("port_in_use", time.Second, t0.Add(adminUIUnavailableAfter))
	if got := adminUIListenerStatus(); got != "unavailable" {
		t.Errorf("unavailable status = %q, want %q", got, "unavailable")
	}

	noteAdminUIServing()
	if got := adminUIListenerStatus(); got != "ready" {
		t.Errorf("recovered status = %q, want %q", got, "ready")
	}
}

// ── controls ─────────────────────────────────────────────────────────────────

// TestChaos57_ReadinessRowIsReportOnly is the control that keeps the fix from
// being worse than the defect.
//
// A node whose admin UI cannot bind is proxying traffic perfectly. If the
// readiness row gated the DEFAULT verdict, the load balancer would eject a
// fully-functional gateway over its management plane — converting a management
// outage into exactly the traffic outage this whole change exists to prevent.
func TestChaos57_ReadinessRowIsReportOnly(t *testing.T) {
	resetAdminUIHealthForTest()
	t.Cleanup(resetAdminUIHealthForTest)

	noteAdminUIConfigured(9090)
	base := time.Now()
	noteAdminUIListenFailure("port_in_use", time.Second, base.Add(-2*adminUIUnavailableAfter))
	noteAdminUIListenFailure("port_in_use", time.Second, base)

	checks := map[string]*readinessCheck{}
	appendAdminUIReadinessCheck(checks)

	row, ok := checks["admin_ui"]
	if !ok {
		t.Fatal("no admin_ui readiness row on a configured, unavailable admin UI")
	}
	if row.Status != "fail" {
		t.Errorf("row status = %q, want %q", row.Status, "fail")
	}
	// The row exists and says fail — but appendAdminUIReadinessCheck must never
	// touch the caller's allOK verdict. It returns nothing and mutates only the
	// map, which is what makes it report-only by construction; assert the
	// signature contract has not grown a verdict channel.
	if len(checks) != 1 {
		t.Errorf("readiness helper wrote %d rows, want exactly 1", len(checks))
	}

	// And it must vanish entirely on a node that never configured a UI.
	resetAdminUIHealthForTest()
	empty := map[string]*readinessCheck{}
	appendAdminUIReadinessCheck(empty)
	if len(empty) != 0 {
		t.Errorf("unconfigured node grew %d readiness rows, want 0", len(empty))
	}
}

// TestChaos57_RecoveryRequiresEvidence pins the house rule: recovery is
// declared by an OBSERVED bind, never by elapsed time. A retry loop that has
// stopped failing because it has stopped attempting looks identical to a bound
// listener.
func TestChaos57_RecoveryRequiresEvidence(t *testing.T) {
	resetAdminUIHealthForTest()
	t.Cleanup(resetAdminUIHealthForTest)

	noteAdminUIConfigured(9090)
	base := time.Now()
	noteAdminUIListenFailure("port_in_use", time.Second, base.Add(-2*adminUIUnavailableAfter))
	noteAdminUIListenFailure("port_in_use", time.Second, base)

	if !adminUIListenerState().Unavailable {
		t.Fatal("precondition: expected the unavailable state to be latched")
	}
	// Time passes. Nothing else happens.
	if snap := adminUIListenerState(); !snap.Unavailable || snap.Serving {
		t.Error("state changed without an observed bind — recovery must be evidence-based")
	}

	noteAdminUIServing()
	if snap := adminUIListenerState(); snap.Unavailable || !snap.Serving {
		t.Error("an observed bind did not clear the unavailable state")
	}
}

// TestChaos57_UnavailabilityIsADurationNotACount: the backoff ceiling is
// reached in under a minute, so a count-keyed threshold would page on every
// redeploy in which a predecessor was still draining the port.
func TestChaos57_UnavailabilityIsADurationNotACount(t *testing.T) {
	resetAdminUIHealthForTest()
	t.Cleanup(resetAdminUIHealthForTest)
	alerts := captureAdminUIAlerts(t)

	noteAdminUIConfigured(9090)
	now := time.Now()
	for i := 0; i < 200; i++ {
		noteAdminUIListenFailure("port_in_use", time.Second, now)
	}
	if adminUIListenerState().Unavailable {
		t.Error("200 failures inside the window latched unavailable — the threshold is a duration, not a count")
	}
	if len(*alerts) != 0 {
		t.Errorf("alert fired inside the window: %v", *alerts)
	}

	noteAdminUIListenFailure("port_in_use", time.Second, now.Add(adminUIUnavailableAfter))
	if !adminUIListenerState().Unavailable {
		t.Error("crossing the duration threshold did not latch unavailable")
	}
	if len(*alerts) != 1 {
		t.Fatalf("alerts after crossing the threshold = %d, want 1", len(*alerts))
	}
	// The alert must state that traffic is unaffected — an operator paged at
	// 03:00 needs to know this is not a traffic incident.
	if !strings.Contains((*alerts)[0], "data plane is UNAFFECTED") {
		t.Errorf("alert does not state the data-plane posture: %q", (*alerts)[0])
	}
}

// TestChaos57_AlertFiresOncePerEpisodeAndRearms: one page per episode, and a
// second incident after a genuine recovery pages again.
func TestChaos57_AlertFiresOncePerEpisodeAndRearms(t *testing.T) {
	resetAdminUIHealthForTest()
	t.Cleanup(resetAdminUIHealthForTest)
	alerts := captureAdminUIAlerts(t)

	noteAdminUIConfigured(9090)
	now := time.Now()
	noteAdminUIListenFailure("port_in_use", time.Second, now)
	for i := 0; i < 20; i++ {
		noteAdminUIListenFailure("port_in_use", time.Second, now.Add(adminUIUnavailableAfter+time.Duration(i)*time.Second))
	}
	if len(*alerts) != 1 {
		t.Fatalf("alerts during one episode = %d, want 1", len(*alerts))
	}

	noteAdminUIServing() // genuine recovery re-arms the latch
	later := now.Add(time.Hour)
	noteAdminUIListenFailure("port_in_use", time.Second, later)
	noteAdminUIListenFailure("port_in_use", time.Second, later.Add(adminUIUnavailableAfter))
	if len(*alerts) != 2 {
		t.Errorf("alerts after a second episode = %d, want 2", len(*alerts))
	}
}

// TestChaos57_PublicSurfacesCarryNoRawError. /health and /ready are served
// UNAUTHENTICATED on the proxy port, so neither may carry the bind address, the
// certificate path or the raw error text. The resolution stays on the
// role-gated contract row, the alert and the log.
func TestChaos57_PublicSurfacesCarryNoRawError(t *testing.T) {
	resetAdminUIHealthForTest()
	t.Cleanup(resetAdminUIHealthForTest)

	noteAdminUIConfigured(9090)
	base := time.Now()
	noteAdminUIListenFailure("port_in_use", time.Second, base.Add(-2*adminUIUnavailableAfter))
	noteAdminUIListenFailure("port_in_use", time.Second, base)

	// /health is a fixed enum.
	switch adminUIListenerStatus() {
	case "disabled", "ready", "degraded", "unavailable", "stopped":
	default:
		t.Errorf("adminUIListenerStatus() returned a non-enum value %q", adminUIListenerStatus())
	}

	// /ready details are fixed strings per branch.
	checks := map[string]*readinessCheck{}
	appendAdminUIReadinessCheck(checks)
	detail := checks["admin_ui"].Detail
	for _, leak := range []string{"9090", "address already in use", "/tmp", ".crt", ".key"} {
		if strings.Contains(detail, leak) {
			t.Errorf("readiness detail %q leaks %q on an unauthenticated surface", detail, leak)
		}
	}
}

// TestChaos57_ContractRowSeverityLadder pins the operator-contract row across
// every state, including that a clean shutdown is never reported as a fault.
func TestChaos57_ContractRowSeverityLadder(t *testing.T) {
	resetAdminUIHealthForTest()
	t.Cleanup(resetAdminUIHealthForTest)

	if got := checkAdminUIListener(); got.Status != diagOK {
		t.Errorf("unconfigured row = %v, want ok", got.Status)
	}

	noteAdminUIConfigured(9090)
	noteAdminUIServing()
	if got := checkAdminUIListener(); got.Status != diagOK {
		t.Errorf("serving row = %v, want ok", got.Status)
	}

	t0 := time.Now()
	noteAdminUIListenFailure("port_in_use", time.Second, t0)
	if got := checkAdminUIListener(); got.Status != diagWarn {
		t.Errorf("transient-failure row = %v, want warn", got.Status)
	}

	noteAdminUIListenFailure("port_in_use", time.Second, t0.Add(adminUIUnavailableAfter))
	row := checkAdminUIListener()
	if row.Status != diagFail {
		t.Errorf("unavailable row = %v, want fail", row.Status)
	}
	if row.OperatorAction == "" {
		t.Error("a fail row must carry an operator action")
	}
	if !strings.Contains(row.OperatorAction, "proxy data plane is unaffected") {
		t.Errorf("fail row does not tell the operator traffic is unaffected: %q", row.OperatorAction)
	}

	// A clean shutdown is not a fault.
	noteAdminUIStopped()
	if got := checkAdminUIListener(); got.Status != diagOK {
		t.Errorf("shutdown row = %v, want ok", got.Status)
	}
	stopChecks := map[string]*readinessCheck{}
	appendAdminUIReadinessCheck(stopChecks)
	if len(stopChecks) != 0 {
		t.Error("a shutting-down node still publishes an admin_ui readiness row")
	}
}

// TestChaos57_ShutdownStopsTheLoopPromptly: the backoff sleep is interruptible,
// so a shutdown never has to wait one out (the CHAOS-54 rule). Also asserts the
// clean exit is not recorded as a fault and fires no alert.
func TestChaos57_ShutdownStopsTheLoopPromptly(t *testing.T) {
	resetAdminUIHealthForTest()
	t.Cleanup(resetAdminUIHealthForTest)
	alerts := captureAdminUIAlerts(t)

	port, release := occupyPort(t)
	defer release()

	noteAdminUIConfigured(port)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		serveAdminUIWithRetry(newTestAdminServer(), port, "", "", stop)
		close(done)
	}()

	waitForAdminUI(t, 5*time.Second, "the loop to enter its backoff", func() bool {
		return adminUIListenerState().Total > 0
	})

	start := time.Now()
	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the retry loop did not stop promptly — the backoff sleep is not interruptible")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("shutdown took %s; the backoff sleep should be interrupted immediately", elapsed)
	}
	if !adminUIListenerState().Stopped {
		t.Error("a clean shutdown was not recorded as stopped")
	}
	if len(*alerts) != 0 {
		t.Errorf("a clean shutdown fired an alert: %v", *alerts)
	}
}

// TestChaos57_ServerShutdownEndsTheLoop: once http.Server.Shutdown has run,
// Serve returns ErrServerClosed and the loop must exit rather than spin trying
// to rebind a server that will never serve again.
func TestChaos57_ServerShutdownEndsTheLoop(t *testing.T) {
	resetAdminUIHealthForTest()
	t.Cleanup(resetAdminUIHealthForTest)

	port, release := occupyPort(t)
	release()

	srv := newTestAdminServer()
	noteAdminUIConfigured(port)
	stop := make(chan struct{})
	defer close(stop)
	done := make(chan struct{})
	go func() {
		serveAdminUIWithRetry(srv, port, "", "", stop)
		close(done)
	}()

	waitForAdminUI(t, 5*time.Second, "the listener to bind", func() bool {
		return adminUIListenerState().Serving
	})
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop kept running after the server was closed")
	}
	if !adminUIListenerState().Stopped {
		t.Error("server shutdown was not recorded as stopped")
	}
}

// TestChaos57_RepeatedFailuresDoNotLeakListeners pins that a persistently
// invalid certificate pair costs no descriptors, however many times the retry
// loop runs.
//
// http.Server.ServeTLS returns a certificate error WITHOUT closing the listener
// it was handed. A retry loop that bound first and validated second would leak
// one socket per attempt against a persistently bad certificate — turning a
// recoverable config fault into descriptor exhaustion, which is the terminal
// state CHAOS-54 spent its whole sweep on. adminUIServeOnce validates the pair
// BEFORE binding for exactly this reason.
func TestChaos57_RepeatedFailuresDoNotLeakListeners(t *testing.T) {
	resetAdminUIHealthForTest()
	t.Cleanup(resetAdminUIHealthForTest)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "bad.crt")
	keyPath := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(certPath, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}

	port, release := occupyPort(t)
	release()

	srv := newTestAdminServer()
	before := openFDCount(t)
	for i := 0; i < 50; i++ {
		if err := adminUIServeOnce(srv, fmt.Sprintf("127.0.0.1:%d", port), certPath, keyPath); err == nil {
			t.Fatal("expected a certificate failure")
		}
	}
	after := openFDCount(t)
	// A leak would be one descriptor per attempt. Allow a small margin for
	// unrelated runtime churn in a shared test binary.
	if after-before > 10 {
		t.Errorf("descriptor count grew by %d across 50 failed attempts — the listener is leaking", after-before)
	}
}

// openFDCount counts this process's open descriptors. Linux-only; the gate
// degrades to a no-op elsewhere rather than failing on an unsupported host.
func openFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("descriptor counting unavailable on this platform: %v", err)
	}
	return len(entries)
}

// TestChaos57_HealthyPathIsUnchanged is the control against a fix that reports
// a fault on an ordinary boot.
func TestChaos57_HealthyPathIsUnchanged(t *testing.T) {
	resetAdminUIHealthForTest()
	t.Cleanup(resetAdminUIHealthForTest)
	alerts := captureAdminUIAlerts(t)

	port, release := occupyPort(t)
	release()

	noteAdminUIConfigured(port)
	runAdminUILoop(t, newTestAdminServer(), port, "", "")

	waitForAdminUI(t, 5*time.Second, "the listener to bind", func() bool {
		return adminUIListenerState().Serving
	})

	snap := adminUIListenerState()
	if snap.Total != 0 {
		t.Errorf("a clean bind recorded %d failures, want 0", snap.Total)
	}
	if snap.Failing || snap.Unavailable {
		t.Error("a clean bind reports a fault")
	}
	if len(*alerts) != 0 {
		t.Errorf("a clean bind fired an alert: %v", *alerts)
	}
	if got := checkAdminUIListener(); got.Status != diagOK {
		t.Errorf("clean-bind contract row = %v, want ok", got.Status)
	}
	checks := map[string]*readinessCheck{}
	appendAdminUIReadinessCheck(checks)
	if checks["admin_ui"] == nil || checks["admin_ui"].Status != "ok" {
		t.Error("clean-bind readiness row is not ok")
	}
}

// TestChaos57_ClassifierUsesErrnoNotStrings. net wraps as
// *net.OpError{*os.SyscallError{syscall.Errno}} and the message text is
// platform-specific, so the classification must go through errors.As. The
// reason is also the alert's dedup key, so it must be a BOUNDED class — a raw
// error would yield one distinct key per failure (the WK-12/RS-5 defect).
func TestChaos57_ClassifierUsesErrnoNotStrings(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "none"},
		{"in use", &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}, "port_in_use"},
		{"denied", &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", syscall.EACCES)}, "permission_denied"},
		{"no addr", &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", syscall.EADDRNOTAVAIL)}, "address_unavailable"},
		{"emfile", &net.OpError{Op: "accept", Err: os.NewSyscallError("accept", syscall.EMFILE)}, "descriptors_exhausted"},
		{"tls", fmt.Errorf("%w: %w", errAdminUITLSMaterial, errors.New("no PEM data")), "tls_certificate"},
		{"unknown", errors.New("something else entirely"), "listen_failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyAdminUIListenError(tc.err); got != tc.want {
				t.Errorf("classifyAdminUIListenError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestChaos57_LogRateGateEmitsOnsetThenSuppresses pins the logging discipline:
// the first failure of an episode always logs (the operator must see the
// onset), then at most one line per interval, and the suppressed count is
// handed back on recovery so the recovery line can state the magnitude.
func TestChaos57_LogRateGateEmitsOnsetThenSuppresses(t *testing.T) {
	resetAdminUIHealthForTest()
	t.Cleanup(resetAdminUIHealthForTest)
	captureAdminUIAlerts(t)

	noteAdminUIConfigured(9090)
	now := time.Now()
	if !noteAdminUIListenFailure("port_in_use", time.Second, now) {
		t.Error("the first failure of an episode must always log")
	}
	suppressedCount := 0
	for i := 1; i <= 5; i++ {
		if !noteAdminUIListenFailure("port_in_use", time.Second, now.Add(time.Duration(i)*time.Second)) {
			suppressedCount++
		}
	}
	if suppressedCount != 5 {
		t.Errorf("suppressed %d of 5 in-window failures, want 5", suppressedCount)
	}
	if !noteAdminUIListenFailure("port_in_use", time.Second, now.Add(adminUIListenLogInterval+time.Second)) {
		t.Error("a failure past the log interval must log again")
	}

	if got := noteAdminUIServing(); got != 5 {
		t.Errorf("recovery reported %d suppressed lines, want 5", got)
	}
	// A second recovery with nothing failing reports nothing.
	if got := noteAdminUIServing(); got != 0 {
		t.Errorf("a redundant recovery reported %d suppressed lines, want 0", got)
	}
}

// TestChaos57_BackoffIsBoundedAndJittered pins the rate bound. The retry count
// is deliberately unbounded (see admin_ui_health.go); the RATE must not be.
func TestChaos57_BackoffIsBoundedAndJittered(t *testing.T) {
	if adminUIListenBackoffInitial <= 0 || adminUIListenBackoffMax < adminUIListenBackoffInitial {
		t.Fatalf("nonsensical backoff bounds: %s..%s", adminUIListenBackoffInitial, adminUIListenBackoffMax)
	}
	// The ceiling must stay below the unavailability threshold, so a fault that
	// clears is picked up before the operator has been paged about it.
	if adminUIListenBackoffMax > adminUIUnavailableAfter {
		t.Errorf("backoff ceiling %s exceeds the unavailability threshold %s",
			adminUIListenBackoffMax, adminUIUnavailableAfter)
	}

	// Jitter spreads a restarting fleet rather than converging it on one cadence.
	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		d := jitterDuration(adminUIListenBackoffMax, adminUIListenJitter)
		lo := time.Duration(float64(adminUIListenBackoffMax) * (1 - adminUIListenJitter))
		hi := time.Duration(float64(adminUIListenBackoffMax) * (1 + adminUIListenJitter))
		if d < lo || d > hi {
			t.Fatalf("jittered backoff %s outside [%s,%s]", d, lo, hi)
		}
		seen[d] = true
	}
	if len(seen) < 50 {
		t.Errorf("jitter produced only %d distinct delays over 200 draws — a fleet would converge", len(seen))
	}
}
