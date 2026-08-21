package main

// CHAOS-09 — /ready DP dependency health rows.
//
// These tests pin four contracts:
//  1. Outside DP mode the rows do not exist — every CP/standalone probe
//     consumer is byte-identical to before.
//  2. In DP mode, sustained CP-poll failure and a failing cert renewal are
//     VISIBLE as fail rows but do NOT gate the default verdict (report-only,
//     the ca/state_file_* posture): a CP outage must not eject the whole DP
//     fleet from a default-configured load balancer.
//  3. /ready?strict=1 is the opt-in that DOES gate on those rows.
//  4. The rows recover: poll success and renewal success clear them.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
)

// withDPMode flips the process into DP mode for one test and restores the
// package-main default (false) afterwards.
func withDPMode(t *testing.T) {
	t.Helper()
	audit.SetDPMode(true)
	t.Cleanup(func() { audit.SetDPMode(false) })
}

// swapCPPollState installs a CP-poll health state and restores the previous
// one on cleanup (PR3d fence-pollution lesson: never leak probe state).
func swapCPPollState(t *testing.T, failing bool, since time.Time) {
	t.Helper()
	prevFailing := dpControlPlanePollFailing.Load()
	prevSince := dpCPPollFailingSince.Load()
	t.Cleanup(func() {
		dpControlPlanePollFailing.Store(prevFailing)
		dpCPPollFailingSince.Store(prevSince)
	})
	dpControlPlanePollFailing.Store(failing)
	if since.IsZero() {
		dpCPPollFailingSince.Store(0)
	} else {
		dpCPPollFailingSince.Store(since.UnixNano())
	}
}

// resetCertRenewalState clears the node_cert probe state (and the CHAOS-12
// alert latch it shares a lifecycle with) on entry AND after the test —
// other suites (dp_cert_renewal_test.go) drive alertDPCertRenewalFailure
// without clearing, so under -shuffle the state must be scrubbed both ways
// (the PR3d fence-pollution lesson).
func resetCertRenewalState(t *testing.T) {
	t.Helper()
	scrub := func() {
		clearDPCertRenewalFailure()
		dpCertExpiryAlert.mu.Lock()
		dpCertExpiryAlert.level = 0
		dpCertExpiryAlert.mu.Unlock()
	}
	scrub()
	t.Cleanup(scrub)
}

// readyChecks calls handleReady and decodes the checks map.
func readyChecks(t *testing.T, target string) (code int, status string, checks map[string]*readinessCheck) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, target, http.NoBody)
	handleReady(w, r)
	var resp struct {
		Status string                     `json:"status"`
		Checks map[string]*readinessCheck `json:"checks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode /ready: %v (body %q)", err, w.Body.String())
	}
	return w.Code, resp.Status, resp.Checks
}

// writeCertExpiringIn writes a self-signed PEM cert with NotAfter = now+d
// (what certNeedsRenewal parses on the DP).
func writeCertExpiringIn(t *testing.T, d time.Duration) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(d),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "node.crt")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHandleReady_NonDPMode_NoDPRows(t *testing.T) {
	// DP mode off (package default). Even with the poll flag stuck on, the
	// rows must not appear — CP/standalone probe output is unchanged.
	swapCPPollState(t, true, time.Now().Add(-time.Hour))

	code, status, checks := readyChecks(t, "/ready")
	if code != http.StatusOK || status != "ready" {
		t.Fatalf("baseline: code=%d status=%q, want 200/ready", code, status)
	}
	if _, ok := checks["cp_poll"]; ok {
		t.Fatal("cp_poll row must not exist outside DP mode")
	}
	if _, ok := checks["node_cert"]; ok {
		t.Fatal("node_cert row must not exist outside DP mode")
	}
}

func TestHandleReady_CPPollFailingSustained_ReportOnlyFailRow(t *testing.T) {
	withDPMode(t)
	swapCPPollState(t, true, time.Now().Add(-2*dpCPPollFailGrace))

	code, status, checks := readyChecks(t, "/ready")
	row := checks["cp_poll"]
	if row == nil || row.Status != "fail" {
		t.Fatalf("cp_poll row = %+v, want fail after sustained poll failure", row)
	}
	// The detail names the degraded SUBSYSTEM and points at the log. It must
	// NOT name the enforcement consequence or measure the outage — /ready is
	// unauthenticated on the proxy port (see readyz_dp_detail_disclosure_test.go,
	// which owns that contract).
	if !strings.Contains(row.Detail, "control plane") || !strings.Contains(row.Detail, "see server logs") {
		t.Errorf("cp_poll detail should name the subsystem and point at the logs, got %q", row.Detail)
	}
	// Report-only: the DEFAULT verdict must not gate on it — a CP outage
	// must not eject the whole DP fleet from a default-configured LB.
	if code != http.StatusOK || status != "ready" {
		t.Fatalf("default verdict changed: code=%d status=%q, want 200/ready (report-only contract)", code, status)
	}
}

func TestHandleReady_CPPollFailingWithinGrace_OKRow(t *testing.T) {
	withDPMode(t)
	swapCPPollState(t, true, time.Now().Add(-10*time.Second))

	_, _, checks := readyChecks(t, "/ready")
	row := checks["cp_poll"]
	if row == nil || row.Status != "ok" {
		t.Fatalf("cp_poll row = %+v, want ok inside the grace window (no probe flap on a missed poll / CP rolling restart)", row)
	}

	// A bare failing flag with no transition stamp (legacy direct writers,
	// tests) must also stay ok — "sustained" cannot be proven without it.
	swapCPPollState(t, true, time.Time{})
	_, _, checks = readyChecks(t, "/ready")
	if row := checks["cp_poll"]; row == nil || row.Status != "ok" {
		t.Fatalf("cp_poll row = %+v, want ok when the failing flag has no since-stamp", row)
	}
}

func TestHandleReady_CPPollRecovers(t *testing.T) {
	withDPMode(t)
	swapCPPollState(t, true, time.Now().Add(-2*dpCPPollFailGrace))

	// The poll loop reports success through dpMarkCPPollHealthy.
	dpMarkCPPollHealthy()
	_, _, checks := readyChecks(t, "/ready")
	if row := checks["cp_poll"]; row == nil || row.Status != "ok" || row.Detail != "" {
		t.Fatalf("cp_poll row = %+v, want clean ok after recovery", row)
	}

	// And a fresh failure re-stamps the transition time.
	dpMarkCPPollFailing()
	if dpCPPollFailingSince.Load() == 0 {
		t.Fatal("dpMarkCPPollFailing must stamp the transition time")
	}
}

func TestHandleReady_NodeCertRenewalFailing_FailRowAndRecovery(t *testing.T) {
	withDPMode(t)
	swapCPPollState(t, false, time.Time{})
	resetCertRenewalState(t)

	// Drive the REAL CHAOS-12 failure path: a cert inside the renewal
	// window plus a failing renewal. (96h ⇒ 3 full days remaining.)
	certFile := writeCertExpiringIn(t, 96*time.Hour)
	alertDPCertRenewalFailure("dp-test", certFile, errors.New("RenewCert RPC: connection refused"))

	code, status, checks := readyChecks(t, "/ready")
	row := checks["node_cert"]
	if row == nil || row.Status != "fail" {
		t.Fatalf("node_cert row = %+v, want fail while renewal is failing inside the window", row)
	}
	// The detail names the degraded SUBSYSTEM and points at the log. The cause
	// and the cert's remaining lifetime are deliberately absent — /ready is
	// unauthenticated on the proxy port (see readyz_dp_detail_disclosure_test.go,
	// which owns that contract).
	if !strings.Contains(row.Detail, "node certificate") || !strings.Contains(row.Detail, "see server logs") {
		t.Errorf("node_cert detail should name the subsystem and point at the logs, got %q", row.Detail)
	}
	if code != http.StatusOK || status != "ready" {
		t.Fatalf("default verdict changed: code=%d status=%q, want 200/ready (report-only contract)", code, status)
	}

	// An ALREADY-EXPIRED cert still produces the failing row. It reports the
	// same fixed detail as the expiring case on purpose: distinguishing them
	// would publish how far past NotAfter this node's mTLS identity is.
	expiredFile := writeCertExpiringIn(t, -48*time.Hour)
	alertDPCertRenewalFailure("dp-test", expiredFile, errors.New("RenewCert RPC: connection refused"))
	_, _, checks = readyChecks(t, "/ready")
	if row := checks["node_cert"]; row == nil || row.Status != "fail" {
		t.Fatalf("node_cert row = %+v, want a failing row for a past-NotAfter cert with failing renewal", row)
	}

	// Successful renewal clears the row through the same reset the renewal
	// path calls (renewDPCert → resetDPCertExpiryAlert).
	resetDPCertExpiryAlert()
	_, _, checks = readyChecks(t, "/ready")
	if row := checks["node_cert"]; row == nil || row.Status != "ok" {
		t.Fatalf("node_cert row = %+v, want ok after successful renewal", row)
	}
}

func TestHandleReady_RenewalFailureOutsideWindow_NoRow(t *testing.T) {
	withDPMode(t)
	swapCPPollState(t, false, time.Time{})
	resetCertRenewalState(t)

	// A rotation-triggered renewal failure on a still-fresh cert has no
	// expiry clock running against it — log-only (CHAOS-12 contract), so
	// the probe row must stay ok.
	certFile := writeCertExpiringIn(t, 365*24*time.Hour)
	alertDPCertRenewalFailure("dp-test", certFile, errors.New("boom"))

	_, _, checks := readyChecks(t, "/ready")
	if row := checks["node_cert"]; row == nil || row.Status != "ok" {
		t.Fatalf("node_cert row = %+v, want ok for a renewal failure outside the renewal window", row)
	}
}

func TestHandleReady_StrictGatesFailRows(t *testing.T) {
	withDPMode(t)
	swapCPPollState(t, true, time.Now().Add(-2*dpCPPollFailGrace))

	// Default probe: 200 (report-only).
	code, _, _ := readyChecks(t, "/ready")
	if code != http.StatusOK {
		t.Fatalf("default probe code = %d, want 200", code)
	}

	// Strict probe: the same state is gating.
	code, status, checks := readyChecks(t, "/ready?strict=1")
	if code != http.StatusServiceUnavailable || status != "not_ready" {
		t.Fatalf("strict probe: code=%d status=%q, want 503/not_ready on a sustained CP-poll failure", code, status)
	}
	if row := checks["cp_poll"]; row == nil || row.Status != "fail" {
		t.Fatalf("strict probe cp_poll row = %+v, want fail", row)
	}

	// Strict with everything healthy: 200. NOTE: strict gates ALL fail
	// rows — the default test fixture has no policy rules, so neutralize
	// the policy_loaded row by checking the healthy-DP case only for the
	// DP rows via direct state, then assert overall via row scan.
	dpMarkCPPollHealthy()
	code, _, checks = readyChecks(t, "/ready?strict=1")
	anyFail := false
	for _, c := range checks {
		if c.Status == "fail" {
			anyFail = true
		}
	}
	if anyFail && code != http.StatusServiceUnavailable {
		t.Fatalf("strict probe must 503 while any row fails, got %d", code)
	}
	if !anyFail && code != http.StatusOK {
		t.Fatalf("strict probe with all rows ok must 200, got %d", code)
	}
}
