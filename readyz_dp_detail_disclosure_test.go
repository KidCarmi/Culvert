package main

// readyz_dp_detail_disclosure_test.go — the unauthenticated-probe detail
// contract, extended to the DP-only rows (CHAOS-09: cp_poll + node_cert).
//
// /ready is served by routeProxyListenerBuiltin on the PROXY listener (pac.go)
// with no authentication and no IP guard: every client that can reach the
// gateway can read every byte of it. readyz_detail_disclosure_test.go closed
// that class for the `ca` and `clamav` rows and left a standing sweep behind —
// but the sweep only inspects the rows PRESENT IN THE TEST PROCESS, and
// appendDPHealthChecks returns early unless audit.DPMode() is set, which no
// disclosure test set. The two DP rows were therefore never swept, and both
// answered with exactly the material the `ca`/`clamav` fix removed:
//
//	cp_poll   → "control plane unreachable for 12m3s — serving last-known-good
//	             config; policy/auth updates are not arriving"
//	node_cert → "node certificate EXPIRED 4 day(s) ago and renewal is failing
//	             (last error: RenewCert RPC: rpc error: code = Unavailable desc
//	             = ... dial tcp 10.0.3.7:9443: connect: connection refused)"
//
// Between them that publishes the control plane's internal address and port,
// the raw gRPC/TLS transport error, the exact remaining lifetime of this
// node's mTLS identity, and — the part that actually arms an attacker — an
// explicit, machine-readable statement of the ENFORCEMENT POSTURE: that policy
// and auth updates are not arriving, i.e. a revoked credential or a
// newly-blocked destination is still being honoured on this node.
//
// These tests pin the same contract the `ca` row got: the failing ROW stays
// (the CHAOS-09 visibility guarantee) and the verdict is unchanged
// (report-only by default, gating under ?strict=1), but the detail is a fixed,
// operator-directed string. Both causes are already logged by their own loops
// (DataPlane: GetConfig error / DataPlane: cert renewal check), so the
// operator loses nothing.

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// dpDisclosureRows puts the process in DP mode with BOTH DP rows failing in
// their most verbose branch and returns the decoded /ready rows.
func dpDisclosureRows(t *testing.T) map[string]struct {
	Status string `json:"status"`
	Detail string `json:"detail"`
} {
	t.Helper()
	withDPMode(t)
	resetCertRenewalState(t)
	// Sustained CP-poll failure: past the grace window, so the verbose branch.
	swapCPPollState(t, true, time.Now().Add(-2*dpCPPollFailGrace))
	// Drive the REAL CHAOS-12 producer with a renewal error shaped like the
	// gRPC transport failure the renewal loop actually hands it.
	certFile := writeCertExpiringIn(t, 96*time.Hour)
	alertDPCertRenewalFailure("dp-test", certFile,
		errors.New("RenewCert RPC: rpc error: code = Unavailable desc = connection error: "+
			"desc = \"transport: Error while dialing dial tcp 10.0.3.7:9443: connect: connection refused\""))
	return readyProbeRows(t)
}

// TestReadyz_CPPollDetailWithholdsPostureAndElapsed is the regression proper
// for the cp_poll row. The row must survive (visibility) but must not state
// the enforcement posture or how long the node has been running on stale
// config.
func TestReadyz_CPPollDetailWithholdsPostureAndElapsed(t *testing.T) {
	captureStartupAlerts(t)
	sslInspectionLoadError.Store("")

	row, ok := dpDisclosureRows(t)["cp_poll"]
	if !ok {
		t.Fatal("cp_poll row missing — the CHAOS-09 visibility contract requires the failing row to be present")
	}
	if row.Status != "fail" {
		t.Fatalf("cp_poll status = %q, want fail (visibility must survive the redaction)", row.Status)
	}
	for _, leak := range []string{
		// The enforcement posture. "cp_poll: fail" says a named subsystem is
		// degraded; it must not say that the SECURITY CONSEQUENCE is stale
		// policy/auth — that is the window an attacker times against.
		"last-known-good",
		"policy",
		"auth",
		"not arriving",
		// The elapsed duration tells an unauthenticated observer how long the
		// node has been stale, and therefore how stale its permit/deny set is.
		"unreachable for",
	} {
		if strings.Contains(strings.ToLower(row.Detail), leak) {
			t.Errorf("cp_poll detail leaks %q on the unauthenticated /ready surface: %q", leak, row.Detail)
		}
	}
	if !strings.Contains(row.Detail, "see server logs") {
		t.Errorf("cp_poll detail = %q, want it to point the operator at the logs "+
			"(DataPlane: GetConfig error is logged on every failing poll)", row.Detail)
	}
}

// TestReadyz_NodeCertDetailWithholdsCauseAndLifetime is the regression proper
// for the node_cert row: no raw transport error, no CP address, no remaining
// lifetime, no expired/expiring distinction.
func TestReadyz_NodeCertDetailWithholdsCauseAndLifetime(t *testing.T) {
	captureStartupAlerts(t)
	sslInspectionLoadError.Store("")

	row, ok := dpDisclosureRows(t)["node_cert"]
	if !ok {
		t.Fatal("node_cert row missing — a failing renewal must stay visible to probes")
	}
	if row.Status != "fail" {
		t.Fatalf("node_cert status = %q, want fail", row.Status)
	}
	for _, leak := range []string{
		"10.0.3.7",           // control-plane address
		"9443",               // control-plane port
		"connection refused", // raw transport cause
		"dial tcp",
		"rpc error",
		"last error",
		// The remaining lifetime of this node's mTLS identity: the precise
		// moment it drops out of the cluster and stops receiving policy.
		"day",
		"expired",
	} {
		if strings.Contains(strings.ToLower(row.Detail), leak) {
			t.Errorf("node_cert detail leaks %q on the unauthenticated /ready surface: %q", leak, row.Detail)
		}
	}
	if !strings.Contains(row.Detail, "see server logs") {
		t.Errorf("node_cert detail = %q, want it to point the operator at the logs "+
			"(DataPlane: cert renewal check is logged on every failed attempt)", row.Detail)
	}
}

// TestReadyz_DPRowsRawErrorNeverEntersProbeState is the defense-in-depth half.
// The renewal loop's raw error and the cert's days-left must not be RETAINED in
// the probe-facing state at all. That state's ONLY consumer is the
// unauthenticated /ready row, so anything stored there is one fmt.Sprintf away
// from the public surface — which is precisely how both came to be published.
// Keeping the state a bare boolean makes the leak unreachable by construction,
// not just unwritten by the current formatter.
func TestReadyz_DPRowsRawErrorNeverEntersProbeState(t *testing.T) {
	withDPMode(t)
	resetCertRenewalState(t)

	certFile := writeCertExpiringIn(t, 96*time.Hour)
	alertDPCertRenewalFailure("dp-test", certFile,
		errors.New("RenewCert RPC: dial tcp 10.0.3.7:9443: connect: connection refused"))

	if !dpCertRenewalFailing() {
		t.Fatal("dpCertRenewalFailing() = false after a real in-window renewal failure — the row would vanish")
	}

	// An EXACT (name, type) allowlist, not a kind allowlist. Permitting every
	// struct-typed field would admit a future time.Time, a url.URL, or any
	// wrapper retaining the cause — leaving this guard green while the contract
	// it claims to pin is broken. Over-broad matching is how the original class
	// survived; the guard must not repeat it.
	//
	// TypeFor rather than TypeOf(sync.Mutex{}): no lock value is ever copied
	// (go vet copylocks), and Elem() off the pointer avoids copying the struct.
	want := map[string]reflect.Type{
		"mu":      reflect.TypeFor[sync.Mutex](),
		"failing": reflect.TypeFor[bool](),
	}
	st := reflect.TypeOf(&dpNodeCertRenewal).Elem()
	if st.NumField() != len(want) {
		t.Errorf("dpNodeCertRenewal has %d fields, want exactly %d", st.NumField(), len(want))
	}
	for i := range st.NumField() {
		f := st.Field(i)
		expect, allowed := want[f.Name]
		if !allowed {
			t.Errorf("dpNodeCertRenewal retains unexpected field %q (%s) — the probe-facing state feeds an "+
				"unauthenticated /ready detail, so it must carry no cause and no measurement; "+
				"keep those in the log and the cert_expiry alert", f.Name, f.Type)
			continue
		}
		if f.Type != expect {
			t.Errorf("dpNodeCertRenewal field %q has type %s, want %s — a widened type can retain "+
				"a renewal cause or a lifetime that reaches the unauthenticated /ready detail", f.Name, f.Type, expect)
		}
	}
}

// TestReadyz_DPSweepNoDetailCarriesRawInternals is the standing sweep with the
// DP rows PRESENT — the coverage gap that let this class survive the ca/clamav
// fix. It re-applies the original sweep's markers plus the posture and
// duration markers, over every row in a DP-mode process.
func TestReadyz_DPSweepNoDetailCarriesRawInternals(t *testing.T) {
	captureStartupAlerts(t)
	sslInspectionLoadError.Store("Root CA load/init failed for /data/ca.bundle: bad passphrase")

	rows := dpDisclosureRows(t)
	if _, ok := rows["cp_poll"]; !ok {
		t.Fatal("cp_poll row absent — the sweep is not actually covering the DP rows")
	}
	if _, ok := rows["node_cert"]; !ok {
		t.Fatal("node_cert row absent — the sweep is not actually covering the DP rows")
	}

	// Markers of a raw error string surfacing verbatim, plus the two classes
	// the DP rows added: an enforcement-posture statement and an elapsed-time
	// or remaining-lifetime measurement.
	markers := []string{
		"dial tcp", "dial unix", "connect: ", "no such file", "permission denied",
		"/data/", "/etc/", "/var/", "rpc error", "last error",
		"last-known-good", "not arriving", "unreachable for",
	}
	for name, row := range rows {
		low := strings.ToLower(row.Detail)
		for _, m := range markers {
			if strings.Contains(low, m) {
				t.Errorf("readiness row %q detail carries raw internals or posture (%q) "+
					"on the unauthenticated /ready surface: %q", name, m, row.Detail)
			}
		}
	}
}

// TestReadyz_DPRowVerdictsUnchanged proves the redaction changed only the
// STRINGS. The DP rows stay report-only for the default verdict and stay
// gating under ?strict=1 — trading an information leak for a monitoring
// regression would be the worse outcome.
func TestReadyz_DPRowVerdictsUnchanged(t *testing.T) {
	captureStartupAlerts(t)
	sslInspectionLoadError.Store("")
	dpDisclosureRows(t)

	if code, status, _ := readyChecks(t, "/ready"); code != 200 || status != "ready" {
		t.Fatalf("default verdict = %d/%q, want 200/ready (DP rows stay report-only)", code, status)
	}
	code, status, checks := readyChecks(t, "/ready?strict=1")
	if code != 503 || status != "not_ready" {
		t.Fatalf("strict verdict = %d/%q, want 503/not_ready (DP rows stay gating under strict)", code, status)
	}
	for _, name := range []string{"cp_poll", "node_cert"} {
		if row := checks[name]; row == nil || row.Status != "fail" {
			t.Errorf("strict probe %s row = %+v, want fail", name, row)
		}
	}
}
