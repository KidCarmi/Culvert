package main

// readyz_dp_detail_disclosure_test.go — the unauthenticated-probe detail
// contract, extended to the two CHAOS-09 data-plane rows.
//
// readyz_detail_disclosure_test.go established the rule for the `ca` and
// `clamav` rows: /ready is served by routeProxyListenerBuiltin on the PROXY
// listener (pac.go) with no authentication and no IP guard, so every client
// that can use the gateway can read every detail written there. The rule that
// closed it is that the failing ROW and its STATUS stay (visibility and gating
// are unchanged) while the DETAIL is a fixed, operator-directed string.
//
// The DP rows added by CHAOS-09 (readyz_dp_health.go) were not brought under
// that rule and still answered with interpolated internals:
//
//	node_cert → "node certificate expires in 3 day(s) and renewal is failing
//	             (last error: RenewCert RPC: rpc error: code = Unavailable
//	             desc = ... dial tcp 10.42.7.9:9443: connect: connection refused)"
//	cp_poll   → "control plane unreachable for 12m41s — serving last-known-good
//	             config; policy/auth updates are not arriving"
//
// Between them that publishes the Control Plane's internal address and port,
// raw dial/x509/filesystem causes from the renewal path, a precise countdown to
// the moment this node's cluster identity dies, and an explicit machine-readable
// statement that policy and authentication updates are NOT reaching this node.
// The last one is the enforcement-posture disclosure appendCAReadinessCheck's
// contract comment forbids by name: it tells an unauthenticated observer exactly
// when the gateway is serving stale policy, so a newly-blocked destination or a
// just-revoked account is knowably still permitted here.
//
// These tests pin the same contract for both rows. The cause remains available
// to operators: every CP-poll failure is logged by DataPlaneClient (GetConfig
// error), and every renewal failure is logged by dpCertRenewalLoop AND raised as
// a cert_expiry alert.

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// dpRenewalErrShape is the verbatim shape a failing RenewCert produces: the gRPC
// error carries the CP's address, so this is the real producer's output rather
// than a convenient stand-in.
const dpRenewalErrShape = "RenewCert RPC: rpc error: code = Unavailable desc = " +
	"connection error: desc = \"transport: Error while dialing dial tcp 10.42.7.9:9443: " +
	"connect: connection refused\""

// TestReadyz_NodeCertDetailWithholdsRenewalCause is the regression proper: a
// failing renewal must produce a failing row whose detail names neither the
// underlying cause nor the days-until-expiry countdown.
func TestReadyz_NodeCertDetailWithholdsRenewalCause(t *testing.T) {
	withDPMode(t)
	resetCertRenewalState(t)
	swapCPPollState(t, false, time.Time{})

	recordDPCertRenewalFailure(3, errors.New(dpRenewalErrShape))

	_, _, checks := readyChecks(t, "/ready")
	row, ok := checks["node_cert"]
	if !ok {
		t.Fatal("node_cert row missing — the CHAOS-09 visibility contract requires the failing row to be present")
	}
	if row.Status != "fail" {
		t.Fatalf("node_cert status = %q, want fail (visibility must survive the redaction)", row.Status)
	}
	for _, leak := range []string{
		"10.42.7.9",          // the Control Plane's internal address
		"9443",               // ...and its port
		"dial tcp",           // raw dial cause
		"connection refused", // ditto
		"rpc error",          // transport internals
		// The countdown. A precise days-to-expiry on an unauthenticated surface
		// is a fingerprint of a degrading node and tells an observer when this
		// node's cluster identity dies.
		"3 day",
		"last error",
	} {
		if strings.Contains(strings.ToLower(row.Detail), strings.ToLower(leak)) {
			t.Errorf("node_cert detail leaks %q on the unauthenticated /ready surface: %q", leak, row.Detail)
		}
	}
	if row.Detail == "" {
		t.Error("node_cert detail is empty — the operator still needs to be pointed somewhere")
	}

	// The other half of the contract: the cause is WITHHELD from the public
	// probe, not dropped from the node. It stays recorded for the role-gated
	// surfaces (and is independently logged and alerted by dpCertRenewalLoop),
	// so redacting the row cost the operator nothing.
	failing, days, lastErr := dpCertRenewalFailureSnapshot()
	if !failing || days != 3 || lastErr != dpRenewalErrShape {
		t.Errorf("recorded renewal state = (%v, %d, %q), want the failure recorded verbatim: "+
			"the redaction must withhold the cause from /ready, not discard it", failing, days, lastErr)
	}
}

// TestReadyz_NodeCertExpiredDetailWithholdsCause covers the second branch: an
// already-expired certificate must not publish the elapsed-since-expiry count or
// the cause either. It is a separate test because the two branches build their
// strings independently, so redacting one would not redact the other.
func TestReadyz_NodeCertExpiredDetailWithholdsCause(t *testing.T) {
	withDPMode(t)
	resetCertRenewalState(t)
	swapCPPollState(t, false, time.Time{})

	recordDPCertRenewalFailure(-9, errors.New(dpRenewalErrShape))

	_, _, checks := readyChecks(t, "/ready")
	row, ok := checks["node_cert"]
	if !ok {
		t.Fatal("node_cert row missing for an expired certificate")
	}
	if row.Status != "fail" {
		t.Fatalf("node_cert status = %q, want fail", row.Status)
	}
	for _, leak := range []string{"10.42.7.9", "dial tcp", "connection refused", "9 day", "expired"} {
		if strings.Contains(strings.ToLower(row.Detail), strings.ToLower(leak)) {
			t.Errorf("node_cert (expired branch) detail leaks %q on the unauthenticated /ready surface: %q",
				leak, row.Detail)
		}
	}
}

// TestReadyz_CPPollDetailWithholdsOutageAndPosture pins the cp_poll row. The
// duration is an outage-length oracle and "policy/auth updates are not arriving"
// is the enforcement-posture statement the ca row's contract forbids.
func TestReadyz_CPPollDetailWithholdsOutageAndPosture(t *testing.T) {
	withDPMode(t)
	resetCertRenewalState(t)
	swapCPPollState(t, true, time.Now().Add(-42*time.Minute))

	_, _, checks := readyChecks(t, "/ready")
	row, ok := checks["cp_poll"]
	if !ok {
		t.Fatal("cp_poll row missing — sustained CP-poll failure must stay visible to probes")
	}
	if row.Status != "fail" {
		t.Fatalf("cp_poll status = %q, want fail (visibility must survive the redaction)", row.Status)
	}
	for _, leak := range []string{
		"42m",             // the outage-duration oracle
		"policy",          // the enforcement-posture statement...
		"auth",            // ...and the half that names authentication
		"last-known-good", // "this node is serving stale config"
		"not arriving",    // ditto, machine-readable
		"unreachable for", // the duration phrasing
	} {
		if strings.Contains(strings.ToLower(row.Detail), strings.ToLower(leak)) {
			t.Errorf("cp_poll detail leaks %q on the unauthenticated /ready surface: %q", leak, row.Detail)
		}
	}
	if row.Detail == "" {
		t.Error("cp_poll detail is empty — the operator still needs to be pointed somewhere")
	}
}

// TestReadyz_CPPollGraceWindowPublishesNothing covers the row's OK branch. The
// code's own comment calls the grace window "not yet a probe-visible failure",
// yet it wrote a probe-visible detail saying CP polling is failing — the same
// degradation fingerprint, on a row that reports ok. An ok row carries no detail.
func TestReadyz_CPPollGraceWindowPublishesNothing(t *testing.T) {
	withDPMode(t)
	resetCertRenewalState(t)
	// Failing, but well inside dpCPPollFailGrace.
	swapCPPollState(t, true, time.Now().Add(-5*time.Second))

	_, _, checks := readyChecks(t, "/ready")
	row, ok := checks["cp_poll"]
	if !ok {
		t.Fatal("cp_poll row missing in DP mode")
	}
	if row.Status != "ok" {
		t.Fatalf("cp_poll status = %q inside the grace window, want ok (grace behaviour unchanged)", row.Status)
	}
	if row.Detail != "" {
		t.Errorf("cp_poll detail = %q on an ok row: the grace window is by definition not a probe-visible "+
			"failure, so it must not publish one to unauthenticated clients", row.Detail)
	}
}

// TestReadyz_DPRowsStillReportOnly is the counterweight: the redaction must have
// changed only the STRINGS. Both rows stay REPORT-ONLY for the default verdict
// (a CP outage must not eject the whole DP fleet from a default-configured load
// balancer) and both stay gating under the opt-in /ready?strict=1.
func TestReadyz_DPRowsStillReportOnly(t *testing.T) {
	withDPMode(t)
	resetCertRenewalState(t)
	swapCPPollState(t, true, time.Now().Add(-42*time.Minute))
	recordDPCertRenewalFailure(3, errors.New(dpRenewalErrShape))

	if code, status, _ := readyChecks(t, "/ready"); code != 200 || status != "ready" {
		t.Fatalf("default verdict = %d/%q with degraded DP rows, want 200/ready (report-only posture unchanged)",
			code, status)
	}
	if code, status, _ := readyChecks(t, "/ready?strict=1"); code != 503 || status != "not_ready" {
		t.Fatalf("strict verdict = %d/%q, want 503/not_ready (strict must still gate on the DP rows)",
			code, status)
	}
}

// TestReadyz_NoDPDetailCarriesRawInternals re-runs the standing sweep from
// readyz_detail_disclosure_test.go with the DP rows actually PRESENT. The
// original sweep never arranged DP mode, so the two rows it was meant to protect
// were silently outside its reach — the gap that let this class survive the fix.
func TestReadyz_NoDPDetailCarriesRawInternals(t *testing.T) {
	withDPMode(t)
	resetCertRenewalState(t)
	swapCPPollState(t, true, time.Now().Add(-42*time.Minute))
	recordDPCertRenewalFailure(-9, errors.New(
		"write cert: atomic write /data/node.crt: create temp: permission denied"))

	markers := []string{"dial tcp", "dial unix", "connect: ", "no such file", "permission denied",
		"/data/", "/etc/", "/var/", "rpc error"}
	_, _, checks := readyChecks(t, "/ready")
	for name, row := range checks {
		for _, m := range markers {
			if strings.Contains(row.Detail, m) {
				t.Errorf("readiness row %q detail carries raw internals (%q) on the unauthenticated /ready surface: %q",
					name, m, row.Detail)
			}
		}
	}
}
