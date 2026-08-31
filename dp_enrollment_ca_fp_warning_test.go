package main

// dp_enrollment_ca_fp_warning_test.go — regression coverage for a silent
// insecure-enrollment path in runEnrollment (dp_enrollment.go).
//
// docker-compose.ha.yml documents the ?ca-fp= enrollment-URL parameter as
// mandatory: "The ?ca-fp=... suffix is NOT optional ... Omitting it accepts
// and persists whatever CA the far end presents." dp_enrollment.go's own
// comment on the verification branch repeats the stakes: "CA fingerprint
// mismatch — possible MITM". But runEnrollment only prints anything when a
// fingerprint IS present and verified ("CA fingerprint verified ✓"); when
// ?ca-fp= is missing from the enrollment URL (a copy/paste mistake, a
// hand-typed URL, or an enrollment command built by an older/customized
// tool), the DP silently enrolls over a completely unauthenticated,
// insecure-transport gRPC connection with NO console output at all telling
// the operator that verification was skipped. That is exactly the class of
// "silent fail-open" this codebase otherwise treats as a bug everywhere else
// (see CLAUDE.md's autoexclude/alert-webhook/CA-health sections: fail-open
// must be COUNTED/VISIBLE, never silent) — here it was neither.
//
// This proves runEnrollment prints an explicit, unmistakable warning when
// asked to enroll without a CA fingerprint to verify, so an operator running
// the install/enrollment command interactively (or reading its captured
// output later) cannot miss that this node's trust anchor was never checked.

import (
	"net"
	"strings"
	"testing"
)

// unusedLocalAddr returns a "host:port" string that refuses TCP connections
// immediately (no dial timeout to wait out): it binds a real listener to
// pick a free port, then closes it before returning, so anything that later
// dials the same port gets a fast "connection refused" from the kernel
// instead of hanging.
func unusedLocalAddr(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return addr
}

// TestRunEnrollment_WarnsWhenCAFingerprintMissing proves that enrolling with
// a URL carrying no ?ca-fp= parameter prints an explicit warning that the
// Control Plane's CA will not be verified. The enrollment itself is expected
// to fail (there is no real Control Plane listening), which is fine — the
// warning must appear regardless of what the network call does, since it
// documents a property of the URL the operator supplied, not of the RPC
// outcome.
func TestRunEnrollment_WarnsWhenCAFingerprintMissing(t *testing.T) {
	addr := unusedLocalAddr(t)
	url := "culvert://enroll/" + addr + "/sometoken"

	out, err := captureStdout(t, func() error {
		_, enrollErr := runEnrollment(url)
		return enrollErr
	})
	if err == nil {
		t.Fatalf("runEnrollment(%q) unexpectedly succeeded against a closed port", url)
	}

	lower := strings.ToLower(out)
	if !strings.Contains(lower, "ca-fp") && !strings.Contains(lower, "fingerprint") {
		t.Errorf("runEnrollment printed no warning about the missing CA fingerprint for an "+
			"enrollment URL with no ?ca-fp= parameter — an operator has no way to know this "+
			"node enrolled (or tried to) without verifying the Control Plane's identity; got output:\n%s", out)
	}
	if !strings.Contains(lower, "mitm") && !strings.Contains(lower, "not verif") && !strings.Contains(lower, "unverif") {
		t.Errorf("runEnrollment's output does not convey the security consequence (MITM exposure) of "+
			"skipping CA fingerprint verification; got output:\n%s", out)
	}
}

// TestRunEnrollment_NoFingerprintWarningWhenCAFPPresent is the control: an
// enrollment URL that DOES carry a ?ca-fp= value must not trigger the
// missing-fingerprint warning (it would be a false alarm — the operator did
// everything right).
func TestRunEnrollment_NoFingerprintWarningWhenCAFPPresent(t *testing.T) {
	addr := unusedLocalAddr(t)
	url := "culvert://enroll/" + addr + "/sometoken?ca-fp=sha256:deadbeef"

	out, err := captureStdout(t, func() error {
		_, enrollErr := runEnrollment(url)
		return enrollErr
	})
	if err == nil {
		t.Fatalf("runEnrollment(%q) unexpectedly succeeded against a closed port", url)
	}

	lower := strings.ToLower(out)
	if strings.Contains(lower, "will not be verified") || strings.Contains(lower, "will not verify") {
		t.Errorf("runEnrollment printed the missing-CA-fingerprint warning even though the enrollment "+
			"URL supplied one — false alarm; got output:\n%s", out)
	}
}
