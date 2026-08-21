package main

// readyz_detail_disclosure_test.go — the unauthenticated-probe detail contract.
//
// /ready is served by routeProxyListenerBuiltin on the PROXY listener (pac.go),
// with no authentication and no IP guard: every client that can use the gateway
// can read it. Two rows used to answer it with a raw internal error string:
//
//	ca      → "Root CA load/init failed for <bundle path>: <OS error> —
//	           SSL inspection DISABLED (TLS traffic is tunnel-only:
//	           no scanning/DLP/CDR)"
//	clamav  → "unreachable: clamav: connect failed: dial tcp <host>:<port>:
//	           connect: connection refused"
//
// Between them that publishes the CA bundle's filesystem path, the internal
// address of the AV daemon, and an explicit, machine-readable statement that
// the gateway's inspection and malware controls are currently off — to anyone
// on the network. It is the fingerprint of a security-degraded node, and it
// lets an insider or malware poll for the window in which DLP/AV/CDR/DPI are
// down and time exfiltration to it.
//
// These tests pin the contract that closed it: the failing ROW stays (that is
// the CHAOS-06 visibility guarantee, and the gating verdict is unchanged), but
// every detail on this surface is a fixed, operator-directed string. The cause
// lives in the process log, the alert, and the role-gated admin APIs.

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/secscan"
)

// unreachableClam is a ClamScanner whose Ping fails with a dial-shaped error —
// the exact shape that carried the daemon's address onto the public surface.
type unreachableClam struct{}

func (unreachableClam) Ping() error {
	return errors.New("clamav: connect failed: dial tcp 10.42.7.13:3310: connect: connection refused")
}

func (unreachableClam) Scan([]byte) (name string, found bool, err error) {
	return "", false, nil
}

// readyProbeRows drives the real handler and returns the decoded rows.
func readyProbeRows(t *testing.T) map[string]struct {
	Status string `json:"status"`
	Detail string `json:"detail"`
} {
	t.Helper()
	rr := httptest.NewRecorder()
	handleReady(rr, nil)
	var r struct {
		Checks map[string]struct {
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"checks"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&r); err != nil {
		t.Fatalf("decode /ready: %v", err)
	}
	return r.Checks
}

// TestReadyz_CADetailWithholdsPathAndCause is the regression proper: a recorded
// CA load failure must produce a failing row whose detail names neither the
// bundle path nor the underlying cause.
func TestReadyz_CADetailWithholdsPathAndCause(t *testing.T) {
	captureStartupAlerts(t) // restores sslInspectionLoadError on cleanup

	// The verbatim string noteSSLInspectionUnavailable records, so the test
	// exercises the real producer's shape rather than a convenient stand-in.
	sslInspectionLoadError.Store("Root CA load/init failed for /data/ca.bundle: " +
		"CA save: CA write: atomic write /data/ca.bundle: create temp: permission denied — " +
		"SSL inspection DISABLED (TLS traffic is tunnel-only: no scanning/DLP/CDR)")

	row, ok := readyProbeRows(t)["ca"]
	if !ok {
		t.Fatal("ca row missing — the CHAOS-06 visibility contract requires the failing row to be present")
	}
	if row.Status != "fail" {
		t.Fatalf("ca status = %q, want fail (visibility must survive the redaction)", row.Status)
	}
	// Case-INSENSITIVE. Matching the producer's exact capitalisation
	// ("SSL inspection DISABLED") would let a replacement string reintroduce the
	// same statement in different case and still pass — which is precisely what
	// the first cut of this fix did ("SSL inspection is disabled").
	for _, leak := range []string{
		"/data/ca.bundle",     // filesystem path
		"permission denied",   // OS-level cause
		"tunnel-only",         // explicit "controls are off" advertisement
		"no scanning/dlp/cdr", // ditto, machine-readable
		// The enforcement POSTURE itself. "ca: fail" says a subsystem is
		// degraded; it must not say which way it fails, because a load failure
		// degrades to uninspected BYPASS and saying so hands an unauthenticated
		// observer the exfiltration window.
		"inspection",
		"disabled",
		"dlp",
	} {
		if strings.Contains(strings.ToLower(row.Detail), leak) {
			t.Errorf("ca detail leaks %q on the unauthenticated /ready surface: %q", leak, row.Detail)
		}
	}
	if !strings.Contains(row.Detail, "see server logs") {
		t.Errorf("ca detail = %q, want it to point the operator at the logs", row.Detail)
	}
}

// TestReadyz_ClamAVDetailWithholdsDaemonAddress pins the same rule for the AV
// row, including the invariant that redacting the detail did not stop the row
// from gating readiness (clamav, unlike ca, is a GATING check).
func TestReadyz_ClamAVDetailWithholdsDaemonAddress(t *testing.T) {
	captureStartupAlerts(t)
	sslInspectionLoadError.Store("")

	prev := globalSecScanner
	globalSecScanner = secscan.New(secscan.Deps{
		Clam:  unreachableClam{},
		Cache: newHashCache(16, time.Minute),
	})
	t.Cleanup(func() { globalSecScanner = prev })

	row, ok := readyProbeRows(t)["clamav"]
	if !ok {
		t.Fatal("clamav row missing — an unreachable AV daemon must stay visible to probes")
	}
	if row.Status != "fail" {
		t.Fatalf("clamav status = %q, want fail", row.Status)
	}
	for _, leak := range []string{"10.42.7.13", "3310", "connection refused", "dial tcp"} {
		if strings.Contains(strings.ToLower(row.Detail), leak) {
			t.Errorf("clamav detail leaks %q on the unauthenticated /ready surface: %q", leak, row.Detail)
		}
	}
	// Deliberately the ADMIN UI, not the log: ClamAV's ping error is logged only
	// by Scanner.Init, so a daemon that dies at runtime produces this row with no
	// log line to find. Pointing at a source that need not record the condition
	// is a dead end for the operator, so it is pinned here.
	if !strings.Contains(row.Detail, "admin UI") {
		t.Errorf("clamav detail = %q, want it to point the operator at the role-gated admin surface "+
			"(the runtime cause is not logged — see Scanner.Init)", row.Detail)
	}
	if strings.Contains(row.Detail, "see server logs") {
		t.Errorf("clamav detail = %q, must not send the operator to the log: a runtime ClamAV outage "+
			"is never logged, only the startup one is", row.Detail)
	}
}

// TestReadyz_ClamAVFailureStillGates proves the redaction changed only the
// STRING. An unreachable AV daemon must still drive the readiness verdict to
// 503, or the fix would have traded an information leak for a monitoring
// regression — a load balancer would keep routing to a node with no malware
// scanning.
func TestReadyz_ClamAVFailureStillGates(t *testing.T) {
	captureStartupAlerts(t)
	sslInspectionLoadError.Store("")

	prev := globalSecScanner
	globalSecScanner = secscan.New(secscan.Deps{
		Clam:  unreachableClam{},
		Cache: newHashCache(16, time.Minute),
	})
	t.Cleanup(func() { globalSecScanner = prev })

	_, code := computeReadiness()
	if code != 503 {
		t.Fatalf("readiness code = %d with an unreachable ClamAV, want 503 (gating unchanged)", code)
	}
}

// TestReadyz_NoDetailCarriesRawInternals is the standing sweep: whatever rows
// happen to be present in this process's configuration, none of their details
// may carry the markers of a raw Go/OS error. It is deliberately broader than
// the two rows fixed above so a NEW row added later cannot quietly reintroduce
// the class on the same unauthenticated surface.
func TestReadyz_NoDetailCarriesRawInternals(t *testing.T) {
	captureStartupAlerts(t)
	sslInspectionLoadError.Store("Root CA load/init failed for /data/ca.bundle: bad passphrase")

	prev := globalSecScanner
	globalSecScanner = secscan.New(secscan.Deps{
		Clam:  unreachableClam{},
		Cache: newHashCache(16, time.Minute),
	})
	t.Cleanup(func() { globalSecScanner = prev })

	// Markers of a raw error string surfacing verbatim: a dial/syscall error, a
	// wrapped-error separator, or an absolute filesystem path.
	markers := []string{"dial tcp", "dial unix", "connect: ", "no such file", "permission denied", "/data/", "/etc/", "/var/"}
	for name, row := range readyProbeRows(t) {
		for _, m := range markers {
			if strings.Contains(row.Detail, m) {
				t.Errorf("readiness row %q detail carries raw internals (%q) on the unauthenticated /ready surface: %q",
					name, m, row.Detail)
			}
		}
	}
}
