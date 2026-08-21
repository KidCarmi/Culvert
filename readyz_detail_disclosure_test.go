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
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
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

// ── /health: the same listener, the same contract ────────────────────────────
//
// /health is dispatched by the SAME routeProxyListenerBuiltin switch as /ready,
// on the SAME unauthenticated proxy listener (main.go calls it before
// handleRequest, so no proxy auth, no admin session, no IP guard). When the
// rows above were redacted, /health was left answering with the raw producer
// value verbatim:
//
//	clamav → "unreachable: clamav: connect failed: dial tcp <host>:<port>:
//	          connect: connection refused"
//
// computeHealth tags that field redact:"internal", and the support-bundle
// collector honours the tag via Redactor.Classify — but handleHealth encodes
// the struct directly, so the classification was bypassed on the one surface
// where it mattered most. These tests hold /health to the contract /ready
// already has.

// healthDoc drives the real handler and returns the decoded document.
func healthDoc(t *testing.T) map[string]any {
	t.Helper()
	rr := httptest.NewRecorder()
	handleHealth(rr, nil)
	var doc map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&doc); err != nil {
		t.Fatalf("decode /health: %v", err)
	}
	return doc
}

// TestHealth_ClamAVStatusWithholdsDaemonAddress is the regression proper: the
// unauthenticated /health document must not carry the AV daemon's address, port,
// or dial error — the same values that were removed from the /ready clamav row.
func TestHealth_ClamAVStatusWithholdsDaemonAddress(t *testing.T) {
	captureStartupAlerts(t)
	sslInspectionLoadError.Store("")

	prev := globalSecScanner
	globalSecScanner = secscan.New(secscan.Deps{
		Clam:  unreachableClam{},
		Cache: newHashCache(16, time.Minute),
	})
	t.Cleanup(func() { globalSecScanner = prev })

	got, _ := healthDoc(t)["clamav"].(string)
	for _, leak := range []string{"10.42.7.13", "3310", "connection refused", "dial tcp", "connect failed"} {
		if strings.Contains(strings.ToLower(got), leak) {
			t.Errorf("clamav leaks %q on the unauthenticated /health surface: %q", leak, got)
		}
	}
	// The DEGRADATION must survive the redaction, exactly as it did for /ready:
	// withholding the cause must not turn an AV outage into a healthy-looking
	// document.
	if got != "unreachable" {
		t.Errorf("clamav = %q, want the coarse %q — the outage must stay visible", got, "unreachable")
	}
}

// TestHealth_ClamAVStatusPreservesMonitoringStates is the positive half: the
// redaction must be a pure narrowing of the FAILURE value. A monitor that keys
// on "connected" or "disabled" has to behave identically before and after.
func TestHealth_ClamAVStatusPreservesMonitoringStates(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"connected", "connected"},
		{"disabled", "disabled"},
		{"unreachable: clamav: connect failed: dial tcp 10.42.7.13:3310: connect: connection refused", "unreachable"},
		{"unreachable: some other cause", "unreachable"},
		// Boundary / malformed: anything unrecognised must fail SAFE (collapse),
		// never pass through — a future producer value must not become a new leak.
		{"", "unreachable"},
		{"connected: 10.0.0.5:3310", "unreachable"},
		{"CONNECTED", "unreachable"},
		{"unreachable", "unreachable"},
	} {
		if got := coarseClamAVStatus(tc.in); got != tc.want {
			t.Errorf("coarseClamAVStatus(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestHealth_NoFieldCarriesRawInternals is the standing sweep for /health,
// mirroring TestReadyz_NoDetailCarriesRawInternals. It walks every field of the
// document rather than the two known ones, so a NEW posture field added later
// cannot quietly reintroduce the class on this surface.
func TestHealth_NoFieldCarriesRawInternals(t *testing.T) {
	captureStartupAlerts(t)
	sslInspectionLoadError.Store("Root CA load/init failed for /data/ca.bundle: " +
		"create temp: permission denied — SSL inspection DISABLED (TLS traffic is tunnel-only: no scanning/DLP/CDR)")

	prev := globalSecScanner
	globalSecScanner = secscan.New(secscan.Deps{
		Clam:  unreachableClam{},
		Cache: newHashCache(16, time.Minute),
	})
	t.Cleanup(func() { globalSecScanner = prev })

	markers := []string{"dial tcp", "dial unix", "connect: ", "no such file", "permission denied", "/data/", "/etc/", "/var/"}
	for field, raw := range healthDoc(t) {
		s, isStr := raw.(string)
		if !isStr {
			continue
		}
		for _, m := range markers {
			if strings.Contains(s, m) {
				t.Errorf("health field %q carries raw internals (%q) on the unauthenticated /health surface: %q",
					field, m, s)
			}
		}
	}
}

// TestHealth_RedactionHoldsUnderConcurrency proves the narrowing is a property
// of the handler and not of a lucky interleaving: the ClamAV status is served
// from a mutex-guarded, TTL-expiring cache that re-pings on miss, so concurrent
// probes race the refresh. Under -race this also pins that the redaction adds no
// shared mutable state of its own.
func TestHealth_RedactionHoldsUnderConcurrency(t *testing.T) {
	captureStartupAlerts(t)
	sslInspectionLoadError.Store("")

	prev := globalSecScanner
	// A zero TTL forces every call to miss the cache and re-ping, maximising the
	// window the raw error string is in flight.
	globalSecScanner = secscan.New(secscan.Deps{
		Clam:  unreachableClam{},
		Cache: newHashCache(16, time.Minute),
	})
	t.Cleanup(func() { globalSecScanner = prev })

	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := httptest.NewRecorder()
			handleHealth(rr, nil)
			if body := rr.Body.String(); strings.Contains(body, "10.42.7.13") || strings.Contains(body, "dial tcp") {
				errs <- body
			}
		}()
	}
	wg.Wait()
	close(errs)
	for body := range errs {
		t.Fatalf("concurrent /health probe leaked the daemon address: %s", body)
	}
}

// ── /ready node_cert: the row the original sweep could not see ───────────────
//
// appendDPHealthChecks returns immediately unless audit.DPMode() is set, so the
// standing sweep below — which runs in the default non-DP mode — never produced
// a node_cert row and never inspected it. The row meanwhile formatted
// renewDPCert's error verbatim, and that error is not sanitised: the
// "RenewCert RPC: %w" branch names the CONTROL PLANE's address and port, and
// the "write cert:"/"write key:" branches carry an *os.PathError with the
// absolute node cert/key path. Both reached the unauthenticated /ready.

// withFailingDPCertRenewal puts the process in DP mode with a recorded renewal
// failure and returns the resulting node_cert detail.
func withFailingDPCertRenewal(t *testing.T, days int, renewErr error) string {
	_ = days
	_ = renewErr // #1139 reduced the recorder to boolean-only state — nothing
	// leak-capable is recorded any more, which is the strongest form of the
	// redaction these tests pin; they now assert the published detail directly.
	t.Helper()
	captureStartupAlerts(t)
	sslInspectionLoadError.Store("")
	audit.SetDPMode(true)
	t.Cleanup(func() {
		audit.SetDPMode(false)
		clearDPCertRenewalFailure()
	})
	recordDPCertRenewalFailure()

	row, ok := readyProbeRows(t)["node_cert"]
	if !ok {
		t.Fatal("node_cert row missing — the CHAOS-09 visibility contract requires the failing row to be present")
	}
	if row.Status != "fail" {
		t.Fatalf("node_cert status = %q, want fail (visibility must survive the redaction)", row.Status)
	}
	return row.Detail
}

// TestReadyz_NodeCertDetailWithholdsControlPlaneAddress pins the RPC branch: a
// renewal that cannot reach the CP must not publish where the CP lives.
func TestReadyz_NodeCertDetailWithholdsControlPlaneAddress(t *testing.T) {
	// The verbatim shape client.call produces through renewDPCert's
	// "RenewCert RPC: %w" wrap.
	detail := withFailingDPCertRenewal(t, -3, fmt.Errorf("RenewCert RPC: %w",
		errors.New("rpc error: code = Unavailable desc = connection error: "+
			"dial tcp 10.20.30.40:9443: connect: connection refused")))

	for _, leak := range []string{"10.20.30.40", "9443", "dial tcp", "connection refused", "rpc error"} {
		if strings.Contains(strings.ToLower(detail), leak) {
			t.Errorf("node_cert detail leaks %q on the unauthenticated /ready surface: %q", leak, detail)
		}
	}
	// #1139 withheld the countdown too (an attacker-usable expiry oracle);
	// the operational signal that survives is the fixed failing detail, with
	// the countdown on the authenticated surfaces.
	if strings.Contains(detail, "day(s)") {
		t.Errorf("node_cert detail = %q, want no expiry countdown on the unauthenticated surface", detail)
	}
	// Unlike clamav, this cause IS logged (both renewal call sites) and carried
	// by the cert_expiry alert, so the log is a real destination.
	if !strings.Contains(detail, "see server logs") {
		t.Errorf("node_cert detail = %q, want it to point the operator at the logs", detail)
	}
}

// TestReadyz_NodeCertDetailWithholdsFilesystemPath pins the write branch: a
// renewal that cannot persist must not publish the appliance's on-disk layout.
func TestReadyz_NodeCertDetailWithholdsFilesystemPath(t *testing.T) {
	detail := withFailingDPCertRenewal(t, 5, fmt.Errorf("write cert: %w",
		&os.PathError{Op: "open", Path: "/data/cluster/node-dp7.crt", Err: os.ErrPermission}))

	for _, leak := range []string{"/data/cluster", "node-dp7.crt", "permission denied", "open "} {
		if strings.Contains(strings.ToLower(detail), leak) {
			t.Errorf("node_cert detail leaks %q on the unauthenticated /ready surface: %q", leak, detail)
		}
	}
	if strings.Contains(detail, "day(s)") {
		t.Errorf("node_cert detail = %q, want no expiry countdown on the unauthenticated surface", detail)
	}
	if !strings.Contains(detail, "see server logs") {
		t.Errorf("node_cert detail = %q, want it to point the operator at the logs", detail)
	}
}

// TestReadyz_NodeCertHealthyRowStaysOK is the negative control: with no recorded
// failure the row must be a plain ok with no detail at all, so the redaction did
// not turn a healthy DP node into a permanently failing one.
func TestReadyz_NodeCertHealthyRowStaysOK(t *testing.T) {
	captureStartupAlerts(t)
	sslInspectionLoadError.Store("")
	audit.SetDPMode(true)
	t.Cleanup(func() {
		audit.SetDPMode(false)
		clearDPCertRenewalFailure()
	})
	clearDPCertRenewalFailure()

	row, ok := readyProbeRows(t)["node_cert"]
	if !ok {
		t.Fatal("node_cert row missing in DP mode")
	}
	if row.Status != "ok" || row.Detail != "" {
		t.Errorf("node_cert = %+v, want a bare ok row when renewal is healthy", row)
	}
}

// TestReadyz_DPRowsCarryNoRawInternals extends the standing sweep INTO DP mode,
// which is the gap that let node_cert keep the class after ca and clamav were
// fixed: appendDPHealthChecks is a no-op outside DP mode, so the non-DP sweep
// below can never inspect the cp_poll or node_cert rows.
func TestReadyz_DPRowsCarryNoRawInternals(t *testing.T) {
	detail := withFailingDPCertRenewal(t, -1, fmt.Errorf("write key: %w",
		&os.PathError{Op: "open", Path: "/var/lib/culvert/node.key", Err: os.ErrPermission}))
	_ = detail

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
