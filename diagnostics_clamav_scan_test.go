package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/secscan"
)

// clamProbeAddr is what a real probe error carries and the row must not.
const clamProbeAddr = "10.0.1.5:3310"

// stubClam is a ClamAV daemon whose ping answers with a fixed error (nil =
// reachable).
type stubClam struct{ pingErr error }

func (s stubClam) Ping() error { return s.pingErr }

func (s stubClam) Scan([]byte) (name string, found bool, err error) { return "", false, s.pingErr }

// withStubClamScanner installs an enabled scanner over the given daemon and
// waits for its first status observation, restoring both scan globals.
func withStubClamScanner(t *testing.T, clam secscan.ClamScanner) {
	t.Helper()
	prevSec, prevRemote := globalSecScanner, globalRemoteScanner
	sc := secscan.New(secscan.Deps{Clam: clam, Cache: newHashCache(16, time.Minute)})
	sc.Init("", 0, nil) // enables scanning and starts the status probe
	sc.WaitStatusProbe()
	globalSecScanner, globalRemoteScanner = sc, &RemoteScanner{}
	t.Cleanup(func() {
		sc.WaitStatusProbe()
		globalSecScanner, globalRemoteScanner = prevSec, prevRemote
	})
}

func TestClamAVScanDiagnostics_NoRowWhenNotDegraded(t *testing.T) {
	// ClamAV not configured: nothing was promised, so nothing is reported.
	withStubClamScanner(t, nil)
	if rows := checkClamAVScan(); len(rows) != 0 {
		t.Fatalf("a node without ClamAV must add no row, got %+v", rows)
	}

	// Daemon answering.
	withStubClamScanner(t, stubClam{})
	if got := globalSecScanner.ClamAVStatus(); got != "connected" {
		t.Fatalf("precondition: status = %q, want connected", got)
	}
	if rows := checkClamAVScan(); len(rows) != 0 {
		t.Fatalf("a reachable daemon must add no row, got %+v", rows)
	}
}

func TestClamAVScanDiagnostics_UnreachableDaemon(t *testing.T) {
	withStubClamScanner(t, stubClam{pingErr: errors.New("clamav: connect failed: dial tcp " + clamProbeAddr + ": connect: connection refused")})
	if got := globalSecScanner.ClamAVStatus(); !strings.Contains(got, clamProbeAddr) {
		t.Fatalf("precondition: status %q must carry the probe error", got)
	}

	rows := checkClamAVScan()
	if len(rows) != 1 {
		t.Fatalf("an unreachable daemon must add exactly one row, got %d", len(rows))
	}
	r := rows[0]
	if r.Code != clamAVScanCode || r.Status != diagWarn || r.OperatorAction == "" {
		t.Fatalf("unexpected row %+v", r)
	}
	if !strings.Contains(r.Message, "fail-open") {
		t.Fatalf("the row must state the fail-open consequence: %q", r.Message)
	}
	if strings.Contains(r.Message, clamProbeAddr) || strings.Contains(r.OperatorAction, clamProbeAddr) {
		t.Fatalf("viewer-readable row must not carry the daemon address: %+v", r)
	}

	contract := buildOperatorContract()
	found := false
	for _, c := range contract.Checks {
		if c.Code == clamAVScanCode {
			found = true
		}
	}
	if !found {
		t.Fatal("clamav_scan row missing from the assembled contract")
	}
	if contract.Verdict == diagOK {
		t.Fatal("the report verdict must not read ok while antivirus scanning is dark")
	}

	// Body scanning delegated to the remote scan service: the local daemon is
	// not the one scanning, so the row is withheld.
	remote := &RemoteScanner{}
	remote.Init("http://scan.invalid:9000")
	if !remote.Enabled() {
		t.Fatal("precondition: remote scanner did not enable")
	}
	globalRemoteScanner = remote
	if rows := checkClamAVScan(); len(rows) != 0 {
		t.Fatalf("remote scan mode must add no row, got %+v", rows)
	}
}
