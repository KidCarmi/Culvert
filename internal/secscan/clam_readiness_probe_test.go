package secscan

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// A daemon whose temporary directory cannot take a file answers PING but
// fails every INSTREAM scan (measured on the appliance under inode
// exhaustion, lab run 37957097250). PING alone reported it connected while
// every scanned body was refused; the status probe must say it cannot scan.
func TestClamStatus_PingAnswersButScansFailIsScanFailing(t *testing.T) {
	clam := &fakeClam{scanErr: errors.New("clamav: scan error: Error writing to temporary file ERROR | stream: OK")}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	before := Counters().ClamScanError
	st := ss.ClamAVStatus()
	if !strings.HasPrefix(st, ClamStatusScanFailingPrefix+":") {
		t.Fatalf("PING ok + scan failing: status %q, want prefix %q", st, ClamStatusScanFailingPrefix)
	}
	// The probe is the status read, not a request: no request-path accounting.
	if d := Counters().ClamScanError - before; d != 0 {
		t.Fatalf("the readiness probe moved the request scan-error counter by %d", d)
	}
	if ss.clamStatusStale.Load() {
		t.Fatal("the readiness probe must not mark the status stale (that would re-probe on every read)")
	}
}

// CONTROL: a healthy daemon is still "connected", and the probe really ran
// (a probe that never scans would pass the defect gate by skipping it).
func TestClamStatus_HealthyDaemonIsConnectedAndProbed(t *testing.T) {
	clam := &fakeClam{}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	if st := ss.ClamAVStatus(); st != "connected" {
		t.Fatalf("healthy daemon: status %q", st)
	}
	if clam.calls != 1 {
		t.Fatalf("the status read must scan the probe exactly once, scanned %d times", clam.calls)
	}
	// cached: a second read inside the TTL does not probe again
	_ = ss.ClamAVStatus()
	if clam.calls != 1 {
		t.Fatalf("a cached status must not re-probe, scanned %d times", clam.calls)
	}
}

// An unreachable daemon stays "unreachable" (the existing enum) and is not
// probed: there is nothing to scan with.
func TestClamStatus_UnreachableIsNotProbed(t *testing.T) {
	clam := &fakeClam{pingErr: errors.New("clamav: connect: refused")}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	if st := ss.ClamAVStatus(); !strings.HasPrefix(st, "unreachable:") {
		t.Fatalf("status %q, want unreachable", st)
	}
	if clam.calls != 0 {
		t.Fatalf("an unreachable daemon must not be probed, scanned %d times", clam.calls)
	}
}

// A probe body reported as infected is not a clean verdict either.
func TestClamStatus_ProbeReportedInfectedIsScanFailing(t *testing.T) {
	clam := &fakeClam{name: "Odd.Signature", found: true}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	if st := ss.ClamAVStatus(); !strings.HasPrefix(st, ClamStatusScanFailingPrefix) {
		t.Fatalf("status %q, want %s", st, ClamStatusScanFailingPrefix)
	}
}

// Recovery is on evidence: once the cached failure ages out, the next read
// probes again and a clean verdict reports connected.
func TestClamStatus_ScanFailingRecoversOnACleanProbe(t *testing.T) {
	clam := &fakeClam{scanErr: errors.New("clamav: empty response (daemon may have closed connection)")}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	if st := ss.ClamAVStatus(); !strings.HasPrefix(st, ClamStatusScanFailingPrefix) {
		t.Fatalf("status %q", st)
	}
	clam.scanErr = nil
	ss.clamStatusExpiry = time.Time{}
	if st := ss.ClamAVStatus(); st != "connected" {
		t.Fatalf("after the daemon can scan again: status %q", st)
	}
}
