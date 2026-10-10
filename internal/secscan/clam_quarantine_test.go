package secscan

// F-P2 gates (clam_quarantine.go). The defect, as recorded in lab run
// 38013626508: during a disk fill clamd failed one stream ("Error writing to
// temporary file") and 0.44 s later answered a bare "stream: OK" to a complete
// EICAR stream, which Culvert delivered. The fake below replays exactly that
// sequence: a fault, then a clean verdict for content that is not clean.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/hashcache"
)

// quarantineClock is an injected clock for the quarantine window.
type quarantineClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *quarantineClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *quarantineClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func withQuarantineClock(t *testing.T) *quarantineClock {
	t.Helper()
	c := &quarantineClock{t: time.Date(2026, 10, 10, 1, 44, 28, 0, time.UTC)}
	t.Cleanup(SetClamQuarantineClockForTest(c.now))
	return c
}

var errSpool = errors.New("clamav: scan error: Error writing to temporary file ERROR | stream: OK")

// DEFECT GATE (closed posture): the clean answer that follows a fault is
// refused, never delivered, never cached.
func TestClamQuarantine_CleanAfterFaultIsRefusedWhenClosed(t *testing.T) {
	withAlertRecorder(t)
	withAVPosture(t, AVUnavailableClosed)
	clock := withQuarantineClock(t)
	clam := &fakeClam{scanErr: errSpool}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})

	_ = ss.ScanBody([]byte("stream clamd failed to spool"))
	clam.scanErr = nil // clamd now says "stream: OK" ...
	eicar := []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	clock.advance(440 * time.Millisecond)
	before := ClamCleanQuarantinedTotal()
	res := ss.ScanBody(eicar) // ... for content it did not actually scan
	if res == nil || !res.Blocked || res.Source != SourceAVUnavailable {
		t.Fatalf("a clean verdict 0.44 s after an engine fault must be refused under the closed posture, got %+v", res)
	}
	if got := ClamCleanQuarantinedTotal() - before; got != 1 {
		t.Fatalf("quarantined counter moved by %d, want 1", got)
	}
	if _, ok := ss.cache.Get(res.Hash); ok {
		t.Fatal("a quarantined verdict must never be cached")
	}
}

// DEFECT GATE: every further fault extends the window — a daemon that keeps
// faulting every few seconds never gets a clean verdict trusted.
func TestClamQuarantine_RepeatedFaultsExtendTheWindow(t *testing.T) {
	withAlertRecorder(t)
	withAVPosture(t, AVUnavailableClosed)
	clock := withQuarantineClock(t)
	clam := &fakeClam{}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	for i := 0; i < 5; i++ {
		clam.scanErr = errSpool
		_ = ss.ScanBody([]byte("faulting stream " + string(rune('a'+i))))
		clock.advance(clamQuarantineWindow - time.Second) // never quite out of the window
	}
	clam.scanErr = nil
	if res := ss.ScanBody([]byte("clean, but the daemon has been faulting")); res == nil || res.Source != SourceAVUnavailable {
		t.Fatalf("the window must be measured from the LAST fault, got %+v", res)
	}
}

// Under the open posture the operator chose forwarding over refusal; the
// quarantine still keeps the untrusted verdict out of the cache, and counts it.
func TestClamQuarantine_OpenPostureForwardsUncached(t *testing.T) {
	withAlertRecorder(t)
	withAVPosture(t, AVUnavailableOpen)
	withQuarantineClock(t)
	clam := &fakeClam{scanErr: errSpool}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	_ = ss.ScanBody([]byte("faulting stream"))
	clam.scanErr = nil
	data := []byte("clean under the open posture")
	before := ClamCleanQuarantinedTotal()
	if res := ss.ScanBody(data); res != nil {
		t.Fatalf("open posture forwards, got %+v", res)
	}
	if ClamCleanQuarantinedTotal()-before != 1 {
		t.Fatal("an untrusted clean verdict must be counted under the open posture too")
	}
	if _, ok := ss.cache.Get(hashcache.SHA256Hex(data)); ok {
		t.Fatal("an untrusted clean verdict must not be cached under the open posture either")
	}
}

// CONTROL: a detection inside the window still blocks as a detection.
func TestClamQuarantine_DetectionStillBlocksAsDetection(t *testing.T) {
	withAlertRecorder(t)
	withAVPosture(t, AVUnavailableClosed)
	withQuarantineClock(t)
	clam := &fakeClam{scanErr: errSpool}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	_ = ss.ScanBody([]byte("faulting stream"))
	clam.scanErr, clam.found, clam.name = nil, true, "Eicar-Signature"
	res := ss.ScanBody([]byte("infected"))
	if res == nil || !res.Blocked || res.Source != "clamav" || res.Reason != "Eicar-Signature" {
		t.Fatalf("a detection inside the window must block as the detection, got %+v", res)
	}
}

// CONTROL: our OWN limits are not engine faults. A budget overrun or a full
// slot queue must not open the window, or one slow scan would refuse a minute
// of clean traffic on a healthy daemon.
func TestClamQuarantine_OwnLimitsDoNotQuarantine(t *testing.T) {
	withAlertRecorder(t)
	withQuarantineClock(t)
	ss := newEnabledTestScanner(Deps{Clam: &fakeClam{}, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	ss.recordClamFailure(ctx, errors.New("clamav: read response: i/o timeout"))
	if r := ss.clamQuarantineRemaining(); r != 0 {
		t.Fatalf("a budget overrun opened the quarantine (%v)", r)
	}
}

// CONTROL: a healthy daemon is never quarantined, and clean verdicts cache.
func TestClamQuarantine_HealthyDaemonUnaffected(t *testing.T) {
	withAlertRecorder(t)
	withAVPosture(t, AVUnavailableClosed)
	withQuarantineClock(t)
	ss := newEnabledTestScanner(Deps{Clam: &fakeClam{}, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	data := []byte("ordinary clean body")
	if res := ss.ScanBody(data); res != nil {
		t.Fatalf("healthy daemon, clean body: got %+v", res)
	}
	if c, ok := ss.cache.Get(hashcache.SHA256Hex(data)); !ok || !c.Clean {
		t.Fatal("a trusted clean verdict must cache as before")
	}
	if st := ss.ClamAVStatus(); st != "connected" {
		t.Fatalf("healthy daemon status %q", st)
	}
}

// A clock that went BACKWARDS past the fault stamp keeps the quarantine on
// (fail-safe) but for one window only, never indefinitely.
func TestClamQuarantine_ClockRollbackCostsOneWindow(t *testing.T) {
	clock := withQuarantineClock(t)
	ss := newEnabledTestScanner(Deps{Clam: &fakeClam{}, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	ss.noteClamEngineFault()
	clock.advance(-24 * time.Hour)
	if r := ss.clamQuarantineRemaining(); r != clamQuarantineWindow {
		t.Fatalf("rollback: remaining %v, want a full window", r)
	}
	clock.advance(clamQuarantineWindow + time.Second)
	if r := ss.clamQuarantineRemaining(); r != 0 {
		t.Fatalf("a rollback must not quarantine beyond one window (remaining %v)", r)
	}
}

// Readiness tells the truth while the window is open, with a bounded value.
func TestClamQuarantine_StatusReportsTheWindow(t *testing.T) {
	clock := withQuarantineClock(t)
	ss := newEnabledTestScanner(Deps{Clam: &fakeClam{}, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	ss.noteClamEngineFault()
	clock.advance(15 * time.Second)
	st := ss.ClamAVStatus()
	if !strings.HasPrefix(st, ClamStatusScanFailingPrefix) || !strings.Contains(st, "45s") {
		t.Fatalf("status inside the window: %q", st)
	}
}
