package secscan

// P1 (review 5478346473 on #1528): a clean verdict cached BEFORE a clamd
// engine fault must not keep admitting its body once the fault has armed the
// quarantine. The F-P2 residual is a wrong "stream: OK" that precedes the
// first fault of an episode; without these gates the cache keeps that wrong
// verdict alive for its whole TTL, served ahead of the fresh-scan check.

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/hashcache"
)

// DEFECT GATE (the reviewer's regression): cache clean -> a different body
// faults -> 440 ms later the first body again. It must be re-judged, not
// admitted from the pre-fault cache.
func TestClamQuarantine_PreFaultCachedCleanIsNotServed(t *testing.T) {
	withAlertRecorder(t)
	withAVPosture(t, AVUnavailableClosed)
	clock := withQuarantineClock(t)
	clam := &fakeClam{}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})

	first := []byte("body clamd called clean before the episode")
	if res := ss.ScanBody(first); res != nil {
		t.Fatalf("setup: first scan should be clean, got %+v", res)
	}
	if c, ok := ss.cache.Get(hashcache.SHA256Hex(first)); !ok || !c.Clean {
		t.Fatal("setup: the clean verdict must be cached")
	}

	clam.scanErr = errSpool
	_ = ss.ScanBody([]byte("a different body hits the spool fault"))
	clam.scanErr = nil
	clock.advance(440 * time.Millisecond)
	if st := ss.ClamAVStatus(); len(st) < len(ClamStatusScanFailingPrefix) || st[:len(ClamStatusScanFailingPrefix)] != ClamStatusScanFailingPrefix {
		t.Fatalf("setup: quarantine must be armed, status %q", st)
	}

	// The scanner would now detect the first body: the pre-fault OK was wrong.
	clam.found, clam.name = true, "Eicar-Signature"
	calls := clam.calls
	stale := ClamCleanCacheStaleTotal()
	res := ss.ScanBody(first)
	if got := ClamCleanCacheStaleTotal() - stale; got != 1 {
		t.Fatalf("the re-judged cache entry must be counted once, counter moved by %d", got)
	}
	if clam.calls == calls {
		t.Fatal("the pre-fault cached clean verdict was served; the body was never re-scanned")
	}
	if res == nil || !res.Blocked || res.Source != "clamav" {
		t.Fatalf("re-scan must block as the detection, got %+v", res)
	}
}

// DEFECT GATE: the same body, and clamd still answers clean inside the window
// (the wrong-OK case): refused as AV-unavailable, not admitted from cache.
func TestClamQuarantine_PreFaultCachedCleanIsRefusedInsideWindow(t *testing.T) {
	withAlertRecorder(t)
	withAVPosture(t, AVUnavailableClosed)
	withQuarantineClock(t)
	clam := &fakeClam{}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	first := []byte("cached clean, then the daemon faults")
	_ = ss.ScanBody(first)
	clam.scanErr = errSpool
	_ = ss.ScanBody([]byte("faulting stream"))
	clam.scanErr = nil
	if res := ss.ScanBody(first); res == nil || res.Source != SourceAVUnavailable {
		t.Fatalf("inside the window a pre-fault clean must be refused, got %+v", res)
	}
}

// DEFECT GATE: entries from before a fault stay invalid AFTER the window: the
// body is re-scanned once, then the new verdict caches normally.
func TestClamQuarantine_StaleEntryAfterWindowIsRescannedThenCached(t *testing.T) {
	withAlertRecorder(t)
	withAVPosture(t, AVUnavailableClosed)
	clock := withQuarantineClock(t)
	clam := &fakeClam{}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	first := []byte("cached long before the episode")
	_ = ss.ScanBody(first)
	clam.scanErr = errSpool
	_ = ss.ScanBody([]byte("faulting stream"))
	clam.scanErr = nil
	clock.advance(clamQuarantineWindow + time.Second)

	calls := clam.calls
	if res := ss.ScanBody(first); res != nil {
		t.Fatalf("after the window a clean body is delivered, got %+v", res)
	}
	if clam.calls != calls+1 {
		t.Fatalf("a pre-fault entry must be re-scanned after the window (calls %d -> %d)", calls, clam.calls)
	}
	if res := ss.ScanBody(first); res != nil || clam.calls != calls+1 {
		t.Fatalf("the post-window verdict must cache normally (res %+v, calls %d)", res, clam.calls)
	}
}

// DEFECT GATE (concurrency): a scan that STARTED before a fault and answers
// clean after it must not leave a cache entry that is honoured later. The
// clean reply is held until a fault has been recorded mid-scan.
func TestClamQuarantine_ScanSpanningAFaultIsNotHonoured(t *testing.T) {
	withAlertRecorder(t)
	withAVPosture(t, AVUnavailableClosed)
	clock := withQuarantineClock(t)
	gate := &spanClam{release: make(chan struct{}), entered: make(chan struct{}, 1)}
	ss := newEnabledTestScanner(Deps{Clam: gate, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	body := []byte("in flight when the daemon faulted")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = ss.ScanBody(body) }()
	<-gate.entered
	ss.noteClamEngineFault() // another stream faults while this one is in clamd
	clock.advance(clamQuarantineWindow + time.Second)
	close(gate.release)
	wg.Wait()

	before := gate.calls.Load()
	_ = ss.ScanBody(body)
	if gate.calls.Load() == before {
		t.Fatal("the body was admitted from a cache entry produced across a fault")
	}
}

// CONTROL: a cached BLOCK survives a fault; blocking is always the safe reading.
func TestClamQuarantine_CachedBlockSurvivesAFault(t *testing.T) {
	withAlertRecorder(t)
	withAVPosture(t, AVUnavailableClosed)
	withQuarantineClock(t)
	clam := &fakeClam{found: true, name: "Eicar-Signature"}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	bad := []byte("infected body")
	_ = ss.ScanBody(bad)
	clam.found, clam.scanErr = false, errSpool
	_ = ss.ScanBody([]byte("faulting stream"))
	clam.scanErr = nil
	calls := clam.calls
	res := ss.ScanBody(bad)
	if res == nil || !res.Blocked || res.Source != "clamav" || res.Reason != "Eicar-Signature" {
		t.Fatalf("a cached detection must still block, got %+v", res)
	}
	if clam.calls != calls {
		t.Fatal("a cached detection must be served from cache, not re-scanned")
	}
}

// CONTROL: with no fault at all, clean verdicts cache exactly as before.
func TestClamQuarantine_NoFaultCleanCacheUnchanged(t *testing.T) {
	withAlertRecorder(t)
	withQuarantineClock(t)
	clam := &fakeClam{}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	body := []byte("ordinary clean body")
	_ = ss.ScanBody(body)
	calls := clam.calls
	for i := 0; i < 3; i++ {
		if res := ss.ScanBody(body); res != nil {
			t.Fatalf("clean body: got %+v", res)
		}
	}
	if clam.calls != calls {
		t.Fatalf("a healthy daemon's clean verdict must be served from cache (calls %d -> %d)", calls, clam.calls)
	}
}

// spanClam answers clean, but holds the reply until release is closed.
type spanClam struct {
	release chan struct{}
	entered chan struct{}
	calls   atomic.Int64
}

func (g *spanClam) Ping() error { return nil }
func (g *spanClam) Scan([]byte) (name string, found bool, err error) {
	if g.calls.Add(1) == 1 {
		g.entered <- struct{}{}
		<-g.release
	}
	return "", false, nil
}
