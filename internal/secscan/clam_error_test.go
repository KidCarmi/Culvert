package secscan

// CHAOS-10: a ClamAV engine error mid-request is fail-open for that single
// request (falls through to YARA, mirrors the remote-sidecar posture) but must
// be VISIBLE (counter + scan_clam_error alert) and must never poison the hash
// cache with a "clean" verdict computed while the daemon was dark — otherwise
// the same content stays admitted by hash long after ClamAV recovers.

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/alerts"
	"github.com/KidCarmi/Culvert/internal/hashcache"
)

// alertRecorder captures alerts.Fire events. The sink is process-global inside
// this test binary, so install/restore around each test (no t.Parallel here).
type alertRecorder struct {
	mu     sync.Mutex
	events []string
}

func (rec *alertRecorder) sink(event string, _ alerts.Payload) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.events = append(rec.events, event)
}

func (rec *alertRecorder) get() []string {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]string(nil), rec.events...)
}

func withAlertRecorder(t *testing.T) *alertRecorder {
	t.Helper()
	rec := &alertRecorder{}
	alerts.SetSink(rec.sink)
	t.Cleanup(func() { alerts.SetSink(func(string, alerts.Payload) {}) })
	return rec
}

func TestClamError_CountedAlertedAndCleanNotCached(t *testing.T) {
	rec := withAlertRecorder(t)
	clam := &fakeClam{scanErr: errors.New("daemon down")}
	ss := newEnabledTestScanner(Deps{
		Clam: clam,
		Yara: &fakeYARA{},
		Excl: fakeExcl{},
		Feed: fakeFeed{},
	})
	data := []byte("content scanned while clam is dark")
	before := atomic.LoadInt64(&statClamScanError)

	if res := ss.ScanBody(data); res != nil {
		t.Fatalf("clam error must stay fail-open for the request, got %+v", res)
	}
	if got := atomic.LoadInt64(&statClamScanError) - before; got != 1 {
		t.Fatalf("ClamScanError counter delta = %d, want 1", got)
	}
	events := rec.get()
	if len(events) != 1 || events[0] != "scan_clam_error" {
		t.Fatalf("want one scan_clam_error alert, got %v", events)
	}
	if _, ok := ss.cache.Get(hashcache.SHA256Hex(data)); ok {
		t.Fatal("verdict computed while ClamAV errored must NOT be cached (cache poisoning)")
	}
}

func TestClamError_RecoveredDaemonRescansAndBlocks(t *testing.T) {
	withAlertRecorder(t)
	clam := &fakeClam{scanErr: errors.New("daemon down")}
	ss := newEnabledTestScanner(Deps{
		Clam: clam,
		Yara: &fakeYARA{},
		Excl: fakeExcl{},
		Feed: fakeFeed{},
	})
	data := []byte("EICAR-ish payload")

	// First pass: daemon down → fail-open, no cached verdict.
	if res := ss.ScanBody(data); res != nil {
		t.Fatalf("first scan (daemon down) should fail open, got %+v", res)
	}

	// Daemon recovers and now detects the content.
	clam.scanErr = nil
	clam.name = "EICAR-Test"
	clam.found = true

	res := ss.ScanBody(data)
	if res == nil || !res.Blocked || res.Source != "clamav" {
		t.Fatalf("recovered daemon must rescan and block (pre-fix: poisoned clean cache admitted it), got %+v", res)
	}
	if clam.calls != 2 {
		t.Fatalf("engine must have been consulted both times, ran %d", clam.calls)
	}
}

func TestClamClean_VerdictStillCached(t *testing.T) {
	withAlertRecorder(t)
	clam := &fakeClam{}
	ss := newEnabledTestScanner(Deps{
		Clam: clam,
		Yara: &fakeYARA{},
		Excl: fakeExcl{},
		Feed: fakeFeed{},
	})
	data := []byte("genuinely clean content")

	if res := ss.ScanBody(data); res != nil {
		t.Fatalf("clean scan must pass, got %+v", res)
	}
	if res := ss.ScanBody(data); res != nil {
		t.Fatalf("cached clean must pass, got %+v", res)
	}
	if clam.calls != 1 {
		t.Fatalf("error-free clean verdicts must still cache (engine ran %d times, want 1)", clam.calls)
	}
}
