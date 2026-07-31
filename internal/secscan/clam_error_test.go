package secscan

// CHAOS-10: a ClamAV engine error mid-request is fail-open for that single
// request (falls through to YARA, mirrors the remote-sidecar posture) but must
// be VISIBLE (counter + scan_clam_error alert) and must never poison the hash
// cache with a "clean" verdict computed while the daemon was dark — otherwise
// the same content stays admitted by hash long after ClamAV recovers.

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/alerts"
	"github.com/KidCarmi/Culvert/internal/hashcache"
)

// alertRecorder captures alerts.Fire events. The sink is process-global inside
// this test binary, so install/restore around each test (no t.Parallel here).
//
// clamScanError fires on its OWN goroutine, so a straggler from an earlier
// test (or an earlier -count run of the same test) can land in a later
// test's recorder — the determinism gate caught exactly that (one run
// observed two scan_clam_error events). Assertions therefore filter on the
// payload Detail carrying a per-invocation unique error string (the CLAUDE.md
// "assert on content, not count" pattern), never on the raw event tally.
type recordedAlert struct {
	event  string
	detail string
}

type alertRecorder struct {
	mu     sync.Mutex
	events []recordedAlert
}

// clamErrSeq makes each test invocation's fake engine error unique across
// -count=N reruns and shuffled orders, so straggler alert goroutines from
// other invocations can never match this invocation's filter.
var clamErrSeq atomic.Int64

func uniqueClamErr(t *testing.T) error {
	t.Helper()
	return fmt.Errorf("daemon down [%s#%d]", t.Name(), clamErrSeq.Add(1))
}

func (rec *alertRecorder) sink(event string, p alerts.Payload) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.events = append(rec.events, recordedAlert{event: event, detail: p.Detail})
}

func (rec *alertRecorder) get() []recordedAlert {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]recordedAlert(nil), rec.events...)
}

// matching returns the recorded events whose detail contains marker.
func (rec *alertRecorder) matching(marker string) []recordedAlert {
	var out []recordedAlert
	for _, ev := range rec.get() {
		if strings.Contains(ev.detail, marker) {
			out = append(out, ev)
		}
	}
	return out
}

func withAlertRecorder(t *testing.T) *alertRecorder {
	t.Helper()
	rec := &alertRecorder{}
	alerts.SetSink(rec.sink)
	t.Cleanup(func() { alerts.SetSink(func(string, alerts.Payload) {}) })
	return rec
}

// waitForMatching polls until the recorder has at least n events whose
// detail contains marker, or the deadline passes (the clam alert fires on
// its own goroutine, mirroring remoteScanFail — Dispatch must never run
// inside ScanBody's timeout).
func (rec *alertRecorder) waitForMatching(t *testing.T, n int, marker string) []recordedAlert {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		events := rec.matching(marker)
		if len(events) >= n || time.Now().After(deadline) {
			return events
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestClamError_CountedAlertedAndCleanNotCached(t *testing.T) {
	rec := withAlertRecorder(t)
	clamErr := uniqueClamErr(t)
	clam := &fakeClam{scanErr: clamErr}
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
	events := rec.waitForMatching(t, 1, clamErr.Error())
	if len(events) != 1 || events[0].event != "scan_clam_error" {
		t.Fatalf("want one scan_clam_error alert for this invocation's error, got %v", events)
	}
	if _, ok := ss.cache.Get(hashcache.SHA256Hex(data)); ok {
		t.Fatal("verdict computed while ClamAV errored must NOT be cached (cache poisoning)")
	}
}

func TestClamError_RecoveredDaemonRescansAndBlocks(t *testing.T) {
	withAlertRecorder(t)
	clam := &fakeClam{scanErr: uniqueClamErr(t)}
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
