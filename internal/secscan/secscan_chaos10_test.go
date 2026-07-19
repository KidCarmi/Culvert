package secscan

// CHAOS-10 regression tests: a ClamAV engine ERROR mid-request stays fail-open
// (availability posture, matching the remote scanner) but must be VISIBLE
// (counter + alert) and must never poison the hash cache with a "clean"
// verdict — content that skipped AV during a daemon outage is rescanned once
// the daemon recovers.

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/alerts"
)

// flakyClam errors for the first failN calls, then reports a detection —
// simulating a ClamAV daemon that crashes mid-stream and later recovers.
type flakyClam struct {
	mu    sync.Mutex
	failN int
	calls int
}

func (f *flakyClam) Ping() error { return nil }
func (f *flakyClam) Scan([]byte) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failN {
		return "", false, errors.New("INSTREAM: connection reset by clamd")
	}
	return "EICAR-Recovered", true, nil
}

func (f *flakyClam) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestSecScanDI_ClamErrorDoesNotCacheClean(t *testing.T) {
	clam := &flakyClam{failN: 1}
	ss := newEnabledTestScanner(Deps{
		Clam: clam,
		Yara: &fakeYARA{},
		Excl: fakeExcl{},
		Feed: fakeFeed{},
	})
	data := []byte("payload scanned during a clamd outage")

	before := Counters().ClamError

	// First scan: clamd errors → fail-open (nil result), counter moves.
	if res := ss.ScanBody(data); res != nil {
		t.Fatalf("clam error must stay fail-open (nil result), got %+v", res)
	}
	if got := Counters().ClamError; got < before+1 {
		t.Fatalf("statClamError not incremented: before=%d after=%d", before, got)
	}

	// Second scan of the SAME content after the daemon recovered: the degraded
	// run must NOT have cached a clean verdict, so the engine reruns and the
	// detection lands. Pre-fix this returned the poisoned cached "clean".
	res := ss.ScanBody(data)
	if res == nil || !res.Blocked || res.Source != "clamav" || res.Reason != "EICAR-Recovered" {
		t.Fatalf("expected clamav block after recovery (clean verdict must not be cached on a degraded run), got %+v", res)
	}
	if clam.callCount() != 2 {
		t.Fatalf("engine must rerun after a degraded scan, ran %d times", clam.callCount())
	}

	// Third scan: the POSITIVE verdict from the recovered run IS cached.
	res2 := ss.ScanBody(data)
	if res2 == nil || !res2.Blocked || res2.Source != "clamav" {
		t.Fatalf("expected cached block, got %+v", res2)
	}
	if clam.callCount() != 2 {
		t.Fatalf("positive verdict must be cache-served, engine ran %d times", clam.callCount())
	}
}

func TestSecScanDI_ClamErrorStillCachesYARABlock(t *testing.T) {
	// A YARA hit is a trustworthy positive verdict regardless of the ClamAV
	// failure — it must be cached like any other block.
	clam := &flakyClam{failN: 100}
	yr := &fakeYARA{loaded: true, enabled: true, matches: []string{"rule_x"}}
	ss := newEnabledTestScanner(Deps{
		Clam: clam,
		Yara: yr,
		Excl: fakeExcl{},
		Feed: fakeFeed{},
	})
	data := []byte("yara-detectable content during clamd outage")

	res := ss.ScanBody(data)
	if res == nil || res.Source != "yara" {
		t.Fatalf("expected yara block, got %+v", res)
	}
	res2 := ss.ScanBody(data)
	if res2 == nil || !res2.Blocked || res2.Source != "yara" {
		t.Fatalf("expected cached yara block, got %+v", res2)
	}
	if yr.calls != 1 {
		t.Fatalf("yara must run once (positive verdict cached), ran %d times", yr.calls)
	}
}

func TestSecScanDI_ClamErrorFiresAlert(t *testing.T) {
	fired := make(chan alerts.Payload, 4)
	alerts.SetSink(func(event string, p alerts.Payload) {
		if event == "scan_clam_error" {
			select {
			case fired <- p:
			default:
			}
		}
	})
	t.Cleanup(func() { alerts.SetSink(func(string, alerts.Payload) {}) })

	clam := &flakyClam{failN: 100}
	ss := newEnabledTestScanner(Deps{
		Clam: clam,
		Yara: &fakeYARA{},
		Excl: fakeExcl{},
		Feed: fakeFeed{},
	})
	if res := ss.ScanBody([]byte("outage content")); res != nil {
		t.Fatalf("expected fail-open nil result, got %+v", res)
	}

	select {
	case p := <-fired:
		if p.Source != "clamav" || p.Detail == "" {
			t.Fatalf("alert payload incomplete: %+v", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scan_clam_error alert not fired within 2s of a ClamAV engine error")
	}
}
