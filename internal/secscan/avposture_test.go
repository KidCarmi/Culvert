package secscan

// av_unavailable posture gates. The defect these pin: an AV engine FAULT
// (ClamAV stopped, crashed, restarting, unreachable; a sidecar that is down or
// answers without a verdict) forwarded the body UNSCANNED with no way for an
// operator to require refusal. The closed posture must refuse in both back
// ends, never cache the refusal, recover the instant the engine answers, and
// leave the budget path (already fail-closed) exactly as it was. The open
// posture must stay byte-identical to the historical behaviour — that is what
// the CONTROL gates below are for, because the cheapest way to pass every
// closed-posture gate is to refuse everything always.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/hashcache"
)

// withAVPosture installs a posture for one test and restores open after.
func withAVPosture(t *testing.T, p string) {
	t.Helper()
	if err := SetAVUnavailablePosture(p); err != nil {
		t.Fatalf("SetAVUnavailablePosture(%q): %v", p, err)
	}
	lastAVRefusalLog.Store(0)
	t.Cleanup(func() {
		_ = SetAVUnavailablePosture(AVUnavailableOpen)
		lastAVRefusalLog.Store(0)
	})
}

func TestAVUnavailable_NormalizeAndSet(t *testing.T) {
	withAVPosture(t, AVUnavailableOpen)
	cases := []struct{ in, want string }{{"open", "open"}, {"CLOSED", "closed"}, {" closed ", "closed"}, {"Open\n", "open"}}
	for _, tc := range cases {
		got, ok := NormalizeAVUnavailable(tc.in)
		if !ok || got != tc.want {
			t.Errorf("NormalizeAVUnavailable(%q) = %q,%v want %q,true", tc.in, got, ok, tc.want)
		}
	}
	for _, bad := range []string{"", "fail_closed", "deny", "true", "clos ed"} {
		if _, ok := NormalizeAVUnavailable(bad); ok {
			t.Errorf("NormalizeAVUnavailable(%q) accepted junk", bad)
		}
		if err := SetAVUnavailablePosture(bad); err == nil {
			t.Errorf("SetAVUnavailablePosture(%q) accepted junk", bad)
		}
		if got := AVUnavailablePosture(); got != AVUnavailableOpen {
			t.Fatalf("a refused value changed the live posture to %q", got)
		}
	}
	if err := SetAVUnavailablePosture("closed"); err != nil || AVUnavailablePosture() != AVUnavailableClosed {
		t.Fatalf("closed not installed: err=%v posture=%q", err, AVUnavailablePosture())
	}
}

// TestAVUnavailableClosed_ClamFaultRefusesAndIsNotCached is the headline gate:
// a genuine ClamAV fault under the closed posture refuses the body with the
// av_unavailable source, does not run YARA as a substitute verdict, and does
// not poison the cache — the same object is judged on its merits the moment
// the daemon answers.
func TestAVUnavailableClosed_ClamFaultRefusesAndIsNotCached(t *testing.T) {
	withAlertRecorder(t)
	withAVPosture(t, AVUnavailableClosed)
	clam := &fakeClam{scanErr: uniqueClamErr(t)}
	yara := &fakeYARA{loaded: true, enabled: true}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: yara, Excl: fakeExcl{}, Feed: fakeFeed{}})
	data := []byte("content arriving while clamd is stopped")
	hash := hashcache.SHA256Hex(data)

	refusedBefore := AVUnavailableRefusedTotal()
	errBefore := atomic.LoadInt64(&statClamScanError)
	res := ss.ScanBody(data)
	if res == nil || !res.Blocked || res.Source != SourceAVUnavailable || res.Reason != AVUnavailableReason {
		t.Fatalf("closed posture must refuse an unscannable body, got %+v", res)
	}
	if res.Hash != hash {
		t.Fatalf("refusal must carry the content hash, got %q", res.Hash)
	}
	if got := AVUnavailableRefusedTotal() - refusedBefore; got != 1 {
		t.Fatalf("av_unavailable refusal counter moved by %d, want 1", got)
	}
	if got := atomic.LoadInt64(&statClamScanError) - errBefore; got != 1 {
		t.Fatalf("the fault itself must still be counted (ClamScanError moved by %d)", got)
	}
	if yara.calls != 0 {
		t.Fatalf("the refusal must not fall through to YARA (ran %d times)", yara.calls)
	}
	if _, ok := ss.cache.Get(hash); ok {
		t.Fatal("an infrastructure refusal must NEVER be cached")
	}

	// Recovery: the daemon comes back and the content is clean.
	clam.scanErr = nil
	if res := ss.ScanBody(data); res != nil {
		t.Fatalf("recovered daemon + clean content must pass, got %+v", res)
	}
	if clam.calls != 2 {
		t.Fatalf("engine must be consulted again after the refusal (calls=%d)", clam.calls)
	}
	if c, ok := ss.cache.Get(hash); !ok || !c.Clean {
		t.Fatalf("a real clean verdict must cache as before, got %+v ok=%v", c, ok)
	}
}

// TestAVUnavailableClosed_RecoveredDaemonDetects: recovery is a real verdict,
// not a reopened gate — a FOUND after the outage blocks as clamav.
func TestAVUnavailableClosed_RecoveredDaemonDetects(t *testing.T) {
	withAlertRecorder(t)
	withAVPosture(t, AVUnavailableClosed)
	clam := &fakeClam{scanErr: uniqueClamErr(t)}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	data := []byte("EICAR-ish while down")
	if res := ss.ScanBody(data); res == nil || res.Source != SourceAVUnavailable {
		t.Fatalf("down: want av_unavailable refusal, got %+v", res)
	}
	clam.scanErr, clam.name, clam.found = nil, "Eicar-Test-Signature", true
	res := ss.ScanBody(data)
	if res == nil || res.Source != "clamav" || res.Reason != "Eicar-Test-Signature" {
		t.Fatalf("recovered daemon must block the threat as clamav, got %+v", res)
	}
}

// TestAVUnavailableOpen_ClamFaultUnchanged is the CONTROL: the default posture
// is the historical fail-open behaviour, byte for byte.
func TestAVUnavailableOpen_ClamFaultUnchanged(t *testing.T) {
	withAlertRecorder(t)
	withAVPosture(t, AVUnavailableOpen)
	clam := &fakeClam{scanErr: uniqueClamErr(t)}
	yara := &fakeYARA{loaded: true, enabled: true}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: yara, Excl: fakeExcl{}, Feed: fakeFeed{}})
	data := []byte("content forwarded while clamd is down (open)")

	refusedBefore := AVUnavailableRefusedTotal()
	if res := ss.ScanBody(data); res != nil {
		t.Fatalf("open posture must stay fail-open (WK-1b), got %+v", res)
	}
	if yara.calls != 1 {
		t.Fatalf("open posture still falls through to YARA (ran %d)", yara.calls)
	}
	if got := AVUnavailableRefusedTotal() - refusedBefore; got != 0 {
		t.Fatalf("open posture must not count refusals (moved by %d)", got)
	}
	if _, ok := ss.cache.Get(hashcache.SHA256Hex(data)); ok {
		t.Fatal("a verdict computed while ClamAV errored must not be cached")
	}
}

// TestAVUnavailable_BudgetPathUnchangedInBothPostures: a scan that runs out of
// budget is the fail-closed timeout path in BOTH postures — never relabelled
// av_unavailable, never counted as one.
func TestAVUnavailable_BudgetPathUnchangedInBothPostures(t *testing.T) {
	for _, posture := range []string{AVUnavailableOpen, AVUnavailableClosed} {
		t.Run(posture, func(t *testing.T) {
			withAVPosture(t, posture)
			withScanBudget(t, 40*time.Millisecond)
			withCooldown(t, 10*time.Second)
			ss := newSlowScanner(t, &ctxGatedClam{}, time.Hour)
			refusedBefore := AVUnavailableRefusedTotal()
			timeoutBefore := atomic.LoadInt64(&statScanTimeout)
			res := ss.ScanBody([]byte("budget path " + posture))
			if res == nil || !res.Blocked || res.Source != "timeout" {
				t.Fatalf("budget exhaustion must stay the timeout refusal, got %+v", res)
			}
			if got := atomic.LoadInt64(&statScanTimeout) - timeoutBefore; got != 1 {
				t.Fatalf("scan timeout moved by %d, want 1", got)
			}
			if got := AVUnavailableRefusedTotal() - refusedBefore; got != 0 {
				t.Fatalf("a budget refusal is not an av_unavailable refusal (moved by %d)", got)
			}
		})
	}
}

// TestAVUnavailable_NoClamConfiguredIsNotAnOutage: a node without ClamAV has
// no AV leg to be unavailable; closed must not refuse YARA-only scanning.
func TestAVUnavailable_NoClamConfiguredIsNotAnOutage(t *testing.T) {
	withAVPosture(t, AVUnavailableClosed)
	ss := newEnabledTestScanner(Deps{Yara: &fakeYARA{loaded: true, enabled: true}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	if res := ss.ScanBody([]byte("yara only")); res != nil {
		t.Fatalf("no ClamAV configured must not read as ClamAV unavailable, got %+v", res)
	}
}

// TestAVUnavailable_FaultMarksClamStatusStale: readiness truth. A cached
// "connected" must not survive a request-path daemon fault for the rest of the
// status TTL — the next status read re-pings.
func TestAVUnavailable_FaultMarksClamStatusStale(t *testing.T) {
	withAlertRecorder(t)
	clam := &fakeClam{}
	ss := newEnabledTestScanner(Deps{Clam: clam, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	if st := ss.ClamAVStatus(); st != "connected" {
		t.Fatalf("healthy daemon: status %q", st)
	}
	// CONTROL: with no request-path fault, the cache keeps answering even
	// though the daemon just died (the 30 s TTL behaviour this gate narrows).
	clam.pingErr = uniqueClamErr(t)
	if st := ss.ClamAVStatus(); st != "connected" {
		t.Fatalf("without a request-path fault the cached status must be served, got %q", st)
	}
	// A scan observes the fault → the cached status is no longer trusted.
	clam.scanErr = clam.pingErr
	_ = ss.ScanBody([]byte("scan that observes the outage"))
	if st := ss.ClamAVStatus(); st == "connected" {
		t.Fatal("status still reports connected after the request path saw the daemon fault")
	}
	// And it recovers on evidence: a healthy ping clears it.
	clam.pingErr, clam.scanErr = nil, nil
	ss.clamStatusExpiry = time.Time{} // let the unreachable entry age out
	if st := ss.ClamAVStatus(); st != "connected" {
		t.Fatalf("recovered daemon must report connected, got %q", st)
	}
}

// ── Remote sidecar: ONE posture for both back ends ──────────────────────────

func TestAVUnavailableClosed_SidecarFaultRefuses(t *testing.T) {
	resetRemoteLogGates(t)
	captureAlerts(t)
	withAVPosture(t, AVUnavailableClosed)
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // stopped sidecar

	rs := newRemoteAt(t, url)
	before := Counters()
	res := rs.ScanBody([]byte("payload for a stopped sidecar"), "")
	after := Counters()
	if res == nil || !res.Blocked || res.Source != SourceAVUnavailable {
		t.Fatalf("closed posture must refuse when the sidecar is down, got %+v", res)
	}
	if res.Hash != hashcache.SHA256Hex([]byte("payload for a stopped sidecar")) {
		t.Fatalf("refusal must carry the locally computed hash, got %q", res.Hash)
	}
	if d := after.AVUnavailableRefused - before.AVUnavailableRefused; d != 1 {
		t.Fatalf("refusal counter moved by %d, want 1", d)
	}
	if d := after.RemoteScanFail - before.RemoteScanFail; d != 0 {
		t.Fatalf("the fail-OPEN counter must not move under closed (moved by %d)", d)
	}
	if d := after.ScanTimeout - before.ScanTimeout; d != 0 {
		t.Fatalf("a fault is not a budget refusal (scan timeout moved by %d)", d)
	}
}

func TestAVUnavailableClosed_SidecarNoVerdictRefuses(t *testing.T) {
	resetRemoteLogGates(t)
	rec := captureAlerts(t)
	withAVPosture(t, AVUnavailableClosed)
	srv := jsonSidecar(t, ScanResponse{}) // 200 with neither clean nor blocked
	rs := newRemoteAt(t, srv.URL)
	res := rs.ScanBody([]byte("nonsense sidecar"), "")
	if res == nil || res.Source != SourceAVUnavailable {
		t.Fatalf("a sidecar answering without a verdict must be refused under closed, got %+v", res)
	}
	// The fault is still alerted under closed — only the content's fate differs.
	rec.waitFor(t, remoteFaultNoVerdict)
}

// TestAVUnavailableOpen_SidecarFaultUnchanged is the remote CONTROL.
func TestAVUnavailableOpen_SidecarFaultUnchanged(t *testing.T) {
	resetRemoteLogGates(t)
	captureAlerts(t)
	withAVPosture(t, AVUnavailableOpen)
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	rs := newRemoteAt(t, url)
	before := Counters()
	if res := rs.ScanBody([]byte("open posture sidecar down"), ""); res != nil {
		t.Fatalf("open posture must stay fail-open (WK-2b), got %+v", res)
	}
	after := Counters()
	if d := after.RemoteScanFail - before.RemoteScanFail; d != 1 {
		t.Fatalf("fail-open counter moved by %d, want 1", d)
	}
	if d := after.AVUnavailableRefused - before.AVUnavailableRefused; d != 0 {
		t.Fatalf("open posture must not count refusals (moved by %d)", d)
	}
}

// TestAVUnavailableClosed_SidecarVerdictsStillHonoured: closed changes only the
// fault branch — a clean verdict is clean, a slow sidecar is still the timeout
// refusal.
func TestAVUnavailableClosed_SidecarVerdictsStillHonoured(t *testing.T) {
	resetRemoteLogGates(t)
	withAVPosture(t, AVUnavailableClosed)
	clean := newRemoteAt(t, jsonSidecar(t, ScanResponse{Clean: true}).URL)
	if res := clean.ScanBody([]byte("clean via sidecar"), ""); res != nil {
		t.Fatalf("an affirmative clean must pass under closed, got %+v", res)
	}
	withScanBudget(t, 100*time.Millisecond)
	slow := newRemoteAt(t, sidecar(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}).URL)
	if res := slow.ScanBody([]byte("slow via sidecar"), ""); res == nil || res.Source != "timeout" {
		t.Fatalf("budget exhaustion must stay the timeout refusal under closed, got %+v", res)
	}
}

// pastDeadlineCtx is a context whose deadline has passed but whose timer has
// not fired yet — the instant at which a ClamAV connection deadline (armed AT
// the budget deadline) has already surfaced an i/o timeout while ctx.Err() is
// still nil. It cannot be produced reliably with a real context, which is why
// the race only showed up under full-suite load.
type pastDeadlineCtx struct{ context.Context }

func (pastDeadlineCtx) Deadline() (time.Time, bool) { return time.Now().Add(-time.Millisecond), true }
func (pastDeadlineCtx) Err() error                  { return nil }

// TestAVUnavailable_BudgetOverrunIsNeverRelabelledAsFault pins the boundary:
// an engine error observed once the budget is spent is the TIMEOUT refusal in
// both postures, never av_unavailable (closed) and never a clean pass (open).
func TestAVUnavailable_BudgetOverrunIsNeverRelabelledAsFault(t *testing.T) {
	if !budgetExhausted(pastDeadlineCtx{context.Background()}) {
		t.Fatal("a passed deadline must count as an exhausted budget even before ctx.Err() is set")
	}
	if budgetExhausted(context.Background()) {
		t.Fatal("a context without a deadline is never exhausted")
	}
	for _, posture := range []string{AVUnavailableOpen, AVUnavailableClosed} {
		t.Run(posture, func(t *testing.T) {
			withAlertRecorder(t)
			withAVPosture(t, posture)
			clam := &fakeClam{scanErr: errors.New("clamav: read response: read tcp: i/o timeout")}
			ss := newEnabledTestScanner(Deps{Clam: clam, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
			refusedBefore := AVUnavailableRefusedTotal()
			res := ss.scanBodyInner(pastDeadlineCtx{context.Background()}, []byte("x"), "h", nil)
			if res == nil || res.Source != "timeout" {
				t.Fatalf("budget overrun must be the timeout refusal, got %+v", res)
			}
			if d := AVUnavailableRefusedTotal() - refusedBefore; d != 0 {
				t.Fatalf("a budget overrun was counted as an av_unavailable refusal (%d)", d)
			}
		})
	}
}
