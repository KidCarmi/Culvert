package yara

// Security regression gates for the yara_degraded producer.
//
// yaraSaturationCheck and yaraDegradedCheck run from matchRegex — once per
// STRING DEFINITION per scanned body — so they sit on the request path of an
// in-line security gateway, reachable by any client that can put scannable
// content through the proxy. Both used to build the alert Detail with
// fmt.Sprintf over the LIVE in-flight count:
//
//	Detail: fmt.Sprintf("regex skipped: inflight=%d max=%d — YARA engine saturated", inflight, limit)
//
// The alert store dedups on "event:detail" within a 30 s window
// (internal/alerts, Q17/CHAOS-27), so the number the message reports being the
// number that changes made every fire a DISTINCT key — dedup could not
// suppress the producer by construction. Neither producer was gated on
// HasSubscriber either, so in the default posture (no webhooks configured)
// every regex match under load paid a goroutine, a payload build, an RFC3339
// format and a round trip through the process-wide dedup mutex, and every
// distinct key that did reach a configured webhook landed a delivery in the
// 500-entry retry queue — where a scanner's own degradation evicts real
// threat_detected alerts (register rows WK-12/RS-5).
//
// The gates below pin the three properties that close it, plus CONTROLS: the
// cheapest way to pass "the Detail is bounded" and "no dispatch without a
// subscriber" is to stop alerting or stop checking saturation at all, which
// would be far worse than the defect.

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/alerts"
)

// degradedRecorder captures alerts.Fire events. The sink and the probe are
// process-global inside this test binary, so each helper installs and restores
// them; the producers fire on their own goroutine, so reads poll.
type degradedRecorder struct {
	mu     sync.Mutex
	events []alerts.Payload
}

func (r *degradedRecorder) sink(event string, p alerts.Payload) {
	p.Event = event
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, p)
}

func (r *degradedRecorder) all() []alerts.Payload {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]alerts.Payload(nil), r.events...)
}

func (r *degradedRecorder) details() []string {
	var out []string
	for _, p := range r.all() {
		if p.Event == "yara_degraded" {
			out = append(out, p.Detail)
		}
	}
	return out
}

// waitForDegraded polls until at least n yara_degraded details are recorded or
// the deadline passes, then returns whatever it has.
func (r *degradedRecorder) waitForDegraded(n int) []string {
	deadline := time.Now().Add(2 * time.Second)
	for {
		d := r.details()
		if len(d) >= n || time.Now().After(deadline) {
			return d
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// withDegradedHarness installs a recorder, forces the subscriber probe to the
// posture under test, and restores every global this file touches — including
// the two log rate gates, which are process-global and would otherwise let one
// test's line suppress another's.
func withDegradedHarness(t *testing.T, subscribed bool) *degradedRecorder {
	t.Helper()
	rec := &degradedRecorder{}
	alerts.SetSink(rec.sink)
	alerts.SetSubscriberProbe(func(string) bool { return subscribed })

	oldMax, oldAlert, oldPosture := GetMaxInflight(), GetAlertDegraded(), GetOnSaturation()
	oldSat, oldApp := lastYARASaturatedLog.Load(), lastYARAApproachingLog.Load()
	lastYARASaturatedLog.Store(0)
	lastYARAApproachingLog.Store(0)

	t.Cleanup(func() {
		alerts.SetSink(func(string, alerts.Payload) {})
		alerts.SetSubscriberProbe(func(string) bool { return true })
		SetMaxInflight(oldMax)
		SetAlertDegraded(oldAlert)
		SetOnSaturation(oldPosture)
		lastYARASaturatedLog.Store(oldSat)
		lastYARAApproachingLog.Store(oldApp)
	})
	SetAlertDegraded(true)
	return rec
}

// boundedDegradedReasons is the complete set a yara_degraded Detail may carry.
var boundedDegradedReasons = map[string]bool{
	yaraReasonSaturated:   true,
	yaraReasonApproaching: true,
}

// TestYARADegraded_DetailIsBoundedAcrossEveryInflightValue is the primary
// regression gate. It drives both producers across a wide range of in-flight
// values and caps — the axis the pre-fix Detail interpolated — and requires the
// number of DISTINCT dedup keys to stay at the fixed class count rather than
// growing with the number of calls.
//
// Verified failing against the reintroduced Sprintf shape: 60 calls produced 60
// distinct details.
func TestYARADegraded_DetailIsBoundedAcrossEveryInflightValue(t *testing.T) {
	rec := withDegradedHarness(t, true)

	const calls = 60
	for i := range calls {
		SetMaxInflight(int64(10 + i)) // the cap moves too, as an admin edit would
		limit := GetMaxInflight()
		yaraDegradedCheck(limit - 1)          // approaching: >= 80% of the cap
		yaraSaturationCheck(limit + int64(i)) // saturated: at or over the cap
	}

	got := rec.waitForDegraded(2 * calls)
	if len(got) < 2*calls {
		t.Fatalf("recorded %d yara_degraded alerts, want %d — the producers must still alert", len(got), 2*calls)
	}
	distinct := map[string]int{}
	for _, d := range got {
		distinct[d]++
		if !boundedDegradedReasons[d] {
			t.Fatalf("yara_degraded Detail %q is not a bounded reason class — it becomes a distinct "+
				"alert-store dedup key per request, so dedup cannot suppress a saturated engine", d)
		}
	}
	if len(distinct) > len(boundedDegradedReasons) {
		t.Fatalf("%d distinct dedup keys across %d calls, want at most %d (the class count): %v",
			len(distinct), 2*calls, len(boundedDegradedReasons), distinct)
	}
	// CONTROL: both classes must actually be reachable, or a "bounded" Detail
	// could be bounded because one of the two states stopped alerting.
	for reason := range boundedDegradedReasons {
		if distinct[reason] == 0 {
			t.Errorf("no yara_degraded alert carried reason %q — that state stopped reporting", reason)
		}
	}
}

// TestYARADegraded_DetailCarriesNoLiveCounter pins the specific shape that
// caused the defect: an interpolated number. A Detail that changes with the
// engine's state is a distinct dedup key however it is worded.
func TestYARADegraded_DetailCarriesNoLiveCounter(t *testing.T) {
	rec := withDegradedHarness(t, true)
	SetMaxInflight(50)

	yaraSaturationCheck(50)
	yaraSaturationCheck(97)
	details := rec.waitForDegraded(2)
	if len(details) < 2 {
		t.Fatalf("want two saturation alerts, got %v", details)
	}
	for _, d := range details {
		if strings.ContainsAny(d, "0123456789") {
			t.Errorf("yara_degraded Detail %q embeds a number: the magnitude belongs to the "+
				"counter and the log line, never to the dedup key", d)
		}
	}
	if details[0] != details[1] {
		t.Errorf("two saturation alerts produced different details (%q, %q): dedup cannot collapse them",
			details[0], details[1])
	}
}

// TestYARADegraded_NoSubscriberNoDispatch pins the HasSubscriber gate: the
// default posture is no webhooks, and a producer whose rate is set by a fault
// must not pay a dispatch to deliver to nobody.
func TestYARADegraded_NoSubscriberNoDispatch(t *testing.T) {
	rec := withDegradedHarness(t, false)
	SetMaxInflight(10)

	for range 20 {
		yaraSaturationCheck(10)
		yaraDegradedCheck(9)
	}
	// Give any (incorrectly spawned) goroutine time to land.
	time.Sleep(50 * time.Millisecond)
	if got := rec.details(); len(got) != 0 {
		t.Fatalf("dispatched %d yara_degraded alerts with no subscriber: %v", len(got), got)
	}
}

// TestYARADegraded_MissingProbeStillFires is the fail-SAFE half of the gate.
// alerts.HasSubscriber answers true with no probe installed, so a missing
// wire-up can never silence a real alert; a gate that defaulted the other way
// would be a silent alerting outage.
func TestYARADegraded_MissingProbeStillFires(t *testing.T) {
	rec := withDegradedHarness(t, true)
	// Clear the probe entirely: nil pointer, the pre-wiring state.
	alerts.SetSubscriberProbe(nil)
	t.Cleanup(func() { alerts.SetSubscriberProbe(func(string) bool { return true }) })
	SetMaxInflight(10)

	yaraSaturationCheck(10)
	if got := rec.waitForDegraded(1); len(got) == 0 {
		t.Fatal("no alert fired with no subscriber probe installed — the seam must fail toward delivery")
	}
}

// TestYARADegraded_AlertDegradedOffStaysSilent is the posture negative: the
// admin toggle still suppresses the alert, unchanged.
func TestYARADegraded_AlertDegradedOffStaysSilent(t *testing.T) {
	rec := withDegradedHarness(t, true)
	SetAlertDegraded(false)
	SetMaxInflight(10)

	yaraSaturationCheck(10)
	yaraDegradedCheck(9)
	time.Sleep(50 * time.Millisecond)
	if got := rec.details(); len(got) != 0 {
		t.Fatalf("alert_degraded=false must suppress the alert, got %v", got)
	}
}

// TestYARASaturation_PostureIsUnchanged is the CONTROL for every gate above:
// the cheapest way to pass them is to stop evaluating saturation, which would
// delete the in-flight cap — a far worse outcome than a noisy alert. The
// verdict matrix is pinned exactly as it was before the alerting change.
func TestYARASaturation_PostureIsUnchanged(t *testing.T) {
	withDegradedHarness(t, true)
	SetMaxInflight(10)

	for _, tc := range []struct {
		name               string
		posture            string
		inflight           int64
		wantSat, wantBlock bool
	}{
		{"below the cap is not saturated", FailClosed, 9, false, false},
		{"at the cap fails closed", FailClosed, 10, true, true},
		{"over the cap fails closed", FailClosed, 11, true, true},
		{"at the cap fails open when configured", FailOpenWithAlert, 10, true, false},
		{"below the cap is not saturated (fail-open posture)", FailOpenWithAlert, 9, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			SetOnSaturation(tc.posture)
			sat, block := yaraSaturationCheck(tc.inflight)
			if sat != tc.wantSat || block != tc.wantBlock {
				t.Fatalf("yaraSaturationCheck(%d) under %s = (%v, %v), want (%v, %v)",
					tc.inflight, tc.posture, sat, block, tc.wantSat, tc.wantBlock)
			}
		})
	}
}

// TestYARASaturation_SkipCounterIsExact pins the other half of the
// count-everything / gate-the-noise contract: the log line is now rate-limited,
// so the counter is where the magnitude lives and it must lose nothing under
// concurrency.
func TestYARASaturation_SkipCounterIsExact(t *testing.T) {
	withDegradedHarness(t, false) // no subscriber: isolate the counter from dispatch
	SetMaxInflight(4)

	before := SaturationSkips()
	const workers, each = 8, 50
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				yaraSaturationCheck(4)
			}
		}()
	}
	wg.Wait()

	if got := SaturationSkips() - before; got != workers*each {
		t.Fatalf("SaturationSkips delta = %d, want %d — a rate-limited log must not cost the magnitude",
			got, workers*each)
	}
}

// TestYARADegraded_LogIsRateLimited pins the request-path half: matchRegex runs
// per string definition per scanned body and internal/logsink BLOCKS a producer
// on a full queue, so an unbounded line here adds latency to every proxied
// response exactly while the engine is already saturated (the CHAOS-54 shape).
// The gate is on the rate-gate primitive rather than on the log sink, so it is
// deterministic on any hardware.
func TestYARADegraded_LogIsRateLimited(t *testing.T) {
	var gate atomic.Int64

	if !yaraDegradedLogAllowed(&gate) {
		t.Fatal("the first line must be allowed immediately: onset must never be suppressed")
	}
	for i := range 100 {
		if yaraDegradedLogAllowed(&gate) {
			t.Fatalf("line %d was allowed inside the %s window", i+2, yaraDegradedLogInterval)
		}
	}
	// Age the gate past its window: the next line is allowed again.
	gate.Store(time.Now().Add(-2 * yaraDegradedLogInterval).UnixNano())
	if !yaraDegradedLogAllowed(&gate) {
		t.Fatal("a line must be allowed again once the window has passed")
	}
}

// TestYARADegraded_RateGatesAreSeparate pins storage_health.go's rule that two
// failures must not share a rate gate: saturation and approaching-saturation
// point at different operator actions, and a shared gate would let the milder
// state swallow the more urgent one.
func TestYARADegraded_RateGatesAreSeparate(t *testing.T) {
	if &lastYARASaturatedLog == &lastYARAApproachingLog {
		t.Fatal("saturated and approaching-saturation share one rate gate")
	}
	var a, b atomic.Int64
	if !yaraDegradedLogAllowed(&a) || !yaraDegradedLogAllowed(&b) {
		t.Fatal("two independent gates must each allow their own first line")
	}
}
