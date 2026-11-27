package otlp

// CHAOS-130 — the push loop's OWNERSHIP, not what it does with a batch.
//
// Configure used to publish the new endpoint and the new loop's cancel under
// TWO separate holds of the mutex. Two concurrent callers therefore overwrote
// each other's cancel and the loser's push loop became UNREACHABLE: no Stop()
// could ever cancel it, because the only handle to it was gone. The gates
// below are the reproductions, kept as regressions.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// livePushLoops counts goroutines currently inside the named push loop.
func livePushLoops(t *testing.T, frag string) int {
	t.Helper()
	buf := make([]byte, 1<<16)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Count(string(buf[:n]), frag)
		}
		buf = make([]byte, 2*len(buf))
	}
}

// settleLoops waits for the goroutine count to reach want, so a cancelled
// loop that has not been scheduled yet is not read as a leak.
func settleLoops(t *testing.T, frag string, base, want int) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	got := livePushLoops(t, frag) - base
	for got != want && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
		got = livePushLoops(t, frag) - base
	}
	return got
}

const spanLoopFrag = "otlp.(*SpanExporter).pushLoop"
const metricsLoopFrag = "otlp.(*MetricsExporter).pushLoop"

func okCollector(t *testing.T, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// Reproduction: 8 concurrent Configure calls left 3 live span push loops, and
// 2 of them survived Stop() for the life of the process.
func TestChaos130_ConcurrentConfigureLeavesOneSpanPushLoop(t *testing.T) {
	ts := okCollector(t, nil)
	// The window is narrow, so a single round is a weak oracle: on the
	// two-phase code one round leaks only sometimes. Rounds are cheap (the
	// interval is an hour — the race is under test, not the ticking) and the
	// invariant is per-round, so a leak anywhere fails the gate.
	const rounds = 60
	for round := 0; round < rounds; round++ {
		e := NewSpans()
		e.client = ts.Client()
		e.interval = time.Hour
		base := livePushLoops(t, spanLoopFrag)

		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); e.Configure(ts.URL, nil) }()
		}
		wg.Wait()

		if got := settleLoops(t, spanLoopFrag, base, 1); got != 1 {
			t.Fatalf("round %d: after 8 concurrent Configure, %d live push loop(s); want exactly 1 — a loop nobody holds the cancel for can never be stopped", round, got)
		}
		e.Stop()
		if got := settleLoops(t, spanLoopFrag, base, 0); got != 0 {
			t.Fatalf("round %d: after Stop(), %d live push loop(s); want 0 — the operator's disable must reclaim every loop", round, got)
		}
	}
}

// The same for the metrics exporter, whose leak is the one with a bill
// attached: push() always POSTs a cumulative snapshot.
func TestChaos130_ConcurrentConfigureLeavesOneMetricsPushLoop(t *testing.T) {
	ts := okCollector(t, nil)
	const rounds = 60
	for round := 0; round < rounds; round++ {
		o := NewMetrics(func(now string) []Metric { return []Metric{{Name: "culvert_test"}} })
		o.client = ts.Client()
		o.interval = time.Hour
		base := livePushLoops(t, metricsLoopFrag)

		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); o.Configure(ts.URL, nil) }()
		}
		wg.Wait()

		if got := settleLoops(t, metricsLoopFrag, base, 1); got != 1 {
			t.Fatalf("round %d: after 8 concurrent Configure, %d live push loop(s); want exactly 1", round, got)
		}
		o.Stop()
		if got := settleLoops(t, metricsLoopFrag, base, 0); got != 0 {
			t.Fatalf("round %d: after Stop(), %d live push loop(s); want 0", round, got)
		}
	}
}

// Reproduction: 40 raced saves at the production 15 s cadence left 9 live
// loops, 8 of which survived Stop(). The leak grew with operator activity and
// nothing but a restart cleared it.
func TestChaos130_RacedSavesDoNotAccumulateLoops(t *testing.T) {
	ts := okCollector(t, nil)
	o := NewMetrics(func(now string) []Metric { return []Metric{{Name: "culvert_test"}} })
	o.client = ts.Client()
	o.interval = 15 * time.Second // production cadence: no ticks during the race

	base := livePushLoops(t, metricsLoopFrag)
	for round := 0; round < 40; round++ {
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); o.Configure(ts.URL, nil) }()
		}
		wg.Wait()
	}
	if got := settleLoops(t, metricsLoopFrag, base, 1); got != 1 {
		t.Errorf("after 40 raced saves: %d live push loop(s); want exactly 1", got)
	}
	o.Stop()
	if got := settleLoops(t, metricsLoopFrag, base, 0); got != 0 {
		t.Errorf("after Stop(): %d live push loop(s); want 0 — every leaked loop keeps pushing at the interval it started with, forever", got)
	}
}

// The operational bill: a leaked loop multiplies the collector's request rate,
// and the multiplication used to survive a disable and re-enable. Measured
// before the fix: 10 POSTs over ~5 intervals where the operator configured 5.
func TestChaos130_RacedSavesDoNotAmplifyCollectorLoad(t *testing.T) {
	var posts atomic.Int64
	ts := okCollector(t, &posts)
	o := NewMetrics(func(now string) []Metric { return []Metric{{Name: "culvert_test"}} })
	o.client = ts.Client()
	o.interval = 20 * time.Millisecond

	// Race enough rounds that a leak is near-certain on the two-phase code
	// (one round leaks only sometimes), then measure what the collector gets.
	for round := 0; round < 40; round++ {
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); o.Configure(ts.URL, nil) }()
		}
		wg.Wait()
	}
	// A clean disable/re-enable: pre-fix this did NOT clear the amplification,
	// because Stop() can only reach the one cancel it still holds.
	o.Stop()
	o.Configure(ts.URL, nil)
	t.Cleanup(o.Stop)

	posts.Store(0)
	const intervals = 10
	time.Sleep(intervals * 20 * time.Millisecond)
	got := posts.Load()
	// One loop at a 20 ms cadence yields ~10 POSTs in 10 intervals. Two yield
	// ~20. The bound admits scheduling slop but not a doubling.
	if got > intervals+intervals/2 {
		t.Errorf("collector received %d POST(s) over ~%d intervals; one push loop cannot exceed ~%d — a leaked loop is still pushing", got, intervals, intervals)
	}
}

// Reproduction: 5 of 200 Stop()/Configure() races ended with Enabled()
// reporting false while a push loop was still running behind it.
func TestChaos130_StopAndConfigureAreExclusive(t *testing.T) {
	ts := okCollector(t, nil)
	for attempt := 0; attempt < 600; attempt++ {
		e := NewSpans()
		e.client = ts.Client()
		e.interval = time.Hour // the race, not the ticking, is under test

		base := livePushLoops(t, spanLoopFrag)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); e.Configure(ts.URL, nil) }()
		go func() { defer wg.Done(); e.Stop() }()
		wg.Wait()

		enabled := e.Enabled()
		want := 0
		if enabled {
			want = 1
		}
		if got := settleLoops(t, spanLoopFrag, base, want); got != want {
			t.Fatalf("attempt %d: Enabled() = %v with %d live push loop(s); want %d — the two reports must agree",
				attempt, enabled, got, want)
		}
		// The same invariant stated on the handle rather than on the
		// scheduler: a disabled exporter owns no loop, so it holds no cancel.
		e.mu.Lock()
		heldCancel := e.cancel != nil
		e.mu.Unlock()
		if heldCancel != enabled {
			t.Fatalf("attempt %d: Enabled() = %v but a stored cancel handle = %v — Stop() and Configure() must not interleave",
				attempt, enabled, heldCancel)
		}
		e.Stop()
		if got := settleLoops(t, spanLoopFrag, base, 0); got != 0 {
			t.Fatalf("attempt %d: %d live push loop(s) survived the final Stop()", attempt, got)
		}
	}
}

// Disabling must leave no handle behind at all: the two-phase version returned
// with an already-cancelled cancel still stored.
func TestChaos130_DisableLeavesNoLoopAndNoStaleCancel(t *testing.T) {
	ts := okCollector(t, nil)
	e := NewSpans()
	e.client = ts.Client()
	e.interval = 20 * time.Millisecond
	base := livePushLoops(t, spanLoopFrag)

	e.Configure(ts.URL, nil)
	if got := settleLoops(t, spanLoopFrag, base, 1); got != 1 {
		t.Fatalf("enable: %d live push loop(s); want 1", got)
	}
	e.Configure("", nil)
	if got := settleLoops(t, spanLoopFrag, base, 0); got != 0 {
		t.Errorf("Configure(\"\"): %d live push loop(s); want 0", got)
	}
	e.mu.Lock()
	cancel := e.cancel
	e.mu.Unlock()
	if cancel != nil {
		t.Error("Configure(\"\") left a cancel handle stored; a disabled exporter owns no loop and must hold no handle to one")
	}
	if e.Enabled() {
		t.Error("Enabled() = true after Configure(\"\")")
	}
}

// Endpoint() is what lets the CP snapshot apply reconcile the traces exporter
// from its OWN state instead of the metrics exporter's (CHAOS-130).
func TestChaos130_SpanExporterReportsItsEndpoint(t *testing.T) {
	ts := okCollector(t, nil)
	e := NewSpans()
	e.client = ts.Client()
	e.interval = time.Hour

	if got := e.Endpoint(); got != "" {
		t.Errorf("Endpoint() = %q before Configure; want empty", got)
	}
	e.Configure(ts.URL+"/", nil)
	t.Cleanup(e.Stop)
	if got := e.Endpoint(); got != ts.URL {
		t.Errorf("Endpoint() = %q; want the normalised %q", got, ts.URL)
	}
	e.Stop()
	if got := e.Endpoint(); got != "" {
		t.Errorf("Endpoint() = %q after Stop(); want empty", got)
	}
}

// The transition must stay atomic under the race detector with recording,
// pushing and reconfiguring all live at once — and must still deliver.
func TestChaos130_ConfigureUnderConcurrentLoadStillDelivers(t *testing.T) {
	var delivered atomic.Int64
	ts := okCollector(t, &delivered)
	e := NewSpans()
	e.client = ts.Client()
	e.interval = 5 * time.Millisecond
	base := livePushLoops(t, spanLoopFrag)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			if e.Enabled() {
				e.RecordSpan(SpanRecord{TraceID: "t", SpanID: "s", Name: "proxy_request"})
			}
			time.Sleep(time.Millisecond)
		}
	}()
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			e.Configure(ts.URL, nil)
			time.Sleep(3 * time.Millisecond)
		}
	}()
	time.Sleep(150 * time.Millisecond)
	cancel()
	wg.Wait()

	e.Stop()
	if got := settleLoops(t, spanLoopFrag, base, 0); got != 0 {
		t.Errorf("%d live push loop(s) survived Stop() after a reconfigure storm; want 0", got)
	}
	if delivered.Load() == 0 {
		t.Error("the collector received nothing across the storm; the exporter must still export while being reconfigured")
	}
}
