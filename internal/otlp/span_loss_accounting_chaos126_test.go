package otlp

// CHAOS-126 — the span buffer's loss accounting.
//
// Every gate here failed before the round. The behaviour they pin is one
// property stated four ways: a span leaves this exporter either DELIVERED or
// COUNTED, never silently. Before the fix `push` drained the ring as its
// first statement and discarded the batch on any error, so a collector that
// was down destroyed every span it was handed while `droppedSpans` — whose
// comment named that exact scenario — stayed at 0, and the buffer could
// never fill, which made the documented "prevents OOM when the collector is
// down" cap unreachable. Control run on the pre-fix tree: 2000 spans
// recorded against a 502 collector → 0 delivered, 0 buffered, 0 dropped.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// failingCollector serves `code` and counts requests. A nil body is returned
// so the exporter's resp.Body.Close() has something real to close.
func failingCollector(t *testing.T, code int, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(code)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// spanCountingCollector accepts batches and records how many spans each
// carried, so a test can prove the SAME spans arrived later rather than
// merely that some request was made.
func spanCountingCollector(t *testing.T, delivered *atomic.Int64, batches *atomic.Int64) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload traceExportRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("collector could not decode the batch: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		n := 0
		for _, rs := range payload.ResourceSpans {
			for _, ss := range rs.ScopeSpans {
				n += len(ss.Spans)
			}
		}
		delivered.Add(int64(n))
		batches.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func testExporter(endpoint string, client *http.Client) *SpanExporter {
	return &SpanExporter{
		endpoint: endpoint,
		interval: time.Hour, // the tests drive push() directly
		client:   client,
		buf:      make([]SpanRecord, spanBufferCap),
	}
}

func recordN(e *SpanExporter, n int) {
	for i := 0; i < n; i++ {
		e.RecordSpan(SpanRecord{
			TraceID: "0af7651916cd43dd8448eb211c80319c", SpanID: "b7ad6b7169203331",
			Name: "proxy_request", Method: "GET", Host: "example.com",
			Status: "OK", StartNano: int64(i), EndNano: int64(i) + 1,
		})
	}
}

// endpointOf reads the stored (normalised) endpoint. A test helper rather
// than a method: the span exporter deliberately has no public Endpoint()
// accessor — the CP snapshot's change detection reads the METRICS
// exporter's, and adding a second public surface here is not this round's
// business.
func endpointOf(e *SpanExporter) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.endpoint
}

func buffered(e *SpanExporter) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.count
}

// ── The headline gate ───────────────────────────────────────────────────────

// A collector that is down must not cost spans. The batch is retained and
// delivered when the collector returns — the round's whole point, since a
// span is a one-shot record with nothing to re-derive it from.
func TestChaos126_CollectorOutageRetainsSpansAndDeliversOnRecovery(t *testing.T) {
	var failHits atomic.Int64
	down := failingCollector(t, http.StatusServiceUnavailable, &failHits)
	e := testExporter(down.URL, down.Client())

	recordN(e, 7)
	if err := e.push(context.Background()); err == nil {
		t.Fatal("push against a 503 collector must report the failure")
	}
	if got := buffered(e); got != 7 {
		t.Fatalf("after a failed push the buffer holds %d span(s); want 7 retained", got)
	}
	if got := e.Health().DroppedSpans; got != 0 {
		t.Errorf("DroppedSpans = %d after a retryable failure; want 0 — nothing was lost yet", got)
	}
	if got := e.Health().FailureCount; got != 1 {
		t.Errorf("FailureCount = %d; want 1", got)
	}

	// The collector comes back. The spans recorded during the outage must
	// arrive — all seven, in one batch.
	var delivered, batches atomic.Int64
	up := spanCountingCollector(t, &delivered, &batches)
	e.mu.Lock()
	e.endpoint = up.URL
	e.client = up.Client()
	e.mu.Unlock()

	if err := e.push(context.Background()); err != nil {
		t.Fatalf("recovery push: %v", err)
	}
	if got := delivered.Load(); got != 7 {
		t.Fatalf("collector received %d span(s) after recovery; want 7", got)
	}
	if got := buffered(e); got != 0 {
		t.Errorf("a DELIVERED batch must clear the buffer; %d span(s) left", got)
	}
	if got := e.Health().DroppedSpans; got != 0 {
		t.Errorf("DroppedSpans = %d; want 0 — every span was delivered", got)
	}
}

// Negative control for the gate above: a healthy push must still empty the
// buffer. A "retain everything" regression would pass the outage gate and
// re-deliver the same spans forever.
func TestChaos126_HealthyPushClearsTheBuffer(t *testing.T) {
	var delivered, batches atomic.Int64
	up := spanCountingCollector(t, &delivered, &batches)
	e := testExporter(up.URL, up.Client())

	recordN(e, 4)
	if err := e.push(context.Background()); err != nil {
		t.Fatalf("push: %v", err)
	}
	if got := buffered(e); got != 0 {
		t.Fatalf("buffer holds %d span(s) after a successful push; want 0", got)
	}
	// A second push must POST nothing at all.
	if err := e.push(context.Background()); err != nil {
		t.Fatalf("second push: %v", err)
	}
	if got := batches.Load(); got != 1 {
		t.Errorf("collector saw %d batches; want 1 — an empty buffer must not POST", got)
	}
	if got := delivered.Load(); got != 4 {
		t.Errorf("collector received %d span(s); want 4 exactly once", got)
	}
}

// ── What retention must NOT do ──────────────────────────────────────────────

// A 4xx is the collector rejecting THIS batch. Re-posting the identical
// bytes cannot change that answer, so the batch is dropped — and counted,
// which is the part that distinguishes a decision from a leak.
func TestChaos126_PermanentRejectionIsDroppedAndCounted(t *testing.T) {
	for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized,
		http.StatusForbidden, http.StatusNotFound, http.StatusRequestEntityTooLarge} {
		var hits atomic.Int64
		ts := failingCollector(t, code, &hits)
		e := testExporter(ts.URL, ts.Client())
		recordN(e, 5)
		if err := e.push(context.Background()); err == nil {
			t.Fatalf("status %d: push must report the failure", code)
		}
		if got := buffered(e); got != 0 {
			t.Errorf("status %d: %d span(s) retained; a rejected batch must not hold the ring", code, got)
		}
		if got := e.Health().DroppedSpans; got != 5 {
			t.Errorf("status %d: DroppedSpans = %d; want 5 — the loss must be counted", code, got)
		}
	}
}

// The retryable set is pinned so a future edit cannot quietly move a code
// from "retain" to "drop" (silent loss) or the reverse (a buffer pinned full
// of data the collector will never accept).
func TestChaos126_RetryableStatusSet(t *testing.T) {
	retain := []int{http.StatusRequestTimeout, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout, 599}
	drop := []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
		http.StatusNotFound, http.StatusRequestEntityTooLarge, http.StatusTeapot, 499}
	for _, c := range retain {
		if !retryableCollectorStatus(c) {
			t.Errorf("status %d must be retained: the condition can change on its own", c)
		}
	}
	for _, c := range drop {
		if retryableCollectorStatus(c) {
			t.Errorf("status %d must NOT be retained: re-posting the same bytes cannot change it", c)
		}
	}
}

// Retention is bounded. A collector that never comes back costs 4096 spans
// of memory and counts the overflow — which is what spanBufferCap and
// droppedSpans were documented to do and could not, because the ring was
// emptied on every tick whatever the outcome.
func TestChaos126_RetentionIsBoundedAndOverflowIsCounted(t *testing.T) {
	var hits atomic.Int64
	down := failingCollector(t, http.StatusBadGateway, &hits)
	e := testExporter(down.URL, down.Client())

	recordN(e, spanBufferCap)
	if err := e.push(context.Background()); err == nil {
		t.Fatal("push against a 502 collector must report the failure")
	}
	if got := buffered(e); got != spanBufferCap {
		t.Fatalf("buffer holds %d span(s); want the full %d retained", got, spanBufferCap)
	}
	if got := e.Health().DroppedSpans; got != 0 {
		t.Fatalf("DroppedSpans = %d; the retained batch exactly fits, nothing is lost yet", got)
	}

	// Traffic continues while the collector stays down: the ring is full, so
	// each new span evicts the oldest, and each eviction is counted.
	const extra = 300
	recordN(e, extra)
	if got := buffered(e); got != spanBufferCap {
		t.Errorf("buffer holds %d span(s); the cap must bound it at %d", got, spanBufferCap)
	}
	if got := e.Health().DroppedSpans; got != extra {
		t.Errorf("DroppedSpans = %d; want %d — every evicted span is a lost span", got, extra)
	}

	// And the next failed push must not double-count what it retains.
	if err := e.push(context.Background()); err == nil {
		t.Fatal("second push against the down collector must report the failure")
	}
	if got := e.Health().DroppedSpans; got != extra {
		t.Errorf("DroppedSpans = %d after re-retaining a full ring; want %d — retention is not a loss", got, extra)
	}
	if got := buffered(e); got != spanBufferCap {
		t.Errorf("buffer holds %d span(s) after re-retention; want %d", got, spanBufferCap)
	}
}

// The overflow arm of RETENTION itself — spans recorded while the failing
// push was in flight do not fit beside the batch coming back, and what no
// longer fits is lost and must be counted. Added after a mutation run: the
// eviction gate below it only exercises RecordSpan's overflow, so removing
// the count from requeue's arm was caught by nothing.
func TestChaos126_RequeueOverflowDuringAnInFlightPushIsCounted(t *testing.T) {
	const concurrent = 50
	var e *SpanExporter
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Traffic keeps arriving while the collector is deciding.
		for i := 0; i < concurrent; i++ {
			e.RecordSpan(SpanRecord{Name: "proxy_request", StartNano: int64(1_000_000 + i)})
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(ts.Close)
	e = testExporter(ts.URL, ts.Client())

	recordN(e, spanBufferCap) // StartNano 0 … cap-1
	if err := e.push(context.Background()); err == nil {
		t.Fatal("expected a push failure")
	}
	if got := buffered(e); got != spanBufferCap {
		t.Errorf("buffer holds %d span(s); the cap must still bound it at %d", got, spanBufferCap)
	}
	if got := e.Health().DroppedSpans; got != concurrent {
		t.Errorf("DroppedSpans = %d; want %d — the spans that no longer fit are lost spans", got, concurrent)
	}
	// Ring semantics: the OLDEST lost, so the retained window starts at
	// StartNano == concurrent and ends with the in-flight arrivals.
	held := e.drain()
	if len(held) != spanBufferCap {
		t.Fatalf("drained %d span(s); want %d", len(held), spanBufferCap)
	}
	if held[0].StartNano != concurrent {
		t.Errorf("oldest retained span StartNano = %d; want %d (the oldest must be the ones dropped)",
			held[0].StartNano, concurrent)
	}
	if last := held[len(held)-1].StartNano; last != 1_000_000+concurrent-1 {
		t.Errorf("newest retained span StartNano = %d; want %d (spans recorded during the push must be kept)",
			last, 1_000_000+concurrent-1)
	}
}

// Order matters for a trace: the retained batch is older than whatever was
// recorded while the push was in flight, so it must come back AHEAD of it.
func TestChaos126_RequeuePreservesOldestFirstOrder(t *testing.T) {
	var hits atomic.Int64
	down := failingCollector(t, http.StatusServiceUnavailable, &hits)
	e := testExporter(down.URL, down.Client())

	recordN(e, 3) // StartNano 0,1,2 — the batch that will fail
	if err := e.push(context.Background()); err == nil {
		t.Fatal("expected a push failure")
	}
	// Spans recorded "while the push was in flight".
	e.RecordSpan(SpanRecord{Name: "proxy_request", StartNano: 100})
	e.RecordSpan(SpanRecord{Name: "proxy_request", StartNano: 101})

	got := e.drain()
	want := []int64{0, 1, 2, 100, 101}
	if len(got) != len(want) {
		t.Fatalf("drained %d span(s); want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].StartNano != want[i] {
			t.Errorf("span[%d].StartNano = %d; want %d (oldest first)", i, got[i].StartNano, want[i])
		}
	}
}

// ── The disable / reconfigure paths ─────────────────────────────────────────

// Stop() used to be the worst case: it cleared the endpoint and the
// cancelled loop's "final flush" then drained the ring and returned at
// `endpoint == ""`. Measured on the pre-fix tree: 5 spans buffered, 0
// requests reaching the collector, DroppedSpans 0. Disabling export may
// still end those spans — it must do so explicitly and counted.
func TestChaos126_StopCountsTheBufferItEnds(t *testing.T) {
	var delivered, batches atomic.Int64
	up := spanCountingCollector(t, &delivered, &batches)
	e := NewSpans()
	e.client = up.Client()
	e.interval = time.Hour
	e.Configure(up.URL, nil)
	recordN(e, 5)

	e.Stop()
	if got := e.Health().DroppedSpans; got != 5 {
		t.Errorf("DroppedSpans = %d after Stop; want 5 — a disable that ends 5 spans must say so", got)
	}
	if got := buffered(e); got != 0 {
		t.Errorf("buffer holds %d span(s) after Stop; want 0", got)
	}
	// The cancelled loop's flush must be a no-op, not a second accounting of
	// the same spans and not a POST to an exporter that was just disabled.
	time.Sleep(200 * time.Millisecond)
	if got := e.Health().DroppedSpans; got != 5 {
		t.Errorf("DroppedSpans = %d after the loop's flush ran; want 5 (no double count)", got)
	}
	if got := batches.Load(); got != 0 {
		t.Errorf("collector saw %d batch(es) after Stop; want 0", got)
	}
}

// A push with export disabled must not touch the buffer at all. This is the
// ordering fix itself: endpoint read BEFORE drain.
func TestChaos126_PushWithExportDisabledDoesNotTouchTheBuffer(t *testing.T) {
	e := testExporter("", nil)
	recordN(e, 6)
	if err := e.push(context.Background()); err != nil {
		t.Fatalf("push with no endpoint must be a silent no-op, got %v", err)
	}
	if got := buffered(e); got != 6 {
		t.Fatalf("buffer holds %d span(s); want 6 untouched — a disabled exporter must not shred its buffer", got)
	}
	if got := e.Health().DroppedSpans; got != 0 {
		t.Errorf("DroppedSpans = %d; want 0", got)
	}
}

// An endpoint that cannot be posted to is a configuration fault, not a
// delivery attempt: the batch stays, and the failure is still reported so an
// operator has a signal.
func TestChaos126_InvalidEndpointRetainsAndStillReports(t *testing.T) {
	e := testExporter("not-a-url", nil)
	recordN(e, 2)
	if err := e.push(context.Background()); err == nil {
		t.Fatal("an unpostable endpoint must report a failure")
	}
	if got := buffered(e); got != 2 {
		t.Errorf("buffer holds %d span(s); want 2 retained", got)
	}
	if got := e.Health().FailureCount; got != 1 {
		t.Errorf("FailureCount = %d; want 1 — the operator's only signal for a bad endpoint", got)
	}
	if got := e.Health().DroppedSpans; got != 0 {
		t.Errorf("DroppedSpans = %d; want 0 — nothing was lost, delivery was never attempted", got)
	}
}

// Repointing the gateway at a different collector must not ship the previous
// collector's window to it. A SpanRecord carries the client IP, the target
// host and the enforcement decision.
func TestChaos126_EndpointChangeDoesNotShipSpansToTheNewCollector(t *testing.T) {
	var deliveredA, batchesA atomic.Int64
	a := spanCountingCollector(t, &deliveredA, &batchesA)
	var deliveredB, batchesB atomic.Int64
	b := spanCountingCollector(t, &deliveredB, &batchesB)

	e := NewSpans()
	e.client = a.Client()
	e.interval = time.Hour
	e.Configure(a.URL, nil)
	recordN(e, 3)

	// Under the mutex: loop-for-A is alive, and Configure's cancel lets its
	// final flush read e.client concurrently.
	e.mu.Lock()
	e.client = b.Client()
	e.mu.Unlock()
	e.Configure(b.URL, nil)
	t.Cleanup(e.Stop)

	if got := e.Health().DroppedSpans; got != 3 {
		t.Errorf("DroppedSpans = %d after repointing; want 3 counted, not silently forwarded", got)
	}
	time.Sleep(200 * time.Millisecond)
	if got := deliveredB.Load(); got != 0 {
		t.Errorf("the NEW collector received %d span(s) collected for the old one; want 0", got)
	}

	// A headers-only reconfigure does NOT throw the buffer away: the
	// destination did not change, so nothing is at risk. (Asserted on
	// delivery rather than on occupancy, because the reconfigure also
	// cancels the old loop, whose flush may legitimately deliver the two
	// spans to the same endpoint before this check runs.)
	recordN(e, 2)
	e.Configure(b.URL, map[string]string{"Authorization": "Bearer x"})
	deadline := time.Now().Add(3 * time.Second)
	for deliveredB.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := deliveredB.Load(); got != 2 {
		t.Errorf("the new collector received %d of the 2 span(s) recorded FOR it; want both", got)
	}
	if got := e.Health().DroppedSpans; got != 3 {
		t.Errorf("DroppedSpans = %d; want 3 — a headers-only change loses nothing", got)
	}
}

// Enabled() must not claim an export that cannot happen. Configure("/")
// normalised to an empty endpoint while active was set from the raw
// argument, so Enabled() reported true and a loop ran that could never post.
func TestChaos126_EnabledTracksTheNormalisedEndpoint(t *testing.T) {
	e := NewSpans()
	t.Cleanup(e.Stop)
	e.Configure("/", nil)
	if e.Enabled() {
		t.Error("Enabled() = true for an endpoint that normalises to empty")
	}
	if got := endpointOf(e); got != "" {
		t.Errorf("stored endpoint = %q; want empty", got)
	}
	e.Configure("  http://collector.example:4318/  ", nil)
	if !e.Enabled() {
		t.Error("Enabled() = false for a configured endpoint")
	}
	if got := endpointOf(e); got != "http://collector.example:4318" {
		t.Errorf("stored endpoint = %q; want the trimmed form", got)
	}
}

// ── Flush ───────────────────────────────────────────────────────────────────

// The flush the shutdown sequence calls must actually deliver.
func TestChaos126_FlushDeliversBufferedSpans(t *testing.T) {
	var delivered, batches atomic.Int64
	up := spanCountingCollector(t, &delivered, &batches)
	e := testExporter(up.URL, up.Client())
	recordN(e, 9)

	if err := e.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := delivered.Load(); got != 9 {
		t.Fatalf("collector received %d span(s); want 9", got)
	}
}

// …and must honour the caller's deadline, because it runs inside a shutdown
// reserve every durable closer shares. A blackholed collector must cost the
// caller's bound, not the client's 10 s timeout — and must not cost the spans.
func TestChaos126_FlushHonoursTheCallersDeadline(t *testing.T) {
	block := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	t.Cleanup(func() { close(block); ts.Close() })

	e := testExporter(ts.URL, ts.Client())
	recordN(e, 3)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := e.Flush(ctx); err == nil {
		t.Fatal("a blackholed collector must report a failure")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Flush took %s; it must honour the caller's deadline, not the client timeout", elapsed)
	}
	if got := buffered(e); got != 3 {
		t.Errorf("buffer holds %d span(s) after an abandoned flush; want 3 retained", got)
	}
}

// ── The loop, end to end ────────────────────────────────────────────────────

// The production shape: a running loop, a collector that is down for several
// intervals and then returns. Pre-fix this lost every span and reported none
// lost (control: 2000 recorded, 0 delivered, 0 dropped).
func TestChaos126_LoopOutageThenRecoveryLosesNothingUpToTheCap(t *testing.T) {
	var delivered, batches atomic.Int64
	var failing atomic.Bool
	failing.Store(true)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		var payload traceExportRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, rs := range payload.ResourceSpans {
			for _, ss := range rs.ScopeSpans {
				delivered.Add(int64(len(ss.Spans)))
			}
		}
		batches.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)

	e := NewSpans()
	e.client = ts.Client()
	e.interval = 20 * time.Millisecond
	e.Configure(ts.URL, nil)
	t.Cleanup(e.Stop)

	const total = 200
	recordN(e, total)
	time.Sleep(120 * time.Millisecond) // several failed intervals

	failing.Store(false)
	deadline := time.Now().Add(5 * time.Second)
	for delivered.Load() < total && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := delivered.Load(); got != total {
		t.Fatalf("collector received %d of %d span(s) after recovery; want all of them", got, total)
	}
	if got := e.Health().DroppedSpans; got != 0 {
		t.Errorf("DroppedSpans = %d; want 0 — the outage was shorter than the cap", got)
	}
	if got := e.Health().FailureCount; got == 0 {
		t.Error("FailureCount = 0; the outage must still be visible to an operator")
	}
}

// ── Gates added by the round's independent review ───────────────────────────
//
// The three below cover defects the first implementation still had. Each was
// reproduced before it was fixed; the reproductions are what these gates are.

// A repoint WHILE A PUSH IS IN FLIGHT must not deliver the old collector's
// spans to the new one. `Configure` discards what is in the RING, but a batch
// already drained by an in-flight push is invisible to it — so testing the
// CURRENT endpoint when the batch came back retained it for a destination it
// was never collected for. Reproduced before the fix: collector B received 2
// spans collected for collector A, with droppedSpans still 0.
func TestChaos126_RepointMidPushDoesNotDeliverToTheNewCollector(t *testing.T) {
	var deliveredB, batchesB atomic.Int64
	b := spanCountingCollector(t, &deliveredB, &batchesB)

	var e *SpanExporter
	// Collector A fails, and the operator repoints to B while A is answering.
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.endpoint = b.URL // what Configure(b.URL) leaves behind
		e.mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(a.Close)

	e = testExporter(a.URL, a.Client())
	recordN(e, 2)
	if err := e.push(context.Background()); err == nil {
		t.Fatal("expected the 503 to be reported")
	}
	if got := buffered(e); got != 0 {
		t.Errorf("%d span(s) retained for an endpoint they were not collected for; want 0", got)
	}
	if got := e.Health().DroppedSpans; got != 2 {
		t.Errorf("DroppedSpans = %d; want 2 — spans ended by a repoint are lost spans and must be counted", got)
	}

	e.mu.Lock()
	e.client = b.Client()
	e.mu.Unlock()
	if err := e.push(context.Background()); err != nil {
		t.Fatalf("push to the new collector: %v", err)
	}
	if got := deliveredB.Load(); got != 0 {
		t.Errorf("collector B received %d span(s) collected for collector A; want 0 — a SpanRecord carries the client IP, the target host and the enforcement decision", got)
	}
}

// Two pushers each hold a drained batch, and requeue puts whichever finishes
// LAST at the front. When the NEWER one finishes last that inverts the
// oldest-first order the ring documents — and at the cap it makes overflow
// evict the NEWEST spans, which are the ones describing the incident. The
// shutdown flush creates that second pusher by design, so push() is
// serialized; this gate is the reproduction that proves it.
func TestChaos126_ConcurrentPushesCannotInvertRingOrder(t *testing.T) {
	g1, g2 := make(chan struct{}), make(chan struct{})
	var n atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch n.Add(1) {
		case 1:
			<-g1
		case 2:
			<-g2
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(ts.Close)

	e := testExporter(ts.URL, ts.Client())
	recordN(e, 3) // older: StartNano 0,1,2

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = e.push(context.Background()) }()
	time.Sleep(100 * time.Millisecond)

	e.RecordSpan(SpanRecord{Name: "proxy_request", StartNano: 100})
	e.RecordSpan(SpanRecord{Name: "proxy_request", StartNano: 101})
	wg.Add(1)
	go func() { defer wg.Done(); _ = e.push(context.Background()) }()
	time.Sleep(100 * time.Millisecond)

	// Release the OLDER batch first, so the newer one would land in front.
	close(g1)
	time.Sleep(100 * time.Millisecond)
	close(g2)
	wg.Wait()

	got := e.drain()
	want := []int64{0, 1, 2, 100, 101}
	if len(got) != len(want) {
		t.Fatalf("drained %d span(s); want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].StartNano != want[i] {
			t.Fatalf("span order = %v; want oldest-first %v — an inverted ring makes overflow evict the NEWEST spans",
				startNanos(got), want)
		}
	}
	// Serialization is the mechanism: only one request can be in flight, so
	// the second pusher never held a batch beside the first.
	if n.Load() != 2 {
		t.Errorf("collector saw %d requests; want 2 (one per push, never concurrent)", n.Load())
	}
}

// The push gate must be acquired under the CALLER's deadline, so a shutdown
// flush spends its own 2s budget rather than the client timeout of a tick
// that reached the slot first — and must take nothing from the ring when it
// gives up.
func TestChaos126_PushGateWaitIsBoundedByTheCaller(t *testing.T) {
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(func() { close(release); ts.Close() })

	e := testExporter(ts.URL, ts.Client())
	recordN(e, 2)
	go func() { _ = e.push(context.Background()) }() // occupies the slot
	time.Sleep(100 * time.Millisecond)

	e.RecordSpan(SpanRecord{Name: "proxy_request", StartNano: 500})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := e.Flush(ctx); err == nil {
		t.Fatal("a flush that cannot get the slot must report it")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("waited %s for the push slot; the caller's deadline must bound it", elapsed)
	}
	if got := buffered(e); got != 1 {
		t.Errorf("buffer holds %d span(s); want the 1 recorded span untouched — a gate timeout takes nothing", got)
	}
	if got := e.Health().DroppedSpans; got != 0 {
		t.Errorf("DroppedSpans = %d; want 0 — nothing was lost", got)
	}
	if got := e.Health().FailureCount; got != 0 {
		t.Errorf("FailureCount = %d; want 0 — losing a race for the slot is not a delivery failure", got)
	}
}

// FlushFinal is for a process that is going away: one attempt, then END what
// is left, counted and named. Retaining it would put the batch back in a ring
// that dies in RAM having moved no counter — the silent loss this round
// removed, relocated to the last second of the process's life.
func TestChaos126_FlushFinalEndsWhatItCouldNotDeliver(t *testing.T) {
	var hits atomic.Int64
	down := failingCollector(t, http.StatusServiceUnavailable, &hits)
	e := testExporter(down.URL, down.Client())
	recordN(e, 6)

	if err := e.FlushFinal(context.Background()); err == nil {
		t.Fatal("a failed terminal flush must report the failure")
	}
	if got := buffered(e); got != 0 {
		t.Errorf("buffer holds %d span(s) after a terminal flush; want 0 — there is no next interval", got)
	}
	if got := e.Health().DroppedSpans; got != 6 {
		t.Errorf("DroppedSpans = %d; want 6 — spans that die at shutdown are lost spans", got)
	}
}

// …and a SUCCESSFUL terminal flush must still deliver, and count nothing.
func TestChaos126_FlushFinalDeliversAndCountsNothingOnSuccess(t *testing.T) {
	var delivered, batches atomic.Int64
	up := spanCountingCollector(t, &delivered, &batches)
	e := testExporter(up.URL, up.Client())
	recordN(e, 6)

	if err := e.FlushFinal(context.Background()); err != nil {
		t.Fatalf("FlushFinal: %v", err)
	}
	if got := delivered.Load(); got != 6 {
		t.Errorf("collector received %d span(s); want 6", got)
	}
	if got := e.Health().DroppedSpans; got != 0 {
		t.Errorf("DroppedSpans = %d; want 0 — everything was delivered", got)
	}
}

// An endpoint that passes the regexp barrier but cannot build a request gives
// the same verdict every interval, so the batch is dropped and counted rather
// than pinning the ring against spans that could still be delivered.
func TestChaos126_UnusableEndpointDropsAndCountsRatherThanPinningTheRing(t *testing.T) {
	// Passes `^https?://[^/]` and fails http.NewRequestWithContext.
	e := testExporter("http://host\x7f\x00bad", &http.Client{})
	recordN(e, 4)
	if err := e.push(context.Background()); err == nil {
		t.Fatal("an unusable endpoint must report a failure")
	}
	if got := buffered(e); got != 0 {
		t.Errorf("buffer holds %d span(s); want 0 — the ring must not be pinned by a batch that can never be built", got)
	}
	if got := e.Health().DroppedSpans; got != 4 {
		t.Errorf("DroppedSpans = %d; want 4 — counted, and attributed to the configuration rather than to overflow", got)
	}
}

func startNanos(spans []SpanRecord) []int64 {
	out := make([]int64, len(spans))
	for i := range spans {
		out[i] = spans[i].StartNano
	}
	return out
}
