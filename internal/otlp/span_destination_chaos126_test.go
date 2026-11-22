package otlp

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

func inflightOf(e *SpanExporter) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.inflight
}

// repoint does what Configure does under e.mu for an endpoint change:
// discard the ring and store the new destination. It starts no push loop, so
// the test alone decides when pushes happen.
func repoint(e *SpanExporter, endpoint string) {
	e.mu.Lock()
	e.discardBufferedLocked()
	e.endpoint = endpoint
	e.mu.Unlock()
}

// taggedCollector accepts every batch and counts spans whose Name is not tag:
// spans recorded for a different collector.
func taggedCollector(t *testing.T, tag string, seen, wrong *atomic.Int64) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p traceExportRequest
		if err := json.NewDecoder(r.Body).Decode(&p); err == nil {
			for _, rs := range p.ResourceSpans {
				for _, ss := range rs.ScopeSpans {
					for i := range ss.Spans {
						seen.Add(1)
						if ss.Spans[i].Name != tag {
							wrong.Add(1)
						}
					}
				}
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// push must take the destination and the batch together. When it read the
// endpoint, released the lock and drained afterwards, a repoint landing in
// between discarded A's ring, spans recorded for B filled it, and the push
// posted B's spans to A with A's headers. The POST succeeded, so requeue's
// destination check never ran. Repoints race a pusher here; every span a
// collector receives must have been recorded while it was the destination.
func TestChaos126_PushNeverPostsSpansRecordedForAnotherCollector(t *testing.T) {
	var seen, wrong atomic.Int64
	a := taggedCollector(t, "for-A", &seen, &wrong)
	b := taggedCollector(t, "for-B", &seen, &wrong)
	e := testExporter(a.URL, &http.Client{Timeout: 5 * time.Second})

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = e.push(context.Background())
			}
		}
	}()
	targets := []struct{ url, tag string }{{a.URL, "for-A"}, {b.URL, "for-B"}}
	for i := 0; i < 4000; i++ {
		tg := targets[i%2]
		repoint(e, tg.url)
		for j := 0; j < 4; j++ {
			e.RecordSpan(SpanRecord{Name: tg.tag, StartNano: int64(i)})
		}
	}
	close(stop)
	wg.Wait()
	_ = e.push(context.Background())

	if seen.Load() == 0 {
		t.Fatal("no span reached either collector; the test exercised nothing")
	}
	if got := wrong.Load(); got != 0 {
		t.Errorf("%d of %d delivered span(s) went to a collector they were not recorded for; want 0", got, seen.Load())
	}
}

// A terminal flush that times out waiting for the push slot cannot see the
// batch the slot's holder drained. It must name that batch, and if the POST
// then fails the batch is counted as dropped, not requeued into a ring the
// exiting process will never read.
func TestChaos126_FlushFinalEndsTheBatchAnotherPushHolds(t *testing.T) {
	arrived := make(chan struct{})
	var once sync.Once
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(arrived) })
		<-release
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(ts.Close)

	e := testExporter(ts.URL, ts.Client())
	recordN(e, 3)
	done := make(chan error, 1)
	go func() { done <- e.push(context.Background()) }()
	<-arrived // the 3 spans are now in flight, outside the ring

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := e.FlushFinal(ctx); err == nil {
		close(release)
		t.Fatal("a terminal flush that cannot get the slot must report it")
	}
	if got := inflightOf(e); got != 3 {
		t.Errorf("in-flight count at shutdown = %d; want 3", got)
	}
	if got := e.Health().DroppedSpans; got != 0 {
		t.Errorf("DroppedSpans = %d before the in-flight push settled; want 0 — its outcome is not known yet", got)
	}

	close(release)
	if err := <-done; err == nil {
		t.Fatal("expected the in-flight push to report the 503")
	}
	if got := buffered(e); got != 0 {
		t.Errorf("buffer holds %d span(s) after finalization; want 0 — a failed push after the shutdown flush must not requeue", got)
	}
	if got := e.Health().DroppedSpans; got != 3 {
		t.Errorf("DroppedSpans = %d; want 3 — the batch that failed after shutdown is lost and must be counted", got)
	}
	if got := inflightOf(e); got != 0 {
		t.Errorf("in-flight count = %d after the push settled; want 0", got)
	}
}

// Every way a push ends settles the in-flight count, so a terminal flush
// never reports a batch that is already delivered, requeued or discarded.
func TestChaos126_EveryPushOutcomeSettlesTheInFlightCount(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
	}{
		{"delivered", http.StatusOK},
		{"requeued", http.StatusServiceUnavailable},
		{"discarded", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int64
			ts := failingCollector(t, tc.code, &hits)
			e := testExporter(ts.URL, ts.Client())
			recordN(e, 2)
			_ = e.push(context.Background())
			if hits.Load() != 1 {
				t.Fatalf("collector saw %d request(s); want 1", hits.Load())
			}
			if got := inflightOf(e); got != 0 {
				t.Errorf("in-flight count = %d after a %d; want 0", got, tc.code)
			}
		})
	}
}
