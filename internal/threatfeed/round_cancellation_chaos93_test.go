package threatfeed

// round_cancellation_chaos93_test.go — CHAOS-93 RT-4 for the URLhaus/OpenPhish
// threat feed.
//
// feedsched.Config.Run is documented "It must respect ctx", and the scheduler's
// cancellation guarantee is only as good as the round's. This round declared
// `Run: func(context.Context) bool` and DROPPED the parameter, so both fetches
// ran on context.Background(): a stalled origin could not be interrupted by
// SIGTERM and the round ran on for up to feedHTTPTimeout (60s) past the point
// where the process was told to stop.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestFetchTextFeed_HonoursContextCancellation is the interruption gate: a
// cancelled context aborts the fetch rather than waiting out feedHTTPTimeout.
func TestFetchTextFeed_HonoursContextCancellation(t *testing.T) {
	stalled := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-stalled // body never arrives
	}))
	defer func() { close(stalled); srv.Close() }()

	tf := New()
	ctx, cancel := context.WithCancel(context.Background())

	errc := make(chan error, 1)
	go func() {
		_, err := tf.fetchTextFeed(ctx, srv.URL, sourceURLhaus, map[string]entry{}, map[string]entry{})
		errc <- err
	}()

	time.Sleep(50 * time.Millisecond) // let the request reach the stalled handler
	cancel()

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("a cancelled fetch must return an error")
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("cancelled fetch did not return: a SIGTERM cannot interrupt a feed round (timeout is %v)", feedHTTPTimeout)
	}
}

// TestSchedulerRound_PropagatesCancellationToTheFetches is the propagation
// gate, and the one that pins the actual defect: the round reached by the
// scheduler's Run closure must be the one that sees the scheduler's context.
//
// Driving it with an already-cancelled context makes the assertion hermetic and
// differential at once. With the context threaded, both fetches fail at
// http.Client.Do before any dial and the round's failure summary names the
// cancellation. With the parameter dropped — the pre-fix shape — the fetches ran
// on context.Background() and went to the real origins, so the summary named
// whatever the network did instead, and never the cancellation.
func TestSchedulerRound_PropagatesCancellationToTheFetches(t *testing.T) {
	tf := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	run := tf.schedulerConfig().Run
	if run == nil {
		t.Fatal("scheduler config has no Run")
	}

	done := make(chan bool, 1)
	go func() { done <- run(ctx) }()

	var ok bool
	select {
	case ok = <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the round did not observe its cancelled context")
	}
	if ok {
		t.Error("a cancelled round must be charged as a failure so the scheduler backs off")
	}

	_, _, errSummary := tf.SyncStatus()
	if !strings.Contains(errSummary, context.Canceled.Error()) {
		t.Errorf("failure summary %q does not name the cancellation: the round is not using the scheduler's context", errSummary)
	}
}
