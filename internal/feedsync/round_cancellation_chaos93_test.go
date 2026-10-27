package feedsync

// round_cancellation_chaos93_test.go — CHAOS-93 RT-4 for the UT1 category feed.
//
// feedsched.Config.Run is documented "It must respect ctx", and the scheduler's
// whole cancellation guarantee rests on the round doing so. This round declared
// `Run: func(context.Context) bool` and DROPPED the parameter, fetching on
// context.Background() instead. Two consequences, both reachable by an ordinary
// SIGTERM against a slow origin:
//
//   - the round could not be interrupted and ran on for up to its HTTP timeout;
//   - it then issued a 50+ MB BulkWrite into a BadgerDB that shutdown hook
//     order 120 is closing, the lifecycle ctx having been cancelled at order 40.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/catdb"
)

// TestDownloadAndParse_HonoursContextCancellation is the interruption gate: the
// fetch aborts on cancellation instead of waiting out feedSyncHTTPTimeout.
func TestDownloadAndParse_HonoursContextCancellation(t *testing.T) {
	stalled := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A stalled origin: headers sent, body never arrives.
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-stalled
	}))
	defer func() { close(stalled); srv.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := downloadAndParse(ctx, srv.URL)
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
		t.Fatal("cancelled fetch did not return: a SIGTERM cannot interrupt a feed round")
	}
}

// TestSyncRound_DoesNotWriteAfterCancellation is the durability gate: a round
// whose context is already cancelled must not start the bulk write, because the
// store it would write into is being closed.
func TestSyncRound_DoesNotWriteAfterCancellation(t *testing.T) {
	// A healthy origin that serves a complete tarball: the round gets all the
	// way to the write, which is the only interesting place to be cancelled.
	body := makeTarGz(t, map[string]string{"blacklists/adult/domains": "example.com\n"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	db, err := catdb.Open(t.TempDir())
	if err != nil {
		t.Fatalf("catdb.Open: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	fs := New(db, srv.URL, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the lifecycle ended while this round was downloading

	if ok := fs.syncRound(ctx); ok {
		t.Error("a round cancelled before its write must be charged as a failure")
	}
	if n := db.Stats(); n != 0 {
		t.Errorf("round wrote %d entries after cancellation; the store is being closed at shutdown order 120", n)
	}
	if got := fs.consecutiveFailures.Load(); got == 0 {
		t.Error("the cancelled round was not counted as a failure, so the health plane cannot see it")
	}
}
