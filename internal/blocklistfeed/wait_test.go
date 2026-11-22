package blocklistfeed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// Wait joins the loop Start launched once its context is cancelled, holds
// while a round is still in flight, and is a no-op on a syncer that was never
// started. The root loader tests rely on it: an unjoined boot round reported
// to the sync observer after its test ended, and the observer's read of the
// process-wide syncer pointer raced the next test's reset of it.
func TestSyncer_WaitJoinsTheLoop(t *testing.T) {
	New(&fakeMerger{}).Wait() // never started: must not block

	t.Cleanup(ssrf.AllowLoopbackForTest())
	arrived := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case arrived <- struct{}{}:
		default:
		}
		<-r.Context().Done() // hold the boot round until the fetch is cancelled
	}))
	t.Cleanup(srv.Close)

	bs := New(&fakeMerger{})
	bs.SetFeed(srv.URL, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bs.Start(ctx)
	select {
	case <-arrived:
	case <-time.After(10 * time.Second):
		t.Fatal("the boot round never reached the origin")
	}

	done := make(chan struct{})
	go func() { bs.Wait(); close(done) }()
	select {
	case <-done:
		t.Fatal("Wait returned while the boot round was still in flight")
	case <-time.After(100 * time.Millisecond):
	}

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Wait did not return after the context was cancelled")
	}
}
