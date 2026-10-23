package main

// catfeeddb_writeabandoned_test.go — F-DISK-RECOVERY-1 item 4 (latched fault
// reporting). An import the watchdog abandoned mid-write is a process-lifetime
// latch: no further import runs until restart. Before this, the only signal was
// the generic "write" sync failure, which reads as retryable. These pin that the
// operator row and /metrics both say "restart required", and that neither
// claims it when the latch is not set.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/catdb"
	"github.com/KidCarmi/Culvert/internal/feedsync"
)

func swapAbandonTestSyncer(t *testing.T) *feedsync.Syncer {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("casino.example.com\n")
	_ = tw.WriteHeader(&tar.Header{Name: "blacklists/gambling/domains", Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = gz.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(buf.Bytes()) }))
	t.Cleanup(srv.Close)
	db, err := catdb.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prev := globalUT1FeedSyncer
	t.Cleanup(func() {
		globalUT1FeedSyncer = prev
		resetCatFeedDBHealthForTest()
		_ = db.Close()
	})
	noteCatFeedDBState(catFeedDBHealth{Configured: true, Available: true})
	sy := feedsync.New(db, srv.URL, time.Hour)
	globalUT1FeedSyncer = sy
	return sy
}

func TestCategoryFeedRow_WriteAbandonedSaysRestartRequired(t *testing.T) {
	for _, tc := range []struct {
		cause, want string
	}{
		{feedsync.AbandonStalled, "did not complete within its deadline"},
		{feedsync.AbandonDegraded, "contained memory fault"},
	} {
		t.Run(tc.cause, func(t *testing.T) {
			sy := swapAbandonTestSyncer(t)
			// CONTROL: no latch, no claim.
			if c := checkCategoryFeedDB(); c.Status != diagOK {
				t.Fatalf("before the latch: %+v", c)
			}
			sy.MarkWriteAbandonedForTest(tc.cause)
			c := checkCategoryFeedDB()
			if c.Status != diagWarn ||
				!strings.Contains(c.Message, "abandoned mid-write") ||
				!strings.Contains(c.Message, tc.want) ||
				!strings.Contains(c.Message, "until this node restarts") ||
				!strings.Contains(c.Message, "no community category data is loaded yet") {
				t.Fatalf("abandoned row: %+v", c)
			}
			if !strings.Contains(c.OperatorAction, "restart this node") {
				t.Fatalf("operator action must say restart: %q", c.OperatorAction)
			}
			h := sy.Health()
			if !h.WriteAbandoned || h.WriteAbandonedCause != tc.cause || h.WriteAbandonedAt.IsZero() {
				t.Fatalf("Health: %+v", h)
			}
		})
	}
}

// The latch outranks a free-space deferral: a deferral retries on its own, an
// abandoned import never does until restart.
func TestCategoryFeedRow_WriteAbandonedOutranksDeferral(t *testing.T) {
	sy := swapAbandonTestSyncer(t)
	sy.SetFreeSpaceProbe(func() (uint64, error) { return 1 << 20, nil })
	sy.Sync()
	if c := checkCategoryFeedDB(); !strings.Contains(c.Message, "deferred") {
		t.Fatalf("precondition: deferral row expected: %+v", c)
	}
	sy.MarkWriteAbandonedForTest(feedsync.AbandonStalled)
	if c := checkCategoryFeedDB(); !strings.Contains(c.Message, "abandoned mid-write") {
		t.Fatalf("the abandoned latch must outrank the deferral: %+v", c)
	}
}

func TestCategoryFeedMetrics_WriteAbandonedGauge(t *testing.T) {
	render := func() string {
		var b strings.Builder
		urlcatWritePrometheus(&b)
		return b.String()
	}
	// Not configured: the series is absent (emit-only-when-configured).
	prev := globalUT1FeedSyncer
	globalUT1FeedSyncer = nil
	out := render()
	globalUT1FeedSyncer = prev
	if strings.Contains(out, "culvert_category_feed_write_abandoned") {
		t.Fatal("the abandoned gauge must not be emitted when the feed is not configured")
	}

	sy := swapAbandonTestSyncer(t)
	if !strings.Contains(render(), "culvert_category_feed_write_abandoned 0\n") {
		t.Fatal("configured, not abandoned: gauge must read 0")
	}
	sy.MarkWriteAbandonedForTest(feedsync.AbandonStalled)
	if !strings.Contains(render(), "culvert_category_feed_write_abandoned 1\n") {
		t.Fatal("abandoned: gauge must read 1")
	}
}

// With data already in the store, the abandoned write may still land in the
// LIVE store, so the row must not claim the earlier data is what serves (ASTRA
// 6359611097 #6): it says the content is an uncertified mix until restart.
func TestCategoryFeedRow_WriteAbandonedNeverClaimsEarlierDataServes(t *testing.T) {
	sy := swapAbandonTestSyncer(t)
	sy.Sync() // load real data first, so the store is not empty
	if sy.StoreEmpty() {
		t.Fatal("precondition: the store must hold data")
	}
	sy.MarkWriteAbandonedForTest(feedsync.AbandonStalled)
	c := checkCategoryFeedDB()
	if !strings.Contains(c.Message, "partial, uncertified mix") || strings.Contains(c.Message, "keep serving") {
		t.Fatalf("abandoned row over existing data must state uncertified content: %+v", c)
	}
}
