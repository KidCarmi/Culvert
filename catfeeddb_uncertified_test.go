package main

// Workstream B pre-review F-B2: a failed import can leave the community
// category store holding a partial, uncertified mix (BeginImport withdrew the
// completion record; the write failed partway). The row used to fall through
// to "community category store loaded" (OK). It now warns — but only after a
// failure, so an ordinary import in progress does not flap the row.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/catdb"
	"github.com/KidCarmi/Culvert/internal/feedsync"
)

// swapUncertifiedSyncer installs a syncer over a store holding entries; when
// certified is false the store has no completion record (an interrupted import).
// failFeed makes every sync round fail at download.
func swapUncertifiedSyncer(t *testing.T, certified, failFeed bool) *feedsync.Syncer {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if failFeed {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
	}))
	t.Cleanup(srv.Close)
	db, err := catdb.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.BeginImport(); err != nil {
		t.Fatal(err)
	}
	if err := db.BulkWrite(map[string]string{"casino.example.com": "gambling"}); err != nil {
		t.Fatal(err)
	}
	if certified {
		if err := db.CompleteImport(catdb.SyncRecord{FeedURL: srv.URL, Entries: 1, CompletedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
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

func TestFB2_FailedImportLeavingPartialStoreWarns(t *testing.T) {
	sy := swapUncertifiedSyncer(t, false, true)
	sy.Sync() // fails at download; the store keeps the partial, uncertified data
	if sy.Health().ConsecutiveFailures == 0 {
		t.Fatal("precondition: the round must have failed")
	}
	c := checkCategoryFeedDB()
	if c.Status != diagWarn || !strings.Contains(c.Message, "incomplete import") || !strings.Contains(c.Message, "partial set of categories") {
		t.Fatalf("an uncertified store after a failed import must warn, got %+v", c)
	}
}

// CONTROL: an uncertified store that has NOT failed (an import in progress, or
// a pre-record store about to be re-synced) keeps the ordinary row.
func TestFB2_UncertifiedWithoutFailureDoesNotWarn(t *testing.T) {
	swapUncertifiedSyncer(t, false, true)
	if c := checkCategoryFeedDB(); c.Status != diagOK {
		t.Fatalf("no failure yet ⇒ no claim, got %+v", c)
	}
}

// CONTROL: a failed round over a CERTIFIED store (a download outage) is not an
// incomplete store; the data that serves is a whole import.
func TestFB2_FailureOverCertifiedStoreDoesNotWarn(t *testing.T) {
	sy := swapUncertifiedSyncer(t, true, true)
	sy.Sync()
	if sy.Health().ConsecutiveFailures == 0 {
		t.Fatal("precondition: the round must have failed")
	}
	if c := checkCategoryFeedDB(); c.Status != diagOK {
		t.Fatalf("a whole certified import must still read OK, got %+v", c)
	}
}
