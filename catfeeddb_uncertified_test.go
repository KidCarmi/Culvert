package main

// Workstream B pre-review F-B2: a failed import can leave the community
// category store holding a partial, uncertified mix (BeginImport withdrew the
// completion record; the write failed partway). The row used to fall through
// to "community category store loaded" (OK). It now warns — but only after a
// failure, so an ordinary import in progress does not flap the row.

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

// swapDeferredSyncer serves a valid feed but refuses every write for disk
// space, over a store that is certified or holds an uncertified partial import.
func swapDeferredSyncer(t *testing.T, certified bool) *feedsync.Syncer {
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
	if err := db.BeginImport(); err != nil {
		t.Fatal(err)
	}
	if err := db.BulkWrite(map[string]string{"partial.example.com": "gambling"}); err != nil {
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
	sy.SetFreeSpaceProbe(func() (uint64, error) { return 0, nil })
	globalUT1FeedSyncer = sy
	return sy
}

// ASTRA 5978949299 WS-B 2: a disk-space deferral over a store a failed write
// left partial must not claim "the previously synced categories keep serving".
func TestFB2_DeferralOverPartialStoreSaysPartial(t *testing.T) {
	sy := swapDeferredSyncer(t, false)
	sy.Sync()
	if sy.Health().LastFailure != feedsync.FailDiskSpace {
		t.Fatalf("precondition: the round must be deferred for disk space, got %q", sy.Health().LastFailure)
	}
	c := checkCategoryFeedDB()
	if c.Status != diagWarn || !strings.Contains(c.Message, "sync deferred") || !strings.Contains(c.Message, "incomplete import") ||
		strings.Contains(c.Message, "keep serving") {
		t.Fatalf("the deferral must keep its disk cause and state the partial coverage, got %+v", c)
	}
	if !strings.Contains(c.OperatorAction, "Free space") {
		t.Fatalf("the disk-space remedy must be kept: %q", c.OperatorAction)
	}
}

// CONTROL: over a certified store the deferral truthfully says the earlier
// import keeps serving.
func TestFB2_DeferralOverCertifiedStoreKeepsServing(t *testing.T) {
	sy := swapDeferredSyncer(t, true)
	sy.Sync()
	if c := checkCategoryFeedDB(); !strings.Contains(c.Message, "previously synced community categories keep serving") {
		t.Fatalf("a certified store under deferral keeps serving, got %+v", c)
	}
}

// ASTRA 5978949299 WS-B 3: a boot that found an interrupted import and could
// not quarantine it opens the partial store with a fresh, zero-failure syncer.
// The row must warn from the start, not read "loaded" until a retry fails.
func TestFB2_KeptInterruptedImportWarnsBeforeAnyFailure(t *testing.T) {
	sy := swapUncertifiedSyncer(t, false, true)
	noteCatFeedDBState(catFeedDBHealth{Configured: true, Available: true, InterruptedImportKept: true})
	if sy.Health().ConsecutiveFailures != 0 {
		t.Fatal("precondition: no sync attempt yet")
	}
	c := checkCategoryFeedDB()
	if c.Status != diagWarn || !strings.Contains(c.Message, "interrupted") || !strings.Contains(c.Message, "partial set of categories") {
		t.Fatalf("a kept interrupted import must warn before the first retry, got %+v", c)
	}
}

// CONTROL: once an import completes, the boot record no longer makes a claim.
func TestFB2_KeptInterruptedImportClearsOnceCertified(t *testing.T) {
	swapUncertifiedSyncer(t, true, true)
	noteCatFeedDBState(catFeedDBHealth{Configured: true, Available: true, InterruptedImportKept: true})
	if c := checkCategoryFeedDB(); c.Status != diagOK {
		t.Fatalf("a certified store must read OK even after a kept interrupted import at boot, got %+v", c)
	}
}
