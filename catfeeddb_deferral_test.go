package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/catdb"
	"github.com/KidCarmi/Culvert/internal/feedsync"
)

// A sync the free-space guard deferred is visible on the category_feed_db
// operator-contract row, which names the cause and states coverage truthfully:
// earlier data serving, or none yet (owner review of 5a86020).
func TestCategoryFeedRow_ReportsDeferredSyncAndCoverage(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("casino.example.com\n")
	_ = tw.WriteHeader(&tar.Header{Name: "blacklists/gambling/domains", Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = gz.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(buf.Bytes()) }))
	defer srv.Close()

	db, err := catdb.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test cleanup
	prev := globalUT1FeedSyncer
	t.Cleanup(func() { globalUT1FeedSyncer = prev; resetCatFeedDBHealthForTest() })
	noteCatFeedDBState(catFeedDBHealth{Configured: true, Available: true})

	sy := feedsync.New(db, srv.URL, time.Hour)
	globalUT1FeedSyncer = sy
	if c := checkCategoryFeedDB(); c.Status != diagOK {
		t.Fatalf("before any sync: %+v", c)
	}

	// First boot, measurement fails: deferred, and NO coverage claimed.
	sy.SetFreeSpaceProbe(func() (uint64, error) { return 0, errors.New("statfs: input/output error") })
	sy.Sync()
	c := checkCategoryFeedDB()
	if c.Status != diagWarn || !strings.Contains(c.Message, "could not be measured") || !strings.Contains(c.Message, "no community category data is loaded yet") {
		t.Fatalf("deferred first sync: %+v", c)
	}

	// Space below the floor with data already present: earlier data serves.
	sy.SetFreeSpaceProbe(func() (uint64, error) { return 8 << 30, nil })
	sy.Sync()
	sy.SetFreeSpaceProbe(func() (uint64, error) { return 1 << 20, nil })
	sy.Sync()
	c = checkCategoryFeedDB()
	if c.Status != diagWarn || !strings.Contains(c.Message, "below the free-space floor") || !strings.Contains(c.Message, "keep serving") {
		t.Fatalf("deferred sync over existing data: %+v", c)
	}

	// CONTROL: a clean round clears the row.
	sy.SetFreeSpaceProbe(func() (uint64, error) { return 8 << 30, nil })
	sy.Sync()
	if c := checkCategoryFeedDB(); c.Status != diagOK {
		t.Fatalf("after a clean sync: %+v", c)
	}
}
