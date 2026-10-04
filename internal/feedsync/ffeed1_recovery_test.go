package feedsync

// F-FEED-1 (PR #1528 §3f): a UT1 import cut off part-way (the first boot's
// container recreate, a power loss) left SOME keys in the store; startup sync
// ran only for an EMPTY store, so the partial store went unsynced for a full
// interval, and the process-local status read "never synced" after every
// restart. Completion is now a durable record; these tests drive a
// controlled feed through interruption, restart and recovery.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/catdb"
)

// controlledFeed serves a fixed UT1 tarball of n gambling domains plus one
// adult domain, and counts downloads.
func controlledFeed(t *testing.T, n int) (url string, domains []string, downloads *int) {
	t.Helper()
	gambling := ""
	for i := 0; i < n; i++ {
		d := "ffeed1-" + itoaTest(i) + ".example"
		domains = append(domains, d)
		gambling += d + "\n"
	}
	tarData := makeTarGz(t, map[string]string{
		"blacklists/gambling/domains": gambling,
		"blacklists/adult/domains":    "ffeed1-adult.example\n",
	})
	count := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count++
		_, _ = w.Write(tarData)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, append(domains, "ffeed1-adult.example"), &count
}

func itoaTest(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

func openStore(t *testing.T, dir string) *catdb.CommunityDB {
	t.Helper()
	db, err := catdb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func present(db *catdb.CommunityDB, domains []string) int {
	n := 0
	for _, d := range domains {
		if _, ok := db.Lookup(d); ok {
			n++
		}
	}
	return n
}

// The reported defect, end to end: an import interrupted after partial
// writes, then a restart, must be completed AUTOMATICALLY by the startup sync.
func TestFFeed1_InterruptedImportIsCompletedAfterRestart(t *testing.T) {
	url, domains, downloads := controlledFeed(t, 50)
	dir := t.TempDir()

	db := openStore(t, dir)
	db.SetBulkWriteFaultForTest(func(n int) error {
		if n == 20 {
			return errors.New("process killed mid-import")
		}
		return nil
	})
	first := New(db, url, 24*time.Hour)
	if first.syncRound() {
		t.Fatal("an interrupted import must not count as a sync")
	}
	if got := present(db, domains); got != 20 {
		t.Fatalf("want a PARTIAL store (20 of %d), got %d", len(domains), got)
	}
	if first.ImportComplete() || !first.Health().LastSuccess.IsZero() {
		t.Fatal("an interrupted import must not be reported as complete")
	}
	_ = db.Close()

	// Restart. The store is non-empty but uncertified: the startup sync must run.
	db = openStore(t, dir)
	defer db.Close()
	second := New(db, url, 24*time.Hour)
	if !second.schedulerConfig().RunNow() {
		t.Fatal("a partially imported store must be synced at startup (the old rule only synced an EMPTY store)")
	}
	if !second.syncRound() {
		t.Fatal("the recovery sync must succeed")
	}
	if got := present(db, domains); got != len(domains) {
		t.Fatalf("recovery must complete the import: %d of %d present", got, len(domains))
	}
	if !second.ImportComplete() || second.Health().Domains != int64(len(domains)) {
		t.Fatalf("recovery must certify the whole import: %+v", second.Health())
	}
	if *downloads != 2 {
		t.Fatalf("want exactly one download per sync, got %d", *downloads)
	}
}

// A completed sync survives a restart: no startup re-download, and the
// status is restored from the record instead of reading "never synced".
func TestFFeed1_CompletedSyncSurvivesRestartWithItsStatus(t *testing.T) {
	url, domains, downloads := controlledFeed(t, 30)
	dir := t.TempDir()
	db := openStore(t, dir)
	first := New(db, url, 24*time.Hour)
	if !first.syncRound() {
		t.Fatal("sync failed")
	}
	done := first.Health().LastSuccess
	_ = db.Close()

	db = openStore(t, dir)
	defer db.Close()
	second := New(db, url, 24*time.Hour)
	if second.schedulerConfig().RunNow() {
		t.Fatal("a certified store must not be re-downloaded at startup")
	}
	h := second.Health()
	if !h.LastSuccess.Equal(done) || h.Domains != int64(len(domains)) {
		t.Fatalf("status must be restored from the record: got last=%v domains=%d, want %v/%d", h.LastSuccess, h.Domains, done, len(domains))
	}
	entries, last, _ := second.Stats() // what /api/urlcat/feed-status serves
	if entries != int64(len(domains)) || !last.Equal(done) {
		t.Fatalf("Stats after restart: %d %v", entries, last)
	}
	if *downloads != 1 {
		t.Fatalf("want one download in total, got %d", *downloads)
	}
}

// A store written before completion records existed (or by an interrupted
// import from an older build) is not certified: it is synced at startup, and
// its data is kept, not wiped.
func TestFFeed1_LegacyStoreWithoutRecordIsSyncedAndKept(t *testing.T) {
	url, domains, _ := controlledFeed(t, 10)
	dir := t.TempDir()
	db := openStore(t, dir)
	defer db.Close()
	if err := db.BulkWrite(map[string]string{"legacy-only.example": "Malicious"}); err != nil {
		t.Fatal(err)
	}
	s := New(db, url, 24*time.Hour)
	if !s.schedulerConfig().RunNow() || !s.Health().LastSuccess.IsZero() {
		t.Fatal("a non-empty store without a record must be synced at startup and not reported as synced")
	}
	if !s.syncRound() || present(db, domains) != len(domains) {
		t.Fatal("the startup sync must import the feed")
	}
	if cat, ok := db.Lookup("legacy-only.example"); !ok || cat != "Malicious" {
		t.Fatal("existing data must be preserved")
	}
}

// A failed write never advances success: not in this process, and — because
// the record was withdrawn before the write — not after a restart either.
func TestFFeed1_FailedWriteDoesNotAdvanceSuccess(t *testing.T) {
	url, _, _ := controlledFeed(t, 10)
	dir := t.TempDir()
	db := openStore(t, dir)
	s := New(db, url, 24*time.Hour)
	if !s.syncRound() {
		t.Fatal("first sync failed")
	}
	before := s.Health().LastSuccess
	db.SetBulkWriteFaultForTest(func(n int) error {
		if n == 3 {
			return errors.New("write failed")
		}
		return nil
	})
	time.Sleep(10 * time.Millisecond)
	if s.syncRound() {
		t.Fatal("a failed write must fail the round")
	}
	h := s.Health()
	if !h.LastSuccess.Equal(before) || h.LastFailure != failWrite {
		t.Fatalf("success must not advance on a failed write: %+v", h)
	}
	if s.ImportComplete() {
		t.Fatal("a store whose re-import failed part-way is no longer certified")
	}
	_ = db.Close()
	db = openStore(t, dir)
	defer db.Close()
	if !New(db, url, 24*time.Hour).schedulerConfig().RunNow() {
		t.Fatal("after a restart the half-written re-import must be redone")
	}
}

// The disk-space guard refuses BEFORE the record is withdrawn: the previous,
// complete import keeps serving and stays certified.
func TestFFeed1_SpaceRefusalKeepsTheCertifiedImport(t *testing.T) {
	url, domains, _ := controlledFeed(t, 10)
	db := openStore(t, t.TempDir())
	defer db.Close()
	s := New(db, url, 24*time.Hour)
	if !s.syncRound() {
		t.Fatal("first sync failed")
	}
	s.SetFreeSpaceProbe(func() (uint64, error) { return 1 << 20, nil })
	if s.syncRound() {
		t.Fatal("the space guard must refuse the write")
	}
	if !s.ImportComplete() || present(db, domains) != len(domains) || s.Health().LastFailure != failDiskSpace {
		t.Fatal("a refused write must leave the certified import untouched")
	}
}

// The record names its feed: an operator who points the syncer at another
// feed gets a startup sync of THAT feed.
func TestFFeed1_RecordForAnotherFeedIsNotComplete(t *testing.T) {
	url, _, _ := controlledFeed(t, 5)
	other, _, _ := controlledFeed(t, 5)
	db := openStore(t, t.TempDir())
	defer db.Close()
	if !New(db, url, time.Hour).syncRound() {
		t.Fatal("sync failed")
	}
	if New(db, other, time.Hour).ImportComplete() {
		t.Fatal("a record for a different feed must not certify this one")
	}
}
