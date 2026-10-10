package catdb

// F-FEED-1 (PR #1528 §3f): whether a feed import FINISHED is recorded only by
// the completion record — a partial store is indistinguishable from a
// complete one by its contents.

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const testFeed = "https://feed.example/blacklists.tar.gz"

func openT(t *testing.T, dir string) *CommunityDB {
	t.Helper()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestImportRecord_RoundTripSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	db := openT(t, dir)
	if _, err := db.ImportRecord(); !errors.Is(err, ErrNoSyncRecord) {
		t.Fatalf("a fresh store must have no record, got %v", err)
	}
	if err := db.BeginImport(); err != nil {
		t.Fatal(err)
	}
	if err := db.BulkWrite(map[string]string{"a.example": "Gambling", "b.example": "Adult"}); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	if err := db.CompleteImport(SyncRecord{FeedURL: testFeed, Entries: 2, CompletedAt: at}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = openT(t, dir)
	defer db.Close()
	rec, err := db.ImportRecord()
	if err != nil || rec.FeedURL != testFeed || rec.Entries != 2 || !rec.CompletedAt.Equal(at) || rec.Version != syncRecordVersion {
		t.Fatalf("record after reopen: %+v, %v", rec, err)
	}
}

// BeginImport withdraws the certificate durably BEFORE any data moves, so an
// interrupted re-import is never reported as complete.
func TestImportRecord_BeginImportWithdrawsTheRecord(t *testing.T) {
	dir := t.TempDir()
	db := openT(t, dir)
	_ = db.BulkWrite(map[string]string{"a.example": "Gambling"})
	if err := db.CompleteImport(SyncRecord{FeedURL: testFeed, Entries: 1, CompletedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := db.BeginImport(); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	db = openT(t, dir)
	defer db.Close()
	if _, err := db.ImportRecord(); !errors.Is(err, ErrNoSyncRecord) {
		t.Fatalf("a begun-but-unfinished import must leave no record, got %v", err)
	}
	if cat, ok := db.Lookup("a.example"); !ok || cat != "Gambling" {
		t.Fatal("withdrawing the record must not touch the data")
	}
}

func TestImportRecord_InvalidRecordsAreRejected(t *testing.T) {
	db := openT(t, t.TempDir())
	defer db.Close()
	for name, raw := range map[string]string{
		"garbage":        "not json",
		"future version": `{"version":2,"feed_url":"` + testFeed + `","entries":3,"completed_at":"2026-10-04T09:00:00Z"}`,
		"no feed":        `{"version":1,"feed_url":"","entries":3,"completed_at":"2026-10-04T09:00:00Z"}`,
		"no entries":     `{"version":1,"feed_url":"` + testFeed + `","entries":0,"completed_at":"2026-10-04T09:00:00Z"}`,
		"no time":        `{"version":1,"feed_url":"` + testFeed + `","entries":3}`,
	} {
		if err := db.setRawImportRecordForTest([]byte(raw)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ImportRecord(); !errors.Is(err, ErrNoSyncRecord) {
			t.Errorf("%s: an invalid record must read as none, got %v", name, err)
		}
	}
	if err := db.CompleteImport(SyncRecord{FeedURL: testFeed, Entries: 0, CompletedAt: time.Now()}); err == nil {
		t.Error("an empty import must never be certified")
	}
}

// The record is metadata: no hostname can read or match it.
func TestImportRecord_KeyIsUnreachableFromLookups(t *testing.T) {
	db := openT(t, t.TempDir())
	defer db.Close()
	if err := db.CompleteImport(SyncRecord{FeedURL: testFeed, Entries: 1, CompletedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{string(syncRecordKey), "x." + string(syncRecordKey)} {
		if cat, ok := db.Lookup(h); ok {
			t.Errorf("Lookup(%q) must not reach the record, got %q", h, cat)
		}
	}
}

func TestBulkWriteFault_LeavesAPartialStore(t *testing.T) {
	db := openT(t, t.TempDir())
	defer db.Close()
	db.SetBulkWriteFaultForTest(func(n int) error {
		if n == 3 {
			return errors.New("interrupted")
		}
		return nil
	})
	entries := map[string]string{"a.example": "X", "b.example": "X", "c.example": "X", "d.example": "X", "e.example": "X"}
	if err := db.BulkWrite(entries); err == nil {
		t.Fatal("the fault must fail the write")
	}
	n := 0
	for d := range entries {
		if _, ok := db.Lookup(d); ok {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("want exactly the 3 staged entries committed, got %d", n)
	}
}

// A process that dies without Close — mid-import, or right after a certified
// import — must leave, after reopen, a store whose record matches its data.
// The child is this test binary re-executed with CATDB_CRASH_CHILD set.
func TestImportRecord_ConsistentAfterUncleanExit(t *testing.T) {
	if mode := os.Getenv("CATDB_CRASH_CHILD"); mode != "" {
		crashChild(mode, os.Getenv("CATDB_CRASH_DIR"))
		return
	}
	for _, mode := range []string{"mid-import", "after-complete"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestImportRecord_ConsistentAfterUncleanExit$") //nolint:gosec // re-exec of this test binary
			cmd.Env = append(os.Environ(), "CATDB_CRASH_CHILD="+mode, "CATDB_CRASH_DIR="+dir)
			if out, err := cmd.CombinedOutput(); err == nil || cmd.ProcessState.ExitCode() != 7 {
				t.Fatalf("child must exit 7 without closing the store: %v\n%s", err, out)
			}
			db := openT(t, dir)
			defer db.Close()
			rec, err := db.ImportRecord()
			_, haveLast := db.Lookup("e199.example")
			switch mode {
			case "mid-import":
				if err == nil {
					t.Fatalf("an import cut off mid-write must leave no record, got %+v", rec)
				}
			case "after-complete":
				if err != nil || rec.Entries != 200 || !haveLast {
					t.Fatalf("a certified import must survive an unclean exit with its data: rec=%+v err=%v last=%v", rec, err, haveLast)
				}
			}
		})
	}
}

func crashChild(mode, dir string) {
	db, err := Open(dir)
	if err != nil {
		os.Exit(2)
	}
	entries := map[string]string{}
	for i := 0; i < 200; i++ {
		entries["e"+itoa(i)+".example"] = "Gambling"
	}
	if db.BeginImport() != nil {
		os.Exit(3)
	}
	if mode == "mid-import" {
		db.SetBulkWriteFaultForTest(func(n int) error {
			if n == 120 {
				os.Exit(7) // dies inside the import, store never closed
			}
			return nil
		})
	}
	if db.BulkWrite(entries) != nil {
		os.Exit(4)
	}
	if db.CompleteImport(SyncRecord{FeedURL: testFeed, Entries: 200, CompletedAt: time.Now()}) != nil {
		os.Exit(5)
	}
	os.Exit(7) // dies right after certifying, store never closed
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// The crash test above kills a PROCESS: its page cache survives, so it cannot
// exercise fsync ordering, and a unit test cannot cut the power. The ordering
// that makes a surviving record imply surviving data is therefore pinned
// structurally: CompleteImport fsyncs the data BEFORE writing the record and
// fsyncs again after; BeginImport fsyncs the withdrawal before returning.
func TestImportRecord_FsyncOrderIsStructural(t *testing.T) {
	src, err := os.ReadFile("catdb.go")
	if err != nil {
		t.Fatal(err)
	}
	body := func(fn string) string {
		s := string(src)
		i := strings.Index(s, "func (c *CommunityDB) "+fn+"(")
		if i < 0 {
			t.Fatalf("%s not found", fn)
		}
		j := strings.Index(s[i:], "\n}\n")
		return s[i : i+j]
	}
	ci := body("CompleteImport")
	first, upd := strings.Index(ci, "c.db.Sync()"), strings.Index(ci, "c.db.Update(")
	last := strings.LastIndex(ci, "c.db.Sync()")
	if first < 0 || upd < first || last < upd {
		t.Fatal("CompleteImport must Sync the data, THEN write the record, THEN Sync again")
	}
	bi := body("BeginImport")
	if d, s := strings.Index(bi, "txn.Delete(syncRecordKey)"), strings.Index(bi, "c.db.Sync()"); d < 0 || s < d {
		t.Fatal("BeginImport must Sync after withdrawing the record")
	}
}
