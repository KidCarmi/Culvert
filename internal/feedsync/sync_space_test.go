package feedsync

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/catdb"
)

// A bulk write onto a full filesystem is not an error return in BadgerDB but
// a SIGBUS (sparse mmapped memtable/vlog), which kills the gateway. Measured
// on the appliance ENOSPC qualification (run 37119291924): the boot-time sync
// was writing 2.57M entries when the disk filled and the proxy died with
// `fatal error: fault` in badger's logFile.writeEntry. These gates pin the
// pre-write floor that turns the already-nearly-full case into a counted
// failure the last-good store survives.

func syncSpaceFixture(t *testing.T) (db *catdb.CommunityDB, url string) {
	t.Helper()
	tarData := makeTarGz(t, map[string]string{
		"blacklists/gambling/domains": "casino.example.com\npoker.example.com\n",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(tarData)
	}))
	t.Cleanup(srv.Close)
	var err error
	db, err = catdb.Open(t.TempDir())
	if err != nil {
		t.Fatalf("catdb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, srv.URL
}

// DEFECT GATE: below the floor the write never starts — nothing reaches the
// store, the round is a failure under its own bounded class, and the previous
// success timestamp is untouched.
func TestSync_RefusesTheWriteBelowTheFreeSpaceFloor(t *testing.T) {
	db, url := syncSpaceFixture(t)
	fs := New(db, url, time.Hour)
	fs.SetFreeSpaceProbe(func() (uint64, error) { return 64 << 20, nil })

	if fs.syncRound() {
		t.Fatal("a round that refused the write reported success")
	}
	if _, ok := db.Lookup("casino.example.com"); ok {
		t.Fatal("the write ran although the filesystem was below the floor")
	}
	h := fs.Health()
	if h.LastFailure != failDiskSpace || h.ConsecutiveFailures != 1 {
		t.Fatalf("health = %+v, want LastFailure=%q ConsecutiveFailures=1", h, failDiskSpace)
	}
	if !h.LastSuccess.IsZero() {
		t.Fatal("a refused round advanced the last-success timestamp")
	}
}

// CONTROL: enough space, or NO probe at all (a compatibility platform that
// cannot measure), leaves the sync exactly as it was.
func TestSync_WritesWhenSpaceIsAmpleOrNotMeasurable(t *testing.T) {
	cases := map[string]func() (uint64, error){
		"ample":    func() (uint64, error) { return 8 << 30, nil },
		"no probe": nil,
	}
	for name, probe := range cases {
		t.Run(name, func(t *testing.T) {
			db, url := syncSpaceFixture(t)
			fs := New(db, url, time.Hour)
			fs.SetFreeSpaceProbe(probe)
			if !fs.syncRound() {
				t.Fatalf("round failed: %+v", fs.Health())
			}
			if cat, ok := db.Lookup("casino.example.com"); !ok || cat != "Gambling" {
				t.Fatalf("lookup = (%q, %v), want (Gambling, true)", cat, ok)
			}
		})
	}
}

// The requirement scales with the write and never underflows.
func TestSyncSpaceNeeded(t *testing.T) {
	if got := syncSpaceNeeded(-5); got != syncFreeFloor {
		t.Fatalf("negative count: %d, want the bare floor %d", got, syncFreeFloor)
	}
	small, large := syncSpaceNeeded(1000), syncSpaceNeeded(2_570_579)
	if large <= small || large < 1<<30 {
		t.Fatalf("a 2.57M-entry write needs %d MiB, want > 1 GiB and > the small write", large>>20)
	}
}

// An INSTALLED probe that cannot measure must defer the write like one that
// would not fit (owner review of 5a86020): with a seeded last-known-good
// store, the failed round starts no write, leaves the existing entries and
// the last-success timestamp untouched, and records its own bounded class.
func TestSync_FailedMeasurementDefersTheWriteAndKeepsLastKnownGood(t *testing.T) {
	db, url := syncSpaceFixture(t)
	fs := New(db, url, time.Hour)
	fs.SetFreeSpaceProbe(func() (uint64, error) { return 8 << 30, nil })
	if !fs.syncRound() {
		t.Fatalf("seeding round failed: %+v", fs.Health())
	}
	seeded := fs.Health().LastSuccess
	if seeded.IsZero() {
		t.Fatal("seed did not record a success")
	}

	// A newer feed arrives, and the measurement now fails.
	newer := makeTarGz(t, map[string]string{"blacklists/gambling/domains": "newcasino.example.net\n"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(newer) }))
	t.Cleanup(srv.Close)
	fs.feedURL = srv.URL
	fs.SetFreeSpaceProbe(func() (uint64, error) { return 0, errors.New("statfs: input/output error") })

	if fs.syncRound() {
		t.Fatal("a round whose space measurement failed reported success")
	}
	if _, ok := db.Lookup("newcasino.example.net"); ok {
		t.Fatal("the bulk write started although free space could not be measured")
	}
	if cat, ok := db.Lookup("casino.example.com"); !ok || cat != "Gambling" {
		t.Fatalf("last-known-good entry changed: (%q, %v)", cat, ok)
	}
	h := fs.Health()
	if h.LastFailure != failDiskSpaceUnknown {
		t.Fatalf("LastFailure = %q, want %q", h.LastFailure, failDiskSpaceUnknown)
	}
	if !h.LastSuccess.Equal(seeded) {
		t.Fatalf("success timestamp moved: %v -> %v", seeded, h.LastSuccess)
	}
	if fs.StoreEmpty() {
		t.Fatal("a seeded store reports empty")
	}
}

// On first boot there is no previous data: the deferral must not claim that
// earlier category data keeps serving.
func TestSync_DeferredFirstSyncReportsNoCoverage(t *testing.T) {
	db, url := syncSpaceFixture(t)
	fs := New(db, url, time.Hour)
	fs.SetFreeSpaceProbe(func() (uint64, error) { return 0, errors.New("statfs: input/output error") })
	if fs.syncRound() {
		t.Fatal("deferred first sync reported success")
	}
	if !fs.StoreEmpty() {
		t.Fatal("an empty store must report empty so the diagnostics say coverage is missing")
	}
	if got := fs.Health().LastFailure; got != failDiskSpaceUnknown {
		t.Fatalf("LastFailure = %q", got)
	}
}
