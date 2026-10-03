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

// CONTROL: enough space, or a probe that cannot answer, leaves the sync
// exactly as it was — an unmeasurable platform must not lose category data.
func TestSync_WritesWhenSpaceIsAmpleOrUnknown(t *testing.T) {
	cases := map[string]func() (uint64, error){
		"ample":    func() (uint64, error) { return 8 << 30, nil },
		"unknown":  func() (uint64, error) { return 0, errors.New("statfs: not supported") },
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
