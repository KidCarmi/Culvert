package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Gates for the admin_roster_durability row's one live probe (Codex P2s
// 4319224642 and 4319224648 on PR #1601).

// Most tests change the disk between two reads of the row and expect the
// second read to see it, so the probe cache is off by default under test;
// TestRosterProbe_TTLReusesOneProbe turns it on.
func init() { rosterProbeTTL = 0 }

func setRosterProbeTiming(t *testing.T, ttl, wait time.Duration) {
	t.Helper()
	prevTTL, prevWait := rosterProbeTTL, rosterProbeWait
	rosterProbeTTL, rosterProbeWait = ttl, wait
	t.Cleanup(func() { rosterProbeTTL, rosterProbeWait = prevTTL, prevWait })
}

// countTargetStats counts the probe's stats of path (one per probe) and lets
// block, when non-nil, hold the first of them.
func countTargetStats(t *testing.T, path string, block <-chan struct{}, entered chan<- struct{}) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	prev := rosterProbeStat
	rosterProbeStat = func(name string) (os.FileInfo, error) {
		if name == path && n.Add(1) == 1 && block != nil {
			close(entered)
			<-block
		}
		return prev(name)
	}
	t.Cleanup(func() { rosterProbeStat = prev })
	return &n
}

// waitProbeIdle waits for an in-flight probe to finish, so a test does not
// leave its probe goroutine running into the next one.
func waitProbeIdle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rosterProbeFlight.mu.Lock()
		idle := rosterProbeFlight.pending == nil
		rosterProbeFlight.mu.Unlock()
		if idle {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("the roster probe did not finish")
}

// TestRosterProbe_StalledStorageIsBoundedAndCoalesced: while the probe's
// stat is stuck (a stalled NFS or FUSE mount), N concurrent requests start
// exactly ONE probe, every request returns within the bound, and each
// reports the storage as not responding — never ok. Removing the bound, or
// the coalescing, fails this test.
func TestRosterProbe_StalledStorageIsBoundedAndCoalesced(t *testing.T) {
	_, path := savedRosterCfg(t)
	const wait = 150 * time.Millisecond
	setRosterProbeTiming(t, 0, wait)
	block, entered := make(chan struct{}), make(chan struct{})
	probes := countTargetStats(t, path, block, entered)
	t.Cleanup(func() {
		close(block)
		waitProbeIdle(t)
	})

	const n = 16
	var wg sync.WaitGroup
	rows := make([]OperatorContractCheck, n)
	took := make([]time.Duration, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start := time.Now()
			rows[i] = checkAdminRosterDurability()
			took[i] = time.Since(start)
		}(i)
	}
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("requests did not return while the storage was stalled")
	}
	select {
	case <-entered:
	default:
		t.Fatal("the probe never reached the filesystem")
	}
	if got := probes.Load(); got != 1 {
		t.Errorf("%d probes reached the stalled filesystem for %d requests, want exactly 1", got, n)
	}
	for i, row := range rows {
		if row.Status != diagWarn || row.Message != rosterTargetNotResponding {
			t.Errorf("request %d: row = %+v, want warn %q", i, row, rosterTargetNotResponding)
		}
		if took[i] > wait+time.Second {
			t.Errorf("request %d took %v, want about the %v bound", i, took[i], wait)
		}
	}
}

// TestRosterProbe_TTLReusesOneProbe: repeated reads within the TTL share one
// probe; a Culvert save (a new write generation) is probed afresh. Disabling
// the cache fails this test.
func TestRosterProbe_TTLReusesOneProbe(t *testing.T) {
	c, path := savedRosterCfg(t)
	setRosterProbeTiming(t, time.Minute, 2*time.Second)
	probes := countTargetStats(t, path, nil, nil)
	for i := 0; i < 5; i++ {
		if row := checkAdminRosterDurability(); row.Status != diagOK {
			t.Fatalf("row = %+v, want ok", row)
		}
	}
	if got := probes.Load(); got != 1 {
		t.Errorf("%d probes for 5 reads within the TTL, want 1", got)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatal(err)
	}
	_ = checkAdminRosterDurability()
	if got := probes.Load(); got != 2 {
		t.Errorf("%d probes after a save, want 2 (a new write generation is re-probed)", got)
	}
}

// TestRosterProbe_ParentLosesWriteCapability: after a landed save, the
// directory stops allowing the next one — a chmod 0555 (real when not root;
// root bypasses mode bits, so injected), an ACL revocation or a read-only
// remount (faccessat's EACCES or EROFS), or statfs reporting ST_RDONLY. The
// row warns with its own message. Dropping the faccessat check, or the statfs
// check, fails this test.
func TestRosterProbe_ParentLosesWriteCapability(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"chmod 0555": func(t *testing.T, dir string) {
			if os.Geteuid() != 0 {
				if err := os.Chmod(dir, 0o555); err != nil { // #nosec G302 -- the condition under test
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // #nosec G302 -- restore for cleanup
				return
			}
			injectParentAccess(t, errEACCES) // root bypasses the mode bits
		},
		"ACL revoked (faccessat EACCES)":      func(t *testing.T, _ string) { injectParentAccess(t, errEACCES) },
		"read-only remount (faccessat EROFS)": func(t *testing.T, _ string) { injectParentAccess(t, errEROFS) },
		"read-only mount (statfs ST_RDONLY)":  func(t *testing.T, _ string) { injectParentReadOnly(t) },
	}
	for name, revoke := range cases {
		t.Run(name, func(t *testing.T) {
			_, path := savedRosterCfg(t)
			if row := checkAdminRosterDurability(); row.Status != diagOK {
				t.Fatalf("precondition: row = %+v, want ok", row)
			}
			revoke(t, filepath.Dir(path))
			row := checkAdminRosterDurability()
			if row.Status != diagWarn || row.Message != rosterParentNotWritable {
				t.Fatalf("row = %+v, want warn %q", row, rosterParentNotWritable)
			}
			if !strings.Contains(row.OperatorAction, "-ui-users-file") || !strings.Contains(row.OperatorAction, "read-write") {
				t.Errorf("action = %q, want the restore-write-permission remedy", row.OperatorAction)
			}
		})
	}
}
