package feedsync

// shutdown_subprocess_test.go — F-DISK-RECOVERY-1 item 4 (cancellation and
// bounded shutdown), Linux source-level evidence in a REAL child process.
//
// catdb.BulkWrite and badger's WriteBatch.Flush take no context, so an
// abandoned writer cannot be cancelled. That is an API limitation, not a reason
// to call cancellation N/A, so these tests establish what the process does
// instead when it is told to stop while such a writer is parked:
//   - no new work: a scheduler round racing the shutdown starts no second
//     writer (stop-admission is the writeAbandoned latch);
//   - bounded exit: SIGTERM runs the production close hook through
//     internal/shutdown, the store closes under the parked writer, and the
//     process exits 0 well inside the shutdown envelope. Nothing joins the
//     parked writer, and nothing needs to;
//   - durable state: the import-pending marker survives, and the next open
//     quarantines the half-written store (TriggerInterruptedImport);
//   - the same holds for SIGKILL, which runs no hook at all.
//
// The child replicates main_shutdown.go's "community-db-close" hook (same
// order, same call) rather than booting the binary. A service-manager stop,
// physical ENOSPC and a booted appliance remain later candidate gates.

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/catdb"
	"github.com/KidCarmi/Culvert/internal/shutdown"
)

const (
	shutdownHelperEnv = "CULVERT_FEEDSYNC_SHUTDOWN_HELPER_DIR"
	childReady        = "FEEDSYNC-CHILD READY"
	childDone         = "FEEDSYNC-CHILD SHUTDOWN-DONE"
	// shutdownExitBound is the test's bound on SIGTERM -> process exit. The
	// production envelope is Total + 2*grace = 51 s; the close itself is
	// milliseconds, so 10 s leaves room for -race on a loaded runner while
	// still failing on any join of the parked writer (whose own stall deadline
	// in production is 90 s).
	shutdownExitBound = 10 * time.Second
	// communityDBCloseOrder mirrors shutdownOrderCommunityDBClose (main_shutdown.go).
	communityDBCloseOrder = 120
)

// TestShutdownHelperProcess is the child. It runs only when the parent sets
// the helper env; otherwise it is a no-op.
func TestShutdownHelperProcess(t *testing.T) {
	dir := os.Getenv(shutdownHelperEnv)
	if dir == "" {
		t.Skip("helper process for the shutdown subprocess tests")
	}
	fail := func(format string, args ...any) {
		fmt.Printf("FEEDSYNC-CHILD FAIL "+format+"\n", args...)
		os.Exit(3)
	}

	withWatchdogTimings(t, time.Second, 20*time.Millisecond) // stall path, no degrade
	url, _, _ := controlledFeed(t, 30)
	db, err := catdb.Open(dir)
	if err != nil {
		fail("open: %v", err)
	}
	var writers atomic.Int64
	var parkOnce sync.Once
	forever := make(chan struct{}) // never closed: the writer is never released
	db.SetBulkWriteFaultForTest(func(n int) error {
		if n == 1 {
			writers.Add(1)
			parkOnce.Do(func() { <-forever })
		}
		return nil
	})
	s := New(db, url, 24*time.Hour)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)

	if s.syncRound() {
		fail("a stalled import must not count as a sync")
	}
	if !s.writeAbandoned.Load() || writers.Load() != 1 {
		fail("expected one parked, abandoned writer: abandoned=%v writers=%d", s.writeAbandoned.Load(), writers.Load())
	}
	fmt.Println(childReady)

	<-sigs
	// A scheduler tick racing the shutdown must not admit a second writer.
	if s.syncRound() {
		fail("a round during shutdown must stay quiesced")
	}
	time.Sleep(50 * time.Millisecond)
	if got := writers.Load(); got != 1 {
		fail("a second BulkWrite started during shutdown: writers=%d", got)
	}

	reg := shutdown.New(shutdown.Options{})
	reg.Register("community-db-close", communityDBCloseOrder, func(context.Context) error {
		return db.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	start := time.Now()
	runErr := reg.RunAll(ctx)
	cancel()
	// The parked writer is still parked here: the close did not wait for it.
	fmt.Printf("%s close_ms=%d writers=%d err=%v\n", childDone, time.Since(start).Milliseconds(), writers.Load(), runErr)
	os.Exit(0)
}

type shutdownChild struct {
	cmd   *exec.Cmd
	dir   string
	lines chan string
	exit  chan error
}

func startShutdownChild(t *testing.T) *shutdownChild {
	t.Helper()
	skipOffLinux(t)
	dir := filepath.Join(t.TempDir(), "catfeeddb")
	cmd := exec.Command(os.Args[0], "-test.run=^TestShutdownHelperProcess$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), shutdownHelperEnv+"="+dir)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c := &shutdownChild{cmd: cmd, dir: dir, lines: make(chan string, 64), exit: make(chan error, 1)}
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			c.lines <- sc.Text()
		}
		close(c.lines)
		c.exit <- cmd.Wait()
	}()
	t.Cleanup(func() { _ = cmd.Process.Kill() }) // backstop only; no-op after exit
	c.expect(t, childReady, 30*time.Second)
	return c
}

// expect waits for a line with the given prefix and returns it; a child FAIL
// line or an early exit fails the test.
func (c *shutdownChild) expect(t *testing.T, prefix string, within time.Duration) string {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case l, ok := <-c.lines:
			if !ok {
				t.Fatalf("child exited before %q", prefix)
			}
			if strings.HasPrefix(l, "FEEDSYNC-CHILD FAIL") {
				t.Fatal(l)
			}
			if strings.HasPrefix(l, prefix) {
				return l
			}
		case <-deadline:
			t.Fatalf("child did not print %q within %s", prefix, within)
		}
	}
}

func (c *shutdownChild) waitExit(t *testing.T, within time.Duration) error {
	t.Helper()
	for {
		select {
		case l, ok := <-c.lines:
			if ok && strings.HasPrefix(l, "FEEDSYNC-CHILD FAIL") {
				t.Fatal(l)
			}
			if !ok {
				c.lines = nil // drained; keep waiting on exit
			}
		case err := <-c.exit:
			return err
		case <-time.After(within):
			t.Fatalf("child did not exit within %s with an abandoned writer parked", within)
		}
	}
}

// assertInterruptedImportRecovered checks the durable half after the child is
// gone: the marker survived and the next open quarantines.
func assertInterruptedImportRecovered(t *testing.T, dir string) {
	t.Helper()
	if !markerPresent(t, dir) {
		t.Fatal("the import-pending marker must survive the process exit")
	}
	db, rec, err := catdb.OpenResilient(dir)
	if err != nil {
		t.Fatalf("reopen after exit: %v", err)
	}
	defer db.Close()
	if rec.Trigger != catdb.TriggerInterruptedImport || !rec.Quarantined {
		t.Fatalf("the next open must quarantine the interrupted import: trigger=%v quarantined=%v", rec.Trigger, rec.Quarantined)
	}
	if markerPresent(t, dir) {
		t.Fatal("recovery must clear the marker")
	}
}

func TestShutdown_SIGTERMExitsBoundedWithAbandonedWriter(t *testing.T) {
	c := startShutdownChild(t)
	sent := time.Now()
	if err := c.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := c.expect(t, childDone, shutdownExitBound)
	if !strings.Contains(done, "writers=1 ") || !strings.HasSuffix(done, "err=<nil>") {
		t.Fatalf("shutdown report: %q (want exactly one writer, no hook error)", done)
	}
	err := c.waitExit(t, shutdownExitBound)
	elapsed := time.Since(sent)
	if err != nil {
		t.Fatalf("child exit: %v (want status 0)", err)
	}
	if elapsed > shutdownExitBound {
		t.Fatalf("SIGTERM -> exit took %s, bound %s", elapsed, shutdownExitBound)
	}
	t.Logf("SIGTERM -> exit %s; %s", elapsed.Round(time.Millisecond), done)
	assertInterruptedImportRecovered(t, c.dir)
}

func TestShutdown_SIGKILLWithAbandonedWriterRecoversOnReopen(t *testing.T) {
	c := startShutdownChild(t)
	if err := c.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err := c.waitExit(t, shutdownExitBound)
	if ee, ok := err.(*exec.ExitError); !ok || ee.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("child exit = %v, want killed by SIGKILL", err)
	}
	assertInterruptedImportRecovered(t, c.dir)
}
