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
	shutdownHelperEnv       = "CULVERT_FEEDSYNC_SHUTDOWN_HELPER_DIR"
	shutdownHelperChattyEnv = "CULVERT_FEEDSYNC_SHUTDOWN_HELPER_CHATTY"
	childReady              = "FEEDSYNC-CHILD READY"
	childDone               = "FEEDSYNC-CHILD SHUTDOWN-DONE"
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
	if os.Getenv(shutdownHelperChattyEnv) != "" {
		// Regression fixture for the parent's deadline: print forever, ignore
		// SIGTERM, never exit. Output must not be able to renew the wait.
		signal.Ignore(syscall.SIGTERM)
		fmt.Println(childReady)
		for i := 0; ; i++ {
			fmt.Printf("chatter %d\n", i)
			time.Sleep(20 * time.Millisecond)
		}
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

// shutdownChild owns the child process and its output. The reader goroutine
// NEVER blocks on the test (lines go into a mutex-guarded slice and a 1-slot
// notify channel is poked without blocking), so cmd.Wait always runs once
// stdout closes; and every wait below is against ONE absolute deadline that
// output cannot renew (ASTRA 6359611097 #5).
type shutdownChild struct {
	cmd    *exec.Cmd
	dir    string
	mu     sync.Mutex
	lines  []string
	eof    bool
	notify chan struct{}
	exited chan struct{} // closed after cmd.Wait returns
	err    error         // cmd.Wait's result; read only after exited is closed
}

func (c *shutdownChild) poke() {
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

// startShutdownChild launches the helper and waits for READY by readyBy. Its
// cleanup KILLs and then JOINS the process (bounded): no child, reader or Wait
// goroutine outlives the test, including on a fatal path.
func startShutdownChild(t *testing.T, readyBy time.Time, extraEnv ...string) *shutdownChild {
	t.Helper()
	skipOffLinux(t)
	dir := filepath.Join(t.TempDir(), "catfeeddb")
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestShutdownHelperProcess$", "-test.count=1", "-test.v") // #nosec G204 -- re-execs this test binary with fixed arguments; no external input
	cmd.Env = append(append(os.Environ(), shutdownHelperEnv+"="+dir), extraEnv...)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c := &shutdownChild{cmd: cmd, dir: dir, notify: make(chan struct{}, 1), exited: make(chan struct{})}
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			c.mu.Lock()
			c.lines = append(c.lines, sc.Text())
			c.mu.Unlock()
			c.poke()
		}
		c.mu.Lock()
		c.eof = true
		c.mu.Unlock()
		c.poke()
		c.err = cmd.Wait()
		close(c.exited)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill() // no-op once exited
		select {
		case <-c.exited:
		case <-time.After(10 * time.Second):
			t.Errorf("teardown: the child did not exit within 10s of SIGKILL")
		}
	})
	c.expect(t, childReady, readyBy)
	return c
}

// expect waits until deadline for a line with the given prefix and returns it;
// a child FAIL line, an early exit or the deadline fails the test.
func (c *shutdownChild) expect(t *testing.T, prefix string, deadline time.Time) string {
	t.Helper()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	next := 0
	for {
		c.mu.Lock()
		pending, eof := c.lines[next:], c.eof
		next = len(c.lines)
		c.mu.Unlock()
		for _, l := range pending {
			if strings.HasPrefix(l, "FEEDSYNC-CHILD FAIL") {
				t.Fatal(l)
			}
			if strings.HasPrefix(l, prefix) {
				return l
			}
		}
		if eof {
			t.Fatalf("child exited before %q", prefix)
		}
		select {
		case <-c.notify:
		case <-timer.C:
			t.Fatalf("child did not print %q by the deadline", prefix)
		}
	}
}

// waitExit waits until deadline for the process to exit and returns cmd.Wait's
// result; a FAIL line the child printed meanwhile fails the test.
func (c *shutdownChild) waitExit(t *testing.T, deadline time.Time) error {
	t.Helper()
	if !c.exitedBy(deadline) {
		t.Fatalf("child did not exit by the deadline with an abandoned writer parked")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range c.lines {
		if strings.HasPrefix(l, "FEEDSYNC-CHILD FAIL") {
			t.Fatal(l)
		}
	}
	return c.err
}

// exitedBy reports whether the process exited by deadline. The deadline is
// absolute: nothing the child prints can extend it.
func (c *shutdownChild) exitedBy(deadline time.Time) bool {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-c.exited:
		return true
	case <-timer.C:
		return false
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
	c := startShutdownChild(t, time.Now().Add(30*time.Second))
	sent := time.Now()
	deadline := sent.Add(shutdownExitBound) // ONE absolute bound for report + exit
	if err := c.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := c.expect(t, childDone, deadline)
	if !strings.Contains(done, "writers=1 ") || !strings.HasSuffix(done, "err=<nil>") {
		t.Fatalf("shutdown report: %q (want exactly one writer, no hook error)", done)
	}
	err := c.waitExit(t, deadline)
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
	c := startShutdownChild(t, time.Now().Add(30*time.Second))
	if err := c.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err := c.waitExit(t, time.Now().Add(shutdownExitBound))
	if ee, ok := err.(*exec.ExitError); !ok || ee.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("child exit = %v, want killed by SIGKILL", err)
	}
	assertInterruptedImportRecovered(t, c.dir)
}

// TestShutdown_DeadlineIsNotRenewedByOutput pins the harness itself (ASTRA
// 6359611097 #5): a child that ignores SIGTERM and prints continuously must
// still be reported as not-exited at the ONE absolute deadline. The previous
// wait created its timer inside the output loop, so every line renewed it and
// this child would have been waited on forever.
func TestShutdown_DeadlineIsNotRenewedByOutput(t *testing.T) {
	c := startShutdownChild(t, time.Now().Add(30*time.Second), shutdownHelperChattyEnv+"=1")
	if err := c.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	// The wait runs under its own watchdog, so a renewing wait fails cleanly
	// here instead of hanging the test binary.
	start := time.Now()
	result := make(chan bool, 1)
	go func() { result <- c.exitedBy(start.Add(time.Second)) }()
	select {
	case exited := <-result:
		if exited {
			t.Fatal("the chatty child must not exit: it ignores SIGTERM")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("the deadline was renewed by output: a 1s deadline had not expired after 5s")
	}
	c.mu.Lock()
	n := len(c.lines)
	c.mu.Unlock()
	if n < 10 {
		t.Fatalf("the child printed only %d lines; the fixture did not exercise output during the wait", n)
	}
	// The cleanup registered by startShutdownChild KILLs and joins it.
}
