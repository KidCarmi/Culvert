package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// Deferred open of a configured audit log whose startup open failed
// (deferred.go). The gates prove both the action (the file opens, the gap is
// written once and in order) and the restraint (nothing happens unless armed,
// after Close, or when another sink is live).

// isolateDeferred gives a test clean ring/persistence/deferred/write-error
// state and closes whatever sink the test opened.
func isolateDeferred(t *testing.T) {
	t.Helper()
	restoreErr := ResetWriteErrorsForTest()
	restore := ResetForTest()
	t.Cleanup(func() {
		mu.Lock()
		c := persistC
		mu.Unlock()
		if c != nil {
			_ = c.Close()
		}
		restore()
		restoreErr()
	})
}

// unopenablePath returns a path whose parent directory does not exist yet, so
// Init fails exactly as it does for a not-yet-provisioned volume.
func unopenablePath(t *testing.T) (dir, path string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "not-yet")
	return dir, filepath.Join(dir, "audit.jsonl")
}

func entry(i int) Entry {
	return Entry{TS: int64(i), Action: "deferred.test", Object: fmt.Sprintf("obj-%d", i)}
}

func fileObjects(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("invalid line %q: %v", line, err)
		}
		out = append(out, e.Object)
	}
	return out
}

func TestDeferredOpen_StartupFailureIsCompletedAndGapWrittenInOrder(t *testing.T) {
	isolateDeferred(t)
	dir, path := unopenablePath(t)

	if err := Init(path); err == nil {
		t.Fatal("precondition: Init must fail while the directory is missing")
	}
	if PersistActive() {
		t.Fatal("precondition: no sink after a failed Init")
	}
	if !ArmDeferredOpen(path) {
		t.Fatal("ArmDeferredOpen refused a configured path with no live sink")
	}
	for i := 0; i < 3; i++ {
		Add(entry(i))
	}

	// Still not openable: the attempt fails, stays armed, keeps the backlog.
	if _, ok, err := TryDeferredOpen(); ok || err == nil {
		t.Fatalf("attempt on a missing directory: ok=%v err=%v, want failure", ok, err)
	}
	if DeferredOpenPending() != path {
		t.Fatal("a failed attempt disarmed the deferred open")
	}
	Add(entry(3))

	// The operator fixes the volume. No restart.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	res, ok, err := TryDeferredOpen()
	if err != nil || !ok {
		t.Fatalf("attempt after the fix: ok=%v err=%v", ok, err)
	}
	if res.Path != path || res.Backfilled != 4 || res.Dropped != 0 {
		t.Fatalf("result = %+v, want path=%s backfilled=4 dropped=0", res, path)
	}
	if !PersistActive() || DeferredOpenPending() != "" {
		t.Fatal("after success the sink must be live and nothing pending")
	}
	Add(entry(4)) // a live write lands after the backlog

	got := fileObjects(t, path)
	want := []string{"obj-0", "obj-1", "obj-2", "obj-3", "obj-4"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("file = %v, want %v (each entry once, in Add order)", got, want)
	}
	if WriteErrors() != 0 {
		t.Fatalf("WriteErrors = %d, want 0 (nothing was lost)", WriteErrors())
	}
	// A second attempt has nothing to do.
	if _, ok, err := TryDeferredOpen(); ok || err != nil {
		t.Fatalf("second attempt: ok=%v err=%v, want a no-op", ok, err)
	}
}

func TestDeferredOpen_NotArmedKeepsTheOldBehaviour(t *testing.T) {
	isolateDeferred(t)
	dir, path := unopenablePath(t)
	if err := Init(path); err == nil {
		t.Fatal("precondition: Init must fail")
	}
	// A one-shot command (prepare-downgrade) refuses here and never arms.
	Add(entry(0))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := TryDeferredOpen(); ok || err != nil {
		t.Fatalf("unarmed attempt: ok=%v err=%v, want a no-op", ok, err)
	}
	if PersistActive() {
		t.Fatal("an unarmed attempt published a sink")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("an unarmed attempt created the file (stat err=%v)", err)
	}
	mu.Lock()
	n := len(backlog)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("backlog = %d entries without an armed deferred open", n)
	}
}

func TestDeferredOpen_RefusedAfterClose(t *testing.T) {
	isolateDeferred(t)
	dir, path := unopenablePath(t)
	if !ArmDeferredOpen(path) {
		t.Fatal("arm refused")
	}
	Add(entry(0))
	if err := Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := TryDeferredOpen(); ok || err != nil {
		t.Fatalf("attempt after Close: ok=%v err=%v, want a no-op", ok, err)
	}
	if PersistActive() {
		t.Fatal("a sink was published after the shutdown hook closed the trail")
	}
	if ArmDeferredOpen(path) {
		t.Fatal("ArmDeferredOpen accepted after Close")
	}
}

func TestDeferredOpen_DisarmsWhenAnotherSinkIsLive(t *testing.T) {
	isolateDeferred(t)
	dir, path := unopenablePath(t)
	if !ArmDeferredOpen(path) {
		t.Fatal("arm refused")
	}
	Add(entry(0))
	var live recordingWriter
	restore := SetPersistForTest(&live)
	defer restore()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := TryDeferredOpen(); ok || err != nil {
		t.Fatalf("attempt with a live sink: ok=%v err=%v, want a no-op", ok, err)
	}
	mu.Lock()
	same := persist == &live
	pending := deferredPath
	mu.Unlock()
	if !same {
		t.Fatal("the deferred open replaced a live sink")
	}
	if pending != "" {
		t.Fatal("still armed although another sink is live")
	}
	if _, err := os.Stat(path); err == nil {
		// The file may have been created by the open, but nothing was written.
		if got := fileObjects(t, path); len(got) != 0 {
			t.Fatalf("backlog written to a superseded file: %v", got)
		}
	}
}

func TestDeferredOpen_EvictedBacklogIsCharged(t *testing.T) {
	isolateDeferred(t)
	dir, path := unopenablePath(t)
	if !ArmDeferredOpen(path) {
		t.Fatal("arm refused")
	}
	const extra = 3
	for i := 0; i < MaxRing+extra; i++ {
		Add(entry(i))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	res, ok, err := TryDeferredOpen()
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if res.Backfilled != MaxRing || res.Dropped != extra {
		t.Fatalf("result = %+v, want backfilled=%d dropped=%d", res, MaxRing, extra)
	}
	if WriteErrors() != extra {
		t.Fatalf("WriteErrors = %d, want %d: evicted entries never reached the durable record", WriteErrors(), extra)
	}
	got := fileObjects(t, path)
	if len(got) != MaxRing || got[0] != fmt.Sprintf("obj-%d", extra) || got[len(got)-1] != fmt.Sprintf("obj-%d", MaxRing+extra-1) {
		t.Fatalf("file holds %d entries [%s … %s], want the newest %d", len(got), got[0], got[len(got)-1], MaxRing)
	}
}

func TestDeferredOpen_ConcurrentAddsAndAttemptsWriteEachEntryOnce(t *testing.T) {
	isolateDeferred(t)
	dir, path := unopenablePath(t)
	if !ArmDeferredOpen(path) {
		t.Fatal("arm refused")
	}
	const before, writers, perWriter = 50, 4, 50
	for i := 0; i < before; i++ {
		Add(entry(i))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var opens sync.Map
	start := make(chan struct{})
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < perWriter; i++ {
				Add(entry(1000 + w*perWriter + i))
			}
		}(w)
	}
	for a := 0; a < 3; a++ {
		wg.Add(1)
		go func(a int) {
			defer wg.Done()
			<-start
			if _, ok, _ := TryDeferredOpen(); ok {
				opens.Store(a, true)
			}
		}(a)
	}
	close(start)
	wg.Wait()

	n := 0
	opens.Range(func(_, _ any) bool { n++; return true })
	if n != 1 {
		t.Fatalf("%d attempts reported opening the file, want exactly 1", n)
	}
	got := fileObjects(t, path)
	seen := map[string]int{}
	for _, o := range got {
		seen[o]++
	}
	if len(got) != before+writers*perWriter || len(seen) != len(got) {
		t.Fatalf("file holds %d lines / %d distinct, want %d each (every entry exactly once)", len(got), len(seen), before+writers*perWriter)
	}
	for i := 0; i < before; i++ {
		if got[i] != fmt.Sprintf("obj-%d", i) {
			t.Fatalf("line %d = %s: the pre-open backlog must precede every later entry, in order", i, got[i])
		}
	}
}
