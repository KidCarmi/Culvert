package reqlog

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// isolateDeferred gives the test isolate()'s private state plus a clean
// deferred-open record, and an unopenable path (its directory does not exist).
func isolateDeferred(t *testing.T) (dir, path string) {
	t.Helper()
	isolate(t)
	resetDeferredForTest()
	t.Cleanup(resetDeferredForTest)
	dir = filepath.Join(t.TempDir(), "not-yet")
	return dir, filepath.Join(dir, "requests.jsonl")
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// The reproduction: Init fails at startup, the path stays unopenable for one
// attempt, the operator fixes it, and the next attempt publishes the sink with
// no restart. Live entries reach the file; nothing recorded before the open is
// replayed into it.
func TestDeferredOpen_CompletesAStartupFailure(t *testing.T) {
	dir, path := isolateDeferred(t)
	if err := Init(path, 7); err == nil {
		t.Fatal("precondition: the startup open must fail")
	}
	if !ArmDeferredOpen(path, 7) {
		t.Fatal("arming refused for a failed startup open")
	}
	Add(Entry{Host: "before.example"})

	if _, opened, err := TryDeferredOpen(); err == nil || opened {
		t.Fatalf("attempt on a still-missing directory: opened=%v err=%v, want an error", opened, err)
	}
	if DeferredOpenPending() != path {
		t.Fatal("a failed attempt disarmed the intent")
	}
	if PersistActive() {
		t.Fatal("persistence reported active after a failed attempt")
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	got, opened, err := TryDeferredOpen()
	if err != nil || !opened || got != path {
		t.Fatalf("attempt after the fix: path=%q opened=%v err=%v", got, opened, err)
	}
	if !PersistActive() || FilePath() != path {
		t.Fatalf("sink not published: active=%v path=%q", PersistActive(), FilePath())
	}
	if DeferredOpenPending() != "" {
		t.Fatal("the intent is still armed after a successful open")
	}

	Add(Entry{Host: "after.example"})
	Sync()
	s := readFile(t, path)
	if !strings.Contains(s, `"after.example"`) {
		t.Fatalf("a live entry did not reach the file:\n%s", s)
	}
	if strings.Contains(s, `"before.example"`) {
		t.Fatalf("an entry recorded before the open was replayed into the file:\n%s", s)
	}
	// The ring still holds both: nothing was taken away from the live view.
	if ring := Get(); len(ring) != 2 {
		t.Fatalf("ring holds %d entries, want 2", len(ring))
	}
	if _, opened, err := TryDeferredOpen(); opened || err != nil {
		t.Fatalf("a second attempt after success: opened=%v err=%v, want a no-op", opened, err)
	}
}

// Restraint: nothing armed means no file and no sink.
func TestDeferredOpen_UnarmedDoesNothing(t *testing.T) {
	dir, path := isolateDeferred(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if p, opened, err := TryDeferredOpen(); p != "" || opened || err != nil {
		t.Fatalf("unarmed attempt: path=%q opened=%v err=%v", p, opened, err)
	}
	if PersistActive() {
		t.Fatal("a sink was published with nothing armed")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a file was created with nothing armed (stat err=%v)", err)
	}
	if ArmDeferredOpen("", 0) {
		t.Fatal("an empty path was armed")
	}
}

// Shutdown: once Close has run, an armed intent publishes nothing even when
// the path becomes writable, and arming is refused.
func TestDeferredOpen_RefusedAfterClose(t *testing.T) {
	dir, path := isolateDeferred(t)
	if !ArmDeferredOpen(path, 0) {
		t.Fatal("arming refused")
	}
	if err := Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, opened, err := TryDeferredOpen(); opened || err != nil {
		t.Fatalf("attempt after Close: opened=%v err=%v, want a refusal", opened, err)
	}
	if PersistActive() {
		t.Fatal("a sink was published after Close")
	}
	if DeferredOpenPending() != "" {
		t.Fatal("the refusal did not disarm the intent")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the refused attempt created the file (stat err=%v)", err)
	}
	if ArmDeferredOpen(path, 0) {
		t.Fatal("arming accepted after Close")
	}
}

// A sink wired by someone else (a later successful Init) is never replaced.
func TestDeferredOpen_NeverReplacesALiveSink(t *testing.T) {
	dir, path := isolateDeferred(t)
	if !ArmDeferredOpen(path, 0) {
		t.Fatal("arming refused")
	}
	other := filepath.Join(t.TempDir(), "other.jsonl")
	if err := Init(other, 0); err != nil {
		t.Fatal(err)
	}
	if ArmDeferredOpen(path, 0) {
		t.Fatal("arming accepted while a sink is live")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, opened, err := TryDeferredOpen(); opened || err != nil {
		t.Fatalf("attempt with a live sink: opened=%v err=%v, want a refusal", opened, err)
	}
	if FilePath() != other {
		t.Fatalf("the live sink was replaced: path=%q, want %q", FilePath(), other)
	}
	if DeferredOpenPending() != "" {
		t.Fatal("the refusal did not disarm the intent")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the refused attempt created the armed file (stat err=%v)", err)
	}
}

// Concurrent attempts racing live traffic: exactly one publishes, and every
// entry added after that publish reaches the file exactly once.
func TestDeferredOpen_ConcurrentAttemptsPublishOnce(t *testing.T) {
	dir, path := isolateDeferred(t)
	if !ArmDeferredOpen(path, 0) {
		t.Fatal("arming refused")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	stopTraffic := make(chan struct{})
	var traffic sync.WaitGroup
	traffic.Add(1)
	go func() {
		defer traffic.Done()
		for {
			select {
			case <-stopTraffic:
				return
			default:
				Add(Entry{Host: "racing.example"})
			}
		}
	}()

	var opens sync.WaitGroup
	results := make(chan bool, 3)
	for range 3 {
		opens.Add(1)
		go func() {
			defer opens.Done()
			_, opened, err := TryDeferredOpen()
			if err != nil {
				t.Error(err)
			}
			results <- opened
		}()
	}
	opens.Wait()
	close(stopTraffic)
	traffic.Wait()
	close(results)
	n := 0
	for ok := range results {
		if ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d attempts published a sink, want exactly 1", n)
	}

	const marker = `"marker-after-open.example"`
	for range 50 {
		Add(Entry{Host: "marker-after-open.example"})
	}
	Sync()
	if c := strings.Count(readFile(t, path), marker); c != 50 {
		t.Fatalf("entries added after the open reached the file %d times, want 50", c)
	}
}
