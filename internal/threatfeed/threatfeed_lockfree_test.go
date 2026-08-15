package threatfeed

import (
	"sync"
	"testing"
	"time"
)

// The per-request threat-feed gate must not read its enabled flag through the
// feed's RWMutex.
//
// These are PROPERTY tests, not timing tests. They do not measure how fast
// anything is — they hold the feed's exclusive lock and assert the gate still
// answers. A regression that puts `mu.RLock()` back into Enabled() makes the
// call block until the writer releases, which these detect deterministically on
// any hardware, unlike a ns/op threshold.
//
// The rationale for the property itself lives on the Feed.enabled field.

// waitForGate runs fn in a goroutine and reports whether it returned within
// the deadline. The caller is expected to be holding tf.mu, so on a regression
// fn is parked inside RLock; the caller must release the lock afterwards, which
// is why this returns rather than calling t.Fatal itself.
func waitForGate(fn func()) (returned bool) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
		return true
	case <-time.After(2 * time.Second):
		return false
	}
}

func TestFeedEnabled_IsLockFree(t *testing.T) {
	tf := newEnabledFeed()

	// Simulate a sync applying a fresh feed: the writer holds mu exclusively for
	// as long as it takes to swap in a several-hundred-thousand-entry map.
	tf.mu.Lock()
	ok := waitForGate(func() { _ = tf.Enabled() })
	tf.mu.Unlock()

	if !ok {
		t.Fatal("Enabled() blocked while the feed write lock was held — it is reading " +
			"through mu again. Enabled() is on the per-request proxy path and must stay " +
			"lock-free; see the Feed.enabled field comment.")
	}
}

// TestFeedCheck_DisabledTakesNoLock pins the default posture: with the threat
// feed off (no Init), neither per-request check may touch mu at all. This is
// the shape most deployments run, and it is the one where a lock acquisition is
// pure waste — there is nothing to look up.
func TestFeedCheck_DisabledTakesNoLock(t *testing.T) {
	tf := New() // not Init'd → disabled

	tf.mu.Lock()
	domainOK := waitForGate(func() { _, _ = tf.CheckDomain("www.example.com") })
	urlOK := waitForGate(func() { _, _ = tf.CheckURL("http://www.example.com/x") })
	tf.mu.Unlock()

	if !domainOK {
		t.Error("CheckDomain blocked on mu with the feed disabled — the gate must " +
			"short-circuit before any lock is taken")
	}
	if !urlOK {
		t.Error("CheckURL blocked on mu with the feed disabled — the gate must " +
			"short-circuit before any lock is taken")
	}
}

// TestFeedEnabled_ConcurrentWithSetAndCheck is the race-detector half: the flag
// is now written outside mu, so prove that readers, the writer, and the lookup
// path coexist cleanly. Verdict correctness is not asserted here (the flag is
// deliberately being flipped underneath); TestThreatFeed_Check* own that.
func TestFeedEnabled_ConcurrentWithSetAndCheck(t *testing.T) {
	tf := newEnabledFeed()
	tf.domains["malware.example.invalid"] = entry{Source: sourceURLhaus}

	const workers = 8
	stop := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = tf.Enabled()
				_, _ = tf.CheckDomain("malware.example.invalid")
				_, _ = tf.CheckURL("http://www.example.com/path")
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			tf.SetEnabledForTest(i%2 == 0)
		}
	}()

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Leave the feed in a defined state for anything reading it afterwards.
	tf.SetEnabledForTest(true)
	if !tf.Enabled() {
		t.Fatal("SetEnabledForTest(true) did not take effect")
	}
}

// TestFeedSetEnabledForTest_ReturnsPrevious guards the setter's contract after
// it moved from a mu-guarded read-then-write to an atomic Swap: callers use the
// returned value to restore the flag in cleanup.
func TestFeedSetEnabledForTest_ReturnsPrevious(t *testing.T) {
	tf := New()
	if old := tf.SetEnabledForTest(true); old {
		t.Fatalf("expected previous value false on a fresh feed, got %v", old)
	}
	if old := tf.SetEnabledForTest(false); !old {
		t.Fatalf("expected previous value true, got %v", old)
	}
	if tf.Enabled() {
		t.Fatal("feed still reports enabled after SetEnabledForTest(false)")
	}
}
