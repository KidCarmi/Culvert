package urlcat

// Isolated deterministic fixtures for paths whose coverage previously depended
// on timing; see roadmap/CI-REDESIGN.md stage 5B.
//
// ContentFingerprint's second memo check (after taking fpMu) is reached only
// when a reader misses the memo, queues on fpMu, and ANOTHER reader publishes
// the fingerprint while it waits — i.e. only when two readers overlap inside
// the single-flight. The concurrent fingerprint gates create that overlap
// probabilistically; the fixture below constructs it on purpose.

import (
	"bytes"
	"runtime"
	"testing"
	"time"
)

// goroutineParkedIn reports whether some goroutine's stack contains every one
// of frames. Used to observe that a goroutine has reached (and is blocked at) a
// specific lock inside ContentFingerprint, without sleeping.
func goroutineParkedIn(frames ...string) bool {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	for _, g := range bytes.Split(buf, []byte("\n\n")) {
		all := true
		for _, f := range frames {
			if !bytes.Contains(g, []byte(f)) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func waitParkedIn(t *testing.T, what string, frames ...string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !goroutineParkedIn(frames...) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		runtime.Gosched()
	}
}

// Pins urlcat.go ContentFingerprint's re-check under fpMu
// `if c := s.fp.Load(); c != nil && c.rev == s.rev.Load() { return c.fp }` —
// a queued reader serves the value a concurrent reader published instead of
// recomputing it.
//
// Determinism: the test holds the store's write lock (standing in for a
// writer inside its critical section — it mutates nothing), so reader A takes
// fpMu and parks on s.mu.RLock; reader B then misses the memo and parks on
// fpMu. Both parks are observed from goroutine stacks before the write lock is
// released, so A necessarily publishes before B's re-check runs, and nothing
// advances s.rev in between — B's re-check can only hit.
func TestIsolation_ContentFingerprintQueuedReaderServesPublishedMemo(t *testing.T) {
	s := New([]*Entry{
		{Name: "Dev Tools", Hosts: []string{"code.example", "*.git.example"}},
		{Name: "News", Hosts: []string{"news.example"}, BuiltIn: true},
	})
	if s.fp.Load() != nil {
		t.Fatal("fixture precondition: the memo must start empty")
	}
	want := computeFingerprint(s.entries)
	rev := s.rev.Load()

	s.mu.Lock() // no mutation: only holds readers at the computation point
	unlocked := false
	defer func() {
		if !unlocked {
			s.mu.Unlock()
		}
	}()

	gotA := make(chan string, 1)
	go func() { gotA <- s.ContentFingerprint() }()
	waitParkedIn(t, "reader A to hold fpMu and park on the store read lock",
		"urlcat.(*Store).ContentFingerprint", "sync.(*RWMutex).RLock")

	gotB := make(chan string, 1)
	go func() { gotB <- s.ContentFingerprint() }()
	waitParkedIn(t, "reader B to miss the memo and park on fpMu",
		"urlcat.(*Store).ContentFingerprint", "sync.(*Mutex).Lock")

	s.mu.Unlock()
	unlocked = true

	a, b := <-gotA, <-gotB
	if a != want || b != want {
		t.Fatalf("fingerprints = (%q, %q), want both %q", a, b, want)
	}
	c := s.fp.Load()
	if c == nil || c.rev != rev || c.fp != want {
		t.Fatalf("memo = %+v, want {rev:%d fp:%q}", c, rev, want)
	}
}
