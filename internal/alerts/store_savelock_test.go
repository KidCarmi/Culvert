package alerts

// store_savelock_test.go — persistence must never run under mu.
//
// mu guards the in-memory hook set that HasSubscriber reads. The proxy consults
// HasSubscriber SYNCHRONOUSLY on the block and DNS-failure request paths, so any
// reader that can block behind an fsync is a request-latency stall: an operator
// saving a webhook on a degraded volume would otherwise pause every blocked
// request for the duration of the write.

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newFileStore(t *testing.T) *Store {
	t.Helper()
	as := &Store{}
	as.Init(filepath.Join(t.TempDir(), "alerts.json"))
	return as
}

// TestSave_DoesNotHoldMuDuringIO is the core invariant. It stalls persistence by
// holding saveMu, then asserts that a mutation still releases mu — so readers
// keep answering while a write is stuck. Before the split, Add held mu across
// AtomicWrite and this would deadlock until the timeout.
// The saveBarrier seam makes this deterministic rather than a scheduling race:
// the test only probes the reader once persistence has provably begun. Without
// it the reader could finish before the writer ever took mu, and an
// implementation that holds mu across fsync would pass by luck.
func TestSave_DoesNotHoldMuDuringIO(t *testing.T) {
	as := newFileStore(t)
	as.Add(Webhook{Name: "seed", URL: "http://example.invalid", Events: []string{"e"}, Enabled: true})

	var once sync.Once
	entered := make(chan struct{}) // closed once persistence has started
	release := make(chan struct{}) // held closed until the test lets it finish
	saveBarrier = func() {
		once.Do(func() { close(entered) })
		<-release
	}
	t.Cleanup(func() { saveBarrier = nil })

	stalled := make(chan struct{})
	go func() {
		as.Add(Webhook{Name: "second", URL: "http://example.invalid", Events: []string{"e"}, Enabled: true})
		close(stalled)
	}()

	<-entered // persistence is now in flight and parked

	// mu MUST already be released, so a reader has to complete promptly.
	//
	// The probe is List, NOT HasSubscriber. HasSubscriber answers from the
	// atomically published subscription index and takes no lock at all
	// (subscriptions.go), so it completes promptly whether or not mu is held
	// and cannot observe this invariant — when it was the only probe here, an
	// implementation that persisted under mu passed both tests in this file.
	// List takes mu.RLock, so it is the reader that still proves the point;
	// the lock-free answer is asserted separately below.
	done := make(chan int, 1)
	go func() { done <- len(as.List()) }()

	select {
	case got := <-done:
		if got == 0 {
			t.Error("List returned no webhooks while one was seeded")
		}
	case <-time.After(5 * time.Second):
		t.Error("List blocked while a save was in flight — persistence is holding mu across disk I/O, " +
			"which stalls the proxy block and DNS-failure request paths")
	}

	// The index reader must also still answer, and must answer without mu.
	if !as.HasSubscriber("e") {
		t.Error("HasSubscriber returned false for a subscribed event")
	}

	close(release)
	select {
	case <-stalled:
	case <-time.After(5 * time.Second):
		t.Fatal("Add did not complete after the writer was released")
	}
}

// TestSave_ReadersProceedDuringConcurrentMutations is the concurrency arm: a
// steady stream of mutations must not starve readers, and the whole thing must
// be race-clean under -race.
func TestSave_ReadersProceedDuringConcurrentMutations(t *testing.T) {
	as := newFileStore(t)
	as.Add(Webhook{Name: "seed", URL: "http://example.invalid", Events: []string{"e"}, Enabled: true})

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			h := as.Add(Webhook{Name: "churn", URL: "http://example.invalid", Events: []string{"other"}, Enabled: true})
			as.Update(h.ID, Webhook{Name: "churn2", URL: "http://example.invalid", Events: []string{"other"}, Enabled: true})
			as.Delete(h.ID)
		}
		close(stop)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// List takes mu.RLock, so this arm starves if a mutation holds mu
			// across its fsync; HasSubscriber alone would not (see
			// TestSave_DoesNotHoldMuDuringIO for why).
			if len(as.List()) == 0 {
				t.Error("List saw no webhooks during concurrent mutation")
				return
			}
			if !as.HasSubscriber("e") {
				t.Error("seed subscriber vanished during concurrent mutation")
				return
			}
		}
	}()

	wg.Wait()
	if !as.HasSubscriber("e") {
		t.Fatal("seed subscriber missing after churn")
	}
}

// TestSave_NewestSnapshotWins pins the ordering contract that replaced lock
// ordering: writers may reach the disk out of order, so a stale snapshot must be
// dropped rather than overwrite a newer one. Reloading from disk must therefore
// observe the final in-memory state.
func TestSave_NewestSnapshotWins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alerts.json")
	as := &Store{}
	as.Init(path)

	h := as.Add(Webhook{Name: "first", URL: "http://example.invalid", Events: []string{"e"}, Enabled: true})
	as.Update(h.ID, Webhook{Name: "final", URL: "http://example.invalid", Events: []string{"e"}, Enabled: true})

	reloaded := &Store{}
	reloaded.Init(path)
	got := reloaded.List()
	if len(got) != 1 {
		t.Fatalf("reloaded %d webhooks, want 1", len(got))
	}
	if got[0].Name != "final" {
		t.Errorf("reloaded webhook Name = %q, want %q — a stale snapshot overwrote the newer one", got[0].Name, "final")
	}
}

// TestSave_StaleSnapshotDropped exercises the sequence guard directly: a closure
// captured earlier must not clobber a newer snapshot that already landed.
func TestSave_StaleSnapshotDropped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alerts.json")
	as := &Store{}
	as.Init(path)

	// Capture an OLD snapshot (seq 1) without running it yet.
	as.mu.Lock()
	as.hooks = []Webhook{{ID: "1", Name: "old", Events: []string{"e"}, Enabled: true}}
	oldPersist := as.beginSaveLocked()
	as.mu.Unlock()

	// A newer snapshot (seq 2) lands first.
	as.mu.Lock()
	as.hooks = []Webhook{{ID: "1", Name: "new", Events: []string{"e"}, Enabled: true}}
	newPersist := as.beginSaveLocked()
	as.mu.Unlock()
	newPersist()

	// The stale writer must now be a no-op.
	oldPersist()

	reloaded := &Store{}
	reloaded.Init(path)
	got := reloaded.List()
	if len(got) != 1 {
		t.Fatalf("reloaded %d webhooks, want 1", len(got))
	}
	if got[0].Name != "new" {
		t.Errorf("reloaded Name = %q, want %q — the stale snapshot was not dropped", got[0].Name, "new")
	}
}
