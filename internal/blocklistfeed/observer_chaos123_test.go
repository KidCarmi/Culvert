package blocklistfeed

// observer_chaos123_test.go — the engine half of CHAOS-123: the push the
// freshness plane depends on, and the three properties that make it safe to
// call from inside a feed round.

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// stubMerger is a Merger that records nothing: these tests assert the
// observer contract, not the merge.
type stubMerger struct{ added int }

func (m *stubMerger) MergeFromLines(lines []string, source string) int { return m.added }

// loopbackFeed is refused by the inline SSRF guard in fetchFeedLines, so a
// round fails deterministically with no network access at all.
const loopbackFeed = "http://127.0.0.1:1/chaos123.txt"

func TestChaos123_FailedRoundNotifiesObserverWithLadderCount(t *testing.T) {
	t.Cleanup(func() { SetSyncObserver(nil) })
	bs := New(&stubMerger{})
	bs.SetFeed(loopbackFeed, time.Hour)

	var got []SyncOutcome
	var mu sync.Mutex
	SetSyncObserver(func(o SyncOutcome) {
		mu.Lock()
		got = append(got, o)
		mu.Unlock()
	})

	for i := 0; i < 2; i++ {
		if _, err := bs.SyncFeed(loopbackFeed); err == nil {
			t.Fatalf("round %d: expected the loopback feed to fail", i)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("want one outcome per round, got %d: %+v", len(got), got)
	}
	for i, o := range got {
		if o.OK {
			t.Errorf("outcome %d: a failed round must report OK=false", i)
		}
		if !o.LastSync.IsZero() {
			t.Errorf("outcome %d: LastSync must stay zero for a feed that has never succeeded, got %v", i, o.LastSync)
		}
		if o.Interval != time.Hour {
			t.Errorf("outcome %d: want the configured interval, got %v", i, o.Interval)
		}
	}
	// The ladder count is what tells the plane "this is a run, not a blip",
	// so it must ADVANCE across rounds rather than be a constant 1.
	if got[0].ConsecutiveFailures != 1 || got[1].ConsecutiveFailures != 2 {
		t.Errorf("want consecutive failures 1 then 2, got %d then %d",
			got[0].ConsecutiveFailures, got[1].ConsecutiveFailures)
	}
}

// TestChaos123_SuccessfulRoundNotifiesThroughTheClockSeam pins both halves of
// the success path: the observer sees OK with the feed's last success, and that
// timestamp comes from the Syncer's clock seam rather than from time.Now().
//
// The seam matters because the freshness plane measures staleness against 2x a
// 24-hour default interval. While the success path used time.Now() directly,
// the only way to assert the staleness contract was to sleep past a day.
func TestChaos123_SuccessfulRoundNotifiesThroughTheClockSeam(t *testing.T) {
	t.Cleanup(func() { SetSyncObserver(nil) })
	fake := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	bs := New(&stubMerger{added: 3})
	bs.now = func() time.Time { return fake }

	srv := newFeedServer(t, "blocked.example.com\n")
	bs.SetFeed(srv, 6*time.Hour)

	var got SyncOutcome
	var called int
	SetSyncObserver(func(o SyncOutcome) { got = o; called++ })

	if _, err := bs.SyncFeed(srv); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if called != 1 {
		t.Fatalf("want exactly one observer call, got %d", called)
	}
	if !got.OK {
		t.Error("a clean round must report OK=true")
	}
	if !got.LastSync.Equal(fake) {
		t.Errorf("LastSync must come from the Syncer clock seam: want %v, got %v", fake, got.LastSync)
	}
	if got.ConsecutiveFailures != 0 {
		t.Errorf("a clean round resets the ladder, got %d", got.ConsecutiveFailures)
	}
	// Feeds() must agree with the pushed outcome — one source of truth.
	fs := bs.Feeds()
	if len(fs) != 1 || !fs[0].LastSync.Equal(fake) {
		t.Errorf("Feeds() must report the same last success: %+v", fs)
	}
}

// TestChaos123_ObserverPanicIsContainedAndDoesNotFailTheRound is the
// containment contract. Without the recover in notifySyncObserver the panic
// would reach the scheduler's obs.SafeCall, which would charge it to the FEED:
// an observability bug would become a feed that costs a tick and reports
// itself unhealthy. The plane that watches the feed must not be able to break
// the feed.
func TestChaos123_ObserverPanicIsContainedAndDoesNotFailTheRound(t *testing.T) {
	t.Cleanup(func() { SetSyncObserver(nil) })
	bs := New(&stubMerger{added: 1})
	srv := newFeedServer(t, "panic.example.com\n")
	bs.SetFeed(srv, time.Hour)

	SetSyncObserver(func(SyncOutcome) { panic("observer blew up") })

	added, err := bs.SyncFeed(srv)
	if err != nil {
		t.Fatalf("the round must still succeed: %v", err)
	}
	if added != 1 {
		t.Fatalf("the merge must still be charged: added=%d", added)
	}
	// And the feed's own state must be the state of a SUCCESSFUL round, not
	// of a contained fault.
	fs := bs.Feeds()
	if len(fs) != 1 || fs[0].LastError != "" || fs[0].LastSync.IsZero() {
		t.Fatalf("the round must be recorded as clean: %+v", fs)
	}
}

// TestChaos123_ObserverIsCalledWithoutHoldingTheLock is the deadlock gate.
//
// The production observer reads the plane's posture, which calls Feeds() and
// therefore takes Syncer.mu for reading. sync.RWMutex is not reentrant against
// a waiting writer, so an observer invoked from inside the critical section
// would wedge the round — and the round runs on the shared scheduler tick, so
// one wedged feed stops every feed on the node.
//
// Asserted on both paths, because they unlock at different points.
func TestChaos123_ObserverIsCalledWithoutHoldingTheLock(t *testing.T) {
	t.Cleanup(func() { SetSyncObserver(nil) })

	for _, tc := range []struct {
		name string
		url  func(t *testing.T) string
		ok   bool
	}{
		{"failed round", func(*testing.T) string { return loopbackFeed }, false},
		{"clean round", func(t *testing.T) string { return newFeedServer(t, "x.example.com\n") }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bs := New(&stubMerger{added: 1})
			feedURL := tc.url(t)
			bs.SetFeed(feedURL, time.Hour)

			reached := make(chan int, 1)
			SetSyncObserver(func(SyncOutcome) {
				// Both lock modes: the plane reads through Feeds() (RLock),
				// and a future writer-side seam would take the write lock.
				n := len(bs.Feeds())
				bs.SetFeed(feedURL, time.Hour)
				reached <- n
			})

			done := make(chan struct{})
			go func() {
				defer close(done)
				_, err := bs.SyncFeed(feedURL)
				if (err == nil) != tc.ok {
					t.Errorf("unexpected round outcome: err=%v", err)
				}
			}()

			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the round did not finish: the observer was called while Syncer.mu was held")
			}
			select {
			case n := <-reached:
				if n != 1 {
					t.Errorf("observer saw %d feeds, want 1", n)
				}
			default:
				t.Fatal("the observer was never called")
			}
		})
	}
}

// TestChaos123_NilObserverIsTheDefaultAndClearable — a round on a node with no
// plane armed (every test binary, and main before the startup slice runs) must
// not fault.
func TestChaos123_NilObserverIsTheDefaultAndClearable(t *testing.T) {
	t.Cleanup(func() { SetSyncObserver(nil) })
	bs := New(&stubMerger{})
	bs.SetFeed(loopbackFeed, time.Hour)

	SetSyncObserver(nil)
	if _, err := bs.SyncFeed(loopbackFeed); err == nil {
		t.Fatal("expected the loopback feed to fail")
	}

	var called bool
	SetSyncObserver(func(SyncOutcome) { called = true })
	SetSyncObserver(nil)
	if _, err := bs.SyncFeed(loopbackFeed); err == nil {
		t.Fatal("expected the loopback feed to fail")
	}
	if called {
		t.Error("a cleared observer must not be invoked")
	}
}

func TestChaos123_SeedFeedStatusForTestRequiresAConfiguredFeed(t *testing.T) {
	bs := New(&stubMerger{})
	if bs.SeedFeedStatusForTest("https://absent.example.com/f.txt", time.Now(), time.Now(), "") {
		t.Error("seeding an unconfigured feed must report false")
	}
	bs.SetFeed(loopbackFeed, time.Hour)
	when := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if !bs.SeedFeedStatusForTest(loopbackFeed, when, when, "boom") {
		t.Fatal("seeding a configured feed must report true")
	}
	fs := bs.Feeds()
	if len(fs) != 1 || !fs[0].LastSync.Equal(when) || !fs[0].LastAttempt.Equal(when) || fs[0].LastError != "boom" {
		t.Fatalf("seeded status not reflected in the snapshot: %+v", fs)
	}
}

// TestChaos123_LastAttemptDistinguishesNeverTriedFromTriedAndFailed is the
// snapshot field the freshness plane needs and LastError cannot supply: a feed
// with auto-sync disabled is never scheduled, so its LastError stays empty
// forever and "configured but contributing nothing" was indistinguishable from
// "healthy".
func TestChaos123_LastAttemptDistinguishesNeverTriedFromTriedAndFailed(t *testing.T) {
	bs := New(&stubMerger{})
	const manual = "https://manual.example.com/list.txt"
	bs.SetFeed(manual, 0)
	bs.SetFeed(loopbackFeed, time.Hour)

	// dueURLs must agree that the manual-only feed is never due, while the
	// auto-sync one is (nextAttempt zero = never attempted = due now).
	if due := bs.dueURLs(time.Now()); len(due) != 1 || due[0] != loopbackFeed {
		t.Fatalf("only the auto-sync feed may be due, got %v", due)
	}
	if _, err := bs.SyncFeed(loopbackFeed); err == nil {
		t.Fatal("expected the loopback feed to fail")
	}
	// And after a failed round the manual-only feed is still never due,
	// however much time passes: it has no schedule at all.
	if due := bs.dueURLs(time.Now().Add(10 * 365 * 24 * time.Hour)); len(due) != 1 || due[0] != loopbackFeed {
		t.Fatalf("a manual-only feed must never become due, got %v", due)
	}

	byURL := map[string]Feed{}
	for _, f := range bs.Feeds() {
		byURL[f.URL] = f
	}
	if f := byURL[manual]; !f.LastAttempt.IsZero() || f.LastError != "" || !f.LastSync.IsZero() {
		t.Errorf("manual-only feed: want never attempted and no error, got %+v", f)
	}
	if f := byURL[loopbackFeed]; f.LastAttempt.IsZero() || f.LastError == "" {
		t.Errorf("auto-sync feed: want an attempt and an error, got %+v", f)
	}
	if f := byURL[loopbackFeed]; f.ConsecutiveFailures != 1 {
		t.Errorf("auto-sync feed: want 1 consecutive failure, got %d", f.ConsecutiveFailures)
	}
}

// newFeedServer serves body from a loopback listener. fetchFeedLines runs the
// inline SSRF guard at every sync, so the test opens the documented loopback
// seam for its own duration — the same way the CHAOS-108 suite does.
func newFeedServer(t *testing.T, body string) string {
	t.Helper()
	t.Cleanup(ssrf.AllowLoopbackForTest())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}
