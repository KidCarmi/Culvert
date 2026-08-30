package threatfeed

// CHAOS-57 — gates for the sync loop's freshness, retry and jitter behaviour.
//
// Provenance, stated precisely because "verified failing against the pre-fix
// tree" is a claim that has to be earned per gate:
//
//   - The DEFECT gates are the boot-sync ones. They were run against the
//     pre-fix condition (`needSync := tf.lastSync.IsZero() ||
//     tf.totalEntries.Load() == 0`) reintroduced in place, and fail:
//     TestChaos57_BootSyncOnStaleData and the resume half of
//     TestChaos57_BootSyncFlooredOnCrashLoop both go red.
//   - The retry and jitter gates pin ARMING conditions. They cannot be run
//     against the pre-fix tree in the same sense, because pre-fix there was no
//     retry and no jitter to test — a bare time.NewTicker(syncInterval) has no
//     delay function to call. They fail against a fix that ships the wrong
//     shape (an unbounded retry, a retry that slows a short interval, a
//     collapse back to a fixed cadence), which is what they are for.
//
// The CONTROL gates matter as much as the defect gates: an "always sync at
// boot" fix would pass the staleness gate while turning every rolling restart
// of a fleet into a synchronised burst against a free public feed, and a retry
// with no floor would pass the retry gate while hammering a service that is
// already refusing us. Both are pinned below.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// newTestFeed returns a Feed with a controlled freshness state and no disk.
func newTestFeed(t *testing.T, entries int64, lastSuccess, lastAttempt time.Time, interval time.Duration) *Feed {
	t.Helper()
	tf := New()
	tf.mu.Lock()
	tf.enabled = true
	tf.syncInterval = interval
	tf.lastSuccess = lastSuccess
	tf.lastRefresh = lastSuccess
	tf.lastSync = lastAttempt
	tf.publishLocked()
	tf.mu.Unlock()
	tf.totalEntries.Store(entries)
	return tf
}

// ── Boot-sync freshness (the CHAOS-57 defect) ────────────────────────────────

// TestChaos57_BootSyncOnStaleData is the DEFECT gate. An appliance that was
// powered off long enough for its persisted intelligence to go stale must
// fetch at startup. Pre-fix this returned false precisely BECAUSE the node had
// data, so a three-week-old feed was served for another full interval and a
// restart — the operator's remedy — made a recovered node strictly worse off
// than a fresh install.
func TestChaos57_BootSyncOnStaleData(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	interval := 6 * time.Hour
	// Synced three weeks ago; last attempt was then too (the node was off).
	stale := now.Add(-21 * 24 * time.Hour)
	tf := newTestFeed(t, 200_000, stale, stale, interval)

	if !tf.needBootSync(now) {
		t.Fatal("stale persisted feed must trigger a boot sync; pre-fix it was skipped because the node had entries")
	}
}

// TestChaos57_BootSyncSkippedWhenFresh is the CONTROL. A node restarted ten
// minutes after a clean sync must NOT refetch: that is the direction which
// turns a rolling upgrade into a thundering herd against a shared upstream.
func TestChaos57_BootSyncSkippedWhenFresh(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-10 * time.Minute)
	tf := newTestFeed(t, 200_000, fresh, fresh, 6*time.Hour)

	if tf.needBootSync(now) {
		t.Fatal("a feed synced 10 minutes ago must not refetch at boot")
	}
}

// TestChaos57_BootSyncFlooredOnCrashLoop is the other CONTROL. Stale data
// justifies a boot fetch; a process restarting every few seconds must not turn
// that into one outbound request per restart.
func TestChaos57_BootSyncFlooredOnCrashLoop(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	// Data is stale (last SUCCESS is ancient) but we attempted a minute ago:
	// this is the crash-loop shape.
	tf := newTestFeed(t, 200_000, now.Add(-21*24*time.Hour), now.Add(-time.Minute), 6*time.Hour)

	if tf.needBootSync(now) {
		t.Fatal("a boot sync one minute after the previous attempt must be floored (crash-loop protection)")
	}
	// ... and it must resume once the floor has elapsed.
	if !tf.needBootSync(now.Add(bootResyncFloor)) {
		t.Fatal("boot sync must resume once bootResyncFloor has elapsed since the last attempt")
	}
}

// TestChaos57_BootSyncOnEmptyOrNeverSynced pins that the pre-fix triggers are
// preserved: the new condition is a strict SUPERSET of the old one, so the
// loop can only ever sync at least as often as it used to.
func TestChaos57_BootSyncOnEmptyOrNeverSynced(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

	t.Run("no entries", func(t *testing.T) {
		tf := newTestFeed(t, 0, now.Add(-time.Minute), now.Add(-time.Minute), 6*time.Hour)
		if !tf.needBootSync(now) {
			t.Fatal("an empty feed must always sync at boot")
		}
	})
	t.Run("never synced", func(t *testing.T) {
		tf := newTestFeed(t, 100, time.Time{}, time.Time{}, 6*time.Hour)
		if !tf.needBootSync(now) {
			t.Fatal("a feed that never synced cleanly must sync at boot")
		}
	})
}

// ── Retry cadence ────────────────────────────────────────────────────────────

// TestChaos57_FailedRoundRetriesBeforeTheFullInterval pins the retry's reason
// for existing. Pre-fix a failed sync waited one full syncInterval — six hours
// by default — so a thirty-second resolver blip landing on the tick froze
// threat intelligence for the rest of the day.
func TestChaos57_FailedRoundRetriesBeforeTheFullInterval(t *testing.T) {
	const interval = 6 * time.Hour
	got := retryDelay(interval, 1)
	if got >= interval {
		t.Fatalf("first retry after a failed round = %s, want well under the %s interval", got, interval)
	}
	if got != syncRetryInitial {
		t.Fatalf("first retry = %s, want %s", got, syncRetryInitial)
	}
}

// TestChaos57_RetryBacksOffAndIsBounded pins that the retry is bounded in RATE
// (so a persistently-down feed is not hammered) and never in ATTEMPTS (so a
// feed that returns after a day is picked up on the next window).
func TestChaos57_RetryBacksOffAndIsBounded(t *testing.T) {
	const interval = 6 * time.Hour
	var prev time.Duration
	for fails := 1; fails <= 12; fails++ {
		d := retryDelay(interval, fails)
		if d <= 0 {
			t.Fatalf("failures=%d: retry delay %s must be positive — a zero delay is a spin loop", fails, d)
		}
		if d > syncRetryMax {
			t.Fatalf("failures=%d: retry delay %s exceeds the %s ceiling", fails, d, syncRetryMax)
		}
		if d < prev {
			t.Fatalf("failures=%d: retry delay %s went backwards from %s — backoff must be monotonic", fails, d, prev)
		}
		prev = d
	}
	if prev != syncRetryMax {
		t.Fatalf("backoff settled at %s, want the %s ceiling", prev, syncRetryMax)
	}
}

// TestChaos57_RetryNeverSlowsAShortInterval: a deployment configured to sync
// every minute must not have its cadence SLOWED to five minutes by the retry
// path. The retry exists to make a failed round recover sooner, never later.
func TestChaos57_RetryNeverSlowsAShortInterval(t *testing.T) {
	const interval = time.Minute
	for fails := 0; fails <= 5; fails++ {
		if d := retryDelay(interval, fails); d > interval {
			t.Fatalf("failures=%d: retry delay %s exceeds the configured %s interval", fails, d, interval)
		}
	}
}

// TestChaos57_SuccessResetsTheCadence pins that a good round returns to the
// full interval rather than staying at the retry floor.
func TestChaos57_SuccessResetsTheCadence(t *testing.T) {
	const interval = 6 * time.Hour
	if d := retryDelay(interval, 0); d != interval {
		t.Fatalf("delay after a successful round = %s, want the full %s interval", d, interval)
	}
}

// ── Failure accounting ───────────────────────────────────────────────────────

// TestChaos57_ConsecutiveFailuresCountRoundsThatFetchedNothing pins the
// narrower definition: a round in which ONE of two feeds succeeded refreshed
// real intelligence and is not a failure. Counting it would hold a fleet at
// the retry floor forever against a feed that is permanently 403ing — which is
// the ordinary steady state of a free public service, not an incident.
func TestChaos57_ConsecutiveFailuresCountRoundsThatFetchedNothing(t *testing.T) {
	tf := New()
	now := time.Now()

	// Both feeds failed: nothing replaced.
	tf.applySync(map[string]entry{}, map[string]entry{},
		[]string{"URLhaus: boom", "OpenPhish: boom"}, map[string]bool{}, now)
	if got := tf.ConsecutiveFailures(); got != 1 {
		t.Fatalf("after a round that fetched nothing: failures=%d, want 1", got)
	}
	tf.applySync(map[string]entry{}, map[string]entry{},
		[]string{"URLhaus: boom", "OpenPhish: boom"}, map[string]bool{}, now)
	if got := tf.ConsecutiveFailures(); got != 2 {
		t.Fatalf("after a second empty round: failures=%d, want 2", got)
	}

	// Partial success: one source replaced. Not a failure round.
	tf.applySync(map[string]entry{"http://a.test": {Source: sourceURLhaus}}, map[string]entry{},
		[]string{"OpenPhish: boom"}, map[string]bool{sourceURLhaus: true}, now)
	if got := tf.ConsecutiveFailures(); got != 0 {
		t.Fatalf("a round that refreshed one source must reset the counter, got %d", got)
	}
}

// ── Jitter ───────────────────────────────────────────────────────────────────

// TestChaos57_ScheduledDelayIsJittered pins the fix for the phase lock (WK-13).
// Pre-fix the loop used a bare time.NewTicker(syncInterval), so every node in a
// fleet that booted together stayed aligned for the life of the deployment,
// aiming a synchronised burst at a free public feed on every window. The gate
// is structural — it asserts the delays are not all identical — rather than
// asserting a distribution, which would flake.
func TestChaos57_ScheduledDelayIsJittered(t *testing.T) {
	tf := newTestFeed(t, 100, time.Now(), time.Now(), time.Hour)

	seen := make(map[time.Duration]struct{})
	for i := 0; i < 64; i++ {
		d := tf.nextSyncDelay()
		if d <= 0 {
			t.Fatalf("jittered delay %s must be positive", d)
		}
		// ±10% of an hour.
		if d < 54*time.Minute || d > 66*time.Minute {
			t.Fatalf("jittered delay %s outside the ±10%% band around 1h", d)
		}
		seen[d] = struct{}{}
	}
	if len(seen) < 8 {
		t.Fatalf("only %d distinct delays in 64 draws — the schedule is effectively phase-locked", len(seen))
	}
}

// TestChaos57_JitterNeverReturnsZero: a zero or negative delay would turn the
// loop into a spin that fetches continuously. Pinned across the degenerate
// inputs a misconfiguration can produce.
func TestChaos57_JitterNeverReturnsZero(t *testing.T) {
	for _, d := range []time.Duration{time.Nanosecond, time.Millisecond, time.Second, time.Hour} {
		if got := jitterDuration(d, syncJitterFrac); got <= 0 {
			t.Fatalf("jitterDuration(%s) = %s, must stay positive", d, got)
		}
	}
	if got := jitterDuration(0, syncJitterFrac); got != 0 {
		t.Fatalf("jitterDuration(0) = %s, want 0 (caller decides what a zero interval means)", got)
	}
}

// ── The observer seam ────────────────────────────────────────────────────────

// swapFeedURLsForTest points both feed origins at a test server and restores
// them. Without this the only way to exercise Sync is to fetch the real
// URLhaus and OpenPhish endpoints — two 60-second timeouts on a CI runner with
// no egress, and a request to a free public service on every run. A change
// about not hammering those feeds must not hammer them from its own tests.
func swapFeedURLsForTest(t *testing.T, urlhaus, openphish string) {
	t.Helper()
	prevU, prevO := urlHausTextFeed, openPhishFeed
	urlHausTextFeed, openPhishFeed = urlhaus, openphish
	t.Cleanup(func() { urlHausTextFeed, openPhishFeed = prevU, prevO })
}

// TestChaos57_ObserverFiresOnEverySyncRound pins that the freshness plane is
// notified by the admin's manual Sync too — otherwise a successful "Sync Now"
// would leave a stale alert latched until the next scheduled window — and that
// it is notified on a FAILED round as well, which is the round an operator
// most needs to hear about.
func TestChaos57_ObserverFiresOnEverySyncRound(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "http://malware.example/payload.bin")
	}))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream down", http.StatusServiceUnavailable)
	}))
	defer bad.Close()

	t.Run("successful round", func(t *testing.T) {
		swapFeedURLsForTest(t, good.URL, good.URL)
		tf := New()
		calls := 0
		tf.SetSyncObserver(func() { calls++ })

		tf.Sync()
		if calls != 1 {
			t.Fatalf("observer called %d times after one Sync, want 1", calls)
		}
		if got := tf.ConsecutiveFailures(); got != 0 {
			t.Fatalf("ConsecutiveFailures = %d after a clean round, want 0", got)
		}
	})

	t.Run("failed round still notifies", func(t *testing.T) {
		swapFeedURLsForTest(t, bad.URL, bad.URL)
		tf := New()
		calls := 0
		tf.SetSyncObserver(func() { calls++ })

		tf.Sync()
		if calls != 1 {
			t.Fatalf("observer called %d times after a failed Sync, want 1 — a failed round is exactly the one the freshness plane must hear about", calls)
		}
		if got := tf.ConsecutiveFailures(); got != 1 {
			t.Fatalf("ConsecutiveFailures = %d after a round that fetched nothing, want 1", got)
		}
	})
}

// TestChaos57_ObserverIsCalledWithoutHoldingTheLock is the deadlock gate. The
// observer reads the feed's own accessors, every one of which takes tf.mu;
// invoking it under the write lock would wedge the sync goroutine forever on a
// non-reentrant RWMutex — the CHAOS-50 cluster-CA defect exactly. The gate
// deadlocks (and so times out) against that shape rather than failing softly.
func TestChaos57_ObserverIsCalledWithoutHoldingTheLock(t *testing.T) {
	tf := New()
	done := make(chan struct{})
	tf.SetSyncObserver(func() {
		// Every one of these takes tf.mu.
		_ = tf.Freshness()
		_, _, _ = tf.Stats()
		_, _, _ = tf.SyncStatus()
		_ = tf.ConsecutiveFailures()
		close(done)
	})

	go tf.notifySyncObserver()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("observer deadlocked reading feed state — it must be invoked with tf.mu released")
	}
}

// TestChaos57_FreshnessIsOneConsistentRead pins that Freshness reports the
// fields of a single generation. Composing the same view from Stats +
// SyncStatus + ConsecutiveFailures takes tf.mu three times and can straddle a
// concurrent applySync, reporting a fresh lastSuccess beside the failure count
// that preceded it.
func TestChaos57_FreshnessIsOneConsistentRead(t *testing.T) {
	tf := New()
	now := time.Now()
	tf.applySync(map[string]entry{"http://a.test": {Source: sourceURLhaus}}, map[string]entry{},
		nil, map[string]bool{sourceURLhaus: true, sourceOpenPhish: true}, now)

	f := tf.Freshness()
	if !f.LastSuccess.Equal(now) {
		t.Fatalf("LastSuccess = %s, want %s", f.LastSuccess, now)
	}
	if f.ConsecutiveFailures != 0 {
		t.Fatalf("ConsecutiveFailures = %d after a clean round, want 0", f.ConsecutiveFailures)
	}
	if f.LastErr != "" {
		t.Fatalf("LastErr = %q after a clean round, want empty", f.LastErr)
	}
	if f.Entries != 1 {
		t.Fatalf("Entries = %d, want 1", f.Entries)
	}
}

// ── Codex review follow-ups (PR #1264) ───────────────────────────────────────

// TestChaos57_PartialRefreshIsNotTreatedAsNeverRefreshed is the DEFECT gate for
// the contradiction Codex found INSIDE this change. consecutiveFailures is
// deliberately narrow — a round that refreshed one of two sources did its job,
// because one free public feed 403ing indefinitely is an ordinary steady state
// — but freshness was originally keyed on lastSuccess, which requires EVERY
// source clean. The two halves disagreed: a feed whose surviving source
// refreshed on every single window had a lastSuccess that never advanced, so
// the boot check saw "never succeeded" and fetched on EVERY restart with no
// crash-loop floor at all.
func TestChaos57_PartialRefreshIsNotTreatedAsNeverRefreshed(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	tf := New()
	// Ten minutes ago: URLhaus refreshed, OpenPhish failed. Never a fully
	// clean round, so lastSuccess stays zero — forever.
	tf.mu.Lock()
	tf.enabled, tf.syncInterval = true, 6*time.Hour
	tf.mu.Unlock()
	tf.applySync(map[string]entry{"http://a.test": {Source: sourceURLhaus}}, map[string]entry{},
		[]string{"OpenPhish: HTTP 403"}, map[string]bool{sourceURLhaus: true}, now.Add(-10*time.Minute))

	f := tf.Freshness()
	if !f.LastSuccess.IsZero() {
		t.Fatal("precondition: a partial round must NOT advance lastSuccess")
	}
	if f.LastRefresh.IsZero() {
		t.Fatal("a round that refreshed one of two sources must advance lastRefresh")
	}
	if tf.needBootSync(now) {
		t.Fatal("a feed refreshed 10 minutes ago by its surviving source must not refetch at boot — " +
			"keying freshness on lastSuccess made this fetch on every restart, with no crash-loop floor")
	}
}

// TestChaos57_FlooredBootRetriesWhenTheFloorExpires is the DEFECT gate for the
// second Codex finding. When the boot fetch is skipped by the crash-loop floor,
// the first scheduled attempt used the ordinary cadence — and because
// consecutiveFailures is process-local and resets to zero on restart, the retry
// path that would have shortened it was not armed. A floor meant to defer a
// fetch by at most 15 minutes deferred it by a full interval instead, leaving
// stale intelligence frozen for another whole window.
func TestChaos57_FlooredBootRetriesWhenTheFloorExpires(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	// Stale data, attempted one minute ago: the floored shape.
	tf := newTestFeed(t, 200_000, now.Add(-21*24*time.Hour), now.Add(-time.Minute), 6*time.Hour)

	decision, floorLeft := tf.bootSyncDecision(now)
	if decision != bootFloored {
		t.Fatalf("decision = %v, want bootFloored", decision)
	}
	want := bootResyncFloor - time.Minute
	if floorLeft != want {
		t.Fatalf("floorLeft = %s, want %s", floorLeft, want)
	}

	got := tf.firstDelay(decision, floorLeft)
	if got > bootResyncFloor {
		t.Fatalf("first scheduled attempt after a floored boot = %s, want <= the %s floor "+
			"(pre-fix it waited the full 6h interval)", got, bootResyncFloor)
	}
}

// TestChaos57_FreshBootStillUsesTheFullCadence is the CONTROL for the above: the
// floor shortcut must apply ONLY to a floored boot. Shortening the first delay
// on a node whose data is simply fresh would refetch every healthy restart —
// the thundering-herd direction this change exists to avoid.
func TestChaos57_FreshBootStillUsesTheFullCadence(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	tf := newTestFeed(t, 200_000, now.Add(-10*time.Minute), now.Add(-10*time.Minute), 6*time.Hour)

	decision, floorLeft := tf.bootSyncDecision(now)
	if decision != bootDataFresh {
		t.Fatalf("decision = %v, want bootDataFresh", decision)
	}
	if got := tf.firstDelay(decision, floorLeft); got < 5*time.Hour {
		t.Fatalf("first delay on a fresh boot = %s, want roughly the full 6h interval", got)
	}
}

// TestChaos57_LastRefreshSurvivesRestart pins the persistence half: the field
// freshness is computed from must round-trip, and a legacy DB written before it
// existed must back-fill from lastSuccess rather than loading as "never
// refreshed" (which would force a fetch on the first boot after upgrade for
// every appliance in a fleet at once).
func TestChaos57_LastRefreshSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/feed.json"
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

	t.Run("round-trips", func(t *testing.T) {
		tf := New()
		tf.mu.Lock()
		tf.dbPath, tf.enabled = path, true
		tf.mu.Unlock()
		tf.applySync(map[string]entry{"http://a.test": {Source: sourceURLhaus}}, map[string]entry{},
			[]string{"OpenPhish: HTTP 403"}, map[string]bool{sourceURLhaus: true}, now)
		if err := tf.saveToDisk(); err != nil {
			t.Fatalf("saveToDisk: %v", err)
		}

		reloaded := New()
		if err := reloaded.loadFromDisk(path); err != nil {
			t.Fatalf("loadFromDisk: %v", err)
		}
		if got := reloaded.Freshness().LastRefresh; !got.Equal(now) {
			t.Fatalf("LastRefresh after restart = %s, want %s", got, now)
		}
	})

	t.Run("legacy DB back-fills from last_success", func(t *testing.T) {
		legacy := dir + "/legacy.json"
		body := `{"last_sync":"2026-08-29T12:00:00Z","last_success":"2026-08-29T12:00:00Z",` +
			`"urls":{},"domains":{},"domain_allowlist":[]}`
		if err := os.WriteFile(legacy, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		tf := New()
		if err := tf.loadFromDisk(legacy); err != nil {
			t.Fatalf("loadFromDisk: %v", err)
		}
		want := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
		if got := tf.Freshness().LastRefresh; !got.Equal(want) {
			t.Fatalf("legacy LastRefresh = %s, want back-fill from last_success (%s)", got, want)
		}
	})
}
