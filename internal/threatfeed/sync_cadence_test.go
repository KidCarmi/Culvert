package threatfeed

// Sync-cadence and sync-health gates.
//
// The finding these pin: internal/threatfeed scheduled itself with a bare
// time.NewTicker(syncInterval), so a failed round was not retried until the
// next FULL interval (six hours by default) — and the failure left no signal
// any alerting rule could read, because the per-source carry-forward that
// closed the stale-erase half of WK-5 also holds the entry-count gauge at its
// last-good value. A feed dead for three weeks and a feed that synced ten
// minutes ago exported identical metrics.
//
// Every gate below except the CONTROLs fails against the pre-fix shape.

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/feedsched"
)

// ── Failure accounting ────────────────────────────────────────────────────────

// TestApplySync_FailureRecordsBoundedReasonAndCounts — the failure must be
// COUNTED and CLASSIFIED, not just carried in a prose error summary.
func TestApplySync_FailureRecordsBoundedReasonAndCounts(t *testing.T) {
	tf := seedFeed()

	out := tf.applySync(
		make(map[string]entry), make(map[string]entry),
		[]string{"URLhaus: dial timeout", "OpenPhish: dial timeout"},
		map[string]bool{}, time.Now(),
		sourceURLhaus, sourceOpenPhish,
	)

	if out.OK {
		t.Fatal("outcome.OK = true for a round in which both feeds failed")
	}
	if out.ConsecutiveFailures != 1 {
		t.Fatalf("ConsecutiveFailures = %d, want 1", out.ConsecutiveFailures)
	}
	// Bounded class, sorted: the alert plane dedups on it, so it must be
	// stable and must never contain an error string.
	if out.FailedSources != "openphish+urlhaus" {
		t.Fatalf("FailedSources = %q, want %q", out.FailedSources, "openphish+urlhaus")
	}
	h := tf.Health()
	if h.TotalFailures != 1 {
		t.Fatalf("TotalFailures = %d, want 1", h.TotalFailures)
	}
	if h.ConsecutiveFailures != 1 {
		t.Fatalf("Health.ConsecutiveFailures = %d, want 1", h.ConsecutiveFailures)
	}
	if !h.LastSuccess.IsZero() {
		t.Fatalf("LastSuccess = %s on a feed that never synced cleanly, want zero", h.LastSuccess)
	}
}

// TestFailedSourcesIsBoundedAndCarriesNoErrorText is the SECURITY-adjacent half
// of the classification: the alert store dedups on event+Detail, so a reason
// derived from err.Error() (which embeds the feed URL and, for a transport
// failure, the ephemeral local port) would produce a distinct key per attempt,
// defeat the dedup window by construction, and evict real threat alerts from
// the bounded retry queue.
func TestFailedSourcesIsBoundedAndCarriesNoErrorText(t *testing.T) {
	// The full space of values this field can ever take.
	want := map[string]bool{"": true, "urlhaus": true, "openphish": true, "openphish+urlhaus": true}

	cases := [][]string{nil, {sourceURLhaus}, {sourceOpenPhish}, {sourceURLhaus, sourceOpenPhish}, {sourceOpenPhish, sourceURLhaus}}
	for _, c := range cases {
		got := classifyFailedSources(c)
		if !want[got] {
			t.Fatalf("classifyFailedSources(%v) = %q, which is outside the bounded value set", c, got)
		}
		if strings.ContainsAny(got, " :/") {
			t.Fatalf("classifyFailedSources(%v) = %q — looks like it carries error/URL text", c, got)
		}
	}
	// Order independence: an alert Detail that flipped between orderings would
	// dedup against itself only half the time.
	if a, b := classifyFailedSources([]string{sourceURLhaus, sourceOpenPhish}),
		classifyFailedSources([]string{sourceOpenPhish, sourceURLhaus}); a != b {
		t.Fatalf("classification is order-dependent: %q vs %q", a, b)
	}
}

// TestApplySync_SuccessResetsFailureState — recovery must be complete, and the
// cumulative total must survive it (an operator needs the HISTORY of transient
// failures after the feed recovers).
func TestApplySync_SuccessResetsFailureState(t *testing.T) {
	tf := seedFeed()
	for i := 0; i < 3; i++ {
		tf.applySync(make(map[string]entry), make(map[string]entry),
			[]string{"URLhaus: dial timeout"}, map[string]bool{}, time.Now(), sourceURLhaus)
	}
	if got := tf.Health().ConsecutiveFailures; got != 3 {
		t.Fatalf("ConsecutiveFailures = %d, want 3", got)
	}

	now := time.Now()
	out := tf.applySync(
		map[string]entry{"http://x.example/a": {Source: sourceURLhaus}},
		map[string]entry{"x.example": {Source: sourceURLhaus}},
		nil,
		map[string]bool{sourceURLhaus: true, sourceOpenPhish: true},
		now,
	)
	if !out.OK {
		t.Fatal("outcome.OK = false for a clean round")
	}
	h := tf.Health()
	if h.ConsecutiveFailures != 0 {
		t.Fatalf("ConsecutiveFailures = %d after a clean round, want 0", h.ConsecutiveFailures)
	}
	if h.FailedSources != "" {
		t.Fatalf("FailedSources = %q after a clean round, want empty", h.FailedSources)
	}
	if !h.LastSuccess.Equal(now) {
		t.Fatalf("LastSuccess = %s, want %s", h.LastSuccess, now)
	}
	if h.TotalFailures != 3 {
		t.Fatalf("TotalFailures = %d after recovery, want the cumulative 3 (history must survive recovery)", h.TotalFailures)
	}
}

// TestApplySync_PartialFailureIsAFailedRound — one source down is a failed
// round for SCHEDULING purposes even though the other source's entries were
// installed. That source's coverage is frozen, so the round must be retried on
// the backoff ladder rather than waiting a full interval.
func TestApplySync_PartialFailureIsAFailedRound(t *testing.T) {
	tf := seedFeed()
	out := tf.applySync(
		map[string]entry{"http://new.example/a": {Source: sourceURLhaus}},
		map[string]entry{"new.example": {Source: sourceURLhaus}},
		[]string{"OpenPhish: HTTP 503"},
		map[string]bool{sourceURLhaus: true},
		time.Now(), sourceOpenPhish,
	)
	if out.OK {
		t.Fatal("a round where OpenPhish failed reported OK — it would be retried only after a full interval")
	}
	if out.FailedSources != "openphish" {
		t.Fatalf("FailedSources = %q, want \"openphish\"", out.FailedSources)
	}
	// The half that DID succeed is still installed, and the half that failed is
	// still carried forward (the shipped WK-5 fix, unchanged by this work).
	if mal, _ := tf.CheckDomain("new.example"); !mal {
		t.Error("the source that fetched cleanly was not installed")
	}
	if mal, _ := tf.CheckDomain("phish.example"); !mal {
		t.Error("the failed source's last-known-good entries were not carried forward")
	}
}

// TestApplySync_CarriedForwardEntriesAreCounted — a REGRESSION gate. Counting
// entries before the carry-forward merge would report a partially-failed sync
// as a nearly-emptied feed on the entries gauge, which is exactly the false
// alarm the carry-forward fix exists to prevent.
func TestApplySync_CarriedForwardEntriesAreCounted(t *testing.T) {
	tf := seedFeed()
	out := tf.applySync(make(map[string]entry), make(map[string]entry),
		[]string{"URLhaus: dial timeout", "OpenPhish: dial timeout"},
		map[string]bool{}, time.Now(), sourceURLhaus, sourceOpenPhish)
	if out.Entries != 3 {
		t.Fatalf("outcome.Entries = %d, want 3 (the carried-forward entries are what the feed now serves)", out.Entries)
	}
	if got, _, _ := tf.Stats(); got != 3 {
		t.Fatalf("Stats entries = %d, want 3", got)
	}
}

// ── Observer seam ─────────────────────────────────────────────────────────────

// TestSyncObserver_ReceivesBothOutcomes — the RECOVERY edge matters as much as
// the failure edge: package main's plane clears its degraded state on observed
// evidence only, so it must be told about clean rounds too.
func TestSyncObserver_ReceivesBothOutcomes(t *testing.T) {
	var mu sync.Mutex
	var got []SyncOutcome
	SetSyncObserver(func(o SyncOutcome) {
		mu.Lock()
		got = append(got, o)
		mu.Unlock()
	})
	t.Cleanup(func() { SetSyncObserver(nil) })

	notifySyncObserver(SyncOutcome{OK: false, FailedSources: "urlhaus", ConsecutiveFailures: 1})
	notifySyncObserver(SyncOutcome{OK: true})

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("observer saw %d outcomes, want 2", len(got))
	}
	if got[0].OK || got[1].OK != true {
		t.Fatalf("observer outcomes = %+v, want [failure, success]", got)
	}
}

// TestSyncObserver_PanicIsContained — the observability plane must never be
// able to break the thing it observes. Without containment here the panic
// would unwind into the scheduler's own recover and be charged to the FEED
// round, so an alerting bug would make a healthy feed back off and report
// itself unhealthy.
func TestSyncObserver_PanicIsContained(t *testing.T) {
	SetSyncObserver(func(SyncOutcome) { panic("observer bug") })
	t.Cleanup(func() { SetSyncObserver(nil) })
	notifySyncObserver(SyncOutcome{OK: true}) // must not panic out
}

// TestSyncObserver_NilIsSafe — the default posture (no observer installed) must
// cost nothing and must never nil-deref.
func TestSyncObserver_NilIsSafe(t *testing.T) {
	SetSyncObserver(nil)
	notifySyncObserver(SyncOutcome{OK: false, FailedSources: "urlhaus"})
}

// ── Scheduling ────────────────────────────────────────────────────────────────

// TestScheduler_FailedRoundRetriesLongBeforeTheInterval is the DEFECT GATE for
// the cadence half of the finding.
//
// The pre-fix loop was `time.NewTicker(tf.syncInterval)`, whose delay after a
// failed round is the full interval by construction. The gate asserts the
// scheduler this feed now builds returns a retry delay strictly below it — and
// bounded above the hot-loop floor, so the fix cannot be "retry immediately".
//
// No network, no sleeping: the cadence is computed from the same Config
// production uses.
func TestScheduler_FailedRoundRetriesLongBeforeTheInterval(t *testing.T) {
	tf := New()
	tf.Init("", 6*time.Hour)

	s := feedsched.New(tf.schedulerConfig())

	if got := s.NextDelay(true); got < 5*time.Hour || got > 7*time.Hour {
		t.Fatalf("delay after a clean round = %s, want ~6h (the configured interval, jittered)", got)
	}
	first := s.NextDelay(false)
	if first >= 6*time.Hour {
		t.Fatalf("delay after a FAILED round = %s — a failure must not wait a full sync interval", first)
	}
	if first < time.Minute {
		t.Fatalf("delay after a failed round = %s — that is a hot loop against a public feed origin", first)
	}
	// The ladder grows and stays bounded.
	prev := first
	for i := 0; i < 10; i++ {
		d := s.NextDelay(false)
		if d < prev {
			// Jitter can make one step non-monotonic only within ±10%; a real
			// regression (reset ladder) collapses it back to the floor.
			if d < time.Duration(float64(prev)*0.8) {
				t.Fatalf("backoff step %d collapsed from %s to %s", i, prev, d)
			}
		}
		if d >= 6*time.Hour {
			t.Fatalf("backoff step %d reached %s — the ceiling must stay below the interval", i, d)
		}
		prev = d
	}
}

// TestScheduler_ColdStartArmsAnImmediateRound — the severe shape. A node whose
// on-disk feed DB is empty must sync at once; if that first round fails it is
// enforcing with NO threat intelligence, which is what the backoff ladder then
// has to recover from.
func TestScheduler_ColdStartArmsAnImmediateRound(t *testing.T) {
	tf := New()
	tf.Init("", 6*time.Hour)

	cfg := tf.schedulerConfig()
	if cfg.RunNow == nil || !cfg.RunNow() {
		t.Fatal("a feed with an empty database did not arm an immediate sync")
	}

	// A warm feed must NOT re-fetch at boot: that is what keeps a fleet-wide
	// restart from becoming a synchronised fetch storm against the origins.
	tf.applySync(
		map[string]entry{"http://x.example/a": {Source: sourceURLhaus}},
		map[string]entry{"x.example": {Source: sourceURLhaus}},
		nil, map[string]bool{sourceURLhaus: true, sourceOpenPhish: true}, time.Now(),
	)
	if tf.schedulerConfig().RunNow() {
		t.Fatal("a feed with a warm database armed an immediate sync — a fleet restart would stampede the origins")
	}
}

// TestRetryBoundsAreSaneRelativeToTheInterval is the CONTROL on the cadence
// change. A retry ladder that fired immediately would satisfy "a failure is
// retried before the next interval" while being far worse than the defect: an
// unbounded hot loop against two third-party feed origins, which is how a
// customer's egress IP gets rate-limited or blocked.
func TestRetryBoundsAreSaneRelativeToTheInterval(t *testing.T) {
	if syncRetryMin < time.Minute {
		t.Fatalf("syncRetryMin = %s — a retry floor below a minute is a hot loop against a public feed origin", syncRetryMin)
	}
	if syncRetryMin > syncRetryMax {
		t.Fatalf("syncRetryMin %s > syncRetryMax %s", syncRetryMin, syncRetryMax)
	}
	tf := New()
	tf.Init("", 6*time.Hour)
	if syncRetryMax >= tf.SyncInterval() {
		t.Fatalf("syncRetryMax %s is not below the default sync interval %s — retrying would loosen the cadence, not tighten it",
			syncRetryMax, tf.SyncInterval())
	}
}

// TestSyncInterval_ReportsTheConfiguredCadence — the health plane derives its
// staleness threshold from this, so a wrong value silently moves the alert.
func TestSyncInterval_ReportsTheConfiguredCadence(t *testing.T) {
	tf := New()
	if got := tf.SyncInterval(); got != 6*time.Hour {
		t.Fatalf("default SyncInterval = %s, want 6h", got)
	}
	tf.Init("", 90*time.Minute)
	if got := tf.SyncInterval(); got != 90*time.Minute {
		t.Fatalf("SyncInterval after Init = %s, want 90m", got)
	}
	if got := tf.Health().SyncInterval; got != 90*time.Minute {
		t.Fatalf("Health.SyncInterval = %s, want 90m", got)
	}
}

// TestHealth_ReportsConfiguredOnlyAfterInit — a zero on a node that never ran
// the feed is indistinguishable from a node whose feed has never once
// succeeded, and the two demand opposite operator actions.
func TestHealth_ReportsConfiguredOnlyAfterInit(t *testing.T) {
	tf := New()
	if tf.Health().Configured {
		t.Fatal("Health.Configured = true before Init")
	}
	tf.Init("", time.Hour)
	if !tf.Health().Configured {
		t.Fatal("Health.Configured = false after Init")
	}
}
