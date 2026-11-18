package main

// blocklist_feed_health_chaos123_test.go — CHAOS-123's gates.
//
// Three groups:
//   1. the SHAPES the pre-round surface could not see (a stale feed, a
//      never-synced feed, a manual-only feed that will never sync, and the
//      window after a settings restore);
//   2. the ALERT discipline (fire once per episode, cleared only on observed
//      evidence from EVERY auto-sync feed, never on elapsed time);
//   3. the CONTAINMENT rules that make an observability plane safe — no
//      operator-configured string on the scrape endpoint, and no series at
//      all on a node that does not use the feature.

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/blocklistfeed"
)

// blFeedHealthTest arms the plane on a fixed clock with a fresh syncer, and
// restores every global it touches.
func blFeedHealthTest(t *testing.T, now time.Time) *BlocklistSyncer {
	t.Helper()
	bs := newTestBlocklistSyncer(t)
	swapFeedSyncer(t, bs)
	prevFire := fireBlocklistFeedStaleAlert
	t.Cleanup(func() {
		fireBlocklistFeedStaleAlert = prevFire
		resetBlocklistFeedHealthForTest()
	})
	resetBlocklistFeedHealthForTest()
	blocklistFeedNow = func() time.Time { return now }
	noteBlocklistFeedConfigured()
	return bs
}

// captureStaleAlert replaces the alert sink with a recorder, so transitions are
// observed synchronously instead of racing the process-global alerts store.
func captureStaleAlert(t *testing.T) *[]string {
	t.Helper()
	var fired []string
	fireBlocklistFeedStaleAlert = func(detail string) { fired = append(fired, detail) }
	return &fired
}

func blFeedMetrics() string {
	var sb strings.Builder
	blocklistFeedWritePrometheus(&sb)
	return sb.String()
}

func wantSeries(t *testing.T, out, series string, value int64) {
	t.Helper()
	want := series + " " + strconv.FormatInt(value, 10) + "\n"
	if !strings.Contains(out, want) {
		t.Errorf("want %q in the scrape, got:\n%s", strings.TrimSuffix(want, "\n"), out)
	}
}

// ─── group 1: the shapes ─────────────────────────────────────────────────────

// TestChaos123_NoFeedConfiguredEmitsNothing is the rule every optional
// feature's gauges follow: a culvert_blocklist_feed_sync_ok 0 on a node that
// never configured a feed is indistinguishable from a node whose feed is
// broken, and the documented paging rule is == 0.
func TestChaos123_NoFeedConfiguredEmitsNothing(t *testing.T) {
	blFeedHealthTest(t, time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC))
	if out := blFeedMetrics(); out != "" {
		t.Errorf("no feed configured must emit no series, got:\n%s", out)
	}
	if rows := checkBlocklistFeeds(); len(rows) != 0 {
		t.Errorf("no feed configured must contribute no diagnostics row, got %+v", rows)
	}
}

// TestChaos123_FreshFeedIsGreen is the positive control: the plane must not
// invent a fault on a healthy node.
func TestChaos123_FreshFeedIsGreen(t *testing.T) {
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	bs := blFeedHealthTest(t, now)
	const feed = "https://feeds.example.com/deny.txt"
	bs.SetFeed(feed, 24*time.Hour)
	bs.SeedFeedStatusForTest(feed, now.Add(-30*time.Minute), now.Add(-30*time.Minute), "")

	snap := blocklistFeedState()
	if snap.StaleFeeds != 0 || snap.FailingFeeds != 0 || snap.NeverSyncedFeeds != 0 {
		t.Fatalf("a feed that synced 30 minutes ago is fresh: %+v", snap)
	}
	out := blFeedMetrics()
	wantSeries(t, out, "culvert_blocklist_feed_sync_ok", 1)
	wantSeries(t, out, "culvert_blocklist_feed_stale", 0)
	wantSeries(t, out, "culvert_blocklist_feed_configured", 1)
	wantSeries(t, out, "culvert_blocklist_feed_autosync_enabled", 1)
	wantSeries(t, out, "culvert_blocklist_feed_stale_seconds", 1800)
	if rows := checkBlocklistFeeds(); len(rows) != 0 {
		t.Errorf("a fresh feed contributes no row, got %+v", rows)
	}
}

// TestChaos123_StaleBeyondTwoIntervalsIsReportedAndPaged is the finding: a
// deny control that stopped being refreshed. Before this round the ONLY
// surface that moved was LastError, which is empty here — the last ATTEMPT
// succeeded long ago and nothing has attempted since, which is exactly the
// state a feed left behind by a dead schedule or a long-gone origin sits in.
func TestChaos123_StaleBeyondTwoIntervalsIsReportedAndPaged(t *testing.T) {
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	bs := blFeedHealthTest(t, now)
	fired := captureStaleAlert(t)
	const feed = "https://feeds.example.com/deny.txt"
	bs.SetFeed(feed, 6*time.Hour)
	// 13 h with a 6 h interval: past 2x, and with NO error recorded.
	bs.SeedFeedStatusForTest(feed, now.Add(-13*time.Hour), now.Add(-13*time.Hour), "")

	snap := blocklistFeedState()
	if snap.StaleFeeds != 1 || snap.FailingFeeds != 0 {
		t.Fatalf("want one stale, zero failing: %+v", snap)
	}

	out := blFeedMetrics()
	wantSeries(t, out, "culvert_blocklist_feed_stale", 1)
	wantSeries(t, out, "culvert_blocklist_feed_sync_ok", 0)
	wantSeries(t, out, "culvert_blocklist_feed_failing", 0)
	wantSeries(t, out, "culvert_blocklist_feed_stale_seconds", int64((13 * time.Hour).Seconds()))
	wantSeries(t, out, "culvert_blocklist_feed_oldest_success_timestamp_seconds", now.Add(-13*time.Hour).Unix())

	rows := checkBlocklistFeeds()
	if len(rows) != 1 || rows[0].Code != "blocklist_feed" || rows[0].Status != diagWarn || rows[0].OperatorAction == "" {
		t.Fatalf("want one blocklist_feed WARN row with an action, got %+v", rows)
	}
	if !strings.Contains(rows[0].Message, "stale") {
		t.Errorf("the row must name the condition, got %q", rows[0].Message)
	}

	// And the alert must have fired, exactly once, on the observed failure.
	noteBlocklistFeedSync(blocklistfeed.SyncOutcome{ConsecutiveFailures: 1, Interval: 6 * time.Hour})
	if len(*fired) != 1 {
		t.Fatalf("want exactly one alert, got %d: %v", len(*fired), *fired)
	}
	if !strings.Contains((*fired)[0], "stale") {
		t.Errorf("alert detail must name the condition, got %q", (*fired)[0])
	}
}

// TestChaos123_NeverSyncedPastGraceIsReportedSeparately — the severe shape. A
// feed that has never completed a round contributes NO entries, so the
// destinations it was added to block are not blocked at all. The wording must
// differ from the stale case because the operator impact does.
func TestChaos123_NeverSyncedPastGraceIsReportedSeparately(t *testing.T) {
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	bs := blFeedHealthTest(t, now)
	fired := captureStaleAlert(t)
	const feed = "https://feeds.example.com/deny.txt"
	bs.SetFeed(feed, 24*time.Hour)

	// Inside the grace: a node that simply has not finished its first round
	// is not a fault, and must not page.
	if snap := blocklistFeedState(); snap.NeverSyncedFeeds != 1 || snap.StaleFeeds != 0 {
		t.Fatalf("inside the grace: want never-synced but not stale, got %+v", snap)
	}
	noteBlocklistFeedSync(blocklistfeed.SyncOutcome{ConsecutiveFailures: 1, Interval: 24 * time.Hour})
	if len(*fired) != 0 {
		t.Fatalf("must not page inside the startup grace, got %v", *fired)
	}
	if rows := checkBlocklistFeeds(); len(rows) != 0 {
		t.Fatalf("no row inside the grace, got %+v", rows)
	}

	// Past the grace.
	blocklistFeedNow = func() time.Time { return now.Add(blocklistFeedNeverSyncedGrace + time.Minute) }
	snap := blocklistFeedState()
	if snap.NeverSyncedFeeds != 1 || snap.StaleFeeds != 1 {
		t.Fatalf("past the grace: want never-synced and stale, got %+v", snap)
	}
	out := blFeedMetrics()
	wantSeries(t, out, "culvert_blocklist_feed_never_synced", 1)
	wantSeries(t, out, "culvert_blocklist_feed_stale", 1)
	// The oldest-success timestamp is the documented 0 sentinel while any
	// auto-sync feed has never succeeded: there is no floor to report.
	wantSeries(t, out, "culvert_blocklist_feed_oldest_success_timestamp_seconds", 0)

	rows := checkBlocklistFeeds()
	if len(rows) != 1 || !strings.Contains(rows[0].Message, "NEVER synced") {
		t.Fatalf("want the never-synced wording, got %+v", rows)
	}
	noteBlocklistFeedSync(blocklistfeed.SyncOutcome{ConsecutiveFailures: 2, Interval: 24 * time.Hour})
	if len(*fired) != 1 || !strings.Contains((*fired)[0], "NEVER synced") {
		t.Fatalf("want one never-synced alert, got %v", *fired)
	}
}

// TestChaos123_ManualOnlyFeedThatNeverSyncedIsReportedButNotPaged is the first
// shape the LastError row was structurally blind to.
//
// The admin API accepts interval "off" (ui_policy.go maps it to 0) and
// dueURLs skips interval <= 0, so the scheduler NEVER attempts the feed: no
// attempt, no LastError, and the pre-round diagnostics row therefore reported
// a green node while a configured deny control contributed nothing — forever.
//
// It gets a row and a gauge, and deliberately no page: the operator turned the
// schedule off, so paging would be paging on their own configuration.
func TestChaos123_ManualOnlyFeedThatNeverSyncedIsReportedButNotPaged(t *testing.T) {
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	bs := blFeedHealthTest(t, now)
	fired := captureStaleAlert(t)
	const feed = "https://feeds.example.com/manual.txt"
	bs.SetFeed(feed, 0)

	// Far past any grace: a manual-only feed never becomes "stale", because
	// nothing was ever scheduled to make it fresh.
	blocklistFeedNow = func() time.Time { return now.Add(30 * 24 * time.Hour) }

	snap := blocklistFeedState()
	if snap.ManualOnlyFeeds != 1 || snap.ManualOnlyNeverSynced != 1 {
		t.Fatalf("want one manual-only never-synced feed: %+v", snap)
	}
	if snap.AutoSyncFeeds != 0 || snap.StaleFeeds != 0 || snap.NeverSyncedFeeds != 0 {
		t.Fatalf("a manual-only feed is not an auto-sync feed and is not stale: %+v", snap)
	}

	out := blFeedMetrics()
	wantSeries(t, out, "culvert_blocklist_feed_configured", 1)
	wantSeries(t, out, "culvert_blocklist_feed_autosync_enabled", 0)
	wantSeries(t, out, "culvert_blocklist_feed_manual_never_synced", 1)
	wantSeries(t, out, "culvert_blocklist_feed_stale", 0)

	rows := checkBlocklistFeeds()
	if len(rows) != 1 || rows[0].Status != diagWarn {
		t.Fatalf("want one WARN row for the manual-only feed, got %+v", rows)
	}
	if !strings.Contains(rows[0].Message, "auto-sync turned off") {
		t.Errorf("the row must explain that nothing will sync it, got %q", rows[0].Message)
	}

	evaluateBlocklistFeedStaleness()
	if len(*fired) != 0 {
		t.Errorf("a manual-only feed must not page, got %v", *fired)
	}

	// Once it HAS been synced manually, the row goes away: the operator's
	// configuration is then coherent and this plane has no opinion on it.
	bs.SeedFeedStatusForTest(feed, now, now, "")
	if rows := checkBlocklistFeeds(); len(rows) != 0 {
		t.Errorf("a manually-synced feed contributes no row, got %+v", rows)
	}
}

// TestChaos123_SettingsRestoreResetsTheOnlyPreRoundFailureSignal is the second
// blind shape, and it is a measurement of existing behaviour rather than a
// change to it.
//
// applyBlocklistFeeds is authoritative over the startup seed and implements
// that as ClearFeeds() + SetFeed(), which builds fresh feedStates — so a
// persistently failing feed's LastError is wiped and the pre-round WARN row
// DISAPPEARS until the next round completes. The window is bounded (the feed
// is due on the next 60 s tick) but during it the only failure signal the
// product had said "healthy". The never-synced gauge and row cover it.
func TestChaos123_SettingsRestoreResetsTheOnlyPreRoundFailureSignal(t *testing.T) {
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	bs := blFeedHealthTest(t, now)
	const feed = "https://feeds.example.com/deny.txt"
	bs.SetFeed(feed, time.Hour)
	bs.SeedFeedStatusForTest(feed, time.Time{}, now.Add(-time.Minute), "fetch: connection refused")

	if snap := blocklistFeedState(); snap.FailingFeeds != 1 {
		t.Fatalf("before the restore the failure is visible: %+v", snap)
	}

	// The restore, exactly as applyBlocklistFeeds performs it.
	bs.ClearFeeds()
	bs.SetFeed(feed, time.Hour)

	snap := blocklistFeedState()
	if snap.FailingFeeds != 0 {
		t.Fatalf("this test documents that the restore clears LastError; if that changed, re-measure: %+v", snap)
	}
	// The post-round surface still knows something is wrong, which is the
	// whole point: the feed has never successfully synced.
	if snap.NeverSyncedFeeds != 1 {
		t.Fatalf("the never-synced count must survive the restore: %+v", snap)
	}
	blocklistFeedNow = func() time.Time { return now.Add(blocklistFeedNeverSyncedGrace + time.Minute) }
	rows := checkBlocklistFeeds()
	if len(rows) != 1 || !strings.Contains(rows[0].Message, "NEVER synced") {
		t.Fatalf("the restore window must not be green, got %+v", rows)
	}
}

// ─── group 2: the alert discipline ───────────────────────────────────────────

// TestChaos123_AlertFiresOncePerEpisode — a feed that stays down must not
// re-page on every round. The counter carries the magnitude.
func TestChaos123_AlertFiresOncePerEpisode(t *testing.T) {
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	bs := blFeedHealthTest(t, now)
	fired := captureStaleAlert(t)
	const feed = "https://feeds.example.com/deny.txt"
	bs.SetFeed(feed, time.Hour)
	bs.SeedFeedStatusForTest(feed, now.Add(-10*time.Hour), now.Add(-time.Minute), "fetch: connection refused")

	for i := 0; i < 5; i++ {
		noteBlocklistFeedSync(blocklistfeed.SyncOutcome{ConsecutiveFailures: i + 1, Interval: time.Hour})
	}
	if len(*fired) != 1 {
		t.Fatalf("want one alert for five failed rounds, got %d: %v", len(*fired), *fired)
	}
}

// TestChaos123_RecoveryNeedsObservedEvidenceFromEveryAutoSyncFeed is the
// anti-flap gate.
//
// A node with one healthy and one dead feed would, if the latch cleared on any
// clean round, clear on every healthy round and re-fire on every dead one —
// paging in a loop. Clearing is therefore conditional on NO auto-sync feed
// being stale, and elapsed time never clears it.
func TestChaos123_RecoveryNeedsObservedEvidenceFromEveryAutoSyncFeed(t *testing.T) {
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	bs := blFeedHealthTest(t, now)
	fired := captureStaleAlert(t)
	const good = "https://good.example.com/deny.txt"
	const dead = "https://dead.example.com/deny.txt"
	bs.SetFeed(good, time.Hour)
	bs.SetFeed(dead, time.Hour)
	bs.SeedFeedStatusForTest(good, now.Add(-10*time.Minute), now.Add(-10*time.Minute), "")
	bs.SeedFeedStatusForTest(dead, now.Add(-10*time.Hour), now.Add(-time.Minute), "fetch: connection refused")

	// The dead feed pages once.
	noteBlocklistFeedSync(blocklistfeed.SyncOutcome{ConsecutiveFailures: 1, Interval: time.Hour})
	if len(*fired) != 1 {
		t.Fatalf("want one alert, got %v", *fired)
	}

	// The healthy feed's clean rounds must NOT clear the episode while the
	// dead one is still stale, or the pair would page in a loop.
	for i := 0; i < 3; i++ {
		noteBlocklistFeedSync(blocklistfeed.SyncOutcome{OK: true, LastSync: now, Interval: time.Hour})
		noteBlocklistFeedSync(blocklistfeed.SyncOutcome{ConsecutiveFailures: 2, Interval: time.Hour})
	}
	if len(*fired) != 1 {
		t.Fatalf("the healthy feed's rounds must not re-arm the alert, got %d: %v", len(*fired), *fired)
	}

	// Now the dead feed recovers. Only observed evidence clears the latch.
	bs.SeedFeedStatusForTest(dead, now, now, "")
	noteBlocklistFeedSync(blocklistfeed.SyncOutcome{OK: true, LastSync: now, Interval: time.Hour})

	// A fresh episode may page again.
	bs.SeedFeedStatusForTest(dead, now.Add(-10*time.Hour), now.Add(-time.Minute), "fetch: connection refused")
	noteBlocklistFeedSync(blocklistfeed.SyncOutcome{ConsecutiveFailures: 1, Interval: time.Hour})
	if len(*fired) != 2 {
		t.Fatalf("a new episode after an observed recovery must page again, got %d: %v", len(*fired), *fired)
	}
}

// TestChaos123_ClockRollbackReportsFreshNotStale — an NTP step or a VM restore
// moves the clock backwards under a running node. The feed genuinely did sync;
// paging on a clock correction is noise.
func TestChaos123_ClockRollbackReportsFreshNotStale(t *testing.T) {
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	bs := blFeedHealthTest(t, now)
	const feed = "https://feeds.example.com/deny.txt"
	bs.SetFeed(feed, time.Hour)
	// A last success in the FUTURE relative to the plane's clock.
	bs.SeedFeedStatusForTest(feed, now.Add(48*time.Hour), now.Add(48*time.Hour), "")

	snap := blocklistFeedState()
	if snap.StaleFeeds != 0 {
		t.Fatalf("a negative age must report fresh, got %+v", snap)
	}
	if snap.WorstAge != 0 {
		t.Errorf("a negative age must be clamped to zero, got %v", snap.WorstAge)
	}
	wantSeries(t, blFeedMetrics(), "culvert_blocklist_feed_stale_seconds", 0)
}

// ─── group 3: containment ────────────────────────────────────────────────────

// TestChaos123_NoSurfaceCarriesTheFeedURL is the leak gate.
//
// A feed URL is operator-configured and routinely embeds a token — the reason
// the pre-round diagnostics row already refused to print it. /metrics is the
// wider exposure of the two: it is commonly scraped unauthenticated when
// metricsToken is unset, so no series here may carry a per-feed label, and the
// alert detail reaches an egress webhook.
func TestChaos123_NoSurfaceCarriesTheFeedURL(t *testing.T) {
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	bs := blFeedHealthTest(t, now)
	fired := captureStaleAlert(t)
	const secret = "token-abc123"
	feed := "https://feeds.example.com/deny.txt?key=" + secret
	bs.SetFeed(feed, time.Hour)
	bs.SeedFeedStatusForTest(feed, now.Add(-10*time.Hour), now.Add(-time.Minute),
		"fetch "+feed+": dial tcp 203.0.113.9:443: connect: connection refused")

	surfaces := map[string]string{"metrics": blFeedMetrics()}
	for i, row := range checkBlocklistFeeds() {
		surfaces["diagnostics row "+strconv.Itoa(i)] = row.Message + " " + row.OperatorAction
	}
	noteBlocklistFeedSync(blocklistfeed.SyncOutcome{ConsecutiveFailures: 1, Interval: time.Hour})
	for i, d := range *fired {
		surfaces["alert detail "+strconv.Itoa(i)] = d
	}
	if len(*fired) == 0 {
		t.Fatal("expected the stale alert to fire, so its detail is actually under test")
	}

	for name, body := range surfaces {
		if strings.Contains(body, secret) {
			t.Errorf("%s leaked the feed URL token: %q", name, body)
		}
		if strings.Contains(body, "feeds.example.com") {
			t.Errorf("%s leaked the feed host: %q", name, body)
		}
		if strings.Contains(body, "203.0.113.9") || strings.Contains(body, "connection refused") {
			t.Errorf("%s leaked the fetch error: %q", name, body)
		}
	}
}

// TestChaos123_UnarmedPlaneEmitsNothing — before the startup slice runs (and in
// a test binary that never arms it) the plane must stay silent rather than
// export zeros that read as a broken feed.
func TestChaos123_UnarmedPlaneEmitsNothing(t *testing.T) {
	bs := newTestBlocklistSyncer(t)
	swapFeedSyncer(t, bs)
	t.Cleanup(resetBlocklistFeedHealthForTest)
	resetBlocklistFeedHealthForTest()
	bs.SetFeed("https://feeds.example.com/deny.txt", time.Hour)

	if out := blFeedMetrics(); out != "" {
		t.Errorf("an unarmed plane must emit no series, got:\n%s", out)
	}
}

// TestChaos123_NilSyncerIsSafeOnEverySurface — blFeedSyncer is nil until
// loadBlocklist runs, and SaveAdminSettings can run from a detached goroutine
// that outlives its caller. Every read-only surface must stay a 200.
func TestChaos123_NilSyncerIsSafeOnEverySurface(t *testing.T) {
	prev := blFeedSyncer
	t.Cleanup(func() {
		blFeedSyncer = prev
		resetBlocklistFeedHealthForTest()
	})
	resetBlocklistFeedHealthForTest()
	blFeedSyncer = nil
	noteBlocklistFeedConfigured()

	if snap := blocklistFeedState(); snap.Feeds != 0 || snap.StaleFeeds != 0 {
		t.Errorf("nil syncer must report no feeds, got %+v", snap)
	}
	if out := blFeedMetrics(); out != "" {
		t.Errorf("nil syncer must emit no series, got:\n%s", out)
	}
	if rows := checkBlocklistFeeds(); len(rows) != 0 {
		t.Errorf("nil syncer must contribute no row, got %+v", rows)
	}
	evaluateBlocklistFeedStaleness()
	noteBlocklistFeedSync(blocklistfeed.SyncOutcome{ConsecutiveFailures: 1})
}

// TestChaos123_SeriesAreRegisteredOnTheScrapeEndpoint — the plane is useless if
// handleMetrics never calls it. Asserted through the same builder metrics.go
// passes, so a dropped call site fails here.
func TestChaos123_SeriesAreRegisteredOnTheScrapeEndpoint(t *testing.T) {
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	bs := blFeedHealthTest(t, now)
	const feed = "https://feeds.example.com/deny.txt"
	bs.SetFeed(feed, time.Hour)
	bs.SeedFeedStatusForTest(feed, now.Add(-time.Minute), now.Add(-time.Minute), "")

	out := blFeedMetrics()
	for _, series := range []string{
		"culvert_blocklist_feed_configured",
		"culvert_blocklist_feed_autosync_enabled",
		"culvert_blocklist_feed_manual_never_synced",
		"culvert_blocklist_feed_failing",
		"culvert_blocklist_feed_never_synced",
		"culvert_blocklist_feed_stale",
		"culvert_blocklist_feed_stale_seconds",
		"culvert_blocklist_feed_oldest_success_timestamp_seconds",
		"culvert_blocklist_feed_sync_ok",
		"culvert_blocklist_feed_consecutive_sync_failures",
	} {
		if !strings.Contains(out, "# HELP "+series+" ") {
			t.Errorf("%s is missing its HELP line", series)
		}
		if !strings.Contains(out, "# TYPE "+series+" ") {
			t.Errorf("%s is missing its TYPE line", series)
		}
	}
}
