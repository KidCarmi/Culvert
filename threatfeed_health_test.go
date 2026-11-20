package main

// Gates for the threat-feed staleness plane (threatfeed_health.go).
//
// The finding: the per-source carry-forward that closed WK-5's stale-erase half
// holds culvert_threat_feed_entries at its last-good value, so after that fix a
// node whose feed has not synced in three weeks exported metrics byte-identical
// to a node that synced ten minutes ago. The only surviving difference reached
// one role-gated admin JSON field that no alerting rule scrapes.
//
// These gates pin the staleness signal, the fire-once alert, the
// recovery-on-observed-evidence rule, and — as CONTROLS — that a healthy feed
// stays silent and that an unconfigured node exports nothing.

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/threatfeed"
)

// tfHealthHarness isolates the process-global feed + health record and captures
// alerts synchronously through the package-level seam (never the real sink —
// that is the -count/-shuffle determinism class the CI gate catches).
//
// The seam mirrors the production sink's contract: it reports DISPATCHED only
// while subscribed is true (the default, so the long-standing gates keep their
// "a page was sent" meaning), and records every attempt separately so a gate
// can tell "never reached the sink" from "reached it, but nobody subscribed".
type tfHealthHarness struct {
	mu         sync.Mutex
	alerts     []string // dispatched pages only
	attempts   int
	subscribed bool
	now        time.Time
}

func newTFHealthHarness(t *testing.T, interval time.Duration) (*tfHealthHarness, *threatfeed.Feed) {
	t.Helper()
	h := &tfHealthHarness{now: time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC), subscribed: true}

	prevFeed := globalThreatFeed
	prevAlert := fireThreatFeedStaleAlert
	resetThreatFeedHealthForTest()

	feed := threatfeed.New()
	feed.Init("", interval) // "" = no persistence
	globalThreatFeed = feed

	threatFeedNow = func() time.Time {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.now
	}
	fireThreatFeedStaleAlert = func(detail string) bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.attempts++
		if !h.subscribed {
			return false
		}
		h.alerts = append(h.alerts, detail)
		return true
	}
	noteThreatFeedConfigured()

	t.Cleanup(func() {
		resetThreatFeedHealthForTest()
		globalThreatFeed = prevFeed
		fireThreatFeedStaleAlert = prevAlert
	})
	return h, feed
}

func (h *tfHealthHarness) advance(d time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(d)
	h.mu.Unlock()
}

func (h *tfHealthHarness) fired() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.alerts...)
}

// syncOK drives a clean round through the same observer production uses.
func (h *tfHealthHarness) syncOK(feed *threatfeed.Feed) {
	h.mu.Lock()
	now := h.now
	h.mu.Unlock()
	feed.SeedSyncSuccessForTest(now)
	noteThreatFeedSync(threatfeed.SyncOutcome{OK: true, LastSuccess: now})
}

// syncFail drives a failed round through the observer.
func (h *tfHealthHarness) syncFail(feed *threatfeed.Feed, sources string, consecutive int) {
	feed.SeedSyncFailureForTest(sources)
	noteThreatFeedSync(threatfeed.SyncOutcome{OK: false, FailedSources: sources, ConsecutiveFailures: consecutive})
}

// ── Staleness detection ───────────────────────────────────────────────────────

// TestThreatFeedStale_FiresAfterTwoIntervals is the primary gate. The feed
// synced cleanly, then stopped; the entry count is unchanged throughout (the
// carry-forward contract), so this is the ONLY signal that anything is wrong.
func TestThreatFeedStale_FiresAfterTwoIntervals(t *testing.T) {
	h, feed := newTFHealthHarness(t, 6*time.Hour)
	h.syncOK(feed)

	// One missed window is not yet stale: that is the transient the backoff
	// ladder exists to absorb, and paging on it would be noise.
	h.advance(7 * time.Hour)
	h.syncFail(feed, "urlhaus", 1)
	if got := h.fired(); len(got) != 0 {
		t.Fatalf("alerted after 7h (< 2x the 6h interval): %v", got)
	}
	if snap := threatFeedState(); snap.Stale {
		t.Fatal("reported stale after 7h with a 6h interval")
	}

	// Past 2x the interval it is no longer a blip.
	h.advance(6 * time.Hour) // 13h total
	h.syncFail(feed, "urlhaus", 2)
	got := h.fired()
	if len(got) != 1 {
		t.Fatalf("alerts fired = %d, want exactly 1 after crossing the staleness threshold", len(got))
	}
	if !strings.Contains(got[0], "urlhaus") {
		t.Errorf("alert detail %q does not name the failing source", got[0])
	}
	if !threatFeedState().Stale {
		t.Fatal("threatFeedState().Stale = false past 2x the interval")
	}
}

// TestThreatFeedStale_FiresOncePerEpisode — a feed that stays down must not
// re-page on every round. The alert store's own dedup window is 30 s; a feed
// retrying hourly would out-live it and page forever.
func TestThreatFeedStale_FiresOncePerEpisode(t *testing.T) {
	h, feed := newTFHealthHarness(t, time.Hour)
	h.syncOK(feed)
	h.advance(5 * time.Hour)

	for i := 1; i <= 10; i++ {
		h.syncFail(feed, "urlhaus+openphish", i)
		h.advance(time.Hour)
	}
	if got := h.fired(); len(got) != 1 {
		t.Fatalf("alerts fired = %d over 10 failing rounds, want exactly 1 (fire-once latch)", len(got))
	}
}

// TestThreatFeedStale_RecoversOnObservedEvidenceOnly — the recovery rule this
// codebase applies everywhere: elapsed time never clears a degraded state,
// because a feed that stopped reporting failures because nothing is running
// looks identical to a healthy one. Only a clean round clears it, and a LATER
// episode must be able to page again.
func TestThreatFeedStale_RecoversOnObservedEvidenceOnly(t *testing.T) {
	h, feed := newTFHealthHarness(t, time.Hour)
	h.syncOK(feed)
	h.advance(5 * time.Hour)
	h.syncFail(feed, "urlhaus", 1)
	if len(h.fired()) != 1 {
		t.Fatalf("expected the first episode to alert, got %v", h.fired())
	}

	// Elapsed time alone must NOT re-arm the latch.
	h.advance(50 * time.Hour)
	if snap := threatFeedState(); !snap.Stale {
		t.Fatal("still-unsynced feed reported fresh purely because time passed")
	}

	// An OBSERVED clean round clears the episode...
	h.syncOK(feed)
	if snap := threatFeedState(); snap.Stale {
		t.Fatal("feed still reported stale after an observed successful sync")
	}
	// ...and a NEW episode can page again.
	h.advance(5 * time.Hour)
	h.syncFail(feed, "openphish", 1)
	if got := h.fired(); len(got) != 2 {
		t.Fatalf("alerts fired = %d, want 2 (a second episode must be able to page)", len(got))
	}
}

// TestThreatFeedStale_HealthyFeedNeverAlerts is the CONTROL. A gate that fired
// on every round would pass every test above while being useless.
func TestThreatFeedStale_HealthyFeedNeverAlerts(t *testing.T) {
	h, feed := newTFHealthHarness(t, time.Hour)
	for i := 0; i < 20; i++ {
		h.syncOK(feed)
		h.advance(time.Hour)
	}
	if got := h.fired(); len(got) != 0 {
		t.Fatalf("a continuously healthy feed alerted %d times: %v", len(got), got)
	}
	if snap := threatFeedState(); snap.Stale || snap.NeverSynced {
		t.Fatalf("healthy feed reported stale=%v neverSynced=%v", snap.Stale, snap.NeverSynced)
	}
}

// TestThreatFeedStale_ClockRollbackDoesNotAlert — an NTP step or a VM restore
// can move the clock backwards under a live process. The feed genuinely did
// sync; paging on a clock correction is noise, and the fail-safe direction here
// is to report fresh.
func TestThreatFeedStale_ClockRollbackDoesNotAlert(t *testing.T) {
	h, feed := newTFHealthHarness(t, time.Hour)
	h.syncOK(feed)
	h.advance(-48 * time.Hour)

	snap := threatFeedState()
	if snap.Stale {
		t.Fatal("reported stale after a backwards clock step")
	}
	if snap.Age < 0 {
		t.Fatalf("Age = %s, want a non-negative value", snap.Age)
	}
}

// ── The never-synced case ─────────────────────────────────────────────────────

// TestThreatFeedNeverSynced_AlertsAfterTheGrace is the SEVERE shape: a fresh or
// re-imaged node whose first sync fails is enforcing with NO threat-feed
// coverage — not stale intelligence, none — while every probe reports a healthy
// node. It must be surfaced in minutes, not at 2x a six-hour interval.
func TestThreatFeedNeverSynced_AlertsAfterTheGrace(t *testing.T) {
	h, feed := newTFHealthHarness(t, 6*time.Hour)

	// Inside the grace, a node that simply has not finished its first sync is
	// not a fault.
	h.advance(5 * time.Minute)
	h.syncFail(feed, "urlhaus+openphish", 1)
	if got := h.fired(); len(got) != 0 {
		t.Fatalf("alerted %d times inside the startup grace: %v", len(got), got)
	}
	if row := checkThreatFeed(); row.Status != diagOK {
		t.Errorf("diagnostics row inside the grace = %q, want ok", row.Status)
	}

	// Past it, the node has been enforcing without coverage long enough to say so.
	h.advance(threatFeedNeverSyncedGrace)
	h.syncFail(feed, "urlhaus+openphish", 2)
	got := h.fired()
	if len(got) != 1 {
		t.Fatalf("alerts fired = %d past the grace, want 1", len(got))
	}
	if !strings.Contains(got[0], "NEVER synced") {
		t.Errorf("alert detail %q does not distinguish the never-synced case", got[0])
	}
	snap := threatFeedState()
	if !snap.NeverSynced || !snap.Stale {
		t.Fatalf("neverSynced=%v stale=%v, want both true", snap.NeverSynced, snap.Stale)
	}
}

// ── Metrics ───────────────────────────────────────────────────────────────────

// TestThreatFeedMetrics_AbsentWhenNotConfigured — the CHAOS-54 rule. A
// `culvert_threat_feed_sync_ok 0` on a node that never ran the feed is
// indistinguishable from a node whose feed is broken, and the documented paging
// rule is `== 0`, so an unconditional gauge would page every deployment that
// does not use the feature.
func TestThreatFeedMetrics_AbsentWhenNotConfigured(t *testing.T) {
	resetThreatFeedHealthForTest()
	var b strings.Builder
	threatFeedWritePrometheus(&b)
	if got := b.String(); got != "" {
		t.Fatalf("metrics emitted on an unconfigured node:\n%s", got)
	}
}

// TestThreatFeedMetrics_ExposeFreshnessWhenConfigured — the whole point: a
// stale feed must be distinguishable from a fresh one on /metrics, where the
// entry-count gauge is identical for both.
func TestThreatFeedMetrics_ExposeFreshnessWhenConfigured(t *testing.T) {
	h, feed := newTFHealthHarness(t, time.Hour)
	h.syncOK(feed)

	var fresh strings.Builder
	threatFeedWritePrometheus(&fresh)
	for _, want := range []string{
		"culvert_threat_feed_last_success_timestamp_seconds",
		"culvert_threat_feed_stale_seconds 0",
		"culvert_threat_feed_sync_ok 1",
		"culvert_threat_feed_sync_failures_total 0",
		"culvert_threat_feed_consecutive_sync_failures 0",
	} {
		if !strings.Contains(fresh.String(), want) {
			t.Errorf("fresh-feed metrics missing %q:\n%s", want, fresh.String())
		}
	}

	h.advance(10 * time.Hour)
	h.syncFail(feed, "urlhaus", 1)

	var stale strings.Builder
	threatFeedWritePrometheus(&stale)
	if !strings.Contains(stale.String(), "culvert_threat_feed_sync_ok 0") {
		t.Errorf("stale-feed metrics do not report sync_ok 0:\n%s", stale.String())
	}
	if !strings.Contains(stale.String(), "culvert_threat_feed_consecutive_sync_failures 1") {
		t.Errorf("stale-feed metrics do not report the consecutive failure count:\n%s", stale.String())
	}
	if strings.Contains(stale.String(), "culvert_threat_feed_stale_seconds 0\n") {
		t.Errorf("stale_seconds still reads 0 after 10h without a successful sync:\n%s", stale.String())
	}
}

// TestThreatFeedMetrics_CarryNoFeedURLsOrErrorText — the metrics surface is
// scraped by systems with a different trust boundary than the admin API, and
// the failure summary embeds feed URLs and ephemeral local ports.
func TestThreatFeedMetrics_CarryNoFeedURLsOrErrorText(t *testing.T) {
	h, feed := newTFHealthHarness(t, time.Hour)
	h.syncOK(feed)
	h.advance(10 * time.Hour)
	h.syncFail(feed, "urlhaus", 1)

	var b strings.Builder
	threatFeedWritePrometheus(&b)
	for _, forbidden := range []string{"http://", "https://", "abuse.ch", "openphish.com", "dial", "timeout"} {
		if strings.Contains(b.String(), forbidden) {
			t.Errorf("metrics contain %q — feed URLs and error text must not reach /metrics:\n%s", forbidden, b.String())
		}
	}
}

// ── Diagnostics row ───────────────────────────────────────────────────────────

// TestCheckThreatFeed_Severities pins the row's severity policy, including the
// deliberate choice NOT to use a fail status: every other control is intact and
// the condition self-heals, so warn is the honest severity.
func TestCheckThreatFeed_Severities(t *testing.T) {
	// Not configured → ok, and no permanent row noise.
	resetThreatFeedHealthForTest()
	if row := checkThreatFeed(); row.Status != diagOK || !strings.Contains(row.Message, "not configured") {
		t.Errorf("unconfigured row = %+v, want an ok 'not configured' row", row)
	}

	h, feed := newTFHealthHarness(t, time.Hour)
	h.syncOK(feed)
	if row := checkThreatFeed(); row.Status != diagOK {
		t.Errorf("fresh-feed row = %q, want ok", row.Status)
	}

	h.advance(10 * time.Hour)
	h.syncFail(feed, "urlhaus", 1)
	row := checkThreatFeed()
	if row.Status != diagWarn {
		t.Fatalf("stale-feed row = %q, want warn", row.Status)
	}
	if row.OperatorAction == "" {
		t.Error("stale-feed row carries no operator action")
	}
	if row.Code != "threat_feed" {
		t.Errorf("row code = %q, want threat_feed", row.Code)
	}

	// Recovery returns the row to ok while retaining the failure HISTORY.
	h.syncOK(feed)
	row = checkThreatFeed()
	if row.Status != diagOK {
		t.Fatalf("recovered row = %q, want ok", row.Status)
	}
	if !strings.Contains(row.Message, "transient sync failure") {
		t.Errorf("recovered row %q does not retain the failure history", row.Message)
	}
}

// TestCheckThreatFeed_RowIsInTheDiagnosticsReport — a row nobody registers is a
// row nobody sees.
func TestCheckThreatFeed_RowIsInTheDiagnosticsReport(t *testing.T) {
	h, feed := newTFHealthHarness(t, time.Hour)
	h.syncOK(feed)
	for _, c := range buildOperatorContract().Checks {
		if c.Code == "threat_feed" {
			return
		}
	}
	t.Fatal("no threat_feed row in the operator-contract report")
}

// ── Review-driven gates (PR #1305, Codex) ─────────────────────────────────────

// TestThreatFeedSyncOK_SurvivesARestartFromAFailedSync — the failure count is
// deliberately not persisted (the true run length across restarts is
// unknowable), so a gauge derived from it reported a green
// culvert_threat_feed_sync_ok 1 after a restart from a DB written by a failed
// sync — for hours, until the next scheduled round. The gauge must derive from
// the PERSISTED error state instead.
func TestThreatFeedSyncOK_SurvivesARestartFromAFailedSync(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.json")

	// A feed that synced cleanly, then failed, then persisted.
	writer := threatfeed.New()
	writer.Init(path, time.Hour)
	writer.SeedSyncSuccessForTest(time.Now().Add(-30 * time.Minute))
	writer.SeedSyncFailureForTest("urlhaus")
	writer.Save()

	// A fresh process loading that DB.
	prevFeed := globalThreatFeed
	prevAlert := fireThreatFeedStaleAlert
	prevDefer := deferThreatFeedStaleAlert
	resetThreatFeedHealthForTest()
	reloaded := threatfeed.New()
	reloaded.Init(path, time.Hour)
	globalThreatFeed = reloaded
	fireThreatFeedStaleAlert = func(string) bool { return false }
	deferThreatFeedStaleAlert = func(string, uint64) {}
	noteThreatFeedConfigured()
	t.Cleanup(func() {
		resetThreatFeedHealthForTest()
		globalThreatFeed = prevFeed
		fireThreatFeedStaleAlert = prevAlert
		deferThreatFeedStaleAlert = prevDefer
	})

	if h := reloaded.Health(); h.LastRoundOK {
		t.Fatal("LastRoundOK = true after loading a DB whose last sync failed")
	}
	var b strings.Builder
	threatFeedWritePrometheus(&b)
	if !strings.Contains(b.String(), "culvert_threat_feed_sync_ok 0") {
		t.Fatalf("sync_ok reports healthy after restarting from a failed-sync DB:\n%s", b.String())
	}
	if strings.Contains(b.String(), "culvert_threat_feed_consecutive_sync_failures 0") {
		t.Fatalf("consecutive failure count reads 0 after restarting from a failed-sync DB:\n%s", b.String())
	}
}

// TestThreatFeedStale_EvaluatedAtStartupForAWarmButStaleDatabase — a node can
// boot ALREADY stale: the on-disk DB is warm (so no immediate round is armed)
// but its last success is days old. Staleness used to be evaluated only after a
// failed round, and the first round is a full jittered interval away — so no
// alert fired for that whole window, and none at all if that round succeeded.
//
// The alert must go through the startup-alert QUEUE, not fire directly: the
// webhook store is loaded by a later startup slice, so a direct fire would fan
// out to an empty subscriber list and vanish.
func TestThreatFeedStale_EvaluatedAtStartupForAWarmButStaleDatabase(t *testing.T) {
	var mu sync.Mutex
	var deferred, direct []string

	prevFeed := globalThreatFeed
	prevAlert := fireThreatFeedStaleAlert
	prevDefer := deferThreatFeedStaleAlert
	resetThreatFeedHealthForTest()

	feed := threatfeed.New()
	feed.Init("", time.Hour)
	feed.SeedSyncSuccessForTest(time.Now().Add(-72 * time.Hour)) // three days stale
	globalThreatFeed = feed
	fireThreatFeedStaleAlert = func(d string) bool { mu.Lock(); direct = append(direct, d); mu.Unlock(); return true }
	deferThreatFeedStaleAlert = func(d string, _ uint64) { mu.Lock(); deferred = append(deferred, d); mu.Unlock() }
	t.Cleanup(func() {
		resetThreatFeedHealthForTest()
		globalThreatFeed = prevFeed
		fireThreatFeedStaleAlert = prevAlert
		deferThreatFeedStaleAlert = prevDefer
	})

	noteThreatFeedConfigured()

	mu.Lock()
	defer mu.Unlock()
	if len(deferred) != 1 {
		t.Fatalf("startup queued %d stale alerts for a 3-day-stale warm database, want 1", len(deferred))
	}
	if !strings.Contains(deferred[0], "stale at startup") {
		t.Errorf("startup alert detail %q does not identify the boot-time case", deferred[0])
	}
	if len(direct) != 0 {
		t.Errorf("startup fired %d alerts directly instead of through the startup queue — they would fan out to an empty webhook list", len(direct))
	}
}

// TestThreatFeedStale_StartupIsSilentForAFreshOrHealthyNode is the CONTROL. An
// alert that fired at every boot would pass the gate above while paging on
// every restart of every healthy appliance.
func TestThreatFeedStale_StartupIsSilentForAFreshOrHealthyNode(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed func(*threatfeed.Feed)
	}{
		{"never synced (fresh install)", func(*threatfeed.Feed) {}},
		{"synced ten minutes ago", func(f *threatfeed.Feed) { f.SeedSyncSuccessForTest(time.Now().Add(-10 * time.Minute)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var deferred []string

			prevFeed := globalThreatFeed
			prevDefer := deferThreatFeedStaleAlert
			prevAlert := fireThreatFeedStaleAlert
			resetThreatFeedHealthForTest()

			feed := threatfeed.New()
			feed.Init("", time.Hour)
			tc.seed(feed)
			globalThreatFeed = feed
			deferThreatFeedStaleAlert = func(d string, _ uint64) { mu.Lock(); deferred = append(deferred, d); mu.Unlock() }
			fireThreatFeedStaleAlert = func(string) bool { return false }
			t.Cleanup(func() {
				resetThreatFeedHealthForTest()
				globalThreatFeed = prevFeed
				deferThreatFeedStaleAlert = prevDefer
				fireThreatFeedStaleAlert = prevAlert
			})

			noteThreatFeedConfigured()

			mu.Lock()
			defer mu.Unlock()
			if len(deferred) != 0 {
				t.Fatalf("startup alerted on a %s node: %v", tc.name, deferred)
			}
		})
	}
}

// ── SEC-TFEED-STALE-LATCH-1: the episode is consumed only by a delivered page ──

// tfAlerted reads the plane's fire-once latch.
func tfAlerted() bool {
	threatFeedHealth.mu.Lock()
	defer threatFeedHealth.mu.Unlock()
	return threatFeedHealth.alerted
}

// TestThreatFeedStale_UndeliveredAlertDoesNotConsumeTheEpisode is the runtime
// half of SEC-TFEED-STALE-LATCH-1, the threat-feed sibling of
// SEC-BLFEED-STALE-LATCH-1.
//
// The stale alert fires at most once per episode, and the episode clears only
// on an OBSERVED clean sync or a restart — never on elapsed time. The latch
// used to be set before the sink ran, and the sink drops the alert when
// nothing subscribes, which is the DEFAULT posture. So the first stale round
// spent the node's one page on nobody, and an operator who subscribed to
// threat_feed_stale afterwards was never paged while the gateway went on
// enforcing against intelligence that was not refreshing.
func TestThreatFeedStale_UndeliveredAlertDoesNotConsumeTheEpisode(t *testing.T) {
	h, feed := newTFHealthHarness(t, 6*time.Hour)
	h.syncOK(feed)
	h.advance(13 * time.Hour) // past 2x the 6h interval

	// Phase 1: nothing subscribes, so the sink dispatches nothing.
	h.mu.Lock()
	h.subscribed = false
	h.mu.Unlock()
	for i := 1; i <= 3; i++ {
		h.syncFail(feed, "tflatch-src-before", i)
		h.advance(time.Hour)
	}
	h.mu.Lock()
	attempts := h.attempts
	h.mu.Unlock()
	if attempts == 0 {
		t.Fatal("precondition: the stale evaluation never reached the alert sink")
	}
	if got := h.fired(); len(got) != 0 {
		t.Fatalf("pages dispatched with no subscriber: %v", got)
	}

	// Phase 2: the operator adds the webhook. The feed is still stale and the
	// episode was never delivered, so the next failed round must page.
	h.mu.Lock()
	h.subscribed = true
	h.mu.Unlock()
	h.syncFail(feed, "tflatch-src-after", 4)
	got := h.fired()
	if len(got) != 1 {
		t.Fatalf("pages after the webhook was added = %d, want 1: the episode was consumed by an alert "+
			"that reached nobody, so a feed that is still stale never pages (SEC-TFEED-STALE-LATCH-1)", len(got))
	}
	if !strings.Contains(got[0], "tflatch-src-after") {
		t.Errorf("page %q is not the post-subscription round's alert", got[0])
	}

	// And the latch still holds once delivery HAS happened.
	for i := 5; i <= 8; i++ {
		h.advance(time.Hour)
		h.syncFail(feed, "tflatch-src-later", i)
	}
	if got := h.fired(); len(got) != 1 {
		t.Errorf("pages = %d after further failed rounds, want 1: a delivered episode must still page only once", len(got))
	}
}

// TestThreatFeedStale_ConcurrentRoundsPageOncePerEpisode — the latch decision
// stays inside the plane's lock, so concurrent failed rounds racing to report
// the same episode dispatch exactly one page. Probing the subscription outside
// the lock and latching afterwards would reopen a double-page window. Run with
// -race.
func TestThreatFeedStale_ConcurrentRoundsPageOncePerEpisode(t *testing.T) {
	h, feed := newTFHealthHarness(t, time.Hour)
	h.syncOK(feed)
	h.advance(5 * time.Hour)
	feed.SeedSyncFailureForTest("tflatch-src-concurrent")

	const rounds = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < rounds; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			noteThreatFeedSync(threatfeed.SyncOutcome{FailedSources: "tflatch-src-concurrent", ConsecutiveFailures: i + 1})
		}(i)
	}
	close(start)
	wg.Wait()

	got := h.fired()
	if len(got) != 1 {
		t.Fatalf("%d concurrent failed rounds dispatched %d pages, want exactly 1", rounds, len(got))
	}
	if !strings.Contains(got[0], "tflatch-src-concurrent") {
		t.Errorf("page %q does not name the failing source", got[0])
	}
	h.mu.Lock()
	attempts := h.attempts
	h.mu.Unlock()
	if attempts != 1 {
		t.Errorf("the sink ran %d times, want 1: once delivered, the latch must short-circuit before the sink", attempts)
	}
}

// TestThreatFeedStale_SinkReportsDispatchOnlyWithASubscriber pins the
// production sink's half of the contract: with no subscriber it reports false
// and dispatches nothing; with one it dispatches and reports true.
func TestThreatFeedStale_SinkReportsDispatchOnlyWithASubscriber(t *testing.T) {
	tfSwapAlertStore(t, false)
	dispatched := make(chan string, 4)
	prevFire := fireAlert
	fireAlert = func(event string, p AlertPayload) {
		if event == "threat_feed_stale" {
			dispatched <- p.Detail
		}
	}
	t.Cleanup(func() { fireAlert = prevFire })

	if fireThreatFeedStaleAlert("tflatch-sink-nobody") {
		t.Fatal("the sink reported a dispatch with no threat_feed_stale subscriber")
	}

	tfSwapAlertStore(t, true)
	if !fireThreatFeedStaleAlert("tflatch-sink-subscribed") {
		t.Fatal("the sink reported no dispatch with a threat_feed_stale subscriber")
	}
	select {
	case d := <-dispatched:
		if d != "tflatch-sink-subscribed" {
			t.Fatalf("dispatched %q, want the subscribed call's detail (the no-subscriber call must dispatch nothing)", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the sink reported a dispatch but none arrived")
	}
}

// ── The deferred startup path ─────────────────────────────────────────────────

// tfSwapAlertStore installs a fresh process-wide alert store, with or without
// an enabled threat_feed_stale webhook, and restores the previous one at
// cleanup. Delivery is never reached: every gate below captures the sinks.
func tfSwapAlertStore(t *testing.T, subscribed bool) {
	t.Helper()
	orig := alertStore()
	t.Cleanup(func() { alertStoreRef.Store(orig) })
	as := &AlertStore{}
	as.Init("")
	if subscribed {
		as.Add(AlertWebhook{Name: "tflatch", URL: "https://alerts.example.invalid/hook", Events: []string{"threat_feed_stale"}, Enabled: true})
	}
	alertStoreRef.Store(as)
}

// tfStartupHarness is a node whose persisted threat DB is warm but three days
// stale, booting with the startup-alert queue isolated (flushed says whether
// the flush has already happened) and the process-wide alert store empty, as
// it is before loadPersistentAdminState loads the webhooks.
//
// Both sinks are captured synchronously: the flush's startupAlertFire, and the
// runtime sink, replaced by a mirror of the production gate that probes the
// REAL subscription index (threatFeedStaleSubscribed) instead of spawning the
// delivery goroutine.
type tfStartupHarness struct {
	mu      sync.Mutex
	runtime []string // runtime-sink pages (always to a subscriber)
	flushTo []string // details the flush handed to Dispatch, tagged with whether anyone subscribed
	feed    *threatfeed.Feed
	now     time.Time

	// recoverOnNow arms a one-shot recovery inside the NEXT threatFeedNow
	// call: a clean round lands after a staleness verdict has read the feed's
	// health but before the latch decision. threatFeedState reads the clock
	// after the health and without the plane's lock, so this is exactly the
	// window SEC-TFEED-STALE-LATCH-1's generation guard closes. Arm it only
	// immediately before a direct threatFeedState caller: noteThreatFeedSync
	// and noteThreatFeedConfigured read the clock under the plane's lock.
	recoverOnNow  bool
	recoveryFired bool
}

func (h *tfStartupHarness) armRecovery() {
	h.mu.Lock()
	h.recoverOnNow = true
	h.mu.Unlock()
}

func (h *tfStartupHarness) recovered() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.recoveryFired
}

// recoverNow drives a clean round through the production observer.
func (h *tfStartupHarness) recoverNow() {
	h.mu.Lock()
	now := h.now
	h.mu.Unlock()
	h.feed.SeedSyncSuccessForTest(now)
	noteThreatFeedSync(threatfeed.SyncOutcome{OK: true, LastSuccess: now})
}

func (h *tfStartupHarness) runtimePages() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.runtime)
}

func newTFStartupHarness(t *testing.T, flushed bool) *tfStartupHarness {
	t.Helper()
	h := &tfStartupHarness{now: time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)}

	startupAlertMu.Lock()
	prevQueue, prevFlushed := startupAlertQueue, startupAlertFlushed
	startupAlertQueue, startupAlertFlushed = nil, flushed
	startupAlertMu.Unlock()
	prevStartupFire := startupAlertFire
	prevFeed := globalThreatFeed
	prevAlert := fireThreatFeedStaleAlert
	prevDefer := deferThreatFeedStaleAlert
	resetThreatFeedHealthForTest()
	t.Cleanup(func() {
		startupAlertMu.Lock()
		startupAlertQueue, startupAlertFlushed = prevQueue, prevFlushed
		startupAlertMu.Unlock()
		startupAlertFire = prevStartupFire
		resetThreatFeedHealthForTest()
		globalThreatFeed = prevFeed
		fireThreatFeedStaleAlert = prevAlert
		deferThreatFeedStaleAlert = prevDefer
	})
	tfSwapAlertStore(t, false)

	startupAlertFire = func(event string, p AlertPayload) {
		if event != "threat_feed_stale" {
			return
		}
		tag := "nobody: "
		if threatFeedStaleSubscribed() {
			tag = "subscriber: "
		}
		h.mu.Lock()
		h.flushTo = append(h.flushTo, tag+p.Detail)
		h.mu.Unlock()
	}
	fireThreatFeedStaleAlert = func(detail string) bool {
		if !threatFeedStaleSubscribed() {
			return false
		}
		h.mu.Lock()
		h.runtime = append(h.runtime, detail)
		h.mu.Unlock()
		return true
	}
	threatFeedNow = func() time.Time {
		h.mu.Lock()
		now, recoverNow := h.now, h.recoverOnNow
		h.recoverOnNow = false
		if recoverNow {
			h.recoveryFired = true
		}
		h.mu.Unlock()
		if recoverNow {
			h.recoverNow()
		}
		return now
	}

	h.feed = threatfeed.New()
	h.feed.Init("", time.Hour)
	h.feed.SeedSyncSuccessForTest(h.now.Add(-72 * time.Hour))
	globalThreatFeed = h.feed
	return h
}

func (h *tfStartupHarness) queued() int {
	startupAlertMu.Lock()
	defer startupAlertMu.Unlock()
	return len(startupAlertQueue)
}

// pages is every page that reached a subscriber, from either path.
func (h *tfStartupHarness) pages() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := append([]string(nil), h.runtime...)
	for _, d := range h.flushTo {
		if strings.HasPrefix(d, "subscriber: ") {
			out = append(out, d)
		}
	}
	return out
}

func (h *tfStartupHarness) flushed() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.flushTo...)
}

func (h *tfStartupHarness) fail(n int) {
	h.feed.SeedSyncFailureForTest("tflatch-src-startup")
	noteThreatFeedSync(threatfeed.SyncOutcome{FailedSources: "tflatch-src-startup", ConsecutiveFailures: n})
}

// TestThreatFeedStale_StartupAlertQueuedThenFlushedPagesOnce — the boot-time
// alert queued before the webhooks load is delivered once at the flush and
// counts as the episode's page: later failed rounds do not re-send it.
func TestThreatFeedStale_StartupAlertQueuedThenFlushedPagesOnce(t *testing.T) {
	h := newTFStartupHarness(t, false)
	noteThreatFeedConfigured()
	if n := h.queued(); n != 1 {
		t.Fatalf("startup queued %d alerts for a 3-day-stale warm DB, want 1", n)
	}
	if tfAlerted() {
		t.Fatal("the episode was latched at ENQUEUE — before anything could know whether the page reaches a subscriber")
	}

	tfSwapAlertStore(t, true) // loadPersistentAdminState: alertStore().Init loads a subscribed webhook
	flushStartupAlerts()
	got := h.pages()
	if len(got) != 1 || !strings.Contains(got[0], "stale at startup") {
		t.Fatalf("pages after the flush = %v, want exactly the boot-time stale alert", got)
	}
	if !tfAlerted() {
		t.Fatal("a delivered startup page did not consume the episode")
	}

	for i := 1; i <= 4; i++ {
		h.fail(i)
	}
	if got := h.pages(); len(got) != 1 {
		t.Fatalf("pages = %v after failed rounds following the flush, want only the startup page (no re-send)", got)
	}
}

// TestThreatFeedStale_StartupAlertFlushedToNobodyDoesNotConsumeTheEpisode is
// the startup half of SEC-TFEED-STALE-LATCH-1, and the review's scenario: a
// node boots with stale threat intelligence and no webhook. Being accepted
// into the queue is not delivery — the flush hands the alert to Dispatch,
// which reaches nobody — so the episode must stay open for the operator who
// subscribes afterwards.
func TestThreatFeedStale_StartupAlertFlushedToNobodyDoesNotConsumeTheEpisode(t *testing.T) {
	h := newTFStartupHarness(t, false)
	noteThreatFeedConfigured()
	flushStartupAlerts() // the store loaded with no webhooks: the default posture

	if got := h.flushed(); len(got) != 1 || !strings.HasPrefix(got[0], "nobody: ") {
		t.Fatalf("flush handed %v to Dispatch, want the one queued alert, with no subscriber", got)
	}

	tfSwapAlertStore(t, true) // the operator adds the threat_feed_stale webhook
	h.fail(1)
	got := h.pages()
	if len(got) != 1 {
		t.Fatalf("pages after the webhook was added = %v, want exactly 1: a node that booted stale with no "+
			"webhook must still page the operator who subscribes later (SEC-TFEED-STALE-LATCH-1)", got)
	}
	if !strings.Contains(got[0], "tflatch-src-startup") {
		t.Errorf("page %q is not the post-subscription round's alert", got[0])
	}
	h.fail(2)
	if got := h.pages(); len(got) != 1 {
		t.Errorf("pages = %v, want 1: the delivered episode must page only once", got)
	}
}

// TestThreatFeedStale_RoundBetweenWebhookLoadAndFlushPagesOnce — a failed
// round that runs after alertStore().Init but before the flush pages the
// episode itself; the queued copy must then be dropped, not sent as a second
// page.
func TestThreatFeedStale_RoundBetweenWebhookLoadAndFlushPagesOnce(t *testing.T) {
	h := newTFStartupHarness(t, false)
	noteThreatFeedConfigured()
	tfSwapAlertStore(t, true)
	h.fail(1)
	if got := h.pages(); len(got) != 1 {
		t.Fatalf("the round after the webhooks loaded paged %v, want 1", got)
	}
	flushStartupAlerts()
	if got := h.flushed(); len(got) != 0 {
		t.Errorf("the flush re-sent the already-paged episode: %v", got)
	}
	if got := h.pages(); len(got) != 1 {
		t.Errorf("pages = %v, want exactly 1 for the episode", got)
	}
}

// TestThreatFeedStale_FlushRacingFailedRoundsPagesOnce — the flush claim and
// the runtime rounds decide under the same lock, so a flush racing concurrent
// failed rounds still pages the episode exactly once. Run with -race.
func TestThreatFeedStale_FlushRacingFailedRoundsPagesOnce(t *testing.T) {
	h := newTFStartupHarness(t, false)
	noteThreatFeedConfigured()
	tfSwapAlertStore(t, true)
	h.feed.SeedSyncFailureForTest("tflatch-src-startup")

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			noteThreatFeedSync(threatfeed.SyncOutcome{FailedSources: "tflatch-src-startup", ConsecutiveFailures: i + 1})
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		flushStartupAlerts()
	}()
	close(start)
	wg.Wait()

	if got := h.pages(); len(got) != 1 {
		t.Fatalf("a flush racing failed rounds paged %d times, want exactly 1: %v", len(got), got)
	}
}

// TestThreatFeedStale_StartupAlertForARecoveredEpisodeIsDropped — a clean
// round that lands before the flush ends the episode the boot-time alert was
// raised in. The flush runs after Start launched the scheduler, so this is
// reachable. The queued copy says the gateway "is enforcing against stale
// intelligence until the feed resyncs", and the episode generation proves it
// has resynced: it is dropped (the CHAOS-71 "condition cleared" rule) and,
// above all, it must not latch — a latch set now would silence the next real
// episode until another clean sync.
func TestThreatFeedStale_StartupAlertForARecoveredEpisodeIsDropped(t *testing.T) {
	h := newTFStartupHarness(t, false)
	noteThreatFeedConfigured()

	h.mu.Lock()
	now := h.now
	h.mu.Unlock()
	h.feed.SeedSyncSuccessForTest(now)
	noteThreatFeedSync(threatfeed.SyncOutcome{OK: true, LastSuccess: now})

	tfSwapAlertStore(t, true)
	flushStartupAlerts()
	if got := h.flushed(); len(got) != 0 {
		t.Fatalf("flush delivered %v for an episode that recovered before it, want the queued copy dropped", got)
	}
	if tfAlerted() {
		t.Fatal("a startup alert for an episode that recovered before the flush latched the plane")
	}

	// The next real episode still pages.
	h.mu.Lock()
	h.now = h.now.Add(3 * time.Hour)
	h.mu.Unlock()
	h.fail(1)
	if got := h.pages(); len(got) != 1 || !strings.Contains(got[0], "tflatch-src-startup") {
		t.Fatalf("pages = %v, want exactly the new episode's page", got)
	}
}

// TestThreatFeedStale_ArmedAfterTheFlushLatchesOnDelivery — after the flush the
// queue is a passthrough that never consults the claim, so a plane armed late
// takes the runtime sink: no subscriber leaves the episode open, a subscriber
// is paged once.
func TestThreatFeedStale_ArmedAfterTheFlushLatchesOnDelivery(t *testing.T) {
	h := newTFStartupHarness(t, true)
	noteThreatFeedConfigured()
	if n := h.queued(); n != 0 {
		t.Fatalf("a post-flush arm queued %d alerts, want 0", n)
	}
	if got := h.flushed(); len(got) != 0 {
		t.Fatalf("a post-flush arm went through the unlatched passthrough: %v", got)
	}
	if tfAlerted() {
		t.Fatal("a post-flush boot alert with no subscriber consumed the episode")
	}

	tfSwapAlertStore(t, true)
	h.fail(1)
	h.fail(2)
	if got := h.pages(); len(got) != 1 || !strings.Contains(got[0], "tflatch-src-startup") {
		t.Fatalf("pages = %v, want exactly one page once a subscriber exists", got)
	}
}

// ── Recovery between the verdict and the latch (Codex P2 on #1971) ────────────

// TestThreatFeedStale_RecoveryBetweenVerdictAndLatchIsNotOverwritten — the
// staleness verdict is read outside the plane's lock (reading it under the lock
// would invert the order with the feed, whose observer takes it). A clean round
// that lands between the verdict and the latch decision clears the latch and
// ends the episode; latching after it set the latch straight back for an
// episode that was over, and the NEXT episode could not page until another
// clean sync. Feed.Sync (the admin manual sync) runs concurrently with the
// scheduler's rounds, so the interleaving is reachable at runtime.
func TestThreatFeedStale_RecoveryBetweenVerdictAndLatchIsNotOverwritten(t *testing.T) {
	h := newTFStartupHarness(t, true) // steady state: the startup flush is long done
	noteThreatFeedConfigured()        // stale at boot, nobody subscribed: nothing latched
	tfSwapAlertStore(t, true)
	h.feed.SeedSyncFailureForTest("tflatch-src-startup")

	h.armRecovery()
	evaluateThreatFeedStaleness()
	if !h.recovered() {
		t.Fatal("precondition: the recovery hook did not run inside the staleness verdict")
	}
	if got := h.pages(); len(got) != 0 {
		t.Errorf("paged %v for an episode that recovered before the latch decision", got)
	}
	if tfAlerted() {
		t.Fatal("a latch decided after a recovery re-latched the episode that recovery ended")
	}

	// The next real episode must page.
	h.mu.Lock()
	h.now = h.now.Add(3 * time.Hour)
	h.mu.Unlock()
	h.fail(1)
	if got := h.pages(); len(got) != 1 || !strings.Contains(got[0], "tflatch-src-startup") {
		t.Fatalf("pages = %v, want exactly the next episode's page: a stale latch silenced it", got)
	}
}

// TestThreatFeedStale_RecoveryAroundTheFlushClaimIsNotOverwritten — the same
// interleaving on the startup path. The flush runs after Start launched the
// scheduler, so a clean round can land while the claim decides. The recovery
// is armed for the first clock read the flush makes; if the claim makes none
// (it decides on the generation captured with the boot-time verdict, so there
// is no verdict to read at the flush), the recovery lands right after the
// claim instead. Whichever order, the episode the recovery ended must not stay
// latched, and the next episode must page.
func TestThreatFeedStale_RecoveryAroundTheFlushClaimIsNotOverwritten(t *testing.T) {
	h := newTFStartupHarness(t, false)
	noteThreatFeedConfigured()
	tfSwapAlertStore(t, true)

	h.armRecovery()
	flushStartupAlerts()
	if !h.recovered() {
		h.mu.Lock()
		h.recoverOnNow = false
		h.mu.Unlock()
		h.recoverNow()
	}
	if tfAlerted() {
		t.Fatal("the flush claim latched an episode that a concurrent recovery ended")
	}

	h.mu.Lock()
	h.now = h.now.Add(3 * time.Hour)
	h.mu.Unlock()
	h.fail(1)
	if n := h.runtimePages(); n != 1 {
		t.Fatalf("the next episode paged %d times, want 1: a stale latch silenced it (pages %v)", n, h.pages())
	}
}
