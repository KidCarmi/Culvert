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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/threatfeed"
)

// tfHealthHarness isolates the process-global feed + health record and captures
// alerts synchronously through the package-level seam (never the real sink —
// that is the -count/-shuffle determinism class the CI gate catches).
type tfHealthHarness struct {
	mu     sync.Mutex
	alerts []string
	now    time.Time
}

func newTFHealthHarness(t *testing.T, interval time.Duration) (*tfHealthHarness, *threatfeed.Feed) {
	t.Helper()
	h := &tfHealthHarness{now: time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)}

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
	fireThreatFeedStaleAlert = func(detail string) {
		h.mu.Lock()
		h.alerts = append(h.alerts, detail)
		h.mu.Unlock()
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
