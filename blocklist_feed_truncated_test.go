package main

// blocklist_feed_truncated_test.go — the freshness plane's truncated-feed
// shape (2026-11-19 security regression review, "Reported, not fixed").
//
// A feed body that reaches internal/blocklistfeed's line cap is truncated, not
// failed, so its round advances LastSync and clears LastError. Before this
// change every surface here read such a feed as a clean, fresh sync. These
// gates pin its own gauge and its own WARN row, and the decision that it moves
// neither culvert_blocklist_feed_sync_ok nor the blocklist_feed_stale alert.
// Fixtures are CHAOS-123's (blFeedHealthTest and friends), which restore every
// global they touch.

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/blocklistfeed"
)

// truncatedRows returns the blocklist_feed rows that report truncation.
func truncatedRows(rows []OperatorContractCheck) []OperatorContractCheck {
	var out []OperatorContractCheck
	for _, r := range rows {
		if strings.Contains(r.Message, "TRUNCATED") {
			out = append(out, r)
		}
	}
	return out
}

// TestTruncatedFeedIsReportedOnItsOwnSurfaces is the finding: a fresh,
// succeeding feed whose latest sync was cut short at the line cap.
func TestTruncatedFeedIsReportedOnItsOwnSurfaces(t *testing.T) {
	now := time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC)
	bs := blFeedHealthTest(t, now)
	fired := captureStaleAlert(t)
	const big, small = "https://feeds.example.com/huge.txt", "https://feeds.example.com/small.txt"
	bs.SetFeed(big, 24*time.Hour)
	bs.SetFeed(small, 0) // manual-only: truncation is counted whatever the schedule
	bs.seedStatus(big, now.Add(-30*time.Minute), now.Add(-30*time.Minute), "")
	bs.seedStatus(small, now.Add(-time.Hour), now.Add(-time.Hour), "")
	bs.markTruncated(big)
	bs.markTruncated(small)

	snap := blocklistFeedState()
	if snap.TruncatedFeeds != 2 {
		t.Fatalf("want both truncated feeds counted, got %+v", snap)
	}
	// Truncation is not staleness and not failure: the rounds succeeded.
	if snap.StaleFeeds != 0 || snap.FailingFeeds != 0 {
		t.Errorf("a truncated feed must not read stale or failing: %+v", snap)
	}

	out := blFeedMetrics()
	wantSeries(t, out, "culvert_blocklist_feed_truncated", 2)
	// The decision under test: sync_ok keeps its documented meaning (failing or
	// stale), so truncation does not hold the paging signal at 0.
	wantSeries(t, out, "culvert_blocklist_feed_sync_ok", 1)
	if strings.Contains(out, "culvert_blocklist_feed_truncated{") {
		t.Errorf("the truncated series must carry no label:\n%s", out)
	}

	rows := checkBlocklistFeeds()
	trunc := truncatedRows(rows)
	if len(rows) != 1 || len(trunc) != 1 {
		t.Fatalf("want exactly one row, the truncation row, got %+v", rows)
	}
	r := trunc[0]
	if r.Code != "blocklist_feed" || r.Status != diagWarn {
		t.Errorf("want a blocklist_feed WARN row, got %+v", r)
	}
	lineCap := strconv.Itoa(blocklistfeed.MaxFeedLines())
	if !strings.Contains(r.Message, "2 of 2") || !strings.Contains(r.Message, lineCap+"-line feed cap") ||
		!strings.Contains(r.Message, "not being blocked") {
		t.Errorf("the row must carry the counts, the cap and the consequence, got %q", r.Message)
	}
	if !strings.Contains(r.OperatorAction, "Split") || !strings.Contains(r.OperatorAction, lineCap) {
		t.Errorf("the action must say to split the list below the cap, got %q", r.OperatorAction)
	}

	// The second half of the decision: a clean (truncated) round must not page
	// through the freshness alert.
	noteBlocklistFeedSync(blocklistfeed.SyncOutcome{OK: true, LastSync: now.Add(-30 * time.Minute), Interval: 24 * time.Hour})
	evaluateBlocklistFeedStaleness()
	if len(*fired) != 0 {
		t.Errorf("truncation must not fire blocklist_feed_stale, got %q", *fired)
	}
}

// TestTruncatedRowSitsBesideTheFailureRows checks that the truncation row is
// additive: a truncated feed that is ALSO stale and failing reports all three
// shapes, and the stale alert still fires for the staleness alone.
func TestTruncatedRowSitsBesideTheFailureRows(t *testing.T) {
	now := time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC)
	bs := blFeedHealthTest(t, now)
	fired := captureStaleAlert(t)
	const feed = "https://feeds.example.com/huge.txt"
	bs.SetFeed(feed, time.Hour)
	bs.seedStatus(feed, now.Add(-10*time.Hour), now.Add(-time.Minute), "HTTP 503")
	bs.markTruncated(feed)

	rows := checkBlocklistFeeds()
	if len(rows) != 3 || len(truncatedRows(rows)) != 1 {
		t.Fatalf("want the stale, failing and truncation rows, got %+v", rows)
	}
	out := blFeedMetrics()
	wantSeries(t, out, "culvert_blocklist_feed_truncated", 1)
	wantSeries(t, out, "culvert_blocklist_feed_sync_ok", 0)
	noteBlocklistFeedSync(blocklistfeed.SyncOutcome{ConsecutiveFailures: 1, Interval: time.Hour})
	if len(*fired) != 1 || strings.Contains((*fired)[0], "TRUNCATED") {
		t.Errorf("want one stale alert describing staleness, not truncation, got %q", *fired)
	}
}
